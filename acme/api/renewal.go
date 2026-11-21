package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"github.com/smallstep/nosql"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/logging"
)

const (
	// renewalInfoRetryAfter is the value of the Retry-After header sent with
	// renewalInfo responses. It tells clients how long to wait before
	// checking the renewal information again (RFC 9773, Section 4.3.1).
	renewalInfoRetryAfter = 6 * time.Hour

	// renewalInfoCacheMaxEntries bounds the number of cached RenewalInfo
	// responses.
	renewalInfoCacheMaxEntries = 1024

	// renewalInfoCacheTTL is how long a cached RenewalInfo response is
	// served before it is recomputed.
	renewalInfoCacheTTL = 10 * time.Minute
)

// RenewalInfoExplanationURL is the value of the explanationURL field in
// RenewalInfo responses. It points to documentation explaining how the
// suggested renewal window is computed. It is a variable so that
// deployers embedding step-ca can point it at their own documentation.
var RenewalInfoExplanationURL = "https://www.rfc-editor.org/rfc/rfc9773.html"

// RenewalInfoWindow bounds the window of time in which the CA recommends
// renewing a certificate (RFC 9773, Section 4.2).
type RenewalInfoWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RenewalInfo is the ACME RenewalInfo object (RFC 9773, Section 4.2).
type RenewalInfo struct {
	SuggestedWindow RenewalInfoWindow `json:"suggestedWindow"`
	ExplanationURL  string            `json:"explanationURL,omitempty"`
}

// ToLog enables response logging for the RenewalInfo type.
func (ri *RenewalInfo) ToLog() (any, error) {
	b, err := json.Marshal(ri)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling renewalInfo for logging")
	}
	return string(b), nil
}

// certificateStore is the subset of the authority database required to
// serve renewal information.
type certificateStore interface {
	GetCertificate(serialNumber string) (*x509.Certificate, error)
}

// certificateStoreFromContext returns the certificate store of the
// authority in the context. It is a variable so that it can be mocked
// in tests.
var certificateStoreFromContext = func(ctx context.Context) (certificateStore, error) {
	provider, ok := mustAuthority(ctx).(interface {
		GetDatabase() db.AuthDB
	})
	if !ok {
		return nil, acme.NewErrorISE("certificate authority does not expose a certificate store")
	}
	return provider.GetDatabase(), nil
}

// GetRenewalInfo is the ACME Renewal Information (ARI) endpoint
// described in RFC 9773. It serves the suggested renewal window for the
// certificate identified by the {certID} path parameter, which is
// constructed as base64url(AKI keyIdentifier) || "." || base64url(DER
// serial number contents). It is an unauthenticated GET endpoint.
func GetRenewalInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certID := chi.URLParam(r, "certID")

	var provName string
	if p, ok := acme.ProvisionerFromContext(ctx); ok {
		provName = p.GetName()
	}
	cacheKey := provName + "/" + certID

	if ri, ok := ariCache.get(cacheKey); ok {
		logRenewalInfo(w, certID, "hit", ri)
		writeRenewalInfo(w, r, ri)
		return
	}

	aki, serial, err := parseRenewalInfoCertID(certID)
	if err != nil {
		render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err, "error parsing renewalInfo certificate identifier"))
		return
	}
	serialString := serial.String()

	store, err := certificateStoreFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	cert, err := store.GetCertificate(serialString)
	switch {
	case nosql.IsErrNotFound(err) || acme.IsErrNotFound(err):
		render.Error(w, r, newCertNotFoundError(serialString))
		return
	case err != nil:
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving certificate with serial %s", serialString))
		return
	}

	// The certificate identified by the client must have been issued by
	// this CA: the AKI in the request has to match the one in the
	// certificate stored under the requested serial number.
	if !bytes.Equal(cert.AuthorityKeyId, aki) {
		render.Error(w, r, newCertNotFoundError(serialString))
		return
	}

	revoked, err := mustAuthority(ctx).IsRevoked(serialString)
	if err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving revocation status of certificate with serial %s", serialString))
		return
	}
	if revoked {
		render.Error(w, r, acme.NewError(acme.ErrorAlreadyRevokedType,
			"certificate with serial %s has been revoked", serialString))
		return
	}

	ri := newRenewalInfo(clock.Now(), cert, certID)
	ariCache.set(cacheKey, ri)
	logRenewalInfo(w, certID, "miss", ri)
	writeRenewalInfo(w, r, ri)
}

// newCertNotFoundError returns an ACME error indicating that no
// certificate is known for the requested identifier. It uses a 404
// status so that unknown certificates can be distinguished from
// malformed requests (400) and revoked certificates (alreadyRevoked).
func newCertNotFoundError(serial string) *acme.Error {
	err := acme.NewError(acme.ErrorMalformedType, "certificate with serial %s not found", serial)
	err.Status = http.StatusNotFound
	return err
}

// parseRenewalInfoCertID parses the unique identifier for a certificate
// as described in RFC 9773, Section 4.1: the base64url encoding of the
// certificate's AKI keyIdentifier, a period, and the base64url encoding
// of the DER-encoded Serial Number field contents (without the tag and
// length bytes).
func parseRenewalInfoCertID(certID string) (aki []byte, serial *big.Int, err error) {
	parts := strings.Split(certID, ".")
	if len(parts) != 2 {
		return nil, nil, errors.Errorf("certificate identifier %q does not consist of two parts", certID)
	}
	aki, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error base64url decoding AKI part of certificate identifier %q", certID)
	}
	if len(aki) == 0 {
		return nil, nil, errors.Errorf("AKI part of certificate identifier %q is empty", certID)
	}
	serialBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error base64url decoding serial part of certificate identifier %q", certID)
	}
	if len(serialBytes) == 0 {
		return nil, nil, errors.Errorf("serial part of certificate identifier %q is empty", certID)
	}
	return aki, new(big.Int).SetBytes(serialBytes), nil
}

// newRenewalInfo computes the RenewalInfo object for a certificate. The
// suggested window covers one twelfth of the certificate lifetime,
// centered on the two-thirds mark of its validity period, and is
// jittered deterministically per certificate so that batches of
// certificates issued together do not all renew at the same second. For
// certificates that have already expired, the window lies entirely in
// the past, signaling to clients that they should renew immediately.
func newRenewalInfo(now time.Time, cert *x509.Certificate, certID string) *RenewalInfo {
	start, end := renewalWindow(now, cert, certID)
	return &RenewalInfo{
		SuggestedWindow: RenewalInfoWindow{
			Start: start,
			End:   end,
		},
		ExplanationURL: RenewalInfoExplanationURL,
	}
}

// renewalWindow computes the suggested renewal window for a certificate.
func renewalWindow(now time.Time, cert *x509.Certificate, certID string) (start, end time.Time) {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	windowLength := lifetime / 12
	if windowLength < time.Second {
		windowLength = time.Second
	}

	// Certificates that have expired (or have a non-positive lifetime)
	// get a window entirely in the past: per RFC 9773, Section 4.2,
	// clients select a random time within the window and renew
	// immediately if that time is in the past.
	if lifetime <= 0 || !now.Before(cert.NotAfter) {
		return now.Add(-windowLength), now
	}

	// Deterministic jitter in [-windowLength/2, windowLength/2), derived
	// from the certificate identifier, so that the window is stable
	// across requests but spread out across certificates.
	h := sha256.Sum256([]byte(certID))
	jitter := time.Duration(int64(binary.BigEndian.Uint64(h[:8])%uint64(windowLength))) - windowLength/2

	start = cert.NotBefore.Add(2 * lifetime / 3).Add(jitter)
	end = start.Add(windowLength)
	if end.After(cert.NotAfter) {
		end = cert.NotAfter
		start = end.Add(-windowLength)
	}
	return start, end
}

// writeRenewalInfo writes a RenewalInfo response, including the
// Retry-After header required by RFC 9773, Section 4.3.
func writeRenewalInfo(w http.ResponseWriter, r *http.Request, ri *RenewalInfo) {
	w.Header().Set("Retry-After", strconv.Itoa(int(renewalInfoRetryAfter/time.Second)))
	render.JSON(w, r, ri)
}

// logRenewalInfo logs the renewalInfo response, including whether it
// was served from the cache.
func logRenewalInfo(w http.ResponseWriter, certID, cacheStatus string, ri *RenewalInfo) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]any{
			"certID":       certID,
			"ari-cache":    cacheStatus,
			"window-start": ri.SuggestedWindow.Start.Format(time.RFC3339),
			"window-end":   ri.SuggestedWindow.End.Format(time.RFC3339),
		})
	}
}

// renewalInfoCacheEntry is a single cached RenewalInfo response.
type renewalInfoCacheEntry struct {
	info      *RenewalInfo
	createdAt time.Time
	expiresAt time.Time
}

// renewalInfoCache is a bounded in-memory cache for RenewalInfo
// responses with per-entry expiration.
type renewalInfoCache struct {
	mu      sync.Mutex
	entries map[string]*renewalInfoCacheEntry
	max     int
	ttl     time.Duration
	now     func() time.Time
}

func newRenewalInfoCache(maxEntries int, ttl time.Duration) *renewalInfoCache {
	return &renewalInfoCache{
		entries: make(map[string]*renewalInfoCacheEntry),
		max:     maxEntries,
		ttl:     ttl,
		now:     clock.Now,
	}
}

// ariCache caches RenewalInfo responses per certificate identifier.
var ariCache = newRenewalInfoCache(renewalInfoCacheMaxEntries, renewalInfoCacheTTL)

// get returns the cached RenewalInfo for the given key, if present and
// not expired.
func (c *renewalInfoCache) get(key string) (*RenewalInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return e.info, true
}

// set stores the RenewalInfo for the given key. Expired entries are
// evicted first; if the cache is still at its bound, the oldest entry
// is evicted.
func (c *renewalInfoCache) set(key string, ri *RenewalInfo) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.max {
		for k, e := range c.entries {
			if !now.Before(e.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.max {
		var (
			oldestKey string
			oldest    time.Time
		)
		for k, e := range c.entries {
			if oldestKey == "" || e.createdAt.Before(oldest) {
				oldestKey, oldest = k, e.createdAt
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = &renewalInfoCacheEntry{
		info:      ri,
		createdAt: now,
		expiresAt: now.Add(c.ttl),
	}
}
