package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
)

// rfc9773TestAKI is the AKI keyIdentifier from the example certificate in
// RFC 9773, Appendix A.
var rfc9773TestAKI, _ = hex.DecodeString("69885b6b87464041e1b37b847ba0ae2cde01c8d4")

// rfc9773TestCertID is the unique identifier for the example certificate
// in RFC 9773, Section 4.1.
const rfc9773TestCertID = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"

func mockCertificateStore(t *testing.T, store certificateStore) {
	t.Helper()
	fn := certificateStoreFromContext
	t.Cleanup(func() {
		certificateStoreFromContext = fn
	})
	certificateStoreFromContext = func(ctx context.Context) (certificateStore, error) {
		return store, nil
	}
}

type mockCertStore struct {
	get  func(serialNumber string) (*x509.Certificate, error)
	call int
}

func (m *mockCertStore) GetCertificate(serialNumber string) (*x509.Certificate, error) {
	m.call++
	return m.get(serialNumber)
}

func resetARICache(t *testing.T) {
	t.Helper()
	c := ariCache
	t.Cleanup(func() {
		ariCache = c
	})
	ariCache = newRenewalInfoCache(renewalInfoCacheMaxEntries, renewalInfoCacheTTL)
}

func Test_parseRenewalInfoCertID(t *testing.T) {
	tests := []struct {
		name    string
		certID  string
		aki     []byte
		serial  *big.Int
		wantErr bool
	}{
		{
			name:   "ok/rfc9773-example",
			certID: rfc9773TestCertID,
			aki:    rfc9773TestAKI,
			// DER contents 00:87:65:43:21, i.e. 0x87654321; the leading
			// zero byte keeps the serial positive.
			serial: big.NewInt(0x87654321),
		},
		{
			name:   "ok/small-serial",
			certID: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) + "." + base64.RawURLEncoding.EncodeToString([]byte{0x2a}),
			aki:    []byte{1, 2, 3},
			serial: big.NewInt(42),
		},
		{name: "fail/no-separator", certID: "abcdef", wantErr: true},
		{name: "fail/too-many-parts", certID: "a.b.c", wantErr: true},
		{name: "fail/bad-aki-encoding", certID: "!!!.AIdlQyE", wantErr: true},
		{name: "fail/bad-serial-encoding", certID: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.!!!", wantErr: true},
		{name: "fail/empty-aki", certID: ".AIdlQyE", wantErr: true},
		{name: "fail/empty-serial", certID: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aki, serial, err := parseRenewalInfoCertID(tt.certID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.FatalError(t, err)
			assert.Equals(t, aki, tt.aki)
			assert.Equals(t, serial.Cmp(tt.serial), 0)
		})
	}
}

func Test_renewalWindow(t *testing.T) {
	now := clock.Now()
	t.Run("ok/within-validity", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: now.Add(-30 * 24 * time.Hour),
			NotAfter:  now.Add(60 * 24 * time.Hour),
		}
		start, end := renewalWindow(now, cert, "some-cert-id")
		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		windowLength := lifetime / 12
		assert.Equals(t, end.Sub(start), windowLength)
		// centered (with jitter) on the two-thirds mark of the lifetime
		renewalPoint := cert.NotBefore.Add(2 * lifetime / 3)
		if start.Before(renewalPoint.Add(-windowLength/2)) || start.After(renewalPoint.Add(windowLength/2)) {
			t.Fatalf("start %v not within jitter range of renewal point %v", start, renewalPoint)
		}
		assert.True(t, !end.After(cert.NotAfter))
	})
	t.Run("ok/deterministic-per-certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: now.Add(-30 * 24 * time.Hour),
			NotAfter:  now.Add(60 * 24 * time.Hour),
		}
		start1, end1 := renewalWindow(now, cert, "cert-id-1")
		start1b, end1b := renewalWindow(now, cert, "cert-id-1")
		assert.Equals(t, start1, start1b)
		assert.Equals(t, end1, end1b)
		start2, _ := renewalWindow(now, cert, "cert-id-2")
		if start1.Equal(start2) {
			t.Fatal("expected different jitter for different certificate identifiers")
		}
	})
	t.Run("ok/clamped-to-not-after", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: now.Add(-89 * 24 * time.Hour),
			NotAfter:  now.Add(24 * time.Hour),
		}
		start, end := renewalWindow(now, cert, "some-cert-id")
		assert.True(t, !end.After(cert.NotAfter))
		assert.True(t, start.Before(end))
	})
	t.Run("ok/expired", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: now.Add(-90 * 24 * time.Hour),
			NotAfter:  now.Add(-time.Hour),
		}
		start, end := renewalWindow(now, cert, "some-cert-id")
		// window must lie entirely in the past so that clients renew
		// immediately, and end must be after start (RFC 9773, 4.2)
		assert.True(t, !end.After(now))
		assert.True(t, start.Before(end))
	})
	t.Run("ok/zero-lifetime", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: now,
			NotAfter:  now,
		}
		start, end := renewalWindow(now, cert, "some-cert-id")
		assert.True(t, start.Before(end))
	})
}

func Test_renewalInfoCache(t *testing.T) {
	now := clock.Now()
	c := newRenewalInfoCache(2, time.Minute)
	c.now = func() time.Time { return now }

	ri1 := &RenewalInfo{SuggestedWindow: RenewalInfoWindow{Start: now, End: now.Add(time.Hour)}}
	ri2 := &RenewalInfo{SuggestedWindow: RenewalInfoWindow{Start: now, End: now.Add(2 * time.Hour)}}

	_, ok := c.get("a")
	assert.False(t, ok)

	c.set("a", ri1)
	got, ok := c.get("a")
	assert.True(t, ok)
	assert.Equals(t, got, ri1)

	// expiration
	c.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, ok = c.get("a")
	assert.False(t, ok)
	c.now = func() time.Time { return now }

	// bound: evicts oldest when full
	c.set("a", ri1)
	c.now = func() time.Time { return now.Add(time.Second) }
	c.set("b", ri2)
	c.now = func() time.Time { return now.Add(2 * time.Second) }
	c.set("c", ri1)
	c.now = func() time.Time { return now }
	_, ok = c.get("a")
	assert.False(t, ok)
	_, ok = c.get("b")
	assert.True(t, ok)
	_, ok = c.get("c")
	assert.True(t, ok)

	// expired entries are evicted first
	c.now = func() time.Time { return now.Add(2 * time.Minute) }
	c.set("d", ri2)
	_, ok = c.get("d")
	assert.True(t, ok)
	assert.Equals(t, len(c.entries), 1)
}

func TestHandler_GetRenewalInfo(t *testing.T) {
	resetARICache(t)

	now := clock.Now()
	serial := new(big.Int).SetBytes([]byte{0x00, 0x87, 0x65, 0x43, 0x21})
	cert := &x509.Certificate{
		SerialNumber:   serial,
		AuthorityKeyId: rfc9773TestAKI,
		NotBefore:      now.Add(-30 * 24 * time.Hour),
		NotAfter:       now.Add(60 * 24 * time.Hour),
	}
	expiredCert := &x509.Certificate{
		SerialNumber:   serial,
		AuthorityKeyId: rfc9773TestAKI,
		NotBefore:      now.Add(-90 * 24 * time.Hour),
		NotAfter:       now.Add(-time.Hour),
	}
	serialString := serial.String()

	certID := rfc9773TestCertID
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("certID", certID)
	badChiCtx := chi.NewRouteContext()
	badChiCtx.URLParams.Add("certID", "not-a-valid-cert-id")

	type test struct {
		ctx        context.Context
		statusCode int
		errType    string
		check      func(t *testing.T, res *http.Response, body []byte)
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/malformed-cert-id": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, badChiCtx)
			return test{
				ctx:        ctx,
				statusCode: 400,
				errType:    "urn:ietf:params:acme:error:malformed",
			}
		},
		"fail/unknown-certificate": func(t *testing.T) test {
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					return nil, errors.Wrap(database.ErrNotFound, "database Get error")
				},
			})
			mockMustAuthority(t, &mockCA{})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 404,
				errType:    "urn:ietf:params:acme:error:malformed",
			}
		},
		"fail/store-error": func(t *testing.T) test {
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("force")
				},
			})
			mockMustAuthority(t, &mockCA{})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 500,
				errType:    "urn:ietf:params:acme:error:serverInternal",
			}
		},
		"fail/aki-mismatch": func(t *testing.T) test {
			other := *cert
			other.AuthorityKeyId = []byte{1, 2, 3}
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					return &other, nil
				},
			})
			mockMustAuthority(t, &mockCA{})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 404,
				errType:    "urn:ietf:params:acme:error:malformed",
			}
		},
		"fail/revoked": func(t *testing.T) test {
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					return cert, nil
				},
			})
			mockMustAuthority(t, &mockCA{
				MockIsRevoked: func(sn string) (bool, error) {
					assert.Equals(t, sn, serialString)
					return true, nil
				},
			})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 400,
				errType:    "urn:ietf:params:acme:error:alreadyRevoked",
			}
		},
		"ok": func(t *testing.T) test {
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					assert.Equals(t, sn, serialString)
					return cert, nil
				},
			})
			mockMustAuthority(t, &mockCA{})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 200,
				check: func(t *testing.T, res *http.Response, body []byte) {
					assert.Equals(t, res.Header.Get("Retry-After"), "21600")
					var ri RenewalInfo
					assert.FatalError(t, json.Unmarshal(body, &ri))
					assert.True(t, ri.SuggestedWindow.Start.Before(ri.SuggestedWindow.End))
					assert.True(t, !ri.SuggestedWindow.End.After(cert.NotAfter))
					assert.Equals(t, ri.ExplanationURL, RenewalInfoExplanationURL)
				},
			}
		},
		"ok/expired-certificate": func(t *testing.T) test {
			mockCertificateStore(t, &mockCertStore{
				get: func(sn string) (*x509.Certificate, error) {
					return expiredCert, nil
				},
			})
			mockMustAuthority(t, &mockCA{})
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			return test{
				ctx:        ctx,
				statusCode: 200,
				check: func(t *testing.T, res *http.Response, body []byte) {
					var ri RenewalInfo
					assert.FatalError(t, json.Unmarshal(body, &ri))
					// expired certificates get a window entirely in the
					// past, so clients renew immediately
					assert.True(t, !ri.SuggestedWindow.End.After(clock.Now()))
					assert.True(t, ri.SuggestedWindow.Start.Before(ri.SuggestedWindow.End))
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			resetARICache(t)
			tc := run(t)
			req := httptest.NewRequest("GET", "https://ca.smallstep.com/acme/prov/renewal-info/"+certID, http.NoBody)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			GetRenewalInfo(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if tc.errType != "" {
				var ae acme.Error
				assert.FatalError(t, json.Unmarshal(body, &ae))
				assert.Equals(t, ae.Type, tc.errType)
			}
			if tc.check != nil {
				tc.check(t, res, body)
			}
		})
	}
}

func TestHandler_GetRenewalInfo_cache(t *testing.T) {
	resetARICache(t)

	now := clock.Now()
	serial := new(big.Int).SetBytes([]byte{0x00, 0x87, 0x65, 0x43, 0x21})
	cert := &x509.Certificate{
		SerialNumber:   serial,
		AuthorityKeyId: rfc9773TestAKI,
		NotBefore:      now.Add(-30 * 24 * time.Hour),
		NotAfter:       now.Add(60 * 24 * time.Hour),
	}
	store := &mockCertStore{
		get: func(sn string) (*x509.Certificate, error) {
			return cert, nil
		},
	}
	mockCertificateStore(t, store)
	mockMustAuthority(t, &mockCA{})

	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("certID", rfc9773TestCertID)
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)

	var first, second RenewalInfo
	for i, dst := range []*RenewalInfo{&first, &second} {
		req := httptest.NewRequest("GET", "https://ca.smallstep.com/acme/prov/renewal-info/"+rfc9773TestCertID, http.NoBody)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		GetRenewalInfo(w, req)
		res := w.Result()
		assert.Equals(t, res.StatusCode, 200)
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		assert.FatalError(t, err)
		assert.FatalError(t, json.Unmarshal(body, dst))
		_ = i
	}

	// the second request must have been served from the cache: the
	// certificate store was only consulted once, and the response is
	// identical
	assert.Equals(t, store.call, 1)
	assert.Equals(t, first, second)
}

func TestHandler_GetRenewalInfo_certIDEncoding(t *testing.T) {
	// verify the certID construction documented in RFC 9773, Section 4.1
	// against the example certificate in its Appendix A
	aki, err := base64.RawURLEncoding.DecodeString(strings.Split(rfc9773TestCertID, ".")[0])
	assert.FatalError(t, err)
	assert.Equals(t, aki, rfc9773TestAKI)

	serialPart := strings.Split(rfc9773TestCertID, ".")[1]
	serialBytes, err := base64.RawURLEncoding.DecodeString(serialPart)
	assert.FatalError(t, err)
	assert.Equals(t, serialBytes, []byte{0x00, 0x87, 0x65, 0x43, 0x21})
}
