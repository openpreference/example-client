package opi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeServer is a minimal OPI server: WebFinger, keys, a signed bundle and a
// signed trust list, enough to exercise every verification path.
type fakeServer struct {
	*httptest.Server
	epsKey, trustKey *ecdsa.PrivateKey
	bundleClaims     map[string]any
	typ              string
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{typ: JWTTypeBundle}
	var err error
	if f.epsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.trustKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	origin := f.URL

	jwks := func(k *ecdsa.PrivateKey, kid string) []byte {
		b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}})
		return b
	}
	sign := func(k *ecdsa.PrivateKey, kid, typ string, claims any) string {
		opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, opts.WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		obj, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := obj.CompactSerialize()
		return out
	}

	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "acct:alice@"+strings.TrimPrefix(origin, "http://") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/jrd+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject": "acct:alice@example.test",
			"links": []map[string]any{
				{"rel": RelPreferences, "href": origin + "/opi/preferences/alice", "type": MediaTypeBundle, "properties": map[string]string{TiersProperty: "public client"}},
				{"rel": RelKeys, "href": origin + "/.well-known/opi-keys.json"},
				{"rel": RelAuth, "href": origin + "/.well-known/oauth-authorization-server"},
			},
		})
	})
	mux.HandleFunc("/.well-known/opi-keys.json", func(w http.ResponseWriter, r *http.Request) { w.Write(jwks(f.epsKey, "eps-1")) })
	mux.HandleFunc("/.well-known/opi-trust-keys.json", func(w http.ResponseWriter, r *http.Request) { w.Write(jwks(f.trustKey, "trust-1")) })
	mux.HandleFunc("/opi/preferences/alice", func(w http.ResponseWriter, r *http.Request) {
		claims := f.bundleClaims
		if claims == nil {
			claims = map[string]any{
				"schema": SchemaEPS, "iss": origin, "sub": "acct:alice@example.test",
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"preferences": []map[string]any{{"type": TypeNamespace + "locale", "version": "1.0.0", "value": map[string]string{"language": "en-CA"}}},
			}
		}
		w.Header().Set("Content-Type", MediaTypeBundle)
		w.Write([]byte(sign(f.epsKey, "eps-1", f.typ, claims)))
	})
	mux.HandleFunc("/trust/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", MediaTypeTrust)
		w.Write([]byte(sign(f.trustKey, "trust-1", JWTTypeTrust, map[string]any{
			"schema": SchemaTrust, "kind": "full", "registry": origin + "/trust/registry",
			"issued": time.Now().UTC().Format(time.RFC3339), "expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			"entries": []map[string]any{{"entity": "https://grocer.test", "client_id": "opi_client_grocer", "verifications": []map[string]any{{"category": "retail", "verified_at": "2026-10-01T00:00:00Z"}}}},
		})))
	})
	return f
}

// The fake server is plain http; the client builds https URLs from the
// WebFinger host, so point Discover at the server directly via a transport
// that rewrites the scheme.
type httpOnly struct{ base http.RoundTripper }

func (h httpOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"
	return h.base.RoundTrip(r)
}

func newClient(f *fakeServer) *Client {
	return &Client{HTTP: &http.Client{Transport: httpOnly{http.DefaultTransport}}}
}

func TestDiscoverReadVerify(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	c := newClient(f)
	ctx := context.Background()
	host := strings.TrimPrefix(f.URL, "http://")

	d, err := c.Discover(ctx, "alice@"+host)
	if err != nil {
		t.Fatal(err)
	}
	if d.PreferencesURL == "" || d.KeysURL == "" || len(d.Tiers) != 2 {
		t.Fatalf("discovery incomplete: %+v", d)
	}
	b, err := c.Read(ctx, d, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Subject != "acct:alice@example.test" || len(b.Preferences) != 1 || ShortType(b.Preferences[0].Type) != "locale" || b.KeyID != "eps-1" {
		t.Fatalf("unexpected bundle: %+v", b)
	}
}

func TestRejectsWrongTypAndExpiry(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	c := newClient(f)
	ctx := context.Background()
	host := strings.TrimPrefix(f.URL, "http://")
	d, _ := c.Discover(ctx, "acct:alice@"+host)

	f.typ = "JWT"
	if _, err := c.Read(ctx, d, ReadOptions{}); err == nil || !strings.Contains(err.Error(), "typ") {
		t.Fatalf("wrong typ accepted: %v", err)
	}
	f.typ = JWTTypeBundle
	f.bundleClaims = map[string]any{"schema": SchemaEPS, "iss": f.URL, "sub": "acct:alice@example.test", "iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(), "preferences": []any{}}
	if _, err := c.Read(ctx, d, ReadOptions{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired bundle accepted: %v", err)
	}
}

func TestTrustList(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	c := newClient(f)
	l, err := c.TrustList(context.Background(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind != "full" || len(l.Entries) != 1 || l.KeyID != "trust-1" {
		t.Fatalf("unexpected list: %+v", l)
	}
	if !l.Trusted("opi_client_grocer", "retail") || l.Trusted("opi_client_grocer", "finance") || l.Trusted("nobody", "") {
		t.Fatal("Trusted() verdicts wrong")
	}
}

func TestPKCEAndAuthorizeURL(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	u, err := AuthorizeURL(&AuthMetadata{AuthorizationEndpoint: "https://srv/oauth/authorize"}, "cid", "https://app/cb", p,
		[]AuthorizationDetail{{PreferenceTypes: []string{TypeNamespace + "dietary"}, Purpose: "Flag allergens", Retention: "P30D"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"code_challenge_method=S256", "code_challenge=" + p.Challenge, "state=" + p.State, "authorization_details=", "pd%2F0.1%2Fauthorization_details"} {
		if !strings.Contains(u, want) {
			t.Fatalf("authorize URL lacks %q: %s", want, u)
		}
	}
}
