// Package opi is a small, dependency-light client for the Open Preference
// Initiative protocol (OPI-PD 0.1, OPI-EPS 0.1, OPI-TRUST 0.1).
//
// It covers the four things every consumer needs:
//
//   - Discover: resolve acct:handle@host to a preference URL, key set and
//     OAuth metadata with WebFinger (OPI-PD §4).
//   - Read: fetch a signed bundle at the public, client or user tier and
//     verify it against the server's published keys (OPI-EPS §9).
//   - Authenticate: client credentials for the client tier and
//     authorization code + PKCE with Rich Authorization Requests for the
//     user tier (OPI-PD §6, §8).
//   - Trust: fetch and verify a trust list and its deltas (OPI-TRUST §4).
//
// Everything is plain net/http plus go-jose for signature checks, so it is
// easy to transliterate into another language.
package opi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// Spec identifiers. Treat them as opaque strings: they are the same on
	// every conforming server.
	SchemaEPS         = "https://openpreference.org/eps/0.1"
	TypeNamespace     = SchemaEPS + "/types/"
	RelPreferences    = "https://openpreference.org/rel/preferences"
	RelKeys           = "https://openpreference.org/rel/keys"
	RelAuth           = "https://openpreference.org/rel/auth"
	TiersProperty     = "https://openpreference.org/pd/0.1/tiers"
	MediaTypeBundle   = "application/opi-eps+jwt"
	JWTTypeBundle     = "opi-eps+jwt"
	JWTTypeTrust      = "opi-trust+jwt"
	SchemaTrust       = "https://openpreference.org/trust/0.1"
	AuthDetailsType   = "https://openpreference.org/pd/0.1/authorization_details"
	MediaTypeTrust    = "application/jose"
	defaultClockSkew  = 2 * time.Minute
	defaultHTTPTimout = 15 * time.Second
)

// Client talks to OPI servers. The zero value is usable; set HTTP to
// customise transport or timeouts.
type Client struct {
	HTTP      *http.Client
	ClockSkew time.Duration

	mu   sync.Mutex
	jwks map[string]*jose.JSONWebKeySet // by URL
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultHTTPTimout}
}

func (c *Client) skew() time.Duration {
	if c.ClockSkew > 0 {
		return c.ClockSkew
	}
	return defaultClockSkew
}

// ---------------------------------------------------------------------------
// Discovery (OPI-PD §4)

// Discovery is what WebFinger tells us about a subject.
type Discovery struct {
	Subject        string   // acct:alice@example.com or https://example.com
	Origin         string   // https://host that serves the preferences
	PreferencesURL string   // rel/preferences href
	KeysURL        string   // rel/keys href
	AuthMetaURL    string   // rel/auth href
	Tiers          []string // advertised tiers, e.g. public client user
}

type webfingerDoc struct {
	Subject string `json:"subject"`
	Links   []struct {
		Rel        string            `json:"rel"`
		Href       string            `json:"href"`
		Type       string            `json:"type"`
		Properties map[string]string `json:"properties"`
	} `json:"links"`
}

// Discover resolves a subject. For acct:handle@host the WebFinger host is
// the part after @; for https://domain it is that domain.
func (c *Client) Discover(ctx context.Context, subject string) (*Discovery, error) {
	subject = strings.TrimSpace(subject)
	var host string
	switch {
	case strings.HasPrefix(subject, "acct:"):
		at := strings.LastIndex(subject, "@")
		if at < 0 {
			return nil, errors.New("acct subject needs an @host")
		}
		host = subject[at+1:]
	case strings.HasPrefix(subject, "https://"):
		u, err := url.Parse(subject)
		if err != nil || u.Host == "" {
			return nil, errors.New("bad https subject")
		}
		host = u.Host
	default:
		// Be forgiving: "alice@example.com" means acct:alice@example.com.
		if strings.Contains(subject, "@") {
			return c.Discover(ctx, "acct:"+subject)
		}
		return nil, errors.New("subject must be acct:handle@host or https://domain")
	}

	wf := "https://" + host + "/.well-known/webfinger?resource=" + url.QueryEscape(subject)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, wf, nil)
	req.Header.Set("Accept", "application/jrd+json, application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webfinger: HTTP %d", resp.StatusCode)
	}
	var doc webfingerDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}
	d := &Discovery{Subject: doc.Subject, Origin: "https://" + host}
	for _, l := range doc.Links {
		switch l.Rel {
		case RelPreferences:
			d.PreferencesURL = l.Href
			if t := l.Properties[TiersProperty]; t != "" {
				d.Tiers = strings.Fields(t)
			}
		case RelKeys:
			d.KeysURL = l.Href
		case RelAuth:
			d.AuthMetaURL = l.Href
		}
	}
	if d.PreferencesURL == "" || d.KeysURL == "" {
		return nil, errors.New("webfinger: no preferences or keys link; not an OPI subject")
	}
	return d, nil
}

// ErrNotFound is returned where the spec mandates a constant 404: unknown
// subjects, and subjects with nothing readable at the caller's tier. The
// two are deliberately indistinguishable (OPI-PD §10).
var ErrNotFound = errors.New("not found (unknown subject, or nothing readable at this tier)")

// ---------------------------------------------------------------------------
// Bundles (OPI-EPS §4, §9)

// Bundle is a verified EPS preference bundle.
type Bundle struct {
	Schema      string    `json:"schema"`
	Issuer      string    `json:"iss"`
	Subject     string    `json:"sub"`
	IssuedAt    int64     `json:"iat"`
	ExpiresAt   int64     `json:"exp"`
	Preferences []Element `json:"preferences"`

	KeyID string `json:"-"` // kid that signed it
	Raw   string `json:"-"` // the compact JWS as received
}

// Element is one preference (OPI-EPS §5).
type Element struct {
	Type       string          `json:"type"`
	Version    string          `json:"version"`
	Value      json.RawMessage `json:"value"`
	Source     string          `json:"source,omitempty"`
	Updated    string          `json:"updated,omitempty"`
	Categories []string        `json:"categories,omitempty"` // client tier only
}

// ShortType trims the baseline namespace for display.
func ShortType(uri string) string {
	return strings.TrimPrefix(uri, TypeNamespace)
}

// ReadOptions narrow a read.
type ReadOptions struct {
	// Types limits the bundle to these type URIs (?types=, OPI-PD §7.3).
	Types []string
	// Bearer is an access token for the client or user tier. Empty = public.
	Bearer string
}

// Read fetches and verifies the subject's bundle. Verification checks the
// JOSE typ, the algorithm, that kid is in the server's published key set,
// the signature, and iat/exp against the clock (OPI-EPS §9.1, §9.2).
func (c *Client) Read(ctx context.Context, d *Discovery, opt ReadOptions) (*Bundle, error) {
	u := d.PreferencesURL
	if len(opt.Types) > 0 {
		u += "?types=" + url.QueryEscape(strings.Join(opt.Types, " "))
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", MediaTypeBundle)
	if opt.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+opt.Bearer)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("unauthorized: %s", resp.Header.Get("WWW-Authenticate"))
	default:
		return nil, fmt.Errorf("preferences: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return c.VerifyBundle(ctx, strings.TrimSpace(string(raw)), d.KeysURL)
}

// VerifyBundle checks a compact JWS bundle against the key set at keysURL.
func (c *Client) VerifyBundle(ctx context.Context, compact, keysURL string) (*Bundle, error) {
	payload, kid, err := c.verifyJWS(ctx, compact, keysURL, JWTTypeBundle)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if b.Schema != SchemaEPS {
		return nil, fmt.Errorf("bundle: unsupported schema %q", b.Schema)
	}
	now := time.Now()
	if b.ExpiresAt > 0 && now.After(time.Unix(b.ExpiresAt, 0)) {
		return nil, errors.New("bundle: expired")
	}
	if b.IssuedAt > 0 && time.Unix(b.IssuedAt, 0).After(now.Add(c.skew())) {
		return nil, errors.New("bundle: issued in the future")
	}
	b.KeyID, b.Raw = kid, compact
	return &b, nil
}

// verifyJWS parses a compact JWS, enforces typ and alg, finds the key by
// kid in the (cached) key set, and returns the verified payload.
func (c *Client) verifyJWS(ctx context.Context, compact, keysURL, wantTyp string) ([]byte, string, error) {
	sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA})
	if err != nil {
		return nil, "", fmt.Errorf("jws: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return nil, "", errors.New("jws: expected exactly one signature")
	}
	h := sig.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != wantTyp {
		return nil, "", fmt.Errorf("jws: typ %q, want %q", typ, wantTyp)
	}
	if h.KeyID == "" {
		return nil, "", errors.New("jws: missing kid")
	}
	keys, err := c.keySet(ctx, keysURL, h.KeyID)
	if err != nil {
		return nil, "", err
	}
	matches := keys.Key(h.KeyID)
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("jws: kid %q not in %s", h.KeyID, keysURL)
	}
	payload, err := sig.Verify(matches[0])
	if err != nil {
		return nil, "", fmt.Errorf("jws: signature invalid: %w", err)
	}
	return payload, h.KeyID, nil
}

// keySet returns the JWK Set at url, refetching when a kid is unknown so a
// server's key rotation is picked up without a restart.
func (c *Client) keySet(ctx context.Context, keysURL, needKid string) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	if c.jwks == nil {
		c.jwks = map[string]*jose.JSONWebKeySet{}
	}
	ks, ok := c.jwks[keysURL]
	c.mu.Unlock()
	if ok && len(ks.Key(needKid)) > 0 {
		return ks, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, keysURL, nil)
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keys: HTTP %d from %s", resp.StatusCode, keysURL)
	}
	var fresh jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&fresh); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	c.mu.Lock()
	c.jwks[keysURL] = &fresh
	c.mu.Unlock()
	return &fresh, nil
}

// ---------------------------------------------------------------------------
// OAuth (OPI-PD §6 client tier, §8 user tier)

// AuthMetadata is the subset of RFC 8414 metadata OPI clients use.
type AuthMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// AuthMeta fetches the server's OAuth metadata from the discovery document.
func (c *Client) AuthMeta(ctx context.Context, d *Discovery) (*AuthMetadata, error) {
	u := d.AuthMetaURL
	if u == "" {
		u = d.Origin + "/.well-known/oauth-authorization-server"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth metadata: HTTP %d", resp.StatusCode)
	}
	var m AuthMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Token is an OAuth token response.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// ClientCredentials obtains a client-tier token. scopes are preference type
// URIs; the server grants only what the client is entitled to (trust
// registry listing and category verification, OPI-PD §6).
func (c *Client) ClientCredentials(ctx context.Context, meta *AuthMetadata, clientID, clientSecret string, scopes []string) (*Token, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(scopes, " ")}}
	return c.token(ctx, meta.TokenEndpoint, clientID, clientSecret, form)
}

func (c *Client) token(ctx context.Context, endpoint, clientID, clientSecret string, form url.Values) (*Token, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret)) // RFC 6749 §2.3.1
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			return nil, fmt.Errorf("token: HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("token: %s: %s", e.Error, e.Desc)
	}
	var t Token
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	return &t, nil
}

// AuthorizationDetail is the Rich Authorization Request object OPI uses
// (RFC 9396 with OPI-PD §8.2 fields). Purpose is shown to the person on the
// consent screen; retention is an ISO 8601 duration such as P30D.
type AuthorizationDetail struct {
	Type            string   `json:"type"`
	PreferenceTypes []string `json:"preference_types"`
	Purpose         string   `json:"purpose"`
	Retention       string   `json:"retention"`
}

// PKCE holds the verifier for one authorization request. Keep it in the
// user's session between redirect and callback.
type PKCE struct {
	Verifier  string
	Challenge string
	State     string
}

// NewPKCE makes a fresh S256 verifier/challenge pair and a random state.
func NewPKCE() (*PKCE, error) {
	v := make([]byte, 32)
	if _, err := rand.Read(v); err != nil {
		return nil, err
	}
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	return &PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		State:     base64.RawURLEncoding.EncodeToString(s),
	}, nil
}

// AuthorizeURL builds the user-tier consent URL (OPI-PD §8).
func AuthorizeURL(meta *AuthMetadata, clientID, redirectURL string, p *PKCE, details []AuthorizationDetail) (string, error) {
	for i := range details {
		details[i].Type = AuthDetailsType
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURL},
		"state":                 {p.State},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(raw)},
	}
	return meta.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Exchange trades the authorization code for a user-tier token.
func (c *Client) Exchange(ctx context.Context, meta *AuthMetadata, clientID, clientSecret, redirectURL, code string, p *PKCE) (*Token, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURL},
		"code_verifier": {p.Verifier},
	}
	return c.token(ctx, meta.TokenEndpoint, clientID, clientSecret, form)
}

// ---------------------------------------------------------------------------
// Trust lists (OPI-TRUST §4)

// TrustList is a verified trust list or delta.
type TrustList struct {
	Schema   string       `json:"schema"`
	Kind     string       `json:"kind"` // full or delta
	Base     string       `json:"base,omitempty"`
	Registry string       `json:"registry"`
	Issued   string       `json:"issued"`
	Expires  string       `json:"expires"`
	Entries  []TrustEntry `json:"entries"`
	KeyID    string       `json:"-"`
}

type TrustEntry struct {
	Entity        string `json:"entity"`
	ClientID      string `json:"client_id,omitempty"`
	Revoked       bool   `json:"revoked,omitempty"`
	Verifications []struct {
		Category   string `json:"category"`
		VerifiedAt string `json:"verified_at"`
		Expires    string `json:"expires,omitempty"`
		Evidence   string `json:"evidence,omitempty"`
	} `json:"verifications"`
}

// TrustList fetches and verifies the registry's full list from origin.
// Keys come from the registry's trust key set, which is separate from the
// preference signing keys.
func (c *Client) TrustList(ctx context.Context, origin string) (*TrustList, error) {
	return c.trust(ctx, origin, origin+"/trust/list")
}

// TrustDelta fetches the delta since the current full list. Apply it only
// when its base equals the issued time of the full list you hold.
func (c *Client) TrustDelta(ctx context.Context, origin string) (*TrustList, error) {
	return c.trust(ctx, origin, origin+"/trust/list/delta")
}

func (c *Client) trust(ctx context.Context, origin, u string) (*TrustList, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", MediaTypeTrust)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust list: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	payload, kid, err := c.verifyJWS(ctx, strings.TrimSpace(string(raw)), origin+"/.well-known/opi-trust-keys.json", JWTTypeTrust)
	if err != nil {
		return nil, err
	}
	var l TrustList
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, fmt.Errorf("trust list: %w", err)
	}
	if l.Schema != SchemaTrust {
		return nil, fmt.Errorf("trust list: unsupported schema %q", l.Schema)
	}
	if exp, err := time.Parse(time.RFC3339, l.Expires); err == nil && time.Now().After(exp) {
		return nil, errors.New("trust list: expired; refetch")
	}
	l.KeyID = kid
	return &l, nil
}

// Trusted reports whether clientID is on the list, unrevoked, with an
// unexpired verification for category (empty category = any).
func (l *TrustList) Trusted(clientID, category string) bool {
	now := time.Now()
	for _, e := range l.Entries {
		if e.ClientID != clientID || e.Revoked {
			continue
		}
		for _, v := range e.Verifications {
			if category != "" && v.Category != category {
				continue
			}
			if v.Expires != "" {
				if exp, err := time.Parse(time.RFC3339, v.Expires); err == nil && now.After(exp) {
					continue
				}
			}
			return true
		}
	}
	return false
}
