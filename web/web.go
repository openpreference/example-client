// Package web is the browser-facing demo: three pages, no JavaScript, no
// framework, so the protocol steps stay visible. State between the consent
// redirect and the callback lives in an in-memory map keyed by the OAuth
// state value; a real service would keep it in the user's session.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openpreference/example-client/opi"
)

//go:embed templates/*.html
var templates embed.FS

// Config is everything the demo needs. ClientID and ClientSecret are
// optional: without them only the public-tier page works.
type Config struct {
	Addr         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	DefaultHost  string
}

type server struct {
	cfg  Config
	opi  *opi.Client
	tmpl *template.Template

	mu      sync.Mutex
	pending map[string]pendingAuth // by state
}

type pendingAuth struct {
	pkce     *opi.PKCE
	disc     *opi.Discovery
	meta     *opi.AuthMetadata
	types    []string
	created  time.Time
	purpose  string
	subject  string
	retained string
}

// Serve runs the demo until the process exits.
func Serve(cfg Config) error {
	t, err := template.New("").Funcs(template.FuncMap{
		"short":    opi.ShortType,
		"shortCat": opi.ShortCategory,
		"json": func(v json.RawMessage) string {
			var x any
			if json.Unmarshal(v, &x) != nil {
				return string(v)
			}
			b, _ := json.MarshalIndent(x, "", "  ")
			return string(b)
		},
		"join": strings.Join,
		"unix": func(n int64) string { return time.Unix(n, 0).UTC().Format(time.RFC3339) },
	}).ParseFS(templates, "templates/*.html")
	if err != nil {
		return err
	}
	s := &server{cfg: cfg, opi: &opi.Client{}, tmpl: t, pending: map[string]pendingAuth{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /public", s.public)
	mux.HandleFunc("GET /client", s.client)
	mux.HandleFunc("GET /ask", s.ask)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("GET /trust", s.trust)
	log.Printf("opi example client on http://%s (default host %s, client tier %s)", cfg.Addr, cfg.DefaultHost,
		map[bool]string{true: "configured", false: "not configured"}[cfg.ClientID != ""])
	return http.ListenAndServe(cfg.Addr, mux)
}

type page struct {
	Title       string
	Cfg         Config
	Subject     string
	Types       []string
	Disc        *opi.Discovery
	Bundle      *opi.Bundle
	Trust       *opi.TrustList
	Tier        string
	Error       string
	Step        []string // protocol steps performed, for the explainer
	AllTypes    []string
	HasClient   bool
	Purpose     string
	Retention   string
	AuthorizeTo string
}

func (s *server) render(w http.ResponseWriter, name string, p page) {
	p.Cfg = s.cfg
	p.HasClient = s.cfg.ClientID != "" && s.cfg.ClientSecret != ""
	if p.AllTypes == nil {
		p.AllTypes = []string{"locale", "units", "accessibility", "dietary", "communications", "content", "marketing", "health/pharmacy"}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// form-action also governs the redirect that follows a form submit, and
	// the consent flow answers a form with a 303 to the person's server.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:")
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	s.render(w, "home.html", page{Title: "OPI example client"})
}

func subjectFrom(r *http.Request, defaultHost string) string {
	sub := strings.TrimSpace(r.URL.Query().Get("subject"))
	if sub == "" {
		return ""
	}
	if !strings.Contains(sub, "@") && !strings.HasPrefix(sub, "https://") {
		sub = sub + "@" + defaultHost // bare handle: assume the default server
	}
	if !strings.HasPrefix(sub, "acct:") && !strings.HasPrefix(sub, "https://") {
		sub = "acct:" + sub
	}
	return sub
}

func typesFrom(r *http.Request) []string {
	var out []string
	for _, t := range r.URL.Query()["type"] {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, opi.TypeNamespace+t)
		}
	}
	return out
}

// public: discover + read with no credentials (OPI-PD §7.1).
func (s *server) public(w http.ResponseWriter, r *http.Request) {
	p := page{Title: "Public tier", Tier: "public", Subject: subjectFrom(r, s.cfg.DefaultHost), Types: r.URL.Query()["type"]}
	if p.Subject == "" {
		s.render(w, "read.html", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	d, err := s.opi.Discover(ctx, p.Subject)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "read.html", p)
		return
	}
	p.Disc = d
	p.Step = append(p.Step, "WebFinger at "+d.Origin+" resolved the subject and found the preferences, keys and auth links.")
	b, err := s.opi.Read(ctx, d, opi.ReadOptions{Types: typesFrom(r)})
	if err != nil {
		p.Error = err.Error()
		if errors.Is(err, opi.ErrNotFound) {
			p.Error = "404. Either nobody has this address or nothing on the card is set to Everyone. The server does not say which."
		}
		s.render(w, "read.html", p)
		return
	}
	p.Bundle = b
	p.Step = append(p.Step, "Fetched the signed bundle with no token (public tier).", "Verified the JWS: typ opi-eps+jwt, ES256, kid "+b.KeyID+" found in the key set, signature valid, not expired.")
	s.render(w, "read.html", p)
}

// client: client-credentials token, then read (OPI-PD §6, §7.2).
func (s *server) client(w http.ResponseWriter, r *http.Request) {
	p := page{Title: "Trusted app (client tier)", Tier: "client", Subject: subjectFrom(r, s.cfg.DefaultHost), Types: r.URL.Query()["type"]}
	if p.Subject == "" || s.cfg.ClientID == "" {
		s.render(w, "read.html", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	d, err := s.opi.Discover(ctx, p.Subject)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "read.html", p)
		return
	}
	p.Disc = d
	meta, err := s.opi.AuthMeta(ctx, d)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "read.html", p)
		return
	}
	types := typesFrom(r)
	if len(types) == 0 {
		types = meta.ScopesSupported
	}
	tok, err := s.opi.ClientCredentials(ctx, meta, s.cfg.ClientID, s.cfg.ClientSecret, types)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "read.html", p)
		return
	}
	p.Step = append(p.Step, "Discovered the server and its OAuth metadata.", "client_credentials grant at "+meta.TokenEndpoint+" with scope = the preference type URIs; granted scope: "+tok.Scope)
	b, err := s.opi.Read(ctx, d, opi.ReadOptions{Types: types, Bearer: tok.AccessToken})
	if err != nil {
		p.Error = err.Error()
		if errors.Is(err, opi.ErrNotFound) {
			p.Error = "404. Nothing on this card is readable by this client: the person has not set those types to Trusted apps, or this client's category is not one they allow. The server does not say which."
		}
		s.render(w, "read.html", p)
		return
	}
	p.Bundle = b
	p.Step = append(p.Step, "Read with the bearer token. This read is now in the person's Activity log with this client's registered purpose.", "Verified the JWS exactly as for the public tier.")
	s.render(w, "read.html", p)
}

// ask: start the user-tier consent flow (OPI-PD §8).
func (s *server) ask(w http.ResponseWriter, r *http.Request) {
	p := page{Title: "Ask the person (user tier)", Tier: "user", Subject: subjectFrom(r, s.cfg.DefaultHost), Types: r.URL.Query()["type"],
		Purpose: r.URL.Query().Get("purpose"), Retention: r.URL.Query().Get("retention")}
	if p.Subject == "" || s.cfg.ClientID == "" || r.URL.Query().Get("go") == "" {
		if p.Purpose == "" {
			p.Purpose = "Show how a consent request looks."
		}
		if p.Retention == "" {
			p.Retention = "PT1H"
		}
		s.render(w, "ask.html", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	d, err := s.opi.Discover(ctx, p.Subject)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "ask.html", p)
		return
	}
	meta, err := s.opi.AuthMeta(ctx, d)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "ask.html", p)
		return
	}
	types := typesFrom(r)
	if len(types) == 0 {
		p.Error = "pick at least one preference type to ask for"
		s.render(w, "ask.html", p)
		return
	}
	pk, err := opi.NewPKCE()
	if err != nil {
		p.Error = err.Error()
		s.render(w, "ask.html", p)
		return
	}
	u, err := opi.AuthorizeURL(meta, s.cfg.ClientID, s.cfg.RedirectURL, pk, []opi.AuthorizationDetail{{PreferenceTypes: types, Purpose: p.Purpose, Retention: p.Retention}})
	if err != nil {
		p.Error = err.Error()
		s.render(w, "ask.html", p)
		return
	}
	s.mu.Lock()
	for k, v := range s.pending {
		if time.Since(v.created) > 10*time.Minute {
			delete(s.pending, k)
		}
	}
	s.pending[pk.State] = pendingAuth{pkce: pk, disc: d, meta: meta, types: types, created: time.Now(), purpose: p.Purpose, subject: p.Subject, retained: p.Retention}
	s.mu.Unlock()
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// callback: the person said yes or no; exchange the code and read.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := page{Title: "Ask the person (user tier)", Tier: "user"}
	s.mu.Lock()
	pa, ok := s.pending[q.Get("state")]
	delete(s.pending, q.Get("state"))
	s.mu.Unlock()
	if !ok {
		p.Error = "unknown or expired state; start again"
		s.render(w, "read.html", p)
		return
	}
	p.Subject, p.Disc, p.Purpose, p.Retention = pa.subject, pa.disc, pa.purpose, pa.retained
	for _, t := range pa.types {
		p.Types = append(p.Types, opi.ShortType(t))
	}
	if e := q.Get("error"); e != "" {
		p.Error = "The person declined: " + e + " " + q.Get("error_description")
		p.Step = append(p.Step, "Sent the person to "+pa.meta.AuthorizationEndpoint+" with PKCE and an authorization_details object naming the types, purpose and retention.", "They came back without a code.")
		s.render(w, "read.html", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := s.opi.Exchange(ctx, pa.meta, s.cfg.ClientID, s.cfg.ClientSecret, s.cfg.RedirectURL, q.Get("code"), pa.pkce)
	if err != nil {
		p.Error = err.Error()
		s.render(w, "read.html", p)
		return
	}
	p.Step = append(p.Step, "Sent the person to "+pa.meta.AuthorizationEndpoint+" with PKCE and an authorization_details object naming the types, purpose and retention.", "They approved; exchanged the code (with the PKCE verifier) for a user-tier token.")
	b, err := s.opi.Read(ctx, pa.disc, opi.ReadOptions{Types: pa.types, Bearer: tok.AccessToken})
	if err != nil {
		p.Error = err.Error()
		if errors.Is(err, opi.ErrNotFound) {
			p.Error = "404: they approved, but unticked every type on the consent screen, so nothing is readable."
		}
		s.render(w, "read.html", p)
		return
	}
	p.Bundle = b
	p.Step = append(p.Step, "Read with the user-tier token: only the types they left ticked come back. The grant shows under their Connected apps until they revoke it.", "Verified the JWS exactly as for the public tier.")
	s.render(w, "read.html", p)
}

// trust: fetch and verify the registry's list.
func (s *server) trust(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimRight(strings.TrimSpace(r.URL.Query().Get("origin")), "/")
	if origin == "" {
		origin = "https://" + s.cfg.DefaultHost
	}
	p := page{Title: "Trust registry", Subject: origin}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	l, err := s.opi.TrustList(ctx, origin)
	if err != nil {
		p.Error = err.Error()
		if errors.Is(err, opi.ErrNotFound) {
			p.Error = "This registry has not published a list yet."
		}
	} else {
		p.Trust = l
		p.Step = append(p.Step, "Fetched "+origin+"/trust/list (application/jose).", "Verified the JWS: typ opi-trust+jwt, kid "+l.KeyID+" from the registry's trust key set, not expired.", fmt.Sprintf("%d entries. A client is trusted for a category only while it is listed, unrevoked and its verification has not expired.", len(l.Entries)))
	}
	s.render(w, "trust.html", p)
}
