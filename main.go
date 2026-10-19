// Command opi-example-client is the reference client for the Open Preference
// Initiative. It shows, in the smallest honest amount of code, how a service
// discovers a person's preference server, reads their card at each tier,
// verifies what it gets, and asks for consent when it needs more.
//
//	opi-example-client lookup acct:alice@openpreference.org   # public tier, verified
//	opi-example-client trust https://openpreference.org       # fetch + verify the trust list
//	opi-example-client serve                                  # web demo on http://localhost:8090
//
// The web demo needs OPI_CLIENT_ID and OPI_CLIENT_SECRET for the client and
// user tiers; register a client at https://openpreference.org/developer with
// redirect URI http://localhost:8090/callback.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openpreference/example-client/opi"
	"github.com/openpreference/example-client/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := &opi.Client{}
	var err error
	switch os.Args[1] {
	case "lookup":
		err = lookup(ctx, c, os.Args[2:])
	case "trust":
		err = trust(ctx, c, os.Args[2:])
	case "serve":
		err = web.Serve(web.Config{
			Addr:         env("OPI_LISTEN", "127.0.0.1:8090"),
			ClientID:     os.Getenv("OPI_CLIENT_ID"),
			ClientSecret: os.Getenv("OPI_CLIENT_SECRET"),
			RedirectURL:  env("OPI_REDIRECT_URL", "http://localhost:8090/callback"),
			DefaultHost:  env("OPI_DEFAULT_HOST", "openpreference.org"),
		})
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
usage:
  opi-example-client lookup <acct:handle@host | https://domain> [type ...]
  opi-example-client trust <https://origin>
  opi-example-client serve            # web demo; see OPI_* environment in README
`))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// lookup is the whole public-tier story in one function: discover, read,
// verify, print.
func lookup(ctx context.Context, c *opi.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("lookup needs a subject")
	}
	d, err := c.Discover(ctx, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("subject      %s\nserver       %s\ntiers        %s\npreferences  %s\nkeys         %s\n",
		d.Subject, d.Origin, strings.Join(d.Tiers, " "), d.PreferencesURL, d.KeysURL)

	var types []string
	for _, t := range args[1:] {
		if !strings.HasPrefix(t, "https://") {
			t = opi.TypeNamespace + t
		}
		types = append(types, t)
	}
	b, err := c.Read(ctx, d, opi.ReadOptions{Types: types})
	if err != nil {
		return err
	}
	fmt.Printf("\nverified with kid %s · issued by %s · expires %s\n\n", b.KeyID, b.Issuer, time.Unix(b.ExpiresAt, 0).UTC().Format(time.RFC3339))
	for _, e := range b.Preferences {
		var v any
		_ = json.Unmarshal(e.Value, &v)
		out, _ := json.Marshal(v)
		fmt.Printf("%-24s v%-7s %s\n", opi.ShortType(e.Type), e.Version, out)
	}
	return nil
}

// trust fetches the registry's signed list and shows who is on it.
func trust(ctx context.Context, c *opi.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("trust needs an origin, e.g. https://openpreference.org")
	}
	l, err := c.TrustList(ctx, strings.TrimRight(args[0], "/"))
	if err != nil {
		return err
	}
	fmt.Printf("registry  %s\nkind      %s\nissued    %s\nexpires   %s\nsigned by %s\nentries   %d\n", l.Registry, l.Kind, l.Issued, l.Expires, l.KeyID, len(l.Entries))
	for _, e := range l.Entries {
		var cats []string
		for _, v := range e.Verifications {
			cats = append(cats, opi.ShortCategory(v.Category))
		}
		state := "active"
		if e.Revoked {
			state = "REVOKED"
		}
		fmt.Printf("  %-40s %-30s %-8s %s\n", e.Entity, e.ClientID, state, strings.Join(cats, ","))
	}
	return nil
}
