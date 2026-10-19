# OPI example client

The reference client for the [Open Preference Initiative](https://openpreference.org).
It shows, in the smallest honest amount of Go, how a service:

1. **discovers** a person's preference server from their address with WebFinger,
2. **reads** their card at the public tier, the client tier or the user tier,
3. **verifies** every bundle against the server's published keys, and
4. **checks the trust registry** before trusting another client.

Everything is `net/http` plus [go-jose](https://github.com/go-jose/go-jose)
for signatures, so it transliterates to any language. The `opi` package is
the reusable part; `main.go` is a CLI; `web/` is a four-page demo with no
JavaScript so the protocol steps stay visible.

## Run

```bash
go run . lookup acct:admin@openpreference.org          # public tier, verified
go run . lookup admin@openpreference.org locale units  # narrow to types
go run . trust https://openpreference.org              # the signed trust list
go run . serve                                         # http://localhost:8090
```

The public page and the trust page work with no setup. For the client tier
and the consent flow, register a client at
<https://openpreference.org/developer> with redirect URI
`http://localhost:8090/callback`, then:

```bash
export OPI_CLIENT_ID=opi_client_…
export OPI_CLIENT_SECRET=opi_sec_…
go run . serve
```

| Variable | Default | Meaning |
|---|---|---|
| `OPI_LISTEN` | `127.0.0.1:8090` | demo listen address |
| `OPI_DEFAULT_HOST` | `openpreference.org` | server assumed for bare handles |
| `OPI_REDIRECT_URL` | `http://localhost:8090/callback` | must match the registered client |
| `OPI_CLIENT_ID`, `OPI_CLIENT_SECRET` | unset | enables the client and user tiers |

## What each page does, mapped to the specs

| Page | Spec | Steps |
|---|---|---|
| Public | OPI-PD §4, §7.1; OPI-EPS §9 | WebFinger → `rel/preferences` href and `rel/keys` → GET with `Accept: application/opi-eps+jwt` → verify JWS (`typ: opi-eps+jwt`, ES256, `kid` in key set, `exp`/`iat`) |
| Trusted app | OPI-PD §6, §7.2 | `client_credentials` with `scope` = type URIs → bearer read → same verification. Only works for clients on the registry, for categories the person allows; reads land in their Activity |
| Ask the person | OPI-PD §8 | authorization code + PKCE S256, `authorization_details` of type `…/pd/0.1/authorization_details` with `preference_types`, `purpose`, `retention` → consent screen on *their* server → code exchange → bearer read of only what they ticked |
| Trust list | OPI-TRUST §4 | GET `/trust/list` (`application/jose`) → verify against `/.well-known/opi-trust-keys.json` (`typ: opi-trust+jwt`) → `Trusted(clientID, category)` |

Two behaviours worth copying:

- **404 means two things on purpose.** An unknown address and an address
  with nothing readable at your tier return the same constant 404, so a
  client can't enumerate users or infer what someone keeps private
  (OPI-PD §10). `opi.ErrNotFound` carries that wording.
- **Key rotation needs no restart.** The key set is cached per URL and
  refetched when a bundle names a `kid` the cache lacks.

## Use the package

```go
c := &opi.Client{}
d, err := c.Discover(ctx, "acct:alice@openpreference.org")
b, err := c.Read(ctx, d, opi.ReadOptions{Types: []string{opi.TypeNamespace + "locale"}})
for _, e := range b.Preferences { fmt.Println(opi.ShortType(e.Type), string(e.Value)) }
```

## Test

```bash
go test ./...
```

The tests run a tiny in-process OPI server with freshly generated keys, so
they exercise discovery, signature verification, `typ` and expiry rejection,
trust-list verification and the PKCE request without touching the network.

## Licence

Apache-2.0. The specifications it implements are CC-BY-4.0 at
<https://github.com/openpreference/opi>.
