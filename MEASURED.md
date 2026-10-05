# Measured evidence

Dated, sanitised observations from a live deployment. Names are placeholders:
tailnet `example.ts.net`, user `you@example.com`. Anything not yet measured is
marked pending. Re-measure and update the date when versions change.

Measured: 2026-10-05.

| # | Observation | Status |
|---|-------------|--------|
| 1 | A tagged device signing in through a patched tsidp `taggedIdentity` grant receives a stable numeric user-id subject (`sub`) through a Cloudflare Access OIDC identity provider. | Measured 2026-10-05 |
| 2 | tsidp OIDC discovery (`/.well-known/openid-configuration`) is reachable publicly over Tailscale Funnel. `/authorize` is not offered over Funnel. | Measured 2026-10-05 |
| 3 | The probe `GET /v1/tailnet` returns `{"tailnet": true}` to a tailnet caller, with an exact-origin CORS response and a Private Network Access preflight answer. | Measured 2026-10-05 |
| 4 | Chrome Local Network Access behaviour for the probe origin. | Pending: record Chrome version and date |

## 1. Tagged device subject

Stock tsidp issues claims for a person. A tagged device has no person, so the
unpatched flow has no stable subject for it. With a patched tsidp that honours
a `taggedIdentity` grant, a tagged device completing the login through an
Access OIDC IdP gets a numeric user-id `sub` that stays the same across logins.
The subject is a device identity, not a person. Treat it as the device tier in
`packages/flags` (see the `resolve` tests), never as proof of a human.

## 2. Public discovery over Funnel

Discovery and JWKS are fetched anonymously from the public Funnel hostname
(`https://idp.example.ts.net`). This is what lets an external OIDC consumer
such as Access validate tokens. Authorization stays tailnet-only, so an
interactive login needs a browser that is on the tailnet.

## 3. Probe and preflight

From a tailnet browser origin `https://app.example.org`:

- `OPTIONS /v1/tailnet` answers with `Access-Control-Allow-Origin` set to
  exactly that origin (no wildcard, `Vary: Origin`) and
  `Access-Control-Allow-Private-Network: true`.
- `GET /v1/tailnet` returns `{"tailnet": true}`.
- A request from an origin not on the allow list gets no CORS grant.

Covered offline by `probe/test_backend.py` (`just test-probe`).

## 4. Chrome Local Network Access (pending)

Chrome gates public pages that reach private or tailnet addresses behind Local
Network Access. Not yet measured. To record, per browser: version, date,
whether a permission prompt appears, and the result for member, non-member and
tailnet-off. Safari and Firefox results are also pending. Until measured, the
probe is a hint tier and the Kit origin remains the enforcement point.

| Browser | Version | Date | Prompt | Result |
|---------|---------|------|--------|--------|
| Chrome  | pending | pending | pending | pending |
| Safari  | pending | pending | pending | pending |
| Firefox | pending | pending | pending | pending |
