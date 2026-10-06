# tsidp with tagged identity (optional)

Upstream tsidp refuses a tagged node (a node with no user identity) at
`/authorize`, the token endpoint and `/userinfo`. `0001-tagged-identity.patch`
lets an operator **grant** supply the subject, email and name for a tagged
caller through the `taggedIdentity` field of the `tailscale.com/cap/tsidp`
capability. The vendored `Grant.dhall` renders that field (`Tsidp.taggedIdentity`).
The identity is never read from the caller. A tagged node without such a grant
is refused exactly as upstream refuses it. Drop the patch when upstream
supports tagged subjects.

Run it instead of the stock `idp` service:

```sh
docker compose --profile tagged-identity config -q   # validate
docker compose --profile tagged-identity up --build idp-tagged
```

`idp-tagged` keeps its state in its own volume (`idp-tagged-state`), so it
registers as a separate node. Run one of `idp` and `idp-tagged` at a time, or
give them different `IDP_HOSTNAME` values.

## Pin

- Upstream: `github.com/tailscale/tsidp` at
  `8fa860f333d9b0ed7eee66e0c7c08531f743fd16`. The Dockerfile checks that the
  fetched HEAD equals the pin.
- Build: `golang:1.26.6-alpine` (go.mod at the pin says `go 1.26.6`).
  Runtime: `alpine:3.22`. Both are pinned by digest.
- The patch applies cleanly at the pin (`git apply --check`), and the image
  build fails if it does not.

The patch is a sanitised copy of the production overlay. Its only edits are in
the new test file (`server/tagged_identity_test.go`): placeholder node, subject
and claim names (`laptop.example.ts.net.`, `device-operator`, `flag_member`).
The code hunks are byte-identical to the production overlay.

## Licensing

tsidp is Copyright (c) 2025 Tailscale Inc & AUTHORS and is licensed under the
BSD 3-Clause License. The patch modifies tsidp source, so it is a derivative of
BSD 3-Clause code and is distributed under the same BSD 3-Clause terms,
including upstream's copyright notice and disclaimer. This repository's MIT
license covers this repository's own files and does not relicense tsidp or the
patch. The Dockerfile fetches upstream source at build time. No tsidp source
is vendored here beyond the patch. An image built from it carries the tsidp
binary, so redistributing that image must carry the BSD 3-Clause notice.
