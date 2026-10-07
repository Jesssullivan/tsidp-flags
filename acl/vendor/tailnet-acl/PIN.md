# Vendored tailnet-acl types

Snapshot of `types/ACL.dhall`, `types/JSON.dhall` and `types/Grant.dhall` from
`Jesssullivan/tailnet-acl` main, commit
`60e7a9d8851b31006f4bbe116523af710fe07f6f` (pull request 42). The previous pin
was `b642f33c494b28b7f95939649ac7fc4049519373` (pull request 37, typed grants).

`ACL.dhall` and `JSON.dhall` are byte copies (unchanged since b642f33).
`Grant.dhall` has exactly one local edit: the `RjGateway` capability name
string was replaced with the placeholder `example.org/cap/gateway` so this repo
carries no real names. Do not make other edits here; re-vendor instead.

What 60e7a9d adds over b642f33 (both in `Grant.dhall`):

- `Tsidp.taggedIdentity : Optional { subject, email, name }`, rendered as the
  `taggedIdentity` object of the `tailscale.com/cap/tsidp` capability. It lets
  a tagged node sign in through tsidp with a fixed identity.
- `Cap.ProbeUser { cap, flag, user }`, a probe capability that also carries a
  `user` field next to the flag.

Why vendored and not a URL import: the build must work offline and in CI with
no network and no import hash to maintain. If you prefer an import, use
`https://raw.githubusercontent.com/Jesssullivan/tailnet-acl/<sha>/types/Grant.dhall sha256:<hash>`
(freeze with `dhall freeze`).

Refresh: `git -C <tailnet-acl checkout> show <sha>:types/<File>.dhall > <File>.dhall`
for the three files, re-apply the one placeholder edit, update the sha above
and run `just acl-check`. CI runs `just acl-check` on every push and pull
request.
