# Vendored tailnet-acl types

Snapshot of `types/ACL.dhall`, `types/JSON.dhall` and `types/Grant.dhall` from
`Jesssullivan/tailnet-acl`, pull request 37 (typed grants), commit
`b642f33c494b28b7f95939649ac7fc4049519373`. `ACL.dhall` and `JSON.dhall` are
byte copies. `Grant.dhall` has exactly one local edit: the `RjGateway`
capability name string was replaced with the placeholder
`example.org/cap/gateway` so this repo carries no real names. Do not make other
edits here; re-vendor instead.

Why vendored and not a URL import: the build must work offline and in CI with
no network and no import hash to maintain. When PR 37 merges, re-pin to the
merge commit and, if you prefer, replace these with a Dhall import such as
`https://raw.githubusercontent.com/Jesssullivan/tailnet-acl/<sha>/types/Grant.dhall sha256:<hash>`
(freeze with `dhall freeze`).

Refresh: `git -C <tailnet-acl checkout> show <sha>:types/<File>.dhall > <File>.dhall`
for the three files, then update the sha above and run `just acl-check`.
