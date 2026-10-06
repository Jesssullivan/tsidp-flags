# Flag manifest contracts

Two manifest shapes exist. One is implemented here, and the other runs in a
production deployment of the same probe pattern. Which one becomes the shared
contract is an **open operator decision**. Until it is made, this repo
implements Surface v1 only, and the items shape below is **PROPOSED**. It is
documentation, not code.

## Surface v1 (implemented)

Served by the probe's `GET /v1/surface` and the kit's `/api/surface`, and
parsed by `parseSurface` in `@tsidp-flags/flags`.

```json
{
  "version": 1,
  "flags": { "member": true },
  "basis": [{ "flag": "member", "source": "tailnet-probe", "trust": "hint" }],
  "status": "settled"
}
```

- `flags`: flag name to boolean. A consumer renders gated markup only for a
  `settled` manifest whose flag is `true`.
- `basis`: which source granted each true flag, at its effective (capped) trust.
- `status`: `pending`, `settled` or `failed`. Anything other than `settled`
  renders nothing gated.
- `parseSurface` returns `null` for anything malformed. `null` renders nothing.

It answers "may this visitor see gated UI?" and leaves what to show to the
page.

## Items (PROPOSED, not implemented)

> **Status: proposed.** Do not build against this until the operator rules
> on Surface v1 vs items. Tracked as row TS8 in the TIN-3692 scaffold
> convergence plan.

The production probe answers `/v1/surface` with the links themselves:

```json
{
  "items": [
    { "slot": "header-join", "kind": "join", "label": "Join", "href": "https://site.example.org/join" },
    { "slot": "footer-sign-in", "kind": "sign-in", "label": "Member sign in", "href": "https://members.example.org/login" }
  ]
}
```

- A yes answer is a fixed, ordered list of `{slot, kind, label, href}`
  objects. The list mirrors the member app's own public-surface builder: same
  slots, kinds, labels and order. A slot may hold more than one item.
- A no answer is `{"items": []}`, so **no link ever appears in a no**.
- The list can depend on server-side state. For example, an `apply` item
  points at the application form only while intake is open, and otherwise at
  the public explanation page.
- There is no `status` and no `basis`. The trust tier stays implicit: it is a
  probe answer, so it is a hint.

### Proposed `parseItems`

If the items shape is adopted, `@tsidp-flags/flags` would gain a parser with
the same fail-closed rules as `parseSurface`:

- Input must be an object with an `items` array. Anything else gives `null`.
- Every item must have string `slot`, `kind`, `label` and `href`, and `href`
  must parse as an absolute `https:` URL. One bad item rejects the whole
  manifest (`null`); it does not drop just that item.
- `{"items": []}` parses to an empty list, and a consumer renders it as
  **closed**, exactly like a `false` flag.
- An unknown `kind` is kept, but a consumer renders only the kinds it knows.
- vitest cases would include `{items: []}` closed, a missing `items`, a
  non-https `href`, a non-string field, and order preserved.

### What a decision needs to settle

1. **One shape or both.** Surface v1 keeps the presentation in the page. Items
   moves it to the server, which changes them in one place (for example, an
   applications-open switch) but makes the probe carry real URLs.
2. **Trust.** Items has no `basis`, so a consumer cannot tell a hint from a
   verified answer. If items comes back from a verified endpoint as well, it
   needs a trust field.
3. **Versioning.** Items has no `version`. A `version: 2` envelope
   (`{version: 2, items, status}`) would let one parser accept both.

Sources: the production probe's `surface_manifest()` and the member site's
manifest consumer. Both were read for shape only, and this repo copies no
names or URLs from them.
