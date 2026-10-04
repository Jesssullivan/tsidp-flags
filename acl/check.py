#!/usr/bin/env python3
"""Structural checks on the rendered example policy (generated/policy.json)."""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "generated/policy.json")
policy = json.loads(path.read_text())

required = {"groups", "tagOwners", "acls", "grants", "ssh", "nodeAttrs", "autoApprovers", "hosts"}
missing = required - set(policy)
assert not missing, f"missing sections: {sorted(missing)}"

assert policy["groups"].get("group:flag-members"), "group:flag-members must exist and be non-empty"
for tag in ("tag:flag-probe", "tag:flag-idp"):
    assert policy["tagOwners"].get(tag) == ["autogroup:admin"], f"{tag} must be admin-owned only"

# Funnel only on the idp tag, never on the probe.
funnel = [t for row in policy["nodeAttrs"] if "funnel" in row["attr"] for t in row["target"]]
assert funnel == ["tag:flag-idp"], f"funnel targets must be exactly tag:flag-idp, got {funnel}"

for index, grant in enumerate(policy["grants"]):
    assert grant.get("src") and grant.get("dst"), f"grant {index} needs src and dst"
    assert "ip" in grant or "app" in grant, f"grant {index} needs ip or app"
    assert None not in grant.values(), f"grant {index} has a null field"

caps = {name for g in policy["grants"] for name in g.get("app", {})}
assert "example.org/cap/flag-probe" in caps, "probe capability grant missing"
assert "tailscale.com/cap/tsidp" in caps, "tsidp capability grant missing"

# Placeholders only.
text = path.read_text()
assert "example" in text and ".ts.net" not in text.replace("example.ts.net", ""), "unexpected tailnet name"

print(f"acl-check ok: {len(policy['grants'])} grants, {len(policy['groups'])} groups")
