#!/usr/bin/env python3
"""Render acl/policy.dhall to generated/policy.json (tab indent, trailing newline)."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT.parent / "generated" / "policy.json"

try:
    done = subprocess.run(
        ["dhall-to-json", "--file", str(ROOT / "policy.dhall")],
        capture_output=True, text=True, check=True, cwd=str(ROOT),
    )
except (OSError, subprocess.CalledProcessError) as exc:
    detail = getattr(exc, "stderr", "") or str(exc)
    print(f"dhall-to-json failed: {detail}", file=sys.stderr)
    sys.exit(1)

policy = json.loads(done.stdout)
order = ["groups", "tagOwners", "acls", "grants", "ssh", "nodeAttrs", "autoApprovers", "hosts"]
policy = {k: policy[k] for k in order if k in policy} | {k: v for k, v in policy.items() if k not in order}
for i, grant in enumerate(policy["grants"]):
    policy["grants"][i] = {k: grant[k] for k in ("src", "dst", "app", "ip") if k in grant}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(policy, indent="\t") + "\n")
print(f"wrote {OUT}", file=sys.stderr)
