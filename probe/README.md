# flag-probe

`backend.py` answers one question: "is this browser in the flag-members
group?" It is served on the tailnet only, by `tailscale serve --https=443` on a
dedicated node tagged `tag:flag-probe`. It never uses Funnel. Python 3 standard
library only, bound to loopback. The answer is a **hint**: gate nothing
sensitive on it.

## Two ways to say yes

1. **User path.** Serve sets `Tailscale-User-Login` and, with
   `--accept-app-caps`, `Tailscale-App-Capabilities`. Yes needs exactly one
   login and exactly one capability header that grants the probe capability
   (`PROBE_CAPABILITY`, default `example.org/cap/flag-probe`).
2. **Device path.** A tagged device (a laptop enrolled under a tag, for
   example) has no user, so Serve sends no login header. When the login
   header is absent, the backend:
   - takes the caller address from the **last** `X-Forwarded-For` entry, and
     only when the TCP peer is loopback (Serve is the one local client) and the
     address is inside `100.64.0.0/10` or `fd7a:115c:a1e0::/48`;
   - asks the probe node's own tailscaled for `whois --json <addr>` (fails
     closed on any error);
   - says yes only if that node is tagged and its CapMap grants the probe
     capability with `{"<PROBE_FLAG>": true, "user": "<non-empty>"}`.

   That grant is what tailnet-acl's `Cap.ProbeUser { cap, flag, user }`
   renders (vendored in `acl/vendor/tailnet-acl/Grant.dhall`). The identity is
   the one policy declares for the device; nothing in the request supplies it.
   The path proves a device, not a person. The `user` value is checked and then
   discarded. It is never returned or logged.

If the login header is present, only the user path runs.

## Node guard and the guard timer

Every yes also needs the node guard to pass: the node is `Running`, carries
exactly its one tag, and has no `AllowFunnel` anywhere in its serve config.
The backend re-checks the guard on demand, at most every `GUARD_TTL` (10)
seconds, so Funnel switched on after start turns every answer into no within
that window. The guard logs only when its state changes.

A deployment should also run the guard from a timer that resets the node's
serve config. The production pattern is a oneshot unit plus a timer every
minute (`OnUnitActiveSec=1min`) that runs `backend.py --guard-once` and, when
the result is a reason to reset, clears serve and re-applies it. The backend
answers no in the meantime anyway. The timer bounds how long a Funnelled or
mis-tagged node stays reachable.

`--guard-once` exit codes:

| code | state |
| --- | --- |
| 0 | ok |
| 10 | not running |
| 11 | wrong tags |
| 12 | Funnel |
| 13 | error (including missing `--tailscale`/`--socket`) |

## Exit 78

A refused start (bad flags, a non-loopback `--bind`, a wildcard or `null`
`--allowed-origin`, a malformed capability, missing guard flags) exits **78**
(`EX_CONFIG`, sysexits.h). Restarting will not fix configuration, so a
systemd unit should set `RestartPreventExitStatus=78` next to
`Restart=on-failure`. An `OSError` at start, such as the port being in use,
exits 1 and stays restartable.

The same convention guards the IdP: a tsidp start guard (`ExecStartPre`) exits
78 when the node has neither enrolled state nor an auth key file, rather than
letting tsnet print an interactive login URL. systemd retries an
`ExecStartPre` refusal until `StartLimitBurst` trips, because
`RestartPreventExitStatus` applies only to the main process.

## Routes

| route | answer |
| --- | --- |
| `GET`/`HEAD /probe.svg` | yes: 200 1x1 SVG; no: 404, no body |
| `GET /v1/tailnet` | 200 `{"tailnet": true\|false}` |
| `GET /v1/surface` | 200 flag manifest, `basis` trust `hint` |
| `OPTIONS /v1/tailnet`, `/v1/surface` | 204; CORS and Private Network Access headers only for the exact allowed origin |
| `OPTIONS /probe.svg` | 204 only for a PNA preflight from the exact origin, else 404 |

Every response is `Cache-Control: no-store` and varies on `Origin`, the
Tailscale identity headers and `X-Forwarded-For`. The login, the device user,
the capabilities and the source address never reach a body, a header or the
log.

## Tests

`python3 -m unittest discover -s probe -p 'test_*.py'` (`just test-probe`).
