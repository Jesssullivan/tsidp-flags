#!/usr/bin/env python3
"""flag-probe backend: answers "is this browser in the flag-members group?" and nothing else.

Sanitised port of a production tailnet probe. Served on the tailnet only, by
`tailscale serve --https=443` on a dedicated node tagged tag:flag-probe. Never
Funnel.

Who gets a yes is decided by tailnet policy, not by this file. The ACL grants
group:flag-members two things on the probe node: tcp:443 (so only member
devices can resolve and reach it) and the app capability (default
example.org/cap/flag-probe), which Serve forwards in Tailscale-App-Capabilities
when the serve helper passes --accept-app-caps. Adding a person to the group is
the only way to widen the yes set.

Decision (server side only):
  1. Serve strips any client-supplied Tailscale-User-* and
     Tailscale-App-Capabilities header and sets its own. Tagged source devices
     get no user header.
  2. Yes needs exactly one non-empty Tailscale-User-Login AND exactly one
     Tailscale-App-Capabilities header whose JSON names the probe capability
     with a non-empty grant list. Anything else is no. That also covers
     anything that reached the loopback port without passing through Serve.
  3. Yes also needs the node guard to pass: the node is Running, carries
     exactly its one tag, and has no Funnel anywhere in its serve config. The
     guard is re-checked at most every GUARD_TTL seconds, on demand.
  4. The login, display name, capabilities and source address never reach the
     response body, the response headers or the log. The log carries the
     route, the status, a per-day request counter and guard state changes.

Trust: the answer is a HINT. A public page that fetches this from a member's
browser learns "this browser can reach the probe", which a page cannot verify
server side. Gate nothing sensitive on it.

Routes (anything else is 404 with no body):
  GET|HEAD /probe.svg    yes: 200 image/svg+xml 1x1   no: 404, no body
  GET      /v1/tailnet   200 {"tailnet": true|false}
  GET      /v1/surface   200 flag manifest (see packages/flags Surface):
                         {"version":1,"flags":{"member":bool},"basis":[...],
                          "status":"settled"}
  OPTIONS  /v1/tailnet, /v1/surface   204 (CORS and Private Network Access
                         headers only for the exact allowed origin)
  OPTIONS  /probe.svg    204 only for a Private Network Access preflight from
                         the exact allowed origin, else 404

`--guard-once` runs the node guard a single time and exits with its code (0
ok, 10 not running, 11 wrong tags, 12 Funnel, 13 error).

Python 3 standard library only. Binds loopback only. Every setting can come
from the environment (ALLOWED_ORIGIN, PROBE_CAPABILITY, PROBE_TAG,
PROBE_PORT, PROBE_FLAG, TAILSCALE_BIN, TAILSCALE_SOCKET).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

LOGIN_HEADER = "Tailscale-User-Login"
APP_CAPS_HEADER = "Tailscale-App-Capabilities"
DEFAULT_ORIGIN = "https://app.example.org"
DEFAULT_TAG = "tag:flag-probe"
DEFAULT_CAPABILITY = "example.org/cap/flag-probe"
DEFAULT_FLAG = "member"
PROBE_ROUTE = "/probe.svg"
JSON_ROUTE = "/v1/tailnet"
SURFACE_ROUTE = "/v1/surface"
KNOWN_ROUTES = (PROBE_ROUTE, JSON_ROUTE, SURFACE_ROUTE)
GUARD_TTL = 10.0

PIXEL = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1" '
    b'viewBox="0 0 1 1"/>'
)

COMMON_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Vary", "Origin, Tailscale-User-Login, Tailscale-App-Capabilities"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)

GUARD_OK = "ok"
GUARD_NOT_RUNNING = "not-running"
GUARD_WRONG_TAGS = "wrong-tags"
GUARD_FUNNEL = "funnel"
GUARD_ERROR = "error"
GUARD_EXIT = {
    GUARD_OK: 0,
    GUARD_NOT_RUNNING: 10,
    GUARD_WRONG_TAGS: 11,
    GUARD_FUNNEL: 12,
    GUARD_ERROR: 13,
}


def decide(login_values: Iterable[str], capability_values: Iterable[str], capability: str) -> bool:
    """True only for one Serve login plus one capability header granting `capability`."""
    logins = [v.strip() for v in login_values]
    if len(logins) != 1 or not logins[0]:
        return False
    caps = list(capability_values)
    if len(caps) != 1:
        return False
    try:
        granted = json.loads(caps[0])
    except ValueError:
        return False
    if not isinstance(granted, dict):
        return False
    rules = granted.get(capability)
    return isinstance(rules, list) and len(rules) > 0


def surface(yes: bool, flag: str = DEFAULT_FLAG) -> dict:
    """The /v1/surface manifest. The probe is a browser-reachable hint, never verified."""
    return {
        "version": 1,
        "flags": {flag: yes},
        "basis": [{"flag": flag, "source": "tailnet-probe", "trust": "hint"}] if yes else [],
        "status": "settled",
    }


def _has_funnel(node: object) -> bool:
    """True if any AllowFunnel map anywhere in a serve config has a true value."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "AllowFunnel" and isinstance(value, dict) and any(value.values()):
                return True
            if _has_funnel(value):
                return True
    elif isinstance(node, list):
        return any(_has_funnel(item) for item in node)
    return False


def node_state(run: Callable[[Sequence[str]], str], tag: str) -> str:
    """Node guard: Running, exactly one tag, no Funnel anywhere. Fails closed."""
    try:
        status = json.loads(run(["status", "--json", "--peers=false"]))
        if not isinstance(status, dict):
            return GUARD_ERROR
        if status.get("BackendState") != "Running":
            return GUARD_NOT_RUNNING
        serve_text = run(["serve", "status", "--json"]).strip()
        serve = json.loads(serve_text) if serve_text else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return GUARD_ERROR
    if not isinstance(serve, (dict, list)):
        return GUARD_ERROR
    if _has_funnel(serve):
        return GUARD_FUNNEL
    me = status.get("Self")
    if not isinstance(me, dict) or me.get("Tags") != [tag]:
        return GUARD_WRONG_TAGS
    return GUARD_OK


def make_runner(tailscale: str, socket: str, timeout: float = 5.0) -> Callable[[Sequence[str]], str]:
    def run(args: Sequence[str]) -> str:
        done = subprocess.run(  # noqa: S603 - fixed binary, no shell, no request input
            [tailscale, f"--socket={socket}", *args],
            capture_output=True, text=True, timeout=timeout, check=True,
        )
        return done.stdout
    return run


class NodeGuard:
    """Caches node_state for `ttl` seconds; logs only state changes."""

    def __init__(self, check: Callable[[], str], log: Callable[[str], None],
                 ttl: float = GUARD_TTL, clock: Callable[[], float] = time.monotonic) -> None:
        self._check = check
        self._log = log
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._state: str | None = None
        self._at = 0.0

    def ok(self) -> bool:
        with self._lock:
            now = self._clock()
            if self._state is None or now - self._at >= self._ttl:
                state = self._check()
                if state != self._state:
                    note = "" if state == GUARD_OK else " (answering no)"
                    self._log(f"flag-probe guard state={state}{note}")
                self._state, self._at = state, now
            return self._state == GUARD_OK


class DailyCounter:
    """Requests per UTC day. Holds a date and an integer, never an identity."""

    def __init__(self, today: Callable[[], datetime.date]) -> None:
        self._today = today
        self._lock = threading.Lock()
        self._day: datetime.date | None = None
        self._count = 0

    def tick(self) -> tuple:
        with self._lock:
            day = self._today()
            if day != self._day:
                self._day, self._count = day, 0
            self._count += 1
            return day.isoformat(), self._count


def make_handler(
    allowed_origin: str,
    guard_ok: Callable[[], bool],
    log: Callable[[str], None],
    capability: str = DEFAULT_CAPABILITY,
    flag: str = DEFAULT_FLAG,
    today: Callable[[], datetime.date] = lambda: datetime.datetime.now(datetime.timezone.utc).date(),
):
    counter = DailyCounter(today)

    class Handler(BaseHTTPRequestHandler):
        server_version = "flag-probe"
        sys_version = ""

        def log_message(self, format: str, *args) -> None:  # noqa: A002, ARG002
            return  # the stdlib line carries the client address; never emit it

        def _record(self, route: str, status: int) -> None:
            day, count = counter.tick()
            log(f"flag-probe route={route} status={status} day={day} n={count}")

        def _send(self, status: int, route: str, body: bytes = b"",
                  content_type: str | None = None,
                  extra: Mapping[str, str] = (), head: bool = False) -> None:
            self.send_response_only(status)
            self.send_header("Server", self.server_version)
            self.send_header("Date", self.date_time_string())
            for name, value in COMMON_HEADERS:
                self.send_header(name, value)
            for name, value in dict(extra).items():
                self.send_header(name, value)
            if content_type:
                self.send_header("Content-Type", content_type)
            if status != 204:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body and not head:
                self.wfile.write(body)
            self._record(route, status)

        def send_error(self, code, message=None, explain=None) -> None:  # noqa: ARG002
            self.close_connection = True
            with contextlib.suppress(OSError):
                self._send(int(code), "malformed")

        def _route(self) -> str:
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            return path if path in KNOWN_ROUTES else "other"

        def _is_yes(self) -> bool:
            if not decide(self.headers.get_all(LOGIN_HEADER) or [],
                          self.headers.get_all(APP_CAPS_HEADER) or [], capability):
                return False
            return guard_ok()

        def _exact_origin(self) -> bool:
            origins = self.headers.get_all("Origin") or []
            return len(origins) == 1 and origins[0] == allowed_origin

        def _cors(self) -> dict:
            return {"Access-Control-Allow-Origin": allowed_origin} if self._exact_origin() else {}

        def _pna_requested(self) -> bool:
            values = self.headers.get_all("Access-Control-Request-Private-Network") or []
            return len(values) == 1 and values[0].strip().lower() == "true"

        def _get(self, head: bool) -> None:
            route = self._route()
            if route == PROBE_ROUTE:
                if self._is_yes():
                    self._send(200, route, PIXEL, "image/svg+xml", head=head)
                else:
                    self._send(404, route, head=head)
            elif route == JSON_ROUTE and not head:
                body = json.dumps({"tailnet": self._is_yes()}).encode()
                self._send(200, route, body, "application/json", self._cors())
            elif route == SURFACE_ROUTE and not head:
                body = json.dumps(surface(self._is_yes(), flag)).encode()
                self._send(200, route, body, "application/json", self._cors())
            else:
                self._send(404, route, head=head)

        def do_GET(self) -> None:
            self._get(head=False)

        def do_HEAD(self) -> None:
            self._get(head=True)

        def do_OPTIONS(self) -> None:
            # Chrome Private Network Access: allowed only to the one exact
            # origin, never reflected, never with credentials.
            route = self._route()
            exact = self._exact_origin()
            pna = self._pna_requested()
            if route in (JSON_ROUTE, SURFACE_ROUTE) or (route == PROBE_ROUTE and exact and pna):
                extra: dict = {}
                if exact:
                    extra = {
                        "Access-Control-Allow-Origin": allowed_origin,
                        "Access-Control-Allow-Methods": "GET",
                        "Access-Control-Max-Age": "600",
                    }
                    if pna:
                        extra["Access-Control-Allow-Private-Network"] = "true"
                self._send(204, route, extra=extra)
                return
            self._send(404, route)

        def _not_found(self) -> None:
            self._send(404, self._route())

        do_POST = do_PUT = do_PATCH = do_DELETE = _not_found  # noqa: N815

    return Handler


def require_loopback(host: str) -> str:
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("flag-probe binds loopback only; tailnet reach is tailscale serve")
    return host


def parse_args(argv: list | None = None) -> argparse.Namespace:
    env = os.environ.get
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(env("PROBE_PORT", "8471")))
    parser.add_argument("--allowed-origin", default=env("ALLOWED_ORIGIN", DEFAULT_ORIGIN))
    parser.add_argument("--app-capability", default=env("PROBE_CAPABILITY", DEFAULT_CAPABILITY))
    parser.add_argument("--tag", default=env("PROBE_TAG", DEFAULT_TAG))
    parser.add_argument("--flag", default=env("PROBE_FLAG", DEFAULT_FLAG))
    parser.add_argument("--tailscale", default=env("TAILSCALE_BIN", ""),
                        help="tailscale CLI for the node guard")
    parser.add_argument("--socket", default=env("TAILSCALE_SOCKET", ""),
                        help="the probe node's tailscaled socket")
    parser.add_argument("--guard-once", action="store_true",
                        help="run the node guard once and exit with its code")
    return parser.parse_args(argv)


def _require_guard_args(args: argparse.Namespace) -> None:
    if not args.tailscale or not args.socket:
        raise ValueError("--tailscale and --socket are required: the node guard is not optional")
    if not args.tag.startswith("tag:"):
        raise ValueError("--tag must be one tag:<name>")


def build_server(args: argparse.Namespace, log: Callable[[str], None]) -> ThreadingHTTPServer:
    host = require_loopback(args.bind)
    if args.allowed_origin in ("", "*", "null") or args.allowed_origin.endswith("/"):
        raise ValueError("--allowed-origin must be one exact origin, never * or null")
    if "/" not in args.app_capability or " " in args.app_capability:
        raise ValueError("--app-capability must be one <domain>/<path> capability name")
    _require_guard_args(args)
    run = make_runner(args.tailscale, args.socket)
    guard = NodeGuard(lambda: node_state(run, args.tag), log)
    handler = make_handler(args.allowed_origin, guard.ok, log,
                           capability=args.app_capability, flag=args.flag)
    return ThreadingHTTPServer((host, args.port), handler)


def main(argv: list | None = None) -> int:
    args = parse_args(argv)

    def log(line: str) -> None:
        print(line, file=sys.stderr, flush=True)

    if args.guard_once:
        try:
            _require_guard_args(args)
        except ValueError as exc:
            log(f"flag-probe: guard: {exc}")
            return GUARD_EXIT[GUARD_ERROR]
        state = node_state(make_runner(args.tailscale, args.socket), args.tag)
        print(state, flush=True)
        return GUARD_EXIT[state]

    try:
        server = build_server(args, log)
    except (OSError, ValueError) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else f"errno={getattr(exc, 'errno', None)}"
        log(f"flag-probe: refusing to start: {type(exc).__name__}: {detail}")
        return 2
    log(f"flag-probe: listening on {args.bind}:{args.port} capability={args.app_capability}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
