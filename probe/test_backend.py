"""Behaviour of probe/backend.py over a real loopback socket (stdlib unittest)."""

from __future__ import annotations

import datetime
import http.client
import json
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend as probe  # noqa: E402

ORIGIN = "https://app.example.org"
LOGIN = "someone.private@example.com"
SOURCE = "100.101.102.103"
CAP = "example.org/cap/flag-probe"
CAPS = json.dumps({CAP: [{}]})
TAG = "tag:flag-probe"
YES = {"Tailscale-User-Login": LOGIN, "Tailscale-App-Capabilities": CAPS}


class Running:
    def __init__(self, guard_ok=lambda: True, whois=None):
        self.lines: list[str] = []
        handler = probe.make_handler(
            ORIGIN, guard_ok, self.lines.append, today=lambda: datetime.date(2026, 10, 4),
            whois=whois,
        )
        self.server = probe.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    def request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body

    def wait_for_lines(self, count, timeout=5.0):
        # The handler logs after it writes the body, so the client can finish reading
        # before the line exists. Wait for it instead of racing the server thread.
        deadline = time.monotonic() + timeout
        while len(self.lines) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return self.lines

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class DecideTest(unittest.TestCase):
    def test_yes_needs_one_login_and_one_capability(self):
        self.assertTrue(probe.decide([LOGIN], [CAPS], CAP))

    def test_no_without_login(self):
        self.assertFalse(probe.decide([], [CAPS], CAP))
        self.assertFalse(probe.decide(["  "], [CAPS], CAP))

    def test_no_with_two_logins_or_two_cap_headers(self):
        self.assertFalse(probe.decide([LOGIN, LOGIN], [CAPS], CAP))
        self.assertFalse(probe.decide([LOGIN], [CAPS, CAPS], CAP))

    def test_no_for_wrong_empty_or_malformed_capability(self):
        self.assertFalse(probe.decide([LOGIN], [json.dumps({"other/cap/x": [{}]})], CAP))
        self.assertFalse(probe.decide([LOGIN], [json.dumps({CAP: []})], CAP))
        self.assertFalse(probe.decide([LOGIN], ["not json"], CAP))
        self.assertFalse(probe.decide([LOGIN], ["[1]"], CAP))
        self.assertFalse(probe.decide([LOGIN], [json.dumps({CAP: "x"})], CAP))


class SurfaceTest(unittest.TestCase):
    def test_yes_is_a_hint_basis(self):
        self.assertEqual(
            probe.surface(True),
            {
                "version": 1,
                "flags": {"member": True},
                "basis": [{"flag": "member", "source": "tailnet-probe", "trust": "hint"}],
                "status": "settled",
            },
        )

    def test_no_has_empty_basis(self):
        self.assertEqual(
            probe.surface(False),
            {"version": 1, "flags": {"member": False}, "basis": [], "status": "settled"},
        )


class GuardTest(unittest.TestCase):
    def node(self, status, serve):
        def run(args):
            return json.dumps(status) if args[0] == "status" else json.dumps(serve)
        return probe.node_state(run, TAG)

    def test_ok(self):
        self.assertEqual(
            self.node({"BackendState": "Running", "Self": {"Tags": [TAG]}}, {}), probe.GUARD_OK
        )

    def test_not_running(self):
        self.assertEqual(
            self.node({"BackendState": "Stopped", "Self": {"Tags": [TAG]}}, {}),
            probe.GUARD_NOT_RUNNING,
        )

    def test_second_tag_is_wrong_tags(self):
        self.assertEqual(
            self.node({"BackendState": "Running", "Self": {"Tags": [TAG, "tag:other"]}}, {}),
            probe.GUARD_WRONG_TAGS,
        )

    def test_funnel_anywhere(self):
        serve = {"Web": {"x:443": {"Handlers": {}}}, "AllowFunnel": {"x:443": True}}
        self.assertEqual(
            self.node({"BackendState": "Running", "Self": {"Tags": [TAG]}}, serve),
            probe.GUARD_FUNNEL,
        )

    def test_error_fails_closed(self):
        def boom(args):
            raise OSError("no tailscale")
        self.assertEqual(probe.node_state(boom, TAG), probe.GUARD_ERROR)

    def test_cache_and_state_change_log(self):
        states = iter([probe.GUARD_OK, probe.GUARD_FUNNEL])
        now = [0.0]
        lines: list[str] = []
        guard = probe.NodeGuard(lambda: next(states), lines.append, ttl=10, clock=lambda: now[0])
        self.assertTrue(guard.ok())
        now[0] = 5
        self.assertTrue(guard.ok())  # cached
        now[0] = 11
        self.assertFalse(guard.ok())  # re-checked
        self.assertEqual(len(lines), 2)


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.srv = Running()
        self.addCleanup(self.srv.close)

    def test_probe_svg_yes_and_no(self):
        status, headers, body = self.srv.request("GET", "/probe.svg", YES)
        self.assertEqual((status, headers["content-type"]), (200, "image/svg+xml"))
        self.assertEqual(body, probe.PIXEL)
        status, _, body = self.srv.request("GET", "/probe.svg", {})
        self.assertEqual((status, body), (404, b""))

    def test_tailnet_json(self):
        _, _, body = self.srv.request("GET", "/v1/tailnet", YES)
        self.assertEqual(json.loads(body), {"tailnet": True})
        _, _, body = self.srv.request("GET", "/v1/tailnet", {})
        self.assertEqual(json.loads(body), {"tailnet": False})

    def test_surface_manifest(self):
        status, headers, body = self.srv.request("GET", "/v1/surface", dict(YES, Origin=ORIGIN))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), probe.surface(True))
        self.assertEqual(headers["access-control-allow-origin"], ORIGIN)
        _, _, body = self.srv.request("GET", "/v1/surface", {})
        self.assertEqual(json.loads(body)["flags"], {"member": False})

    def test_no_store_on_every_response(self):
        for path in ("/probe.svg", "/v1/tailnet", "/v1/surface", "/nope"):
            _, headers, _ = self.srv.request("GET", path, YES)
            self.assertEqual(headers["cache-control"], "no-store", path)

    def test_cors_is_exact_origin_only(self):
        for origin in ("https://evil.example", ORIGIN + ".evil.example", ORIGIN + "/", "null"):
            _, headers, _ = self.srv.request("GET", "/v1/surface", dict(YES, Origin=origin))
            self.assertNotIn("access-control-allow-origin", headers, origin)
        _, headers, _ = self.srv.request("GET", "/v1/surface", dict(YES, Origin=ORIGIN))
        self.assertEqual(headers["access-control-allow-origin"], ORIGIN)

    def test_options_preflight(self):
        status, headers, _ = self.srv.request(
            "OPTIONS", "/v1/surface",
            {"Origin": ORIGIN, "Access-Control-Request-Private-Network": "true"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers["access-control-allow-origin"], ORIGIN)
        self.assertEqual(headers["access-control-allow-private-network"], "true")
        status, headers, _ = self.srv.request("OPTIONS", "/v1/surface", {"Origin": "https://evil.example"})
        self.assertEqual(status, 204)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_probe_svg_preflight_needs_exact_origin_and_pna(self):
        status, _, _ = self.srv.request(
            "OPTIONS", "/probe.svg",
            {"Origin": ORIGIN, "Access-Control-Request-Private-Network": "true"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(self.srv.request("OPTIONS", "/probe.svg", {"Origin": ORIGIN})[0], 404)

    def test_other_routes_and_methods_are_404_without_body(self):
        for method, path in (("GET", "/"), ("GET", "/v1/other"), ("POST", "/v1/surface"),
                             ("PUT", "/probe.svg"), ("DELETE", "/v1/tailnet")):
            status, _, body = self.srv.request(method, path, YES)
            self.assertEqual((status, body), (404, b""), (method, path))

    def test_no_identity_in_body_headers_or_log(self):
        headers_in = dict(YES, Origin=ORIGIN, **{"Tailscale-User-Name": "Someone Private"})
        for path in ("/probe.svg", "/v1/tailnet", "/v1/surface"):
            _, headers, body = self.srv.request("GET", path, headers_in)
            blob = (json.dumps(headers) + body.decode("latin-1")).lower()
            self.assertNotIn("someone", blob)
            self.assertNotIn(LOGIN.lower(), blob)
        log = "\n".join(self.srv.wait_for_lines(3)).lower()
        for secret in ("someone", "example.com", SOURCE, "127.0.0.1"):
            self.assertNotIn(secret, log)
        self.assertIn("route=/v1/surface status=200 day=2026-10-04", log)

    def test_guard_failure_turns_yes_into_no(self):
        srv = Running(guard_ok=lambda: False)
        self.addCleanup(srv.close)
        self.assertEqual(srv.request("GET", "/probe.svg", YES)[0], 404)
        self.assertEqual(json.loads(srv.request("GET", "/v1/surface", YES)[2])["flags"], {"member": False})


DEVICE_USER = "device.owner@example.com"


def device_whois(grant=None, tags=None):
    """A WhoIs body for a tagged node whose CapMap carries `grant` under CAP."""
    if grant is None:
        grant = {"member": True, "user": DEVICE_USER}
    return {
        "Node": {"Tags": [TAG.replace("flag-probe", "laptop")] if tags is None else tags},
        "CapMap": {CAP: [grant]},
    }


class ForwardedCallerTest(unittest.TestCase):
    def test_loopback_peer_last_tailnet_entry(self):
        self.assertEqual(probe.forwarded_caller("127.0.0.1", [SOURCE]), SOURCE)
        self.assertEqual(probe.forwarded_caller("::1", [f"203.0.113.9, {SOURCE}"]), SOURCE)
        self.assertEqual(probe.forwarded_caller("127.0.0.1", ["fd7a:115c:a1e0::5"]), "fd7a:115c:a1e0::5")

    def test_non_loopback_peer_is_never_trusted(self):
        self.assertIsNone(probe.forwarded_caller(SOURCE, [SOURCE]))
        self.assertIsNone(probe.forwarded_caller("not-an-ip", [SOURCE]))

    def test_outside_tailnet_ranges_or_ambiguous_is_none(self):
        self.assertIsNone(probe.forwarded_caller("127.0.0.1", ["203.0.113.9"]))
        self.assertIsNone(probe.forwarded_caller("127.0.0.1", [f"{SOURCE}, 203.0.113.9"]))
        self.assertIsNone(probe.forwarded_caller("127.0.0.1", [SOURCE, SOURCE]))
        self.assertIsNone(probe.forwarded_caller("127.0.0.1", []))
        self.assertIsNone(probe.forwarded_caller("127.0.0.1", ["garbage"]))


class DeviceGrantTest(unittest.TestCase):
    def test_tagged_node_with_flag_and_user(self):
        self.assertTrue(probe.device_grant_yes(device_whois(), CAP))
        as_text = device_whois(grant=json.dumps({"member": True, "user": DEVICE_USER}))
        self.assertTrue(probe.device_grant_yes(as_text, CAP))

    def test_custom_flag_name(self):
        whois = device_whois(grant={"qa": True, "user": DEVICE_USER})
        self.assertTrue(probe.device_grant_yes(whois, CAP, flag="qa"))
        self.assertFalse(probe.device_grant_yes(whois, CAP))

    def test_no_without_tags_flag_user_or_capability(self):
        self.assertFalse(probe.device_grant_yes(device_whois(tags=[]), CAP))
        self.assertFalse(probe.device_grant_yes(device_whois(grant={"member": True}), CAP))
        self.assertFalse(probe.device_grant_yes(device_whois(grant={"member": True, "user": " "}), CAP))
        self.assertFalse(probe.device_grant_yes(device_whois(grant={"member": "true", "user": DEVICE_USER}), CAP))
        self.assertFalse(probe.device_grant_yes(device_whois(), "example.org/cap/other"))
        for junk in (None, [], "x", {"Node": "x"}, {"Node": {"Tags": ["tag:a"]}, "CapMap": []}):
            self.assertFalse(probe.device_grant_yes(junk, CAP))

    def test_make_whois_fails_closed(self):
        def boom(_args):
            raise OSError("no socket")
        self.assertIsNone(probe.make_whois(boom)(SOURCE))
        self.assertIsNone(probe.make_whois(lambda _a: "not json")(SOURCE))
        seen = []
        whois = probe.make_whois(lambda a: seen.append(list(a)) or json.dumps(device_whois()))
        self.assertTrue(probe.device_grant_yes(whois(SOURCE), CAP))
        self.assertEqual(seen, [["whois", "--json", SOURCE]])


class DeviceHttpTest(unittest.TestCase):
    def setUp(self):
        self.asked: list[str] = []

        def whois(addr):
            self.asked.append(addr)
            return device_whois()

        self.srv = Running(whois=whois)
        self.addCleanup(self.srv.close)

    def test_device_yes_via_forwarded_tailnet_address(self):
        status, _, body = self.srv.request("GET", "/probe.svg", {"X-Forwarded-For": SOURCE})
        self.assertEqual((status, body), (200, probe.PIXEL))
        self.assertEqual(self.asked, [SOURCE])
        surface = json.loads(self.srv.request("GET", "/v1/surface", {"X-Forwarded-For": SOURCE})[2])
        self.assertEqual(surface["flags"], {"member": True})
        self.assertEqual(surface["basis"][0]["trust"], "hint")

    def test_no_forwarded_header_or_outside_range_is_no(self):
        self.assertEqual(self.srv.request("GET", "/probe.svg", {})[0], 404)
        self.assertEqual(self.srv.request("GET", "/probe.svg", {"X-Forwarded-For": "203.0.113.9"})[0], 404)
        self.assertEqual(self.asked, [])

    def test_login_header_present_uses_the_user_path_only(self):
        headers = {"Tailscale-User-Login": LOGIN, "X-Forwarded-For": SOURCE}
        self.assertEqual(self.srv.request("GET", "/probe.svg", headers)[0], 404)
        self.assertEqual(self.asked, [])

    def test_device_identity_never_reaches_body_headers_or_log(self):
        for path in ("/probe.svg", "/v1/tailnet", "/v1/surface"):
            _, headers, body = self.srv.request("GET", path, {"X-Forwarded-For": SOURCE, "Origin": ORIGIN})
            blob = (json.dumps(headers) + body.decode("latin-1")).lower()
            self.assertNotIn(DEVICE_USER, blob)
            self.assertNotIn(SOURCE, blob)
        log = "\n".join(self.srv.wait_for_lines(3)).lower()
        self.assertNotIn(DEVICE_USER, log)
        self.assertNotIn(SOURCE, log)

    def test_vary_covers_forwarded_for(self):
        _, headers, _ = self.srv.request("GET", "/v1/tailnet", {"X-Forwarded-For": SOURCE})
        self.assertIn("x-forwarded-for", headers["vary"].lower())

    def test_guard_failure_turns_device_yes_into_no(self):
        srv = Running(guard_ok=lambda: False, whois=lambda _a: device_whois())
        self.addCleanup(srv.close)
        self.assertEqual(srv.request("GET", "/probe.svg", {"X-Forwarded-For": SOURCE})[0], 404)

    def test_without_whois_the_device_path_is_off(self):
        srv = Running()
        self.addCleanup(srv.close)
        self.assertEqual(srv.request("GET", "/probe.svg", {"X-Forwarded-For": SOURCE})[0], 404)


class ExitCodeTest(unittest.TestCase):
    def test_config_refusal_exits_78(self):
        self.assertEqual(probe.EXIT_CONFIG, 78)
        self.assertEqual(probe.main(["--allowed-origin", "*", "--tailscale", "ts", "--socket", "/s"]), 78)
        self.assertEqual(probe.main([]), 78)


class ArgsTest(unittest.TestCase):
    def build(self, **overrides):
        args = probe.parse_args(["--tailscale", "ts", "--socket", "/s"])
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_binds_loopback_only(self):
        with self.assertRaises(ValueError):
            probe.require_loopback("0.0.0.0")
        self.assertEqual(probe.require_loopback("127.0.0.1"), "127.0.0.1")

    def test_origin_must_be_exact(self):
        for bad in ("*", "null", "", "https://app.example.org/"):
            with self.assertRaises(ValueError, msg=bad):
                probe.build_server(self.build(allowed_origin=bad, port=0), lambda _l: None)

    def test_guard_args_are_required(self):
        with self.assertRaises(ValueError):
            probe.build_server(probe.parse_args([]), lambda _l: None)

    def test_env_supplies_origin(self):
        import os
        old = os.environ.get("ALLOWED_ORIGIN")
        os.environ["ALLOWED_ORIGIN"] = "https://site.example.org"
        try:
            self.assertEqual(probe.parse_args([]).allowed_origin, "https://site.example.org")
        finally:
            if old is None:
                del os.environ["ALLOWED_ORIGIN"]
            else:
                os.environ["ALLOWED_ORIGIN"] = old


if __name__ == "__main__":
    unittest.main()
