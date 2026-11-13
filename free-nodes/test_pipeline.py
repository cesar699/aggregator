#!/usr/bin/env python3
"""Offline regression tests for the free-nodes aggregation pipeline.

Run with: python -m unittest discover -s free-nodes -p 'test_*.py'
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "free-nodes"))

import run
import validate


IPV6 = "2001:4860:4860::8888"
UUID = "00000000-0000-4000-8000-000000000001"


def sample_node(exit_ip, blacklist_flag, blacklist_status):
    return {
        "name": "test-vless",
        "protocol": "vless",
        "server": IPV6,
        "port": 443,
        "latency_ms": 42,
        "exit_ip": exit_ip,
        "country": "US",
        "countryCode": "US",
        "asn": "AS15169",
        "org": "Example",
        "isp": "Example ISP",
        "hosting": False,
        "datacenter": False,
        "residential": True,
        "mobile": False,
        "network_type": "likely-residential",
        "proxy_flag": False,
        "vpn_flag": False,
        "tor_flag": False,
        "public_risk_flags": [],
        "public_risk_flag": False,
        "risk_score": 0,
        "blacklist_flag": blacklist_flag,
        "blacklist_status": blacklist_status,
        "blacklist_source": "test blacklist",
        "blacklist_checked_at": "2026-11-13T12:00:00+08:00",
        "netflix": "unknown",
        "chatgpt": "unknown",
    }


class IPv6ShareLinkTests(unittest.TestCase):
    def test_all_uri_protocol_builders_bracket_ipv6_and_roundtrip(self):
        proxies = [
            {"name": "vless6", "type": "vless", "server": IPV6,
             "port": 443, "uuid": UUID},
            {"name": "trojan6", "type": "trojan", "server": IPV6,
             "port": 443, "password": "p@ss"},
            {"name": "ss6", "type": "ss", "server": IPV6,
             "port": 8388, "cipher": "chacha20-ietf-poly1305", "password": "p@ss"},
            {"name": "hy2-6", "type": "hysteria2", "server": IPV6,
             "port": 443, "password": "p@ss"},
        ]
        for proxy in proxies:
            with self.subTest(protocol=proxy["type"]):
                link = run.build_link(proxy)
                self.assertIn(f"@[{IPV6}]:{proxy['port']}", link)
                parsed = run.parse_link(link)
                self.assertEqual(parsed["server"], IPV6)
                self.assertEqual(parsed["port"], proxy["port"])

    def test_domain_authority_is_unchanged(self):
        self.assertEqual(run._uri_hostport("node.example", 443), "node.example:443")


class BlacklistCoverageValidationTests(unittest.TestCase):
    def _validate_report(self, exit_ip, blacklist_flag, blacklist_status):
        blacklist_meta = {
            "name": "test blacklist",
            "url": "https://example.invalid/list.txt",
            "checked_at": "2026-11-13T12:00:00+08:00",
            "entries": 10,
            "ip_versions": [4],
            "reporting_window_hours": 48,
        }
        proxy = {"name": "test-vless", "type": "vless", "server": IPV6,
                 "port": 443, "uuid": UUID, "udp": True}
        report_node = sample_node(exit_ip, blacklist_flag, blacklist_status)
        cfg = {"test_urls": {"google_204": "https://www.google.com/generate_204"}}
        counts = {"raw": 1, "deduped": 1, "alive": 1, "kept": 1}
        enrichment = {
            "ip_reputation": {"provider": "IPQuery", "url": "https://api.ipquery.io/?format=json"},
            "blacklist": blacklist_meta,
        }
        with tempfile.TemporaryDirectory() as td:
            run.build_outputs([(proxy, 42)], [report_node], td, cfg, [], counts,
                              {"prev_kept": 1, "min_required": 1, "passed": True},
                              enrichment)
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                rc = validate.validate_dir(Path(td))
            return rc, errors.getvalue()

    def test_uncovered_ip_version_is_valid_unknown_not_a_false_no_match(self):
        rc, error = self._validate_report(IPV6, None, "ip_version_not_covered")
        self.assertEqual(rc, 0, error)

    def test_covered_ip_version_still_requires_boolean_match_result(self):
        rc, error = self._validate_report("8.8.8.8", None, "no_match")
        self.assertEqual(rc, 1)
        self.assertIn("blacklist flag is not a boolean", error)


if __name__ == "__main__":
    unittest.main()
