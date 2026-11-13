#!/usr/bin/env python3
"""Offline regression tests for the free-nodes aggregation pipeline.

Run with: python -m unittest discover -s free-nodes -p 'test_*.py'
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
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


class LocalPublishTests(unittest.TestCase):
    filenames = ["clash.yaml", "v2ray.txt", "singbox.json", "report.json"]

    def _stage(self, path, kept):
        path.mkdir(parents=True, exist_ok=True)
        for name in self.filenames[:-1]:
            (path / name).write_text(f"test:{name}\n", encoding="utf-8")
        report = {"counts": {"kept": kept}, "gate": {"passed": None}, "nodes": []}
        (path / "report.json").write_text(json.dumps(report), encoding="utf-8")

    def test_failed_gate_and_incomplete_stage_keep_current_release(self):
        cfg = {"min_keep": 20, "gist_filenames": self.filenames}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            staged = root / "staged"
            published = root / "published"
            self._stage(staged, 30)
            self.assertEqual(run.local_update(staged, published, cfg), 0)
            self.assertTrue(published.is_symlink())
            original_target = published.readlink()
            self.assertEqual(json.loads((published / "report.json").read_text())
                             ["gate"], {"prev_kept": None, "min_required": 20, "passed": True})

            self._stage(staged, 19)
            self.assertEqual(run.local_update(staged, published, cfg), 3)
            self.assertEqual(published.readlink(), original_target)
            self.assertEqual(json.loads((published / "report.json").read_text())["counts"]["kept"], 30)

            self._stage(staged, 25)
            self.assertEqual(run.local_update(staged, published, cfg), 0)
            updated_target = published.readlink()
            self.assertNotEqual(updated_target, original_target)
            self.assertEqual(json.loads((published / "report.json").read_text())["counts"]["kept"], 25)

            self._stage(staged, 24)
            (staged / "singbox.json").unlink()
            self.assertEqual(run.local_update(staged, published, cfg), 4)
            self.assertEqual(published.readlink(), updated_target)
            self.assertTrue((published / "singbox.json").is_file())

    def test_first_publish_below_minimum_does_not_create_a_release(self):
        cfg = {"min_keep": 20, "gist_filenames": self.filenames}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            staged = root / "staged"
            published = root / "published"
            self._stage(staged, 19)
            self.assertEqual(run.local_update(staged, published, cfg), 3)
            self.assertFalse(published.exists())
            self.assertFalse((root / "published.releases").exists())

    def test_local_publish_refuses_to_replace_an_unmanaged_directory(self):
        cfg = {"min_keep": 20, "gist_filenames": self.filenames}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            staged = root / "staged"
            published = root / "published"
            self._stage(staged, 30)
            published.mkdir()
            self.assertEqual(run.local_update(staged, published, cfg), 4)
            self.assertTrue(published.is_dir())
            self.assertFalse((root / "published.releases").exists())


class SourceIsolationTests(unittest.TestCase):
    def test_one_source_failure_does_not_stop_later_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            good_one = root / "one.txt"
            good_two = root / "two.txt"
            missing = root / "missing.txt"
            link = f"vless://{UUID}@node.example:443?security=none#test"
            good_one.write_text(link, encoding="utf-8")
            good_two.write_text(link.replace("node.example", "other.example"), encoding="utf-8")
            urls = ["https://one.example/sub", "https://two.example/sub", "https://three.example/sub"]
            mapping = {urls[0]: str(good_one), urls[1]: str(missing), urls[2]: str(good_two)}
            mapping_file = root / "sources.json"
            mapping_file.write_text(json.dumps(mapping), encoding="utf-8")
            cfg = {"sources": [{"name": f"source-{i}", "kind": "links", "url": url}
                               for i, url in enumerate(urls, 1)]}

            with contextlib.redirect_stdout(io.StringIO()):
                proxies, reports, counters = run.collect_sources(cfg, mapping_file)

            self.assertEqual([r["fetched"] for r in reports], [True, False, True])
            self.assertEqual([r["count"] for r in reports], [1, 0, 1])
            self.assertEqual(len(proxies), 2)
            self.assertEqual(counters["raw"], 2)


class SourceDiscoveryTests(unittest.TestCase):
    class Response:
        def __init__(self, status_code, body=None, content=b""):
            self.status_code = status_code
            self._body = body or {}
            self.content = content
            self.is_redirect = status_code in (301, 302, 303, 307, 308)

        def json(self):
            return self._body

    def test_discovers_only_recent_high_signal_files_and_skips_existing_repo(self):
        now = datetime.now(timezone.utc).isoformat()
        search = self.Response(200, {"total_count": 2, "items": [
            {"full_name": "known/provider", "default_branch": "main",
             "updated_at": now, "archived": False, "fork": False},
            {"full_name": "new/provider", "default_branch": "main",
             "updated_at": now, "archived": False, "fork": False},
        ]})
        tree = self.Response(200, {"tree": [
            {"path": "config.yaml", "type": "blob", "size": 1000},
            {"path": "output/clash.yaml", "type": "blob", "size": 2000},
            {"path": "examples/clash.yaml", "type": "blob", "size": 1000},
        ]}, content=b"tree")
        cfg = {
            "sources": [{"name": "known", "url":
                         "https://raw.githubusercontent.com/known/provider/main/clash.yaml"}],
            "source_discovery": {"enabled": True, "max_repositories": 8,
                                 "max_sources": 4, "max_age_days": 180},
        }
        with patch.object(run.requests, "get", side_effect=[search, tree]) as get:
            sources, report = run.discover_sources(cfg, token="dummy-token")

        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["api_requests"], 2)
        self.assertEqual(report["repositories_inspected"], 1)
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["kind"], "clash")
        self.assertEqual(sources[0]["repository"], "new/provider")
        self.assertEqual(sources[0]["url"],
                         "https://raw.githubusercontent.com/new/provider/main/output/clash.yaml")
        self.assertTrue(get.call_args_list[0].kwargs["headers"]["Authorization"].startswith("Bearer "))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            feed = root / "discovered.yaml"
            feed.write_text(
                "proxies:\n  - name: discovered\n    type: vless\n"
                f"    server: discovered.example\n    port: 443\n    uuid: {UUID}\n",
                encoding="utf-8")
            mapping = root / "sources.json"
            mapping.write_text(json.dumps({sources[0]["url"]: str(feed)}), encoding="utf-8")
            proxies, source_reports, _ = run.collect_sources(cfg, mapping, sources)
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["name"], "discovered")
        self.assertEqual(source_reports[-1]["source_type"], "discovered")
        self.assertTrue(source_reports[-1]["fetched"])

    def test_rate_limited_discovery_is_not_retried_and_fixed_sources_still_work(self):
        limited = self.Response(403, {"message": "rate limit exceeded"})
        url = "https://fixed.example/sub.txt"
        cfg = {"sources": [{"name": "fixed", "kind": "links", "url": url}],
               "source_discovery": {"enabled": True}}
        with patch.object(run.requests, "get", return_value=limited) as get:
            discovered, report = run.discover_sources(cfg, token="dummy-token")
        self.assertEqual(get.call_count, 1)
        self.assertEqual(discovered, [])
        self.assertEqual(report["status"], "unavailable")
        self.assertIn("without retry", report["error"])

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            feed = root / "fixed.txt"
            feed.write_text(f"vless://{UUID}@fixed.example:443?security=none#fixed", encoding="utf-8")
            mapping = root / "sources.json"
            mapping.write_text(json.dumps({url: str(feed)}), encoding="utf-8")
            proxies, source_reports, _ = run.collect_sources(cfg, mapping, discovered)
        self.assertEqual(len(proxies), 1)
        self.assertTrue(source_reports[0]["fetched"])
        self.assertEqual(source_reports[0]["source_type"], "configured")

    def test_discovered_feed_redirects_are_rejected(self):
        redirect = self.Response(302)
        with patch.object(run.requests, "get", return_value=redirect) as get:
            with self.assertRaisesRegex(RuntimeError, "redirects are disabled"):
                run.fetch_source("https://raw.githubusercontent.com/example/repo/main/clash.yaml",
                                 allow_redirects=False)
        self.assertFalse(get.call_args.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
