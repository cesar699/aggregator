#!/usr/bin/env python3
"""Validate the outputs of free-nodes/run.py.

Usage:
    python free-nodes/validate.py --dir out
    python free-nodes/validate.py            # defaults to out/ next to repo root

Checks (first problem found exits non-zero):
  - clash.yaml parses as YAML, has proxies > 0, names unique
  - singbox.json parses as JSON, has outbounds > 0
  - v2ray.txt base64-decodes and every line parses as a known-scheme link
  - report.json parses and kept >= 1
"""
import argparse
import base64
import ipaddress
import json
import subprocess
import sys
import tempfile
from pathlib import Path

KNOWN_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")


def fail(msg):
    print(f"VALIDATE FAIL: {msg}", file=sys.stderr)
    return 1


def check_mihomo(clash_path: Path, mihomo_bin: str) -> int:
    """Run `mihomo -t` on the generated clash.yaml. NOTE: mihomo -t exits
    0 even when the test fails, so grep the output for the success line."""
    with tempfile.TemporaryDirectory() as td:
        try:
            r = subprocess.run([mihomo_bin, "-d", td, "-f", str(clash_path), "-t"],
                               capture_output=True, text=True, timeout=120)
        except Exception as e:
            return fail(f"mihomo -t could not run: {e}")
    out = (r.stdout or "") + (r.stderr or "")
    if "test is successful" in out:
        print("MIHOMO CHECK OK: clash.yaml accepted by mihomo -t")
        return 0
    return fail(f"mihomo -t rejected clash.yaml: {out[-500:]!r}")


def check_singbox(singbox_path: Path, singbox_bin: str) -> int:
    try:
        r = subprocess.run([singbox_bin, "check", "-c", str(singbox_path)],
                           capture_output=True, text=True, timeout=120)
    except Exception as e:
        return fail(f"sing-box check could not run: {e}")
    if r.returncode == 0:
        print("SING-BOX CHECK OK: singbox.json accepted by sing-box check")
        return 0
    out = (r.stdout or "") + (r.stderr or "")
    return fail(f"sing-box check rejected singbox.json: {out[-500:]!r}")


def validate_dir(out_dir: Path, mihomo_bin=None, singbox_bin=None) -> int:
    import yaml  # local import so --help works without deps

    clash_path = out_dir / "clash.yaml"
    v2ray_path = out_dir / "v2ray.txt"
    singbox_path = out_dir / "singbox.json"
    report_path = out_dir / "report.json"

    for p in (clash_path, v2ray_path, singbox_path, report_path):
        if not p.exists():
            return fail(f"missing file: {p}")

    # --- clash.yaml ---
    try:
        clash = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
    except Exception as e:
        return fail(f"clash.yaml is not valid YAML: {e}")
    if not isinstance(clash, dict):
        return fail("clash.yaml top level is not a mapping")
    proxies = clash.get("proxies") or []
    if not isinstance(proxies, list) or len(proxies) == 0:
        return fail("clash.yaml has no proxies")
    names = [p.get("name") for p in proxies if isinstance(p, dict)]
    if len(names) != len(set(names)):
        return fail("clash.yaml has duplicate proxy names")
    for p in proxies:
        if not isinstance(p, dict) or not p.get("type") or not p.get("server") or not p.get("port"):
            return fail(f"clash.yaml proxy missing type/server/port: {p.get('name')!r}")

    # --- singbox.json ---
    try:
        singbox = json.loads(singbox_path.read_text(encoding="utf-8"))
    except Exception as e:
        return fail(f"singbox.json is not valid JSON: {e}")
    outbounds = singbox.get("outbounds") if isinstance(singbox, dict) else None
    if not isinstance(outbounds, list) or len(outbounds) == 0:
        return fail("singbox.json has no outbounds")
    proxy_outbounds = [o for o in outbounds if isinstance(o, dict) and o.get("type") != "selector"]
    selectors = [o for o in outbounds if isinstance(o, dict) and o.get("type") == "selector"]
    if len(proxy_outbounds) != len(proxies):
        return fail(f"singbox.json proxy outbounds ({len(proxy_outbounds)}) != Clash proxies ({len(proxies)})")
    route = singbox.get("route")
    if not isinstance(route, dict) or len(selectors) != 1 or route.get("final") != selectors[0].get("tag"):
        return fail("singbox.json must have exactly one selector matching route.final")

    # --- v2ray.txt ---
    raw = v2ray_path.read_text(encoding="utf-8").strip()
    if not raw:
        return fail("v2ray.txt is empty")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except Exception as e:
        return fail(f"v2ray.txt is not valid base64: {e}")
    lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    if not lines:
        return fail("v2ray.txt decodes to no links")
    for ln in lines:
        if not ln.startswith(KNOWN_SCHEMES):
            return fail("v2ray.txt contains an unknown-scheme link")
    try:
        from run import parse_link
    except Exception as e:
        return fail(f"V2Ray share-link parser unavailable: {type(e).__name__}")
    for i, ln in enumerate(lines, 1):
        try:
            parse_link(ln)
        except Exception as e:
            return fail(f"V2Ray link #{i} is invalid ({type(e).__name__})")

    # --- report.json ---
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        return fail(f"report.json is not valid JSON: {e}")
    kept = (report.get("counts") or {}).get("kept")
    if not isinstance(kept, int) or kept < 1:
        return fail(f"report.json kept < 1 (kept={kept!r})")
    if kept > 200:
        return fail(f"report.json kept exceeds the 200-node limit (kept={kept})")
    nodes = report.get("nodes") or []
    if len(nodes) != kept:
        return fail(f"report.json nodes ({len(nodes)}) != kept ({kept})")
    if len(proxies) != kept or len(lines) != kept or len(proxy_outbounds) != kept:
        return fail("Clash, V2Ray, Sing-box and report node counts do not match")
    enrichment = report.get("enrichment") or {}
    reputation = enrichment.get("ip_reputation") if isinstance(enrichment, dict) else None
    blacklist = enrichment.get("blacklist") if isinstance(enrichment, dict) else None
    if not isinstance(reputation, dict) or reputation.get("provider") != "IPQuery" or not str(reputation.get("url", "")).startswith("https://"):
        return fail("report.json is missing the IPQuery reputation source")
    if not isinstance(blacklist, dict) or not str(blacklist.get("url", "")).startswith("https://"):
        return fail("report.json is missing the public blacklist source")
    if not isinstance(blacklist.get("entries"), int) or blacklist["entries"] < 1:
        return fail("report.json blacklist snapshot has no valid entries")
    if not isinstance(blacklist.get("checked_at"), str) or not blacklist["checked_at"]:
        return fail("report.json blacklist snapshot is missing checked_at")
    if blacklist.get("reporting_window_hours") != 48:
        return fail("report.json blacklist reporting window is not 48 hours")
    ip_versions = blacklist.get("ip_versions")
    if not isinstance(ip_versions, list) or not ip_versions or any(v not in (4, 6) for v in ip_versions):
        return fail("report.json blacklist snapshot has invalid IP-version coverage")
    latencies = []
    for i, node in enumerate(nodes, 1):
        if not isinstance(node, dict):
            return fail(f"report node #{i} is not an object")
        required_fields = ("country", "asn", "network_type", "proxy_flag", "vpn_flag", "tor_flag",
                           "public_risk_flag", "risk_score", "blacklist_flag", "blacklist_status",
                           "blacklist_source", "blacklist_checked_at", "netflix", "chatgpt")
        if any(field not in node for field in required_fields):
            return fail(f"report node #{i} is missing required purity fields")
        try:
            address = ipaddress.ip_address(str(node.get("exit_ip", "")))
        except ValueError:
            return fail(f"report node #{i} has an invalid exit IP")
        if not address.is_global:
            return fail(f"report node #{i} exit IP is not public")
        if address.version not in ip_versions:
            return fail(f"blacklist snapshot does not cover report node #{i} IP version")
        for field in ("proxy_flag", "vpn_flag", "tor_flag", "public_risk_flag", "blacklist_flag"):
            if type(node.get(field)) is not bool:
                return fail(f"report node #{i} field {field} is not a boolean result")
        if not isinstance(node.get("risk_score"), int) or isinstance(node["risk_score"], bool) or not 0 <= node["risk_score"] <= 100:
            return fail(f"report node #{i} has an invalid IPQuery risk_score")
        expected_status = "match" if node["blacklist_flag"] else "no_match"
        if node["blacklist_status"] != expected_status:
            return fail(f"report node #{i} blacklist flag/status disagree")
        if node["blacklist_source"] != blacklist.get("name") or node["blacklist_checked_at"] != blacklist["checked_at"]:
            return fail(f"report node #{i} blacklist metadata does not match the checked snapshot")
        if node.get("network_type") not in ("datacenter", "mobile", "likely-residential", "unknown"):
            return fail(f"report node #{i} has an unknown network_type")
        if node.get("netflix") not in ("yes", "no", "unknown") or node.get("chatgpt") not in ("yes", "no", "unknown"):
            return fail(f"report node #{i} has invalid unlock-probe results")
        latency = node.get("latency_ms")
        if not isinstance(latency, int) or latency < 0 or latency > 5000:
            return fail(f"report node #{i} latency is missing or over 5000 ms")
        latencies.append(latency)
    if latencies != sorted(latencies):
        return fail("report nodes are not sorted by latency")

    print(
        f"VALIDATE OK: clash={len(proxies)} proxies, "
        f"singbox={len(outbounds)} outbounds, v2ray={len(lines)} links, "
        f"report kept={kept}"
    )

    # Deep checks against the real parsers (plain YAML/JSON parsing alone
    # missed the illegal "version" field and the hy2-missing-TLS bug).
    if mihomo_bin:
        rc = check_mihomo(clash_path, mihomo_bin)
        if rc != 0:
            return rc
    if singbox_bin:
        rc = check_singbox(singbox_path, singbox_bin)
        if rc != 0:
            return rc
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate free-nodes outputs")
    ap.add_argument("--dir", default=None, help="output directory (default: <repo>/out)")
    ap.add_argument("--mihomo-bin", default=None, help="path to mihomo binary for -t check")
    ap.add_argument("--singbox-bin", default=None, help="path to sing-box binary for check")
    args = ap.parse_args()
    if args.dir:
        out_dir = Path(args.dir)
    else:
        out_dir = Path(__file__).resolve().parent.parent / "out"
    return validate_dir(out_dir, args.mihomo_bin, args.singbox_bin)


if __name__ == "__main__":
    raise SystemExit(main())
