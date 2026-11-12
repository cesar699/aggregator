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
import json
import sys
from pathlib import Path

KNOWN_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")


def fail(msg):
    print(f"VALIDATE FAIL: {msg}", file=sys.stderr)
    return 1


def validate_dir(out_dir: Path) -> int:
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

    # --- v2ray.txt ---
    raw = v2ray_path.read_text(encoding="utf-8").strip()
    if not raw:
        return fail("v2ray.txt is empty")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8")
    except Exception as e:
        return fail(f"v2ray.txt is not valid base64: {e}")
    lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    if not lines:
        return fail("v2ray.txt decodes to no links")
    for ln in lines:
        if not ln.startswith(KNOWN_SCHEMES):
            return fail(f"v2ray.txt contains unknown-scheme link: {ln[:80]!r}")

    # --- report.json ---
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        return fail(f"report.json is not valid JSON: {e}")
    kept = (report.get("counts") or {}).get("kept")
    if not isinstance(kept, int) or kept < 1:
        return fail(f"report.json kept < 1 (kept={kept!r})")
    nodes = report.get("nodes") or []
    if len(nodes) != kept:
        return fail(f"report.json nodes ({len(nodes)}) != kept ({kept})")

    print(
        f"VALIDATE OK: clash={len(proxies)} proxies, "
        f"singbox={len(outbounds)} outbounds, v2ray={len(lines)} links, "
        f"report kept={kept}"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate free-nodes outputs")
    ap.add_argument("--dir", default=None, help="output directory (default: <repo>/out)")
    args = ap.parse_args()
    if args.dir:
        out_dir = Path(args.dir)
    else:
        out_dir = Path(__file__).resolve().parent.parent / "out"
    return validate_dir(out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
