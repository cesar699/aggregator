#!/usr/bin/env python3
"""Free-nodes aggregation pipeline (fork of wzdnz/aggregator, CSMP edition).

Steps: fetch 4 public sources -> parse to canonical Clash proxy dicts ->
dedupe -> Mihomo liveness test (google generate_204 + YouTube static, both
must pass < max_latency_ms) -> per-node exit-IP purity check (ip-api +
Netflix / ChatGPT unlock probes) -> emit clash.yaml / v2ray.txt /
singbox.json / report.json -> gate -> PATCH a GitHub Gist.

Exit codes: 0 ok, 2 all sources failed, 3 gate failed (no Gist update),
4 Gist API failure, 5 output validation failure.

Env: GIST_PAT (fallback PUSH_TOKEN), GIST_ID. Tokens are never printed.
Stdlib + PyYAML + requests only.
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN") or str(REPO_ROOT / "clash" / "clash-linux-amd")
CONTROLLER = "http://127.0.0.1:9090"
MIXED_PORT = 7890
GROUP_TYPES = {"select", "url-test", "fallback", "load-balance", "relay"}
KNOWN_TYPES = {"vless", "vmess", "trojan", "ss", "hysteria2"}
CST = timezone(timedelta(hours=8))

# ---------------------------------------------------------------- helpers

def log(msg):
    print(f"[{datetime.now(CST).strftime('%H:%M:%S')}] {msg}", flush=True)


def b64decode_padded(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64encode_nopad(s: bytes) -> str:
    return base64.b64encode(s).decode().rstrip("=")


def b64encode_std(s: bytes) -> str:
    return base64.b64encode(s).decode()


def q(name):
    return urllib.parse.quote(str(name), safe="")


def _alpn_list(v):
    """Mihomo requires alpn to be a list; sources often give 'h2' or
    'h2,http/1.1' as a plain string."""
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return []


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------- link -> clash dict

def _split_link(link):
    """Return (scheme, body, name) for scheme://body#name."""
    scheme, rest = link.split("://", 1)
    if "#" in rest:
        body, frag = rest.split("#", 1)
        name = urllib.parse.unquote(frag)
    else:
        body, name = rest, ""
    return scheme.lower(), body, name


def _parse_hostport(hostport):
    if hostport.startswith("["):  # IPv6 [::1]:port
        host, _, port = hostport[1:].partition("]:")
        return host, int(port)
    host, _, port = hostport.rpartition(":")
    return host, int(port)


def _ws_opts(d, params):
    net = params.get("type", [d.get("network", "tcp")])[0]
    d["network"] = net
    if net == "ws":
        path = params.get("path", [""])[0]
        host = params.get("host", [""])[0]
        opts = {}
        if path:
            opts["path"] = urllib.parse.unquote(path)
        if host:
            opts["headers"] = {"Host": host}
        if opts:
            d["ws-opts"] = opts
    elif net == "grpc":
        d["grpc-opts"] = {"grpc-service-name": params.get("serviceName", [""])[0]}


def parse_vless(link):
    scheme, body, name = _split_link(link)
    userinfo, _, rest = body.partition("@")
    hostport, _, query = rest.partition("?")
    host, port = _parse_hostport(hostport)
    params = urllib.parse.parse_qs(query)
    d = {"name": name, "type": "vless", "server": host, "port": port,
         "uuid": urllib.parse.unquote(userinfo), "udp": True}
    sec = params.get("security", ["none"])[0]
    if sec == "tls":
        d["tls"] = True
    elif sec == "reality":
        d["tls"] = True
        d["reality-opts"] = {"public-key": params.get("pbk", [""])[0],
                             "short-id": params.get("sid", [""])[0]}
    if params.get("sni"):
        d["servername"] = params["sni"][0]
    if params.get("fp"):
        d["client-fingerprint"] = params["fp"][0]
    if params.get("flow"):
        d["flow"] = params["flow"][0]
    if params.get("alpn"):
        d["alpn"] = _alpn_list(params["alpn"][0])
    if params.get("allowInsecure", ["0"])[0] in ("1", "true"):
        d["skip-cert-verify"] = True
    _ws_opts(d, params)
    return d


def parse_vmess(link):
    _, body, _name = _split_link(link)
    try:
        raw = b64decode_padded(body.split("?")[0]).decode("utf-8")
        j = json.loads(raw)
    except Exception as e:
        raise ValueError(f"bad vmess payload: {e}")
    d = {"name": j.get("ps", ""), "type": "vmess", "server": j.get("add", ""),
         "port": int(j.get("port", 0)), "uuid": j.get("id", ""),
         "alterId": int(j.get("aid", 0) or 0), "cipher": j.get("scy", "auto"),
         "udp": True}
    if str(j.get("tls", "")) in ("tls", "1", "true"):
        d["tls"] = True
    if j.get("sni"):
        d["servername"] = j["sni"]
    if j.get("fp"):
        d["client-fingerprint"] = j["fp"]
    net = j.get("net", "tcp")
    d["network"] = net
    if net == "ws":
        opts = {}
        if j.get("path"):
            opts["path"] = j["path"]
        if j.get("host"):
            opts["headers"] = {"Host": j["host"]}
        if opts:
            d["ws-opts"] = opts
    elif net == "grpc":
        d["grpc-opts"] = {"grpc-service-name": j.get("path", "")}
    return d


def parse_trojan(link):
    scheme, body, name = _split_link(link)
    userinfo, _, rest = body.partition("@")
    hostport, _, query = rest.partition("?")
    host, port = _parse_hostport(hostport)
    params = urllib.parse.parse_qs(query)
    d = {"name": name, "type": "trojan", "server": host, "port": port,
         "password": urllib.parse.unquote(userinfo), "udp": True}
    sni = params.get("sni", [""])[0]
    if sni:
        d["sni"] = sni
        d["servername"] = sni
    if params.get("allowInsecure", ["0"])[0] in ("1", "true"):
        d["skip-cert-verify"] = True
    _ws_opts(d, params)
    return d


def parse_ss(link):
    scheme, body, name = _split_link(link)
    if "@" in body:
        user_b64, _, hostport = body.rpartition("@")
        try:
            userinfo = b64decode_padded(user_b64).decode("utf-8")
        except Exception:
            userinfo = urllib.parse.unquote(user_b64)
        host, port = _parse_hostport(hostport.split("?")[0].split("/")[0])
    else:  # whole body is base64(method:password@host:port)
        decoded = b64decode_padded(body.split("?")[0].split("/")[0]).decode("utf-8")
        userinfo, _, hostport = decoded.rpartition("@")
        # some sources append a stray "?" after the port inside the payload
        hostport = hostport.split("?")[0].split("/")[0]
        host, port = _parse_hostport(hostport)
    method, _, password = userinfo.partition(":")
    return {"name": name, "type": "ss", "server": host, "port": port,
            "cipher": method, "password": password, "udp": True}


def parse_hysteria2(link):
    scheme, body, name = _split_link(link)
    userinfo, _, rest = body.partition("@")
    hostport, _, query = rest.partition("?")
    host, port = _parse_hostport(hostport)
    params = urllib.parse.parse_qs(query)
    d = {"name": name, "type": "hysteria2", "server": host, "port": port,
         "password": urllib.parse.unquote(userinfo), "udp": True}
    if params.get("sni"):
        d["sni"] = params["sni"][0]
    if params.get("insecure", ["0"])[0] in ("1", "true"):
        d["skip-cert-verify"] = True
    if params.get("obfs"):
        d["obfs"] = params["obfs"][0]
    if params.get("obfs-password"):
        d["obfs-password"] = params["obfs-password"][0]
    if params.get("alpn"):
        d["alpn"] = _alpn_list(params["alpn"][0])
    return d


LINK_PARSERS = {"vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan,
                "ss": parse_ss, "hysteria2": parse_hysteria2, "hy2": parse_hysteria2}


def parse_link(link):
    """Parse one share link to a Clash proxy dict. Raises ValueError."""
    link = link.strip()
    if "://" not in link:
        raise ValueError("no scheme")
    scheme = link.split("://", 1)[0].lower()
    if scheme == "ssr":
        raise ValueError("ssr-dropped")
    fn = LINK_PARSERS.get(scheme)
    if not fn:
        raise ValueError(f"unknown-scheme:{scheme}")
    d = fn(link)
    if d["type"] == "hy2":
        d["type"] = "hysteria2"
    check_required(d)
    return d


# ------------------------------------------------------- clash dict -> link

def _enc_name(name):
    return urllib.parse.quote(str(name), safe="")


def _uri_hostport(host, port):
    """Format an address for URI authority syntax, bracketing IPv6 literals."""
    host = str(host).strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if ":" in host:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as e:
            raise ValueError(f"invalid IP literal in server address: {host!r}") from e
        if address.version == 6:
            host = f"[{address.compressed}]"
        else:
            host = address.compressed
    return f"{host}:{int(port)}"


def _ws_params(d):
    p = {}
    net = d.get("network", "tcp")
    p["type"] = net
    if net == "ws":
        ws = d.get("ws-opts") or {}
        if ws.get("path"):
            p["path"] = ws["path"]
        hdrs = ws.get("headers") or {}
        if hdrs.get("Host"):
            p["host"] = hdrs["Host"]
    elif net == "grpc":
        grpc = d.get("grpc-opts") or {}
        if grpc.get("grpc-service-name"):
            p["serviceName"] = grpc["grpc-service-name"]
    return p


REQUIRED_FIELDS = {"vless": ("uuid",), "vmess": ("uuid",),
                   "trojan": ("password",), "hysteria2": ("password",),
                   "ss": ("cipher", "password")}


def check_required(d):
    """Required fields per protocol. A node missing one would make Mihomo
    reject the whole config at startup (verified: 'key uuid missing'),
    so drop it here and count it as dropped_bad instead."""
    if not d.get("server"):
        raise ValueError("missing server")
    try:
        port = int(d["port"])
    except Exception:
        raise ValueError("missing/invalid port")
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    for k in REQUIRED_FIELDS.get(d["type"], ()):
        if not d.get(k):
            raise ValueError(f"missing {k}")
    if d.get("type") not in KNOWN_TYPES:
        raise ValueError(f"unsupported protocol: {d.get('type')}")
    if d["type"] in ("vless", "vmess"):
        try:
            uuid.UUID(str(d.get("uuid", "")))
        except (ValueError, AttributeError, TypeError):
            raise ValueError("invalid uuid")
    if d["type"] == "vless" and d.get("reality-opts") is not None:
        ro = d["reality-opts"]
        if not isinstance(ro, dict):
            raise ValueError("invalid reality-opts")
        sid = str(ro.get("short-id") or "")
        if len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", sid):
            raise ValueError("invalid REALITY short ID")
        try:
            public_key = b64decode_padded(str(ro.get("public-key") or ""))
        except Exception:
            public_key = b""
        if len(public_key) != 32:
            raise ValueError("invalid REALITY public key")
        ro["short-id"] = sid


def build_vless(d):
    if d.get("reality-opts"):
        # Reality must stay reality: downgrading to plain TLS (the old
        # behaviour) makes the client handshake against a Reality server
        # and always fail.
        ro = d["reality-opts"]
        p = {"encryption": "none", "security": "reality",
             "pbk": ro.get("public-key", ""), "sid": ro.get("short-id", "")}
    else:
        p = {"encryption": "none", "security": "tls" if d.get("tls") else "none"}
    p.update(_ws_params(d))
    if d.get("servername"):
        p["sni"] = d["servername"]
    if d.get("client-fingerprint"):
        p["fp"] = d["client-fingerprint"]
    if d.get("flow"):
        p["flow"] = d["flow"]
    if d.get("alpn"):
        p["alpn"] = ",".join(d["alpn"]) if isinstance(d["alpn"], list) else d["alpn"]
    return ("vless://" + d["uuid"] + "@" + _uri_hostport(d["server"], d["port"]) +
            "?" + urllib.parse.urlencode(p) + "#" + _enc_name(d["name"]))


def build_vmess(d):
    ws = d.get("ws-opts") or {}
    j = {"v": "2", "ps": d["name"], "add": d["server"], "port": str(d["port"]),
         "id": d["uuid"], "aid": str(d.get("alterId", 0)),
         "scy": d.get("cipher", "auto"), "net": d.get("network", "tcp"),
         "type": "none", "host": (ws.get("headers") or {}).get("Host", ""),
         "path": ws.get("path", ""),
         "tls": "tls" if d.get("tls") else "",
         "sni": d.get("servername", ""), "fp": d.get("client-fingerprint", "")}
    return "vmess://" + b64encode_std(json.dumps(j, ensure_ascii=False).encode())


def build_trojan(d):
    p = {}
    p.update(_ws_params(d))
    if d.get("sni") or d.get("servername"):
        p["sni"] = d.get("sni") or d.get("servername")
    if d.get("skip-cert-verify"):
        p["allowInsecure"] = "1"
    qs = ("?" + urllib.parse.urlencode(p)) if p else ""
    return ("trojan://" + urllib.parse.quote(d["password"], safe="") + "@" +
            _uri_hostport(d["server"], d["port"]) + qs + "#" + _enc_name(d["name"]))


def build_ss(d):
    user = b64encode_nopad((d["cipher"] + ":" + d["password"]).encode())
    return ("ss://" + user + "@" + _uri_hostport(d["server"], d["port"]) +
            "#" + _enc_name(d["name"]))


def build_hysteria2(d):
    p = {}
    if d.get("sni"):
        p["sni"] = d["sni"]
    if d.get("skip-cert-verify"):
        p["insecure"] = "1"
    if d.get("obfs"):
        p["obfs"] = d["obfs"]
    if d.get("obfs-password"):
        p["obfs-password"] = d["obfs-password"]
    qs = ("?" + urllib.parse.urlencode(p)) if p else ""
    return ("hysteria2://" + urllib.parse.quote(d["password"], safe="") + "@" +
            _uri_hostport(d["server"], d["port"]) + qs + "#" + _enc_name(d["name"]))


LINK_BUILDERS = {"vless": build_vless, "vmess": build_vmess, "trojan": build_trojan,
                 "ss": build_ss, "hysteria2": build_hysteria2}


def build_link(d):
    fn = LINK_BUILDERS.get(d["type"])
    if not fn:
        raise ValueError(f"no builder for {d['type']}")
    return fn(d)


# ------------------------------------------------------- clash dict -> sing-box

def _sb_tls(d):
    if not d.get("tls"):
        return None
    tls = {"enabled": True}
    sni = d.get("servername") or d.get("sni")
    if sni:
        tls["server_name"] = sni
    if d.get("skip-cert-verify"):
        tls["insecure"] = True
    if d.get("alpn"):
        tls["alpn"] = d["alpn"] if isinstance(d["alpn"], list) else [d["alpn"]]
    if d.get("client-fingerprint"):
        tls["utls"] = {"enabled": True, "fingerprint": d["client-fingerprint"]}
    if d.get("reality-opts") and d["reality-opts"].get("public-key"):
        # Without this, sing-box does plain TLS against a Reality server.
        ro = d["reality-opts"]
        reality = {"enabled": True, "public_key": ro["public-key"]}
        if ro.get("short-id"):
            reality["short_id"] = ro["short-id"]
        tls["reality"] = reality
        if "utls" not in tls:
            # sing-box requires uTLS for Reality ("uTLS is required by
            # reality client"); default to chrome when the source gives
            # no fingerprint.
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
    return tls


def _sb_transport(d):
    net = d.get("network", "tcp")
    if net == "ws":
        ws = d.get("ws-opts") or {}
        t = {"type": "ws", "path": ws.get("path", "/")}
        hdrs = ws.get("headers") or {}
        if hdrs.get("Host"):
            t["headers"] = {"Host": hdrs["Host"]}
        return t
    if net == "grpc":
        grpc = d.get("grpc-opts") or {}
        return {"type": "grpc", "service_name": grpc.get("grpc-service-name", "")}
    return None


def clash_to_singbox(d):
    t = d["type"]
    ob = {"tag": d["name"], "server": d["server"], "server_port": int(d["port"])}
    if t == "vless":
        ob["type"] = "vless"
        ob["uuid"] = d["uuid"]
        if d.get("flow") == "xtls-rprx-vision":
            ob["flow"] = d["flow"]
        # sing-box supports only xtls-rprx-vision; mihomo-only flows like
        # xtls-rprx-vision-udp443 make `sing-box check` reject the whole
        # file, so they are dropped (the node still works as plain VLESS).
    elif t == "vmess":
        ob["type"] = "vmess"
        ob["uuid"] = d["uuid"]
        ob["alter_id"] = int(d.get("alterId", 0) or 0)
        ob["security"] = d.get("cipher", "auto")
    elif t == "trojan":
        ob["type"] = "trojan"
        ob["password"] = d["password"]
        # Explicit TLS (sing-box tolerates it missing, but be explicit).
        tls = {"enabled": True}
        sni = d.get("sni") or d.get("servername")
        if sni:
            tls["server_name"] = sni
        if d.get("skip-cert-verify"):
            tls["insecure"] = True
        ob["tls"] = tls
    elif t == "ss":
        ob["type"] = "shadowsocks"
        ob["method"] = d["cipher"]
        ob["password"] = d["password"]
    elif t == "hysteria2":
        ob["type"] = "hysteria2"
        ob["password"] = d["password"]
        # sing-box REQUIRES tls for hysteria2 ("TLS required" without it);
        # Clash hy2 dicts never carry a tls key, so build it here.
        tls = {"enabled": True}
        sni = d.get("sni") or d.get("servername")
        if sni:
            tls["server_name"] = sni
        if d.get("skip-cert-verify"):
            tls["insecure"] = True
        tls["alpn"] = d["alpn"] if isinstance(d.get("alpn"), list) and d["alpn"] else ["h3"]
        ob["tls"] = tls
        if d.get("obfs"):
            ob["obfs"] = {"type": d["obfs"]}
            if d.get("obfs-password"):
                ob["obfs"]["password"] = d["obfs-password"]
    else:
        raise ValueError(f"no sing-box mapping for {t}")
    tls = _sb_tls(d)
    if tls:
        ob["tls"] = tls
    tr = _sb_transport(d)
    if tr:
        ob["transport"] = tr
    return ob

# ------------------------------------------------------------- fetch + parse

def fetch_source(url, timeout=30):
    last = None
    for attempt in range(2):  # 1 retry
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "cesar699-aggregator/1.0"})
            r.raise_for_status()
            # Decode as UTF-8 explicitly: requests defaults to latin-1 when
            # the server sends no charset, which turns flag emoji bytes into
            # U+009F control chars that break YAML parsing downstream.
            return r.content.decode("utf-8", errors="replace")
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status is None or status < 500:
                # Never repeat a rejected or rate-limited request (including 403/429).
                raise
            last = e
        except (requests.Timeout, requests.ConnectionError) as e:
            last = e
        except Exception:
            raise
        if attempt == 0:
            time.sleep(2)
    raise last


def fetch_blacklist(cfg):
    """Download and strictly parse the public, recent-attack IP list once."""
    blacklist_cfg = cfg.get("blacklist") or {}
    url = blacklist_cfg.get("url")
    if not url:
        raise ValueError("blacklist URL is not configured")
    response = requests.get(
        url, timeout=blacklist_cfg.get("timeout_s", 30),
        headers={"User-Agent": "cesar699-aggregator/1.0"})
    if response.status_code != 200:
        # One request only: do not repeat a rejected or rate-limited list fetch.
        raise RuntimeError(f"blacklist feed HTTP {response.status_code}")
    try:
        text = response.content.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise RuntimeError("blacklist feed is not valid UTF-8") from e
    addresses = set()
    invalid_lines = 0
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith(("#", ";")):
            continue
        try:
            addresses.add(ipaddress.ip_address(value))
        except ValueError:
            invalid_lines += 1
    if invalid_lines:
        raise RuntimeError(f"blacklist feed contains {invalid_lines} non-IP data lines")
    if not addresses:
        raise RuntimeError("blacklist feed is empty; refusing to publish unchecked results")
    meta = {
        "name": blacklist_cfg.get("name", "public IP blacklist"),
        "url": url,
        "checked_at": datetime.now(CST).isoformat(),
        "entries": len(addresses),
        "ip_versions": sorted({address.version for address in addresses}),
        "reporting_window_hours": blacklist_cfg.get("reporting_window_hours"),
        "update_interval_minutes": blacklist_cfg.get("update_interval_minutes"),
        "scope": "IPs reported as attacking blocklist.de or partner systems in the last 48 hours; not a universal abuse blacklist",
    }
    log(f"blacklist loaded: {meta['name']} entries={meta['entries']} versions={meta['ip_versions']}")
    return addresses, meta


def parse_links_text(text):
    """v2ray.txt: plain links, or a single-line base64 blob of links."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines and not any("://" in ln for ln in lines):
        try:
            decoded = b64decode_padded("".join(lines)).decode("utf-8")
            lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
        except Exception:
            pass
    return lines


def normalise_clash_dict(p):
    """Pass a Clash proxy dict through, normalising keys we rely on."""
    d = dict(p)
    t = str(d.get("type", "")).lower()
    if t == "hy2":
        t = "hysteria2"
    d["type"] = t
    if d.get("alpn") is not None:
        d["alpn"] = _alpn_list(d["alpn"])
    if d.get("servername") and not d.get("sni") and t in ("trojan", "hysteria2"):
        d["sni"] = d["servername"]
    if d.get("sni") and not d.get("servername"):
        d["servername"] = d["sni"]
    if d.get("reality-opts") is not None:
        if not isinstance(d["reality-opts"], dict):
            raise ValueError("invalid reality-opts")
        d["reality-opts"] = dict(d["reality-opts"])
        d["reality-opts"]["short-id"] = str(d["reality-opts"].get("short-id") or "")
    d["port"] = int(d["port"])
    check_required(d)
    d.setdefault("name", f"{t}-{d['server']}:{d['port']}")
    return d


def collect_sources(cfg, sources_file=None):
    """Return (proxies, source_reports, counters). Single-source failure
    never fails the run; all failing -> caller exits 2."""
    local_map = None
    if sources_file:
        local_map = json.loads(Path(sources_file).read_text(encoding="utf-8"))
    proxies, reports = [], []
    counters = {"raw": 0, "dropped_ssr": 0, "dropped_unknown": 0, "dropped_bad": 0}
    for src in cfg["sources"]:
        url, kind = src["url"], src.get("kind", "links")
        rep = {"url": url, "fetched": False, "count": 0, "error": None}
        try:
            if local_map is not None and url in local_map:
                text = Path(local_map[url]).read_text(encoding="utf-8")
            else:
                text = fetch_source(url)
            rep["fetched"] = True
        except Exception as e:
            rep["error"] = str(e)[:200]
            log(f"source FAILED: {url} ({rep['error']})")
            reports.append(rep)
            continue
        got = []
        try:
            if kind == "clash":
                # Strip stray control chars (belt & braces for mis-decoded
                # sources) before YAML parsing.
                text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)
                data = yaml.safe_load(text) or {}
                for p in data.get("proxies") or []:
                    if not isinstance(p, dict):
                        continue
                    counters["raw"] += 1
                    if str(p.get("type", "")).lower() in GROUP_TYPES:
                        counters["raw"] -= 1  # groups are not nodes
                        continue
                    if str(p.get("type", "")).lower() == "ssr":
                        counters["dropped_ssr"] += 1
                        continue
                    try:
                        got.append(normalise_clash_dict(p))
                    except Exception:
                        counters["dropped_bad"] += 1
            else:
                for ln in parse_links_text(text):
                    counters["raw"] += 1
                    try:
                        got.append(parse_link(ln))
                    except ValueError as e:
                        msg = str(e)
                        if msg == "ssr-dropped":
                            counters["dropped_ssr"] += 1
                        elif msg.startswith("unknown-scheme"):
                            counters["dropped_unknown"] += 1
                        else:
                            counters["dropped_bad"] += 1
                    except Exception:
                        counters["dropped_bad"] += 1
        except Exception as e:
            rep["error"] = f"parse error: {e}"[:200]
            log(f"source PARSE FAILED: {url} ({rep['error']})")
            reports.append(rep)
            continue
        if kind == "clash":
            pass  # raw already counted per entry above
        rep["count"] = len(got)
        proxies.extend(got)
        reports.append(rep)
        log(f"source ok: {url} -> {len(got)} nodes")
    return proxies, reports, counters


def dedupe(proxies):
    seen, out = {}, []
    for p in proxies:
        identity = p.get("uuid") or p.get("password") or ""
        key = (p["type"], str(p["server"]).lower(), int(p["port"]), identity)
        if key in seen:
            continue
        seen[key] = True
        out.append(p)
    # unique names
    used, counts = set(), {}
    for p in out:
        base = str(p.get("name") or f"{p['type']}-{p['server']}:{p['port']}")
        if base.casefold() in {"auto", "proxy"}:
            base = f"node-{base}"
        if base not in used:
            p["name"] = base
            used.add(base)
            counts[base] = 1
        else:
            n = counts.get(base, 1) + 1
            while f"{base}-{n}" in used:
                n += 1
            p["name"] = f"{base}-{n}"
            used.add(p["name"])
            counts[base] = n
    return out


# ------------------------------------------------------------------ mihomo

def write_mihomo_config(path, proxies):
    names = [p["name"] for p in proxies]
    cfg = {"mixed-port": MIXED_PORT, "allow-lan": False, "mode": "rule",
           "log-level": "warning",
           "external-controller": "127.0.0.1:9090",
           "proxies": proxies,
           "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": names}],
           "rules": ["MATCH,PROXY"]}
    Path(path).write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")


def prevalidate_mihomo_nodes(proxies, workdir):
    """Use Mihomo's own parser to remove only individually invalid proxies."""
    valid = list(proxies)
    rejected = 0
    cfg_path = Path(workdir) / "mihomo-preflight.yaml"
    while valid:
        write_mihomo_config(cfg_path, valid)
        try:
            result = subprocess.run(
                [MIHOMO_BIN, "-d", str(workdir), "-f", str(cfg_path), "-t"],
                capture_output=True, text=True, timeout=120)
        except Exception as e:
            raise RuntimeError(f"Mihomo preflight could not run: {e}")
        output = (result.stdout or "") + (result.stderr or "")
        if "test is successful" in output:
            return valid, rejected
        match = re.search(r"proxy\s+(\d+):", output, flags=re.IGNORECASE)
        if not match:
            raise RuntimeError(f"Mihomo rejected generated proxy config: {output[-500:]}")
        index = int(match.group(1))
        if index < 0 or index >= len(valid):
            raise RuntimeError(f"Mihomo reported invalid proxy index {index} outside the proxy list")
        bad = valid.pop(index)
        rejected += 1
        log(f"mihomo preflight dropped invalid node {bad.get('name', '<unnamed>')!r}; remaining={len(valid)}")
    return valid, rejected


class Mihomo:
    def __init__(self, workdir):
        self.workdir = Path(workdir)
        self.proc = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def start(self, proxies):
        if not proxies:
            raise RuntimeError("no proxies to start mihomo with")
        self.stop()
        cfg_path = self.workdir / "mihomo.yaml"
        write_mihomo_config(cfg_path, proxies)
        self.log_path = self.workdir / "mihomo.log"
        self.log_file = open(self.log_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [MIHOMO_BIN, "-d", str(self.workdir), "-f", str(cfg_path)],
            stdout=self.log_file, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.log_file.flush()
                tail = ""
                try:
                    tail = self.log_path.read_text(
                        encoding="utf-8", errors="replace")[-1000:]
                except Exception:
                    pass
                raise RuntimeError(
                    f"mihomo exited early rc={self.proc.returncode}: "
                    f"{tail.strip()}")
            try:
                r = requests.get(CONTROLLER + "/version", timeout=2)
                if r.status_code == 200:
                    log(f"mihomo up ({r.json().get('version', '?')})")
                    return
            except Exception:
                time.sleep(1)
        raise RuntimeError("mihomo controller did not respond in 30s")

    def stop(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=10)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        if getattr(self, "log_file", None) is not None:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None

    def delay(self, name, url, timeout_ms):
        r = requests.get(f"{CONTROLLER}/proxies/{q(name)}/delay",
                         params={"url": url, "timeout": timeout_ms}, timeout=timeout_ms / 1000 + 10)
        r.raise_for_status()
        return r.json().get("delay")

    def select(self, name):
        r = requests.put(CONTROLLER + "/proxies/PROXY", json={"name": name}, timeout=10)
        r.raise_for_status()


def liveness_test(mihomo, proxies, cfg):
    """Both test URLs must return delay <= max_latency_ms. Returns
    list of (proxy, latency_ms) sorted by latency."""
    t = cfg["test_urls"]
    max_ms = cfg["max_latency_ms"]

    def check(p):
        try:
            d1 = mihomo.delay(p["name"], t["google_204"], max_ms)
            if d1 is None or d1 > max_ms:
                return None
            d2 = mihomo.delay(p["name"], t["youtube_static"], max_ms)
            if d2 is None or d2 > max_ms:
                return None
            return (p, max(int(d1), int(d2)))
        except Exception:
            return None

    alive = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(check, p): p for p in proxies}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                alive.append(res)
    alive.sort(key=lambda x: x[1])
    return alive

# ------------------------------------------------------------------- purity

class PurityChecker:
    """Per-node exit-IP + unlock probes, all traffic via the local
    Mihomo mixed port (the selected node is the exit)."""

    def __init__(self, cfg, blacklist_ips=None, blacklist_meta=None):
        self.cfg = cfg
        self.proxies = {"http": f"http://127.0.0.1:{MIXED_PORT}",
                        "https": f"http://127.0.0.1:{MIXED_PORT}"}
        self.blacklist_ips = set(blacklist_ips or ())
        self.blacklist_meta = blacklist_meta or {}
        self.ip_cache = {}
        self.ip_lock = threading.Lock()
        self.last_ip_call = 0.0
        self.min_interval = float(cfg.get("exit_ip_min_interval_s", 1.6))
        self.api_blocked_reason = None

    def _rate_limited_ip_api(self):
        if self.api_blocked_reason:
            raise RuntimeError(f"IPQuery disabled after {self.api_blocked_reason}")
        with self.ip_lock:
            wait = self.min_interval - (time.time() - self.last_ip_call)
            if wait > 0:
                time.sleep(wait)
            self.last_ip_call = time.time()
        r = requests.get(self.cfg["exit_ip_url"], proxies=self.proxies,
                         timeout=self.cfg.get("exit_ip_timeout_s", 5))
        if r.status_code != 200:
            self.api_blocked_reason = f"IPQuery HTTP {r.status_code}"
            raise RuntimeError(self.api_blocked_reason)
        r.raise_for_status()
        try:
            data = r.json()
        except Exception as e:
            self.api_blocked_reason = "IPQuery returned invalid JSON"
            raise RuntimeError(self.api_blocked_reason) from e
        if not isinstance(data, dict):
            self.api_blocked_reason = "IPQuery returned a non-object response"
            raise ValueError("IPQuery returned a non-object response")
        return data

    def exit_info(self):
        """Return IPQuery info only for a valid public exit IP."""
        info = self._rate_limited_ip_api()
        ip = info.get("ip")
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        if not address.is_global:
            return None
        with self.ip_lock:
            if ip in self.ip_cache:
                return self.ip_cache[ip]
            self.ip_cache[ip] = info
            return info

    def _probe(self, url):
        try:
            r = requests.get(url, proxies=self.proxies,
                             timeout=self.cfg.get("probe_timeout_s", 8))
            return r
        except Exception:
            return None

    def netflix(self):
        r = self._probe(self.cfg["netflix_url"])
        if r is None:
            return "unknown"
        body = r.text.lower()
        # "yes" only when we actually land on the title page. The old
        # check also accepted "watch" anywhere in the body, which appears
        # in Netflix nav/footer even on region-block pages (false "yes").
        if r.status_code == 200 and "/title/" in r.url:
            return "yes"
        if r.status_code in (403, 404) or "not available" in body or "nses-" in body:
            return "no"
        return "unknown"

    def chatgpt(self):
        r = self._probe(self.cfg["chatgpt_url"])
        if r is None:
            return "unknown"
        body = r.text.lower()
        if r.status_code == 200:
            return "yes"
        if r.status_code == 403 or "unsupported country" in body or \
                "not available in your country" in body:
            return "no"
        return "unknown"

    def check(self, mihomo, proxy, latency_ms):
        """Return a report row, or None when exit or required reputation data is unusable.
        A blacklist match is reported but does not itself drop the node."""
        try:
            mihomo.select(proxy["name"])
        except Exception:
            return None
        try:
            info = self.exit_info()
        except Exception:
            return None
        if info is None:
            return None
        risk = info.get("risk") if isinstance(info.get("risk"), dict) else {}
        isp = info.get("isp") if isinstance(info.get("isp"), dict) else {}
        location = info.get("location") if isinstance(info.get("location"), dict) else {}
        risk_bool_fields = ("is_datacenter", "is_mobile", "is_proxy", "is_vpn", "is_tor")
        if any(type(risk.get(field)) is not bool for field in risk_bool_fields):
            return None
        risk_score = risk.get("risk_score")
        if not isinstance(risk_score, int) or isinstance(risk_score, bool) or not 0 <= risk_score <= 100:
            return None
        datacenter = risk.get("is_datacenter")
        mobile = risk.get("is_mobile")
        if datacenter is True:
            network_type = "datacenter"
            residential = False
        elif mobile is True:
            network_type = "mobile"
            residential = None
        elif datacenter is False:
            network_type = "likely-residential"
            residential = True
        else:
            network_type = "unknown"
            residential = None
        risk_flags = [name for name, value in (
            ("proxy", risk.get("is_proxy")),
            ("vpn", risk.get("is_vpn")),
            ("tor", risk.get("is_tor")),
        ) if value is True]
        public_risk_flag = bool(risk_flags)
        exit_address = ipaddress.ip_address(str(info["ip"]).strip())
        covered_versions = self.blacklist_meta.get("ip_versions", [])
        if exit_address.version in covered_versions:
            blacklist_flag = exit_address in self.blacklist_ips
            blacklist_status = "match" if blacklist_flag else "no_match"
        else:
            blacklist_flag = None
            blacklist_status = "ip_version_not_covered"
        with ThreadPoolExecutor(max_workers=2) as ex:
            netflix_future = ex.submit(self.netflix)
            chatgpt_future = ex.submit(self.chatgpt)
            netflix_result = netflix_future.result()
            chatgpt_result = chatgpt_future.result()
        return {
            "name": proxy["name"], "protocol": proxy["type"],
            "server": proxy["server"], "port": int(proxy["port"]),
            "latency_ms": latency_ms,
            "exit_ip": str(info.get("ip")), "country": location.get("country"),
            "countryCode": location.get("country_code"), "asn": isp.get("asn"),
            "org": isp.get("org"), "isp": isp.get("isp"),
            "hosting": datacenter, "datacenter": datacenter,
            "residential": residential, "mobile": mobile,
            "network_type": network_type,
            "proxy_flag": risk.get("is_proxy"),
            "vpn_flag": risk.get("is_vpn"), "tor_flag": risk.get("is_tor"),
            "public_risk_flags": risk_flags,
            "public_risk_flag": public_risk_flag,
            "blacklist_flag": blacklist_flag,
            "blacklist_status": blacklist_status,
            "blacklist_source": self.blacklist_meta.get("name"),
            "blacklist_checked_at": self.blacklist_meta.get("checked_at"),
            "risk_score": risk_score,
            "netflix": netflix_result, "chatgpt": chatgpt_result,
        }


def purity_check(mihomo, kept, cfg, blacklist_ips=None, blacklist_meta=None):
    """kept: list of (proxy, latency_ms). Returns nodes, drops and API stop reason.

    NOTE: Mihomo's selected proxy is global state, so checks run serially.
    IPQuery requests are paced; a rejected response stops further lookups.
    """
    checker = PurityChecker(cfg, blacklist_ips, blacklist_meta)
    nodes, dropped = [], 0
    for i, (proxy, lat) in enumerate(kept, 1):
        if checker.api_blocked_reason:
            remaining = len(kept) - i + 1
            dropped += remaining
            log(f"purity stopped after {checker.api_blocked_reason}; excluded remaining={remaining}")
            break
        res = checker.check(mihomo, proxy, lat)
        if res is None:
            dropped += 1
        else:
            nodes.append(res)
        if i % 25 == 0:
            log(f"purity progress: {i}/{len(kept)} checked, {len(nodes)} kept")
    nodes.sort(key=lambda n: (n["latency_ms"] is None, n["latency_ms"] or 0))
    return nodes, dropped, checker.api_blocked_reason


# ------------------------------------------------------------------ outputs

def build_outputs(proxies_sorted, nodes, out_dir, cfg, source_reports, counts, gate, enrichment=None):
    """proxies_sorted: [(proxy, latency)] in final order (== nodes order).
    nodes: purity report rows (same order)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    names = [p["name"] for p, _ in proxies_sorted]

    clash = {"mixed-port": MIXED_PORT, "allow-lan": False, "mode": "rule",
             "log-level": "info",
             "proxies": [p for p, _ in proxies_sorted],
             "proxy-groups": [
                 {"name": "auto", "type": "url-test",
                  "url": cfg["test_urls"]["google_204"], "interval": 300,
                  "proxies": names},
                 {"name": "PROXY", "type": "select",
                  "proxies": ["auto"] + names}],
             "rules": ["MATCH,PROXY"]}
    (out_dir / "clash.yaml").write_text(
        yaml.safe_dump(clash, allow_unicode=True, sort_keys=False), encoding="utf-8")

    links = []
    for p, _ in proxies_sorted:
        try:
            links.append(build_link(p))
        except Exception as e:
            raise RuntimeError(f"V2Ray link conversion failed for {p['name']}: {e}")
    if len(links) != len(proxies_sorted):
        raise RuntimeError("V2Ray output count does not match kept nodes")
    (out_dir / "v2ray.txt").write_text(
        b64encode_std("\n".join(links).encode()), encoding="utf-8")

    outbounds = []
    for p, _ in proxies_sorted:
        try:
            outbounds.append(clash_to_singbox(p))
        except Exception as e:
            raise RuntimeError(f"Sing-box conversion failed for {p['name']}: {e}")
    if len(outbounds) != len(proxies_sorted):
        raise RuntimeError("Sing-box output count does not match kept nodes")
    outbounds.append({"type": "selector", "tag": "PROXY",
                      "outbounds": names, "default": names[0] if names else ""})
    # NOTE: sing-box has no top-level "version" field; adding one makes
    # `sing-box check` reject the whole file ("unknown field version").
    singbox = {"outbounds": outbounds,
               "route": {"final": "PROXY"}}
    (out_dir / "singbox.json").write_text(
        json.dumps(singbox, ensure_ascii=False, indent=2), encoding="utf-8")

    report = {
        "generated_at": datetime.now(CST).isoformat(),
        "sources": source_reports,
        "enrichment": enrichment or {},
        "counts": counts,
        "gate": gate,
        "nodes": nodes,
    }
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


# --------------------------------------------------------------------- gist

def gist_update(out_dir, cfg):
    """Gate + single PATCH. Returns exit code (0 ok, 3 gate, 4 api fail)."""
    if os.environ.get("AGGREGATOR_LOCAL_TEST"):
        log("GIST SKIP: local test mode never publishes unverified or incomplete results")
        return 0
    token = os.environ.get("GIST_PAT") or os.environ.get("PUSH_TOKEN")
    gist_id = os.environ.get("GIST_ID")
    if not token or not gist_id:
        # Fail closed: silently "succeeding" while publishing nothing hides
        # a broken setup and never trips the consecutive-failure alert.
        log("GIST FAIL: GIST_PAT/PUSH_TOKEN or GIST_ID not set")
        return 4
    out_dir = Path(out_dir)
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    kept = report["counts"]["kept"]

    prev_kept = None
    try:
        r = requests.get(f"https://api.github.com/gists/{gist_id}",
                         headers={"Authorization": f"Bearer {token}",
                                  "Accept": "application/vnd.github+json"},
                         timeout=30)
        r.raise_for_status()
        files = r.json().get("files") or {}
        prev = files.get("report.json")
        if prev:
            content = prev.get("content")
            if not content and prev.get("raw_url"):
                previous_response = requests.get(prev["raw_url"], timeout=30)
                previous_response.raise_for_status()
                content = previous_response.text
            if not content:
                raise ValueError("previous report exists but cannot be read")
            previous_report = json.loads(content)
            previous_counts = previous_report.get("counts")
            if previous_counts is not None:
                if not isinstance(previous_counts, dict) or not isinstance(previous_counts.get("kept"), int):
                    raise ValueError("previous report has invalid counts.kept")
                prev_kept = previous_counts["kept"]
            elif previous_report:
                raise ValueError("previous report is not a recognized placeholder or report")
    except Exception as e:
        log(f"GIST FAIL: cannot safely read previous result; Gist NOT updated ({e})")
        return 4

    half_previous = (prev_kept + 1) // 2 if prev_kept is not None else 0
    min_required = max(cfg["min_keep"], half_previous)
    passed = kept >= min_required
    report["gate"] = {"prev_kept": prev_kept, "min_required": min_required,
                      "passed": passed}
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if not passed:
        log(f"GATE FAIL: kept={kept} prev_kept={prev_kept} "
            f"min_required={min_required} -> Gist NOT updated")
        return 3

    payload = {"files": {}}
    for fn in cfg["gist_filenames"]:
        payload["files"][fn] = {"content": (out_dir / fn).read_text(encoding="utf-8")}
    try:
        r = requests.patch(f"https://api.github.com/gists/{gist_id}",
                           headers={"Authorization": f"Bearer {token}",
                                    "Accept": "application/vnd.github+json"},
                           json=payload, timeout=60)
        r.raise_for_status()
        updated_files = (r.json().get("files") or {})
        missing = [fn for fn in cfg["gist_filenames"] if fn not in updated_files]
        if missing:
            raise RuntimeError(f"Gist response missing updated files: {missing}")
    except Exception as e:
        log(f"GIST FAIL: PATCH failed ({e}); no partial update was made")
        return 4
    log(f"GIST OK: updated gist {gist_id} ({kept} nodes)")
    return 0


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Free-nodes aggregation pipeline")
    ap.add_argument("--limit", type=int, default=0, help="cap deduped nodes (testing)")
    ap.add_argument("--skip-mihomo", action="store_true")
    ap.add_argument("--skip-purity", action="store_true")
    ap.add_argument("--out", default="out")
    ap.add_argument("--sources-file", default=None,
                    help="JSON mapping source URL -> local file (offline testing)")
    args = ap.parse_args()

    cfg = load_config()
    proxies, reports, counters = collect_sources(cfg, args.sources_file)
    if not any(r["fetched"] for r in reports):
        log("FATAL: all sources failed")
        return 2
    deduped = dedupe(proxies)
    if not deduped:
        log("FATAL: sources returned no valid supported nodes")
        return 2
    if args.limit:
        deduped = deduped[: args.limit]
    deduped_source_count = len(deduped)
    if (args.skip_mihomo or args.skip_purity) and not os.environ.get("AGGREGATOR_LOCAL_TEST"):
        log("FATAL: --skip-mihomo/--skip-purity are allowed only in AGGREGATOR_LOCAL_TEST mode")
        return 2
    log(f"counts: raw={counters['raw']} deduped={len(deduped)} "
        f"dropped_ssr={counters['dropped_ssr']} "
        f"dropped_unknown={counters['dropped_unknown']} "
        f"dropped_bad={counters['dropped_bad']}")

    kept, nodes = [], []
    dropped_purity_check = 0
    dropped_mihomo_invalid = 0
    purity_provider_blocked = None
    blacklist_meta = None
    alive_count = 0
    if args.skip_mihomo:
        kept = [(p, None) for p in deduped]
        alive_count = len(deduped)
        log("SKIP-MIHOMO: treating deduped nodes as kept (latency null)")
    else:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with Mihomo(td) as m:
                deduped, dropped_mihomo_invalid = prevalidate_mihomo_nodes(deduped, td)
                log(f"mihomo preflight: invalid_nodes_dropped={dropped_mihomo_invalid} valid={len(deduped)}")
                if not deduped:
                    log("FATAL: Mihomo preflight rejected every node")
                    return 3
                m.start(deduped)
                alive = liveness_test(m, deduped, cfg)
                log(f"liveness: alive={len(alive)} / {len(deduped)}")
                alive_count = len(alive)
                kept = alive[: cfg["max_keep"]]
                if not kept:
                    log("FATAL: no alive nodes after liveness test")
                    return 3
                if args.skip_purity:
                    nodes = [{"name": p["name"], "protocol": p["type"],
                              "server": p["server"], "port": int(p["port"]),
                              "latency_ms": lat, "exit_ip": None,
                              "country": None, "countryCode": None, "asn": None,
                              "org": None, "isp": None, "hosting": None,
                              "network_type": "unknown", "proxy_flag": None,
                              "netflix": "unknown", "chatgpt": "unknown"}
                             for p, lat in kept]
                else:
                    try:
                        blacklist_ips, blacklist_meta = fetch_blacklist(cfg)
                    except Exception as e:
                        log(f"FATAL: required blacklist check unavailable; Gist NOT updated ({type(e).__name__}: {e})")
                        return 4
                    m.start([p for p, _ in kept])  # restart with kept only
                    nodes, dropped_purity_check, purity_provider_blocked = purity_check(
                        m, kept, cfg, blacklist_ips, blacklist_meta)
                    kept = [(p, lat) for (p, lat) in kept
                            if any(n["name"] == p["name"] for n in nodes)]
                    log(f"purity: kept={len(nodes)} dropped_purity_check={dropped_purity_check}")
    if args.skip_mihomo and args.skip_purity:
        nodes = [{"name": p["name"], "protocol": p["type"],
                  "server": p["server"], "port": int(p["port"]),
                  "latency_ms": None, "exit_ip": None,
                  "country": None, "countryCode": None, "asn": None,
                  "org": None, "isp": None, "hosting": None,
                  "network_type": "unknown", "proxy_flag": None,
                  "netflix": "unknown", "chatgpt": "unknown"}
                 for p, _ in kept]

    # final order = nodes order (latency-sorted); kept pairs follow nodes
    node_by_name = {n["name"]: n for n in nodes}
    kept = [(p, lat) for (p, lat) in kept if p["name"] in node_by_name]
    kept.sort(key=lambda x: (node_by_name[x[0]["name"]]["latency_ms"] is None,
                             node_by_name[x[0]["name"]]["latency_ms"] or 0))
    nodes = [node_by_name[p["name"]] for p, _ in kept]

    counts = {"raw": counters["raw"], "deduped": deduped_source_count,
              "alive": alive_count,
              "kept": len(kept), "dropped_purity_check": dropped_purity_check,
              "dropped_mihomo_invalid": dropped_mihomo_invalid,
              "purity_provider_blocked": purity_provider_blocked,
              "dropped_ssr": counters["dropped_ssr"]}
    gate = {"prev_kept": None, "min_required": cfg["min_keep"], "passed": None}
    enrichment = {
        "ip_reputation": {"provider": "IPQuery", "url": cfg["exit_ip_url"]},
        "blacklist": blacklist_meta,
    }
    build_outputs(kept, nodes, args.out, cfg, reports, counts, gate, enrichment)

    # internal validation
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import validate as _v
        mihomo_bin = os.environ.get("MIHOMO_BIN") or str(REPO_ROOT / "clash" / "clash-linux-amd")
        singbox_bin = os.environ.get("SINGBOX_BIN")
        if _v.validate_dir(Path(args.out),
                           mihomo_bin if Path(mihomo_bin).exists() else None,
                           singbox_bin if singbox_bin and Path(singbox_bin).exists() else None) != 0:
            return 5
    except ImportError as e:
        log(f"FATAL: required output validator not importable: {e}")
        return 5

    rc = gist_update(args.out, cfg)
    log(f"SUMMARY: raw={counts['raw']} deduped={counts['deduped']} "
        f"alive={counts['alive']} kept={counts['kept']} "
        f"dropped_purity_check={dropped_purity_check} "
        f"dropped_ssr={counts['dropped_ssr']} gist_rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
