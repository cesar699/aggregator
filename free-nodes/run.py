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
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
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
    if not d.get("server") or not d.get("port"):
        raise ValueError("missing server/port")
    return d


# ------------------------------------------------------- clash dict -> link

def _enc_name(name):
    return urllib.parse.quote(str(name), safe="")


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


def build_vless(d):
    p = {"encryption": "none", "security": "tls" if d.get("tls") else "none"}
    p.update(_ws_params(d))
    if d.get("servername"):
        p["sni"] = d["servername"]
    if d.get("client-fingerprint"):
        p["fp"] = d["client-fingerprint"]
    if d.get("flow"):
        p["flow"] = d["flow"]
    return ("vless://" + d["uuid"] + "@" + d["server"] + ":" + str(d["port"]) +
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
            d["server"] + ":" + str(d["port"]) + qs + "#" + _enc_name(d["name"]))


def build_ss(d):
    user = b64encode_nopad((d["cipher"] + ":" + d["password"]).encode())
    return ("ss://" + user + "@" + d["server"] + ":" + str(d["port"]) +
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
            d["server"] + ":" + str(d["port"]) + qs + "#" + _enc_name(d["name"]))


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
        if d.get("flow"):
            ob["flow"] = d["flow"]
    elif t == "vmess":
        ob["type"] = "vmess"
        ob["uuid"] = d["uuid"]
        ob["alter_id"] = int(d.get("alterId", 0) or 0)
        ob["security"] = d.get("cipher", "auto")
    elif t == "trojan":
        ob["type"] = "trojan"
        ob["password"] = d["password"]
    elif t == "ss":
        ob["type"] = "shadowsocks"
        ob["method"] = d["cipher"]
        ob["password"] = d["password"]
    elif t == "hysteria2":
        ob["type"] = "hysteria2"
        ob["password"] = d["password"]
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
        except Exception as e:
            last = e
            time.sleep(2)
    raise last


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
    d["port"] = int(d["port"])
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
    """Both test URLs must return delay < max_latency_ms. Returns
    list of (proxy, latency_ms) sorted by latency."""
    t = cfg["test_urls"]
    max_ms = cfg["max_latency_ms"]

    def check(p):
        try:
            d1 = mihomo.delay(p["name"], t["google_204"], max_ms)
            if d1 is None or d1 >= max_ms:
                return None
            d2 = mihomo.delay(p["name"], t["youtube_static"], max_ms)
            if d2 is None or d2 >= max_ms:
                return None
            return (p, int(d1))
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

    def __init__(self, cfg):
        self.cfg = cfg
        self.proxies = {"http": f"http://127.0.0.1:{MIXED_PORT}",
                        "https": f"http://127.0.0.1:{MIXED_PORT}"}
        self.ip_cache = {}
        self.ip_lock = threading.Lock()
        self.last_ip_call = 0.0
        self.min_interval = float(cfg.get("ip_api_min_interval_s", 1.6))

    def _rate_limited_ip_api(self):
        with self.ip_lock:
            wait = self.min_interval - (time.time() - self.last_ip_call)
            if wait > 0:
                time.sleep(wait)
            self.last_ip_call = time.time()
        r = requests.get(self.cfg["ip_api_url"], proxies=self.proxies,
                         timeout=self.cfg.get("probe_timeout_s", 8))
        r.raise_for_status()
        return r.json()

    def exit_info(self):
        """Cached by exit IP. Returns dict or None (unresolvable)."""
        info = self._rate_limited_ip_api()
        if info.get("status") != "success" or not info.get("query"):
            return None
        ip = info["query"]
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
        if r.status_code == 200 and ("/title/" in r.url or "watch" in body):
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
        """Returns node report dict, or None if exit IP unresolvable
        (node is dropped). Only a missing exit IP drops a node."""
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
        hosting = bool(info.get("hosting"))
        return {
            "name": proxy["name"], "protocol": proxy["type"],
            "server": proxy["server"], "port": int(proxy["port"]),
            "latency_ms": latency_ms,
            "exit_ip": info.get("query"), "country": info.get("country"),
            "countryCode": info.get("countryCode"), "asn": info.get("as"),
            "org": info.get("org"), "isp": info.get("isp"),
            "hosting": hosting,
            "network_type": "datacenter" if hosting else "likely-residential",
            "proxy_flag": bool(info.get("proxy")),
            "netflix": self.netflix(), "chatgpt": self.chatgpt(),
        }


def purity_check(mihomo, kept, cfg):
    """kept: list of (proxy, latency_ms). Returns (nodes, dropped_no_exit).

    NOTE: Mihomo's selected proxy is global state (one mixed port), so
    nodes are checked strictly one at a time. ip-api is additionally
    rate-limited to ~1 call / 1.6s and cached by exit IP, so a full
    200-node run typically takes a few minutes, worst case ~15 min.
    """
    checker = PurityChecker(cfg)
    nodes, dropped = [], 0
    for i, (proxy, lat) in enumerate(kept, 1):
        res = checker.check(mihomo, proxy, lat)
        if res is None:
            dropped += 1
        else:
            nodes.append(res)
        if i % 25 == 0:
            log(f"purity progress: {i}/{len(kept)} checked, {len(nodes)} kept")
    nodes.sort(key=lambda n: (n["latency_ms"] is None, n["latency_ms"] or 0))
    return nodes, dropped


# ------------------------------------------------------------------ outputs

def build_outputs(proxies_sorted, nodes, out_dir, cfg, source_reports, counts, gate):
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
            log(f"link build skipped for {p['name']}: {e}")
    (out_dir / "v2ray.txt").write_text(
        b64encode_std("\n".join(links).encode()), encoding="utf-8")

    outbounds = []
    for p, _ in proxies_sorted:
        try:
            outbounds.append(clash_to_singbox(p))
        except Exception as e:
            log(f"sing-box build skipped for {p['name']}: {e}")
    outbounds.append({"type": "selector", "tag": "PROXY",
                      "outbounds": names, "default": names[0] if names else ""})
    singbox = {"version": 2, "outbounds": outbounds,
               "route": {"final": "PROXY"}}
    (out_dir / "singbox.json").write_text(
        json.dumps(singbox, ensure_ascii=False, indent=2), encoding="utf-8")

    report = {
        "generated_at": datetime.now(CST).isoformat(),
        "sources": source_reports,
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
    token = os.environ.get("GIST_PAT") or os.environ.get("PUSH_TOKEN")
    gist_id = os.environ.get("GIST_ID")
    if not token or not gist_id:
        log("GIST SKIP: GIST_PAT/PUSH_TOKEN or GIST_ID not set; outputs kept locally")
        return 0
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
        prev = files.get("report.json") or {}
        content = prev.get("content")
        if not content and prev.get("raw_url"):
            content = requests.get(prev["raw_url"], timeout=30).text
        if content:
            prev_kept = json.loads(content)["counts"]["kept"]
    except Exception as e:
        log(f"GIST WARN: could not read previous report ({e}); gate uses min_keep only")

    min_required = max(cfg["min_keep"], (prev_kept // 2) if prev_kept else 0)
    passed = kept >= cfg["min_keep"] and (prev_kept is None or kept >= prev_kept // 2)
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
    if args.limit:
        deduped = deduped[: args.limit]
    log(f"counts: raw={counters['raw']} deduped={len(deduped)} "
        f"dropped_ssr={counters['dropped_ssr']} "
        f"dropped_unknown={counters['dropped_unknown']} "
        f"dropped_bad={counters['dropped_bad']}")

    kept, nodes = [], []
    dropped_no_exit = 0
    if args.skip_mihomo:
        kept = [(p, None) for p in deduped]
        log("SKIP-MIHOMO: treating deduped nodes as kept (latency null)")
    else:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with Mihomo(td) as m:
                m.start(deduped)
                alive = liveness_test(m, deduped, cfg)
                log(f"liveness: alive={len(alive)} / {len(deduped)}")
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
                    m.start([p for p, _ in kept])  # restart with kept only
                    nodes, dropped_no_exit = purity_check(m, kept, cfg)
                    kept = [(p, lat) for (p, lat) in kept
                            if any(n["name"] == p["name"] for n in nodes)]
                    log(f"purity: kept={len(nodes)} dropped_no_exit_ip={dropped_no_exit}")
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

    counts = {"raw": counters["raw"], "deduped": len(deduped),
              "alive": len(kept) if not args.skip_mihomo else len(deduped),
              "kept": len(kept), "dropped_no_exit_ip": dropped_no_exit,
              "dropped_ssr": counters["dropped_ssr"]}
    gate = {"prev_kept": None, "min_required": cfg["min_keep"], "passed": None}
    build_outputs(kept, nodes, args.out, cfg, reports, counts, gate)

    # internal validation
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import validate as _v
        if _v.validate_dir(Path(args.out)) != 0:
            return 5
    except ImportError:
        log("validate.py not importable; skipping internal validation")

    rc = gist_update(args.out, cfg)
    log(f"SUMMARY: raw={counts['raw']} deduped={counts['deduped']} "
        f"alive={counts['alive']} kept={counts['kept']} "
        f"dropped_no_exit_ip={dropped_no_exit} "
        f"dropped_ssr={counts['dropped_ssr']} gist_rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
