#!/usr/bin/env python3
"""
VPN Gate SSTP èç¹æ£æµæµæ°´çº¿
============================
æµç¨:
  1. è·å VPN Gate åå§èç¹ (å®æ¹ api/iphone CSV, å¤±è´¥æ¶åé GitHub é¢è§£æéå)
  2. åªä¿çãå¸¦ TCP å¥å£ãçä¸­ç»§ = SSTP å¯ç¨èç¹
     (OpenVPN éç½®é proto tcp + remote <ip> <port>; UDP-only ä¸­ç»§æ æ³èµ° SSTP/xray é¾, ç´æ¥ä¸¢å¼)
  3. æ host+port+protocol å»é
  4. å¹¶åè°ç¨å·²é¨ç½²ç Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (åèç¹ HTTP æå != èç¹å¯ç¨; ä»¥ Worker h¿å JSON ç success å­æ®µä¸ºå)
  5. ä¿ç success=true çèç¹, æå½å®¶åç», çæ public/data.json + public/index.html
  6. ç½é¡µç«¯ (GitHub Pages) è¯»å data.json å±ç¤º

éåºç :
  0 = æ­£å¸¸å®æ (åè®¸é¨åèç¹æ£æµå¤±è´¥)
  1 = ç¡¬æ§å¤±è´¥ (æ°æ®æºå¨æ / è§£æä¸åº SSTP èç¹ / Worker å®å¨ä¸å¯è¾¾ / ç¨åºå¼å¸¸)
     è¿äºæåµç»ä¸åè®¸"åæå"
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requestsip(),
        })
    return rows


# ---------------------------------------------------------------------------
# ç¬¬ 2 æ­¥: ç­é SSTP èç¹ (åªä¿çå¸¦ TCP å¥å£çä¸­ç»§)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    """æåå§è¡è½¬æ SSTP èç¹: è§£ç  OpenVPN éç½®, ä»ä¿ç proto tcp + remote ç«¯å£ã
    host ç»ä¸ä¸º <short>.opengw.net å½¢å¼; è¿åå»éåçèç¹åè¡¨ã"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # æ  TCP å¥å£ -> ä¸æ¯ SSTP å¯ç¨èç¹, ä¸¢å¼
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    """æ host+port+protocol å»éã"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# ç¬¬ 3 æ­¥: å¹¶åè°ç¨ Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """ä½å®/æºæ¿åç±», æå¯ä¿¡åº¦æåº:
    1) Worker è¿åççå® is_datacenter æ å¿ (IP ææ¥åº);
    2) åºå£ ASN ç»ç»åå³é®è¯;
    3) host åç¼å¯åå¼ (æåååº, å±ä¼°ç®)ã"""
    # 1) çå®æ°æ®ä¸­å¿æ å¿ (SSTP ç Worker é¡¶å± exit ç´æ¥ç»åº)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) åºå£ç»ç»åå³é®è¯
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host åç¼å¯åå¼ (ä¼°ç®)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate å®æ¹å¬å±ä¸­ç»§ (æºæ¿/æç®¡)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # æ°å­ç¼å· = æ³¨åçå®¶ç¨å®½å¸¦ä¸­ç»§ (å®¶å®½, ä¼°ç®)
    return "unknown"


def check_one(node, session):
    """è°ç¨ Worker æ£æµåèç¹ãè¿åèç¹+æ£æµç»æçåå¹¶ dictã
    åèç¹å¤±è´¥ (ç½ç»éè¯¯/é 200/å JSON) ä¸ä¼æåº, ç»ä¸è®° success=Falseã"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP ç Worker: é¡¶å±ç´æ¥è¿å exit, å«çå® is_datacenter æ å¿ + åµå¥ asn å¯¹è±¡
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    """32 å¹¶å (ä¸ç½é¡µç«¯ä¸è´)ãåèç¹å¤±è´¥ä¸å½±åæ´ä½; ä½åºå'èç¹ä¸å¯ç¨'ä¸'Worker å¼å¸¸'ã"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# ç¬¬ 4 æ­¥: çæç½é¡µæ°æ®
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "æªç¥"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", "https://huazi688.github.io/gate/chains.txt")


def build_chains_text(data):
    """çæ edgetunnel é¾å¼ä»£çæ¸å: æå½å®¶åç», æ¯å½ç¼å·åºå®, ä½å®ä¼å, å»¶è¿ååºã
    æ¯è¡ = ãåå­ + $sstp://vpn:vpn@host:portã, åå­ä¸å, æä»¤æ¯ 30 åéèªå¨æ¢ã"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP èç¹ -> edgetunnel é¾å¼ä»£çæ¸å",
        f"# èªå¨æ´æ°: {data['generated_at']} (æ¯ 30 åééæ°æ£æµ)",
        f"# åºå®å°å: {CHAIN_URL}",
        "#",
        "# ç¨æ³: å¨ edgetunnel èç¹å¤æ³¨éç´æ¥ç²è´´ä¸é¢ä»»æä¸è¡ (åå­ä¸æä»¤è¿å)",
        "#   ä¾: æ¥æ¬-ä½å®-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# åå­ä¿æä¸å, åªæ $sstp:// åé¢çå°åæ¯ 30 åéèªå¨æ´æ¢",
        "# è´¦å·å¯ç åºå® vpn:vpn ; ç«¯å£å¿é¡»ä¿ç",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms) or 0,
                nn["host"] or "",
             ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} Â· {grp['count']} èç¹ (ä½å® {grp['residential']} / æºæ¿ {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-ä½å®-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-æºæ¿-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel å¥å£å°åæ± : å®¢æ·ç«¯ç´è¿ Cloudflare çä¼é IP:ç«¯å£ (å¾ªç¯åéç»æ¯ä¸ªå½å®¶èç¹å½å¥å£)
# å¯éè¿ç¯å¢åé EDGE_HOSTS è¦ç (éå·åé)
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "www.5199dy.com:443,hzytjy.cn:443,ali.nonull.pp.ua:443,auto.dolby.dpdns.org:443,"
        "cdn.cnno.de:443,saas.sin.fan:443,cf.1o.ee:443",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", "https://huazi688.github.io/gate/hosts.txt")


def build_hosts_text(data):
    """çæå¯ç´æ¥ç²è´´å° edgetunnel åå°ãèªå®ä¹ä¼éIPãæ¡çæ¸åã
    æ¯è¡ = å¥å£å°å#åå­$sstp://... ; åå­åºå®, åºä¸ SSTP èç¹æ¯ 30 åéèªå¨æ¢ã"""
    countries = data["countries"]
    # å¥å£: é»è®¤ç¨ 7 ä¸ªå®æµå¯ç¨ä¼éååå¾ªç¯åé; å¯ç¨ HOSTS_ENTRY è¦ç(éå·åé)
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    lines = [
        "# edgetunnelãèªå®ä¹ä¼éIPãæ¸å (æ´æ®µå¤å¶, è¿½å å°åå°ç°æåå®¹åé¢)",
        f"# èªå¨æ´æ°: {data['generated_at']} (æ¯ 30 åééæ°æ£æµ)",
        f"# åºå®å°å: {HOSTS_URL}",
        "# æ¯è¡ = å¥å£å°å#åå­$sstp://vpn:vpn@èç¹:ç«¯å£",
        "# å¥å£ç¨ 7 ä¸ªå®æµå¯ç¨ä¼éååå¾ªç¯åé",
        "# åå­ = å½å®¶-ä½å®/æºæ¿-ç¼å·, ç´æ¥åºåä½å®ä¸æºæ¿",
        "# åå­åºå®; åªæ $sstp:// åé¢çèç¹å°åæ¯ 30 åéèªå¨æ´æ¢",
        "# è´¦å·å¯ç åºå® vpn:vpn ; èç¹ç«¯å£å¿é¡»ä¿ç",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} Â· {grp['count']} èç¹ (ä½å® {grp['residential']} / æºæ¿ {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-ä½å®-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-æºæ¿-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel å®æ´è®¢é (vless://) éç½®
EDT_UUID = os.environ.get("EDT_UUID", "1948efb3-4efc-4e29-8926-983ab06e582a")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "edgetunnel.hua330818481.workers.dev")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", "https://huazi688.github.io/gate/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """å¤å» edgetunnel ç base64SecretEncode: UTF-8 å¾ªç¯å¯é¥ XOR + æ å base64ã"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """å¤å» edgetunnel ç è·åSOCKS5è´¦å·: user:pass@host:port -> {username,password,hostname,port}ã"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """çæ edgetunnel å®æ´ vless:// è®¢é (é¾å¼ä»£çç¼ç å¨ path)ã
    å¡«è¿ edgetunnel åå°ãè®¢éé¾æ¥ãURL, å®¢æ·ç«¯å®æ¶æåå³å¯èªå¨è½®æ¢ã"""
    countries = data["countries"]
    lines = [
        "# edgetunnel å®æ´è®¢é (vless://) ââ å¡«è¿åå°ãè®¢éé¾æ¥ãURL",
        f"# èªå¨æ´æ°: {data['generated_at']} (æ¯ 30 åééæ°æ£æµ)",
        f"# åºå®å°å: {SUB_URL}",
        f"# èç¹åå: {EDT_DOMAIN} (ä¼ è¾ ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# åå­åºå®; $sstp:// é¾å¼ä»£ç(ç¼ç å¨ path)æ¯ 30 åéèªå¨æ´æ¢",
        "# è´¦å·å¯ç åºå® vpn:vpn ; èç¹ç«¯å£å·²ç¼ç è¿ path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # åºå®ç½é¡µ: å§ç»ç¨ web/index.html æ¨¡æ¿çæåä¸ä¸ª index.html (æ°æ®æ¥èª data.json)
    html_path = os.path.ioin(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP èç¹</title></head>"
                "<body><h1>VPN Gate SSTP èç¹</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='å è½½å¤±è´¥:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel é¾å¼ä»£çæ¸å (åºå® URL, æ¹æ¡ä¸: åå­ä¸åãæä»¤èªå¨æ¢)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # å¯ç´æ¥ç²è´´è¿åå°ãèªå®ä¹ä¼éIPãæ¡çæ¸å (å¥å£å°å#åå­$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # å®æ´ vless:// è®¢é (å¡«è¿åå°ãè®¢éé¾æ¥ãURL, å®¢æ·ç«¯èªå¨è½®æ¢)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) æ°æ®æº
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate è¿å 0 ä¸ªåå§èç¹ (æ°æ®æºå¼å¸¸, ä¸åè®¸çæç©ºç»æ)")

    # 2) SSTP ç­é + å»é
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"ä» {raw_count} ä¸ªåå§èç¹ä¸­æ²¡æè§£æåºä»»ä½ SSTP(TCP) èç¹ â æ°æ®æ ¼å¼å¯è½å·²åå, éè¦äººå·¥éé")
    uniq = edupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        unip = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f": ë~ååå§èç¹: {raw_count}")
    log("VPN GATE", f"SSTP èç¹: {sstp_count}")
    log("VPN GATE", f"å»éå: {len(uniq)}")

    # 3) å¹¶åæ£æµ
    log("CLOUDFLARE WORKER", f"æäº¤æ£æµ: {len(uniq)} (å¹¶å {CONCURRENCY}, åè¯·æ±è¶æ¶ {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in failed if not r.get("success"}
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f".j8kX¾hX©ó¢¶ÆVâ7V66W72Ò"Ð¢Æör$4ÄõTDdÄ$Rtõ$´U""Âb.j8kX¾ZKJS¢¶ÆVâfÆVBÒ"²b"X[nKÒv÷&¶W"[È.[¶ÆVâv÷&¶W%öW'&÷'2Ò"bv÷&¶W%öW'&÷'2VÇ6R""Ð¢Æör$4ÄõTDdÄ$Rtõ$´U""Âb.	~i{c¢¶VÆ6VC¢ãg×2"Ð Ð¢2zÎh
~ZKJS¢v÷&¶W"ZèÎXZKÞXúþëâk*iÈK»¾KÙ^KK®û~k.h»þXjÚ>[Y8Þ[©BÐ¢bVææBæ÷B7V66W72æBÆVâv÷&¶W%öW'&÷'2ÓÒÆVâVæ Ð¢FR%v÷&¶W"XZ:û~k.[È.[Âj8kX¾iÈÞXªKÞXúþyJ(	BiÊÎjÊùÎXNZé®ZKJRKÞyIþhz®{¹>iéÂ"Ð Ð¢2B{¹>iéÂ²{ÙPÐ¢FFÒ'VÆEö÷WGWG2&W7VÇG2Â&uö6÷VçBÂ77Gö6÷VçBÂ6÷W&6RÐ¢Æör%$U5TÅB"Âb.XúþyJ¨.x+¢¶ÆVâ7V66W72Ò"Ð¢Æör%$U5TÅB"Âb.Y»ÞZëni[xó¢¶FF²w7FG2uÕ²v6÷VçG&W2u×Ò"Ð Ð¢FF÷FÂFÖÅ÷FÂ6ç5÷FÂ÷7G5÷FÂ7V%÷FÒw&FUö÷WGWG2FFÐ¢Æör%tT%4DR"Âb.yIþh¶÷2çFç&VÇFFF÷FÂ$UõôD"Ò"Ð¢Æör%tT%4DR"Âb.yIþh¶÷2çFç&VÇFFÖÅ÷FÂ$UõôD"Ò"Ð¢Æör%tT%4DR"Âb.yIþh¶÷2çFç&VÇFhains_path, REPO_DIR)}")
    log("WEBSITE", f"çæ {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"çæ {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "å®æ (GitHub Pages é¨ç½²ç± workflow æ§è¡)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"ç¨åºå¼å¸¸: {type(exc).__name__}: {exc}")
