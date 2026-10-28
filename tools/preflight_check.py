#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""preflight_check.py —— 上机前连通性自检（服务器 / 扫描机）

用途：把 ShadowScan 部署到服务器后，先确认两件事，再开扫：
  A. 大模型网关是否可达、key 是否有效（真实发一次请求验证）
  B. 内网目标域名是否可达（DNS 解析 + TCP 端口 + HTTP 探测，Host 头用域名以兼容虚拟主机）

零第三方依赖（仅 Python3 标准库），与 ShadowScan 一致；端口探测并发执行。

用法：
  source env.sh
  python3 tools/preflight_check.py --targets assets_intranet_round1.txt
  python3 tools/preflight_check.py --targets assets_intranet_round1.txt --ports 80,443,8080 --timeout 4

退出码：0=网关与全部目标通过；1=有目标不可达；2=网关不可用
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8888]
HTTPS_PORTS = {443, 8443, 9443, 4443, 10443, 8444}


def resolve(host):
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def tcp_ok(ip, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def http_code(host, ip, port, timeout):
    scheme = "https" if port in HTTPS_PORTS else "http"
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        s = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) if scheme == "https" else raw
        s.settimeout(timeout)
        req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: preflight\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % host)
        s.sendall(req.encode())
        data = s.recv(256)
        s.close()
        if data.startswith(b"HTTP/"):
            return int(data.split(b" ")[1])
    except Exception:
        return 0
    return 0


def check_target_ports(host, ips, ports, timeout):
    hits = []
    for ip in ips:
        for p in ports:
            if tcp_ok(ip, p, timeout):
                hits.append((ip, p, http_code(host, ip, p, timeout)))
    return hits


def check_gateway(url, key, model, timeout):
    print("=== A. 大模型网关 ===")
    if not url or not key:
        print("  [跳过] 未配置 SHADOWSCAN_LLM_URL / SHADOWSCAN_LLM_KEY（请先 source env.sh）")
        return None
    print("  URL  : %s" % url)
    print("  模型 : %s" % model)
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": "只回复两个字符：ok"}],
                       "max_tokens": 64}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + key})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read().decode("utf-8"))
        dt = time.time() - t0
        msg = (resp.get("choices") or [{}])[0].get("message", {}) or {}
        content = (msg.get("content") or "").strip()
        print("  [OK] HTTP 200，模型=%s，耗时=%.2fs，content=%r" % (resp.get("model", model), dt, content[:40]))
        return True
    except urllib.error.HTTPError as e:
        print("  [失败] HTTP %s：%s" % (e.code, e.read()[:200]))
        return False
    except Exception as e:
        print("  [失败] %s: %s" % (type(e).__name__, e))
        return False


def load_targets(arg):
    if os.path.isfile(arg):
        out = []
        for line in open(arg, encoding="utf-8"):
            line = line.split("#")[0].strip()
            if line:
                out.append(line)
        return out
    return [a.strip() for a in arg.split(",") if a.strip()]


def main():
    ap = argparse.ArgumentParser(description="ShadowScan 上机前连通性自检")
    ap.add_argument("--targets", required=True, help="资产清单文件或逗号分隔列表")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="目标探测端口（默认 80,443,8080,8443,8000,8888）")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--skip-gateway", action="store_true", help="只测目标，不测网关")
    args = ap.parse_args()

    ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    gw = None
    if not args.skip_gateway:
        gw = check_gateway(os.environ.get("SHADOWSCAN_LLM_URL", ""),
                           os.environ.get("SHADOWSCAN_LLM_KEY", ""),
                           os.environ.get("SHADOWSCAN_LLM_MODEL", "deepseek-v4-pro"),
                           max(args.timeout, 30))

    targets = load_targets(args.targets)
    hosts = []
    for t in targets:
        h = t
        if t.startswith(("http://", "https://")):
            h = t.split("//", 1)[1].split("/")[0].split(":")[0]
        elif ":" in t and t.rsplit(":", 1)[1].isdigit():
            h = t.rsplit(":", 1)[0]
        hosts.append((h, resolve(h)))

    print("\n=== B. 内网目标（%d 个，端口 %s）===" % (len(targets), ",".join(map(str, ports))))
    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check_target_ports, h, ips, ports, args.timeout): h
                for h, ips in hosts if ips}
        for f in as_completed(futs):
            results[futs[f]] = f.result()

    reachable = 0
    for h, ips in hosts:
        if not ips:
            print("  %-45s DNS解析失败 -> 不可达" % h)
            continue
        hits = results.get(h, [])
        real = [x for x in hits if x[2] >= 100]  # 必须有真实 HTTP 响应才算可达
        if real:
            reachable += 1
            print("  %-45s %s  [可达]" % (h, ", ".join("%s:%d(HTTP %s)" % x for x in real)))
        elif hits:
            print("  %-45s %s  [TCP开放但无HTTP响应，疑似代理/fake-ip，不可信]"
                  % (h, ", ".join("%s:%d" % (x[0], x[1]) for x in hits)))
        else:
            print("  %-45s %s  [不可达]" % (h, ",".join(ips)))

    print("\n=== 结论 ===")
    print("  目标可达：%d/%d" % (reachable, len(targets)))
    print("  网关：%s" % ({True: "OK", False: "失败", None: "未测"}[gw]))
    if reachable == 0:
        print("  ⚠️ 无任何目标可达：环境不对（未连内网/VPN、ZTNA 未授权、或需在办公网/扫描机运行）。")
        print("     此时扫描会得到“存活 0”的假阴性，请勿采信。")
    if gw is False:
        sys.exit(2)
    sys.exit(1 if reachable == 0 else 0)


if __name__ == "__main__":
    main()