#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_layer.py —— 命中验证层（证据驱动研判）

与 ai_layer 的本质区别：
    ai_layer  只把「扫描器的结论」（命中记录 url/status/desc）喂给模型 —— 属**盲判**，
              扫描器说错了，AI 必然跟着错（如 401 认证失败页被回声路径而误命中）。
    verify_layer 先**回抓真实响应**构建证据包，再连同证据一起喂给模型 —— 属**证据驱动研判**。

三件事：
    ① 证据回填：状态码 / Content-Type / 长度 / 正文片段(脱敏) / 重定向链 / 认证失败特征 / catch-all 比对
    ② 有界追问：对高风险类发现，探测「文档化的下一跳端点」是否可达（HEAD，只取状态码与长度）
    ③ AI 研判：基于证据输出 真伪 / 危害等级 / 利用前置是否成立 / 处置建议

边界（严格只读）：
    - 只发 GET / HEAD；正文最多取 64KB，二进制类（堆转储等）只取状态码与长度；
    - 不提取、不使用任何凭据；不爆破、不绕过认证；不上传载荷；不做任何写入；
    - 送 AI 的正文片段经脱敏（口令/token/key 一律打码）并截断。

用法：
    python3 tools/verify_layer.py --findings out/findings.jsonl --out verify_out
    python3 tools/verify_layer.py --findings out/findings.jsonl --out verify_out --no-ai
    python3 tools/verify_layer.py --findings out/findings.jsonl --out verify_out --limit 5
"""
import argparse
import csv
import json
import os
import re
import sys
import random
from datetime import datetime, timezone
from urllib.parse import urlparse

# 复用扫描器同一套 HTTP 栈（限速/重定向/解压行为完全一致）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import shadowscan as ss
except ImportError:
    ss = None

try:
    import probe_policy as pp
except ImportError:
    pp = None

_RULE_PATHS = set()
if ss is not None and pp is not None:
    _RULE_PATHS = pp.rule_path_set(ss)

# ---------------------------------------------------------------------------
# 证据回填
# ---------------------------------------------------------------------------
# 认证失败/拒绝特征（与扫描器保持一致，避免"错误页回显路径"类误报）
AUTH_FAIL_MARKERS = (
    '"code":401', '"code": 401', '"code":403', '"code": 403',
    '认证失败', '未认证', '未授权访问', '请先登录', '请登录后', '登录已过期', '无权限访问',
    'unauthorized', 'forbidden', 'authentication failed', 'access denied',
    'login required', 'not logged in', 'invalid token', 'token expired', 'permission denied',
)

# 文档化的「下一跳」端点：命中 A 时，攻击者接下来会看 B。仅做可达性探测（HEAD）。
NEXT_HOP = {
    "/actuator": ["/actuator/env", "/actuator/heapdump", "/actuator/mappings",
                  "/actuator/configprops", "/actuator/beans"],
    "/actuator/health": ["/actuator/env", "/actuator/heapdump"],
    "/druid/index.html": ["/druid/datasource.json", "/druid/sql.json", "/druid/websession.json"],
    "/druid/login.html": ["/druid/datasource.json", "/druid/sql.json"],
    "/nacos/": ["/nacos/v1/auth/users", "/nacos/v1/cs/configs"],
    "/nacos/v1/console/namespaces": ["/nacos/v1/auth/users", "/nacos/v1/cs/configs"],
    "/doc.html": ["/v2/api-docs", "/v3/api-docs"],
    "/swagger-ui.html": ["/v2/api-docs", "/v3/api-docs"],
    "/api/v2.0/systeminfo": ["/api/v2.0/projects"],
    "/graph": ["/api/v1/status/config", "/api/v1/targets"],
    "/api/health": [],
    "/manager/html": [],
    "/minio/health/live": [],
}

_SECRET_PAT = re.compile(
    r'(?i)("?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|credential)"?\s*[:=]\s*)("?)([^"\s,}]{2,})')


def sanitize(text, limit=400):
    """脱敏 + 截断：送 AI 的正文片段不得包含凭据。"""
    if not text:
        return ""
    text = _SECRET_PAT.sub(lambda m: m.group(1) + m.group(2) + "***MASKED***", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _fetch(url, timeout, max_body=64_000, method="GET", extra_headers=None, direct_ip=True):
    """用扫描器的 HTTP 栈取一次响应；返回 dict 或 None。"""
    if ss is None:
        return None
    u = urlparse(url)
    host = u.hostname
    if not host:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    # direct_ip=True 复现扫描器行为（直连解析 IP，绕过 CDN）；
    # direct_ip=False 走正常 DNS（等价于外部攻击者视角）
    ip = (ss.resolve_ipv4(host) or [host])[0] if direct_ip else None
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    res = ss.http_fetch(host, ip, port, u.scheme, path, timeout=timeout,
                        method=method, max_body=max_body, extra_headers=extra_headers)
    if res is None:
        return None
    return {
        "status": res.status,
        "content_type": res.headers.get("content-type", ""),
        "server": res.headers.get("server", ""),
        "length": len(res.body),
        "declared_length": int(res.headers.get("content-length") or 0) or None,
        "final_path": res.url,
        "final_origin": getattr(res, "origin", None),
        "redirected": bool(getattr(res, "redirected", False)),
        "body": res.body,
    }


def collect_evidence(finding, timeout, want_next_hop=True):
    """回抓真实响应，构建证据包。"""
    url = finding["url"]
    ev = {"fetched": False}
    r = _fetch(url, timeout)
    if r is None:
        ev["note"] = "无法建立连接（可能已下线/被网关拦截）"
        return ev
    ev["fetched"] = True
    ev["http_status"] = r["status"]
    ev["content_type"] = r["content_type"]
    ev["server"] = r["server"]
    ev["length"] = r["length"]
    ev["final_url"] = (r["final_origin"] or "") + (r["final_path"] or "")
    ev["redirected"] = r["redirected"]
    body_txt = r["body"][:8000].decode("utf-8", "replace")
    low = body_txt.lower()
    ev["auth_failure"] = any(m.lower() in low for m in AUTH_FAIL_MARKERS)
    ev["body_snippet"] = sanitize(body_txt)
    ev["_body"] = r["body"]   # 仅内部用于签名重校，输出前剔除

    # 重定向语义：最终路径是否仍是本端点
    exp_path = urlparse(url).path.rstrip("/")
    fin_path = (r["final_path"] or "").split("?", 1)[0].rstrip("/")
    ev["redirect_changed_path"] = bool(r["redirected"] and exp_path and fin_path and exp_path != fin_path)

    # 外部视角：走正常 DNS（CDN/负载均衡）是否同样可达？
    # 扫描器直连源站 IP，可能报出“公网经 CDN 实际不可达”的端点，须区分。
    ext = _fetch(url, timeout, max_body=4096, direct_ip=False)
    if ext is None:
        ev["external"] = {"status": None, "note": "DNS 解析失败/连接失败"}
    else:
        ev["external"] = {"status": ext["status"], "length": ext["length"]}
    ev["origin_only"] = bool(ext is None or ext["status"] != r["status"])

    # catch-all 比对：随机路径是否返回与命中相同的正文
    if r["status"] == 200 and r["body"]:
        u = urlparse(url)
        rnd = "%s/__vl_probe_%08x__" % (u.path.rsplit("/", 1)[0] if "/" in u.path else "", random.getrandbits(32))
        rr = _fetch("%s://%s%s" % (u.scheme, u.netloc, rnd), timeout, max_body=64_000)
        if rr and rr["status"] == 200 and rr["body"] == r["body"]:
            ev["catch_all"] = True

    # 有界追问：下一跳端点是否可达（HEAD，仅状态码与长度）
    if want_next_hop:
        hops = NEXT_HOP.get(finding.get("endpoint", ""), [])
        if hops:
            u = urlparse(url)
            base = "%s://%s" % (u.scheme, u.netloc)
            nh = []
            for h in hops:
                rh = _fetch(base + h, timeout, max_body=2048, method="GET",
                            extra_headers={"Range": "bytes=0-0"})
                if rh is None:
                    nh.append({"path": h, "status": None})
                else:
                    nh.append({"path": h, "by": "static", "status": rh["status"],
                               "length": rh.get("declared_length") or rh["length"],
                               "ctype": rh["content_type"]})
            ev["next_hop"] = nh
    return ev


# ---------------------------------------------------------------------------
# AI 提议 → 白名单内执行（约束型智能体：AI 有提议权，代码有执行权）
# ---------------------------------------------------------------------------
# 只有命中这些正则的路径，AI 的提议才会被真正执行。
# 全部为「只读 GET」的文档化端点族；不含任何写入/上传/删除/登录/爆破类路径。
PROBE_ALLOWLIST = (
    r"^/actuator(/[A-Za-z0-9_\-\.]+){0,3}$",
    r"^/druid/[A-Za-z0-9_\-]+\.(json|html)$",
    r"^/nacos/v1/(auth|cs|console|ns|service|config)/[A-Za-z0-9_\-/\.]*$",
    r"^/api/v1/[A-Za-z0-9_\-/]+$",            # Prometheus 查询/状态 API
    r"^/api/v2\.0/[A-Za-z0-9_\-/]+$",         # Harbor API
    r"^/(v2|v3)/api-docs$",
    r"^/swagger-resources[A-Za-z0-9_\-/]*$",
    r"^/minio/[A-Za-z0-9_\-/]+$",
    r"^/api/[A-Za-z0-9_\-/]+$",
    r"^/[A-Za-z0-9_\-\.]+\.(json|html|txt|yml|yaml)$",
    r"^(/[A-Za-z0-9_\-\.]+)*/\.DS_Store$",   # 同类元数据文件（只读，直接相关）
)
# 危险动词安全阀：路径中出现即拒绝（即便命中端点族正则）——防止 AI 提议出
# 登录/删除/上传/执行类动作（本层只做只读可达性验证）
_FORBIDDEN_TOKENS = (
    "login", "logout", "signin", "sign_in", "delete", "remove", "update", "create",
    "reset", "shutdown", "exec", "upload", "import", "install", "restart", "kill",
    "drop", "write", "modify", "edit", "save", "publish", "deploy",
)
MAX_PROBES_PER_ROUND = 4
MAX_PROBE_ROUNDS = 2


def _path_allowed(path):
    """白名单校验（委托共享策略 probe_policy，mode=verify 窄白名单）。

    验证层的任务是判断**已知发现**的危害上限，不需要广度，因此用窄白名单；
    发现阶段（shadowscan --adaptive）用 MODE_SCAN 宽白名单，两者共用同一套只读约束。"""
    if pp is not None:
        return pp.path_allowed(path, pp.MODE_VERIFY, rule_paths=_RULE_PATHS)
    if not isinstance(path, str) or not path.startswith("/"):
        return False, "非绝对路径"
    if len(path) > 120:
        return False, "路径过长"
    if ".." in path or "\\" in path:
        return False, "含穿越字符"
    low = path.lower()
    for tok in _FORBIDDEN_TOKENS:
        if tok in low:
            return False, "含危险动词 %s" % tok
    if not any(re.match(rx, path) for rx in PROBE_ALLOWLIST):
        return False, "不在允许的端点族内"
    return True, ""


def _probe_one(base, path, timeout):
    """执行一次只读探测（GET + Range，仅取状态码与声明长度）。"""
    rh = _fetch(base + path, timeout, max_body=2048, method="GET",
                extra_headers={"Range": "bytes=0-0"})
    if rh is None:
        return {"path": path, "status": None, "by": "ai"}
    return {"path": path, "status": rh["status"],
            "length": rh.get("declared_length") or rh["length"],
            "ctype": rh["content_type"], "by": "ai"}


def ai_propose_probes(finding, ev, ai, asked):
    """让模型基于已有证据提出下一轮要探测的路径（**只提议，不执行**）。"""
    sys_prompt = (
        "你是渗透测试验证助手。基于已收集的只读证据，提出**下一轮要探测的端点**，"
        "用于判断该发现的危害上限。只输出一个 JSON 对象，不要解释文字：\n"
        '{"done": true/false, "probe": ["/path1", "/path2"], "why": "一句话理由"}\n'
        "规则（严格遵守）：\n"
        "1) 只能提出**只读 GET** 的路径；禁止任何写入/上传/删除/登录/口令尝试/命令执行类路径；\n"
        "2) 最多 4 条；**不要重复**已探测过的路径；\n"
        "3) 只提出与该组件（framework/desc）相关的**文档化端点**（如 Actuator 的 env/heapdump、"
        "Prometheus 的 /api/v1/*、Harbor 的 /api/v2.0/*）；\n"
        "4) 不得编造不存在的接口名；证据已足够或你不确定时，输出 done=true；\n"
        "5) 你的提议会被白名单审核，越界的会被拒绝——所以只提你确信属于该组件的端点。"
    )
    payload = {
        "finding": {k: finding.get(k) for k in ("url", "endpoint", "framework", "category", "desc")},
        "evidence": {k: v for k, v in ev.items() if k not in ("body", "_body")},
        "already_probed": sorted(asked),
    }
    try:
        import ai_layer as _al
        content, _ = _al._chat(ai.api_url, ai.api_key, ai.assess_model,
                               [{"role": "system", "content": sys_prompt},
                                {"role": "user", "content": "已有信息如下（JSON）：\n"
                                 + json.dumps(payload, ensure_ascii=False)}],
                               timeout=ai.timeout, temperature=0.0, max_tokens=1200)
        obj = _al._first_json(content)
        if isinstance(obj, dict):
            return obj
    except Exception as e:
        print("  [AI 提议失败] %s: %s" % (finding.get("url"), e), file=sys.stderr)
    return None


def ai_investigate(finding, ev, ai, timeout, rounds):
    """AI 提议 → 白名单执行 → 回填证据；循环最多 rounds 轮。
    全过程留痕：ev["probe_audit"] 记录每条提议的「放行/拒绝及原因」。"""
    if ai is None or rounds <= 0:
        return ev
    u = urlparse(finding["url"])
    base = "%s://%s" % (u.scheme, u.netloc)
    asked = {h.get("path") for h in (ev.get("next_hop") or []) if h.get("path")}
    audit = ev.setdefault("probe_audit", [])
    for rnd in range(1, rounds + 1):
        prop = ai_propose_probes(finding, ev, ai, asked)
        if not prop or prop.get("done"):
            audit.append({"round": rnd, "proposal": [], "note": "AI 判定无需继续"})
            break
        cand = []
        for path in (prop.get("probe") or [])[:MAX_PROBES_PER_ROUND * 2]:
            ok, why = _path_allowed(path)
            if path in asked:
                audit.append({"round": rnd, "path": path, "action": "跳过", "why": "已探测过"})
            elif ok:
                cand.append(path)
            else:
                audit.append({"round": rnd, "path": path, "action": "拒绝", "why": why})
        cand = cand[:MAX_PROBES_PER_ROUND]
        if not cand:
            audit.append({"round": rnd, "proposal": prop.get("probe") or [],
                          "note": "提议全部被拒/重复，终止"})
            break
        got = []
        for path in cand:
            asked.add(path)
            r = _probe_one(base, path, timeout)
            got.append(r)
            audit.append({"round": rnd, "path": path, "action": "放行",
                          "why": prop.get("why", ""), "status": r.get("status"),
                          "length": r.get("length")})
        ev.setdefault("next_hop", []).extend(got)
        ev["ai_probe_rounds"] = rnd
        print("       [AI 提议] 第%d轮放行 %d 条：%s" % (rnd, len(got),
              "、".join("%s=%s" % (g["path"], g.get("status")) for g in got)), flush=True)
    return ev


# ---------------------------------------------------------------------------
# 规则研判（AI 不可用时的降级路径）
# ---------------------------------------------------------------------------
# 规则表索引：用于对“新响应”独立重校签名（不信任扫描器的结论）
_RULE_BY_PATH = {}
if ss is not None:
    for _r in getattr(ss, "ENDPOINT_RULES", []):
        _RULE_BY_PATH.setdefault(_r["path"], _r)


def _resignature(finding, ev):
    """用规则表独立重校：新响应是否仍满足该规则的签名/魔数/认证条件。
    返回 True/False；无对应规则时返回 None（无法复核）。"""
    rule = _RULE_BY_PATH.get(finding.get("endpoint", ""))
    if not rule:
        return None
    body = ev.get("_body") or b""
    if rule.get("binary"):
        if not rule.get("magic"):
            return True
        return rule["magic"].encode("latin-1") in body[:64]
    if rule.get("auth_401"):
        return ev.get("http_status") == 401
    signs = rule.get("sign") or []
    if signs:
        low = body.decode("utf-8", "replace").lower()
        return any(x.lower() in low for x in signs)
    return True


# 敏感端点 / 敏感字段：响应内容本身即构成高危（泄露连接串、凭据、会话、配置）
_SENSITIVE_ENDPOINTS = (
    "/datasource.json", "/websession.json", "/actuator/env", "/actuator/configprops",
    "/api/v1/status/config", "/api/v1/targets", "/nacos/v1/cs/configs", "/nacos/v1/auth/users",
    "/v1/agent/self", "/api/v2.0/systeminfo",
)
_SENSITIVE_FIELDS = ("password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
                     "accesskey", "access_key", "privatekey", "private_key", "credential",
                     "jdbc:", "username", "user_name", "\"url\"", "connectionstring")


def _sensitive_hit(finding, ev):
    """命中内容是否属于敏感数据泄露（凭据/连接串/会话/配置）。"""
    ep = (finding.get("endpoint") or "").lower()
    if ep in _SENSITIVE_ENDPOINTS:
        return True
    blob = ((ev.get("body_snippet") or "") + " " + (ev.get("_body") or b"").decode("utf-8", "replace")[:8000]).lower()
    return sum(1 for f in _SENSITIVE_FIELDS if f in blob) >= 2


def rule_verify(finding, ev):
    """纯规则判定：只依据证据包，不依赖模型。"""
    if not ev.get("fetched"):
        return {"verdict": "已下线/不可达", "harm_level": "none",
                "reason": ev.get("note", "无响应"), "impact": "", "preconditions": "—",
                "action": "确认是否已下线或仅内网可达"}
    st = ev.get("http_status")
    if ev.get("auth_failure"):
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "响应为认证失败/拒绝（正文含 %s 类特征），端点并未真正暴露"
                          % "认证失败",
                "impact": "", "preconditions": "不成立（需认证）",
                "action": "无需处置"}
    if ev.get("catch_all"):
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "随机路径返回与命中完全相同的正文 ⇒ 站点 catch-all 兜底页",
                "impact": "", "preconditions": "不成立", "action": "无需处置"}
    if ev.get("redirect_changed_path"):
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "命中经重定向到 %s（非本端点）⇒ 命中的是跳转目标页" % ev.get("final_url"),
                "impact": "", "preconditions": "不成立", "action": "无需处置"}
    if st in (401, 403):
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "复核返回 %d（需认证）" % st, "impact": "",
                "preconditions": "不成立（需认证）", "action": "无需处置"}
    if st != 200:
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "复核返回 %s（非 200，已不可达）" % st, "impact": "",
                "preconditions": "不成立", "action": "确认是否已下线或仅内网可达"}
    # 独立重校签名：不信任扫描器结论，用规则表在新响应上重验一次
    sig = _resignature(finding, ev)
    if sig is False:
        return {"verdict": "已排除", "harm_level": "none",
                "reason": "复核响应已不含该端点的特征签名/魔数（可能已下线或已加固）",
                "impact": "", "preconditions": "不成立", "action": "无需处置"}

    # 源站独有：直连 IP 可达但走 DNS 不可达 ⇒ 公网实际打不到，危害降级
    if ev.get("origin_only") and ev.get("external", {}).get("status") != 200:
        return {"verdict": "疑似", "harm_level": "low",
                "reason": "直连源站 IP 返回 %s，但经 DNS/CDN 访问返回 %s ⇒ 仅源站可达，公网不可达"
                          % (st, ev.get("external", {}).get("status")),
                "impact": "外部攻击者经正常域名访问不可达，实际风险显著低于扫描结论",
                "preconditions": "需先获得源站 IP 且网络可达",
                "action": "确认源站 IP 是否应对外暴露；如需则加访问控制"}

    # 登录页类规则：公网可达属常态，价值低 ⇒ 低危信息项
    _r = _RULE_BY_PATH.get(finding.get("endpoint", "")) or {}
    if _r.get("login_page"):
        return {"verdict": "确认危害", "harm_level": "low",
                "reason": "登录页可达（签名复核通过）；登录页公网可达属常态，价值低",
                "impact": "仅页面可达，未见未授权数据读取",
                "preconditions": "不成立（需认证）",
                "action": "按信息项处理；如可默认口令登录则升级"}

    # 敏感内容泄露：内容本身即高危（与下一跳无关）
    if _sensitive_hit(finding, ev):
        return {"verdict": "确认危害", "harm_level": "high",
                "reason": "未授权返回敏感内容（端点/字段命中：连接串、账号、配置或会话类信息）",
                "impact": "直接泄露配置/连接信息，为后续直连后端或横向提供条件",
                "preconditions": "第 1 跳成立（已获取敏感数据）；后续取决于凭据可用性与网络可达",
                "action": "立即收敛访问来源并加认证；按已泄露处理并轮换相关凭据"}

    # 可达且签名仍匹配 ⇒ 按「下一跳」判断危害上限
    hops = ev.get("next_hop") or []
    reachable = [h for h in hops if h.get("status") == 200 and (h.get("length") or 0) > 60]
    if reachable:
        names = "、".join("%s(%sB)" % (h["path"], h.get("length") or 0) for h in reachable)
        return {"verdict": "确认危害", "harm_level": "high",
                "reason": "未授权可访问，且下一跳端点可达：%s" % names,
                "impact": "可进一步读取配置/内存/会话数据，危害上限显著抬升",
                "preconditions": "第 1 跳成立，需继续确认凭据可用性",
                "action": "立即收敛该端点访问来源并加认证"}
    if hops:
        names = "、".join("%s(%s)" % (h["path"], h.get("status")) for h in hops)
        return {"verdict": "确认危害", "harm_level": "low",
                "reason": "未授权可访问，但下一跳端点均不可达（%s）" % names,
                "impact": "仅端点本身可达，未见可延伸的数据读取",
                "preconditions": "第 1 跳成立，第 2 跳不成立（下一跳不可达）",
                "action": "纳入常规整改，按信息泄露处置"}
    return {"verdict": "确认危害", "harm_level": "low",
            "reason": "未授权可访问（%s），签名已独立复核通过；无已知下一跳可延伸" % st,
            "impact": "信息泄露（端点本身可达）",
            "preconditions": "第 1 跳成立；无已知后续跳",
            "action": "纳入常规整改，按信息泄露处置"}


# ---------------------------------------------------------------------------
# AI 研判（证据驱动）
# ---------------------------------------------------------------------------
def ai_verify(finding, ev, ai):
    """把「命中记录 + 证据包」一起交给模型研判。失败则返回 None（由调用方降级）。"""
    if ai is None:
        return None
    sys_prompt = (
        "你是资深应用安全专家，正在**基于真实响应证据**核验一个扫描命中。"
        "只输出一个 JSON 对象，不要任何解释文字，字段：\n"
        "{"
        '"verdict": "确认危害" 或 "疑似" 或 "已排除",'
        '"harm_level": "high" 或 "medium" 或 "low" 或 "none",'
        '"reason": "一句话判定依据，必须引用证据中的具体字段（状态码/重定向/认证特征/下一跳）",'
        '"impact": "攻击者实际能得到什么，不得夸大",'
        '"preconditions": "利用前置条件是否成立（逐跳说明）",'
        '"action": "最该做的一步处置建议"'
        "}\n"
        "判定规则（严格遵守）：\n"
        "1) 证据显示认证失败特征、401/403、或重定向到非本端点、或随机路径返回相同正文（catch-all）"
        "→ 一律 \"已排除\"；\n"
        "2) 命中可达且 next_hop 中有 status=200 且 length 明显大于 60 的端点 → \"确认危害\"，"
        "harm_level 至少 medium；\n"
        "3) 命中可达但 next_hop 全部 404/403/0 字节 → \"确认危害\" 但 harm_level=low（仅端点可达）；\n"
        "4) 不得编造 CVE、不得声称已获得系统权限、不得给出任何实际入侵操作步骤。"
    )
    user_prompt = ("【扫描命中】\n" + json.dumps(
        {k: finding.get(k) for k in ("url", "site", "endpoint", "framework", "category",
                                     "status", "exposure", "desc")}, ensure_ascii=False)
        + "\n\n【真实响应证据（只读回抓，正文已脱敏截断）】\n"
        + json.dumps({k: v for k, v in ev.items() if k not in ("body", "_body")},
                     ensure_ascii=False))
    try:
        import ai_layer as _al
        content, _ = _al._chat(ai.api_url, ai.api_key, ai.assess_model,
                              [{"role": "system", "content": sys_prompt},
                               {"role": "user", "content": user_prompt}],
                              timeout=ai.timeout, temperature=0.0, max_tokens=4000)
        obj = _al._first_json(content)
        if isinstance(obj, dict) and obj.get("verdict"):
            return obj
    except Exception as e:
        print("  [AI 调用失败] %s: %s" % (finding.get("url"), e), file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# 报告渲染
# ---------------------------------------------------------------------------
def render_report(rows, meta):
    conf = [r for r in rows if r["verdict"] == "确认危害"]
    susp = [r for r in rows if r["verdict"] == "疑似"]
    excl = [r for r in rows if r["verdict"] not in ("确认危害", "疑似")]
    order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    conf.sort(key=lambda r: order.get(r["harm_level"], 9))

    L = []
    L.append("# 命中验证报告（证据驱动）\n")
    L.append("- 输入：`%s`（%d 条命中）" % (meta["input"], len(rows)))
    L.append("- 验证时间：%s" % meta["when"])
    L.append("- 方式：真实响应回填 + 有界下一跳追问（HEAD，仅状态码/长度）+ %s"
             % ("AI 证据研判" if meta["ai"] else "规则研判"))
    L.append("- **边界**：只读（GET/HEAD）；不下载大体积内容、不提取凭据、不爆破、不绕过、不写入\n")

    L.append("## 一、总览\n")
    L.append("| 结论 | 条数 |")
    L.append("|---|---|")
    L.append("| 🔴 确认危害 | **%d** |" % len(conf))
    L.append("| 🟡 疑似（需人工） | %d |" % len(susp))
    L.append("| 🟢 已排除 | %d |" % len(excl))
    L.append("| **合计** | **%d** |\n" % len(rows))
    hl = {}
    for r in conf:
        hl[r["harm_level"]] = hl.get(r["harm_level"], 0) + 1
    if hl:
        L.append("确认危害的危害等级分布：" + "、".join(
            "%s %d 条" % (k, hl[k]) for k in ("high", "medium", "low") if k in hl) + "\n")

    def table(rs, title):
        if not rs:
            return
        L.append("## %s\n" % title)
        L.append("| 站点 | 端点 | 危害 | 判定依据 | 利用前置 | 建议 |")
        L.append("|---|---|---|---|---|---|")
        for r in rs:
            L.append("| `%s` | `%s` | %s | %s | %s | %s |" % (
                r["site"], r["endpoint"], r["harm_level"], r["reason"],
                r["preconditions"], r["action"]))
        L.append("")

    table(conf, "二、确认危害（按危害排序）")
    table(susp, "三、疑似（需人工确认）")

    if excl:
        L.append("## 四、已排除（附排除依据）\n")
        L.append("| 站点 | 端点 | 排除依据 |")
        L.append("|---|---|---|")
        for r in excl:
            L.append("| `%s` | `%s` | %s |" % (r["site"], r["endpoint"], r["reason"]))
        L.append("")

    L.append("## %s、证据明细\n" % ("五" if excl else "四"))
    for r in rows:
        ev = {k: v for k, v in r["evidence"].items() if k != "_body"}
        L.append("### %s" % r["url"])
        L.append("- 结论：**%s**（%s）" % (r["verdict"], r["harm_level"]))
        if ev.get("fetched"):
            L.append("- 响应：status=%s | type=%s | len=%s%s"
                     % (ev.get("http_status"), ev.get("content_type") or "-",
                        ev.get("length"), " | server=%s" % ev["server"] if ev.get("server") else ""))
            if ev.get("redirected"):
                L.append("- 重定向：是 → `%s`%s"
                         % (ev.get("final_url"), "（路径已改变）" if ev.get("redirect_changed_path") else ""))
            if ev.get("auth_failure"):
                L.append("- 认证特征：**命中认证失败特征**")
            if ev.get("catch_all"):
                L.append("- catch-all：**随机路径返回相同正文**")
            if ev.get("next_hop"):
                L.append("- 追问端点：%s" % "；".join(
                    "`%s`→%s%s%s" % (h["path"], h.get("status"),
                                     "(%sB)" % h.get("length") if h.get("length") else "",
                                     "[AI]" if h.get("by") == "ai" else "[静态]")
                    for h in ev["next_hop"]))
            if ev.get("probe_audit"):
                rej = [a for a in ev["probe_audit"] if a.get("action") == "拒绝"]
                L.append("- AI 提议审计：共 %d 条记录，白名单拒绝 %d 条%s"
                         % (len(ev["probe_audit"]), len(rej),
                            ("（" + "；".join("`%s`:%s" % (a["path"], a["why"]) for a in rej) + "）")
                            if rej else ""))
            if ev.get("body_snippet"):
                L.append("- 正文片段（已脱敏）：`%s`" % ev["body_snippet"][:200])
        else:
            L.append("- %s" % ev.get("note", "无响应"))
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
def load_findings(path):
    if path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser(description="ShadowScan 命中验证层（证据驱动研判）")
    ap.add_argument("--findings", required=True, help="findings.jsonl 或 findings.csv")
    ap.add_argument("--out", default="verify_out", help="输出目录")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--limit", type=int, default=0, help="只验证前 N 条（0=全部）")
    ap.add_argument("--no-ai", action="store_true", help="只用规则研判，不调用 LLM")
    ap.add_argument("--no-next-hop", action="store_true", help="关闭下一跳追问")
    ap.add_argument("--workers", type=int, default=5, help="并发验证条数（默认 5）")
    ap.add_argument("--ai-probe-rounds", type=int, default=2,
                    help="AI 提议探测的最大轮数（0=关闭，退回静态 NEXT_HOP；默认 2）")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rows_in = load_findings(args.findings)
    if args.limit:
        rows_in = rows_in[:args.limit]
    print("待验证命中：%d 条" % len(rows_in))

    ai = None
    if not args.no_ai:
        try:
            import ai_layer
            ai = ai_layer.AILayer()
            if not ai.available:
                print("AI 未配置（缺 api_key），降级为规则研判")
                ai = None
        except ImportError:
            print("未找到 ai_layer.py，降级为规则研判")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    done = [0]

    def _one(idx_f):
        i, f = idx_f
        url = f.get("url", "")
        ev = collect_evidence(f, args.timeout, want_next_hop=not args.no_next_hop)
        # 约束型智能体：AI 提议 → 白名单校验 → 只读执行 → 证据回填（最多 N 轮）
        if ai is not None and args.ai_probe_rounds > 0:
            ev = ai_investigate(f, ev, ai, args.timeout, args.ai_probe_rounds)
        res = ai_verify(f, ev, ai) if ai else None
        by = "ai"
        if res is None:
            res = rule_verify(f, ev)
            by = "rule"
        done[0] += 1
        print("[%d/%d] %-58s -> %s(%s, %s)"
              % (done[0], len(rows_in), url[:58], res.get("verdict"), res.get("harm_level"), by),
              flush=True)
        return {
            "url": url, "site": f.get("site", ""), "endpoint": f.get("endpoint", ""),
            "framework": f.get("framework", ""), "category": f.get("category", ""),
            "verdict": res.get("verdict", "疑似"), "harm_level": res.get("harm_level", "low"),
            "reason": res.get("reason", ""), "impact": res.get("impact", ""),
            "preconditions": res.get("preconditions", ""), "action": res.get("action", ""),
            "by": by, "evidence": ev,
        }

    rows = [None] * len(rows_in)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(_one, (i, f)): i for i, f in enumerate(rows_in)}
        for fu in as_completed(futs):
            try:
                rows[futs[fu]] = fu.result()
            except Exception as e:
                print("  验证异常：%s" % e, file=sys.stderr)
    rows = [r for r in rows if r]

    meta = {"input": args.findings, "when": datetime.now(timezone.utc).astimezone().isoformat(),
            "ai": bool(ai)}
    md = render_report(rows, meta)
    rep = os.path.join(args.out, "verify_report.md")
    with open(rep, "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(args.out, "verify_evidence.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            ev = {k: v for k, v in r["evidence"].items() if k not in ("body", "_body")}
            fh.write(json.dumps({**{k: v for k, v in r.items() if k != "evidence"}, "evidence": ev},
                                ensure_ascii=False) + "\n")
    conf = sum(1 for r in rows if r["verdict"] == "确认危害")
    excl = sum(1 for r in rows if r["verdict"] not in ("确认危害", "疑似"))
    print("\n完成：确认危害 %d / 疑似 %d / 已排除 %d" % (conf, len(rows) - conf - excl, excl))
    print("报告：%s" % rep)


if __name__ == "__main__":
    main()