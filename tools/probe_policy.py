#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_policy.py —— 探测策略：白名单 + 只读约束 + AI 提议 + 审计留痕（共享模块）

被两处复用：
    tools/verify_layer.py  （MODE_VERIFY，窄白名单：只判断已知发现的危害上限）
    shadowscan.py --adaptive（MODE_SCAN，  宽白名单：发现阶段，广度优先）

## 设计要点

**真正的安全阀是「方法 + 副作用」，不是路径**：
    ① 只用 GET/HEAD        —— HTTP 语义上无状态变更
    ② 禁止 query string    —— 无法参数注入、无法触发定向动作
    ③ 只取状态码/声明长度  —— 不下载堆转储、不落地数据
    ④ 不提交任何凭据       —— 无爆破、无登录尝试
路径白名单是**第二道带**（防越权探测 admin/破坏性 GET 端点）。

**两层白名单**：
    MODE_SCAN   宽：规则表路径 ∪ 组件端点族 ∪ 通用只读类 —— 广度优先
    MODE_VERIFY 窄：只放行与该发现所属组件相关的端点族     —— 安全优先

**全程留痕**：每条提议记录 放行/拒绝 + 理由 + 结果，写入 audit 列表，可审计。
"""
import json
import re
import sys
from urllib.parse import urlparse

MODE_SCAN = "scan"
MODE_VERIFY = "verify"

# ---------------------------------------------------------------------------
# 组件端点族（宽）：覆盖规则表涉及的全部组件。AI 提议命中任一即进入下一道校验。
# ---------------------------------------------------------------------------
_FAMILIES = (
    # Spring Boot / Actuator
    r"/actuator(/[A-Za-z0-9_\-\.]+){0,4}",
    # Druid
    r"/druid(/[A-Za-z0-9_\-\.]+)*",
    # 注册中心 / 配置中心
    r"/nacos(/v\d)?(/[A-Za-z0-9_\-/\.]*)?",
    r"/eureka(/[A-Za-z0-9_\-/\.]*)?",
    r"/consul(/[A-Za-z0-9_\-/\.]*)?",
    r"/v1/agent/[A-Za-z0-9_\-/\.]*",
    r"/spring-cloud-config(/[A-Za-z0-9_\-/\.]*)?",
    r"/apollo(/[A-Za-z0-9_\-/\.]*)?",
    # 网关 / 服务治理
    r"/hystrix[A-Za-z0-9_\-/\.]*",
    r"/sentinel-dashboard(/[A-Za-z0-9_\-/\.]*)?",
    r"/dubbo(/[A-Za-z0-9_\-/\.]*)?",
    # 监控 / APM
    r"/graph",
    r"/metrics",
    r"/api/v\d(/[A-Za-z0-9_\-/\.]*)?",          # Prometheus / Grafana / 通用 v1|v2
    r"/api/v2\.0(/[A-Za-z0-9_\-/\.]*)?",        # Harbor
    r"/api/health",
    r"/api/overview",
    r"/api/frontend/[A-Za-z0-9_\-/\.]*",        # Grafana
    r"/api/datasources[A-Za-z0-9_\-/\.]*",
    r"/api/dashboards[A-Za-z0-9_\-/\.]*",
    r"/api/org[A-Za-z0-9_\-/\.]*",
    r"/api/search",
    r"/app/kibana[A-Za-z0-9_\-/\.]*",
    r"/zipkin(/[A-Za-z0-9_\-/\.]*)?",
    r"/skywalking(/[A-Za-z0-9_\-/\.]*)?",
    r"/jaeger(/[A-Za-z0-9_\-/\.]*)?",
    # 中间件管理台
    r"/manager(/[A-Za-z0-9_\-/\.]*)?",          # Tomcat
    r"/jmx-console(/[A-Za-z0-9_\-/\.]*)?",      # JBoss
    r"/management(/[A-Za-z0-9_\-/\.]*)?",       # WildFly
    r"/auth/realms(/[A-Za-z0-9_\-/\.]*)?",      # Keycloak
    r"/console/login/[A-Za-z0-9_\-/\.]*",       # WebLogic
    r"/solr(/[A-Za-z0-9_\-/\.]*)?",
    r"/jenkins(/[A-Za-z0-9_\-/\.]*)?",
    r"/zabbix(/[A-Za-z0-9_\-/\.]*)?",
    r"/phpmyadmin(/[A-Za-z0-9_\-/\.]*)?",
    r"/adminer[A-Za-z0-9_\-/\.]*",
    r"/mongo-express(/[A-Za-z0-9_\-/\.]*)?",
    r"/admin(/[A-Za-z0-9_\-/\.]*)?",            # Spring Boot Admin / Django
    r"/webtools(/[A-Za-z0-9_\-/\.]*)?",         # OFBiz
    r"/elfinder(/[A-Za-z0-9_\-/\.]*)?",
    r"/api/jsonws",                             # Liferay
    r"/struts(/[A-Za-z0-9_\-/\.]*)?",
    # 容器 / 云原生
    r"/v2/?",                                   # Docker Registry
    r"/minio(/[A-Za-z0-9_\-/\.]*)?",
    r"/api/v1/nodes[A-Za-z0-9_\-/\.]*",
    r"/kubernetes-dashboard(/[A-Za-z0-9_\-/\.]*)?",
    r"/portainer(/[A-Za-z0-9_\-/\.]*)?",
    r"/api/v2\.0/systeminfo",
    # 大数据
    r"/dfshealth\.html",
    r"/api/v1/cluster[A-Za-z0-9_\-/\.]*",
    r"/api/v1/apps[A-Za-z0-9_\-/\.]*",
    r"/api/v1/jobs[A-Za-z0-9_\-/\.]*",
    r"/api/v1/tasks[A-Za-z0-9_\-/\.]*",
    r"/ambari(/[A-Za-z0-9_\-/\.]*)?",
    r"/spark(/[A-Za-z0-9_\-/\.]*)?",
    # 接口文档
    r"/swagger-ui[A-Za-z0-9_\-/\.]*",
    r"/swagger-resources[A-Za-z0-9_\-/\.]*",
    r"/doc\.html",
    r"/(v2|v3)/api-docs",
    r"/webjars/[A-Za-z0-9_\-/\.]*",
    # 源码/配置泄漏（只读文件）
    r"/(\.git|\.svn|\.env|WEB-INF|\.DS_Store)(/[A-Za-z0-9_\-/\.]*)?",
    r"(/[A-Za-z0-9_\-\.]+)*/\.DS_Store",
    r"/[A-Za-z0-9_\-\.]+\.(json|html|txt|yml|yaml|xml|properties|sql|log)",
)

# 通用只读类（仅 MODE_SCAN 额外放开：/api/* 与裸文件）
_SCAN_EXTRA = (
    r"/api(/[A-Za-z0-9_\-/\.]*)?",
    r"/[A-Za-z0-9_\-/\.]+\.(json|html|txt|yml|yaml|xml|properties)",
)

# 危险动词黑名单：路径含即拒（即便命中端点族）——本模块只做只读可达性验证
FORBIDDEN_TOKENS = (
    "login", "logout", "signin", "sign_in", "sign-in", "delete", "remove", "update",
    "create", "reset", "shutdown", "exec", "upload", "import", "install", "restart",
    "kill", "drop", "write", "modify", "edit", "save", "publish", "deploy", "clear",
    "purge", "flush", "reload", "enable", "disable", "register", "unregister",
)

MAX_PATH_LEN = 120
MAX_PROBES_PER_ROUND = 4
MAX_PROBE_ROUNDS = 2


def path_allowed(path, mode=MODE_VERIFY, rule_paths=None):
    """白名单校验。返回 (bool, 拒绝原因)。

    校验顺序：形态 → 只读约束（禁 query） → **规则表路径直通** → 危险动词 → 端点族匹配。

    `rule_paths`：扫描器规则表里的路径集合。这些路径是工具**自身的词汇表**，
    其探测方式（GET，只取签名）已由规则表预先约束为只读，因此跳过危险动词校验——
    否则 /console/login/LoginForm.jsp、/druid/login.html 这类**已在规则表内**的
    路径会被误拒，反而收窄了发现范围。
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return False, "非绝对路径"
    if len(path) > MAX_PATH_LEN:
        return False, "路径过长"
    if ".." in path or "\\" in path:
        return False, "含穿越字符"
    if "?" in path or "#" in path:
        return False, "含 query（禁止带参数，避免参数注入）"
    if rule_paths and path in rule_paths:
        return True, ""          # 规则表路径直通（预校验过的只读探测）
    low = path.lower()
    for tok in FORBIDDEN_TOKENS:
        if tok in low:
            return False, "含危险动词 %s" % tok
    fams = list(_FAMILIES) + (list(_SCAN_EXTRA) if mode == MODE_SCAN else [])
    for rx in fams:
        if re.match(r"^%s$" % rx, path):
            return True, ""
    return False, "不在允许的端点族内（mode=%s）" % mode


def load_rule_paths(scanner_module):
    """从扫描器规则表取全部规则路径（这些路径天然允许——它们就是工具的词汇表）。"""
    out = []
    for r in getattr(scanner_module, "ENDPOINT_RULES", []) or []:
        p = r.get("path")
        if p and p.startswith("/"):
            out.append(p)
    return out


def rule_path_set(scanner_module):
    return set(load_rule_paths(scanner_module))


# ---------------------------------------------------------------------------
# 只读探测执行
# ---------------------------------------------------------------------------
def probe_one(fetch, base, path, timeout, by="ai"):
    """执行一次只读探测：GET + Range，仅取状态码与声明长度。fetch 由调用方注入。"""
    rh = fetch(base + path, timeout, max_body=2048, method="GET",
               extra_headers={"Range": "bytes=0-0"})
    if rh is None:
        return {"path": path, "status": None, "by": by}
    return {"path": path, "status": rh["status"],
            "length": rh.get("declared_length") or rh["length"],
            "ctype": rh["content_type"], "by": by}


# ---------------------------------------------------------------------------
# AI 提议 → 白名单执行 → 审计留痕
# ---------------------------------------------------------------------------
PROPOSE_SYS_PROMPT = (
    "你是渗透测试验证助手。基于已收集的**只读**证据，提出下一轮要探测的端点，"
    "用于判断该目标的暴露面/危害上限。只输出一个 JSON 对象，不要解释文字：\n"
    '{"done": true/false, "probe": ["/path1", "/path2"], "why": "一句话理由"}\n'
    "规则（严格遵守）：\n"
    "1) 只能提出**只读 GET 且不带 query 参数**的路径；\n"
    "2) **禁止**任何写入/上传/删除/创建/修改/重置/重启/登录尝试/口令爆破类路径；\n"
    "3) 最多 4 条；不要重复已探测过的路径；\n"
    "4) 只提出与目标组件（framework/desc）相关的**文档化端点**；\n"
    "5) 不得编造不存在的接口名；证据已足够或不确定时输出 done=true；\n"
    "6) 你的提议会被白名单审核，越界会被拒绝——所以只提你确信属于该组件的端点。"
)


def ai_propose(ai, payload, asked, chat_fn, first_json_fn):
    """让模型提出下一轮探测路径（只提议，不执行）。"""
    body = dict(payload)
    body["already_probed"] = sorted(asked)
    try:
        content, _ = chat_fn(ai.api_url, ai.api_key, ai.assess_model,
                             [{"role": "system", "content": PROPOSE_SYS_PROMPT},
                              {"role": "user", "content": "已有信息如下（JSON）：\n"
                               + json.dumps(body, ensure_ascii=False)}],
                             timeout=ai.timeout, temperature=0.0, max_tokens=1200)
        obj = first_json_fn(content)
        if isinstance(obj, dict):
            return obj
    except Exception as e:
        print("  [AI 提议失败] %s" % e, file=sys.stderr)
    return None


def ai_investigate(*, ai, payload, ev, base, asked, timeout, rounds, mode,
                   fetch, chat_fn, first_json_fn, label="", logger=None):
    """AI 提议 → 白名单校验 → 只读执行 → 证据回填；最多 rounds 轮，全程留痕。

    参数：
        payload     送给模型的上下文（finding + 已有证据）
        ev          证据 dict；结果追加到 ev["next_hop"]，审计写入 ev["probe_audit"]
        asked       已探测过的路径集合（会被就地更新）
        fetch       (url, timeout, max_body, method, extra_headers) -> dict|None
    返回 ev。
    """
    if ai is None or rounds <= 0:
        return ev
    audit = ev.setdefault("probe_audit", [])
    for rnd in range(1, rounds + 1):
        prop = ai_propose(ai, {**payload, "evidence": {k: v for k, v in ev.items()
                                                       if k not in ("body", "_body")}},
                          asked, chat_fn, first_json_fn)
        if not prop or prop.get("done"):
            audit.append({"round": rnd, "proposal": [], "note": "AI 判定无需继续"})
            break
        cand = []
        for path in (prop.get("probe") or [])[:MAX_PROBES_PER_ROUND * 3]:
            if not isinstance(path, str):
                continue
            if path in asked:
                audit.append({"round": rnd, "path": path, "action": "跳过", "why": "已探测过"})
                continue
            ok, why = path_allowed(path, mode)
            if ok:
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
            r = probe_one(fetch, base, path, timeout)
            got.append(r)
            audit.append({"round": rnd, "path": path, "action": "放行",
                          "why": prop.get("why", ""), "status": r.get("status"),
                          "length": r.get("length")})
        ev.setdefault("next_hop", []).extend(got)
        ev["ai_probe_rounds"] = rnd
        msg = "       [AI 提议%s] 第%d轮放行 %d 条：%s" % (
            (" " + label) if label else "", rnd, len(got),
            "、".join("%s=%s" % (g["path"], g.get("status")) for g in got))
        print(msg, flush=True)
        if logger:
            logger.info(msg.strip())
    return ev


def summarize_audit(ev):
    """审计摘要：(放行数, 拒绝数, 拒绝明细列表)。"""
    aud = ev.get("probe_audit") or []
    allow = [a for a in aud if a.get("action") == "放行"]
    rej = [a for a in aud if a.get("action") == "拒绝"]
    return len(allow), len(rej), rej
