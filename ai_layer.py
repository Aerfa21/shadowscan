#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_layer.py —— ShadowScan 的 AI 增能层（可选，--ai 显式开启）

定位：ShadowScan 的核心是"确定性规则引擎"（手写签名 + 正则 + 状态码），
     可靠、零依赖、可长期运营。本模块在**规则引擎之上**增加一层"AI 裁决/研判/解读"，
     让 LLM 在**运行时**出力——这正是"AI 安全应用"与"AI 辅助写脚本"的本质区别。

设计原则：
  1. 解耦：不 import shadowscan，靠传入结构化 findings 工作，可独立测试；
  2. 降级：LLM 调用失败/超时/未配置时，静默返回"未置信"标记，绝不阻塞主流程；
  3. 可审计：每一条 AI 判断都记录模型、置信度、耗时，输出到 ai_findings.jsonl；
  4. 合规：不向 LLM 发送任何口令明文（weak 字段只发"是否命中"，不发账密）。

能力点（对应 --ai 开关下的四个子能力）：
  A  误报裁决  verdict        ：对"签名边界情况"判定真/假阳性，减少漏报/误报
  B  智能报告  smart_report   ：读全部 findings，输出优先级排序 + 修复建议 + 一句话结论
  C  风险研判  risk_assess    ：对单个命中研判真实可利用性/影响面/处置紧迫度
  D  合规映射  compliance     ：把命中映射到合规条款(等保2.0/EU AI Act/ISO 42001/数据安全法)

用法（供 shadowscan.py 调用）：
  from ai_layer import AILayer
  layer = AILayer(api_url=..., api_key=..., model="deepseek-v4-pro", timeout=30)
  layer.enhance(findings)       # 对每条命中做 verdict + risk + compliance
  report = layer.smart_report(findings)
"""
import json
import logging
import os
import re
import time
import urllib.request
import urllib.error

log = logging.getLogger("shadowscan.ai")

# 默认端点（OpenAI 兼容网关，OpenAI 兼容 /v1/chat/completions）
DEFAULT_API_URL = os.environ.get(
    "SHADOWSCAN_LLM_URL",
    "https://your-llm-gateway.example.com/v1/chat/completions")   # 改成你的 OpenAI 兼容端点
DEFAULT_MODEL = os.environ.get("SHADOWSCAN_LLM_MODEL", "deepseek-v4-pro")
# 逐条研判用轻量模型（推理开销小、响应快、成本低）；智能报告用主模型（需深度总结）
ASSESS_MODEL = os.environ.get("SHADOWSCAN_LLM_ASSESS_MODEL", "deepseek-v4-flash")
# 单次调用超时（推理型模型 + 网关并发限流下 60s 偏紧，易误判为失败；默认 120s，可用环境变量/参数覆盖）
DEFAULT_TIMEOUT = int(os.environ.get("SHADOWSCAN_LLM_TIMEOUT", "120"))

# 单次判断的置信度阈值：低于此值视为"AI 不确定"，不据此改判
CONFIDENCE_FLOOR = 0.6

# 命中类别 → 合规条款映射（静态兜底表，AI 可在此基础上做语义细化）
COMPLIANCE_RULES = {
    "druid": ["GB/T 22239-2019（等保2.0）8.1.4 访问控制", "可能导致数据库连接信息/会话/SQL 泄露"],
    "swagger": ["GB/T 22239-2019 8.1.3 安全审计边界", "接口定义暴露扩攻击面，属信息过度暴露"],
    "actuator": ["GB/T 22239-2019 8.1.4 访问控制", "环境变量/堆转储可泄露密钥与源码"],
    "source-leak": ["GB/T 22239-2019 8.1.2 安全计算环境", "源码/配置泄露违反最小暴露原则"],
    "middleware": ["GB/T 22239-2019 8.1.4 访问控制", "中间件管理台未授权可能被接管"],
    "component": ["GB/T 22239-2019 8.1.4 访问控制", "组件指纹确认，需进一步验证默认凭证"],
}


def _mask(data):
    """脱敏：屏蔽口令/API Key 类敏感字段，禁止外发。"""
    if not isinstance(data, dict):
        return data
    out = {}
    for k, v in data.items():
        if k.lower() in ("weak", "password", "passwd", "secret", "apikey", "token"):
            out[k] = "(已脱敏)" if v else ""
        elif isinstance(v, dict):
            out[k] = _mask(v)
        elif isinstance(v, list):
            out[k] = [_mask(x) if isinstance(x, dict) else x for x in v]
        else:
            out[k] = v
    return out


def _chat(api_url, api_key, model, messages, timeout=30, temperature=0.0, max_tokens=2000):
    """调用 OpenAI 兼容 /chat/completions。返回 (content, raw_usage) 或抛异常。
    关键：常见推理型模型会在响应里同时返回 content(最终答案) 与
    reasoning_content(思考过程)。max_tokens 约束的是二者
    之和，若预算不足会先把 content 预留给 reasoning 导致正文为空(finish_reason=length)。
    故：1) max_tokens 必须给足；2) content 为空一律视为失败(抛异常)，绝不能拿
    reasoning_content 冒充正文——它是思考过程，不是答案。"""
    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    req = urllib.request.Request(
        api_url, data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + (api_key or ""),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.loads(r.read().decode("utf-8"))
    msg = resp["choices"][0]["message"]
    content = msg.get("content") or ""
    finish = resp["choices"][0].get("finish_reason", "")
    # content 为空 = 推理型模型把预算耗尽在 reasoning 上(finish_reason=length)，
    # 或网络异常导致正文缺失。此时返回空，交由上层降级处理，绝不拿思考过程冒充。
    if not content:
        raise ValueError("LLM 返回空 content（finish_reason=%s，疑似推理预算不足）" % finish)
    return content, resp.get("usage", {})


def _strip_fence(text):
    """剥掉 LLM 输出最外层多余的 ```markdown / ``` 代码块围栏（保留正文）。"""
    if not text:
        return text
    t = text.strip()
    if t.startswith("```"):
        # 去掉首行 ```markdown 或 ```
        lines = t.split("\n")
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        # 去掉末尾的 ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return t


def _first_json(text):
    """从 LLM 输出里稳健提取第一个 JSON 对象（容忍前后夹带说明文字）。"""
    if not text:
        return None
    # 优先匹配 ```json ... ``` 或 ``` ... ```
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # 兜底：找首个 { 到最后一个 }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


class AILayer:
    def __init__(self, api_url=None, api_key=None, model=None, timeout=None):
        self.api_url = api_url or DEFAULT_API_URL
        self.api_key = api_key or os.environ.get("SHADOWSCAN_LLM_KEY", "")
        self.model = model or DEFAULT_MODEL
        self.assess_model = ASSESS_MODEL
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.available = bool(self.api_url and self.api_key)
        if not self.available:
            log.warning("AI 层未配置（缺 api_key/url），--ai 将跳过全部增强")

    # ------------------------------------------------------------------
    # 内部：单条命中的三合一研判（verdict + risk + compliance）
    # ------------------------------------------------------------------
    def _assess_one(self, f):
        """返回 dict，含 verdict / risk / compliance 三块，失败则返回空标记。"""
        payload = _mask(f)
        sys_prompt = (
            "你是资深应用安全专家，正在核验一个自动化扫描器的命中结果。"
            "你的任务分三部分，必须只输出一个 JSON 对象（不要输出任何解释文字），字段如下：\n"
            "{"
            '"verdict": "true_positive" 或 "false_positive" 或 "uncertain",'
            '"verdict_confidence": 0到1之间的小数,'
            '"verdict_reason": "一句话判断依据",'
            '"risk_level": "critical" 或 "high" 或 "medium" 或 "low",'
            '"exploitability": "一句话真实可利用性（能拿什么/能干什么，不要夸大）",'
            '"priority_action": "最该做的一步处置建议",'
            '"compliance": ["命中的合规条款，可多条，中文表述"]'
            "}\n"
            "判断规则："
            "1) verdict 依据命中描述与状态判断是否真实存在该影子端点（false_positive 仅当明显是误报，如统一 404 页、自定义错误页冒充）；不确定就输出 uncertain；"
            "2) risk_level 综合暴露等级与数据敏感度；"
            "3) 不得编造 CVE 编号，不得给出未经验证的说法。"
        )
        user_prompt = "扫描命中信息如下（JSON）：\n" + json.dumps(payload, ensure_ascii=False)
        try:
            content, _ = _chat(
                self.api_url, self.api_key, self.assess_model,
                [{"role": "system", "content": sys_prompt},
                 {"role": "user", "content": user_prompt}],
                 timeout=self.timeout, temperature=0.0, max_tokens=6000)
            obj = _first_json(content) or {}
        except Exception as e:
            log.warning("AI 研判调用失败 %s: %s", f.get("url"), e)
            return {"verdict": "uncertain", "verdict_confidence": 0.0,
                    "verdict_reason": "AI 调用失败", "risk_level": "",
                    "exploitability": "", "priority_action": "",
                    "compliance": []}
        return obj

    # ------------------------------------------------------------------
    # 能力 A + C + D：对全部命中做逐条研判（并发，避免推理型模型串行太慢）
    # ------------------------------------------------------------------
    def enhance(self, findings, max_workers=3, on_result=None):
        """对每条命中追加 ai_verdict / ai_risk / ai_compliance，返回 (新findings, ai_records)。
        逐条研判并发执行（并发上限 4，避免触发网关限流）；单条超时/失败静默降级为 uncertain，不阻塞主流程。
        on_result(finding, record)：每条研判完成后回调（用于逐条落盘、实现 AI 阶段断点续跑）。"""
        ai_records = [None] * len(findings)

        def _worker(idx_f):
            idx, f = idx_f
            t0 = time.time()
            r = self._assess_one(f)
            cost = round(time.time() - t0, 2)
            return idx, f, r, cost

        from concurrent.futures import ThreadPoolExecutor, as_completed
        workers = min(max_workers, max(1, len(findings)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_worker, (i, f)) for i, f in enumerate(findings)]
            for fut in as_completed(futs):
                try:
                    idx, f, r, cost = fut.result()
                except Exception as e:
                    log.warning("AI 研判线程异常: %s", e)
                    continue
                verdict = r.get("verdict", "uncertain")
                conf = r.get("verdict_confidence", 0.0)
                f["ai_verdict"] = verdict
                f["ai_confidence"] = conf
                f["ai_reason"] = r.get("verdict_reason", "")
                f["ai_risk_level"] = r.get("risk_level", "")
                f["ai_exploitability"] = r.get("exploitability", "")
                f["ai_priority_action"] = r.get("priority_action", "")
                comp = r.get("compliance") or []
                if not comp:
                    comp = COMPLIANCE_RULES.get(f.get("category"), [])
                f["ai_compliance"] = comp
                ai_records[idx] = {
                    "url": f.get("url"), "framework": f.get("framework"),
                    "category": f.get("category"), "verdict": verdict,
                    "confidence": conf, "risk_level": r.get("risk_level", ""),
                    "compliance": comp, "model": self.assess_model,
                    "latency_s": cost, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                }
                if on_result is not None:
                    try:
                        on_result(f, ai_records[idx])
                    except Exception as e:
                        log.warning("AI 结果回调失败 %s: %s", f.get("url"), e)
        ai_records = [r for r in ai_records if r]
        return findings, ai_records

    # ------------------------------------------------------------------
    # 能力 B：智能报告（读全部命中，输出优先级排序 + 结论）
    # ------------------------------------------------------------------
    def smart_report(self, findings):
        """返回一段 Markdown 智能报告正文；调用失败返回 None。"""
        if not findings:
            return None
        # 只发摘要字段，控制 token 并二次脱敏
        summary = []
        for f in findings:
            summary.append(_mask({
                "site": f.get("site"), "url": f.get("url"),
                "framework": f.get("framework"), "category": f.get("category"),
                "exposure": f.get("exposure"), "desc": f.get("desc"),
                "weak_hit": bool(f.get("weak")),
            }))
        sys_prompt = (
            "你是资深应用安全负责人，正在给管理层写一份影子端点扫描的整改结论。"
            "基于给定命中清单，输出 Markdown，包含："
            "1) 一段 2~3 句的总体结论（这批风险到底严重到什么程度）；"
            "2) 一个优先级排序表（列：优先级/站点/端点/原因/建议动作，按 risk 从高到低，最多列前 8 项）；"
            "3) 3 条落地整改动作（可执行、可验收）。"
            "语气务实、不说教、不夸大。不得编造数据。")
        user_prompt = "命中清单（JSON 数组）：\n" + json.dumps(summary, ensure_ascii=False)
        try:
            content, _ = _chat(
                self.api_url, self.api_key, self.model,
                [{"role": "system", "content": sys_prompt},
                 {"role": "user", "content": user_prompt}],
                timeout=max(self.timeout, 180), temperature=0.2, max_tokens=8000)
            content = _strip_fence(content)
            return content
        except Exception as e:
            log.warning("AI 智能报告生成失败: %s", e)
            return None