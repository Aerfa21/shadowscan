# ShadowScan AI 增能层 —— 能力与使用说明

> 本文档回答一个问题：**确定性扫描器之上，LLM 到底能帮上什么忙，怎么接，怎么用。**
> 归属 AI4SEC 体系 / AI 安全应用动手实践（方向 2 归档）。

---

## 〇、定位：AI 是必要环节，不是可选增强

本工具的目标是**「找得到 + 看得准」**：规则库保证覆盖，**AI 保证精准**。
常规扫描器的问题不是「扫不到」，而是「扫到一堆、判不准」——影子端点必须精准，
一条误报就会让整改失去信任。

**推荐用法（生产模式）**：

```bash
source env.sh
python3 shadowscan.py --targets assets.txt --production --authorized -o out
```

`--production` ≡ `--ai --adaptive`，即同时开启：

- **扫描期**：AI 自适应扩探（提议 → 白名单 → 只读探测），发现规则库之外的端点；
- **扫描后**：AI 证据验证与研判（回抓真实响应、有界追问、真伪/危害/合规）。

> 「可降级」是**工程健壮性**（AI 不可用时扫描照跑、不阻塞），不是「可选项」——
> 定位上 AI 是达成精准的必要环节；降级运行的结果**不作为结论**，需人工复核。

---

## 一、为什么要有这一层

ShadowScan 的核心是**确定性规则引擎**（手写签名 + 正则 + 状态码判定），可靠、零依赖、可长期运营。但它有三个天花板：

| 天花板 | 规则引擎的局限 | 增能层补位 |
|---|---|---|
| 误报 | 签名命中≠真漏洞，边界情况会误报 | **A 误报裁决**：LLM 判真/假阳性 |
| 解读 | 只给"命中了"，不说"多严重、怎么办" | **C 风险研判 + B 智能报告** |
| 对齐 | 命中不自动关联合规/治理要求 | **D 合规语义映射** |

本质区别：规则引擎是"写码时用 AI 辅助"，增能层是"**运行时让 LLM 出力**"——后者才是真正的 AI 安全应用。

---

## 二、四个能力点（A/B/C/D）

| 能力 | 方法 | 输入 | 输出 | 用哪个模型 |
|---|---|---|---|---|
| **A 误报裁决** | `enhance()` 内 verdict 判定 + **报告落地过滤** | 单条命中的 URL/类别/签名 | `true_positive`/`false_positive` + 置信度；高置信假阳性从报告正文剔除 | flash |
| **B 智能报告** | `smart_report()` | 全量 findings | 优先级表 + 整改动作 + 结论 | pro |
| **C 风险研判** | `enhance()` 内 risk 分级 | 单条命中 | critical/high/medium/low + 可利用性说明 | flash |
| **D 合规映射** | `enhance()` 内 compliance | 命中类别 | 等保2.0/数据安全法/EU AI Act 条款 | flash |

**模型分工原则**：
- 逐条研判（A/C/D）**量大、要求快** → 用 `deepseek-v4-flash`；
- 智能报告（B）**要深度总结、只需一次** → 用 `deepseek-v4-pro`。

---

## 三、架构与降级策略

```
shadowscan.py (主流程)
   │  --ai 显式开启
   ▼
ai_layer.py (增能层，解耦、无反向 import)
   ├─ AILayer.enhance(findings)   → 逐条 verdict + risk + compliance
   └─ AILayer.smart_report(findings) → 一段 Markdown 报告
```

**四条设计红线**：
1. **解耦**：不 import shadowscan，靠传入结构化 findings 工作，可独立单测；
2. **降级**：LLM 调用失败/超时/未配置时，静默降级为 `uncertain`，**绝不阻塞主流程**——AI 挂了扫描照跑；
3. **可审计**：每一条 AI 判断记录模型、置信度、耗时，落 `ai_findings.jsonl`；
4. **合规**：不向 LLM 发送任何口令明文（weak 字段只发"是否命中"，不发账密）。

---

## 四、使用方法

### 1. 快速开始

```bash
# 开启 AI 增能层（默认接某企业 LLM 网关，关键：显式加 --ai）
export SHADOWSCAN_LLM_KEY="你的-KEY"
python3 shadowscan.py --targets assets.txt --authorized --ai -o out
```

不加 `--ai` 时，扫描器就是纯规则引擎（默认关闭，符合"随时可回退"）。

### 2. 参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `--ai` | 开启增能层（四个能力全开） | 关闭 |
| `--ai-key` | LLM Key | 读环境变量 `SHADOWSCAN_LLM_KEY` |
| `--ai-model` | 主模型（报告用） | `deepseek-v4-pro` |
| `--ai-keep-fp` | 关闭误报过滤（保留全部命中在正文） | 关闭（即默认过滤） |
| `--ai-min-confidence` | 判定假阳性并剔除的最低置信度 | 0.6 |
| `--ai-timeout` | AI 单次调用超时秒数 | 120（报告 180） |

### 3. 可配置环境变量（ai_layer.py 内）

| 变量 | 作用 | 默认 |
|---|---|---|
| `SHADOWSCAN_LLM_URL` | 网关地址 | `https://your-llm-gateway.example.com/v1/chat/completions` |
| `SHADOWSCAN_LLM_MODEL` | 主模型 | `deepseek-v4-pro` |
| `SHADOWSCAN_LLM_ASSESS_MODEL` | 研判轻量模型 | `deepseek-v4-flash` |
| `SHADOWSCAN_LLM_KEY` | API Key | 空 |
| `SHADOWSCAN_LLM_TIMEOUT` | 单次调用超时(秒) | 120 |

### 4. 输出

| 文件 | 内容 |
|---|---|
| `report.md` | 正文命中清单（已剔除 AI 判定的高置信假阳性）；新增「AI 已排除（疑似误报）」与「AI 智能研判」章节 |
| `findings.csv` | 全量命中，新增 `ai_verdict`/`ai_risk_level`/`ai_confidence` 列 |
| `findings.jsonl` | 全量命中（含被排除项，数据不丢） |
| `ai_findings.jsonl` | 逐条 AI 判决：verdict / confidence / risk_level / compliance / latency_s / model |

### 5. 误报过滤（能力 A 的落地）

`--ai` 下，逐条研判若判定为 `false_positive` 且置信度 ≥ `--ai-min-confidence`（默认 0.6），该命中会：

- **从报告正文的命中清单与风险摘要中剔除**（降噪）；
- **移入「AI 已排除（疑似误报）」章节**并附判断依据与置信度（可人工复核、可回捞）；
- **仍保留在 `findings.jsonl` / `findings.csv`**（数据不丢，CSV 带 AI 列）。

关闭过滤：加 `--ai-keep-fp`（保留全部命中在正文）。

---

## 五、接入注意事项

接入推理型模型时需要注意以下几点：

1. **`max_tokens` 约束的是 reasoning+content 之和**，推理型模型思考过程会把正文挤空（`finish_reason=length`）；
2. **兜底逻辑禁用 reasoning_content 冒充正文**——content 为空应报错降级，绝不拿"内心独白"当答案；
3. **常见推理型模型都会返回 `reasoning_content`**，差别只在推理程度；
4. **报告类长任务 max_tokens 要给足**（8000），逐条研判 4000；
5. **并发过高触发网关限流**，研判并发降到 4（已进一步降到 3）；
6. **默认超时 60s 偏紧**：推理型模型 + 网关限流下，个别研判/报告会超时被误判为失败（表现为 `uncertain` + 报告缺失）。已将默认超时提到 120s、报告类 180s，并提供 `--ai-timeout` / `SHADOWSCAN_LLM_TIMEOUT` 可调。
7. **审计字段必须写实际使用的模型**，避免记录错误。

---

## 六、三层能力与安全阀

AI 能力分三层，适用场景不同：

| 层 | 组件 | 输入给模型的东西 | 能力 | 局限 |
|---|---|---|---|---|
| ① 盲判 | `ai_layer.py`（`--ai`） | **只有命中记录**（url/status/desc，脱敏） | 误报裁决 / 风险研判 / 合规映射 | **看不到真实响应** → 扫描器说错它就跟着错 |
| ② 证据驱动 | `tools/verify_layer.py` | **命中记录 + 真实响应证据包** | 真伪 / 危害等级 / 利用前置是否成立 / 处置建议 | 只做「定性」，不做「发现」 |
| ③ 约束型智能体 | `tools/probe_policy.py` + `--adaptive` | 证据 + **允许 AI 提议下一步探什么** | AI 提议 → 白名单校验 → 只读探测 → 多轮追问 | 提议受白名单约束（刻意） |

### 安全阀：真正的约束是「方法 + 副作用」，不是路径

| 约束 | 作用 |
|---|---|
| 只用 GET/HEAD | HTTP 语义上无状态变更 |
| **禁止 query string** | 无法参数注入、无法触发定向动作 |
| 只取状态码/声明长度 | 不下载堆转储、不落地数据 |
| 不提交任何凭据 | 无爆破、无登录尝试 |
| 危险动词黑名单（23 个） | 拦住 login/delete/upload/exec… 类路径 |
| 规则表路径直通 | 工具自身词汇表，避免误拒反而收窄发现 |

**两层白名单**（职责不同，不该共用一套）：

| 模式 | 用于 | 宽度 |
|---|---|---|
| `MODE_SCAN` | `shadowscan --adaptive`（**发现**） | 宽：63 条组件端点族 ∪ 通用只读类 |
| `MODE_VERIFY` | `verify_layer`（**定性**） | 窄：只放行与该发现组件相关的族 |

**全程审计留痕**：每条提议记录「放行/拒绝 + 理由 + 结果」→ `adaptive_audit.jsonl` / `probe_audit` 字段。

### 怎么选

| 场景 | 建议 |
|---|---|
| 快速扫一批、要零成本 | 纯规则（不加 `--ai`） |
| 已有结果，要判断**哪些真有危害** | `verify_layer.py`（证据驱动，**推荐**） |
| 发现阶段想要更广的覆盖 | `shadowscan --adaptive`（**默认关**；对外部资产建议保持关闭） |

---

## 七、后续可扩展

- 把 A/B/C/D 封装成可独立调用的 CLI（`python3 ai_layer.py --report findings.jsonl`）；
- 增能层结论回写 CAASM 平台的资产风险标签；
- 合规映射从静态兜底表升级为「条款条文级」向量召回。