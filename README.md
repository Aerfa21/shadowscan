# ShadowScan · 影子端点专项扫描器

> 针对「框架自带、上线后忘了关」的调试 / 监控 / 管理端点做专项排查。
> 规则库负责**找得到**，AI 负责**看得准**。

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#依赖)

---

## 这是什么

ShadowScan 扫描**影子端点（shadow endpoints）**——框架自带、开发期方便、上线后常被遗留的调试 / 监控 / 管理端点：

| 类别 | 例子 |
|---|---|
| 监控 / 管理台 | Druid 监控台、Nacos、xxl-job、Tomcat Manager、Jenkins、Solr、Zabbix |
| 接口文档 | Swagger UI、Knife4j、`/v2/api-docs` |
| Spring Boot Actuator | `/actuator/env`、`/heapdump`、`/mappings` |
| 源码 / 配置泄漏 | `/.git/config`、`/.svn/entries`、`/.env`、`/.DS_Store`、`/web.xml` |
| 云原生 / 大数据 | K8s API、Harbor、MinIO、HDFS、Spark、Flink |

这些端点不在业务设计里，资产台账上也查不到，但一旦暴露往往可以直接读到配置、密钥、内存转储，或还原源码。

**当前规则库**：81 条规则 / 9 个类别 · 34 个探测端口。

### 不做的事

不是综合漏洞扫描器——**不查** SQLi / XSS / 命令注入，**不查**组件 CVE / 反序列化利用。
只把「影子端点」这一类做深做透。

---

## 为什么需要它：常规漏扫扫不到

影子端点扫不到，根源大多在**路径**上：

| 难点 | 说明 |
|---|---|
| 只测固定路径 | 只打 `/admin`、`/login` 等标准路径；`/druid`、`/actuator`、`/.git` 不在字典里 |
| 不认上下文前缀 | 应用部署在 `/portal` 下时，真实路径是 `/portal/actuator/env`，只打根路径必然漏 |
| 靠状态码判断 | Java 应用对任意路径都可能返回 200 或统一错误页，靠 200/404 判断会大量误报漏报 |
| 认证后不可达 | 很多端点需登录态，未带 cookie 时返回登录页，容易被判为"不存在" |

**对应设计**：

- **内容签名判定**（而非状态码）——比对响应内容特征，规避 Java 统一 404 的假阳性；
- **上下文前缀拼接**——轻爬首页提取顶层路径，按「前缀 × 端点」组合扫描；
- **规则库直击**——不依赖目录字典，规则即端点路径 + 命中签名。

---

## 核心特性

### 1. 三层 AI（可选，但推荐）

AI 不是"锦上添花"，而是达成**精准**的关键。三层分别位于扫描期与扫描后：

```
shadowscan.py（确定性规则引擎，零依赖，可独立运行）
      │
      ├─ AI 层① 自适应扩探（扫描期）   AI 提议 → 白名单 → 只读探测
      ├─ AI 层② 证据验证（扫描后）     回抓真实响应 → 证据包 → 有界追问
      └─ AI 层③ 增能研判（扫描后）     误报裁决 / 风险研判 / 合规映射 / 智能报告
```

```bash
source env.sh
python3 shadowscan.py --targets assets.txt --production --authorized -o out
# --production ≡ --ai --adaptive
```

> 只跑纯规则也可以（去掉 `--production`）。AI 未配置或不可用时自动降级，扫描照跑。

**关键设计：AI 看到的是「真实响应」，不是「扫描器的结论」。**

把命中的记录直接发给 LLM 让它判真伪，效果并不好——模型看到的只是"扫描器说这是未授权访问"，
它没法质疑。实测中一批 34 条命中，盲判把 4 条误报**全部判为真阳性**（其中包括返回
`{"code":401,"msg":"认证失败"}` 的页面和 302 跳转页）。

改成先回抓真实响应构建**证据包**再交给模型后，同一批数据自动排除 3 条误报，与人工复核结论一致。
证据包含：状态码 / Content-Type / 长度 / 正文片段（脱敏）/ 重定向链 / 认证失败特征 /
catch-all 比对 / 双视角对照 / 有界下一跳追问。

### 2. 安全阀：AI 提议，代码执行

给 AI 提议权（"再探这几个端点"）之后，需要保证它不会越界。真正起作用的不是路径白名单，
而是**方法 + 副作用的约束**：

| 硬约束 | 作用 |
|---|---|
| 只用 `GET` / `HEAD` | HTTP 语义上无状态变更 |
| 禁止 query string | 无法参数注入、无法触发定向动作 |
| 只取状态码与声明长度 | 不下载堆转储、不落地数据 |
| 不提交任何凭据 | 无爆破、无登录尝试 |
| 危险动词黑名单（23 个） | 拦住 `login` / `delete` / `upload` / `exec`… |

每条提议都记录「放行 / 拒绝 + 理由 + 结果」到 `adaptive_audit.jsonl`，可审计。

### 3. 误报治理：四层防护

| 层 | 机制 | 解决什么 |
|---|---|---|
| 1 | 前缀堆叠去重 | 同一端点被 `/app` `/web` `/manage` `/admin` 重复命中 |
| 2 | JSON 端点校验 | JSON 端点在 catch-all 站点返回 HTML 被误判 |
| 3 | `self_path` 校验 | 上下文型端点被站点兜底首页误命中 |
| 4 | catch-all 守卫 | 随机路径探一次，与首页同正文 → 该站点内容签名命中一律判否 |
| + | 跨协议去重 | 同一发现在 http/https 各报一条 |

### 4. 大规模运行

- **两级断点**：站点级（`checkpoint.jsonl`）+ AI 判决级（`ai_checkpoint.jsonl`），中断可续、不重算；
- **分片并行**：`--shard i/n` 多机同时跑；
- **两阶段 AI**：先纯规则全量快扫，再对结果跑 AI（`--ai-only`），可控成本；
- **限速与抖动**：`--rate-limit` / `--jitter`，降低 WAF 拦截与规律性流量特征。

---

## 快速开始

### 依赖

**零第三方依赖**——仅需 Python 3.8+（标准库）。

### 安装

```bash
git clone <repo-url> && cd shadowscan
cp env.example.sh env.sh && chmod 600 env.sh
# 编辑 env.sh，填入你的 OpenAI 兼容 LLM 端点与 key（不启用 AI 可跳过）
```

### 跑一次

```bash
# 资产清单：每行一个（# 注释）
#   http://app.example.com    显式 URL
#   app2.example.com          域名（自动探测常见 Web 端口）
#   10.0.0.10:8080         指定端口
python3 shadowscan.py --targets assets.txt --production --authorized -o out

# 纯规则（不用 AI）
python3 shadowscan.py --targets assets.txt --authorized -o out

# 开启弱口令验证（仅内置默认口令表，不爆破）
python3 shadowscan.py --targets assets.txt --weak-check --authorized -o out
```

### 上机自检

```bash
python3 tools/preflight_check.py --targets assets.txt
# 检查：LLM 网关是否可达、key 是否有效、目标是否可达
```

---

## 输出

| 文件 | 内容 |
|---|---|
| `report.md` | 聚合报告（风险摘要 / 按站点分布 / 命中清单 / 整改建议） |
| `report.html` | 自包含 HTML 报告（零依赖，可直接打开 / 转发） |
| `findings.csv` | 全量命中（含 AI 列），Excel 可打开 |
| `findings.jsonl` | 机器可读明细 |
| `ai_findings.jsonl` | 逐条 AI 判决（模型 / 置信度 / 耗时） |
| `adaptive_audit.jsonl` | AI 扩探的提议审计（放行 / 拒绝 + 理由） |
| `scan.log` | 审计日志 |

---

## 工具链

`tools/` 下 4 个工具：

| 工具 | 用途 |
|---|---|
| `preflight_check.py` | 上机自检（网关 + 目标可达性） |
| `batch_scan.sh` | 分批 / 分片 / 限速 / 断点续跑编排 |
| `verify_layer.py` | **验证层**：证据驱动研判（回抓真实响应 + 有界追问） |
| `probe_policy.py` | **共享探测策略**：两层白名单 + 只读约束 + 审计留痕 |

---

## 扩展规则

规则库是「端点路径 × 命中签名」的清单，新增一条只需加一行记录（见 `shadowscan.py` 的 `ENDPOINT_RULES`）：

```python
{"framework": "Jenkins", "cat": "middleware", "path": "/jenkins/",
 "sign": ["Jenkins"], "desc": "Jenkins 控制台"},
```

建议：

1. **签名用特征词，不用通用词**——`Swagger` 这种泛词会被任何提到它的页面命中；
2. JSON 类端点请加进 `JSON_ENDPOINTS`，强制返回 JSON；
3. 上下文型端点可加 `self_path: True`（要求响应体引用自身路径）；
4. 登录页类端点可加 `login_page: True`（降级为信息项）；
5. 加完做一次语法检查：`python3 -m py_compile shadowscan.py`。

详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 合规边界

**本工具仅可用于已获书面授权的资产。**

- 必须显式声明 `--authorized`；
- 不爆破（弱口令仅内置默认口令表 ≤3 组合）；
- 不触发 RCE 利用、不下载大文件（上限 2MB）；
- AI 扩探只发 `GET`/`HEAD`、禁 query、不提交凭据，受白名单约束并全程留痕；
- 生产网络请控制并发与节奏（`--rate-limit` / `--max-workers`），审计日志留痕可追溯。

> ⚠️ 公网资产扫描前请核实归属（云主机 / 共享 IP 可能不属于你），并提前报备 SOC / 云厂商。

---

## 许可

[Apache License 2.0](LICENSE)

## 贡献

欢迎提 Issue 与 PR，尤其是**新规则补充**。见 [CONTRIBUTING.md](CONTRIBUTING.md)。
