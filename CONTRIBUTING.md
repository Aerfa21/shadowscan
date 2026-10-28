# 贡献指南

感谢有兴趣参与。这个项目最需要的是**规则补充**——影子端点五花八门，规则库永远不够全。

---

## 最有价值的贡献：新增一条规则

规则库是「端点路径 × 命中签名」的清单，位于 `shadowscan.py` 的 `ENDPOINT_RULES`。
新增一条只需加一行记录：

```python
{"framework": "Jenkins", "cat": "middleware", "path": "/jenkins/",
 "sign": ["Jenkins"], "desc": "Jenkins 控制台"},
```

### 字段说明

| 字段 | 必填 | 说明 |
|---|---|---|
| `framework` | ✅ | 组件名（出现在报告里） |
| `cat` | ✅ | 类别，取值见下表 |
| `path` | ✅ | 端点路径（`/` 开头的规则只在根前缀测一次） |
| `sign` | ⚠️ | 命中签名列表，**任一命中即算命中** |
| `header_sign` | ⚠️ | 按响应头判定（与 `sign` 二选一或并用） |
| `desc` | ✅ | 一句话说明 |
| `binary` | | 二进制资源（配合 `magic` 做魔数校验） |
| `magic` | | 文件魔数，如 `JAVA PROFILE`、`Bud1` |
| `no_html` | | 返回 HTML 则判否（用于 `.svn/entries` 这类非 HTML 资源） |
| `self_path` | | 要求响应体引用自身路径（上下文型端点用） |
| `login_page` | | 登录页类，未验证出默认口令时降级为信息项 |
| `auth_401` + `auth_realm` | | 401 + 指定认证域判定（如 Tomcat Manager） |

### `cat` 取值

`druid` · `swagger` · `actuator` · `source-leak` · `middleware` ·
`apm` · `cloud-native` · `bigdata` · `db-admin` · `component`

---

## 加规则时的五条约定

**1. 签名用特征词，不用通用词。**

`sign` 是"任一命中"，所以签名里的每个词都会单独生效。像 `Swagger`、`Druid`、`login` 这类
**通用英文词**，会被任何提到它的页面命中——一个含 "swagger" 的首页就能造出一条误报。

推荐做法：用**组件独有的路径片段或字面量**，例如：

```python
# ✗ 会被任意含 swagger 的页面命中
"sign": ["knife4j", "Swagger"]

# ✓ 只命中真正的 Knife4j 页面
"sign": ["knife4j"]
```

**2. JSON 类端点请加进 `JSON_ENDPOINTS`。**

很多 catch-all 站点对任意路径都返回首页 HTML。JSON 端点如果只靠内容签名，
就会被这类页面命中。加进 `JSON_ENDPOINTS` 后会强制校验「content-type 含 json 或正文以 `{`/`[` 开头」。

**3. 上下文型端点加 `self_path`。**

真实应用会引用自身路径（如 xxl-job 的 favicon 是 `/xxl-job-admin/static/...`），
站点兜底首页不会。加 `self_path: True` 可过滤掉这类误报。

**4. 登录页类端点加 `login_page`。**

`/admin/login/`、`/druid/login.html` 这类"登录页公网可达"属常态，价值低。
加 `login_page: True` 后，未验证出默认口令时会降级为「信息项」。

**5. 加完做一次语法检查。**

```bash
python3 -m py_compile shadowscan.py
```

---

## 提 PR 前

```bash
python3 -m py_compile shadowscan.py ai_layer.py tools/*.py
```

PR 描述里请说明：

- 新增/修改了什么规则，针对哪个组件；
- 为什么选这个签名（最好附一条真实响应片段，**域名请脱敏**）；
- 回归测试结果。

---

## 其它方向的贡献

| 方向 | 说明 |
|---|---|
| 新工具 | `tools/` 下的辅助脚本（对比、转换、复核…） |
| 判定加固 | 减少误报的机制（如新的 catch-all 识别方式） |
| 文档 | 使用说明、故障排查、翻译 |
| Bug | 直接提 Issue，附复现步骤与最小样例 |

---

## 不要做的事

- **不要提交真实资产信息**——报告、日志、`env.sh` 里的凭据一律不要进仓库；
- **不要提交爆破/利用类功能**——本工具定位是「无触点专项巡检」，不爆破、不触发 RCE、不上传载荷；
- **不要提交大文件**——仓库保持轻量。

---

## 代码风格

- 零第三方依赖（仅 `tools/` 下 PPT 相关工具例外，用 `python-pptx`）；
- 注释写"为什么"，不写"是什么"；
- 关键判定逻辑请补注释说明它防的是哪类误报。
