#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan v2.1.0 —— 影子端点专项扫描器（企业资产批量版 / 内外网通用）
针对"框架影子端点"（Druid 监控台 / Swagger·Knife4j / Spring Boot Actuator /
源码泄漏 .git/.svn / 中间件管理台等）做全资产专项排查，输出聚合报告。

核心链路：
  资产清单(域名/IP/URL) → ① 站点发现(域名解析+常见Web端口探测+HTTP/HTTPS存活)
                          → ② 框架指纹(响应头/报错页/页面特征)
                          → ③ 上下文前缀收集(轻爬首页提取顶层路径 + 兜底前缀)
                          → ④ 前缀 × 影子端点规则库扫描(内容签名判定+暴露分级)
                          → ⑤ 聚合报告(CSV/JSONL/summary.md/审计日志)

与 EASM/CAASM 平台产品的差异：无持久化、无工作流，跑一次出一份专项报告。
合规：必须 --authorized；不爆破、不触发RCE利用、弱口令验证(--weak-check)仅内置默认口令表；
      请求节奏受 --max-workers / --timeout 控制，审计日志留痕。

用法：
  python3 shadowscan.py --targets assets.txt --authorized -o out
  python3 shadowscan.py --targets "http://app.example.com,10.0.0.0/24" --weak-check --authorized -o out
  资产文件每行一个：URL / 域名 / IP / IP:端口 均可，# 注释

外网增强（V2.1.0）：支持 chunked/gzip 解码、307/308 跨主机重定向、限速+抖动、扩端口。
  python3 shadowscan.py --targets assets.txt --rate-limit 3 --jitter 0.5 --max-workers 4 --authorized -o out
"""
import argparse
import base64
import csv
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

# 让同目录下的 tools/ 可被导入（--adaptive 复用 tools/probe_policy.py）
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))

VERSION = "2.1.0"
UA = "ShadowScan/" + VERSION

# 常见 Web 服务端口（对无显式端口的资产探测）——外网扩端口
WEB_PORTS = [80, 81, 88, 443, 4443, 3000, 5000, 5601, 7001, 7002, 8000, 8001, 8008,
             8080, 8081, 8082, 8088, 8090, 8161, 8180, 8443, 8444, 8880, 8888, 9000,
             9001, 9080, 9090, 9200, 9443, 10000, 10443, 18080, 28080]
# 默认按 HTTPS 优先尝试的端口
HTTPS_PORTS = {443, 4443, 8443, 8444, 9443, 10443}
# 兜底上下文前缀（在爬取结果之外补充）
FALLBACK_PREFIXES = ["", "/app", "/web", "/manage", "/admin"]

# ---------------------------------------------------------------------------
# 端点规则库：framework / 分类 / 路径 / 命中签名 / 类型
# ---------------------------------------------------------------------------
ENDPOINT_RULES = [
    # Druid
    {"framework": "Druid", "cat": "druid", "path": "/druid/index.html",
     "sign": ["Druid", "StatViewServlet", "druidStatView"], "desc": "Druid监控台首页"},
    # 修复误报 ③：/druid/login.html 仅凭 loginUsername/loginPassword 关键字，
    # 会被 Nextcloud 等 SPA/catch-all 兜底页误命中。改用“druid 专属动作端点”作为强签名：
    # 真实 Druid 登录页表单 action 指向 /druid/submitLogin；catch-all 兜底页不含该端点。
    {"framework": "Druid", "cat": "druid", "path": "/druid/login.html",
     "sign": ["loginUsername", "loginPassword", "submitLogin"], "login_page": True, "desc": "Druid监控台登录页"},
    {"framework": "Druid", "cat": "druid", "path": "/druid/websession.json",
     "sign": ["session", "principal", "createTime"], "desc": "Druid Session列表"},
    {"framework": "Druid", "cat": "druid", "path": "/druid/sql.json",
     "sign": ["sql", "executeCount"], "desc": "Druid SQL监控数据"},
    {"framework": "Druid", "cat": "druid", "path": "/druid/datasource.json",
     "sign": ["url", "username", "dbType"], "desc": "Druid 数据源信息"},
    # Swagger / Knife4j / springdoc
    {"framework": "Swagger", "cat": "swagger", "path": "/swagger-ui.html",
     "sign": ["swagger-ui", "SwaggerUIBundle"], "desc": "Swagger UI"},
    {"framework": "Swagger", "cat": "swagger", "path": "/swagger-ui/index.html",
     "sign": ["swagger-ui", "SwaggerUIBundle"], "desc": "Swagger UI(新版路径)"},
    {"framework": "Swagger", "cat": "swagger", "path": "/doc.html",
     "sign": ["knife4j", "Swagger"], "desc": "Knife4j 文档页"},
    {"framework": "Swagger", "cat": "swagger", "path": "/v2/api-docs",
     "sign": ["swagger", "\"paths\"", "\"info\""], "desc": "OpenAPI v2 定义"},
    {"framework": "Swagger", "cat": "swagger", "path": "/v3/api-docs",
     "sign": ["openapi", "swagger", "\"paths\""], "desc": "OpenAPI v3 定义"},
    {"framework": "Swagger", "cat": "swagger", "path": "/swagger-resources",
     "sign": ["location", "swagger"], "desc": "Swagger 资源配置"},
    # Spring Boot Actuator
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator",
     "sign": ["_links", "health"], "desc": "Actuator 端点索引"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/env",
     "sign": ["propertySources", "activeProfiles", "spring.datasource"], "desc": "Actuator 环境配置(可能含口令)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/heapdump",
     "sign": [], "status": 200, "binary": True, "magic": "JAVA PROFILE",
     "desc": "Actuator 堆转储(可提取密钥)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/mappings",
     "sign": ["contexts", "mappings"], "desc": "Actuator 接口映射(全量路由)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/configprops",
     "sign": ["contexts", "beans"], "desc": "Actuator 配置属性"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/gateway/routes",
     "sign": ["route_id", "uri"], "desc": "网关路由"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/health",
     "sign": ["status", "UP"], "desc": "Actuator 健康检查"},
    # 源码 / 配置泄漏
    {"framework": "Git", "cat": "source-leak", "path": "/.git/config",
     "sign": ["repositoryformatversion", "[core]"], "desc": "Git 仓库泄漏"},
    {"framework": "Git", "cat": "source-leak", "path": "/.git/HEAD",
     "sign": ["ref: refs/heads"], "desc": "Git HEAD 泄漏"},
    {"framework": "SVN", "cat": "source-leak", "path": "/.svn/entries",
     "sign": ["dir", "file", "svn"], "no_html": True, "desc": "SVN 元数据泄漏"},
    {"framework": "DS_Store", "cat": "source-leak", "path": "/.DS_Store",
     "sign": [], "status": 200, "binary": True, "magic": "Bud1",
     "desc": ".DS_Store(目录结构)"},
    {"framework": "Backup", "cat": "source-leak", "path": "/web.xml",
     "sign": ["web-app", "servlet"], "no_html": True, "desc": "Java Web 配置泄漏"},
    # 中间件管理台
    # Tomcat Manager：改用“Basic 认证域指纹 + 后端容器指纹”双因子判定，见 auth_401 命中分支。
    # 旧规则仅凭“任意 401 + 任意 WWW-Authenticate”即报 Tomcat，导致 nginx/OpenResty 前置 Basic 认证
    # （higanbana/jamfdp/tjavdl 空壳）全被误判为 Tomcat Manager（误报 ① ②）。
    {"framework": "Tomcat", "cat": "middleware", "path": "/manager/html",
     "sign": [], "auth_401": True, "auth_realm": "Tomcat Manager Application", "login_page": True,
     "desc": "Tomcat Manager"},
    {"framework": "Nacos", "cat": "middleware", "path": "/nacos/v1/auth/users",
     "sign": ["username", "pageItems"], "desc": "Nacos 用户列表"},
    {"framework": "Nacos", "cat": "middleware", "path": "/nacos/",
     "sign": ["nacos"], "desc": "Nacos 控制台"},
    {"framework": "Nacos", "cat": "middleware", "path": "/nacos/v1/console/namespaces",
     "sign": ["namespaceShowName"], "desc": "Nacos 命名空间接口(未授权可读元数据)"},
    {"framework": "xxl-job", "cat": "middleware", "path": "/xxl-job-admin/",
     "sign": ["XXL-JOB"], "self_path": True, "desc": "xxl-job 调度中心"},
    # --- 外网高价值补充：Actuator 更多端点 ---
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/beans",
     "sign": ["contexts", "beans"], "desc": "Actuator Bean 列表"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/threaddump",
     "sign": ["threadName", "threads"], "desc": "Actuator 线程转储"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/loggers",
     "sign": ["loggers", "configuredLevel"], "desc": "Actuator 日志配置(可动态调级)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/httptrace",
     "sign": ["traces", "request"], "desc": "Actuator HTTP 追踪(含请求明细)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/jolokia",
     "sign": ["jolokia"], "desc": "Actuator Jolokia(JMX 代理)"},
    {"framework": "SpringBoot", "cat": "actuator", "path": "/actuator/gateway/globalfilters",
     "sign": ["globalfilters", "RouteDefinition"], "desc": "网关全局过滤器"},
    # --- 外网高价值补充：源码/配置泄漏 ---
    {"framework": "Env", "cat": "source-leak", "path": "/.env",
     "sign": ["DB_PASSWORD", "DB_HOST", "SECRET_KEY", "APP_ENV"], "desc": ".env 配置文件泄漏"},
    {"framework": "PHPInfo", "cat": "source-leak", "path": "/phpinfo.php",
     "sign": ["phpinfo()", "PHP Version"], "desc": "phpinfo 信息泄漏"},
    {"framework": "JavaWeb", "cat": "source-leak", "path": "/WEB-INF/web.xml",
     "sign": ["<web-app", "servlet-name"], "desc": "WEB-INF 配置泄漏"},
    # --- 外网高价值补充：中间件/平台管理台 ---
    {"framework": "Jenkins", "cat": "middleware", "path": "/jenkins/",
     "sign": ["Jenkins"], "desc": "Jenkins 控制台"},
    {"framework": "Grafana", "cat": "middleware", "path": "/api/health",
     "sign": ["database", "version"], "desc": "Grafana 健康接口(确认暴露)"},
    {"framework": "Prometheus", "cat": "middleware", "path": "/graph",
     "sign": ["Prometheus"], "desc": "Prometheus 控制台"},
    {"framework": "Kibana", "cat": "middleware", "path": "/app/kibana",
     "sign": ["kibana"], "desc": "Kibana 控制台"},
    {"framework": "Elasticsearch", "cat": "middleware", "path": "/",
     "sign": ["You Know, for Search", "cluster_name"], "desc": "Elasticsearch 未授权访问"},
    {"framework": "RabbitMQ", "cat": "middleware", "path": "/api/overview",
     "sign": ["rabbitmq_version", "management_version"], "desc": "RabbitMQ 管理接口"},
    {"framework": "Zabbix", "cat": "middleware", "path": "/zabbix/",
     "sign": ["Zabbix"], "desc": "Zabbix 控制台"},
    {"framework": "Solr", "cat": "middleware", "path": "/solr/",
     "sign": ["solr-admin", "Solr"], "desc": "Solr 管理台"},
    {"framework": "Weblogic", "cat": "middleware", "path": "/console/login/LoginForm.jsp",
     "sign": ["WebLogic"], "login_page": True, "desc": "WebLogic 控制台"},
    {"framework": "DockerRegistry", "cat": "middleware", "path": "/v2/",
     "header_sign": ["docker-distribution-api-version"], "desc": "Docker Registry v2 API"},
    {"framework": "Hystrix", "cat": "middleware", "path": "/hystrix",
     "sign": ["hystrix"], "desc": "Hystrix Dashboard"},
    # === 以下为选择性吸收的增强规则（签名已收紧 / 加内容类型校验）===
    # --- 微服务：注册中心 / 配置中心 / 网关 ---
    {"framework": "Eureka", "cat": "middleware", "path": "/eureka/",
     "sign": ["Eureka"], "desc": "Eureka 注册中心(全量服务实例+IP)"},
    {"framework": "SpringBootAdmin", "cat": "middleware", "path": "/admin/",
     "sign": ["Spring Boot Admin"], "desc": "Spring Boot Admin(聚合 Actuator)"},
    {"framework": "SpringCloudConfig", "cat": "middleware", "path": "/spring-cloud-config/",
     "sign": ["propertySources"], "desc": "Spring Cloud Config(全环境配置)"},
    {"framework": "Consul", "cat": "middleware", "path": "/v1/agent/self",
     "sign": ["Datacenter"], "desc": "Consul Agent 信息(服务发现)"},
    # --- APM / 可观测性 ---
    {"framework": "SkyWalking", "cat": "apm", "path": "/",
     "sign": ["SkyWalking"], "desc": "SkyWalking UI(全量 trace+拓扑)"},
    {"framework": "Jaeger", "cat": "apm", "path": "/",
     "sign": ["Jaeger"], "desc": "Jaeger UI(全量 trace)"},
    {"framework": "Zipkin", "cat": "apm", "path": "/zipkin/",
     "sign": ["Zipkin"], "desc": "Zipkin UI(全量 trace)"},
    {"framework": "Apollo", "cat": "apm", "path": "/",
     "sign": ["apollo-portal"], "desc": "Apollo 配置中心"},
    # --- 云原生 / 容器 ---
    {"framework": "K8s", "cat": "cloud-native", "path": "/api/v1/nodes",
     "sign": ["NodeList"], "desc": "Kubernetes API Server 未授权"},
    {"framework": "K8sDashboard", "cat": "cloud-native", "path": "/kubernetes-dashboard/",
     "sign": ["kubernetes-dashboard"], "desc": "Kubernetes Dashboard"},
    {"framework": "Portainer", "cat": "cloud-native", "path": "/",
     "sign": ["Portainer"], "desc": "Portainer(Docker/K8s 管理 UI)"},
    {"framework": "Harbor", "cat": "cloud-native", "path": "/api/v2.0/systeminfo",
     "sign": ["harbor_version"], "desc": "Harbor 镜像仓库 API"},
    {"framework": "MinIO", "cat": "cloud-native", "path": "/minio/health/live",
     "header_sign": ["minio"], "desc": "MinIO 对象存储"},
    # --- 大数据 ---
    {"framework": "HDFS", "cat": "bigdata", "path": "/dfshealth.html",
     "sign": ["NameNode"], "desc": "Hadoop HDFS NameNode UI"},
    {"framework": "Spark", "cat": "bigdata", "path": "/",
     "sign": ["Spark Master"], "desc": "Spark Master UI"},
    {"framework": "Flink", "cat": "bigdata", "path": "/",
     "sign": ["Apache Flink"], "desc": "Flink Dashboard"},
    {"framework": "Ambari", "cat": "bigdata", "path": "/",
     "sign": ["Ambari"], "desc": "Ambari 管理台"},
    # --- 数据库管理台 ---
    {"framework": "phpMyAdmin", "cat": "db-admin", "path": "/phpmyadmin/",
     "sign": ["phpMyAdmin"], "login_page": True, "desc": "phpMyAdmin(MySQL 管理台)"},
    {"framework": "Adminer", "cat": "db-admin", "path": "/adminer.php",
     "sign": ["Adminer"], "login_page": True, "desc": "Adminer(单文件数据库管理器)"},
    {"framework": "MongoExpress", "cat": "db-admin", "path": "/",
     "sign": ["mongo-express"], "desc": "mongo-express(MongoDB 管理台)"},
    # --- 其他高价值框架/管理台 ---
    {"framework": "Django", "cat": "middleware", "path": "/admin/login/",
     "sign": ["Django"], "login_page": True, "desc": "Django Admin 登录页"},
    {"framework": "JBoss", "cat": "middleware", "path": "/jmx-console/",
     "sign": ["JMImplementation"], "desc": "JBoss JMX 控制台"},
    {"framework": "WildFly", "cat": "middleware", "path": "/management/",
     "sign": ["management-major-version"], "desc": "WildFly 管理 API"},
    {"framework": "Keycloak", "cat": "middleware", "path": "/auth/realms/master",
     "sign": ["public_key"], "desc": "Keycloak Realm 信息"},
    {"framework": "Liferay", "cat": "middleware", "path": "/api/jsonws",
     "sign": ["jsonws"], "desc": "Liferay JSONWS API"},
    {"framework": "OFBiz", "cat": "middleware", "path": "/webtools/control/main",
     "sign": ["OFBiz"], "desc": "Apache OFBiz WebTools"},
    {"framework": "ActiveMQ", "cat": "middleware", "path": "/admin/",
     "sign": ["ActiveMQ"], "desc": "ActiveMQ 管理控制台"},
    {"framework": "Sentinel", "cat": "middleware", "path": "/sentinel-dashboard/",
     "sign": ["Sentinel"], "desc": "Sentinel 流控控制台"},
    {"framework": "Dubbo", "cat": "middleware", "path": "/dubbo/",
     "sign": ["Dubbo"], "desc": "Dubbo Admin(服务治理)"},
    {"framework": "Struts2", "cat": "middleware", "path": "/struts/webconsole.html",
     "sign": ["webconsole"], "desc": "Struts2 DevMode 调试控制台"},
    {"framework": "elFinder", "cat": "source-leak", "path": "/elfinder/",
     "sign": ["elFinder"], "desc": "elFinder Web 文件管理器"},
    # --- 源码/配置泄漏补充（非 HTML 资源）---
    {"framework": "Backup", "cat": "source-leak", "path": "/backup.sql",
     "sign": ["CREATE TABLE", "INSERT INTO"], "no_html": True, "desc": "SQL 备份文件泄漏"},
    {"framework": "Config", "cat": "source-leak", "path": "/application.yml",
     "sign": ["datasource", "spring:"], "no_html": True, "desc": "Spring Boot 配置文件泄漏"},
]

# 这些端点本应返回 JSON；若返回 HTML（catch-all/SPA 站点常见），一律判为误报
JSON_ENDPOINTS = {
    "/druid/websession.json", "/druid/sql.json", "/druid/datasource.json",
    "/v2/api-docs", "/v3/api-docs", "/swagger-resources",
    "/actuator", "/actuator/env", "/actuator/mappings", "/actuator/configprops",
    "/actuator/gateway/routes", "/actuator/health", "/actuator/beans",
    "/actuator/threaddump", "/actuator/loggers", "/actuator/httptrace",
    "/actuator/jolokia", "/actuator/gateway/globalfilters",
    "/nacos/v1/auth/users", "/api/health", "/api/overview",
    "/nacos/v1/console/namespaces",
    "/spring-cloud-config/", "/v1/agent/self", "/api/v1/nodes",
    "/api/v2.0/systeminfo", "/management/", "/auth/realms/master",
    "/",  # Elasticsearch 根（返回 JSON）
}

WEAK_DEFAULT_CREDS = [("admin", "admin"), ("admin", "123456"), ("admin", "1234")]

# 简单框架指纹（报告 meta 用；真正判定仍靠端点签名命中）
FRAMEWORK_HINTS = [
    (r"X-Application-Context|Spring Boot|Whitelabel Error", "SpringBoot"),
    (r"Tomcat|Apache-Coyote|JSESSIONID", "Java/Tomcat"),
    (r"Jetty", "Jetty"),
    (r"X-Powered-By:\s*PHP|ThinkPHP", "PHP"),
    (r"Nacos", "Nacos"),
    (r"nginx", "nginx"),
]

# ---------------------------------------------------------------------------
# 基础
# ---------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def ssl_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

# 全局限速器（--rate-limit / --jitter 控制；默认关闭，不影响内网默认行为）
_LIMITER = None

class RateLimiter:
    """请求间隔限速 + 随机抖动：降低对 WAF/生产系统的冲击，削弱规律性流量特征。"""
    def __init__(self, rps=0.0, jitter=0.0):
        self.interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self.jitter = jitter or 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if self.interval <= 0 and self.jitter <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if self._next < now:
                self._next = now
            delay = self._next - now
            self._next += self.interval
        if self.jitter:
            delay += random.uniform(0, self.jitter)
        if delay > 0:
            time.sleep(delay)

def throttle():
    if _LIMITER is not None:
        _LIMITER.wait()

def resolve_ipv4(host):
    try:
        return list(dict.fromkeys(
            x[4][0] for x in socket.getaddrinfo(host, None, socket.AF_INET)))
    except socket.gaierror:
        return []

class Resp:
    __slots__ = ("status", "headers", "body", "url", "origin", "redirected")

def _dechunk(body):
    """解码 Transfer-Encoding: chunked 正文（分块长度标记会破坏内容签名，必须还原）。"""
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        size_line = body[i:j].split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            break
        i = j + 2
        out += body[i:i + size]
        i += size + 2  # 跳过 chunk 数据后的 CRLF
    return bytes(out)

def _decompress(body, headers):
    """按 Content-Encoding 解压（gzip / deflate），失败则原样返回。"""
    enc = (headers.get("content-encoding") or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        return body
    return body

def http_fetch(host, ip, port, scheme, path, timeout=4.0, method="GET",
               max_body=2_000_000, follow=2, extra_headers=None, post_body=None,
               _redirected=False):
    """按 ip 直连，但 Host 头/SNI 用 host（兼容虚拟主机）。

    外网增强：Accept-Encoding(gzip/deflate) + 分块传输解码 + 内容解压 +
    301/302/303/307/308 重定向跟随（支持 http<->https 及跨主机跳转）。
    返回 Resp 或 None。"""
    throttle()
    connect_ip = ip or host
    try:
        if scheme == "https":
            raw = socket.create_connection((connect_ip, port), timeout=timeout)
            s = ssl_ctx().wrap_socket(raw, server_hostname=host)
        else:
            s = socket.create_connection((connect_ip, port), timeout=timeout)
        s.settimeout(timeout)
        target_path = path if path.startswith("/") else "/" + path
        host_hdr = host if port in (80, 443) else "%s:%d" % (host, port)
        extra = ""
        if extra_headers:
            extra = "".join("%s: %s\r\n" % (k, v) for k, v in extra_headers.items())
        if post_body is not None:
            extra += "Content-Length: %d\r\n" % len(post_body)
        req = ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "Connection: close\r\n%s\r\n") % (method, target_path, host_hdr, UA, extra)
        s.sendall(req.encode("utf-8"))
        if post_body:
            s.sendall(post_body)
        data = b""
        while len(data) < max_body:
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
    except Exception:
        return None
    head, _, raw_body = data.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/\d\.\d\s+(\d+)", head)
    status = int(m.group(1)) if m else 0
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    # 分块传输解码
    if "chunked" in (headers.get("transfer-encoding") or "").lower():
        raw_body = _dechunk(raw_body)
    # 内容压缩解码
    body = _decompress(raw_body, headers)
    # 重定向跟随：301/302/303/307/308，支持跨主机与 http<->https
    if follow and status in (301, 302, 303, 307, 308) and "location" in headers:
        loc = headers["location"].strip()
        u = urlparse(urljoin("%s://%s%s" % (scheme, host_hdr, target_path), loc))
        if u.hostname:
            nhost = u.hostname
            nscheme = u.scheme or scheme
            nport = u.port or (443 if nscheme == "https" else 80)
            nips = resolve_ipv4(nhost)
            nip = nips[0] if nips else nhost
            npath = u.path or "/"
            if u.query:
                npath += "?" + u.query
            return http_fetch(nhost, nip, nport, nscheme, npath, timeout, method,
                              max_body, follow - 1, extra_headers, None, True)
        return None
    r = Resp()
    r.status, r.headers, r.body, r.url = status, headers, body, target_path
    r.origin = "%s://%s:%d" % (scheme, host, port)   # 跳转后的最终地址（未跳转时即请求地址）
    r.redirected = _redirected
    return r

# ---------------------------------------------------------------------------
# ① 站点发现
# ---------------------------------------------------------------------------
def asset_sites(asset, timeout, log):
    """把一个资产(URL/域名/IP[:端口])转成候选站点 (scheme, host, ip, port)。
    返回 list of dict。"""
    candidates = []
    a = asset.strip()
    if a.startswith(("http://", "https://")):
        u = urlparse(a)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
        ips = resolve_ipv4(host) or [host]
        candidates.append({"scheme": u.scheme, "host": host, "ip": ips[0], "port": port,
                           "base": u.scheme + "://" + host + (":" + str(port) if port not in (80, 443) else ""),
                           "url_path": u.path})
        return candidates
    # host:port 或 host
    if a.count(":") == 1:
        host, _, port_s = a.rpartition(":")
        if port_s.isdigit():
            port = int(port_s)
            for scheme in ("http", "https"):
                ips = resolve_ipv4(host) or [host]
                candidates.append({"scheme": scheme, "host": host, "ip": ips[0], "port": port,
                                   "base": "%s://%s:%d" % (scheme, host, port), "url_path": ""})
            return candidates
    # 纯 host / IP
    host = a
    try:
        if ipaddress.ip_address(host).version == 4:
            ips = [host]
        else:
            log.warning("暂不支持 IPv6 资产直扫: %s", host)
            return []
    except ValueError:
        ips = resolve_ipv4(host)
    if not ips:
        log.warning("域名解析失败: %s", host)
        return []
    # 探测常见 Web 端口（并发 TCP）
    out = []
    with ThreadPoolExecutor(max_workers=min(32, len(WEB_PORTS))) as ex:
        fut = {ex.submit(probe_port, host, ip, p, timeout): (ip, p) for ip in ips for p in WEB_PORTS}
        for f in as_completed(fut):
            if f.result():
                out.append(fut[f])
    for ip, p in sorted(set(out)):
        # 标准/HTTPS 端口优先按 https 尝试，其余优先 http；另一协议由存活确认兜底
        schemes = ("https", "http") if p in HTTPS_PORTS else ("http", "https")
        for scheme in schemes:
            candidates.append({"scheme": scheme, "host": host, "ip": ip, "port": p,
                               "base": "%s://%s:%d" % (scheme, host, p), "url_path": ""})
    return candidates

def probe_port(host, ip, port, timeout):
    # 说明：TCP 连接探测（SYN）远比 HTTP 请求轻量，不受 --rate-limit 约束；
    # 其并发由 asset_sites 内的线程池上限控制，不会对目标造成应用层压力。
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False

def get_alive_sites(candidates, timeout):
    """对候选站点发 GET / 确认 HTTP 存活，保留首页响应。
    同一 host:port 只保留首个存活协议，避免 http/https 重复扫描。"""
    alive = []
    seen = set()
    for c in candidates:
        key = (c["host"], c["port"])
        if key in seen:
            continue
        base_path = c.get("url_path") or "/"
        r = http_fetch(c["host"], c["ip"], c["port"], c["scheme"], base_path, timeout=timeout, max_body=512_000)
        if r and r.status:
            c["homepage"] = r
            alive.append(c)
            seen.add(key)
    return alive

# ---------------------------------------------------------------------------
# ② 框架指纹 / ③ 前缀收集
# ---------------------------------------------------------------------------
def fingerprint(site):
    r = site.get("homepage")
    if not r:
        return []
    blob = "\n".join("%s: %s" % (k, v) for k, v in r.headers.items())
    body = r.body.decode("utf-8", "replace")[:5000]
    low = (blob + "\n" + body).lower()
    tags = []
    for pat, tag in FRAMEWORK_HINTS:
        if re.search(pat.lower(), low):
            tags.append(tag)
    return tags

# 影子端点自身根路径：不能作为"上下文前缀"再次拼接（避免 /druid/druid/ 类堆叠误报）
SHADOW_ROOT_PREFIXES = {"/druid", "/actuator", "/swagger-ui", "/doc", "/manager",
                        "/nacos", "/xxl-job", "/.git", "/.svn", "/v2", "/v3"}

def crawl_top_prefixes(site, limit=6):
    """轻爬首页：解析 href/src 链接，取本站顶层路径前缀（1 段）。不深爬。
    排除影子端点自身根路径，避免堆叠误报。"""
    r = site.get("homepage")
    if not r:
        return []
    body = r.body.decode("utf-8", "replace")
    host = site["host"]
    port = site["port"]
    prefixes = []
    for m in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', body, re.I):
        u = m.group(1).strip()
        if u.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        if u.startswith(("http://", "https://")):
            p = urlparse(u)
            if p.hostname != host:
                continue
            path = p.path or "/"
        elif u.startswith("//"):
            continue
        else:
            path = u.split("?")[0].split("#")[0]
            if not path.startswith("/"):
                continue
        seg = path.split("/")
        prefix = "/" + seg[1] if len(seg) > 1 and seg[1] else ""
        if (prefix and prefix not in SHADOW_ROOT_PREFIXES
                and not re.search(r"\.(js|css|png|jpg|jpeg|gif|ico|woff2?|svg|map)$", prefix, re.I)
                and prefix not in prefixes):
            prefixes.append(prefix)
    return prefixes[:limit]

# ---------------------------------------------------------------------------
# ④ 端点扫描
# ---------------------------------------------------------------------------
# 哨兵：区分“请求无响应”（可重试）与“有响应但未命中”（不应重试）
_NO_RESPONSE = object()

# 猜测的兜底前缀存在性探针：若上下文真实存在，这些路径通常会有响应（非 404）
_PREFIX_CANARIES = ["/", "/actuator/health", "/swagger-ui.html"]

def _prefix_alive(site, prefix, timeout):
    """判断“猜测的兜底前缀”（如 /app /web /manage /admin）是否真实存在。
    在该前缀下探少量“若上下文存在则通常有响应”的路径；全部 404/410 或无响应 ⇒ 判定不存在。
    仅用于**猜测的兜底前缀**；从首页爬到的真实上下文前缀不做此判定（保证覆盖不降）。
    收益：兜底前缀下共 4×~73 条规则探测 → 压缩为每个前缀 1~3 次。"""
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    for canary in _PREFIX_CANARIES:
        res = http_fetch(host, ip, port, scheme, prefix + canary,
                         timeout=timeout, max_body=8_000)
        if res is not None and res.status not in (404, 410):
            return True
    return False

# 认证失败/拒绝响应特征：出现即说明请求被服务端拒绝（端点并未真正暴露）
# 典型误报：错误页/网关页把请求路径回显在正文里（如 {"msg":"请求访问：/jsonws，认证失败"}）
_AUTH_FAIL_MARKERS = (
    '"code":401', '"code": 401', '"code":403', '"code": 403',
    '认证失败', '未认证', '未授权访问', '请先登录', '请登录后', '登录已过期', '无权限访问',
    'unauthorized', 'forbidden', 'authentication failed', 'access denied',
    'login required', 'not logged in', 'invalid token', 'token expired', 'permission denied',
)

def _looks_auth_failure(body_txt):
    """正文是否为“认证失败/被拒绝”响应。用于剔除因错误信息回显请求路径而误命中的端点。"""
    low = body_txt[:6000].lower()
    return any(m.lower() in low for m in _AUTH_FAIL_MARKERS)

def _detect_catchall(site, prefix, timeout):
    """随机路径探测：识别 catch-all / SPA / 302-redirect 型兜底站点，用于抑制
    “内容签名被通用首页命中”的系统性误报。返回该站点兜底正文的 sha1 指纹；否则 None。

    覆盖两类兜底（修复误报 ③，Nextcloud 20/23 即此类）：
      A. 200 型：两个随机路径均返回 200 且正文 sha1 完全一致（原逻辑）；
      B. 302/200-统一登录页型：任一随机路径返回 302（跳登录）或 200 但内容为
         站点兜底登录页（多个随机路径正文经“去动态 token 后”仍一致）。"""
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    fp = None
    redirect_seen = False
    for _ in range(2):
        probe = "%s/__ss_probe_%08x__" % (prefix or "", random.getrandbits(32))
        res = http_fetch(host, ip, port, scheme, probe, timeout=timeout, max_body=64_000)
        if res is None or not res.body:
            return None
        # B 型：随机路径被 302 重定向（典型 Nextcloud 未登录跳 /login，或统一跳认证首页）
        if res.status in (301, 302, 303, 307, 308):
            loc = res.headers.get("location", "")
            if loc and ("login" in loc.lower() or "auth" in loc.lower()):
                redirect_seen = True
                continue
            return None
        if res.status != 200:
            return None
        body = res.body
        # 去动态 token 后再比指纹（Nextcloud 兜底页每请求带 CSRF/session 随机数，
        # 直接 sha1 永不相等，导致原守卫失效从而漏放 Druid 类误报）
        norm = re.sub(rb"(?i)(csrf[^\"'=\s]{0,64}|token[^\"'=\s]{0,64}|requesttoken[^\"'=\s]{0,64})",
                      b"__TOKEN__", body)
        cur = hashlib.sha1(norm).hexdigest()
        if fp is None:
            fp = cur
        elif cur != fp:
            return None
    # B 型（两个随机路径都被 302 到登录页）⇒ 用登录页指纹，依然判定为 catch-all 兜底
    if redirect_seen and fp is None:
        return None
    if redirect_seen:
        return fp
    return fp

def check_endpoint(site, prefix, rule, weak_check, timeout):
    """对 prefix+rule.path 做一次探测。
    返回：命中 dict / None（有响应但未命中）/ _NO_RESPONSE（无响应，可重试）。"""
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    path = (prefix or "") + rule["path"]
    base = "%s://%s%s" % (scheme, host, ":" + str(port) if port not in (80, 443) else "")
    res = http_fetch(host, ip, port, scheme, path, timeout=timeout, max_body=512_000)
    if res is None:
        return _NO_RESPONSE
    status = res.status
    body_txt = res.body.decode("utf-8", "replace") if not rule.get("binary") else ""
    hit = False
    if rule.get("binary"):
        hit = status == rule.get("status", 200) and len(res.body) > 100
        if hit and rule.get("magic"):
            # 文件魔数校验：避免“任何返回 200 的页面”被误判为二进制泄露（SPA 常见）
            hit = rule["magic"].encode("latin-1") in res.body[:64]
    elif rule.get("auth_401"):
        # Tomcat Manager 判定的收紧（修复误报 ① ②）：
        #   1) 返回 401 且带 WWW-Authenticate；
        #   2) WWW-Authenticate 的 Basic realm 必须命中 Tomcat 特征域（默认
        #      "Tomcat Manager Application"），而非任意 Basic realm；
        #   3) 排除 nginx/OpenResty 作为后端容器（其前置 Basic 认证无 Tomcat realm 特征）。
        # 这样 higanbana/jamfdp（nginx Basic 401）、tjavdl（OpenResty 空壳）不再被误判为 Tomcat。
        ww = res.headers.get("www-authenticate", "")
        hit = False
        if status == 401 and ww:
            server = res.headers.get("server", "").lower()
            neg_backend = ("nginx" in server or "openresty" in server)
            if not neg_backend:
                realm = rule.get("auth_realm")
                if realm:
                    hit = realm.lower() in ww.lower()
                else:
                    hit = True  # 无 realm 要求时仅凭 401+WWW-Authenticate（历史兜底）
            # 即便后端未被识别为 nginx，若 realm 明显不属于 Tomcat，仍判误报
            if hit and "tomcat" not in ww.lower():
                hit = False
    elif status == 200 and (rule.get("sign") or rule.get("header_sign")):
        low = body_txt.lower()
        hblob = "\n".join("%s: %s" % (k, v) for k, v in res.headers.items()).lower()
        hit = (any(s.lower() in low for s in rule.get("sign", []))
               or any(s.lower() in hblob for s in rule.get("header_sign", [])))
        # catch-all 守卫：命中正文与站点“任意路径通用响应”字节一致 ⇒ 无路径证据，判为误报
        # 注意：与 _detect_catchall 的归一化指纹保持一致（去动态 token 后比较），
        # 否则 Nextcloud 等带 CSRF/session 随机数的兜底页每次 sha1 都不同，守卫失效。
        if hit and not rule.get("self_path") and site.get("_catchall_fp"):
            norm_body = re.sub(rb"(?i)(csrf[^\"'=\s]{0,64}|token[^\"'=\s]{0,64}|requesttoken[^\"'=\s]{0,64})",
                                b"__TOKEN__", res.body)
            if hashlib.sha1(norm_body).hexdigest() == site["_catchall_fp"]:
                hit = False
    # JSON 类端点：若返回 HTML 或非 JSON 内容（catch-all 站点常见），判为误报
    if hit and rule["path"] in JSON_ENDPOINTS:
        ct = res.headers.get("content-type", "").lower()
        first = res.body.lstrip(b"\xef\xbb\xbf \t\r\n")[:1]
        if "html" in ct or first not in (b"{", b"["):
            hit = False
    # 非 HTML 类资源（.svn/entries、web.xml 等）：若返回 HTML（catch-all），判为误报
    if hit and rule.get("no_html"):
        if "html" in res.headers.get("content-type", "").lower():
            hit = False
    # 要求响应体引用其自身上下文路径（真实应用会，catch-all 首页不会）
    if hit and rule.get("self_path"):
        sp = rule["path"].strip("/").lower()
        if sp and sp not in body_txt.lower():
            hit = False
    # 【修复 1】认证失败响应：正文表明请求被服务端拒绝（典型：错误页/网关页把请求路径回显在正文里，
    # 如 {"msg":"请求访问：/jsonws，认证失败"}）⇒ 端点并未真正暴露，判为误报。
    if hit and not rule.get("binary") and not rule.get("auth_401"):
        if _looks_auth_failure(body_txt):
            hit = False
    # 【修复 2a】跳转语义：跟随跳转后若最终路径已不是本端点，说明命中的是跳转目标页（如
    # /druid/login.html -> 302 -> /login 通用登录页），判为误报。
    if hit and getattr(res, "redirected", False):
        fin = (res.url or "").split("?", 1)[0].rstrip("/")
        exp = path.split("?", 1)[0].rstrip("/")
        if fin and exp and fin != exp:
            hit = False
    if not hit:
        return None
    if rule.get("auth_401") or status in (401, 403):
        exposure = "需认证(%d)" % status
    elif status == 200:
        exposure = "未授权可访问"
    else:
        exposure = "可达(status=%d)" % status
    # 【修复 2b】跳转归属：命中若经跨主机/端口跳转得到（如 8080 --308--> 8443），归属到最终地址，
    # 避免同一发现在两个端口各报一条（后续跨协议去重可将其合并）。
    eff_base, eff_site = base, host + (":" + str(port) if port not in (80, 443) else "")
    if getattr(res, "redirected", False) and getattr(res, "origin", None):
        _u = urlparse(res.origin)
        _p = _u.port or (443 if _u.scheme == "https" else 80)
        _sfx = ":" + str(_p) if _p not in (80, 443) else ""
        eff_base, eff_site = "%s://%s%s" % (_u.scheme, _u.hostname, _sfx), _u.hostname + _sfx
    f = {"url": eff_base + path, "site": eff_site,
         "status": status, "framework": rule["framework"], "category": rule["cat"],
         "endpoint": path, "exposure": exposure,
         "tags": ",".join(site.get("tags", [])),
         "desc": rule["desc"], "weak": "", "checked_at": now_iso()}
    # 弱口令验证（管理台；仅内置默认口令表，不爆破）
    if weak_check and rule["path"] in WEAK_CHECK_PATHS:
        f["weak"] = _weak_check(site, prefix, rule["path"], timeout)
    # 【修复 3】登录页类规则：登录页公网可达属常态、价值低 ⇒ 降级为“信息项”（除非验证出默认口令）
    if rule.get("login_page") and not f["weak"]:
        f["exposure"] = "登录页可达(信息)"
        f["category"] = "info"
    return f

# 支持弱口令验证的管理台（仅这些路径触发；判定已收紧）
WEAK_CHECK_PATHS = {"/druid/login.html", "/nacos/", "/xxl-job-admin/", "/manager/html"}

def _weak_check(site, prefix, rule_path, timeout):
    """管理台默认口令验证（仅内置默认口令表，不爆破；判定收紧，避免假“默认口令”）。"""
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    base = prefix or ""
    if rule_path == "/druid/login.html":
        return druid_weak_check(site, prefix, timeout)
    if rule_path == "/nacos/":
        for u, p in [("nacos", "nacos")] + list(WEAK_DEFAULT_CREDS):
            path = base + "/nacos/v1/auth/login?username=%s&password=%s" % (u, p)
            res = http_fetch(host, ip, port, scheme, path, timeout=timeout,
                             method="POST", max_body=200_000)
            if res and res.status == 200 and '"accessToken"' in res.body.decode("utf-8", "replace"):
                return "默认口令可登录(%s/%s)" % (u, p)
        return ""
    if rule_path == "/xxl-job-admin/":
        for u, p in [("admin", "123456"), ("admin", "admin")] + list(WEAK_DEFAULT_CREDS):
            body = ("userName=%s&password=%s" % (u, p)).encode()
            path = base + "/xxl-job-admin/login"
            res = http_fetch(host, ip, port, scheme, path, timeout=timeout, method="POST",
                             max_body=200_000, post_body=body,
                             extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
            if res and res.status == 200 and '"code":200' in res.body.decode("utf-8", "replace"):
                return "默认口令可登录(%s/%s)" % (u, p)
        return ""
    if rule_path == "/manager/html":
        for u, p in [("tomcat", "tomcat"), ("admin", "admin")] + list(WEAK_DEFAULT_CREDS):
            tok = base64.b64encode(("%s:%s" % (u, p)).encode()).decode()
            path = base + "/manager/html"
            res = http_fetch(host, ip, port, scheme, path, timeout=timeout, max_body=200_000,
                             extra_headers={"Authorization": "Basic " + tok})
            if res and res.status == 200 and "Tomcat Web Application Manager" in res.body.decode("utf-8", "replace"):
                return "默认口令可登录(%s/%s)" % (u, p)
        return ""
    return ""

def druid_weak_check(site, prefix, timeout):
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    for u, p in WEAK_DEFAULT_CREDS:
        path = (prefix or "") + "/druid/submitLogin?loginUsername=%s&loginPassword=%s" % (u, p)
        res = http_fetch(host, ip, port, scheme, path, timeout=timeout, method="POST", max_body=200_000)
        if res and res.status == 200:
            low = res.body.decode("utf-8", "replace").lower()
            if "success" in low:
                return "默认口令可登录(%s/%s)" % (u, p)
    return ""

def _probe_with_retry(site, pre, rule, weak_check, timeout, retries=2):
    """仅在“无响应”时重试（降低瞬时连接抖动导致的漏检）；
    有响应但未命中不再重试，避免把请求量翻倍。"""
    for i in range(retries):
        hit = check_endpoint(site, pre, rule, weak_check, timeout)
        if hit is not _NO_RESPONSE:
            return hit
    return None

# 猜测的兜底前缀（不含根路径）；真实上下文前缀（如 /portal，来自首页爬取）不参与合并
_FALLBACK_SET = {p for p in FALLBACK_PREFIXES if p}

def _dedupe_prefix_stack(findings):
    """前缀堆叠去重：同一 host 下，同一规则路径被多个**猜测的兜底前缀**
    （/app /web /manage /admin）命中时，判为 catch-all 堆叠，合并为一条（保留最短前缀、优先 https）。
    注意：真实上下文前缀（如 /portal）不参与合并，避免误合真实发现（每个上下文仍各报一次）。"""
    groups = {}
    order = []
    for f in findings:
        rp = f.pop("_rulepath", f["endpoint"])
        key = (f["site"], rp)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        g = groups[key]
        rp = key[1]

        def _pfx(x, rp=rp):
            ep = x["endpoint"]
            return ep[:-len(rp)] if (rp and ep.endswith(rp)) else ep

        # 合并条件：① 含猜测的兑底前缀（前缀堆叠）；② http/https 双协议重复（同一端点）
        schemes = {x["url"].split("://", 1)[0] for x in g}
        if len(g) > 1 and (any(_pfx(x) in _FALLBACK_SET for x in g) or len(schemes) > 1):
            g = [min(g, key=lambda x: (len(x["endpoint"]),
                                       0 if x["url"].startswith("https") else 1, x["url"]))]
        out.extend(g)
    return out

def _dedupe_cross_scheme(findings):
    """跨站点 http/https 去重：同一 (site, 路径) 在 http 与 https 各报一条时合并为一条（保留 https）。
    场景：站点同时监听 80/443，或 80 端口 301/308 跳转到 443——扫描器跟随跳转后
    在两个“站点”各命中一次，实为同一逻辑发现（例：/.DS_Store 被报两次）。
    注意：site 字段已含非默认端口，故不同端口上的命中不会被误合。"""
    best, order = {}, []
    for f in findings:
        key = (f["site"], urlparse(f["url"]).path)
        if key not in best:
            best[key] = f
            order.append(key)
        elif best[key]["url"].startswith("http://") and f["url"].startswith("https://"):
            best[key] = f
    return [best[k] for k in order]

def scan_site(site, weak_check, timeout, max_workers):
    """扫描单个站点所有前缀 × 规则。"""
    # 资产入口 URL 自带的路径（如 http://host/v1/api）天然就是应用上下文前缀，
    # 直接纳入扫描（解决 /v1/api 两层前缀场景，爬虫仅按单段提取会丢失）。
    # 注意：带 url_path 的站点只扫自身上下文，不再自动 fallback 到根路径
    # （避免同一 host:port 下多个上下文的端点互相污染/重复）。
    url_prefix = (site.get("url_path") or "").rstrip("/")
    if url_prefix and url_prefix != "/" and url_prefix not in SHADOW_ROOT_PREFIXES:
        prefixes = [url_prefix] + crawl_top_prefixes(site)
    else:
        prefixes = FALLBACK_PREFIXES + crawl_top_prefixes(site)
    seen, uniq = set(), []
    for p in prefixes:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    findings = []
    # 路径为 "/" 的规则（应用部署在站点根）只在根前缀测一次，避免多前缀重复探测
    root_pre = uniq[0] if uniq else ""
    # 兜底前缀（/app /web /manage /admin）是**猜测值**：先判存在性，不存在则整组跳过，
    # 把每站点探测数从 ~372 压到 ~80（爬到的真实上下文前缀不参与此判定，保证覆盖不降）。
    _log = logging.getLogger("shadowscan")
    active, skipped = [], 0
    for p in uniq:
        if p in _FALLBACK_SET and p != root_pre and not _prefix_alive(site, p, timeout):
            skipped += 1
            continue
        active.append(p)
    if skipped:
        _log.info("  兜底前缀跳过 %d 个（判定不存在）", skipped)
    uniq = active
    # catch-all 守卫：先探随机路径；若与首页返回同一正文，则该站点后续内容签名命中一律判误报
    site["_catchall_fp"] = _detect_catchall(site, root_pre, timeout)
    tasks = [(pre, r) for pre in uniq for r in ENDPOINT_RULES
             if r["path"] != "/" or pre == root_pre]
    # 站点内并发限制在较小值，避免瞬时连接风暴；整体多站点由外部串行控制
    workers = min(max_workers, 6)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(_probe_with_retry, site, pre, r, weak_check, timeout): (pre, r)
               for pre, r in tasks}
        for f in as_completed(fut):
            try:
                hit = f.result()
            except Exception:
                continue
            if hit:
                hit["_rulepath"] = fut[f][1]["path"]  # 内部字段，用于前缀堆叠去重
                findings.append(hit)
    out = _dedupe_prefix_stack(findings)
    if len(out) != len(findings):
        logging.getLogger("shadowscan").info(
            "  前缀堆叠去重：%d -> %d 条", len(findings), len(out))
    return out


# ---------------------------------------------------------------------------
# ⑧ 自适应扩探（--adaptive）：AI 提议 → 白名单校验 → 只读执行 → AI 判定 → 审计留痕
# ---------------------------------------------------------------------------
# 与验证层（tools/verify_layer.py）共用同一套策略模块 probe_policy：
#   扫描阶段用 MODE_SCAN 宽白名单（广度优先），安全约束靠「只 GET / 禁 query / 不取正文 / 不提交凭据」。
ai_layer_mod = None

_ADAPTIVE_JUDGE_PROMPT = (
    "你是应用安全专家。下面是对某站点若干端点的**只读探测**结果（GET，未带参数，未提交凭据）。"
    "请判断其中哪些是**真实暴露的影子端点**（未授权可访问且泄露信息），哪些只是正常页面/错误页/兜底页。"
    "只输出一个 JSON 对象，不要解释文字：\n"
    '{"confirmed": [{"path": "/x", "framework": "组件名", "category": "分类", "desc": "一句话", '
    '"reason": "判定依据"}], "rejected": [{"path": "/y", "why": "不算的原因"}]}\n'
    "规则：\n"
    "1) category 只能取：actuator / druid / swagger / source-leak / middleware / apm / "
    "cloud-native / bigdata / db-admin / component；\n"
    "2) 仅当响应确实属于某组件的敏感端点（配置/指标/列表/文档/元数据/管理面）才算 confirmed；\n"
    "3) 正常首页、404、认证失败页、通用兜底页、健康探针一律不算；\n"
    "4) 不得编造；最多 5 条；没有就返回空数组。"
)


def _probe_fetch(url, timeout, max_body=2048, method="GET", extra_headers=None):
    """把 http_fetch 适配成 probe_policy 需要的签名（只读探测用）。"""
    u = urlparse(url)
    host = u.hostname
    if not host:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    ips = resolve_ipv4(host) or [host]
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    res = http_fetch(host, ips[0], port, u.scheme, path, timeout=timeout,
                     method=method, max_body=max_body, extra_headers=extra_headers)
    if res is None:
        return None
    return {"status": res.status, "content_type": res.headers.get("content-type", ""),
            "length": len(res.body), "body": res.body,
            "declared_length": int(res.headers.get("content-length") or 0) or None}


def _write_adaptive_audit(out_dir, site, ev):
    """自适应扩探审计留痕：每条提议的放行/拒绝 + 理由 + 结果，追加到 adaptive_audit.jsonl。"""
    try:
        path = os.path.join(out_dir, "adaptive_audit.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "site": "%s://%s:%d" % (site["scheme"], site["host"], site["port"]),
                "rounds": ev.get("ai_probe_rounds"),
                "judged": ev.get("adaptive_judged"),
                "audit": ev.get("probe_audit") or [],
            }, ensure_ascii=False) + "\n")
    except OSError:
        pass


def adaptive_expand(site, base_findings, ai, timeout, log, rounds=1):
    """对一个**已有命中**的站点做自适应扩探，返回 (新增发现, 审计 dict)。

    触发条件刻意收窄为「站点已有命中」——绝大多数站点无命中，因此不产生 AI 调用，
    成本与「命中数」成正比而非与「站点数」成正比。
    """
    global ai_layer_mod
    try:
        import probe_policy as pp
    except ImportError as e:
        log.warning("  自适应扩探不可用（无法导入 probe_policy）：%s", e)
        return [], None
    if ai_layer_mod is None:
        try:
            import ai_layer as ai_layer_mod
        except ImportError:
            return [], None
    base = "%s://%s%s" % (site["scheme"], site["host"],
                          ":" + str(site["port"]) if site["port"] not in (80, 443) else "")
    hp = ""
    try:
        h = site.get("homepage")
        if h is not None and h.body:
            hp = h.body[:600].decode("utf-8", "replace")
    except Exception:
        hp = ""
    payload = {
        "site": base,
        "already_found": [{"endpoint": f["endpoint"], "framework": f["framework"],
                           "desc": f["desc"]} for f in base_findings][:20],
        "homepage_snippet": re.sub(r"\s+", " ", hp)[:600],
    }
    ev = {}
    asked = {f["endpoint"] for f in base_findings if f.get("endpoint")}
    ev = pp.ai_investigate(
        ai=ai, payload=payload, ev=ev, base=base, asked=asked, timeout=timeout,
        rounds=rounds, mode=pp.MODE_SCAN, fetch=_probe_fetch,
        chat_fn=ai_layer_mod._chat, first_json_fn=ai_layer_mod._first_json,
        label=site["host"], logger=log)
    cands = [h for h in (ev.get("next_hop") or [])
             if h.get("status") == 200 and (h.get("length") or 0) > 60][:5]
    if not cands:
        return [], ev
    # 取正文（只读、截断、脱敏）交模型判定
    evidence = []
    for h in cands:
        r = _probe_fetch(base + h["path"], timeout, max_body=8192)
        if r is None:
            continue
        txt = r["body"][:4000].decode("utf-8", "replace")
        evidence.append({"path": h["path"], "status": r["status"],
                         "ctype": r["content_type"],
                         "snippet": re.sub(r"\s+", " ", txt)[:600]})
    if not evidence:
        return [], ev
    try:
        content, _ = ai_layer_mod._chat(
            ai.api_url, ai.api_key, ai.assess_model,
            [{"role": "system", "content": _ADAPTIVE_JUDGE_PROMPT},
             {"role": "user", "content": "站点：%s\n已有命中：%s\n探测结果（JSON）：\n%s" % (
                 base, json.dumps(payload["already_found"], ensure_ascii=False),
                 json.dumps(evidence, ensure_ascii=False))}],
            timeout=ai.timeout, temperature=0.0, max_tokens=2500)
        obj = ai_layer_mod._first_json(content) or {}
    except Exception as e:
        log.warning("  自适应判定失败 %s: %s", base, e)
        return [], ev
    out = []
    for c in (obj.get("confirmed") or [])[:5]:
        path = c.get("path")
        if not path or not isinstance(path, str):
            continue
        if not any(path == e["path"] for e in evidence):
            continue          # 只接受确有证据支撑的
        out.append({
            "url": base + path, "site": site["host"] + (":" + str(site["port"])
                   if site["port"] not in (80, 443) else ""),
            "status": 200, "framework": c.get("framework") or "未知",
            "category": c.get("category") or "component", "endpoint": path,
            "exposure": "未授权可访问", "tags": ",".join(site.get("tags", [])),
            "desc": (c.get("desc") or "") + "（自适应扩探）", "weak": "",
            "checked_at": now_iso(), "adaptive": True,
        })
    ev["adaptive_judged"] = {"confirmed": len(out), "rejected": len(obj.get("rejected") or [])}
    return out, ev


# ---------------------------------------------------------------------------
# ⑤ 组件级指纹检测（Shiro 等：非固定路径，需站点级指纹判定）
# ---------------------------------------------------------------------------
# 无害探测 payload：org.apache.shiro.subject.SimplePrincipalCollection 的 Java 序列化字节
# （由 shiro-core 1.7.1 生成，serialVersionUID 在 shiro 1.x 全系稳定，可通用于目标端反序列化）
SHIRO_PAYLOAD_B64 = (
    "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBzcgAXamF2YS51dGlsLkxpbmtlZEhhc2hNYXA0wE5cEGzA+wIAAVoAC2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAADHcIAAAAEAAAAAF0AAxkZWZhdWx0UmVhbG1zcgAXamF2YS51dGlsLkxpbmtlZEhhc2hTZXTYbNdald0qHgIAAHhyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAABA/QAAAAAAAAXQAEHNoYWRvd3NjYW4tcHJvYmV4eAB3AQFxAH4ABXg="
)

SHIRO_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",     # shiro 最常用默认 key
    "4AvVhmFLUs0KTA3Kprsdag==",     # shiro 1.x 另一常见默认 key
    "3AvVhmFLUs0KTA3Kprsdag==",
]

def shiro_key_check(site, timeout):
    """Shiro 默认 Key 确定性验证（需系统 openssl）：
    用候选 key + 随机 IV 加密【合法 SimplePrincipalCollection payload】，格式与真实 Shiro
    一致（base64(IV||AES-CBC密文)）。判定：
      * key 正确 → 服务端解密+反序列化成功 → 响应不再返回 rememberMe=deleteMe → 确认命中
      * key 错误 → 解密失败 → 返回 rememberMe=deleteMe → 继续试下一个 key
    注意：随机字节 payload 无法区分 key 对错（错误时也会 deleteMe），必须用本 payload。
    纯标准库无 AES，依赖 openssl 命令；缺失时自动跳过。
    """
    import base64, subprocess
    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, timeout=3)
        if r.returncode != 0:
            return ""
    except Exception:
        return ""
    payload = base64.b64decode(SHIRO_PAYLOAD_B64)
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    for kb64 in SHIRO_KEYS:
        try:
            key = base64.b64decode(kb64)
            iv = os.urandom(16)
            p = subprocess.run(
                ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()],
                input=payload, capture_output=True, timeout=5)
            if p.returncode != 0 or not p.stdout:
                continue
            cookie = base64.b64encode(iv + p.stdout).decode()   # IV||密文，与 Shiro 一致
        except Exception:
            continue
        res = http_fetch(host, ip, port, scheme, "/", timeout=timeout, max_body=200_000,
                         extra_headers={"Cookie": "rememberMe=" + cookie})
        if res is None:
            continue
        setc = res.headers.get("set-cookie", "").lower()
        if "rememberme=deleteme" not in setc:
            return "默认Key确认命中(%s)：可构造RememberMe反序列化利用链" % kb64
    return ""

def component_probe(site, timeout, key_check):
    """站点级组件指纹。返回 findings 列表。"""
    scheme, host, ip, port = site["scheme"], site["host"], site["ip"], site["port"]
    base = "%s://%s%s" % (scheme, host, ":" + str(port) if port not in (80, 443) else "")
    res = http_fetch(host, ip, port, scheme, "/", timeout=timeout, max_body=200_000)
    hits = []
    if res is None:
        return hits
    setc = res.headers.get("set-cookie", "").lower()
    if "rememberme=deleteme" in setc:
        f = {"url": base + "/", "site": host + (":" + str(port) if port not in (80, 443) else ""),
             "status": res.status, "framework": "Shiro", "category": "component",
             "endpoint": "/ (RememberMe指纹)", "exposure": "框架确认",
             "tags": ",".join(site.get("tags", [])), "desc": "Shiro框架确认(rememberMe=deleteMe)，建议做默认Key验证",
             "weak": "", "checked_at": now_iso()}
        if key_check:
            f["weak"] = shiro_key_check(site, timeout)
            if f["weak"]:
                f["desc"] += "；" + f["weak"]
        hits.append(f)
    return hits

# ---------------------------------------------------------------------------
# 输入解析 / 输出
# ---------------------------------------------------------------------------
def parse_assets(arg):
    assets = []
    if os.path.isfile(arg):
        with open(arg, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    assets.append(line)
    else:
        assets = [a.strip() for a in arg.split(",") if a.strip()]
    return assets

_CN_NUM = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五", 6: "六", 7: "七", 8: "八"}

def _cn_num(n):
    return _CN_NUM.get(n, str(n))

def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))

def _md_inline(s):
    s = _esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s

def _md_to_html(md):
    """极简 Markdown -> HTML（标题/表格/加粗/列表），供 AI 研判章节用。"""
    out, in_table, in_list = [], False, False
    lines = md.split("\n")

    def is_sep(x):
        return x.startswith("|") and all(set(c.strip()) <= set("-: ") for c in x.strip("|").split("|"))

    for i, raw in enumerate(lines):
        s = raw.rstrip()
        nxt = lines[i + 1].rstrip() if i + 1 < len(lines) else ""
        if in_list and not s.startswith(("- ", "* ")):
            out.append("</ul>"); in_list = False
        if in_table and not (s.startswith("|") and s.endswith("|")):
            out.append("</table>"); in_table = False
        if s.startswith("#"):
            lv = min(len(s) - len(s.lstrip("#")) + 1, 6)
            out.append("<h%d>%s</h%d>" % (lv, _md_inline(s.lstrip("# ").strip()), lv))
        elif s.startswith("|") and s.endswith("|"):
            if is_sep(s):
                continue
            if not in_table:
                out.append('<table class="md">'); in_table = True
            tag = "th" if is_sep(nxt) else "td"
            cells = [c.strip() for c in s.strip("|").split("|")]
            out.append("<tr>" + "".join("<%s>%s</%s>" % (tag, _md_inline(c), tag) for c in cells) + "</tr>")
        elif s.startswith(("- ", "* ")):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append("<li>%s</li>" % _md_inline(s[2:]))
        elif s:
            out.append("<p>%s</p>" % _md_inline(s))
    if in_list:
        out.append("</ul>")
    if in_table:
        out.append("</table>")
    return "\n".join(out)

_HTML_CSS = """
body{font:15px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;
     color:#1f2937;background:#f6f8fb;margin:0;padding:32px 16px}
.wrap{max-width:960px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:34px 40px}
h1{font-size:24px;margin:0 0 6px} h2{font-size:18px;margin:30px 0 12px;padding-bottom:7px;border-bottom:2px solid #eef2f7}
h3{font-size:15px;margin:18px 0 8px;color:#2563eb}
.meta{color:#6b7280;font-size:13.5px;margin-bottom:8px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:14px}
th,td{border:1px solid #e5e7eb;padding:9px 12px;text-align:left;vertical-align:top}
th{background:#f1f5f9;font-weight:600;color:#475569} tr:nth-child(even) td{background:#fafbfc}
code{background:#f1f5f9;border:1px solid #e5e7eb;border-radius:5px;padding:1px 5px;
     font-family:"SF Mono",Consolas,monospace;font-size:12.5px;color:#1d4ed8}
.summary{background:#f8fafc;border-left:4px solid #2563eb;border-radius:8px;padding:12px 18px;margin:14px 0;font-size:14px}
.warn{background:#fff7ed;border-left:4px solid #f59e0b;border-radius:8px;padding:12px 18px;margin:14px 0}
ul{padding-left:22px} li{margin:5px 0}
footer{margin-top:30px;padding-top:14px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:12.5px;text-align:center}
"""

def write_html_report(out_dir, findings, excluded, scanned, started, by_cat, by_site, weak, ai_report):
    """生成自包含的 report.html（与 report.md 同源数据）。"""
    def tr(cells):
        return "<tr>" + "".join("<td>%s</td>" % c for c in cells) + "</tr>"

    cat_rows = "".join(tr([_esc(c), str(len(by_cat[c]))]) for c in sorted(by_cat))
    site_rows = "".join(tr(["<code>%s</code>" % _esc(s), str(len(by_site[s]))]) for s in sorted(by_site))
    hit_rows = "".join(
        tr([_esc(r["site"]), "<code>%s</code>" % _esc(r["endpoint"]), _esc(r["framework"]),
            _esc(r["exposure"]), _esc(r.get("weak") or "-"), _esc(r["desc"])])
        for r in sorted(findings, key=lambda x: (x["site"], x["endpoint"])))
    weak_rows = "".join(tr(["<code>%s</code>" % _esc(r["url"]), _esc(r["weak"]), _esc(r["desc"])]) for r in weak)
    exc_rows = "".join(
        tr([_esc(r["site"]), "<code>%s</code>" % _esc(r["endpoint"]), _esc(r["framework"]),
            _esc(r.get("ai_confidence", "")), _esc(r.get("ai_reason") or "-")])
        for r in sorted(excluded, key=lambda x: (x["site"], x["endpoint"])))

    h = ['<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         '<title>影子端点专项扫描报告</title><style>%s</style></head><body><div class="wrap">' % _HTML_CSS,
         '<h1>影子端点专项扫描报告</h1>',
         '<div class="meta">扫描时间 %s ｜ 存活站点 %d ｜ 命中 %d ｜ 耗时 %.1fs</div>' %
         (_esc(now_iso()), len(scanned), len(findings), time.time() - started)]
    if excluded:
        h.append('<div class="warn">AI 已排除疑似误报：%d 条（详见「AI 已排除」章节）</div>' % len(excluded))
    h.append("<h2>一、风险摘要</h2><table><tr><th>分类</th><th>命中数</th></tr>%s%s</table>" %
             (cat_rows, tr(["<b>合计</b>", "<b>%d</b>" % len(findings)])))
    if weak:
        h.append("<h2>二、严重项（默认口令可登录）</h2><table><tr><th>URL</th><th>弱口令</th><th>说明</th></tr>%s</table>" % weak_rows)
    h.append("<h2>三、按站点分布</h2><table><tr><th>站点</th><th>命中数</th></tr>%s</table>" % site_rows)
    h.append("<h2>四、命中清单</h2><table><tr><th>站点</th><th>端点</th><th>框架</th><th>暴露</th><th>弱口令</th><th>说明</th></tr>%s</table>" % hit_rows)
    if excluded:
        h.append("<h2>五、AI 已排除（疑似误报，供人工确认）</h2><table><tr><th>站点</th><th>端点</th><th>框架</th><th>置信度</th><th>AI 判断依据</th></tr>%s</table>" % exc_rows)
    h.append("<h2>六、整改建议</h2><div class=\"summary\">"
             "1. 影子端点一律禁止公网可达（网关/WAF 加 URL 黑名单：<code>/druid</code> <code>/actuator</code> <code>/swagger*</code> <code>/.git</code> 等）；<br>"
             "2. Actuator 仅保留 <code>/health</code>；Swagger/Knife4j 仅 dev 环境；Druid 设强口令+白名单并关闭 reset；<br>"
             "3. 数据库/中间件口令在泄露确认后全部轮换；<br>"
             "4. 治理长期化：发布 Checklist + CI 门禁 + 新应用登记。</div>")
    if ai_report:
        h.append("<h2>七、AI 智能研判（供参考，需人工复核）</h2>")
        h.append(_md_to_html(ai_report))
    h.append("<footer>ShadowScan v%s ｜ %s</footer></div></body></html>" % (VERSION, _esc(now_iso())))
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(h) + "\n")
    return os.path.join(out_dir, "report.html")

def write_report(findings, out_dir, scanned, started, ai_layer=None, excluded=None):
    """findings=确认命中（报告正文用）；excluded=AI 判定为疑似误报的命中。
    文件输出(jsonl/csv)始终写全量(findings+excluded)，保证数据不丢。"""
    excluded = excluded or []
    all_findings = findings + excluded
    os.makedirs(out_dir, exist_ok=True)
    jsonl = os.path.join(out_dir, "findings.jsonl")
    with open(jsonl, "w", encoding="utf-8") as f:
        for r in all_findings:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    csv_path = os.path.join(out_dir, "findings.csv")
    if all_findings:
        fields = ["site", "url", "framework", "category", "endpoint", "status",
                  "exposure", "weak", "tags", "desc", "checked_at",
                  "ai_verdict", "ai_risk_level", "ai_confidence"]
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in all_findings:
                w.writerow(r)
    # summary.md（可直接阅读）
    by_cat = {}
    for r in findings:
        by_cat.setdefault(r["category"], []).append(r)
    by_site = {}
    for r in findings:
        by_site.setdefault(r["site"], []).append(r)
    weak = [r for r in findings if r.get("weak")]
    lines = [
        "# 影子端点专项扫描报告",
        "",
        "- 扫描时间：%s" % now_iso(),
        "- 扫描站点数：%d（存活 Web 资产）" % len(scanned),
        "- 命中影子端点：%d 个 | 耗时 %.1fs" % (len(findings), time.time() - started),
    ]
    if excluded:
        lines.append("- AI 已排除疑似误报：%d 个（详见第五节，人工可复核）" % len(excluded))
    lines += [
        "",
        "## 一、风险摘要",
        "",
        "| 分类 | 命中数 |",
        "|---|---|",
    ]
    for c in sorted(by_cat):
        lines.append("| %s | %d |" % (c, len(by_cat[c])))
    lines.append("| **合计** | **%d** |" % len(findings))
    if weak:
        lines += ["", "## 二、严重项（默认口令可登录）", ""]
        for r in weak:
            lines.append("- **%s**  %s（%s）" % (r["url"], r["weak"], r["desc"]))
    lines += ["", "## 三、按站点分布", ""]
    for s in sorted(by_site):
        lines.append("- `%s`：%d 处" % (s, len(by_site[s])))
    lines += ["", "## 四、命中清单", "",
              "| 站点 | 端点 | 框架 | 暴露 | 弱口令 | 说明 |",
              "|---|---|---|---|---|---|"]
    for r in sorted(findings, key=lambda x: (x["site"], x["endpoint"])):
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            r["site"], r["endpoint"], r["framework"], r["exposure"],
            r.get("weak") or "-", r["desc"]))
    # AI 误报过滤产出：把高置信假阳性单独列出（不混在命中清单里）
    if excluded:
        lines += ["", "## 五、AI 已排除（疑似误报，供人工确认）", "",
                  "| 站点 | 端点 | 框架 | 置信度 | AI 判断依据 |",
                  "|---|---|---|---|---|"]
        for r in sorted(excluded, key=lambda x: (x["site"], x["endpoint"])):
            lines.append("| %s | %s | %s | %s | %s |" % (
                r["site"], r["endpoint"], r["framework"],
                r.get("ai_confidence", ""), r.get("ai_reason") or "-"))
    # AI 增能层产出（--ai 开启且配置可用时）
    ai_report = ""
    if ai_layer is not None and ai_layer.available and findings:
        ai_report = ai_layer.smart_report(findings) or ""
    lines += ["", "## %s、整改建议" % _cn_num(6 if excluded else 5), "",
              "1. 影子端点一律禁止公网可达（网关/WAF 加 URL 黑名单：`/druid` `/actuator` `/swagger*` `/.git` 等）；",
              "2. Actuator 仅保留 `/health`；Swagger/Knife4j 仅 dev 环境；Druid 设强口令+白名单并关闭 reset；",
              "3. 数据库/中间件口令在泄露确认后全部轮换；",
              "4. 治理长期化：发布 Checklist + CI 门禁 + 新应用登记，防止新项目复发。"]
    if ai_report:
        lines += ["", "## %s、AI 智能研判（供参考，需人工复核）" % _cn_num(7 if excluded else 6), ""]
        lines.append(ai_report.strip())
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        write_html_report(out_dir, findings, excluded, scanned, started,
                          by_cat, by_site, weak, ai_report)
    except Exception as e:
        logging.getLogger("shadowscan").warning("HTML 报告生成失败: %s", e)
    return "\n".join(lines)


def write_ai_output(ai_records, out_dir):
    """写 ai_findings.jsonl（逐条 AI 判决）。findings.jsonl 已由 write_report 写全量。"""
    if not ai_records:
        return ""
    ai_path = os.path.join(out_dir, "ai_findings.jsonl")
    with open(ai_path, "w", encoding="utf-8") as f:
        for r in ai_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return ai_path

def site_key(s):
    """站点稳定标识（用于断点续跑去重）。"""
    return "%s://%s:%d%s" % (s["scheme"], s["host"], s["port"], s.get("url_path") or "")

def load_checkpoint(path):
    """读取 checkpoint.jsonl，返回 {site_key: [findings...]}；容忍中断产生的半行。"""
    done = {}
    if not os.path.exists(path):
        return done
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and "key" in rec:
                done[rec["key"]] = rec.get("findings", [])
    return done

def load_ai_checkpoint(path):
    """读取 ai_checkpoint.jsonl，返回 {url: {"record":..., "ai":...}}；容忍半行。"""
    done = {}
    if not os.path.exists(path):
        return done
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("url"):
                done[rec["url"]] = rec
    return done

# AI 研判优先级（越小越先研判）：弱口令 > 源码泄露 > Actuator > Druid > 中间件 > Swagger > 组件
_AI_PRIORITY = {"source-leak": 1, "actuator": 2, "druid": 3, "middleware": 4, "swagger": 5, "component": 6}

def _finding_rank(f):
    if f.get("weak"):
        return (0, 0)
    return (1, _AI_PRIORITY.get(f.get("category"), 9))

def main():
    global WEB_PORTS, _LIMITER
    ap = argparse.ArgumentParser(description="ShadowScan v%s 影子端点专项扫描器" % VERSION)
    ap.add_argument("--targets", default=None, help="资产文件或逗号分隔列表（URL/域名/IP/IP:端口，#注释）")
    ap.add_argument("--ports", default=",".join(map(str, WEB_PORTS)),
                    help="无显式端口资产的探测端口（默认常见Web端口）")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--max-workers", type=int, default=12, help="并发(默认12，控制对生产网络干扰)")
    ap.add_argument("--weak-check", action="store_true", help="默认口令验证(仅内置表,不爆破)")
    ap.add_argument("--key-check", action="store_true", help="Shiro默认Key启发式验证(实验性,需系统openssl)")
    ap.add_argument("--rate-limit", type=float, default=0.0,
                    help="全局限速(请求/秒,0=不限速;外网建议2~5,避免触发WAF/告警)")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="每请求随机抖动上限(秒;外网建议0.3~1.0,削弱规律特征)")
    ap.add_argument("--ai", action="store_true", help="启用AI增能层(误报裁决/风险研判/合规映射/智能报告,需配置LLM端点)")
    ap.add_argument("--ai-key", default=os.environ.get("SHADOWSCAN_LLM_KEY", ""), help="LLM API Key(默认读环境变量 SHADOWSCAN_LLM_KEY)")
    ap.add_argument("--ai-model", default=None, help="模型名(默认读 ai_layer 的 deepseek-v4-pro)")
    ap.add_argument("--ai-keep-fp", action="store_true",
                    help="关闭 AI 误报过滤（默认将高置信假阳性从报告正文剔除，移入“AI 已排除”章节）")
    ap.add_argument("--ai-min-confidence", type=float, default=0.6,
                    help="判定假阳性并剔除的最低置信度（默认 0.6）")
    ap.add_argument("--ai-timeout", type=int, default=None,
                    help="AI 单次调用超时秒数（默认读 ai_layer 的 SHADOWSCAN_LLM_TIMEOUT/120）")
    ap.add_argument("--ai-top", type=int, default=0,
                    help="AI 仅研判优先级最高的前 N 条命中（0=全部；控制 AI 成本/耗时）")
    ap.add_argument("--ai-concurrency", type=int, default=3,
                    help="AI 并发（默认3；过大触发网关限流）")
    ap.add_argument("--ai-only", action="store_true",
                    help="两阶段-阶段2：不扫描，仅对 -o 目录已有 findings.jsonl 运行 AI 增强")
    ap.add_argument("--resume", action="store_true",
                    help="断点续跑：跳过 -o/checkpoint.jsonl 中已完成的站点")
    ap.add_argument("--shard", default=None,
                    help="分片：i/n（如 1/10），只处理第 i 片；用于多机并行")
    ap.add_argument("-o", "--out", default="shadowscan_batch_out")
    ap.add_argument("--adaptive", action="store_true",
                    help="自适应扩探：对**已有命中**的站点，由 AI 提议额外端点、"
                         "经白名单校验后做只读探测，全过程审计留痕（默认关）")
    ap.add_argument("--adaptive-rounds", type=int, default=1,
                    help="自适应扩探的 AI 提议轮数（默认 1）")
    ap.add_argument("--production", action="store_true",
                    help="生产推荐模式：等价于 --ai --adaptive（AI 研判 + 自适应扩探）。"
                         "AI 未配置或不可用时自动降级为纯规则扫描，不阻塞流程")
    ap.add_argument("--authorized", action="store_true", help="【必填】已获授权")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if not args.authorized:
        print("错误：必须声明 --authorized", file=sys.stderr)
        sys.exit(2)
    # --production：一键打开 AI 研判与自适应扩探（本工具的推荐用法）
    if args.production:
        args.ai = True
        args.adaptive = True
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    log = logging.getLogger("shadowscan")
    WEB_PORTS = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    _LIMITER = RateLimiter(args.rate_limit, args.jitter)

    os.makedirs(args.out, exist_ok=True)
    audit = os.path.join(args.out, "scan.log")
    fh = logging.FileHandler(audit, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(fh)

    started = time.time()
    findings = []
    alive = []

    if args.ai_only:
        # 两阶段-阶段2：不重新扫描，只对已有 findings.jsonl 做 AI 增强
        fp = os.path.join(args.out, "findings.jsonl")
        if not os.path.exists(fp):
            print("错误：--ai-only 需要 -o 目录下已存在 findings.jsonl（请先完成阶段1扫描）", file=sys.stderr)
            sys.exit(2)
        with open(fp, encoding="utf-8") as f:
            findings = [json.loads(l) for l in f if l.strip()]
        alive = sorted({f.get("site", "") for f in findings})
        log.info("AI-only（阶段2）：载入已有命中 %d 条（来自 %d 个站点），不重新扫描",
                 len(findings), len(alive))
    else:
        if not args.targets:
            print("错误：非 --ai-only 模式必须提供 --targets", file=sys.stderr)
            sys.exit(2)
        assets = parse_assets(args.targets)
        if not assets:
            print("无有效资产输入", file=sys.stderr)
            sys.exit(2)
        if args.shard:
            try:
                si, sn = (int(x) for x in args.shard.split("/"))
                assert 1 <= si <= sn
            except Exception:
                print("错误：--shard 格式应为 i/n（如 1/10），且 1<=i<=n", file=sys.stderr)
                sys.exit(2)
            total = len(assets)
            assets = assets[si - 1::sn]
            log.info("分片：第 %d/%d 片，%d -> %d 个资产", si, sn, total, len(assets))
        log.info("ShadowScan v%s | 操作者:%s | 资产数:%d | weak:%s | 并发:%d | 限速:%s",
                 VERSION, os.environ.get("USER", "unknown"), len(assets), args.weak_check,
                 args.max_workers, ("%g req/s" % args.rate_limit) if args.rate_limit else "off")
        if args.production:
            log.info("生产推荐模式（--production）：AI 研判 + 自适应扩探已启用；"
                     "AI 不可用时自动降级为纯规则扫描")

        ckpt = os.path.join(args.out, "checkpoint.jsonl")
        done = load_checkpoint(ckpt) if args.resume else {}
        if args.resume:
            log.info("断点续跑：checkpoint 已完成 %d 个站点，将跳过", len(done))
        else:
            open(ckpt, "w").close()  # 全新运行，清空旧断点

        # ① 站点发现
        all_candidates = []
        for a in assets:
            cs = asset_sites(a, args.timeout, log)
            log.info("资产 %s -> %d 个候选Web站点", a, len(cs))
            all_candidates.extend(cs)
        # 去重
        seen = set()
        uniq_cand = []
        for c in all_candidates:
            k = (c["scheme"], c["host"], c["port"], c.get("url_path", ""))
            if k not in seen:
                seen.add(k)
                uniq_cand.append(c)
        alive = get_alive_sites(uniq_cand, args.timeout)
        log.info("站点发现完成：候选 %d，存活 Web 服务 %d", len(uniq_cand), len(alive))
        for s in alive:
            s["tags"] = fingerprint(s)
            log.info("  [存活] %s://%s:%d | 指纹:%s", s["scheme"], s["host"], s["port"],
                     ",".join(s["tags"]) or "-")

        # ③.5 自适应扩探所需的 AI 层（仅在 --adaptive 时创建；无 key 则自动降级关闭）
        _adaptive_ai = None
        if args.adaptive:
            try:
                import ai_layer as _aim
                _adaptive_ai = _aim.AILayer(api_key=args.ai_key, model=args.ai_model,
                                            timeout=args.ai_timeout)
                if not _adaptive_ai.available:
                    log.warning("--adaptive 需要 AI 配置（缺 api_key），本次跳过自适应扩探")
                    _adaptive_ai = None
                else:
                    log.info("自适应扩探已启用：对**已有命中**的站点做 AI 提议 → 白名单 → 只读探测"
                             "（轮数 %d，全程审计留痕）", args.adaptive_rounds)
            except ImportError:
                log.error("未找到 ai_layer.py，--adaptive 不可用")

        # ④ 逐个站点扫描（站点级断点落盘，中断后 --resume 续跑）
        ckpt_fh = open(ckpt, "a", encoding="utf-8")
        consumed = set()
        try:
            for s in alive:
                k = site_key(s)
                if k in done:
                    findings.extend(done[k])
                    consumed.add(k)
                    log.info("[跳过-已完成] %s（命中 %d）", k, len(done[k]))
                    continue
                pre = crawl_top_prefixes(s)
                fs = scan_site(s, args.weak_check, args.timeout, args.max_workers)
                comp = component_probe(s, args.timeout, args.key_check)
                log.info("[扫描] %s://%s:%d 前缀%d个 命中%d | %s",
                         s["scheme"], s["host"], s["port"], len(pre), len(fs),
                         ", ".join(f["endpoint"] for f in fs) or "-")
                for c in comp:
                    log.info("  [组件] %s | %s | %s %s", c["url"], c["framework"], c["exposure"],
                             ("| " + c["weak"]) if c.get("weak") else "")
                site_findings = fs + comp
                # ⑧ 自适应扩探：仅对**已有命中**的站点触发（成本与命中数成正比，与站点数无关）
                if _adaptive_ai is not None and site_findings:
                    extra, aev = adaptive_expand(s, site_findings, _adaptive_ai,
                                                 args.timeout, log, args.adaptive_rounds)
                    if aev:
                        _write_adaptive_audit(args.out, s, aev)
                    if extra:
                        log.info("  [自适应] 新增 %d 条命中（AI 提议→白名单→只读探测）", len(extra))
                        for e in extra:
                            log.info("    [自适应命中] %s | %s | %s",
                                     e["url"], e["framework"], e["desc"])
                        site_findings = site_findings + extra
                findings.extend(site_findings)
                ckpt_fh.write(json.dumps({"key": k, "findings": site_findings},
                                         ensure_ascii=False) + "\n")
                ckpt_fh.flush()
                try:
                    os.fsync(ckpt_fh.fileno())
                except OSError:
                    pass
        finally:
            ckpt_fh.close()
        # 补回 checkpoint 中已存在、但本次未出现在存活列表的站点（避免断点数据丢失）
        for k, fs in done.items():
            if k not in consumed:
                findings.extend(fs)
                log.info("[跳过-已完成(本次未存活)] %s（命中 %d）", k, len(fs))

        # 跨站点 http/https 去重（同一发现的 http 与 https 两条合并；置于 AI 之前以省调用）
        n0 = len(findings)
        findings = _dedupe_cross_scheme(findings)
        if len(findings) != n0:
            log.info("跨站点 http/https 去重：%d -> %d 条", n0, len(findings))

    # ⑤ AI 增能层（--ai 显式开启才启用）
    ai_layer = None
    ai_records = []
    excluded = []
    if args.ai and findings:
        try:
            import ai_layer as ai_mod
            ai_layer = ai_mod.AILayer(api_key=args.ai_key, model=args.ai_model,
                                      timeout=args.ai_timeout)
            if ai_layer.available:
                subset = findings
                if args.ai_top and len(findings) > args.ai_top:
                    subset = sorted(findings, key=_finding_rank)[:args.ai_top]
                    log.info("AI 限额：仅研判优先级最高的前 %d/%d 条（其余保留原始结果，不调用 LLM）",
                             args.ai_top, len(findings))
                log.info("AI 增能层已启用：model=%s，并发=%d，研判 %d 条…",
                         ai_layer.model, args.ai_concurrency, len(subset))
                # AI 阶段断点续跑：逐条落盘 ai_checkpoint.jsonl，中断后 --resume 不重算
                ai_ckpt = os.path.join(args.out, "ai_checkpoint.jsonl")
                if not args.resume:
                    open(ai_ckpt, "w").close()  # 全新运行，清空 AI 断点
                ai_done = load_ai_checkpoint(ai_ckpt) if args.resume else {}
                pending = []
                for f in subset:
                    rec = ai_done.get(f.get("url"))
                    if rec:
                        if rec.get("ai"):
                            f.update(rec["ai"])
                        if rec.get("record"):
                            ai_records.append(rec["record"])
                    else:
                        pending.append(f)
                if args.resume and len(subset) - len(pending):
                    log.info("AI 断点续跑：已完成 %d 条判决，待研判 %d 条",
                             len(subset) - len(pending), len(pending))
                if pending:
                    ai_ckpt_fh = open(ai_ckpt, "a", encoding="utf-8")

                    def _on_result(f, rec):
                        ai_ckpt_fh.write(json.dumps(
                            {"url": f.get("url"), "record": rec,
                             "ai": {k: v for k, v in f.items() if k.startswith("ai_")}},
                            ensure_ascii=False) + "\n")
                        ai_ckpt_fh.flush()
                        try:
                            os.fsync(ai_ckpt_fh.fileno())
                        except OSError:
                            pass

                    try:
                        _, new_records = ai_layer.enhance(pending, max_workers=args.ai_concurrency,
                                                          on_result=_on_result)
                        ai_records.extend(new_records)
                    finally:
                        ai_ckpt_fh.close()
                # AI 误报过滤：高置信假阳性从报告正文剔除（保留在 findings.jsonl / csv）
                if not args.ai_keep_fp:
                    kept = []
                    for f in findings:
                        try:
                            conf = float(f.get("ai_confidence") or 0)
                        except (TypeError, ValueError):
                            conf = 0.0
                        if f.get("ai_verdict") == "false_positive" and conf >= args.ai_min_confidence:
                            excluded.append(f)
                        else:
                            kept.append(f)
                    findings = kept
                    if excluded:
                        log.info("AI 误报过滤：排除 %d 条疑似误报（置信度≥%.2f），报告正文保留 %d 条",
                                 len(excluded), args.ai_min_confidence, len(findings))
            else:
                log.warning("AI 增能层配置不完整（缺 api_key），跳过 AI，按纯规则输出")
        except ImportError:
            log.error("未找到 ai_layer.py，请将 ai_layer.py 与 shadowscan.py 放在同一目录")
            ai_layer = None

    report = write_report(findings, args.out, alive, started, ai_layer, excluded)
    ai_out = write_ai_output(ai_records, args.out)
    print(report)
    print("\n输出目录：%s" % args.out)
    if ai_out:
        print("AI 研判明细：%s" % ai_out)
    log.info("完成：%d 站点，命中 %d 端点（AI 排除 %d）",
             len(alive), len(findings), len(excluded))

if __name__ == "__main__":
    main()