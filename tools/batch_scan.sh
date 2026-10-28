#!/usr/bin/env bash
# batch_scan.sh —— ShadowScan 分批 + 分片 + 限速 编排脚本
#
# 用途：把几千个资产安全地跑完——切批、可多机分片、全程限速、支持断点续跑。
#
# 用法：
#   ./tools/batch_scan.sh --targets assets_all.txt [选项]
#
# 选项：
#   --targets FILE   资产清单（必填，每行一个）
#   --batch N        每批资产数（默认 150）
#   --shard i/n      只跑第 i 片（共 n 片），用于多机并行
#   --ports LIST     探测端口（默认用扫描器自带的常见端口列表，约34个）
#   --rate R         全局限速 HTTP 请求/秒（默认 0=不限速；大批量/共享入口建议 8~20）
#   --jitter S       每请求抖动上限秒（默认 0；限速时才需要）
#   --workers N      站点内并发（默认 8）
#   --timeout S      单请求超时（默认 4）
#   --ai             扫描时启用 AI
#   --ai-top N       AI 仅研判优先级最高的前 N 条
#   --two-stage      两阶段：先纯规则全量，再对结果跑 AI（省 AI 成本）
#   --scanner PATH   扫描器入口（默认 <项目根>/shadowscan.py，也可用 shadowscan.pyz）
#   --out DIR        输出根目录（默认 batch_out；固定名便于 --resume 续跑）
#   --dry-run        只打印将执行的命令，不实际扫描
#
# 断点续跑：直接重跑同一条命令即可（每批用 --resume 自动跳过已完成站点与 AI 判决）。
set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

TARGETS=""; BATCH=150; SHARD=""; PORTS=""
RATE=0; JITTER=0; WORKERS=8; TIMEOUT=4
AI=0; AI_TOP=0; TWO_STAGE=0
SCANNER="$ROOT_DIR/shadowscan.py"; OUT="batch_out"; DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) TARGETS="$2"; shift 2;;
    --batch)   BATCH="$2"; shift 2;;
    --shard)   SHARD="$2"; shift 2;;
    --ports)   PORTS="$2"; shift 2;;
    --rate|--rate-limit) RATE="$2"; shift 2;;  # 两种写法都支持
    --jitter)  JITTER="$2"; shift 2;;
    --workers) WORKERS="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --ai)      AI=1; shift;;
    --ai-top)  AI_TOP="$2"; AI=1; shift 2;;
    --two-stage) TWO_STAGE=1; shift;;
    --scanner) SCANNER="$2"; shift 2;;
    --out)     OUT="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) echo "未知参数: $1" >&2; exit 2;;
  esac
done

[ -n "$TARGETS" ] || { echo "错误：必须指定 --targets" >&2; exit 2; }
[ -f "$TARGETS" ] || { echo "错误：资产文件不存在：$TARGETS" >&2; exit 2; }
[ -f "$SCANNER" ] || { echo "错误：扫描器不存在：$SCANNER" >&2; exit 2; }

mkdir -p "$OUT"; WORK="$OUT/.work"; rm -rf "$WORK"; mkdir -p "$WORK"

# 分片（多机并行时各机指定不同 i/n）
SRC="$TARGETS"
if [ -n "$SHARD" ]; then
  si="${SHARD%/*}"; sn="${SHARD#*/}"
  awk -v i="$si" -v n="$sn" 'NR%n==(i%n)' "$TARGETS" > "$WORK/sharded.txt"
  SRC="$WORK/sharded.txt"
  echo "分片：第 $si/$sn 片"
fi

split -l "$BATCH" "$SRC" "$WORK/batch_"
BATCHES=( "$WORK"/batch_* )
[ "${#BATCHES[@]}" -gt 0 ] || { echo "无有效批次（资产为空？）" >&2; exit 1; }

PORT_FLAG=""
[ -n "$PORTS" ] && PORT_FLAG="--ports $PORTS"

AI_FLAG=""
[ "$AI" = "1" ] && AI_FLAG="--ai"
[ "$AI_TOP" != "0" ] && AI_FLAG="$AI_FLAG --ai-top $AI_TOP"
# 两阶段模式下，阶段1 只做纯规则扫描（AI 全部留给阶段2）
STAGE1_AI_FLAG="$AI_FLAG"
[ "$TWO_STAGE" = "1" ] && STAGE1_AI_FLAG=""

echo "资产 $(grep -cve '^[[:space:]]*$' "$SRC" || true) 个 | 批次 ${#BATCHES[@]} 个（每批 ≤${BATCH}）"
echo "限速 $RATE req/s | 抖动 $JITTER | 并发 $WORKERS | 超时 ${TIMEOUT}s | 端口 ${PORTS:-扫描器默认} | AI: ${AI_FLAG:-关}"
echo "输出根目录：$OUT"

run() { if [ "$DRY" = "1" ]; then echo "[dry-run] $*"; else "$@"; fi; }

# ── 阶段1：扫描（每批带 --resume，可续跑）─────────────────────────────
for b in "${BATCHES[@]}"; do
  name="$(basename "$b")"; outdir="$OUT/$name"
  echo ""; echo "===== [扫描] $name -> $outdir ====="
  run python3 "$SCANNER" --targets "$b" \
      $PORT_FLAG --max-workers "$WORKERS" --timeout "$TIMEOUT" \
      --rate-limit "$RATE" --jitter "$JITTER" \
      --weak-check --authorized --resume $STAGE1_AI_FLAG -o "$outdir"
done

# ── 阶段2（可选）：两阶段 AI ───────────────────────────────────────────
if [ "$TWO_STAGE" = "1" ]; then
  echo ""; echo "===== [阶段2] 对已有结果运行 AI ====="
  ONLY_FLAG="--ai"
  [ "$AI_TOP" != "0" ] && ONLY_FLAG="$ONLY_FLAG --ai-top $AI_TOP"
  for b in "${BATCHES[@]}"; do
    name="$(basename "$b")"; outdir="$OUT/$name"
    if [ ! -f "$outdir/findings.jsonl" ]; then echo "跳过 ${name}（无结果）"; continue; fi
    echo "--- AI: $name ---"
    run python3 "$SCANNER" --ai-only $ONLY_FLAG --resume --authorized -o "$outdir"
  done
fi

# ── 汇总 ──────────────────────────────────────────────────────────────
if [ "$DRY" != "1" ]; then
  merged="$OUT/all_findings.csv"; first=1
  for c in "$OUT"/batch_*/findings.csv; do
    [ -f "$c" ] || continue
    if [ "$first" = "1" ]; then cat "$c" > "$merged"; first=0
    else tail -n +2 "$c" >> "$merged"; fi
  done
  echo ""; echo "===== 完成 ====="
  echo "输出根目录：$OUT"
  if [ -f "$merged" ]; then
    echo "汇总命中：${merged}（$(($(wc -l < "$merged") - 1)) 行）"
  fi
fi