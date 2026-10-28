# ShadowScan 环境变量示例 —— 复制为 env.sh 后填入自己的值
#   cp env.example.sh env.sh && chmod 600 env.sh
#
# 任何 OpenAI 兼容的 /chat/completions 端点都可以用（自建 vLLM / Ollama / 商业 API 均可）

export SHADOWSCAN_LLM_URL="https://your-llm-gateway.example.com/v1/chat/completions"
export SHADOWSCAN_LLM_KEY="sk-your-api-key"

# 模型分工：逐条研判量大求快用轻量模型；智能报告要深度总结用强模型
export SHADOWSCAN_LLM_MODEL="your-strong-model"          # 智能报告（B）
export SHADOWSCAN_LLM_ASSESS_MODEL="your-fast-model"     # 逐条研判（A/C/D）

# 单次调用超时（秒）。推理型模型偏慢，建议 120
export SHADOWSCAN_LLM_TIMEOUT="120"
