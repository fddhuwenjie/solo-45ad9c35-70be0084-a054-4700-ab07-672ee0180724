#!/usr/bin/env bash
# 本地启动脚本（无外部服务依赖）。
# 优先使用随仓库的 ./.pylibs；否则在 ./.venv 中创建虚拟环境并安装依赖。
set -euo pipefail
cd "$(dirname "$0")"

export FORENSIC_DB="${FORENSIC_DB:-$(pwd)/data/forensic.db}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"

PYBIN="python3"
if [ -d ".pylibs" ]; then
  export PYTHONPATH="$(pwd)/.pylibs:${PYTHONPATH:-}"
elif [ -d ".venv" ]; then
  PYBIN="$(pwd)/.venv/bin/python"
else
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements.txt
  PYBIN="$(pwd)/.venv/bin/python"
fi

exec "$PYBIN" -m uvicorn app.main:app --host "$HOST" --port "$PORT"
