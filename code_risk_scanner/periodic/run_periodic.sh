#!/usr/bin/env bash
# 周期巡检。有 Critical 也只告警，退出码保持 0。
# 可选：BLAME=1 补最近修改人；DINGTALK_WEBHOOK 发钉钉。
# Cron（北京时间，每周一、周四 03:00）：0 0 3 * * 1,4
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-${ROOT}/scan_report.json}"
ARGS=(
  --repo-path "${REPO_PATH:-$ROOT}"
  --skill-dir "${ROOT}/code_risk_scanner"
  --scan-mode FULL_PERIODIC
  --output "$OUT"
)
if [[ -n "${BLAME:-}" ]]; then
  ARGS+=(--blame)
fi

python3 "${ROOT}/code_risk_scanner/run_scanner.py" "${ARGS[@]}"
python3 "${ROOT}/code_risk_scanner/run_scanner.py" --render-alert "$OUT" > "${OUT%.json}.md"
if [[ -n "${DINGTALK_WEBHOOK:-}" ]]; then
  python3 "${ROOT}/code_risk_scanner/run_scanner.py" --notify "$OUT" || true
fi
