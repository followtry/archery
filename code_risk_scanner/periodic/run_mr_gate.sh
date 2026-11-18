#!/usr/bin/env bash
# MR 合入门禁。gate_status=BLOCK（存在 Critical）时退出码为 1。
# DIFF_BASE 默认 origin/master。基线不可用时退回全量，避免静默放过。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-${ROOT}/scan_report.json}"
set +e
python3 "${ROOT}/code_risk_scanner/run_scanner.py" \
  --repo-path "${REPO_PATH:-$ROOT}" \
  --skill-dir "${ROOT}/code_risk_scanner" \
  --scan-mode INCREMENTAL_MR \
  --diff-base "${DIFF_BASE:-origin/master}" \
  --output "$OUT"
code=$?
set -e
python3 "${ROOT}/code_risk_scanner/run_scanner.py" --render-alert "$OUT" > "${OUT%.json}.md" || true
exit "$code"
