#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
BASE="http://localhost:${PORT}"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        pkill -P "$SERVER_PID" 2>/dev/null || true
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# If the service is not already running, start it ourselves
if ! curl -sf --max-time 2 "$BASE/healthz" >/dev/null 2>&1; then
    bash ./scripts/run.sh &
    SERVER_PID=$!
    for _ in $(seq 1 40); do
        if curl -sf --max-time 1 "$BASE/healthz" >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
fi

total=0
pass=0

check() {
    local name="$1"
    total=$((total + 1))
    if "$2" > /dev/null 2>&1; then
        pass=$((pass + 1))
        echo "PASS: $name"
    else
        echo "FAIL: $name"
    fi
}

# Test 1: GET / returns 200 and a greeting
check "GET / returns 200 with greeting" \
    "bash -c 'code=\$(curl -s -o /tmp/inf345_body -w \"%{http_code}\" \"$BASE/\") && [[ \"\$code\" == \"200\" ]] && grep -q \"Hello\" /tmp/inf345_body'"

# Test 2: GET /healthz returns 200 and is not empty
check "GET /healthz returns 200, non-empty" \
    "bash -c 'body=\$(curl -sf \"$BASE/healthz\") && [[ -n \"\$body\" ]]'"

# Test 3: GET /notes returns 200 with a JSON list
check "GET /notes returns 200 with notes list" \
    "bash -c 'code=\$(curl -s -o /tmp/inf345_notes -w \"%{http_code}\" \"$BASE/notes\") && [[ \"\$code\" == \"200\" ]] && grep -q \"buy milk\" /tmp/inf345_notes'"

echo "TESTS: $pass/$total"
[[ "$pass" -eq "$total" ]]