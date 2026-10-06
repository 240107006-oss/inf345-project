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

record() {
    total=$((total + 1))
    if [[ "$2" -eq 0 ]]; then
        pass=$((pass + 1))
        echo "PASS: $1"
    else
        echo "FAIL: $1"
    fi
}

# Test 1: GET / returns 200 and a greeting
code=$(curl -s -o /tmp/inf345_body -w "%{http_code}" "$BASE/" || true)
if [[ "$code" == "200" ]] && grep -q "Hello" /tmp/inf345_body; then
    record "GET / returns 200 with greeting" 0
else
    record "GET / returns 200 with greeting" 1
fi

# Test 2: GET /healthz returns 200 and is not empty
body=$(curl -sf --max-time 5 "$BASE/healthz" || true)
if [[ -n "$body" ]]; then
    record "GET /healthz returns 200, non-empty" 0
else
    record "GET /healthz returns 200, non-empty" 1
fi

# Test 3: GET /notes returns 200 and a JSON list
code=$(curl -s -o /tmp/inf345_notes -w "%{http_code}" "$BASE/notes" || true)
if [[ "$code" == "200" ]] && grep -q "buy milk" /tmp/inf345_notes; then
    record "GET /notes returns 200 with notes list" 0
else
    record "GET /notes returns 200 with notes list" 1
fi

echo "TESTS: $pass/$total"
[[ "$pass" -eq "$total" ]]