#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${SDN_RUNTIME_DIR:-$ROOT/runtime}"

mkdir -p "$RUNTIME"

echo "[]" > "$RUNTIME/block_requests.json"
echo "[]" > "$RUNTIME/connection_events.json"

if [ ! -f "$RUNTIME/experiment_context.json" ]; then
    cp "$ROOT/config/experiment_context.example.json" "$RUNTIME/experiment_context.json"
fi

touch "$RUNTIME/block_requests.lock" "$RUNTIME/connection_events.json.lock" "$RUNTIME/block_events.lock"

chmod 777 "$RUNTIME"
chmod 666 "$RUNTIME"/*

echo "Runtime directory ready: $RUNTIME"
