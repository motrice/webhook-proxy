#!/usr/bin/env bash
# PostToolUse hook: format a Rust file the moment it is written, so no agent
# ever burns a turn on a formatting diff and `just fmt-check` stays quiet.
set -euo pipefail

path=$(jq -r '.tool_input.file_path // empty')
[[ "$path" == *.rs ]] || exit 0
[[ -f "$path" ]] || exit 0

rustfmt --edition 2024 "$path" 2>/dev/null || true
