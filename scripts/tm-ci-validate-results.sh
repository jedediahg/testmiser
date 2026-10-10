#!/usr/bin/env bash
set -euo pipefail

make build/tm
if [[ -n "${TM_TRUST_POLICY_JSON:-}" ]]; then
    policy_file=$(mktemp)
    trap 'rm -f "$policy_file"' EXIT
    printf '%s' "$TM_TRUST_POLICY_JSON" >"$policy_file"
    chmod 600 "$policy_file"
    ./build/tm validate --root . --trust-policy "$policy_file" --require-trust
else
    # Without an operator policy, no sidecar can authorize CI reuse.
    ./build/tm validate --root . --require-trust
fi
