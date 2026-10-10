#!/usr/bin/env bash
set -euo pipefail

make build/tm
if [[ -d .tm/blobs/sha256 ]]; then
    # Git preserves only the executable bit, so normalize checked-in CAS blobs
    # back to the immutable mode required by validation after checkout.
    find .tm/blobs/sha256 -type f -exec chmod 0444 -- {} +
fi
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
