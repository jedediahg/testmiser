#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
tm_bin=$repo_root/build/tm
work=$(mktemp -d "${TMPDIR:-/tmp}/tm-portable-ci.XXXXXX")
runtime=$work/runtime
profile=$work/profile.json
policy=$work/trust-policy.json
private_key=$work/producer.pem
key_json=$work/public-key.json

cleanup() {
    if [[ -d "$runtime" ]]; then sudo rm -rf -- "$runtime"; fi
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

if ! command -v bwrap >/dev/null || ! command -v busybox >/dev/null; then
    printf '%s\n' 'Install bubblewrap and busybox-static before running this acceptance test.' >&2
    exit 2
fi
sudo chmod u-s "$(command -v bwrap)"
if ! bwrap --unshare-user --unshare-ipc --unshare-pid --unshare-net \
    --unshare-uts --unshare-cgroup --uid 0 --gid 0 --ro-bind / / \
    -- /usr/bin/true; then
    printf '%s\n' 'Hosted runner cannot create the Bubblewrap profile namespaces required by the acceptance test.' >&2
    exit 1
fi

make -C "$repo_root" build/tm build/portable-reuse-probe
sudo install -d -o root -g root -m 0755 "$runtime/bin"
sudo install -o root -g root -m 0755 "$(command -v busybox)" \
    "$runtime/bin/busybox"
sudo ln -s busybox "$runtime/bin/sh"
sudo chmod -R a-w "$runtime"

runtime_digest=$("$tm_bin" runtime digest "$runtime")
printf '{"schema_version":1,"repository_id":"testmiser-portable-ci",'\
'"backend_contract":"bubblewrap-linux-x86_64-v2",'\
'"runtime_digest":"%s","workspace_path":"/workspace",'\
'"deterministic":true,"privacy_class":"public","environment":{},'\
'"input_roots":["build/portable-input.txt","build/portable-reuse-probe"],'\
'"output_roots":["build/reports"],"scratch_roots":["/tmp"]}\n' \
    "$runtime_digest" >"$profile"
chmod 0600 "$profile"
"$tm_bin" key generate "$private_key" >"$key_json"
profile_digest=$("$tm_bin" profile digest "$profile" | awk '{print $NF}')
key_id=$(jq -r '.key_id' "$key_json")
public_key=$(jq -r '.public_key' "$key_json")
printf '{"schema_version":1,"repositories":[{'\
'"repository_id":"testmiser-portable-ci","minimum_trust_epoch":1,'\
'"allowed_semantics":[2],"profiles":["%s"],"keys":[{'\
'"key_id":"%s","public_key":"%s","role":"developer"}],'\
'"revoked_key_ids":[]}]}\n' \
    "$profile_digest" "$key_id" "$public_key" >"$policy"
chmod 0600 "$policy"

TM_ACCEPTANCE_PROFILE=$profile \
TM_ACCEPTANCE_TRUST_POLICY=$policy \
TM_ACCEPTANCE_RUNTIME_ROOT=$runtime \
TM_ACCEPTANCE_SIGNING_KEY=$private_key \
TM_BIN=$tm_bin \
    "$repo_root/tests/portable-reuse.sh"
