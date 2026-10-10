# CI Integration Runbook

This runbook describes a cautious beta rollout of `tm` in an existing project
with GitLab CI and multiple local Git worktrees. The goal is to let a test job
verify and reuse trusted evidence before it spends a loaded runner executing
the test command. `tm` wraps the existing command; it does not replace the
project's build or test tools.

## Readiness and prerequisites

Portable skipping requires more than installing the binary. The project needs
an operator-approved deterministic profile, a matching runtime tree, a
public trust policy, and a Linux x86-64 runner that can enforce the Bubblewrap
profile and ptrace observation. The CI variables must point to those exact
approved files. If the backend cannot enforce the profile, ordinary runs fall
back to execution without reuse. A producer invocation with `--signing-key`
fails closed if the controlled backend cannot start.

Keep producers and consumers on a compatible execution context. `tm` includes
host kernel identity, CPU features/affinity, resource limits, descriptor state,
and other non-normalized context in the fingerprint. The same container or
runtime tree does not make heterogeneous hosts equivalent. Use a homogeneous
runner pool or a common VM contract; expect a safe miss when these values
differ, and do not remove them from the fingerprint to raise hit rates.

The current result transport that works across machines is checked-in `.tm`
evidence. The optional `TM_SHARED_STORE` is a mounted filesystem prototype;
its root and private store directories must be owned by the same numeric UID
as each client, and its filesystem must provide coherent `flock`. A typical
shared volume mounted for runners with different UIDs will not work. There is
no GitLab object-store adapter or lease/fencing coordinator yet. Do not count
GitLab cache restore as verified evidence: records and referenced blobs still
need signature and input validation.

## Prepare a project and its trust policy

1. Choose the exact command CI already runs, including all arguments. Keep
   setup and test inputs explicit; do not wrap a command that consumes mutable
   databases, network services, secrets, or undeclared generated state.
2. Until a general installation package exists, build the binary from an
   operator-pinned TestMiser source revision with `make -C /path/to/testmiser
   build/tm`. Provision that same reviewed build for local agents and the
   compatible CI runner pool. Create the team's profile/runtime through an operator-owned
   process. The profile must declare the canonical workspace, public
   environment, all permitted input/output roots, scratch roots, runtime
   digest, backend contract, and deterministic behavior. Profile and runtime
   changes require operator approval.
3. Approve the profile digest and producer public key in a trust policy that
   CI controls. Check in the profile if useful, but keep trust policy and
   signing credentials in protected operator/CI configuration. Verify
   provisioning with:

   ```sh
   tm profile digest .tm/profiles/portable-linux.json
   tm runtime verify .tm/profiles/portable-linux.json \
     /etc/testmiser/trust-policy.json /opt/testmiser/runtime
   ```

   Trust policy format and the profile's repository ID must match what the
   project will pass to `tm`.

## Local worktrees and agent workflow

Create worktrees using the team's usual convention, for example:

```sh
mkdir -p .worktrees
git worktree add .worktrees/agent-issue-123 -b agent/issue-123
cd .worktrees/agent-issue-123
TM_RUNTIME_ROOT=/opt/testmiser/runtime \
  tm --root . \
    --profile .tm/profiles/portable-linux.json \
    --trust-policy /etc/testmiser/trust-policy.json \
    --output build/reports --explain -- ./scripts/test.sh
```

Make the pinned executable available on each agent's `PATH`, or replace `tm`
with its absolute path. Same-user worktrees share `tm`'s private per-user
cache automatically. They can also consume checked-in `.tm/results` and
`.tm/blobs`. Run with `--explain` during rollout and inspect `RUN`/`SKIP` and
the trust/input reason. A successful eligible run can be signed only when
the selected profile, runtime, key, and trust approval agree:

```sh
tm --root . --profile .tm/profiles/portable-linux.json \
  --trust-policy /etc/testmiser/trust-policy.json \
  --signing-key /secure/path/producer.pem \
  --output build/reports -- ./scripts/test.sh
```

Review and commit only the generated `.tm/results/**` and `.tm/blobs/**`
evidence needed by the project. Never commit private keys. CI can trust a
developer-produced record only after an operator approves that developer's
public key and profile. Concurrent local worktrees are tested against the same
per-user cache; edits to declared inputs during a run cause validation to
reject publication or reuse.

## GitLab consumer job

Install the versioned `tm` binary, select a compatible isolated runner, and
provide the approved runtime and public trust policy through protected
configuration. Set `TM_BIN` to the pinned executable path,
`TM_RUNTIME_ROOT` to the approved runtime tree, and
`TM_TRUST_POLICY_FILE` to the operator-managed public policy. The test job
should invoke the same command and declarations used by local producers:

```yaml
test:
  stage: test
  script:
    - >-
      TM_RUNTIME_ROOT="$TM_RUNTIME_ROOT"
      "$TM_BIN" --root .
      --profile .tm/profiles/portable-linux.json
      --trust-policy "$TM_TRUST_POLICY_FILE"
      --output build/reports --explain -- ./scripts/test.sh
```

Adapt YAML quoting to the project's shell and install/build process. If `tm`
is not on `PATH` locally, invoke the binary built from the pinned source
checkout. Keep the profile/runtime compatible across producer and consumer;
changing command, arguments, declared environment, profile, or observed
inputs should result in a miss. With public verification material, CI can skip
a trusted hit. On a miss it runs tests but does not publish a trusted result.
Do not expose a producer key to merge-request code. A protected producer job
must use disposable runners and prevent untrusted pipeline configuration
from accessing the signing secret.

For evidence-only commits, the test suite itself can be omitted after strict
validation. The repository scripts `scripts/tm-result-diff.sh` and
`scripts/tm-ci-validate-results.sh` show the current policy: detect changes
limited to `.tm/results/**` and `.tm/blobs/**`, then run
`tm validate --require-trust`. For mixed source/evidence changes, run the
ordinary test job and validate evidence too. Adapt the base/head selection for
merge requests and first commits; an unknown diff base must run tests rather
than be treated as evidence-only.

In an adopting project, vendor or adapt the reviewed result-diff helper and
use logic like this in the test job. `tm-result-diff.sh` exits successfully
only when the Git diff is limited to the two evidence trees:

```sh
base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"
results_only=false
has_results=false
if [[ -n "$base" ]] &&
  bash scripts/tm-result-diff.sh any "$base" "$CI_COMMIT_SHA"; then
  has_results=true
  if bash scripts/tm-result-diff.sh only "$base" "$CI_COMMIT_SHA"; then
    results_only=true
  fi
fi

if [[ "$results_only" == true ]]; then
  echo "Evidence-only change; skipping application tests."
else
  TM_RUNTIME_ROOT="$TM_RUNTIME_ROOT" "$TM_BIN" --root . \
    --profile .tm/profiles/portable-linux.json \
    --trust-policy "$TM_TRUST_POLICY_FILE" \
    --output build/reports -- ./scripts/test.sh
fi

if [[ "$has_results" == true ]]; then
  "$TM_BIN" validate --root . \
    --trust-policy "$TM_TRUST_POLICY_FILE" --require-trust
fi
```

This preserves test execution for source changes and unknown diff bases while
avoiding the suite for an evidence-only commit. Use the provider's correct
merge-request base SHA and ensure the job has enough Git history for the
three-dot comparison. A missing trust policy must fail strict validation;
never downgrade it to a successful no-op.

Do not put the key in a normal GitLab variable available to arbitrary jobs.
The `tm` supervisor keeps the key out of the test process, but it cannot
protect a secret from malicious CI shell commands that run outside `tm`.
Protected branch/ref rules, reviewed CI configuration, restricted runners,
and isolated disposable workers are still required.

## Rollout and operating checks

Start with one deterministic, self-contained test command and a narrow
profile. First run it with `--explain` on a compatible runner and confirm a
real `RUN`, then produce signed evidence through an authorized producer and
confirm a clean worktree/CI consumer reports `SKIP: trusted result`. Repeat on
each runner pool and compare the reported context fingerprints; different
fingerprints mean the pools are not yet portable equivalents. Change an input
and confirm it runs. Confirm invalid signatures, unapproved profiles, missing
blobs, unsupported observations, and unavailable sandbox capability never
cause a skip. Only after those cases pass should the project rely on the job
for runner savings.

Record total job time, actual test-command duration, trusted-hit rate, and
reasons for misses for the pilot. A warm hit should avoid test execution, but
checkout, binary startup, profile preflight, and evidence validation still
cost time. If misses dominate, widen coverage only by adding real stable inputs
or an approved runtime; never weaken observation or trust checks to raise the
hit rate. The upstream acceptance procedure is documented in
[`tests/README.md`](../tests/README.md); it requires working user/network
namespaces and ptrace and is a release gate, not an optional local test.

## Current beta limits

The repo's current CI validates this repository's evidence and runs its own
tests; that does not prove a separate project's test job is integrated.
Cross-worktree behavior has an acceptance script, but the full portable gate
must pass on the target runner. Shared filesystem coordination can still
duplicate cold runs if locking is unavailable and is not partition-safe.
Remote result stores, strict distributed coordination, cross-provider
acceptance, and a general-purpose installation package are not implemented.
Treat this as a controlled pilot until the target project's GitLab producer
and consumer flow has passed the checks above.
