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

The GitHub Actions acceptance job runs Bubblewrap inside a disposable
privileged Debian container as a non-root user. Standard GitHub-hosted runners
deny the required network namespace, even for that nested container. The job
uses a dedicated self-hosted runner group whose Docker daemon permits the
nested namespace and ptrace operations. The GitLab gate uses
the `linux-bwrap` runner tag for the same reason. Mark that runner protected,
and reserve the tag for a dedicated disposable host. The job runs only on
protected branch/tag pipelines and explicitly excludes merge-request pipelines,
including same-project requests whose source and target branches are both
protected. Merge requests run verification on ordinary runners and qualify
for portable acceptance after merge. A runner tag or job-level rule alone is
not a security boundary because a merge request can edit `.gitlab-ci.yml`.
Provision only runners that pass the portable
acceptance gate; a successful repository workflow does not prove a separate
project's runner has the same namespace, ptrace, filesystem, or UID behavior.

For GitHub, create an organization runner group named
`tm-portable-acceptance`, allow only the `jedediahg/testmiser` repository, and
restrict workflow access to
`jedediahg/testmiser/.github/workflows/ci.yml@refs/heads/main`. Register a
dedicated self-hosted runner in that group with the label
`tm-portable-acceptance`:

```sh
./config.sh --url https://github.com/jedediahg/testmiser \
  --token "$RUNNER_TOKEN" --labels tm-portable-acceptance --ephemeral
gh variable set TM_PORTABLE_ACCEPTANCE_ENABLED \
  --repo jedediahg/testmiser --body true
```

The privileged acceptance job is skipped until the variable is set to `true`,
then runs only on pushes to `main`; pull requests run the hosted test job and
qualify for portable acceptance after merge. GitHub treats a conditionally
skipped job as successful, so the separate `portable-acceptance-policy` check
fails a main-branch source-change run unless the privileged acceptance job
actually succeeds. It passes on pull requests because privileged acceptance
is deliberately deferred until after merge. Keep the variable unset until the
runner group and runner are configured; do not qualify a main-branch source
commit or beta release while this policy check is failing.
The runner-group
restriction is a security boundary: the job-level event condition is useful for
scheduling but is not sufficient because pull requests can change workflow
files. Use a one-job ephemeral runner and destroy or reimage its VM after the
job. `--ephemeral` deregisters the runner after one job but does not wipe its
host. Do not expose secrets, deployment credentials, or internal network access
to this runner. Do not attach this runner to the default or any unrestricted
group.

The repository's `.gitlab-ci.yml` routes verification, portable acceptance,
and a final acceptance-policy check to ordered stages. The policy recomputes
whether a source change requires acceptance, validates a dotenv success result
from the acceptance job, and fails if a protected source change
skipped that job. It also rejects an unprotected default branch or release
tag. Workflow rules prevent duplicate branch pipelines when a
merge request is open. The verification job starts only for source, test,
build, specification, CI, or `.tm` evidence changes; its shared classifier
then skips source tests for evidence-only commits while still requiring strict
trusted validation. Configure `TM_CI_TRUST_POLICY_FILE` as a GitLab file-type
variable containing the operator-managed public consumer trust policy; make it
available to every pipeline that must validate evidence. Portable acceptance
uses pinned Docker CLI/daemon images and requires the protected `linux-bwrap`
runner to permit privileged Docker-in-Docker, nested user/network namespaces,
and ptrace. Its Docker executor must mount `/certs/client` for TLS. Configure
it as protected in GitLab runner settings and ensure no unprotected runner
advertises that tag; this server-side setting is the access control. Ordinary
shared runners are not suitable for that job.

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
2. Until a general installation package exists, build from an operator-pinned
   TestMiser source revision and stage the executable without changing the
   build host:

   ```sh
   make -C /path/to/testmiser
   make -C /path/to/testmiser install PREFIX=/usr \
     DESTDIR=/path/to/staging/testmiser
   # Staged binary: /path/to/staging/testmiser/usr/bin/tm
   ```

   Provision that same reviewed build for local agents and the compatible CI
   runner pool. Create the team's profile/runtime through an operator-owned
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
`.tm/blobs`. Run with `--explain` during rollout and inspect `RUN`, `WAIT`, or
`SKIP` plus the trust/input reason. `WAIT` means an equivalent invocation
currently owns the shared or per-user execution slot; `tm` waits, then checks
for newly published trusted evidence before deciding whether to run. A
successful eligible run can be signed only when
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
validation. The repository helper `scripts/tm-ci-classify-changes.sh` combines
the source-change and result-diff checks and fails if it cannot classify the
Git history. It handles an all-zero first-push base by comparing the full tree
with Git's empty tree. For other unavailable bases, fetch enough history or
fall back to running the full test suite and validating all available
evidence; never ignore the classification error. Mixed source/evidence
changes run the ordinary test job and validate evidence too.

The repository's `.gitlab-ci.yml` and GitHub Actions workflow call the shared
`scripts/tm-ci-run-tests.sh` policy runner. Its regression test verifies that
result-only changes skip test execution but still require strict trust
validation, mixed changes run tests and validate evidence, and validation
failure fails the job. A real-validator integration test confirms a malformed
result-only sidecar fails the job without running tests. Adopting projects can
vendor this policy runner and replace its `make clean test` and `make analyze`
commands with their normal verification commands.

In an adopting project, vendor or adapt the reviewed result-diff helper and
use logic like this in the test job. `tm-result-diff.sh` exits successfully
only when the Git diff is limited to the two evidence trees:

The validation helper accepts either `TM_TRUST_POLICY_FILE` (a path, suitable
for GitLab file-type variables) or `TM_TRUST_POLICY_JSON` (policy contents,
suitable for a protected GitHub Actions variable). Set at most one. If neither
is set, it uses the repository's default trust policy and still requires
trusted evidence.

```sh
base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"
classification=$(bash scripts/tm-ci-classify-changes.sh \
  "$base" "$CI_COMMIT_SHA")
tests_required=$(printf '%s\n' "$classification" |
  sed -n 's/^tests_required=//p')
has_results=$(printf '%s\n' "$classification" |
  sed -n 's/^has_results=//p')
results_only=$(printf '%s\n' "$classification" |
  sed -n 's/^results_only=//p')

if [[ "$results_only" == true ]]; then
  echo "Evidence-only change; skipping application tests."
elif [[ "$tests_required" == true ]]; then
  TM_RUNTIME_ROOT="$TM_RUNTIME_ROOT" "$TM_BIN" --root . \
    --profile .tm/profiles/portable-linux.json \
    --trust-policy "$TM_TRUST_POLICY_FILE" \
    --output build/reports -- ./scripts/test.sh
else
  echo "No test-relevant source changes."
fi

if [[ "$has_results" == true ]]; then
  if [[ -d .tm/blobs/sha256 && ! -L .tm && ! -L .tm/blobs &&
        ! -L .tm/blobs/sha256 ]]; then
    find .tm/blobs/sha256 -type f -exec chmod 0444 -- {} +
  fi
  "$TM_BIN" validate --root . \
    --trust-policy "$TM_TRUST_POLICY_FILE" --require-trust
fi
```

This preserves test execution for source changes and rejects unknown diff
bases instead of accidentally treating them as evidence-only. Use the
provider's correct merge-request base SHA and ensure the job has enough Git
history for the three-dot comparison. A missing trust policy must fail strict
validation; never downgrade it to a successful no-op. Git does not preserve
read-only permission bits for checked-in regular files, so restore immutable
blob mode `0444` before validation; the helper script performs this
normalization.

For ordinary GitLab pushes and merge requests, use `rules:changes` to avoid
creating the test job for unrelated paths. Keep source, headers, tests, build
scripts, profiles, specification, and CI configuration in the test-relevant
set; documentation-only paths can omit the job. The repository's
`.gitlab-ci.yml` is an example. Keep a conservative fallback for tags,
schedules, manually started pipelines, and new branches: GitLab can treat
`rules:changes` as true when there is no push diff, and unknown diff bases must
run tests. Do not broaden the evidence-only exception to source or profile
changes.

For jobs where overlapping cold runs are unacceptable, set
`TM_COORDINATION_MODE=strict` and configure a coherent shared filesystem in
`TM_SHARED_STORE`. In this mode `tm` returns 125 before launching the command
if it cannot open the shared store or acquire the execution slot. The current
implementation uses blocking `flock`; it has no leases or fencing tokens and
does not prove that an abandoned remote owner has stopped. Use this mode only
on storage whose locking behavior is established for every client. Omit the
variable for the default available mode, which allows duplicate execution
when shared coordination is unavailable.

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

Before and during the pilot, record runner queue wait, whole-job duration,
actual test-command duration, dependency-install time, trusted-hit rate,
reasons for misses, and how many test jobs path rules omit. A warm hit avoids
the test command, but checkout, binary startup, profile preflight, and evidence
validation still cost time. Compare the critical path and runner wait as well
as test time; [GitLab's pipeline efficiency guidance](https://docs.gitlab.com/ci/pipelines/pipeline_efficiency/)
recommends measuring job duration, dependencies, runner availability, and
setup overhead.
If misses dominate, widen coverage only by adding real stable inputs or an
approved runtime; never weaken observation or trust checks to raise the hit
rate. The upstream acceptance procedure is documented in
[`acceptance test guide`](ACCEPTANCE-TESTS.md); it requires working user/network
namespaces and ptrace and is a release gate, not an optional local test.

## Current beta limits

The repo's current CI validates this repository's evidence and runs its own
tests; that does not prove a separate project's test job is integrated.
Cross-worktree behavior has an acceptance script, but the full portable gate
must pass on the target runner. Available-mode shared filesystem coordination
can duplicate cold runs if locking is unavailable; strict mode fails before
launch in that case, but neither mode is partition-safe or uses leases/fencing.
Remote result stores, cross-provider acceptance, and a general-purpose
installation package are not implemented.
Treat this as a controlled pilot until the target project's GitLab producer
and consumer flow has passed the checks above.
