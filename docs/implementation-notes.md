# Specification Review: Implementation Decisions

The [technical specification](spec/tm-test-memoization-technical-specification.md) targets portable reuse across local worktrees and developer workstations, GitLab pipelines, and GitHub Actions workflows. The implementation includes a Linux x86-64 observer prototype with successful-open/read/close descriptor provenance, OpenSSL SHA-256 and Ed25519 primitives, command/context/verification fingerprint helpers, bounded JSON/JCS support, signed v2 records with optional output manifests, protected operator trust policy, `tm validate`, closed profile-v1 parsing plus repository/digest approval, immutable atomic publication under `.tm/results/<command-id>/<verification-id>/<record-id>.tm.json`, an exact-slot lookup API that verifies record signatures and current manifests, output-tree capture that publishes SHA-256 blobs under `.tm/blobs/sha256`, and a library restore API that verifies blobs and stages declared roots before replacement. The repeatable `--input PATH` option captures stable regular-file contents or immediate directory membership before launch and rechecks them after the child exits; directory members need separate file observations for content coverage; absent paths are tracked as nonexistence states, safe relative symlink targets are captured, and special files are rejected without blocking. Declarations never enable a hit by themselves. Approved profile constants are delivered as the child environment, with host variables removed; `tm profile digest FILE` prints the profile approval digest. Descriptor duplication and shared `CLONE_FILES` remain ineligible. The bubblewrap/runtime view and complete observation are not enforced. Signed output manifests can be created and inspected, and declared roots have a staged restore API; the default lookup rejects output-bearing records, while `tm_result_find_and_restore` returns a hit only after trusted input validation and successful restoration. Wrapper lookup/reuse remains unimplemented, so every wrapped command still executes. This document describes target decisions, not completed functionality.

## 1. Trust and provenance — portable signed evidence

Use Ed25519 signatures over the complete canonical result payload, including repository identity, inputs, environment/profile identity, output manifest, trust epoch, and successful outcome (spec sections 25–27). Consumers receive approved public keys, never shared private signing keys. A new clone can reuse checked-in results without first running the test locally.

Operator-controlled policy approves stable repository IDs, producer keys, profile digests, semantics, epochs, and revocations. A checked-in key or profile cannot approve itself. Local, GitLab, and GitHub producers use the same format; consumer policy decides which producers it accepts. A developer's result is usable in CI only if CI approves that developer's producer key/profile.

Untrusted test code must not access the signing capability or forge the supervisor's evidence. CI consumers can verify records without credentials; producing trusted records for untrusted PR/MR code requires an isolated supervisor. Signing arbitrary uploaded JSON in a later privileged job would not establish provenance.

Failures never become reusable successes. Track pending/failed attempts across local worktrees; quarantine contradictory same-fingerprint forced failures and distribute authenticated invalidations when connected. Preserve successes for unrelated input states. Offline verification uses an approved trust snapshot and cannot promise awareness of later revocations.

## 2. Environment identity — public, stable, and actually enforced

Portable command/context identities use SHA-256, without per-workstation HMAC keys. Signing keys and producer identities do not change a verification fingerprint. Stable repository identity is independent of checkout path, remote URL, branch, or CI provider (sections 7–8 and 17–18).

Construct a clean child environment from approved constants and explicit public inputs. Hash the entire environment actually delivered. Remove volatile GitLab/GitHub IDs, tokens, and host paths before execution; excluding them only from the fingerprint would be unsound. Unset and empty values differ, and argument boundaries remain significant.

The execution backend must realize canonical workspace/runtime paths, controlled HOME/TMPDIR, locale/timezone, descriptor policy, identity, and limits. Runtime content, observable kernel/CPU/ABI differences, and unnormalized metadata remain real inputs. A container image digest alone does not make different hosts equivalent; use compatible contexts or an enforced common VM/runtime contract.

Only declared public inputs may enter portable records. Secret-dependent shared results are deferred: plain hashes can reveal guessable secrets, while sharing HMAC keys would undermine the public-consumer model. Supervisor transport/signing credentials never reach the child.

## 3. Observation limits — supported execution contract

Retain Linux x86-64 `ptrace`, complete descendant tracking, explicit syscall classification, and conservative rejection of unsupported observations (sections 12–15). A trusted signature does not compensate for incomplete discovery.

Test socket/network access, external mutable services, unmodeled IPC/descriptors/syscalls, or uncontrolled nondeterminism prevent publication. Supervisor result downloads/uploads are outside this observation boundary and are allowed. Observer failure after launch never restarts the command.

The portable backend provides stable input/runtime views, hides `.tm` metadata, starts scratch/output roots empty, and controls the delivered environment. A native discovery mode can run uncached when those guarantees are unavailable. Normalized filesystem metadata must actually be exposed consistently, not merely omitted from the hash.

## 4. Process outcomes and CLI — retained with portable additions

Normal child exit codes pass through; signal termination returns `128 + signal`; wrapper usage/internal errors use 125; cannot-execute and missing-command use 126/127. Child codes may overlap these values. A cache publication error preserves the collected child outcome.

On Linux x86-64, the wrapper forwards SIGINT, SIGTERM, SIGHUP, and SIGQUIT to the wrapped process tree and reaps traced descendants after interruption. `PTRACE_O_EXITKILL` protects tracees if the wrapper exits unexpectedly. The CLI test covers a direct child and a live grandchild; this process-lifecycle support does not make observation complete or enable reuse.

The mandatory `--` and exact argv semantics remain. Target additions include approved `--profile`/`--trust-policy`, repeatable `--input`/`--output`, `validate --require-trust`, and scoped `clean` (section 34). `--force` deliberately overrides reuse and participates in failed-attempt/quarantine rules.

`validate` never runs tests or signs records. `clean` preserves checked-in results by default and never discards trust keys or invalidations as disposable cache state. Explain output distinguishes a genuine input change, unavailable evidence/artifacts, untrusted producer, incompatible context, force, and coordination outages.

## 5. Implementation sequence — portability is a release gate

Follow section 52:

1. Preserve the wrapper contract while developing the observer with skips disabled. The observer, SHA-256, Ed25519, and command/verification fingerprint primitives are present, but the observer does not yet produce complete stable input manifests.
2. Establish the reference portable execution profile/backend and rejection rules.
3. Integrate output capture, signed output manifests, storage, and restoration into producer/consumer paths. Capture, CAS blob publication, signed manifest encoding/validation, and a staged library restore API exist. The default lookup remains output-free; `tm_result_find_and_restore` validates inputs, calls restore, and returns only after restoration succeeds. The wrapper still does not call lookup or skip execution. Immutable output-free record publication and exact-fingerprint lookup validate signatures and current declared inputs, but the wrapper does not call lookup or skip execution. `tm validate` checks record-ID filenames. Cryptographic and fingerprint primitives alone do not authorize reuse.
4. Demonstrate checked-in-result reuse across clean worktrees/workstations and both GitLab and GitHub, using verification-only consumers.
5. Implement common result distribution and optional coordination, including failure recovery and invalidation.
6. Pilot actual workloads and measure eligibility, warm hits, validation cost, and concurrent duplicate rate.

Profile schema v1 is now frozen, parsed, operator-approved by repository ID plus canonical digest, and exposed through `tm profile digest FILE`. The selected bubblewrap contract is not yet enforced: v1 still needs an immutable runtime provision/mapping contract, and the backend must prove network and mount namespace capabilities before launch. On the current WSL2 development host, Bubblewrap 0.12.0 can create user, PID, IPC, and UTS namespaces, but `--unshare-net` fails while creating the route socket (`Operation not permitted`); profile invocations therefore remain uncached here. Integrating output restoration, wrapper lookup/reuse, common remote transport, and shared coordination remain open implementation work. There is no local-only caching milestone that counts as completing the product objective.

## How the no-repeat objective works

| Situation | Required behavior |
| --- | --- |
| Available trusted result; same effective inputs/context | Reuse locally, in another worktree/workstation, or in either CI provider. |
| New branch/commit with only unrelated changes | Reuse; commit identity is not the cache key. |
| Return to a previously verified input state | Reuse the retained immutable result for that state. |
| Required report/artifact on a hit | Verify and restore declared outputs before reporting success. |
| Simultaneous cold requests with healthy shared coordination | One owner executes; waiters re-query and reuse. |
| Disconnected cold requests | Duplicate work remains possible because no result/ownership is shared. |
| Coordinator outage | Available mode permits duplicates; strict mode waits/fails before launch. |
| Crash after computation, before durable publication | May need to recompute; no exactly-once recovery claim. |
| Changed inputs, failure, force, revoked trust, missing evidence | Execute or apply explicit strict policy; never fabricate a hit. |

The generic cache unit is a command invocation. Overlapping suites cannot deduplicate individual test cases without a future framework adapter. “Never run the same test twice” means avoiding repeated eligible successful verification for a complete fingerprint, with these availability and granularity limits explicit.

## Changes from the earlier review

| Earlier decision | Revised decision |
| --- | --- |
| Private per-checkout receipt/HMAC required for reuse | Portable Ed25519 evidence, public verification policy, and unkeyed public-input identities. |
| Fresh clone always runs | Fresh clone can immediately reuse an approved checked-in record. |
| One latest sidecar per command | Immutable `.tm/results/<command-id>/<verification-id>/<record-id>.tm.json` history. |
| Full inherited CI environment hashed | Clean actual child environment; hash every delivered value. |
| Writes/reports make all runs ineligible | Allow isolated empty scratch and declared captured/restored output roots. |
| Metadata hiding/sandboxing deferred | Enforced portable execution view required for shared eligibility. |
| Shared trust, signatures, and CI reuse deferred | First portable release requirements for both GitLab and GitHub. |
| Local lock only | Shared worktree lock plus optional provider-neutral coordinator for cold misses. |
| Routine exhaustive reruns recommended | Explicit optional audits; no automatic age/pipeline-based repeat of accepted results. |

Acceptance criteria AC-13 through AC-25 cover provenance, privacy, output restoration, canonical identities, worktree/workstation sharing, GitLab/GitHub interoperability, concurrent cold misses, partitions, and no implicit repeat policy. These are future implementation checks; this update adds no executable implementation or tests.

## Technical references

- [Linux ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) and [vDSO](https://man7.org/linux/man-pages/man7/vdso.7.html): observation mechanisms and the limits of syscall-only determinism detection.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): canonical JSON and Ed25519.
- [GitLab predefined variables](https://docs.gitlab.com/ci/variables/predefined_variables/) and [GitHub variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables): CI-specific values that must remain outside the portable child environment unless explicitly required.
- [GitLab caching](https://docs.gitlab.com/ci/caching/) and [GitHub dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching): transport availability and scope limitations; provider caches are not globally available proof stores.
