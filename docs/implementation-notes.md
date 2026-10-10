# Specification Review: Implementation Decisions

The CLI reports version `0.1`; newly produced signed sidecars use schema version 3 with signed `tm_version` producer metadata and retain verification semantics version 2. The x86-64 observer accepts pathname-based `execveat` calls with zero flags, records the executable path on successful exec, and treats `AT_EMPTY_PATH` or other flagged forms as unsupported.

The observer treats `getcwd` as covered by the command's working-directory identity and tracked `chdir`/`fchdir` transitions. A statically linked probe guards against reclassifying this syscall as unmodeled filesystem metadata.

The observer models direct `readlink` path probes alongside `readlinkat`: successful calls contribute symlink candidates, `ENOENT`/`ENOTDIR` contribute absence candidates, and other errors block eligibility.

The observer rejects PID/TID, user/group identity, affinity, and resource-limit observations until those values are included in an enforced verification context; the current profile backend does not normalize them. Direct probes cover `getpid`, `getppid`, `gettid`, `getuid`, `set_tid_address`, and `prlimit64`.

Bubblewrap launcher and preflight children close all inherited descriptors above standard input/output/error with `close_range`, falling back to `/proc/self/fd` enumeration and the open-file limit. A backend integration test covers a non-close-on-exec descriptor above 65,535 when the host limit allows it.

The `bubblewrap-linux-x86_64-v1` backend contract fixes the child umask at `022`; profile schema v1 does not permit a per-profile umask. The separately versioned v2 contract also explicitly creates a user namespace and runs with namespace UID/GID 0. Resource limits, CPU affinity, kernel/CPU context, and stable workspace snapshots remain unresolved; no portable hit is enabled.

The [technical specification](spec/tm-test-memoization-technical-specification.md) targets portable reuse across local worktrees and developer workstations, GitLab pipelines, and GitHub Actions workflows. The implementation includes a Linux x86-64 observer prototype with successful-open/read/close descriptor provenance and a bounded structured candidate report (repository-relative paths only; external host paths are redacted), OpenSSL SHA-256 and Ed25519 primitives, command/context/verification fingerprint helpers, bounded JSON/JCS support, schema-v3 signed records (v2 semantics) with optional output manifests, protected operator trust policy, `tm validate`, closed profile-v1 parsing plus repository/digest approval, immutable atomic publication under `.tm/results/<command-id>/<verification-id>/<record-id>.tm.json`, exact-slot lookup plus bounded context-wide lookup APIs that verify signatures and current inputs or pinned snapshots, output-tree capture that publishes SHA-256 blobs under `.tm/blobs/sha256`, and APIs that restore signed output manifests before returning a cross-worktree hit. The repeatable `--input PATH` option captures stable regular-file contents or immediate directory membership before launch and rechecks them after the child exits; directory members need separate file observations for content coverage; absent paths are tracked as nonexistence states, safe relative symlink targets are captured, and special files are rejected without blocking. Declarations never enable a hit by themselves. Profile launches build a clean child environment from approved constants. When the effective HOME and TMPDIR values are configured scratch roots, missing HOME/TMPDIR default to the first scratch root and missing PATH defaults to `/usr/bin:/bin`; host variables remain removed. `tm profile digest FILE` prints the profile approval digest. The observer preserves path provenance across `dup`, `dup2`, `dup3`, `fcntl`'s `F_DUPFD`/`F_DUPFD_CLOEXEC`, and `close_range` close/close-on-exec operations. Independent `clone3` process descriptor tables are copied; shared `CLONE_FILES`, inherited descriptors, range unsharing, and other `fcntl` operations remain ineligible. `chdir` and tracked-directory `fchdir` report cwd changes, while later relative accesses resolve against the tracee's live cwd. Directory opens/listings become sorted immediate-child membership digests through the candidate-to-manifest API, which can resolve approved repository candidates against pinned input-root snapshots; the controlled backend captures eligible reports against pinned snapshots and returns that manifest to the CLI for eligible output-free publication; lookup remains limited to trusted output-free repository records validated against profile snapshots. Controlled-profile observation now treats filesystem paths outside `/workspace` as covered by the approved runtime/scratch view; metadata access remains ineligible until all exposed metadata is normalized. Symlink resolution chains and runtime metadata/context equivalence still prevent reuse. Only `ENOENT`/`ENOTDIR` path failures become negative-input candidates; other file, exec, read, directory, and descriptor errors block eligibility. Bubblewrap preflight checks that `.tm` is empty, the runtime root rejects writes, and configured scratch roots are writable, but complete observation remains unavailable. Declared output roots are staged, captured, and restored, and modeled successful output-bearing runs can be signed and reused after snapshot validation. Broader observer coverage and external result distribution remain incomplete. This document describes target decisions and current implementation status.

## 1. Trust and provenance — portable signed evidence

Use Ed25519 signatures over the complete canonical result payload, including repository identity, inputs, environment/profile identity, output manifest, trust epoch, and successful outcome (spec sections 25–27). Consumers receive approved public keys, never shared private signing keys. A new clone can reuse checked-in results without first running the test locally.

Operator-controlled policy approves stable repository IDs, producer keys, profile digests, semantics, epochs, and revocations. A checked-in key or profile cannot approve itself. Local, GitLab, and GitHub producers use the same format; consumer policy decides which producers it accepts. A developer's result is usable in CI only if CI approves that developer's producer key/profile.

Untrusted test code must not access the signing capability or forge the supervisor's evidence. CI consumers can verify records without credentials; producing trusted records for untrusted PR/MR code requires an isolated supervisor. Signing arbitrary uploaded JSON in a later privileged job would not establish provenance.

Failures never become reusable successes. Track pending/failed attempts across local worktrees; quarantine contradictory same-fingerprint forced failures and distribute authenticated invalidations when connected. Preserve successes for unrelated input states. Offline verification uses an approved trust snapshot and cannot promise awareness of later revocations.

## 2. Environment identity — public, stable, and actually enforced

Portable command/context identities use SHA-256, without per-workstation HMAC keys. Signing keys and producer identities do not change a verification fingerprint. Stable repository identity is independent of checkout path, remote URL, branch, or CI provider (sections 7–8 and 17–18).

Construct a clean child environment from approved constants and explicit public inputs. Hash the entire environment actually delivered. Remove volatile GitLab/GitHub IDs, tokens, and host paths before execution; excluding them only from the fingerprint would be unsound. Unset and empty values differ, and argument boundaries remain significant.

The Bubblewrap path realizes a read-only runtime, an empty workspace exposing only operator-approved input roots as read-only binds, hidden writable `.tm` metadata, empty scratch roots, canonical cwd, cleared profile environment, and isolated network when its preflight succeeds. Each approved input root is copied into a private staging directory (4 GiB aggregate copy limit); recursive before/after inventories compare device, inode, mode, owner, link count, size, modification/change times, regular-file SHA-256 digests, and exact symlink targets. The staged tree is also checked against those source digests before use. Changed, unsupported, foreign-owned, or hard-linked entries force uncached execution. Bubblewrap receives pinned descriptors for the staged trees, so later host edits cannot change the guest's input view. The runtime is digested and checked before its pinned read-only bind; every non-scratch entry must be root-owned and have no owner/group/other write bits, with effective ACL and capability checks for the invoking process. This blocks unprivileged concurrent writers; privileged host administration remains trusted. Scratch subtrees are exempt because Bubblewrap replaces them with empty tmpfs mounts. The ptrace supervisor now wraps Bubblewrap, preserves only pinned bind-source descriptors, and follows launcher descendants. It ignores launcher setup until the requested executable successfully starts; failed or unmatched observation remains explicitly ineligible. Reuse remains disabled because this does not yet construct stable input manifests or integrate publication/lookup. The host currently rejects network namespace setup, so profile execution falls back to native uncached mode here. Output restoration, result publication/lookup, and complete context equivalence remain unimplemented.

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

1. Preserve the wrapper contract while developing the observer. Eligible controlled-backend reports can be converted into complete manifests from pinned input snapshots. `--signing-key` publishes successful eligible runs without declared inputs or outputs under an approved deterministic public profile. The wrapper can now skip a trusted, output-free checked-in result without explicit declarations after Bubblewrap preflight and input-manifest validation against a stable profile snapshot; shared user/remote stores and output restoration remain disconnected from the CLI.
2. Establish the reference portable execution profile/backend and rejection rules.
3. Integrate output capture, signed output manifests, storage, and restoration into producer/consumer paths. Capture, CAS blob publication, signed manifest encoding/validation, controlled-backend staging/capture/restoration, modeled output-write observation, signed publication, and snapshot-validated CLI lookup with restoration now exist. The observer permits descriptor writes, shared writable mappings, and modeled create/remove/truncate/permission operations only within declared output roots; rename/link/symlink and other unsupported mutations remain ineligible. Other observer gates still conservatively reject many workloads. Shared local/remote stores, coordination, and beta acceptance across worktrees and CI providers remain open. `tm validate` checks record-ID filenames.
4. Demonstrate checked-in-result reuse across clean worktrees/workstations and both GitLab and GitHub, using verification-only consumers.
5. Implement common result distribution and optional coordination, including failure recovery and invalidation.
6. Pilot actual workloads and measure eligibility, warm hits, validation cost, and concurrent duplicate rate.

Profile schema v1 is parsed and operator-approved by repository ID plus canonical digest, and is exposed through `tm profile digest FILE`. Explicit input/output declarations are checked against the profile's permitted roots. `tm runtime digest ROOTFS_DIR` hashes the normalized runtime tree; `tm runtime verify PROFILE TRUST_POLICY ROOTFS_DIR` additionally checks approval and that tree's match to the profile. `TM_RUNTIME_ROOT` is checked against that approved identity before Bubblewrap preflight. On the current WSL2 development host, Bubblewrap 0.12.0 can create user, PID, IPC, and UTS namespaces, but `--unshare-net` fails while creating the route socket (`Operation not permitted`); profile invocations therefore use the native uncached fallback here. Output-aware lookup, complete guest observation, common remote transport, and shared coordination remain open implementation work. There is no local-only caching milestone that counts as completing the product objective.

`tm --explain` prints a domain-separated profile-context fingerprint when the Linux x86-64 host context can be captured. The collector includes kernel identity, effective IDs and groups, affinity and flags for every allowed CPU, resource limits, umask, and standard descriptor availability/type/TTY state. The Bubblewrap projection normalizes umask to 022 and stdin to `/dev/null`; v2 also normalizes effective UID/GID to 0. Other captured host context, including supplementary groups, remains in the fingerprint conservatively. The resolved Bubblewrap executable's content digest is now included, and the backend rejects binaries that are not root-owned, immutable regular files. This remains diagnostic only: complete child-context equivalence is not yet proved, and the fingerprint does not authorize lookup or publication.

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
