# Specification Review: Implementation Decisions

Reviewed against [the technical specification](spec/tm-test-memoization-technical-specification.md), `src/main.c`, `include/tm/tm.h`, and the current Makefile. These decisions describe the target implementation. Today only the command wrapper exists; every invocation runs.

## 1. Trust and provenance — resolved

**Decision:** Version 0.1 trusts a local supervisor's private authenticated receipt, not Git ancestry or committed JSON (spec sections 25–27).

The supervisor keeps a random 256-bit key and success receipts outside the checkout. A receipt authenticates the entire canonical sidecar, including the input manifest, execution identity, policy, and result. The store is scoped to a repository instance and trust domain. Editing a sidecar, cloning the repository, losing the store, or rotating the key causes execution. `tm validate` checks structure; it never grants trust.

A developer account is the local trust boundary. Running hostile code under that same account can expose its private store, so CI must isolate the supervisor/store from untrusted children before enabling reuse. Owner-only permissions alone are insufficient. Fresh CI jobs execute; importing receipts between machines is deferred until an authenticated transport and issuer policy exist.

Before every real run, including `--force`, revoke the previous receipt durably. Publish a replacement only after an eligible successful run. Otherwise a forced failure could leave an earlier success available to skip the next invocation. Serialize validation, revocation, execution, and publication with one command lock.

## 2. Environment identity — resolved

**Decision:** Fingerprint the whole environment delivered to the child, plus an explicit execution context and controlled runtime (sections 8, 15, 17–18, and 30).

Canonicalize UTF-8 `[name, value]` pairs sorted by name. Omission means unset; a present empty string means empty. Duplicate names and unsupported encodings disable reuse. Remove wrapper-only `TM_FORCE` consistently before delivery to the child. Do not omit any remaining variable from the fingerprint. An environment allowlist cannot establish completeness for arbitrary commands.

Use a private HMAC for environment/context and command identity. Plain hashes of small secrets can be guessed offline. Store neither raw argv nor environment values in sidecars. Include kernel/architecture/ABI, CPU feature identity, effective credentials/groups, umask, resource limits, and standard descriptor/TTY context. Unsupported context means execution without reuse.

A runtime version string is insufficient: executable/interpreter content, libraries, loader configuration, and system data must be covered by an immutable runtime digest and operator-enforced read-only coverage. An image digest does not cover mutable mounts or the host kernel. Host-specific values and local HMAC keys intentionally limit portability of success reuse.

Use RFC 8785 canonical JSON, a closed schema, explicit input sorting, and domain-separated digest preimages. Reject unknown versions/fields, duplicates, unsafe paths, and malformed hashes. Golden vectors are a prerequisite for the implementation's reuse gate.

## 3. Observation limits and external state — resolved

**Decision:** Begin with `ptrace` on Linux x86-64 native ABI, with an explicit syscall classification table and no skips during prototyping (sections 12–15 and 28–31).

Track all threads/descendants before first exec, descriptor and cwd changes, executable/interpreter loading, file reads/mappings, existence probes, symlinks, and directory enumeration. Unsupported observations invalidate the whole execution. File contents do not validate timestamps, ownership, inode identity, or other metadata returned by `stat`; the MVP declines reuse where it cannot model those observations.

Any socket creation or communication attempt disables reuse, including failed attempts, DNS, loopback, Unix sockets, and inherited sockets. A fixture hash cannot override this. Unknown syscalls, `io_uring`, uncontrolled descriptors, shared memory, namespace changes, trace loss, unsupported ABI changes, or escaped descendants also disable publication. A failed observer never restarts an already launched command.

Tracing cannot establish determinism. The operator must explicitly enable a profile for a deterministic command, and reliably detected uncontrolled time/randomness still prevents reuse. The profile also establishes stable input/runtime views and no required artifacts or effects. Without these preconditions, commands execute normally.

## 4. Process outcomes and CLI — resolved

**Decision:** Preserve the existing numeric exit convention and argument contract (sections 9–10, 34–36, and 51).

| Situation | Result |
| --- | --- |
| Normal child exit | Return its exact code, including 125–127. |
| Child terminated by signal | Return `128 + signal`; do not claim identical signal termination. |
| Usage/internal wrapper error | 125. |
| Command cannot execute | 126. |
| Command not found | 127. |
| Eligible cache hit | 0. |
| Cache write/observation failure after a collected outcome | Preserve child outcome; no reusable receipt. |

`--force` and `--explain` precede a mandatory `--`; following arguments pass unchanged without an implicit shell. Unknown/incomplete invocations return 125. Help returns 0. Numeric outcomes alone cannot distinguish wrapper errors from a child choosing the same code.

The spec now labels `--root`, `--input`, `TM_FORCE=1`, `validate`, and `clean` as target additions. They are not implemented today. `validate` returns 0 for structurally valid sidecars, 1 for invalid metadata, and 125 for usage/I/O errors, without running tests. `--external-input` and `--env-input` are deferred.

## 5. Implementation sequence — resolved

Follow the delivery gates in section 52:

1. Keep the existing wrapper and CLI checks as the baseline.
2. Prototype observation and rejection reasons with skips disabled.
3. Freeze the canonical schema and operator configuration interface; implement hashing, private state, validation, and atomic publication with skips disabled.
4. Enable local reuse only after provenance, input stability, failure revocation, concurrency, and all acceptance criteria pass.
5. Pilot eligible workloads and compare forced outcomes against proposed cache decisions before expanding coverage.

Reuse maintained cryptographic/JSON components where practical. Defer shared trust, adapters, output restoration, network reuse, and broad host support. Observer overhead and the fraction of eligible commands must be measured before making performance or delivery commitments.

The exact operator-profile/private-store configuration syntax is a remaining implementation deliverable, not permission to infer trust from repository files. No configured profile means no skips.

## Additional specification defects fixed

| Issue | Decision and implication |
| --- | --- |
| Post-run hashes can certify bytes the test never read; before/after comparison misses change-and-restore races. | Require a stable snapshot/read-only view or an explicit operator-enforced exclusion of writers. Ordinary advisory locks alone are insufficient (section 38). |
| A passing command may generate reports, binaries, caches, or side effects needed later. | No output replay in 0.1. Such commands execute uncached; eligible runs only return a reusable exit outcome (section 38). |
| Ignoring metadata actually read by the child hides dependencies. | Exclude supervisor activity only. Child access to `.tm`, including visible directory membership, disables reuse unless an enforced view hides it (section 22). |
| Guessing a primary test path is ambiguous and adjacent sidecars collide across command variants. | Always use root `.tm/commands/<command-id>.tm.json` in 0.1 (sections 7 and 16). |
| Symlinks, absent files, directory membership, untracked files, and PATH lookup affect behavior. | Track them explicitly or reject reuse; repository membership follows resolution, not a lexical path prefix (sections 6 and 13–17). |
| Direct-child success does not imply complete descendant observation. | Require accounted-for completion; surviving daemons prevent publication without indefinitely delaying the direct child's status (section 12). |
| Atomic JSON rename does not by itself authenticate a result or handle failed reruns. | Revoke receipt before execution, publish durable sidecar first and authenticated receipt last, under one lock (sections 20 and 38–39). |
| Sidecar validation was conflated with CI trust. | Validation never certifies a test result. CI may validate metadata-only changes only when the metadata is not an application input (sections 23–26 and 43). |

Sections 59 AC-13 through AC-20 add acceptance cases for these contracts. They are future implementation requirements; no cache implementation or new tests were added in this documentation review.

## Technical references

- [Linux ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html): syscall and descendant event mechanisms used by the proposed observer.
- [Linux vDSO manual](https://man7.org/linux/man-pages/man7/vdso.7.html): userspace time access illustrates why syscall tracing cannot prove determinism.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): canonical JSON encoding used by the proposed digest contract.
