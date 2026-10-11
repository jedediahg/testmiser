# Acceptance Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including
exit propagation and a short-lived descendant. With ptrace permission it also
checks network and mutation rejection. Unit checks cover SHA-256, Ed25519,
fingerprints, bounded JSON/JCS, signed records, trust policy, output manifests,
and observer behavior, including forcing libc vDSO clock reads through the
unsupported-syscall path. Run the ordinary suite with `make test`; OpenSSL EVP
development files are required. When ptrace is unavailable, the CLI suite
checks the uncached fallback.

## Portable reuse gate

`portable-reuse.sh` verifies signed output-bearing reuse in a clean clone,
declared-only input invalidation and state reversion, test executable
invalidation, repeated execution
after a failed input state while preserving an unrelated trusted success,
forced same-fingerprint failure quarantine, persistence across successful
reruns, and reuse only after explicit operator resolution,
sign-enabled signal termination without result publication, stale-output
replacement, linked worktree reuse from the per-user store, and cross-client
reuse through the optional filesystem store. The clean-clone hit uses a new
branch and old sidecar/blob mtimes, proving transport age and branch changes
alone do not expire accepted evidence. It also checks that `--explain`
reports each hit's trusted record, verification fingerprint, and store source,
plus revoked-producer lookup rejection and approval restoration, CI metadata
redaction, strict coordination failure and the available-mode duplicate-work
warning when the shared store is unavailable, and exactly-one execution for
concurrent cold requests. That cold-miss test also asserts that the CLI reports
one `WAIT` before the waiter reuses the owner's trusted result. The probe uses
GitLab-like and GitHub-like environment variables; this does not exercise
either provider's actual pipeline configuration.

Run the self-contained wrapper from the repository root on Linux x86-64:

```sh
TM_REQUIRE_PTRACE=1 make clean test
make analyze
bash tests/portable-reuse-ci.sh
```

The required-ptrace setting applies to `make test`, which runs the observer
integration checks. `make analyze` runs the compiler's static analyzer and does
not execute those tests.

The wrapper needs Bubblewrap, BusyBox static, `jq`, `sudo`, a C toolchain,
OpenSSL development headers, and Git. Its host must permit user, IPC, PID,
network, UTS, cgroup, and mount namespaces plus ptrace. It builds a temporary
runtime/profile/key/policy and invokes the full reuse test. Run as an
unprivileged user on an isolated, disposable runner; the wrapper uses `sudo`
to create and remove a root-owned read-only runtime, and removes temporary
credentials on exit. `TM_ACCEPTANCE_KEEP_WORK=1` retains diagnostic files and
requires manual cleanup.

To use a provisioned fixture directly, set absolute paths in
`TM_ACCEPTANCE_PROFILE`, `TM_ACCEPTANCE_TRUST_POLICY`,
`TM_ACCEPTANCE_RUNTIME_ROOT`, `TM_ACCEPTANCE_SIGNING_KEY`, and `TM_BIN`, then
run `tests/portable-reuse.sh`. Optional `TM_ACCEPTANCE_SHARED_STORE` must be an
existing private directory on a filesystem with coherent `flock`, owned by
the same numeric UID as the client. The script creates a private temporary
subdirectory there.

Unavailable namespaces or ptrace cause a failure, not a skipped pass. GitHub
runs this gate in a privileged Debian Trixie container on the protected
`tm-portable-acceptance` self-hosted runner group, for pushes to `main` only.
GitLab uses its protected `linux-bwrap` runner tag. Passing this gate proves
only its local/filesystem scenarios. Follow
[`docs/CI-INTEGRATION.md`](../docs/CI-INTEGRATION.md) to validate an adopting
project's runner, trust provisioning, and producer/consumer jobs.
