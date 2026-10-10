# TestMiser

`tm` is a Linux-first C utility that memoizes successful verification
commands. It observes files and execution context, records signed result
evidence, and skips a command only when a previous successful result is still
safe to reuse.

The project is in early development. The design is in [the technical
specification](docs/spec/tm-test-memoization-technical-specification.md); open
design questions from review are tracked in [implementation
notes](docs/implementation-notes.md).

## Build

Requirements: a C11 compiler and GNU Make on Linux.

```sh
make          # build build/tm
make test     # run command-line integration checks
make clean    # remove generated build files
```

Build requires a C11 compiler, GNU Make, and OpenSSL development
headers/libraries (EVP, `-lcrypto`).

`tm --version` reports `tm 0.1`. Signed result sidecars use schema version 3
and carry the producing `tm_version`; verification semantics remain version 2.

Local operators can create an Ed25519 producer key with
`tm key generate ~/.config/testmiser/producer.pem`. The private key is created
with mode `0600`; the command prints the matching key ID and base64 public key
for operator-managed trust policy. Keep private keys outside the repository.
`--signing-key FILE` publishes signed evidence only for eligible successful
runs inside the enforced profile backend. A protected key, matching
profile/key approval, deterministic public profile, and `TM_RUNTIME_ROOT` are
required. If the backend cannot enforce isolation, the command is not launched
with signing enabled, so test code cannot access the signer through a native
fallback.

The current executable is a transparent command wrapper with a Linux x86-64
`ptrace` observer prototype, OpenSSL-backed SHA-256/Ed25519 primitives,
command/context/verification fingerprint helpers, bounded JSON/JCS support,
schema-v3 signed records (v2 semantics) with optional output manifests, and
operator-managed trust policy. The observer tracks a conservative subset of
file descriptor provenance; unsupported syscalls and metadata observations
prevent reuse.

Repeatable `--input PATH` declarations capture stable regular-file contents
or, for a directory, sorted immediate-child names and kinds. Directories do
not recursively attest file contents, so those files need their own
declarations. Absent paths are tracked as explicit nonexistence states and
rechecked after execution; creating one during the command is reported as a
change. Special files are rejected without blocking.

Repeatable `--output PATH` declarations accept canonical, non-overlapping
repository-relative roots; malformed declarations fail before launch. The
controlled backend stages declared roots and safely captures/restores their
contents after success. The observer permits descriptor writes, shared
writable mappings, and modeled directory/file metadata mutations only within
declared output roots; rename/link/symlink and other unsupported mutation
patterns remain ineligible. Output-bearing CLI lookup restores declared
outputs before reporting a trusted hit. A missing, unsafe, or changed input
declaration is reported by `--explain`, but the command still runs. Relative
symlink targets are captured only when they contain no absolute path or `..`
traversal. Explicit input checks are not complete dependency observation.

`--root DIR` selects the repository root; otherwise `tm` uses the nearest
ancestor containing `.git`, then the current directory. Approved profile
constants are delivered as the child environment, with inherited host
variables removed. `--profile FILE --trust-policy FILE` validates the closed
profile format and requires operator approval for its repository ID and
digest. Explicit `--input` and `--output` paths must be covered by the
profile's corresponding permitted roots.

With a deterministic public profile and an enforceable Bubblewrap view, `tm`
checks trusted repository and per-user shared-store records against a stable
profile snapshot. On an output-bearing hit, it restores declared outputs
before reporting success. Eligible successful output-free and supported
output-bearing runs can be signed with `--signing-key`; records and verified
output blobs are copied to the per-user store for other local worktrees.
Declared output roots are staged as writable sandbox mounts and safely
captured/restored after successful runs. The observer permits only modeled
mutations inside declared outputs; unsupported mutation patterns remain
ineligible. Committed sidecars and the optional shared-filesystem store
transport records and blobs; remote object-store adapters and cross-provider
acceptance remain unimplemented. `tm profile digest FILE` prints the
profile's repository ID and canonical v1 digest. `tm validate` accepts the
`--root`, `--trust-policy`, and `--require-trust` options to check stored
record structure and trust status without running tests.

`tm runtime digest ROOTFS_DIR` computes the normalized runtime-tree identity.
`tm runtime verify PROFILE TRUST_POLICY ROOTFS_DIR` checks that an
operator-approved profile names that tree; this provisioning check does not
itself enforce sandbox execution. When `TM_RUNTIME_ROOT` is set with
`--profile`, `tm` rejects a tree whose digest differs from the approved profile
before launching the command, then probes the Bubblewrap profile view. Runtime
trees must be root-owned and have all write bits clear. Bubblewrap must be a
root-owned, regular, non-set-ID file without group/world write access, in
similarly protected directories. A passing probe runs with a read-only
runtime, an empty workspace populated only with approved input-root snapshots,
hidden writable `.tm` metadata, empty scratch roots, a cleared environment,
and network isolation. Snapshots compare source-node identity, metadata, file
hashes, and symlink targets across copying, then mount by pinned descriptor.
The ptrace observer follows sandbox descendants and reports eligibility.
Output capture/restoration is implemented for supported declared outputs;
broader observation and cross-host context equivalence remain incomplete. The
portable acceptance script requires working Bubblewrap user/network namespaces
and ptrace. The tested development host cannot create the required network
namespace, so signed portable acceptance must pass on a compatible isolated
runner before beta readiness.

Set `TM_SHARED_STORE` to an existing absolute directory on storage shared by
participating machines to exchange signed records and output blobs. The root
must be owned by the invoking user and not be group/world-writable; all clients
must use the same numeric UID because `tm` creates private `0700` store
directories. On filesystems with coherent `flock`, clients serialize
equivalent cold misses and recheck the store after waiting. By default,
`tm` uses available coordination and falls back to per-user locking if the
shared lock is unavailable, so duplicate work is possible. Set
`TM_COORDINATION_MODE=strict` to require a configured shared store and refuse
to launch unless the shared execution slot is acquired. Strict mode currently
uses filesystem `flock`; it does not provide lease fencing or partition
safety. Mount availability, coherent locking, durability, and access control
remain operator responsibilities. Never expose producer signing keys to
untrusted test jobs.

For unprofiled/native commands, `tm` removes its control variables
`TM_SHARED_STORE`, `TM_RUNTIME_ROOT`, `TM_COORDINATION_MODE`, and `TM_FORCE`
from the child environment while preserving ordinary application variables.
Approved-profile commands receive only the profile's declared environment.

## Intended usage

`tm clean --root DIR --records` removes regular `.tm.json` records under that
repository's `.tm/results` tree, including tracked records. It preserves trust
policy, signing material, content-addressed blobs, and local
attempt/quarantine state. `tm clean` without `--records` is currently a no-op
because rebuildable indexes and staged downloads are not yet implemented.

Local failed-attempt state is shared across worktrees in the user's TestMiser
cache directory. An operator can explicitly resolve a quarantined fingerprint
or all blocks for one command/context with:

```text
tm attempt resolve --repository-id ID --command-fingerprint SHA256 \
  --profile-digest SHA256 --context-digest SHA256 \
  (--fingerprint SHA256 | --all)
```

`--all` clears every local attempt marker only within that exact scope.

The wrapper accepts a command after `--` and preserves its argument boundaries:

```sh
tm --root . --input tests/fixtures/risk.json -- pytest tests/test_risk.py
tm -- go test ./pkg/risk
tm --force -- ./build/unit_tests
TM_FORCE=1 tm -- ./build/unit_tests
```

Native observer runs always execute the command. An approved deterministic
public profile can reuse a trusted matching sidecar when its pinned inputs,
controlled context, and required output artifacts still verify. `--force` and
the exact value `TM_FORCE=1` express an explicit rerun request; other
`TM_FORCE` values do not enable force mode. Successful eligible runs can
publish signed results. Local failures block the matching fingerprint; a
forced failure contradicting an existing trusted result quarantines it until
explicit operator resolution. Uncertain or invalid state causes the command
to run.

## Repository layout

```text
include/tm/     public and internal C interfaces
src/            CLI and Linux syscall-observer prototype
tests/          unit, CLI, and portable-reuse acceptance checks
docs/spec/      technical design specification
docs/           implementation review notes
```

## Development status

The implementation is not yet beta-ready. Run `make test` for the CLI and
unit suite. This repository's CI runs that suite directly; it does not wrap
`make test` in `tm`. Evidence-only changes are strictly validated with
`tm validate --require-trust`, while mixed/source changes run the suite and
validate changed evidence.

An application CI job can reuse committed evidence only when it invokes the
same command through `tm` with a matching approved profile, runtime, and
public trust policy. See the [CI integration runbook](docs/CI-INTEGRATION.md)
for rollout steps with local worktrees and GitLab runners, and the [portable
acceptance test](tests/README.md) for the producer/consumer test setup.

The current development host cannot complete Bubblewrap network namespace
setup, and cross-provider portability has not been demonstrated. CI also runs
GCC's `-fanalyzer` for code changes. See [AGENTS.md](AGENTS.md) for contributor
guidance.
