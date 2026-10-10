# TestMiser

`tm` is a planned Linux-first C utility that memoizes successful verification commands. It aims to observe the files and execution context used by a command, record a deterministic fingerprint, and skip the command on later runs only when its previous successful result is still safe to reuse.

The project is in early development. The design is in [the technical specification](docs/spec/tm-test-memoization-technical-specification.md); open design questions from review are tracked in [implementation notes](docs/implementation-notes.md).

## Build

Requirements: a C11 compiler and GNU Make on Linux.

```sh
make          # build build/tm
make test     # run command-line integration checks
make clean    # remove generated build files
```

Build requires a C11 compiler, GNU Make, and OpenSSL development headers/libraries (EVP, `-lcrypto`).

`tm --version` reports `tm 0.1`. Signed result sidecars use schema version 3 and carry the producing `tm_version`; verification semantics remain version 2.

Local operators can create an Ed25519 producer key with `tm key generate ~/.config/testmiser/producer.pem`. The private key is created with mode `0600`; the command prints the matching key ID and base64 public key for operator-managed trust policy. Keep private keys outside the repository. `--signing-key FILE` publishes signed evidence only for eligible, successful runs with no declared inputs or outputs inside the enforced profile backend; a protected key, matching profile/key approval, deterministic public profile, and `TM_RUNTIME_ROOT` are required. If the backend cannot enforce isolation, the command is not launched with signing enabled, so test code cannot access the signer through a native fallback.

The current executable is a transparent command wrapper with a Linux x86-64 `ptrace` observer prototype, OpenSSL-backed SHA-256/Ed25519 primitives, command/context/verification fingerprint helpers, bounded JSON/JCS support, schema-v3 signed records (v2 semantics) with optional output manifests, and operator-managed trust policy. The observer tracks a conservative subset of file descriptor provenance; unsupported syscalls and metadata observations prevent reuse. Repeatable `--input PATH` declarations capture stable regular-file contents or, for a directory, sorted immediate-child names and kinds; directories do not recursively attest file contents, so those files need their own declarations. Absent paths are tracked as explicit nonexistence states and rechecked after execution; creating one during the command is reported as a change. Special files are rejected without blocking. Repeatable `--output PATH` declarations accept canonical, non-overlapping repository-relative roots; malformed declarations fail before launch. The controlled backend stages declared roots and safely captures/restores their contents after success. Output writes still make observer reports ineligible, so these manifests are not yet published or reused. A missing, unsafe, or changed input declaration is reported by `--explain`, but the command still runs. Relative symlink targets are captured only when they contain no absolute path or `..` traversal. Explicit input checks are not complete dependency observation.

`--root DIR` selects the repository root; otherwise `tm` uses the nearest ancestor containing `.git`, then the current directory. Approved profile constants are delivered as the child environment, with inherited host variables removed. `--profile FILE --trust-policy FILE` validates the closed profile format and requires operator approval for its repository ID and digest. Explicit `--input` and `--output` paths must be covered by the profile's corresponding permitted roots. With a deterministic public profile, no explicit declarations, and an enforceable Bubblewrap view, `tm` checks signed output-free records in the repository and skips only after trust validation and matching their inputs against a stable snapshot. Eligible successful output-free runs can be signed with `--signing-key`. Declared output roots are staged as writable sandbox mounts and safely captured/restored after successful runs. Output-bearing runs are not yet eligible for signed publication or lookup because the observer cannot yet distinguish declared output writes from other mutations. Shared local stores and remote stores are not searched yet. `tm profile digest FILE` prints the profile's repository ID and canonical v1 digest. `tm validate [--root DIR] [--trust-policy FILE] [--require-trust]` checks stored record structure and trust status without running tests.

`tm runtime digest ROOTFS_DIR` computes the normalized runtime-tree identity. `tm runtime verify PROFILE TRUST_POLICY ROOTFS_DIR` checks that an operator-approved profile names that tree; this provisioning check does not itself enforce sandbox execution. When `TM_RUNTIME_ROOT` is set with `--profile`, `tm` rejects a tree whose digest differs from the approved profile before launching the command, then probes the Bubblewrap profile view. The backend requires the runtime and Bubblewrap binary to be root-owned, regular, immutable files/trees; this prevents another unprivileged account from changing them after digesting. A passing probe runs with a read-only runtime, an empty workspace populated only with approved input-root snapshots, hidden writable `.tm` metadata, empty scratch roots, a cleared environment, and network isolation. Snapshots compare source-node identity, metadata, file hashes, and symlink targets across copying, then mount by pinned descriptor. The ptrace observer follows sandbox descendants and reports eligibility. Output capture/restoration and complete execution-context equivalence remain open; this host's Bubblewrap policy does not pass the trust preflight, so beta testing signed execution/reuse requires a compatible Linux host.

## Intended usage

`tm clean --root DIR --records` removes regular `.tm.json` records under that repository's `.tm/results` tree, including tracked records. It preserves trust policy, signing material, content-addressed blobs, and symlinked entries. `tm clean` without `--records` is currently a no-op because rebuildable indexes and staged downloads are not yet implemented.

The wrapper accepts a command after `--` and preserves its argument boundaries:

```sh
tm --root . --input tests/fixtures/risk.json -- pytest tests/test_risk.py
tm -- go test ./pkg/risk
tm --force -- ./build/unit_tests
TM_FORCE=1 tm -- ./build/unit_tests
```

Every invocation currently runs the command. `--force` and the exact value `TM_FORCE=1` express an explicit rerun request; other `TM_FORCE` values do not enable force mode. The target behavior is to record a result only after a normal successful exit and skip later only when command identity, complete repository inputs, controlled execution context, and trusted provenance still match. Uncertain or invalid state must cause the command to run.

## Repository layout

```text
include/tm/     public and internal C interfaces
src/            CLI and Linux syscall-observer prototype
tests/          command-line integration checks and future tests
docs/spec/      technical design specification
docs/           implementation review notes
```

## Development status

The MVP target is Linux and C. It is intended to remain test-framework independent and to use SHA-256 plus deterministic JSON sidecars. Sidecars and `.tm` state must never become test inputs or trigger broad test runs. Run `make test` for the CLI and unit suite. GitHub Actions and GitLab CI run the standard suite and GCC's `-fanalyzer` build. See [AGENTS.md](AGENTS.md) for contributor guidance.
