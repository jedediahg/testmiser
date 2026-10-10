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

The current executable is a transparent process wrapper with a Linux x86-64 `ptrace` observer prototype, OpenSSL-backed SHA-256/Ed25519 primitives, command and verification fingerprints, bounded JSON/JCS support, signed output-free v2 records, and operator-managed trust policy. `tm validate [--root DIR] [--trust-policy FILE] [--require-trust]` checks stored record structure and reports trust status without running tests. `--profile FILE --trust-policy FILE` validates the closed profile-v1 format and requires operator approval for its repository ID and canonical digest. An approved profile still runs uncached: backend enforcement, complete dependency/input validation, output restoration, lookup, and skips are not implemented.

## Intended usage

Once implemented, the wrapper is intended to accept a command after `--`:

```sh
tm -- pytest tests/test_risk.py
tm -- go test ./pkg/risk
tm --force -- ./build/unit_tests
```

The target behavior is to observe dependencies and record a result only after a normal successful exit. A later run may skip only when command identity, repository inputs, execution environment, and trusted provenance still match. Uncertain or invalid state must cause the command to run.

## Repository layout

```text
include/tm/     public and internal C interfaces
src/            CLI and Linux syscall-observer prototype
tests/          command-line integration checks and future tests
docs/spec/      technical design specification
docs/           implementation review notes
```

## Development status

The MVP target is Linux and C. It is intended to remain test-framework independent and to use SHA-256 plus deterministic JSON sidecars. Sidecars and `.tm` state must never become test inputs or trigger broad test runs. See [AGENTS.md](AGENTS.md) for contributor guidance. The initial shell-based CLI checks run with `make test`; no CI pipeline is configured yet.
