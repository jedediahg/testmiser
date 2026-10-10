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

The current executable is a transparent process wrapper with a Linux x86-64 `ptrace` observer prototype and OpenSSL-backed SHA-256 and Ed25519 primitives. It supports `--help`, `--force`, and `--explain`, launches the command directly without a shell, and returns the child's exit code (or 128 plus its terminating signal). With `--explain`, the prototype reports observed executable, file, and metadata path candidates plus rejection reasons. If tracing is unavailable, it runs the command uncached. Every invocation still runs: observer-to-digest integration, canonical records, trust policy, output restoration, and cache skips are not implemented.

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
