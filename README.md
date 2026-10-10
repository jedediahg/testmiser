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

The current executable is a transparent command wrapper with a Linux x86-64 `ptrace` observer prototype, OpenSSL-backed SHA-256/Ed25519 primitives, command/context/verification fingerprint helpers, bounded JSON/JCS support, signed output-free v2 records, and operator-managed trust policy. The observer tracks a conservative subset of file descriptor provenance; unsupported syscalls and metadata observations prevent reuse. Repeatable `--input PATH` declarations are captured as stable regular files below the repository root and rechecked after execution. A missing, unsafe, or changed declaration is reported by `--explain`, but the command still runs. This input check is not complete dependency observation and does not enable caching.

`--root DIR` selects the repository root; otherwise `tm` uses the nearest ancestor containing `.git`, then the current directory. Approved profile constants are delivered as the child environment, with inherited host variables removed. `--profile FILE --trust-policy FILE` validates the closed profile format and requires operator approval for its repository ID and digest, but approved profiles still run uncached because runtime/backend enforcement is incomplete. `tm profile digest FILE` prints a profile's repository ID and canonical v1 digest. `tm validate [--root DIR] [--trust-policy FILE] [--require-trust]` checks stored record structure and trust status without running tests. The input API and `tm_result_verify_inputs_match` can recheck file contents, existence probes, directory membership, and symlink text against an open root; these helpers are not integrated with complete observation. Library APIs can atomically publish output-free signed records at the specified immutable path and search an exact fingerprint slot while checking trust and current declared inputs. Wrapped runs do not yet publish or look up records, output capture/restoration is unsupported, and every invocation still executes.

## Intended usage

The wrapper accepts a command after `--` and preserves its argument boundaries:

```sh
tm --root . --input tests/fixtures/risk.json -- pytest tests/test_risk.py
tm -- go test ./pkg/risk
tm --force -- ./build/unit_tests
```

Every invocation currently runs the command. The target behavior is to record a result only after a normal successful exit and skip later only when command identity, complete repository inputs, controlled execution context, and trusted provenance still match. Uncertain or invalid state must cause the command to run.

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
