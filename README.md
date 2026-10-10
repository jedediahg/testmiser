# TestMiser

`tm` is a planned Linux-first C utility that memoizes successful verification commands. It aims to observe the files and execution context used by a command, record a deterministic fingerprint, and skip the command on later runs only when its previous successful result is still safe to reuse.

The project is at scaffold stage. The design is in [the technical specification](docs/spec/tm-test-memoization-technical-specification.md); command execution, dependency observation, fingerprints, sidecars, and cache reuse are not implemented yet. Open design questions from review are tracked in [implementation notes](docs/implementation-notes.md).

## Build

Requirements: a C11 compiler and GNU Make on Linux.

```sh
make          # build build/tm
make clean    # remove generated build files
```

The current executable is a CLI placeholder. It supports `--help`; other invocations report that the application is not implemented and exit with the reserved internal-error status (125).

## Intended usage

Once implemented, the wrapper is intended to accept a command after `--`:

```sh
tm -- pytest tests/test_risk.py
tm -- go test ./pkg/risk
tm --force -- ./build/unit_tests
```

The first run should observe dependencies and record a result only after a normal successful exit. A later run may skip only when command identity, repository inputs, execution environment, and trusted provenance still match. Uncertain or invalid state must cause the command to run.

## Repository layout

```text
include/tm/     public and internal C interfaces
src/            application source; observer and cache modules are future work
tests/          future unit and integration tests
docs/spec/      technical design specification
docs/           implementation review notes
```

## Development status

The MVP target is Linux and C. It is intended to remain test-framework independent and to use SHA-256 plus deterministic JSON sidecars. Sidecars and `.tm` state must never become test inputs or trigger broad test runs. See [AGENTS.md](AGENTS.md) for contributor guidance. No automated test suite or CI pipeline is configured yet.
