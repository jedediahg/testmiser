# Repository Guidelines

## Project Structure & Module Organization

The design lives in `docs/spec/tm-test-memoization-technical-specification.md`. C sources are in `src/`, public interfaces in `include/tm/`, and CLI/unit checks in `tests/`. `docs/implementation-notes.md` records implementation decisions. Observer, digest, Ed25519, fingerprints, bounded JSON/JCS, signed output-free records, and trust-policy loading exist as library foundations; CLI policy integration, controlled execution, and cache skips are not implemented.

## Build, Test, and Development Commands

Run `make` to build `build/tm`, `make test` to run CLI integration checks, and `make clean` to remove generated output. The specification’s examples, such as `tm -- pytest tests/test_risk.py`, describe commands the utility can wrap, not tests for this repository.

## Coding Style & Naming Conventions

The target implementation is C and Linux-first, using OpenSSL EVP for SHA-256 and Ed25519. Build with C11, OpenSSL development headers/libraries, and the Makefile’s `-Wall -Wextra -Wpedantic -Werror` warnings. Use four spaces for indentation. Keep JSON sidecars deterministic. Store repository-controlled paths relative to the repository root, and do not persist user-specific absolute paths.

## Testing Guidelines

`tests/cli.sh` exercises help, argument preservation, child exit and signal status, missing commands, explain mode, option parsing, and descendant completion. With ptrace permission it also checks network and mutation rejection. It uses POSIX shell and system utilities. There is no coverage target. Add tests for successful reuse, input invalidation, and rerunning after a failed command when the cache is implemented.

## Commit & Pull Request Guidelines

The available Git history contains only `Initial spec commit`, so no commit subject convention can be inferred. Use concise, action-oriented commit subjects. Pull requests should describe the behavior changed, link relevant issues or discussion, and report the checks run and their results. Include screenshots only when they clarify a user-visible change.

## Specification & Configuration

Use the technical specification as the current design reference. Update it when implementation decisions change its requirements. Treat external network state as non-cacheable unless a future design explicitly establishes a safe way to track it.
