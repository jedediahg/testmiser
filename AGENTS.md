# Repository Guidelines

## Project Structure & Module Organization

The design lives in `docs/spec/tm-test-memoization-technical-specification.md`. C sources are in `src/`, public interfaces in `include/tm/`, and CLI/unit checks in `tests/`. `docs/implementation-notes.md` records implementation decisions. The CLI supports profile approval/environment setup, result validation, and uncached command execution. Library APIs cover signed output-free records, immutable publication, and trusted exact-fingerprint lookup; controlled profile execution and wrapper cache skips remain unimplemented.

## Build, Test, and Development Commands

Run `make` to build `build/tm`, `make test` to run CLI integration checks, and `make clean` to remove generated output. The specification’s examples, such as `tm -- pytest tests/test_risk.py`, describe commands the utility can wrap, not tests for this repository.

## Coding Style & Naming Conventions

The implementation is C and Linux-first, using OpenSSL EVP for SHA-256 and Ed25519. Build with C11, OpenSSL development headers/libraries, and the Makefile’s `-Wall -Wextra -Wpedantic -Werror` warnings. Use four spaces for indentation. Keep JSON sidecars deterministic. Store repository-controlled paths relative to the repository root, and do not persist user-specific absolute paths.

## Testing Guidelines

`tests/cli.sh` exercises help, argument preservation, child exit and signal status, missing commands, explain mode, option parsing, profile environment handling, and descendant completion. With ptrace permission it also checks network and mutation rejection. C tests cover fingerprints, signatures, trust policy, immutable record storage, exact-slot lookup, and changed-input misses. Run them all with `make test`; there is no coverage target. Add regression cases alongside the relevant unit or CLI test.

## Commit & Pull Request Guidelines

Recent commits use concise, imperative subjects such as `Capture and recheck declared input files` and `Publish portable signed result records`. Keep commits focused on one behavior. Pull requests should describe the behavior changed, link relevant issues or discussion, and report the checks run and their results. Include screenshots only when they clarify a user-visible change.

## Specification & Configuration

Use the technical specification as the current design reference. Update it when implementation decisions change its requirements. Treat external network state as non-cacheable unless a future design explicitly establishes a safe way to track it.
