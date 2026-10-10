# Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including exit propagation and a short-lived descendant. With ptrace permission it also checks network and mutation rejection. `digest.c` verifies SHA-256 against standard empty-string and `abc` vectors and hashes a regular file. Run all checks with `make test`; OpenSSL EVP development files are required. When ptrace is unavailable, the CLI suite checks the uncached fallback. Add input invalidation, sidecar validation, and trust-failure cases when those modules exist.
