# Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including exit propagation and a short-lived descendant. With ptrace permission it also checks network and mutation rejection. Run it with `make test`. When ptrace is unavailable, it checks the uncached fallback. Add input invalidation, sidecar validation, and trust-failure cases when those modules exist.
