# Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including exit propagation and a short-lived descendant. With ptrace permission it also checks network and mutation rejection. Unit checks cover SHA-256, Ed25519 attestation vectors/tamper rejection, command identity, and the v2 verification-fingerprint vector plus input ordering and path validation. Run all checks with `make test`; OpenSSL EVP development files are required. When ptrace is unavailable, the CLI suite checks the uncached fallback. Add sidecar validation and trust-policy cases as those modules land.
