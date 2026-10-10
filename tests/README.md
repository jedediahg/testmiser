# Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including exit propagation and a short-lived descendant. With ptrace permission it also checks network and mutation rejection. Unit checks cover SHA-256, Ed25519 vectors/tamper rejection, command and verification fingerprints, bounded JSON/JCS behavior, signed output-free record creation/inspection/trust verification, and protected trust-policy loading/authorization. Run all checks with `make test`; OpenSSL EVP development files are required. When ptrace is unavailable, the CLI suite checks the uncached fallback. Extend result tests for policy-driven validation and output manifests.

`portable-reuse.sh` is an opt-in acceptance test for a compatible Linux host. It signs an output-bearing run in a temporary producer clone, commits the result sidecar and blobs, then clones that commit with a separate empty per-user cache and requires a trusted skip plus restored output. Provision a deterministic public profile that permits `build/reports`, its matching protected trust policy, a matching runtime, and an authorized producer key, then run:

```sh
make build/tm
TM_ACCEPTANCE_PROFILE=/absolute/path/profile.json \
TM_ACCEPTANCE_TRUST_POLICY=/absolute/path/policy.json \
TM_ACCEPTANCE_RUNTIME_ROOT=/absolute/path/runtime \
TM_ACCEPTANCE_SIGNING_KEY=/absolute/path/producer.pem \
  tests/portable-reuse.sh
```

The script needs working Bubblewrap user/network namespaces and ptrace. It fails if the producer is ineligible or the consumer executes instead of reusing. The private key is used only in the producer invocation; the consumer receives only the profile and public trust policy.
