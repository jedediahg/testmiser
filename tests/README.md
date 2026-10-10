# Tests

`cli.sh` contains POSIX-shell integration checks for the wrapper, including
exit propagation and a short-lived descendant. With ptrace permission it also
checks network and mutation rejection. Unit checks cover SHA-256, Ed25519
vectors/tamper rejection, command and verification fingerprints, bounded
JSON/JCS behavior, signed output-free record creation/inspection/trust
verification, and protected trust-policy loading/authorization. Run all
checks with `make test`; OpenSSL EVP development files are required. When
ptrace is unavailable, the CLI suite checks the uncached fallback. Extend
result tests for policy-driven validation and output manifests.

`portable-reuse.sh` is an opt-in acceptance test for a compatible Linux host.
It signs an output-bearing run in a temporary producer clone, commits the
result sidecar, blobs, static probe, and input fixture, then clones that commit
with a separate empty per-user cache. The unchanged consumer must skip,
replace stale files under `build/reports`, and restore the signed output. After
changing `build/portable-input.txt`, it must execute and produce updated
output, then restore the original input and require reuse of its retained
record. A linked worktree with checked-in evidence removed must also skip from
the producer's per-user cache, exercising same-user agent worktrees. The test
repeats producer/consumer reuse, invalidation, and state reversion with
`TM_SHARED_STORE`, then launches two equivalent cold requests concurrently
and requires exactly one execution. Set `TM_ACCEPTANCE_SHARED_STORE` to an
existing absolute directory to test a mounted store; the script creates and
removes a unique private subdirectory there. By default it creates a private
temporary store. The gate also checks that `TM_COORDINATION_MODE=strict`
refuses to launch when the shared execution slot is unavailable.
For a common CI store, configure the GitHub repository variable and GitLab CI
variable with this name and mount the same protected directory on both runner
pools. Provision a deterministic public profile that permits
`build/portable-input.txt` and `build/portable-reuse-probe` as inputs and
`build/reports` as output, its matching protected trust policy, a matching
runtime, and an authorized producer key. Build the static probe and run:

```sh
make build/tm
make build/portable-reuse-probe
TM_ACCEPTANCE_PROFILE=/absolute/path/profile.json \
TM_ACCEPTANCE_TRUST_POLICY=/absolute/path/policy.json \
TM_ACCEPTANCE_RUNTIME_ROOT=/absolute/path/runtime \
TM_ACCEPTANCE_SIGNING_KEY=/absolute/path/producer.pem \
  tests/portable-reuse.sh
```

The script needs working Bubblewrap user/network namespaces and ptrace. It
fails if the producer is ineligible or the consumer executes instead of
reusing. GitHub Actions treats unavailable namespaces as a failure; set the
repository variable `TM_PORTABLE_ACCEPTANCE_RUNNER` to a runner label that can
create the required namespaces when the hosted runner cannot. GitLab runs the
same gate on a shell runner tagged `linux-bwrap`. Since these jobs install
packages with `sudo` and execute repository code, any self-hosted runner must
be isolated and disposable, without persistent credentials or shared writable
state. The GitLab worker also needs passwordless `sudo` and Bubblewrap
user/network namespace support. For local diagnosis only,
`TM_ALLOW_BACKEND_UNAVAILABLE=1` lets the helper warn and exit successfully;
never set it on an acceptance CI job. The private key is generated inside the
acceptance job and used only for the producer; the consumer receives only the
profile and public trust policy.
