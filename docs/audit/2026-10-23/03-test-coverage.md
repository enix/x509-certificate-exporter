# Test coverage and verification gaps

The existing Go suite and all 77 checked Helm example/schema cases passed. This is useful baseline evidence, but the additional reproductions found failures in state transitions, configuration composition and generated deployment semantics. Statement coverage alone would not have predicted those failures.

## Executed checks

| Check | Result | Scope and qualification |
| --- | --- | --- |
| `go test -race -coverprofile=/tmp/x509-audit/coverage.out ./...` | Pass | Main Go module, including fuzz seed corpora; no Go data race reported. The first attempt could not open local httptest sockets in the sandbox; rerunning with that restriction removed passed. |
| `go vet ./...` | Pass | Main module; does not imply the full configured golangci-lint set passed. |
| `go test -tags=e2e -run '^$' ./test/e2e/...` | Pass | Compilation only: no E2E scenario executed. |
| PEM `FuzzParse`, 5 seconds, 2 workers | Pass | 240,238 executions; short smoke run, not comprehensive fuzzing. |
| DER `FuzzParse`, 5 seconds, 2 workers | Pass | 250,485 executions. |
| fileglob `FuzzCompile`, 5 seconds, 2 workers | Pass | 145,251 executions; primarily parser/matcher behavior, not stateful filesystem rotation. |
| Helm documented examples | 10/10 pass | `helm lint chart --values <example>` for `docs/examples/**/*.values.yaml`. |
| Helm positive schema fixtures | 25/25 pass | `helm lint` with each valid fixture. |
| Helm negative schema fixtures | 42/42 pass | `helm template` fails and contains the paired expected substrings. |
| Additional Kubernetes/config regression assertions | 10 tests demonstrate defects | 12 cases including Secret/ConfigMap variants; fake clients, actual watch-loop code and a deterministic blocking Sink. |
| Additional application-wiring assertions | 2 tests demonstrate defects | Four PKCS#12/JKS literal/file-password cases, plus missing explicit config; fake HTTP transport, real parsers and builder. |
| Additional core regression assertions | 8 tests demonstrate defects | Registry identity/labels, duplicate CRLs/errors, parser fallback, symlink rotation/containment and exclusion-prefix matching. |
| HTTP partial-collection check | Reproduced B09 | Gather error, HTTP 200, one emitted error series for two item errors. |
| Independent format checks | Reproduced B16/B17 | Java keytool non-ASCII JCEKS and OpenSSL trusted PEM; ordinary/direct-parser controls verified. |
| Bounded JKS allocation check | Reproduced B01 | 38-byte input allocated 16,787,208 bytes; no OOM attempted. |
| Registry scaling sample | Quadratic insertion cost observed | Empty bundles, no filesystem/parsing work; details in [architecture](04-architecture.md). |
| Local golangci-lint | Could not run | Version 2.11.3, built with Go 1.26.0, rejected the project's target toolchain 1.27.3 before analysis. This is an environment/tool mismatch, not a lint finding. |

Commands used `GOCACHE=/tmp/x509-audit/go-build`. Local Go was `go1.26.8-X:nodwarf5 linux/amd64`, with `GOTOOLCHAIN=local` and CGO enabled. The repository specifies `go 1.26.0` and `toolchain go1.27.3`; these results therefore do **not** replace CI verification with its selected toolchain. Local Helm was 4.2.2; the Dagger image pins 4.3.1. No dependency files or toolchain settings were changed.

The added assertions deliberately expect correct behavior and fail on the audited implementation. They were temporary audit probes, excluded from the baseline coverage measurement, and removed from source directories. Reproduction code/logs were left under `/tmp/x509-audit*` for this session; the durable findings record the inputs and outcomes without depending on those temporary paths.

## Measured statement coverage

This profile is the existing suite, with the standard per-package coverage scope; it is not cross-package integration coverage and contains no E2E coverage.

| Package | Covered / instrumented statements | Coverage | Assessment |
| --- | --- | --- | --- |
| `cmd/x509-certificate-exporter` | 0 / 358 | **0.0%** | Highest-value gap: CLI/config translation, source construction, auth/probe wiring and lifecycle. |
| `internal/config` | 116 / 135 | 85.9% | Good basic validation coverage; missing strict decoding, per-kind defaults and composition semantics. |
| `internal/log` | 23 / 23 | 100.0% | Small package; percentage does not establish secret-redaction behavior. |
| `internal/product` | 0 / 22 | 0.0% | No dedicated package tests; version formatting can be covered cheaply, but is less urgent than monitoring correctness. |
| `internal/server` | 69 / 91 | 75.8% | `BuildProbe` and stats rendering have no direct coverage in this profile. |
| `pkg/cert` | 7 / 7 | 100.0% | Small model helpers only. |
| `pkg/cert/der` | 21 / 22 | 95.5% | Preserve malformed-input and real-format coverage. |
| `pkg/cert/jks` | 128 / 152 | 84.2% | Missing independent Unicode fixtures and upstream allocation bounds. |
| `pkg/cert/pem` | 40 / 41 | 97.6% | High coverage misses real trusted-PEM interoperability. |
| `pkg/cert/pkcs12` | 38 / 43 | 88.4% | Package parsing tests bypass application password wiring. |
| `pkg/fileglob` | 302 / 335 | 90.1% | Missing multi-hop/path-component containment and neighboring-prefix exclusions. |
| `pkg/registry` | 442 / 490 | 90.2% | `emitItemErrors` has 0% direct coverage; ownership and CRL identity are untested. |
| `pkg/source/cabundle` | 160 / 218 | 73.4% | Missing configuration default integration and more failure/reconnect transitions. |
| `pkg/source/file` | 86 / 104 | 82.7% | Existing symlink test replaces the outer link, missing stable-link target rotation. |
| `pkg/source/k8s` | 334 / 566 | **59.0%** | Largest production behavior gap after main; reconciliation, watch errors and invalidation. |
| `pkg/source/kubeconfig` | 98 / 112 | 87.5% | Add transition/error recovery and identity edge cases rather than more copies of happy paths. |
| `dev/scenarios` | 227 / 276 | 82.2% | Fixture generation, not application integration. |
| `dev/scenarios/secauth`, `dev/seed`, `dev/seed-hostpath` | 0 / 277 | 0.0% | Primarily E2E tooling; do not prioritize simply to raise the total. |
| **Entire main module** | **2,091 / 3,272** | **63.9%** | Includes dev tooling. |
| **Production packages only** | **1,864 / 2,719** | **68.6%** | Excludes `dev/**`, includes the binary entrypoint. |

## T1 — P1 — Make reconciliation and transitions the first regression layer

Add tests alongside fixes for B02–B08 and B13–B15. Each source should satisfy a shared set of invariants:

- After an object update, its registry refs equal the current matching payloads, with removed keys absent.
- Deleting/rejecting one exact object or owner never removes another object or owner's data.
- Every relevant namespace/dependency change reaches every affected resource loop.
- Publication cannot resurrect data invalidated by a newer generation.
- A successful refresh replaces stale/error state, and a failed refresh has an explicit, testable retention policy.

Use deterministic fake watches and synchronization barriers, not sleeps, for concurrent event ordering. Keep `-race`, but B05 demonstrates why it cannot detect transaction-order bugs. Add transport-level tests for paginated continuation/resourceVersion, failure after an initial page, watch start failure, EOF/flapping, 410 expiry, cancellation during initial sync and namespace changes during LIST. Existing fake-client happy paths cannot establish all API semantics.

## T2 — P1 — Test effective configuration through the real application builders

The 868-line [main.go](../../../cmd/x509-certificate-exporter/main.go) has no baseline package coverage. The B19/B20 probes show that testing parsers and config structs separately leaves broken wiring undetected.

Extract injectable composition functions and test YAML/CLI → normalized configuration → constructed source. Include every source kind and format; literal/file/key/SecretRef password choices; unknown keys; no-op rules; explicit missing config; label normalization; listener/probe/TLS combinations; startup failure; and bounded graceful shutdown. These tests can use a fake HTTP transport and temporary files without a Kubernetes cluster.

## T3 — P1 — Add security and compatibility assertions across the deployed boundary

| Missing test | Why current checks miss it | Required outcome |
| --- | --- | --- |
| Direct exporter-port access in proxy mode | Proxy E2E only calls the proxy endpoint. | Other Pods cannot bypass RBAC through upstream or host-network listeners. |
| Operator-managed HTTPS scrape | Proxy E2E disables ServiceMonitor. | Authenticated scrape succeeds with verified serving certificates; defaults/requirements are coherent. |
| Independent exporter/proxy hangs | Render checks do not execute probes. | The failed container, not its healthy peer, is restarted. |
| Multiple extension filters / overlapping watch modes | Helm can render invalid Kubernetes specs successfully. | Unique volumes/mounts and accepted Pod specs. |
| Global and per-DaemonSet setting parity | Existing all-watch-modes fixture uses only the less-constrained override branch. | Both paths validate and produce equivalent scan behavior. |
| Upgrade fixtures from supported historical layouts | Clean-install E2E never runs migration history. | Stable and prerelease upgrades preserve availability and only recreate intended resources. |
| Generated exporter config loading | Helm validates its outer YAML, not the embedded runtime schema/semantics. | Every ConfigMap configuration passes the actual runtime loader and has the intended effective values. |

Validate against Kubernetes and Prometheus Operator schemas where possible, then reserve live E2E for behavior schema validation cannot establish. Do not treat `helm lint` as server-side admission validation.

## T4 — P2 — Test observability as a contract

Test Gather **and** the HTTP handler: `ContinueOnError` hid dropped metric identities behind HTTP 200 in B09. Require unique identities, explicit collection-error visibility and deterministic collision behavior across certificates, CRLs and malformed items. Add bounded label-cardinality checks for GET/LIST/WATCH instrumentation.

Add `promtool test rules` cases for isolated increments, unresolved startup errors, counter resets, expired certificates, missing sources and multi-source targets. The H8 event-window/hold-time defect cannot be caught by checking rendered alert strings. Evaluate dashboard queries on a minimal synthetic metric dataset, especially the exporter count in H7.

## T5 — P2 — Strengthen parser tests with independent producers and resource budgets

Keep the current unit/fuzz foundation. Supplement self-generated fixtures with keytool/OpenSSL-produced artifacts so producer and parser cannot share the same encoding mistake. Include Unicode passwords and trusted PEM auxiliary data.

For JCEKS fuzzing, most arbitrary mutations invalidate the digest before reaching the entry parser. Add a test-only fuzz path that recomputes the digest around mutated payloads, plus direct structural length/count cases. For JKS, fix B01 before increasing unrestricted fuzz time; enforce memory/time limits in an isolated process. A successful five-second no-panic smoke run is not evidence of bounded allocation or acceptable CPU use.

## T6 — P2 — Close CI and artifact gaps

| Reference | Gap | Action |
| --- | --- | --- |
| [.github/workflows/test.yaml:26](../../../.github/workflows/test.yaml#L26), [Taskfile.yml:213](../../../Taskfile.yml#L213) | Local aggregate runs Helm render and fuzz checks; CI has neither job and does not select render-only fixture changes. | Add explicit jobs/path filters and verify workflow changes trigger relevant checks. |
| [.github/workflows/release.yaml:108](../../../.github/workflows/release.yaml#L108) | Release explicitly skips E2E. | State the intended release gate and require evidence from a corresponding tested revision or a suitable release-specific deployment check. |
| [dagger/test.go:16](../../../dagger/test.go#L16) | JUnit/coverage files are written inside a container, but the function returns only stdout. | Expose artifacts, upload them in CI and review trends. Ratchet critical-path regressions before selecting an arbitrary global percentage. |
| [dagger/main.go:38](../../../dagger/main.go#L38), [dagger/go.mod](../../../dagger/go.mod) | The pipeline excludes `dagger/` from its source and ordinary root-module Go checks do not include the nested module. | Add separate checks for authored Dagger code; exclude generated bindings selectively. Unit-test pure render-validation helpers. |
| [.github/workflows/chart-readme.yaml:18](../../../.github/workflows/chart-readme.yaml#L18) | Generated-output-only edits and generator/version changes can bypass lockstep checks. | Include outputs and generator dependencies in paths; verify before publishing. |
| [dagger/test.go:33](../../../dagger/test.go#L33) | Documentation tests cover values files, not operational fenced snippets. | Move authoritative snippets into checked fixtures or extract and validate them. DOC-01/02/31 are concrete failures. |

## Checks not completed

- Full E2E cluster execution: `k3d`, `tilt` and `goreleaser` were unavailable on the active PATH. No existing development cluster was modified.
- Dagger pipeline execution and its exact pinned toolchains; the CLI was not available on the active PATH. Local equivalent checks are identified above.
- Full golangci-lint analysis, for the version mismatch stated above; no claim of a clean lint result.
- Fresh govulncheck/Trivy/gitleaks scans, dynamic JKS/PKCS#12 fuzz campaigns, server-side Kubernetes admission, promtool evaluation, cross-platform binaries and release signing/publishing.
- Actual repository/Environment protection settings, deployed RBAC/network policy, and validity of published attestations or signatures.

These limits do not invalidate the local reproductions, but they prevent interpreting this audit as a complete dependency-vulnerability, deployment or supply-chain certification.
