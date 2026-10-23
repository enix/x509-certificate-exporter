# Architecture and maintainability

The current layering is worth preserving: format parsers produce a neutral `cert.Bundle`, sources own discovery, and the registry owns Prometheus exposition. The most valuable work is to strengthen contracts at those boundaries, not to replace the application wholesale. Recommendations below are justified by observed defects or explicit code paths; they are separate from the confirmed bug list.

## A1 — P1 — Model owned object reconciliation explicitly

References: [pkg/cert/cert.go:60](../../../pkg/cert/cert.go#L60), [pkg/source/k8s/k8s.go:1057](../../../pkg/source/k8s/k8s.go#L1057), [pkg/registry/registry.go:269](../../../pkg/registry/registry.go#L269).

Several defects share one cause: state is split between flattened string keys, per-source tracking sets and registry bundles, with no atomic object-replacement operation. Prefix deletion, removed-key retention, namespace publication races and cross-source overwrite are B02/B03/B05/B08.

Introduce typed identities for source owner, resource object and payload key. Give reconciliation an explicit contract: replace this owner's complete observation of this object, remove its previous refs, and publish only if the selection generation is still current. Preserve public metric deduplication separately; merely adding source names to internal keys without updating collision behavior can create duplicate public series.

The CA-bundle implementation already reconciles per-object emitted sets. Reuse that contract, with resource-specific adapters, rather than forcing unrelated discovery mechanisms into one large abstraction. Record the policy for partial LIST failures and parse failures: retain last-good data or withdraw it, and how users can distinguish the two.

## A2 — P2 — Extract application composition from main

Reference: [cmd/x509-certificate-exporter/main.go:72](../../../cmd/x509-certificate-exporter/main.go#L72).

The entrypoint spans 868 lines and combines CLI parsing, config fallback, defaults, logging, metrics, passphrase loading, API-client construction, source wiring, readiness, HTTP/TLS listeners and shutdown. Its baseline package coverage is zero. B19/B20 survived otherwise substantial parser/config tests because they occur between those units.

Keep main responsible for process entry/exit. Move validated configuration normalization and application construction into a small internal package with injected file/client/listener dependencies. Share passphrase-option translation only where behavior is actually the same. Return construction errors before starting background work, and expose enough assembled state to test each supported configuration without a real cluster.

## A3 — P2 — Unify the duplicated LIST/WATCH lifecycle

References: [pkg/source/k8s/k8s.go:444](../../../pkg/source/k8s/k8s.go#L444), [675](../../../pkg/source/k8s/k8s.go#L675), [pkg/source/k8s/metrics.go:138](../../../pkg/source/k8s/metrics.go#L138).

Secret and ConfigMap loops duplicate pagination, watch handling, resync, cancellation and backoff. A single notification channel is accidentally shared while transport counters describe an older implementation. Extract a narrowly scoped resource-loop helper with typed LIST/WATCH/process/identity adapters. Keep namespace filtering and password dependency reconciliation explicit rather than hiding them in callbacks with unclear ordering.

Define ownership and joining of goroutines for cancellation during initial synchronization as well as normal shutdown. The audit did not demonstrate a goroutine leak; this is a lifecycle contract to test. Treat watch reconnects, relists, first sync and cached informer resync as different events in instrumentation and naming.

## A4 — P2 — Avoid a full registry scan on every mutation

Reference: [pkg/registry/registry.go:330](../../../pkg/registry/registry.go#L330). Every Upsert/Delete calls `refreshSourceCounts`, which rescans all bundles and resets every known source's gauge. Inserting N distinct bundles therefore performs roughly N²/2 bundle visits before accounting for parsing or Kubernetes work. Concurrent refreshes also compute counts before taking the gauge-publication lock, so publication ordering deserves explicit treatment.

A single local sample inserting empty bundles measured:

| Bundles | Time |
| --- | --- |
| 1,000 | 29 ms |
| 2,000 | 103 ms |
| 4,000 | 408 ms |
| 8,000 | 1,363 ms |

These are illustrative, unoptimized measurements on this host, not a performance SLA or controlled benchmark suite. The code establishes the complexity; the sample confirms that registry bookkeeping alone is material.

Maintain per-owner counts while holding the bundle mutation lock, or derive counts once from the same scrape snapshot. Batch object replacement and namespace invalidation to avoid repeated full scans. Add size-scaling benchmarks with overlapping sources, replacements and mass deletion; measure before introducing certificate interning or other speculative optimizations.

## A5 — P2 — Define one resolution/cache contract for filesystem sources

References: [pkg/fileglob/fileglob.go:589](../../../pkg/fileglob/fileglob.go#L589), [pkg/source/file/file.go:215](../../../pkg/source/file/file.go#L215), [pkg/source/kubeconfig/kubeconfig.go:242](../../../pkg/source/kubeconfig/kubeconfig.go#L242).

The walker returns a display path, link metadata and a partly resolved read path; the cache assumes those identify unchanged contents. B06/B11 show the contract is insufficient. Define a resolved entry containing display identity, final read target, target metadata and resolution/scope status. Make target changes invalidate cached parses.

Replace delimiter-encoded bookkeeping (`path|kind|key|idx` in kubeconfig; `kind:location#key` elsewhere) with typed keys or stored refs. File paths and kubeconfig names are not generally forbidden from containing those delimiters. This is a robustness recommendation; the audit did not include a full user-facing delimiter reproduction.

Also separate diagnostic events from durable discovered bundles. File walk/read errors can publish synthetic refs not inserted in the parse cache, while disappearance cleanup only iterates that cache. The retention/cleanup policy for such refs is unclear and should be tested through error→recovery→disappearance. Define bounded reads and parsing budgets for local files; `io.ReadAll` currently has no application-level size limit. Prioritize the demonstrated JKS allocation amplification first.

## A6 — P2 — Make metric identity, errors and health explicit contracts

References: [pkg/registry/collector.go:183](../../../pkg/registry/collector.go#L183), [276](../../../pkg/registry/collector.go#L276), [internal/server/server.go:85](../../../internal/server/server.go#L85), [cmd/x509-certificate-exporter/main.go:193](../../../cmd/x509-certificate-exporter/main.go#L193).

Use a common identity/collision policy for certificates, CRLs and failed items. Validate exposed label names before descriptor creation. Collectors should expose any partial-exposition failure through a bounded counter/log, so HTTP 200 does not mean unnoticed metric loss. Decide whether scrape-driven collision counters are the intended semantic contract before changing them.

Keep first-sync completion distinct from current health and data freshness. Current readiness is intentionally a latch, and `source_up` is primarily a first-sync callback result; neither is a continuous health guarantee. A future health model could expose last successful observation, current transport failure and unresolved parse errors separately. This is a design improvement, not a claim that the existing latch contradicts its code contract. It would make alert rules such as H8 reflect persistent unreadability directly rather than infer it from event counters.

Document immutability/ownership of bundle slices, attributes and certificate pointers passed into the registry. Its snapshot is shallow. Public claims of concurrency safety need a clear caller contract about mutation after Upsert; the audit did not reproduce a race from production callers.

## A7 — P2 — Centralize effective Helm configuration and tighten override schemas

References: [chart/templates/configmap.yaml](../../../chart/templates/configmap.yaml), [chart/templates/deployment.yaml](../../../chart/templates/deployment.yaml), [chart/templates/daemonset.yaml](../../../chart/templates/daemonset.yaml), [chart/values.schema.json:221](../../../chart/values.schema.json#L221).

Normalize effective listeners/auth/probe settings and filesystem mount roots in small shared helpers. Deployment and DaemonSet duplicate security-sensitive plumbing, and ConfigMap scan paths are derived separately from mounts. H1–H5 and H10/H11 show concrete drift. Deduplicate mount roots without collapsing distinct scan patterns.

The per-DaemonSet schema currently validates only that an override is an object. Reuse definitions for chart-owned fields across global and override settings, while retaining permissiveness for actual Kubernetes pass-through fields. Keep generated schema/README outputs generated from their source annotations; do not patch only the generated files.

## A8 — P2 — Make build/release assertions evidence-based

References: [dagger/main.go:38](../../../dagger/main.go#L38), [dagger/test.go:16](../../../dagger/test.go#L16), [.github/workflows/test.yaml:26](../../../.github/workflows/test.yaml#L26), [.github/workflows/release.yaml:111](../../../.github/workflows/release.yaml#L111).

Expose coverage/JUnit as actual artifacts, check authored Dagger code in its own module, and make local and CI verification contracts visibly consistent. Test publishing configuration with custom image/chart names before release. Distinguish Go's minimum-language directive from the suggested toolchain, and verify with the same selected toolchain as CI.

Correct SLSA assurance claims unless the necessary builder isolation and verification are established. The current useful provenance/signature steps do not by themselves prove Level 3. [The delivery report](02-chart-and-delivery.md) records the workflow evidence and authoritative guidance. No claim is made about unseen remote protection settings or the validity of published signatures.

## A9 — P3 — Remove dead promises and reduce documentation duplication

References: [internal/config/config.go:81](../../../internal/config/config.go#L81), [89](../../../internal/config/config.go#L89), [128](../../../internal/config/config.go#L128), [pkg/source/kubeconfig/kubeconfig.go:246](../../../pkg/source/kubeconfig/kubeconfig.go#L246).

Resolve inert configuration fields such as `server.systemdSocket`, `log.timing` and source `workers`: implement a tested contract or deprecate/reject them explicitly. Avoid silently accepting knobs that operators believe affect behavior. Delete unused bookkeeping after its replacement is verified; examples include the kubeconfig decoder's unused index variable and contradictory cache comments.

Create one authoritative standalone YAML reference and generate change-prone metric/reason/alert/version tables where practical. Keep the migration guide focused on migration differences. The [documentation cleanup table](05-documentation-cleanup.md) gives concrete occurrences; it is more valuable to eliminate their shared source of drift than repeatedly edit duplicated prose.

## Suggested implementation sequence

1. Add focused regression cases and fix B01/H1, then certificate-loss/rotation issues B02–B06. Keep patches small enough to review independently.
2. Introduce owner/object reconciliation with compatibility tests; fix password/config wiring and partial-metric visibility.
3. Repair Helm combinations, add admission/monitoring tests and decide supported upgrade histories.
4. Extract composition/resource-loop helpers as needed by those fixes; address measured registry scaling.
5. Export verification artifacts, align CI and update documentation from the corrected contracts. Link each audit ID to its implementing issue/PR and record closure evidence.
