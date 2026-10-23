# Project audit — 2026-10-23

**Audit performed by GPT-6 Astra (effort Ultra).**

**Reviewed revision:** `294f721b74990447a72ca9fd216e2674ec217d04`

The project has a useful modular structure and a substantial unit-test foundation, but several supported configurations can silently lose or retain incorrect monitoring data. The highest priorities are the JKS allocation amplification, the proxy upstream access-control bypass, Kubernetes reconciliation defects and missed symlink-target rotation. Passing existing tests does not cover these cases.

This audit delivers findings and a remediation plan. Production code, chart sources and existing tests were left unchanged. All six reports are in English; documentation/comment cleanup is deliberately tabular.

## Reports

| File | Contents |
| --- | --- |
| [01-runtime-and-correctness.md](01-runtime-and-correctness.md) | B01–B22: parsing, discovery, synchronization, metric identity, configuration and diagnostics. Each finding states evidence, trigger/impact and remedy/test. |
| [02-chart-and-delivery.md](02-chart-and-delivery.md) | H1–H13: Helm, monitoring, probes, upgrade/publishing combinations; D1–D4: delivery/verification risks. |
| [03-test-coverage.md](03-test-coverage.md) | Executed checks, measured package coverage, missing scenarios, CI gaps and explicit verification limits. |
| [04-architecture.md](04-architecture.md) | A1–A9: targeted structural changes and implementation order, tied to observed defects. |
| [05-documentation-cleanup.md](05-documentation-cleanup.md) | Concise file/line tables of outdated operational instructions, comments and developer guidance. |

The finding counts are organizational, not a count of independent vulnerabilities: some documentation, testing and architecture entries refer to the same underlying defect.

## Fix first

| Priority | Finding | Evidence | Consequence |
| --- | --- | --- | --- |
| P1 | B01 — JKS input-controlled allocations | Bounded local reproduction | 38 input bytes triggered a 16 MiB allocation before integrity verification; larger declared lengths create denial-of-service risk for watched JKS inputs. |
| P1 | H1 — proxy upstream binds all interfaces | Rendered manifests + listener code | Peers that can reach the Pod/node upstream port can bypass kube-rbac-proxy. No live-cluster exploit was performed. |
| P1 | B02 — object deletion matches name prefixes | Secret and ConfigMap reproductions | Deleting `foo` also removes `foobar` from monitoring. |
| P1 | B03 — removed data keys remain registered | Update + relist reproductions | Deleted certificate payloads remain visible indefinitely while the parent object exists. |
| P1 | B04 — namespace invalidation is not broadcast | Both watch loops exercised | One resource kind can disappear until its next resync when a source watches Secrets and ConfigMaps. |
| P1 | B06 — symlink target rotation is not detected | Real filesystem/polling reproduction | A stable outer link leaves the default cache serving an old certificate after its target changes. |

The next batch should address B05/B08 ownership and publication ordering, B19/B20 configuration wiring, H2–H5 deployment defaults, and B09's silent partial metric loss. Use the domain reports for conditions and fixes rather than treating every item as equally urgent.

## Verification outcome

- **Existing Go tests passed with the race detector.** Measured statement coverage: **63.9%** for the main module, **68.6%** excluding development tooling. The entrypoint has **0.0%** baseline package coverage; the Kubernetes source has **59.0%**.
- **Go vet passed.** Three five-second fuzz smoke runs passed (PEM, DER and fileglob). E2E code compiled; E2E scenarios were not run.
- **All 77 existing Helm checks passed:** 10 documented values examples, 25 positive fixtures and 42 negative fixtures. Additional renders exposed invalid supported combinations that those checks do not cover.
- **Additional audit probes demonstrated runtime failures**, including real application password wiring, Java/OpenSSL interoperability, logical event-ordering races and partial HTTP-200 metric loss. Temporary test files were removed from source directories after the checks.
- **Full lint/deployment/security scans remain unverified.** Local golangci-lint rejected the project's newer target toolchain before analysis. Dagger/E2E tooling was unavailable on the active PATH. See [the complete evidence and limits](03-test-coverage.md).

Local Go was 1.26.8 with `GOTOOLCHAIN=local`; the repository declares a 1.27.3 toolchain. Local Helm was 4.2.2 versus the pipeline's pinned 4.3.1. Results are tied to the reviewed source and these environments, not represented as a full pinned-pipeline run.

## Priorities and evidence

| Level | Meaning |
| --- | --- |
| P1 | Urgent: meaningful access-control/resource-exhaustion risk or silent monitoring loss under a supported scenario. Fix before relying on the affected feature in production. |
| P2 | Material defect, validation/observability gap, or structural risk with a clear trigger and practical consequence. Plan a focused fix and regression test. |
| P3 | Lower-impact cleanup, documentation maintenance or conditional risk whose production failure was not established. |

**Reproduced** means a local executable assertion, parser invocation or render demonstrated the stated behavior. Fake Kubernetes clients/transports establish application behavior, not API-server admission or deployed network behavior. **Source inspection/semantic analysis** means the conclusion follows from the cited code or query, but the operational scenario was not executed. **Architecture recommendation** is proposed design work, not a separate demonstrated bug.

No P0 emergency or active compromise is asserted. H6 is deliberately a conditional migration-policy risk: prerelease comparisons were reproduced, but a failing historical upgrade was not established. Readiness is intentionally a first-sync latch; continuous health/freshness metrics are a design recommendation rather than an assumed existing guarantee.

## Remediation approach

1. Pair the six P1 findings with focused failing regression tests, then repair them in independently reviewable changes.
2. Strengthen object/source ownership and replacement semantics before extending source features. Test transitions and cancellation, including deterministic event interleavings.
3. Test effective application/Helm configurations across their boundaries: generated YAML, actual source builders, metric exposition, authentication, probes and upgrades.
4. Align CI with the intended checks, expose coverage/JUnit artifacts and verify with pinned toolchains. Add PromQL and independent producer-format fixtures.
5. Apply the documentation cleanup alongside corrected behavior; keep historical changelog entries historical. Track closure by audit ID with the implementing change and verification evidence.

## Scope

Reviewed parsers, fileglob, file/kubeconfig/Kubernetes/CA-bundle sources, registry, configuration/server/entrypoint, unit/fuzz/E2E test structure, Helm schema/templates/dashboard/alerts, Dagger, build/release workflows and operator/developer documentation. Existing local configuration credentials were not needed or inspected. No production cluster, remote repository settings, registry publication or release signing was changed. This is a broad source audit with targeted execution, not a guarantee that all defects or dependency vulnerabilities have been found.
