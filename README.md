<!-- markdownlint-disable-next-line MD041 -->
<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.webp">
      <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo.webp">
      <img alt="X.509 Certificate Exporter" title="X.509 Certificate Exporter" src="docs/assets/logo.webp">
    </picture>
</p>

<div align="center">

[![GitHub Release][release-img]][release] [![Cosign signed][cosign-img]][cosign] [![SLSA Level 3][slsa-img]][slsa] [![OpenSSF Scorecard][ossf-img]][ossf] [![Made at ENIX][enix-img]][enix]<br/>
[![Artifact Hub][artifacthub-img]][artifacthub]

[release]: https://github.com/enix/x509-certificate-exporter/releases/latest
[release-img]: https://img.shields.io/github/v/release/enix/x509-certificate-exporter?sort=semver&display_name=tag&style=flat&logo=github&label=Release&color=3a6ed7
[cosign]: https://docs.sigstore.dev
[cosign-img]: https://img.shields.io/badge/Sigstore-cosign_signed-chartreuse
[slsa]: https://slsa.dev/spec/v1.0/levels
[slsa-img]: https://img.shields.io/badge/SLSA-level%203-chartreuse
[ossf]: https://securityscorecards.dev/viewer/?uri=github.com/enix/x509-certificate-exporter
[ossf-img]: https://img.shields.io/ossf-scorecard/github.com/enix/x509-certificate-exporter?style=flat&label=OSSF%20Scorecard
[enix]: https://enix.io
[enix-img]: https://img.shields.io/badge/Banana--grade-ENIX-3a6ed7?logo=gamebanana
[artifacthub]: https://artifacthub.io/packages/helm/enix/x509-certificate-exporter
[artifacthub-img]: https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/x509-certificate-exporter

</div>

A Prometheus exporter for X.509 certificates, built **for Kubernetes first**.
It watches your cluster's TLS material as native Kubernetes resources —
Secrets, ConfigMaps, kubeconfigs, on-disk PKI on the nodes — and turns
expirations into actionable Prometheus series. Designed to run inside the
cluster it observes, but equally happy as a standalone binary.

---

## 🔍️ What it watches

- **TLS Secrets** of any type — `kubernetes.io/tls`, opaque PEM bundles,
  full chains — across all namespaces or a curated subset.
- **ConfigMaps** holding PEM material (`ca.crt`, custom keys).
- **PKCS#12** keystores and truststores, with passphrase pulled from a
  sibling key in the same Secret, an external file, a cross-namespace
  Secret reference, or none (`tryEmptyPassphrase`).
- **Kubeconfigs** with embedded base64 certificates or PEM file references —
  every `cluster` and `user` block exposed as its own series.
- **Files on disk** — glob patterns (`*`, `**`, `?`), atomic symlink swaps
  detected on the next poll (certbot renewals, kubelet projected `..data/`
  mounts), and dual deployment: inside the exporter pod **or** as a
  node-local DaemonSet for cluster PKI (kubelet, etcd, kube-apiserver).
- **PEM chains** — every certificate in a multi-cert bundle becomes its own
  series, so intermediate CAs and trust roots appear alongside leaf certs
  with no extra configuration.

## 📖 Documentation

| Where to go | What you'll find |
| --- | --- |
| 🚀 [**Install on Kubernetes**](./chart) | Helm chart values, secretTypes / PKCS#12 wiring, hostPath PKI DaemonSets |
| 📊 [**Metrics**](./docs/metrics.md) | Per-cert / per-source / health series, label schema, PromQL examples |
| 🛡️ [**Hardening**](./docs/hardening.md) | Supply-chain verification, SBOM queries, immutable-digest pinning |
| ❓ [**FAQ**](./docs/faq.md) | Memory sizing, cardinality control, HA, non-Kubernetes use |
| 🏗️ [**Contributing**](./CONTRIBUTING.md) | Dev loop with Tilt + k3d + Dagger, conventions, release flow |

> [!WARNING]
> **Upgrading from version 3?** Start with the
> [v3 → v4 migration guide](./docs/migration-v3-to-v4.md) — chart distribution
> moved to OCI on `quay.io`, the Alpine image variant is retired, and a few
> values keys changed shape.

## ⚙️ Under the hood

- **100% Go.** A few thousand lines, no CGO, no plugins — auditable end
  to end in an afternoon.

- **Performance-aware.** Parsed certificates are cached so repeat scrapes
  don't re-decode the same PEM blocks. On Kubernetes, the exporter wires
  shared **informers** + watch streams instead of polling `kube-apiserver`,
  with watch traffic that scales with churn, not with scrape rate.

- **Helm-first delivery.** A first-party [Helm chart](./chart) covers
  Deployments, DaemonSets, RBAC, ServiceMonitor, PrometheusRule, and a
  Grafana dashboard. Published as an OCI artifact.

- **Cross-platform binaries.** Each release ships statically-linked
  binaries for Linux, macOS, Windows, FreeBSD, OpenBSD, NetBSD, Illumos
  and Solaris across `amd64`, `arm64`, `armv7` and `riscv64`. Drop one on
  a legacy box, run it under systemd or Windows Services — the exporter
  has no daemon dependencies and reads files straight from disk.

- **Plays with any Prometheus-compatible collector.** The `/metrics`
  endpoint speaks the canonical OpenMetrics text format and supports
  TLS + BasicAuth via `prometheus/exporter-toolkit` (`--web.config.file`),
  so **mTLS** scrapes work out of the box. Tested against / known to
  work with: Prometheus, Grafana Agent / Alloy, VictoriaMetrics (`vmagent`),
  Thanos, Cortex / Grafana Mimir, OpenTelemetry Collector, Datadog Agent,
  Elastic Metricbeat, Splunk OTel Collector, Sysdig, New Relic, Dynatrace,
  Sumo Logic, Wavefront, Telegraf.

- **Open, signed, attested supply chain.** Every release is built by a
  single open-source GitHub Actions
  [pipeline](.github/workflows/release.yaml). Container images, Helm
  chart, and binaries are signed with **sigstore/cosign** keyless (no
  maintainer-held private key); binaries carry a **SLSA Level 3** in-toto
  provenance attestation; images carry a CycloneDX SBOM as a cosign
  attestation. Verification recipes live in the
  [hardening guide](./docs/hardening.md).

- **Defensive by intent.** The project tracks the
  [OpenSSF Scorecard][ossf] and converges on its recommendations —
  pinned dependencies, branch protection, signed commits, dependency
  review, SBOM, no force-pushes. Finding a defensive practice we don't
  follow yet? Open an issue.

## 🔁 How it fits in your DevOps loop

End-to-end, the exporter is one piece in a four-stage pipeline that you
likely already run for every other workload. No new tooling to learn, no
parallel control plane — just one more metric family in the observability
stack you already have.

1. **Deploy.** A single `helm install` drops a Deployment (in-cluster
   Secrets / ConfigMaps) and, optionally, DaemonSets (on-node PKI like
   kubelet, etcd, kube-apiserver). No CRDs of its own, no operator.
   Outside Kubernetes, the same binary runs as a systemd unit pointed at
   files on disk.

2. **Scrape.** The chart creates a `ServiceMonitor` (or `PodMonitor`) so
   a [prometheus-operator][po]-managed Prometheus picks the exporter up
   automatically. On clusters without the operator, the standard
   `prometheus.io/scrape` Pod annotations work just as well.

3. **Alert.** A `PrometheusRule` ships with four batteries-included
   alerts: read-errors canary (RBAC / parsing / missing files),
   per-certificate error, renewal warning (28 days out by default),
   expiration critical (14 days out). Alertmanager routes them like any
   other rule — Slack, PagerDuty, email, webhooks — and the thresholds
   plus individual alerts are tunable per install.

4. **Visualize.** A ready-to-import [Grafana dashboard][dash] lists every
   certificate the exporter sees, sorted by time remaining, sliced by
   namespace, source, and issuer. Deploy it via the chart as a
   sidecar-discovered ConfigMap (`grafana.createDashboard: true`) or
   import the JSON by hand.

The net effect: a certificate renewal is no longer an outage waiting to
happen. The on-call rotation that already triages your service alerts
also catches expiring certs — 28 days ahead for the leaf, 14 for the
critical ones — and the team that owns the workload owns the renewal,
instead of a platform team scrambling the day a `cert-manager` annotation
turns out to have been misspelled six months ago.

[po]: https://github.com/prometheus-operator/prometheus-operator
[dash]: https://grafana.com/grafana/dashboards/13922
