<!-- markdownlint-disable-next-line MD041 -->
<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.webp">
      <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo.webp">
      <img alt="X.509 Certificate Exporter" title="X.509 Certificate Exporter" src="docs/assets/logo.webp">
    </picture>
</p>

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/enix/x509-certificate-exporter?sort=semver&display_name=tag&style=flat&logo=github&label=Release&color=3a6ed7)](https://github.com/enix/x509-certificate-exporter/releases/latest) [![Cosign signed](https://img.shields.io/badge/cosign-signed-chartreuse)](https://docs.sigstore.dev/cosign/overview/) [![SLSA Level 3](https://img.shields.io/badge/SLSA-level%203-chartreuse)](https://slsa.dev/spec/v1.0/levels) [![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/enix/x509-certificate-exporter?style=flat&label=OSSF%20Scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/enix/x509-certificate-exporter) [![Made at ENIX](https://img.shields.io/badge/Banana--grade-ENIX-3a6ed7?logo=gamebanana)](https://enix.io)<br/>
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/x509-certificate-exporter)](https://artifacthub.io/packages/helm/enix/x509-certificate-exporter)

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
| [**Install on Kubernetes**](./chart) | Helm chart values, secretTypes / PKCS#12 wiring, hostPath PKI DaemonSets |
| [**Metrics**](./docs/metrics.md) | Per-cert / per-source / health series, label schema, PromQL examples |
| [**Hardening**](./docs/hardening.md) | Supply-chain verification, SBOM queries, immutable-digest pinning |
| [**FAQ**](./docs/faq.md) | Memory sizing, cardinality control, HA, non-Kubernetes use |
| [**Contributing**](./CONTRIBUTING.md) | Dev loop with Tilt + k3d + Dagger, conventions, release flow |

> [!WARNING]
> **Upgrading from version 3?** Start with the [v3 → v4 migration guide](./docs/migration-v3-to-v4.md) — chart distribution moved to OCI on `quay.io`, the Alpine image variant is retired, and a few values keys changed shape.

## 📊 Metrics

The exporter emits four metric families:

- **Per-certificate** — one series per certificate, dense label set
  (`subject_*`, `issuer_*`, `serial_number`, source-specific
  `secret_*` / `configmap_*` / `filepath`, optional surfaced Secret
  labels)
- **Per-source** — health, bundle count, and error breakdown for each
  configured input
- **Health & process** — `/metrics` scrape latency, panic counter,
  build info
- **Internal** — Kubernetes informer scope and queue-depth gauges, for
  debugging

Full reference with label schemas, gating conditions, reason codes and
PromQL examples: see [`docs/metrics.md`](./docs/metrics.md).

## ❔ FAQ

Common questions covered in [`docs/faq.md`](./docs/faq.md):

- Why expose `not_after` rather than a remaining duration?
- How do I detect that the exporter has stopped seeing my certs?
- Does the exporter read or store private keys?
- What's the memory footprint? How many certs can it handle?
- How do I keep label cardinality under control?
- Can I run multiple replicas?
- How do I monitor a non-Kubernetes host?

## 🏗️ Contributing

The project uses Tilt + k3d + Dagger for an interactive dev loop. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for environment setup, common
workflows, and troubleshooting.

Architectural notes for AI assistants live in [CLAUDE.md](./CLAUDE.md).
