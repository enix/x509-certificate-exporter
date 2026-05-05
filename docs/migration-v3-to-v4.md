# Migrating from v3 to v4

This guide walks through every breaking change between the v3 and v4
releases of the x509-certificate-exporter. The order below reflects
operational priority: recommended migration steps first, then chart
values shape, then metrics changes, then the rest.

---

## At a glance

| Area | v3 | v4 |
| --- | --- | --- |
| Helm chart distribution | `https://charts.enix.io` (classic) **and** `oci://quay.io/enix/charts/...` | Both still work — OCI recommended |
| Container image variants | `busybox` (default), `alpine`, `scratch` | `scratch` (default, minimal), `busybox` (alt, with shell) — Alpine retired |
| Image registries | Docker Hub, Quay | Docker Hub, Quay, GHCR |
| Exporter configuration | CLI flags | YAML config file (`--config`) |
| Helm `secretTypes` shape | `{type, key}` | `{type, key, format, pkcs12}` — `format` and `pkcs12` are optional |
| `x509_read_errors` metric | Single gauge per error | Removed — see metrics section |
| Per-source observability | None | `x509_source_up`, `x509_source_bundles`, `x509_source_errors_total{reason}` |

---

## 1. Helm chart distribution: OCI recommended

The classic Helm repository at `https://charts.enix.io` continues to
work and will keep receiving v4 releases — **no action required** if
you stay on it. That said, we recommend migrating to the OCI reference
at your own pace: OCI artifacts are the direction the Helm ecosystem is
heading, and the OCI publication is where cosign signatures, SBOM
attestations and provenance are attached.

> [!TIP]
> If your tooling already supports OCI (Helm 3.8+, Argo CD 2.6+,
> Flux source-controller 1.0+), the switch is a one-line change and
> unlocks the full supply-chain verification story documented in the
> [hardening guide](./hardening.md).

### Switching to OCI (recommended)

```sh
# Remove the legacy repo entry if you had it:
helm repo remove enix

helm install x509-certificate-exporter \
  oci://quay.io/enix/charts/x509-certificate-exporter \
  --version 4.0.0
```

Argo CD and Flux snippets:

```yaml
# Argo CD Application
spec:
  source:
    repoURL: quay.io/enix/charts
    chart: x509-certificate-exporter
    targetRevision: 4.0.0
    # NOTE: Argo CD treats OCI registries differently from HTTP repos —
    # `repoURL` must be the registry+namespace, without the `oci://`
    # scheme and without the chart name; `chart:` carries the chart name.
```

```yaml
# Flux HelmRelease
spec:
  chart:
    spec:
      chart: x509-certificate-exporter
      version: "4.0.0"
      sourceRef:
        kind: HelmRepository  # type: oci
        name: enix-charts
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: enix-charts
spec:
  type: oci
  url: oci://quay.io/enix/charts
```

### Staying on the classic repo (still supported)

```sh
helm repo add enix https://charts.enix.io
helm repo update
helm upgrade x509-certificate-exporter enix/x509-certificate-exporter \
  --version 4.0.0
```

No other change needed — the chart name and values shape are identical
across both distribution channels.

---

## 2. Container images: registries and variants

### Registries

In v3, `enix/x509-certificate-exporter` was the canonical reference
(implicitly Docker Hub). v4 publishes the same image to **three**
registries simultaneously, with byte-identical contents and signatures:

- `ghcr.io/enix/x509-certificate-exporter`
- `quay.io/enix/x509-certificate-exporter`
- `docker.io/enix/x509-certificate-exporter` (`enix/x509-certificate-exporter` short form)

Pick whichever fits your egress / pull-rate-limit policy. The chart's
default `image.registry` value is unchanged (`docker.io`), so no edit is
needed unless you want to switch.

### Variants

v3 published three variants via tag suffix (`-busybox`, `-alpine`,
`-scratch`). **v4 retires the Alpine variant** and **flips the
default**:

- `scratch` (default — empty `tagSuffix`). Distroless, no shell, no
  utilities. Smallest image; use `kubectl debug` to inspect a running
  pod when needed.
- `busybox` (set `image.tagSuffix: -busybox`). Ships `/bin/sh`,
  `wget`, `cat`, etc., for `kubectl exec` debugging.

> [!IMPORTANT]
> Plain upgrades that don't override `image.tagSuffix` will move from
> the busybox base to scratch. If your operational tooling assumes a
> shell in the running pod (init scripts, `kubectl exec`-based
> diagnostics, sidecars with shared `command:`/`args:`), set
> `image.tagSuffix: -busybox` to stay on the previous base.

If you currently set `image.tagSuffix: -alpine`, switch to one of:

- `image.tagSuffix: ""` → `scratch`. Distroless, smallest, no shell.
- `image.tagSuffix: -busybox` → closest replacement for Alpine:
  still has `/bin/sh`, `wget`, `cat`, etc.

---

## 3. Helm chart values

### `secretTypes` — extended shape

The simple `{type, key}` form keeps working unchanged: a v3 user with

```yaml
# values.yaml — v3 form, still valid in v4
secretTypes:
  - type: kubernetes.io/tls
    key: tls.crt
```

needs no edit. The shape was extended to support new sources:

```yaml
# values.yaml — v4 extended form
secretTypes:
  # Plain PEM in any Secret type:
  - type: kubernetes.io/tls
    key: tls.crt

  # Multiple keys via a regex pattern (alternative to a single `key`):
  - type: Opaque
    keyPatterns:
      - '^.*\.crt$'

  # PKCS#12 keystore with the passphrase in a sibling key:
  - type: Opaque
    key: keystore.p12
    format: pkcs12          # default is "pem"
    pkcs12:
      passphraseKey: keystore-passphrase  # sibling key in the same Secret
      # OR passphraseFile: /path/in/container
      # OR passphraseSecretRef: { namespace, name, key }
      # OR tryEmptyPassphrase: true
```

If you don't use PKCS#12 or regex matching, ignore this — the v3 form is
still parsed.

### Service: `headless: true` is the new default

`service.headless` flips from `false` (v3) to `true` (v4). The Service
is now created with `clusterIP: None` by default, which is the right
shape for a metrics endpoint: a Pod-level discovery anchor, not a
load-balanced application.

In practice, **this changes nothing for the dominant scrape paths**:

- `prometheus-operator` `ServiceMonitor` and `PodMonitor` discover
  Pods via Endpoints / EndpointSlices and scrape Pod IPs directly —
  the Service's ClusterIP is irrelevant.
- Prometheus' `kubernetes_sd_configs` does the same.
- `kubectl port-forward svc/x509-certificate-exporter 9793` still
  works (kubectl picks a backing Pod).

The one case where the change is observable is a Prometheus job using
`dns_sd_configs` (or a `static_configs` with the Service DNS name):
the resolver now returns one A record per Pod instead of a single
ClusterIP. If you have `replicas > 1` and were relying on the
ClusterIP's round-robin to distribute scrapes, you almost certainly
had a latent bug — only one Pod was scraped per attempt. Headless
fixes that.

To restore the v3 behaviour explicitly:

```yaml
service:
  headless: false
```

> [!NOTE]
> Kubernetes refuses to mutate a Service's `clusterIP` in place. A naive
> `helm upgrade` from v3 (with an assigned ClusterIP) to v4 (headless,
> `clusterIP: None`) would fail with `spec.clusterIPs[0]: may not change
> once set`. The chart ships a pre-upgrade hook that detects a v3 release
> via the existing Service's `helm.sh/chart` label and deletes the old
> Service before the upgrade reconciles, so helm can recreate it cleanly
> from the new template. A few seconds of scrape disruption during the
> upgrade window; Pods themselves stay up.

### Image schema — `digest` and split `migration.image`

Every image block (`image`, `migration.image`, `rbacProxy.image`) now
exposes the same five fields: `registry`, `repository`, `tag`,
`digest`, `pullPolicy` (plus `tagSuffix` on `image` for the
`scratch`/`busybox` flavor switch). When set, `digest` takes precedence
over `tag` and produces a `registry/repository@sha256:...` reference —
the recommended form in production once you have run `cosign verify`.

One small schema break: `migration.image.repository` used to bundle the
registry (`registry.k8s.io/kubectl`); v4 splits it into
`registry: registry.k8s.io` + `repository: kubectl`. If you override
the kubectl image in `values.yaml`, update both keys.

### PSA-restricted hardening on by default

Every component (`secretsExporter`, `hostPathsExporter`, `migration`,
`rbacProxy`) now ships with the two extra fields the Pod Security
Admission `restricted` profile requires:

- `podSecurityContext.seccompProfile.type: RuntimeDefault`
- `securityContext.allowPrivilegeEscalation: false`

The chart was already running as `runAsNonRoot: true` with `drop: [ALL]`
capabilities and `readOnlyRootFilesystem: true`; the two new fields
close the remaining PSA gap. No action required for stock deployments
— modern container runtimes (containerd, CRI-O, Docker) ship a
permissive default seccomp profile that a plain Go HTTP server
runs under unchanged. If you have an unusual cluster that
forbids `seccompProfile: RuntimeDefault`, override per-component:

```yaml
secretsExporter:
  podSecurityContext:
    seccompProfile: null
```

### `web.enableStats` — new optional endpoint

v4 exposes a small HTML status page at `/` (cache stats, source health,
process info). It's enabled by default in the chart (`web.enableStats:
true`). Disable it with `--set web.enableStats=false` if you want strict
metrics-only exposure.

### `kubeVersion` value removed

v3 exposed a top-level `kubeVersion: ""` knob to override the cluster
version detection — useful only with `helm template`. Helm 3.10+
exposes the `--kube-version` CLI flag for the same purpose, so v4
drops the value. If you set `kubeVersion:` in `values.yaml`, remove it
and pass `--kube-version v1.29.0` (or similar) when rendering.

---

## 4. Configuration: CLI flags → YAML file

v3 was driven entirely by CLI flags (`--watch-dir`, `--secret-type`,
`--include-namespace`, …). v4 makes a YAML config file the source of
truth (`--config /etc/x509-exporter/config.yaml`). A subset of the v3
flags (`--watch-file`, `--watch-dir`, `--watch-kubeconf`,
`--watch-kube-secrets`, `--listen-address`, `--web.config.file`,
`--debug`, `--profile`) still works as ergonomic shortcuts mapped
onto the YAML schema at parse time, but **their use is deprecated and
not recommended** — they may be removed in a future release. The
richer flags (`--secret-type`, `--include-namespace`, …) have no v4
CLI equivalent: express those rules in YAML.

If you deploy via the Helm chart, **you don't see this**: the chart
generates the YAML config from the same `values.yaml` you've always
edited and ships it as a `ConfigMap`. The break applies only to:

1. Custom CLI invocations (systemd units, dev environments running the
   binary directly).
2. Forks of the chart that assemble flags by hand instead of going
   through the official chart's templates.

For standalone use, see [`docs/faq.md`](./faq.md) (the
"non-Kubernetes host" entry) and the exhaustive `dev/values.yaml` for
every supported source kind.

---

## 5. Metrics: changed series

### Removed: `x509_read_errors`

v3 had a single gauge `x509_read_errors` that counted failed reads. It's
**removed** in v4 because the new
`x509_source_errors_total{source_kind, source_name, reason}` counter
gives strictly more information (per-source, per-reason, monotonically
increasing).

Update your alerts and dashboards:

```promql
# v3
x509_read_errors > 0

# v4
increase(x509_source_errors_total[15m]) > 0
```

The `reason` label gives a stable error code (e.g.
`source_unreachable`, `parse_failed`, `passphrase_wrong`,
`invalid_key_format`) — useful for routing alerts.

### Same name, same labels — no change needed

These v3 metrics are kept verbatim in v4. PromQL queries, alerts and
dashboards using them continue to work:

- `x509_cert_not_after`
- `x509_cert_expired` (now gated by `metrics.exposeExpired`, **on by
  default** — set to `false` if your alerts only consume
  `x509_cert_not_after - time()` and you want to halve the per-cert
  series count)
- `x509_cert_not_before` (now gated by `metrics.exposeNotBefore`,
  **off by default** — turn on to detect certificates issued in the
  future or clock-skew issues)
- `x509_cert_expires_in_seconds` (still gated by `metrics.exposeRelative`)
- `x509_cert_valid_since_seconds` (still gated by `metrics.exposeRelative`)
- `x509_cert_error` (still gated by `metrics.exposePerCertError`)
- `x509_exporter_build_info`

The per-certificate label set (`subject_CN`, `issuer_CN`,
`serial_number`, `secret_*`, `filepath`, surfaced Secret labels via
`exposeLabels`) is unchanged. v4 adds `configmap_name`,
`configmap_namespace` for the new ConfigMap source kind.

> [!IMPORTANT]
> **`x509_cert_not_before` is off by default in v4.** v3 always
> emitted it. If you have an alert/dashboard panel relying on it, set
> `metrics.exposeNotBefore: true` (chart: `exposeNotBeforeMetric: true`)
> to keep the series.

### New in v4

These series are entirely new and worth wiring into your dashboards:

| Metric | Type | Default | Use it for |
| --- | --- | --- | --- |
| `x509_source_up{source_kind, source_name}` | gauge | on | Per-source liveness — `== 0` means a source has stopped reporting |
| `x509_source_bundles{source_kind, source_name}` | gauge | on | Number of bundles (Secrets, files, etc.) currently held by each source |
| `x509_source_errors_total{source_kind, source_name, reason}` | counter | on | Per-source, per-reason error count (replaces `x509_read_errors`) |
| `x509_kube_watch_resyncs_total{source_name, resource}` | counter | on | API watch resyncs / 410 Gone events; sustained increase signals an unhealthy watch (network, apiserver) |
| `x509_scrape_duration_seconds` | histogram | on | Total time to serve a `/metrics` request |
| `x509_panic_total{component}` | counter | on | Recovered goroutine panics; should always be `0` in steady state |
| `x509_kube_request_duration_seconds{verb, resource}` | histogram | gated by `metrics.exposeDiagnostics` | client-go API call latency |
| `x509_kube_informer_scope{source_name, scope}` | gauge | gated by `metrics.exposeDiagnostics` | Whether the source is namespace-scoped or cluster-scoped (legacy metric name kept for dashboard compatibility) |
| `x509_informer_queue_depth{source_name, resource}` | gauge | gated by `metrics.exposeDiagnostics` | Real-time event-queue depth — populated by the namespace informer when label-based namespace rules are configured |
| `x509_parse_duration_seconds{format}` | histogram | gated by `metrics.exposeDiagnostics` | Per-format (PEM / PKCS#12) parse latency |
| `x509_pkcs12_passphrase_failures_total{source_name}` | counter | auto (only if a source declares `format: pkcs12`) | Specific to PKCS#12; a sustained increase usually means a Secret was rotated but the passphrase wasn't |

The chart's bundled `PrometheusRule` already references the new metrics;
re-enable rendering with `prometheusRules.create=true` to pick up the
defaults.

> [!NOTE]
> The four metrics gated by `metrics.exposeDiagnostics` (chart:
> `exposeDiagnosticMetrics`) are useful when troubleshooting the
> exporter itself, not when monitoring certificates. Default off keeps
> `/metrics` lean; flip on whenever you need to look inside.

---

## 6. Performance and caching

v4 substantially reduced memory footprint and parsing redundancy. No
configuration is required to benefit from the changes; we document them
here so you understand what changed if you notice lower memory usage
post-upgrade.

- **Direct paginated LIST + WATCH.** v3 polled the API server on a
  fixed cadence; the early v4 prototype used a SharedInformer cache,
  which OOM'ed on clusters with many large Helm release secrets
  because client-go's `pager.List` accumulates every page in memory
  before yielding. v4 ships a direct paginated LIST + WATCH loop that
  processes each page (default 50 objects, tunable via
  `secretsExporter.listPageSize`) before fetching the next, capping
  peak sync memory to roughly `pageSize × average object size`.
- **Server-side filtering.** v4 pushes label and field selectors onto
  every LIST and WATCH call. When all secret rules share a single
  Type (e.g. `kubernetes.io/tls`), a `fieldSelector=type=...` is
  applied automatically — the API server never returns Helm release
  secrets, ServiceAccount tokens or docker configs. Combined with
  namespace include/exclude (by name *or* by namespace label), this
  is the lever for clusters with tens of thousands of Secrets.
- **Adaptive source scope.** When a config restricts to a single
  literal namespace, v4 scopes the LIST + WATCH to that namespace
  rather than going cluster-wide. The `x509_kube_informer_scope`
  metric (legacy name kept for dashboard compatibility) exposes the
  decision.
- **Memoization by `ResourceVersion`.** v3 re-parsed every Secret on
  every change event. v4 keeps a per-object hash of the bundle keyed by
  `ResourceVersion`; a watch event for an unchanged Secret short-circuits
  through the cache.
- **Watch bookmarks.** Bookmarks let the API server advance the watch
  resource version without sending object updates, so reconnections
  resume from a recent point instead of triggering a full re-LIST.
- **Namespace label change → immediate re-list.** When namespace labels
  change, v4 short-circuits the resync timer and re-lists secrets and
  configmaps right away so newly-allowed objects appear without waiting
  up to 30 minutes.
- **File-source poll cache.** The new `cache.filePoll.skipUnchanged`
  short-circuits parsing when `(mtime, size, inode)` hasn't moved since
  the last poll — meaningful when watching `/etc/letsencrypt/live/...`
  with thousands of certs.

The chart's default resources reflect the new footprint:

| Component | Request | Limit |
| --- | --- | --- |
| Cluster-wide Secrets/ConfigMaps exporter | 20 Mi | 150 Mi |
| Node-local hostPath exporter (per DaemonSet) | 20 Mi | 40 Mi |

If you bumped these in v3 because the exporter was struggling on a large
cluster, lower them back and watch `x509_source_bundles` — the actual
number of bundles in cache is the load metric to size against.

---

## 7. Kubernetes / Helm deployment notes worth knowing

Beyond the breaking changes above, v4 ships a few additions that are
worth mentioning during a migration:

- **`/healthz` and `/readyz`** are now first-class endpoints alongside
  `/metrics`. The chart wires both into the Pod's probes by default.
  v3 deployments that disabled probes (because they didn't work) can
  re-enable them with no extra config.
- **ConfigMap watching is native.** v3 needed `--configmap-keys`; v4
  treats ConfigMaps as a regular source kind, with the same filtering
  options as Secrets (label selectors, namespace include/exclude).

---

## 8. Standalone (non-Kubernetes) use

If you run the binary on bare metal / VMs / systemd units rather than in
Kubernetes, two things change:

1. **Prefer a YAML config file.** A handful of v3-era CLI shortcuts
   (`--watch-file`, `--watch-dir`, `--watch-kubeconf`, …) still work,
   but they're a deprecated surface: they don't expose every v4
   capability (PKCS#12, ConfigMaps, regex key patterns, namespace
   labels, per-source rate limits, …) and may be removed in a future
   release. Write a small YAML config and pass it via `--config` to
   insulate yourself from future churn and to unlock the full feature
   set:

   ```yaml
   server:
     listen: :9793
   sources:
     - kind: file
       name: host-pki
       paths:
         - /etc/ssl/certs/*.pem
         - /etc/letsencrypt/live/*/fullchain.pem
   ```

   ```sh
   x509-certificate-exporter --config /etc/x509-exporter.yaml
   ```

2. **Pre-built binaries** are still attached to every GitHub Release.
   v4 keeps the matrix to Linux, macOS, Windows, FreeBSD, OpenBSD,
   NetBSD, Illumos and Solaris across `amd64`, `arm64`, `armv7` and
   `riscv64` (with exclusions for non-existent OS/arch combos). The
   binary name is `x509-certificate-exporter` (unchanged across forks).
   SLSA-3 provenance attestations (queryable via `gh attestation verify`)
   and SHA256 checksums are published alongside each binary — see the
   [hardening guide](./hardening.md) for the verification recipe.

This path is supported, but most operational documentation in v4 is
written assuming the Helm chart. If you need a feature that isn't
exposed in the standalone YAML config (e.g. `tryEmptyPassphrase` on a
file-based PKCS#12 keystore), open an issue — it's likely just missing
documentation rather than a missing feature.
