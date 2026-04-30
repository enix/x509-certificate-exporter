# Migrating from v3 to v4

This guide walks through every breaking change between the v3 and v4
releases of the x509-certificate-exporter. The order below reflects
operational priority: distribution channels first (because the wrong URL
gets you `404`), then chart values shape, then metrics changes (which
need PromQL/dashboard updates), then the rest.

The Go module path also changed from
`github.com/enix/x509-certificate-exporter/v3` to
`github.com/enix/x509-certificate-exporter/v4`. If you import the
exporter as a library, update your imports accordingly. Most operators
deploy via Helm and won't be affected.

---

## At a glance

| Area | v3 | v4 |
| --- | --- | --- |
| Helm chart distribution | `https://charts.enix.io` (classic) **and** `oci://quay.io/enix/charts/...` | `oci://quay.io/enix/charts/x509-certificate-exporter` only |
| Container image variants | `busybox`, `alpine`, `scratch` | `busybox`, `scratch` (Alpine retired) |
| Image registries | Docker Hub (canonical) | Docker Hub, GHCR, Quay (all three) |
| Architectures | `amd64`, `arm64` | `amd64`, `arm64`, `riscv64` |
| Exporter configuration | CLI flags | YAML config file (`--config`) |
| Helm `secretTypes` shape | `{type, key}` | `{type, key, format?, pkcs12?}` (extended) |
| Node-PKI DaemonSet config | `hostPathsDaemonSet:` (single, flat) | `hostPathsExporter.daemonSets.<name>:` (map, multi-instance) |
| `kube-rbac-proxy` sidecar | Required for TLS / BasicAuth on `/metrics` | Not needed — exporter-toolkit handles both natively |
| `kube-rbac-proxy` image tag | `v0.13.1` | `v0.22.0` |
| `x509_read_errors` metric | Single gauge per error | Removed — see metrics section |
| Per-source observability | None | `x509_source_up`, `x509_source_bundles`, `x509_source_errors_total{reason}` |

---

## 1. Helm chart distribution: OCI only

In v3 the chart was double-published — to the classic Helm repository at
`https://charts.enix.io` *and* as an OCI artifact on `quay.io`. In v4
the classic repo is **retired**; only the OCI publication is kept. The
chart on disk is the same name (`x509-certificate-exporter`); only the
download URL changes.

This requires Helm **3.8 or later** (OCI support became GA in 3.8.0).

### Before (v3)

```sh
helm repo add enix https://charts.enix.io
helm repo update
helm install x509-certificate-exporter enix/x509-certificate-exporter \
  --version 3.21.0
```

### After (v4)

```sh
helm install x509-certificate-exporter \
  oci://quay.io/enix/charts/x509-certificate-exporter \
  --version 4.0.0
```

If you keep the chart pinned in a wrapper (Argo CD `Application`,
Flux `HelmRelease`, etc.), update the source:

```yaml
# Argo CD Application (v4)
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
# Flux HelmRelease (v4)
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

The chart is cosign-signed; verifying the OCI artifact is documented in
[the README](../README.md#-verifying-authenticity).

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
`-scratch`). **v4 retires the Alpine variant.** Only two variants
remain:

- `busybox` (default — empty `tagSuffix`)
- `scratch` (set `image.tagSuffix: -scratch`)

If you currently set `image.tagSuffix: -alpine`, switch to one of:

- `image.tagSuffix: ""` → `busybox`. Closest to Alpine: still has
  `/bin/sh`, `wget`, `cat`, etc., useful for `kubectl exec` debugging.
- `image.tagSuffix: -scratch` → distroless. No shell, no utilities.
  Smallest image; `kubectl debug` is the way to inspect a running pod.

### Architectures

v4 adds `linux/riscv64` to the previous `linux/amd64,arm64` matrix. No
action required for existing AMD64/ARM64 deployments.

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

### Node-PKI DaemonSets — restructured

The chart used to expose **one** `hostPathsDaemonSet` block. v4 replaces
it with **a map of named DaemonSets** so the same chart release can ship
several disjoint hostPath scanners (kubelet PKI, etcd PKI, kube-apiserver
PKI on different nodes, etc.).

#### Before (v3)

```yaml
hostPathsDaemonSet:
  enabled: true
  watchDirectories:
    - /etc/kubernetes/pki
  watchFiles:
    - /var/lib/kubelet/pki/kubelet.crt
  watchKubeconfFiles:
    - /etc/kubernetes/admin.conf
```

#### After (v4)

```yaml
hostPathsExporter:
  # Cluster-wide defaults applied to every entry under daemonSets:
  debug: false
  restartPolicy: Always
  resources:
    requests: { cpu: 10m, memory: 20Mi }
    limits:   { memory: 40Mi }

  daemonSets:
    node-pki:
      watchDirectories:
        - /etc/kubernetes/pki
      watchFiles:
        - /var/lib/kubelet/pki/kubelet.crt
      watchKubeconfFiles:
        - /etc/kubernetes/admin.conf
```

The keys under `daemonSets.<name>` are the same fields as v3's flat
block. The wrapping is the only structural change.

### `kube-rbac-proxy` — sidecar no longer required

v3 documented `kube-rbac-proxy` as the sidecar to terminate TLS or
enforce BasicAuth on `/metrics`. v4 ships the
[`prometheus-exporter-toolkit`](https://github.com/prometheus/exporter-toolkit/tree/master/web)
inside the exporter itself: TLS + BasicAuth are first-class config
options on the exporter, no sidecar needed.

If you still want the sidecar (e.g. because policy mandates the proxy
pattern), the chart keeps it; the sidecar's image tag was bumped from
`v0.13.1` to `v0.22.0`. If you pin the tag in `values.yaml`, update.

If you don't, consider removing `kubeRBACProxy.enabled: true` and using
the exporter's native `web.config.file` and TLS config. One pod, one
process, one less network hop.

### `web.enableStats` — new optional endpoint

v4 exposes a small HTML status page at `/` (cache stats, source health,
process info). It's enabled by default in the chart (`web.enableStats:
true`). Disable it with `--set web.enableStats=false` if you want strict
metrics-only exposure.

---

## 4. Configuration: CLI flags → YAML file

v3 was driven entirely by CLI flags (`--watch-dir`, `--secret-type`,
`--include-namespace`, …). v4 takes a single YAML config file
(`--config /etc/x509-exporter/config.yaml`) and exposes only a handful
of flags (`--config`, `--debug`, `--version`).

If you deploy via the Helm chart, **you don't see this**: the chart
generates the YAML config from the same `values.yaml` you've always
edited and ships it as a `ConfigMap`. The breaking-ness applies only to:

1. Custom CLI invocations (systemd units, dev environments running the
   binary directly).
2. Forks of the chart that assemble flags by hand instead of going
   through the official chart's templates.

For standalone use, see the
[example config in the README](../README.md#how-do-i-monitor-a-non-kubernetes-host)
and the exhaustive `dev/values.yaml` for every supported source kind.

---

## 5. Metrics: changed series

### Same name, same labels — no change needed

These v3 metrics are kept verbatim in v4. PromQL queries, alerts and
dashboards using them continue to work:

- `x509_cert_expired`
- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expires_in_seconds` (still gated by `metrics.exposeRelative`)
- `x509_cert_valid_since_seconds` (still gated by `metrics.exposeRelative`)
- `x509_cert_error` (still gated by `metrics.exposePerCertError`)
- `x509_exporter_build_info`

The per-certificate label set (`subject_CN`, `issuer_CN`,
`serial_number`, `secret_*`, `filepath`, surfaced Secret labels via
`exposeLabels`) is unchanged. v4 adds `configmap_name`,
`configmap_namespace` for the new ConfigMap source kind.

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

### New in v4

These series are entirely new and worth wiring into your dashboards:

| Metric | Type | Use it for |
| --- | --- | --- |
| `x509_source_up{source_kind, source_name}` | gauge | Per-source liveness — `== 0` means a source has stopped reporting |
| `x509_source_bundles{source_kind, source_name}` | gauge | Number of bundles (Secrets, files, etc.) currently held by each source |
| `x509_source_errors_total{source_kind, source_name, reason}` | counter | Per-source, per-reason error count (replaces `x509_read_errors`) |
| `x509_kube_watch_resyncs_total{source_name, resource}` | counter | API watch resyncs / 410 Gone events; sustained increase signals an unhealthy informer |
| `x509_kube_request_duration_seconds{verb, resource}` | histogram | client-go API call latency |
| `x509_pkcs12_passphrase_failures_total{source_name}` | counter | Specific to PKCS#12; a sustained increase usually means a Secret was rotated but the passphrase wasn't |
| `x509_parse_duration_seconds{format}` | histogram | Per-format (PEM / PKCS#12) parse latency |
| `x509_scrape_duration_seconds` | histogram | Total time to serve a `/metrics` request |
| `x509_panic_total{component}` | counter | Recovered goroutine panics; should always be `0` in steady state |

The chart's bundled `PrometheusRule` already references the new metrics;
re-enable rendering with `prometheusRules.create=true` to pick up the
defaults.

---

## 6. Performance and caching

v4 substantially reduced informer footprint and parsing redundancy. No
configuration is required to benefit from the changes; document them
here mostly so you know what changed when you read about lower memory
usage post-upgrade.

- **Server-side filtering.** The old behavior was to list every Secret
  cluster-wide, then drop in-process. v4 pushes label selectors and
  field selectors to the Kubernetes API server via informers, so the
  cache only ever contains what's in scope. Combined with namespace
  include/exclude (by name *or* by namespace label), this is the lever
  for clusters with tens of thousands of Secrets.
- **Adaptive informer scope.** When a config restricts to a small
  namespace set, v4 spawns per-namespace informers instead of a
  cluster-wide one. The `x509_kube_informer_scope` metric exposes the
  decision.
- **Memoization by `ResourceVersion`.** v3 re-parsed every Secret on
  every change event. v4 keeps a per-object hash of the bundle keyed by
  `ResourceVersion`; a watch event for an unchanged Secret short-circuits
  through the cache.
- **Watch bookmarks + `WatchListClient`.** Reconnections are cheaper:
  bookmarks let the API server skip full-list resyncs after a brief
  disconnect, and `WatchListClient` uses the streaming list endpoint
  for the initial sync (less RAM during cold-start).
- **Shared informer factories.** Two sources watching the same resource
  type now share the underlying informer.
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
  v3 deployments that disabled probes (because they didn't exist) can
  re-enable them with no extra config.
- **ConfigMap watching is native.** v3 needed `--configmap-keys`; v4
  treats ConfigMaps as a regular source kind, with the same filtering
  options as Secrets (label selectors, namespace include/exclude).
- **`PrometheusPodMonitor`** alongside `PrometheusServiceMonitor`. If
  your Prometheus is configured to discover via PodMonitor instead, the
  chart now supports that (`prometheusPodMonitor.create: true`).
- **Multiple node-PKI DaemonSets per release.** Useful when control-plane
  nodes and worker nodes have different PKI layouts and you want a
  scanner sized differently for each — see the `daemonSets:` map in
  Section 3.

---

## 8. Standalone (non-Kubernetes) use

If you run the binary on bare metal / VMs / systemd units rather than in
Kubernetes, two things change:

1. **CLI flags are gone.** v3's `--watch-dir`, `--watch-file`,
   `--secret-type` etc. no longer exist. Write a small YAML config and
   pass it via `--config`:

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

2. **Pre-built binaries** are still attached to every GitHub Release
   for Linux, macOS, Windows on amd64/arm64. The binary name is
   `x509-certificate-exporter` (unchanged across forks). SLSA-3
   provenance and SHA256 checksums are published next to each binary —
   see [the README](../README.md#-verifying-authenticity) for the
   `slsa-verifier` recipe.

This path is supported, but most operational documentation in v4 is
written assuming the Helm chart. If you need a feature that isn't
exposed in the standalone YAML config (e.g. `tryEmptyPassphrase` on a
file-based PKCS#12 keystore), open an issue — it's likely just missing
documentation rather than a missing feature.
