# FAQ

- [Why expose `not_after` rather than a remaining duration?](#why-expose-not_after-rather-than-a-remaining-duration)
- [How do I detect that the exporter has stopped seeing my certs?](#how-do-i-detect-that-the-exporter-has-stopped-seeing-my-certs)
- [Does the exporter read or store private keys?](#does-the-exporter-read-or-store-private-keys)
- [What's the memory footprint? How many certs can it handle?](#whats-the-memory-footprint-how-many-certs-can-it-handle)
- [How do I keep label cardinality under control?](#how-do-i-keep-label-cardinality-under-control)
- [Can I run multiple replicas?](#can-i-run-multiple-replicas)
- [How do I monitor a non-Kubernetes host?](#how-do-i-monitor-a-non-kubernetes-host)

## Why expose `not_after` rather than a remaining duration?

Because constant values store and query best in Prometheus, and because
doing the math in PromQL keeps the result accurate down to scrape time
rather than baking in stale "minutes-ago" values:

```promql
(x509_cert_not_after - time()) / 86400   # days remaining, exact at query time
```

The TSDB's chunk encoding compresses runs of identical samples into a
near-zero footprint. A relative-duration gauge would change every
scrape (`-15s`, `-30s`, `-45s`, …), defeating that compression and
inflating disk usage on long-retained data.

For backends that lack timestamp arithmetic (Datadog scraping
`/metrics`, OTLP collectors with restrictive transforms, etc.),
`metrics.exposeRelative: true` adds two extra gauges,
`x509_cert_expires_in_seconds` and `x509_cert_valid_since_seconds`,
that ship the relative durations precomputed. They cost roughly 2× the
storage of the absolute series, so leave them off unless you actually
consume them.

## How do I detect that the exporter has stopped seeing my certs?

Three complementary signals; the chart's `PrometheusRule` ships
defaults for all of them.

```promql
# 1. The source itself is down (watch loop crash, fatal config error)
x509_source_up == 0

# 2. The source produces errors (parse failures, API errors, missing files)
increase(x509_source_errors_total[15m]) > 0

# 3. The set of bundles in scope shrank — a cert was renamed,
#    relabelled out of scope, or its file disappeared
delta(x509_source_bundles[15m]) < 0
```

The exporter never silently drops a bundle: any disappearance is
attributed by `x509_source_bundles` going down **and**
`x509_source_errors_total{reason="not_found"}` going up. If a bundle
moves out of scope because a label changed, it shows in the bundle
count delta but produces no error.

Always pair `x509_source_up == 0` with a `for: ≥30s` in alerting rules
— sources legitimately report `0` for the first few seconds after pod
boot while the initial sync runs.

## Does the exporter read or store private keys?

No. The exporter is read-only on certificate **public** material.

The PEM parser keeps only `CERTIFICATE` and `TRUSTED CERTIFICATE`
blocks; everything else (`PRIVATE KEY`, `EC PARAMETERS`, `CERTIFICATE
REQUEST`, …) is dropped before any further processing — see
[`pkg/cert/pem`](../pkg/cert/pem). PKCS#12 archives are the one path
where the exporter does decrypt private material, because the cert
bag and the key bag share the same passphrase and the archive is
opaque before decoding; once the cert bag is extracted the embedded
private key is immediately discarded. Passphrases never appear in
logs (the structured logger redacts known passphrase fields) or in
metric labels.

What the exporter needs to function:

- Read access on the certificate-bearing resources (Kubernetes RBAC
  for `secrets`/`configmaps`, filesystem permissions for files).
- Read access on the passphrase carrier when watching PKCS#12 — the
  sibling Secret key, an external file, or another Secret referenced
  by `passphraseSecretRef`.

It never opens TLS connections to verify the certificate, never
re-signs anything, never writes back. The complete egress surface in
Kubernetes mode is the API server (LIST + WATCH), and in
standalone mode is the metrics listener plus the optional `pprof`
listener if `diagnostics.pprof.enabled: true`.

## What's the memory footprint? How many certs can it handle?

Two distinct workloads, two distinct sizing rules.

**Cluster-wide Kubernetes mode** — the chart's
`secretsExporter`/`configMapsExporter`. The exporter does **not** keep
a Kubernetes object cache. It pages through the API (LIST + WATCH)
and processes each batch inline, so peak memory during the initial
sync is bounded by `pageSize × average object size`, not by the
total count in scope. Steady-state memory is dominated by the parsed
certificate bundles plus the Prometheus series — typically a few MB
for hundreds of certs, tens of MB for thousands.

The page size defaults to **50** and is tunable via the chart's
`secretsExporter.listPageSize` value (or `sources[].listPageSize` in
the YAML config). Lower it (e.g. `20`) on memory-constrained pods
that watch many large Helm release secrets; raise it (e.g. `200`)
to speed up sync on smaller objects. `0` keeps the built-in default.

Server-side filtering still matters because every object the API
server returns has to be parsed, even if most are quickly discarded:

- **Automatic Secret type filter** — when every `secretTypes` entry
  shares the same `type` (e.g. `kubernetes.io/tls`), the exporter
  appends a server-side `fieldSelector=type=...`. This is automatic
  and dramatically reduces the API payload on clusters with many
  Helm release secrets, ServiceAccount tokens, or docker configs.
- `namespaces.include` / `namespaces.exclude` (by name or by
  namespace label) — applied at the API server.
- `secrets.includeLabels` / `excludeLabels` and the equivalent for
  ConfigMaps — pushed down as `labelSelector`.
- A focused `secretTypes` list — narrows the per-object work the
  exporter performs after the LIST returns.

The chart's defaults (`20 Mi` request / `150 Mi` limit) are sized for
mid-thousands of certificates. Raise the limit if you watch tens of
thousands; tighten filters first if the bottleneck is API server
load rather than memory.

**Per-node hostPath mode** — the
`hostPathsExporter.daemonSets.<name>` entries. Just parsed bundles in
memory. The chart's defaults (`20 Mi` / `40 Mi`) hold hundreds of
node-local certs comfortably.

In both modes, `x509_source_bundles` is the operational load metric:

```promql
sum by (source_kind, source_name) (x509_source_bundles)
```

Watch this curve over a week before raising memory limits — bundles
fluctuate as Secrets get rotated and cert-manager Orders churn. CPU
sits idle in steady state; the only spike-prone phase is the initial
LIST at pod boot, which scales linearly with the number of objects
returned by the API server (after server-side selectors apply) and
typically completes in seconds.

## How do I keep label cardinality under control?

Per-certificate metrics carry a wide label set
([full schema](./metrics.md#common-labels-per-certificate-metrics)).
Cardinality is the product of:

- the number of distinct certificates in scope (one series per cert),
- the number of distinct values for `subject_*` and `issuer_*` fields
  (a sprawling chain set inflates this),
- the optional `secret_label_*` / `configmap_label_*` exposed via
  `metrics.exposeSecretLabels` / `exposeConfigMapLabels`.

Knobs that genuinely cut cardinality:

- `metrics.exposeSubjectFields: ["CN"]` — keep only the Common Name in
  the subject DN, drop `C/ST/L/O/OU`. Same for `exposeIssuerFields`.
  Often halves the per-series label width.
- `metrics.trimPathComponents: <n>` — drop the first *n* directory
  components from `filename`/`filepath`, useful when watching deeply
  nested PKI trees.
- Tighter `secrets.includeLabels` / namespace selectors — fewer
  bundles in scope, fewer series.

Don't expose `secret_label_*` for labels with high-cardinality values
(commit SHAs, timestamps, request IDs). Each distinct value adds a
full series.

## Can I run multiple replicas?

Yes — the chart's `replicas` value defaults to `1` but is safe to
raise. There is **no leader election**: every replica runs its own
LIST + WATCH against `kube-apiserver`, parses its own bundles, and
serves its own `/metrics`. Prometheus's `honor_labels: false` and
standard `instance` relabeling deduplicates the resulting series
naturally.

The HA cost is RAM and API-server load: `N` replicas means `N`
parallel watch streams plus `N` parsed-bundle sets in memory.
[Server-side filtering](#how-do-i-keep-label-cardinality-under-control)
is the same lever as for sizing a single replica — the cost is
per-replica, but each replica still benefits from the same selector
narrowing.

## How do I monitor a non-Kubernetes host?

Run the binary directly with a YAML config declaring only file-shaped
sources — no Kubernetes connection is attempted unless a `kind:
kubernetes` source is declared:

```yaml
# /etc/x509-exporter.yaml
server:
  listen: :9793
sources:
  - kind: file
    name: host-pki
    paths:
      - /etc/ssl/certs/*.pem
      - /etc/letsencrypt/live/*/fullchain.pem
    refreshInterval: 1m
```

```sh
x509-certificate-exporter --config /etc/x509-exporter.yaml
```

The default `cache.filePoll.skipUnchanged: true` short-circuits unchanged
files by comparing `(mtime, size)` between polls — meaningful when
watching dense PKI trees (hundreds of `live/*/fullchain.pem` entries).
The stat is taken on the **symlink itself** (`Lstat`, not `Stat`), so a
certbot renewal — which atomically swaps the `live/<domain>/fullchain.pem`
symlink onto a new `archive/<domain>/fullchainN.pem` target — bumps the
symlink's mtime/size and triggers a re-parse on the next poll. Same
holds for Kubernetes `subPath`/projected-volume mounts where kubelet
swaps the inner `..data` symlink atomically.

Typical systemd unit:

```ini
[Unit]
Description=X.509 certificate exporter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/x509-certificate-exporter --config /etc/x509-exporter.yaml
DynamicUser=true
ReadOnlyPaths=/etc/ssl /etc/letsencrypt
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
RestrictNamespaces=true
SystemCallFilter=@system-service
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
