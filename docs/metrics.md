# Metrics

Every metric exposed by the exporter, with its label schema, the conditions
under which it is emitted, and worked PromQL examples where useful.

The exporter splits its output into four families:

- **Per-certificate metrics** — one series per certificate found, dense
  label set. The bread-and-butter of expiry alerts.
- **Per-source metrics** — one series per configured source. The right
  lens for "is this watcher healthy".
- **Diagnostic metrics** — gated by `metrics.exposeDiagnostics` and off
  by default. Parse / Kubernetes-API latencies and informer internals.
  Useful when troubleshooting the exporter; noise otherwise.
- **Health and process metrics** — cardinality-1 series describing the
  exporter process itself, independent of the data it watches.

## At a glance

| Family | Metric | Type | Gating |
| --- | --- | --- | --- |
| Per-certificate | `x509_cert_not_after` | gauge | always |
| Per-certificate | `x509_cert_not_before` | gauge | `metrics.exposeNotBefore: true` (off by default) |
| Per-certificate | `x509_cert_expired` | gauge | `metrics.exposeExpired: true` (**on by default**) |
| Per-certificate | `x509_cert_expires_in_seconds` | gauge | `metrics.exposeRelative: true` |
| Per-certificate | `x509_cert_valid_since_seconds` | gauge | `metrics.exposeRelative: true` |
| Per-certificate | `x509_cert_error` | gauge | `metrics.exposePerCertError: true` |
| Per-source | `x509_source_up` | gauge | always |
| Per-source | `x509_source_bundles` | gauge | always |
| Per-source | `x509_source_errors_total` | counter | always |
| Per-source | `x509_kube_watch_resyncs_total` | counter | Kubernetes sources only |
| Per-source | `x509_pkcs12_passphrase_failures_total` | counter | auto: when any source declares `format: pkcs12` |
| Per-source | `x509_cert_collision_total` | counter | always |
| Diagnostic | `x509_parse_duration_seconds` | histogram | `metrics.exposeDiagnostics: true` |
| Diagnostic | `x509_kube_request_duration_seconds` | histogram | `metrics.exposeDiagnostics: true`, Kubernetes sources only |
| Diagnostic | `x509_kube_informer_scope` | gauge | `metrics.exposeDiagnostics: true`, Kubernetes sources only |
| Diagnostic | `x509_informer_queue_depth` | gauge | `metrics.exposeDiagnostics: true`, Kubernetes sources only |
| Health | `x509_scrape_duration_seconds` | histogram | always |
| Health | `x509_panic_total` | counter | always |
| Health | `x509_exporter_build_info` | gauge | always |

## Common labels (per-certificate metrics)

Per-certificate metrics share a single label schema. Every per-cert
metric (`x509_cert_*`) emits the same label set; values irrelevant to
a given source kind are populated as the empty string `""` so that
PromQL aggregation across heterogeneous source kinds remains valid.

| Label | When populated | Notes |
| --- | --- | --- |
| `serial_number` | always | Decimal serial number of the certificate (empty string when the bundle item failed to parse) |
| `subject_C`, `subject_ST`, `subject_L`, `subject_O`, `subject_OU`, `subject_CN` | always | Subject DN fields. The set of fields kept is configurable via `metrics.exposeSubjectFields` (default: all six). Unselected fields don't appear at all |
| `issuer_C`, `issuer_ST`, `issuer_L`, `issuer_O`, `issuer_OU`, `issuer_CN` | always | Same shape as `subject_*`, configurable via `metrics.exposeIssuerFields` |
| `filename`, `filepath` | `file`, `kubeconfig` | Container-local path. Empty for Kubernetes sources |
| `embedded_kind`, `embedded_key` | `kubeconfig` only | Whether the cert came from a `cluster` or `user` block, plus the YAML key. Empty for other source kinds |
| `secret_namespace`, `secret_name`, `secret_key` | `kube-secret` only | Identifies the Secret and the data key within it |
| `configmap_namespace`, `configmap_name`, `configmap_key` | `kube-configmap` only | Same, for ConfigMaps |
| `secret_label_<name>` | `kube-secret`, optional | One label per entry in `sources[].secrets.exposeLabels` (chart: `secretsExporter.exposeSecretLabels`). Names are sanitised: any non-alnum/underscore char becomes `_`, leading digit gets a `_` prefix |
| `configmap_label_<name>` | `kube-configmap`, optional | One label per entry in `sources[].configMaps.exposeLabels`. Same sanitisation rule. Not currently exposed by the Helm chart |
| `discriminator` | conditional | Slot exists when `metrics.collisionDiscriminator` is `auto` (default) or `always`; absent under `never`. Populated with a per-cert SHA-256 prefix in `always` mode unconditionally and in `auto` mode only when a label collision was detected (see [`x509_cert_collision_total`](#x509_cert_collision_total)) |

The discriminator slot, when absent (`never` mode), is genuinely
missing from the label set rather than emitted as empty.

Use `metrics.trimPathComponents` to strip a fixed number of leading
directory components from `filepath` — handy on hostPath-style
deployments where every path starts with the same `/mnt/watch/...`
prefix.

---

## Per-certificate metrics

### `x509_cert_not_before`

Unix timestamp of the certificate's `NotBefore` field.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Emitted only when `metrics.exposeNotBefore` is `true` (off by default).**

Off by default because the canonical "is this cert usable" check works
against `NotAfter`. Turn this on if you specifically need to detect
"issued in the future" misconfigurations or clock skew.

### `x509_cert_not_after`

Unix timestamp of the certificate's `NotAfter` field. The series users
end up alerting on most.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Always emitted.**

```promql
# Days remaining for every cert in scope
(x509_cert_not_after - time()) / 86400

# Anything expiring in the next 14 days
(x509_cert_not_after - time()) / 86400 < 14

# Same, but exclude trust roots stored in kube-public (they're meant
# to outlive everything else, you don't want them in your alert noise)
(x509_cert_not_after - time()) / 86400 < 14
  unless x509_cert_not_after{secret_namespace="kube-public"}

# Earliest-expiring cert per namespace — driver for a "what to renew
# next" dashboard panel
bottomk(1, x509_cert_not_after - time()) by (secret_namespace)

# Total cert count per namespace (the per-cert label set has no
# `source_kind` — for a count by source kind, use `x509_source_bundles`)
count by (secret_namespace) (x509_cert_not_after{secret_namespace!=""})
```

> The "exclude trust roots" example uses `unless` rather than a label
> matcher. `x509_cert_not_after - time()` has the same label set as
> `x509_cert_not_after`, so the right-hand side aligns naturally.
> Server-side filtering (`excludeNamespaces`, `excludeLabels`) is
> preferable when the goal is to never see those certs at all — the
> metric just isn't emitted.

### `x509_cert_expired`

`1` if the cert is currently expired (`now > NotAfter`), `0` otherwise.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Emitted when `metrics.exposeExpired` is `true` (default on).**

A convenience: `x509_cert_expired == 1` selects the same series as
`x509_cert_not_after < time()` (use the `bool` modifier —
`(x509_cert_not_after < bool time())` — if you need a 0/1 gauge from
the comparison form). Pick whichever reads better in your alerts.
Set `exposeExpired: false` to drop the metric if you only ever alert
on the `not_after - time()` form.

### `x509_cert_expires_in_seconds`

Number of seconds until `NotAfter`. Negative once expired.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Emitted only when `metrics.exposeRelative` is `true`.**

This is redundant with `x509_cert_not_after - time()` and is off by
default to keep cardinality minimal. Enable it when scraping from a
backend that lacks PromQL-style timestamp arithmetic (Datadog, OTLP
collectors with restrictive transforms, etc.).

### `x509_cert_valid_since_seconds`

Number of seconds since `NotBefore`. Negative if the cert is not yet
valid (rare but happens with clock skew or pre-issued certs).

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Emitted only when `metrics.exposeRelative` is `true`.**

### `x509_cert_error`

`1` if the bundle item that should have been a certificate failed to
parse (bad PEM, wrong PKCS#12 passphrase, unreadable file, …);
`0` otherwise.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Emitted only when `metrics.exposePerCertError` is `true`.**

This series gives you per-item error visibility, which is usually too
granular for alerting (use [`x509_source_errors_total`](#x509_source_errors_total)
instead). The intended use is per-cert dashboards where you want a "this
specific cert failed to parse" pill next to the rest of its labels.

---

## Per-source metrics

A **source** is one configured input the exporter watches: a Kubernetes
Secrets watcher, a kubeconfig path, a file glob on disk, etc. Each is
identified by a `source_name` label (the `name` field in the YAML
config) and a `source_kind` label.

| `source_kind` value | Origin |
| --- | --- |
| `file` | `kind: file` source — disk paths and globs |
| `kubeconfig` | `kind: kubeconfig` source |
| `kube-secret` | `kind: kubernetes` watching Secrets |
| `kube-configmap` | `kind: kubernetes` watching ConfigMaps |

### `x509_source_up`

`1` once the source has produced its first sync (initial list complete,
informers running, files first scanned), `0` after a fatal error.

- **Type**: gauge
- **Labels**: `source_kind`, `source_name`
- **Emitted from the moment the source's first readiness callback
  fires.** During the cold-start window (typically sub-second for file
  sources, a few seconds for Kubernetes informers awaiting their
  initial list), the series is absent rather than `0` — Prometheus
  alerting on `x509_source_up == 0` should pair with a `for: 30s` (or
  similar) clause to tolerate this.

```promql
# Sources currently down. Pair with Alertmanager's `for: 1m` to
# tolerate the boot window without an extra PromQL clause; the
# exporter does not expose `process_start_time_seconds`.
x509_source_up == 0

# Same, expressed as "down for at least 60s straight" if you don't
# control the alert's `for:` (e.g. you query from Grafana directly)
min_over_time(x509_source_up[1m]) == 0
```

### `x509_source_bundles`

Number of bundles currently held by the source. A "bundle" is one
addressable unit — a Secret, a ConfigMap, a file path. The number of
*certificates* may be larger if a single bundle holds a chain.

- **Type**: gauge
- **Labels**: `source_kind`, `source_name`
- **Emitted from the first `Upsert` per (kind, name).** Before any
  bundle has been published by a source, the series doesn't exist;
  after subsequent deletions bring the count back to zero, the series
  remains and reads `0`.

This is the right metric to size cluster-wide informer caches against
— if it's an order of magnitude bigger than expected, your label
selectors are too loose.

### `x509_source_errors_total`

Per-source error counter, broken down by reason code.

- **Type**: counter
- **Labels**: `source_kind`, `source_name`, `reason`
- **Emitted lazily**: a series for a given `(source_kind, source_name,
  reason)` triple appears the first time that error fires. Sources
  that never err never produce series here. PromQL `increase(...) > 0`
  works as the "any-error" probe regardless.

The `reason` label takes one of a stable set of values; see the
[reason codes reference](#reason-codes) below.

```promql
# Any new error in the last 15 minutes (the canonical "is something
# wrong" probe)
increase(x509_source_errors_total[15m]) > 0

# PKCS#12 passphrase failures specifically
increase(x509_source_errors_total{reason="bad_passphrase"}[15m]) > 0

# File-source filesystem issues (broken symlinks, permission denied,
# missing files announced by inotify but gone by the time we read them)
increase(x509_source_errors_total{reason=~"broken_symlink|permission_denied|not_found|walk_error|read_failed"}[15m]) > 0

# Top-3 most-frequent reasons across all sources (driver for an
# "errors breakdown" dashboard panel)
topk(3, sum by (reason) (rate(x509_source_errors_total[1h])))

# Kubernetes transport-layer issues — these come in via client-go and
# show up with source_kind="kubernetes", source_name="kube-api" rather
# than per user-defined source. Worth a separate alert.
increase(x509_source_errors_total{source_kind="kubernetes", reason=~"rate_limited|http_5..|http_401|http_403"}[15m]) > 0
```

### `x509_kube_watch_resyncs_total`

Number of forced informer resyncs — typically caused by a
`watch expired` or HTTP `410 Gone` from the API server.

- **Type**: counter
- **Labels**: `source_name`, `resource`
- **Emitted only for Kubernetes sources** (`kind: kubernetes`). The
  series for a given `(source_name, resource)` pair appears the first
  time a resync fires; healthy informers can run indefinitely without
  producing a single series here.

`resource` is whatever name client-go's reflector publishes for the
watched type — typically the resource kind, but the exact string is
controlled by client-go and can vary between versions.

> ⚠ The `source_name` label is the constant `"kubernetes"` rather
> than the user-defined source name — this metric is fed by client-go's
> reflector, which has no per-source context. If you run multiple
> Kubernetes sources, they all aggregate here.

A steady increase is a sign of an unhappy informer — flapping API
server, network instability, or a watch cache too small on the
apiserver side. A few per hour is normal; dozens per minute warrants
investigation.

```promql
# Resync rate over 15 minutes — anything sustained > 1/min is
# probably a watch-cache issue on the apiserver side
rate(x509_kube_watch_resyncs_total[15m]) * 60 > 1
```

### `x509_pkcs12_passphrase_failures_total`

PKCS#12 keystore decoding attempts that failed because the passphrase
was wrong.

- **Type**: counter
- **Labels**: `source_name`
- **Auto-gated**: registered only when at least one source declares
  `format: pkcs12` (file source `formats:`, kubernetes source
  `secrets.types[].format`, or `configMaps.format`). Deployments
  without PKCS#12 don't see the metric in `/metrics` at all.

A spike usually means a Secret was rotated but the sibling passphrase
key wasn't, or a `passphraseFile` was stale.

### `x509_cert_collision_total`

Number of times the registry detected two distinct certificates that
would have produced the same Prometheus label set, and resolved the
collision by adding a `discriminator` label to one of them.

- **Type**: counter
- **Labels**: `source_kind`
- **Always emitted.**

Collisions usually indicate an over-aggressive `metrics.trimPathComponents`
or a too-narrow `metrics.exposeSubjectFields`/`exposeIssuerFields`. The
counter increasing means the exporter is working around the ambiguity
with the discriminator scheme set in `metrics.collisionDiscriminator`
(default `auto`); investigate so you can disambiguate at the source
rather than rely on the auto-discriminator.

---

## Health and process metrics

These describe the exporter process itself, regardless of how many or
which sources it watches.

### `x509_scrape_duration_seconds`

Total wall time spent serving one `/metrics` request.

- **Type**: histogram
- **Labels**: none
- **Buckets**: `0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30` seconds

Use this to detect when scrape time is climbing against the Prometheus
scrape timeout — the exporter never re-parses bundles during a scrape,
so this should stay flat regardless of the certificate count. A growing
p99 signals contention on the registry mutex (lots of bundles changing
during the scrape).

### `x509_panic_total`

Goroutine panics caught by the exporter's recover handlers, by
component. **Should always be `0`** in a steady-state deployment.

- **Type**: counter
- **Labels**: `component` — typical values: `source/<source-name>`
  (one of the source goroutines panicked), `pprof` (the optional
  pprof endpoint goroutine panicked)
- **Emitted lazily**: the series for a given component appears only
  after that component has panicked at least once. In a healthy
  deployment, `/metrics` shows no `x509_panic_total` series at all.

```promql
# Any panic in the last hour, regardless of component
increase(x509_panic_total[1h]) > 0

# Has any source ever panicked since the process started
sum by (component) (x509_panic_total{component=~"source/.*"}) > 0
```

### `x509_exporter_build_info`

Constant gauge equal to `1`, whose label set carries the exporter's
build information.

- **Type**: gauge
- **Labels** (constant per build): `version`, `built` (build timestamp),
  `git_commit`, `go_runtime`, `go_os`, `go_arch`
- **Always emitted.**

The standard pattern for surfacing version skew in dashboards:

```promql
# Number of distinct exporter versions running across all replicas
count by (version) (x509_exporter_build_info)

# Pin alerts to a specific version (in case a rollout broke metric shape)
x509_cert_not_after * on(instance) group_left(version) x509_exporter_build_info
```

---

## Diagnostic metrics

Self-introspection of the exporter — parser latencies, Kubernetes-API
latencies, informer internals. Useful when troubleshooting the
exporter itself; pure noise during normal operations. The whole
family is gated by `metrics.exposeDiagnostics: true` and **off by
default**.

The chart values name is `exposeDiagnosticMetrics`. Flip it on
temporarily, scrape, investigate, flip it off.

### `x509_parse_duration_seconds`

Time spent parsing a single bundle (PEM block sequence, PKCS#12 archive,
etc.) into the internal certificate representation.

- **Type**: histogram
- **Labels**: `format`
- **Buckets**: `0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5` seconds
- **Emitted only when `metrics.exposeDiagnostics` is `true`.**

`format` takes one of `pem` or `pkcs12`. PKCS#12 is meaningfully slower
because of the KDF — expect millisecond-range parse times on PEM and
double-digit-millisecond on PKCS#12.

### `x509_kube_request_duration_seconds`

Latency of Kubernetes API requests issued by the exporter through
client-go. The metric is fed by client-go's
[`metrics.LatencyMetric`](https://pkg.go.dev/k8s.io/client-go/tools/metrics#LatencyMetric);
`verb` is the **HTTP method** (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`),
not the Kubernetes-style verb. Watches and lists both surface as `GET`.

- **Type**: histogram
- **Labels**: `verb` (HTTP method, uppercase), `resource` (last
  segment of the request path, e.g. `secrets`, `configmaps`,
  `namespaces`)
- **Buckets**: `0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30` seconds
- **Emitted only when `metrics.exposeDiagnostics` is `true`** (and only
  for Kubernetes sources).

```promql
# p95 GET latency to the API server, broken down by resource
histogram_quantile(0.95,
  sum by (le, resource) (
    rate(x509_kube_request_duration_seconds_bucket{verb="GET"}[5m])
  )
)

# Request rate by resource (Secrets vs ConfigMaps vs Namespaces) —
# useful to understand whether a chatty informer is responsible for
# the load on your apiserver
sum by (resource) (rate(x509_kube_request_duration_seconds_count[5m]))
```

### `x509_kube_informer_scope`

`1` for the scope mode the informer is currently running with, `0` for
every other mode. Useful when investigating whether the adaptive
cluster-vs-namespace logic chose what you expected for a given source.

- **Type**: gauge
- **Labels**: `source_name`, `scope`
- **Emitted only when `metrics.exposeDiagnostics` is `true`** (and only
  for Kubernetes sources).

`scope` takes one of `cluster` or `namespace`.

### `x509_informer_queue_depth`

Current depth of the informer's internal event queue. Sustained
non-zero values mean events are arriving faster than the exporter is
consuming them — usually a sign of an upstream burst (mass-rotation of
Secrets) rather than an exporter problem.

- **Type**: gauge
- **Labels**: `source_name`, `resource`
- **Emitted only when `metrics.exposeDiagnostics` is `true`** (and only
  for Kubernetes sources).

> ⚠ Same caveat as [`x509_kube_watch_resyncs_total`](#x509_kube_watch_resyncs_total):
> `source_name` is the constant `"kubernetes"`, not the user-defined
> source name.

---

## Reference

### Reason codes

Stable values for the `reason` label of `x509_source_errors_total`.
Reason names are exported as constants in
[`pkg/cert/reason.go`](../pkg/cert/reason.go) so external consumers
can pin to them.

The codes split into two groups: **bundle-level** errors emitted by
the configured sources (file, kubeconfig, kube-secret, kube-configmap)
and **transport-level** errors emitted by the Kubernetes client-go
metrics provider with the synthetic `source_kind="kubernetes"`,
`source_name="kube-api"` pair.

#### Bundle-level

| Reason | Emitted by | Cause |
| --- | --- | --- |
| `bad_pem` | any source running the PEM parser (file, kubeconfig, kube-secret with `format: pem`, kube-configmap) | PEM block present but malformed |
| `no_certificate_found` | same | The bundle decoded successfully but contained no `CERTIFICATE` block |
| `bad_pkcs12` | any source running the PKCS#12 parser (file with `formats: [pkcs12]`, kube-secret / kube-configmap with `format: pkcs12`) | PKCS#12 archive malformed or uses an unsupported algorithm |
| `bad_passphrase` | same | PKCS#12 archive structurally valid but the configured passphrase was wrong |
| `read_failed` | `file`, `kubeconfig` | Generic I/O error opening or reading a file |
| `permission_denied` | `file` | EACCES on a watched path |
| `not_found` | `file` | Path disappeared between announcement and read |
| `broken_symlink` | `file` | Symlink target is missing or unreachable |
| `walk_error` | `file` | Filesystem traversal under a `watchDirectories` entry failed |
| `decode_failed` | `kubeconfig` | Base64 decoding of an embedded `(client-)?certificate-data` field failed |

#### Transport-level (Kubernetes API)

Emitted with `source_kind="kubernetes"`, `source_name="kube-api"`
when client-go's HTTP round-trip surfaces a non-2xx response. These
exist regardless of how many user-defined Kubernetes sources are
configured — one synthetic series per reason code observed.

| Reason | Cause |
| --- | --- |
| `rate_limited` | HTTP 429 — the apiserver is throttling client-go (typically because the configured `rateLimit.qps` is too high or the apiserver is overloaded) |
| `http_401` | Unauthorized — token expired or service-account RBAC missing |
| `http_403` | Forbidden — RBAC denies the verb on the resource |
| `http_5xx` (where `xx` is the actual code: `http_500`, `http_502`, `http_503`, …) | Any 5xx response — the apiserver hit an internal error or its etcd backend is unreachable. Filter with `reason=~"http_5.."` in PromQL to catch all of them at once |

### Source kinds

| `source_kind` | YAML `kind:` | What it watches | Where it shows up |
| --- | --- | --- | --- |
| `file` | `file` | Files and directories on the exporter's filesystem | All metrics carrying `source_kind` |
| `kubeconfig` | `kubeconfig` | One or more kubeconfig YAML documents | All metrics carrying `source_kind` |
| `kube-secret` | `kubernetes` (Secret rules) | Kubernetes Secrets | All metrics carrying `source_kind` |
| `kube-configmap` | `kubernetes` (ConfigMap rules) | Kubernetes ConfigMaps | All metrics carrying `source_kind` |
| `kubernetes` | (none — synthetic) | Transport layer (client-go HTTP round-trips) | Only `x509_source_errors_total` (with `source_name="kube-api"`, see [transport-level reasons](#transport-level-kubernetes-api)) |

### Cardinality budget

The default per-cert label set carries 24 fixed slots (filename,
filepath, embedded_kind, embedded_key, secret_namespace, secret_name,
secret_key, configmap_namespace, configmap_name, configmap_key,
serial_number, six issuer fields, six subject fields, discriminator)
plus one slot per entry in `secrets.exposeLabels` /
`configMaps.exposeLabels`.

Total active series ≈ **(certs in scope) × (per-cert metrics enabled)**.
Worked example for a Kubernetes cluster with 5 000 watched certs and
the default config (`exposeExpired` on, the others off):

- 5 000 × 2 = 10 000 series for `x509_cert_not_after` + `x509_cert_expired`.
- ~30 series total across the per-source / health / diagnostic
  families.

Levers to bring this down, in order of impact:

1. **Narrow scope at the source.** `secrets.includeLabels`,
   `excludeNamespaces`, file globs that don't `**`-recurse — the metric
   isn't emitted at all, which beats every PromQL filter.
2. **Drop one or both per-cert gauges you don't query.**
   `metrics.exposeExpired: false` halves the per-cert series count
   if you alert only on `not_after - time()`. `exposeRelative: false`
   (the default) is already saving you 2× another duplication.
3. **Trim the DN field set** with `exposeSubjectFields` /
   `exposeIssuerFields`. This doesn't reduce series count (each cert
   still produces one series), but it reduces the per-series label
   payload — relevant if Prometheus's WAL or remote-write throughput
   is the bottleneck rather than series count.
4. **Skip `secret_label_*` / `configmap_label_*`** if your Secret
   labels include high-churn values (build IDs, timestamps). They
   don't multiply cardinality directly but a Secret label that
   changes between scrapes will leave behind stale series until
   they fall out of retention.

If your Prometheus is groaning under the cert load, attack lever #1
first.
