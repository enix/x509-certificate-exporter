# Metrics

Every metric exposed by the exporter, with its label schema, the conditions
under which it is emitted, and worked PromQL examples where useful.

The exporter splits its output into four families:

- **Per-certificate metrics** — one series per certificate found, dense
  label set. The bread-and-butter of expiry alerts.
- **Per-source metrics** — one series per configured source. The right
  lens for "is this watcher healthy".
- **Health and process metrics** — cardinality-1 series describing the
  exporter process itself, independent of the data it watches.
- **Internal informer metrics** — low-level Kubernetes informer counters
  for debugging cache and watch behavior. Safe to ignore in normal
  operations.

## At a glance

| Family | Metric | Type | Gating |
| --- | --- | --- | --- |
| Per-certificate | `x509_cert_not_before` | gauge | always |
| Per-certificate | `x509_cert_not_after` | gauge | always |
| Per-certificate | `x509_cert_expired` | gauge | always |
| Per-certificate | `x509_cert_expires_in_seconds` | gauge | `metrics.exposeRelative: true` |
| Per-certificate | `x509_cert_valid_since_seconds` | gauge | `metrics.exposeRelative: true` |
| Per-certificate | `x509_cert_error` | gauge | `metrics.exposePerCertError: true` |
| Per-source | `x509_source_up` | gauge | always |
| Per-source | `x509_source_bundles` | gauge | always |
| Per-source | `x509_source_errors_total` | counter | always |
| Per-source | `x509_kube_watch_resyncs_total` | counter | Kubernetes sources only |
| Per-source | `x509_pkcs12_passphrase_failures_total` | counter | always |
| Per-source | `x509_kube_request_duration_seconds` | histogram | Kubernetes sources only |
| Per-source | `x509_parse_duration_seconds` | histogram | always |
| Per-source | `x509_cert_collision_total` | counter | always |
| Health | `x509_scrape_duration_seconds` | histogram | always |
| Health | `x509_panic_total` | counter | always |
| Health | `x509_exporter_build_info` | gauge | always |
| Internal | `x509_kube_informer_scope` | gauge | Kubernetes sources only |
| Internal | `x509_informer_queue_depth` | gauge | Kubernetes sources only |

## Common labels (per-certificate metrics)

Per-certificate metrics share a single label schema. Labels that don't
apply to a given series are emitted as the empty string `""` so that
PromQL aggregation across heterogeneous source kinds works.

| Label | Always present | Notes |
| --- | --- | --- |
| `serial_number` | yes | Decimal serial number of the certificate |
| `subject_C`, `subject_ST`, `subject_L`, `subject_O`, `subject_OU`, `subject_CN` | yes | Subject DN fields. Subset configurable via `metrics.exposeSubjectFields` |
| `issuer_C`, `issuer_ST`, `issuer_L`, `issuer_O`, `issuer_OU`, `issuer_CN` | yes | Issuer DN fields. Subset configurable via `metrics.exposeIssuerFields` |
| `filename`, `filepath` | file / kubeconfig only | Path in the container's filesystem |
| `embedded_kind`, `embedded_key` | kubeconfig only | Whether the cert came from a `cluster` or `user` block, and the YAML key |
| `secret_namespace`, `secret_name`, `secret_key` | `kube-secret` only | Identifies the Secret and the data key within it |
| `configmap_namespace`, `configmap_name`, `configmap_key` | `kube-configmap` only | Same, for ConfigMaps |
| `secret_label_*` | `kube-secret`, optional | One label per name in `metrics.exposeSecretLabels` |
| `configmap_label_*` | `kube-configmap`, optional | One label per name in `metrics.exposeConfigMapLabels` |
| `discriminator` | conditional | Added when `metrics.collisionDiscriminator` resolves a label collision (see [`x509_cert_collision_total`](#x509_cert_collision_total)) |

Use `metrics.trimPathComponents` to strip leading directory components
from `filepath` if you want shorter labels — say, drop
`/etc/letsencrypt/live/` from every series.

---

## Per-certificate metrics

### `x509_cert_not_before`

Unix timestamp of the certificate's `NotBefore` field.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Always emitted.**

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

# Anything currently expired or expiring in the next 7 days,
# excluding the trust roots in the kube-public namespace
(
  (x509_cert_not_after - time()) < 7 * 86400
)
unless on(serial_number) (
  x509_cert_not_after{secret_namespace="kube-public"}
)
```

### `x509_cert_expired`

`1` if the cert is currently expired (`now > NotAfter`), `0` otherwise.

- **Type**: gauge
- **Labels**: see [common labels](#common-labels-per-certificate-metrics)
- **Always emitted.**

This is a convenience: `x509_cert_expired == 1` is equivalent to
`x509_cert_not_after < time()`. Use whichever reads better in your alerts.

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
informers running, files first scanned), `0` before that or after a
fatal error.

- **Type**: gauge
- **Labels**: `source_kind`, `source_name`
- **Always emitted** (one series per declared source, from boot).

```promql
# Any source that is still down 60s after boot
x509_source_up == 0
  and on(source_name) (time() - process_start_time_seconds) > 60
```

### `x509_source_bundles`

Number of bundles currently held by the source. A "bundle" is one
addressable unit — a Secret, a ConfigMap, a file path. The number of
*certificates* may be larger if a single bundle holds a chain.

- **Type**: gauge
- **Labels**: `source_kind`, `source_name`
- **Always emitted.**

This is the right metric to size cluster-wide informer caches against
— if it's an order of magnitude bigger than expected, your label
selectors are too loose.

### `x509_source_errors_total`

Per-source error counter, broken down by reason code.

- **Type**: counter
- **Labels**: `source_kind`, `source_name`, `reason`
- **Always emitted.**

The `reason` label takes one of a stable set of values; see the
[reason codes reference](#reason-codes) below.

```promql
# Anything erroring at all
increase(x509_source_errors_total[15m]) > 0

# Just passphrase-related errors on PKCS#12 sources
increase(x509_source_errors_total{reason="bad_passphrase"}[15m]) > 0

# Filesystem walk errors (broken symlink, permission denied)
increase(x509_source_errors_total{reason=~"walk_error|broken_symlink|permission_denied"}[15m]) > 0
```

### `x509_kube_watch_resyncs_total`

Number of forced informer resyncs — typically caused by a
`watch expired` or HTTP `410 Gone` from the API server.

- **Type**: counter
- **Labels**: `source_name`, `resource`
- **Emitted only for Kubernetes sources** (`kind: kubernetes`).

`resource` is the API resource being watched (`secrets` or
`configmaps`). A steady increase here is a sign of an unhappy
informer — flapping API server, network instability, or a watch cache
too small on the apiserver side. A few per hour is normal; dozens per
minute warrants investigation.

### `x509_pkcs12_passphrase_failures_total`

PKCS#12 keystore decoding attempts that failed because the passphrase
was wrong.

- **Type**: counter
- **Labels**: `source_name`
- **Always emitted** (the metric exists from boot; it stays at `0` for
  sources that don't handle PKCS#12).

A spike usually means a Secret was rotated but the sibling passphrase
key wasn't, or a `passphraseFile` was stale.

### `x509_kube_request_duration_seconds`

Latency of Kubernetes API requests issued by the exporter through
client-go.

- **Type**: histogram
- **Labels**: `verb`, `resource`
- **Buckets**: `0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30` seconds
- **Emitted only for Kubernetes sources.**

```promql
# 95th percentile latency for LIST requests in the last 5 minutes
histogram_quantile(0.95,
  sum by (le, resource) (
    rate(x509_kube_request_duration_seconds_bucket{verb="list"}[5m])
  )
)
```

### `x509_parse_duration_seconds`

Time spent parsing a single bundle (PEM block sequence, PKCS#12 archive,
etc.) into the internal certificate representation.

- **Type**: histogram
- **Labels**: `format`
- **Buckets**: `0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5` seconds
- **Always emitted.**

`format` takes one of `pem` or `pkcs12`. PKCS#12 is meaningfully slower
because of the KDF — expect millisecond-range parse times on PEM and
double-digit-millisecond on PKCS#12.

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
- **Labels**: `component`
- **Always emitted.**

```promql
# Any panic since the process started
increase(x509_panic_total[1h]) > 0
```

### `x509_exporter_build_info`

Constant gauge equal to `1`, whose label set carries the exporter's
build information.

- **Type**: gauge
- **Labels** (constant per build): `version`, `revision`, `branch`,
  `go_version`, `tags`
- **Always emitted.**

The standard pattern for surfacing version skew in dashboards:

```promql
# Number of distinct exporter versions running across all instances
count by (version) (x509_exporter_build_info)
```

---

## Internal informer metrics

These two gauges are aimed at debugging Kubernetes informer behavior. In
normal operations they're noise; ignore them unless you're chasing a
specific cache or watch problem.

### `x509_kube_informer_scope`

`1` for the scope mode the informer is currently running with, `0` for
every other mode. Useful when investigating whether the adaptive
cluster-vs-namespace logic chose what you expected for a given source.

- **Type**: gauge
- **Labels**: `source_name`, `scope`
- **Emitted only for Kubernetes sources.**

`scope` takes one of `cluster` or `namespace`.

### `x509_informer_queue_depth`

Current depth of the informer's internal event queue. Sustained
non-zero values mean events are arriving faster than the exporter is
consuming them — usually a sign of an upstream burst (mass-rotation of
Secrets) rather than an exporter problem.

- **Type**: gauge
- **Labels**: `source_name`, `resource`
- **Emitted only for Kubernetes sources.**

---

## Reference

### Reason codes

Stable values for the `reason` label of `x509_source_errors_total`.
Defined as exported constants in
[`pkg/cert/reason.go`](../pkg/cert/reason.go), so external consumers
can pin to them.

| Reason | Source kinds | Cause |
| --- | --- | --- |
| `bad_pem` | all | PEM block present but malformed |
| `bad_pkcs12` | file, `kube-secret` | PKCS#12 archive malformed or unsupported algorithm |
| `bad_passphrase` | file, `kube-secret` | PKCS#12 archive readable but passphrase wrong |
| `no_certificate_found` | all | The bundle decoded but contained no `CERTIFICATE` block |
| `read_failed` | file | Generic I/O error reading a file |
| `permission_denied` | file | EACCES on a watched path |
| `not_found` | file, `kube-secret`, `kube-configmap` | Path or object disappeared after being announced |
| `broken_symlink` | file | Symlink target missing |
| `walk_error` | file | Filesystem traversal failed |
| `parse_timeout` | file, `kube-secret` | Per-bundle parse took longer than the configured timeout |
| `decode_failed` | `kube-secret`, `kube-configmap` | Base64 / data-key decoding failed |
| `api_error` | `kube-secret`, `kube-configmap` | Kubernetes API call failed (transient API errors are retried; this counter increments only when the source bubbles the error up) |

### Source kinds

| `source_kind` | YAML `kind:` | What it watches |
| --- | --- | --- |
| `file` | `file` | Files and directories on the exporter's filesystem |
| `kubeconfig` | `kubeconfig` | One or more kubeconfig YAML documents |
| `kube-secret` | `kubernetes` (Secret rules) | Kubernetes Secrets |
| `kube-configmap` | `kubernetes` (ConfigMap rules) | Kubernetes ConfigMaps |

### Cardinality budget

Default per-cert label set has a few dozen entries. The biggest drivers
of cardinality:

- The number of distinct certs in scope (one series per cert and per
  per-cert metric).
- The number of distinct values for `subject_*` and `issuer_*` fields
  combined — long-tail trust roots inflate this.
- Optional `secret_label_*` / `configmap_label_*` if you surface labels
  with high-cardinality values.

If your Prometheus is groaning under the cert load, narrow scope at the
source (label/namespace selectors) before tuning what's exposed.
