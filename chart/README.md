<!-- markdownlint-disable-next-line MD041 -->
<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://github.com/enix/x509-certificate-exporter/raw/main/docs/assets/logo2-dark.webp">
      <source media="(prefers-color-scheme: light)" srcset="https://github.com/enix/x509-certificate-exporter/raw/main/docs/assets/logo2.webp">
      <img alt="X.509 Certificate Exporter" title="X.509 Certificate Exporter" src="https://github.com/enix/x509-certificate-exporter/raw/main/docs/assets/logo2.webp">
    </picture>
</p>

<div align="center">

[![GitHub Release][release-img]][release] [![Cosign signed][cosign-img]][cosign] [![SLSA Level 3][slsa-img]][slsa] [![OpenSSF Scorecard][ossf-img]][ossf] [![Made at ENIX][enix-img]][enix]

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

</div>

A Prometheus exporter for X.509 certificates, built **for Kubernetes first**.
It watches your cluster's TLS material as native Kubernetes resources —
Secrets, ConfigMaps, kubeconfigs, on-disk PKI on the nodes — and turns
expirations into actionable Prometheus series. Designed to run inside the
cluster it observes, but equally happy as a standalone binary.

---

| [🚀 Quick install](#-quick-install) | [📚 Examples](#-examples--starting-points) | [🧩 Concepts](#-configuration-concepts) | [🛡️ Hardening](#%EF%B8%8F-supply-chain-verification) | [🎛️ Values](#%EF%B8%8F-values-reference) |
| --- | --- | --- | --- | --- |

> [!WARNING]
> **Upgrading from version 3?** Start with the [v3 → v4 migration guide][v3-v4]
> — chart distribution moved to OCI on `quay.io`, the Alpine image variant is
> retired, and a few values keys changed shape.

[v3-v4]: https://github.com/enix/x509-certificate-exporter/blob/main/docs/migration-v3-to-v4.md

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

## 🚀 Quick install

The chart ships as an OCI artifact on `quay.io` — no `helm repo add`,
Helm 3.8+ pulls OCI refs directly. One command:

```sh
helm -n monitoring install x509-certificate-exporter \
  oci://quay.io/enix/charts/x509-certificate-exporter
```

That's the whole install. The exporter starts watching every
`kubernetes.io/tls` Secret in the cluster and serves metrics on `/metrics`.

The chart also drops a `ServiceMonitor` and a `PrometheusRule` so a
[prometheus-operator][po]-managed Prometheus picks the exporter up and
ships with ready-to-use alerts — no extra wiring.

[po]: https://github.com/prometheus-operator/prometheus-operator

No prometheus-operator in the cluster? Skip the CRDs and let Prometheus
discover the Pod via annotations instead. Save the snippet below as
`values.yaml` and pass it to Helm with `--values values.yaml`:

```yaml
# values.yaml
prometheusServiceMonitor:
  create: false
prometheusRules:
  create: false
secretsExporter:
  podAnnotations:
    prometheus.io/port: "9793"
    prometheus.io/scrape: "true"
```

## 📚 Examples & starting points

A curated set of ready-to-adapt `values.yaml` files lives in
[`docs/examples/`][examples] — generic baselines (a fully tuned
secretsExporter, a rich hostPathsExporter with role-specific
DaemonSets) plus distribution-specific examples for kubeadm, Talos,
RKE2, k3s, k0s and OpenShift.

[examples]: https://github.com/enix/x509-certificate-exporter/blob/main/docs/examples/README.md

> [!TIP]
> The [project FAQ][faq] answers common questions, both Kubernetes-specific
> and about the exporter in general.

[faq]: https://github.com/enix/x509-certificate-exporter/blob/main/docs/faq.md

## 🛡️ Supply-chain verification

Curious how the chart and images are signed, or want to enforce that only
verified releases run in your cluster? The [hardening guide][hardening]
covers the territory:

- Immutable image-digest pinning via the chart's `image.digest` value
- cosign keyless signature verification (sigstore, Fulcio, Rekor)
- CycloneDX SBOM attestations on container images
- Strict certificate-identity pinning to the release workflow at a
  given tag
- Wiring cosign verification into CI pipelines and cluster admission
  (sigstore/policy-controller, Kyverno)

[hardening]: https://github.com/enix/x509-certificate-exporter/blob/main/docs/hardening.md

## 🧩 Configuration concepts

Every knob is documented in the [Values](#values) section below; this
prose just sketches *what each block lets you do*. Ready-to-adapt
`values.yaml` for the common shapes — including kubeadm, Talos, RKE2,
k3s, k0s, OpenShift, and a fully tuned `hostPathsExporter` with
role-split DaemonSets — lives in [`docs/examples/`][examples].

### Watching Secrets

The default install runs a single Deployment watching
`kubernetes.io/tls` Secrets across all namespaces — disable with
`secretsExporter.enabled: false`.

### Multiple Secret types and PKCS#12

`secretsExporter.secretTypes` accepts any mix of types and keys: a
literal `key` (regex `^<key>$` is built for you) or a `keyPatterns`
list for full regex control, with optional `format: pkcs12` plus a
`pkcs12:` block. Passphrases are pulled from a sibling Secret key
(`pkcs12.passphraseKey`), an external file, a cross-namespace Secret
ref, or skipped entirely with `tryEmptyPassphrase: true` for
passwordless keystores.

### Watching ConfigMaps

Set `secretsExporter.configMapKeys` to a list of data keys and
ConfigMaps are watched alongside Secrets. Series come out under
`configmap_namespace` / `configmap_name` / `configmap_key` instead of
the `secret_*` set — same `subject_CN`, `not_after`, alerts.

### Filtering by namespace and label

Four orthogonal axes evaluated server-side: namespace name (globs
supported), namespace label, Secret label, each with `include*` and
`exclude*` flavours under `secretsExporter.*`. `exclude*` runs after
`include*`. Namespace-label filters trigger Namespace watching too, so
membership re-evaluates whenever a namespace's labels change.

### Surfacing Secret labels as Prometheus labels

`secretsExporter.exposeSecretLabels` lifts selected Secret labels onto
every cert metric, prefixed with `secret_label_` —
e.g. `x509_cert_not_after{..., secret_label_environment="prod"}`.

### Metrics for node certificates (hostPath)

Cluster PKI (kubelet, etcd, kube-apiserver, kubeconfigs, …) is the
most common preventable outage source. `hostPathsExporter` deploys
DaemonSets with hostPath mounts so each node publishes metrics for its
own PKI. Defaults under `hostPathsExporter.*` cascade into every
`hostPathsExporter.daemonSets` entry, which can override individually
— spawn one DaemonSet per node role (control plane, ingress, …) with
its own `nodeSelector` / `tolerations` / watch list. Three watch knobs:

* `watchDirectories` — every PEM in a directory (no recursion)
* `watchFiles` — explicit paths (recommended when paths are predictable)
* `watchKubeconfFiles` — kubeconfigs with embedded or referenced PEMs

Distribution-specific starter values live in [`docs/examples/`][examples].

### Custom Resources for the Prometheus Operator

When [prometheus-operator][po] is installed, the chart creates a
`ServiceMonitor` (or `PodMonitor` if `podMonitor.create=true`) plus a
`PrometheusRule`. Without the operator's CRDs, Helm fails to render
them — disable with `prometheusServiceMonitor.create=false` and
`prometheusRules.create=false`.

The shipped alerts:

| Alert | Trigger | Severity |
|---|---|---|
| `X509ExporterReadErrors` | `delta(x509_source_errors_total[15m]) > 0` for 5m | warning |
| `CertificateError` | `x509_cert_error == 1` | warning |
| `CertificateRenewal` | `(x509_cert_not_after - time()) / 86400 < 28` | warning |
| `CertificateExpiration` | `(x509_cert_not_after - time()) / 86400 < 14` | critical |

Tunable via `prometheusRules.warningDaysLeft` / `criticalDaysLeft`;
disable any individually with
`prometheusRules.alertOn{ReadErrors,CertificateError,CertificateRenewal,CertificateExpiration}`.

> ⚠️ `X509ExporterReadErrors` is the early-warning canary for
> misconfigurations (RBAC, missing files, malformed Secrets). Keep it
> on, and split your `hostPathsExporter` DaemonSets along role
> boundaries rather than disabling the alert.

### Securing the `/metrics` endpoint

v4 supports `prometheus/exporter-toolkit` natively — set
`webConfiguration` to a [web-config][web-config] body (TLS cert/key,
BasicAuth users) and the chart wires a Secret + volume mount +
`--web.config.file`. Use `webConfigurationExistingSecret` to point at
an existing Secret instead.

The legacy `kube-rbac-proxy` sidecar (`rbacProxy.enabled`) is still
available for clusters authenticating scrapes via TokenReview, but
exporter-toolkit is the recommended path on new installs.

[web-config]: https://prometheus.io/docs/prometheus/latest/configuration/https/

# 🎛️ Values reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| nameOverride | string | `""` | Partially override x509-certificate-exporter.fullname template (will prepend the release name) |
| fullnameOverride | string | `""` | Fully override x509-certificate-exporter.fullname template |
| namespaceOverride | string | `""` | Override the deployment namespace |
| extraDeploy | list | `[]` | Additional objects to deploy with the release |
| extraDeployVerbatim | list | `[]` | Same as `extraDeploy` but objects won't go through the templating engine |
| imagePullSecrets | list | `[]` | Specify docker-registry secret names as an array |
| image.registry | string | `"quay.io"` | Exporter image registry |
| image.repository | string | `"enix/x509-certificate-exporter"` | Exporter image repository |
| image.tag | string | `""` | Exporter image tag (defaults to Chart appVersion) |
| image.tagSuffix | string | `""` | Appended to the image tag to select a container flavor. Use `-busybox` for a shell-enabled image |
| image.digest | string | `""` | Exporter image digest. When set, takes precedence over `tag` (immutable reference) |
| image.pullPolicy | string | `"IfNotPresent"` | Exporter image pull policy |
| migration.image.registry | string | `"registry.k8s.io"` | kubectl image registry |
| migration.image.repository | string | `"kubectl"` | kubectl image repository |
| migration.image.tag | string | `""` | kubectl image tag. When set, takes precedence over the auto-detected cluster version. |
| migration.image.digest | string | `""` | kubectl image digest. When set, takes precedence over `tag` (immutable reference) |
| migration.image.pullPolicy | string | `"IfNotPresent"` | kubectl image pull policy |
| migration.annotations | object | `{}` | Annotations added to Helm hook Pods |
| migration.extraLabels | object | `{}` | Additional labels added to Helm hook Pods |
| migration.resources | object | see `values.yaml` | ResourceRequirements for containers of Helm hooks |
| migration.podSecurityContext | object | see `values.yaml` | PodSecurityContext for Pods of Helm hooks |
| migration.securityContext | object | see `values.yaml` | SecurityContext for containers of Helm hooks |
| exposePerCertificateErrorMetrics | bool | `false` | Enable additional metrics to report per-certificate errors ; helps with identifying the origin of read errors without having to look at exporter logs, at the expense of additional storage on Prometheus |
| exposeRelativeMetrics | bool | `false` | Enable additional metrics with relative durations instead of absolute timestamps ; not recommended with Prometheus |
| exposeNotBeforeMetric | bool | `false` | Expose `x509_cert_not_before` (Unix timestamp of the certificate's NotBefore). Off by default — most users only alert on expiry; enable if you specifically need to detect "issued in the future" misconfigurations or clock skew. |
| exposeExpiredMetric | bool | `true` | Expose `x509_cert_expired` (1 if the certificate is expired, 0 otherwise). On by default ; turn off to halve the per-cert series count if you only alert on `x509_cert_not_after - time()`. |
| exposeDiagnosticMetrics | bool | `false` | Expose self-introspection metrics for debugging the exporter itself (`x509_parse_duration_seconds`, `x509_kube_request_duration_seconds`, `x509_kube_informer_scope`, `x509_informer_queue_depth`). Off by default ; enable when you actually need to look inside. |
| metricLabelsFilterList | list | `nil` | Restrict metric labels to this list if set. **Warning** : use with caution as reducing cardinality may yield metrics collisions and force the exporter to ignore certificates. This will also degrade the usability of the Grafana dashboard. This list should always include at least `filepath`, `secret_namespace` and `secret_name`. Also `subject_CN` is highly recommended for when a file contains multiple certificates. |
| grafana.createDashboard | bool | `false` | Should the Grafana dashboard be deployed as a ConfigMap (requires Grafana sidecar) |
| grafana.sidecarLabel | string | `"grafana_dashboard"` | ConfigMap label name the Grafana sidecar is looking for |
| grafana.sidecarLabelValue | string | `"1"` | ConfigMap label value the Grafana sidecar is looking for |
| grafana.annotations | object | `{}` | Annotations added to the Grafana dashboard ConfigMap (example in `values.yaml`) |
| grafana.extraLabels | object | `{}` | Additional labels added to the Grafana dashboard ConfigMap |
| secretsExporter.enabled | bool | `true` | Should the TLS Secrets exporter be running |
| secretsExporter.annotations | object | `{}` | Additional Deployment annotations |
| secretsExporter.debugMode | bool | `false` | Should debug messages be produced by the TLS Secrets exporter |
| secretsExporter.replicas | int | `1` | Desired number of TLS Secrets exporter Pods |
| secretsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of the TLS Secrets exporter |
| secretsExporter.strategy | object | `{}` | DeploymentStrategy for the TLS Secrets exporter |
| secretsExporter.revisionHistoryLimit | int | `nil` | Number of old ReplicaSets to retain for rollback |
| secretsExporter.resources | object | see `values.yaml` | ResourceRequirements for containers of the TLS Secrets exporter |
| secretsExporter.readinessProbe | object | see `values.yaml` | Readiness probe definition for the secrets exporter (.httpGet cannot be changed) |
| secretsExporter.livenessProbe | object | see `values.yaml` | Liveness probe definition for the secrets exporter (.httpGet cannot be changed) |
| secretsExporter.nodeSelector | object | `{}` | Node selector for Pods of the TLS Secrets exporter |
| secretsExporter.tolerations | list | `[]` | Tolerations for Pods of the TLS Secrets exporter |
| secretsExporter.affinity | object | `{}` | Affinity for Pods of the TLS Secrets exporter |
| secretsExporter.priorityClassName | string | `""` | PriorityClassName for Pods of the TLS Secrets exporter |
| secretsExporter.podExtraLabels | object | `{}` | Additional labels added to Pods of the TLS Secrets exporter |
| secretsExporter.podAnnotations | object | `{}` | Annotations added to Pods of the TLS Secrets exporter |
| secretsExporter.podSecurityContext | object | see `values.yaml` | PodSecurityContext for Pods of the TLS Secrets exporter |
| secretsExporter.securityContext | object | see `values.yaml` | SecurityContext for containers of the TLS Secrets exporter |
| secretsExporter.extraVolumes | list | `[]` | Additional volumes added to Pods of the TLS Secrets exporter (combined with global `extraVolumes`) |
| secretsExporter.extraVolumeMounts | list | `[]` | Additional volume mounts added to Pod containers of the TLS Secrets exporter (combined with global `extraVolumeMounts`) |
| secretsExporter.secretTypes | list | see `values.yaml` | Which type of Secrets should be watched. Each entry takes either `key` (a single Secret data key — the matching regex `^<key>$` is built for you) or `keyPatterns` (a list of regexes, full control). Optional `format` is "pem" (default) or "pkcs12"; `pkcs12` block accepts `passphrase`, `passphraseKey` (read passphrase from a sibling key in the same Secret), `passphraseFile`, `passphraseSecretRef`, `tryEmptyPassphrase`. |
| secretsExporter.configMapKeys | list | see `values.yaml` | If the exporter should watch for certificates in ConfigMaps, just specify the keys it needs to watch. E.g.: `configMapKeys: ["tls.crt"]` |
| secretsExporter.includeNamespaces | list | `[]` | Restrict the list of namespaces the TLS Secrets exporter should scan for certificates to watch (all namespaces if empty) |
| secretsExporter.excludeNamespaces | list | `[]` | Exclude namespaces from being scanned by the TLS Secrets exporter (evaluated after `includeNamespaces`) |
| secretsExporter.includeNamespaceLabels | list | `[]` | Only watch namespaces having these labels (all namespaces if empty). Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.excludeNamespaceLabels | list | `[]` | Exclude namespaces having these labels. Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.includeLabels | list | `[]` | Only watch TLS Secrets having these labels (all secrets if empty). Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.excludeLabels | list | `[]` | Exclude TLS Secrets having these labels. Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.exposeSecretLabels | list | `[]` | Expose selected labels from Kubernetes Secrets as Prometheus labels. **Beware of high-cardinality labels** (e.g. `pod-template-hash`, `controller-revision-hash`, build/git SHAs, timestamps, request IDs): each unique value adds a fresh series for every certificate metric, which can quickly explode the Prometheus index. Stick to slow-changing identifiers (app, team, environment, owner). |
| secretsExporter.exposeConfigMapLabels | list | `[]` | Expose selected labels from Kubernetes ConfigMaps as Prometheus labels. Same caveat as `exposeSecretLabels` — keep the list to slow-changing identifiers and avoid high-cardinality values. |
| secretsExporter.extraArgs | list | `[]` | Additional arguments to append to the exporter command line. E.g.: `--watch-file="/extra-cert/tls.crt"`. |
| secretsExporter.cache.enabled | bool | `true` | Enable caching of Kubernetes objects to prevent scraping timeouts |
| secretsExporter.cache.maxDuration | int | `300` | Maximum time an object can stay in cache unrefreshed (seconds) - it will be at least half of that |
| secretsExporter.kubeApiRateLimits.enabled | bool | `false` | Should requests to the Kubernetes API server be rate-limited |
| secretsExporter.kubeApiRateLimits.queriesPerSecond | int | `5` | Maximum rate of queries sent to the API server (per second) |
| secretsExporter.kubeApiRateLimits.burstQueries | int | `10` | Burst bucket size for queries sent to the API server |
| secretsExporter.listPageSize | int | `0` | Page size used by the paginated initial LIST against the Kubernetes API. The exporter processes each page inline and releases it to the GC before fetching the next, so peak memory during sync is roughly proportional to this × average secret size. Default `50` is conservative enough to keep the pod under 100 Mi even on clusters with many large Helm release secrets; raise it for faster sync on smaller objects, lower it on memory-constrained pods. `0` keeps the built-in default. |
| secretsExporter.env | list | `[]` | Additional environment variables for containers |
| hostPathsExporter.annotations | object | `{}` | Additional DaemonSet annotations |
| hostPathsExporter.debugMode | bool | `false` | Should debug messages be produced by hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.skipSymlinks | bool | `false` | Skip symlinks when scanning files and directories. Does not apply to Kubernetes secrets. |
| hostPathsExporter.refreshInterval | string | `"300s"` | Polling interval at which the file source re-walks watched paths and re-parses changed files. Accepts a Go duration (e.g. `30s`, `5m`). Default is suited for slowly-rotated PKI; lower it for tests or fast-rotation flows. |
| hostPathsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.updateStrategy | object | `{}` | updateStrategy for DaemonSets of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.revisionHistoryLimit | int | `nil` | Number of old ReplicaSets to retain for rollback (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.resources | object | see `values.yaml` | ResourceRequirements for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.readinessProbe | object | see `values.yaml` | Readiness probe definition for the host paths exporter (.httpGet cannot be changed) |
| hostPathsExporter.livenessProbe | object | see `values.yaml` | Liveness probe definition for the host paths exporter (.httpGet cannot be changed) |
| hostPathsExporter.nodeSelector | object | `{}` | Node selector for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.tolerations | list | `[]` | Tolerations for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.affinity | object | `{}` | Affinity for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.priorityClassName | string | `""` | PriorityClassName for Pods of hostPath exporters |
| hostPathsExporter.podExtraLabels | object | `{}` | Additional labels added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podAnnotations | object | `{}` | Annotations added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podSecurityContext | object | see `values.yaml` | PodSecurityContext for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.securityContext | object | see `values.yaml` | SecurityContext for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.extraVolumes | list | `[]` | Additional volumes added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets ; combined with global `extraVolumes`) |
| hostPathsExporter.extraVolumeMounts | list | `[]` | Additional volume mounts added to Pod containers of hostPath exporters (default for all hostPathsExporter.daemonSets ; combined with global `extraVolumeMounts`) |
| hostPathsExporter.hostPathVolumeType | string | `"Directory"` | Type for HostPath volumes used with watched paths. Can be set to `""` or null to use Kubernetes defaults. May be required with RKE if Pods don't start. |
| hostPathsExporter.watchDirectories | list | `[]` | [SEE README] List of directory paths of the host to scan for PEM encoded certificate files to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchSpecificExtensionDirectories | list | `[]` | [SEE README] List of directory paths of the host to scan for specific extension files to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchFiles | list | `[]` | [SEE README] List of file paths of the host for PEM encoded certificates to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchKubeconfFiles | list | `[]` | [SEE README] List of Kubeconf file paths of the host to scan for embedded certificates to export metrics about |
| hostPathsExporter.env | list | `[]` | Additional environment variables for containers |
| hostPathsExporter.daemonSets | object | `{}` | [SEE README] Map to define one or many DaemonSets running hostPath exporters. Key is used as a name ; value is a map to override all default settings set by `hostPathsExporter.*`. |
| podListenPort | int | `9793` | TCP port to expose Pods on (whether kube-rbac-proxy is enabled or not) |
| probeListenPort | int | `0` | TCP port for a separate plain-HTTP server exposing only `/healthz` and `/readyz`, used as the kubelet probe target. `0` disables it; the chart auto-enables `8080` when the main `/metrics` port is auth-gated (`webConfiguration` set or `rbacProxy.enabled`), so kubelet probes can succeed without a TLS / mTLS / Bearer credential. Set explicitly to override the auto-default. |
| hostNetwork | bool | `false` | Enable hostNetwork mode. Useful when Prometheus is deployed outside of the Kubernetes cluster |
| web.enableStats | bool | `true` | Expose internal cache statistics via HTML on the root endpoint (/) |
| webConfiguration | string | `""` | HTTP server configuration for enabling TLS and authentication (password, mTLS) ; see [documentation at Exporter Toolkit](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) |
| webConfigurationExistingSecret | string | `""` | Load the HTTP server configuration from an existing Secret instead of `webConfiguration`. Key must be `webconfig.yaml`. |
| service.create | bool | `true` | Should a Service be installed, targeting all Deployment and DaemonSet instances (required for ServiceMonitor) |
| service.headless | bool | `true` | Should the Service be headless (`clusterIP: None`). |
| service.port | int | `9793` | TCP port to expose the Service on |
| service.annotations | object | `{}` | Annotations to add to the Service |
| service.extraLabels | object | `{}` | Additional labels to add to the Service |
| prometheusServiceMonitor.create | bool | `true` | Should a ServiceMonitor object be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusServiceMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the ServiceMonitor |
| prometheusServiceMonitor.scrapeTimeout | string | `"30s"` | Target scrape timeout set in the ServiceMonitor |
| prometheusServiceMonitor.extraLabels | object | `{}` | Additional labels to add to ServiceMonitor objects |
| prometheusServiceMonitor.extraAnnotations | object | `{}` | Additional annotations to add to ServiceMonitor objects |
| prometheusServiceMonitor.metricRelabelings | list | `[]` | Metric relabel config for the ServiceMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusServiceMonitor.relabelings | list | `[]` | Relabel config for the ServiceMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusServiceMonitor.scheme | string | `"http"` | Scheme config for the ServiceMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusServiceMonitor.tlsConfig | object | `{}` | Custom TLS configuration, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.TLSConfig |
| prometheusPodMonitor.create | bool | `false` | Should a PodMonitor object be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusPodMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the PodMonitor |
| prometheusPodMonitor.scrapeTimeout | string | `"30s"` | Target scrape timeout set in the PodMonitor |
| prometheusPodMonitor.extraLabels | object | `{}` | Additional labels to add to PodMonitor objects |
| prometheusPodMonitor.metricRelabelings | list | `[]` | Metric relabel config for the PodMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusPodMonitor.relabelings | list | `[]` | Relabel config for the PodMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusPodMonitor.scheme | string | `"http"` | Scheme config for the PodMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusPodMonitor.tlsConfig | object | `{}` | Custom TLS configuration, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.TLSConfig |
| prometheusRules.create | bool | `true` | Should a PrometheusRule object be installed to alert on certificate expiration. For prometheus-operator (kube-prometheus) users. |
| prometheusRules.alertOnReadErrors | bool | `true` | Should the X509ExporterReadErrors alerting rule be created to notify when the exporter can't read files or authenticate with the Kubernetes API. It aims at preventing undetected misconfigurations and monitoring regressions. |
| prometheusRules.readErrorsSeverity | string | `"warning"` | Severity for the X509ExporterReadErrors alerting rule |
| prometheusRules.alertOnCertificateErrors | bool | `true` | Should the CertificateError alerting rule be created to notify when the exporter can't decode or process a certificate. Depends on `exposePerCertificateErrorMetrics` to be enabled too. |
| prometheusRules.certificateErrorsSeverity | string | `"warning"` | Severity for the CertificateError alerting rule |
| prometheusRules.certificateRenewalsSeverity | string | `"warning"` | Severity for the CertificateRenewal alerting rule |
| prometheusRules.certificateExpirationsSeverity | string | `"critical"` | Severity for the CertificateExpiration alerting rule |
| prometheusRules.warningDaysLeft | int | `28` | Raise a warning alert when this few days are left before a certificate expiration (cert-manager would renew Let's Encrypt certs before day 29) |
| prometheusRules.criticalDaysLeft | int | `14` | Raise a critical alert when this few days are left before a certificate expiration (two weeks to deal with ACME rate limiting should this be an issue) |
| prometheusRules.extraLabels | object | `{}` | Additional labels to add to PrometheusRule objects |
| prometheusRules.alertExtraLabels | object | `{}` | Additional labels to add to PrometheusRule rules |
| prometheusRules.alertExtraAnnotations | object | `{}` | Additional annotations to add to PrometheusRule rules |
| prometheusRules.rulePrefix | string | `""` | Additional rulePrefix to PrometheusRule rules |
| prometheusRules.disableBuiltinAlertGroup | bool | `false` | Skip all built-in alerts when using extraAlertGroups |
| prometheusRules.extraAlertGroups | list | `[]` | Additional alert groups for custom configuration (example in `values.yaml`) |
| extraLabels | object | `{}` | Additional labels added to all chart objects |
| podExtraLabels | object | `{}` | Additional labels added to all Pods |
| podAnnotations | object | `{}` | Annotations added to all Pods |
| priorityClassName | string | `""` | PriorityClassName set for all Pods by default (can be overridden with `secretsExporter` and `hostPathsExporter` specific values) |
| extraVolumes | list | `[]` | Additional volumes added to all Pods (see also the `secretsExporter` and `hostPathsExporter` variants) |
| extraVolumeMounts | list | `[]` | Additional volume mounts added to all Pod containers (see also the `secretsExporter` and `hostPathsExporter` variants) |
| psp.create | bool | `false` | Should Pod Security Policy objects be created |
| rbac.create | bool | `true` | Should RBAC objects be created |
| rbac.secretsExporter.serviceAccountName | string | `nil` | Name of the ServiceAccount for the Secrets exporter (required if `rbac.create=false`) |
| rbac.secretsExporter.serviceAccountAnnotations | object | `{}` | Annotations added to the ServiceAccount for the Secrets exporter |
| rbac.secretsExporter.clusterRoleAnnotations | object | `{}` | Annotations added to the ClusterRole for the Secrets exporter |
| rbac.secretsExporter.clusterRoleBindingAnnotations | object | `{}` | Annotations added to the ClusterRoleBinding for the Secrets exporter |
| rbac.hostPathsExporter.serviceAccountName | string | `nil` | Name of the ServiceAccount for hostPath exporters (required if `rbac.create=false`) |
| rbac.hostPathsExporter.serviceAccountAnnotations | object | `{}` | Annotations added to the ServiceAccount for the hostPath exporters |
| rbac.hostPathsExporter.clusterRoleAnnotations | object | `{}` | Annotations added to the ClusterRole for the hostPath exporters |
| rbac.hostPathsExporter.clusterRoleBindingAnnotations | object | `{}` | Annotations added to the ClusterRoleBinding for the hostPath exporters |
| rbacProxy.enabled | bool | `false` | Should kube-rbac-proxy be used to expose exporters |
| rbacProxy.tls.existingSecretName | string | `""` | Pre-provisioned Secret carrying `tls.crt` + `tls.key` for the kube-rbac-proxy serving cert. When empty, the chart auto-generates a self-signed cert at install time and reuses it across upgrades via `lookup`. Set this to a cert-manager-managed Secret (or similar) for a cert with a real chain you can rotate independently. |
| rbacProxy.image.registry | string | `"quay.io"` | kube-rbac-proxy image registry |
| rbacProxy.image.repository | string | `"brancz/kube-rbac-proxy"` | kube-rbac-proxy image repository |
| rbacProxy.image.tag | string | `"v0.22.0"` | kube-rbac-proxy image tag |
| rbacProxy.image.digest | string | `""` | kube-rbac-proxy image digest. When set, takes precedence over `tag` (immutable reference) |
| rbacProxy.image.pullPolicy | string | `"IfNotPresent"` | kube-rbac-proxy image pull policy |
| rbacProxy.upstreamListenPort | int | `9091` | Listen port for the exporter running inside kube-rbac-proxy exposed Pods |
| rbacProxy.resources | object | see `values.yaml` | ResourceRequirements for all containers of kube-rbac-proxy |
| rbacProxy.securityContext | object | see `values.yaml` | SecurityContext for all containers of kube-rbac-proxy |
