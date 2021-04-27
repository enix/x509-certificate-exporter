<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
# 🔏 X.509 Certificate Exporter

<<<<<<< HEAD
[![Build status](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/pipeline.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Code coverage](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/coverage.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Go Report](https://goreportcard.com/badge/github.com/enix/x509-certificate-exporter)](https://goreportcard.com/report/github.com/enix/x509-certificate-exporter)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go. Designed to monitor Kubernetes clusters from inside, it can also be used as a standalone exporter.
=======
# 🔏 X.509 Exporter
=======
# 🔏 X.509 Certificates Exporter
>>>>>>> f516475 (doc(x509-certificate-exporter): fix project name in README header 2/2)
=======
# 🔏 X.509 Certificate Exporter
>>>>>>> ad808db (doc(x509-certificate-exporter): update badges)

<p style="text-align: center;">

=======
>>>>>>> 84c506b (doc(x509-certificate-exporter): remove HTML align for badges)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go with cloud deployments in mind.
>>>>>>> 3bcfe63 (doc(x509-certificate-exporter): no deprecation message in newer package)

Get notified before they expire:
<<<<<<< HEAD

- PEM encoded files, by path or scanning directories
- Kubeconfigs with embedded certificates or file references
- TLS Secrets from a Kubernetes cluster
=======
* TLS Secrets from a Kubernetes cluster
* PEM encoded files, by path or scanning directories
* Kubeconfigs with embedded certificates or file references
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)

The following metrics are available:

- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expired`
- `x509_read_errors`

Best when used with the [Grafana Dashboard](https://grafana.com/grafana/dashboards/13922) ID `13922`:

![Grafana Dashboard](https://raw.githubusercontent.com/enix/x509-certificate-exporter/master/docs/grafana-dashboard.jpg)

## 🏃 TL;DR

It only takes two commands to install x509-certificate-exporter, however you should read the instructions in the next section to
take advantage of all the features!

Add our Charts repository :

```
$ helm repo add enix https://charts.enix.io
```

Install x509-certificate-exporter for TLS Secrets monitoring with prometheus-operator support :

```
$ helm install x509-certificate-exporter enix/x509-certificate-exporter
```

To remove built-in Prometheus alerts if you'd rather craft your own :

```
$ helm upgrade x509-certificate-exporter enix/x509-certificate-exporter --reuse-values --set prometheusRules.create=false
```

If you don't use the Prometheus operator at all, and don't have the CRD, disable resource creation and perhaps add Pod
annotations for scrapping :
<<<<<<< HEAD

```
=======
```yaml
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)
secretsExporter:
  podAnnotations:
    prometheus.io/port: "9793"
    prometheus.io/scrape: "true"
service:
  create: false
prometheusServiceMonitor:
  create: false
prometheusRules:
  create: false
```

## 📜 Using the Chart

This will guide you through writing the initial set of values.

### Metrics for TLS Secrets

By default we only run a Deployment to provide metrics on TLS Secrets stored in the Kubernetes cluster. It helps
detect expiring certificates whether you manage them on your own or rely on controllers such as
[cert-manager](https://cert-manager.io).

> 🙂 If you're only interested in this feature, you could probably install the Chart not specifying any value.

Disable this exporter when Secrets metrics are not wanted – if you're looking for hostPath DaemonSets only :
<<<<<<< HEAD

```
=======
```yaml
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)
secretsExporter:
  enabled: false
```

### Metrics for node certificates (hostPath)

Kubernetes components use many certificates to authenticate and secure communications between each others. This PKI is
critical to the operation of a cluster and its health should be monitored carefully. Expiring Kubernetes certificates
are a common source of outages, and depending on your distribution could happen a few months after installation if left
unattended.

This Chart provides a facility to deploy `DaemonSets` so that each node of a cluster can run its own x509-certificate-exporter
and export metrics for host files :

- `etcd` server and client certificates
- Kubernetes CA
- `kube-apiserver` certificates
- `kubelet` certificates
- kubeconfig files with embedded certificates
- etc.
  Obviously it also works with any other application deployed on cluster nodes as long as it uses PEM encoded certicates
  (deployment agents, security tools, etc.).

> ⚙️ You'll have to compile a list of files and directories of interest. There is no "one size fits all" configuration
> that we could recommend, or even a decent boilerplate. Examples below should give an idea of what to look after.

> 🏙️ While having a single DaemonSet sounds like a fair option, it is not uncommon for nodes to assume different roles,
> and as a result hold different sets of certificate files requiring targeted x509-certificate-exporter configurations.
> For example, with the help of node selectors and tolerations, we can have nodes of the control plane run their own
> exporter targeting API and etcd certificates, while regular nodes would have a simpler configuration for Kubelet alone.

Deployment of hostPath exporters is controlled under the `hostPathsExporter` key of [Chart Values](#values).
All values are defaults that would apply to any number of DaemonSet you wish to run, unless overridden individually.
Then you'll need to create at least one DaemonSet in `hostPathsExporter.daemonSets`.

This is the most basic configuration. It will create one DaemonSet named `nodes` with an empty configuration. Exporters
won't export no certificate metric.
<<<<<<< HEAD

```
=======
```yaml
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)
hostPathsExporter:
  daemonSets:
    nodes: {}
```

![Grafana Dashboard](./docs/grafana-dashboard.jpg)

<<<<<<< HEAD
## Installation
=======
This will create a DaemonSet able to monitor the same files on all nodes. It could fit a typical kubeadm cluster with no
control plane dedicated nodes :
```yaml
hostPathsExporter:
  daemonSets:
    nodes:
      watchFiles:
      - /var/lib/kubelet/pki/kubelet-client-current.pem
      - /etc/kubernetes/pki/apiserver.crt
      - /etc/kubernetes/pki/apiserver-etcd-client.crt
      - /etc/kubernetes/pki/apiserver-kubelet-client.crt
      - /etc/kubernetes/pki/ca.crt
      - /etc/kubernetes/pki/front-proxy-ca.crt
      - /etc/kubernetes/pki/front-proxy-client.crt
      - /etc/kubernetes/pki/etcd/ca.crt
      - /etc/kubernetes/pki/etcd/healthcheck-client.crt
      - /etc/kubernetes/pki/etcd/peer.crt
      - /etc/kubernetes/pki/etcd/server.crt
      watchKubeconfFiles:
      - /etc/kubernetes/admin.conf
      - /etc/kubernetes/controller-manager.conf
      - /etc/kubernetes/scheduler.conf
```
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)

<<<<<<< HEAD
### 🏃 TL; DR
=======
Dedicated nodes will require other DaemonSets. Based on our kubeadm example, it could be extended like this :
```yaml
hostPathsExporter:
  podAnnotations:
    prometheus.io/port: "9793"
    prometheus.io/scrape: "true"
>>>>>>> ca8ba8c (refactor(x509-exporter): set default port to 9793)

<<<<<<< HEAD
The [Helm chart](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter#-tldr) is the most straightforward way to get a fully-featured exporter running on your cluster.
The chart is also highly-customizable if you wish to. See the [chart documentation](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter) to learn more.
=======
  daemonSets:
    cp:
      nodeSelector:
        node-role.kubernetes.io/master: ""
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      watchFiles:
      - /var/lib/kubelet/pki/kubelet-client-current.pem
      - /etc/kubernetes/pki/apiserver.crt
      - /etc/kubernetes/pki/apiserver-etcd-client.crt
      - /etc/kubernetes/pki/apiserver-kubelet-client.crt
      - /etc/kubernetes/pki/ca.crt
      - /etc/kubernetes/pki/front-proxy-ca.crt
      - /etc/kubernetes/pki/front-proxy-client.crt
      - /etc/kubernetes/pki/etcd/ca.crt
      - /etc/kubernetes/pki/etcd/healthcheck-client.crt
      - /etc/kubernetes/pki/etcd/peer.crt
      - /etc/kubernetes/pki/etcd/server.crt
      watchKubeconfFiles:
      - /etc/kubernetes/admin.conf
      - /etc/kubernetes/controller-manager.conf
      - /etc/kubernetes/scheduler.conf

    nodes:
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/ingress
        operator: Exists
      watchFiles:
      - /var/lib/kubelet/pki/kubelet-client-current.pem
      - /etc/kubernetes/pki/ca.crt
```
>>>>>>> 5db219d (doc(x509-certificate-exporter): update kubeadm example)

The provided [Grafana Dashboard](https://grafana.com/grafana/dashboards/13922) can also be used to display the exporter's metrics on your Grafana instance.

### Using Docker

A docker image is available at [enix/x509-certificate-exporter](https://hub.docker.com/r/enix/x509-certificate-exporter).

<<<<<<< HEAD
### Using the pre-built binaries
=======
When it's missing and you don't have the CRD, helm will raise one of this error :
```
Error: unable to build kubernetes objects from release manifest: [unable to recognize "": no matches for kind "PrometheusRule" in version "monitoring.coreos.com/v1", unable to recognize "": no matches for kind "ServiceMonitor" in version "monitoring.coreos.com/v1"]
```
Add the following values to disable creation of `ServiceMonitors` and `PrometheusRules` :
```yaml
prometheusServiceMonitor:
  create: false
prometheusRules:
  create: false
```
Then perhaps you would need Pod annotations to work with the Kubernetes service discovery in Prometheus :
```yaml
secretsExporter:
  podAnnotations:
    prometheus.io/port: "9793"
    prometheus.io/scrape: "true"
```
Also in such case the headless service may not serve any purpose and can be removed :
```yaml
service:
  create: false
```

> ℹ️ [Chart Values](#values) provide a few knobs to control Prometheus rules, such as numbers of days before
certificate expiration for warning and critical alerts are triggered.

> ⚠️ Special alert `X509ExporterReadErrors` is meant to report anomalies with the exporter, such as API authorization
issues or unreadable files. If the Kubernetes API is unstable it could be disabled with
`prometheusRules.alertOnReadErrors`.\
When using hostPath exporters, and some nodes don't have all the files, it's better to add other DaemonSet profiles
to target each situation and preserve this alert. Detecting configuration regressions is especially important when
working with files that can change path over time and on cluster upgrades.

### Installing the Chart
>>>>>>> ca8ba8c (refactor(x509-exporter): set default port to 9793)

Every [release](https://github.com/enix/x509-certificate-exporter/releases) comes with pre-built binaries for many supported platforms.
Create a file named `x509-certificate-exporter.values.yaml` with your values, as discussed previously and with the help of
[Chart Values](#values).

### Using the source

The project's entry point is `./cmd/x509-certificate-exporter`.
You can run & build it as any other Go program :

```bash
go build ./cmd/x509-certificate-exporter
```

## Usage

The following metrics are available:

- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expired`
- `x509_read_errors`

### Prometheus Alerts

When installation is not performed with Helm, the following Prometheus alerting
rules may be deployed manually:

```
rules:
    - alert: X509ExporterReadErrors
        annotations:
            description: Over the last 15 minutes, this x509-certificate-exporter instance
                has experienced errors reading certificate files or querying the Kubernetes
                API. This could be caused by a misconfiguration if triggered when the exporter
                starts.
            summary: Increasing read errors for x509-certificate-exporter
        expr: delta(x509_read_errors[15m]) > 0
        for: 5m
        labels:
            severity: warning
    - alert: CertificateRenewal
        annotations:
            description: Certificate for "{{ $labels.subject_CN }}" should be renewed
                {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
                }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
            summary: Certificate should be renewed
        expr: ((x509_cert_not_after - time()) / 86400) < 28
        for: 15m
        labels:
            severity: warning
    - alert: CertificateExpiration
        annotations:
            description: Certificate for "{{ $labels.subject_CN }}" is about to expire
                {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
                }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
            summary: Certificate is about to expire
        expr: ((x509_cert_not_after - time()) / 86400) < 14
        for: 15m
        labels:
            severity: critical
```

### Advanced usage

For advanced configuration, see the program's `--help` :

```
Usage: x509-certificate-exporter [-hv] [-b value] [--debug] [-d value] [--exclude-label value] [--exclude-namespace value] [--expose-per-cert-error-metrics] [--expose-relative-metrics] [-f value] [--include-label value] [--include-namespace value] [-k value] [-l value] [--max-cache-duration value] [-s value] [--trim-path-components value] [--watch-kube-secrets] [parameters ...]
 -b, --listen-address=value
                address on which to bind and expose metrics [:9793]
     --debug    enable debug mode
 -d, --watch-dir=value
                watch one or more directory which contains x509 certificate
                files (not recursive)
     --exclude-label=value
                removes the kube secrets with the given label (or label
                value if specified) from the watch list (applied after
                --include-label)
     --exclude-namespace=value
                removes the given kube namespace from the watch list
                (applied after --include-namespace)
     --expose-per-cert-error-metrics
                expose additionnal error metric for each certificate
                indicating wether it has failure(s)
     --expose-relative-metrics
                expose additionnal metrics with relative durations instead
                of absolute timestamps
 -f, --watch-file=value
                watch one or more x509 certificate file
 -h, --help     show this help message and exit
     --include-label=value
                add the kube secrets with the given label (or label value if
                specified) to the watch list (when used, all secrets are
                excluded by default)
     --include-namespace=value
                add the given kube namespace to the watch list (when used,
                all namespaces are excluded by default)
 -k, --watch-kubeconf=value
                watch one or more Kubernetes client configuration (kind
                Config) which contains embedded x509 certificates or PEM
                file paths
 -l, --expose-labels=value
     --max-cache-duration=value
                maximum cache duration for kube secrets. cache is per
                namespace and randomized to avoid massive requests.
 -s, --secret-type=value
                one or more kubernetes secret type & key to watch (e.g.
                "kubernetes.io/tls:tls.crt"
     --trim-path-components=value
                remove <n> leading component(s) from path(s) in label(s)
 -v, --version  show version info and exit
     --watch-kube-secrets
                scrape kubernetes.io/tls secrets and monitor them
```

## FAQ

### Why are you using the `not after` timestamp rather than a remaining number of seconds?

For two reasons.

First, Prometheus tends to do better storage consumption when a value stays identical over checks.

Then, it is better to compute the remaining time through a prometheus query as some latency (seconds) can exist
between this exporter check and your alert or query being run.

Here is an exemple:

```
x509_cert_not_after - time()
```

When collecting metrics from tools like Datadog that does not have timestamp functions,
the exporter can be run with the `--expose-relative-metrics` flag in order to add the following optional metrics:

- `x509_cert_valid_since_seconds`
- `x509_cert_expires_in_seconds`

### How to ensure it keeps working over time?

Changes in paths or deleted files may silently break the ability to watch critical certificates.

Because it's never convenient to alert on disapearing metrics, the exporter will publish on `x509_read_errors` how many
paths could not be read. It will also count Kubernetes API responses failures, but won't count deleted secrets.

A basic alert would be:

```
x509_read_errors > 0
```
<<<<<<< HEAD
=======

## 📝 Notes

### `watchFiles` and inode change

Because of limitations with mount binding that CRIs use to expose a single host file to a container, we cannot use
`subPath` in `volumeMounts`. This feature would in fact result in the perfect implementation where the exporter can only
access designated files. However if a certificate file is not replaced in-place and it's inode is altered, the exporter
would keep seeing the old content and can't even tell if it still exists on the host. This situation is common with
Kubernetes control-plane certificates.

Be aware that for every file path provided to `watchFiles`, the exporter container will be given read access to the
parent directory. This is how we handle the problem of changing inodes. Metrics will of course be limited to the single
targetted path, as the program is told to watch the real path from `watchFiles`.

This is to be taken into consideration if you're doing threat assessment. In such case it's recommended not to put
secret keys in the same directory as certificate files.

### Watching symbolic links

Starting with version 2.6.0, the exporter is now handling symlinks in a special way to better suit containerization and
the limited access to host filesystem.

When a symlink is added to a `watchFiles` list, we are able to resolve and read it's target as long as it's in the same
directory. This is dynamic for each metrics scrape and will track symlink changes.

A typical case of this is the Kubelet client certificate that now uses a symlink pointing to a new file each time the
certificate gets rotated.
For instance you may be using :
```yaml
watchFiles:
- /var/lib/kubelet/pki/kubelet-client-current.pem
```
Because all client certificates reside in the `pki` directory, the exporter will be able to read
`kubelet-client-current.pem` and it's target properly. Even though the Operating System cannot resolve the link itself
in the container namespace.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| kubeVersion | string | `""` | Override Kubernetes version detection ; usefull with "helm template" |
| extraLabels | object | `{}` | Extra labels to add on chart resources |
| nameOverride | string | `""` | Partially override x509-certificate-exporter.fullname template (will prepend the release name) |
| fullnameOverride | string | `""` | Fully override x509-certificate-exporter.fullname template |
| imagePullSecrets | list | `[]` | Specify docker-registry secret names as an array |
| image.registry | string | `"docker.io"` | x509-certificate-exporter image registry |
| image.repository | string | `"enix/x509-certificate-exporter"` | x509-certificate-exporter image repository |
| image.tag | string | `nil` | x509-certificate-exporter image tag (defaults to Chart appVersion) |
| image.pullPolicy | string | `"IfNotPresent"` | x509-certificate-exporter image pull policy |
| psp.create | bool | `false` | Should Pod Security Policy resources be created |
| rbac.create | bool | `true` | Should RBAC resources be created |
| rbac.secretsExporter.serviceAccountName | string | `nil` | Name of the ServiceAccount for the Secrets exporter (required if `rbac.create=false`) |
| rbac.secretsExporter.serviceAccountAnnotations | object | `{}` | Annotations added to the ServiceAccount for the Secrets exporter |
| rbac.secretsExporter.clusterRoleAnnotations | object | `{}` | Annotations added to the ClusterRole for the Secrets exporter |
| rbac.secretsExporter.clusterRoleBindingAnnotations | object | `{}` | Annotations added to the ClusterRoleBinding for the Secrets exporter |
| rbac.hostPathsExporter.serviceAccountName | string | `nil` | Name of the ServiceAccount for hostPath exporters (required if `rbac.create=false`) |
| rbac.hostPathsExporter.serviceAccountAnnotations | object | `{}` | Annotations added to the ServiceAccount for the hostPath exporters |
| rbac.hostPathsExporter.clusterRoleAnnotations | object | `{}` | Annotations added to the ClusterRole for the hostPath exporters |
| rbac.hostPathsExporter.clusterRoleBindingAnnotations | object | `{}` | Annotations added to the ClusterRoleBinding for the hostPath exporters |
| podExtraLabels | object | `{}` | Extra labels added to all Pods |
| podAnnotations | object | `{}` | Annotations added to all Pods |
| exposeRelativeMetrics | bool | `false` | Enable additional metrics with relative durations instead of absolute timestamps |
| secretsExporter.enabled | bool | `true` | Should the TLS Secrets exporter be running |
| secretsExporter.debugMode | bool | `false` | Should debug messages be produced by the TLS Secrets exporter |
| secretsExporter.replicas | int | `1` | Desired number of TLS Secrets exporter Pod |
| secretsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of the TLS Secrets exporter |
| secretsExporter.strategy | object | `{}` | DeploymentStrategy for the TLS Secrets exporter |
| secretsExporter.resources | object | see values.yaml | ResourceRequirements for containers of the TLS Secrets exporter |
| secretsExporter.nodeSelector | object | `{}` | Node selector for Pods of the TLS Secrets exporter |
| secretsExporter.tolerations | list | `[]` | Toleration for Pods of the TLS Secrets exporter |
| secretsExporter.affinity | object | `{}` | Affinity for Pods of the TLS Secrets exporter |
| secretsExporter.podExtraLabels | object | `{}` | Extra labels added to Pods of the TLS Secrets exporter |
| secretsExporter.podAnnotations | object | `{}` | Annotations added to Pods of the TLS Secrets exporter |
| secretsExporter.podSecurityContext | object | `{}` | PodSecurityContext for Pods of the TLS Secrets exporter |
| secretsExporter.securityContext | object | see values.yaml | SecurityContext for containers of the TLS Secrets exporter |
| secretsExporter.secretTypes | list | `[{"key":"tls.crt","type":"kubernetes.io/tls"}]` | Choose which type of secrets should be watched. Key is the map key in the secret data. |
| secretsExporter.includeNamespaces | list | `[]` | Restrict the list of namespaces the TLS Secrets exporter should scan for certificates to watch (all namespaces if empty) |
| secretsExporter.excludeNamespaces | list | `[]` | Exclude namespaces from being scanned by the TLS Secrets exporter (evaluated after `includeNamespaces`) |
| secretsExporter.includeLabels | list | `[]` | Only watch TLS Secrets having these labels (all secrets if empty). Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.excludeLabels | list | `[]` | Exclude TLS Secrets having these labels. Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| hostPathsExporter.debugMode | bool | `false` | Should debug messages be produced by hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.updateStrategy | object | `{}` | updateStrategy for DaemonSet of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.resources | object | see values.yaml | ResourceRequirements for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.nodeSelector | object | `{}` | Node selector for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.tolerations | list | `[]` | Toleration for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.affinity | object | `{}` | Affinity for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podExtraLabels | object | `{}` | Extra labels added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podAnnotations | object | `{}` | Annotations added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podSecurityContext | object | `{}` | PodSecurityContext for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.securityContext | object | see values.yaml | SecurityContext for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.watchDirectories | list | `[]` | [SEE README] List of directory paths of the host to scan for PEM encoded certificate files to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchFiles | list | `[]` | [SEE README] List of file paths of the host for PEM encoded certificates to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchKubeconfFiles | list | `[]` | [SEE README] List of Kubeconf file paths of the host to scan for embedded certificates to export metrics about |
| hostPathsExporter.daemonSets | object | `{}` | [SEE README] Map to define one or many DaemonSets running hostPath exporters. Key is used as a name ; value is a map to override all default settings set by `hostPathsExporter.*`. |
| rbacProxy.enabled | bool | `false` | Should kube-rbac-proxy be used to expose exporters |
| rbacProxy.image.registry | string | `"quay.io"` | kube-rbac-proxy image registry |
| rbacProxy.image.repository | string | `"coreos/kube-rbac-proxy"` | kube-rbac-proxy image repository |
| rbacProxy.image.tag | string | `"v0.5.0"` | kube-rbac-proxy image version |
| rbacProxy.image.pullPolicy | string | `"IfNotPresent"` | kube-rbac-proxy image pull policy |
| rbacProxy.upstreamListenPort | int | `9091` | Listen port for the exporter running inside kube-rbac-proxy exposed Pods |
| rbacProxy.resources | object | see values.yaml | ResourceRequirements for all containers of kube-rbac-proxy |
| rbacProxy.securityContext | object | see values.yaml | SecurityContext for all containers of kube-rbac-proxy |
| podListenPort | int | `9793` | TCP port to expose Pods on (whether kube-rbac-proxy is enabled or not) |
| hostNetwork | bool | `false` | Enable hostNetwork mode. Useful when Prometheus is deployed outside of the Kubernetes cluster |
| service.create | bool | `true` | Should a headless Service be installed, targets all instances Deployment and DaemonSets (required for ServiceMonitor) |
| service.port | int | `9793` | TCP port to expose the Service on |
| service.annotations | object | `{}` | Annotations to add to the Service |
| service.extraLabels | object | `{}` | Extra labels to add to the Service |
| prometheusServiceMonitor.create | bool | `true` | Should a ServiceMonitor ressource be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusServiceMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the ServiceMonitor |
| prometheusServiceMonitor.extraLabels | object | `{}` | Extra labels to add on ServiceMonitor ressources |
| prometheusServiceMonitor.relabelings | object | `{}` | Relabel config for the ServiceMonitor, see: https://coreos.com/operators/prometheus/docs/latest/api.html#relabelconfig |
| prometheusPodMonitor.create | bool | `false` | Should a PodMonitor ressource be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusPodMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the PodMonitor |
| prometheusPodMonitor.extraLabels | object | `{}` | Extra labels to add on PodMonitor ressources |
| prometheusPodMonitor.relabelings | object | `{}` | Relabel config for the PodMonitor, see: https://coreos.com/operators/prometheus/docs/latest/api.html#relabelconfig |
| prometheusRules.create | bool | `true` | Should a PrometheusRule ressource be installed to alert on certificate expiration. For prometheus-operator (kube-prometheus) users. |
| prometheusRules.alertOnReadErrors | bool | `true` | Should the X509ExporterReadErrors alerting rule be created to notify when the exporter can't read files or authenticate with the Kubernetes API. It aims at preventing undetected misconfigurations and monitoring regressions. |
| prometheusRules.readErrorsSeverity | string | `"warning"` | Severity for the X509ExporterReadErrors alerting rule |
| prometheusRules.warningDaysLeft | int | `28` | Raise a warning alert when this little days are left before a certificate expiration (cert-manager would renew Let's Encrypt certs before day 29) |
| prometheusRules.criticalDaysLeft | int | `14` | Raise a critical alert when this little days are left before a certificate expiration (two weeks to deal with ACME rate limiting should this be an issue) |
| prometheusRules.extraLabels | object | `{}` | Extra labels to add on PrometheusRule ressources |

## ⚖️ License

```
Copyright (c) 2020, 2021 ENIX

<<<<<<< HEAD
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
>>>>>>> ca8ba8c (refactor(x509-exporter): set default port to 9793)
=======
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
<<<<<<< HEAD
>>>>>>> f86c4d6 (chore(x509-certificate-exporter): change of license)
=======
```
>>>>>>> 6aee8e2 (doc(x509-certificate-exporter): fix code blocks)
