# 🔏 X.509 Certificate Exporter

[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go with cloud deployments in mind.

Get notified before they expire:
* TLS Secrets from a Kubernetes cluster
* PEM encoded files, by path or scanning directories
* Kubeconfigs with embedded certificates or file references

The following metrics are available:
* `x509_cert_not_before`
* `x509_cert_not_after`
* `x509_cert_expired`
* `x509_cert_expires_in_seconds` (optional)
* `x509_cert_valid_since_seconds` (optional)
* `x509_cert_error` (optional)
* `x509_read_errors`
* `x509_exporter_build_info`

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
```yaml
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
```yaml
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
* `etcd` server and client certificates
* Kubernetes CA
* `kube-apiserver` certificates
* `kubelet` certificates
* kubeconfig files with embedded certificates
* etc.
Obviously it also works with any other application deployed on cluster nodes as long as it uses PEM encoded certicates
(deployment agents, security tools, etc.).

> ⚙️ You'll have to compile a list of files and directories of interest. There is no "one size fits all" configuration
that we could recommend, or even a decent boilerplate. Examples below should give an idea of what to look after.

> 🏙️ While having a single DaemonSet sounds like a fair option, it is not uncommon for nodes to assume different roles,
and as a result hold different sets of certificate files requiring targeted x509-certificate-exporter configurations.
For example, with the help of node selectors and tolerations, we can have nodes of the control plane run their own
exporter targeting API and etcd certificates, while regular nodes would have a simpler configuration for Kubelet alone.

Deployment of hostPath exporters is controlled under the `hostPathsExporter` key of [Chart Values](#values).
All values are defaults that would apply to any number of DaemonSet you wish to run, unless overridden individually.
Then you'll need to create at least one DaemonSet in `hostPathsExporter.daemonSets`.

This is the most basic configuration. It will create one DaemonSet named `nodes` with an empty configuration. Exporters
won't export no certificate metric.
```yaml
hostPathsExporter:
  daemonSets:
    nodes: {}
```

Moving on, we can add all flavors of "watch" settings :
* `watchDirectories` : to monitor all PEM files found in a host directory (no recursion in subdirectories)
* `watchFiles` : to target known file paths, this is highly recommended over the directory option when file paths are
predictable
* `watchKubeconfFiles` : look for base64 encoded embedded certificates in Kubeconfig files

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

Dedicated nodes will require other DaemonSets. Based on our kubeadm example, it could be extended like this :
```yaml
hostPathsExporter:
  podAnnotations:
    prometheus.io/port: "9793"
    prometheus.io/scrape: "true"

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

With this last configuration we demonstrated :
* using `podAnnotations` right under `hostPathsExporter`, it will apply to all `hostPathsExporter.daemonSets` because
they don't override that setting
* two DaemonSets, `cp` for control plane nodes, and `nodes` for regular ones
* `nodeSelector` on the control plane DaemonSet to schedule Pods on "masters" only
* `tolerations` for both. On `cp` it's required to be scheduled on those tainted nodes. Because this cluster would also
have nodes dedicated to ingress controllers, DaemonSet `nodes` also get a toleration for this role.

### Custom Resources for the Prometheus operator

Users of the prometheus-operator will immediately scrape exporters thanks to the creation of a `ServiceMonitor`
resource, and get basic alerting rules from the new `PrometheusRule`.
The operator is usually installed with [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) or by
the Kubernetes distribution.

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

Create a file named `x509-certificate-exporter.values.yaml` with your values, as discussed previously and with the help of
[Chart Values](#values).

Add our Charts repository :
```
$ helm repo add enix https://charts.enix.io
```

Install the x509-certificate-exporter with release name `x509-certificate-exporter` :
```
$ helm install x509-certificate-exporter enix/x509-certificate-exporter --values x509-certificate-exporter.values.yaml
```

The `upgrade` command is used to change configuration when values are modified :
```
$ helm upgrade x509-certificate-exporter enix/x509-certificate-exporter --values x509-certificate-exporter.values.yaml
```

### Upgrading the Chart

Update Helm repositories :
```
$ helm repo update
```

Upgrade release names `x509-certificate-exporter` to the latest version :
```
$ helm upgrade x509-certificate-exporter enix/x509-certificate-exporter
```

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

### HostPath types and Rancher Kubernetes Engine (RKE)

When file or directory paths are provided for running DaemonSet exporters, Pods will use HostPath volumes with type
`Directory` by default. This is a safety so that misconfigurations are easily caught at deployment, and also to prevent
the creation of paths that don't exist already.

However some Kubernetes distributions such as RKE may not allow the kubelet to probe for volume paths existence or type, raising
errors such as:
```
MountVolume.SetUp failed for volume "file-f9f012b96b66ef1f9f2c759856d9e752a1691104" :
  hostPath type check failed: /opt/rke/etc/kubernetes/ssl is not a directory
```

In this case the use of value `hostPathVolumeType` will let Kubernetes use the default HostPath type and disable checks.  
Just like other settings it can be set at the `hostPathsExporter` level:
```yaml
hostPathsExporter:
  hostPathVolumeType: null
  daemonSets:
    node:
      [...]
      watchFiles:
      - /etc/kubernetes/pki/*.pem
      - /etc/kubernetes/pki/*.crt
```
Or it can be set at the DaemonSet level:
```yaml
hostPathsExporter:
  daemonSets:
    node:
      [...]
      watchFiles:
      - /etc/kubernetes/pki/*.pem
      - /etc/kubernetes/pki/*.crt
    oldnode:
      hostPathVolumeType: null
      [...]
      watchFiles:
      - /etc/kubernetes/pki/*.pem
      - /etc/kubernetes/pki/*.crt
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| nameOverride | string | `""` | Partially override x509-certificate-exporter.fullname template (will prepend the release name) |
| fullnameOverride | string | `""` | Fully override x509-certificate-exporter.fullname template |
| namespaceOverride | string | `""` | Override the deployment namespace |
| extraDeploy | list | `[]` | Additional objects to deploy with the release |
| extraDeployVerbatim | list | `[]` | Same as `extraDeploy` but objects won't go through the templating engine |
| imagePullSecrets | list | `[]` | Specify docker-registry secret names as an array |
| image.registry | string | `"docker.io"` | x509-certificate-exporter image registry |
| image.repository | string | `"enix/x509-certificate-exporter"` | x509-certificate-exporter image repository |
| image.tag | string | `""` | x509-certificate-exporter image tag (defaults to Chart appVersion) |
| image.tagSuffix | string | `""` | Suffix added to image tags for container flavor selection (could be `-busybox`, `-alpine`, or `-scratch`) |
| image.pullPolicy | string | `"IfNotPresent"` | x509-certificate-exporter image pull policy |
| exposePerCertificateErrorMetrics | bool | `false` | Enable additional metrics to report per-certificate errors ; helps with identifying read errors origin not having to look at exporter logs, at the expense of additional storage on Prometheus |
| exposeRelativeMetrics | bool | `false` | Enable additional metrics with relative durations instead of absolute timestamps ; not recommended with Prometheus |
| metricLabelsFilterList | list | `nil` | Restrict metric labels to this list if set. **Warning** : use with caution as reducing cardinality may yield metrics collisions and force the exporter to ignore certificates. This will also degrade the usability of the Grafana dashboard. This list should always include at least `filepath`, `secret_namespace` and `secret_name`. Also `subject_CN` is highly recommended for when a file contains multiple certificates. |
| grafana.createDashboard | bool | `false` | Should the Grafana dashboard be deployed as a ConfigMap (requires Grafana sidecar) |
| grafana.sidecarLabel | string | `"grafana_dashboard"` | ConfigMap label name the Grafana sidecar is looking for |
| grafana.sidecarLabelValue | string | `"1"` | ConfigMap label value the Grafana sidecar is looking for |
| grafana.annotations | object | `{}` | Annotations added to the Grafana dashboard ConfigMap (example in `values.yaml`) |
| grafana.extraLabels | object | `{}` | Additional labels added to the Grafana dashboard ConfigMap |
| secretsExporter.enabled | bool | `true` | Should the TLS Secrets exporter be running |
| secretsExporter.debugMode | bool | `false` | Should debug messages be produced by the TLS Secrets exporter |
| secretsExporter.replicas | int | `1` | Desired number of TLS Secrets exporter Pod |
| secretsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of the TLS Secrets exporter |
| secretsExporter.strategy | object | `{}` | DeploymentStrategy for the TLS Secrets exporter |
| secretsExporter.resources | object | check `values.yaml` | ResourceRequirements for containers of the TLS Secrets exporter |
| secretsExporter.nodeSelector | object | `{}` | Node selector for Pods of the TLS Secrets exporter |
| secretsExporter.tolerations | list | `[]` | Toleration for Pods of the TLS Secrets exporter |
| secretsExporter.affinity | object | `{}` | Affinity for Pods of the TLS Secrets exporter |
| secretsExporter.priorityClassName | string | `""` | PriorityClassName for Pods of the TLS Secrets exporter |
| secretsExporter.podExtraLabels | object | `{}` | Additional labels added to Pods of the TLS Secrets exporter |
| secretsExporter.podAnnotations | object | `{}` | Annotations added to Pods of the TLS Secrets exporter |
| secretsExporter.podSecurityContext | object | check `values.yaml` | PodSecurityContext for Pods of the TLS Secrets exporter |
| secretsExporter.securityContext | object | check `values.yaml` | SecurityContext for containers of the TLS Secrets exporter |
| secretsExporter.extraVolumes | list | `[]` | Additionnal volumes added to Pods of the TLS Secrets exporter (combined with global `extraVolumes`) |
| secretsExporter.extraVolumeMounts | list | `[]` | Additionnal volume mounts added to Pod containers of the TLS Secrets exporter (combined with global `extraVolumeMounts`) |
| secretsExporter.secretTypes | list | check `values.yaml` | Which type of Secrets should be watched ; "key" is the map key in the secret data |
| secretsExporter.includeNamespaces | list | `[]` | Restrict the list of namespaces the TLS Secrets exporter should scan for certificates to watch (all namespaces if empty) |
| secretsExporter.excludeNamespaces | list | `[]` | Exclude namespaces from being scanned by the TLS Secrets exporter (evaluated after `includeNamespaces`) |
| secretsExporter.includeLabels | list | `[]` | Only watch TLS Secrets having these labels (all secrets if empty). Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.excludeLabels | list | `[]` | Exclude TLS Secrets having these labels. Items can be keys such as `my-label` or also require a value with syntax `my-label=my-value`. |
| secretsExporter.cache.enabled | bool | `true` | Enable caching of Kubernetes objects to prevent scraping timeouts |
| secretsExporter.cache.maxDuration | int | `300` | Maximum time an object can stay in cache unrefreshed (seconds) - it will be at least half of that |
| secretsExporter.kubeApiRateLimits.enabled | bool | `false` | Should requests to the Kubernetes API server be rate-limited |
| secretsExporter.kubeApiRateLimits.queriesPerSecond | int | `5` | Maximum rate of queries sent to the API server (per second) |
| secretsExporter.kubeApiRateLimits.burstQueries | int | `10` | Burst bucket size for queries sent to the API server |
| secretsExporter.env | list | `[]` | Additional environment variables for container |
| hostPathsExporter.debugMode | bool | `false` | Should debug messages be produced by hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.restartPolicy | string | `"Always"` | restartPolicy for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.updateStrategy | object | `{}` | updateStrategy for DaemonSet of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.resources | object | check `values.yaml` | ResourceRequirements for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.nodeSelector | object | `{}` | Node selector for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.tolerations | list | `[]` | Toleration for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.affinity | object | `{}` | Affinity for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.priorityClassName | string | `""` | PriorityClassName for Pods of hostPath exporters |
| hostPathsExporter.podExtraLabels | object | `{}` | Additional labels added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podAnnotations | object | `{}` | Annotations added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.podSecurityContext | object | `{}` | PodSecurityContext for Pods of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.securityContext | object | check `values.yaml` | SecurityContext for containers of hostPath exporters (default for all hostPathsExporter.daemonSets) |
| hostPathsExporter.extraVolumes | list | `[]` | Additionnal volumes added to Pods of hostPath exporters (default for all hostPathsExporter.daemonSets ; combined with global `extraVolumes`) |
| hostPathsExporter.extraVolumeMounts | list | `[]` | Additionnal volume mounts added to Pod containers of hostPath exporters (default for all hostPathsExporter.daemonSets ; combined with global `extraVolumes`) |
| hostPathsExporter.hostPathVolumeType | string | `"Directory"` | Type for HostPath volumes used with watched paths. Can be set to `""` or null to use Kubernetes defaults. May be required with RKE if Pods don't start. |
| hostPathsExporter.watchDirectories | list | `[]` | [SEE README] List of directory paths of the host to scan for PEM encoded certificate files to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchFiles | list | `[]` | [SEE README] List of file paths of the host for PEM encoded certificates to be watched and exported as metrics (one level deep) |
| hostPathsExporter.watchKubeconfFiles | list | `[]` | [SEE README] List of Kubeconf file paths of the host to scan for embedded certificates to export metrics about |
| hostPathsExporter.env | list | `[]` | Additional environment variables for container |
| hostPathsExporter.daemonSets | object | `{}` | [SEE README] Map to define one or many DaemonSets running hostPath exporters. Key is used as a name ; value is a map to override all default settings set by `hostPathsExporter.*`. |
| podListenPort | int | `9793` | TCP port to expose Pods on (whether kube-rbac-proxy is enabled or not) |
| hostNetwork | bool | `false` | Enable hostNetwork mode. Useful when Prometheus is deployed outside of the Kubernetes cluster |
| webConfiguration | string | `""` | HTTP server configuration for enabling TLS and authentication (password, mTLS) ; see [documentation at Exporter Toolkit](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) |
| webConfigurationExistingSecret | string | `""` | Load the HTTP server configuration from an existing Secret instead of `webConfiguration`. Key must `webconfig.yaml`. |
| service.create | bool | `true` | Should a Service be installed, targets all instances Deployment and DaemonSets (required for ServiceMonitor) |
| service.headless | bool | `false` | Should the Service be headless |
| service.port | int | `9793` | TCP port to expose the Service on |
| service.annotations | object | `{}` | Annotations to add to the Service |
| service.extraLabels | object | `{}` | Additional labels to add to the Service |
| prometheusServiceMonitor.create | bool | `true` | Should a ServiceMonitor object be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusServiceMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the ServiceMonitor |
| prometheusServiceMonitor.scrapeTimeout | string | `"30s"` | Target scrape timeout set in the ServiceMonitor |
| prometheusServiceMonitor.extraLabels | object | `{}` | Additional labels to add to ServiceMonitor objects |
| prometheusServiceMonitor.metricRelabelings | list | `[]` | Metrics relabel config for the ServiceMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusServiceMonitor.relabelings | list | `[]` | Relabel config for the ServiceMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusPodMonitor.create | bool | `false` | Should a PodMonitor object be installed to scrape this exporter. For prometheus-operator (kube-prometheus) users. |
| prometheusPodMonitor.scrapeInterval | string | `"60s"` | Target scrape interval set in the PodMonitor |
| prometheusPodMonitor.scrapeTimeout | string | `"30s"` | Target scrape timeout set in the PodMonitor |
| prometheusPodMonitor.extraLabels | object | `{}` | Additional labels to add to PodMonitor objects |
| prometheusPodMonitor.metricRelabelings | list | `[]` | Metric relabel config for the PodMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusPodMonitor.relabelings | list | `[]` | Relabel config for the PodMonitor, see: https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#monitoring.coreos.com/v1.Endpoint |
| prometheusRules.create | bool | `true` | Should a PrometheusRule object be installed to alert on certificate expiration. For prometheus-operator (kube-prometheus) users. |
| prometheusRules.alertOnReadErrors | bool | `true` | Should the X509ExporterReadErrors alerting rule be created to notify when the exporter can't read files or authenticate with the Kubernetes API. It aims at preventing undetected misconfigurations and monitoring regressions. |
| prometheusRules.readErrorsSeverity | string | `"warning"` | Severity for the X509ExporterReadErrors alerting rule |
| prometheusRules.alertOnCertificateErrors | bool | `true` | Should the CertificateError alerting rule be created to notify when the exporter can't decode or process a certificate. Depends on `exposePerCertificateErrorMetrics` to be enabled too. |
| prometheusRules.certificateErrorsSeverity | string | `"warning"` | Severity for the CertificateError alerting rule |
| prometheusRules.certificateRenewalsSeverity | string | `"warning"` | Severity for the CertificateRenewal alerting rule |
| prometheusRules.certificateExpirationsSeverity | string | `"critical"` | Severity for the CertificateExpiration alerting rule |
| prometheusRules.warningDaysLeft | int | `28` | Raise a warning alert when this little days are left before a certificate expiration (cert-manager would renew Let's Encrypt certs before day 29) |
| prometheusRules.criticalDaysLeft | int | `14` | Raise a critical alert when this little days are left before a certificate expiration (two weeks to deal with ACME rate limiting should this be an issue) |
| prometheusRules.extraLabels | object | `{}` | Additional labels to add to PrometheusRule objects |
| prometheusRules.alertExtraLabels | object | `{}` | Additional labels to add to PrometheusRule rules |
| prometheusRules.alertExtraAnnotations | object | `{}` | Additional annotations to add to PrometheusRule rules |
| prometheusRules.rulePrefix | string | `""` | Additional rulePrefix to PrometheusRule rules |
| prometheusRules.disableBuiltinAlertGroup | bool | `false` | Skip all built-in alerts when using extraAlertGroups |
| prometheusRules.extraAlertGroups | list | `[]` | Additional alert groups for custom configuration (example in `values.yaml`) |
| extraLabels | object | `{}` | Additional labels added to all chart objects |
| podExtraLabels | object | `{}` | Additional labels added to all Pods |
| podAnnotations | object | `{}` | Annotations added to all Pods |
| priorityClassName | string | `""` | PriorityClassName set for all Pods by default (could be overrided with `secretsExporter` and `hostPathsExporter` specific values) |
| extraVolumes | list | `[]` | Additionnal volumes added to all Pods (see also the `secretsExporter` and `hostPathsExporter` variants) |
| extraVolumeMounts | list | `[]` | Additionnal volume mounts added to all Pod containers (see also the `secretsExporter` and `hostPathsExporter` variants) |
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
| rbacProxy.image.registry | string | `"quay.io"` | kube-rbac-proxy image registry |
| rbacProxy.image.repository | string | `"brancz/kube-rbac-proxy"` | kube-rbac-proxy image repository |
| rbacProxy.image.tag | string | `"v0.13.1"` | kube-rbac-proxy image version |
| rbacProxy.image.pullPolicy | string | `"IfNotPresent"` | kube-rbac-proxy image pull policy |
| rbacProxy.upstreamListenPort | int | `9091` | Listen port for the exporter running inside kube-rbac-proxy exposed Pods |
| rbacProxy.resources | object | check `values.yaml` | ResourceRequirements for all containers of kube-rbac-proxy |
| rbacProxy.securityContext | object | check `values.yaml` | SecurityContext for all containers of kube-rbac-proxy |
| kubeVersion | string | `""` | Override Kubernetes version detection ; usefull with "helm template" |

## ⚖️ License

```
Copyright (c) 2020, 2021 ENIX

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
```
