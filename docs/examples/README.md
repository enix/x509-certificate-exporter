# Helm values examples

Curated `values.yaml` files for the x509-certificate-exporter chart. Each
file is a self-contained, valid input for:

```sh
helm install x509-certificate-exporter \
  oci://quay.io/enix/charts/x509-certificate-exporter \
  --values <one-of-the-files>.yaml
```

Pick the closest starting point, copy it into your cluster's configuration,
**then adapt**.

> [!WARNING]
> These files are **documentation, not turn-key configurations**.
> Read each setting, understand what it does, and decide if it fits your
> cluster before applying. Drop what you don't need; layer multiple
> `--values` flags or merge pieces of different examples freely.

---

## Generic examples

| File | What it covers |
| --- | --- |
| [`secrets-tuned.values.yaml`](./secrets-tuned.values.yaml) | Secrets-only deployment with **every reasonable knob** turned on: namespace and label filtering, PKCS#12 with sibling-key passphrases, surfaced Secret labels, ConfigMap watching, HA via 2 replicas + anti-affinity, mTLS on `/metrics` via `webConfiguration`, custom alert thresholds, Grafana dashboard, API-server rate limits. Use as a reference for what's tunable on the cluster-watching side. |
| [`hostpath-rich.values.yaml`](./hostpath-rich.values.yaml) | `secretsExporter` left at chart defaults **paired with three hostPath DaemonSets** carved up by node OS role: `controlplane` (kubeadm CP PKI), `storage-nodes` (Ceph daemons running as systemd units, PKI under `/etc/ceph/`), and `edge-nodes` (strongSwan IPsec terminator, X.509 in `/etc/ipsec.d/{certs,cacerts}/`). Demonstrates per-DS `nodeSelector`, conditional `tolerations:` (only where the pool is tainted), and the `watchFiles` / `watchDirectories` / `watchKubeconfFiles` triplet. Common thread: the PKI is on disk because the *node OS* manages a daemon — never a Pod misusing the host filesystem. |

## Distribution-specific examples

These target the on-node PKI layout of common Kubernetes distributions.
They configure only `hostPathsExporter` (the cluster-level
`secretsExporter` is distribution-agnostic — pair them with one of the
generic examples or with the chart defaults).

| Distribution | File | Notes |
| --- | --- | --- |
| **kubeadm** (vanilla upstream) | [`distros/kubeadm.values.yaml`](./distros/kubeadm.values.yaml) | Reference layout for the kubernetes/kubernetes apiserver/etcd/kubelet PKI under `/etc/kubernetes/pki/` + `/var/lib/kubelet/pki/`. The other distro examples are mostly variations on this one. |
| **Talos** | [`distros/talos.values.yaml`](./distros/talos.values.yaml) | Full control-plane PKI surfaced via Talos's `/system/secrets/{kubernetes,etcd}` tree (apiserver + aggregator + etcd-client material, etcd peer/server, plus the kubeadm-shaped `/etc/kubernetes/pki/ca.crt` convenience copy). Two specifics: `hostPathVolumeType: null` to skip the kubelet's pre-mount type-check (Talos's bind mounts confuse it), and **don't add `privileged: true`** — the chart's defaults already match PSA `baseline`, escalation would push past it and Talos PSA would reject the Pod. |
| **RKE2** (Rancher) | [`distros/rke2.values.yaml`](./distros/rke2.values.yaml) | Server PKI under `/var/lib/rancher/rke2/server/tls/`, agent PKI under `/var/lib/rancher/rke2/agent/`, kubeconfig at `/etc/rancher/rke2/rke2.yaml`. Sets `hostPathVolumeType: null` because RKE2's embedded kubelet runs in its own mount namespace and the chart's default `Directory` type-check fails on the redirected paths. |
| **k3s** (Rancher) | [`distros/k3s.values.yaml`](./distros/k3s.values.yaml) | `/var/lib/rancher/k3s/server/tls/` + `/var/lib/rancher/k3s/agent/`. Same shape as RKE2; smaller surface (single-node-friendly). |
| **k0s** (Mirantis) | [`distros/k0s.values.yaml`](./distros/k0s.values.yaml) | `/var/lib/k0s/pki/` for the control plane, `/var/lib/k0s/kubelet/pki/` for the kubelet. Embedded etcd PKI under `/var/lib/k0s/pki/etcd/`. |
| **OpenShift** | [`distros/openshift.values.yaml`](./distros/openshift.values.yaml) | Control-plane static-pod resources at `/etc/kubernetes/static-pod-resources/` and a kubelet client at `/var/lib/kubelet/pki/`. Requires the `hostmount-anyuid` (or `privileged`) SCC — annotated in the file. |

## Spot a missing distro or a wrong path?

Open an issue or a PR. The PKI layouts evolve from one minor release to
the next — sometimes a path moves, sometimes a new file appears. These
examples are best-effort snapshots tested against current releases of
each distribution; we'd rather hear about a stale path than ship one.
