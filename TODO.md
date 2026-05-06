# TODO

## Refactor: host-namespace paths everywhere in the file source

### What

Move the file source so that the exporter reads, caches, and labels every
on-disk artefact by its **host-namespace path** (the path the operator
reads `kubectl exec`-ing into a node, e.g. `/var/lib/kubelet/pki/...`),
and applies `PathMapping.From → To` translation **uniformly at every
filesystem operation** — `open`, `Stat`, `Lstat`, `ReadDir`, `Readlink`.

Today (post-symlink-mapping change) the chart writes **in-pod** paths
into the configmap (`/mnt/watch/file-<sha1>/var/lib/kubelet/pki/...`),
and `PathMapping` is consulted only when an absolute symlink target is
read back — i.e. only inside `pkg/fileglob.handleSymlink`. The
proposal is to flip the polarity: have the chart write raw host paths,
and let the runtime translate transparently for every FS op.

### Why we'd want to

1. **Drop `trimPathComponents`.** `chart/templates/configmap.yaml`
   currently sets `metrics.trimPathComponents: 3` for hostPath sources
   so that `/mnt/watch/file-<sha1>/var/lib/kubelet/pki/foo.pem` displays
   as `var/lib/kubelet/pki/foo.pem` in `filepath` Prometheus labels.
   That's a workaround for a label-cosmetics problem that goes away if
   the runtime knows the host path natively.

2. **One translation point, not two.** Right now
   `pkg/fileglob.handleSymlink` has bespoke translation +
   containment logic. With a universal translator, the same logic
   covers every code path that touches the FS, so any new FS-using
   feature is covered for free.

3. **Operator UX.** Labels match what humans type. No mental mapping
   from `/mnt/watch/file-9dff…/var/lib/kubelet/pki/...` back to the
   real file.

### Why this is *not* done as part of the symlink-mapping change

- **Blast radius.** It touches every FS op in `fileglob`, not just
  symlink resolution. The cache key in `pkg/source/file/file.go`
  becomes the host path (today it's the walker's `Path` = in-pod),
  affecting cache invariants and the `SkipUnchanged` machinery.

- **Public API ripple.** `pkg/cert.SourceRef.Location` and the
  registry's `filepath` label semantics change in user-visible ways.
  Needs a deprecation cycle for downstream consumers reading those
  labels (Grafana dashboards, alert rules).

- **Test churn.** Every fileglob/source/file/cmd test that asserts on
  paths needs to be revisited. Today's symlink-mapping change is
  surgical; this would be a multi-package rewrite.

- **`trimPathComponents` removal is a chained breaking change.** The
  values key would have to be deprecated separately.

### When to revisit

- After the symlink-mapping change has had at least one release in the
  wild and we have feedback from real DaemonSet operators about the
  shape of `filepath` labels they'd prefer.
- When we next plan a `pkg/cert` API revision (anything that already
  forces consumers to update their dashboards is a natural moment to
  bundle this in).
- If a third concrete need for "exporter knows the host path" surfaces
  (e.g. exposing the host path in error messages, in `/healthz`
  diagnostics, in a future audit trail). Two needs is a coincidence,
  three is a pattern that justifies the refactor.

### Sketch of the change

- `pkg/fileglob/walkfs.go` (new): a small `WalkFS` decorator that
  takes `[]PathMapping` and a base `WalkFS`, applies the
  longest-prefix `From → To` rewrite to every method's `name`
  argument, and forwards. The walker becomes oblivious to the
  translation — it sees host paths everywhere.
- `pkg/source/file/file.go`: drop the special-case
  `if e.LinkTo != "" { readPath = e.LinkTo }` (no longer needed —
  `Reader` would also be wrapped to apply the translation).
- `chart/templates/configmap.yaml`: write host paths in
  `paths:` and `pathMappings:`; remove `metrics.trimPathComponents:`.
- `chart/values.yaml`: deprecate `metrics.trimPathComponents` (keep
  for backwards compat for one release, then remove).
- Tests: every test that hardcodes `/mnt/watch/file-<sha1>/...` flips
  to host paths.
