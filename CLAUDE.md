# Project notes for Claude

## Layout (v4)

- `cmd/x509-certificate-exporter/` — binary entrypoint
- `pkg/cert/` — public API for certificate parsing (`pem`, `pkcs12` subpackages)
- `pkg/registry/` — public Prometheus collector + label registry
- `pkg/fileglob/` — public glob/walk engine (EXPERIMENTAL — promoted in v4 RC)
- `pkg/source/{file,k8s,kubeconfig}/` — public Source implementations (EXPERIMENTAL)
- `internal/` — wiring & process-lifecycle: config, log, server, product
- `chart/` — Helm chart

The v3 code was deleted; v4 is at the repo root. The Go module path uses `/v4`
(`github.com/enix/x509-certificate-exporter/v4/...`).

## Build & test workflow

Three tools share the workload, all wrapped by `Taskfile.yml`. Prefer
`task` targets when working interactively; `task --list` enumerates
everything.

- **Dagger Module** (`dagger.json` at repo root, source files in
  `dagger/`) — sandboxed QA/CI pipelines: lint (Go/Helm/Renovate/
  Markdown), unit tests, security scans, helm chart docs. Each
  exported method on the `X509Ce` struct is a Dagger function, called
  via `dagger call <function>` (find-up locates `dagger.json` from
  any cwd in the repo). The `New` constructor takes the working tree
  via `defaultPath="/"`, so no `--source` flag is needed.
- **GoReleaser** (`.goreleaser.yaml`) — every container image in the
  repo, dev OR release. Release pipeline: cross-compile binaries × OS/
  arch, archives, checksums, multi-arch container images for the
  scratch (default) + busybox (alt) variants, push to
  ghcr/quay/docker.io, cosign keyless on everything, GitHub Release
  (CI via `release.yaml`).
  Local: `task build:image:host` (host-arch, fast iteration),
  `task build:image:all` (every cross-arch variant). Dev: Tilt's
  `custom_build` calls `goreleaser` directly with
  `GORELEASER_TILT=1`, gating a dedicated dockers_v2 entry that uses
  `build/Dockerfile.busybox` (the alt release variant — chosen for
  dev because it ships a shell for `kubectl exec` debugging, not
  because it's the project default).
- **Direct CLI** for things that don't need a sandbox: k3d/tilt/helm
  on the dev cluster, Renovate dry-run via Docker, and `go mod tidy`
  / `go get -u` (pure toolchain operations — Dagger overhead would buy
  us nothing because `GOTOOLCHAIN=auto` makes host execution
  bit-identical anyway). GitHub Action SHA-pinning is owned by
  Renovate (`pinDigests: true` in `renovate.json5`).

| Goal | Command | Notes |
|---|---|---|
| Local binary | `task build:binary:host` | `goreleaser build --single-target --snapshot --clean` — host-arch binary under `dist/x509ce_<os>_<arch>_<v>/x509-certificate-exporter`, with a stable relative symlink at `dist/x509-certificate-exporter` (same flags / ldflags / version stamping as the release pipeline) |
| Snapshot host-arch only | `task build:image:host` | `goreleaser release --snapshot --skip=publish,sign` with `GORELEASER_LOCAL_PLATFORM=1` — fast iteration, no QEMU cross-build |
| Snapshot all images | `task build:image:all` | Like `task build:image:host` but every cross-arch variant — validates the full release matrix without pushing |
| Lint Go | `task lint:go` | `dagger call lint-go` — full golangci-lint set |
| Lint Helm | `task lint:helm` | `dagger call lint-helm` |
| Lint Markdown | `task lint:markdown` | `dagger call lint-markdown` |
| Lint all | `task lint` | Go + Helm + Renovate + Markdown |
| All tests | `task test` | runs `test:unit` + `test:fuzz` + `test:helm-examples` + `test:helm-fixtures` + `test:e2e` sequentially |
| Unit tests | `task test:unit` | `dagger call test` — gotestsum + `-race` + coverage |
| Fuzz smoke | `task test:fuzz` | each `Fuzz*` target run for 5s — catches seed-corpus regressions |
| Helm examples | `task test:helm-examples` | `dagger call test-helm-examples` — `helm lint chart --values` on every `docs/examples/**/*.values.yaml` |
| Helm schema fixtures | `task test:helm-fixtures` | `dagger call test-helm-fixtures` — regression net for `chart/values.schema.json` (positive + paired `.expect.txt` negatives under `test/schema/{valid,invalid}/`) |
| End-to-end tests | `task test:e2e` | throwaway k3d cluster, Helm install, scrape `/metrics` |
| Vuln scan | `task security:govulncheck` | `dagger call govulncheck` |
| Vuln scan (deps) | `task security:vuln-deps` | `dagger call trivy --scan-type=fs` |
| Chart misconfig | `task security:chart-misconfig` | `dagger call trivy --scan-type=config --scan-ref=chart` |
| Tidy go.mod | `task go:tidy` | `go mod tidy` on main + `dagger/` (direct, no Dagger) |
| Bump Go deps | `task go:upgrade` | `go get -u ./...` + tidy on main + `dagger/` (direct) |
| Renovate dry-run | `task renovate:plan` | extracts deps + lists planned bumps without modifying files (debug `renovate.json5`) |
| Renovate apply | `task renovate:patch` | applies the same bumps to the working tree, format-preserving, best-effort (skips ambiguous cases) |
| Render chart README | `task doc:helm` | `dagger call helm-docs export --path=chart/README.md` |
| Visualize package deps | `task analysis:graph` | `goda graph ./...` → `dot -Tsvg` → `xdg-open` (writes to `dist/graph.svg`) |
| Inspect binary size | `task analysis:size` | builds the host-arch binary then opens `gsa --tui` on it |

## Dagger module architecture

A standard Dagger Module: `dagger.json` at the repo root with
`source: "dagger"` pointing at the source directory. The Dagger CLI
locates the module via find-up, so `dagger call <function>` works
from anywhere in the repo without `-m`.

Layout:

- `dagger.json` (repo root) — module manifest (name, SDK, source dir,
  engine version).
- `dagger/main.go` — `X509Ce` struct + `New` constructor. `New`'s
  `source *dagger.Directory` parameter has `+defaultPath="/"` (resolves
  to the module root = repo root) and a `+ignore=` list for cache-key
  hygiene (excludes `dist/`, `.git/`, etc.).
- `dagger/base.go` — pinned image versions (Renovate-tracked via the
  regex manager in `renovate.json5`) and the `goBase` helper that
  prepares a Go container with go.mod/sum prefetched and cache
  volumes mounted. Helpers are package-private (lowercase) so they're
  not exposed as Dagger functions.
- `dagger/lint.go` — `LintGo`, `LintHelm`, `LintRenovate`,
  `LintMarkdown`. golangci-lint is compiled from source against the
  project's Go toolchain (`GOTOOLCHAIN=auto`) — official prebuilt
  images embed go/parser+go/types of whatever Go they were built with.
- `dagger/test.go` — `Test` runs gotestsum with `-race` + coverage.
  Adds `gcc` + `musl-dev` to the alpine container because `-race`
  requires CGO, which on Alpine pulls those.
- `dagger/security.go` — `Govulncheck` (`@latest` — accepting the
  small drift in exchange for not having to track a separate version)
  and `Trivy` (one parameterized function for both scan families:
  `--scan-type=fs` for Go deps + lockfiles + OS packages; `--scan-type=config`
  with `--scan-ref=chart` for IaC misconfig). Trivy DB cached via a
  Dagger CacheVolume so successive runs skip the ~50 MB download.
- `dagger/helm.go` — `HelmDocs` runs jnorwood/helm-docs and returns a
  `*dagger.File`. The Taskfile chains `... export --path=chart/README.md`
  to materialize it back to the working tree.
- `dagger/dagger.gen.go`, `dagger/internal/` — generated bindings,
  refreshed by `dagger develop`. Gitignored (see `dagger/.gitignore`).

## Dev environment

End-to-end dev loop driven by **Tilt + k3d + Dagger**:

```bash
task dev:cluster:up   # one-shot: k3d cluster + local registry on :5000
task dev:up           # tilt up: watches sources, rebuilds via Dagger, redeploys
task dev:down         # tilt down + destroy cluster, registry, kubeconfig
task test:e2e         # build/deploy/seed and run ./test/e2e against /metrics
```

Layout:

- `Taskfile.yml` `dev:cluster:up` / `dev:cluster:down` tasks — k3d
  bootstrap, fully inlined (no shell wrappers). Idempotent via `if !
  k3d ... get` checks. The cluster is wired to the local registry via
  `--registry-use` so nodes pull from `k3d-x509ce-dev-registry:5000`
  natively. Traefik + ServiceLB are disabled to keep the cluster
  minimal. The kubeconfig is written to `kubeconfig.yaml` at the repo
  root (gitignored) and `~/.kube/config` is left untouched.
- `dev/scenarios/` — single source of truth for fixtures: cert/keypair/chain
  helpers + a list of `Scenario` values describing each Kubernetes object the
  cluster should hold (lifecycle, key algo, format, expected metric series).
  Both the seed and the e2e test import this package.
- `dev/seed/main.go` — applies `scenarios.All()` to the cluster (idempotent
  upsert of namespaces, Secrets and ConfigMaps via `client-go`). Never edit
  YAML manifests for test data — extend the scenarios list instead.
- `dev/values.yaml` — Helm values shared by Tilt and `task test:e2e`. Defines
  every `secretTypes` rule (PEM via `kubernetes.io/tls`, PEM via `Opaque`,
  PKCS#12 with `passphraseKey`, passwordless PKCS#12 via
  `tryEmptyPassphrase`), enables ConfigMap watching, exposes a couple of
  Secret labels, and excludes the negative-test namespace by label.
- `Taskfile.yml` `test:e2e` task — pure-Taskfile pipeline (no shell wrapper).
  Stands up a fully isolated, throwaway k3d cluster + registry whose
  names are suffixed with a random `RUN_ID` (`x509ce-e2e-<hex>` and
  `x509ce-e2e-registry-<hex>`), and asks the kernel for a free
  registry port via `socket.bind(0)` — so multiple `task test:e2e`
  invocations can run in parallel without colliding on docker
  container names or host ports. Generates an ephemeral KUBECONFIG
  via `mktemp`, exports the cluster/registry coordinates as
  `E2E_CLUSTER_NAME` / `E2E_REGISTRY_NAME` / `E2E_REGISTRY_PORT`,
  then hands off to `tilt -f test/e2e/Tiltfile ci`. Teardown is
  registered as a `defer:` command at the top of `cmds:` and runs
  unconditionally — success, failure, or Ctrl-C — covering cluster
  delete, registry delete, and KUBECONFIG removal. No pre-flight
  cleanup pass: stale state from a previous run cannot share names
  with this one. Completely independent from the dev cluster.
- `test/e2e/Tiltfile` — drives everything that runs *inside* the e2e cluster:
  Dagger image build + push to local e2e registry → `helm_resource()`
  with `dev/values.yaml` + `test/e2e/values.yaml` overrides → seed →
  `local_resource("e2e-test")` running `go test -tags=e2e`. Run via
  `tilt ci`, exits non-zero iff any resource fails.
- `test/e2e/values.yaml` — e2e overrides on top of `dev/values.yaml`.
  Disables the chart's ServiceMonitor + PrometheusRule (no
  prom-operator CRDs needed; the test scrapes `/metrics` directly).
- `test/e2e/e2e_test.go` — gated behind the `e2e` build tag. Scrapes
  `/metrics` from the running exporter, parses with `expfmt.TextParser`,
  asserts every `scenarios.All()` entry has the expected
  `x509_cert_not_after` / `x509_cert_expired` series and that the negative
  scenarios are absent / produce the right `x509_source_errors_total` reason.
- `Tiltfile` — dev loop only. Orchestrates: ensure-cluster → install
  kube-prometheus-stack (operator + lightweight Prometheus, all optional
  sub-charts disabled) → `custom_build()` calling Dagger → `helm_resource()`
  deploy of the exporter (`--values ./dev/values.yaml`) → seed. Distinct
  cluster (`x509ce-dev`) and registry (port 5000), so a `task test:e2e` run
  can happen in parallel without clashing on cluster state.

GoReleaser + Tilt hookup: `custom_build()` watches `cmd/`, `pkg/`,
`internal/`, `go.mod`, `go.sum`, `build/Dockerfile.busybox`, `.goreleaser.yaml`.
On any change Tilt invokes `goreleaser release --snapshot ...` with
`GORELEASER_TILT=1`, which builds a single host-arch image from
`build/Dockerfile.busybox` (the alt release variant — kept for dev
because it ships a shell, even though scratch is the project default)
and loads it into the local Docker daemon. A `docker tag` post-step strips the
`-<arch>` suffix that dockers_v2 appends in snapshot mode so Tilt
finds the image at exactly `EXPECTED_REF`. Tilt then pushes to the
local registry; Helm is reconfigured with the new tag and the pod
restarts.

Forwarded ports:

- `localhost:9793` — exporter metrics
- `localhost:9090` — Prometheus UI (already configured to scrape the exporter
  via the chart's ServiceMonitor; rules from `prometheusRules.create=true` are
  also picked up because Prometheus has no selector filter)

The exporter chart's `prometheusServiceMonitor.create` and `prometheusRules.create`
default to `true`, so no extra config is needed for Prometheus to scrape and
alert on the dev cluster.

**Note on build times**: Rebuilding and redeploying the `x509-certificate-exporter`
Tilt resource takes about a minute. Keep this delay in mind when checking
the pod's state or making HTTP requests to it right after modifying source files.

## Coding conventions

- Public API lives in `pkg/`, internals in `internal/`. Don't promote a package
  from `internal/` without a real consumer.
- Tests use the standard `*_test.go` colocated layout. Prefer table-driven tests
  for the parser/registry packages.
- Parsers that consume untrusted bytes (PEM, PKCS#12, fileglob patterns) carry
  `Fuzz*` targets in `*_fuzz_test.go` files. `task test:fuzz` runs each for 5s
  (smoke); for a real session use `go test -fuzz=<name> -fuzztime=10m ./<pkg>`.
  A crash gets persisted under `testdata/fuzz/...` and becomes a regression
  test — commit those files alongside the fix.
- Version metadata is injected at build time via `-ldflags -X` into
  `internal/product`. Don't read it from env or from disk at runtime.
- The `formatVersion` short form is `MAJOR.MINOR.PATCH+gSHORTSHA` and gets a
  `.dirty` suffix when the working tree is dirty.

## Chart conventions

**Whenever you touch `chart/values.yaml`, `chart/templates/**`, or
anything else that influences the chart's rendered output**, walk
through this checklist before considering the work done — the test
infrastructure exists to catch the cases you forget, but the
discipline minimises that load. Think hard about each item; the
generated artefacts and the schema fixtures are intentionally a
ratchet that cannot be loosened without explicit human review.

1. **Regenerate the doc artefacts**: `task doc:helm` rebuilds both
   `chart/README.md` (helm-docs from `chart/README.md.gotmpl` +
   `# --` docstrings) and `chart/values.schema.json` (helm-schema
   from `# @schema` annotations). Commit both alongside your change.
   The `chart-readme.yaml` CI workflow enforces lockstep.
2. **Audit the schema annotations on `chart/values.yaml`**. Every
   new value field deserves a `# @schema` block. Convention:
   - Strict on chart-defined params: enums (`pullPolicy`, `severity`,
     `format`, …), `minimum`/`maximum` ranges (ports, replicas,
     retention windows), `oneOf` mutex (e.g. `secretTypes` items),
     `additionalProperties: false` on closed structures.
   - Permissive (`additionalProperties: true; properties: {}`) on K8s
     pass-through fields where the user must be free to set anything
     the K8s API admits — `resources`, probes, `securityContext`,
     `nodeSelector`, `affinity`, `tolerations[].items`, etc.
3. **Add fixtures** under `test/schema/{valid,invalid}/`:
   - `valid/<name>.yaml` for any new constraint that should accept a
     class of legitimate user input (lock down "this works").
   - `invalid/<name>.yaml` paired with `<name>.expect.txt` listing
     JSON-path-anchored substrings (e.g. `at '/foo/bar'`) that helm
     lint must surface in the rejection. Anchor on the path, not the
     wording — helm's exact error string is less stable than the path.
   - Run `task test:helm-fixtures` to validate.
4. **Verify `task test:helm-examples`** still passes — every file
   under `docs/examples/**` must continue to validate against the
   updated schema. If it doesn't, you either broke a documented
   path (regression — fix the schema or the chart) or the example
   was wrong all along (legitimate find — fix the example, mention
   it in the commit message).

Treat the schema + fixtures as a regression net. A future intentional
loosening of a constraint surfaces as a fixture failure that the
reviewer must explicitly acknowledge by deleting / weakening the
fixture. That's the right level of friction.

## Go version: single source of truth

`go.mod`'s `go X.Y.Z` directive is the only place the Go version is pinned.
Every other reference is intentionally loose:

- `dagger/base.go`'s `golangImage` constant (`golang:X.Y.Z-alpine`) is
  a *bootstrap* image; Renovate keeps it close to `go.mod` for cache
  hits, but if it drifts, Go's `GOTOOLCHAIN=auto` (set in the `goBase`
  helper) downloads the exact toolchain declared in `go.mod` on demand.
- `flake.nix` uses unpinned `pkgs.go` for the same reason — the dev shell
  runs whatever Go nixpkgs ships, and `GOTOOLCHAIN=auto` handles the rest.
- The CI workflows use `actions/setup-go@v5` with `go-version-file: go.mod`,
  so the runner automatically picks up whatever version `go.mod` declares.
  No separate `VERSION_GOLANG` env to track.

To bump Go: change `go.mod`'s `go` directive (or let Renovate do it).
Everything else either auto-updates or auto-resolves at build time.

## Release pipeline

Releases are tag-driven. A maintainer pushes a `vX.Y.Z` tag manually
(or via automation) and the [`release.yaml`](.github/workflows/release.yaml)
workflow fires. GoReleaser drives all the heavy lifting: changelog generation,
binary cross-compilation, container images, chart packaging, signing, and
creating a draft GitHub Release. The maintainer reviews the draft and
publishes it manually.

Changelog sections in GoReleaser's `changelog.groups` (`.goreleaser.yaml`)
mirror the Conventional Commit type mapping:
Security Updates (`security:`), Features (`feat:`), Bug Fixes (`fix:`),
Performance (`perf:`), Dependencies (`deps:`), Documentation (`docs:`).
Types `ci:`, `chore:`, `refactor:`, `test:`, `build:` are excluded from the
public changelog.

### Build & publish — release.yaml

Triggered by a `v*` tag push. The pipeline splits "build everything"
from "push to public registries" so reviewers gate **publishing**, not
**building** — which means the artifacts they approve are bit-identical
to what users pull (verified by digest, not rebuilt). Five jobs:

1. **`security` / `lint` / `test`** — reusable workflows, same gates as
   PRs. No `release` Environment access.
2. **`build`** (no Environment) — drives `goreleaser release` with
   `GORELEASER_PUBLISH_TARGETS=ghcr-only`. Builds binaries × 6 OS / 4
   archs (with exclusions), archives, checksums, two multi-arch
   container images (scratch default, busybox alt) — and pushes
   them **only to GHCR** (auth via `GITHUB_TOKEN`). Cosign-signs the
   checksums file (`signs:` blob) and every pushed image
   (`docker_signs` by digest). Emits a SLSA Build Level 3 provenance
   attestation over `dist/checksums.txt` via
   `actions/attest-build-provenance`. Generates a CycloneDX SBOM per
   image (syft) and attaches it as a cosign attestation. Packages the
   Helm chart, pushes it to GHCR staging at
   `ghcr.io/enix/<IMAGE_NAME>/charts/<CHART_NAME>:<VERSION>`, signs it
   with cosign keyless. Creates the GitHub Release as a **draft** with
   binaries + checksums + sigstore bundle attached. Uploads
   `dist/publish-manifest.json` (image refs, chart ref, prerelease
   flag) as a workflow artifact for the publish job.
3. **`publish`** (env `release`, gated by required reviewers) — pure
   mirror step. Logs into quay.io, docker.io, and `CHART_REGISTRY`,
   then `oras copy -r`s every staged image and the chart from GHCR
   to the public registries. `oras copy -r` follows OCI 1.1
   referrers, so the cosign signature, SLSA provenance attestation,
   and CycloneDX SBOM all travel with the artifact by digest;
   nothing is rebuilt or re-signed. (cosign 3.x stores all three as
   referrers; `cosign copy` is deprecated and does not follow them.)
   The destination ref's chart path is the canonical user-facing
   form (`<CHART_REGISTRY>/<CHART_NAME>`), not the GHCR staging
   path.
4. **`helm-index`** (env `release`) — pulls the chart back from
   `CHART_REGISTRY`, regenerates the classic Helm repo index, pushes
   it as an OCI artifact, then triggers the publish workflow in
   `enix/helm-charts` to refresh `https://charts.enix.io`. Keeps the
   legacy `helm repo add` install path working.
5. **`release-edit`** — flips the GitHub Release out of draft state.
   Last step: if any prior job fails, the release stays a draft and
   no public-facing announcement happens.

GoReleaser refuses to release on a dirty working tree, which gives a
free reproducibility guarantee.

The `GORELEASER_PUBLISH_TARGETS=ghcr-only` env var swaps the
`dockers_v2` entries via `disable:` templates: `scratch` and `busybox`
disable themselves, while `scratch-ghcr` and `busybox-ghcr` (single
GHCR target, otherwise identical) take over. Manual `goreleaser
release` runs (env unset) keep pushing to all three registries — the
ghcr-only mode is opt-in for the CI build phase only.

**Repo-level** variables (Settings → Variables, no Environment scope —
accessible to the build job which runs without environment access):

- `IMAGE_NAME` — container image name (e.g. `x509-certificate-exporter`)
- `CHART_NAME` — Helm chart name (often == `IMAGE_NAME`)

**Environment-scoped** variable on `release`:

- `CHART_REGISTRY` — OCI host/namespace where the chart is pushed,
  WITHOUT the `oci://` scheme (e.g. `quay.io/enix/charts`).

The container image registries (`ghcr.io/enix`, `quay.io/enix`,
`docker.io/enix`) are hardcoded in `.goreleaser.yaml` rather than
sourced from a variable. A fork that needs different namespaces edits
that file directly.

The Go binary is hardcoded as `x509-certificate-exporter` in
`.goreleaser.yaml`'s `binary:` field (and in the archive
`name_template`). Release archives are therefore named uniformly
across forks — only the *image* and *chart* identities change via
the `vars.*` overrides. Consumers downloading binaries always
extract a binary called `x509-certificate-exporter` and can script
against that name.

Registry credentials live on the `release` Environment (only the
publish + helm-index jobs need them; the build job runs with only
`GITHUB_TOKEN` for GHCR):

- Image registries: `QUAY_USERNAME`/`QUAY_TOKEN`,
  `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`. GHCR uses the runner's
  `GITHUB_TOKEN`.
- Chart registry: `CHART_REGISTRY_USERNAME`/`CHART_REGISTRY_TOKEN` —
  intentionally provider-agnostic (no `QUAY_*` re-use) so the chart
  can be hosted independently of the image registries (e.g. quay.io
  for images and ghcr.io for the chart, or vice-versa).

Verification commands for downstream consumers are documented in the
[hardening guide](./docs/hardening.md).

## Renovate

**Self-hosted on GitHub Actions** (no Mend app installed). The
[`renovate` workflow](.github/workflows/renovate.yaml) invokes the
Renovate CLI on a weekly cron + `workflow_dispatch` + on every push that
modifies `renovate.json5`. Auth is via a GitHub App
(`RENOVATE_APP_CLIENT_ID` + `RENOVATE_APP_PRIVATE_KEY` secrets) so
PRs/commits come from the bot identity and downstream workflows trigger
on them.

`renovate.json5` deliberately has **no top-level `schedule:`** — the
workflow's cron is the single source of timing truth. Adding a schedule
to the config would silently neuter manual `workflow_dispatch` runs
outside the configured window.

For local config debugging, `task renovate:plan` runs the CLI in
`--platform=local` mode with the default `dryRun=lookup`: extract +
lookup phases only, nothing written to disk. Use it to verify that
managers catch what you expect, inspect `skipReason`s, and see how
groupings/branches resolve. Actual bumps still come from the Actions
workflow.

`task renovate:patch` is the same dry-run, but its JSON debug output
is piped to `scripts/renovate-patch.py`, which finds the
`packageFiles with updates` event and applies each dep's first update
in place — replacing the exact `replaceString` Renovate would have
edited, preserving formatting and comments byte-for-byte. Best-effort:
any ambiguity (replaceString missing/non-unique, pinDigest on a
previously unpinned dep, rollback updates, etc.) is SKIPPED with a
diagnostic on stderr. The intent is to leave the working tree in a
state Renovate's own delta logic can pick up cleanly on its next
scheduled run.

Both `renovate:plan` and `renovate:patch` template the same image from
the Taskfile var `RENOVATE_IMAGE`. A regex manager in `renovate.json5`
tracks that one declaration, so the Taskfile auto-bumps in lockstep
with `renovateImage` in `dagger/base.go` — no manual sync required.

Config validated via `task lint:renovate` (runs `renovate-config-validator`
inside the official Renovate image, sandboxed by Dagger). Highlights:

- `build/Dockerfile.scratch` (default variant) and `build/Dockerfile.busybox`
  (alt variant with shell) `FROM` lines tracked natively by the
  dockerfile manager, with `pinDigests: true` (via packageRule with
  `matchCategories: ["docker"]`).
- Custom regex managers for the K3s image in `Taskfile.yml`
  (`K3S_IMAGE`, shared by dev + e2e clusters), the kube-prometheus-stack version in `Tiltfile`
  (`KUBE_PROMETHEUS_VERSION`), the container images pinned as Go
  constants in `dagger/base.go` (`golangImage`, `alpineImage`,
  `helmImage`, `renovateImage`, `helmDocsImage`), and the
  `golangciLint` / `gotestsumModule` Go install versions in the same
  file.
- Go-toolchain bumps (gomod + `dagger/base.go` `golangImage`) land in
  a single PR via `groupName: "golang toolchain"`. CI workflows pick
  up the Go version from `go.mod` directly via `setup-go`'s
  `go-version-file`.
- `flake.lock` and transitive `go.sum` entries refreshed on every
  Renovate run via `lockFileMaintenance`.
