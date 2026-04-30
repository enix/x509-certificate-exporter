# Project notes for Claude

## Layout (v4)

- `cmd/x509-certificate-exporter/` — binary entrypoint
- `pkg/cert/` — public API for certificate parsing (`pem`, `pkcs12` subpackages)
- `pkg/registry/` — public Prometheus collector + label registry
- `internal/` — everything else (config, log, source/{file,k8s}, server, fileglob, product)
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
  busybox + scratch variants, push to ghcr/quay/docker.io, cosign
  keyless on everything, GitHub Release (CI via `release.yaml`).
  Local: `task image` (full snapshot), `task image:local` (host-arch
  only). Dev: Tilt's `custom_build` calls `goreleaser` directly with
  `GORELEASER_TILT=1`, gating a dedicated dockers_v2 entry that uses
  the same `build/Dockerfile.busybox` as the release — single source of
  truth for the image, dev == release.
- **Direct CLI** for things that don't need a sandbox: k3d/tilt/helm
  on the dev cluster, ratchet against `.github/workflows/*.yaml`,
  Renovate dry-run via Docker, and `go mod tidy` / `go get -u` (pure
  toolchain operations — Dagger overhead would buy us nothing because
  `GOTOOLCHAIN=auto` makes host execution bit-identical anyway).

| Goal | Command | Notes |
|---|---|---|
| Local binary | `task build` | Direct `go build -trimpath -tags netgo,osusergo` to `bin/x509-certificate-exporter` |
| Snapshot all images | `task image` | `goreleaser release --snapshot --skip=publish,sign` — verify config without pushing |
| Snapshot host-arch only | `task image:local` | Same as `task image` but only host arch (no QEMU cross-build) |
| Lint Go | `task lint:go` | `dagger call lint-go` — full golangci-lint set |
| gocritic only | `task lint:gocritic` | `dagger call lint-go --mode=gocritic` |
| Go lint without gocritic | `task lint:gonocritic` | `dagger call lint-go --mode=no-critic` |
| Lint Helm | `task lint:helm` | `dagger call lint-helm` |
| Lint Markdown | `task lint:markdown` | `dagger call lint-markdown` |
| Lint all | `task lint` | Go + Helm + Renovate + Markdown |
| All tests | `task test` | runs `test:unit` + `test:e2e` sequentially |
| Unit tests | `task test:unit` | `dagger call test` — gotestsum + `-race` + coverage |
| End-to-end tests | `task test:e2e` | throwaway k3d cluster, Helm install, scrape `/metrics` |
| Vuln scan | `task security:govulncheck` | `dagger call govulncheck` |
| Vuln scan (deps) | `task security:vuln-deps` | `dagger call trivy --scan-type=fs` |
| Chart misconfig | `task security:chart-misconfig` | `dagger call trivy --scan-type=config --scan-ref=chart` |
| Tidy go.mod | `task go:tidy` | `go mod tidy` on main + `dagger/` (direct, no Dagger) |
| Bump Go deps | `task go:upgrade` | `go get -u ./...` + tidy on main + `dagger/` (direct) |
| Renovate dry-run | `task renovate:plan` | extracts deps + lists planned bumps without modifying files (debug `renovate.json5`) |
| Pin GH Actions to SHAs | `task ratchet:pin` | one-shot bootstrap: rewrite every `@v4` to `@<sha> # v4` in workflows |
| Refresh pinned Action SHAs | `task ratchet:update` | resolve current pinned SHAs to latest of their tracked tag (out-of-band of Renovate) |
| Render chart README | `task doc:helm` | `dagger call helm-docs export --path=chart/README.md` |

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
  hygiene (excludes `bin/`, `dist/`, `.git/`, etc.).
- `dagger/base.go` — pinned image versions (Renovate-tracked via the
  regex manager in `renovate.json5`) and the `goBase` helper that
  prepares a Go container with go.mod/sum prefetched and cache
  volumes mounted. Helpers are package-private (lowercase) so they're
  not exposed as Dagger functions.
- `dagger/lint.go` — `LintGo` (with `--mode=` flag for full /
  `gocritic` / `no-critic` subsets), `LintHelm`, `LintRenovate`,
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
task dev:down         # tilt down (cluster persists)
task dev:cluster:down # full teardown
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
  Stands up an isolated, throwaway k3d cluster (`x509ce-e2e`) + registry
  (port 5001), generates an ephemeral KUBECONFIG via `mktemp`, hands off
  to `tilt -f test/e2e/Tiltfile ci`. Teardown is registered as a `defer:`
  command at the top of `cmds:` and runs unconditionally — success,
  failure, or Ctrl-C — covering cluster delete, registry delete, and
  KUBECONFIG removal. A pre-flight cleanup pass clears any leftover
  state from a previous run that died before its defer could fire
  (SIGKILL, power loss). Completely independent from the dev cluster:
  different cluster name, different registry port, ephemeral kubeconfig.
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
`GORELEASER_TILT=1`, which builds a single host-arch busybox image
(via `build/Dockerfile.busybox` — same as the release) and loads it into
the local Docker daemon. A `docker tag` post-step strips the
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
- Version metadata is injected at build time via `-ldflags -X` into
  `internal/product`. Don't read it from env or from disk at runtime.
- The `formatVersion` short form is `MAJOR.MINOR.PATCH+gSHORTSHA` and gets a
  `.dirty` suffix when the working tree is dirty.

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

Two workflows cooperate:

### Versioning & tagging — release-please

The [`release-please` workflow](.github/workflows/release-please.yaml)
runs on every push to `main`. It maintains a permanent "release PR"
that aggregates Conventional Commits since the last released tag,
computes the next SemVer bump, and updates `CHANGELOG.md` +
`.release-please-manifest.json`. Merging that PR causes release-please
to:

- Push a `vX.Y.Z` tag on the merge commit
- Create an empty GitHub Release stub

Config in `release-please-config.json`. Section mapping is conventional
(feat → Features, fix → Bug Fixes, deps → Dependencies, etc.); chore /
ci / refactor / test / build are kept hidden from the public changelog
but still inform the SemVer bump.

The workflow runs under a GitHub App identity (`RELEASE_PLEASE_APP_*`
secrets) — required because tags pushed under the default `GITHUB_TOKEN`
do not trigger downstream workflows. The App-issued token is exempt
from that guard, so the `release.yaml` pipeline picks up the new tag.

### Build & publish — release.yaml

Triggered by the tag created above. Three jobs, all driven by
[`.goreleaser.yaml`](./.goreleaser.yaml) for the heavy lifting:

1. **`goreleaser`** (env `release`, gated by required reviewers) —
   builds binaries × 6 OS / 4 archs (with exclusions for non-existent
   combos), packages as `.tar.gz` / `.zip`, computes checksums, signs
   the checksums file with cosign keyless. Builds two multi-arch
   container images (busybox + scratch, each spanning amd64/arm64/
   riscv64) via GoReleaser's `dockers_v2` — one `docker buildx build
   --push --platform=...` per variant, hitting ghcr/quay/docker.io in
   one go. Each pushed multi-arch image is signed with cosign keyless
   (`docker_signs` → `artifacts: images`). Then a post-loop reads
   `dist/artifacts.json`, resolves each pushed image tag → digest,
   runs syft for an image SBOM, and attaches it as a cosign
   attestation (predicateType `cyclonedx`). The Dockerfiles use
   `ARG TARGETPLATFORM` + `COPY $TARGETPLATFORM/<binary>` per the
   dockers_v2 build-context layout.
2. **`slsa`** — invokes the
   [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
   reusable workflow with the base64-encoded `dist/checksums.txt` from
   GoReleaser as the subject. Produces `x509-certificate-exporter.intoto.jsonl`
   attached to the GitHub Release. **Tag-pinned (not SHA-pinned)** —
   the workflow's internal logic uses the tag to download its release
   binary; SHA-pin would break it. See the comment above the `slsa:`
   job for details.
3. **`chart`** (env `release`) — packages the Helm chart with `helm
   package` (overriding `name:`/`version:`/`appVersion:` in-runner
   from the env vars + tag, so the chart on disk stays generic),
   pushes as an OCI artifact, signs with cosign keyless. Waits on
   `goreleaser` so the chart's image references point to images that
   actually exist in the registries.

GoReleaser refuses to release on a dirty working tree, which gives a
free reproducibility guarantee.

The `goreleaser` and `chart` jobs both run in the `release` GitHub
Environment. Three `vars.*` MUST be set on that Environment (no
fallback — the workflow validates and fails fast):

- `IMAGE_NAME`     — container image name (e.g. `x509-certificate-exporter`)
- `CHART_NAME`     — Helm chart name (often == `IMAGE_NAME`)
- `CHART_REGISTRY` — OCI host/namespace where the chart is pushed,
                     WITHOUT the `oci://` scheme (e.g. `quay.io/enix/charts`).
                     The workflow prepends `oci://` only where helm
                     needs it; cosign and the verification commands
                     consume the bare form directly.

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

Registry credentials live on the `release` Environment:

- Image registries: `QUAY_USERNAME`/`QUAY_TOKEN`,
  `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`. GHCR uses the runner's
  `GITHUB_TOKEN`.
- Chart registry: `CHART_REGISTRY_USERNAME`/`CHART_REGISTRY_TOKEN` —
  intentionally provider-agnostic (no `QUAY_*` re-use) so the chart
  can be hosted independently of the image registries (e.g. quay.io
  for images and ghcr.io for the chart, or vice-versa).

Verification commands for downstream consumers are documented in the
[README](./README.md#-verifying-authenticity).

## Renovate

**Self-hosted on GitHub Actions** (no Mend app installed). The
[`renovate` workflow](.github/workflows/renovate.yaml) invokes the
Renovate CLI on a weekly cron + `workflow_dispatch` + on every push that
modifies `renovate.json5`. Auth is via a GitHub App (`RENOVATE_APP_ID` +
`RENOVATE_APP_PRIVATE_KEY` secrets) so PRs/commits come from the bot
identity and downstream workflows trigger on them.

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

The Renovate image tag in that task must stay in sync with the
`renovateImage` constant in `dagger/base.go` (Renovate's dockerfile
manager doesn't scan inside `docker run` invocations or Go const
declarations directly — both rely on regex managers configured in
`renovate.json5`).

Config validated via `task lint:renovate` (runs `renovate-config-validator`
inside the official Renovate image, sandboxed by Dagger). Highlights:

- `build/Dockerfile.busybox` and `build/Dockerfile.scratch` `FROM` lines tracked
  natively by the dockerfile manager, with `pinDigests: true` (via
  packageRule with `matchCategories: ["docker"]`).
- Custom regex managers for the K3s image in `Taskfile.yml`
  (`DEV_K3S_IMAGE`), the kube-prometheus-stack version in `Tiltfile`
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
