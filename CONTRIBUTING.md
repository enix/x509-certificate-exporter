# Contributing

Welcome — this document is the developer's manual for the
`x509-certificate-exporter` repository. It walks you through environment
setup, the toolchain, the dev loop, common workflows, and troubleshooting.

If you're an end-user looking to deploy the exporter, head to the
[main README](./README.md) and the [chart README](./chart) instead. If you
came here because you want to fix a bug or ship a feature, you're in the
right place.

## Quickstart

For the impatient. Assumes a Linux or macOS host with [Nix](https://nixos.org/download)
installed and the Docker daemon running:

```sh
git clone git@github.com:enix/x509-certificate-exporter.git
cd x509-certificate-exporter
nix develop                    # drops you into a shell with every tool pinned
task --list                    # discover every available task and what it does
task dev:cluster:up            # spins up a k3d cluster + local registry
task dev:up                    # tilt up: builds, deploys, seeds, watches
```

Tilt's UI is available immediately at `http://localhost:10350`. Once Tilt
signals every resource as Ready, the exporter is being scraped on
`http://localhost:9793/metrics` and Prometheus is running at
`http://localhost:9090` with the chart's ServiceMonitor and PrometheusRule
already loaded. Edit a `.go` file under `cmd/`, `pkg/`, or `internal/` and
Tilt rebuilds + redeploys automatically.

## Prerequisites

### Supported platforms

The dev loop runs on Linux (any reasonably recent distro) and macOS. Windows
isn't tested but should work via WSL2.

You need a working **container runtime** that exposes a Docker-compatible
socket — Docker Desktop, Colima, OrbStack, or a native Docker installation
on Linux all work. Dagger and Tilt both interact with this socket; if
`docker ps` doesn't return cleanly, neither will work.

**RAM**: 8 GB minimum. The k3d cluster + Prometheus + the exporter consume
~2 GB; the Dagger engine needs 1-2 GB during builds; the rest is your
editor and OS.

**Disk**: 10 GB free. Dagger's cache volumes can grow to several GB. Run
`docker volume rm dagger-cache-go-mod dagger-cache-go-build` to reclaim
space (see Troubleshooting).

### What to install before everything else

The bare minimum the host machine must have:

- **A POSIX shell** (`bash` or `zsh`)
- **Git** ≥ 2.30
- **A Docker-compatible socket** (see above)
- **[Nix](https://nixos.org/download)** with flakes enabled (recommended), OR the manual list below

Everything else — Go, Dagger, GoReleaser, Task, Tilt, k3d, kubectl, Helm —
is pulled in by the Nix flake. Don't try to install them separately if
you go the Nix route; you'll fight version drift forever.

### The Nix way (recommended)

The repository ships a [`flake.nix`](./flake.nix) that pins the exact
versions of every CLI used in the dev loop. Activate it with:

```sh
nix develop
```

You'll find yourself in a shell where `go`, `dagger`, `goreleaser`,
`task`, `tilt`, `k3d`, `kubectl` and `helm` are all on the `$PATH`, all
consistent with what CI uses. Exit with `Ctrl-D`.

To make this automatic on every `cd` into the repo, install
[direnv](https://direnv.net) and run `direnv allow` once. From that point
forward, entering the repo loads the dev shell; leaving unloads it. No
mental overhead.

The flake is tested on `x86_64-linux` and `aarch64-darwin`. If you're on
something more exotic, file an issue.

#### Why pinning Go feels different

The flake exposes `pkgs.go` (whatever Go version Nixpkgs ships at the
moment of `flake.lock`'s last update) — *unpinned at the patch level*.
This is intentional. The actual Go toolchain used by `go build` is the
one declared in [`go.mod`](./go.mod)'s `go X.Y.Z` directive, thanks to
`GOTOOLCHAIN=auto` (set in the Dagger `goBase` helper). If your local
shell's `go` is older than `go.mod`'s declared version, Go itself will
download the matching toolchain on first use. So:

- The flake's `go` is just a bootstrap.
- `go.mod`'s `go` directive is the single source of truth for the
  language version.
- Renovate keeps both close together so the bootstrap doesn't trigger
  toolchain downloads.

If you ever need to bump Go: edit `go.mod` only, or let Renovate do it.

### The "pet my system" way (without Nix)

Not recommended, but if you can't or won't use Nix, install these manually
at the versions Nixpkgs currently ships (run `nix develop` once on a
peer's machine to read the exact versions, or check `flake.lock`):

- **Go** ≥ what `go.mod` declares
- **[Dagger CLI](https://dagger.io)** (only needed if you want
  `dagger` on your `$PATH`; the SDK in `dagger/` runs without it)
- **[GoReleaser](https://goreleaser.com/install/)** (for local image
  snapshots via `task image:local` / `task image:all`)
- **[Task](https://taskfile.dev/installation/)** ≥ 3
- **[Tilt](https://docs.tilt.dev/install.html)**
- **[k3d](https://k3d.io)**
- **`kubectl`** matching your target cluster
- **`helm`** ≥ 3.18

You're on your own for keeping these in sync with what CI uses.

## Toolchain

The repo deliberately uses a stack of small, sharp tools rather than one
monolithic build system. Each tool does one thing well and delegates
the rest. Here's what each one does and why it's there.

### Dagger — sandboxed QA/CI pipelines

[Dagger](https://dagger.io) drives every reproducible QA/CI pipeline
in the repo: linting, unit tests, security scans, helm chart docs.
It's wired as a [Dagger Module](https://docs.dagger.io/modules) —
[`dagger.json`](./dagger.json) at the repo root, source files under
[`dagger/`](./dagger/). The Dagger CLI locates the module via find-up
from any cwd in the repo, so `dagger call` Just Works. Container
image builds — both release and dev — go through GoReleaser instead,
so there's a single Dockerfile path.

Each exported method on the `X509Ce` struct is exposed as a function:

```sh
dagger call lint-go                          # full golangci-lint set
dagger call lint-markdown                    # markdownlint on hand-written docs
dagger call test                             # unit tests with race + coverage
dagger call govulncheck                      # reachability-based CVE scan
dagger call helm-docs export --path=chart/README.md  # regenerate chart/README.md
```

Things that *don't* run via Dagger, on purpose: `go mod tidy` and
`go get -u` are pure toolchain operations — no third-party tools, no
heavy compilation — so `task go:{tidy,upgrade}` invokes them directly
on the host. `GOTOOLCHAIN=auto` (Go's default) makes the result
bit-identical to a sandboxed run, without paying engine-startup cost.

Why Dagger:

- **Reproducibility**: each function defines a container, a series of
  commands, and the inputs/outputs explicitly. Same result on your
  laptop and on a fresh CI runner.
- **Cache volumes**: persistent caches for `/go/pkg/mod` and
  `/root/.cache/go-build` are shared across runs; subsequent
  invocations are seconds, not minutes.
- **Just Go code**: pipelines are `*.go` files you read and debug like
  any other Go code. No DSL, no CI YAML.
- **Local Docker daemon as backend**: Dagger auto-starts an engine via
  the local Docker socket on first call. Nothing else to configure.

You'll rarely invoke `go run ./dagger ...` directly — [`Taskfile.yml`](./Taskfile.yml)
wraps every function as a `task` target. But for ad-hoc invocations or
debugging a pipeline definition, the SDK code is heavily commented in
[`dagger/`](./dagger/).

### GoReleaser — every container image (release AND dev)

[GoReleaser](https://goreleaser.com) handles every container image in
the repo. For releases: cross-compile binaries × OS/arch, package as
`.tar.gz` / `.zip`, compute checksums, build multi-arch container
images for the scratch (default) and busybox (alt) variants, push to
the three registries, sign everything with sigstore/cosign keyless,
attach assets to a GitHub Release.

Locally:

- `task image:local` — host-arch snapshot, fast iteration.
- `task image:all` — full snapshot (all archs, both variants);
  validates the release config end-to-end without pushing.
- Tilt's `custom_build` invokes `goreleaser` directly with
  `GORELEASER_TILT=1`, which gates a dedicated `dockers_v2` entry
  using `build/Dockerfile.busybox` (the alt release variant — picked
  for dev because it ships a shell, even though scratch is the project
  default). The dev image is the release image's alt variant — minus
  the multi-arch and the registry push.

The whole pipeline is declared in [`.goreleaser.yaml`](./.goreleaser.yaml).
CI runs it via [`.github/workflows/release.yaml`](./.github/workflows/release.yaml).

### Task — the developer façade

[go-task](https://taskfile.dev) is a Make replacement that's nice to
read, nice to write, and supports cross-platform shell quirks better
than Make ever did. Our [`Taskfile.yml`](./Taskfile.yml) is a thin
layer that maps short, namespaced names to either Dagger functions,
GoReleaser invocations, or direct CLI calls:

```sh
task --list                   # show every available task with description
task build                    # `goreleaser build --single-target` — host-arch binary, stable symlink at dist/x509-certificate-exporter
task image:local              # `goreleaser release --snapshot ...` host-arch only
task image:all                # same but every cross-arch variant
task lint                     # → go run ./dagger lint:go (+helm, +renovate)
task test                     # runs test:unit, test:fuzz, test:e2e
```

Whenever you're not sure what command to run, `task --list` is the answer.

A few things Task adds beyond aliasing:

- **Defer hooks**: the `test:e2e` task uses `defer:` to guarantee cluster
  teardown even on Ctrl-C or SIGKILL.
- **Variable interpolation**: dev cluster name, registry port, Kubeconfig
  path — all defined once at the top of `Taskfile.yml`.
- **Task chaining**: `task lint` runs `lint:go`, `lint:helm`, and
  `lint:renovate` in order, fail-fast.

### Nix — the dev shell

[Nix](https://nixos.org) is a package manager + functional configuration
language. Its only job in this repo is to provision the dev shell —
nothing builds the binary or the images via Nix.

The flake's `devShells.default` lists every CLI you need (`go`, `task`,
`dagger`, `goreleaser`, `tilt`, `k3d`, `kubectl`, `helm`, `cosign`,
`rekor-cli`, plus `goda` and `gsa` for Go binary-size analysis).
Activating the shell sets `$PATH` to include those, so they resolve
without you ever installing them globally. When you leave the shell,
they're gone from your `$PATH` again. No system pollution.

Adding a new tool: edit [`flake.nix`](./flake.nix), add the package to
`packages`, and run `task nix:update` to refresh the lockfile. Open a PR.

### Tilt — the live dev loop

[Tilt](https://tilt.dev) watches your source tree, rebuilds the image
when something changes, redeploys to the dev cluster, and shows you
everything in a web dashboard at `http://localhost:10350`.

Two Tiltfiles in the repo:

- **[`Tiltfile`](./Tiltfile)** drives `task dev:up`. It deploys the
  exporter into the long-lived `x509ce-dev` cluster alongside
  kube-prometheus-stack. Use this for daily development.
- **[`test/e2e/Tiltfile`](./test/e2e/Tiltfile)** drives `task test:e2e`. It runs
  in a throwaway cluster (`x509ce-e2e-<hex>`), seeds fixtures, runs the
  e2e test, and exits non-zero if anything fails.

Tilt's secret sauce in this repo is its `custom_build()` directive: when
a watched file changes, Tilt invokes `goreleaser release --snapshot`
in tilt mode (`GORELEASER_TILT=1`), which builds a single host-arch
image from `build/Dockerfile.busybox` (kept for dev because of the
shell — scratch is the project default), loads it into local Docker,
then Tilt pushes to the k3d registry and lets Helm reconcile. End-to-end on a small change is about a minute.

When something looks weird, the Tilt UI shows the build log per resource
in real time — usually the fastest way to debug.

### k3d — the local Kubernetes cluster

[k3d](https://k3d.io) wraps [k3s](https://k3s.io) (lightweight Kubernetes)
in Docker containers. It's our local cluster for both dev and e2e.

Two clusters live side by side:

| Cluster | Created by | Purpose | Registry port |
| --- | --- | --- | --- |
| `x509ce-dev` | `task dev:cluster:up` | Long-lived dev loop | 5000 |
| `x509ce-e2e-<hex>` | `task test:e2e` | Throwaway, per-run | random (free port allocated by the kernel) |

The e2e cluster + registry names carry a random hex suffix and the
registry port is allocated dynamically, so multiple `task test:e2e`
invocations can run in parallel without colliding on docker container
names or host ports.

Both clusters run with Traefik and ServiceLB disabled (we don't need
ingress) and use a local registry (dev: `k3d-x509ce-dev-registry:5000`;
e2e: `k3d-x509ce-e2e-registry-<hex>:<random>`) that the cluster nodes
pull from natively via `--registry-use`. This means Tilt can push to a
fast local registry instead of a remote one.

The kubeconfig for the dev cluster is written to `kubeconfig.yaml` at the
repo root (gitignored). Your `~/.kube/config` is **never** modified —
this is intentional, so you don't lose context to whatever else you run
on the side.

### direnv — optional auto-activation

[direnv](https://direnv.net) reads `.envrc` whenever you `cd` into a
directory and runs whatever's in it. The repo's `.envrc` activates the
Nix flake. After `direnv allow` once, every shell you open inside the
repo has the dev shell loaded, no manual `nix develop`.

If you don't want this, ignore `.envrc` — it has zero effect without
direnv.

## Repository layout

```text
.
├── cmd/x509-certificate-exporter/    Binary entrypoint (main.go and CLI flags)
├── pkg/                              Public Go API
│   ├── cert/                         Certificate parsing (PEM, PKCS#12)
│   └── registry/                     Prometheus collector + label registry
├── internal/                         Implementation details
│   ├── config/                       YAML config loader
│   ├── log/                          Structured logging setup
│   ├── source/                       The "source" abstraction
│   │   ├── file/                     File / directory globbing
│   │   └── k8s/                      Kubernetes informers
│   ├── server/                       HTTP server, metrics endpoint
│   ├── fileglob/                     Glob expansion helpers
│   └── product/                      Build-time injected version metadata
├── chart/                            Helm chart (THE primary deploy method)
├── dev/
│   ├── scenarios/                    Test fixtures shared by seed + e2e
│   ├── seed/                         Populates the dev cluster with scenarios
│   └── values.yaml                   Helm values for dev + e2e
├── test/
│   └── e2e/                          End-to-end test (Go, build-tag e2e)
├── dagger.json                       Dagger Module manifest (root level
│                                     so `dagger call` find-up works)
├── dagger/                           Dagger Module source: lint/test/etc.
│   ├── go.mod                        Isolated from the main module
│   ├── main.go                       X509Ce struct + New constructor
│   └── *.go                          One file per concern (lint, test, ...)
├── .goreleaser.yaml                  Release pipeline (binaries + images)
├── build/                            Dockerfiles for GoReleaser image variants
│   ├── Dockerfile.scratch            (default — minimal, no shell)
│   └── Dockerfile.busybox            (alt — shell for kubectl exec debugging)
├── Taskfile.yml                      Developer façade
├── Tiltfile                          Dev loop orchestration
├── flake.nix                         Dev shell definition
└── renovate.json5                    Dependency update config
```

## Daily development workflows

### Live dev loop

The most common workflow: cluster up once, Tilt up, edit code, watch it
redeploy.

```sh
task dev:cluster:up           # idempotent — fast no-op on subsequent runs
task dev:up                   # tilt up
```

Tilt's UI lives at `http://localhost:10350`. Each resource (Dagger build,
Helm install, seed, etc.) has its own log pane. Click on a resource to
see why it's red.

Forwarded ports while `tilt up` is running:

- **`localhost:9793`** — exporter `/metrics` and `/healthz` / `/readyz`
- **`localhost:9090`** — Prometheus UI (the chart's ServiceMonitor
  and PrometheusRule are already loaded)
- **`localhost:10350`** — Tilt dashboard

When you're done:

```sh
task dev:down                 # tilt down + destroy cluster, registry, kubeconfig
```

To keep the cluster running between sessions (faster restart — no
prometheus-operator bootstrap), run `tilt down` directly instead;
`task dev:up` then brings Tilt back without rebuilding the cluster.

#### Build-cycle expectations

Tilt rebuilds whenever any of these change: `cmd/`, `pkg/`, `internal/`,
`go.mod`, `go.sum`, `dagger/`. End-to-end timing on a typical laptop:

- **Tiny code change** (one Go file): about a minute (Dagger cache
  volumes hit; only the final binary build + Docker push is fresh)
- **`go.mod` change** (Renovate-style dep bump): ~2-3 minutes (forces
  `go mod download` and full rebuild)
- **`dagger/` change**: depends on what you touched

If you've been hacking on the same branch for a while and rebuilds are
getting slow, see the troubleshooting section for cache cleanup.

### Running unit tests

```sh
task test:unit                # → go run ./dagger test
```

This runs `gotestsum` (a friendlier wrapper over `go test`) with:

- `-race`: data race detector enabled (we run informers + HTTP handlers
  concurrently, so this matters)
- `-coverprofile`: coverage written to `/tmp/coverage.out` inside the
  Dagger container, retrievable as an artifact

Output format is `pkgname-and-test-fails` — silent on green packages,
verbose only when something failed. JUnit XML is emitted at
`/tmp/junit.xml` for CI to consume.

To run a single package or test locally without Dagger (faster iteration
on a specific test):

```sh
go test -race ./pkg/cert/pem/...
go test -race -run TestParseChain ./pkg/cert/pem/
```

Tests follow the standard `*_test.go` colocated layout. Prefer
table-driven tests for the parser and registry packages — there are
plenty of examples to copy from.

### Running e2e tests

```sh
task test:e2e
```

What happens:

1. Spins up an isolated `x509ce-e2e-<hex>` k3d cluster with a random
   per-run suffix (separate from the dev cluster, and from any other
   concurrent `task test:e2e` invocation — multiple runs can race-free
   coexist).
2. Builds the exporter image via Dagger, pushes it to the e2e local
   registry.
3. Helm-installs the chart with `dev/values.yaml` + `test/e2e/values.yaml`
   as overrides.
4. Seeds the cluster with every scenario in `dev/scenarios/`.
5. Runs `go test -tags=e2e ./test/e2e/...` which scrapes `/metrics` and
   asserts the expected series exist with the right labels.
6. **Tears everything down** — even on success, failure, or Ctrl-C. The
   `defer:` blocks at the top of the Taskfile entry guarantee this.

Adding a new test scenario: edit [`dev/scenarios/scenarios.go`](./dev/scenarios/scenarios.go),
add a `Scenario` struct describing the fixture and the expected metric
behavior. Both the seed and the e2e test pick it up automatically.
**Never edit YAML manifests for test data** — extend the scenarios list
instead.

### Linting

Three Go-related lint flavours, all backed by the same Dagger
`lintGoBase` helper that compiles golangci-lint from source against
the project's Go toolchain:

```sh
task lint:go                  # full set: staticcheck, errcheck, ineffassign, unused, gocritic
task lint:gocritic            # gocritic only — opinionated checks
task lint:gonocritic          # full set MINUS gocritic
```

The gocritic split exists because gocritic is more opinionated than
the others. If you want a quick "is my code unambiguously broken?"
check, `task lint:gonocritic` runs everything except the opinionated
noise. If you're already fixing gocritic suggestions,
`task lint:gocritic` keeps the loop tight.

Plus:

```sh
task lint:helm                # helm lint on the chart
task lint:renovate            # validates renovate.json5 schema
task lint:markdown            # markdownlint-cli2 on hand-written Markdown
task lint                     # all of the above
```

`task lint:markdown` reads its rules from `.markdownlint-cli2.jsonc` at
the repo root. `CHANGELOG.md` and `chart/README.md` are ignored there
(both are auto-generated and would just produce noise on every PR).

### Vulnerability scanning

```sh
task security:govulncheck     # Reachability-based CVE scan on Go code (govulncheck)
task security:vuln-deps       # Trivy filesystem scan — Go deps + lockfiles + OS packages
task security:chart-misconfig # Trivy IaC misconfig scan on chart/
task security                 # all of the above
```

`govulncheck` is fast (~30 s) and reaches into the call graph to flag
only CVEs on code paths that actually execute. Run it before opening a
PR if you've touched dependencies.

CodeQL runs in CI on every push (see
[`.github/workflows/security.yaml`](./.github/workflows/security.yaml)).
We don't run it locally — the CLI is heavy (downloads + 3-5 min of DB
build per run) and CI catches everything before merge.

### Dependency updates (Renovate)

Dependencies are kept current by Renovate, **self-hosted on GitHub
Actions** rather than via the Mend hosted app. The
[Renovate workflow](./.github/workflows/renovate.yaml) runs every Monday
morning + on every push that modifies `renovate.json5`, and opens PRs
authored by the bot identity of the GitHub App that backs it. You'll
see them tagged with the `dependencies` label.

There is intentionally **no `schedule:` field at the top of
`renovate.json5`** — the workflow's cron is the single source of timing
truth. A repo-config schedule would silently neuter manual
`workflow_dispatch` runs outside the configured window.

To debug `renovate.json5` locally — verify a manager catches what you
expect, inspect groupings, see `skipReason`s — without polluting GitHub
with experimental PRs:

```sh
task renovate:plan      # list planned bumps, do not modify files
task renovate:patch     # apply the same bumps to the working tree
```

`renovate:plan` runs the Renovate CLI in `--platform=local` mode and
logs every detected update. It does NOT modify files. `renovate:patch`
runs the same dry-run, then pipes the JSON debug output to
`scripts/renovate-patch.py` which applies each dep's first update by
substituting the exact `replaceString` Renovate would have edited —
formatting and comments preserved byte-for-byte. Anything ambiguous
gets skipped (with a diagnostic on stderr) so Renovate can pick it up
cleanly on its next run. To force a real run between weekly cron
triggers, use the `workflow_dispatch` button on the
Actions tab.

## Working on the Helm chart

The chart at [`chart/`](./chart) is the primary way users deploy the
exporter, so changes there have a wide blast radius. Useful tasks:

```sh
task lint:helm                # syntax + best practices via helm lint
task doc:helm                 # regenerate chart/README.md from values.yaml
```

The chart's `README.md` is **auto-generated** from
[`chart/README.md.gotmpl`](./chart/README.md.gotmpl) + the docstrings on
each value in [`chart/values.yaml`](./chart/values.yaml). Don't edit the
README directly — touch the `.gotmpl` or the values, then run
`task doc:helm`.

To test the chart end-to-end with your changes, the dev loop already
deploys with `dev/values.yaml`. To exercise additional values, override
in `Tiltfile`:

```python
helm_resource(
    name="x509-certificate-exporter",
    chart="./chart",
    flags=["--values=./dev/values.yaml", "--set=server.tls.enabled=true"],
)
```

## Release flow

Releases are tag-driven. A maintainer pushes a `vX.Y.Z` tag on the
commit to be released (pre-releases use a `-alpha`/`-beta`/`-rc` suffix
and are auto-detected by GoReleaser).

Pushing a `v*` tag triggers the
[Release workflow](./.github/workflows/release.yaml), which:

1. Builds binaries (matrix of OS × arch) and packages them as archives
2. Pushes container images to all configured registries
3. Packages and pushes the Helm chart to its OCI registry
4. Signs everything with cosign keyless and generates SLSA Level 3
   provenance for the binaries
5. Creates a **draft** GitHub Release with a changelog generated from
   Conventional Commits since the previous tag

The maintainer reviews the draft release and publishes it manually once
everything looks correct. Before tagging, update `chart/Chart.yaml`'s
`version` and `appVersion` to the new version.

Verification commands for downstream consumers are documented in the
[hardening guide](./docs/hardening.md).

## Common tasks reference

`task --list` is the canonical reference. Quick summary:

| Task | What it does |
| --- | --- |
| `task build` | Build host-arch binary via GoReleaser snapshot — symlinked at `dist/x509-certificate-exporter` (real path: `dist/x509ce_<os>_<arch>_<v>/x509-certificate-exporter`) |
| `task image:local` | Host-arch image variants via GoReleaser snapshot — fast iteration, no QEMU cross-build |
| `task image:all` | Like `task image:local` but every cross-arch variant — validates the full release matrix without pushing |
| `task dev:cluster:up` | Bring up dev k3d cluster + registry |
| `task dev:up` | Tilt up — full dev loop |
| `task dev:down` | Tilt down + full cluster teardown |
| `task dev:cluster:down` | Destroy dev cluster + registry |
| `task test` | Run unit + fuzz smoke + e2e tests sequentially |
| `task test:unit` | Unit tests with race detector + coverage (Dagger) |
| `task test:fuzz` | Smoke-run every `Fuzz*` target (5s each) |
| `task test:e2e` | Full e2e against fresh throwaway cluster |
| `task lint` | All linters (Go + Helm + Renovate) |
| `task lint:{go,gocritic,gonocritic,helm,renovate}` | Single linter (Dagger) |
| `task security` | All security checks |
| `task security:govulncheck` | govulncheck only (Dagger) |
| `task go:tidy` | `go mod tidy` on main module + `dagger/` (direct, no sandbox) |
| `task go:upgrade` | `go get -u ./...` + tidy on main + `dagger/` (direct) |
| `task nix:update` | `nix flake update` (refresh flake.lock) |
| `task renovate:plan` | Dry-run Renovate locally; no PRs, just logs the bumps it would propose |
| `task renovate:patch` | Apply Renovate's planned bumps to the working tree (best-effort, format-preserving) |
| `task doc` | Regenerate all documentation |
| `task doc:helm` | Regenerate chart/README.md only (Dagger) |
| `task analysis:graph` | Render & open the full package dependency graph (goda + graphviz) |
| `task analysis:size` | Build the host-arch binary then explore its size with `gsa --tui` |

## Troubleshooting

### Dagger build is suddenly slow on every run

The cache volumes (`go-mod`, `go-build`) might have grown stale. Reset
just those:

```sh
docker volume rm dagger-cache-go-mod dagger-cache-go-build
```

(Volume names follow Dagger's `dagger-cache-<name>` convention.) The
next build re-warms the caches; subsequent ones go back to fast.

For a more aggressive nuke — full Dagger engine reset:

```sh
docker rm -f $(docker ps -a --filter "name=dagger-engine" -q)
```

The engine auto-restarts on the next call.

### k3d cluster won't come up / port conflict

Most likely cause: a previous run died without cleanup, leaving a
container or network behind. Clean slate:

```sh
task dev:cluster:down         # destroy whatever's there
docker ps -a | grep k3d-      # confirm nothing lingers
docker network ls | grep k3d  # confirm no orphan networks
task dev:cluster:up
```

If `task dev:cluster:down` itself fails, fall back to:

```sh
k3d cluster delete x509ce-dev
k3d registry delete x509ce-dev-registry
rm -f kubeconfig.yaml
```

### Tilt UI shows a red resource I can't diagnose

Click the resource in the UI. The full build log is on the right pane.
If that's not enough:

```sh
kubectl --kubeconfig=kubeconfig.yaml -n x509-certificate-exporter logs -l app.kubernetes.io/name=x509-certificate-exporter -f
kubectl --kubeconfig=kubeconfig.yaml -n x509-certificate-exporter describe pod -l app.kubernetes.io/name=x509-certificate-exporter
```

### Renovate landed a Go dep update and now things don't build

If the failure is a compile error in a transitive package: usually a
patch is missing on the receiving end. Check the dep's release notes
for breaking changes. Workaround until upstream fixes it:

```sh
go get <module>@<previous-version>
go mod tidy
```

If the failure is a Go toolchain mismatch (e.g. `golangci-lint refuses
to load` with a Go-version error): the linter may have been compiled
against an older Go than `go.mod` declares. The fix is the
`golangciLint` constant in [`dagger/base.go`](./dagger/base.go) — bump
to a newer release (Renovate tracks this via the regex manager in
`renovate.json5`).

### `task test:e2e` hangs forever waiting on a pod

Usually means the seed job or the exporter is stuck. The Tilt UI of
`test/e2e/Tiltfile` shows per-resource state. The most common cause:
its timeout was hit but the cluster is stuck. The `defer:`
will eventually clean up, but you can force it:

```sh
# Each run names its cluster x509ce-e2e-<hex> — find the leftover:
k3d cluster list
k3d cluster delete x509ce-e2e-<hex>          # replace <hex>
k3d registry delete x509ce-e2e-registry-<hex>
```

### `cosign verify` fails on a tagged release I just made

Releases publish signatures to the Rekor public log, which can take a
few seconds to propagate after the workflow finishes. Wait a minute
and retry. If it still fails, check the release workflow's
`goreleaser` job logs (the cosign sign step) for the actual command
GoReleaser ran.

### My PR's `sensitive` label means it's blocked, right?

No — the label is a visibility cue, not a blocker. What blocks is
[`.github/CODEOWNERS`](./.github/CODEOWNERS): if the file you touched
matches a path in CODEOWNERS, the listed reviewer must approve before
the PR can merge. The label exists to make those PRs filterable in the
repo UI.

## Conventions

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) where
practical. GoReleaser consumes these to generate the public changelog
sections, so getting the type right matters:

- `feat:` — new user-visible behavior. Triggers a minor bump.
- `fix:` — bug fix. Triggers a patch bump.
- `perf:` — performance improvement (visible in the changelog).
- `security:` — fix or hardening that addresses a CVE / vulnerability.
  Appears in the **Security Updates** changelog section. Use this for
  changes a security scanner or downstream operator would care about;
  reserve plain `fix:` for functional bugs without security impact.
- `deps:` — dependency bump (own section in the changelog).
- `doc:` — documentation only.
- `chore:` — maintenance, infra, internal cleanup. Hidden from changelog
  but still informs the SemVer bump.
- `ci:` — CI / workflow changes. Hidden.
- `refactor:` — neither feature nor fix, internal restructure. Hidden.
- `test:` / `build:` — likewise hidden.

Optional scope after the type: `feat(chart): ...`,
`security(deps): bump golang.org/x/crypto`, `fix(k8s-source): ...`.

A breaking change uses `!` after the type and a `BREAKING CHANGE:`
footer, triggering a major bump:

```text
feat(api)!: rename `--config-path` flag to `--config`

BREAKING CHANGE: existing deployments must update their CLI args.
```

### Pull requests

A PR is mergeable into `main` when:

1. CI is green (lint + tests + security workflows)
2. Code-owner approval, if any sensitive path was touched
3. Branch is up to date with `main` (the protection rule enforces this)

Larger changes welcome a design discussion in the issue tracker before
PR — gives you a chance to validate the direction before sinking time
into implementation.

### Code style

- **Public API in `pkg/`, internals in `internal/`.** Don't promote
  without a real consumer.
- **Tests colocated with code** as `*_test.go`.
- **Table-driven tests** for parsers, registries, anything with many
  similar cases.
- **No comments stating the obvious** — comments explain *why*, not
  *what*.
- **No premature abstraction** — three similar lines beats a clever
  helper that only one of them actually needs.
- **golangci-lint** must pass clean. If a check is wrong for a specific
  spot, prefer a `//nolint:checker-name // reason` comment over disabling
  it globally.

## What's next

- **For the operator perspective**: the [chart README](./chart) is the
  authoritative reference for deployment.
- **For the supply-chain story**: the [release workflow](./.github/workflows/release.yaml)
  documents how images are signed (cosign keyless), how SBOMs are attached,
  and how SLSA Level 3 provenance is generated. Verification commands are
  in [docs/hardening.md](./docs/hardening.md).
- **For AI-assisted development**: the repository has a [`CLAUDE.md`](./CLAUDE.md)
  giving Claude / Cursor / Aider / similar tools the architectural context
  in a denser, agent-tuned format. Keep it up to date alongside this file
  when you change the dev workflow.

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](./LICENSE) — the same license as the project.
