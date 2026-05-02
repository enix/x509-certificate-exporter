# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive
reports.

Use [GitHub's private vulnerability reporting][report] instead. It
opens a private channel between you and the maintainers, with a clear
audit trail and the option to coordinate a CVE / advisory once a fix
is ready.

[report]: https://github.com/enix/x509-certificate-exporter/security/advisories/new

We aim to acknowledge new reports within **3 working days** and to
ship a fix or mitigation within **30 days** for confirmed
vulnerabilities. Severity, scope, and complexity may stretch that
window — we'll keep you posted on the advisory thread.

## Scope

In scope:

- The `x509-certificate-exporter` binary and any code under
  `cmd/`, `pkg/`, `internal/`.
- The Helm chart under `chart/` (templates, default values,
  RBAC, security contexts).
- Container images published to `ghcr.io/enix`, `quay.io/enix`,
  and `docker.io/enix`.
- The release supply chain (GitHub Actions workflows, Sigstore
  signatures, SLSA provenance, SBOMs).

Out of scope:

- Issues affecting only the `dev/` and `test/` directories
  (development tooling, e2e fixtures).
- Vulnerabilities in upstream dependencies — please report those
  to the upstream project. We track advisories via Renovate and
  govulncheck and will pick them up.

## Verifying releases

Every release ships with cosign keyless signatures, SLSA Build
Level 3 build provenance, and a CycloneDX SBOM. Verification recipes
are documented in [`docs/hardening.md`](./docs/hardening.md).
