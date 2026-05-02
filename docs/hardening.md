# Hardening

Operational guidance for running the x509-certificate-exporter with a
strong supply-chain and runtime posture. The page is grouped by concern;
sections are independent and can be applied piecemeal.

- [Verifying release authenticity](#verifying-release-authenticity) —
  cosign / SLSA / SBOM commands and what each one proves
- [Trust chain](#trust-chain) — the keyless model and why it's
  designed-in
- [Pinning to immutable digests](#pinning-to-immutable-digests) — the
  difference between a tag and a digest, and why pinning matters even
  with signed images
- [Automating verification](#automating-verification) — how to wire
  cosign verification into CI and into cluster admission

## Verifying release authenticity

Every tagged release is signed and attested by the
[release workflow](../.github/workflows/release.yaml) running on
GitHub Actions. Consumers can verify what they pull before trusting it
— no vendor key distribution required, no GPG dance.

### Container images

Signed keyless via [sigstore/cosign](https://docs.sigstore.dev/cosign/overview/)
(GitHub OIDC → Fulcio short-lived cert → Rekor transparency log) and
shipped with a [CycloneDX](https://cyclonedx.org) SBOM attached as a
cosign attestation. The same commands work against `quay.io/enix/...`,
`ghcr.io/enix/...`, and `enix/...` (Docker Hub).

```sh
# Verify the signature
cosign verify ghcr.io/enix/x509-certificate-exporter:4.0.0 \
  --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Inspect the SBOM (CycloneDX, attached as a cosign attestation)
cosign verify-attestation ghcr.io/enix/x509-certificate-exporter:4.0.0 \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

A successful `cosign verify` proves three things at once:

1. The image was pushed by the GitHub Actions workflow at
   `github.com/enix/x509-certificate-exporter` (the certificate
   identity).
2. The signature is recorded in the public
   [Rekor](https://docs.sigstore.dev/rekor/overview/) transparency log,
   so any later tampering is detectable.
3. The Fulcio CA chain was anchored in the Sigstore TUF root at the
   time of signing.

The SBOM payload lists every Go module (and its version) that landed
in the image. To check for a specific package:

```sh
cosign verify-attestation ghcr.io/enix/x509-certificate-exporter:4.0.0 \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson
           | .predicate.components[]
           | select(.name | contains("k8s.io/client-go"))
           | "\(.name)@\(.version)"'
```

### Helm chart

The Helm chart is published as a cosign-signed OCI artifact.

```sh
helm pull oci://quay.io/enix/charts/x509-certificate-exporter --version 4.0.0
cosign verify quay.io/enix/charts/x509-certificate-exporter:4.0.0 \
  --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The chart's `image.digest` Helm value lets you pin the rendered Pod
spec to a specific image digest (see [Pinning to immutable digests](#pinning-to-immutable-digests)
below).

### Binary releases

Binaries ship with a
[SLSA Build Level 3](https://slsa.dev/spec/v1.0/levels#build-l3)
provenance attestation, signed via Sigstore (Fulcio + Rekor) and
uploaded to GitHub's native [Attestations API][gh-attest]. Verify with
the GitHub CLI:

```sh
gh attestation verify x509-certificate-exporter-v4.0.0-linux-amd64.tar.gz \
  --owner enix \
  --source-ref refs/tags/v4.0.0
```

[gh-attest]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds

A passing verification proves the archive was produced by this repo's
release workflow at the named tag, on a GitHub-hosted runner. SLSA-3
implies the build ran in a non-tampered, ephemeral, isolated environment —
an attacker who compromises a maintainer's local laptop cannot forge a
release that passes this check.

A `checksums.txt` file is also published next to each release for
quick byte-level integrity checks (cheaper than SLSA verification but
weaker — checksums alone don't tell you who produced them).

### Stricter verification: pinning identity to workflow and tag

The verification commands above use `--certificate-identity-regexp` for
ergonomics — the same command works across releases and survives a future
rename of the release workflow. A more defensive consumer can pin the
certificate identity to **exactly this workflow file at exactly this tag**:

```sh
cosign verify ghcr.io/enix/x509-certificate-exporter:4.0.0 \
  --certificate-identity \
    'https://github.com/enix/x509-certificate-exporter/.github/workflows/release.yaml@refs/tags/v4.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This tightens the contract to *exactly that workflow, exactly that tag*:
no other workflow path in the repo, no other ref, can produce a signature
that passes — even one signed legitimately by an unrelated job in the
same repository. The trade-off is that the command must be updated on
every release.

Paranoid consumers (compliance-driven environments, supply-chain audit
tooling, downstream integrators rebuilding their own images on top) should
prefer this form and parameterize the tag in their automation.

## Trust chain

The whole pipeline is **keyless** — there is no long-lived private
key held by a maintainer or CI secret. Each release run mints a
short-lived (~10 minutes) signing certificate from
[Fulcio](https://docs.sigstore.dev/fulcio/overview/), signs the
artifacts, and immediately discards the key. The mapping from
"signature on disk" to "person/system that signed" is enforced by
three independent properties:

- **OIDC binding**. Fulcio issues the certificate only after
  validating an OIDC token from a trusted issuer (here:
  `https://token.actions.githubusercontent.com`). The token's claims —
  workflow path, repository, ref, run ID — are baked into the
  certificate's SAN and OID extensions.
- **Transparency log**. Rekor records the signing event in a public
  append-only Merkle tree. Any later attempt to swap an artifact and
  re-sign it leaves a visible trail.
- **TUF-rooted CA chain**. The Fulcio root CA is delivered through
  [The Update Framework](https://theupdateframework.io/) so cosign
  clients can detect compromise of the Sigstore infrastructure itself.

The practical consequence: an attacker who compromises a maintainer's
laptop, GitHub account password, or even a runner secret cannot
produce a passing `cosign verify` — they would also need to make the
release flow run **inside the official workflow**, on an official
runner, and that signing event would still appear in Rekor.

## Pinning to immutable digests

A tag (`:4.0.0`, `:latest`, …) is mutable. A digest (`@sha256:abc…`)
is not. Cosign signatures are anchored to digests, not tags — so a
verification on a tag implicitly resolves the tag *now* and then
verifies the digest. Two consequences:

1. **Pin in production manifests** to the digest, not the tag. The
   chart's `image.digest` value handles this:

   ```yaml
   image:
     repository: quay.io/enix/x509-certificate-exporter
     tag: "4.0.0"               # cosmetic, for readability
     digest: "sha256:abcdef…"   # actually used by Pod spec
   ```

   To find the current digest for a tag:

   ```sh
   crane digest quay.io/enix/x509-certificate-exporter:4.0.0
   # or, without crane:
   docker buildx imagetools inspect quay.io/enix/x509-certificate-exporter:4.0.0 \
     --format '{{ .Manifest.Digest }}'
   ```

2. **Verify the digest, not the tag**, in scripted contexts. Otherwise
   a TOCTOU window exists between "I checked tag X" and "the runtime
   pulled tag X" — they could resolve to different images.

   ```sh
   ref="quay.io/enix/x509-certificate-exporter:4.0.0"
   digest=$(crane digest "$ref")
   cosign verify "${ref%:*}@${digest}" \
     --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

The `release.yaml` workflow itself does this internally when it
attaches SBOMs — see the `Generate + attest image SBOMs` step for
the canonical pattern.

## Automating verification

### In a CI pipeline

Drop a verification step before any deploy stage. A typical GitHub
Actions snippet:

```yaml
- uses: sigstore/cosign-installer@<sha>  # SHA-pinned in your repo
- name: Verify exporter image
  run: |
    cosign verify quay.io/enix/x509-certificate-exporter:${{ env.VERSION }} \
      --certificate-identity-regexp '^https://github\.com/enix/x509-certificate-exporter/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The verification is offline-friendly past the initial Sigstore TUF
fetch — useful for air-gapped CI runners that can reach the registry
but not the public internet.

### At cluster admission

For Kubernetes clusters, enforce the verification on every Pod admission
rather than trusting CI alone. Two production-grade options:

- **[sigstore/policy-controller](https://github.com/sigstore/policy-controller)**
  — a dedicated admission controller for cosign signatures. Declarative
  `ClusterImagePolicy` resources match images by repository pattern and
  require a passing keyless cosign verification with a configured
  identity:

  ```yaml
  apiVersion: policy.sigstore.dev/v1beta1
  kind: ClusterImagePolicy
  metadata:
    name: enix-x509-exporter
  spec:
    images:
      - glob: "**/enix/x509-certificate-exporter*"
    authorities:
      - keyless:
          identities:
            - issuer: https://token.actions.githubusercontent.com
              subjectRegExp: ^https://github\.com/enix/x509-certificate-exporter/
  ```

- **[Kyverno](https://kyverno.io/)** with the `verifyImages` rule —
  same outcome, broader policy framework. Useful if you already run
  Kyverno for other admission rules.

Both controllers cache verification results per-digest, so the
runtime cost is one-shot per image even at high pod-churn rates.
