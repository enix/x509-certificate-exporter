# Changelog

## [4.0.0](https://github.com/enix/x509-certificate-exporter/compare/v3.21.0...v4.0.0) (2026-04-30)


### ⚠ BREAKING CHANGES

* the Helm chart is now published exclusively as an OCI artifact at oci://quay.io/enix/charts/x509-certificate-exporter. The legacy Helm repository at https://charts.enix.io is no longer updated; users must switch to the OCI reference (Helm 3.8+ required). Installation: `helm install x509-certificate-exporter oci://quay.io/enix/charts/x509-certificate-exporter --version <vX.Y.Z>`. the Helm chart's values schema may diverge from v3 in edge cases despite a best-effort to preserve backwards compatibility. Review your existing values against the updated chart/values.yaml before upgrading. A JSON schema (chart/values.schema.json) is shipped with the chart so `helm install` / `helm upgrade` will reject any values that no longer match the expected shape, surfacing regressions early instead of at runtime. Alpine-based container images are no longer published. The release pipeline now ships only the `busybox` and `scratch` variants on linux/amd64,arm64,riscv64. Users pulling `*-alpine` tags must switch to one of the new variants — `busybox` is the closest functional replacement (still has a shell), `scratch` is the minimal distroless option.

### Features

* rewrite from scratch with new architecture and toolchain ([b4f3f84](https://github.com/enix/x509-certificate-exporter/commit/b4f3f84086a9feed9f32da678ffe7af2eda1a4fb))


### Documentation

* add v3-to-v4 migration guide ([d93d187](https://github.com/enix/x509-certificate-exporter/commit/d93d1879fc36f058248a3db31ce3dd18cf2a8d1b))
* dedicated metrics reference under docs/ ([6b5078c](https://github.com/enix/x509-certificate-exporter/commit/6b5078cd062e27dcf1cab0c7c072cbd82cdd7542))
* fix markdown linting issues ([5bcb838](https://github.com/enix/x509-certificate-exporter/commit/5bcb838941fe30dca0b9d8b556daa9a6fc207795))
* new page with frequent questions ([ba3bd51](https://github.com/enix/x509-certificate-exporter/commit/ba3bd512071bce439545ea784f645bdd413a3de1))
* **README:** add logo and refactor badges ([efe4de8](https://github.com/enix/x509-certificate-exporter/commit/efe4de88a9cd5b7f2d4268a93c775a9ddcd6e0e3))
* **README:** fix links to the github project ([0a780d9](https://github.com/enix/x509-certificate-exporter/commit/0a780d941009db3128ed38e9f59000a3c18c62a0))
* relocate grafana dashboard screenshot ([9cbeb94](https://github.com/enix/x509-certificate-exporter/commit/9cbeb941ee51c45e1d8f2ab19098735d3399325b))
