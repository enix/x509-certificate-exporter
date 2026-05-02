# Changelog

## [4.0.0-alpha.1](https://github.com/enix/x509-certificate-exporter/compare/v3.21.0...v4.0.0-alpha.1) (2026-05-02)


### ⚠ BREAKING CHANGES

* **container:** switch default variant from busybox to scratch (floating tags)
* **chart:** make the Service headless by default (no ClusterIP)
* the Helm chart is now published exclusively as an OCI artifact at oci://quay.io/enix/charts/x509-certificate-exporter. The legacy Helm repository at https://charts.enix.io is no longer updated; users must switch to the OCI reference (Helm 3.8+ required). Installation: `helm install x509-certificate-exporter oci://quay.io/enix/charts/x509-certificate-exporter --version <vX.Y.Z>`. the Helm chart's values schema may diverge from v3 in edge cases despite a best-effort to preserve backwards compatibility. Review your existing values against the updated chart/values.yaml before upgrading. A JSON schema (chart/values.schema.json) is shipped with the chart so `helm install` / `helm upgrade` will reject any values that no longer match the expected shape, surfacing regressions early instead of at runtime. Alpine-based container images are no longer published. The release pipeline now ships only the `busybox` and `scratch` variants on linux/amd64,arm64,riscv64. Users pulling `*-alpine` tags must switch to one of the new variants — `busybox` is the closest functional replacement (still has a shell), `scratch` is the minimal distroless option.

* release 4.0.0-alpha.1 ([3f5d581](https://github.com/enix/x509-certificate-exporter/commit/3f5d581ae8b9c04ec30b24c90fa0835326b13d27))


### Features

* **chart:** make the Service headless by default (no ClusterIP) ([b1d5b5c](https://github.com/enix/x509-certificate-exporter/commit/b1d5b5cbe9f23b4080661455b07110dcafa5c002))
* **chart:** remove support for legacy apiVersion (k8s &lt; 1.16) ([7f560fd](https://github.com/enix/x509-certificate-exporter/commit/7f560fd8371fafee4c00163ec6316c8cbd401ac6))
* **chart:** satisfy PSA restricted profile and OpenShift restricted-v2 SCC ([3d8b935](https://github.com/enix/x509-certificate-exporter/commit/3d8b935f2e6b3c3cf6bc93376996b3cf8fa9cb21))
* **chart:** support image digest pinning across all images ([fd81d79](https://github.com/enix/x509-certificate-exporter/commit/fd81d79a171616bf1acb3af9e67aa0b1d1c58baa))
* **container:** switch default variant from busybox to scratch (floating tags) ([5ef7b43](https://github.com/enix/x509-certificate-exporter/commit/5ef7b43913287d37b32a390e5bb2972706c51a83))
* rewrite from scratch with new architecture and toolchain ([b4f3f84](https://github.com/enix/x509-certificate-exporter/commit/b4f3f84086a9feed9f32da678ffe7af2eda1a4fb))
* symlink path mapping and containment ([bbd179c](https://github.com/enix/x509-certificate-exporter/commit/bbd179c05b643d1221e490d1fd2ccb0bae65e574))


### Documentation

* **3to4:** fix codeql warning on typescript syntax ([584ecdb](https://github.com/enix/x509-certificate-exporter/commit/584ecdb351e80634b3a369354221b92822ef9e0a))
* add a v3 to v4 migration guide ([da6ba51](https://github.com/enix/x509-certificate-exporter/commit/da6ba51d937d09221b55dc09deafc4a54a32fa49))
* add security policy with reporting channels and scope ([146d4c0](https://github.com/enix/x509-certificate-exporter/commit/146d4c0c3149b86b370b60dd00f3a75b904e2c54))
* add v3-to-v4 migration guide ([d93d187](https://github.com/enix/x509-certificate-exporter/commit/d93d1879fc36f058248a3db31ce3dd18cf2a8d1b))
* **assets:** new alternative logo ([0a7d655](https://github.com/enix/x509-certificate-exporter/commit/0a7d655048928e1b66cccb973907f43f83745f47))
* **chart:** add a menu ([1212b90](https://github.com/enix/x509-certificate-exporter/commit/1212b902d53de19b0068d6b4d23be11199c6af28))
* **chart:** fix image URLs in README ([79e927e](https://github.com/enix/x509-certificate-exporter/commit/79e927ebb2d7538bb9858e88a62b0c3bed93d086))
* **chart:** link to the hardening guide ([1a39d3f](https://github.com/enix/x509-certificate-exporter/commit/1a39d3f736fc017d18c60ffdefa9b3d7411a75fd))
* **chart:** remove old notes ; link to curated starter values ([a393d5a](https://github.com/enix/x509-certificate-exporter/commit/a393d5aaa5d92ee332dc59d14d0f3161531ac7e8))
* **chart:** update README with new project template ; migration to v4 ([a90955b](https://github.com/enix/x509-certificate-exporter/commit/a90955b143d806492cce100b1b7735ef33283d7e))
* dedicated metrics reference under docs/ ([6b5078c](https://github.com/enix/x509-certificate-exporter/commit/6b5078cd062e27dcf1cab0c7c072cbd82cdd7542))
* **examples:** add curated values.yaml starters for generic and per-distro setups ([297fd74](https://github.com/enix/x509-certificate-exporter/commit/297fd7489d684188acfa648d3a6773d1b9d6367a))
* fix markdown linting issues ([5bcb838](https://github.com/enix/x509-certificate-exporter/commit/5bcb838941fe30dca0b9d8b556daa9a6fc207795))
* new page with frequent questions ([ba3bd51](https://github.com/enix/x509-certificate-exporter/commit/ba3bd512071bce439545ea784f645bdd413a3de1))
* **README:** add logo and refactor badges ([efe4de8](https://github.com/enix/x509-certificate-exporter/commit/efe4de88a9cd5b7f2d4268a93c775a9ddcd6e0e3))
* **README:** fix broken link for sigstore ; better badge label ([30d3015](https://github.com/enix/x509-certificate-exporter/commit/30d301500f61a5e858b6eba92b3aa5efb6a77aec))
* **README:** fix links to the github project ([0a780d9](https://github.com/enix/x509-certificate-exporter/commit/0a780d941009db3128ed38e9f59000a3c18c62a0))
* **README:** new sections and markdown readability ([1df03e4](https://github.com/enix/x509-certificate-exporter/commit/1df03e450e79fc35e77ad82e04e01c0c03d25fd8))
* **README:** relocate hardening to a dedicated page ; add a menu ([30d1174](https://github.com/enix/x509-certificate-exporter/commit/30d1174718c8da2a58e6bdc8891911f4938ff6e4))
* relocate grafana dashboard screenshot ([9cbeb94](https://github.com/enix/x509-certificate-exporter/commit/9cbeb941ee51c45e1d8f2ab19098735d3399325b))
* **SECURITY:** drop schedule ([7d68bd5](https://github.com/enix/x509-certificate-exporter/commit/7d68bd5e37c9df316caf3265d0d1ff7ab68b98bd))
* **SECURITY:** restore timeline ([b45520f](https://github.com/enix/x509-certificate-exporter/commit/b45520f7ff0d3f738391912734054eb6d1d85764))
