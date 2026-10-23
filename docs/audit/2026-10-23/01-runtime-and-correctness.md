# Runtime and correctness findings

Audit of commit `294f721b74990447a72ca9fd216e2674ec217d04`, dated 2026-10-23. Priorities and evidence levels are defined in [the overview](README.md). The existing test suite passes; the reproductions below exercise additional cases. No implementation fixes are included in this audit.

## B01 — P1 — Tiny malformed JKS inputs cause disproportionate memory allocation

**Evidence: reproduced, with a bounded allocation.** [pkg/cert/jks/jks.go:149](../../../pkg/cert/jks/jks.go#L149) passes input directly to `keystore-go`'s `Load`. In the pinned `github.com/pavlo-v-chernykh/keystore-go/v4@v4.5.0`, `decoder.go:36–45` allocates a declared `uint32` byte length before reading it; `decoder.go:120` also allocates a certificate-chain capacity from an input count. `keystore.go:184–201` parses entries before validating the trailing digest.

A **38-byte truncated store declaring a 16 MiB certificate allocated 16,787,208 bytes**, then returned `bad_jks`. No valid digest or password was necessary. Larger declared lengths can exhaust memory; the audit deliberately did not attempt an OOM. This affects deployments parsing JKS from files or watched Kubernetes objects writable by another actor. It is not an unauthenticated HTTP upload vulnerability.

**Remedy:** validate lengths/counts against remaining input before allocating, in an upstream fix or bounded local decoder. A cap on input bytes alone does not prevent this amplification. Check the private-key length and chain-count paths too. Keep the existing bounded JCEKS implementation, and add allocation-budget regression tests in an isolated process.

## B02 — P1 — Deleting one Kubernetes object deletes name-prefix siblings

**Evidence: reproduced for Secrets and ConfigMaps.** [pkg/source/k8s/k8s.go:1074](../../../pkg/source/k8s/k8s.go#L1074) matches tracked keys using `HasPrefix(kind + ":" + location)` without an object-name boundary.

With `ns/foo#tls.crt` and `ns/foobar#tls.crt` tracked, deleting `ns/foo` emits deletes for both. The surviving object's metrics disappear until another object event or full relist, normally up to 30 minutes. Client-side filter rejection uses the same path.

**Remedy/test:** index by exact kind/namespace/name, or require the `#` boundary after the location. Cover deletion and rejection with `foo`, `foobar` and `foo-bar` present together.

## B03 — P1 — Removing a Secret/ConfigMap data key leaves its certificate indefinitely

**Evidence: reproduced through update and subsequent relist.** [pkg/source/k8s/k8s.go:858](../../../pkg/source/k8s/k8s.go#L858) and [977](../../../pkg/source/k8s/k8s.go#L977) only upsert current keys. Relist cleanup at [640](../../../pkg/source/k8s/k8s.go#L640) checks whether the object still exists, not its emitted key set.

Remove or rename a watched key while keeping its parent object: the old certificate remains in the registry, even after relisting. A Secret type transition can have the same effect when multiple types are watched. Monitoring may retain obsolete expiry alerts or imply that a deleted certificate is still present.

**Remedy/test:** replace the complete emitted-reference set for each object and delete the difference. The CA-bundle source already follows this contract at [pkg/source/cabundle/cabundle.go:387](../../../pkg/source/cabundle/cabundle.go#L387). Cover key removal, rename, empty data, type changes and relist recovery.

## B04 — P1 — Namespace changes wake only one of two resource watchers

**Evidence: reproduced using both watch loops and fake watches.** One channel is created at [pkg/source/k8s/k8s.go:250](../../../pkg/source/k8s/k8s.go#L250), consumed independently at [600](../../../pkg/source/k8s/k8s.go#L600) and [805](../../../pkg/source/k8s/k8s.go#L805), and sent to once at [1251](../../../pkg/source/k8s/k8s.go#L1251).

When a source watches both Secrets and ConfigMaps with namespace-label filtering, a namespace label change deletes both kinds' tracked refs. Only one loop receives the relist notification. The other kind disappears until its own event/resync, normally up to 30 minutes. Even an irrelevant label change on a still-permitted namespace can trigger this.

**Remedy/test:** broadcast invalidation or maintain a separate coalescing notification per consumer. Avoid purging unaffected namespaces. Test both watchers, rapid label changes and changes during initial LIST.

## B05 — P2 — Namespace invalidation can be undone by an in-flight publication

**Evidence: reproduced deterministically with a blocking Sink.** [pkg/source/k8s/k8s.go:1057](../../../pkg/source/k8s/k8s.go#L1057) records a ref under a lock, unlocks, then calls `sink.Upsert`. Namespace invalidation independently removes tracking and calls `sink.Delete` at [1232](../../../pkg/source/k8s/k8s.go#L1232).

If the namespace becomes excluded between tracking and publication, the delete completes before the pending upsert. The certificate then exists in the sink but not in `tracked`; later rejection cannot remove the orphan. The reproduction ended with one bundle and an empty tracking map. This is a logical ordering defect, not a Go data race.

**Remedy/test:** make acceptance, generation checking, tracking and publication a coherent reconciliation operation. Use deterministic barriers to exercise allow→deny while parsing/publishing; require both registry and source index to agree afterward.

## B06 — P1 — Stable symlinks conceal certificate rotation

**Evidence: reproduced with a real symlink and repeated polling.** [pkg/fileglob/fileglob.go:632](../../../pkg/fileglob/fileglob.go#L632) emits the symlink's `Lstat` metadata; [pkg/source/file/file.go:219](../../../pkg/source/file/file.go#L219) uses it for the unchanged-file cache.

Changing the target contents while leaving the outer symlink untouched produces no reparse with the default `skipUnchanged: true`. The reproduction changed target size and polled every 5 ms for 200 ms; the parser ran only once. An intermediate `..data`-style link rotation can likewise leave the outer link's metadata unchanged. The existing rotation test recreates the outer symlink, so it misses this case.

**Remedy/test:** include the final resolved target identity/metadata in cache invalidation. Test target replacement, target content changes and intermediate-link swaps while preserving the outer link. Coordinate this with B11's full-chain resolution.

## B07 — P2 — All-parser failure is silently discarded for multi-format files

**Evidence: reproduced.** [pkg/source/file/file.go:272](../../../pkg/source/file/file.go#L272) continues on every fatal parser result whenever more than one format is configured, including the last parser. The loop then exits without publishing an error.

With `formats: [pem, der]` and unreadable certificate bytes, no bundle/error is emitted. If a previously valid file becomes invalid, its old registry bundle can remain because the path is still seen. Readiness also does not reflect this parse failure.

**Remedy/test:** try alternatives, then publish a useful terminal failure if none succeeds; replace the previous bundle. Test valid→invalid and invalid→valid transitions, all-fatal results, and partial-success bundles.

## B08 — P2 — One source can overwrite or delete another source's bundle

**Evidence: reproduced.** [pkg/cert/cert.go:70](../../../pkg/cert/cert.go#L70) omits `SourceName` from `SourceRef.String`; [pkg/registry/registry.go:269](../../../pkg/registry/registry.go#L269) uses that string as its storage key.

Two configured sources observing the same kind/location/key collapse to one bundle: the second overwrites the first, including attributes and source ownership. A delete from either source then removes the other's still-valid observation. The reproduction observed one bundle after both sources published and zero after deleting only source A. Separate cluster sources observing identically named Secrets can represent different real objects, making the overwrite especially problematic. Deliberate metric deduplication of the same physical file is reasonable; losing independent ownership is the defect.

**Remedy/test:** separate source-owned storage identity from metric-series deduplication. Include owner identity or maintain explicit owner sets. Test overlapping sources with different filters/labels and withdrawal of only one owner.

## B09 — P2 — CRLs and item errors bypass effective metric collision handling

**Evidence: reproduced at Gather and HTTP-handler levels.** [pkg/registry/collector.go:276](../../../pkg/registry/collector.go#L276) emits CRLs without collision resolution; [317](../../../pkg/registry/collector.go#L317) emits item errors without a distinguishing index. [pkg/registry/labels.go:321](../../../pkg/registry/labels.go#L321) does not encode a CRL index either.

Two CRLs with the same exposed issuer/number/location, or two malformed items in one bundle with `exposePerCertError: true`, produce duplicate metric identities. `Gather` reports duplicate-series errors. Because [internal/server/server.go:85](../../../internal/server/server.go#L85) uses `ContinueOnError` with no error logger/counter registry, the tested HTTP response was **200 with one error series for two input errors**. This is silent partial loss, not a demonstrated whole-endpoint outage. Which colliding CRL value survives should not be relied on.

**Remedy/test:** define collision handling for every emitted family, including CRLs and failed items. Surface collection errors explicitly. Assert emitted identity uniqueness and HTTP-level visibility with duplicate CRLs, multiple malformed PEM blocks, and path trimming that collapses locations.

## B10 — P2 — Valid exposed label keys can prevent startup

**Evidence: reproduced by collector registration.** [pkg/registry/labels.go:83](../../../pkg/registry/labels.go#L83) sanitizes punctuation to `_`; [214](../../../pkg/registry/labels.go#L214) appends resulting names without checking collisions.

Exposing both `app.kubernetes.io/name` and `app_kubernetes_io_name` creates duplicate Prometheus label names. Both are valid Kubernetes keys, but registration fails and [cmd/x509-certificate-exporter/main.go:164](../../../cmd/x509-certificate-exporter/main.go#L164) terminates startup. Unioning exposed keys across sources also creates this risk.

**Remedy/test:** detect normalized collisions during configuration validation and provide the conflicting original keys, or support explicit unique aliases. Cover duplicate keys and punctuation-equivalent keys in all three exposed-label families.

## B11 — P2 — Symlink containment checks only the first hop

**Evidence: reproduced with a two-link filesystem chain.** [pkg/fileglob/fileglob.go:589](../../../pkg/fileglob/fileglob.go#L589) reads one link, checks its textual target against allowed mappings, then calls `Stat`, which follows subsequent links.

`allowed/first.pem → allowed/second → outside/cert` is emitted as a readable entry despite configured scope containment. The file reader then follows the remaining chain. This can expose certificate metadata outside the intended scan scope when the process can read that path. It does not grant filesystem permissions or expose arbitrary file contents as metrics.

**Remedy/test:** resolve and validate the complete chain, including intermediate path components and mappings, with cycle bounds. If containment is a security boundary, also address the race between validation and opening. Add multi-hop, intermediate-directory, translated-target and escape tests.

## B12 — P2 — Exclude patterns confuse neighboring directory prefixes

**Evidence: reproduced through the public matcher.** [pkg/fileglob/fileglob.go:354](../../../pkg/fileglob/fileglob.go#L354) strips a static prefix without requiring a `/` boundary.

`MustCompile("/etc/pki/**/*.pem").Match("/etc/pki-old/a.pem")` returns true. Since exclusions use `Match` at [779](../../../pkg/fileglob/fileglob.go#L779), an exclusion can silently suppress certificates in an unrelated neighboring directory.

**Remedy/test:** make prefix matching segment-aware. Cover `pki` versus `pki-old`, root prefixes, relative paths and both direct Match and Walk exclusion behavior.

## B13 — P2 — ConfigMap binaryData is ignored

**Evidence: reproduced.** [pkg/source/k8s/k8s.go:978](../../../pkg/source/k8s/k8s.go#L978) only iterates `cm.Data`, although [cmd/x509-certificate-exporter/main.go:621](../../../cmd/x509-certificate-exporter/main.go#L621) supports binary formats for ConfigMap rules.

A matching DER certificate in `binaryData` produces no parser invocation, bundle or error. The source can complete initial sync while missing those certificates.

**Remedy/test:** process `Data` and `BinaryData` together and reconcile the combined key set. Cover binary DER and supported keystore cases, mixed fields and removal. Define or reject unsupported passphrase combinations explicitly.

## B14 — P2 — Passphrase-Secret changes do not refresh dependent certificates

**Evidence: reproduced.** [pkg/source/k8s/k8s.go:869](../../../pkg/source/k8s/k8s.go#L869) fetches passwords only when processing certificate keys; [1009](../../../pkg/source/k8s/k8s.go#L1009) performs an isolated GET, with no reverse dependency tracking.

Rotate the certificate first and its password Secret second, or fix a missing password Secret: the dependent certificate retains the previous error state until its own update or the next full relist, normally up to 30 minutes. Even delivering the password Secret's event did not re-invoke the dependent parser in the reproduction. Certificate-selection filters may exclude that Secret from watches entirely.

**Remedy/test:** track dependencies and requeue dependents, including cross-namespace refs, or define a bounded retry mechanism. Test both rotation orders, missing-ref creation and refs outside certificate selectors.

## B15 — P2 — Empty-valued namespace label changes can miss invalidation

**Evidence: reproduced.** [pkg/source/k8s/k8s.go:1257](../../../pkg/source/k8s/k8s.go#L1257) compares `b[k]` without checking membership.

`{old: ""}` and `{new: ""}` compare equal. An existence-based filter can change its result without triggering purge/relist. The stored labels do update; the missing step is invalidation, until another event/resync.

**Remedy/test:** use `maps.Equal` or compare both value and key presence. Test empty-value key replacement as well as ordinary value/count changes.

## B16 — P2 — Non-ASCII JCEKS passphrases reject valid stores

**Evidence: reproduced with Java keytool.** [pkg/cert/jks/jks.go:370](../../../pkg/cert/jks/jks.go#L370) widens UTF-8 bytes individually rather than encoding the password's UTF-16 code units.

A JCEKS generated by `keytool` using store password `pässword` was readable by keytool but returned `bad_passphrase: invalid digest` in this parser. The existing fixtures reproduce the implementation's byte-widening scheme, so they cannot detect this interoperability defect.

**Remedy/test:** encode Java-compatible UTF-16BE, including surrogate pairs. Keep independent keytool fixtures for ASCII, accented and supplementary-plane characters. Review the upstream JKS path separately; this audit's executed interoperability test covered JCEKS.

## B17 — P2 — OpenSSL TRUSTED CERTIFICATE blocks with auxiliary data fail

**Evidence: reproduced with OpenSSL.** [pkg/cert/pem/pem.go:58](../../../pkg/cert/pem/pem.go#L58) treats `TRUSTED CERTIFICATE` as a plain certificate DER blob.

The same certificate parsed successfully as ordinary PEM, but `openssl x509 -addtrust serverAuth -trustout` produced a trusted PEM that returned `bad_pem: x509: trailing data`. Its auxiliary trust structure follows the certificate; passing the entire block to `x509.ParseCertificate` rejects it. This contradicts the parser's advertised block support.

**Remedy/test:** parse the certificate portion with bounded ASN.1 handling and define how auxiliary data is treated, or explicitly reject/document this format. Add an independently generated OpenSSL trusted-certificate fixture.

## B18 — P2 — Permissive configuration can silently disable or broaden scanning

**Evidence: reproduced.** [internal/config/config.go:290](../../../internal/config/config.go#L290) uses permissive YAML unmarshalling; validation at [402](../../../internal/config/config.go#L402) checks only non-nil Kubernetes sections.

`secrets: {}` validates and can become a ready source with no rules. A typo such as `excludePath` is silently ignored instead of rejecting the configuration, potentially broadening scope. Passing the Helm schema does not validate arbitrary directly supplied exporter YAML.

**Remedy/test:** reject unknown keys, require usable rules and validate the final CLI/YAML composition. Validate per-kind fields, selectors, formats and passphrase choices before client construction. Include empty rules and misspelled exclusion keys as negative tests.

## B19 — P2 — Kubernetes literal/file passphrases are accepted but discarded

**Evidence: reproduced through the real source builder and Run, using a fake HTTP transport.** [chart/values.yaml:353](../../../chart/values.yaml#L353) advertises literal and file passphrases. [cmd/x509-certificate-exporter/main.go:576](../../../cmd/x509-certificate-exporter/main.go#L576) transfers only key/ref/try-empty options for PKCS#12 and JKS Secret rules. The file-source branch at [461](../../../cmd/x509-certificate-exporter/main.go#L461) handles literal/file values.

Encrypted Secret data configured with a nonempty literal password or mounted password file reaches its parser with an empty password. All four format/mechanism combinations returned zero certificates and `bad_passphrase`; the same fixtures succeeded in direct-parser controls. Existing package tests construct rules directly, bypassing this broken composition path.

**Remedy/test:** share passphrase-option construction where semantics match; otherwise reject unsupported settings. Test the actual configured-source builder for both formats and all password mechanisms.

## B20 — P2 — Explicit missing config paths silently fall back to defaults

**Evidence: reproduced through run().** [cmd/x509-certificate-exporter/main.go:84](../../../cmd/x509-certificate-exporter/main.go#L84) suppresses `os.ErrNotExist` even for explicitly supplied `--config`; [internal/config/config.go:304](../../../internal/config/config.go#L304) had correctly preserved that error.

With `--config /typo/config.yaml` and a CLI watch source, the exporter can start using defaults while omitting intended YAML security/filter settings. The reproduction reached listener startup and failed only on a deliberately invalid listen address, instead of returning the missing-config error. Without CLI sources, it reports no sources instead of the missing-file error.

**Remedy/test:** tolerate absence only during optional autodiscovery. Add executable/config-loading tests for explicit missing and unreadable files and ordinary no-file autodiscovery.

## B21 — P2 — CA-bundle default resync is accidentally sixty times too frequent

**Evidence: reproduced through LoadFile.** [internal/config/config.go:357](../../../internal/config/config.go#L357) applies the file-poll interval to every kind except `kubernetes`, including `cabundle`. [cmd/x509-certificate-exporter/main.go:745](../../../cmd/x509-certificate-exporter/main.go#L745) then receives 30 seconds instead of applying its intended 30-minute default.

The resulting informer resync repeatedly reparses cached CA bundles, and malformed bundles increment error counters more often. This is **cached-object reprocessing, not sixty times as many API LIST requests**.

**Remedy/test:** default intervals explicitly by source kind. Test all four kinds with omitted/explicit intervals and a custom global file-poll interval.

## B22 — P2/P3 — Kubernetes diagnostics no longer describe the operations being performed

**Evidence: direct call-site inspection.** The direct loops at [pkg/source/k8s/k8s.go:444](../../../pkg/source/k8s/k8s.go#L444) and [675](../../../pkg/source/k8s/k8s.go#L675) do not call `MarkWatchResync`; the remaining caller at [pkg/source/k8s/metrics.go:157](../../../pkg/source/k8s/metrics.go#L157) is an informer short-watch callback. Preinitialized Secret/ConfigMap resync counters can therefore stay zero during actual relists.

Additionally, [metrics.go:88](../../../pkg/source/k8s/metrics.go#L88) treats the final URL segment as the resource: a password GET ending in `/secrets/my-password` produces `resource="my-password"`. Histograms acquire per-object cardinality and misleading resource attribution. Queue metrics at [102](../../../pkg/source/k8s/metrics.go#L102) hardcode a source name instead of distinguishing configured sources.

**Remedy/test:** instrument actual LIST/WATCH operations with explicit, bounded resource/source labels. Test list/watch/get URL shapes and multiple sources. Treat metric semantics and label changes as compatibility work.
