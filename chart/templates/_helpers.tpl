{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "x509-certificate-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{/*
Effective probe listen port. Returns "0" when the probe server is
disabled. Auto-enables to 8080 when the main /metrics port is
auth-gated (webConfiguration set or rbacProxy.enabled). User-set
probeListenPort > 0 takes precedence.
*/}}
{{- define "x509-certificate-exporter.probeListenPort" -}}
{{- if gt (int .Values.probeListenPort) 0 -}}
{{- .Values.probeListenPort -}}
{{- else if or .Values.webConfiguration .Values.webConfigurationExistingSecret .Values.rbacProxy.enabled -}}
8080
{{- else -}}
0
{{- end -}}
{{- end -}}

{{- define "x509-certificate-exporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Allow the release namespace to be overridden for multi-namespace deployments in combined charts
*/}}
{{- define "x509-certificate-exporter.namespace" -}}
{{- if .Values.namespaceOverride }}
{{- .Values.namespaceOverride }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "x509-certificate-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "x509-certificate-exporter.labels" -}}
helm.sh/chart: {{ include "x509-certificate-exporter.chart" . }}
{{ include "x509-certificate-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- range $label, $value := .Values.extraLabels }}
{{ $label }}: {{ $value | quote }}
{{- end }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "x509-certificate-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "x509-certificate-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Return the x509-certificate-exporter image reference.
Precedence: digest > tag (+ tagSuffix). global.imageRegistry overrides registry.
When digest is set the tag is omitted from the reference (digest is immutable).
*/}}
{{- define "x509-certificate-exporter.image" -}}
{{- $registry := .Values.image.registry -}}
{{- if and .Values.global .Values.global.imageRegistry -}}
  {{- $registry = .Values.global.imageRegistry -}}
{{- end -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
  {{- printf "%s/%s@%s" $registry $repo .Values.image.digest -}}
{{- else -}}
  {{- $tag := printf "%s%s" (default .Chart.AppVersion .Values.image.tag | toString) (default "" .Values.image.tagSuffix | toString) -}}
  {{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- end -}}
{{- end -}}

{{/*
Return the kube-rbac-proxy image reference.
Precedence: digest > tag. global.imageRegistry overrides registry.
*/}}
{{- define "x509-certificate-exporter.rbacProxy.image" -}}
{{- $registry := .Values.rbacProxy.image.registry -}}
{{- if and .Values.global .Values.global.imageRegistry -}}
  {{- $registry = .Values.global.imageRegistry -}}
{{- end -}}
{{- $repo := .Values.rbacProxy.image.repository -}}
{{- if .Values.rbacProxy.image.digest -}}
  {{- printf "%s/%s@%s" $registry $repo .Values.rbacProxy.image.digest -}}
{{- else -}}
  {{- printf "%s/%s:%s" $registry $repo (.Values.rbacProxy.image.tag | toString) -}}
{{- end -}}
{{- end -}}

{{/*
Names of ServiceAccounts
*/}}
{{- define "x509-certificate-exporter.secretsExporterServiceAccountName" -}}
{{- if .Values.rbac.create -}}
{{ default (include "x509-certificate-exporter.fullname" .) .Values.rbac.secretsExporter.serviceAccountName }}
{{- else -}}
{{ default "default" .Values.rbac.secretsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{- define "x509-certificate-exporter.hostPathsExporterServiceAccountName" -}}
{{- if .Values.rbac.create -}}
{{ default (printf "%s-node" (include "x509-certificate-exporter.fullname" .)) .Values.rbac.hostPathsExporter.serviceAccountName }}
{{- else -}}
{{ default "default" .Values.rbac.hostPathsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{/*
Names of ClusterRoles
*/}}
{{- define "x509-certificate-exporter.secretsExporterClusterRoleName" -}}
{{- if .Values.rbac.create -}}
{{ default (include "x509-certificate-exporter.fullname" .) .Values.rbac.secretsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{- define "x509-certificate-exporter.hostPathsExporterClusterRoleName" -}}
{{- if .Values.rbac.create -}}
{{ default (printf "%s-node" (include "x509-certificate-exporter.fullname" .)) .Values.rbac.hostPathsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{/*
Names of ClusterRoleBindings
*/}}
{{- define "x509-certificate-exporter.secretsExporterClusterRoleBindingName" -}}
{{- if .Values.rbac.create -}}
{{ default (include "x509-certificate-exporter.fullname" .) .Values.rbac.secretsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{- define "x509-certificate-exporter.hostPathsExporterClusterRoleBindingName" -}}
{{- if .Values.rbac.create -}}
{{ default (printf "%s-node" (include "x509-certificate-exporter.fullname" .)) .Values.rbac.hostPathsExporter.serviceAccountName }}
{{- end -}}
{{- end -}}

{{/*
Secrets exporter Deployment
*/}}
{{- define "x509-certificate-exporter.secretsExporterName" -}}
{{ include "x509-certificate-exporter.fullname" . }}
{{- end -}}

{{/*
Web configuration Secret name
*/}}
{{- define "x509-certificate-exporter.webConfigurationSecretName" -}}
{{ include "x509-certificate-exporter.fullname" . }}-webconf
{{- end -}}

{{/*
kube-rbac-proxy serving cert Secret name. Always defined; the actual
Secret in use is `rbacProxy.tls.existingSecretName` if set, otherwise
the chart-generated one named here.
*/}}
{{- define "x509-certificate-exporter.rbacProxy.tlsSecretName" -}}
{{ include "x509-certificate-exporter.fullname" . }}-rbac-proxy-tls
{{- end -}}

{{/*
kubectl image for hook jobs.
Precedence: digest > explicit tag > auto-detected cluster version.
When digest is set the tag is omitted (digest is immutable).
*/}}
{{- define "migration.kubectlImage" -}}
{{- $repo := printf "%s/%s" .Values.migration.image.registry .Values.migration.image.repository -}}
{{- if .Values.migration.image.digest -}}
  {{- printf "%s@%s" $repo .Values.migration.image.digest -}}
{{- else if .Values.migration.image.tag -}}
  {{- printf "%s:%s" $repo (.Values.migration.image.tag | toString) -}}
{{- else -}}
  {{- printf "%s:%s" $repo (.Capabilities.KubeVersion.Version | regexFind "v[0-9]+\\.[0-9]+\\.[0-9]+") -}}
{{- end -}}
{{- end -}}

{{/*
Detect the previous chart version from any chart-managed resource that
is still in the cluster. Probes Service → Deployment → DaemonSets and
returns the version stripped from the `helm.sh/chart` label of the
first hit. Returns empty when not an upgrade or when no chart-labeled
resource is found.
*/}}
{{- define "migration.prevVersion" -}}
{{- $result := "" -}}
{{- if .Release.IsUpgrade -}}
  {{- $ns := include "x509-certificate-exporter.namespace" . -}}
  {{- $existingResource := dict -}}
  {{- if .Values.service.create -}}
    {{- $svc := lookup "v1" "Service" $ns (include "x509-certificate-exporter.fullname" .) -}}
    {{- if $svc }}{{ $existingResource = $svc }}{{ end -}}
  {{- end -}}
  {{- if not $existingResource -}}
    {{- $dep := lookup "apps/v1" "Deployment" $ns (include "x509-certificate-exporter.secretsExporterName" .) -}}
    {{- if $dep }}{{ $existingResource = $dep }}{{ end -}}
  {{- end -}}
  {{- if not $existingResource -}}
    {{- range $name, $_ := .Values.hostPathsExporter.daemonSets -}}
      {{- if not $existingResource -}}
        {{- $dsName := printf "%s-%s" (include "x509-certificate-exporter.fullname" $) $name -}}
        {{- $ds := lookup "apps/v1" "DaemonSet" $ns $dsName -}}
        {{- if $ds }}{{ $existingResource = $ds }}{{ end -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- if $existingResource -}}
    {{- $chartLabel := index $existingResource.metadata.labels "helm.sh/chart" -}}
    {{- if $chartLabel -}}
      {{/* Helm replaces `+` with `_` when building the chart label
           (labels can't contain `+`); revert to get parseable semver
           build metadata, e.g. `3.20.0_abcdef` → `3.20.0+abcdef`. */}}
      {{- $result = trimPrefix "x509-certificate-exporter-" $chartLabel | replace "_" "+" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- $result -}}
{{- end -}}

{{/*
Compute the set of pre-upgrade cleanup tasks to run, based on the
detected previous chart version. Returns a YAML-encoded dict with
boolean keys. Callers parse it via `fromYaml`.

Rule table (all guards OR-merged into the same dict):

  prev<3.20.0 AND target<4.0.0 → deleteDeployment, deleteDaemonsets
  prev<4.0.0                   → deleteService (if service.create),
                                 deleteDeployment, deleteDaemonsets
  prev<4.1.0 AND target>=4.1.0 → deleteDaemonsets

To extend, add a rule branch below. Each task is further gated on
its own preconditions (deleteService requires service.create;
deleteDaemonsets requires hostPathsExporter.daemonSets non-empty),
so the Role's verbs and the Job's args stay in sync automatically.
*/}}
{{- define "migration.tasks" -}}
{{- $tasks := dict "deleteService" false "deleteDeployment" false "deleteDaemonsets" false -}}
{{- $prev := include "migration.prevVersion" . -}}
{{- if $prev -}}
  {{- if and (semverCompare "<3.20.0" $prev) (semverCompare "<4.0.0" .Chart.Version) -}}
    {{- $_ := set $tasks "deleteDeployment" true -}}
    {{- $_ := set $tasks "deleteDaemonsets" true -}}
  {{- end -}}
  {{- if semverCompare "<4.0.0" $prev -}}
    {{- if .Values.service.create -}}{{- $_ := set $tasks "deleteService" true -}}{{- end -}}
    {{- $_ := set $tasks "deleteDeployment" true -}}
    {{- $_ := set $tasks "deleteDaemonsets" true -}}
  {{- end -}}
  {{- if and (semverCompare "<4.1.0" $prev) (semverCompare ">=4.1.0" .Chart.Version) -}}
    {{- $_ := set $tasks "deleteDaemonsets" true -}}
  {{- end -}}
  {{- if not .Values.hostPathsExporter.daemonSets -}}
    {{- $_ := set $tasks "deleteDaemonsets" false -}}
  {{- end -}}
{{- end -}}
{{- $tasks | toYaml -}}
{{- end -}}

{{/*
Truthy ("true") iff at least one migration task is enabled. Used to
gate the entire pre-upgrade hook bundle (SA + Role + RoleBinding +
Job).
*/}}
{{- define "migration.needsHook" -}}
{{- $tasks := fromYaml (include "migration.tasks" .) -}}
{{- if or $tasks.deleteService $tasks.deleteDeployment $tasks.deleteDaemonsets -}}true{{- end -}}
{{- end -}}

{{/*
Build the Role's `rules:` list as the union of the verbs needed by the
enabled tasks. Returns a YAML list (no leading newline) suitable for
`{{ include "migration.roleRules" . | nindent 2 }}` under `rules:`.
*/}}
{{- define "migration.roleRules" -}}
{{- $tasks := fromYaml (include "migration.tasks" .) -}}
{{- $rules := list -}}
{{- if $tasks.deleteService -}}
{{- $rules = append $rules (dict "apiGroups" (list "") "resources" (list "services") "verbs" (list "get" "list" "delete")) -}}
{{- end -}}
{{- $appsRes := list -}}
{{- if $tasks.deleteDeployment -}}{{- $appsRes = append $appsRes "deployments" -}}{{- end -}}
{{- if $tasks.deleteDaemonsets -}}{{- $appsRes = append $appsRes "daemonsets" -}}{{- end -}}
{{- if $appsRes -}}
{{- $rules = append $rules (dict "apiGroups" (list "apps") "resources" $appsRes "verbs" (list "get" "list" "delete")) -}}
{{- end -}}
{{- $rules | toYaml -}}
{{- end -}}
