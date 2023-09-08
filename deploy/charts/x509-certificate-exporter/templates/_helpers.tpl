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
Return the proper x509-certificate-exporter image name
*/}}
{{- define "x509-certificate-exporter.image" -}}
{{- $registryName := .Values.image.registry -}}
{{- $repositoryName := .Values.image.repository -}}
{{- $tag := printf "%s%s" ( default .Chart.AppVersion .Values.image.tag | toString ) ( default "" .Values.image.tagSuffix | toString ) -}}
{{/*
Helm 2.11 supports the assignment of a value to a variable defined in a different scope,
but Helm 2.9 and 2.10 doesn't support it, so we need to implement this if-else logic.
Also, we can't use a single if because lazy evaluation is not an option
*/}}
{{- if .Values.global }}
    {{- if .Values.global.imageRegistry }}
        {{- printf "%s/%s:%s" .Values.global.imageRegistry $repositoryName $tag -}}
    {{- else -}}
        {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
    {{- end -}}
{{- else -}}
    {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}
{{- end -}}

{{/*
Return the proper kube-rbac-proxy image name
*/}}
{{- define "x509-certificate-exporter.rbacProxy.image" -}}
{{- $registryName := .Values.rbacProxy.image.registry -}}
{{- $repositoryName := .Values.rbacProxy.image.repository -}}
{{- $tag := .Values.rbacProxy.image.tag | toString -}}
{{/*
Helm 2.11 supports the assignment of a value to a variable defined in a different scope,
but Helm 2.9 and 2.10 doesn't support it, so we need to implement this if-else logic.
Also, we can't use a single if because lazy evaluation is not an option
*/}}
{{- if .Values.global }}
    {{- if .Values.global.imageRegistry }}
        {{- printf "%s/%s:%s" .Values.global.imageRegistry $repositoryName $tag -}}
    {{- else -}}
        {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
    {{- end -}}
{{- else -}}
    {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
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
