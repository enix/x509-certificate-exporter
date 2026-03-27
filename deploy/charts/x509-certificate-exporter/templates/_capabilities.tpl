{{- define "capabilities.kubeVersion" -}}
{{- if .Values.kubeVersion -}}
{{- .Values.kubeVersion | regexFind "v[0-9]+\\.[0-9]+\\.[0-9]+" -}}
{{- else -}}
{{- .Capabilities.KubeVersion.Version | regexFind "v[0-9]+\\.[0-9]+\\.[0-9]+" -}}
{{- end -}}
{{- end -}}

{{- define "capabilities.deployment.apiVersion" -}}
{{- if semverCompare "<1.14-0" (include "capabilities.kubeVersion" .) -}}
{{- print "extensions/v1beta1" -}}
{{- else -}}
{{- print "apps/v1" -}}
{{- end -}}
{{- end -}}

{{- define "capabilities.rbac.apiVersion" -}}
{{- if semverCompare "<1.17-0" (include "capabilities.kubeVersion" .) -}}
{{- print "rbac.authorization.k8s.io/v1beta1" -}}
{{- else -}}
{{- print "rbac.authorization.k8s.io/v1" -}}
{{- end -}}
{{- end -}}
