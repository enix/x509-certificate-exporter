{{- define "capabilities.kubeVersion" -}}
{{- default .Capabilities.KubeVersion.Version .Values.kubeVersion -}}
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
