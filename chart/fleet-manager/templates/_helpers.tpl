{{- define "fleet-manager.name" -}}
fleet-manager
{{- end -}}

{{- define "fleet-manager.labels" -}}
app.kubernetes.io/name: {{ include "fleet-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "fleet-manager.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
