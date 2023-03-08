{{/*
Expand the name of the chart.
*/}}
{{- define "kmgm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kmgm.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }} {{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kmgm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kmgm.labels" -}}
helm.sh/chart: {{ include "kmgm.chart" . }}
{{ include "kmgm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kmgm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kmgm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kmgm-issuer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s-issuer" (include "kmgm.fullname" .) | trunc 63) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "kmgm-issuer.clusterRoleName" -}}
{{- if .Values.clusterRole.create }}
{{- default (printf "%s-issuer" (include "kmgm.fullname" .) | trunc 63) .Values.clusterRole.name }}
{{- else }}
{{- default "default" .Values.clusterRole.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the bootstrap token secret to use
*/}}
{{- define "kmgm.tokenSecretName" -}}
{{- if .Values.kmgm.bootstrap.secret.create }}
{{- default (printf "%s-bootstrap-token" (include "kmgm.fullname" .) | trunc 63) .Values.kmgm.bootstrap.secret.name }}
{{- else }}
{{- default "default" .Values.kmgm.bootstrap.secret.name }}
{{- end }}
{{- end }}

{{/*
Create bootstrap token
*/}}
{{- define "kmgm.bootstrapToken" -}}
{{- if .Values.kmgm.bootstrap.token -}}
{{-   .Values.kmgm.bootstrap.token -}}
{{- else -}}
{{-   $previous := lookup "v1" "Secret" .Release.Namespace (include "kmgm.tokenSecretName" .) }}
{{-   if $previous -}}
{{-     $previous.data.token | b64dec -}}
{{-   else -}}
{{-     randAlphaNum 32 -}}
{{-   end -}}
{{- end -}}
{{- end }}
