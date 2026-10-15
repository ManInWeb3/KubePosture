{{/*
Expand the name of the chart.
*/}}
{{- define "kubeposture-import.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kubeposture-import.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
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
{{- define "kubeposture-import.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubeposture-import.labels" -}}
helm.sh/chart: {{ include "kubeposture-import.chart" . }}
{{ include "kubeposture-import.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubeposture-import.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubeposture-import.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubeposture-import.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kubeposture-import.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Pod-level security context shared by every importer pod.
*/}}
{{- define "kubeposture-import.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
{{- end }}

{{/*
Container-level security context shared by every importer container.
*/}}
{{- define "kubeposture-import.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end }}

{{/*
Environment shared by every importer container. The token is read from
KUBEPOSTURE_TOKEN (not passed as a positional arg) so it doesn't show up
in `ps` output inside the container or `kubectl describe pod`.

Takes a dict: (dict "root" $ "cronjobName" "<name or empty>")
*/}}
{{- define "kubeposture-import.containerEnv" -}}
{{- $root := .root -}}
- name: KUBEPOSTURE_URL
  value: {{ $root.Values.kubepostureUrl | quote }}
- name: KUBEPOSTURE_HTTP_TIMEOUT
  value: {{ $root.Values.httpTimeoutSeconds | quote }}
- name: KUBEPOSTURE_TOKEN
{{- if $root.Values.token.secretRef.name }}
  valueFrom:
    secretKeyRef:
      name: {{ $root.Values.token.secretRef.name }}
      key: {{ $root.Values.token.secretRef.key }}
{{- else }}
  value: {{ $root.Values.token.value | quote }}
{{- end }}
- name: KUBEPOSTURE_RELEVANCE_FILTER
  value: {{ $root.Values.relevanceFilter | quote }}
- name: KUBEPOSTURE_COVERAGE_MIN_RATIO
  value: {{ $root.Values.coverage.minRatio | quote }}
- name: KUBEPOSTURE_UPLOAD_DEADLINE_SECONDS
  value: {{ $root.Values.uploadDeadlineSeconds | quote }}
- name: KUBEPOSTURE_LOG_LEVEL
  value: {{ $root.Values.logLevel | quote }}
- name: KUBEPOSTURE_TMP
  value: "/tmp"
- name: TMPDIR
  value: "/tmp"
{{- if .cronjobName }}
- name: KUBEPOSTURE_CLEANUP_FAILED_JOBS
  value: {{ $root.Values.cleanupFailedJobsOnSuccess | quote }}
- name: KUBEPOSTURE_CRONJOB_NAME
  value: {{ .cronjobName | quote }}
- name: KUBEPOSTURE_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- end }}
{{- end }}

{{/*
Scratch volume for bundle building (readOnlyRootFilesystem is on).
*/}}
{{- define "kubeposture-import.tmpVolume" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmp.sizeLimit }}
{{- end }}
