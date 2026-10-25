{{/*
Expand the name of the chart.
*/}}
{{- define "kubeposture.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubeposture.fullname" -}}
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
Suffix of the setup Job's name: a hash of the chart version, the app
version and every value, so a changed Job is a new object. A Job's pod
template is immutable; with a fixed name every release would need
`helm upgrade --force`, Argo's `Replace=true` or a hook. With this one
Helm creates the new Job and deletes the old, and ArgoCD prunes it.
`setupJob.nameSuffixOverride` pins it.
*/}}
{{- define "kubeposture.setupJobSuffix" -}}
{{- if .Values.setupJob.nameSuffixOverride -}}
{{- .Values.setupJob.nameSuffixOverride -}}
{{- else -}}
{{- printf "%s-%s-%s" .Chart.Version .Chart.AppVersion (.Values | toYaml | b64enc) | sha256sum | trunc 7 -}}
{{- end -}}
{{- end }}

{{/*
`<fullname>-setup-<suffix>`, at most 63 characters (a Job name is a label value).
*/}}
{{- define "kubeposture.setupJobName" -}}
{{- $name := include "kubeposture.fullname" . | trunc 49 | trimSuffix "-" -}}
{{- printf "%s-setup-%s" $name (include "kubeposture.setupJobSuffix" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubeposture.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubeposture.labels" -}}
helm.sh/chart: {{ include "kubeposture.chart" . }}
{{ include "kubeposture.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubeposture.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubeposture.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubeposture.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kubeposture.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Common environment variables shared across web, worker, cronjobs.
*/}}
{{- define "kubeposture.env" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.db.secretName }}
      key: {{ .Values.db.urlKey }}
{{- if .Values.db.caSecret.name }}
- name: PGSSLROOTCERT
  value: /etc/kubeposture/db-ca/ca.crt
{{- end }}
- name: SECRET_KEY
{{- if .Values.secretKey.secretRef.name }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secretKey.secretRef.name }}
      key: {{ .Values.secretKey.secretRef.key }}
{{- else }}
  value: {{ .Values.secretKey.value | quote }}
{{- end }}
{{- range $key, $value := .Values.app.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{/*
Pod security context (shared across all pods).
*/}}
{{- define "kubeposture.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
{{- end }}

{{/*
Container security context (shared across all containers).
*/}}
{{- define "kubeposture.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end }}

{{/*
Volumes/mounts shared by every container: writable /tmp, plus the DB CA
bundle (libpq reads it via PGSSLROOTCERT) when db.caSecret.name is set.
*/}}
{{- define "kubeposture.volumeMounts" -}}
- name: tmp
  mountPath: /tmp
{{- if .Values.db.caSecret.name }}
- name: db-ca
  mountPath: /etc/kubeposture/db-ca
  readOnly: true
{{- end }}
{{- end }}

{{- define "kubeposture.volumes" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmp.sizeLimit }}
{{- if .Values.db.caSecret.name }}
- name: db-ca
  secret:
    secretName: {{ .Values.db.caSecret.name }}
    items:
      - key: {{ .Values.db.caSecret.key }}
        path: ca.crt
{{- end }}
{{- end }}

{{/*
wait-for-db init container — blocks pod startup until Postgres is reachable.
Uses the app image so it has Django + psycopg available, no extra tooling.
Pass the root context (.) — needs .Values.image and the env helper.
*/}}
{{- define "kubeposture.waitForDb" -}}
- name: wait-for-db
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command:
    - /bin/sh
    - -c
    - |
      echo "Waiting for database..."
      until err=$(python -c "import django, os; os.environ.setdefault('DJANGO_SETTINGS_MODULE','kubeposture.settings'); django.setup(); from django.db import connection; connection.ensure_connection()" 2>&1); do
        echo "  not ready ($(echo "$err" | tail -n 1)), retrying in 2s..."
        sleep 2
      done
      echo "Database ready."
  env:
    {{- include "kubeposture.env" . | nindent 4 }}
  volumeMounts:
    {{- include "kubeposture.volumeMounts" . | nindent 4 }}
  securityContext:
    {{- include "kubeposture.securityContext" . | nindent 4 }}
  # requests == limits: QoS is decided per pod, so a Burstable init
  # container would demote every batch job out of Guaranteed.
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 100m
      memory: 128Mi
{{- end }}

{{/*
Block until the setup Job has applied every migration. `migrate --check`
exits non-zero while unapplied migrations exist and never applies them, so
the Job stays the only writer (two `migrate` runs race on the same DDL) and
a new image cannot serve on an old schema. If the Job fails, the rollout
stalls here and the previous pods keep serving. Run after waitForDb.
*/}}
{{- define "kubeposture.waitForMigrations" -}}
- name: wait-for-migrations
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command:
    - /bin/sh
    - -c
    - |
      echo "Waiting for migrations (applied by the setup Job)..."
      until python manage.py migrate --check --noinput >/dev/null 2>&1; do
        echo "  unapplied migrations remain, retrying in 5s..."
        sleep 5
      done
      echo "Migrations applied."
  env:
    {{- include "kubeposture.env" . | nindent 4 }}
  volumeMounts:
    {{- include "kubeposture.volumeMounts" . | nindent 4 }}
  securityContext:
    {{- include "kubeposture.securityContext" . | nindent 4 }}
  resources:
    {{- toYaml .Values.migration.resources | nindent 4 }}
{{- end }}
