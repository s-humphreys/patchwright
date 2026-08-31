{{/*
The image to run.

image.tag when set, and the chart's appVersion otherwise - which for a RELEASED chart
is exactly the image published beside it, so there is nothing to pin. The charts in the
repository carry a development version instead, and rendering one of those without an
explicit tag fails here rather than deploying a reference that cannot be pulled.

That failure is the point. The previous arrangement left appVersion at 0.1.0 while the
image was at v1.29, so the chart's own default pointed at a tag that did not exist and
every deployment had to know to override it. A default that silently cannot work is
worse than no default.
*/}}
{{- define "patchwright.image" -}}
{{- $tag := .Values.image.tag | default "" | trim -}}
{{- if not $tag -}}
{{- $tag = .Chart.AppVersion -}}
{{- if or (not $tag) (hasPrefix "0.0.0-dev" $tag) -}}
{{- fail (printf "this chart is a development copy (appVersion %q), so it has no image to default to. Install the released chart - helm install pw oci://ghcr.io/s-humphreys/charts/patchwright --version <x.y.z> - or set image.tag to the version you want." $tag) -}}
{{- end -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "patchwright.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

# The release name alone when it already names the chart, so a release called
# patchwright is not deployed as "patchwright-patchwright". The standard Helm idiom,
# which this had lost.
{{- define "patchwright.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "patchwright.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "patchwright.labels" -}}
app.kubernetes.io/name: {{ include "patchwright.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "patchwright.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "patchwright.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
