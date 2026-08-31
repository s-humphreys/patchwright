{{/*
Name of the ClusterRole and its binding.
*/}}
{{- define "patchwright-rbac.name" -}}
{{- default "patchwright-reader" .Values.rbac.name -}}
{{- end -}}

{{/*
Standard labels. Kept minimal: these objects are grants, and a label implying ownership
by a release in a cluster where patchwright does not run is misleading.
*/}}
{{- define "patchwright-rbac.labels" -}}
app.kubernetes.io/name: {{ include "patchwright-rbac.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
The subject to bind, validated so a mistake is a render failure rather than a broken
binding in every cluster.

The validation is not decoration. The hand-applied file this chart replaces carried a
bare OBJECT_ID placeholder, which envsubst leaves untouched because it has no dollar
sign: applying the result bound the role to a user literally called "OBJECT_ID", and
every cluster refused the real identity on the next run. So the shapes a placeholder
takes are rejected by name, the bare one included.
*/}}
{{- define "patchwright-rbac.subjectName" -}}
{{- $name := .Values.subject.name | default "" | trim -}}
{{- if not $name -}}
{{- fail "subject.name is required: the AAD object (principal) ID for authMode=azure, or the name of the User, Group or ServiceAccount your kubeconfig context authenticates as. An empty subject would replace a working binding with one that grants nobody anything." -}}
{{- end -}}

{{- /* ${VAR}, $VAR, and <VAR>: a template that was never rendered. */ -}}
{{- if regexMatch "^\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?$" $name -}}
{{- fail (printf "subject.name is %q, which is an unrendered template variable rather than an identity. Applying it would replace a working binding with one that authenticates nobody." $name) -}}
{{- end -}}
{{- if regexMatch "^<.+>$" $name -}}
{{- fail (printf "subject.name is %q, which is a placeholder rather than an identity." $name) -}}
{{- end -}}
{{- $lower := lower $name -}}
{{- range $marker := list "changeme" "placeholder" "todo" "your-" "example" -}}
{{- if contains $marker $lower -}}
{{- fail (printf "subject.name is %q, which reads as a placeholder rather than an identity. Bind the identity your kubeconfig context actually authenticates as." $name) -}}
{{- end -}}
{{- end -}}

{{- /*
A User named in SCREAMING_SNAKE is the case that actually shipped: envsubst leaves a
bare OBJECT_ID alone, and it looks like a name rather than a variable. Restricted to
User because a Group legitimately might be capitalised, while an AAD user subject has
to be a GUID.
*/ -}}
{{- if and (eq .Values.subject.kind "User") (regexMatch "^[A-Z][A-Z0-9_]{2,}$" $name) -}}
{{- fail (printf "subject.name is %q, which looks like an unsubstituted placeholder rather than an identity - envsubst leaves a name with no dollar sign untouched, which is exactly how a previous binding came to authenticate a user called \"OBJECT_ID\". For authMode=azure this is the managed identity's object (principal) ID, a GUID: kubectl -n patchwright get managedidentity patchwright -o jsonpath='{.status.principalId}'" $name) -}}
{{- end -}}
{{- $name -}}
{{- end -}}
