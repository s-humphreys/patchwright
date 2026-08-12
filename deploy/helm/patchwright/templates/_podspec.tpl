{{/*
Shared pod internals for both the CronJob (assess) and the Deployment (serve),
so they stay in sync. Callers pass a dict:
  root        the top context (.)
  command     "assess" or "serve"
  remediation bool — pass --remediation
  modeArgs    list of extra command args (e.g. --format, --addr, --interval)
  ports       bool — render a containerPort (server mode)
*/}}

{{- define "patchwright.container" -}}
- name: patchwright
  image: "{{ .root.Values.image.repository }}:{{ .root.Values.image.tag | default .root.Chart.AppVersion }}"
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args:
    - {{ .command }}
    - "--provider={{ .root.Values.provider.name }}"
    - "--mode={{ .root.Values.provider.mode }}"
    {{- if eq .root.Values.provider.mode "csv" }}
    - "--input=/data/{{ .root.Values.provider.input.key }}"
    {{- else if eq .root.Values.provider.mode "api" }}
    - "--option=base-url={{ required "provider.api.baseURL is required for api mode" .root.Values.provider.api.baseURL }}"
    {{- end }}
    - "--config=/etc/patchwright"
    - "--log-level={{ .root.Values.logLevel }}"
    - "--log-format={{ .root.Values.logFormat }}"
    {{- if .root.Values.reconcile.enabled }}
    - "--live-source=kube"
    {{- if .root.Values.reconcile.local }}
    - "--live-option=inCluster=true"
    {{- end }}
    {{- if .root.Values.reconcile.remote.kubeconfigSecret }}
    - "--live-option=kubeconfig=/etc/patchwright-kubeconfig/kubeconfig"
    {{- if .root.Values.reconcile.remote.contexts }}
    - "--live-option=contexts={{ join "," .root.Values.reconcile.remote.contexts }}"
    {{- end }}
    {{- end }}
    {{- end }}
    {{- if .remediation }}
    - "--remediation"
    {{- end }}
    {{- if .root.Values.scan.enabled }}
    - "--vuln-source={{ .root.Values.scan.vulnSource }}"
    {{- if .root.Values.scan.exploitSource }}
    - "--exploit-source={{ .root.Values.scan.exploitSource }}"
    {{- end }}
    {{- end }}
    {{- if and (eq .command "serve") .root.Values.ticketing.autoTicket }}
    - "--auto-ticket"
    {{- end }}
    {{- range .modeArgs }}
    - {{ . | quote }}
    {{- end }}
    {{- range .root.Values.extraArgs }}
    - {{ . | quote }}
    {{- end }}
  {{- if or .root.Values.scan.enabled .root.Values.registryAuth.dockerConfigSecret .root.Values.server.auth.secretName .root.Values.ticketing.credentialsSecretName (eq .root.Values.provider.mode "api") }}
  env:
    {{- if eq .root.Values.provider.mode "api" }}
    - name: RAPID7_API_KEY
      valueFrom:
        secretKeyRef:
          name: {{ required "provider.api.credentialsSecretName is required for api mode" .root.Values.provider.api.credentialsSecretName }}
          key: {{ .root.Values.provider.api.credentialsSecretKey }}
    {{- end }}
    {{- if .root.Values.ticketing.credentialsSecretName }}
    - name: JIRA_BASE_URL
      valueFrom:
        secretKeyRef: { name: {{ .root.Values.ticketing.credentialsSecretName }}, key: baseUrl }
    - name: JIRA_EMAIL
      valueFrom:
        secretKeyRef: { name: {{ .root.Values.ticketing.credentialsSecretName }}, key: email }
    - name: JIRA_API_TOKEN
      valueFrom:
        secretKeyRef: { name: {{ .root.Values.ticketing.credentialsSecretName }}, key: apiToken }
    {{- end }}
    {{- if .root.Values.server.auth.secretName }}
    - name: PATCHWRIGHT_API_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ .root.Values.server.auth.secretName }}
          key: {{ .root.Values.server.auth.secretKey }}
    {{- end }}
    {{- if .root.Values.scan.enabled }}
    - name: TRIVY_CACHE_DIR
      value: /tmp/trivy-cache
    - name: TMPDIR
      value: /tmp
    {{- end }}
    {{- if .root.Values.registryAuth.dockerConfigSecret }}
    - name: DOCKER_CONFIG
      value: /etc/patchwright-dockerconfig
    {{- end }}
  {{- end }}
  {{- if .ports }}
  ports:
    - name: http
      containerPort: {{ .root.Values.server.port }}
  {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
  {{- with .root.Values.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: rules
      mountPath: /etc/patchwright
      readOnly: true
    {{- if eq .root.Values.provider.mode "csv" }}
    - name: export
      mountPath: /data
      readOnly: true
    {{- end }}
    {{- if .root.Values.reconcile.remote.kubeconfigSecret }}
    - name: kubeconfig
      mountPath: /etc/patchwright-kubeconfig
      readOnly: true
    {{- end }}
    {{- if .root.Values.scan.enabled }}
    - name: tmp
      mountPath: /tmp
    {{- end }}
    {{- if .root.Values.registryAuth.dockerConfigSecret }}
    - name: dockerconfig
      mountPath: /etc/patchwright-dockerconfig
      readOnly: true
    {{- end }}
{{- end -}}

{{- define "patchwright.volumes" -}}
- name: rules
  configMap:
    name: {{ include "patchwright.fullname" .root }}-rules
{{- if eq .root.Values.provider.mode "csv" }}
- name: export
  secret:
    secretName: {{ required "provider.input.secretName is required for csv mode" .root.Values.provider.input.secretName }}
{{- end }}
{{- if .root.Values.reconcile.remote.kubeconfigSecret }}
- name: kubeconfig
  secret:
    secretName: {{ .root.Values.reconcile.remote.kubeconfigSecret }}
{{- end }}
{{- if .root.Values.scan.enabled }}
- name: tmp
  emptyDir: {}
{{- end }}
{{- if .root.Values.registryAuth.dockerConfigSecret }}
- name: dockerconfig
  secret:
    secretName: {{ .root.Values.registryAuth.dockerConfigSecret }}
    items:
      - key: {{ .root.Values.registryAuth.dockerConfigKey | quote }}
        path: config.json
{{- end }}
{{- end -}}
