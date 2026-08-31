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
  image: {{ include "patchwright.image" .root | quote }}
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
    {{- if .root.Values.reconcile.remote.authMode }}
    - "--live-option=authMode={{ .root.Values.reconcile.remote.authMode }}"
    {{- end }}
    {{- if .root.Values.reconcile.remote.contexts }}
    - "--live-option=contexts={{ join "," .root.Values.reconcile.remote.contexts }}"
    {{- end }}
    {{- end }}
    {{- with .root.Values.reconcile.exposure }}
    {{- if .publicHostnames }}
    - "--live-option=publicHostnames={{ join "," .publicHostnames }}"
    {{- end }}
    {{- if .internalHostnames }}
    - "--live-option=internalHostnames={{ join "," .internalHostnames }}"
    {{- end }}
    {{- if .internalGateways }}
    - "--live-option=internalGateways={{ join "," .internalGateways }}"
    {{- end }}
    {{- end }}
    {{- end }}
    {{- if .remediation }}
    - "--remediation"
    {{- end }}
    {{- if .root.Values.scan.enabled }}
    - "--vuln-source={{ .root.Values.scan.vulnSource }}"
    {{- range .root.Values.scan.vulnOptions }}
    - "--vuln-option={{ . }}"
    {{- end }}
    {{- if .root.Values.scan.exploitSource }}
    - "--exploit-source={{ .root.Values.scan.exploitSource }}"
    {{- range .root.Values.scan.exploitOptions }}
    - "--exploit-option={{ . }}"
    {{- end }}
    {{- end }}
    {{- end }}
    {{- if .root.Values.age.source }}
    - "--age-source={{ .root.Values.age.source }}"
    {{- range .root.Values.age.options }}
    - "--age-option={{ . }}"
    {{- end }}
    {{- end }}
    {{- with .root.Values.auth.oidc }}
    {{- if .issuer }}
    - "--oidc-issuer={{ .issuer }}"
    - "--oidc-client-id={{ required "auth.oidc.clientID is required when an issuer is set" .clientID }}"
    - "--oidc-redirect-url={{ required "auth.oidc.redirectURL is required when an issuer is set" .redirectURL }}"
    {{- range .allowedGroups }}
    - "--oidc-allowed-group={{ . }}"
    {{- end }}
    {{- range .allowedEmails }}
    - "--oidc-allowed-email={{ . }}"
    {{- end }}
    {{- range .allowedDomains }}
    - "--oidc-allowed-domain={{ . }}"
    {{- end }}
    {{- range .scopes }}
    - "--oidc-scope={{ . }}"
    {{- end }}
    {{- with .sessionTTL }}
    - "--oidc-session-ttl={{ . }}"
    {{- end }}
    {{- end }}
    {{- end }}
    {{- if .root.Values.support.source }}
    - "--support-source={{ .root.Values.support.source }}"
    {{- range .root.Values.support.options }}
    - "--support-option={{ . }}"
    {{- end }}
    {{- end }}
    {{- if and (eq .command "serve") .root.Values.metrics.requireAuth }}
    - "--metrics-require-auth"
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
  {{- $oidc := .root.Values.auth.oidc }}
  {{- if or .root.Values.scan.enabled .root.Values.registryAuth.dockerConfigSecret $oidc.clientSecretRef.name $oidc.sessionKeyRef.name }}
  env:
    {{- if $oidc.clientSecretRef.name }}
    # Referenced rather than injected through values: a client secret in a HelmRelease's
    # values is readable by anyone who can read HelmReleases, and shows up in git if the
    # values ever get committed. The Secret is akv2k8s output, so the key names are the
    # vault's JSON, not ours - hence a name/key pair rather than envFrom.
    - name: PATCHWRIGHT_OIDC_CLIENT_SECRET
      valueFrom:
        secretKeyRef:
          name: {{ $oidc.clientSecretRef.name }}
          key: {{ $oidc.clientSecretRef.key | default "clientSecret" }}
    {{- end }}
    {{- if $oidc.sessionKeyRef.name }}
    - name: PATCHWRIGHT_SESSION_KEY
      valueFrom:
        secretKeyRef:
          name: {{ $oidc.sessionKeyRef.name }}
          key: {{ $oidc.sessionKeyRef.key | default "sessionKey" }}
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
  {{- if .root.Values.credentialsSecretName }}
  # One Secret, whose keys are the environment variables the binary reads. It replaced
  # five separate secretName/secretKey pairs — Rapid7, Azure DevOps, three Jira values
  # and the API token — each of which had to agree with a key name the operator could
  # not see from the chart.
  #
  # Absent keys are simply absent: patchwright reports what it could not do rather than
  # failing, so a Secret with only RAPID7_API_KEY gives an assessment with no ticketing
  # and no in-flight detection, and says so.
  envFrom:
    - secretRef:
        name: {{ .root.Values.credentialsSecretName }}
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
    {{- if .root.Values.scan.cache.persistence.enabled }}
    - name: trivy-cache
      mountPath: /tmp/trivy-cache
    {{- end }}
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
{{- if .root.Values.scan.cache.persistence.enabled }}
- name: trivy-cache
  persistentVolumeClaim:
    claimName: {{ .root.Values.scan.cache.persistence.existingClaim | default (printf "%s-trivy-cache" (include "patchwright.fullname" .root)) }}
{{- end }}
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
