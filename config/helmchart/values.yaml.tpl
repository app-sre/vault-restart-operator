replicaCount: 1

image:
  repository: ${image_repo}
  pullPolicy: IfNotPresent
  tag: ${version}

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

# Additional environment variables for the operator
env: []

podAnnotations: {}

# Pod security context
podSecurityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault

# Container security context
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - "ALL"

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 10m
    memory: 128Mi

# kube-rbac-proxy sidecar for securing metrics endpoint
kube_rbac_proxy:
  image:
    repository: quay.io/redhat-cop/kube-rbac-proxy
    pullPolicy: IfNotPresent
    tag: v0.11.0
  resources:
    limits:
      cpu: 500m
      memory: 128Mi
    requests:
      cpu: 5m
      memory: 64Mi

# Leader election configuration
leaderElection:
  enabled: true

# Health probe bind address
healthProbeBindAddress: ":8081"

nodeSelector: {}

tolerations: []

affinity: {}

# Enable Prometheus ServiceMonitor (requires prometheus-operator)
enableMonitoring: false

# Service account name (will use controller-manager if not overridden)
serviceAccount:
  create: true
  name: controller-manager
  annotations: {}
