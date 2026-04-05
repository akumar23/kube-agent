# Kube-Agent: Autonomous Kubernetes Management Agent

A Kubernetes operator that provides intelligent cluster management, automated deployments with public URL exposure, vulnerability scanning, automated patching, and self-healing capabilities.

## Features

- **Multi-Cluster Management**: Manage local (minikube/kind) and cloud clusters (AWS EKS, GKE, AKS)
- **GitOps Deployments**: Accept git repos, Helm charts, or Docker images and deploy automatically
- **Public URL Exposure**: Automatically create Ingress with TLS certificates via Let's Encrypt
- **Vulnerability Scanning**: Periodic container image and cluster security scans
- **Automated Patching**: Test and apply security patches for medium+ severity vulnerabilities
- **Progressive Delivery**: Canary/Blue-Green deployments with automatic rollback
- **Self-Healing**: Diagnose and remediate common pod failures automatically
- **Security Reports**: Scheduled reports delivered via Slack, email, or webhooks

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kube-Agent Operator                         │
│  ┌───────────────┬───────────────┬───────────────┐             │
│  │  Deployment   │   Security    │   Self-Heal   │             │
│  │  Controller   │   Controller  │   Controller  │             │
│  └───────────────┴───────────────┴───────────────┘             │
│  ┌───────────────┬───────────────┬───────────────┐             │
│  │  Diagnostic   │    Report     │    Upgrade    │             │
│  │  Controller   │   Controller  │   Controller  │             │
│  └───────────────┴───────────────┴───────────────┘             │
└─────────────────────────────────────────────────────────────────┘
         │                │                │
         ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   ArgoCD    │  │    Trivy    │  │ Argo        │
│   (GitOps)  │  │  (Scanner)  │  │ Rollouts    │
└─────────────┘  └─────────────┘  └─────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21+
- Kubernetes cluster (local or cloud)
- kubectl configured
- Helm 3.x

### Installation

#### From published chart (when image is published to a registry)

```bash
helm repo add kube-agent https://kube-agent.github.io/charts
helm install kube-agent kube-agent/kube-agent -n kube-agent-system --create-namespace
```

#### From source against a remote cluster (no registry)

When deploying to a cluster that can't pull from a registry (e.g. a bare kind cluster), build the image locally and load it directly into the cluster node.

```bash
# 1. Build chart dependencies
helm dependency build ./charts/kube-agent

# 2. Build the image for linux/amd64
#    (Dockerfile had a stale Trivy version — 0.69.3 is the fixed default)
docker build --platform linux/amd64 -t kube-agent:dev .

# 3. Export the image
docker save kube-agent:dev -o /tmp/kube-agent-dev.tar

# 4. Run a privileged pod on the node to access containerd
kubectl --kubeconfig <kubeconfig> apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: image-loader
  namespace: kube-system
spec:
  nodeName: kind-control-plane
  hostPID: true
  hostNetwork: true
  tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
  containers:
  - name: loader
    image: alpine:3.19
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: containerd-sock
      mountPath: /run/containerd/containerd.sock
    - name: tmp
      mountPath: /import
  volumes:
  - name: containerd-sock
    hostPath:
      path: /run/containerd/containerd.sock
  - name: tmp
    hostPath:
      path: /tmp
EOF

# 5. Wait for the pod, copy the image tar in, and import via ctr
kubectl --kubeconfig <kubeconfig> wait pod/image-loader -n kube-system --for=condition=Ready --timeout=60s
kubectl --kubeconfig <kubeconfig> cp /tmp/kube-agent-dev.tar kube-system/image-loader:/import/kube-agent-dev.tar
kubectl --kubeconfig <kubeconfig> exec -n kube-system image-loader -- sh -c \
  "apk add --no-cache containerd-ctr 2>/dev/null; ctr --address /run/containerd/containerd.sock -n k8s.io images import /import/kube-agent-dev.tar"
kubectl --kubeconfig <kubeconfig> delete pod image-loader -n kube-system

# 6. Deploy with imagePullPolicy=Never so the node uses the local image
helm upgrade --install kube-agent ./charts/kube-agent \
  --namespace kube-agent-system \
  --create-namespace \
  --set image.repository=kube-agent \
  --set image.tag=dev \
  --set image.pullPolicy=Never \
  --kubeconfig <kubeconfig>
```

> **Note on the kubeconfig TLS mismatch**: if your kubeconfig points to a kind cluster via a LAN IP and kubectl reports a certificate error, run:
> ```bash
> kubectl config set-cluster <cluster-name> --insecure-skip-tls-verify=true --kubeconfig <kubeconfig>
> ```

### Deploy Your First Application

```yaml
apiVersion: agent.kubeagent.io/v1alpha1
kind: ManagedApplication
metadata:
  name: my-app
  namespace: default
spec:
  source:
    type: git
    repository: https://github.com/your-org/your-app
    path: ./kubernetes
    branch: main
  deployment:
    strategy: canary
    canary:
      steps:
        - setWeight: 20
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 5m}
        - setWeight: 100
    autoRollback: true
  publicAccess:
    enabled: true
    host: my-app.example.com
    tls:
      enabled: true
      issuer: letsencrypt-prod
  security:
    vulnerabilityScanning:
      enabled: true
      schedule: "0 */6 * * *"
      severityThreshold: MEDIUM
      autoBlock: true
  selfHealing:
    enabled: true
    maxRetries: 3
```

## Custom Resource Definitions

### ManagedApplication
Deploy and manage applications with GitOps, progressive delivery, and automatic public URL exposure.

### SecurityScan
Configure vulnerability scanning for container images and cluster resources.

### SecurityReport
Schedule periodic security reports with customizable delivery options.

### ClusterConfig
Configure cluster-wide settings and multi-cluster management.

### RemediationPolicy
Define self-healing policies and automated remediation rules.

## Integrated Tools

| Tool | Purpose | Version |
|------|---------|---------|
| ArgoCD | GitOps continuous delivery | 2.10+ |
| Argo Rollouts | Progressive delivery | 1.6+ |
| Trivy | Container vulnerability scanning | 0.50+ |
| Kubescape | Cluster security scanning | 3.0+ |
| kube-bench | CIS benchmark scanning | 0.7+ |
| cert-manager | TLS certificate management | 1.14+ |
| Traefik | Ingress controller | 3.0+ |

## Development

```bash
# Run locally against cluster
make run

# Run tests
make test

# Build container image
make docker-build IMG=kube-agent:latest

# Generate CRDs
make manifests
```

## Security Considerations

- The agent operates with least-privilege RBAC
- All destructive operations require explicit approval or policy
- Full audit logging of all actions
- Supports dry-run mode for testing changes

## License

Apache License 2.0
