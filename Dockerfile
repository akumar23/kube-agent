# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build the operator
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o manager cmd/operator/main.go

# Build the CLI
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o kube-agent cmd/cli/main.go

# Runtime stage
FROM alpine:3.19

WORKDIR /

# Install Trivy for vulnerability scanning.
# Download directly from the GitHub release rather than piping an install script
# through sh, which avoids supply chain risk from a potentially compromised script.
# Pin to a specific version and verify using the official checksums file.
ARG TRIVY_VERSION=0.69.3
RUN apk add --no-cache ca-certificates wget && \
    wget -qO /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" && \
    wget -qO /tmp/trivy.checksums \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" && \
    expected=$(grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" /tmp/trivy.checksums | awk '{print $1}') && \
    actual=$(sha256sum /tmp/trivy.tar.gz | awk '{print $1}') && \
    [ "$expected" = "$actual" ] || (echo "checksum mismatch" && exit 1) && \
    tar -xz -C /usr/local/bin -f /tmp/trivy.tar.gz trivy && \
    rm /tmp/trivy.tar.gz /tmp/trivy.checksums && \
    apk del wget

# Copy binaries from builder
COPY --from=builder /workspace/manager /manager
COPY --from=builder /workspace/kube-agent /usr/local/bin/kube-agent

# Create non-root user
RUN adduser -D -u 65532 nonroot
USER 65532:65532

ENTRYPOINT ["/manager"]
