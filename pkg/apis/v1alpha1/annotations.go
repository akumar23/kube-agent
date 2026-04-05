package v1alpha1

// AnnotationScanRequestedAt is set on a ManagedApplication to request an immediate
// vulnerability scan (consumed by SecurityScanReconciler). The value is an RFC3339 timestamp.
const AnnotationScanRequestedAt = "agent.kubeagent.io/scan-requested-at"
