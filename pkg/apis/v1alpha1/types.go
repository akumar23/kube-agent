// Package v1alpha1 contains API Schema definitions for the agent v1alpha1 API group
// +kubebuilder:object:generate=true
// +groupName=agent.kubeagent.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceType defines the type of application source
type SourceType string

const (
	SourceTypeGit    SourceType = "git"
	SourceTypeHelm   SourceType = "helm"
	SourceTypeDocker SourceType = "docker"
)

// DeploymentStrategy defines the deployment strategy
type DeploymentStrategy string

const (
	DeploymentStrategyRolling   DeploymentStrategy = "rolling"
	DeploymentStrategyCanary    DeploymentStrategy = "canary"
	DeploymentStrategyBlueGreen DeploymentStrategy = "blue-green"
)

// SeverityLevel defines vulnerability severity levels
type SeverityLevel string

const (
	SeverityLevelCritical SeverityLevel = "CRITICAL"
	SeverityLevelHigh     SeverityLevel = "HIGH"
	SeverityLevelMedium   SeverityLevel = "MEDIUM"
	SeverityLevelLow      SeverityLevel = "LOW"
)

// ApplicationPhase defines the phase of the application
type ApplicationPhase string

const (
	ApplicationPhasePending     ApplicationPhase = "Pending"
	ApplicationPhaseDeploying   ApplicationPhase = "Deploying"
	ApplicationPhaseRunning     ApplicationPhase = "Running"
	ApplicationPhaseDegraded    ApplicationPhase = "Degraded"
	ApplicationPhaseFailed      ApplicationPhase = "Failed"
	ApplicationPhaseRollingBack ApplicationPhase = "RollingBack"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.status.publicURL`
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.health`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ManagedApplication is the Schema for deploying and managing applications
type ManagedApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManagedApplicationSpec   `json:"spec,omitempty"`
	Status ManagedApplicationStatus `json:"status,omitempty"`
}

// ManagedApplicationSpec defines the desired state of ManagedApplication
type ManagedApplicationSpec struct {
	// Source defines where the application comes from
	Source ApplicationSource `json:"source"`

	// Deployment defines how the application should be deployed
	// +optional
	Deployment DeploymentSpec `json:"deployment,omitempty"`

	// PublicAccess defines how the application is exposed publicly
	// +optional
	PublicAccess PublicAccessSpec `json:"publicAccess,omitempty"`

	// Security defines security scanning and policies
	// +optional
	Security SecuritySpec `json:"security,omitempty"`

	// SelfHealing defines self-healing configuration
	// +optional
	SelfHealing SelfHealingSpec `json:"selfHealing,omitempty"`

	// TargetNamespace is the namespace where the app will be deployed
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`
}

// ApplicationSource defines the source of the application
type ApplicationSource struct {
	// Type is the source type (git, helm, docker)
	// +kubebuilder:validation:Enum=git;helm;docker
	Type SourceType `json:"type"`

	// Repository is the git repository URL or Helm chart repo
	// +optional
	Repository string `json:"repository,omitempty"`

	// Path is the path within the repository
	// +optional
	Path string `json:"path,omitempty"`

	// Branch is the git branch
	// +optional
	Branch string `json:"branch,omitempty"`

	// Chart is the Helm chart name
	// +optional
	Chart string `json:"chart,omitempty"`

	// ChartVersion is the Helm chart version
	// +optional
	ChartVersion string `json:"chartVersion,omitempty"`

	// Image is the Docker image for docker source type
	// +optional
	Image string `json:"image,omitempty"`

	// FallbackImage is used when the primary image fails (for self-healing)
	// +optional
	FallbackImage string `json:"fallbackImage,omitempty"`

	// Command overrides the container command
	// +optional
	Command []string `json:"command,omitempty"`

	// Args are arguments to the command
	// +optional
	Args []string `json:"args,omitempty"`

	// Values are Helm values to apply
	// +optional
	Values map[string]string `json:"values,omitempty"`
}

// DeploymentSpec defines deployment configuration
type DeploymentSpec struct {
	// Strategy is the deployment strategy
	// +kubebuilder:default=rolling
	// +kubebuilder:validation:Enum=rolling;canary;blue-green
	Strategy DeploymentStrategy `json:"strategy,omitempty"`

	// Canary defines canary deployment configuration
	// +optional
	Canary *CanarySpec `json:"canary,omitempty"`

	// BlueGreen defines blue-green deployment configuration
	// +optional
	BlueGreen *BlueGreenSpec `json:"blueGreen,omitempty"`

	// AutoRollback enables automatic rollback on failure.
	// Use json:"autoRollback" (no omitempty) so that an explicit false is preserved
	// and not overwritten by the kubebuilder default webhook.
	// +kubebuilder:default=true
	AutoRollback bool `json:"autoRollback"`

	// HealthChecks configures health check behavior
	// +optional
	HealthChecks *HealthCheckSpec `json:"healthChecks,omitempty"`

	// Replicas is the desired number of replicas
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`
}

// CanarySpec defines canary deployment steps
type CanarySpec struct {
	// Steps defines the canary rollout steps
	Steps []CanaryStep `json:"steps,omitempty"`

	// Analysis defines automated analysis for promotion decisions
	// +optional
	Analysis *AnalysisSpec `json:"analysis,omitempty"`
}

// CanaryStep defines a single canary step
type CanaryStep struct {
	// SetWeight sets the canary weight percentage
	// +optional
	SetWeight *int32 `json:"setWeight,omitempty"`

	// Pause pauses the rollout for a duration
	// +optional
	Pause *PauseSpec `json:"pause,omitempty"`
}

// PauseSpec defines pause configuration
type PauseSpec struct {
	// Duration is how long to pause (e.g., "5m", "1h")
	Duration string `json:"duration,omitempty"`
}

// BlueGreenSpec defines blue-green deployment configuration
type BlueGreenSpec struct {
	// AutoPromotionEnabled enables automatic promotion
	AutoPromotionEnabled bool `json:"autoPromotionEnabled,omitempty"`

	// AutoPromotionSeconds is seconds to wait before auto promotion
	AutoPromotionSeconds int32 `json:"autoPromotionSeconds,omitempty"`

	// PreviewService is the name of the preview service
	// +optional
	PreviewService string `json:"previewService,omitempty"`
}

// AnalysisSpec defines analysis configuration for promotions
type AnalysisSpec struct {
	// SuccessCondition is the condition for successful analysis
	SuccessCondition string `json:"successCondition,omitempty"`

	// FailureCondition is the condition for failed analysis
	FailureCondition string `json:"failureCondition,omitempty"`

	// Interval is how often to run the analysis
	Interval string `json:"interval,omitempty"`

	// Count is how many times to run the analysis
	Count int32 `json:"count,omitempty"`
}

// HealthCheckSpec defines health check configuration
type HealthCheckSpec struct {
	// Enabled enables health checks.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// FailureThreshold is the number of failures before marking unhealthy
	// +kubebuilder:default=3
	FailureThreshold int32 `json:"failureThreshold,omitempty"`

	// SuccessThreshold is the number of successes before marking healthy
	// +kubebuilder:default=1
	SuccessThreshold int32 `json:"successThreshold,omitempty"`
}

// PublicAccessSpec defines public access configuration
type PublicAccessSpec struct {
	// Enabled enables public access
	Enabled bool `json:"enabled"`

	// Host is the hostname for the application
	// +optional
	Host string `json:"host,omitempty"`

	// TLS configures TLS/SSL
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`

	// Port is the service port to expose
	// +kubebuilder:default=80
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// IngressClass is the ingress class to use
	// +optional
	IngressClass string `json:"ingressClass,omitempty"`
}

// TLSSpec defines TLS configuration
type TLSSpec struct {
	// Enabled enables TLS
	Enabled bool `json:"enabled"`

	// Issuer is the cert-manager issuer to use
	// +kubebuilder:default=letsencrypt-prod
	Issuer string `json:"issuer,omitempty"`

	// SecretName is the name of the TLS secret
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// SecuritySpec defines security configuration
type SecuritySpec struct {
	// VulnerabilityScanning configures vulnerability scanning
	// +optional
	VulnerabilityScanning *VulnerabilityScanSpec `json:"vulnerabilityScanning,omitempty"`

	// ClusterScanning configures cluster security scanning
	// +optional
	ClusterScanning *ClusterScanSpec `json:"clusterScanning,omitempty"`
}

// VulnerabilityScanSpec defines vulnerability scanning configuration
type VulnerabilityScanSpec struct {
	// Enabled enables vulnerability scanning
	Enabled bool `json:"enabled"`

	// Schedule is the cron schedule for scanning (e.g., "0 */6 * * *")
	// +kubebuilder:default="0 */6 * * *"
	Schedule string `json:"schedule,omitempty"`

	// SeverityThreshold is the minimum severity to report/block
	// +kubebuilder:default=MEDIUM
	// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW
	SeverityThreshold SeverityLevel `json:"severityThreshold,omitempty"`

	// AutoBlock blocks deployments with vulnerabilities above threshold
	AutoBlock bool `json:"autoBlock,omitempty"`

	// AutoPatch enables automatic patching of vulnerabilities
	AutoPatch bool `json:"autoPatch,omitempty"`
}

// ClusterScanSpec defines cluster security scanning configuration
type ClusterScanSpec struct {
	// Enabled enables cluster scanning
	Enabled bool `json:"enabled"`

	// Frameworks are the security frameworks to scan against
	// +kubebuilder:default={"NSA","CIS"}
	Frameworks []string `json:"frameworks,omitempty"`

	// Schedule is the cron schedule for scanning
	// +kubebuilder:default="0 0 * * 0"
	Schedule string `json:"schedule,omitempty"`
}

// SelfHealingSpec defines self-healing configuration
type SelfHealingSpec struct {
	// Enabled enables self-healing
	Enabled bool `json:"enabled"`

	// MaxRetries is the maximum number of remediation attempts
	// +kubebuilder:default=3
	MaxRetries int32 `json:"maxRetries,omitempty"`

	// DiagnosticCollection enables diagnostic data collection on failures.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	DiagnosticCollection bool `json:"diagnosticCollection"`

	// AutoRestart enables automatic pod restarts.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	AutoRestart bool `json:"autoRestart"`

	// AutoScale enables automatic scaling on resource pressure
	AutoScale bool `json:"autoScale,omitempty"`

	// NotifyOnRemediation enables notifications on remediation actions
	NotifyOnRemediation bool `json:"notifyOnRemediation,omitempty"`
}

// ManagedApplicationStatus defines the observed state of ManagedApplication
type ManagedApplicationStatus struct {
	// Phase is the current phase of the application
	Phase ApplicationPhase `json:"phase,omitempty"`

	// Health is the health status
	Health string `json:"health,omitempty"`

	// PublicURL is the public URL of the application
	// +optional
	PublicURL string `json:"publicURL,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastDeployedAt is when the application was last deployed
	// +optional
	LastDeployedAt *metav1.Time `json:"lastDeployedAt,omitempty"`

	// LastScannedAt is when security scanning was last performed
	// +optional
	LastScannedAt *metav1.Time `json:"lastScannedAt,omitempty"`

	// VulnerabilityCount is the count of vulnerabilities by severity
	// +optional
	VulnerabilityCount map[string]int32 `json:"vulnerabilityCount,omitempty"`

	// CurrentRevision is the current deployment revision
	// +optional
	CurrentRevision string `json:"currentRevision,omitempty"`

	// DesiredRevision is the desired deployment revision
	// +optional
	DesiredRevision string `json:"desiredRevision,omitempty"`

	// RemediationAttempts is the number of self-healing attempts
	// +optional
	RemediationAttempts int32 `json:"remediationAttempts,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true

// ManagedApplicationList contains a list of ManagedApplication
type ManagedApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagedApplication `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.connectionStatus`

// ClusterConfig is the Schema for cluster-wide configuration
type ClusterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterConfigSpec   `json:"spec,omitempty"`
	Status ClusterConfigStatus `json:"status,omitempty"`
}

// ClusterConfigSpec defines the desired cluster configuration
type ClusterConfigSpec struct {
	// Provider is the cluster provider (local, eks, gke, aks)
	Provider string `json:"provider"`

	// Region is the cloud region (for cloud providers)
	// +optional
	Region string `json:"region,omitempty"`

	// KubeconfigSecret references the kubeconfig secret
	// +optional
	KubeconfigSecret *SecretReference `json:"kubeconfigSecret,omitempty"`

	// DefaultIngress configures default ingress settings
	// +optional
	DefaultIngress *IngressConfig `json:"defaultIngress,omitempty"`

	// DefaultSecurity configures default security settings
	// +optional
	DefaultSecurity *DefaultSecurityConfig `json:"defaultSecurity,omitempty"`

	// Notifications configures notification channels
	// +optional
	Notifications *NotificationConfig `json:"notifications,omitempty"`
}

// SecretReference references a Kubernetes secret
type SecretReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Key       string `json:"key,omitempty"`
}

// IngressConfig configures default ingress settings
type IngressConfig struct {
	// Class is the default ingress class
	Class string `json:"class,omitempty"`

	// Domain is the base domain for applications
	Domain string `json:"domain,omitempty"`

	// TLSIssuer is the default cert-manager issuer
	TLSIssuer string `json:"tlsIssuer,omitempty"`
}

// DefaultSecurityConfig configures default security settings
type DefaultSecurityConfig struct {
	// ScanSchedule is the default scan schedule
	ScanSchedule string `json:"scanSchedule,omitempty"`

	// SeverityThreshold is the default severity threshold
	SeverityThreshold SeverityLevel `json:"severityThreshold,omitempty"`

	// EnforceNetworkPolicies enables network policy enforcement
	EnforceNetworkPolicies bool `json:"enforceNetworkPolicies,omitempty"`
}

// NotificationConfig configures notifications
type NotificationConfig struct {
	// Slack configures Slack notifications
	// +optional
	Slack *SlackConfig `json:"slack,omitempty"`

	// Email configures email notifications
	// +optional
	Email *EmailConfig `json:"email,omitempty"`

	// Webhook configures webhook notifications
	// +optional
	Webhook *WebhookConfig `json:"webhook,omitempty"`
}

// SlackConfig configures Slack notifications
type SlackConfig struct {
	// Channel is the Slack channel
	Channel string `json:"channel"`

	// WebhookSecret references the webhook URL secret
	WebhookSecret SecretReference `json:"webhookSecret"`
}

// EmailConfig configures email notifications
type EmailConfig struct {
	// Recipients are email addresses to notify
	Recipients []string `json:"recipients"`

	// SMTPSecret references SMTP credentials
	SMTPSecret SecretReference `json:"smtpSecret"`
}

// WebhookConfig configures webhook notifications
type WebhookConfig struct {
	// URL is the webhook URL
	URL string `json:"url"`

	// Secret references authentication secret
	// +optional
	Secret *SecretReference `json:"secret,omitempty"`
}

// ClusterConfigStatus defines the observed state of ClusterConfig
type ClusterConfigStatus struct {
	// ConnectionStatus is the cluster connection status
	ConnectionStatus string `json:"connectionStatus,omitempty"`

	// LastConnectedAt is when the cluster was last connected
	// +optional
	LastConnectedAt *metav1.Time `json:"lastConnectedAt,omitempty"`

	// KubernetesVersion is the cluster Kubernetes version
	// +optional
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`

	// NodeCount is the number of nodes in the cluster
	// +optional
	NodeCount int32 `json:"nodeCount,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterConfigList contains a list of ClusterConfig
type ClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterConfig `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Last Run",type=date,JSONPath=`.status.lastRunAt`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`

// SecurityReport is the Schema for scheduling security reports
type SecurityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityReportSpec   `json:"spec,omitempty"`
	Status SecurityReportStatus `json:"status,omitempty"`
}

// SecurityReportSpec defines the desired security report configuration
type SecurityReportSpec struct {
	// Schedule is the cron schedule for report generation
	// +kubebuilder:default="0 0 * * 0"
	Schedule string `json:"schedule"`

	// Targets are namespaces or applications to include
	// +optional
	Targets []ReportTarget `json:"targets,omitempty"`

	// Formats are the output formats
	// +kubebuilder:default={"HTML","JSON"}
	Formats []string `json:"formats,omitempty"`

	// Delivery configures report delivery
	// +optional
	Delivery *DeliveryConfig `json:"delivery,omitempty"`

	// IncludeClusterScan includes cluster-wide security scan.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	IncludeClusterScan bool `json:"includeClusterScan"`

	// IncludeVulnerabilities includes vulnerability scan results.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	IncludeVulnerabilities bool `json:"includeVulnerabilities"`

	// IncludeRemediation includes remediation recommendations.
	// No omitempty so an explicit false is not dropped by serialization.
	// +kubebuilder:default=true
	IncludeRemediation bool `json:"includeRemediation"`
}

// ReportTarget defines a report target
type ReportTarget struct {
	// Namespace is a namespace to include
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Application is an application name to include
	// +optional
	Application string `json:"application,omitempty"`
}

// DeliveryConfig configures report delivery
type DeliveryConfig struct {
	// Slack channel for delivery
	// +optional
	Slack string `json:"slack,omitempty"`

	// Email addresses for delivery
	// +optional
	Email []string `json:"email,omitempty"`

	// Webhook URL for delivery
	// +optional
	Webhook string `json:"webhook,omitempty"`

	// S3Bucket for archival
	// +optional
	S3Bucket string `json:"s3Bucket,omitempty"`
}

// SecurityReportStatus defines the observed state of SecurityReport
type SecurityReportStatus struct {
	// Phase is the current phase
	Phase string `json:"phase,omitempty"`

	// LastRunAt is when the report was last generated
	// +optional
	LastRunAt *metav1.Time `json:"lastRunAt,omitempty"`

	// NextRunAt is when the report will next be generated
	// +optional
	NextRunAt *metav1.Time `json:"nextRunAt,omitempty"`

	// LastReportURL is the URL of the last generated report
	// +optional
	LastReportURL string `json:"lastReportURL,omitempty"`

	// Summary contains the last report summary
	// +optional
	Summary *ReportSummary `json:"summary,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ReportSummary contains report summary information
type ReportSummary struct {
	// TotalVulnerabilities is the total count
	TotalVulnerabilities int32 `json:"totalVulnerabilities,omitempty"`

	// CriticalCount is the critical severity count
	CriticalCount int32 `json:"criticalCount,omitempty"`

	// HighCount is the high severity count
	HighCount int32 `json:"highCount,omitempty"`

	// MediumCount is the medium severity count
	MediumCount int32 `json:"mediumCount,omitempty"`

	// ComplianceScore is the overall compliance percentage
	ComplianceScore int32 `json:"complianceScore,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityReportList contains a list of SecurityReport
type SecurityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityReport `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// RemediationPolicy defines automated remediation rules
type RemediationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RemediationPolicySpec   `json:"spec,omitempty"`
	Status RemediationPolicyStatus `json:"status,omitempty"`
}

// RemediationPolicySpec defines remediation rules
type RemediationPolicySpec struct {
	// Enabled enables this policy
	Enabled bool `json:"enabled"`

	// Selector selects which resources this policy applies to
	// +optional
	Selector *ResourceSelector `json:"selector,omitempty"`

	// Rules are the remediation rules
	Rules []RemediationRule `json:"rules"`

	// SafetyLimits configures safety constraints
	// +optional
	SafetyLimits *SafetyLimits `json:"safetyLimits,omitempty"`
}

// ResourceSelector selects resources
type ResourceSelector struct {
	// Namespaces to include
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// LabelSelector to match
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// RemediationRule defines a single remediation rule
type RemediationRule struct {
	// Name is the rule name
	Name string `json:"name"`

	// Condition is when this rule triggers
	Condition RemediationCondition `json:"condition"`

	// Action is what to do when triggered
	Action RemediationAction `json:"action"`

	// Cooldown is the minimum time between actions (e.g., "5m", "1h")
	// +kubebuilder:default="5m"
	Cooldown string `json:"cooldown,omitempty"`
}

// RemediationCondition defines when a rule triggers
type RemediationCondition struct {
	// Type is the condition type
	// +kubebuilder:validation:Enum=CrashLoopBackOff;OOMKilled;ImagePullBackOff;Pending;Unschedulable;ReadinessFailure;LivenessFailure;HighResourceUsage
	Type string `json:"type"`

	// Threshold is the number of occurrences before triggering
	// +kubebuilder:default=3
	Threshold int32 `json:"threshold,omitempty"`

	// Duration is how long the condition must persist
	// +optional
	Duration string `json:"duration,omitempty"`
}

// RemediationAction defines what action to take
type RemediationAction struct {
	// Type is the action type
	// +kubebuilder:validation:Enum=restart;scale;rollback;useFallback;notify;increaseResources
	Type string `json:"type"`

	// Parameters are action-specific parameters
	// +optional
	Parameters map[string]string `json:"parameters,omitempty"`
}

// SafetyLimits constrains automated actions
type SafetyLimits struct {
	// MaxActionsPerHour limits actions per hour
	// +kubebuilder:default=10
	MaxActionsPerHour int32 `json:"maxActionsPerHour,omitempty"`

	// MaxAffectedPodsPercent limits the percentage of pods affected (0-100)
	// +kubebuilder:default=25
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MaxAffectedPodsPercent int32 `json:"maxAffectedPodsPercent,omitempty"`

	// RequireApproval requires human approval for destructive actions
	RequireApproval bool `json:"requireApproval,omitempty"`

	// DryRunMode only logs actions without executing
	DryRunMode bool `json:"dryRunMode,omitempty"`
}

// RemediationPolicyStatus defines the observed state
type RemediationPolicyStatus struct {
	// ActionsExecuted is the total actions executed
	ActionsExecuted int64 `json:"actionsExecuted,omitempty"`

	// LastActionAt is when the last action was taken
	// +optional
	LastActionAt *metav1.Time `json:"lastActionAt,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// RemediationPolicyList contains a list of RemediationPolicy
type RemediationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RemediationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&ManagedApplication{}, &ManagedApplicationList{},
		&ClusterConfig{}, &ClusterConfigList{},
		&SecurityReport{}, &SecurityReportList{},
		&RemediationPolicy{}, &RemediationPolicyList{},
	)
}
