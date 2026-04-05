package security

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// SecurityReportReconciler reconciles SecurityReport objects
type SecurityReportReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Log      logr.Logger
}

// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=securityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=securityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for SecurityReport
func (r *SecurityReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("securityreport", req.NamespacedName)

	// Fetch the SecurityReport
	report := &agentv1alpha1.SecurityReport{}
	if err := r.Get(ctx, req.NamespacedName, report); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if it's time to generate a report
	if !r.shouldGenerateReport(report) {
		nextRun := nextScheduleTime(report.Spec.Schedule, 7*24*time.Hour)
		report.Status.NextRunAt = &metav1.Time{Time: nextRun}
		if err := r.Status().Update(ctx, report); err != nil {
			log.Error(err, "Failed to update next run time")
		}
		return ctrl.Result{RequeueAfter: time.Until(nextRun)}, nil
	}

	log.Info("Generating security report")
	r.Recorder.Event(report, corev1.EventTypeNormal, "ReportStarted", "Starting report generation")

	// Collect data from all targets
	reportData, err := r.collectReportData(ctx, report, log)
	if err != nil {
		log.Error(err, "Failed to collect report data")
		report.Status.Phase = "Failed"
		if statusErr := r.Status().Update(ctx, report); statusErr != nil {
			log.Error(statusErr, "Failed to update report status to Failed")
		}
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Generate report in requested formats
	for _, format := range report.Spec.Formats {
		if err := r.generateReport(ctx, report, reportData, format, log); err != nil {
			log.Error(err, "Failed to generate report", "format", format)
		}
	}

	// Deliver report
	if report.Spec.Delivery != nil {
		if err := r.deliverReport(ctx, report, reportData, log); err != nil {
			log.Error(err, "Failed to deliver report")
		}
	}

	// Update status
	report.Status.Phase = "Completed"
	report.Status.LastRunAt = &metav1.Time{Time: time.Now()}
	report.Status.NextRunAt = &metav1.Time{Time: nextScheduleTime(report.Spec.Schedule, 7*24*time.Hour)}
	report.Status.Summary = &agentv1alpha1.ReportSummary{
		TotalVulnerabilities: reportData.TotalVulnerabilities,
		CriticalCount:        reportData.CriticalCount,
		HighCount:            reportData.HighCount,
		MediumCount:          reportData.MediumCount,
		ComplianceScore:      reportData.ComplianceScore,
	}

	if err := r.Status().Update(ctx, report); err != nil {
		log.Error(err, "Failed to update report status")
		return ctrl.Result{}, err
	}

	r.Recorder.Event(report, corev1.EventTypeNormal, "ReportGenerated",
		fmt.Sprintf("Security report generated with %d total vulnerabilities", reportData.TotalVulnerabilities))

	log.Info("Security report generated successfully",
		"total", reportData.TotalVulnerabilities,
		"critical", reportData.CriticalCount,
		"high", reportData.HighCount)

	return ctrl.Result{RequeueAfter: time.Until(report.Status.NextRunAt.Time)}, nil
}

// ReportData contains aggregated report data
type ReportData struct {
	GeneratedAt          time.Time
	TotalVulnerabilities int32
	CriticalCount        int32
	HighCount            int32
	MediumCount          int32
	LowCount             int32
	ComplianceScore      int32
	Applications         []ApplicationReport
	ClusterFindings      []ClusterFinding
	Recommendations      []Recommendation
}

// ApplicationReport contains per-application vulnerability data
type ApplicationReport struct {
	Name            string
	Namespace       string
	Images          []string
	Vulnerabilities map[string]int32
	LastScanned     *metav1.Time
}

// ClusterFinding represents a cluster-level security finding
type ClusterFinding struct {
	Framework   string
	Control     string
	Severity    string
	Description string
	Remediation string
	Resources   []string
}

// Recommendation provides actionable security advice
type Recommendation struct {
	Priority    string
	Title       string
	Description string
	Impact      string
	Effort      string
}

// shouldGenerateReport determines if a report should be generated now based on the cron schedule.
func (r *SecurityReportReconciler) shouldGenerateReport(report *agentv1alpha1.SecurityReport) bool {
	return shouldRunNow(report.Spec.Schedule, report.Status.LastRunAt, 7*24*time.Hour)
}

// collectReportData gathers data from all targets
func (r *SecurityReportReconciler) collectReportData(ctx context.Context, report *agentv1alpha1.SecurityReport, log logr.Logger) (*ReportData, error) {
	data := &ReportData{
		GeneratedAt: time.Now(),
	}

	// Collect from specified namespaces or cluster-wide
	var namespaceFilter []string
	if len(report.Spec.Targets) > 0 {
		for _, target := range report.Spec.Targets {
			if target.Namespace != "" {
				namespaceFilter = append(namespaceFilter, target.Namespace)
			}
		}
	}

	// List apps per namespace to avoid a cluster-wide scan when targets are scoped.
	var allApps []agentv1alpha1.ManagedApplication
	if len(namespaceFilter) > 0 {
		for _, ns := range namespaceFilter {
			nsList := &agentv1alpha1.ManagedApplicationList{}
			if err := r.List(ctx, nsList, client.InNamespace(ns)); err != nil {
				return nil, fmt.Errorf("failed to list applications in namespace %s: %w", ns, err)
			}
			allApps = append(allApps, nsList.Items...)
		}
	} else {
		// No namespace filter – list cluster-wide
		clusterList := &agentv1alpha1.ManagedApplicationList{}
		if err := r.List(ctx, clusterList); err != nil {
			return nil, fmt.Errorf("failed to list applications: %w", err)
		}
		allApps = clusterList.Items
	}

	for _, app := range allApps {
		appReport := ApplicationReport{
			Name:            app.Name,
			Namespace:       app.Namespace,
			Vulnerabilities: app.Status.VulnerabilityCount,
			LastScanned:     app.Status.LastScannedAt,
		}

		if app.Spec.Source.Image != "" {
			appReport.Images = append(appReport.Images, app.Spec.Source.Image)
		}

		data.Applications = append(data.Applications, appReport)

		// Aggregate vulnerability counts
		if app.Status.VulnerabilityCount != nil {
			data.CriticalCount += app.Status.VulnerabilityCount["CRITICAL"]
			data.HighCount += app.Status.VulnerabilityCount["HIGH"]
			data.MediumCount += app.Status.VulnerabilityCount["MEDIUM"]
			data.LowCount += app.Status.VulnerabilityCount["LOW"]
		}
	}

	data.TotalVulnerabilities = data.CriticalCount + data.HighCount + data.MediumCount + data.LowCount

	// Include cluster scan results if enabled
	if report.Spec.IncludeClusterScan {
		findings, err := r.collectClusterFindings(ctx, log)
		if err != nil {
			log.Error(err, "Failed to collect cluster findings")
		} else {
			data.ClusterFindings = findings
		}
	}

	// Generate recommendations
	if report.Spec.IncludeRemediation {
		data.Recommendations = r.generateRecommendations(data)
	}

	// Calculate compliance score (simple weighted average)
	data.ComplianceScore = r.calculateComplianceScore(data)

	return data, nil
}

// collectClusterFindings runs cluster security scans
func (r *SecurityReportReconciler) collectClusterFindings(ctx context.Context, log logr.Logger) ([]ClusterFinding, error) {
	// TODO: Integrate with Kubescape and kube-bench
	// For now, return placeholder findings
	log.Info("Would run cluster security scan with Kubescape/kube-bench")

	return []ClusterFinding{
		{
			Framework:   "NSA",
			Control:     "Containers should not run as root",
			Severity:    "HIGH",
			Description: "Running containers as root increases attack surface",
			Remediation: "Set securityContext.runAsNonRoot: true in pod spec",
		},
		{
			Framework:   "CIS",
			Control:     "Ensure network policies are defined",
			Severity:    "MEDIUM",
			Description: "Network policies provide network segmentation",
			Remediation: "Create NetworkPolicy resources for each namespace",
		},
	}, nil
}

// generateRecommendations creates actionable recommendations
func (r *SecurityReportReconciler) generateRecommendations(data *ReportData) []Recommendation {
	var recommendations []Recommendation

	if data.CriticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "Critical",
			Title:       "Address Critical Vulnerabilities Immediately",
			Description: fmt.Sprintf("Found %d critical vulnerabilities that require immediate attention", data.CriticalCount),
			Impact:      "Critical vulnerabilities can lead to full system compromise",
			Effort:      "Medium - requires updating dependencies and redeploying",
		})
	}

	if data.HighCount > 5 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "High",
			Title:       "Enable Automatic Patching",
			Description: "Consider enabling auto-patching for high severity vulnerabilities",
			Impact:      "Reduces time-to-remediation for security issues",
			Effort:      "Low - configuration change",
		})
	}

	// Add standard recommendations
	recommendations = append(recommendations, Recommendation{
		Priority:    "Medium",
		Title:       "Implement Regular Scanning Schedule",
		Description: "Ensure all applications have vulnerability scanning enabled with appropriate schedules",
		Impact:      "Maintains visibility into security posture",
		Effort:      "Low",
	})

	return recommendations
}

// calculateComplianceScore computes an overall compliance score
func (r *SecurityReportReconciler) calculateComplianceScore(data *ReportData) int32 {
	// Simple weighted scoring
	// Start at 100 and deduct points for vulnerabilities
	score := int32(100)

	score -= data.CriticalCount * 10
	score -= data.HighCount * 5
	score -= data.MediumCount * 2
	score -= data.LowCount * 1

	if score < 0 {
		score = 0
	}

	return score
}

// generateReport generates a report in the specified format
func (r *SecurityReportReconciler) generateReport(ctx context.Context, report *agentv1alpha1.SecurityReport, data *ReportData, format string, log logr.Logger) error {
	log.Info("Generating report", "format", format)

	switch format {
	case "HTML":
		return r.generateHTMLReport(data)
	case "JSON":
		return r.generateJSONReport(data)
	case "SARIF":
		return r.generateSARIFReport(data)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// generateHTMLReport generates an HTML report
func (r *SecurityReportReconciler) generateHTMLReport(data *ReportData) error {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {{.GeneratedAt.Format "2006-01-02"}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #4a90d9; color: white; }
    </style>
</head>
<body>
    <h1>Security Report</h1>
    <p>Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>

    <div class="summary">
        <h2>Summary</h2>
        <p>Compliance Score: <strong>{{.ComplianceScore}}%</strong></p>
        <p>Total Vulnerabilities: {{.TotalVulnerabilities}}</p>
        <ul>
            <li class="critical">Critical: {{.CriticalCount}}</li>
            <li class="high">High: {{.HighCount}}</li>
            <li class="medium">Medium: {{.MediumCount}}</li>
            <li class="low">Low: {{.LowCount}}</li>
        </ul>
    </div>

    <h2>Applications</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Namespace</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
        {{range .Applications}}
        <tr>
            <td>{{.Name}}</td>
            <td>{{.Namespace}}</td>
            <td class="critical">{{index .Vulnerabilities "CRITICAL"}}</td>
            <td class="high">{{index .Vulnerabilities "HIGH"}}</td>
            <td class="medium">{{index .Vulnerabilities "MEDIUM"}}</td>
            <td class="low">{{index .Vulnerabilities "LOW"}}</td>
        </tr>
        {{end}}
    </table>

    <h2>Recommendations</h2>
    {{range .Recommendations}}
    <div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 4px;">
        <strong>[{{.Priority}}] {{.Title}}</strong>
        <p>{{.Description}}</p>
        <p><em>Impact:</em> {{.Impact}}</p>
        <p><em>Effort:</em> {{.Effort}}</p>
    </div>
    {{end}}
</body>
</html>
`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return err
	}

	// TODO: Store the report (S3, ConfigMap, etc.)
	_ = buf.String()

	return nil
}

// generateJSONReport generates a JSON report
func (r *SecurityReportReconciler) generateJSONReport(data *ReportData) error {
	// TODO: Implement JSON report generation
	return nil
}

// generateSARIFReport generates a SARIF format report for integration with security tools
func (r *SecurityReportReconciler) generateSARIFReport(data *ReportData) error {
	// TODO: Implement SARIF report generation
	return nil
}

// deliverReport sends the report to configured destinations
func (r *SecurityReportReconciler) deliverReport(ctx context.Context, report *agentv1alpha1.SecurityReport, data *ReportData, log logr.Logger) error {
	delivery := report.Spec.Delivery

	if delivery.Slack != "" {
		if err := r.sendSlackNotification(ctx, delivery.Slack, data); err != nil {
			log.Error(err, "Failed to send Slack notification")
		}
	}

	if len(delivery.Email) > 0 {
		if err := r.sendEmailNotification(ctx, delivery.Email, data); err != nil {
			log.Error(err, "Failed to send email notification")
		}
	}

	if delivery.Webhook != "" {
		if err := r.sendWebhookNotification(ctx, delivery.Webhook, data); err != nil {
			log.Error(err, "Failed to send webhook notification")
		}
	}

	return nil
}

// sendSlackNotification sends a Slack notification
func (r *SecurityReportReconciler) sendSlackNotification(ctx context.Context, channel string, data *ReportData) error {
	// TODO: Implement Slack webhook integration
	return nil
}

// sendEmailNotification sends an email notification
func (r *SecurityReportReconciler) sendEmailNotification(ctx context.Context, recipients []string, data *ReportData) error {
	// TODO: Implement email sending
	return nil
}

// sendWebhookNotification sends a webhook notification
func (r *SecurityReportReconciler) sendWebhookNotification(ctx context.Context, url string, data *ReportData) error {
	// TODO: Implement webhook notification
	return nil
}

// SetupWithManager sets up the controller with the Manager
func (r *SecurityReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("SecurityReport")

	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.SecurityReport{}).
		Complete(r)
}
