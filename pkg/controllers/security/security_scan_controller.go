package security

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
	"github.com/kube-agent/kube-agent/pkg/types"
)

// Scanner interface for vulnerability scanning
type Scanner interface {
	Scan(ctx context.Context, image string) (*types.ScanResult, error)
}

// SecurityScanReconciler reconciles security scans for ManagedApplications
type SecurityScanReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	Recorder    record.EventRecorder
	Log         logr.Logger
	VulnScanner Scanner
}

// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for security scanning
func (r *SecurityScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("securityscan", req.NamespacedName)

	// Fetch the ManagedApplication
	app := &agentv1alpha1.ManagedApplication{}
	if err := r.Get(ctx, req.NamespacedName, app); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if security scanning is enabled
	if app.Spec.Security.VulnerabilityScanning == nil || !app.Spec.Security.VulnerabilityScanning.Enabled {
		if metav1.HasAnnotation(app.ObjectMeta, agentv1alpha1.AnnotationScanRequestedAt) {
			if err := r.removeScanRequestAnnotation(ctx, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}
			r.Recorder.Event(app, corev1.EventTypeWarning, "ScanRejected",
				"Vulnerability scanning is disabled; cleared scan request annotation")
		}
		return ctrl.Result{}, nil
	}

	scanRequested := metav1.HasAnnotation(app.ObjectMeta, agentv1alpha1.AnnotationScanRequestedAt)
	scanConfig := app.Spec.Security.VulnerabilityScanning
	if !scanRequested && !r.shouldScan(app, scanConfig) {
		nextScan := nextScheduleTime(scanConfig.Schedule, 6*time.Hour)
		return ctrl.Result{RequeueAfter: time.Until(nextScan)}, nil
	}

	log.Info("Starting vulnerability scan", "app", app.Name, "scanRequested", scanRequested)
	r.Recorder.Event(app, corev1.EventTypeNormal, "ScanStarted", "Starting vulnerability scan")

	// Get container images from the application
	images, err := r.getApplicationImages(ctx, app)
	if err != nil {
		log.Error(err, "Failed to get application images")
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Scan each image
	totalVulns := make(map[string]int32)
	var criticalVulns []types.VulnerabilityInfo

	for _, image := range images {
		result, err := r.scanImage(ctx, image, log)
		if err != nil {
			log.Error(err, "Failed to scan image", "image", image)
			continue
		}

		// Aggregate results
		for severity, count := range result.Counts {
			totalVulns[severity] += count
		}

		// Collect critical/high vulnerabilities for reporting
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == string(agentv1alpha1.SeverityLevelCritical) ||
				vuln.Severity == string(agentv1alpha1.SeverityLevelHigh) {
				criticalVulns = append(criticalVulns, vuln)
			}
		}
	}

	// Update application status
	app.Status.VulnerabilityCount = totalVulns
	app.Status.LastScannedAt = &metav1.Time{Time: time.Now()}

	// Check if we should block/degrade based on severity threshold
	shouldBlock := r.shouldBlockDeployment(totalVulns, scanConfig)
	if shouldBlock && scanConfig.AutoBlock {
		app.Status.Phase = agentv1alpha1.ApplicationPhaseDegraded
		app.Status.Message = fmt.Sprintf("Application has %d critical and %d high severity vulnerabilities",
			totalVulns["CRITICAL"], totalVulns["HIGH"])
		r.Recorder.Event(app, corev1.EventTypeWarning, "VulnerabilitiesFound",
			app.Status.Message)
	}

	if err := r.Status().Update(ctx, app); err != nil {
		log.Error(err, "Failed to update application status")
		return ctrl.Result{}, err
	}

	if scanRequested {
		if err := r.removeScanRequestAnnotation(ctx, req.NamespacedName); err != nil {
			log.Error(err, "Failed to clear scan request annotation")
			return ctrl.Result{}, err
		}
	}

	// Handle auto-patching if enabled
	if scanConfig.AutoPatch && len(criticalVulns) > 0 {
		r.handleAutoPatch(ctx, app, criticalVulns, log)
	}

	log.Info("Vulnerability scan completed",
		"critical", totalVulns["CRITICAL"],
		"high", totalVulns["HIGH"],
		"medium", totalVulns["MEDIUM"],
		"low", totalVulns["LOW"])

	// Schedule next scan based on the configured cron expression
	nextScan := nextScheduleTime(scanConfig.Schedule, 6*time.Hour)
	return ctrl.Result{RequeueAfter: time.Until(nextScan)}, nil
}

// removeScanRequestAnnotation deletes AnnotationScanRequestedAt from the ManagedApplication.
func (r *SecurityScanReconciler) removeScanRequestAnnotation(ctx context.Context, key k8stypes.NamespacedName) error {
	latest := &agentv1alpha1.ManagedApplication{}
	if err := r.Get(ctx, key, latest); err != nil {
		return err
	}
	if latest.Annotations == nil {
		return nil
	}
	if _, ok := latest.Annotations[agentv1alpha1.AnnotationScanRequestedAt]; !ok {
		return nil
	}
	patchBase := client.MergeFrom(latest.DeepCopy())
	delete(latest.Annotations, agentv1alpha1.AnnotationScanRequestedAt)
	if len(latest.Annotations) == 0 {
		latest.Annotations = nil
	}
	return r.Patch(ctx, latest, patchBase)
}

// shouldScan determines if a scan should be performed now based on the cron schedule.
func (r *SecurityScanReconciler) shouldScan(app *agentv1alpha1.ManagedApplication, config *agentv1alpha1.VulnerabilityScanSpec) bool {
	return shouldRunNow(config.Schedule, app.Status.LastScannedAt, 6*time.Hour)
}

// getApplicationImages gets container images from the application
func (r *SecurityScanReconciler) getApplicationImages(ctx context.Context, app *agentv1alpha1.ManagedApplication) ([]string, error) {
	var images []string

	// For Docker source type, use the specified image
	if app.Spec.Source.Type == agentv1alpha1.SourceTypeDocker && app.Spec.Source.Image != "" {
		images = append(images, app.Spec.Source.Image)
		return images, nil
	}

	// For other source types, query pods with our label
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.MatchingLabels{
		"agent.kubeagent.io/app": app.Name,
	}); err != nil {
		return nil, err
	}

	imageSet := make(map[string]bool)
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			imageSet[container.Image] = true
		}
		for _, container := range pod.Spec.InitContainers {
			imageSet[container.Image] = true
		}
	}

	for image := range imageSet {
		images = append(images, image)
	}

	return images, nil
}

// scanImage scans a container image for vulnerabilities
func (r *SecurityScanReconciler) scanImage(ctx context.Context, image string, log logr.Logger) (*types.ScanResult, error) {
	log.Info("Scanning image", "image", image)

	// Use scanner if available
	if r.VulnScanner != nil {
		return r.VulnScanner.Scan(ctx, image)
	}

	// Fallback: Return empty result (in production, this would fail)
	log.Info("Vulnerability scanner not configured, skipping actual scan")
	return &types.ScanResult{
		Image:  image,
		Counts: make(map[string]int32),
	}, nil
}

// shouldBlockDeployment determines if deployment should be blocked
func (r *SecurityScanReconciler) shouldBlockDeployment(vulns map[string]int32, config *agentv1alpha1.VulnerabilityScanSpec) bool {
	threshold := config.SeverityThreshold

	switch threshold {
	case agentv1alpha1.SeverityLevelCritical:
		return vulns["CRITICAL"] > 0
	case agentv1alpha1.SeverityLevelHigh:
		return vulns["CRITICAL"] > 0 || vulns["HIGH"] > 0
	case agentv1alpha1.SeverityLevelMedium:
		return vulns["CRITICAL"] > 0 || vulns["HIGH"] > 0 || vulns["MEDIUM"] > 0
	case agentv1alpha1.SeverityLevelLow:
		return vulns["CRITICAL"] > 0 || vulns["HIGH"] > 0 || vulns["MEDIUM"] > 0 || vulns["LOW"] > 0
	}

	return false
}

// handleAutoPatch initiates automatic patching for vulnerabilities
func (r *SecurityScanReconciler) handleAutoPatch(ctx context.Context, app *agentv1alpha1.ManagedApplication, vulns []types.VulnerabilityInfo, log logr.Logger) {
	log.Info("Auto-patch triggered", "vulnerabilities", len(vulns))

	// Group vulnerabilities by package with available fixes
	patchable := make(map[string]string) // package -> fixed version
	for _, vuln := range vulns {
		if vuln.FixedVersion != "" {
			patchable[vuln.Package] = vuln.FixedVersion
		}
	}

	if len(patchable) == 0 {
		log.Info("No patchable vulnerabilities found")
		return
	}

	r.Recorder.Event(app, corev1.EventTypeNormal, "AutoPatchInitiated",
		fmt.Sprintf("Initiating auto-patch for %d packages", len(patchable)))

	// TODO: Implement actual patching logic:
	// 1. Create a new branch in the git repo
	// 2. Update dependency versions
	// 3. Run tests in a staging environment
	// 4. If tests pass, create PR for review or auto-merge based on policy
	// 5. Trigger canary deployment to validate

	for pkg, version := range patchable {
		log.Info("Would patch package", "package", pkg, "to_version", version)
	}
}

// SetupWithManager sets up the controller with the Manager
func (r *SecurityScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("SecurityScan")

	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.ManagedApplication{}).
		Complete(r)
}

// cronParser is a standard 5-field cron parser (minute hour dom month dow).
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// nextScheduleTime returns the next time the given cron schedule should fire.
// Falls back to now+fallback on parse errors, logging is handled by the caller.
func nextScheduleTime(schedule string, fallback time.Duration) time.Time {
	sched, err := cronParser.Parse(schedule)
	if err != nil {
		return time.Now().Add(fallback)
	}
	return sched.Next(time.Now())
}

// shouldRunNow returns true if the cron schedule indicates it is time to run
// given the last run time. Uses fallback interval when the schedule is unparsable.
func shouldRunNow(schedule string, lastRun *metav1.Time, fallback time.Duration) bool {
	if lastRun == nil {
		return true
	}
	sched, err := cronParser.Parse(schedule)
	if err != nil {
		return time.Since(lastRun.Time) >= fallback
	}
	// The next run time after the last run; if that moment has passed, run now.
	return time.Now().After(sched.Next(lastRun.Time))
}
