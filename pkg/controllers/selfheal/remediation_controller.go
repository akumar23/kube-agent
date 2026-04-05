package selfheal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// PodIssueType represents types of pod issues we can detect and remediate
type PodIssueType string

const (
	IssueCrashLoopBackOff  PodIssueType = "CrashLoopBackOff"
	IssueOOMKilled         PodIssueType = "OOMKilled"
	IssueImagePullBackOff  PodIssueType = "ImagePullBackOff"
	IssuePending           PodIssueType = "Pending"
	IssueUnschedulable     PodIssueType = "Unschedulable"
	IssueReadinessFailure  PodIssueType = "ReadinessFailure"
	IssueLivenessFailure   PodIssueType = "LivenessFailure"
	IssueHighResourceUsage PodIssueType = "HighResourceUsage"
)

// RemediationReconciler reconciles pod issues and applies remediation
type RemediationReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Log      logr.Logger

	// Rate limiting - all fields protected by mu
	mu            sync.Mutex
	actionCounts  map[string]int
	lastResetTime time.Time
}

// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=remediationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=remediationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch

// Reconcile watches for pod issues and applies remediation policies
func (r *RemediationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("pod", req.NamespacedName)

	// Reset rate limit counters if an hour has elapsed
	r.resetRateLimitIfNeeded()

	// Fetch the pod
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Detect issues
	issues := r.detectPodIssues(pod)
	if len(issues) == 0 {
		// Pod is healthy - no need to requeue healthy pods aggressively
		return ctrl.Result{}, nil
	}

	log.Info("Detected pod issues", "issues", issues)

	// Get applicable remediation policies
	policies := &agentv1alpha1.RemediationPolicyList{}
	if err := r.List(ctx, policies); err != nil {
		log.Error(err, "Failed to list remediation policies")
		return ctrl.Result{}, err
	}

	// Apply matching remediation actions
	for _, issue := range issues {
		for _, policy := range policies.Items {
			if !policy.Spec.Enabled {
				continue
			}

			// Check if policy matches this pod
			if !r.policyMatchesPod(&policy, pod) {
				continue
			}

			// Find matching rule
			for _, rule := range policy.Spec.Rules {
				if r.ruleMatchesIssue(rule, issue) {
					if err := r.applyRemediation(ctx, pod, &policy, rule, issue, log); err != nil {
						log.Error(err, "Failed to apply remediation", "rule", rule.Name)
					}
				}
			}
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// PodIssue represents a detected pod issue
type PodIssue struct {
	Type        PodIssueType
	Container   string
	Message     string
	Count       int32
	FirstSeen   time.Time
	LastSeen    time.Time
	Suggestions []string
}

// detectPodIssues analyzes a pod and returns detected issues
func (r *RemediationReconciler) detectPodIssues(pod *corev1.Pod) []PodIssue {
	var issues []PodIssue

	// Check container statuses
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			switch cs.State.Waiting.Reason {
			case "CrashLoopBackOff":
				issues = append(issues, PodIssue{
					Type:      IssueCrashLoopBackOff,
					Container: cs.Name,
					Message:   cs.State.Waiting.Message,
					Count:     cs.RestartCount,
					Suggestions: []string{
						"Check application logs for errors",
						"Verify startup command and arguments",
						"Check for missing environment variables or config",
						"Review resource limits - may need more memory",
					},
				})
			case "ImagePullBackOff", "ErrImagePull":
				issues = append(issues, PodIssue{
					Type:      IssueImagePullBackOff,
					Container: cs.Name,
					Message:   cs.State.Waiting.Message,
					Suggestions: []string{
						"Verify image name and tag exist",
						"Check registry credentials (ImagePullSecret)",
						"Ensure registry is accessible from cluster",
					},
				})
			}
		}

		// Check for OOMKilled in last terminated state
		if cs.LastTerminationState.Terminated != nil {
			if cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
				issues = append(issues, PodIssue{
					Type:      IssueOOMKilled,
					Container: cs.Name,
					Message:   "Container was killed due to Out of Memory",
					Count:     cs.RestartCount,
					Suggestions: []string{
						"Increase memory limits for the container",
						"Check for memory leaks in the application",
						"Review application memory usage patterns",
					},
				})
			}
		}
	}

	// Check pod conditions
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
			if cond.Reason == "Unschedulable" {
				issues = append(issues, PodIssue{
					Type:    IssueUnschedulable,
					Message: cond.Message,
					Suggestions: []string{
						"Check node resources - may need to scale cluster",
						"Review node selectors and affinity rules",
						"Check for taints that may be blocking scheduling",
					},
				})
			}
		}

		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionFalse {
			issues = append(issues, PodIssue{
				Type:    IssueReadinessFailure,
				Message: cond.Message,
				Suggestions: []string{
					"Check readiness probe configuration",
					"Verify the application is listening on the correct port",
					"Review application startup time - may need longer initialDelaySeconds",
				},
			})
		}
	}

	// Check if pod is pending for too long
	if pod.Status.Phase == corev1.PodPending {
		creationTime := pod.CreationTimestamp.Time
		if time.Since(creationTime) > 5*time.Minute {
			issues = append(issues, PodIssue{
				Type:      IssuePending,
				Message:   fmt.Sprintf("Pod has been pending for %v", time.Since(creationTime)),
				FirstSeen: creationTime,
				Suggestions: []string{
					"Check for resource constraints",
					"Review pending events for more details",
					"Verify PersistentVolumeClaims are bound",
				},
			})
		}
	}

	return issues
}

// policyMatchesPod checks if a policy applies to a pod
func (r *RemediationReconciler) policyMatchesPod(policy *agentv1alpha1.RemediationPolicy, pod *corev1.Pod) bool {
	if policy.Spec.Selector == nil {
		return true // No selector means match all
	}

	// Check namespace selector
	if len(policy.Spec.Selector.Namespaces) > 0 {
		found := false
		for _, ns := range policy.Spec.Selector.Namespaces {
			if ns == pod.Namespace {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check label selector
	if policy.Spec.Selector.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(policy.Spec.Selector.LabelSelector)
		if err != nil {
			return false
		}
		if !selector.Matches(labels.Set(pod.Labels)) {
			return false
		}
	}

	return true
}

// ruleMatchesIssue checks if a rule applies to an issue
func (r *RemediationReconciler) ruleMatchesIssue(rule agentv1alpha1.RemediationRule, issue PodIssue) bool {
	return rule.Condition.Type == string(issue.Type) &&
		issue.Count >= rule.Condition.Threshold
}

// applyRemediation applies a remediation action
func (r *RemediationReconciler) applyRemediation(ctx context.Context, pod *corev1.Pod, policy *agentv1alpha1.RemediationPolicy, rule agentv1alpha1.RemediationRule, issue PodIssue, log logr.Logger) error {
	// Check safety limits
	if policy.Spec.SafetyLimits != nil {
		r.mu.Lock()
		count := r.actionCounts[policy.Name]
		r.mu.Unlock()

		if count >= int(policy.Spec.SafetyLimits.MaxActionsPerHour) {
			log.Info("Rate limit exceeded for policy", "policy", policy.Name)
			return nil
		}

		if policy.Spec.SafetyLimits.DryRunMode {
			log.Info("Dry-run mode: would apply remediation",
				"action", rule.Action.Type,
				"pod", pod.Name)
			r.Recorder.Event(pod, corev1.EventTypeNormal, "DryRunRemediation",
				fmt.Sprintf("Would apply %s remediation for %s", rule.Action.Type, issue.Type))
			return nil
		}

		if policy.Spec.SafetyLimits.RequireApproval {
			log.Info("Remediation requires approval",
				"action", rule.Action.Type,
				"pod", pod.Name)
			r.Recorder.Event(pod, corev1.EventTypeNormal, "RemediationPending",
				fmt.Sprintf("Remediation %s requires approval", rule.Action.Type))
			return nil
		}
	}

	// useFallback is a destructive, irreversible mutation - require explicit SafetyLimits
	if rule.Action.Type == "useFallback" && policy.Spec.SafetyLimits == nil {
		log.Info("useFallback action requires SafetyLimits to be configured to prevent accidental irreversible mutations")
		r.Recorder.Event(pod, corev1.EventTypeWarning, "RemediationBlocked",
			"useFallback requires SafetyLimits configuration")
		return nil
	}

	log.Info("Applying remediation",
		"action", rule.Action.Type,
		"pod", pod.Name,
		"issue", issue.Type)

	var actionErr error
	switch rule.Action.Type {
	case "restart":
		actionErr = r.restartPod(ctx, pod, log)
	case "scale":
		actionErr = r.scalePodOwner(ctx, pod, rule.Action.Parameters, log)
	case "rollback":
		actionErr = r.rollbackDeployment(ctx, pod, log)
	case "useFallback":
		actionErr = r.useFallbackImage(ctx, pod, log)
	case "notify":
		actionErr = r.sendNotification(ctx, pod, issue, rule.Action.Parameters)
	case "increaseResources":
		actionErr = r.increaseResources(ctx, pod, issue, log)
	default:
		log.Info("Unknown remediation action type", "type", rule.Action.Type)
		return nil
	}

	if actionErr != nil {
		return actionErr
	}

	// Increment rate-limit counter for successfully dispatched actions
	r.mu.Lock()
	r.actionCounts[policy.Name]++
	r.mu.Unlock()

	// Update policy status
	policy.Status.ActionsExecuted++
	policy.Status.LastActionAt = &metav1.Time{Time: time.Now()}
	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update policy status")
	}

	return nil
}

// restartPod deletes a pod to trigger recreation
func (r *RemediationReconciler) restartPod(ctx context.Context, pod *corev1.Pod, log logr.Logger) error {
	log.Info("Restarting pod", "pod", pod.Name, "namespace", pod.Namespace)

	r.Recorder.Event(pod, corev1.EventTypeNormal, "Restarting",
		"Restarting pod due to self-healing policy")

	return r.Delete(ctx, pod)
}

// scalePodOwner scales the deployment/replicaset owning the pod
func (r *RemediationReconciler) scalePodOwner(ctx context.Context, pod *corev1.Pod, params map[string]string, log logr.Logger) error {
	// Find the owner deployment
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			// Get the ReplicaSet to find the Deployment
			// TODO: Implement scaling logic
			log.Info("Would scale deployment", "owner", ref.Name)
		}
	}
	return nil
}

// rollbackDeployment rolls back to the previous deployment revision
func (r *RemediationReconciler) rollbackDeployment(ctx context.Context, pod *corev1.Pod, log logr.Logger) error {
	log.Info("Would rollback deployment for pod", "pod", pod.Name)
	// TODO: Implement rollback using Argo Rollouts or native rollback
	return nil
}

// sendNotification sends a notification about the issue
func (r *RemediationReconciler) sendNotification(ctx context.Context, pod *corev1.Pod, issue PodIssue, params map[string]string) error {
	// TODO: Implement notification (Slack, email, webhook)
	return nil
}

// increaseResources increases resource limits for OOM issues
func (r *RemediationReconciler) increaseResources(ctx context.Context, pod *corev1.Pod, issue PodIssue, log logr.Logger) error {
	if issue.Type != IssueOOMKilled {
		return nil
	}

	log.Info("Would increase memory limits for container",
		"pod", pod.Name,
		"container", issue.Container)

	// TODO: Update deployment to increase memory limits
	// This requires modifying the parent Deployment/StatefulSet

	return nil
}

// useFallbackImage switches the ManagedApplication to use its fallback image
func (r *RemediationReconciler) useFallbackImage(ctx context.Context, pod *corev1.Pod, log logr.Logger) error {
	// Get the app name from the pod label
	appName, ok := pod.Labels["agent.kubeagent.io/app"]
	if !ok {
		return fmt.Errorf("pod does not have agent.kubeagent.io/app label")
	}

	// Find the ManagedApplication
	app := &agentv1alpha1.ManagedApplication{}
	if err := r.Get(ctx, client.ObjectKey{Name: appName, Namespace: pod.Namespace}, app); err != nil {
		return fmt.Errorf("failed to get ManagedApplication: %w", err)
	}

	// Check if fallback image is configured
	if app.Spec.Source.FallbackImage == "" {
		log.Info("No fallback image configured", "app", appName)
		r.Recorder.Event(pod, corev1.EventTypeWarning, "NoFallback",
			"No fallback image configured for self-healing")
		return nil
	}

	// Check if already using fallback
	if app.Spec.Source.Image == app.Spec.Source.FallbackImage {
		log.Info("Already using fallback image", "app", appName, "image", app.Spec.Source.FallbackImage)
		return nil
	}

	originalImage := app.Spec.Source.Image
	log.Info("Switching to fallback image",
		"app", appName,
		"originalImage", originalImage,
		"fallbackImage", app.Spec.Source.FallbackImage)

	// Record original image in annotations so it can be restored
	if app.Annotations == nil {
		app.Annotations = make(map[string]string)
	}
	app.Annotations["agent.kubeagent.io/original-image"] = originalImage
	app.Annotations["agent.kubeagent.io/fallback-activated-at"] = time.Now().UTC().Format(time.RFC3339)

	// Switch to fallback image; preserve Command/Args (they belong to the app, not the image)
	app.Spec.Source.Image = app.Spec.Source.FallbackImage

	if err := r.Update(ctx, app); err != nil {
		return fmt.Errorf("failed to update ManagedApplication with fallback: %w", err)
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, "FallbackActivated",
		fmt.Sprintf("Switched from %s to fallback image %s", originalImage, app.Spec.Source.FallbackImage))

	// Also record event on the ManagedApplication
	r.Recorder.Event(app, corev1.EventTypeWarning, "FallbackActivated",
		fmt.Sprintf("Self-healing activated fallback image due to repeated failures. Original: %s, Fallback: %s",
			originalImage, app.Spec.Source.FallbackImage))

	return nil
}

// resetRateLimitIfNeeded resets rate limit counters hourly
func (r *RemediationReconciler) resetRateLimitIfNeeded() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Since(r.lastResetTime) >= time.Hour {
		r.actionCounts = make(map[string]int)
		r.lastResetTime = time.Now()
	}
}

// SetupWithManager sets up the controller with the Manager
func (r *RemediationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("Remediation")

	r.mu.Lock()
	r.actionCounts = make(map[string]int)
	r.lastResetTime = time.Now()
	r.mu.Unlock()

	// Filter to only watch pods with the kube-agent label, avoiding unnecessary
	// reconciliation of unrelated pods in large clusters.
	agentPodPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		_, ok := obj.GetLabels()["agent.kubeagent.io/app"]
		return ok
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(agentPodPredicate)).
		Complete(r)
}
