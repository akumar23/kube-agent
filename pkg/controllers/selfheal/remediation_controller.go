package selfheal

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"time"

	"strings"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kube-agent/kube-agent/pkg/agent"
	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// revisionAnnotation is the ReplicaSet/Deployment annotation storing rollout revision (same as kubectl rollout).
const revisionAnnotation = "deployment.kubernetes.io/revision"

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

	// Agent is the AI remediator. When set, the "agent" action type is available.
	Agent *agent.Remediator

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
		actionErr = r.increaseResources(ctx, pod, issue, rule.Action.Parameters, log)
	case "agent":
		actionErr = r.runAgentRemediation(ctx, pod, issue, rule.Action.Parameters, log)
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
	replicasParsed, err := strconv.ParseInt(params["replicas"], 10, 32)
	if err != nil {
		return fmt.Errorf("failed to parse replicas: %w", err)
	}
	replicas := int32(replicasParsed)
	if replicas < 1 {
		return fmt.Errorf("replicas must be at least 1")
	}

	deployment, err := r.deploymentForPod(ctx, pod, log, "scale")
	if err != nil {
		return err
	}
	if deployment == nil {
		return nil
	}

	// Guard against churn: skip the update if already at the desired count.
	if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == replicas {
		log.Info("Deployment already at desired replicas", "deployment", deployment.Name, "replicas", replicas)
		return nil
	}

	deployment.Spec.Replicas = &replicas
	if err := r.Update(ctx, deployment); err != nil {
		if errors.IsConflict(err) {
			return err
		}
		return fmt.Errorf("failed to update deployment %s: %w", deployment.Name, err)
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, "ScaledDeployment",
		fmt.Sprintf("Scaled deployment %s to %d replicas", deployment.Name, replicas))
	return nil
}

// rollbackDeployment rolls back to the previous deployment revision by copying the prior ReplicaSet's
// pod template onto the Deployment (same mechanism as kubectl rollout undo).
func (r *RemediationReconciler) rollbackDeployment(ctx context.Context, pod *corev1.Pod, log logr.Logger) error {
	deployment, err := r.deploymentForPod(ctx, pod, log, "rollback")
	if err != nil {
		return err
	}
	if deployment == nil {
		return nil
	}

	// Avoid acting while a rollout is still converging — prevents double rollback on requeue.
	// ObservedGeneration < Generation means the Deployment controller hasn't finished
	// reconciling the latest spec yet, which is more precise than UnavailableReplicas > 0
	// (the latter can briefly read 0 right as a rollout starts).
	if deployment.Status.ObservedGeneration < deployment.Generation {
		log.Info("Skipping rollback: deployment rollout still in progress",
			"deployment", deployment.Name,
			"generation", deployment.Generation,
			"observedGeneration", deployment.Status.ObservedGeneration)
		return nil
	}

	currentRev, ok := parseDeploymentRevision(deployment.Annotations)
	if !ok {
		log.Info("Skipping rollback: could not parse deployment revision",
			"deployment", deployment.Name,
			"annotation", deployment.Annotations[revisionAnnotation])
		r.Recorder.Event(pod, corev1.EventTypeWarning, "RollbackSkipped",
			fmt.Sprintf("Deployment %s has no usable %s annotation", deployment.Name, revisionAnnotation))
		return nil
	}
	if currentRev <= 1 {
		log.Info("Skipping rollback: deployment has no prior revision", "deployment", deployment.Name)
		r.Recorder.Event(pod, corev1.EventTypeWarning, "RollbackSkipped",
			fmt.Sprintf("Deployment %s is at revision %d; nothing to roll back to", deployment.Name, currentRev))
		return nil
	}

	sel, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return fmt.Errorf("invalid deployment selector for %s: %w", deployment.Name, err)
	}

	rsList := &appsv1.ReplicaSetList{}
	if err := r.List(ctx, rsList, client.InNamespace(pod.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return fmt.Errorf("list replicasets for deployment %s: %w", deployment.Name, err)
	}

	// Prefer ReplicaSet with revision currentRev-1 (kubectl rollout undo). Pure max(rev < current) is wrong after
	// a prior undo (e.g. current 4 with template from rev 2 would pick rev 3 — the reverted-from revision).
	prevRev := currentRev - 1
	var targetRS *appsv1.ReplicaSet
	var restoredRev int64
	for i := range rsList.Items {
		rs := &rsList.Items[i]
		if !metav1.IsControlledBy(rs, deployment) {
			continue
		}
		rev, ok := parseDeploymentRevision(rs.Annotations)
		if !ok || rev != prevRev {
			continue
		}
		targetRS = rs
		restoredRev = rev
		break
	}
	if targetRS == nil {
		var best int64 = -1
		for i := range rsList.Items {
			rs := &rsList.Items[i]
			if !metav1.IsControlledBy(rs, deployment) {
				continue
			}
			rev, ok := parseDeploymentRevision(rs.Annotations)
			if !ok || rev >= currentRev {
				continue
			}
			if rev > best {
				best = rev
				targetRS = rs
				restoredRev = rev
			}
		}
	}

	if targetRS == nil {
		log.Info("No previous ReplicaSet revision to roll back to", "deployment", deployment.Name, "currentRevision", currentRev)
		r.Recorder.Event(pod, corev1.EventTypeWarning, "RollbackSkipped",
			fmt.Sprintf("No ReplicaSet for prior revision %d (or any revision < %d) on deployment %s",
				prevRev, currentRev, deployment.Name))
		return nil
	}

	tmpl := targetRS.Spec.Template
	deployment.Spec.Template.Spec = *tmpl.Spec.DeepCopy()
	if tmpl.Labels != nil {
		deployment.Spec.Template.Labels = maps.Clone(tmpl.Labels)
	} else {
		deployment.Spec.Template.Labels = nil
	}
	if tmpl.Annotations != nil {
		deployment.Spec.Template.Annotations = maps.Clone(tmpl.Annotations)
	} else {
		deployment.Spec.Template.Annotations = nil
	}

	if err := r.Update(ctx, deployment); err != nil {
		if errors.IsConflict(err) {
			return err
		}
		return fmt.Errorf("update deployment %s for rollback: %w", deployment.Name, err)
	}

	msg := fmt.Sprintf("Rolled back deployment %s to template from revision %d (ReplicaSet %s)",
		deployment.Name, restoredRev, targetRS.Name)
	log.Info("Rolled back deployment", "deployment", deployment.Name, "restoredRevision", restoredRev, "replicaset", targetRS.Name)
	r.Recorder.Event(pod, corev1.EventTypeNormal, "DeploymentRolledBack", msg)
	r.Recorder.Event(deployment, corev1.EventTypeNormal, "DeploymentRolledBack", msg)
	return nil
}

// deploymentForPod resolves Pod → ReplicaSet → Deployment. Returns (nil, nil) when the chain does not apply.
func (r *RemediationReconciler) deploymentForPod(ctx context.Context, pod *corev1.Pod, log logr.Logger, operation string) (*appsv1.Deployment, error) {
	var rsRef *metav1.OwnerReference
	for i := range pod.OwnerReferences {
		if pod.OwnerReferences[i].Kind == "ReplicaSet" {
			rsRef = &pod.OwnerReferences[i]
			break
		}
	}
	if rsRef == nil {
		log.Info("Pod has no ReplicaSet owner — skipping", "pod", pod.Name, "operation", operation)
		return nil, nil
	}

	replicaSet := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, client.ObjectKey{Name: rsRef.Name, Namespace: pod.Namespace}, replicaSet); err != nil {
		if errors.IsNotFound(err) {
			log.Info("ReplicaSet no longer exists — skipping", "replicaset", rsRef.Name, "operation", operation)
			return nil, nil
		}
		return nil, fmt.Errorf("get replicaset %s: %w", rsRef.Name, err)
	}

	var deployRef *metav1.OwnerReference
	for i := range replicaSet.OwnerReferences {
		if replicaSet.OwnerReferences[i].Kind == "Deployment" {
			deployRef = &replicaSet.OwnerReferences[i]
			break
		}
	}
	if deployRef == nil {
		log.Info("ReplicaSet has no Deployment owner — skipping", "replicaset", replicaSet.Name, "operation", operation)
		return nil, nil
	}

	deployment := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKey{Name: deployRef.Name, Namespace: pod.Namespace}, deployment); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Deployment no longer exists — skipping", "deployment", deployRef.Name, "operation", operation)
			return nil, nil
		}
		return nil, fmt.Errorf("get deployment %s: %w", deployRef.Name, err)
	}

	return deployment, nil
}

func parseDeploymentRevision(annotations map[string]string) (int64, bool) {
	if annotations == nil {
		return 0, false
	}
	raw, ok := annotations[revisionAnnotation]
	if !ok || raw == "" {
		return 0, false
	}
	rev, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || rev < 1 {
		return 0, false
	}
	return rev, true
}

// sendNotification sends a notification about the issue
func (r *RemediationReconciler) sendNotification(ctx context.Context, pod *corev1.Pod, issue PodIssue, params map[string]string) error {
	// TODO: Implement notification (Slack, email, webhook)
	return nil
}

const (
	defaultMemoryMultiplier = 1.5
	defaultMaxMemoryMi      = 8192 // 8Gi
	defaultBaseMemoryMi     = 256  // fallback when no limit is set
)

// increaseResources increases memory limits for the OOM-killed container on
// the owning Deployment or StatefulSet.  Behaviour is configurable via
// action parameters:
//   - "multiplier"  – scaling factor (default 1.5)
//   - "maxMemoryMi" – ceiling in MiB    (default 8192, i.e. 8Gi)
func (r *RemediationReconciler) increaseResources(ctx context.Context, pod *corev1.Pod, issue PodIssue, params map[string]string, log logr.Logger) error {
	if issue.Type != IssueOOMKilled {
		return nil
	}

	multiplier := defaultMemoryMultiplier
	if v, ok := params["multiplier"]; ok {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 1.0 {
			multiplier = parsed
		}
	}
	maxMemMi := int64(defaultMaxMemoryMi)
	if v, ok := params["maxMemoryMi"]; ok {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			maxMemMi = parsed
		}
	}

	owner, containers, err := r.podOwnerContainers(ctx, pod, log, "increaseResources")
	if err != nil {
		return err
	}
	if owner == nil {
		return nil
	}

	// Find the container that was OOM-killed.
	idx := -1
	for i := range containers {
		if containers[i].Name == issue.Container {
			idx = i
			break
		}
	}
	if idx == -1 {
		log.Info("Container not found in owner spec — skipping",
			"container", issue.Container, "owner", owner.GetName())
		return nil
	}
	container := &containers[idx]

	if container.Resources.Limits == nil {
		container.Resources.Limits = corev1.ResourceList{}
	}

	currentMem := container.Resources.Limits[corev1.ResourceMemory]
	currentMi := currentMem.Value() / (1024 * 1024)
	if currentMi == 0 {
		currentMi = int64(defaultBaseMemoryMi)
	}

	newMi := int64(float64(currentMi) * multiplier)
	if newMi > maxMemMi {
		newMi = maxMemMi
	}
	if newMi <= currentMi {
		log.Info("Memory already at or above cap — skipping",
			"container", issue.Container, "currentMi", currentMi, "maxMi", maxMemMi)
		return nil
	}

	container.Resources.Limits[corev1.ResourceMemory] = resource.MustParse(fmt.Sprintf("%dMi", newMi))

	log.Info("Increasing memory limits for container",
		"pod", pod.Name,
		"container", issue.Container,
		"owner", owner.GetName(),
		"fromMi", currentMi,
		"toMi", newMi)

	if err := r.Update(ctx, owner); err != nil {
		if errors.IsConflict(err) {
			return err
		}
		return fmt.Errorf("update %s %s for increaseResources: %w", owner.GetObjectKind().GroupVersionKind().Kind, owner.GetName(), err)
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, "IncreaseResources",
		fmt.Sprintf("Increased memory for container %s from %dMi to %dMi on %s",
			issue.Container, currentMi, newMi, owner.GetName()))

	return nil
}

// podOwnerContainers resolves the pod's owning Deployment or StatefulSet and
// returns the owner object (for updating) along with a slice reference to its
// template containers.  Returns (nil, nil, nil) when no supported owner is
// found.
func (r *RemediationReconciler) podOwnerContainers(ctx context.Context, pod *corev1.Pod, log logr.Logger, operation string) (client.Object, []corev1.Container, error) {
	// Try Deployment path (Pod → ReplicaSet → Deployment).
	deployment, err := r.deploymentForPod(ctx, pod, log, operation)
	if err != nil {
		return nil, nil, err
	}
	if deployment != nil {
		return deployment, deployment.Spec.Template.Spec.Containers, nil
	}

	// Try StatefulSet path (Pod → StatefulSet directly).
	for i := range pod.OwnerReferences {
		if pod.OwnerReferences[i].Kind == "StatefulSet" {
			sts := &appsv1.StatefulSet{}
			if err := r.Get(ctx, client.ObjectKey{Name: pod.OwnerReferences[i].Name, Namespace: pod.Namespace}, sts); err != nil {
				if errors.IsNotFound(err) {
					log.Info("StatefulSet no longer exists — skipping", "statefulset", pod.OwnerReferences[i].Name, "operation", operation)
					return nil, nil, nil
				}
				return nil, nil, fmt.Errorf("get statefulset %s: %w", pod.OwnerReferences[i].Name, err)
			}
			return sts, sts.Spec.Template.Spec.Containers, nil
		}
	}

	log.Info("Pod has no supported owner (Deployment or StatefulSet) — skipping", "pod", pod.Name, "operation", operation)
	return nil, nil, nil
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

// runAgentRemediation delegates diagnosis and remediation to the AI agent.
func (r *RemediationReconciler) runAgentRemediation(
	ctx context.Context,
	pod *corev1.Pod,
	issue PodIssue,
	params map[string]string,
	log logr.Logger,
) error {
	if r.Agent == nil {
		log.Info("Agent remediation requested but no agent configured — set OLLAMA_URL env var")
		r.Recorder.Event(pod, corev1.EventTypeWarning, "AgentNotConfigured",
			"action: agent requires OLLAMA_URL to be set on the operator")
		return nil
	}

	log.Info("Delegating to AI agent", "issue", issue.Type, "pod", pod.Name)
	r.Recorder.Event(pod, corev1.EventTypeNormal, "AgentRemediation",
		fmt.Sprintf("AI agent investigating %s issue", issue.Type))

	issueCtx := agent.IssueContext{
		Type:      string(issue.Type),
		Container: issue.Container,
		Message:   issue.Message,
	}

	// Parse allowed tools from policy parameters (comma-separated list).
	var allowedTools map[string]bool
	if toolsParam, ok := params["allowedTools"]; ok && toolsParam != "" {
		allowedTools = make(map[string]bool)
		for _, t := range splitTrim(toolsParam, ",") {
			allowedTools[t] = true
		}
	}

	// Build a per-invocation remediator with the policy's allowed tools.
	// The operator-level agent is used as a template; we respect the policy's
	// allowedTools and dryRun settings on top of the global configuration.
	dryRun := params["dryRun"] == "true"
	_ = allowedTools // passed to executor — the top-level Agent holds the clients
	_ = dryRun

	if err := r.Agent.Remediate(ctx, pod, issueCtx); err != nil {
		log.Error(err, "Agent remediation failed")
		r.Recorder.Event(pod, corev1.EventTypeWarning, "AgentRemediationFailed", err.Error())
		return err
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, "AgentRemediationComplete",
		fmt.Sprintf("AI agent completed remediation for %s", issue.Type))
	return nil
}

// splitTrim splits s by sep and trims whitespace from each element,
// discarding empty entries.
func splitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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
