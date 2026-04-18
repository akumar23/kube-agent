package diagnostic

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kube-agent/kube-agent/pkg/utils/executor"
)

// DiagnosticReconciler performs diagnostic analysis on failing pods
type DiagnosticReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Log       logr.Logger
	Clientset *kubernetes.Clientset
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods/log,verbs=get
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;patch

// Reconcile analyzes failing pods and generates diagnostic reports
func (r *DiagnosticReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("pod", req.NamespacedName)

	// Fetch the pod
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Only analyze pods with issues
	if pod.Status.Phase == corev1.PodRunning {
		// Check if all containers are ready
		allReady := true
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				allReady = false
				break
			}
		}
		if allReady {
			return ctrl.Result{}, nil
		}
	}

	log.Info("Running diagnostics on pod")

	// Collect diagnostic information
	diagnosis := r.collectDiagnostics(ctx, pod, log)

	// Log diagnosis
	if len(diagnosis.Issues) > 0 {
		log.Info("Diagnostic results",
			"issues", len(diagnosis.Issues),
			"suggestions", len(diagnosis.Suggestions))

		// Create diagnostic event
		r.Recorder.Event(pod, corev1.EventTypeNormal, "DiagnosticsComplete",
			fmt.Sprintf("Found %d issues: %s", len(diagnosis.Issues), strings.Join(diagnosis.Issues, "; ")))

		// Add suggestion event if we have any
		if len(diagnosis.Suggestions) > 0 {
			limit := len(diagnosis.Suggestions)
			if limit > 3 {
				limit = 3
			}
			r.Recorder.Event(pod, corev1.EventTypeNormal, "DiagnosticSuggestions",
				strings.Join(diagnosis.Suggestions[:limit], "; "))
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// Diagnosis contains diagnostic results
type Diagnosis struct {
	PodName     string
	Namespace   string
	Issues      []string
	Suggestions []string
	LogPatterns []LogPattern
	Events      []EventSummary
	Resources   ResourceAnalysis
}

// LogPattern represents a detected pattern in logs
type LogPattern struct {
	Pattern     string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	Severity    string
	Explanation string
}

// EventSummary summarizes relevant Kubernetes events
type EventSummary struct {
	Type    string
	Reason  string
	Message string
	Count   int32
	Age     time.Duration
}

// ResourceAnalysis contains resource usage analysis
type ResourceAnalysis struct {
	CPURequested    string
	CPULimit        string
	MemoryRequested string
	MemoryLimit     string
	IssueDetected   bool
	Analysis        string
}

// collectDiagnostics gathers diagnostic information about a pod
func (r *DiagnosticReconciler) collectDiagnostics(ctx context.Context, pod *corev1.Pod, log logr.Logger) *Diagnosis {
	diagnosis := &Diagnosis{
		PodName:   pod.Name,
		Namespace: pod.Namespace,
	}

	// Analyze container statuses
	r.analyzeContainerStatuses(pod, diagnosis)

	// Analyze pod conditions
	r.analyzePodConditions(pod, diagnosis)

	// Analyze logs for error patterns
	r.analyzeLogsForPatterns(ctx, pod, diagnosis, log)

	// Analyze events
	r.analyzeEvents(ctx, pod, diagnosis, log)

	// Analyze resource configuration
	r.analyzeResources(pod, diagnosis)

	// Generate suggestions based on analysis
	r.generateSuggestions(diagnosis)

	return diagnosis
}

// analyzeContainerStatuses analyzes container status for issues
func (r *DiagnosticReconciler) analyzeContainerStatuses(pod *corev1.Pod, diagnosis *Diagnosis) {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			reason := cs.State.Waiting.Reason
			message := cs.State.Waiting.Message

			switch reason {
			case "CrashLoopBackOff":
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Container '%s' is in CrashLoopBackOff (restarted %d times)", cs.Name, cs.RestartCount))
			case "ImagePullBackOff", "ErrImagePull":
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Container '%s' cannot pull image: %s", cs.Name, message))
			case "CreateContainerConfigError":
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Container '%s' config error: %s", cs.Name, message))
			}
		}

		if cs.LastTerminationState.Terminated != nil {
			term := cs.LastTerminationState.Terminated
			switch term.Reason {
			case "OOMKilled":
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Container '%s' was OOMKilled (exit code %d)", cs.Name, term.ExitCode))
			case "Error":
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Container '%s' terminated with error (exit code %d)", cs.Name, term.ExitCode))
			}
		}
	}

	// Check init containers
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil || (cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0) {
			diagnosis.Issues = append(diagnosis.Issues,
				fmt.Sprintf("Init container '%s' failed", cs.Name))
		}
	}
}

// analyzePodConditions analyzes pod conditions for issues
func (r *DiagnosticReconciler) analyzePodConditions(pod *corev1.Pod, diagnosis *Diagnosis) {
	for _, cond := range pod.Status.Conditions {
		if cond.Status == corev1.ConditionFalse {
			switch cond.Type {
			case corev1.PodScheduled:
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Pod unschedulable: %s", cond.Message))
			case corev1.PodReady:
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Pod not ready: %s", cond.Message))
			case corev1.ContainersReady:
				diagnosis.Issues = append(diagnosis.Issues,
					fmt.Sprintf("Containers not ready: %s", cond.Message))
			}
		}
	}
}

// Known error patterns in logs
var errorPatterns = []struct {
	Pattern     *regexp.Regexp
	Severity    string
	Explanation string
	Suggestion  string
}{
	{
		Pattern:     regexp.MustCompile(`(?i)out of memory|oom|memory allocation failed`),
		Severity:    "HIGH",
		Explanation: "Application ran out of memory",
		Suggestion:  "Increase memory limits or optimize memory usage",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)connection refused|ECONNREFUSED`),
		Severity:    "MEDIUM",
		Explanation: "Failed to connect to a service",
		Suggestion:  "Check if dependent services are running and accessible",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)permission denied|EACCES`),
		Severity:    "MEDIUM",
		Explanation: "Permission denied error",
		Suggestion:  "Check file permissions and security context settings",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)no such file|ENOENT|file not found`),
		Severity:    "MEDIUM",
		Explanation: "Missing file or directory",
		Suggestion:  "Verify volume mounts and file paths in configuration",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)timeout|timed out|deadline exceeded`),
		Severity:    "MEDIUM",
		Explanation: "Operation timed out",
		Suggestion:  "Increase timeout values or investigate slow dependencies",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)panic|fatal|segmentation fault|SIGSEGV`),
		Severity:    "CRITICAL",
		Explanation: "Application crashed with fatal error",
		Suggestion:  "Review stack trace and fix application bug",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)authentication failed|unauthorized|401`),
		Severity:    "HIGH",
		Explanation: "Authentication failure",
		Suggestion:  "Check credentials and authentication configuration",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)database.*error|sql.*error|connection.*database`),
		Severity:    "HIGH",
		Explanation: "Database connection or query error",
		Suggestion:  "Check database connectivity and credentials",
	},
}

// containerLogResult holds pattern-match findings for a single container.
type containerLogResult struct {
	patterns    []LogPattern
	suggestions []string
}

// analyzeLogsForPatterns scans container logs for known error patterns.
// Containers are scanned in parallel using a bounded worker pool.
func (r *DiagnosticReconciler) analyzeLogsForPatterns(ctx context.Context, pod *corev1.Pod, diagnosis *Diagnosis, log logr.Logger) {
	if r.Clientset == nil {
		log.Info("Kubernetes clientset not configured, skipping log analysis")
		return
	}

	containers := pod.Spec.Containers
	if len(containers) == 0 {
		return
	}

	const maxWorkers = 5
	pool := executor.NewPool(min(len(containers), maxWorkers), log)

	tailLines := int64(100)
	for _, container := range containers {
		container := container
		if err := pool.Submit(executor.Task{
			Name: container.Name,
			Execute: func(ctx context.Context) (interface{}, error) {
				logs, err := r.Clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
					Container:  container.Name,
					TailLines:  &tailLines,
					Timestamps: true,
				}).Do(ctx).Raw()
				if err != nil {
					return nil, err
				}

				logStr := string(logs)
				var result containerLogResult
				for _, ep := range errorPatterns {
					matches := ep.Pattern.FindAllString(logStr, -1)
					if len(matches) > 0 {
						result.patterns = append(result.patterns, LogPattern{
							Pattern:     ep.Pattern.String(),
							Count:       len(matches),
							Severity:    ep.Severity,
							Explanation: ep.Explanation,
						})
						result.suggestions = append(result.suggestions, ep.Suggestion)
					}
				}
				return result, nil
			},
		}); err != nil {
			log.Error(err, "Failed to submit log analysis task", "container", container.Name)
		}
	}

	for _, res := range pool.Execute(ctx) {
		if res.Error != nil {
			log.Error(res.Error, "Failed to get logs", "container", res.Name)
			continue
		}
		if res.Data == nil {
			continue
		}
		scanResult := res.Data.(containerLogResult)
		diagnosis.LogPatterns = append(diagnosis.LogPatterns, scanResult.patterns...)
		diagnosis.Suggestions = append(diagnosis.Suggestions, scanResult.suggestions...)
	}
}

// analyzeEvents analyzes Kubernetes events for the pod
func (r *DiagnosticReconciler) analyzeEvents(ctx context.Context, pod *corev1.Pod, diagnosis *Diagnosis, log logr.Logger) {
	events := &corev1.EventList{}
	// Requires field index "involvedObject.name" registered in SetupWithManager
	err := r.List(ctx, events, client.InNamespace(pod.Namespace),
		client.MatchingFields{"involvedObject.name": pod.Name})

	if err != nil {
		log.Error(err, "Failed to list events")
		return
	}

	for _, event := range events.Items {
		// Only include warning events or recent normal events
		if event.Type == corev1.EventTypeWarning ||
			time.Since(event.LastTimestamp.Time) < 10*time.Minute {
			diagnosis.Events = append(diagnosis.Events, EventSummary{
				Type:    event.Type,
				Reason:  event.Reason,
				Message: event.Message,
				Count:   event.Count,
				Age:     time.Since(event.LastTimestamp.Time),
			})
		}
	}
}

// analyzeResources analyzes resource configuration
func (r *DiagnosticReconciler) analyzeResources(pod *corev1.Pod, diagnosis *Diagnosis) {
	for _, container := range pod.Spec.Containers {
		resources := container.Resources

		// Check if requests are set
		if resources.Requests.Cpu().IsZero() || resources.Requests.Memory().IsZero() {
			diagnosis.Issues = append(diagnosis.Issues,
				fmt.Sprintf("Container '%s' has no resource requests set", container.Name))
			diagnosis.Suggestions = append(diagnosis.Suggestions,
				"Set resource requests for better scheduling and stability")
		}

		// Check if limits are set
		if resources.Limits.Cpu().IsZero() || resources.Limits.Memory().IsZero() {
			diagnosis.Issues = append(diagnosis.Issues,
				fmt.Sprintf("Container '%s' has no resource limits set", container.Name))
			diagnosis.Suggestions = append(diagnosis.Suggestions,
				"Set resource limits to prevent resource exhaustion")
		}

		// Check for potential resource issues
		if !resources.Requests.Memory().IsZero() && !resources.Limits.Memory().IsZero() {
			requestMem := resources.Requests.Memory().Value()
			limitMem := resources.Limits.Memory().Value()

			// If limit is much higher than request, might have memory issues
			if float64(limitMem)/float64(requestMem) > 4 {
				diagnosis.Suggestions = append(diagnosis.Suggestions,
					fmt.Sprintf("Container '%s' memory limit is much higher than request - consider narrowing the range", container.Name))
			}
		}

		diagnosis.Resources = ResourceAnalysis{
			CPURequested:    resources.Requests.Cpu().String(),
			CPULimit:        resources.Limits.Cpu().String(),
			MemoryRequested: resources.Requests.Memory().String(),
			MemoryLimit:     resources.Limits.Memory().String(),
		}
	}
}

// generateSuggestions generates additional suggestions based on analysis
func (r *DiagnosticReconciler) generateSuggestions(diagnosis *Diagnosis) {
	// Deduplicate suggestions
	seen := make(map[string]bool)
	var unique []string
	for _, s := range diagnosis.Suggestions {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}
	diagnosis.Suggestions = unique

	// Add general suggestions based on issue count
	if len(diagnosis.Issues) > 3 {
		diagnosis.Suggestions = append(diagnosis.Suggestions,
			"Multiple issues detected - consider reviewing the deployment configuration holistically")
	}
}

// SetupWithManager sets up the controller with the Manager
func (r *DiagnosticReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("Diagnostic")

	// Register field index so analyzeEvents can query events by involvedObject.name
	// without a cluster-wide list+filter.
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&corev1.Event{},
		"involvedObject.name",
		func(o client.Object) []string {
			event, ok := o.(*corev1.Event)
			if !ok {
				return nil
			}
			return []string{event.InvolvedObject.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to index events by involvedObject.name: %w", err)
	}

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

func int64Ptr(i int64) *int64 {
	return &i
}
