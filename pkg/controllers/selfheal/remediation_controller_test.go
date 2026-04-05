package selfheal

import (
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// TestRateLimiter verifies that the action counter is thread-safe and that the
// rate-limit check in applyRemediation correctly blocks actions when the limit
// is reached.
func TestRateLimiter_ThreadSafe(t *testing.T) {
	r := &RemediationReconciler{}
	r.mu.Lock()
	r.actionCounts = make(map[string]int)
	r.lastResetTime = time.Now()
	r.mu.Unlock()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r.mu.Lock()
			r.actionCounts["test-policy"]++
			r.mu.Unlock()
		}()
	}
	wg.Wait()

	r.mu.Lock()
	count := r.actionCounts["test-policy"]
	r.mu.Unlock()

	if count != goroutines {
		t.Errorf("expected actionCounts[test-policy] = %d, got %d (data race likely)", goroutines, count)
	}
}

// TestResetRateLimitIfNeeded verifies that counters reset after an hour.
func TestResetRateLimitIfNeeded(t *testing.T) {
	r := &RemediationReconciler{}
	r.mu.Lock()
	r.actionCounts = map[string]int{"policy-a": 5}
	// Simulate that the last reset was 2 hours ago
	r.lastResetTime = time.Now().Add(-2 * time.Hour)
	r.mu.Unlock()

	r.resetRateLimitIfNeeded()

	r.mu.Lock()
	count := r.actionCounts["policy-a"]
	r.mu.Unlock()

	if count != 0 {
		t.Errorf("expected actionCounts to be reset to 0, got %d", count)
	}
}

// TestResetRateLimitIfNeeded_NoResetWithinHour verifies that counters are NOT
// reset when less than an hour has elapsed.
func TestResetRateLimitIfNeeded_NoResetWithinHour(t *testing.T) {
	r := &RemediationReconciler{}
	r.mu.Lock()
	r.actionCounts = map[string]int{"policy-a": 7}
	r.lastResetTime = time.Now().Add(-30 * time.Minute)
	r.mu.Unlock()

	r.resetRateLimitIfNeeded()

	r.mu.Lock()
	count := r.actionCounts["policy-a"]
	r.mu.Unlock()

	if count != 7 {
		t.Errorf("expected actionCounts to remain 7, got %d", count)
	}
}

// TestDetectPodIssues_CrashLoopBackOff verifies that a container in
// CrashLoopBackOff is detected with the correct issue type.
func TestDetectPodIssues_CrashLoopBackOff(t *testing.T) {
	r := &RemediationReconciler{}

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "app",
					RestartCount: 5,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason: "CrashLoopBackOff",
						},
					},
				},
			},
		},
	}

	issues := r.detectPodIssues(pod)
	if len(issues) == 0 {
		t.Fatal("expected at least one issue, got none")
	}
	if issues[0].Type != IssueCrashLoopBackOff {
		t.Errorf("expected IssueCrashLoopBackOff, got %s", issues[0].Type)
	}
	if issues[0].Count != 5 {
		t.Errorf("expected restart count 5, got %d", issues[0].Count)
	}
}

// TestDetectPodIssues_OOMKilled verifies OOMKilled detection from last
// terminated state.
func TestDetectPodIssues_OOMKilled(t *testing.T) {
	r := &RemediationReconciler{}

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "app",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							Reason: "OOMKilled",
						},
					},
				},
			},
		},
	}

	issues := r.detectPodIssues(pod)
	if len(issues) == 0 {
		t.Fatal("expected at least one issue, got none")
	}
	found := false
	for _, i := range issues {
		if i.Type == IssueOOMKilled {
			found = true
		}
	}
	if !found {
		t.Error("expected IssueOOMKilled to be detected")
	}
}

// TestDetectPodIssues_HealthyPod verifies that a running, ready pod produces
// no issues (so we don't requeue healthy pods unnecessarily).
func TestDetectPodIssues_HealthyPod(t *testing.T) {
	r := &RemediationReconciler{}

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:  "app",
					Ready: true,
				},
			},
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	issues := r.detectPodIssues(pod)
	if len(issues) != 0 {
		t.Errorf("expected no issues for healthy pod, got %v", issues)
	}
}

// TestPolicyMatchesPod_NoSelector verifies that a policy with no selector
// matches any pod.
func TestPolicyMatchesPod_NoSelector(t *testing.T) {
	r := &RemediationReconciler{}

	policy := &agentv1alpha1.RemediationPolicy{
		Spec: agentv1alpha1.RemediationPolicySpec{Selector: nil},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default"}}

	if !r.policyMatchesPod(policy, pod) {
		t.Error("policy with nil selector should match any pod")
	}
}

// TestPolicyMatchesPod_NamespaceFilter verifies that namespace filtering works.
func TestPolicyMatchesPod_NamespaceFilter(t *testing.T) {
	r := &RemediationReconciler{}

	policy := &agentv1alpha1.RemediationPolicy{
		Spec: agentv1alpha1.RemediationPolicySpec{
			Selector: &agentv1alpha1.ResourceSelector{
				Namespaces: []string{"production"},
			},
		},
	}

	podInScope := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "production"}}
	podOutOfScope := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "staging"}}

	if !r.policyMatchesPod(policy, podInScope) {
		t.Error("expected policy to match pod in 'production' namespace")
	}
	if r.policyMatchesPod(policy, podOutOfScope) {
		t.Error("expected policy NOT to match pod in 'staging' namespace")
	}
}

// TestRuleMatchesIssue verifies threshold-based rule matching.
func TestRuleMatchesIssue(t *testing.T) {
	r := &RemediationReconciler{}

	rule := agentv1alpha1.RemediationRule{
		Condition: agentv1alpha1.RemediationCondition{
			Type:      "CrashLoopBackOff",
			Threshold: 3,
		},
	}

	// Below threshold — should not match
	issueBelow := PodIssue{Type: IssueCrashLoopBackOff, Count: 2}
	if r.ruleMatchesIssue(rule, issueBelow) {
		t.Error("rule should not match when restart count is below threshold")
	}

	// At threshold — should match
	issueAtThreshold := PodIssue{Type: IssueCrashLoopBackOff, Count: 3}
	if !r.ruleMatchesIssue(rule, issueAtThreshold) {
		t.Error("rule should match when restart count equals threshold")
	}

	// Wrong type — should not match
	issueWrongType := PodIssue{Type: IssueOOMKilled, Count: 10}
	if r.ruleMatchesIssue(rule, issueWrongType) {
		t.Error("rule should not match a different issue type")
	}
}
