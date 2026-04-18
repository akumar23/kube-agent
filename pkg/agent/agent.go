package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IssueContext is a minimal description of the detected problem passed to the agent.
type IssueContext struct {
	Type      string // e.g. "Unschedulable", "CrashLoopBackOff"
	Container string
	Message   string
}

// Remediator runs an agentic loop to diagnose and fix Kubernetes pod issues.
type Remediator struct {
	client   *Client
	executor *Executor
	// Output is where the agent writes its reasoning. Defaults to io.Discard.
	Output io.Writer
}

// NewRemediator creates a Remediator.
//
//   - ollamaURL: base URL of the Ollama instance (e.g. "https://host/")
//   - model: model name, or "" for DefaultModel
//   - crClient: controller-runtime client
//   - clientset: native Kubernetes clientset (needed for log streaming)
//   - allowedTools: write tools the agent may call (nil = permit all)
//   - dryRun: if true, write tools log intent only
func NewRemediator(
	ollamaURL, model string,
	crClient client.Client,
	clientset *kubernetes.Clientset,
	allowedTools map[string]bool,
	dryRun bool,
) *Remediator {
	return &Remediator{
		client:   NewClient(ollamaURL, model),
		executor: NewExecutor(crClient, clientset, allowedTools, dryRun),
		Output:   io.Discard,
	}
}

// SetConfirmFn sets a callback invoked before each write operation (interactive mode).
func (r *Remediator) SetConfirmFn(fn func(toolName, description string) bool) {
	r.executor.ConfirmFn = fn
}

// Remediate runs the agentic loop for a failing pod.
// It returns nil when the loop completes (whether or not the issue was fixed).
func (r *Remediator) Remediate(ctx context.Context, pod *corev1.Pod, issue IssueContext) error {
	tools := r.executor.BuildTools()

	// Build the tool schemas to send to the model.
	schemas := make([]Tool, len(tools))
	for i, t := range tools {
		schemas[i] = t.Schema
	}

	// Index tools by name for dispatch.
	toolIndex := make(map[string]ToolDef, len(tools))
	for _, t := range tools {
		toolIndex[t.Schema.Function.Name] = t
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt()},
		{Role: "user", Content: r.buildUserMessage(pod, issue)},
	}

	r.printf("\n[kube-agent] Starting remediation: %s on pod %s/%s\n",
		issue.Type, pod.Namespace, pod.Name)

	for round := 0; round < MaxRounds; round++ {
		// Give the model a generous timeout per round.
		roundCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		choice, err := r.client.Chat(roundCtx, messages, schemas)
		cancel()
		if err != nil {
			return fmt.Errorf("round %d: %w", round, err)
		}

		// Print the model's reasoning if it provided text.
		if choice.Message.Content != "" {
			r.printf("\n[Agent] %s\n", choice.Message.Content)
		}

		// No tool calls means the agent is done.
		if choice.FinishReason == "stop" || len(choice.Message.ToolCalls) == 0 {
			break
		}

		// Append assistant message with tool calls.
		messages = append(messages, choice.Message)

		// Execute each tool call and append results.
		for _, tc := range choice.Message.ToolCalls {
			result := r.executeToolCall(ctx, tc, toolIndex)
			messages = append(messages, Message{
				Role:       "tool",
				Content:    result,
				ToolCallID: tc.ID,
			})
		}
	}

	r.printf("\n[kube-agent] Remediation loop complete.\n")
	return nil
}

// executeToolCall dispatches a single tool call and returns its output.
func (r *Remediator) executeToolCall(ctx context.Context, tc ToolCall, toolIndex map[string]ToolDef) string {
	def, ok := toolIndex[tc.Function.Name]
	if !ok {
		r.printf("[Tool] %s — unknown tool\n", tc.Function.Name)
		return fmt.Sprintf("error: unknown tool %q", tc.Function.Name)
	}

	var args map[string]interface{}
	if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
		r.printf("[Tool] %s — bad arguments: %v\n", tc.Function.Name, err)
		return fmt.Sprintf("error: bad arguments: %v", err)
	}

	r.printf("[Tool] %s(%s)\n", tc.Function.Name, formatArgs(args))

	result, err := def.Execute(ctx, args)
	if err != nil {
		r.printf("  → error: %v\n", err)
		return fmt.Sprintf("error: %v", err)
	}

	// Truncate very long results so they don't blow the context window.
	if len(result) > 3000 {
		result = result[:3000] + "\n... (truncated)"
	}

	r.printf("  → %s\n", firstLine(result))
	return result
}

func (r *Remediator) printf(format string, args ...interface{}) {
	fmt.Fprintf(r.Output, format, args...)
}

// buildUserMessage constructs the initial problem description for the model.
func (r *Remediator) buildUserMessage(pod *corev1.Pod, issue IssueContext) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Pod %s/%s is failing.\n\n", pod.Namespace, pod.Name)
	fmt.Fprintf(&sb, "Detected issue: %s\n", issue.Type)
	if issue.Container != "" {
		fmt.Fprintf(&sb, "Container: %s\n", issue.Container)
	}
	if issue.Message != "" {
		fmt.Fprintf(&sb, "Message: %s\n", issue.Message)
	}

	// Inline node selector so the agent has immediate context.
	if len(pod.Spec.NodeSelector) > 0 {
		fmt.Fprintf(&sb, "Pod node selector: %v\n", pod.Spec.NodeSelector)
	}

	fmt.Fprintf(&sb, "\nInvestigate the root cause and fix it using the available tools.")
	return sb.String()
}

// systemPrompt returns the agent's system instructions.
func systemPrompt() string {
	return `You are an autonomous Kubernetes self-healing agent embedded in kube-agent.

Your job:
1. Investigate why a pod is failing using the read tools (get_pod_events, get_pod_logs, list_nodes, describe_pod).
2. Identify the root cause.
3. Take corrective action using write tools (label_node, delete_pod, patch_deploy).
4. Confirm the action taken and stop.

Rules:
- Always investigate before acting. Read events first — they usually explain the failure.
- Explain your reasoning in plain text before each tool call.
- Use the minimum number of actions needed to fix the problem.
- If you cannot fix the issue with the available tools, explain why and stop.
- Do not loop endlessly. Once you have taken action, summarize and stop.`
}

// --- Helpers ---

func formatArgs(args map[string]interface{}) string {
	parts := make([]string, 0, len(args))
	for k, v := range args {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(parts, ", ")
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx] + " ..."
	}
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
