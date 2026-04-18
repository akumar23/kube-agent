package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// writeTools is the set of tools that mutate cluster state and require authorization.
var writeTools = map[string]bool{
	"label_node":   true,
	"delete_pod":   true,
	"patch_deploy": true,
}

// ToolDef pairs the schema (sent to the model) with its implementation.
type ToolDef struct {
	Schema  Tool
	Execute func(ctx context.Context, args map[string]interface{}) (string, error)
}

// Executor holds Kubernetes clients and policy settings for tool execution.
type Executor struct {
	crClient     client.Client
	clientset    *kubernetes.Clientset
	allowedTools map[string]bool // nil = all write tools allowed
	dryRun       bool
	// ConfirmFn is called before write operations in interactive mode.
	// Return false to skip the action. If nil, writes execute without confirmation.
	ConfirmFn func(toolName, description string) bool
}

// NewExecutor creates an Executor. allowedTools is the set of write tool names
// the agent is permitted to use (nil permits all). dryRun logs intent without executing.
func NewExecutor(crClient client.Client, clientset *kubernetes.Clientset, allowedTools map[string]bool, dryRun bool) *Executor {
	return &Executor{
		crClient:     crClient,
		clientset:    clientset,
		allowedTools: allowedTools,
		dryRun:       dryRun,
	}
}

// authorized returns true if the named tool may be executed.
func (e *Executor) authorized(name string) bool {
	if !writeTools[name] {
		return true // read tools are always allowed
	}
	if e.dryRun {
		return false
	}
	if e.allowedTools == nil {
		return true // nil = permit all
	}
	return e.allowedTools[name]
}

// confirm calls ConfirmFn if set, otherwise returns true (auto-approve).
func (e *Executor) confirm(toolName, description string) bool {
	if e.ConfirmFn == nil {
		return true
	}
	return e.ConfirmFn(toolName, description)
}

// BuildTools returns tool definitions with execution functions bound to this Executor.
func (e *Executor) BuildTools() []ToolDef {
	return []ToolDef{
		e.toolDescribePod(),
		e.toolGetPodEvents(),
		e.toolGetPodLogs(),
		e.toolListNodes(),
		e.toolLabelNode(),
		e.toolDeletePod(),
		e.toolPatchDeployEnv(),
	}
}

// --- Read tools ---

func (e *Executor) toolDescribePod() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "describe_pod",
				Description: "Get full status, conditions, and container states of a pod.",
				Parameters:  strParams("namespace", "pod_name"),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			ns := strArg(args, "namespace")
			name := strArg(args, "pod_name")
			pod := &corev1.Pod{}
			if err := e.crClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, pod); err != nil {
				return "", err
			}
			out, _ := json.MarshalIndent(map[string]interface{}{
				"phase":              pod.Status.Phase,
				"conditions":         pod.Status.Conditions,
				"containerStatuses":  pod.Status.ContainerStatuses,
				"nodeSelector":       pod.Spec.NodeSelector,
				"affinity":           pod.Spec.Affinity,
				"nodeName":           pod.Spec.NodeName,
			}, "", "  ")
			return string(out), nil
		},
	}
}

func (e *Executor) toolGetPodEvents() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "get_pod_events",
				Description: "List Kubernetes events for a specific pod. Shows scheduling failures, image pull errors, etc.",
				Parameters:  strParams("namespace", "pod_name"),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			ns := strArg(args, "namespace")
			name := strArg(args, "pod_name")

			eventList := &corev1.EventList{}
			if err := e.crClient.List(ctx, eventList, client.InNamespace(ns)); err != nil {
				return "", err
			}

			var sb strings.Builder
			for _, ev := range eventList.Items {
				if ev.InvolvedObject.Name != name {
					continue
				}
				fmt.Fprintf(&sb, "[%s] %s: %s\n", ev.Type, ev.Reason, ev.Message)
			}
			if sb.Len() == 0 {
				return "No events found for this pod.", nil
			}
			return sb.String(), nil
		},
	}
}

func (e *Executor) toolGetPodLogs() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "get_pod_logs",
				Description: "Get recent log output from a pod container. Useful for diagnosing CrashLoopBackOff.",
				Parameters: strParamsWithOptional(
					[]string{"namespace", "pod_name"},
					map[string]string{"container": "container name (optional, defaults to first container)"},
				),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			ns := strArg(args, "namespace")
			name := strArg(args, "pod_name")
			container := strArg(args, "container")

			tailLines := int64(50)
			opts := &corev1.PodLogOptions{TailLines: &tailLines}
			if container != "" {
				opts.Container = container
			}

			req := e.clientset.CoreV1().Pods(ns).GetLogs(name, opts)
			stream, err := req.Stream(ctx)
			if err != nil {
				return "", fmt.Errorf("log stream: %w", err)
			}
			defer stream.Close()

			var buf bytes.Buffer
			io.Copy(&buf, stream) //nolint:errcheck
			if buf.Len() == 0 {
				return "No logs available.", nil
			}
			return buf.String(), nil
		},
	}
}

func (e *Executor) toolListNodes() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "list_nodes",
				Description: "List all nodes with their labels, taints, and conditions. Use this to understand scheduling constraints.",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			nodeList := &corev1.NodeList{}
			if err := e.crClient.List(ctx, nodeList); err != nil {
				return "", err
			}

			var sb strings.Builder
			for _, node := range nodeList.Items {
				fmt.Fprintf(&sb, "Node: %s\n", node.Name)
				fmt.Fprintf(&sb, "  Labels: %v\n", node.Labels)
				if len(node.Spec.Taints) > 0 {
					fmt.Fprintf(&sb, "  Taints: %v\n", node.Spec.Taints)
				}
				for _, cond := range node.Status.Conditions {
					if cond.Type == corev1.NodeReady {
						fmt.Fprintf(&sb, "  Ready: %s\n", cond.Status)
					}
				}
				sb.WriteString("\n")
			}
			return sb.String(), nil
		},
	}
}

// --- Write tools ---

func (e *Executor) toolLabelNode() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "label_node",
				Description: "Add or update a label on a Kubernetes node. Use when a pod is unschedulable due to a missing node label.",
				Parameters:  strParams("node_name", "label_key", "label_value"),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			nodeName := strArg(args, "node_name")
			key := strArg(args, "label_key")
			value := strArg(args, "label_value")

			if !e.authorized("label_node") {
				return fmt.Sprintf("[dry-run] Would label node %s: %s=%s", nodeName, key, value), nil
			}
			desc := fmt.Sprintf("label node %s with %s=%s", nodeName, key, value)
			if !e.confirm("label_node", desc) {
				return "Action skipped by user.", nil
			}

			patch := []byte(fmt.Sprintf(`{"metadata":{"labels":{%q:%q}}}`, key, value))
			node := &corev1.Node{}
			node.Name = nodeName
			if err := e.crClient.Patch(ctx, node, client.RawPatch(types.MergePatchType, patch)); err != nil {
				return "", fmt.Errorf("patch node: %w", err)
			}
			return fmt.Sprintf("Successfully labeled node %s: %s=%s", nodeName, key, value), nil
		},
	}
}

func (e *Executor) toolDeletePod() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "delete_pod",
				Description: "Delete a pod to trigger recreation by its ReplicaSet/Deployment. Use for CrashLoopBackOff or stuck pods.",
				Parameters:  strParams("namespace", "pod_name"),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			ns := strArg(args, "namespace")
			name := strArg(args, "pod_name")

			if !e.authorized("delete_pod") {
				return fmt.Sprintf("[dry-run] Would delete pod %s/%s", ns, name), nil
			}
			desc := fmt.Sprintf("delete pod %s/%s (will be recreated by its controller)", ns, name)
			if !e.confirm("delete_pod", desc) {
				return "Action skipped by user.", nil
			}

			pod := &corev1.Pod{}
			pod.Name = name
			pod.Namespace = ns
			if err := e.crClient.Delete(ctx, pod); err != nil {
				return "", fmt.Errorf("delete pod: %w", err)
			}
			return fmt.Sprintf("Pod %s/%s deleted. It will be recreated by its controller.", ns, name), nil
		},
	}
}

func (e *Executor) toolPatchDeployEnv() ToolDef {
	return ToolDef{
		Schema: Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        "patch_deploy",
				Description: "Add or update an environment variable on a Deployment's first container. Use for missing config causing CrashLoopBackOff.",
				Parameters:  strParams("namespace", "deployment_name", "env_key", "env_value"),
			},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (string, error) {
			ns := strArg(args, "namespace")
			deployName := strArg(args, "deployment_name")
			envKey := strArg(args, "env_key")
			envValue := strArg(args, "env_value")

			if !e.authorized("patch_deploy") {
				return fmt.Sprintf("[dry-run] Would set %s=%s on deployment %s/%s", envKey, envValue, ns, deployName), nil
			}
			desc := fmt.Sprintf("set env %s=%s on deployment %s/%s", envKey, envValue, ns, deployName)
			if !e.confirm("patch_deploy", desc) {
				return "Action skipped by user.", nil
			}

			// Fetch the deployment, add/update the env var, then update.
			deploy, err := e.clientset.AppsV1().Deployments(ns).Get(ctx, deployName, metav1.GetOptions{})
			if err != nil {
				return "", fmt.Errorf("get deployment: %w", err)
			}
			if len(deploy.Spec.Template.Spec.Containers) == 0 {
				return "", fmt.Errorf("deployment has no containers")
			}

			container := &deploy.Spec.Template.Spec.Containers[0]
			updated := false
			for i, e := range container.Env {
				if e.Name == envKey {
					container.Env[i].Value = envValue
					updated = true
					break
				}
			}
			if !updated {
				container.Env = append(container.Env, corev1.EnvVar{Name: envKey, Value: envValue})
			}

			if _, err := e.clientset.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				return "", fmt.Errorf("update deployment: %w", err)
			}
			return fmt.Sprintf("Set %s=%s on deployment %s/%s", envKey, envValue, ns, deployName), nil
		},
	}
}

// --- Helpers ---

// strArg extracts a string from args, returning empty string if missing.
func strArg(args map[string]interface{}, key string) string {
	v, _ := args[key].(string)
	return v
}

// strParams returns a JSON Schema object requiring all listed string parameters.
func strParams(names ...string) map[string]interface{} {
	props := make(map[string]interface{}, len(names))
	for _, n := range names {
		props[n] = map[string]string{"type": "string"}
	}
	return map[string]interface{}{
		"type":       "object",
		"properties": props,
		"required":   names,
	}
}

// strParamsWithOptional returns a JSON Schema with required and optional string parameters.
func strParamsWithOptional(required []string, optional map[string]string) map[string]interface{} {
	props := make(map[string]interface{})
	for _, n := range required {
		props[n] = map[string]string{"type": "string"}
	}
	for n, desc := range optional {
		props[n] = map[string]interface{}{"type": "string", "description": desc}
	}
	return map[string]interface{}{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}
