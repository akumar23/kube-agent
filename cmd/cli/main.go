package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
	"github.com/kube-agent/kube-agent/pkg/agent"
)

var (
	kubeconfig string
	namespace  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "kube-agent",
		Short: "Kube-Agent CLI - Manage your Kubernetes applications",
		Long: `Kube-Agent is an autonomous Kubernetes management agent that provides:
- Automated deployments with GitOps
- Public URL exposure with TLS
- Vulnerability scanning and reporting
- Self-healing and diagnostics
- Progressive delivery with rollbacks`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")

	// Add subcommands
	rootCmd.AddCommand(
		newDeployCmd(),
		newListCmd(),
		newStatusCmd(),
		newScanCmd(),
		newReportCmd(),
		newDeleteCmd(),
		newLogsCmd(),
		newDiagnoseCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newDeployCmd creates the deploy subcommand
func newDeployCmd() *cobra.Command {
	var (
		image        string
		gitRepo      string
		gitPath      string
		gitBranch    string
		helmChart    string
		helmVersion  string
		host         string
		tlsEnabled   bool
		scanEnabled  bool
		selfHealing  bool
		replicas     int32
		strategy     string
	)

	cmd := &cobra.Command{
		Use:   "deploy [name]",
		Short: "Deploy an application",
		Long:  "Deploy an application from a Docker image, Git repository, or Helm chart",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			// Determine source type
			var sourceType, source string
			switch {
			case image != "":
				sourceType = "docker"
				source = image
			case gitRepo != "":
				sourceType = "git"
				source = gitRepo
			case helmChart != "":
				sourceType = "helm"
				source = helmChart
			default:
				return fmt.Errorf("must specify --image, --git-repo, or --helm-chart")
			}

			fmt.Printf("Deploying %s from %s (%s)\n", name, source, sourceType)

			// Build the ManagedApplication manifest
			app := buildManagedApplication(name, namespace, sourceType, map[string]interface{}{
				"image":       image,
				"gitRepo":     gitRepo,
				"gitPath":     gitPath,
				"gitBranch":   gitBranch,
				"helmChart":   helmChart,
				"helmVersion": helmVersion,
				"host":        host,
				"tlsEnabled":  tlsEnabled,
				"scanEnabled": scanEnabled,
				"selfHealing": selfHealing,
				"replicas":    replicas,
				"strategy":    strategy,
			})

			// Create using dynamic client
			client, err := getDynamicClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}

			_, err = client.Resource(gvr).Namespace(namespace).Create(
				context.Background(), app, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create application: %w", err)
			}

			fmt.Printf("✓ Application '%s' created successfully\n", name)
			fmt.Printf("  Run 'kube-agent status %s' to check deployment progress\n", name)

			return nil
		},
	}

	cmd.Flags().StringVar(&image, "image", "", "Docker image to deploy")
	cmd.Flags().StringVar(&gitRepo, "git-repo", "", "Git repository URL")
	cmd.Flags().StringVar(&gitPath, "git-path", "./", "Path within the git repository")
	cmd.Flags().StringVar(&gitBranch, "git-branch", "main", "Git branch")
	cmd.Flags().StringVar(&helmChart, "helm-chart", "", "Helm chart reference")
	cmd.Flags().StringVar(&helmVersion, "helm-version", "", "Helm chart version")
	cmd.Flags().StringVar(&host, "host", "", "Public hostname for the application")
	cmd.Flags().BoolVar(&tlsEnabled, "tls", true, "Enable TLS with Let's Encrypt")
	cmd.Flags().BoolVar(&scanEnabled, "scan", true, "Enable vulnerability scanning")
	cmd.Flags().BoolVar(&selfHealing, "self-healing", true, "Enable self-healing")
	cmd.Flags().Int32Var(&replicas, "replicas", 1, "Number of replicas")
	cmd.Flags().StringVar(&strategy, "strategy", "rolling", "Deployment strategy (rolling, canary, blue-green)")

	return cmd
}

// newListCmd creates the list subcommand
func newListCmd() *cobra.Command {
	var allNamespaces bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List deployed applications",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getDynamicClient()
			if err != nil {
				return err
			}

			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}

			var list *unstructured.UnstructuredList
			if allNamespaces {
				list, err = client.Resource(gvr).List(context.Background(), metav1.ListOptions{})
			} else {
				list, err = client.Resource(gvr).Namespace(namespace).List(context.Background(), metav1.ListOptions{})
			}

			if err != nil {
				return fmt.Errorf("failed to list applications: %w", err)
			}

			if len(list.Items) == 0 {
				fmt.Println("No applications found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tNAMESPACE\tPHASE\tURL\tAGE")

			for _, item := range list.Items {
				name := item.GetName()
				ns := item.GetNamespace()
				phase, _, _ := unstructured.NestedString(item.Object, "status", "phase")
				url, _, _ := unstructured.NestedString(item.Object, "status", "publicURL")
				age := time.Since(item.GetCreationTimestamp().Time).Round(time.Second)

				if phase == "" {
					phase = "Unknown"
				}
				if url == "" {
					url = "-"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, ns, phase, url, age)
			}

			w.Flush()
			return nil
		},
	}

	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "List across all namespaces")

	return cmd
}

// newStatusCmd creates the status subcommand
func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [name]",
		Short: "Show application status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			client, err := getDynamicClient()
			if err != nil {
				return err
			}

			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}

			app, err := client.Resource(gvr).Namespace(namespace).Get(
				context.Background(), name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get application: %w", err)
			}

			// Extract status fields
			phase, _, _ := unstructured.NestedString(app.Object, "status", "phase")
			health, _, _ := unstructured.NestedString(app.Object, "status", "health")
			url, _, _ := unstructured.NestedString(app.Object, "status", "publicURL")
			message, _, _ := unstructured.NestedString(app.Object, "status", "message")
			vulns, _, _ := unstructured.NestedMap(app.Object, "status", "vulnerabilityCount")

			fmt.Printf("Application: %s\n", name)
			fmt.Printf("Namespace:   %s\n", namespace)
			fmt.Printf("Phase:       %s\n", phase)
			fmt.Printf("Health:      %s\n", health)
			if url != "" {
				fmt.Printf("URL:         %s\n", url)
			}
			if message != "" {
				fmt.Printf("Message:     %s\n", message)
			}

			if len(vulns) > 0 {
				fmt.Println("\nVulnerabilities:")
				for severity, count := range vulns {
					fmt.Printf("  %s: %v\n", severity, count)
				}
			}

			return nil
		},
	}

	return cmd
}

// newScanCmd creates the scan subcommand
func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [name]",
		Short: "Trigger a vulnerability scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			dyn, err := getDynamicClient()
			if err != nil {
				return err
			}

			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}

			ctx := context.Background()
			app, err := dyn.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get application: %w", err)
			}

			vs, found, err := unstructured.NestedMap(app.Object, "spec", "security", "vulnerabilityScanning")
			if err != nil || !found || vs == nil {
				return fmt.Errorf("vulnerability scanning is not configured for %q in namespace %q", name, namespace)
			}
			enabled, _ := vs["enabled"].(bool)
			if !enabled {
				return fmt.Errorf("vulnerability scanning is disabled for %q; enable spec.security.vulnerabilityScanning.enabled", name)
			}

			ts := time.Now().UTC().Format(time.RFC3339)
			patch := map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						agentv1alpha1.AnnotationScanRequestedAt: ts,
					},
				},
			}
			patchBytes, err := json.Marshal(patch)
			if err != nil {
				return fmt.Errorf("marshal patch: %w", err)
			}

			_, err = dyn.Resource(gvr).Namespace(namespace).Patch(
				ctx, name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("failed to request scan: %w", err)
			}

			fmt.Printf("Scan requested for %s/%s. Use 'kube-agent status %s' to view results after the operator reconciles.\n",
				namespace, name, name)
			return nil
		},
	}

	return cmd
}

// newReportCmd creates the report subcommand
func newReportCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate or view security reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Security Report")
			fmt.Println("===============")

			// TODO: Implement report generation/viewing
			fmt.Println("Report generation not yet implemented")

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json, html)")

	return cmd
}

// newDeleteCmd creates the delete subcommand
func newDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if !force {
				fmt.Printf("Are you sure you want to delete '%s'? (y/N): ", name)
				var confirm string
				fmt.Scanln(&confirm)
				if confirm != "y" && confirm != "Y" {
					fmt.Println("Aborted")
					return nil
				}
			}

			client, err := getDynamicClient()
			if err != nil {
				return err
			}

			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}

			err = client.Resource(gvr).Namespace(namespace).Delete(
				context.Background(), name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("failed to delete application: %w", err)
			}

			fmt.Printf("✓ Application '%s' deleted\n", name)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")

	return cmd
}

// newLogsCmd creates the logs subcommand
func newLogsCmd() *cobra.Command {
	var (
		follow    bool
		tailLines int64
	)

	cmd := &cobra.Command{
		Use:   "logs [name]",
		Short: "View application logs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			ctx := context.Background()

			// Step 1: confirm the ManagedApplication exists.
			dynClient, err := getDynamicClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			gvr := schema.GroupVersionResource{
				Group:    "agent.kubeagent.io",
				Version:  "v1alpha1",
				Resource: "managedapplications",
			}
			if _, err = dynClient.Resource(gvr).Namespace(namespace).Get(
				ctx, name, metav1.GetOptions{}); err != nil {
				return fmt.Errorf("application %q not found in namespace %q: %w",
					name, namespace, err)
			}

			// Step 2: list pods for this application.
			clientset, err := getClientset()
			if err != nil {
				return fmt.Errorf("failed to create clientset: %w", err)
			}

			labelSelector := fmt.Sprintf("agent.kubeagent.io/app=%s", name)
			pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				return fmt.Errorf("failed to list pods: %w", err)
			}
			if len(pods.Items) == 0 {
				return fmt.Errorf("no pods found for application %q (label %s)",
					name, labelSelector)
			}

			// Step 3: stream logs concurrently from every pod.
			var wg sync.WaitGroup
			errCh := make(chan error, len(pods.Items))

			for _, pod := range pods.Items {
				wg.Add(1)
				go func(podName string) {
					defer wg.Done()
					if err := streamPodLogs(ctx, clientset, namespace, podName, follow, tailLines); err != nil {
						errCh <- fmt.Errorf("pod %s: %w", podName, err)
					}
				}(pod.Name)
			}

			// Close the error channel once all goroutines finish so the
			// range below terminates.
			go func() {
				wg.Wait()
				close(errCh)
			}()

			// Collect and report errors without hiding successful pods.
			var errs []error
			for err := range errCh {
				errs = append(errs, err)
			}
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "error: %v\n", e)
				}
				return fmt.Errorf("log streaming finished with %d error(s)", len(errs))
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().Int64Var(&tailLines, "tail", 100, "Number of lines to show")

	return cmd
}

// streamPodLogs opens a log stream for a single pod and writes each line to
// stdout prefixed with the pod name. It returns nil on normal EOF.
func streamPodLogs(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	ns, podName string,
	follow bool,
	tailLines int64,
) error {
	opts := &corev1.PodLogOptions{
		Follow:    follow,
		TailLines: &tailLines,
	}

	req := clientset.CoreV1().Pods(ns).GetLogs(podName, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to open log stream: %w", err)
	}
	defer stream.Close()

	prefix := fmt.Sprintf("[%s] ", podName)
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		fmt.Printf("%s%s\n", prefix, scanner.Text())
	}

	return scanner.Err()
}

// newDiagnoseCmd creates the diagnose subcommand — runs the AI agent interactively.
func newDiagnoseCmd() *cobra.Command {
	var (
		ollamaURL   string
		ollamaModel string
		dryRun      bool
		autoApprove bool
	)

	cmd := &cobra.Command{
		Use:   "diagnose [app-name]",
		Short: "Run AI-powered diagnostics and self-healing on an application",
		Long: `Runs an AI agent (via Ollama) to diagnose and fix issues with a managed application.
The agent investigates pod events and logs, then takes corrective actions.
You will be prompted to approve any write operations unless --auto-approve is set.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appName := args[0]

			if ollamaURL == "" {
				ollamaURL = os.Getenv("OLLAMA_URL")
			}
			if ollamaURL == "" {
				return fmt.Errorf("--ollama-url or OLLAMA_URL env var is required")
			}

			ctx := context.Background()

			// Build Kubernetes clients.
			restConfig, err := buildRestConfig()
			if err != nil {
				return fmt.Errorf("build kubeconfig: %w", err)
			}
			clientset, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return fmt.Errorf("create clientset: %w", err)
			}

			scheme := runtime.NewScheme()
			clientgoscheme.AddToScheme(scheme)   //nolint:errcheck
			agentv1alpha1.AddToScheme(scheme)    //nolint:errcheck
			crClient, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: scheme})
			if err != nil {
				return fmt.Errorf("create controller-runtime client: %w", err)
			}

			// Find unhealthy pods for this app.
			labelSelector := fmt.Sprintf("agent.kubeagent.io/app=%s", appName)
			pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				return fmt.Errorf("list pods for %s: %w", appName, err)
			}
			if len(pods.Items) == 0 {
				return fmt.Errorf("no pods found for application %q (label %s)", appName, labelSelector)
			}

			unhealthy := filterUnhealthyPods(pods.Items)
			if len(unhealthy) == 0 {
				fmt.Printf("All pods for %q appear healthy. Run 'kube-agent logs %s' to inspect further.\n",
					appName, appName)
				return nil
			}

			fmt.Printf("Found %d unhealthy pod(s) for %q. Starting AI diagnosis...\n\n", len(unhealthy), appName)

			// Build the remediator with interactive confirmation.
			remediator := agent.NewRemediator(
				ollamaURL, ollamaModel,
				crClient, clientset,
				nil, // nil = all write tools permitted (gated by confirm below)
				dryRun,
			)
			remediator.Output = os.Stdout

			if !autoApprove {
				remediator.SetConfirmFn(func(toolName, description string) bool {
					fmt.Printf("\n  ⚠  Write operation: %s\n  Proceed? [y/N]: ", description)
					var input string
					fmt.Scanln(&input)
					return strings.ToLower(strings.TrimSpace(input)) == "y"
				})
			}

			for i := range unhealthy {
				pod := &unhealthy[i]
				issue := detectIssue(pod)
				if err := remediator.Remediate(ctx, pod, issue); err != nil {
					fmt.Fprintf(os.Stderr, "error remediating %s: %v\n", pod.Name, err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama base URL (or set OLLAMA_URL env var)")
	cmd.Flags().StringVar(&ollamaModel, "ollama-model", "", "Ollama model (default: "+agent.DefaultModel+")")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what the agent would do without executing writes")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "Execute write operations without confirmation prompts")

	return cmd
}

// filterUnhealthyPods returns pods that are not fully running/ready.
func filterUnhealthyPods(pods []corev1.Pod) []corev1.Pod {
	var unhealthy []corev1.Pod
	for _, pod := range pods {
		if pod.Status.Phase == corev1.PodPending || pod.Status.Phase == corev1.PodFailed {
			unhealthy = append(unhealthy, pod)
			continue
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil || !cs.Ready {
				unhealthy = append(unhealthy, pod)
				break
			}
		}
	}
	return unhealthy
}

// detectIssue constructs a basic IssueContext from pod status for the initial agent message.
func detectIssue(pod *corev1.Pod) agent.IssueContext {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			return agent.IssueContext{
				Type:      cs.State.Waiting.Reason,
				Container: cs.Name,
				Message:   cs.State.Waiting.Message,
			}
		}
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
			return agent.IssueContext{
				Type:    cond.Reason,
				Message: cond.Message,
			}
		}
	}
	return agent.IssueContext{
		Type:    string(pod.Status.Phase),
		Message: pod.Status.Message,
	}
}

// buildRestConfig builds a REST config from (in priority order):
// 1. --kubeconfig flag
// 2. KUBECONFIG env var
// 3. ~/.kube/config
// 4. in-cluster config (when running inside a pod)
func buildRestConfig() (*rest.Config, error) {
	// Explicit flag takes priority.
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	// Use default loading rules: respects KUBECONFIG env var and ~/.kube/config.
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, &clientcmd.ConfigOverrides{})
	if config, err := clientConfig.ClientConfig(); err == nil {
		return config, nil
	}
	// Last resort: in-cluster config when running as a pod.
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("no kubeconfig found — pass --kubeconfig, set KUBECONFIG env var, or run inside a cluster")
	}
	return config, nil
}

// Helper functions

func getDynamicClient() (dynamic.Interface, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		// Try in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	return dynamic.NewForConfig(config)
}

func getClientset() (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(config)
}

func buildManagedApplication(name, ns, sourceType string, opts map[string]interface{}) *unstructured.Unstructured {
	app := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "agent.kubeagent.io/v1alpha1",
			"kind":       "ManagedApplication",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": ns,
			},
			"spec": map[string]interface{}{
				"source":     buildSource(sourceType, opts),
				"deployment": buildDeployment(opts),
			},
		},
	}

	// Add public access if host specified
	if host, ok := opts["host"].(string); ok && host != "" {
		publicAccess := map[string]interface{}{
			"enabled": true,
			"host":    host,
			"port":    int64(80),
		}
		if tls, ok := opts["tlsEnabled"].(bool); ok && tls {
			publicAccess["tls"] = map[string]interface{}{
				"enabled": true,
				"issuer":  "letsencrypt-prod",
			}
		}
		unstructured.SetNestedMap(app.Object, publicAccess, "spec", "publicAccess")
	}

	// Add security settings
	if scan, ok := opts["scanEnabled"].(bool); ok && scan {
		security := map[string]interface{}{
			"vulnerabilityScanning": map[string]interface{}{
				"enabled":           true,
				"schedule":          "0 */6 * * *",
				"severityThreshold": "MEDIUM",
				"autoBlock":         true,
			},
		}
		unstructured.SetNestedMap(app.Object, security, "spec", "security")
	}

	// Add self-healing
	if heal, ok := opts["selfHealing"].(bool); ok && heal {
		selfHealing := map[string]interface{}{
			"enabled":              true,
			"maxRetries":           int64(3),
			"diagnosticCollection": true,
			"autoRestart":          true,
		}
		unstructured.SetNestedMap(app.Object, selfHealing, "spec", "selfHealing")
	}

	return app
}

func buildSource(sourceType string, opts map[string]interface{}) map[string]interface{} {
	source := map[string]interface{}{
		"type": sourceType,
	}

	switch sourceType {
	case "docker":
		if image, ok := opts["image"].(string); ok {
			source["image"] = image
		}
	case "git":
		if repo, ok := opts["gitRepo"].(string); ok {
			source["repository"] = repo
		}
		if path, ok := opts["gitPath"].(string); ok {
			source["path"] = path
		}
		if branch, ok := opts["gitBranch"].(string); ok {
			source["branch"] = branch
		}
	case "helm":
		if chart, ok := opts["helmChart"].(string); ok {
			source["chart"] = chart
		}
		if version, ok := opts["helmVersion"].(string); ok {
			source["chartVersion"] = version
		}
	}

	return source
}

func buildDeployment(opts map[string]interface{}) map[string]interface{} {
	deploy := map[string]interface{}{
		"autoRollback": true,
	}

	if strategy, ok := opts["strategy"].(string); ok {
		deploy["strategy"] = strategy
	}

	if replicas, ok := opts["replicas"].(int32); ok {
		deploy["replicas"] = int64(replicas)
	}

	return deploy
}
