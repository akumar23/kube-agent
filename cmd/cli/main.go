package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
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
			fmt.Printf("Fetching logs for %s...\n", name)

			// TODO: Implement log streaming
			fmt.Println("Log streaming not yet implemented")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().Int64Var(&tailLines, "tail", 100, "Number of lines to show")

	return cmd
}

// newDiagnoseCmd creates the diagnose subcommand
func newDiagnoseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnose [name]",
		Short: "Run diagnostics on an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			fmt.Printf("Running diagnostics for %s...\n\n", name)

			// TODO: Implement diagnostics
			fmt.Println("Diagnostics not yet implemented")

			return nil
		},
	}

	return cmd
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
