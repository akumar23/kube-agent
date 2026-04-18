package main

import (
	"context"
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
	"github.com/kube-agent/kube-agent/pkg/agent"
	"github.com/kube-agent/kube-agent/pkg/controllers/deployment"
	"github.com/kube-agent/kube-agent/pkg/controllers/diagnostic"
	"github.com/kube-agent/kube-agent/pkg/controllers/security"
	"github.com/kube-agent/kube-agent/pkg/controllers/selfheal"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(agentv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var enableSelfHealing bool
	var enableSecurityScanning bool
	var ollamaURL string
	var ollamaModel string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&ollamaURL, "ollama-url", os.Getenv("OLLAMA_URL"), "Ollama base URL for AI-powered remediation (e.g. https://host/)")
	flag.StringVar(&ollamaModel, "ollama-model", os.Getenv("OLLAMA_MODEL"), "Ollama model to use (default: "+agent.DefaultModel+")")
	// Default to true: running without leader election in multi-replica deployments
	// risks two controllers acting on the same resources simultaneously.
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableSelfHealing, "enable-self-healing", true, "Enable self-healing controller")
	flag.BoolVar(&enableSecurityScanning, "enable-security-scanning", true, "Enable security scanning controller")

	// Default Development to false for production-appropriate JSON log output.
	// Pass --zap-devel to enable human-readable development mode logging.
	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "kube-agent.kubeagent.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup Deployment Controller
	if err = (&deployment.ManagedApplicationReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("managed-application-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ManagedApplication")
		os.Exit(1)
	}

	// Setup Security Controller
	if enableSecurityScanning {
		if err = (&security.SecurityScanReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("security-scan-controller"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "SecurityScan")
			os.Exit(1)
		}

		if err = (&security.SecurityReportReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("security-report-controller"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "SecurityReport")
			os.Exit(1)
		}
	}

	// Setup Self-Healing Controller
	if enableSelfHealing {
		// Build an AI remediator if an Ollama URL is configured.
		var agentRemediator *agent.Remediator
		if ollamaURL != "" {
			clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
			if err != nil {
				setupLog.Error(err, "unable to create clientset for agent remediator")
				os.Exit(1)
			}
			agentRemediator = agent.NewRemediator(ollamaURL, ollamaModel,
				mgr.GetClient(), clientset, nil, false)
			setupLog.Info("AI agent remediator enabled", "url", ollamaURL, "model", func() string {
				if ollamaModel != "" {
					return ollamaModel
				}
				return agent.DefaultModel
			}())
		}

		if err = (&selfheal.RemediationReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("remediation-controller"),
			Agent:    agentRemediator,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Remediation")
			os.Exit(1)
		}

		// Build a native Kubernetes clientset from the manager's REST config so that
		// the DiagnosticReconciler can fetch raw pod logs (not available via the
		// controller-runtime client).
		clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			setupLog.Error(err, "unable to create kubernetes clientset for diagnostic controller")
			os.Exit(1)
		}

		if err = (&diagnostic.DiagnosticReconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			Recorder:  mgr.GetEventRecorderFor("diagnostic-controller"),
			Clientset: clientset,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Diagnostic")
			os.Exit(1)
		}
	}

	// Register a context-aware field indexer for events so the DiagnosticReconciler
	// can query events by involvedObject.name without a cluster-wide list.
	// This must happen before mgr.Start(), which is guaranteed since SetupWithManager
	// also calls IndexField; this block is intentionally left as documentation.
	_ = context.Background() // imported for potential future use

	// Setup health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
