package deployment

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// FinalizerName is the finalizer added to ManagedApplication resources.
// Exported so other packages (e.g., tests, other controllers) can reference it.
const FinalizerName = "agent.kubeagent.io/finalizer"

// ManagedApplicationReconciler reconciles a ManagedApplication object
type ManagedApplicationReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Log      logr.Logger
}

// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agent.kubeagent.io,resources=managedapplications/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for ManagedApplication
func (r *ManagedApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("managedapplication", req.NamespacedName)

	// Fetch the ManagedApplication instance
	app := &agentv1alpha1.ManagedApplication{}
	if err := r.Get(ctx, req.NamespacedName, app); err != nil {
		if errors.IsNotFound(err) {
			log.Info("ManagedApplication resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get ManagedApplication")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !app.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, app, log)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(app, FinalizerName) {
		controllerutil.AddFinalizer(app, FinalizerName)
		if err := r.Update(ctx, app); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Determine target namespace
	targetNS := app.Spec.TargetNamespace
	if targetNS == "" {
		targetNS = app.Namespace
	}

	// Update status to deploying
	if app.Status.Phase != agentv1alpha1.ApplicationPhaseDeploying {
		app.Status.Phase = agentv1alpha1.ApplicationPhaseDeploying
		if err := r.Status().Update(ctx, app); err != nil {
			return ctrl.Result{}, err
		}
		r.Recorder.Event(app, corev1.EventTypeNormal, "Deploying", "Starting deployment")
	}

	// Reconcile based on source type
	var reconcileErr error
	switch app.Spec.Source.Type {
	case agentv1alpha1.SourceTypeDocker:
		reconcileErr = r.reconcileDockerSource(ctx, app, targetNS, log)
	case agentv1alpha1.SourceTypeGit:
		reconcileErr = r.reconcileGitSource(ctx, app, targetNS, log)
	case agentv1alpha1.SourceTypeHelm:
		reconcileErr = r.reconcileHelmSource(ctx, app, targetNS, log)
	default:
		reconcileErr = fmt.Errorf("unsupported source type: %s", app.Spec.Source.Type)
	}

	if reconcileErr != nil {
		log.Error(reconcileErr, "Failed to reconcile source")
		app.Status.Phase = agentv1alpha1.ApplicationPhaseFailed
		app.Status.Message = reconcileErr.Error()
		if statusErr := r.Status().Update(ctx, app); statusErr != nil {
			log.Error(statusErr, "Failed to update status")
		}
		r.Recorder.Event(app, corev1.EventTypeWarning, "DeployFailed", reconcileErr.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Reconcile public access (Ingress)
	if app.Spec.PublicAccess.Enabled {
		if err := r.reconcileIngress(ctx, app, targetNS, log); err != nil {
			log.Error(err, "Failed to reconcile ingress")
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
	}

	// For Docker source, verify the Deployment rollout is complete before marking Running.
	// Git and Helm sources are managed externally (ArgoCD/Flux) so we trust their status.
	if app.Spec.Source.Type == agentv1alpha1.SourceTypeDocker {
		deploy := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: app.Name, Namespace: targetNS}, deploy); err == nil {
			desiredReplicas := int32(1)
			if deploy.Spec.Replicas != nil {
				desiredReplicas = *deploy.Spec.Replicas
			}
			if deploy.Status.ReadyReplicas < desiredReplicas || deploy.Status.UnavailableReplicas > 0 {
				app.Status.Phase = agentv1alpha1.ApplicationPhaseDeploying
				app.Status.Health = "Progressing"
				if err := r.Status().Update(ctx, app); err != nil {
					return ctrl.Result{}, err
				}
				// Requeue to check again once the rollout progresses
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}
	}

	// Update status to running
	app.Status.Phase = agentv1alpha1.ApplicationPhaseRunning
	app.Status.Health = "Healthy"
	app.Status.LastDeployedAt = &metav1.Time{Time: time.Now()}

	if app.Spec.PublicAccess.Enabled && app.Spec.PublicAccess.Host != "" {
		protocol := "http"
		if app.Spec.PublicAccess.TLS != nil && app.Spec.PublicAccess.TLS.Enabled {
			protocol = "https"
		}
		app.Status.PublicURL = fmt.Sprintf("%s://%s", protocol, app.Spec.PublicAccess.Host)
	}

	if err := r.Status().Update(ctx, app); err != nil {
		return ctrl.Result{}, err
	}

	r.Recorder.Event(app, corev1.EventTypeNormal, "Deployed", "Application deployed successfully")
	log.Info("Successfully reconciled ManagedApplication", "publicURL", app.Status.PublicURL)

	// Requeue periodically to check deployment health
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// reconcileDockerSource handles Docker image deployments
func (r *ManagedApplicationReconciler) reconcileDockerSource(ctx context.Context, app *agentv1alpha1.ManagedApplication, namespace string, log logr.Logger) error {
	log.Info("Reconciling Docker source", "image", app.Spec.Source.Image)

	// Create or update Deployment
	deploy := r.buildDeployment(app, namespace)
	if err := r.createOrUpdateDeployment(ctx, app, deploy, log); err != nil {
		return fmt.Errorf("failed to reconcile deployment: %w", err)
	}

	// Create or update Service
	svc := r.buildService(app, namespace)
	if err := r.createOrUpdateService(ctx, app, svc, log); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	return nil
}

// reconcileGitSource handles Git repository deployments via ArgoCD
func (r *ManagedApplicationReconciler) reconcileGitSource(ctx context.Context, app *agentv1alpha1.ManagedApplication, namespace string, log logr.Logger) error {
	log.Info("Reconciling Git source", "repository", app.Spec.Source.Repository)

	// TODO: Integrate with ArgoCD Application CRD
	// For now, we'll create a placeholder that logs the intent
	// In production, this would:
	// 1. Create an ArgoCD Application CR pointing to the git repo
	// 2. Configure sync policy based on deployment strategy
	// 3. Monitor sync status

	r.Recorder.Event(app, corev1.EventTypeNormal, "GitSync",
		fmt.Sprintf("Would sync from %s (path: %s, branch: %s)",
			app.Spec.Source.Repository,
			app.Spec.Source.Path,
			app.Spec.Source.Branch))

	return nil
}

// reconcileHelmSource handles Helm chart deployments
func (r *ManagedApplicationReconciler) reconcileHelmSource(ctx context.Context, app *agentv1alpha1.ManagedApplication, namespace string, log logr.Logger) error {
	log.Info("Reconciling Helm source", "chart", app.Spec.Source.Chart)

	// TODO: Integrate with Helm operator or ArgoCD
	// In production, this would:
	// 1. Create a HelmRelease CR (for Flux) or ArgoCD Application
	// 2. Pass values from app.Spec.Source.Values
	// 3. Monitor release status

	r.Recorder.Event(app, corev1.EventTypeNormal, "HelmSync",
		fmt.Sprintf("Would install chart %s version %s",
			app.Spec.Source.Chart,
			app.Spec.Source.ChartVersion))

	return nil
}

// buildDeployment creates a Deployment spec for the application
func (r *ManagedApplicationReconciler) buildDeployment(app *agentv1alpha1.ManagedApplication, namespace string) *appsv1.Deployment {
	lbls := map[string]string{
		"app.kubernetes.io/name":       app.Name,
		"app.kubernetes.io/managed-by": "kube-agent",
		"agent.kubeagent.io/app":       app.Name,
	}

	replicas := app.Spec.Deployment.Replicas
	if replicas == 0 {
		replicas = 1
	}

	// Resolve the container port - fall back to 8080 when not explicitly set.
	containerPort := app.Spec.PublicAccess.Port
	if containerPort == 0 {
		containerPort = 8080
	}

	container := corev1.Container{
		Name:    "app",
		Image:   app.Spec.Source.Image,
		Command: app.Spec.Source.Command,
		Args:    app.Spec.Source.Args,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: containerPort,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		// Resource limits for safety
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    mustParseQuantity("100m"),
				corev1.ResourceMemory: mustParseQuantity("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    mustParseQuantity("500m"),
				corev1.ResourceMemory: mustParseQuantity("512Mi"),
			},
		},
	}

	// Only attach HTTP health probes when public access is enabled with a valid port.
	// Without a known HTTP endpoint the probes would always fail.
	if app.Spec.PublicAccess.Enabled && app.Spec.PublicAccess.Port > 0 {
		probePort := intstr.FromInt(int(app.Spec.PublicAccess.Port))
		container.LivenessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: probePort,
				},
			},
			InitialDelaySeconds: 15,
			PeriodSeconds:       10,
			FailureThreshold:    3,
		}
		container.ReadinessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: probePort,
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       5,
			FailureThreshold:    3,
		}
	}

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.Name,
			Namespace: namespace,
			Labels:    lbls,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: lbls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: lbls,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{container},
				},
			},
		},
	}

	return deploy
}

// buildService creates a Service spec for the application
func (r *ManagedApplicationReconciler) buildService(app *agentv1alpha1.ManagedApplication, namespace string) *corev1.Service {
	lbls := map[string]string{
		"app.kubernetes.io/name":       app.Name,
		"app.kubernetes.io/managed-by": "kube-agent",
	}

	port := app.Spec.PublicAccess.Port
	if port == 0 {
		port = 80
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.Name,
			Namespace: namespace,
			Labels:    lbls,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"agent.kubeagent.io/app": app.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

// reconcileIngress creates or updates the Ingress for public access
func (r *ManagedApplicationReconciler) reconcileIngress(ctx context.Context, app *agentv1alpha1.ManagedApplication, namespace string, log logr.Logger) error {
	if app.Spec.PublicAccess.Host == "" {
		log.Info("No host specified for public access, skipping ingress")
		return nil
	}

	desired := r.buildIngress(app, namespace)

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	op, err := controllerutil.CreateOrPatch(ctx, r.Client, ingress, func() error {
		if err := controllerutil.SetControllerReference(app, ingress, r.Scheme); err != nil {
			return err
		}
		// Merge labels (ours take precedence)
		if ingress.Labels == nil {
			ingress.Labels = desired.Labels
		} else {
			for k, v := range desired.Labels {
				ingress.Labels[k] = v
			}
		}
		// Merge annotations (ours take precedence)
		if ingress.Annotations == nil {
			ingress.Annotations = desired.Annotations
		} else {
			for k, v := range desired.Annotations {
				ingress.Annotations[k] = v
			}
		}
		ingress.Spec = desired.Spec
		return nil
	})
	if err != nil {
		return err
	}
	if op != controllerutil.OperationResultNone {
		log.Info("Ingress reconciled", "operation", op, "name", ingress.Name, "host", app.Spec.PublicAccess.Host)
	}
	return nil
}

// buildIngress creates an Ingress spec for the application
func (r *ManagedApplicationReconciler) buildIngress(app *agentv1alpha1.ManagedApplication, namespace string) *networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix

	annotations := map[string]string{}

	// Use ingressClassName if specified, otherwise default to nginx
	ingressClass := app.Spec.PublicAccess.IngressClass
	if ingressClass == "" {
		ingressClass = "nginx"
	}

	// Add TLS annotations for cert-manager
	if app.Spec.PublicAccess.TLS != nil && app.Spec.PublicAccess.TLS.Enabled {
		issuer := app.Spec.PublicAccess.TLS.Issuer
		if issuer == "" {
			issuer = "letsencrypt-prod"
		}
		annotations["cert-manager.io/cluster-issuer"] = issuer
	}

	port := app.Spec.PublicAccess.Port
	if port == 0 {
		port = 80
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.Name,
			Namespace:   namespace,
			Annotations: annotations,
			Labels: map[string]string{
				"app.kubernetes.io/name":       app.Name,
				"app.kubernetes.io/managed-by": "kube-agent",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			Rules: []networkingv1.IngressRule{
				{
					Host: app.Spec.PublicAccess.Host,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: app.Name,
											Port: networkingv1.ServiceBackendPort{
												Number: port,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Add TLS configuration
	if app.Spec.PublicAccess.TLS != nil && app.Spec.PublicAccess.TLS.Enabled {
		secretName := app.Spec.PublicAccess.TLS.SecretName
		if secretName == "" {
			secretName = fmt.Sprintf("%s-tls", app.Name)
		}
		ingress.Spec.TLS = []networkingv1.IngressTLS{
			{
				Hosts:      []string{app.Spec.PublicAccess.Host},
				SecretName: secretName,
			},
		}
	}

	return ingress
}

// createOrUpdateDeployment creates or updates a Deployment using server-side patch semantics.
// Using CreateOrPatch avoids clobbering annotations or labels set by other controllers (e.g. HPA).
func (r *ManagedApplicationReconciler) createOrUpdateDeployment(ctx context.Context, app *agentv1alpha1.ManagedApplication, desired *appsv1.Deployment, log logr.Logger) error {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	op, err := controllerutil.CreateOrPatch(ctx, r.Client, deploy, func() error {
		if err := controllerutil.SetControllerReference(app, deploy, r.Scheme); err != nil {
			return err
		}
		// Merge labels (ours take precedence, external labels are preserved)
		if deploy.Labels == nil {
			deploy.Labels = desired.Labels
		} else {
			for k, v := range desired.Labels {
				deploy.Labels[k] = v
			}
		}
		deploy.Spec = desired.Spec
		return nil
	})
	if err != nil {
		return err
	}
	if op != controllerutil.OperationResultNone {
		log.Info("Deployment reconciled", "operation", op, "name", deploy.Name)
	}
	return nil
}

// createOrUpdateService creates or updates a Service using server-side patch semantics.
func (r *ManagedApplicationReconciler) createOrUpdateService(ctx context.Context, app *agentv1alpha1.ManagedApplication, desired *corev1.Service, log logr.Logger) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	op, err := controllerutil.CreateOrPatch(ctx, r.Client, svc, func() error {
		if err := controllerutil.SetControllerReference(app, svc, r.Scheme); err != nil {
			return err
		}
		if svc.Labels == nil {
			svc.Labels = desired.Labels
		} else {
			for k, v := range desired.Labels {
				svc.Labels[k] = v
			}
		}
		// Preserve the immutable ClusterIP field on updates
		desired.Spec.ClusterIP = svc.Spec.ClusterIP
		svc.Spec = desired.Spec
		return nil
	})
	if err != nil {
		return err
	}
	if op != controllerutil.OperationResultNone {
		log.Info("Service reconciled", "operation", op, "name", svc.Name)
	}
	return nil
}

// handleDeletion handles the deletion of a ManagedApplication
func (r *ManagedApplicationReconciler) handleDeletion(ctx context.Context, app *agentv1alpha1.ManagedApplication, log logr.Logger) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(app, FinalizerName) {
		log.Info("Handling deletion of ManagedApplication")
		r.Recorder.Event(app, corev1.EventTypeNormal, "Deleting", "Cleaning up resources")

		// Resources are cleaned up via OwnerReference cascading delete
		// Additional cleanup logic can be added here if needed

		controllerutil.RemoveFinalizer(app, FinalizerName)
		if err := r.Update(ctx, app); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *ManagedApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("ManagedApplication")

	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.ManagedApplication{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}

// mustParseQuantity parses a resource quantity string and panics on invalid input.
// Only called with compile-time constants so a panic here is a programming error.
func mustParseQuantity(s string) resource.Quantity {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		panic(fmt.Sprintf("invalid resource quantity %q: %v", s, err))
	}
	return q
}
