package deployment

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	agentv1alpha1 "github.com/kube-agent/kube-agent/pkg/apis/v1alpha1"
)

// TestBuildDeployment_WithPublicAccess verifies that HTTP health probes are
// added when publicAccess is enabled with a valid port.
func TestBuildDeployment_WithPublicAccess(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			Source: agentv1alpha1.ApplicationSource{
				Image: "nginx:latest",
			},
			PublicAccess: agentv1alpha1.PublicAccessSpec{
				Enabled: true,
				Port:    8080,
			},
		},
	}
	app.Name = "test-app"

	deploy := r.buildDeployment(app, "default")

	containers := deploy.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	c := containers[0]

	if c.LivenessProbe == nil {
		t.Error("expected liveness probe to be set when publicAccess is enabled")
	}
	if c.ReadinessProbe == nil {
		t.Error("expected readiness probe to be set when publicAccess is enabled")
	}

	expectedPort := intstr.FromInt(8080)
	if c.LivenessProbe.HTTPGet.Port != expectedPort {
		t.Errorf("expected liveness probe port 8080, got %v", c.LivenessProbe.HTTPGet.Port)
	}
}

// TestBuildDeployment_WithoutPublicAccess verifies that health probes are NOT
// added when publicAccess is disabled, preventing port-0 probe failures.
func TestBuildDeployment_WithoutPublicAccess(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			Source: agentv1alpha1.ApplicationSource{
				Image: "my-worker:latest",
			},
			PublicAccess: agentv1alpha1.PublicAccessSpec{
				Enabled: false,
			},
		},
	}
	app.Name = "worker-app"

	deploy := r.buildDeployment(app, "default")

	containers := deploy.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	c := containers[0]

	if c.LivenessProbe != nil {
		t.Error("liveness probe must be nil when publicAccess is disabled (port 0 would be invalid)")
	}
	if c.ReadinessProbe != nil {
		t.Error("readiness probe must be nil when publicAccess is disabled")
	}
}

// TestBuildDeployment_DefaultReplicas verifies that replicas default to 1 when
// not explicitly set.
func TestBuildDeployment_DefaultReplicas(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			Source: agentv1alpha1.ApplicationSource{Image: "test:v1"},
		},
	}
	app.Name = "test-app"

	deploy := r.buildDeployment(app, "default")

	if deploy.Spec.Replicas == nil || *deploy.Spec.Replicas != 1 {
		t.Errorf("expected default replicas = 1, got %v", deploy.Spec.Replicas)
	}
}

// TestBuildDeployment_AgentLabel verifies the kube-agent pod label is present
// (required for self-healing and diagnostic controllers to identify managed pods).
func TestBuildDeployment_AgentLabel(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			Source: agentv1alpha1.ApplicationSource{Image: "test:v1"},
		},
	}
	app.Name = "my-app"

	deploy := r.buildDeployment(app, "default")

	podLabels := deploy.Spec.Template.ObjectMeta.Labels
	if podLabels["agent.kubeagent.io/app"] != "my-app" {
		t.Errorf("expected pod label agent.kubeagent.io/app=my-app, got %q", podLabels["agent.kubeagent.io/app"])
	}
}

// TestBuildService_DefaultPort verifies that service port defaults to 80 when
// not specified.
func TestBuildService_DefaultPort(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			PublicAccess: agentv1alpha1.PublicAccessSpec{Port: 0},
		},
	}
	app.Name = "test-app"

	svc := r.buildService(app, "default")

	if len(svc.Spec.Ports) != 1 {
		t.Fatalf("expected 1 service port, got %d", len(svc.Spec.Ports))
	}
	if svc.Spec.Ports[0].Port != 80 {
		t.Errorf("expected default service port 80, got %d", svc.Spec.Ports[0].Port)
	}
}

// TestBuildService_ExplicitPort verifies that an explicitly set port is used.
func TestBuildService_ExplicitPort(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			PublicAccess: agentv1alpha1.PublicAccessSpec{Port: 3000},
		},
	}
	app.Name = "test-app"

	svc := r.buildService(app, "default")
	if svc.Spec.Ports[0].Port != 3000 {
		t.Errorf("expected port 3000, got %d", svc.Spec.Ports[0].Port)
	}
}

// TestBuildIngress_TLS verifies that TLS is configured when enabled.
func TestBuildIngress_TLS(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			PublicAccess: agentv1alpha1.PublicAccessSpec{
				Enabled: true,
				Host:    "example.com",
				Port:    443,
				TLS: &agentv1alpha1.TLSSpec{
					Enabled:    true,
					SecretName: "example-tls",
				},
			},
		},
	}
	app.Name = "test-app"

	ingress := r.buildIngress(app, "default")

	if len(ingress.Spec.TLS) == 0 {
		t.Fatal("expected TLS to be configured on ingress")
	}
	if ingress.Spec.TLS[0].SecretName != "example-tls" {
		t.Errorf("expected TLS secret name 'example-tls', got %q", ingress.Spec.TLS[0].SecretName)
	}
	if _, ok := ingress.Annotations["cert-manager.io/cluster-issuer"]; !ok {
		t.Error("expected cert-manager.io/cluster-issuer annotation to be set")
	}
}

// TestBuildIngress_DefaultTLSSecretName verifies the default TLS secret name
// follows the <app-name>-tls convention.
func TestBuildIngress_DefaultTLSSecretName(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			PublicAccess: agentv1alpha1.PublicAccessSpec{
				Enabled: true,
				Host:    "example.com",
				TLS:     &agentv1alpha1.TLSSpec{Enabled: true},
			},
		},
	}
	app.Name = "my-app"

	ingress := r.buildIngress(app, "default")

	if len(ingress.Spec.TLS) == 0 {
		t.Fatal("expected TLS config")
	}
	if ingress.Spec.TLS[0].SecretName != "my-app-tls" {
		t.Errorf("expected default secret name 'my-app-tls', got %q", ingress.Spec.TLS[0].SecretName)
	}
}

// TestMustParseQuantity_ValidInput verifies that valid quantity strings parse
// without panicking.
func TestMustParseQuantity_ValidInput(t *testing.T) {
	cases := []string{"100m", "500m", "128Mi", "512Mi", "1Gi", "2"}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("mustParseQuantity(%q) panicked: %v", tc, r)
				}
			}()
			q := mustParseQuantity(tc)
			if q.IsZero() {
				t.Errorf("mustParseQuantity(%q) returned zero quantity", tc)
			}
		})
	}
}

// TestBuildDeployment_ResourceRequirements verifies that resource requests and
// limits are set on the container.
func TestBuildDeployment_ResourceRequirements(t *testing.T) {
	r := &ManagedApplicationReconciler{}
	app := &agentv1alpha1.ManagedApplication{
		Spec: agentv1alpha1.ManagedApplicationSpec{
			Source: agentv1alpha1.ApplicationSource{Image: "test:v1"},
		},
	}
	app.Name = "test-app"

	deploy := r.buildDeployment(app, "default")
	c := deploy.Spec.Template.Spec.Containers[0]

	if c.Resources.Requests == nil {
		t.Error("expected resource requests to be set")
	}
	if c.Resources.Limits == nil {
		t.Error("expected resource limits to be set")
	}
	cpu := c.Resources.Requests[corev1.ResourceCPU]
	if cpu.IsZero() {
		t.Error("expected non-zero CPU request")
	}
	mem := c.Resources.Requests[corev1.ResourceMemory]
	if mem.IsZero() {
		t.Error("expected non-zero memory request")
	}
}
