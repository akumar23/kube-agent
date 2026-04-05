package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/kube-agent/kube-agent/pkg/types"
)

// Scanner provides Trivy vulnerability scanning capabilities
type Scanner struct {
	Log        logr.Logger
	BinaryPath string
	CacheDir   string
	Timeout    time.Duration
}

// NewScanner creates a new Trivy scanner
func NewScanner() *Scanner {
	return &Scanner{
		Log:        ctrl.Log.WithName("trivy-scanner"),
		BinaryPath: "trivy",
		CacheDir:   "/tmp/trivy-cache",
		Timeout:    5 * time.Minute,
	}
}

// TrivyOutput represents the JSON output from Trivy
type TrivyOutput struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

// Result represents a Trivy scan result
type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Vulnerability represents a single vulnerability
type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
	CVSS             CVSS     `json:"CVSS"`
}

// CVSS represents CVSS scoring information
type CVSS struct {
	NVD    *CVSSScore `json:"nvd"`
	RedHat *CVSSScore `json:"redhat"`
}

// CVSSScore represents a CVSS score
type CVSSScore struct {
	V2Score float64 `json:"V2Score"`
	V3Score float64 `json:"V3Score"`
}

// Scan performs a vulnerability scan on the specified image
func (s *Scanner) Scan(ctx context.Context, image string) (*types.ScanResult, error) {
	s.Log.Info("Starting Trivy scan", "image", image)

	// Build Trivy command
	args := []string{
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--cache-dir", s.CacheDir,
		"--timeout", s.Timeout.String(),
		image,
	}

	// Create context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// Execute Trivy
	cmd := exec.CommandContext(scanCtx, s.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Check if it's a timeout
		if scanCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("trivy scan timed out after %v", s.Timeout)
		}
		// Trivy returns exit code 1 when vulnerabilities are found, which is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 1 {
			return nil, fmt.Errorf("trivy scan failed: %s", stderr.String())
		}
	}

	// Parse JSON output
	var output TrivyOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert to our result format
	result := &types.ScanResult{
		Image:  image,
		Counts: make(map[string]int32),
	}

	for _, res := range output.Results {
		for _, vuln := range res.Vulnerabilities {
			// Count by severity
			result.Counts[vuln.Severity]++

			// Add vulnerability info
			result.Vulnerabilities = append(result.Vulnerabilities, types.VulnerabilityInfo{
				ID:             vuln.VulnerabilityID,
				Package:        vuln.PkgName,
				CurrentVersion: vuln.InstalledVersion,
				FixedVersion:   vuln.FixedVersion,
				Severity:       vuln.Severity,
				Title:          vuln.Title,
				Description:    vuln.Description,
			})
		}
	}

	s.Log.Info("Trivy scan completed",
		"image", image,
		"critical", result.Counts["CRITICAL"],
		"high", result.Counts["HIGH"],
		"medium", result.Counts["MEDIUM"],
		"low", result.Counts["LOW"])

	return result, nil
}

// ScanFilesystem scans a filesystem path for vulnerabilities
func (s *Scanner) ScanFilesystem(ctx context.Context, path string) (*types.ScanResult, error) {
	s.Log.Info("Starting Trivy filesystem scan", "path", path)

	args := []string{
		"fs",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--cache-dir", s.CacheDir,
		"--timeout", s.Timeout.String(),
		path,
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("trivy scan timed out after %v", s.Timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 1 {
			return nil, fmt.Errorf("trivy scan failed: %s", stderr.String())
		}
	}

	var output TrivyOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	result := &types.ScanResult{
		Image:  path,
		Counts: make(map[string]int32),
	}

	for _, res := range output.Results {
		for _, vuln := range res.Vulnerabilities {
			result.Counts[vuln.Severity]++
			result.Vulnerabilities = append(result.Vulnerabilities, types.VulnerabilityInfo{
				ID:             vuln.VulnerabilityID,
				Package:        vuln.PkgName,
				CurrentVersion: vuln.InstalledVersion,
				FixedVersion:   vuln.FixedVersion,
				Severity:       vuln.Severity,
				Title:          vuln.Title,
				Description:    vuln.Description,
			})
		}
	}

	return result, nil
}

// ScanConfig scans Kubernetes manifests for misconfigurations
func (s *Scanner) ScanConfig(ctx context.Context, path string) (*ConfigScanResult, error) {
	s.Log.Info("Starting Trivy config scan", "path", path)

	args := []string{
		"config",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		path,
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("trivy scan timed out after %v", s.Timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 1 {
			return nil, fmt.Errorf("trivy config scan failed: %s", stderr.String())
		}
	}

	// Parse and return config scan results
	result := &ConfigScanResult{
		Misconfigurations: make(map[string]int32),
	}

	// TODO: Parse actual Trivy config output
	return result, nil
}

// ConfigScanResult contains configuration scan results
type ConfigScanResult struct {
	Misconfigurations map[string]int32
	Findings          []ConfigFinding
}

// ConfigFinding represents a single configuration issue
type ConfigFinding struct {
	Type        string
	ID          string
	Title       string
	Description string
	Severity    string
	Resolution  string
	Resource    string
}

// GenerateSBOM generates a Software Bill of Materials for an image
func (s *Scanner) GenerateSBOM(ctx context.Context, image string) ([]byte, error) {
	s.Log.Info("Generating SBOM", "image", image)

	args := []string{
		"image",
		"--format", "cyclonedx",
		"--cache-dir", s.CacheDir,
		image,
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %s", stderr.String())
	}

	return stdout.Bytes(), nil
}
