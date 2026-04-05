package types

// ScanResult contains vulnerability scan results
type ScanResult struct {
	Image           string
	Counts          map[string]int32
	Vulnerabilities []VulnerabilityInfo
}

// VulnerabilityInfo contains vulnerability details
type VulnerabilityInfo struct {
	ID             string
	Package        string
	CurrentVersion string
	FixedVersion   string
	Severity       string
	Title          string
	Description    string
}
