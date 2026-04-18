package executor

import (
	"fmt"
	"strings"
	"time"
)

// CountSuccessful returns the number of results without errors.
func CountSuccessful(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Error == nil {
			n++
		}
	}
	return n
}

// CountFailed returns the number of results with errors.
func CountFailed(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Error != nil {
			n++
		}
	}
	return n
}

// FilterSuccessful returns only results without errors.
func FilterSuccessful(results []Result) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if r.Error == nil {
			out = append(out, r)
		}
	}
	return out
}

// FilterFailed returns only results with errors.
func FilterFailed(results []Result) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if r.Error != nil {
			out = append(out, r)
		}
	}
	return out
}

// GetErrors returns the errors from all failed results.
func GetErrors(results []Result) []error {
	errs := make([]error, 0)
	for _, r := range results {
		if r.Error != nil {
			errs = append(errs, r.Error)
		}
	}
	return errs
}

// HasErrors returns true if any result has an error.
func HasErrors(results []Result) bool {
	for _, r := range results {
		if r.Error != nil {
			return true
		}
	}
	return false
}

// AllSuccessful returns true if every result is successful.
func AllSuccessful(results []Result) bool {
	return !HasErrors(results)
}

// SuccessRate returns the percentage of successful results (0–100).
func SuccessRate(results []Result) float64 {
	if len(results) == 0 {
		return 0
	}
	return float64(CountSuccessful(results)) / float64(len(results)) * 100
}

// FailureRate returns the percentage of failed results (0–100).
func FailureRate(results []Result) float64 {
	if len(results) == 0 {
		return 0
	}
	return float64(CountFailed(results)) / float64(len(results)) * 100
}

// AverageDuration returns the mean task duration.
func AverageDuration(results []Result) time.Duration {
	if len(results) == 0 {
		return 0
	}
	var total time.Duration
	for _, r := range results {
		total += r.Duration
	}
	return total / time.Duration(len(results))
}

// MaxDuration returns the longest task duration.
func MaxDuration(results []Result) time.Duration {
	if len(results) == 0 {
		return 0
	}
	max := results[0].Duration
	for _, r := range results[1:] {
		if r.Duration > max {
			max = r.Duration
		}
	}
	return max
}

// Summary holds aggregate statistics for a set of results.
type Summary struct {
	Total       int
	Successful  int
	Failed      int
	AvgDuration time.Duration
	MaxDuration time.Duration
}

// String returns a one-line description of the summary.
func (s Summary) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("total=%d successful=%d failed=%d", s.Total, s.Successful, s.Failed))
	if s.Total > 0 {
		sb.WriteString(fmt.Sprintf(" avg=%s max=%s",
			s.AvgDuration.Round(time.Millisecond),
			s.MaxDuration.Round(time.Millisecond)))
	}
	return sb.String()
}

// Summarize returns aggregate statistics for the results.
func Summarize(results []Result) Summary {
	return Summary{
		Total:       len(results),
		Successful:  CountSuccessful(results),
		Failed:      CountFailed(results),
		AvgDuration: AverageDuration(results),
		MaxDuration: MaxDuration(results),
	}
}
