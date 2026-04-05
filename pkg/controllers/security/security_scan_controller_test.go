package security

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestNextScheduleTime verifies that a valid cron expression produces a future
// time, and that an invalid expression falls back to the provided duration.
func TestNextScheduleTime(t *testing.T) {
	t.Run("valid cron expression", func(t *testing.T) {
		// "0 */6 * * *" runs every 6 hours — the next run must be in the future
		next := nextScheduleTime("0 */6 * * *", 6*time.Hour)
		if !next.After(time.Now()) {
			t.Errorf("expected a future time, got %v", next)
		}
		// And no more than 6 hours ahead
		if next.After(time.Now().Add(7 * time.Hour)) {
			t.Errorf("next schedule time is too far in the future: %v", next)
		}
	})

	t.Run("invalid cron expression falls back", func(t *testing.T) {
		fallback := 3 * time.Hour
		before := time.Now()
		next := nextScheduleTime("not-a-cron", fallback)
		after := time.Now()

		// Should be approximately now+fallback
		lo := before.Add(fallback)
		hi := after.Add(fallback)
		if next.Before(lo) || next.After(hi) {
			t.Errorf("expected fallback time around %v, got %v", lo, next)
		}
	})
}

// TestShouldRunNow verifies that shouldRunNow correctly interprets a cron
// schedule relative to the last run time.
func TestShouldRunNow(t *testing.T) {
	// "* * * * *" fires every minute — if last run was 2 minutes ago, should run
	lastRunLongAgo := &metav1.Time{Time: time.Now().Add(-2 * time.Minute)}
	if !shouldRunNow("* * * * *", lastRunLongAgo, time.Hour) {
		t.Error("expected shouldRunNow=true when last run was 2 minutes ago with every-minute schedule")
	}

	// "0 */6 * * *" fires every 6h — if last run was 1 minute ago, should NOT run
	lastRunJustNow := &metav1.Time{Time: time.Now().Add(-1 * time.Minute)}
	if shouldRunNow("0 */6 * * *", lastRunJustNow, 6*time.Hour) {
		t.Error("expected shouldRunNow=false when last run was 1 minute ago with 6-hour schedule")
	}

	// nil lastRun — always run
	if !shouldRunNow("0 */6 * * *", nil, 6*time.Hour) {
		t.Error("expected shouldRunNow=true when lastRun is nil")
	}

	// Invalid schedule — falls back to duration comparison
	lastRunRecently := &metav1.Time{Time: time.Now().Add(-30 * time.Minute)}
	if shouldRunNow("bad-cron", lastRunRecently, 2*time.Hour) {
		t.Error("expected shouldRunNow=false when fallback duration has not elapsed")
	}

	lastRunLongAgo2 := &metav1.Time{Time: time.Now().Add(-3 * time.Hour)}
	if !shouldRunNow("bad-cron", lastRunLongAgo2, 2*time.Hour) {
		t.Error("expected shouldRunNow=true when fallback duration has elapsed")
	}
}
