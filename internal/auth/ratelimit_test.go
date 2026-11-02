package auth

import (
	"testing"
	"time"
)

func TestLimiterPrunesExpiredKeysOnNewAttempts(t *testing.T) {
	l := NewLimiter()
	l.fail["stale"] = []time.Time{time.Now().Add(-l.lockFor - time.Second)}
	l.Fail("current")
	if len(l.fail) != 1 || len(l.fail["current"]) != 1 {
		t.Fatalf("expired keys were retained: %#v", l.fail)
	}
}
