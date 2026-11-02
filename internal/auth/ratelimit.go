package auth

import (
	"sync"
	"time"
)

// Limiter is a simple in-memory sliding-window rate limiter for login attempts.
type Limiter struct {
	mu        sync.Mutex
	fail      map[string][]time.Time
	max       int
	lockFor   time.Duration
	lastSweep time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{
		fail:    map[string][]time.Time{},
		max:     5,
		lockFor: 5 * time.Minute,
	}
}

// Blocked reports whether key is currently locked out.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now)
	strikes := l.pruneAtLocked(key, now)
	return len(strikes) >= l.max
}

// Fail records a failed attempt for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now)
	l.fail[key] = append(l.pruneAtLocked(key, now), now)
}

func (l *Limiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < time.Minute {
		return
	}
	for key := range l.fail {
		l.pruneAtLocked(key, now)
	}
	l.lastSweep = now
}

// Reset clears failure history for key after success.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, key)
}

func (l *Limiter) pruneLocked(key string) []time.Time {
	return l.pruneAtLocked(key, time.Now())
}

func (l *Limiter) pruneAtLocked(key string, now time.Time) []time.Time {
	kept := l.fail[key][:0]
	for _, t := range l.fail[key] {
		if now.Sub(t) < l.lockFor {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fail, key)
		return kept
	}
	l.fail[key] = kept
	return kept
}
