package auth

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestTOTPFailuresAccumulateAcrossTickets(t *testing.T) {
	m := NewManager()
	tickets := make([]string, 6)
	for i := range tickets {
		var err error
		tickets[i], err = m.NewTicket("admin")
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, ticket := range tickets[:5] {
		if _, err := m.ConsumeTicket(ticket, "invalid", "JBSWY3DPEHPK3PXP"); err == nil {
			t.Fatal("invalid code accepted")
		}
	}
	if _, err := m.NewTicket("admin"); !errors.Is(err, ErrTOTPBlocked) {
		t.Fatalf("new ticket bypassed lockout: %v", err)
	}
	if _, err := m.ConsumeTicket(tickets[5], "invalid", "JBSWY3DPEHPK3PXP"); !errors.Is(err, ErrTOTPBlocked) {
		t.Fatalf("existing ticket bypassed lockout: %v", err)
	}
	m.mu.Lock()
	for i := range m.totpFailures["admin"] {
		m.totpFailures["admin"][i] = time.Now().Add(-6 * time.Minute)
	}
	m.mu.Unlock()
	if _, err := m.NewTicket("admin"); err != nil {
		t.Fatalf("lockout never expired: %v", err)
	}
}

func TestRevokeUserExceptClearsSessionsAndTickets(t *testing.T) {
	m := NewManager()
	keep, _ := m.NewSession("admin")
	other, _ := m.NewSession("admin")
	unrelated, _ := m.NewSession("other")
	ticket, _ := m.NewTicket("admin")
	m.RevokeUserExcept("admin", keep.Token)
	if _, ok := m.Get(keep.Token); !ok {
		t.Fatal("caller revoked")
	}
	if _, ok := m.Get(other.Token); ok {
		t.Fatal("other session survived")
	}
	if _, ok := m.Get(unrelated.Token); !ok {
		t.Fatal("unrelated user revoked")
	}
	if _, err := m.ConsumeTicket(ticket, "invalid", "JBSWY3DPEHPK3PXP"); err == nil || m.tickets[ticket] != nil {
		t.Fatal("old ticket survived")
	}
}

func TestAuthCapacityRejectsAndPrunesExpiredEntries(t *testing.T) {
	m := NewManager()
	now := time.Now()

	m.mu.Lock()
	for i := 0; i < maxSessions; i++ {
		m.sessions[fmt.Sprintf("session-%d", i)] = &Session{Expires: now.Add(time.Hour)}
	}
	for i := 0; i < maxTickets; i++ {
		m.tickets[fmt.Sprintf("ticket-%d", i)] = &ticket{Username: "admin", Expires: now.Add(time.Hour)}
	}
	m.mu.Unlock()

	if _, err := m.NewSession("admin"); !errors.Is(err, ErrAuthCapacity) {
		t.Fatalf("session capacity was not enforced: %v", err)
	}
	if _, err := m.NewTicket("admin"); !errors.Is(err, ErrAuthCapacity) {
		t.Fatalf("ticket capacity was not enforced: %v", err)
	}

	m.mu.Lock()
	for _, session := range m.sessions {
		session.Expires = now.Add(-time.Minute)
	}
	for _, pending := range m.tickets {
		pending.Expires = now.Add(-time.Minute)
	}
	m.mu.Unlock()

	if _, err := m.NewSession("admin"); err != nil {
		t.Fatalf("expired sessions were not pruned: %v", err)
	}
	if _, err := m.NewTicket("admin"); err != nil {
		t.Fatalf("expired tickets were not pruned: %v", err)
	}
}
