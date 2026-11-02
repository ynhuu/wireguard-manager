package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

var (
	ErrTOTPBlocked  = errors.New("验证码尝试过多，请等待五分钟后重试")
	ErrAuthCapacity = errors.New("当前登录会话过多，请稍后重试")
)

const (
	sessionCookie = "wgm_session"
	SessionTTL    = 12 * time.Hour
	TicketTTL     = 5 * time.Minute
	maxSessions   = 256
	maxTickets    = 128
)

// Session holds an authenticated admin session plus its CSRF token.
type Session struct {
	Token    string
	CSRF     string
	Username string
	Expires  time.Time
}

type ticket struct {
	Username  string
	Expires   time.Time
	Remaining int // failed TOTP attempts
}

// Manager tracks sessions and pending-TOTP tickets in memory.
type Manager struct {
	mu           sync.Mutex
	sessions     map[string]*Session
	tickets      map[string]*ticket
	totpFailures map[string][]time.Time
}

func NewManager() *Manager {
	m := &Manager{
		sessions:     map[string]*Session{},
		tickets:      map[string]*ticket{},
		totpFailures: map[string][]time.Time{},
	}
	go m.gcLoop()
	return m
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewTicket creates a short-lived ticket after password verification.
func (m *Manager) NewTicket(username string) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.pruneExpiredLocked(now)
	if m.totpBlockedLocked(username) {
		return "", ErrTOTPBlocked
	}
	if len(m.tickets) >= maxTickets {
		return "", ErrAuthCapacity
	}
	m.tickets[id] = &ticket{Username: username, Expires: now.Add(TicketTTL), Remaining: 5}
	return id, nil
}

// ConsumeTicket validates a TOTP code against a pending ticket and issues a session.
func (m *Manager) ConsumeTicket(ticketID, code, secret string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[ticketID]
	if !ok || time.Now().After(t.Expires) {
		delete(m.tickets, ticketID)
		return nil, fmt.Errorf("登录票据已过期，请重新登录")
	}
	if m.totpBlockedLocked(t.Username) {
		return nil, ErrTOTPBlocked
	}
	if !totp.Validate(code, secret) {
		m.totpFailures[t.Username] = append(m.totpFailures[t.Username], time.Now())
		t.Remaining--
		if t.Remaining <= 0 {
			delete(m.tickets, ticketID)
			return nil, fmt.Errorf("验证码错误次数过多，请重新登录")
		}
		return nil, fmt.Errorf("验证码错误")
	}
	delete(m.tickets, ticketID)
	delete(m.totpFailures, t.Username)
	return m.newSessionLocked(t.Username)
}

func (m *Manager) totpBlockedLocked(username string) bool {
	now := time.Now()
	kept := m.totpFailures[username][:0]
	for _, when := range m.totpFailures[username] {
		if now.Sub(when) < 5*time.Minute {
			kept = append(kept, when)
		}
	}
	if len(kept) == 0 {
		delete(m.totpFailures, username)
		return len(kept) >= 5
	}
	m.totpFailures[username] = kept
	return len(kept) >= 5
}

// NewSession creates a session directly (used when 2FA is disabled).
func (m *Manager) NewSession(username string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.newSessionLocked(username)
}

func (m *Manager) newSessionLocked(username string) (*Session, error) {
	m.pruneExpiredLocked(time.Now())
	if len(m.sessions) >= maxSessions {
		return nil, ErrAuthCapacity
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	s := &Session{Token: token, CSRF: csrf, Username: username, Expires: time.Now().Add(SessionTTL)}
	m.sessions[token] = s
	return s, nil
}

// Get returns the live session for a token.
func (m *Manager) Get(token string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok || time.Now().After(s.Expires) {
		delete(m.sessions, token)
		return nil, false
	}
	return s, true
}

// Destroy removes a session.
func (m *Manager) Destroy(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

// Credential changes revoke all pending login tickets and all other sessions.
// Keeping only the verified caller allows it to finish staged TOTP enrollment.
func (m *Manager) RevokeUserExcept(username, keepToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, s := range m.sessions {
		if s.Username == username && token != keepToken {
			delete(m.sessions, token)
		}
	}
	for id, t := range m.tickets {
		if t.Username == username {
			delete(m.tickets, id)
		}
	}
}

// SetCookie writes the session cookie on w.
func SetCookie(w http.ResponseWriter, s *Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  s.Expires,
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// CookieToken extracts the session token from r.
func CookieToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func (m *Manager) gcLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		m.pruneExpiredLocked(now)
		for username := range m.totpFailures {
			m.totpBlockedLocked(username)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) pruneExpiredLocked(now time.Time) {
	for token, session := range m.sessions {
		if now.After(session.Expires) {
			delete(m.sessions, token)
		}
	}
	for id, t := range m.tickets {
		if now.After(t.Expires) {
			delete(m.tickets, id)
		}
	}
}

// GenerateSecret creates a new base32 TOTP secret and provisioning URL.
func GenerateSecret(username, issuer string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// SecretURL reconstructs provisioning data only after credential verification.
func SecretURL(username, secret string) string {
	values := url.Values{"secret": {secret}, "issuer": {"WireGuard Manager"}}
	return "otpauth://totp/" + url.PathEscape("WireGuard Manager:"+username) + "?" + values.Encode()
}

// ValidateTOTP checks a 6-digit code with ±1 period drift tolerance.
func ValidateTOTP(code, secret string) bool {
	ok, err := totp.ValidateCustom(code, secret, time.Now(),
		totp.ValidateOpts{Period: 30, Skew: 1, Digits: 6})
	if err != nil {
		return false
	}
	return ok
}
