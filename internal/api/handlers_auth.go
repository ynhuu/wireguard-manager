package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/yq/wireguard-manager/internal/auth"
	"github.com/yq/wireguard-manager/internal/store"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)

// --- initial setup ------------------------------------------------------------

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_setup": u == nil || !u.TOTPEnabled})
}

type setupReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func validateCredentials(username, password string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("username must be 3-32 chars of letters/digits/_/-")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func totpQRDataURL(url string) (string, error) {
	png, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// handleSetup creates the admin account and starts TOTP enrollment.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if !readJSON(w, r, &req) {
		return
	}
	if err := validateCredentials(req.Username, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	if u != nil {
		if u.TOTPEnabled {
			writeErr(w, http.StatusConflict, "already initialized")
			return
		}
		key := clientIP(r) + "|setup-resume"
		if s.limiter.Blocked(key) {
			writeErr(w, http.StatusTooManyRequests, "too many attempts, wait a few minutes")
			return
		}
		if req.Username != u.Username || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
			s.limiter.Fail(key)
			writeErr(w, http.StatusUnauthorized, "enter the existing administrator credentials to resume enrollment")
			return
		}
		s.limiter.Reset(key)
		qr, err := totpQRDataURL(auth.SecretURL(u.Username, u.TOTPSecret))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "render QR")
			return
		}
		s.Audit(r, "setup.resume", "credentials verified")
		writeJSON(w, http.StatusOK, map[string]any{"secret": u.TOTPSecret, "qr_data_url": qr})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash password")
		return
	}
	secret, url, err := auth.GenerateSecret(req.Username, "WireGuard Manager")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "generate TOTP secret")
		return
	}
	user := &store.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		TOTPSecret:   secret,
		TOTPEnabled:  false,
		CreatedAt:    nowUTC(),
	}
	qr, err := totpQRDataURL(url)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "render QR")
		return
	}
	if err := s.store.SaveUser(user); err != nil {
		writeErr(w, http.StatusInternalServerError, "save user")
		return
	}
	s.Audit(r, "setup", "admin created")
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"qr_data_url": qr,
	})
}

type verifyReq struct {
	Code string `json:"code"`
}

// handleSetupVerify confirms the first TOTP code and activates the account.
// Rate-limited: the account is not yet 2FA-protected during this window.
func (s *Server) handleSetupVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	key := clientIP(r) + "|setup-verify"
	if s.limiter.Blocked(key) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, wait a few minutes")
		return
	}
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	if u == nil {
		writeErr(w, http.StatusConflict, "not initialized")
		return
	}
	if u.TOTPEnabled {
		writeErr(w, http.StatusConflict, "2FA already enabled")
		return
	}
	if !auth.ValidateTOTP(req.Code, u.TOTPSecret) {
		s.limiter.Fail(key)
		writeErr(w, http.StatusBadRequest, "invalid code")
		return
	}
	u.TOTPEnabled = true
	if err := s.store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, "save user")
		return
	}
	s.limiter.Reset(key)
	s.Audit(r, "setup.verify", "2FA enabled")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- login ----------------------------------------------------------------------

type loginResp struct {
	Stage  string `json:"stage"` // "totp"
	Ticket string `json:"ticket"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	key := clientIP(r)
	if s.limiter.Blocked(key) {
		s.Audit(r, "login.blocked", req.Username)
		writeErr(w, http.StatusTooManyRequests, "登录尝试过多，请稍后几分钟再试")
		return
	}
	u, err := s.store.GetUser()
	if err != nil || u == nil || bcrypt.CompareHashAndPassword(
		[]byte(u.PasswordHash), []byte(req.Password)) != nil ||
		req.Username != u.Username {
		s.limiter.Fail(key)
		s.Audit(r, "login.fail", req.Username)
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	if !u.TOTPEnabled {
		writeErr(w, http.StatusConflict, "两步验证尚未完成，请刷新设置页面")
		return
	}
	ticket, err := s.sess.NewTicket(u.Username)
	if err != nil {
		if errors.Is(err, auth.ErrTOTPBlocked) || errors.Is(err, auth.ErrAuthCapacity) {
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, "create ticket")
		return
	}
	s.limiter.Reset(key)
	s.Audit(r, "login.password.ok", "")
	writeJSON(w, http.StatusOK, loginResp{Stage: "totp", Ticket: ticket})
}

func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	u, err := s.store.GetUser()
	if err != nil || u == nil || !u.TOTPEnabled {
		writeErr(w, http.StatusUnauthorized, "登录票据无效")
		return
	}
	sess, err := s.sess.ConsumeTicket(req.Ticket, req.Code, u.TOTPSecret)
	if err != nil {
		s.Audit(r, "login.totp.fail", err.Error())
		if errors.Is(err, auth.ErrTOTPBlocked) || errors.Is(err, auth.ErrAuthCapacity) {
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	auth.SetCookie(w, sess, secureRequest(r))
	s.limiter.Reset(clientIP(r))
	s.Audit(r, "login.totp.ok", "")
	writeJSON(w, http.StatusOK, map[string]string{"csrf": sess.CSRF})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := auth.CookieToken(r)
	if _, ok := s.sess.Get(tok); ok {
		s.Audit(r, "logout", "")
		s.sess.Destroy(tok)
	}
	auth.ClearCookie(w, secureRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- session-scoped settings -------------------------------------------------------

type passwordReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	u, err := s.store.GetUser()
	if err != nil || u == nil {
		writeErr(w, http.StatusUnauthorized, "not initialized")
		return
	}
	resp := map[string]any{
		"username":     u.Username,
		"totp_enabled": u.TOTPEnabled,
	}
	// 刷新页面后会话 Cookie 仍有效但前端内存中的 CSRF 已丢失，
	// 这里随 /api/me 下发当前会话的 CSRF，避免首个写操作 403。
	if sess, ok := s.sess.Get(auth.CookieToken(r)); ok {
		resp["csrf"] = sess.CSRF
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordReq
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if _, ok := s.sess.Get(auth.CookieToken(r)); !ok {
		writeErr(w, http.StatusUnauthorized, "session revoked")
		return
	}
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	if u == nil || bcrypt.CompareHashAndPassword(
		[]byte(u.PasswordHash), []byte(req.Current)) != nil {
		writeErr(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash password")
		return
	}
	u.PasswordHash = string(hash)
	if err := s.store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, "save user")
		return
	}
	s.Audit(r, "settings.password.change", "")
	s.sess.RevokeUserExcept(u.Username, auth.CookieToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Stage a replacement secret; the verified secret remains active until commit.
func (s *Server) handleTOTPReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if _, ok := s.sess.Get(auth.CookieToken(r)); !ok {
		writeErr(w, http.StatusUnauthorized, "session revoked")
		return
	}
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	if u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "password incorrect")
		return
	}
	secret, url, err := auth.GenerateSecret(u.Username, "WireGuard Manager")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "generate secret")
		return
	}
	qr, err := totpQRDataURL(url)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "render QR")
		return
	}
	u.PendingTOTPSecret = secret
	if err := s.store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, "save user")
		return
	}
	s.Audit(r, "settings.totp.reset", "")
	s.sess.RevokeUserExcept(u.Username, auth.CookieToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "qr_data_url": qr})
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !readJSON(w, r, &req) {
		return
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if _, ok := s.sess.Get(auth.CookieToken(r)); !ok {
		writeErr(w, http.StatusUnauthorized, "session revoked")
		return
	}
	u, err := s.store.GetUser()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load user")
		return
	}
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not initialized")
		return
	}
	secret := u.PendingTOTPSecret
	if secret == "" {
		writeErr(w, http.StatusConflict, "no pending TOTP enrollment; start a reset first")
		return
	}
	if !auth.ValidateTOTP(req.Code, secret) {
		writeErr(w, http.StatusBadRequest, "invalid code")
		return
	}
	u.TOTPEnabled = true
	u.TOTPSecret = secret
	u.PendingTOTPSecret = ""
	if err := s.store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, "save user")
		return
	}
	s.Audit(r, "settings.totp.enable", "")
	s.sess.RevokeUserExcept(u.Username, auth.CookieToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
