package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/jackc/pgx/v5/stdlib"

	"sharelocal/internal/ids"
	"sharelocal/internal/protocol"
)

const maxBodyBytes = 10 << 20

const defaultBaseURL = "https://on.sharelocal.dev"

const maxSessionKeyTTLSeconds = 7 * 24 * 60 * 60

type registerRequest struct {
	DeviceKey string `json:"device_key"`
}

type registerResponse struct {
	TunnelID string `json:"tunnel_id"`
}

type tunnelState struct {
	tunnelID            string
	localPort           int
	sessionKeyHash      []byte
	sessionKeyExpiresAt time.Time
	conn                *websocket.Conn
	writeMu             sync.Mutex
	pendingMu           sync.Mutex
	pendingByID         map[string]chan protocol.Envelope
	closed              chan struct{}
}

type activeTunnels struct {
	mu     sync.RWMutex
	byID   map[string]*tunnelState
	byConn map[*websocket.Conn]string
}

func newActiveTunnels() *activeTunnels {
	return &activeTunnels{
		byID:   map[string]*tunnelState{},
		byConn: map[*websocket.Conn]string{},
	}
}

func (a *activeTunnels) set(tunnelID string, t *tunnelState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.byID[tunnelID]; ok {
		delete(a.byConn, existing.conn)
		delete(a.byID, tunnelID)
		_ = existing.conn.Close()
	}
	a.byID[tunnelID] = t
	a.byConn[t.conn] = tunnelID
}

func (a *activeTunnels) get(tunnelID string) (*tunnelState, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	t, ok := a.byID[tunnelID]
	return t, ok
}

func (a *activeTunnels) removeByConn(conn *websocket.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnelID, ok := a.byConn[conn]
	if !ok {
		return
	}
	delete(a.byConn, conn)
	delete(a.byID, tunnelID)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	baseURL := strings.TrimRight(os.Getenv("BASE_URL"), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		log.Fatal(err)
	}
	cancel()

	if err := ensureSchema(context.Background(), db); err != nil {
		log.Fatal(err)
	}

	active := newActiveTunnels()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		handleRegister(w, r, db)
	})
	mux.HandleFunc("GET /v1/tunnel", func(w http.ResponseWriter, r *http.Request) {
		handleTunnelWS(w, r, db, active)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleIngress(w, r, active, baseURL)
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
create table if not exists devices (
  device_key_hash text primary key,
  tunnel_id text unique not null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);`)
	return err
}

func handleRegister(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var req registerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DeviceKey) == "" {
		http.Error(w, "missing device_key", http.StatusBadRequest)
		return
	}

	deviceHash := sha256Hex(req.DeviceKey)

	tunnelID, err := upsertAndResolveTunnelID(r.Context(), db, deviceHash)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(registerResponse{TunnelID: tunnelID})
}

func upsertAndResolveTunnelID(ctx context.Context, db *sql.DB, deviceHash string) (string, error) {
	var tunnelID string
	err := db.QueryRowContext(ctx, `select tunnel_id from devices where device_key_hash = $1`, deviceHash).Scan(&tunnelID)
	if err == nil {
		_, _ = db.ExecContext(ctx, `update devices set last_seen_at = now() where device_key_hash = $1`, deviceHash)
		return tunnelID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	newTunnelID, err := ids.NewCrockfordBase32ID(20)
	if err != nil {
		return "", err
	}

	_, err = db.ExecContext(ctx, `
insert into devices(device_key_hash, tunnel_id) values ($1, $2)
on conflict (device_key_hash) do update set last_seen_at = now()
`, deviceHash, newTunnelID)
	if err != nil {
		return "", err
	}
	return newTunnelID, nil
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleTunnelWS(w http.ResponseWriter, r *http.Request, db *sql.DB, active *activeTunnels) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn.SetReadLimit(2 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	_, msg, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return
	}

	var handshake protocol.TunnelHandshake
	if err := json.Unmarshal(msg, &handshake); err != nil {
		_ = conn.Close()
		return
	}
	if strings.TrimSpace(handshake.DeviceKey) == "" || handshake.LocalPort < 1 || handshake.LocalPort > 65535 {
		_ = conn.Close()
		return
	}
	if strings.TrimSpace(handshake.SessionKey) == "" {
		_ = conn.Close()
		return
	}
	if handshake.TTLSeconds < 0 {
		_ = conn.Close()
		return
	}
	if handshake.TTLSeconds > maxSessionKeyTTLSeconds {
		handshake.TTLSeconds = maxSessionKeyTTLSeconds
	}

	expiresAt := time.Time{}
	if handshake.TTLSeconds > 0 {
		expiresAt = time.Now().Add(time.Duration(handshake.TTLSeconds) * time.Second)
	}

	sessionKeyHash := sha256.Sum256([]byte(handshake.SessionKey))
	sessionKeyHashBytes := sessionKeyHash[:]

	deviceHash := sha256Hex(handshake.DeviceKey)
	var tunnelID string
	err = db.QueryRowContext(r.Context(), `select tunnel_id from devices where device_key_hash = $1`, deviceHash).Scan(&tunnelID)
	if err != nil {
		_ = conn.Close()
		return
	}
	_, _ = db.ExecContext(r.Context(), `update devices set last_seen_at = now() where device_key_hash = $1`, deviceHash)

	tunnel := &tunnelState{
		tunnelID:            tunnelID,
		localPort:           handshake.LocalPort,
		sessionKeyHash:      sessionKeyHashBytes,
		sessionKeyExpiresAt: expiresAt,
		conn:                conn,
		pendingByID:         map[string]chan protocol.Envelope{},
		closed:              make(chan struct{}),
	}
	active.set(tunnelID, tunnel)

	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go tunnelPingLoop(tunnel)
	go tunnelReadLoop(tunnel, active)
}

func tunnelPingLoop(t *tunnelState) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.writeMu.Lock()
			err := t.conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
			t.writeMu.Unlock()
			if err != nil {
				_ = t.conn.Close()
				return
			}
		case <-t.closed:
			return
		}
	}
}

func tunnelReadLoop(t *tunnelState, active *activeTunnels) {
	defer func() {
		close(t.closed)
		active.removeByConn(t.conn)
		_ = t.conn.Close()
	}()

	for {
		var env protocol.Envelope
		if err := t.conn.ReadJSON(&env); err != nil {
			return
		}
		if env.Type != "response" || env.ID == "" {
			continue
		}

		t.pendingMu.Lock()
		ch, ok := t.pendingByID[env.ID]
		if ok {
			delete(t.pendingByID, env.ID)
		}
		t.pendingMu.Unlock()

		if ok {
			select {
			case ch <- env:
			default:
			}
		}
	}
}

func handleIngress(w http.ResponseWriter, r *http.Request, active *activeTunnels, baseURL string) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		return
	}

	if strings.HasPrefix(r.URL.Path, "/v1/") {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/p/") {
		tunnelID, ok := cookieTunnelID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		sessionKey, ok := cookieSessionKey(r)
		if !ok {
			http.NotFound(w, r)
			return
		}

		path := r.URL.Path
		filteredQuery := rawQueryWithoutKey(r.URL)
		if filteredQuery != "" {
			path = path + "?" + filteredQuery
		}
		proxyToTunnel(w, r, active, baseURL, tunnelID, sessionKey, path)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	tunnelID := parts[0]

	setTunnelCookie(w, r, tunnelID)
	sessionKey := r.URL.Query().Get("k")
	if strings.TrimSpace(sessionKey) != "" {
		setSessionKeyCookie(w, r, sessionKey)
	} else {
		cookieKey, ok := cookieSessionKey(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		sessionKey = cookieKey
	}
	if len(parts) == 1 {
		target := "/p/" + tunnelID + "/"
		if r.URL.RawQuery != "" {
			target = target + "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return
	}
	path := "/"
	if len(parts) == 2 && parts[1] != "" {
		path = "/" + parts[1]
	}
	filteredQuery := rawQueryWithoutKey(r.URL)
	if filteredQuery != "" {
		path = path + "?" + filteredQuery
	}
	proxyToTunnel(w, r, active, baseURL, tunnelID, sessionKey, path)
}

func proxyToTunnel(w http.ResponseWriter, r *http.Request, active *activeTunnels, baseURL string, tunnelID string, sessionKey string, path string) {
	tunnel, ok := active.get(tunnelID)
	if !ok {
		writeOfflinePage(w, tunnelID, baseURL, sessionKey, r)
		return
	}
	if !isValidSessionKey(tunnel, sessionKey) {
		http.NotFound(w, r)
		return
	}

	body, err := readLimitedBody(r)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	env := protocol.Envelope{
		Type:       "request",
		ID:         newRequestID(),
		Method:     r.Method,
		Path:       path,
		Headers:    protocol.Headers(copyRequestHeaders(r)),
		BodyBase64: base64.StdEncoding.EncodeToString(body),
	}
	if len(body) == 0 {
		env.BodyBase64 = ""
	}

	resp, err := tunnelRoundTrip(r.Context(), tunnel, env)
	if err != nil {
		writeOfflinePage(w, tunnelID, baseURL, sessionKey, r)
		return
	}

	for k, values := range http.Header(resp.Headers) {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(resp.Status)

	if resp.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
		if err == nil {
			_, _ = w.Write(decoded)
		}
	}
}

func cookieTunnelID(r *http.Request) (string, bool) {
	c, err := r.Cookie("sharelocal_tunnel")
	if err != nil {
		return "", false
	}
	if strings.TrimSpace(c.Value) == "" {
		return "", false
	}
	return c.Value, true
}

func cookieSessionKey(r *http.Request) (string, bool) {
	c, err := r.Cookie("sharelocal_key")
	if err != nil {
		return "", false
	}
	if strings.TrimSpace(c.Value) == "" {
		return "", false
	}
	return c.Value, true
}

func setTunnelCookie(w http.ResponseWriter, r *http.Request, tunnelID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sharelocal_tunnel",
		Value:    tunnelID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func setSessionKeyCookie(w http.ResponseWriter, r *http.Request, sessionKey string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sharelocal_key",
		Value:    sessionKey,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func rawQueryWithoutKey(u *url.URL) string {
	q := u.Query()
	q.Del("k")
	return q.Encode()
}

func isValidSessionKey(t *tunnelState, provided string) bool {
	if strings.TrimSpace(provided) == "" {
		return false
	}
	if !t.sessionKeyExpiresAt.IsZero() && time.Now().After(t.sessionKeyExpiresAt) {
		return false
	}
	sum := sha256.Sum256([]byte(provided))
	if len(t.sessionKeyHash) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(t.sessionKeyHash, sum[:]) == 1
}

func tunnelRoundTrip(ctx context.Context, t *tunnelState, req protocol.Envelope) (protocol.Envelope, error) {
	ch := make(chan protocol.Envelope, 1)

	t.pendingMu.Lock()
	t.pendingByID[req.ID] = ch
	t.pendingMu.Unlock()

	t.writeMu.Lock()
	err := t.conn.WriteJSON(req)
	t.writeMu.Unlock()
	if err != nil {
		t.pendingMu.Lock()
		delete(t.pendingByID, req.ID)
		t.pendingMu.Unlock()
		return protocol.Envelope{}, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	select {
	case resp := <-ch:
		if resp.Status == 0 {
			resp.Status = http.StatusBadGateway
		}
		return resp, nil
	case <-timeoutCtx.Done():
		t.pendingMu.Lock()
		delete(t.pendingByID, req.ID)
		t.pendingMu.Unlock()
		return protocol.Envelope{}, timeoutCtx.Err()
	case <-t.closed:
		t.pendingMu.Lock()
		delete(t.pendingByID, req.ID)
		t.pendingMu.Unlock()
		return protocol.Envelope{}, errors.New("tunnel closed")
	}
}

func readLimitedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()

	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBodyBytes {
		return nil, errors.New("request too large")
	}
	return data, nil
}

func copyRequestHeaders(r *http.Request) http.Header {
	out := http.Header{}
	for k, values := range r.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range values {
			out.Add(k, v)
		}
	}
	out.Del("host")
	stripSharelocalCookies(r, out)

	xff := clientIP(r)
	if existing := out.Get("x-forwarded-for"); existing != "" {
		xff = existing + ", " + xff
	}
	out.Set("x-forwarded-for", xff)
	if r.TLS != nil {
		out.Set("x-forwarded-proto", "https")
	} else {
		out.Set("x-forwarded-proto", "http")
	}
	out.Set("x-forwarded-host", r.Host)
	return out
}

func stripSharelocalCookies(r *http.Request, headers http.Header) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}

	kept := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "sharelocal_tunnel" || c.Name == "sharelocal_key" {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	if len(kept) == 0 {
		headers.Del("cookie")
		return
	}
	headers.Set("cookie", strings.Join(kept, "; "))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func writeOfflinePage(w http.ResponseWriter, tunnelID string, baseURL string, sessionKey string, r *http.Request) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	canonicalBase := baseURL
	link := canonicalBase + "/p/" + tunnelID + "/"
	if strings.TrimSpace(sessionKey) != "" {
		link = link + "?k=" + url.QueryEscape(sessionKey)
	}
	_, _ = io.WriteString(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Preview offline</title></head><body><h1>Preview offline</h1><p>This sharelocal link is not currently connected.</p><p><a href=\""+link+"\">"+link+"</a></p></body></html>")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
