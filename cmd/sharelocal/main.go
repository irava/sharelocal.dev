package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"sharelocal/internal/protocol"
	"sharelocal/internal/sharelocalconfig"
)

const maxBodyBytes = 10 << 20

type registerRequest struct {
	DeviceKey string `json:"device_key"`
}

type registerResponse struct {
	TunnelID string `json:"tunnel_id"`
}

func main() {
	if len(os.Args) < 2 {
		printMissingPort()
		os.Exit(2)
	}

	portStr := os.Args[1]
	port, err := parsePort(portStr)
	if err != nil {
		printInvalidPort(portStr)
		os.Exit(2)
	}

	if err := ensureLocalPortOpen(port); err != nil {
		printNothingRunning(port)
		os.Exit(2)
	}

	baseURL := os.Getenv("SHARELOCAL_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sharelocal.fly.dev"
	}

	configPath, err := sharelocalconfig.DefaultConfigPath()
	if err != nil {
		printServiceUnreachable()
		os.Exit(1)
	}

	cfg, err := sharelocalconfig.Load(configPath)
	if err != nil {
		printServiceUnreachable()
		os.Exit(1)
	}

	if cfg.DeviceKey == "" {
		deviceKey, err := newDeviceKey()
		if err != nil {
			printServiceUnreachable()
			os.Exit(1)
		}
		cfg.DeviceKey = deviceKey
	}

	tunnelID, err := register(context.Background(), baseURL, cfg.DeviceKey)
	if err != nil {
		printServiceUnreachable()
		os.Exit(1)
	}
	cfg.TunnelID = tunnelID

	if err := sharelocalconfig.Save(configPath, cfg); err != nil {
		printServiceUnreachable()
		os.Exit(1)
	}

	publicURL := strings.TrimRight(baseURL, "/") + "/p/" + tunnelID

	fmt.Printf("✔ Sharing localhost:%d\n", port)
	fmt.Printf("✔ Live URL:\n%s\n\n", publicURL)
	fmt.Println("Anyone with this link can view your local app while this is running.")
	fmt.Println("Press Ctrl+C to stop.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	if err := runTunnel(ctx, baseURL, cfg.DeviceKey, port); err != nil {
		os.Exit(1)
	}
}

func runTunnel(ctx context.Context, baseURL, deviceKey string, port int) error {
	for {
		err := connectAndServe(ctx, baseURL, deviceKey, port, nil)
		if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil
		}

		fmt.Println("\n⚠ Connection lost — reconnecting…")

		for attempt := 1; attempt <= 6; attempt++ {
			onConnected := func() { fmt.Println("✔ Reconnected") }
			err = connectAndServe(ctx, baseURL, deviceKey, port, onConnected)
			if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}

			if attempt == 6 {
				fmt.Println("✖ Couldn’t reconnect")
				fmt.Println("Check your internet connection and run the command again.")
				return err
			}

			backoff := time.Duration(attempt) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func connectAndServe(ctx context.Context, baseURL, deviceKey string, port int, onConnected func()) error {
	wsURL, err := toWebSocketURL(strings.TrimRight(baseURL, "/") + "/v1/tunnel")
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetReadLimit(10 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	handshake := protocol.TunnelHandshake{DeviceKey: deviceKey, LocalPort: port}
	if err := conn.WriteJSON(handshake); err != nil {
		return err
	}

	if onConnected != nil {
		onConnected()
	}

	serveDone := make(chan struct{})
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
			case <-serveDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			close(serveDone)
			return ctx.Err()
		default:
		}

		var env protocol.Envelope
		if err := conn.ReadJSON(&env); err != nil {
			close(serveDone)
			<-pingDone
			return err
		}
		if env.Type != "request" || env.ID == "" {
			continue
		}

		resp := handleLocalRequest(ctx, port, env)
		if err := conn.WriteJSON(resp); err != nil {
			close(serveDone)
			<-pingDone
			return err
		}
	}
}

func handleLocalRequest(ctx context.Context, port int, req protocol.Envelope) protocol.Envelope {
	localURL := fmt.Sprintf("http://127.0.0.1:%d%s", port, req.Path)
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, localURL, nil)
	if err != nil {
		return protocol.Envelope{Type: "response", ID: req.ID, Status: http.StatusBadGateway}
	}

	var bodyReader io.Reader
	if req.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err == nil {
			bodyReader = bytes.NewReader(decoded)
		}
	}
	if bodyReader != nil {
		httpReq.Body = io.NopCloser(bodyReader)
	}

	for k, values := range http.Header(req.Headers) {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range values {
			httpReq.Header.Add(k, v)
		}
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return protocol.Envelope{Type: "response", ID: req.ID, Status: http.StatusBadGateway}
	}
	defer httpResp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxBodyBytes))
	resp := protocol.Envelope{
		Type:       "response",
		ID:         req.ID,
		Status:     httpResp.StatusCode,
		Headers:    protocol.Headers(filterResponseHeaders(httpResp.Header)),
		BodyBase64: base64.StdEncoding.EncodeToString(respBody),
	}
	if len(respBody) == 0 {
		resp.BodyBase64 = ""
	}
	return resp
}

func register(ctx context.Context, baseURL, deviceKey string) (string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/register"
	body, _ := json.Marshal(registerRequest{DeviceKey: deviceKey})

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("register failed: %s", resp.Status)
	}

	var out registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.TunnelID == "" {
		return "", errors.New("missing tunnel_id")
	}
	return out.TunnelID, nil
}

func newDeviceKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func ensureLocalPortOpen(port int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if p < 1 || p > 65535 {
		return 0, errors.New("out of range")
	}
	return p, nil
}

func printMissingPort() {
	fmt.Println("✖ Missing port")
	fmt.Println("Usage: sharelocal <port>")
	fmt.Println("Example: sharelocal 3000")
}

func printInvalidPort(value string) {
	fmt.Printf("✖ Invalid port: %q\n", value)
	fmt.Println("Port must be a number between 1 and 65535.")
}

func printNothingRunning(port int) {
	fmt.Printf("✖ Nothing is running on localhost:%d\n", port)
	fmt.Println("Start your app, then try again.")
	fmt.Printf("Tip: open http://localhost:%d in your browser to confirm.\n", port)
}

func printServiceUnreachable() {
	fmt.Println("✖ Can’t reach the sharelocal service")
	fmt.Println("Check your internet connection and try again.")
}

func toWebSocketURL(httpURL string) (string, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	return u.String(), nil
}

func filterResponseHeaders(in http.Header) http.Header {
	out := http.Header{}
	for k, values := range in {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range values {
			out.Add(k, v)
		}
	}
	return out
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
