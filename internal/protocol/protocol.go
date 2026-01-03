package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Headers http.Header

func (h *Headers) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*h = Headers(http.Header{})
		return nil
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	header := http.Header{}
	for k, v := range raw {
		switch typed := v.(type) {
		case string:
			header.Add(k, typed)
		case []any:
			for _, item := range typed {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("invalid header value type for %q", k)
				}
				header.Add(k, s)
			}
		default:
			return fmt.Errorf("invalid header value type for %q", k)
		}
	}
	*h = Headers(header)
	return nil
}

func (h Headers) MarshalJSON() ([]byte, error) {
	out := map[string][]string(http.Header(h))
	return json.Marshal(out)
}

type TunnelHandshake struct {
	DeviceKey string `json:"device_key"`
	LocalPort int    `json:"local_port"`
}

type Envelope struct {
	Type       string  `json:"type"`
	ID         string  `json:"id,omitempty"`
	Method     string  `json:"method,omitempty"`
	Path       string  `json:"path,omitempty"`
	Headers    Headers `json:"headers,omitempty"`
	BodyBase64 string  `json:"body_base64,omitempty"`
	Status     int     `json:"status,omitempty"`
}
