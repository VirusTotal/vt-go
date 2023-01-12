package vt

import (
	"net/http"
	"testing"
)

func TestNewClientWithHTTPClientOption(t *testing.T) {
	httpClient := &http.Client{}

	c := NewClient("api-key", WithHTTPClient(httpClient))
	if c.httpClient != httpClient {
		t.Fatalf("failed to set custom http")
	}
}

func TestNewClientWithClientHeaders(t *testing.T) {
	c := NewClient("api-key", WithClientHeaders(map[string]string{"foo": "bar"}))
	if c.headers["foo"] != "bar" {
		t.Fatalf("failed to set custom headers")
	}
}
