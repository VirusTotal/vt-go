package vt

import (
	"net/http"
	"testing"
)

func TestNewClientWithHTTPClientOption(t *testing.T) {
	httpClient := &http.Client{}

	c := NewClientWithOptions("api-key", WithHTTPClient(httpClient))
	if c.httpClient != httpClient {
		t.Fatalf("failed to set custom http")
	}
}
