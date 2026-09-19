package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHealthProbeUsesLoopbackAndBasicAuthFromEnvironment(t *testing.T) {
	t.Setenv("OPENCODE_SERVER_PASSWORD", "synthetic-secret")
	t.Setenv("OPENCODE_SERVER_USERNAME", "synthetic-user")

	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true,"version":"1.2.3"}`))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	err := run(
		[]string{"health", server.URL + "/global/health"},
		&stdout,
		&probe{client: server.Client()},
	)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if authorization == "" || !strings.HasPrefix(authorization, "Basic ") {
		t.Fatalf("expected Basic authorization, got %q", authorization)
	}
	if got := stdout.String(); got != "{"healthy":true,"version":"1.2.3"}\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestHealthProbeOmitsAuthWhenPasswordAbsent(t *testing.T) {
	_ = os.Unsetenv("OPENCODE_SERVER_PASSWORD")
	_ = os.Unsetenv("OPENCODE_SERVER_USERNAME")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		_, _ = w.Write([]byte(`{"healthy":true,"version":"1.2.3"}`))
	}))
	defer server.Close()

	var stdout bytes.Buffer
	if err := run(
		[]string{"health", server.URL + "/global/health"},
		&stdout,
		&probe{client: server.Client()},
	); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestHealthProbeRejectsNonLoopbackOrWrongPath(t *testing.T) {
	cases := []string{
		"https://127.0.0.1:4096/global/health",
		"http://example.com:4096/global/health",
		"http://127.0.0.1:4096/api/health",
		"http://127.0.0.1:4096/global/health?q=1",
	}
	for _, endpoint := range cases {
		t.Run(endpoint, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := run(
				[]string{"health", endpoint},
				&stdout,
				newProbe(),
			); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestHealthProbeRejectsUnhealthyAndOversizedResponses(t *testing.T) {
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":false,"version":"1.2.3"}`))
	}))
	defer unhealthy.Close()

	var stdout bytes.Buffer
	if err := run(
		[]string{"health", unhealthy.URL + "/global/health"},
		&stdout,
		&probe{client: unhealthy.Client()},
	); err == nil || !strings.Contains(err.Error(), "not healthy") {
		t.Fatalf("expected unhealthy error, got %v", err)
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer oversized.Close()

	stdout.Reset()
	if err := run(
		[]string{"health", oversized.URL + "/global/health"},
		&stdout,
		&probe{client: oversized.Client()},
	); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}
