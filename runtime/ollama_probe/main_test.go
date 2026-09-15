package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVersionEmitsMinimalReadinessEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/version" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing JSON accept header")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"0.12.0","ignored":"value"}`)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	if err := run([]string{"version"}, &stdout, newProbe(server.URL)); err != nil {
		t.Fatalf("version probe failed: %v", err)
	}
	var got readinessResponse
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if got.Provider != "ollama" || !got.Ready || got.Version != "0.12.0" {
		t.Fatalf("unexpected readiness output: %+v", got)
	}
	if strings.Contains(stdout.String(), "ignored") {
		t.Fatalf("version output leaked unrelated provider fields")
	}
}

func TestTagsPreservesProviderInventoryAfterShapeValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[{"name":"qwen-local","digest":"abc"}],"provider_meta":{"x":1}}`)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	if err := run([]string{"tags"}, &stdout, newProbe(server.URL)); err != nil {
		t.Fatalf("tags probe failed: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if _, ok := got["models"]; !ok {
		t.Fatalf("validated models field was not preserved")
	}
	if _, ok := got["provider_meta"]; !ok {
		t.Fatalf("provider inventory metadata was not preserved")
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		fmt.Fprint(w, `{"version":"unexpected"}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	var stdout bytes.Buffer
	err := run([]string{"version"}, &stdout, newProbe(redirector.URL))
	if err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("probe followed redirect outside the selected endpoint")
	}
}

func TestProbeRejectsOversizedAndMalformedPayloads(t *testing.T) {
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"version":"`+strings.Repeat("x", maxResponseSize)+`"}`)
	}))
	defer oversized.Close()
	var stdout bytes.Buffer
	if err := run([]string{"version"}, &stdout, newProbe(oversized.URL)); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size-limit rejection, got %v", err)
	}

	badTags := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"models":{"not":"an-array"}}`)
	}))
	defer badTags.Close()
	stdout.Reset()
	if err := run([]string{"tags"}, &stdout, newProbe(badTags.URL)); err == nil ||
		!strings.Contains(err.Error(), "not an array") {
		t.Fatalf("expected tags shape rejection, got %v", err)
	}
}

func TestRunRejectsUnsupportedCommandAndInvalidArity(t *testing.T) {
	var stdout bytes.Buffer
	p := newProbe("http://127.0.0.1:1")
	for _, args := range [][]string{{}, {"version", "extra"}} {
		if err := run(args, &stdout, p); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("expected usage error for %v, got %v", args, err)
		}
	}
	if err := run([]string{"infer"}, &stdout, p); err == nil ||
		!strings.Contains(err.Error(), "unsupported command") {
		t.Fatalf("expected unsupported-command error, got %v", err)
	}
}
