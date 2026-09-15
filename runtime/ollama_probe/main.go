package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseURL  = "http://127.0.0.1:11434"
	maxResponseSize = 8 * 1024 * 1024
)

type versionResponse struct {
	Version string `json:"version"`
}

type readinessResponse struct {
	Provider string `json:"provider"`
	Ready    bool   `json:"ready"`
	Version  string `json:"version"`
}

type probe struct {
	baseURL string
	client  *http.Client
}

func newProbe(baseURL string) *probe {
	return &probe{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func newProductionProbe() *probe {
	return newProbe(defaultBaseURL)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, newProductionProbe()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, p *probe) error {
	if len(args) != 1 {
		return errors.New("usage: rt-ollama-probe <version|tags>")
	}
	if p == nil || p.client == nil || p.baseURL == "" {
		return errors.New("probe configuration is incomplete")
	}

	switch args[0] {
	case "version":
		return p.emitVersion(stdout)
	case "tags":
		return p.emitTags(stdout)
	default:
		return fmt.Errorf("unsupported command: %s", args[0])
	}
}

func (p *probe) emitVersion(stdout io.Writer) error {
	var payload versionResponse
	if err := p.getJSON("/api/version", &payload); err != nil {
		return err
	}
	if payload.Version == "" {
		return errors.New("Ollama version response is missing version")
	}
	return json.NewEncoder(stdout).Encode(readinessResponse{
		Provider: "ollama",
		Ready:    true,
		Version:  payload.Version,
	})
}

func (p *probe) emitTags(stdout io.Writer) error {
	payload := make(map[string]json.RawMessage)
	if err := p.getJSON("/api/tags", &payload); err != nil {
		return err
	}
	rawModels, ok := payload["models"]
	if !ok {
		return errors.New("Ollama tags response is missing models")
	}
	var models []json.RawMessage
	if err := json.Unmarshal(rawModels, &models); err != nil {
		return errors.New("Ollama tags response models is not an array")
	}
	return json.NewEncoder(stdout).Encode(payload)
}

func (p *probe) getJSON(path string, destination any) error {
	request, err := http.NewRequest(http.MethodGet, p.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("request Ollama loopback endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Ollama endpoint returned status %d", response.StatusCode)
	}

	limited := io.LimitReader(response.Body, maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read Ollama response: %w", err)
	}
	if len(data) > maxResponseSize {
		return errors.New("Ollama response exceeds probe size limit")
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode Ollama JSON response: %w", err)
	}
	return nil
}
