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
	baseURL         = "http://127.0.0.1:11434"
	maxResponseSize = 8 * 1024 * 1024
)

var client = &http.Client{Timeout: 5 * time.Second}

type versionResponse struct {
	Version string `json:"version"`
}

type readinessResponse struct {
	Provider string `json:"provider"`
	Ready    bool   `json:"ready"`
	Version  string `json:"version"`
}

func main() {
	if len(os.Args) != 2 {
		fail(errors.New("usage: rt-ollama-probe <version|tags>"))
	}

	switch os.Args[1] {
	case "version":
		if err := emitVersion(); err != nil {
			fail(err)
		}
	case "tags":
		if err := emitTags(); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unsupported command: %s", os.Args[1]))
	}
}

func emitVersion() error {
	var payload versionResponse
	if err := getJSON("/api/version", &payload); err != nil {
		return err
	}
	if payload.Version == "" {
		return errors.New("Ollama version response is missing version")
	}
	return json.NewEncoder(os.Stdout).Encode(readinessResponse{
		Provider: "ollama",
		Ready:    true,
		Version:  payload.Version,
	})
}

func emitTags() error {
	var payload map[string]any
	if err := getJSON("/api/tags", &payload); err != nil {
		return err
	}
	models, ok := payload["models"]
	if !ok {
		return errors.New("Ollama tags response is missing models")
	}
	if _, ok := models.([]any); !ok {
		return errors.New("Ollama tags response models is not an array")
	}
	return json.NewEncoder(os.Stdout).Encode(payload)
}

func getJSON(path string, destination any) error {
	request, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	response, err := client.Do(request)
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
