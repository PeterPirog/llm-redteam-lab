package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	defaultUsername = "opencode"
	maxResponseSize = 1024 * 1024
)

type healthResponse struct {
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
}

type probe struct {
	client *http.Client
}

func newProbe() *probe {
	return &probe{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout, newProbe()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, p *probe) error {
	if len(args) != 2 || args[0] != "health" {
		return errors.New("usage: rt-opencode-probe health <loopback-url>")
	}
	if p == nil || p.client == nil {
		return errors.New("probe configuration is incomplete")
	}
	endpoint, err := validateLoopbackURL(args[1])
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build OpenCode health request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	password := os.Getenv("OPENCODE_SERVER_PASSWORD")
	if password != "" {
		username := os.Getenv("OPENCODE_SERVER_USERNAME")
		if username == "" {
			username = defaultUsername
		}
		request.SetBasicAuth(username, password)
	}

	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("request OpenCode loopback health: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("OpenCode health endpoint returned status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read OpenCode health response: %w", err)
	}
	if len(data) > maxResponseSize {
		return errors.New("OpenCode health response exceeds probe size limit")
	}
	var payload healthResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("decode OpenCode health JSON response: %w", err)
	}
	if !payload.Healthy {
		return errors.New("OpenCode health response is not healthy")
	}
	if payload.Version == "" {
		return errors.New("OpenCode health response is missing version")
	}
	return json.NewEncoder(stdout).Encode(payload)
}

func validateLoopbackURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("OpenCode health URL is invalid")
	}
	if parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("OpenCode health URL must be plain HTTP without credentials/query/fragment")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("OpenCode health URL must use a loopback host")
	}
	if parsed.Port() == "" || parsed.Path != "/global/health" {
		return "", errors.New("OpenCode health URL must target /global/health on an explicit port")
	}
	return parsed.String(), nil
}
