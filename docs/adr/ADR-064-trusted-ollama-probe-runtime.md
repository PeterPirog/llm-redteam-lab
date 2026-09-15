# ADR-064: Trusted Ollama probe runtime is a fixed loopback-only measurement component

Status: Proposed

Date: 2026-09-15

## Context

Exact runtime artifact verification must inspect the Ollama instance inside the owned model-peer container without issuing inference requests and without allowing the verifier to execute an arbitrary command. PR #102 therefore fixed the verifier contract to `/usr/local/bin/rt-ollama-probe tags`.

The probe itself becomes part of the trusted measurement base. If it can contact arbitrary hosts, follow redirects, accept unbounded responses, or drift independently of CI, exact-artifact evidence is weaker than the surrounding runtime ownership proofs.

## Decision

Maintain a laboratory-owned `runtime/ollama_probe` Go module with only two commands:

- `version`: GET `http://127.0.0.1:11434/api/version` and emit minimal readiness evidence;
- `tags`: GET `http://127.0.0.1:11434/api/tags`, require a JSON `models` array, and emit the provider inventory for existing `OllamaArtifactContract` verification.

Production behavior is fixed to the loopback origin. There is no environment variable, command-line option, DNS host, credential input, inference endpoint, or cloud fallback. HTTP redirects are not followed. Responses are capped at 8 MiB and requests time out after five seconds.

The multi-stage image build requires the trusted build process to provide both the Go builder and Ollama base images as digest-pinned references. The probe binary is built with CGO disabled, source paths trimmed, VCS stamping disabled, and an empty Go build ID.

CI uses Go 1.27 and independently requires:

1. `gofmt` cleanliness;
2. `go vet ./...`;
3. `go test -race ./...`;
4. the same deterministic build flags used by the Dockerfile.

The repository CI actions are moved to the current v7 action line and checkout credentials are not persisted in the workspace.

## Security consequences

- A malicious or drifted Ollama redirect cannot make the probe contact another endpoint.
- Probe configuration cannot silently change the selected service away from container loopback.
- Response-size and timeout bounds prevent the inventory path from becoming an unbounded resource sink.
- The verifier executes one fixed laboratory interface rather than an operator-supplied command.
- The probe does not perform model inference and does not require provider credentials.

## Measurement semantics

The probe source, Go toolchain line, build flags, builder image digest and Ollama base image digest are measurement-significant build inputs. A future runtime-image qualification step must bind the resulting image digest to the `DockerModelPeerProfile`; source-level CI alone is not sufficient proof of the image running on HAL.

## Follow-up

1. compose the probe with a digest-pinned Ollama model-peer image and exact staged model store;
2. bind the resulting image/artifact evidence to the owned model-peer lease;
3. compose model-peer artifact proof with OpenCode environment attestation;
4. expose the complete runtime through a `DISPOSABLE_SANDBOX` trial lease before the first HAL smoke.
