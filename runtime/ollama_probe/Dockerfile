# syntax=docker/dockerfile:1

ARG GO_BUILDER_IMAGE
ARG OLLAMA_BASE_IMAGE

FROM ${GO_BUILDER_IMAGE} AS probe-builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o /out/rt-ollama-probe \
    . \
 && CGO_ENABLED=0 GOOS=linux go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o /out/rt-opencode-probe \
    ./cmd/opencode-probe

FROM ${OLLAMA_BASE_IMAGE}
COPY --from=probe-builder /out/rt-ollama-probe /usr/local/bin/rt-ollama-probe
COPY --from=probe-builder /out/rt-opencode-probe /usr/local/bin/rt-opencode-probe
ENTRYPOINT ["/bin/ollama"]
