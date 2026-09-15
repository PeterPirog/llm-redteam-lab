# syntax=docker/dockerfile:1

ARG GO_BUILDER_IMAGE
ARG OLLAMA_BASE_IMAGE

FROM ${GO_BUILDER_IMAGE} AS probe-builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o /out/rt-ollama-probe \
    .

FROM ${OLLAMA_BASE_IMAGE}
COPY --from=probe-builder /out/rt-ollama-probe /usr/local/bin/rt-ollama-probe
ENTRYPOINT ["/bin/ollama"]
