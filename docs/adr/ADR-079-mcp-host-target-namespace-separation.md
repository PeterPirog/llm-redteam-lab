# ADR-079 — Separate MCP host staging from target-visible paths

- Status: Proposed
- Date: 2026-09-13

## Context

The OpenCode MCP fixture transport intentionally keeps attacker-controlled indirect context
out of the ordinary HTTP prompt. `McpFixtureBridgeProfile` currently declares the context and
hash paths used by the MCP stdio sidecar.

That works in the trusted-harness tests because the control plane and OpenCode share one
filesystem namespace. It is not a valid Docker assumption. On a Windows host, for example,
the control plane may stage a file below `D:\...` while the isolated Linux container must see
that file at `/control/mcp/context.txt`.

Reusing one raw path for both meanings creates two problems:

1. host staging and target-visible configuration become accidentally coupled;
2. a later Docker implementation is tempted either to expose the writable Blue workspace or
   to fake a path that does not exist in one of the namespaces.

The existing hardened Docker sandbox correctly refuses extra mounts. It must not be weakened
until the control-plane/target path distinction is explicit.

## Decision

Introduce a provider-neutral MCP fixture staging boundary before adding a compound Docker
mount.

`McpFixtureBridgeProfile` remains the stable **target-visible** policy. Its paths are the
paths passed to the OpenCode MCP server configuration and are part of Blue application
identity.

`McpFixtureStagingBackend` owns the **control-plane host** namespace. The initial filesystem
implementation receives explicit host context/hash paths and never assumes they equal the
bridge paths.

A `McpFixtureRuntimeBinding` binds the two sides only through hashes:

- bridge policy SHA-256;
- staging policy SHA-256;
- host context-path SHA-256;
- host hash-path SHA-256.

Raw host paths remain runtime handles and must not be persisted as experiment provenance.

## Stage lifecycle

The filesystem staging backend:

1. requires trusted, real parent directories;
2. rejects path symlinks and symlink-traversing parents;
3. refuses any pre-existing sidecar instead of overwriting it;
4. verifies the supplied content hash before writing;
5. creates the context and hash files exclusively;
6. records an ephemeral stage handle;
7. verifies staged bytes and hash text again before cleanup;
8. removes only files belonging to its active stage;
9. emits a hash-only cleanup/integrity result.

An integrity failure and a cleanup failure are separate facts. Future target integration must
fail closed if staged content changed unexpectedly or if sidecars cannot be cleared.

## Identity semantics

The target-visible bridge policy contributes to Blue target identity. Ephemeral host staging
locations do **not**: a different temporary host directory for the next trial must not create a
new logical Blue target.

The host-path hashes belong to per-run runtime evidence and later Docker mount attestation.

The staging *semantics* have their own policy fingerprint so changing how the trusted control
plane stages/clears fixture data remains auditable without embedding raw host paths in target
configuration.

## Trusted-harness compatibility

`FilesystemMcpFixtureStagingBackend.from_bridge_paths()` is retained as a compatibility mode
for tests or trusted harnesses where host and target intentionally share one filesystem
namespace. Docker code must not use that shortcut.

## Docker follow-up

The next compound-isolation milestone should add a dedicated Docker profile that verifies
exactly:

- one read-write Blue workspace mount; and
- one separately controlled read-only MCP fixture/control mount.

The existing one-mount `DockerSandboxProfile` remains the strict default and should not be
relaxed globally.

The compound profile must bind the read-only mount destination to the target-visible bridge
policy and bind the mount source to the hash-only runtime staging binding. Fixture content
hash remains per-run attack evidence, not Blue target identity.

## Security consequences

This separation prevents attacker-controlled MCP content from expanding its own permissions:

- the content is staged by the trusted control plane;
- target-visible paths are fixed before the attack;
- the future Docker mount is read-only to Blue;
- raw host paths are not exposed as model inputs or persisted evidence;
- stale sidecars fail closed.

It does not by itself prove Docker confinement, network denial or system compromise. Those
remain responsibilities of runtime attestation and independent system-state verification.

## Tests

Deterministic tests require that:

- host staging paths can differ from target-visible `/control/...` paths;
- OpenCode MCP environment continues to contain only target-visible paths;
- runtime bindings persist only hashes, not raw host paths;
- sidecars contain the exact synthetic content/hash while active;
- pre-existing sidecars are never overwritten;
- tampered staged bytes produce an integrity failure;
- wrong content hash fails before files are created;
- only the active stage can clear its sidecars;
- changing only the ephemeral host namespace changes runtime binding but not bridge identity.

No Docker daemon, Ollama daemon, GPU, model endpoint or model inference is required.
