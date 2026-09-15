# ADR-070: Every disposable AGENT trial receives an owned fresh Blue workspace

Status: Proposed

Date: 2026-09-15

## Context

`DISPOSABLE_SANDBOX` isolation requires more than a fresh conversation. OpenCode can mutate
files, tool state and repository contents, so reusing a host workspace across Red trials
would leak state and destroy comparability.

The control plane must also avoid deleting operator data. A generic temporary-directory
cleanup is insufficient because a path can be misconfigured, replaced by an alias or point
into the immutable template itself.

## Decision

Introduce `DisposableWorkspaceSupervisor` with a narrow ownership model:

- the immutable template is hashed before trials begin;
- template and sandbox roots must be disjoint in both directions;
- symlinks and, where the Python runtime exposes them, filesystem junctions are rejected;
- the sandbox root must be empty when the laboratory ownership marker is first created;
- every `trial_id` deterministically produces a unique active lease/path under that root;
- materialization is accepted only when its tree hash equals the template hash;
- persisted lease evidence contains only stable hashes, never the raw workspace path;
- cleanup is permitted only while the exact lease, profile, path hash and ownership marker
  still agree;
- aliases introduced during a trial fail cleanup closed rather than risking traversal;
- the final tree hash is recorded before deletion; and
- cleanup is complete only after the workspace path is verified absent.

## Security consequences

The laboratory never recursively deletes a non-empty unowned directory. A tampered
ownership marker, reused lease, path drift, template/sandbox overlap or filesystem alias
blocks cleanup instead of broadening deletion scope.

The final workspace tree hash is evidence of the trial's filesystem end-state, not a
persistent copy of potentially sensitive generated files.

## Follow-up

Compose this supervisor into the final OpenCode `DISPOSABLE_SANDBOX` lease provider. Target
transport must be awaited closed first, followed by AGENT, staged Ollama peer, isolated
network and finally this owned workspace before `cleanup_complete=true` is emitted.
