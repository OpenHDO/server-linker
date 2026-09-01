# ADR-0001: Server-side Linker session boundary

## Status

Accepted

## Decision

The server boundary uses versioned JSON-shaped messages under `openhdo.linker/1`.
It negotiates an exact `major.minor` protocol version during `hello`, validates
the manifest before registration, and routes only four inbound message types:
`hello`, `register`, `heartbeat`, and `command_reply`.

Each connection receives a server-issued `session_id`. The Linker-provided
`linker_id` is the stable registry identity, so reconnecting replaces the
current session without creating a duplicate registry entry. Pending commands
remain keyed by their server-issued `command_id`; a reply from the replacement
session can therefore complete a command issued before reconnect.

Session lifecycle and liveness are separate, explicit state machines. Sessions
move through `new -> negotiating -> registered -> active`, can become `stale`
when the heartbeat deadline expires, and end at `closed`. Health moves from
`unknown` to `healthy`, `stale`, or `offline`. State and command events are
emitted through an injected event sink for metrics and audit integration.

## Consequences

- Transport, authentication, device drivers, and driver-specific payloads stay
  outside this repository.
- The in-memory registry and bounded completed-command store are local-first and
  suitable for a modular monolith; a later multi-process deployment must place
  those stores behind a shared repository/message store.
- Only exact versions currently supported by the server are negotiated. Adding
  a protocol version requires adding its implementation and tests explicitly.
