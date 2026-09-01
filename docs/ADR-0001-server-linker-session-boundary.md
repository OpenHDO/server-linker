# ADR-0001: Server-side Linker session boundary

## Status

Accepted; reconciled with `server/contracts/v1` on 2026-09-01.

## Decision

The wire boundary uses the normative v1 Message Envelope exactly:

```json
{
  "v": 1,
  "id": "uuid",
  "type": "link.register",
  "ts": "2026-01-01T00:00:00Z",
  "source": "linker.example",
  "payload": {}
}
```

The boundary does not add a `schema` or protocol namespace, and does not put
session metadata at the top level. `Envelope` validates the v1 fields and
major version before routing. The v1 `link-manifest` payload is also used
without additions: `id`, semantic `version`, `name`, and unique lowercase
`transports`.

Authentication is an adapter concern. The adapter opens a local session with
the already authenticated `authenticated_source`; every incoming envelope's
`source` must match it, and registration requires `payload.id` to match it.
The opaque `session_id` is local routing context and is never serialized into
the v1 envelope. Reconnecting with the same stable manifest `id` replaces the
current session without duplicating the registry identity.

The v1 major version is the protocol negotiation boundary. There is no second
`hello`/minor-version namespace: unsupported `v` values are rejected before
payload processing, as required by the server contract.

Heartbeats use `link.heartbeat` with a monotonic `sequence`; acknowledgements
are v1 envelopes correlated to the heartbeat envelope `id`. Session lifecycle
and liveness remain explicit: `authenticated -> registered -> active`, with
`stale` and terminal `closed`; health is `unknown`, `healthy`, `stale`, or
`offline`.

Commands use `light.command` envelopes. The command envelope `id` is the
Correlation Identifier. Linker results use `command.result` with that UUID in
`correlation_id`; duplicate results are acknowledged from a bounded in-memory
completed store. Pending commands remain across session replacement, so an
authenticated reconnect can finish an in-flight command. `light.event` is
reserved for the same v1 envelope and is not interpreted as a device driver.

## Consequences

- Transport, credentials, authorization policy, persistence, and physical
  device drivers stay outside this repository.
- The pending/completed stores provide only local in-process delivery and
  idempotence. A multi-process deployment must replace them with a durable
  repository/message store before claiming delivery across process failure.
- Response envelopes use `correlation_id` for request-reply and have the server
  source; session routing remains an adapter-side concern.
