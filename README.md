# OpenHDO Server Linker

`server-linker` is the server-side Python module boundary for authenticated
Linker sessions. It owns Linker registration, stable identity, health,
lifecycle, and command routing; physical device drivers remain in the
standalone Linker process. It is not a gateway or runtime.

## Contract boundary

Wire messages use the normative [server `contracts/v1`](https://github.com/OpenHDO/server/tree/master/contracts/v1)
Message Envelope:

- required `v`, `id`, `type`, `ts`, `source`, and object `payload`;
- optional `correlation_id` for command results and request-reply;
- `v: 1` is the only supported protocol major;
- `link.register` payloads are exactly `id`, `version`, `name`, and unique
  lowercase `transports`.

The local `session_id` is supplied to `LinkerBoundary.handle()` by the
transport/authentication adapter and never becomes a top-level wire field.
`open_session(authenticated_source=...)` binds the session to the already
authenticated envelope source. Reconnects replace the current session for the
same manifest `id` while preserving pending command correlation.

The boundary uses `light.command`, `command.result`, and v1 envelopes for
future Light command/event integration. It does not implement transport or
device drivers.

Install the package and run the checks from a clean checkout with:

```sh
python -m pip install .
python -m unittest discover -s tests -v
python -m compileall -q server_linker tests
```

See [ADR-0001](docs/ADR-0001-server-linker-session-boundary.md) for the
reconciliation and state decisions.
