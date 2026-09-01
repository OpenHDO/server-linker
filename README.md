# OpenHDO Server Linker

`server-linker` is the server-side module for authenticated
`openhdo-linker` sessions. It owns Linker registration, identity, locations,
health, capabilities, device inventory, lifecycle, and command routing.

## Boundary

This module speaks the versioned Linker protocol. It does not contain Wi-Fi,
Bluetooth, Zigbee, USB, serial, or device-specific drivers; those belong in
the standalone [linker](https://github.com/OpenHDO/linker) process.

## Status

The first server-side session-boundary slice is implemented in the dependency-
free `server_linker` package. It negotiates protocol `1.0`, validates and
registers a manifest, tracks explicit session/health states, preserves stable
`linker_id` identity across reconnects, and correlates idempotent command
replies by server-issued `command_id`.

The boundary accepts JSON-shaped mappings and leaves authentication and
transport adapters to the caller. Run its checks with:

```text
python -m unittest discover -s tests -v
```

See [ADR-0001](docs/ADR-0001-server-linker-session-boundary.md) for the
identity, state, and command-correlation decisions.

See the [project architecture](https://github.com/OpenHDO/about/blob/main/ARCHITECTURE.md)
and [server contracts](https://github.com/OpenHDO/server/tree/master/contracts/v1).
