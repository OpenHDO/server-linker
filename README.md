# OpenHDO Server Linker

`server-linker` is the server-side module for authenticated
`openhdo-linker` sessions. It owns Linker registration, identity, locations,
health, capabilities, device inventory, lifecycle, and command routing.

## Boundary

This module speaks the versioned Linker protocol. It does not contain Wi-Fi,
Bluetooth, Zigbee, USB, serial, or device-specific drivers; those belong in
the standalone [linker](https://github.com/OpenHDO/linker) process.

## Status

Repository scaffold. The first vertical slice should authenticate one Linker,
register its manifest, maintain a heartbeat, and expose one device in the
server registry.

See the [project architecture](https://github.com/OpenHDO/about/blob/main/ARCHITECTURE.md)
and [server contracts](https://github.com/OpenHDO/server/tree/master/contracts/v1).
