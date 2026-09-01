"""Transport-independent Linker session boundary.

The boundary accepts and returns JSON-shaped mappings. Authentication and the
transport that carries those mappings are intentionally owned by callers.
"""

from __future__ import annotations

import math
import re
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


SCHEMA = "openhdo.linker/1"
_PROTOCOL_NAME = "openhdo-linker"
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class BoundaryError(Exception):
    """Base error raised by the Linker boundary."""


class ValidationError(BoundaryError, ValueError):
    """A message or public method argument failed validation."""


class InvalidTransition(BoundaryError):
    """An operation is not valid for the session's current state."""


class ProtocolNegotiationError(BoundaryError):
    """No protocol version is shared by the Linker and server."""


class CommandCorrelationError(BoundaryError):
    """A command reply cannot be safely correlated to an issued command."""


class SessionState(str, Enum):
    NEW = "new"
    NEGOTIATING = "negotiating"
    REGISTERED = "registered"
    ACTIVE = "active"
    STALE = "stale"
    CLOSED = "closed"


class HealthState(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    STALE = "stale"
    OFFLINE = "offline"


@dataclass(frozen=True, slots=True, order=True)
class ProtocolVersion:
    """A major/minor protocol version advertised during negotiation."""

    major: int
    minor: int

    def __post_init__(self) -> None:
        if not isinstance(self.major, int) or isinstance(self.major, bool) or self.major < 0:
            raise ValidationError("protocol major must be a non-negative integer")
        if not isinstance(self.minor, int) or isinstance(self.minor, bool) or self.minor < 0:
            raise ValidationError("protocol minor must be a non-negative integer")

    @classmethod
    def parse(cls, value: Any) -> "ProtocolVersion":
        if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
            raise ValidationError(f"invalid protocol version: {value!r}")
        major, minor = (int(part) for part in value.split("."))
        return cls(major, minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True, slots=True)
class DeviceManifest:
    device_id: str
    kind: str
    name: str
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_id(self.device_id, "device_id")
        _validate_text(self.kind, "kind", 64)
        _validate_text(self.name, "name", 128)
        _validate_strings(self.capabilities, "device capabilities", 64)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "DeviceManifest":
        if not isinstance(payload, Mapping):
            raise ValidationError("device manifest must be an object")
        return cls(
            device_id=_required(payload, "device_id"),
            kind=_required(payload, "kind"),
            name=_required(payload, "name"),
            capabilities=_string_sequence(payload.get("capabilities", ()), "device capabilities"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "kind": self.kind,
            "name": self.name,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True, slots=True)
class LinkerManifest:
    linker_id: str
    name: str
    version: str
    devices: tuple[DeviceManifest, ...] = ()
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_id(self.linker_id, "linker_id")
        _validate_text(self.name, "name", 128)
        _validate_text(self.version, "version", 64)
        _validate_strings(self.capabilities, "capabilities", 64)
        if not isinstance(self.devices, Sequence) or isinstance(self.devices, (str, bytes)):
            raise ValidationError("devices must be an array")
        if any(not isinstance(device, DeviceManifest) for device in self.devices):
            raise ValidationError("devices must contain DeviceManifest values")
        device_ids = [device.device_id for device in self.devices]
        if len(device_ids) != len(set(device_ids)):
            raise ValidationError("device_id values must be unique")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "LinkerManifest":
        if not isinstance(payload, Mapping):
            raise ValidationError("manifest must be an object")
        devices_value = payload.get("devices", ())
        if not isinstance(devices_value, Sequence) or isinstance(devices_value, (str, bytes)):
            raise ValidationError("manifest devices must be an array")
        return cls(
            linker_id=_required(payload, "linker_id"),
            name=_required(payload, "name"),
            version=_required(payload, "version"),
            devices=tuple(DeviceManifest.from_payload(item) for item in devices_value),
            capabilities=_string_sequence(payload.get("capabilities", ()), "capabilities"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "linker_id": self.linker_id,
            "name": self.name,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "devices": [device.to_payload() for device in self.devices],
        }


@dataclass(frozen=True, slots=True)
class BoundaryEvent:
    event_type: str
    session_id: str
    at: float
    linker_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CommandCompletion:
    command_id: str
    linker_id: str
    device_id: str
    status: str
    result: Any = None
    error: str | None = None
    duplicate: bool = False


@dataclass(slots=True)
class _Session:
    session_id: str
    opened_at: float
    state: SessionState = SessionState.NEW
    health: HealthState = HealthState.UNKNOWN
    protocol: ProtocolVersion | None = None
    linker_id: str | None = None
    manifest: LinkerManifest | None = None
    registered_at: float | None = None
    last_heartbeat_at: float | None = None
    last_heartbeat_sequence: int = 0


@dataclass(frozen=True, slots=True)
class _PendingCommand:
    command_id: str
    linker_id: str
    device_id: str
    issued_session_id: str
    issued_at: float


_ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.NEW: frozenset({SessionState.NEGOTIATING, SessionState.CLOSED}),
    SessionState.NEGOTIATING: frozenset({SessionState.REGISTERED, SessionState.CLOSED}),
    SessionState.REGISTERED: frozenset({SessionState.ACTIVE, SessionState.STALE, SessionState.CLOSED}),
    SessionState.ACTIVE: frozenset({SessionState.STALE, SessionState.CLOSED}),
    SessionState.STALE: frozenset({SessionState.ACTIVE, SessionState.CLOSED}),
    SessionState.CLOSED: frozenset(),
}


class LinkerBoundary:
    """Owns Linker identity, registration, liveness, and command correlation.

    ``handle`` is the versioned message boundary. It does not read sockets,
    perform authentication, or talk to device drivers.
    """

    def __init__(
        self,
        *,
        supported_protocols: Iterable[ProtocolVersion | str] = ("1.0",),
        heartbeat_timeout_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        event_sink: Callable[[BoundaryEvent], None] | None = None,
        completed_command_limit: int = 1024,
    ) -> None:
        protocols = tuple(
            value if isinstance(value, ProtocolVersion) else ProtocolVersion.parse(value)
            for value in supported_protocols
        )
        if not protocols:
            raise ValidationError("at least one supported protocol is required")
        if len(protocols) != len(set(protocols)):
            raise ValidationError("supported protocols must be unique")
        if heartbeat_timeout_seconds <= 0 or not math.isfinite(heartbeat_timeout_seconds):
            raise ValidationError("heartbeat timeout must be a positive finite number")
        if not isinstance(completed_command_limit, int) or isinstance(completed_command_limit, bool):
            raise ValidationError("completed command limit must be an integer")
        if completed_command_limit < 1:
            raise ValidationError("completed command limit must be at least one")

        self.supported_protocols = tuple(sorted(protocols, reverse=True))
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._clock = clock
        self._event_sink = event_sink or (lambda event: None)
        self._completed_command_limit = completed_command_limit
        self._sessions: dict[str, _Session] = {}
        self._current_by_linker: dict[str, str] = {}
        self._manifests: dict[str, LinkerManifest] = {}
        self._pending_commands: dict[str, _PendingCommand] = {}
        self._completed_commands: dict[str, CommandCompletion] = {}

    def open_session(self, *, now: float | None = None) -> str:
        """Allocate a server-side session ID for one authenticated connection."""
        at = self._now(now)
        session_id = f"ses_{uuid.uuid4().hex}"
        self._sessions[session_id] = _Session(session_id=session_id, opened_at=at)
        self._emit("session.opened", self._sessions[session_id], at)
        return session_id

    def handle(self, message: Mapping[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """Validate and route one versioned inbound protocol message."""
        if not isinstance(message, Mapping):
            raise ValidationError("message must be an object")
        if message.get("schema") != SCHEMA:
            raise ValidationError(f"schema must be {SCHEMA!r}")
        message_type = message.get("type")
        if message_type not in {"hello", "register", "heartbeat", "command_reply"}:
            raise ValidationError(f"unsupported message type: {message_type!r}")
        session_id = _required(message, "session_id")
        _validate_id(session_id, "session_id")
        at = self._now(now)
        if message_type == "hello":
            return self._handle_hello(session_id, message, at)
        if message_type == "register":
            return self._handle_register(session_id, message, at)
        if message_type == "heartbeat":
            return self._handle_heartbeat(session_id, message, at)
        return self._handle_command_reply(session_id, message, at)

    def issue_command(
        self,
        *,
        linker_id: str,
        device_id: str,
        name: str,
        args: Mapping[str, Any] | None = None,
        command_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Create a correlated command for the current healthy Linker session."""
        _validate_id(linker_id, "linker_id")
        _validate_id(device_id, "device_id")
        _validate_text(name, "command name", 128)
        if args is None:
            command_args: dict[str, Any] = {}
        elif isinstance(args, Mapping):
            command_args = dict(args)
        else:
            raise ValidationError("command args must be an object")
        _validate_json(command_args, "command args")

        session = self._current_session(linker_id)
        if session.state is not SessionState.ACTIVE or session.health is not HealthState.HEALTHY:
            raise InvalidTransition("commands require an active healthy Linker session")
        manifest = session.manifest
        assert manifest is not None
        if device_id not in {device.device_id for device in manifest.devices}:
            raise ValidationError(f"unknown device_id: {device_id!r}")

        at = self._now(now)
        resolved_command_id = command_id or f"cmd_{uuid.uuid4().hex}"
        _validate_id(resolved_command_id, "command_id")
        if resolved_command_id in self._pending_commands or resolved_command_id in self._completed_commands:
            raise CommandCorrelationError(f"command_id already exists: {resolved_command_id!r}")
        self._pending_commands[resolved_command_id] = _PendingCommand(
            command_id=resolved_command_id,
            linker_id=linker_id,
            device_id=device_id,
            issued_session_id=session.session_id,
            issued_at=at,
        )
        self._emit(
            "command.issued",
            session,
            at,
            {"command_id": resolved_command_id, "device_id": device_id, "name": name},
        )
        return {
            "schema": SCHEMA,
            "type": "command",
            "protocol_name": _PROTOCOL_NAME,
            "protocol": str(session.protocol),
            "session_id": session.session_id,
            "linker_id": linker_id,
            "device_id": device_id,
            "command_id": resolved_command_id,
            "name": name,
            "args": command_args,
        }

    def check_health(self, *, now: float | None = None) -> tuple[dict[str, Any], ...]:
        """Mark current sessions stale when their heartbeat deadline expires."""
        at = self._now(now)
        changed: list[dict[str, Any]] = []
        for session in tuple(self._sessions.values()):
            if session.state not in {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE}:
                continue
            if session.linker_id is None or self._current_by_linker.get(session.linker_id) != session.session_id:
                continue
            heartbeat_base = (
                session.last_heartbeat_at
                if session.last_heartbeat_at is not None
                else session.registered_at
            )
            if heartbeat_base is None or at - heartbeat_base < self.heartbeat_timeout_seconds:
                continue
            if session.state is not SessionState.STALE:
                self._transition(session, SessionState.STALE, "heartbeat_timeout", at)
            self._set_health(session, HealthState.STALE, at, "heartbeat_timeout")
            changed.append(self.status(session.linker_id, now=at))
        return tuple(changed)

    def close_session(self, session_id: str, *, now: float | None = None, reason: str = "closed") -> None:
        """Close a session and leave its stable identity visible as offline."""
        _validate_id(session_id, "session_id")
        session = self._get_session(session_id)
        at = self._now(now)
        if session.state is SessionState.CLOSED:
            return
        self._transition(session, SessionState.CLOSED, reason, at)
        self._set_health(session, HealthState.OFFLINE, at, reason)
        if session.linker_id and self._current_by_linker.get(session.linker_id) == session_id:
            del self._current_by_linker[session.linker_id]

    def status(self, linker_id: str, *, now: float | None = None) -> dict[str, Any]:
        """Return the server's current registry view for one stable Linker ID."""
        _validate_id(linker_id, "linker_id")
        manifest = self._manifests.get(linker_id)
        if manifest is None:
            raise ValidationError(f"unknown linker_id: {linker_id!r}")
        session_id = self._current_by_linker.get(linker_id)
        session = self._sessions.get(session_id) if session_id else None
        at = self._now(now)
        if session is None:
            return {
                "schema": SCHEMA,
                "linker_id": linker_id,
                "manifest": manifest.to_payload(),
                "session_id": None,
                "state": SessionState.CLOSED.value,
                "health": HealthState.OFFLINE.value,
                "protocol": None,
                "last_heartbeat_sequence": 0,
            }
        return {
            "schema": SCHEMA,
            "linker_id": linker_id,
            "manifest": manifest.to_payload(),
            "session_id": session.session_id,
            "state": session.state.value,
            "health": session.health.value,
            "protocol": str(session.protocol) if session.protocol else None,
            "last_heartbeat_sequence": session.last_heartbeat_sequence,
            "heartbeat_age_seconds": (
                None
                if session.last_heartbeat_at is None
                else max(0.0, at - session.last_heartbeat_at)
            ),
        }

    def registry_snapshot(self, *, now: float | None = None) -> tuple[dict[str, Any], ...]:
        """Return all known stable identities, including offline Linkers."""
        return tuple(self.status(linker_id, now=now) for linker_id in sorted(self._manifests))

    def _handle_hello(self, session_id: str, message: Mapping[str, Any], at: float) -> dict[str, Any]:
        session = self._get_session(session_id)
        self._require_state(session, {SessionState.NEW})
        if message.get("protocol_name") != _PROTOCOL_NAME:
            raise ValidationError(f"protocol_name must be {_PROTOCOL_NAME!r}")
        versions = message.get("protocol_versions")
        if not isinstance(versions, Sequence) or isinstance(versions, (str, bytes)) or not versions:
            raise ValidationError("protocol_versions must be a non-empty array")
        offered = tuple(ProtocolVersion.parse(value) for value in versions)
        if len(offered) != len(set(offered)):
            raise ValidationError("protocol_versions must be unique")
        selected = self._select_protocol(offered)
        session.protocol = selected
        self._transition(session, SessionState.NEGOTIATING, "protocol_negotiated", at)
        return {
            "schema": SCHEMA,
            "type": "hello_ack",
            "session_id": session_id,
            "protocol_name": _PROTOCOL_NAME,
            "protocol": str(selected),
            "heartbeat_timeout_seconds": self.heartbeat_timeout_seconds,
        }

    def _handle_register(self, session_id: str, message: Mapping[str, Any], at: float) -> dict[str, Any]:
        session = self._get_session(session_id)
        self._require_state(session, {SessionState.NEGOTIATING})
        manifest = LinkerManifest.from_payload(_required(message, "manifest"))
        old_session_id = self._current_by_linker.get(manifest.linker_id)
        if old_session_id and old_session_id != session_id:
            old_session = self._get_session(old_session_id)
            self._transition(old_session, SessionState.CLOSED, "reconnected", at)
            self._set_health(old_session, HealthState.OFFLINE, at, "reconnected")
        session.linker_id = manifest.linker_id
        session.manifest = manifest
        session.registered_at = at
        session.last_heartbeat_at = None
        session.last_heartbeat_sequence = 0
        self._manifests[manifest.linker_id] = manifest
        self._current_by_linker[manifest.linker_id] = session_id
        self._transition(session, SessionState.REGISTERED, "manifest_registered", at)
        self._emit(
            "linker.registered",
            session,
            at,
            {"device_count": len(manifest.devices), "manifest_version": manifest.version},
        )
        return {
            "schema": SCHEMA,
            "type": "register_ack",
            "session_id": session_id,
            "linker_id": manifest.linker_id,
            "protocol_name": _PROTOCOL_NAME,
            "protocol": str(session.protocol),
            "state": session.state.value,
            "health": session.health.value,
            "heartbeat_timeout_seconds": self.heartbeat_timeout_seconds,
        }

    def _handle_heartbeat(self, session_id: str, message: Mapping[str, Any], at: float) -> dict[str, Any]:
        session = self._get_session(session_id)
        self._require_state(session, {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE})
        linker_id = _required(message, "linker_id")
        _validate_id(linker_id, "linker_id")
        if session.linker_id != linker_id:
            raise ValidationError("heartbeat linker_id does not match the session identity")
        sequence = message.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise ValidationError("heartbeat sequence must be a positive integer")
        if sequence <= session.last_heartbeat_sequence:
            self._emit("heartbeat.duplicate", session, at, {"sequence": sequence})
            return {
                "schema": SCHEMA,
                "type": "heartbeat_ack",
                "session_id": session_id,
                "linker_id": linker_id,
                "sequence": session.last_heartbeat_sequence,
                "duplicate": True,
                "state": session.state.value,
                "health": session.health.value,
            }
        session.last_heartbeat_sequence = sequence
        session.last_heartbeat_at = at
        if session.state is not SessionState.ACTIVE:
            self._transition(session, SessionState.ACTIVE, "heartbeat_received", at)
        self._set_health(session, HealthState.HEALTHY, at, "heartbeat_received")
        self._emit("heartbeat.received", session, at, {"sequence": sequence})
        return {
            "schema": SCHEMA,
            "type": "heartbeat_ack",
            "session_id": session_id,
            "linker_id": linker_id,
            "sequence": sequence,
            "duplicate": False,
            "state": session.state.value,
            "health": session.health.value,
        }

    def _handle_command_reply(self, session_id: str, message: Mapping[str, Any], at: float) -> dict[str, Any]:
        session = self._get_session(session_id)
        self._require_state(session, {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE})
        linker_id = _required(message, "linker_id")
        device_id = _required(message, "device_id")
        command_id = _required(message, "command_id")
        _validate_id(linker_id, "linker_id")
        _validate_id(device_id, "device_id")
        _validate_id(command_id, "command_id")
        if session.linker_id != linker_id or self._current_by_linker.get(linker_id) != session_id:
            raise CommandCorrelationError("reply session is not the current session for linker_id")
        status = message.get("status")
        if status not in {"ok", "error"}:
            raise ValidationError("reply status must be 'ok' or 'error'")
        result = message.get("result")
        error = message.get("error")
        if status == "error":
            _validate_text(error, "reply error", 512)
        elif error is not None:
            raise ValidationError("successful reply cannot contain error")
        _validate_json(result, "reply result")

        pending = self._pending_commands.get(command_id)
        if pending is None:
            previous = self._completed_commands.get(command_id)
            if previous is None:
                raise CommandCorrelationError(f"unknown command_id: {command_id!r}")
            if previous.linker_id != linker_id or previous.device_id != device_id:
                raise CommandCorrelationError("reply identity does not match completed command")
            self._emit("command.duplicate_reply", session, at, {"command_id": command_id})
            return _command_ack(previous, duplicate=True)
        if pending.linker_id != linker_id or pending.device_id != device_id:
            raise CommandCorrelationError("reply identity does not match pending command")

        completion = CommandCompletion(
            command_id=command_id,
            linker_id=linker_id,
            device_id=device_id,
            status=status,
            result=result,
            error=error,
        )
        del self._pending_commands[command_id]
        self._completed_commands[command_id] = completion
        while len(self._completed_commands) > self._completed_command_limit:
            del self._completed_commands[next(iter(self._completed_commands))]
        self._emit(
            "command.completed",
            session,
            at,
            {"command_id": command_id, "status": status, "issued_session_id": pending.issued_session_id},
        )
        return _command_ack(completion, duplicate=False)

    def _select_protocol(self, offered: Sequence[ProtocolVersion]) -> ProtocolVersion:
        shared = [version for version in self.supported_protocols if version in offered]
        if not shared:
            raise ProtocolNegotiationError(
                f"no compatible protocol; offered={[str(value) for value in offered]!r}, "
                f"supported={[str(value) for value in self.supported_protocols]!r}"
            )
        return max(shared)

    def _current_session(self, linker_id: str) -> _Session:
        session_id = self._current_by_linker.get(linker_id)
        if session_id is None:
            raise InvalidTransition(f"Linker is not registered: {linker_id!r}")
        return self._get_session(session_id)

    def _get_session(self, session_id: str) -> _Session:
        try:
            return self._sessions[session_id]
        except KeyError as error:
            raise BoundaryError(f"unknown session_id: {session_id!r}") from error

    @staticmethod
    def _require_state(session: _Session, expected: set[SessionState]) -> None:
        if session.state not in expected:
            names = ", ".join(state.value for state in sorted(expected, key=lambda value: value.value))
            raise InvalidTransition(
                f"session {session.session_id!r} is {session.state.value!r}; expected one of {names}"
            )

    def _transition(self, session: _Session, target: SessionState, reason: str, at: float) -> None:
        if target is session.state:
            return
        if target not in _ALLOWED_TRANSITIONS[session.state]:
            raise InvalidTransition(
                f"invalid transition {session.state.value!r} -> {target.value!r}"
            )
        previous = session.state
        session.state = target
        self._emit(
            "session.state_changed",
            session,
            at,
            {"from": previous.value, "to": target.value, "reason": reason},
        )

    def _set_health(self, session: _Session, target: HealthState, at: float, reason: str) -> None:
        if target is session.health:
            return
        previous = session.health
        session.health = target
        self._emit(
            "session.health_changed",
            session,
            at,
            {"from": previous.value, "to": target.value, "reason": reason},
        )

    def _emit(
        self,
        event_type: str,
        session: _Session,
        at: float,
        details: Mapping[str, Any] = (),
    ) -> None:
        self._event_sink(
            BoundaryEvent(
                event_type=event_type,
                session_id=session.session_id,
                at=at,
                linker_id=session.linker_id,
                details=dict(details),
            )
        )

    def _now(self, now: float | None) -> float:
        value = self._clock() if now is None else now
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValidationError("time must be a finite number")
        return float(value)


def _command_ack(completion: CommandCompletion, *, duplicate: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "type": "command_ack",
        "command_id": completion.command_id,
        "linker_id": completion.linker_id,
        "device_id": completion.device_id,
        "status": completion.status,
        "accepted": True,
        "duplicate": duplicate,
        "result": completion.result,
        "error": completion.error,
    }


def _required(payload: Mapping[str, Any], name: str) -> Any:
    if name not in payload:
        raise ValidationError(f"missing required field: {name}")
    return payload[name]


def _validate_id(value: Any, field: str) -> None:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ValidationError(f"{field} must be a non-empty identifier (letters, digits, _ . : -)")


def _validate_text(value: Any, field: str, max_length: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValidationError(f"{field} must be non-empty text of at most {max_length} characters")


def _validate_strings(values: Any, field: str, max_length: int) -> None:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValidationError(f"{field} must be an array")
    if any(not isinstance(value, str) or not value or len(value) > max_length for value in values):
        raise ValidationError(f"{field} must contain non-empty strings of at most {max_length} characters")
    if len(values) != len(set(values)):
        raise ValidationError(f"{field} must not contain duplicates")


def _string_sequence(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValidationError(f"{field} must be an array")
    values = tuple(value)
    _validate_strings(values, field, 64)
    return values


def _validate_json(value: Any, field: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{field} must contain only finite JSON numbers")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _validate_json(item, field)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"{field} object keys must be strings")
            _validate_json(item, field)
        return
    raise ValidationError(f"{field} contains a non-JSON value: {type(value).__name__}")
