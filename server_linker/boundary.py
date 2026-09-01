"""Transport-independent server boundary for OpenHDO Linker sessions.

Wire messages are the v1 envelope from ``server/contracts/v1``. Authentication
and transport remain caller-owned; this module receives the authenticated
source when a local session is opened.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import math
import re
import time
from typing import Any
from uuid import UUID, uuid4


PROTOCOL_VERSION = 1
LINK_REGISTER = "link.register"
LINK_REGISTERED = "link.registered"
LINK_HEARTBEAT = "link.heartbeat"
LINK_HEARTBEAT_ACK = "link.heartbeat.ack"
LIGHT_COMMAND = "light.command"
LIGHT_EVENT = "light.event"
COMMAND_RESULT = "command.result"
COMMAND_ACK = "command.ack"

_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
_SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class BoundaryError(Exception):
    """Base error raised by the Linker boundary."""


class ProtocolError(BoundaryError, ValueError):
    """A v1 envelope, manifest, or message payload is invalid."""


class ValidationError(ProtocolError):
    """Backward-compatible name for boundary validation failures."""


class InvalidTransition(BoundaryError):
    """An operation is not valid for a session's current state."""


class CommandCorrelationError(BoundaryError):
    """A command result cannot be safely correlated to an issued command."""


class SessionState(str, Enum):
    AUTHENTICATED = "authenticated"
    REGISTERED = "registered"
    ACTIVE = "active"
    STALE = "stale"
    CLOSED = "closed"


class HealthState(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    STALE = "stale"
    OFFLINE = "offline"


@dataclass(frozen=True, slots=True)
class Envelope:
    """Validated OpenHDO v1 Message Envelope."""

    type: str
    source: str
    payload: Mapping[str, Any]
    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: UUID | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version: {self.version!r}")
        if not isinstance(self.id, UUID):
            raise ProtocolError("id must be a UUID")
        if self.correlation_id is not None and not isinstance(self.correlation_id, UUID):
            raise ProtocolError("correlation_id must be a UUID")
        if not isinstance(self.type, str) or not _TYPE_PATTERN.fullmatch(self.type):
            raise ProtocolError("type must be a lowercase domain name")
        if not isinstance(self.source, str) or not self.source or len(self.source) > 128:
            raise ProtocolError("source must contain 1 to 128 characters")
        if not isinstance(self.payload, Mapping):
            raise ProtocolError("payload must be an object")
        _validate_json(self.payload, "payload")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ProtocolError("timestamp must include a timezone")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "v": self.version,
            "id": str(self.id),
            "type": self.type,
            "ts": self.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": self.source,
            "payload": dict(self.payload),
        }
        if self.correlation_id is not None:
            data["correlation_id"] = str(self.correlation_id)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True, allow_nan=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Envelope":
        if not isinstance(data, Mapping):
            raise ProtocolError("envelope must be an object")
        required = {"v", "id", "type", "ts", "source", "payload"}
        allowed = required | {"correlation_id"}
        missing = required - set(data)
        unknown = set(data) - allowed
        if missing:
            raise ProtocolError(f"envelope is missing fields: {sorted(missing)!r}")
        if unknown:
            raise ProtocolError(f"unknown envelope fields: {sorted(unknown)!r}")
        if type(data["v"]) is not int or data["v"] != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version: {data['v']!r}")
        payload = data["payload"]
        if not isinstance(payload, Mapping):
            raise ProtocolError("payload must be an object")
        correlation = (
            None
            if "correlation_id" not in data
            else _parse_uuid(data["correlation_id"], "correlation_id")
        )
        return cls(
            type=data["type"],
            source=data["source"],
            payload=payload,
            id=_parse_uuid(data["id"], "id"),
            timestamp=_parse_timestamp(data["ts"]),
            correlation_id=correlation,
        )

    @classmethod
    def from_json(cls, value: str | bytes) -> "Envelope":
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as error:
            raise ProtocolError("envelope must contain valid JSON") from error
        if not isinstance(data, Mapping):
            raise ProtocolError("envelope must be an object")
        return cls.from_dict(data)


@dataclass(frozen=True, slots=True)
class LinkerManifest:
    """The v1 ``link.register`` payload."""

    id: str
    version: str
    name: str
    transports: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.id, "id")
        if not isinstance(self.version, str) or not _SEMVER_PATTERN.fullmatch(self.version):
            raise ProtocolError("version must use semantic versioning")
        _validate_text(self.name, "name", 128)
        if not isinstance(self.transports, tuple):
            raise ProtocolError("transports must be a tuple")
        if any(not isinstance(transport, str) or not _IDENTIFIER_PATTERN.fullmatch(transport) for transport in self.transports):
            raise ProtocolError("transports must be lowercase identifiers")
        if len(set(self.transports)) != len(self.transports):
            raise ProtocolError("transports must be unique")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "LinkerManifest":
        if not isinstance(payload, Mapping):
            raise ProtocolError("link.register payload must be an object")
        expected = {"id", "version", "name", "transports"}
        missing = expected - set(payload)
        unknown = set(payload) - expected
        if missing:
            raise ProtocolError(f"manifest is missing fields: {sorted(missing)!r}")
        if unknown:
            raise ProtocolError(f"unknown manifest fields: {sorted(unknown)!r}")
        transports = payload["transports"]
        if not isinstance(transports, Sequence) or isinstance(transports, (str, bytes)):
            raise ProtocolError("transports must be an array")
        return cls(
            id=payload["id"],
            version=payload["version"],
            name=payload["name"],
            transports=tuple(transports),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "transports": list(self.transports),
        }

    def registration(self, source: str) -> Envelope:
        return Envelope(LINK_REGISTER, source, self.to_payload())


@dataclass(frozen=True, slots=True)
class BoundaryEvent:
    event_type: str
    session_id: str
    at: float
    source: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IssuedCommand:
    """Local dispatch context plus its v1 wire envelope."""

    session_id: str
    envelope: Envelope

    def to_dict(self) -> dict[str, Any]:
        return self.envelope.to_dict()


@dataclass(frozen=True, slots=True)
class CommandCompletion:
    command_id: UUID
    source: str
    device_id: str
    status: str
    result: Any = None
    error: str | None = None


@dataclass(slots=True)
class _Session:
    session_id: str
    authenticated_source: str
    opened_at: float
    state: SessionState = SessionState.AUTHENTICATED
    health: HealthState = HealthState.UNKNOWN
    source: str | None = None
    manifest: LinkerManifest | None = None
    registered_at: float | None = None
    last_heartbeat_at: float | None = None
    last_heartbeat_sequence: int = 0


@dataclass(frozen=True, slots=True)
class _PendingCommand:
    command_id: UUID
    source: str
    device_id: str
    issued_session_id: str
    issued_at: float


_ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.AUTHENTICATED: frozenset({SessionState.REGISTERED, SessionState.CLOSED}),
    SessionState.REGISTERED: frozenset({SessionState.ACTIVE, SessionState.STALE, SessionState.CLOSED}),
    SessionState.ACTIVE: frozenset({SessionState.STALE, SessionState.CLOSED}),
    SessionState.STALE: frozenset({SessionState.ACTIVE, SessionState.CLOSED}),
    SessionState.CLOSED: frozenset(),
}


class LinkerBoundary:
    """Session, manifest, liveness, and command-correlation service layer."""

    def __init__(
        self,
        *,
        server_source: str = "server",
        heartbeat_timeout_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        event_sink: Callable[[BoundaryEvent], None] | None = None,
        completed_command_limit: int = 1024,
    ) -> None:
        _validate_text(server_source, "server_source", 128)
        if heartbeat_timeout_seconds <= 0 or not math.isfinite(heartbeat_timeout_seconds):
            raise ValidationError("heartbeat timeout must be a positive finite number")
        if not isinstance(completed_command_limit, int) or isinstance(completed_command_limit, bool):
            raise ValidationError("completed command limit must be an integer")
        if completed_command_limit < 1:
            raise ValidationError("completed command limit must be at least one")
        self.protocol_version = PROTOCOL_VERSION
        self.server_source = server_source
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._clock = clock
        self._wall_clock = wall_clock
        self._event_sink = event_sink or (lambda event: None)
        self._completed_command_limit = completed_command_limit
        self._sessions: dict[str, _Session] = {}
        self._current_by_source: dict[str, str] = {}
        self._manifests: dict[str, LinkerManifest] = {}
        self._pending_commands: dict[UUID, _PendingCommand] = {}
        self._completed_commands: dict[UUID, CommandCompletion] = {}

    def open_session(self, *, authenticated_source: str, now: float | None = None) -> str:
        """Open a local session for a source already authenticated by the caller."""
        _validate_text(authenticated_source, "authenticated_source", 128)
        at = self._now(now)
        session_id = f"ses_{uuid4().hex}"
        session = _Session(
            session_id=session_id,
            authenticated_source=authenticated_source,
            opened_at=at,
        )
        self._sessions[session_id] = session
        self._emit("link.session.opened", session, at)
        return session_id

    def handle(
        self,
        session_id: str,
        message: Mapping[str, Any] | Envelope,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Validate and route one v1 envelope in a session context."""
        envelope = message if isinstance(message, Envelope) else Envelope.from_dict(message)
        session = self._get_session(session_id)
        at = self._now(now)
        if envelope.source != session.authenticated_source:
            raise ProtocolError("envelope source does not match authenticated session source")
        if envelope.type == LINK_REGISTER:
            return self._handle_register(session, envelope, at)
        if envelope.type == LINK_HEARTBEAT:
            return self._handle_heartbeat(session, envelope, at)
        if envelope.type == COMMAND_RESULT:
            return self._handle_command_result(session, envelope, at)
        raise ProtocolError(f"unsupported Linker message type: {envelope.type!r}")

    def issue_command(
        self,
        *,
        linker_id: str,
        device_id: str,
        name: str,
        args: Mapping[str, Any] | None = None,
        command_id: UUID | str | None = None,
        now: float | None = None,
    ) -> IssuedCommand:
        """Create a v1 ``light.command`` with a bounded local pending store."""
        _validate_identifier(linker_id, "linker_id")
        _validate_text(device_id, "device_id", 128)
        _validate_text(name, "command name", 128)
        command_args = {} if args is None else dict(args) if isinstance(args, Mapping) else None
        if command_args is None:
            raise ValidationError("command args must be an object")
        _validate_json(command_args, "command args")
        session = self._current_session(linker_id)
        if session.state is not SessionState.ACTIVE or session.health is not HealthState.HEALTHY:
            raise InvalidTransition("commands require an active healthy Linker session")
        resolved_command_id = uuid4() if command_id is None else _parse_uuid(command_id, "command_id")
        if resolved_command_id in self._pending_commands or resolved_command_id in self._completed_commands:
            raise CommandCorrelationError(f"command_id already exists: {resolved_command_id}")
        at = self._now(now)
        envelope = Envelope(
            type=LIGHT_COMMAND,
            source=self.server_source,
            payload={"device_id": device_id, "command": name, "args": command_args},
            id=resolved_command_id,
            timestamp=self._timestamp(),
        )
        self._pending_commands[resolved_command_id] = _PendingCommand(
            command_id=resolved_command_id,
            source=linker_id,
            device_id=device_id,
            issued_session_id=session.session_id,
            issued_at=at,
        )
        self._emit(
            "light.command.issued",
            session,
            at,
            {"command_id": str(resolved_command_id), "device_id": device_id, "name": name},
        )
        return IssuedCommand(session_id=session.session_id, envelope=envelope)

    def check_health(self, *, now: float | None = None) -> tuple[dict[str, Any], ...]:
        """Mark current sessions stale after their heartbeat deadline expires."""
        at = self._now(now)
        changed: list[dict[str, Any]] = []
        for session in tuple(self._sessions.values()):
            if session.state not in {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE}:
                continue
            if session.source is None or self._current_by_source.get(session.source) != session.session_id:
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
            changed.append(self.status(session.source, now=at))
        return tuple(changed)

    def close_session(
        self,
        session_id: str,
        *,
        now: float | None = None,
        reason: str = "closed",
    ) -> None:
        """Close a session and retain its stable identity as offline."""
        _validate_text(session_id, "session_id", 128)
        _validate_text(reason, "close reason", 128)
        session = self._get_session(session_id)
        at = self._now(now)
        if session.state is SessionState.CLOSED:
            return
        self._transition(session, SessionState.CLOSED, reason, at)
        self._set_health(session, HealthState.OFFLINE, at, reason)
        if session.source and self._current_by_source.get(session.source) == session_id:
            del self._current_by_source[session.source]

    def status(self, linker_id: str, *, now: float | None = None) -> dict[str, Any]:
        """Return the internal registry view for one stable Linker ID."""
        _validate_identifier(linker_id, "linker_id")
        manifest = self._manifests.get(linker_id)
        if manifest is None:
            raise ValidationError(f"unknown linker_id: {linker_id!r}")
        session_id = self._current_by_source.get(linker_id)
        session = self._sessions.get(session_id) if session_id else None
        at = self._now(now)
        if session is None:
            return {
                "id": linker_id,
                "manifest": manifest.to_payload(),
                "session_id": None,
                "state": SessionState.CLOSED.value,
                "health": HealthState.OFFLINE.value,
                "last_heartbeat_sequence": 0,
            }
        return {
            "id": linker_id,
            "manifest": manifest.to_payload(),
            "session_id": session.session_id,
            "state": session.state.value,
            "health": session.health.value,
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

    def _handle_register(self, session: _Session, envelope: Envelope, at: float) -> dict[str, Any]:
        self._require_state(session, {SessionState.AUTHENTICATED})
        manifest = LinkerManifest.from_payload(envelope.payload)
        if manifest.id != session.authenticated_source:
            raise ProtocolError("manifest id does not match authenticated session source")
        old_session_id = self._current_by_source.get(manifest.id)
        if old_session_id and old_session_id != session.session_id:
            old_session = self._get_session(old_session_id)
            self._transition(old_session, SessionState.CLOSED, "reconnected", at)
            self._set_health(old_session, HealthState.OFFLINE, at, "reconnected")
        session.source = manifest.id
        session.manifest = manifest
        session.registered_at = at
        session.last_heartbeat_at = None
        session.last_heartbeat_sequence = 0
        self._manifests[manifest.id] = manifest
        self._current_by_source[manifest.id] = session.session_id
        self._transition(session, SessionState.REGISTERED, "manifest_registered", at)
        self._emit(
            "link.registered",
            session,
            at,
            {"manifest_id": manifest.id, "transport_count": len(manifest.transports)},
        )
        return self._response(
            LINK_REGISTERED,
            {
                "id": manifest.id,
                "heartbeat_timeout_seconds": self.heartbeat_timeout_seconds,
            },
            correlation_id=envelope.id,
        )

    def _handle_heartbeat(self, session: _Session, envelope: Envelope, at: float) -> dict[str, Any]:
        self._require_current(session)
        self._require_state(session, {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE})
        sequence = envelope.payload.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise ProtocolError("heartbeat sequence must be a positive integer")
        duplicate = sequence <= session.last_heartbeat_sequence
        if duplicate:
            self._emit("link.heartbeat.duplicate", session, at, {"sequence": sequence})
        else:
            session.last_heartbeat_sequence = sequence
            session.last_heartbeat_at = at
            if session.state is not SessionState.ACTIVE:
                self._transition(session, SessionState.ACTIVE, "heartbeat_received", at)
            self._set_health(session, HealthState.HEALTHY, at, "heartbeat_received")
            self._emit("link.heartbeat.received", session, at, {"sequence": sequence})
        return self._response(
            LINK_HEARTBEAT_ACK,
            {
                "id": session.source,
                "sequence": session.last_heartbeat_sequence,
                "duplicate": duplicate,
                "state": session.state.value,
                "health": session.health.value,
            },
            correlation_id=envelope.id,
        )

    def _handle_command_result(self, session: _Session, envelope: Envelope, at: float) -> dict[str, Any]:
        self._require_current(session)
        self._require_state(session, {SessionState.REGISTERED, SessionState.ACTIVE, SessionState.STALE})
        if envelope.correlation_id is None:
            raise CommandCorrelationError("command.result requires correlation_id")
        device_id = envelope.payload.get("device_id")
        _validate_text(device_id, "device_id", 128)
        status = envelope.payload.get("status")
        if status not in {"ok", "error"}:
            raise ProtocolError("command.result status must be 'ok' or 'error'")
        result = envelope.payload.get("result")
        error = envelope.payload.get("error")
        if status == "error":
            _validate_text(error, "command.result error", 512)
        elif error is not None:
            raise ProtocolError("successful command.result cannot contain error")
        _validate_json(result, "command.result result")

        pending = self._pending_commands.get(envelope.correlation_id)
        if pending is None:
            previous = self._completed_commands.get(envelope.correlation_id)
            if previous is None:
                raise CommandCorrelationError(f"unknown command correlation_id: {envelope.correlation_id}")
            if previous.source != session.source or previous.device_id != device_id:
                raise CommandCorrelationError("command.result identity does not match completed command")
            self._emit(
                "command.result.duplicate",
                session,
                at,
                {"command_id": str(previous.command_id)},
            )
            return self._command_ack(previous, envelope.id, duplicate=True)
        if pending.source != session.source or pending.device_id != device_id:
            raise CommandCorrelationError("command.result identity does not match pending command")
        completion = CommandCompletion(
            command_id=pending.command_id,
            source=pending.source,
            device_id=device_id,
            status=status,
            result=result,
            error=error,
        )
        del self._pending_commands[pending.command_id]
        self._completed_commands[pending.command_id] = completion
        while len(self._completed_commands) > self._completed_command_limit:
            del self._completed_commands[next(iter(self._completed_commands))]
        self._emit(
            "command.result.accepted",
            session,
            at,
            {"command_id": str(pending.command_id), "issued_session_id": pending.issued_session_id},
        )
        return self._command_ack(completion, envelope.id, duplicate=False)

    def _command_ack(
        self,
        completion: CommandCompletion,
        correlation_id: UUID,
        *,
        duplicate: bool,
    ) -> dict[str, Any]:
        return self._response(
            COMMAND_ACK,
            {
                "command_id": str(completion.command_id),
                "device_id": completion.device_id,
                "status": completion.status,
                "accepted": True,
                "duplicate": duplicate,
                "result": completion.result,
                "error": completion.error,
            },
            correlation_id=correlation_id,
        )

    def _response(
        self,
        message_type: str,
        payload: Mapping[str, Any],
        *,
        correlation_id: UUID,
    ) -> dict[str, Any]:
        return Envelope(
            type=message_type,
            source=self.server_source,
            payload=payload,
            correlation_id=correlation_id,
            timestamp=self._timestamp(),
        ).to_dict()

    def _current_session(self, linker_id: str) -> _Session:
        session_id = self._current_by_source.get(linker_id)
        if session_id is None:
            raise InvalidTransition(f"Linker is not registered: {linker_id!r}")
        return self._get_session(session_id)

    def _require_current(self, session: _Session) -> None:
        if session.source is None or self._current_by_source.get(session.source) != session.session_id:
            raise InvalidTransition("session is no longer current for its Linker identity")

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
            raise InvalidTransition(f"invalid transition {session.state.value!r} -> {target.value!r}")
        previous = session.state
        session.state = target
        self._emit(
            "link.session.state_changed",
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
            "link.health.changed",
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
                source=session.source or session.authenticated_source,
                details=dict(details),
            )
        )

    def _now(self, now: float | None) -> float:
        value = self._clock() if now is None else now
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValidationError("time must be a finite number")
        return float(value)

    def _timestamp(self) -> datetime:
        value = self._wall_clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValidationError("wall clock must return a timezone-aware datetime")
        return value


def _parse_uuid(value: Any, field_name: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ProtocolError(f"{field_name} must be a UUID")
    try:
        return UUID(value)
    except ValueError as error:
        raise ProtocolError(f"{field_name} must be a UUID") from error


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("ts must be an ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ProtocolError("ts must be an ISO-8601 string") from error
    if timestamp.tzinfo is None:
        raise ProtocolError("ts must include a timezone")
    return timestamp.astimezone(timezone.utc)


def _validate_identifier(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ProtocolError(f"{field_name} must be a lowercase identifier")


def _validate_text(value: Any, field_name: str, max_length: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ProtocolError(f"{field_name} must contain 1 to {max_length} characters")


def _validate_json(value: Any, field_name: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProtocolError(f"{field_name} must contain only finite JSON numbers")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _validate_json(item, field_name)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"{field_name} object keys must be strings")
            _validate_json(item, field_name)
        return
    raise ProtocolError(f"{field_name} contains a non-JSON value: {type(value).__name__}")
