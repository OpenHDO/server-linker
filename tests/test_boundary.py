import unittest
from datetime import datetime, timezone
from uuid import UUID, uuid4

from server_linker import (
    COMMAND_RESULT,
    CommandCorrelationError,
    Envelope,
    HealthState,
    InvalidTransition,
    LIGHT_COMMAND,
    LIGHT_EVENT,
    LINK_HEARTBEAT,
    LINK_REGISTER,
    LinkerBoundary,
    LinkerManifest,
    PROTOCOL_VERSION,
    ProtocolError,
    SessionState,
)


SOURCE = "linker.kitchen"
MANIFEST = {
    "id": SOURCE,
    "version": "0.1.0",
    "name": "Kitchen Linker",
    "transports": ["zigbee", "bluetooth"],
}


def message(message_type, source=SOURCE, payload=None, **kwargs):
    return Envelope(
        type=message_type,
        source=source,
        payload={} if payload is None else payload,
        **kwargs,
    ).to_dict()


class LinkerBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 100.0
        self.events = []
        self.boundary = LinkerBoundary(
            heartbeat_timeout_seconds=10,
            clock=lambda: self.now,
            wall_clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_sink=self.events.append,
        )

    def open_registered(self, manifest=MANIFEST, source=SOURCE):
        session_id = self.boundary.open_session(authenticated_source=source, now=self.now)
        register = message(LINK_REGISTER, source, manifest)
        ack = self.boundary.handle(session_id, register, now=self.now)
        self.assertEqual(ack["v"], PROTOCOL_VERSION)
        self.assertEqual(ack["type"], "link.registered")
        self.assertEqual(ack["correlation_id"], register["id"])
        self.assertNotIn("session_id", ack)
        return session_id

    def heartbeat(self, session_id, sequence=1):
        return self.boundary.handle(
            session_id,
            message(LINK_HEARTBEAT, payload={"sequence": sequence}),
            now=self.now,
        )

    def test_envelope_round_trip_matches_v1_shape(self):
        correlation_id = uuid4()
        envelope = Envelope(
            type="command.result",
            source=SOURCE,
            payload={"ok": True},
            correlation_id=correlation_id,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        decoded = Envelope.from_json(envelope.to_json())

        self.assertEqual(decoded, envelope)
        self.assertEqual(
            set(envelope.to_dict()),
            {"v", "id", "type", "ts", "source", "payload", "correlation_id"},
        )
        self.assertEqual(envelope.to_dict()["v"], 1)

    def test_legacy_namespace_and_unsupported_major_are_rejected(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(
                {
                    "schema": "openhdo.linker/1",
                    "type": "hello",
                    "session_id": "ses_old",
                    "payload": {},
                }
            )
        legacy_fields = message(LINK_REGISTER, payload=MANIFEST)
        legacy_fields["schema"] = "openhdo.linker/1"
        legacy_fields["session_id"] = "ses_old"
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(legacy_fields)
        unsupported = message("link.register")
        unsupported["v"] = 2
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(unsupported)

    def test_register_uses_normative_v1_manifest_and_authenticated_source(self):
        session_id = self.open_registered()
        status = self.boundary.status(SOURCE, now=self.now)

        self.assertEqual(status["id"], SOURCE)
        self.assertEqual(status["manifest"], MANIFEST)
        self.assertEqual(status["state"], SessionState.REGISTERED.value)
        self.assertEqual(status["health"], HealthState.UNKNOWN.value)
        self.assertNotIn("devices", status["manifest"])
        self.assertIn("link.registered", [event.event_type for event in self.events])
        self.assertEqual(self.boundary.registry_snapshot()[0]["session_id"], session_id)

    def test_auth_source_and_manifest_shape_are_validated(self):
        session_id = self.boundary.open_session(authenticated_source=SOURCE, now=self.now)
        with self.assertRaises(ProtocolError):
            self.boundary.handle(session_id, message(LINK_REGISTER, "other.linker", MANIFEST), now=self.now)

        with self.assertRaises(ProtocolError):
            self.boundary.handle(
                session_id,
                message(LINK_REGISTER, SOURCE, {**MANIFEST, "devices": []}),
                now=self.now,
            )
        with self.assertRaises(ProtocolError):
            LinkerManifest(SOURCE, "not-semver", "Linker", ("zigbee",))

    def test_explicit_heartbeat_health_transitions(self):
        session_id = self.open_registered()
        heartbeat = message(LINK_HEARTBEAT, payload={"sequence": 1})
        ack = self.boundary.handle(session_id, heartbeat, now=self.now)
        self.assertEqual(ack["correlation_id"], heartbeat["id"])
        self.assertEqual(ack["payload"]["health"], HealthState.HEALTHY.value)

        self.now = 111.0
        changed = self.boundary.check_health(now=self.now)
        self.assertEqual(changed[0]["state"], SessionState.STALE.value)
        self.assertEqual(changed[0]["health"], HealthState.STALE.value)
        self.now = 112.0
        self.assertEqual(self.heartbeat(session_id, 2)["payload"]["state"], SessionState.ACTIVE.value)
        self.boundary.close_session(session_id, now=self.now)
        status = self.boundary.status(SOURCE, now=self.now)
        self.assertEqual(status["health"], HealthState.OFFLINE.value)
        self.assertIsNone(status["session_id"])

    def test_zero_timestamp_heartbeat_still_expires(self):
        self.now = 0.0
        session_id = self.open_registered()
        self.heartbeat(session_id)
        self.now = 10.0
        self.assertEqual(self.boundary.check_health(now=self.now)[0]["health"], HealthState.STALE.value)

    def test_reconnect_preserves_identity_and_pending_correlation(self):
        old_session_id = self.open_registered()
        self.heartbeat(old_session_id)
        command = self.boundary.issue_command(
            linker_id=SOURCE,
            device_id="light.kitchen",
            name="set_state",
            args={"state": "on"},
            now=self.now,
        )
        self.assertEqual(command.envelope.to_dict()["v"], 1)
        self.assertEqual(command.envelope.type, LIGHT_COMMAND)
        self.assertNotIn("session_id", command.envelope.to_dict())

        new_session_id = self.open_registered()
        self.assertNotEqual(new_session_id, old_session_id)
        self.heartbeat(new_session_id)
        self.assertEqual(self.boundary.status(SOURCE)["session_id"], new_session_id)
        self.assertEqual(self.boundary.status(SOURCE)["state"], SessionState.ACTIVE.value)

        result = message(
            COMMAND_RESULT,
            payload={"device_id": "light.kitchen", "status": "ok", "result": {"state": "on"}},
            correlation_id=command.envelope.id,
        )
        ack = self.boundary.handle(new_session_id, result, now=self.now)
        self.assertEqual(ack["type"], "command.ack")
        self.assertEqual(ack["correlation_id"], result["id"])
        self.assertEqual(ack["payload"]["command_id"], str(command.envelope.id))

    def test_command_result_is_idempotent_and_requires_correlation(self):
        session_id = self.open_registered()
        self.heartbeat(session_id)
        command = self.boundary.issue_command(
            linker_id=SOURCE,
            device_id="light.kitchen",
            name="set_state",
            now=self.now,
        )
        result = message(
            COMMAND_RESULT,
            payload={"device_id": "light.kitchen", "status": "error", "error": "rejected"},
            correlation_id=command.envelope.id,
        )
        self.assertFalse(self.boundary.handle(session_id, result, now=self.now)["payload"]["duplicate"])
        self.assertTrue(self.boundary.handle(session_id, result, now=self.now)["payload"]["duplicate"])

        uncorrelated = message(
            COMMAND_RESULT,
            payload={"device_id": "light.kitchen", "status": "ok"},
        )
        with self.assertRaises(CommandCorrelationError):
            self.boundary.handle(session_id, uncorrelated, now=self.now)

    def test_future_light_event_is_a_v1_envelope_not_a_new_namespace(self):
        event = Envelope(LIGHT_EVENT, SOURCE, {"device_id": "light.kitchen", "state": "on"})
        decoded = Envelope.from_dict(event.to_dict())
        self.assertEqual(decoded.type, LIGHT_EVENT)
        self.assertEqual(decoded.version, PROTOCOL_VERSION)

    def test_registration_requires_the_authenticated_state(self):
        session_id = self.boundary.open_session(authenticated_source=SOURCE, now=self.now)
        self.boundary.handle(session_id, message(LINK_REGISTER, payload=MANIFEST), now=self.now)
        with self.assertRaises(InvalidTransition):
            self.boundary.handle(session_id, message(LINK_REGISTER, payload=MANIFEST), now=self.now)


if __name__ == "__main__":
    unittest.main()
