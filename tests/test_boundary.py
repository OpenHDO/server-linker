import unittest

from server_linker import (
    CommandCorrelationError,
    HealthState,
    InvalidTransition,
    LinkerBoundary,
    ProtocolNegotiationError,
    SCHEMA,
    SessionState,
    ValidationError,
)


MANIFEST = {
    "linker_id": "linker-kitchen",
    "name": "Kitchen Linker",
    "version": "1.2.0",
    "capabilities": ["inventory"],
    "devices": [
        {
            "device_id": "switch-kitchen",
            "kind": "switch",
            "name": "Kitchen light",
            "capabilities": ["switch"],
        }
    ],
}


class LinkerBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = []
        self.boundary = LinkerBoundary(
            heartbeat_timeout_seconds=10,
            clock=lambda: self.now,
            event_sink=self.events.append,
        )
        self.now = 100.0

    def open_registered(self, manifest=MANIFEST):
        session_id = self.boundary.open_session(now=self.now)
        hello = self.boundary.handle(
            {
                "schema": SCHEMA,
                "type": "hello",
                "session_id": session_id,
                "protocol_name": "openhdo-linker",
                "protocol_versions": ["1.0"],
            },
            now=self.now,
        )
        self.assertEqual(hello["protocol"], "1.0")
        register = self.boundary.handle(
            {
                "schema": SCHEMA,
                "type": "register",
                "session_id": session_id,
                "manifest": manifest,
            },
            now=self.now,
        )
        self.assertEqual(register["state"], SessionState.REGISTERED.value)
        return session_id

    def heartbeat(self, session_id, sequence=1):
        return self.boundary.handle(
            {
                "schema": SCHEMA,
                "type": "heartbeat",
                "session_id": session_id,
                "linker_id": MANIFEST["linker_id"],
                "sequence": sequence,
            },
            now=self.now,
        )

    def test_negotiates_registers_and_exposes_manifest(self):
        session_id = self.open_registered()
        status = self.boundary.status("linker-kitchen", now=self.now)

        self.assertEqual(status["session_id"], session_id)
        self.assertEqual(status["health"], HealthState.UNKNOWN.value)
        self.assertEqual(status["manifest"], MANIFEST)
        self.assertEqual(len(self.boundary.registry_snapshot()), 1)
        self.assertIn("linker.registered", [event.event_type for event in self.events])

    def test_explicit_state_and_health_transitions(self):
        session_id = self.open_registered()
        self.assertEqual(self.heartbeat(session_id)["health"], HealthState.HEALTHY.value)
        self.now = 111.0
        changed = self.boundary.check_health(now=self.now)
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["state"], SessionState.STALE.value)
        self.assertEqual(changed[0]["health"], HealthState.STALE.value)
        self.now = 112.0
        self.assertEqual(self.heartbeat(session_id, 2)["state"], SessionState.ACTIVE.value)
        self.boundary.close_session(session_id, now=self.now)
        status = self.boundary.status("linker-kitchen", now=self.now)
        self.assertEqual(status["health"], HealthState.OFFLINE.value)
        self.assertEqual(status["session_id"], None)

    def test_zero_timestamp_heartbeat_still_expires(self):
        self.now = 0.0
        session_id = self.open_registered()
        self.heartbeat(session_id)
        self.now = 10.0
        self.assertEqual(self.boundary.check_health(now=self.now)[0]["health"], HealthState.STALE.value)

    def test_reconnect_preserves_identity_and_pending_command_correlation(self):
        old_session_id = self.open_registered()
        self.heartbeat(old_session_id)
        command = self.boundary.issue_command(
            linker_id="linker-kitchen",
            device_id="switch-kitchen",
            name="set",
            args={"on": True},
            command_id="cmd-light-1",
            now=self.now,
        )
        new_session_id = self.open_registered()
        self.assertNotEqual(new_session_id, old_session_id)
        self.heartbeat(new_session_id)
        status = self.boundary.status("linker-kitchen", now=self.now)
        self.assertEqual(status["session_id"], new_session_id)
        self.assertEqual(status["state"], SessionState.ACTIVE.value)

        reply = self.boundary.handle(
            {
                "schema": SCHEMA,
                "type": "command_reply",
                "session_id": new_session_id,
                "linker_id": "linker-kitchen",
                "device_id": "switch-kitchen",
                "command_id": command["command_id"],
                "status": "ok",
                "result": {"on": True},
            },
            now=self.now,
        )
        self.assertTrue(reply["accepted"])
        self.assertFalse(reply["duplicate"])

    def test_command_reply_is_correlated_and_duplicate_safe(self):
        session_id = self.open_registered()
        self.heartbeat(session_id)
        command = self.boundary.issue_command(
            linker_id="linker-kitchen",
            device_id="switch-kitchen",
            name="set",
            now=self.now,
        )
        reply = {
            "schema": SCHEMA,
            "type": "command_reply",
            "session_id": session_id,
            "linker_id": "linker-kitchen",
            "device_id": "switch-kitchen",
            "command_id": command["command_id"],
            "status": "error",
            "error": "device rejected command",
        }
        self.assertFalse(self.boundary.handle(reply, now=self.now)["duplicate"])
        self.assertTrue(self.boundary.handle(reply, now=self.now)["duplicate"])

        with self.assertRaises(CommandCorrelationError):
            self.boundary.issue_command(
                linker_id="linker-kitchen",
                device_id="switch-kitchen",
                name="set",
                command_id=command["command_id"],
                now=self.now,
            )

    def test_boundary_rejects_invalid_order_schema_and_protocol(self):
        session_id = self.boundary.open_session(now=self.now)
        with self.assertRaises(InvalidTransition):
            self.boundary.handle(
                {"schema": SCHEMA, "type": "register", "session_id": session_id, "manifest": MANIFEST},
                now=self.now,
            )
        with self.assertRaises(ValidationError):
            self.boundary.handle(
                {
                    "schema": "openhdo.linker/2",
                    "type": "hello",
                    "session_id": session_id,
                    "protocol_name": "openhdo-linker",
                    "protocol_versions": ["1.0"],
                },
                now=self.now,
            )
        with self.assertRaises(ProtocolNegotiationError):
            self.boundary.handle(
                {
                    "schema": SCHEMA,
                    "type": "hello",
                    "session_id": session_id,
                    "protocol_name": "openhdo-linker",
                    "protocol_versions": ["2.0"],
                },
                now=self.now,
            )

    def test_manifest_validation_and_duplicate_heartbeat(self):
        bad_manifest = {**MANIFEST, "devices": [MANIFEST["devices"][0], MANIFEST["devices"][0]]}
        session_id = self.boundary.open_session(now=self.now)
        self.boundary.handle(
            {
                "schema": SCHEMA,
                "type": "hello",
                "session_id": session_id,
                "protocol_name": "openhdo-linker",
                "protocol_versions": ["1.0"],
            },
            now=self.now,
        )
        with self.assertRaises(ValidationError):
            self.boundary.handle(
                {"schema": SCHEMA, "type": "register", "session_id": session_id, "manifest": bad_manifest},
                now=self.now,
            )

        session_id = self.open_registered()
        first = self.heartbeat(session_id, 1)
        duplicate = self.heartbeat(session_id, 1)
        self.assertFalse(first["duplicate"])
        self.assertTrue(duplicate["duplicate"])


if __name__ == "__main__":
    unittest.main()
