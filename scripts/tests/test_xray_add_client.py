"""Offline transaction tests; real Xray parser is a separate release gate."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location(
    "add_client", Path(__file__).resolve().parents[1] / "xray-add-client.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = {"log": {"loglevel": "warning"}, "custom": {"keep": True},
                       "inbounds": [{"port": 8443, "protocol": "vless",
                         "settings": {"clients": [
                             {"id": "00000000-0000-4000-8000-000000000001",
                              "flow": "xtls-rprx-vision", "email": "existing", "level": 7}],
                             "decryption": "none"},
                         "streamSettings": {"network": "tcp", "security": "reality",
                            "realitySettings": {"privateKey": "test-private",
                                "shortIds": ["abcd"], "serverNames": ["example.org"]}}}],
                       "outbounds": [{"protocol": "freedom", "tag": "direct"},
                                     {"protocol": "blackhole", "tag": "blocked"}],
                       "routing": {"domainStrategy": "AsIs", "rules": [
                           {"type": "field", "user": ["existing"], "outboundTag": "direct"},
                           {"type": "field", "domain": ["example.net"], "outboundTag": "blocked"},
                           {"type": "field", "port": "0-65535", "outboundTag": "direct"},
                       ]}}
        self.keys = {"private_key": "test-private", "public_key": "test-public",
                     "short_id": "abcd"}
        self.original = mod.encode(self.config)
        (self.directory / "config.json").write_bytes(self.original)
        (self.directory / "keys.json").write_bytes(mod.encode(self.keys))
        self.validator = Mock()
        self.restart = Mock()

    def provision(self):
        return mod.provision(self.directory, "erg-slot-6", "exit.example.org",
                             self.validator, self.restart)

    def current(self):
        return (self.directory / "config.json").read_bytes()

    def test_add_preserves_everything_else_and_is_idempotent(self):
        self.assertTrue(self.provision())
        after = json.loads(self.current())
        client = after["inbounds"][0]["settings"]["clients"].pop()
        self.assertEqual(after["outbounds"].pop(), {
            "tag": "erg-ipv4", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}})
        self.assertEqual(after["routing"]["rules"].pop(0), {
            "type": "field", "user": ["erg-slot-6"], "outboundTag": "erg-ipv4"})
        self.assertEqual(after, self.config)
        self.assertNotEqual(client["id"], self.config["inbounds"][0]["settings"]["clients"][0]["id"])
        self.assertEqual((self.directory / "keys.json").read_bytes(), mod.encode(self.keys))
        self.assertFalse(self.provision())
        self.restart.assert_called_once()
        self.assertEqual(self.validator.call_args.args[0][1:6], ["run", "-test", "-format", "json", "-config"])
        backup, = self.directory.glob("config.backup-*")
        self.assertEqual(backup.read_bytes(), self.original)
        profile = self.directory / "client-profiles/erg-slot-6.json"
        self.assertEqual(json.loads(profile.read_bytes())["uuid"], client["id"])
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_second_slot_gets_distinct_identity(self):
        self.provision()
        mod.provision(self.directory, "erg-slot-7", "exit.example.org", self.validator, self.restart)
        clients = json.loads(self.current())["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len({c["id"] for c in clients}), 3)
        self.assertEqual(json.loads(self.current())["routing"]["rules"][0]["user"],
                         ["erg-slot-6", "erg-slot-7"])
        self.assertFalse(self.provision())

    def test_existing_client_gets_route_without_identity_or_profile_change(self):
        client = {"id": "00000000-0000-4000-8000-000000000006",
                  "email": "erg-slot-6", "flow": "xtls-rprx-vision"}
        self.config["inbounds"][0]["settings"]["clients"].append(client)
        old = mod.encode(self.config)
        (self.directory / "config.json").write_bytes(old)
        _, profile = mod.plan(old, mod.encode(self.keys), "erg-slot-6", "exit.example.org")
        profiles = self.directory / "client-profiles"
        profiles.mkdir()
        profile_path = profiles / "erg-slot-6.json"
        profile_bytes = json.dumps(profile).encode()
        profile_path.write_bytes(profile_bytes)
        self.assertTrue(self.provision())
        after = json.loads(self.current())
        self.assertEqual(after["inbounds"], self.config["inbounds"])
        self.assertEqual(after["outbounds"][:-1], self.config["outbounds"])
        self.assertEqual(after["routing"]["rules"][1:], self.config["routing"]["rules"])
        self.assertEqual(profile_path.read_bytes(), profile_bytes)
        self.assertFalse(self.provision())
        self.restart.assert_called_once()

    def test_conflicting_tags_and_rules_are_rejected_before_deployment(self):
        outbound = {"tag": "erg-ipv4", "protocol": "freedom",
                    "settings": {"domainStrategy": "UseIPv4"}}
        good_rule = {"type": "field", "user": ["erg-slot-6"], "outboundTag": "erg-ipv4"}
        conflicts = []
        config = copy.deepcopy(self.config)
        config["outbounds"].append({**outbound, "settings": {"domainStrategy": "AsIs"}})
        conflicts.append(config)
        config = copy.deepcopy(self.config)
        config["outbounds"].extend([outbound, outbound])
        conflicts.append(config)
        for rule in (
            {**good_rule, "user": ["existing"]},
            {**good_rule, "user": ["erg-slot-6", "erg-slot-6"]},
            {**good_rule, "user": ["erg-slot-99"]},
            {**good_rule, "port": "443"},
            {**good_rule, "outboundTag": "direct"},
        ):
            config = copy.deepcopy(self.config)
            config["routing"]["rules"].insert(0, rule)
            conflicts.append(config)
        config = copy.deepcopy(self.config)
        config["routing"]["rules"].append(good_rule)
        conflicts.append(config)
        config = copy.deepcopy(self.config)
        config["routing"]["balancers"] = [{"tag": "legacy", "selector": ["erg"]}]
        conflicts.append(config)
        for config in conflicts:
            with self.subTest(config=config):
                raw = mod.encode(config)
                (self.directory / "config.json").write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.provision()
                self.assertEqual(self.current(), raw)
        self.validator.assert_not_called()
        self.restart.assert_not_called()

    def test_no_existing_routing_and_noncanonical_json_are_idempotent(self):
        del self.config["routing"]
        candidate, profile = mod.plan(mod.encode(self.config), mod.encode(self.keys), "erg-slot-6", "exit.example.org")
        compact = json.dumps(json.loads(candidate)).encode()
        again, same_profile = mod.plan(compact, mod.encode(self.keys), "erg-slot-6", "exit.example.org")
        self.assertEqual(again, compact)
        self.assertEqual(profile, same_profile)

    def test_empty_default_or_cross_inbound_email_cannot_affect_legacy_clients(self):
        config = copy.deepcopy(self.config)
        config["outbounds"] = []
        with self.assertRaises(ValueError):
            mod.plan(mod.encode(config), mod.encode(self.keys), "erg-slot-6", "exit.example.org")
        config = copy.deepcopy(self.config)
        config["inbounds"].append({"protocol": "vmess", "settings": {"clients": [
            {"email": "erg-slot-6", "id": "00000000-0000-4000-8000-000000000002"}]}})
        with self.assertRaises(ValueError):
            mod.plan(mod.encode(config), mod.encode(self.keys), "erg-slot-6", "exit.example.org")

    def test_parser_rejection_never_deploys(self):
        self.validator.side_effect = RuntimeError("invalid config")
        with self.assertRaises(RuntimeError):
            self.provision()
        self.assertEqual(self.current(), self.original)
        self.restart.assert_not_called()
        self.assertFalse(list(self.directory.glob("config.backup-*")))

    def test_external_edit_during_validation_is_not_overwritten(self):
        edited = self.original + b"\n"
        self.validator.side_effect = lambda argv: (self.directory / "config.json").write_bytes(edited)
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.current(), edited)
        self.restart.assert_not_called()

    def test_restart_failure_rolls_back_exact_bytes(self):
        self.restart.side_effect = [RuntimeError("restart failed"), None]
        with self.assertRaises(RuntimeError):
            self.provision()
        self.assertEqual(self.current(), self.original)
        self.assertEqual(self.restart.call_count, 2)
        self.assertFalse((self.directory / "client-update.pending.json").exists())
        self.assertFalse((self.directory / "client-profiles/erg-slot-6.json").exists())

    def test_failed_rollback_keeps_recoverable_marker(self):
        self.restart.side_effect = RuntimeError("service failed")
        with self.assertRaises(RuntimeError):
            self.provision()
        marker = self.directory / "client-update.pending.json"
        self.assertTrue(marker.exists())
        with self.assertRaises(ValueError):
            self.provision()
        mod.recover(self.directory, Mock())
        self.assertEqual(self.current(), self.original)
        self.assertFalse(marker.exists())

    def test_external_edit_after_restart_blocks_rollback(self):
        edited = self.original + b"\n"
        self.restart.side_effect = lambda: (self.directory / "config.json").write_bytes(edited)
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.current(), edited)
        self.assertTrue((self.directory / "client-update.pending.json").exists())
        with self.assertRaises(ValueError):
            mod.recover(self.directory, Mock())
        self.assertEqual(self.current(), edited)

    def test_profile_conflict_does_not_deploy(self):
        self.provision()
        before = self.current()
        profile = self.directory / "client-profiles/erg-slot-6.json"
        profile.write_text('{"uuid": "someone-else"}')
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.current(), before)
        self.restart.assert_called_once()

    def test_duplicate_identity_labels_and_key_mismatch_rejected(self):
        for field in ("id", "email"):
            config = copy.deepcopy(self.config)
            clients = config["inbounds"][0]["settings"]["clients"]
            second = {"id": "00000000-0000-4000-8000-000000000002", "email": "second"}
            second[field] = clients[0][field]
            clients.append(second)
            with self.assertRaises(ValueError):
                mod.plan(mod.encode(config), mod.encode(self.keys), "erg-slot-6", "exit.example.org")
        self.keys["private_key"] = "different"
        with self.assertRaises(ValueError):
            mod.plan(self.original, mod.encode(self.keys), "erg-slot-6", "exit.example.org")

    def test_symlink_profile_refused(self):
        profiles = self.directory / "client-profiles"
        profiles.mkdir()
        (profiles / "erg-slot-6.json").symlink_to(self.directory / "keys.json")
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.current(), self.original)

    def test_interrupted_restart_can_be_recovered(self):
        self.restart.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.provision()
        self.assertNotEqual(self.current(), self.original)
        self.assertTrue((self.directory / "client-update.pending.json").exists())
        mod.recover(self.directory, Mock())
        self.assertEqual(self.current(), self.original)

    def test_key_edit_during_validation_is_preserved(self):
        edited = mod.encode({**self.keys, "public_key": "external"})
        self.validator.side_effect = lambda argv: (self.directory / "keys.json").write_bytes(edited)
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.current(), self.original)
        self.assertEqual((self.directory / "keys.json").read_bytes(), edited)
        self.restart.assert_not_called()

    def test_invalid_json_and_ambiguous_inbounds_fail_without_restart(self):
        for raw in (b"{invalid", mod.encode({**self.config, "inbounds": self.config["inbounds"] * 2})):
            (self.directory / "config.json").write_bytes(raw)
            with self.assertRaises(ValueError):
                self.provision()
            self.assertEqual(self.current(), raw)
            self.restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()
