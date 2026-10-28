import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("diagnose_link", Path(__file__).resolve().parents[1] / "scripts/diagnose-link.py")
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
LINK = "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=reality&pbk=" + "AQ" * 21 + "E&sid=aabb&flow=xtls-rprx-vision&sni=cover.example"


class DiagnosticPrivacyTests(unittest.TestCase):
    def test_configuration_keeps_authentication_in_stdin_data_and_disables_logs(self):
        host, port, user, query = diagnostic.parse_link(LINK)
        config = diagnostic.configuration("192.0.2.1", port, user, query, 2081, host)
        self.assertEqual(config["log"], {"access": "none", "error": "none", "loglevel": "none", "dnsLog": False})
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        remote = config["outbounds"][0]
        self.assertEqual(remote["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(remote["streamSettings"]["realitySettings"]["show"], False)

    def test_insecure_unknown_duplicate_and_wrong_transport_parameters_are_rejected(self):
        for suffix in ["&allowInsecure=true", "&unknown=1", "&security=tls", "&type=ws", "&mux=true", "&mode=stream-one", "&spx=%2Fcustom"]:
            with self.subTest(suffix=suffix):
                with self.assertRaises(diagnostic.DiagnosticError):
                    diagnostic.parse_link(LINK + suffix)
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.parse_link(LINK.replace(":443?", ":0?"))

    def test_ipv6_is_rejected_without_network_access(self):
        with patch.object(diagnostic.socket, "getaddrinfo") as lookup:
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.ipv4("2001:db8::1", 443)
            lookup.assert_not_called()

    def test_uplink_binding_changes_only_the_outbound_socket_settings(self):
        host, port, user, query = diagnostic.parse_link(LINK)
        config = diagnostic.configuration("192.0.2.1", port, user, query, 2081, host, "eth-test")
        stream = config["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["sockopt"], {"interface": "eth-test"})
        self.assertEqual(stream["realitySettings"]["publicKey"], query["pbk"])
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")

    def test_probe_omits_credentials_and_discards_server_output(self):
        with patch.object(diagnostic.subprocess, "run", return_value=subprocess.CompletedProcess([], 35, b"000 3.02")) as run:
            self.assertEqual(diagnostic.probe(2081, "https://example.com/"), (35, "000", 3.02))
            args, kwargs = run.call_args
            self.assertEqual(args[0][:2], ["curl", "--disable"])
            self.assertNotIn(LINK, args[0])
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 10)
            self.assertIn("/dev/null", args[0])

    def test_cleanup_kills_and_reaps_a_core_that_ignores_termination(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("xray", 3), 0]
        diagnostic.stop(child)
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
