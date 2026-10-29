import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "custom-soar.py"
spec = importlib.util.spec_from_file_location("custom_soar", SCRIPT)
custom_soar = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = custom_soar
spec.loader.exec_module(custom_soar)


class Value:
    def __init__(self, value):
        self.value = value


class Entry:
    def __init__(self, dn="CN=Alice,DC=example,DC=test", uac=0x220, admin_count="0"):
        self.distinguishedName = Value(dn)
        self.userAccountControl = Value(uac)
        self.adminCount = Value(admin_count)


class FakeConnection:
    next_entries = [Entry()]
    modify_result = {"result": 0}
    readback_uac = None
    instances = []

    def __init__(self, *args, **kwargs):
        self.server = args[0]
        self.settings = kwargs
        self.entries = []
        self.result = {"result": 0}
        self.filters = []
        self.modified = []
        self.unbound = False
        self.__class__.instances.append(self)

    def bind(self):
        return True

    def search(self, search_base, search_filter, search_scope, attributes):
        self.filters.append(search_filter)
        self.result = {"result": 0}
        if search_base.startswith("CN="):
            if self.__class__.readback_uac is None:
                self.entries = []
            else:
                self.entries = [Entry(uac=self.__class__.readback_uac)]
        else:
            self.entries = list(self.__class__.next_entries)
        return True

    def modify(self, dn, changes):
        self.modified.append((dn, changes))
        self.result = dict(self.__class__.modify_result)
        return self.result.get("result", 1) == 0

    def unbind(self):
        self.unbound = True
        return True


class FakeServer:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class LdapIntegrationTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.next_entries = [Entry()]
        FakeConnection.modify_result = {"result": 0}
        FakeConnection.readback_uac = 0x222
        FakeConnection.instances = []
        self.settings = patch.multiple(
            custom_soar,
            Connection=FakeConnection,
            Server=FakeServer,
            ALLOW_ACCOUNT_DISABLE=True,
            DOMAIN_ADMIN="EXAMPLE\\svc-soar",
            DOMAIN_PASS="secret",
            DC_IP="dc.example.test",
            BASE_DN="DC=example,DC=test",
            USE_LDAPS=False,
        )
        self.settings.start()
        self.env = patch.dict(os.environ, {"AD_EXCLUDED_IDENTITIES": "breakglass"}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.settings.stop()

    def test_filter_is_escaped_and_uac_flags_are_read_back(self):
        ok, note = custom_soar.disable_ad_account_safely("Alice*(bad)")
        self.assertTrue(ok, note)
        self.assertEqual(len(FakeConnection.instances), 1)
        self.assertIn(r"Alice\2a\28bad\29", FakeConnection.instances[0].filters[0])
        self.assertTrue(FakeConnection.instances[0].unbound)

        FakeConnection.next_entries = [Entry(uac=0x220)]
        FakeConnection.readback_uac = 0x222
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertTrue(ok, note)
        self.assertEqual(FakeConnection.instances[-1].modified[0][1]["userAccountControl"][0][1], [0x222])
        self.assertTrue(FakeConnection.instances[-1].unbound)

    def test_duplicate_search_results_are_refused(self):
        FakeConnection.next_entries = [Entry(), Entry(dn="CN=Alice2,DC=example,DC=test")]
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertIn("matched 2", note)
        self.assertEqual(FakeConnection.instances[0].modified, [])

    def test_search_error_does_not_modify_and_closes_connection(self):
        with patch.object(FakeConnection, "search", return_value=False):
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertEqual(FakeConnection.instances[0].modified, [])
        self.assertTrue(FakeConnection.instances[0].unbound)

    def test_modify_refusal_is_failure(self):
        FakeConnection.modify_result = {"result": 50, "message": "insufficientAccessRights"}
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertIn("modify failed", note)

    def test_readback_without_disable_bit_is_failure(self):
        FakeConnection.readback_uac = 0x220
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertIn("readback", note)

    def test_readback_losing_existing_flags_is_failure(self):
        FakeConnection.readback_uac = 0x202
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertIn("readback", note)

    def test_bind_exception_still_closes_connection(self):
        with patch.object(FakeConnection, "bind", side_effect=OSError("bind failure")):
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertTrue(FakeConnection.instances[0].unbound)

    def test_connection_and_receive_timeouts_are_bounded(self):
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertTrue(ok, note)
        connection = FakeConnection.instances[0]
        self.assertEqual(connection.server.kwargs["connect_timeout"], 5)
        self.assertEqual(connection.settings["receive_timeout"], 5)
        self.assertNotIn("tls", connection.server.kwargs)

    def test_ldaps_validates_with_system_trust(self):
        with patch.object(custom_soar, "USE_LDAPS", True), patch.object(
            custom_soar, "LDAP_CA_FILE", ""
        ), patch.object(custom_soar, "Tls") as tls:
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertTrue(ok, note)
        tls.assert_called_once_with(validate=custom_soar.ssl.CERT_REQUIRED, ca_certs_file=None)
        connection = FakeConnection.instances[0]
        self.assertTrue(connection.server.kwargs["use_ssl"])
        self.assertEqual(connection.server.kwargs["port"], 636)
        self.assertIs(connection.server.kwargs["tls"], tls.return_value)

    def test_ldaps_validates_with_operator_ca_file(self):
        with patch.object(custom_soar, "USE_LDAPS", True), patch.object(
            custom_soar, "LDAP_CA_FILE", "/etc/ssl/lab-root-ca.pem"
        ), patch.object(custom_soar, "Tls") as tls:
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertTrue(ok, note)
        tls.assert_called_once_with(
            validate=custom_soar.ssl.CERT_REQUIRED, ca_certs_file="/etc/ssl/lab-root-ca.pem"
        )

    def test_ldaps_configuration_error_never_connects(self):
        with patch.object(custom_soar, "USE_LDAPS", True), patch.object(
            custom_soar, "Tls", side_effect=ValueError("CA file unavailable")
        ):
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertEqual(FakeConnection.instances, [])

    def test_disable_requires_opt_in_even_when_called_directly(self):
        with patch.object(custom_soar, "ALLOW_ACCOUNT_DISABLE", False):
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertEqual(FakeConnection.instances, [])

    def test_missing_ad_password_never_connects(self):
        with patch.object(custom_soar, "DOMAIN_PASS", ""):
            ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertEqual(FakeConnection.instances, [])

    def test_protected_privileged_and_machine_accounts_are_excluded(self):
        for name in ("Administrator", "breakglass", "SERVER$", "EXAMPLE\\svc-soar"):
            FakeConnection.instances = []
            ok, note = custom_soar.disable_ad_account_safely(name)
            self.assertFalse(ok)
            self.assertEqual(FakeConnection.instances, [])
        FakeConnection.next_entries = [Entry(admin_count="1")]
        ok, note = custom_soar.disable_ad_account_safely("Alice")
        self.assertFalse(ok)
        self.assertIn("adminCount", note)


class AlertDispatchTests(unittest.TestCase):
    def alert(self, rule_id, **event):
        return {"rule": {"id": rule_id}, "data": {"win": {"eventdata": event}}, "timestamp": "2026-10-29T00:00:00Z"}

    def test_asrep_default_does_not_disable_and_unknown_context_stays_unknown(self):
        with patch.object(custom_soar, "ALLOW_ACCOUNT_DISABLE", False), patch.object(
            custom_soar, "disable_ad_account_safely"
        ) as disable, patch.object(custom_soar, "send_telegram_alert", return_value=True) as telegram:
            self.assertEqual(custom_soar.process_alert(self.alert("100101", targetUserName="EXAMPLE\\alice")), 0)
        disable.assert_not_called()
        context = telegram.call_args.args[1]
        self.assertEqual(context["src_ip"], "Unknown")
        self.assertEqual(context["target_host"], "Unknown")

    def test_kerberoast_never_disables_an_account(self):
        with patch.object(custom_soar, "disable_ad_account_safely") as disable, patch.object(
            custom_soar, "send_telegram_alert", return_value=True
        ):
            self.assertEqual(
                custom_soar.process_alert(self.alert("100100", targetUserName="alice", serviceName="HTTP/app")), 0
            )
        disable.assert_not_called()

    def test_telegram_failure_propagates_nonzero(self):
        with patch.object(custom_soar, "send_telegram_alert", return_value=False):
            self.assertEqual(self._run("100100"), 1)

    def test_containment_failure_is_not_labeled_as_success(self):
        with patch.object(custom_soar, "ALLOW_ACCOUNT_DISABLE", True), patch.object(
            custom_soar, "disable_ad_account_safely", return_value=(False, "LDAP refused")
        ), patch.object(custom_soar, "send_telegram_alert", return_value=True) as telegram:
            self.assertEqual(self._run("100101"), 1)
        self.assertEqual(telegram.call_args.args[2], "CONTAINMENT FAILED")

    def test_event_computer_and_source_ip_are_taken_from_alert(self):
        alert = self.alert("100100", targetUserName="alice", ipAddress="::ffff:10.0.0.7")
        alert["data"]["win"]["system"] = {"computer": "dc.actual.test"}
        with patch.object(custom_soar, "send_telegram_alert", return_value=True) as telegram:
            self.assertEqual(custom_soar.process_alert(alert), 0)
        self.assertEqual(telegram.call_args.args[1]["target_host"], "dc.actual.test")
        self.assertEqual(telegram.call_args.args[1]["src_ip"], "10.0.0.7")

    def test_missing_telegram_credentials_never_sends_network_request(self):
        with patch.object(custom_soar, "TELEGRAM_BOT_TOKEN", ""), patch.object(
            custom_soar.urllib.request, "urlopen"
        ) as request, patch("sys.stderr", new_callable=io.StringIO):
            self.assertFalse(custom_soar.send_telegram_alert("test", {}, "detected", "test"))
        request.assert_not_called()

    def test_telegram_uses_plain_text_and_requires_api_confirmation(self):
        for api_ok in (False, True):
            response = io.BytesIO(json.dumps({"ok": api_ok}).encode())
            response.status = 200
            with patch.object(custom_soar, "TELEGRAM_BOT_TOKEN", "test-token"), patch.object(
                custom_soar, "TELEGRAM_CHAT_ID", "test-chat"
            ), patch.object(custom_soar.urllib.request, "urlopen", return_value=response) as request, patch(
                "sys.stderr", new_callable=io.StringIO
            ):
                self.assertEqual(
                    custom_soar.send_telegram_alert("test", {"user": "*alice*"}, "detected", "test"), api_ok
                )
            payload = json.loads(request.call_args.args[0].data)
            self.assertNotIn("parse_mode", payload)
            self.assertIn("*alice*", payload["text"])
            self.assertNotIn("< 3 seconds", payload["text"])
            self.assertNotIn("Incident Register", payload["text"])

    def test_http_exception_returns_failure_without_exposing_token(self):
        with patch.object(custom_soar, "TELEGRAM_BOT_TOKEN", "secret-token"), patch.object(
            custom_soar, "TELEGRAM_CHAT_ID", "test-chat"
        ), patch.object(custom_soar.urllib.request, "urlopen", side_effect=OSError("secret-token")), patch(
            "sys.stderr", new_callable=io.StringIO
        ) as errors:
            self.assertFalse(custom_soar.send_telegram_alert("test", {}, "detected", "test"))
        self.assertNotIn("secret-token", errors.getvalue())

    def test_main_reads_wazuh_argument_file_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alert.json"
            path.write_text(json.dumps(self.alert("100100")), encoding="utf-8")
            with patch.object(custom_soar, "send_telegram_alert", return_value=False):
                self.assertEqual(custom_soar.main([str(path), "unused-api-key", "unused-url"]), 1)
            path.write_text("[]", encoding="utf-8")
            with patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(custom_soar.main([str(path)]), 1)
        self.assertEqual(custom_soar.main([]), 1)

    def _run(self, rule_id):
        return custom_soar.process_alert(self.alert(rule_id, targetUserName="alice"))


if __name__ == "__main__":
    unittest.main()
