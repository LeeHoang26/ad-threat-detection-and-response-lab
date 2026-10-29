#!/usr/bin/env python3
"""Wazuh Kerberos alert integration. Author: Le Duc Hoang."""

import json
import os
import ssl
import sys
import urllib.request

from ldap3 import BASE, Connection, MODIFY_REPLACE, SUBTREE, Server, Tls
from ldap3.utils.conv import escape_filter_chars

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
DC_IP = os.getenv("DOMAIN_CONTROLLER_IP", "192.168.50.10")
DOMAIN_ADMIN = os.getenv("DOMAIN_ADMIN_USER", "HOANG\\svc_soar")
DOMAIN_PASS = os.getenv("DOMAIN_ADMIN_PASS", "")
BASE_DN = os.getenv("AD_BASE_DN", "DC=hoang,DC=vn")
LDAP_CA_FILE = os.getenv("AD_LDAP_CA_FILE", "")
USE_LDAPS = os.getenv("AD_USE_LDAPS", "false").lower() in {"true", "1", "yes"}
ALLOW_ACCOUNT_DISABLE = os.getenv("AD_ALLOW_ACCOUNT_DISABLE", "false").lower() in {"true", "1", "yes"}
UAC_ACCOUNTDISABLE = 0x0002
PROTECTED_IDENTITIES = {"administrator", "guest", "krbtgt"}


def configured_exclusions():
    configured = os.getenv("AD_EXCLUDED_IDENTITIES", "")
    return PROTECTED_IDENTITIES | {normalize_sam_account(DOMAIN_ADMIN).lower()} | {
        normalize_sam_account(value).lower()
        for value in configured.split(",")
        if normalize_sam_account(value)
    }


def normalize_sam_account(raw_name):
    if not raw_name:
        return ""
    name = str(raw_name).strip()
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def sanitize_ip(raw_ip):
    if not raw_ip:
        return "Unknown"
    clean_ip = str(raw_ip).strip()
    if clean_ip in {"", "-"}:
        return "Unknown"
    return clean_ip[7:] if clean_ip.lower().startswith("::ffff:") else clean_ip


def _entry_value(entry, attribute, default=None):
    value = getattr(entry, attribute, default)
    if hasattr(value, "value"):
        value = value.value
    return value if value is not None else default


def disable_ad_account_safely(username):
    """Disable one non-protected AD user and verify the resulting UAC value."""
    if not ALLOW_ACCOUNT_DISABLE:
        return False, "Account disablement is not enabled (AD_ALLOW_ACCOUNT_DISABLE)"
    sam_account = normalize_sam_account(username)
    clean_user = sam_account.lower()
    if not clean_user:
        return False, "Target identity is empty"
    if clean_user in configured_exclusions() or clean_user.endswith("$"):
        return False, f"Target identity '{clean_user}' is protected or is a machine account"
    if not DOMAIN_ADMIN or not DOMAIN_PASS or not DC_IP or not BASE_DN:
        return False, "AD connection credentials or base DN are not configured"

    conn = None
    try:
        ldap_port = 636 if USE_LDAPS else 389
        server_kwargs = {
            "port": ldap_port,
            "use_ssl": USE_LDAPS,
            "get_info": None,
            "connect_timeout": 5,
        }
        if USE_LDAPS:
            server_kwargs["tls"] = Tls(
                validate=ssl.CERT_REQUIRED,
                ca_certs_file=LDAP_CA_FILE or None,
            )
        server = Server(DC_IP, **server_kwargs)
        conn = Connection(server, user=DOMAIN_ADMIN, password=DOMAIN_PASS, auto_bind=False, receive_timeout=5)
        if not conn.bind():
            return False, f"LDAP bind failed: {conn.result}"
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName="
            f"{escape_filter_chars(sam_account)}))"
        )
        if not conn.search(
            search_base=BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "userAccountControl", "adminCount"],
        ) or (conn.result or {}).get("result", 1) != 0:
            return False, f"LDAP search failed: {conn.result}"
        if len(conn.entries) != 1:
            return False, f"Identity '{sam_account}' matched {len(conn.entries)} LDAP entries; refusing ambiguity"

        target_entry = conn.entries[0]
        if str(_entry_value(target_entry, "adminCount", "0")) == "1":
            return False, f"Identity '{sam_account}' is protected by policy (adminCount=1)"
        user_dn = str(_entry_value(target_entry, "distinguishedName", ""))
        current_uac = int(_entry_value(target_entry, "userAccountControl"))
        if not user_dn:
            return False, f"Identity '{sam_account}' has no distinguishedName"
        if current_uac & UAC_ACCOUNTDISABLE:
            return True, f"Identity '{sam_account}' was already disabled in AD"

        new_uac = current_uac | UAC_ACCOUNTDISABLE
        modified = conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
        result = conn.result or {}
        if not modified or result.get("result", 1) != 0:
            return False, f"LDAP modify failed: {result}"

        if not conn.search(
            search_base=user_dn,
            search_filter="(objectClass=user)",
            search_scope=BASE,
            attributes=["userAccountControl"],
        ) or (conn.result or {}).get("result", 1) != 0 or len(conn.entries) != 1:
            return False, "LDAP modify reported success but UAC readback failed"
        readback_uac = int(_entry_value(conn.entries[0], "userAccountControl"))
        if readback_uac != new_uac:
            return False, f"LDAP UAC readback did not verify disablement: {readback_uac}"
        return True, f"Identity '{sam_account}' ({user_dn}) disabled via UAC ({current_uac} -> {readback_uac})"
    except Exception as err:
        return False, f"LDAP operation failed: {err}"
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def send_telegram_alert(attack_type, forensic_data, containment_action, containment_note):
    """Send a plain-text notice; return False for missing credentials or HTTP failure."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[-] Telegram credentials are not configured", file=sys.stderr)
        return False
    lines = [
        "SOC incident briefing",
        f"Containment status: {containment_action}",
        f"Threat technique: {attack_type}",
        f"Target identity: {forensic_data.get('user', 'Unknown')}",
        f"Source IP: {forensic_data.get('src_ip', 'Unknown')}",
        f"Target host: {forensic_data.get('target_host', 'Unknown')}",
        f"Event timestamp: {forensic_data.get('timestamp', 'Unknown')}",
        f"Action detail: {containment_note}",
    ]
    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": "\n".join(lines)}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.load(response)
            delivered = response.status == 200 and isinstance(result, dict) and result.get("ok") is True
            if not delivered:
                print("[-] Telegram did not confirm delivery", file=sys.stderr)
            return delivered
    except Exception as err:
        # Avoid putting the bot token from a request URL in local error output.
        print(f"[-] Telegram dispatch error: {type(err).__name__}", file=sys.stderr)
        return False


def process_alert(alert_payload):
    """Process one Wazuh alert and return an exit status (0 success, 1 failure)."""
    rule_meta = alert_payload.get("rule", {})
    event_data = alert_payload.get("data", {}).get("win", {}).get("eventdata", {})
    system_data = alert_payload.get("data", {}).get("win", {}).get("system", {})
    rule_id = str(rule_meta.get("id", ""))
    requester_user = event_data.get("targetUserName", "")
    target_service = event_data.get("serviceName", "")
    forensic_context = {
        "user": normalize_sam_account(requester_user) or "Unknown",
        "service": target_service or "Unknown",
        "src_ip": sanitize_ip(event_data.get("ipAddress")),
        "target_host": system_data.get("computer") or alert_payload.get("agent", {}).get("name") or "Unknown",
        "timestamp": alert_payload.get("timestamp") or "Unknown",
    }

    if rule_id == "100101":
        target_account = normalize_sam_account(requester_user)
        if ALLOW_ACCOUNT_DISABLE:
            success, note = disable_ad_account_safely(target_account)
            action = "AUTO-CONTAINED (IDENTITY DISABLED)" if success else "CONTAINMENT FAILED"
        else:
            success = True
            action = "DETECTED (IDENTITY DISABLEMENT NOT ENABLED)"
            note = "No LDAP action attempted; set AD_ALLOW_ACCOUNT_DISABLE=true to enable account disablement."
        telegram_ok = send_telegram_alert("AS-REP Roasting (MITRE T1558.004)", forensic_context, action, note)
        return 0 if success and telegram_ok else 1

    if rule_id == "100100":
        note = (
            f"TGS requested for SPN {target_service or 'Unknown'} by requester "
            f"{requester_user or 'Unknown'}. Service account was not disabled."
        )
        telegram_ok = send_telegram_alert(
            "Kerberoasting Request (MITRE T1558.003)",
            forensic_context,
            "DETECTED (SERVICE ACCOUNT NOT DISABLED)",
            note,
        )
        return 0 if telegram_ok else 1

    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return 1
    try:
        with open(argv[0], "r", encoding="utf-8") as alert_file:
            alert_payload = json.load(alert_file)
    except (OSError, ValueError) as err:
        print(f"[-] Failed to read alert payload: {err}", file=sys.stderr)
        return 1
    try:
        return process_alert(alert_payload)
    except (TypeError, AttributeError) as err:
        print(f"[-] Invalid alert payload: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
