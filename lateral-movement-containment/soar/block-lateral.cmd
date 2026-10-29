@echo off
setlocal enableextensions enabledelayedexpansion

:: ==============================================================================
:: Wazuh passes the alert JSON on standard input to the PowerShell handler.
:: Target: C:\Program Files (x86)\ossec-agent\active-response\bin\block-lateral.cmd
:: ==============================================================================

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\SOC_Lateral_Defense\isolate_attacker.ps1" %*
