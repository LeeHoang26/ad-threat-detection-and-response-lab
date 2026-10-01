@echo off
setlocal enableextensions enabledelayedexpansion

:: ==============================================================================
:: Wazuh Active Response Windows Bridge
:: Target: C:\Program Files (x86)\ossec-agent\active-response\bin\canary-triage.cmd
:: ==============================================================================

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\SOC_Triage\triage_soar_handler.ps1" %*
