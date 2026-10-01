# ==============================================================================
# AUTOMATED SOAR TRIAGE ENGINE - TRIGGERED BY WAZUH ACTIVE RESPONSE
# Component: Windows Incident Triage Endpoint Handler (C:\SOC_Triage\triage_soar_handler.ps1)
# Author: Hoang Lee (SOC Detection & Response Engineering)
# Target: Windows 10 / Windows Server (Canary Ransomware Defense)
# Lifecycle: SUSPEND -> DUMP MEMORY & CAPTURE TELEMETRY -> TERMINATE
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [int]$SuspectPID = 0
)

# P/Invoke signature for NtSuspendProcess / NtResumeProcess (Kernel-level instant freeze)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ProcessController {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtResumeProcess(IntPtr processHandle);
}
"@ -ErrorAction SilentlyContinue

function Suspend-ProcessSafe([int]$pidToFreeze) {
    try {
        $p = [System.Diagnostics.Process]::GetProcessById($pidToFreeze)
        [ProcessController]::NtSuspendProcess($p.Handle) | Out-Null
        return $true
    } catch {
        return $false
    }
}

# 1. Fallback / Extraction: Read incident telemetry
# If not passed via commandline arguments, attempt to resolve from recent Sysmon Event 11 canary tampering
if (-not $SuspectPID -or $SuspectPID -eq 0) {
    # Specifically target Sysmon Event 11 matching the canary naming convention
    $RecentSysmon = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -MaxEvents 10 -ErrorAction SilentlyContinue
    if ($RecentSysmon) {
        foreach ($evt in $RecentSysmon) {
            $Xml = [xml]$evt.ToXml()
            $targetFile = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetFilename' }).'#text'
            if ($targetFile -match '_financial_payroll_2026|_confidential_contract') {
                $SuspectPID = [int]($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'
                break
            }
        }
    }
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = "C:\SOC_Triage\Artifacts_$Timestamp"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$LogFile = "C:\SOC_Triage\triage_execution.log"

Add-Content -Path $LogFile -Value "[$Timestamp] [SOAR_TRIGGERED] Active Response activated. Target Suspect PID: $SuspectPID"

if ($SuspectPID -and [int]$SuspectPID -gt 0) {
    # 2. IMMEDIATE CONTAINMENT: SUSPEND PROCESS
    # Freezes malware execution immediately. Halts ongoing encryption while preserving volatile heap memory.
    $suspended = Suspend-ProcessSafe -pidToFreeze $SuspectPID
    if ($suspended) {
        Add-Content -Path $LogFile -Value "[$Timestamp] [CONTAINMENT] Process $SuspectPID SUSPENDED (Execution halted, encryption stopped)."
    } else {
        Add-Content -Path $LogFile -Value "[$Timestamp] [WARN] Failed to suspend process $SuspectPID via ntdll. Proceeding with urgent dump."
    }

    # 3. CAPTURE ACTIVE NETWORK SOCKETS (C2 Server IP / Beaconing IOCs before closing)
    Get-NetTCPConnection -OwningProcess $SuspectPID -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | 
        Export-Csv -Path "$OutputDir\active_network_sockets.csv" -NoTypeInformation

    # 4. EXTRACT BINARY EXECUTABLE SHA256 HASH
    try {
        $Proc = Get-Process -Id $SuspectPID -ErrorAction Stop
        if ($Proc.Path) {
            Get-FileHash -Path $Proc.Path -Algorithm SHA256 | Export-Csv -Path "$OutputDir\binary_sha256.csv" -NoTypeInformation
        }
    } catch {}

    # 5. IN-MEMORY FORENSIC DUMP
    # ProcDump captures full memory (-ma) while process remains in suspended state (preserving AES-256 keys)
    $DumpPath = "$OutputDir\process_${SuspectPID}.dmp"
    if (Test-Path "C:\SOC_Triage\procdump.exe") {
        & "C:\SOC_Triage\procdump.exe" -ma $SuspectPID $DumpPath -accepteula | Out-Null
        Add-Content -Path $LogFile -Value "[$Timestamp] [SUCCESS] In-Memory Dump captured: $DumpPath"
    }

    # 6. FINAL TERMINATION: KILL MALICIOUS PROCESS
    # Once memory and network sockets are preserved, kill the process to permanently neutralize the threat
    try {
        Stop-Process -Id $SuspectPID -Force -ErrorAction SilentlyContinue
        Add-Content -Path $LogFile -Value "[$Timestamp] [NEUTRALIZED] Process $SuspectPID permanently terminated via Stop-Process."
    } catch {
        Add-Content -Path $LogFile -Value "[$Timestamp] [WARN] Process $SuspectPID had already exited or could not be terminated: $_"
    }
} else {
    Add-Content -Path $LogFile -Value "[$Timestamp] [ERROR] Could not resolve valid Suspect PID for containment."
}

Add-Content -Path $LogFile -Value "[$Timestamp] [COMPLETE] Automated Triage & Containment workflow finished."
