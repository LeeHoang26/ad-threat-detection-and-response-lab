# Collect a process dump for a canary alert after checking the process identity.
param([string]$LogPath = 'C:\SOC_Triage\triage_execution.log', [string]$ArtifactRoot = 'C:\SOC_Triage')

function Convert-CanaryTime([object]$Value) {
    if ($Value -is [DateTimeOffset]) { return [DateTimeOffset]$Value }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return [DateTimeOffset]::new($Value.ToUniversalTime())
    }
    $parsed = [DateTimeOffset]::MinValue
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$parsed)) {
        throw 'A valid Sysmon UTC timestamp is required.'
    }
    return $parsed
}

function Read-CanaryMessage([string]$Json) {
    if ([string]::IsNullOrWhiteSpace($Json)) { throw 'Active Response JSON is missing.' }
    $message = $Json | ConvertFrom-Json -ErrorAction Stop
    if ($message.command -ne 'add') { throw 'Only the add command is supported.' }
    $alert = $message.parameters.alert
    $data = $alert.data.win.eventdata
    if ([string]$alert.rule.id -ne '100200' -or [string]$alert.data.win.system.eventID -ne '11') {
        throw 'Expected rule 100200 and Sysmon Event 11.'
    }
    $computer = [string]$alert.data.win.system.computer
    if (-not $computer -or $computer.Split('.')[0] -ine $env:COMPUTERNAME) { throw 'The alert does not identify this endpoint.' }
    if ([string]$data.targetFilename -notmatch '(?i)(?:^|[\\/])!(?:_financial_payroll_2026|_confidential_contract)\.txt$') {
        throw 'The target is not a configured TXT canary.'
    }
    $processId = 0
    $processGuid = [Guid]::Empty
    if (-not [int]::TryParse([string]$data.processId, [ref]$processId) -or $processId -le 4 -or $processId -eq $PID) {
        throw 'A valid, separate process ID is required.'
    }
    if (-not [Guid]::TryParse([string]$data.processGuid, [ref]$processGuid) -or $processGuid -eq [Guid]::Empty -or -not $data.image) {
        throw 'The alert must include ProcessGuid and Image.'
    }
    $eventTime = Convert-CanaryTime $data.utcTime
    $age = ([DateTimeOffset]::UtcNow - $eventTime).TotalSeconds
    if ($age -gt 300 -or $age -lt -5) { throw 'The alert is stale or its timestamp is in the future.' }
    return $alert
}

function Get-CanaryProcess($Alert) {
    $data = $Alert.data.win.eventdata
    $processId = [int]$data.processId
    $guidValue = [Guid]::Parse([string]$data.processGuid)
    $xpath = "*[System[EventID=1] and EventData[Data[@Name='ProcessId']='$processId']]"
    $events = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -MaxEvents 1 -ErrorAction Stop)
    if ($events.Count -ne 1) { throw 'The matching Sysmon process-creation record is unavailable.' }
    $xml = [xml]$events[0].ToXml()
    $fields = @{}
    foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
    if ([Guid]::Parse($fields.ProcessGuid) -ne $guidValue -or [int]$fields.ProcessId -ne $processId -or $fields.Image -ine [string]$data.image) {
        throw 'The Sysmon process-creation identity does not match the alert.'
    }
    $created = Convert-CanaryTime $fields.UtcTime
    $eventTime = Convert-CanaryTime $data.utcTime
    if ($created -gt $eventTime) { throw 'The process-creation record is later than the file event.' }
    $process = Get-Process -Id $processId -ErrorAction Stop
    # Open the process handle before the identity checks; keep this object for the response.
    try {
        $null = $process.Handle
        if (-not $process.Path -or $process.Path -ine [string]$data.image -or
            [Math]::Abs(($process.StartTime.ToUniversalTime() - $created.UtcDateTime).TotalSeconds) -gt 1) {
            throw 'The current PID has a different image or creation time.'
        }
        return $process
    } catch {
        $process.Dispose()
        throw
    }
}

function Suspend-CanaryProcess($Process) {
    if (-not ('CanaryProcessControl' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CanaryProcessControl {
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr handle);
}
'@ -ErrorAction Stop
    }
    $status = [CanaryProcessControl]::NtSuspendProcess($Process.Handle)
    if ($status -ne 0) { throw "Process suspension failed with NTSTATUS $status." }
}

function Write-CanaryLog([string]$Path, [string]$Message) {
    Add-Content -LiteralPath $Path -Encoding UTF8 -Value "[$([DateTimeOffset]::UtcNow.ToString('o'))] $Message" -ErrorAction Stop
}

function Invoke-CanaryResponse($Alert, [string]$Path, [string]$Root) {
    $process = $null
    $suspended = $false
    try {
        $parent = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        $data = $Alert.data.win.eventdata
        if ($env:CANARY_ENABLE_RESPONSE -ine 'true') {
            Write-CanaryLog $Path "[REVIEW] Canary write by PID $($data.processId), Image $($data.image). Response is disabled."
            return 0
        }
        $dumpTool = Join-Path $Root 'procdump.exe'
        if (-not (Test-Path -LiteralPath $dumpTool)) { throw 'procdump.exe is missing; no process action was taken.' }
        $output = Join-Path $Root ('Artifacts_' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
        # Recheck immediately before acting; a reused PID must not become the target.
        $process = Get-CanaryProcess $Alert
        $processId = [int]$process.Id
        Suspend-CanaryProcess $process
        $suspended = $true
        Write-CanaryLog $Path "[SUSPENDED] PID $processId, ProcessGuid $($data.processGuid)."
        try {
            @(Get-NetTCPConnection -OwningProcess $processId -ErrorAction Stop) |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
                Export-Csv -LiteralPath (Join-Path $output 'active_network_sockets.csv') -NoTypeInformation -ErrorAction Stop
        } catch {
            Write-CanaryLog $Path "[SOCKETS] No TCP rows were collected: $($_.Exception.Message)"
        }
        Get-FileHash -LiteralPath $process.Path -Algorithm SHA256 -ErrorAction Stop |
            Export-Csv -LiteralPath (Join-Path $output 'binary_sha256.csv') -NoTypeInformation -ErrorAction Stop
        $dumpPath = Join-Path $output "process_${processId}.dmp"
        & $dumpTool -accepteula -ma $processId $dumpPath | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dumpPath) -or
            (Get-Item -LiteralPath $dumpPath -ErrorAction Stop).Length -le 0) {
            throw 'ProcDump did not produce a non-empty process dump. The process remains suspended for review.'
        }
        Write-CanaryLog $Path "[DUMPED] Non-empty process dump: $dumpPath"
        $process.Refresh()
        if ($process.HasExited) { throw 'The selected process exited before termination.' }
        Stop-Process -InputObject $process -Force -ErrorAction Stop
        if (-not $process.WaitForExit(5000)) { throw 'The selected process did not exit within five seconds.' }
        Write-CanaryLog $Path "[TERMINATED] PID $processId exited. Artifacts: $output"
        return 0
    } catch {
        [Console]::Error.WriteLine("Canary response failed: $($_.Exception.Message)")
        if (Test-Path -LiteralPath (Split-Path -Parent $Path)) {
            Write-CanaryLog $Path "[FAILED] $($_.Exception.Message)"
            if ($suspended) { Write-CanaryLog $Path "[REVIEW] Suspension was applied to PID $processId; termination was not verified." }
        }
        return 1
    } finally {
        if ($process) { $process.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $alert = Read-CanaryMessage ([Console]::In.ReadLine())
        exit (Invoke-CanaryResponse $alert $LogPath $ArtifactRoot)
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
