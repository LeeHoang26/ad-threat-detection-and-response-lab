<#
Offline regression checks for both active-response handlers.
The test doubles below deliberately fail closed. No firewall, process, dump,
LDAP, or network operation is allowed to reach the host running this script.
#>
$ErrorActionPreference = 'Stop'
$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:TempRoot = Join-Path $PSScriptRoot ('temp-active-response-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
$script:FakeImage = Join-Path $script:TempRoot 'writer.exe'
Set-Content -LiteralPath $script:FakeImage -Value 'offline-test-image' -NoNewline
$oldComputer = $env:COMPUTERNAME
$oldResponse = $env:CANARY_ENABLE_RESPONSE
$script:CreatedTime = [DateTimeOffset]::UtcNow.AddSeconds(-10)
$env:COMPUTERNAME = 'TEST-WK01'
$script:FirewallRule = $null
$script:Process = $null
$script:WinEvents = @()
$script:ProcDumpMode = 'exit'
$dumpTool = $null
$script:Assertions = 0
$script:StopMode = 'deny'
$script:WaitResult = $true
# Load the built-in hash function before shadowing it; module autoload must not
# replace the test double halfway through a response.
Get-Command Get-FileHash -ErrorAction Stop | Out-Null

function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { $script:Failures.Add($Message) }
}
function Assert-Equal($Expected, $Actual, [string]$Message) {
    $script:Assertions++
    if ($Expected -ne $Actual) { $script:Failures.Add("$Message (expected '$Expected', got '$Actual')") }
}
function Assert-Throws([scriptblock]$Code, [string]$Message) {
    $thrown = $false
    try { & $Code } catch { $thrown = $true }
    Assert-True $thrown $Message
}

# Host-call stubs. A test must opt into each return value explicitly.
function Get-WinEvent { if ($null -eq $script:WinEvents) { throw 'unexpected Get-WinEvent call' }; return $script:WinEvents }
function Get-Process { if ($null -eq $script:Process) { throw 'unexpected Get-Process call' }; return $script:Process }
function New-NetFirewallRule {
    param([string]$Name, [string]$DisplayName, [string]$Direction, [string]$Action, [string]$RemoteAddress, [string]$Profile, $Enabled)
    if ($script:FirewallRule -eq 'refuse') { throw 'firewall API refused test request' }
    $script:FirewallRule = [pscustomobject]@{ Name = $Name; Enabled = [string]$Enabled; Direction = $Direction; Action = $Action; RemoteAddress = $RemoteAddress; Profile = $Profile }
    return $script:FirewallRule
}
function Get-NetFirewallRule { param([string]$Name); if ($script:FirewallRule -is [string]) { return $null }; return $script:FirewallRule }
function Get-NetFirewallAddressFilter { process { [pscustomobject]@{ RemoteAddress = $script:FirewallRule.RemoteAddress } } }
function Get-NetTCPConnection { throw 'network enumeration is disabled in this test' }
function Stop-Process {
    param($InputObject, [switch]$Force)
    if ($script:StopMode -ne 'simulate') { throw 'process termination is disabled in this test' }
    $InputObject.HasExited = $true
}
function Get-FileHash { return [pscustomobject]@{ Algorithm = 'SHA256'; Hash = 'TEST-HASH'; Path = 'C:\Tools\writer.exe' } }

. (Join-Path $PSScriptRoot '..\lateral-movement-containment\soar\isolate_attacker.ps1')
. (Join-Path $PSScriptRoot '..\ransomware-memory-triage\triage\triage_soar_handler.ps1')

function New-LateralAlert([string]$Computer = $env:COMPUTERNAME, [string]$LogonId = '0x1234', [string]$UtcTime = '') {
    if (-not $UtcTime) { $UtcTime = [DateTimeOffset]::UtcNow.ToString('o') }
    return [pscustomobject]@{
        rule = [pscustomobject]@{ id = '100300' }
        data = [pscustomobject]@{
            win = [pscustomobject]@{
                system = [pscustomobject]@{ eventID = '1'; computer = $Computer }
                eventdata = [pscustomobject]@{ logonId = $LogonId; utcTime = $UtcTime; user = 'LAB\analyst'; processId = '4242' }
            }
        }
    }
}
function New-CanaryAlert([string]$Computer = $env:COMPUTERNAME, [string]$ProcessGuid = '{11111111-1111-1111-1111-111111111111}', [string]$ProcessId = '4242', [string]$UtcTime = '') {
    if (-not $UtcTime) { $UtcTime = [DateTimeOffset]::UtcNow.ToString('o') }
    return [pscustomobject]@{
        rule = [pscustomobject]@{ id = '100200' }
        data = [pscustomobject]@{
            win = [pscustomobject]@{
                system = [pscustomobject]@{ eventID = '11'; computer = $Computer }
        eventdata = [pscustomobject]@{ targetFilename = 'C:\Users\Public\!_financial_payroll_2026.txt'; image = $script:FakeImage; processId = $ProcessId; processGuid = $ProcessGuid; utcTime = $UtcTime }
            }
        }
    }
}
function Message($Command, $Alert) { return ([pscustomobject]@{ command = $Command; parameters = [pscustomobject]@{ alert = $Alert } } | ConvertTo-Json -Depth 12) }
function New-SecurityEvent([string]$LogonId = '0x1234', [string]$Ip = '203.0.113.20', [string]$User = 'analyst') {
    $xml = @"
<Event><EventData>
<Data Name="LogonType">3</Data><Data Name="TargetLogonId">$LogonId</Data>
<Data Name="TargetDomainName">LAB</Data><Data Name="TargetUserName">$User</Data><Data Name="IpAddress">$Ip</Data>
</EventData></Event>
"@
    $event = [pscustomobject]@{}
    $event | Add-Member ScriptMethod ToXml ({ $xml }.GetNewClosure())
    return $event
}
function New-SysmonEvent([string]$Guid = '{11111111-1111-1111-1111-111111111111}', [string]$ProcessId = '4242', [string]$Image = $script:FakeImage, [string]$UtcTime = '') {
    if (-not $UtcTime) { $UtcTime = $script:CreatedTime.ToString('o') }
    $xml = @"
<Event><EventData><Data Name="ProcessGuid">$Guid</Data><Data Name="ProcessId">$ProcessId</Data><Data Name="Image">$Image</Data><Data Name="UtcTime">$UtcTime</Data></EventData></Event>
"@
    $event = [pscustomobject]@{}
    $event | Add-Member ScriptMethod ToXml ({ $xml }.GetNewClosure())
    return $event
}
function New-FakeProcess([string]$Path = $script:FakeImage, [datetime]$StartTime = $script:CreatedTime.UtcDateTime, [int]$Id = 4242) {
    $p = [pscustomobject]@{ Id = $Id; Handle = [IntPtr]::new(42); Path = $Path; StartTime = $StartTime; HasExited = $false }
    $p | Add-Member ScriptMethod Refresh { } -Force
    $p | Add-Member ScriptMethod WaitForExit { param([int]$Milliseconds); return $script:WaitResult } -Force
    $p | Add-Member ScriptMethod Dispose { $script:Disposed = $true } -Force
    return $p
}

try {
    # JSON/rule/host validation for both handlers.
    $lat = New-LateralAlert
    $can = New-CanaryAlert
    foreach ($pair in @(@('lateral', $lat, ${function:Read-LateralMessage}), @('canary', $can, ${function:Read-CanaryMessage}))) {
        $name, $alert, $reader = $pair
        Assert-Equal $alert.rule.id (& $reader (Message 'add' $alert)).rule.id "$name valid message"
        Assert-Throws { & $reader '' } "$name rejects empty JSON"
        Assert-Throws { & $reader '{invalid' } "$name rejects malformed JSON"
        Assert-Throws { & $reader (Message 'delete' $alert) } "$name rejects non-add command"
        $bad = (Message 'add' $alert | ConvertFrom-Json).parameters.alert; $bad.rule = [pscustomobject]@{ id = '999999' }
        Assert-Throws { & $reader (Message 'add' $bad) } "$name rejects wrong rule"
        $bad = (Message 'add' $alert | ConvertFrom-Json).parameters.alert; $bad.data.win.system.computer = 'OTHER-HOST'
        Assert-Throws { & $reader (Message 'add' $bad) } "$name rejects wrong host"
    }

    # Lateral correlation: missing/wrong LogonId and ambiguous sources fail closed.
    Assert-Throws { Resolve-LateralSource (New-LateralAlert -LogonId '') } 'missing LogonId fails closed'
    $script:WinEvents = @(New-SecurityEvent -LogonId '0x9999')
    Assert-Throws { Resolve-LateralSource $lat } 'wrong LogonId fails closed'
    $script:WinEvents = @((New-SecurityEvent -LogonId '0x9999' -Ip '203.0.113.99'), (New-SecurityEvent))
    Assert-Equal '203.0.113.20' (Resolve-LateralSource $lat) 'exact LogonId wins over newest unrelated network logon'
    $script:WinEvents = @(New-SecurityEvent -User 'other-user')
    Assert-Throws { Resolve-LateralSource $lat } 'matching LogonId with wrong identity fails closed'
    $script:WinEvents = @((New-SecurityEvent), (New-SecurityEvent -Ip '203.0.113.21'))
    Assert-Throws { Resolve-LateralSource $lat } 'ambiguous source IP fails closed'
    $script:WinEvents = @((New-SecurityEvent), (New-SecurityEvent))
    $script:FirewallRule = $null
    Assert-Equal 0 (Invoke-LateralResponse $lat (Join-Path $script:TempRoot 'lateral.log')) 'correct source is blocked and verified'
    $lateralLog = Get-Content (Join-Path $script:TempRoot 'lateral.log') -Raw
    Assert-True ($lateralLog -match '\[BLOCKED\]') 'verified block is logged'
    $script:FirewallRule = 'refuse'
    Assert-Equal 1 (Invoke-LateralResponse $lat (Join-Path $script:TempRoot 'refuse.log')) 'firewall refusal is failure'
    $script:FirewallRule = [pscustomobject]@{ Enabled = $false; Direction = 'Inbound'; Action = 'Block'; RemoteAddress = '198.51.100.9' }
    Assert-Equal 1 (Invoke-LateralResponse $lat (Join-Path $script:TempRoot 'mismatch.log')) 'firewall readback mismatch is failure'
    Assert-True ((Get-Content (Join-Path $script:TempRoot 'mismatch.log') -Raw) -notmatch '\[BLOCKED\]') 'mismatch does not log success'
    $script:FirewallRule = [pscustomobject]@{ Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'; RemoteAddress = '203.0.113.20'; Profile = 'Private' }
    Assert-Equal 1 (Invoke-LateralResponse $lat (Join-Path $script:TempRoot 'profile.log')) 'a partial-profile rule does not satisfy the requested Any-profile block'
    $script:FirewallRule = [pscustomobject]@{ Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'; RemoteAddress = @('203.0.113.20', '203.0.113.21'); Profile = 'Any' }
    Assert-Equal 1 (Invoke-LateralResponse $lat (Join-Path $script:TempRoot 'addresses.log')) 'a broader address set does not satisfy a one-source block'
    Assert-Throws { Resolve-LateralSource (New-LateralAlert -UtcTime ([DateTimeOffset]::UtcNow.AddMinutes(-10).ToString('o'))) } 'stale lateral alert fails closed'

    # Canary review is the default and must perform no process action.
    Remove-Item Env:CANARY_ENABLE_RESPONSE -ErrorAction SilentlyContinue
    $reviewLog = Join-Path $script:TempRoot 'review.log'
    Assert-Equal 0 (Invoke-CanaryResponse $can $reviewLog $script:TempRoot) 'default canary mode is review only'
    Assert-True ((Get-Content $reviewLog -Raw) -match '\[REVIEW\]') 'review decision is logged'

    # Canary identity checks: stale, missing GUID, PID reuse, image/start-time mismatch.
    Assert-Throws { Read-CanaryMessage (Message 'add' (New-CanaryAlert -ProcessGuid '')) } 'missing ProcessGuid fails closed'
    Assert-Throws { Read-CanaryMessage (Message 'add' (New-CanaryAlert -UtcTime ([DateTimeOffset]::UtcNow.AddMinutes(-10).ToString('o')))) } 'stale canary fails closed'
    $script:WinEvents = @(New-SysmonEvent)
    $script:Process = New-FakeProcess
    Assert-Equal $script:Process (Get-CanaryProcess $can) 'matching ProcessGuid/Event 1 resolves process'
    $script:WinEvents = @()
    Assert-Throws { Get-CanaryProcess $can } 'missing process-creation record fails closed'
    $script:WinEvents = @(New-SysmonEvent -ProcessId '9999')
    Assert-Throws { Get-CanaryProcess $can } 'wrong process ID in Event 1 fails closed'
    $script:WinEvents = @(New-SysmonEvent -Guid '{22222222-2222-2222-2222-222222222222}')
    Assert-Throws { Get-CanaryProcess $can } 'PID reuse with wrong ProcessGuid fails closed'
    $script:WinEvents = @(New-SysmonEvent)
    $script:Process = New-FakeProcess -Path 'C:\Tools\other.exe'
    Assert-Throws { Get-CanaryProcess $can } 'image mismatch fails closed'
    $script:Process = New-FakeProcess -StartTime ([DateTime]::UtcNow.AddMinutes(-10))
    Assert-Throws { Get-CanaryProcess $can } 'start-time mismatch fails closed'

    # Native suspension status is tested through a fake CanaryProcessControl type.
    if (-not ('CanaryProcessControl' -as [type])) {
        Add-Type -TypeDefinition 'public static class CanaryProcessControl { public static int Status = 0; public static int NtSuspendProcess(System.IntPtr h) { return Status; } }'
    }
    [CanaryProcessControl]::Status = 1
    Assert-Throws { Suspend-CanaryProcess (New-FakeProcess) } 'nonzero native suspension status fails closed'
    [CanaryProcessControl]::Status = 0

    # ProcDump exit/missing dump and termination failure never produce false success logs.
    $dumpTool = Join-Path $script:TempRoot 'procdump.exe'; New-Item -ItemType File -Path $dumpTool -Force | Out-Null
    Set-Item -Path ('Function:' + $dumpTool) -Value { $global:LASTEXITCODE = 1 } -Force
    $env:CANARY_ENABLE_RESPONSE = 'true'; $script:Process = New-FakeProcess
    $exitLog = Join-Path $script:TempRoot 'dump-exit.log'
    Assert-Equal 1 (Invoke-CanaryResponse $can $exitLog $script:TempRoot) 'ProcDump nonzero exit fails closed'
    Assert-True ((Get-Content $exitLog -Raw) -notmatch '\[DUMPED\]|\[TERMINATED\]') 'ProcDump exit has no false success log'
    Set-Item -Path ('Function:' + $dumpTool) -Value { $global:LASTEXITCODE = 0 } -Force
    $missingLog = Join-Path $script:TempRoot 'dump-missing.log'
    Assert-Equal 1 (Invoke-CanaryResponse $can $missingLog $script:TempRoot) 'missing dump fails closed'
    Assert-True ((Get-Content $missingLog -Raw) -notmatch '\[DUMPED\]|\[TERMINATED\]') 'missing dump has no false success log'
    Set-Item -Path ('Function:' + $dumpTool) -Value { [System.IO.File]::WriteAllText($args[-1], 'dump'); $global:LASTEXITCODE = 0 } -Force
    $terminationLog = Join-Path $script:TempRoot 'termination.log'
    Assert-Equal 1 (Invoke-CanaryResponse $can $terminationLog $script:TempRoot) 'termination failure fails closed'
    Assert-True ((Get-Content $terminationLog -Raw) -match '\[DUMPED\]' -and (Get-Content $terminationLog -Raw) -notmatch '\[TERMINATED\]') 'termination failure does not log termination success'
    $script:Process = New-FakeProcess; $script:StopMode = 'simulate'; $script:WaitResult = $false
    $timeoutLog = Join-Path $script:TempRoot 'termination-timeout.log'
    Assert-Equal 1 (Invoke-CanaryResponse $can $timeoutLog $script:TempRoot) 'termination verification timeout fails closed'
    Assert-True ((Get-Content $timeoutLog -Raw) -notmatch '\[TERMINATED\]') 'termination timeout has no false success log'
    $script:Process = New-FakeProcess; $script:WaitResult = $true; $script:Disposed = $false
    $successLog = Join-Path $script:TempRoot 'verified-termination.log'
    Assert-Equal 0 (Invoke-CanaryResponse $can $successLog $script:TempRoot) 'verified fake dump and fake exit complete successfully'
    Assert-True ((Get-Content $successLog -Raw) -match '\[DUMPED\]' -and (Get-Content $successLog -Raw) -match '\[TERMINATED\]') 'success log requires verified dump and exit'
    Assert-True $script:Disposed 'process handle is disposed after response'
}
finally {
    if ($dumpTool) { Remove-Item -Path ('Function:' + $dumpTool) -ErrorAction SilentlyContinue }
    if ($oldComputer) { $env:COMPUTERNAME = $oldComputer } else { Remove-Item Env:COMPUTERNAME -ErrorAction SilentlyContinue }
    if ($oldResponse) { $env:CANARY_ENABLE_RESPONSE = $oldResponse } else { Remove-Item Env:CANARY_ENABLE_RESPONSE -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count) {
    $script:Failures | ForEach-Object { Write-Error $_ }
    exit 1
}
Write-Output "ACTIVE RESPONSE TESTS PASSED: $script:Assertions assertions"
