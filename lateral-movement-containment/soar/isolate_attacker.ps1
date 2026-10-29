# Block the source IP tied to a Wazuh Sysmon process-creation alert.
param([string]$LogPath = 'C:\SOC_Lateral_Defense\lateral_containment.log')

function Read-LateralMessage([string]$Json) {
    if ([string]::IsNullOrWhiteSpace($Json)) { throw 'Active Response JSON is missing.' }
    $message = $Json | ConvertFrom-Json -ErrorAction Stop
    if ($message.command -ne 'add') { throw 'Only the add command is supported.' }
    $alert = $message.parameters.alert
    if ([string]$alert.rule.id -ne '100300' -or [string]$alert.data.win.system.eventID -ne '1') {
        throw 'Expected rule 100300 and Sysmon Event 1.'
    }
    $computer = [string]$alert.data.win.system.computer
    if (-not $computer -or $computer.Split('.')[0] -ine $env:COMPUTERNAME) {
        throw 'The alert does not identify this endpoint.'
    }
    return $alert
}

function Convert-LateralTime([object]$Value) {
    if ($Value -is [DateTimeOffset]) { return [DateTimeOffset]$Value }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return [DateTimeOffset]::new($Value.ToUniversalTime())
    }
    $parsed = [DateTimeOffset]::MinValue
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$parsed)) {
        throw 'The alert has no valid event timestamp.'
    }
    return $parsed
}

function Convert-LogonId([string]$Value) {
    if ($Value -notmatch '^0[xX][0-9a-fA-F]+$') { throw 'A hexadecimal LogonId is required.' }
    $number = [Convert]::ToUInt64($Value.Substring(2), 16)
    if ($number -eq 0) { throw 'An empty LogonId cannot identify a network session.' }
    return $number
}

function Resolve-LateralSource($Alert) {
    $data = $Alert.data.win.eventdata
    $logonId = Convert-LogonId ([string]$data.logonId)
    $eventTime = Convert-LateralTime $data.utcTime
    $age = ([DateTimeOffset]::UtcNow - $eventTime).TotalSeconds
    if ($age -gt 300 -or $age -lt -5) { throw 'The alert is stale or its timestamp is in the future.' }
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4624
        StartTime = $eventTime.LocalDateTime.AddSeconds(-60)
        EndTime = $eventTime.LocalDateTime.AddSeconds(2)
    } -ErrorAction Stop)
    $sources = @()
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $fields = @{}
        foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
        if ($fields.LogonType -ne '3' -or -not $fields.TargetLogonId) { continue }
        if ((Convert-LogonId $fields.TargetLogonId) -ne $logonId) { continue }
        if ($data.user) {
            $alertUser = ([string]$data.user -split '\\')[-1].Split('@')[0]
            if ($alertUser -ine $fields.TargetUserName) { continue }
            if ([string]$data.user -match '\\' -and
                ([string]$data.user -split '\\')[0] -ine $fields.TargetDomainName) { continue }
        }
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($fields.IpAddress, [ref]$ip)) { continue }
        if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
        if ([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or
            $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal) { continue }
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            ($ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224)) { continue }
        $sources += $ip.ToString()
    }
    $sources = @($sources | Sort-Object -Unique)
    if ($sources.Count -ne 1) { throw 'The matching logon does not identify one remote source IP.' }
    if ($sources[0] -in @('192.168.50.10', '192.168.50.1', '192.168.50.2')) {
        throw 'The source IP belongs to a protected lab host.'
    }
    return $sources[0]
}

function Write-LateralLog([string]$Path, [string]$Message) {
    Add-Content -LiteralPath $Path -Encoding UTF8 -Value "[$([DateTimeOffset]::UtcNow.ToString('o'))] $Message" -ErrorAction Stop
}

function Invoke-LateralResponse($Alert, [string]$Path) {
    try {
        $source = Resolve-LateralSource $Alert
        $ruleName = "SOC_AUTO_BLOCK_$source"
        $parent = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        Write-LateralLog $Path "[SOURCE] Rule 100300, LogonId $($Alert.data.win.eventdata.logonId), IP $source"
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if (-not $rule) {
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Block `
                -RemoteAddress $source -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        }
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
        $addresses = @(($rule | Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress)
        if ([string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Inbound' -or
            [string]$rule.Action -ne 'Block' -or [string]$rule.Profile -ne 'Any' -or
            $addresses.Count -ne 1 -or $source -notin $addresses) {
            throw 'The firewall rule did not read back as the requested source-IP block.'
        }
        Write-LateralLog $Path "[BLOCKED] Inbound source-IP rule verified for $source."
        $reportedId = [string]$Alert.data.win.eventdata.processId
        Write-LateralLog $Path "[AUDIT] Recorded alert process ID: $reportedId."
        return 0
    } catch {
        [Console]::Error.WriteLine("Lateral response failed: $($_.Exception.Message)")
        if (Test-Path -LiteralPath (Split-Path -Parent $Path)) {
            Write-LateralLog $Path "[FAILED] $($_.Exception.Message)"
        }
        return 1
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $alert = Read-LateralMessage ([Console]::In.ReadLine())
        exit (Invoke-LateralResponse $alert $LogPath)
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
