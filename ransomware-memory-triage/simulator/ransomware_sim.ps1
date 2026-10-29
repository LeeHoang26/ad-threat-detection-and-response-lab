# Write one canary file and keep the process alive for a lab response test.
param(
    [string]$CanaryPath = 'C:\Users\Administrator\Desktop\!_financial_payroll_2026.txt',
    [ValidateRange(1, 120)][int]$WaitSeconds = 30
)

if ([IO.Path]::GetFileName($CanaryPath) -notin @('!_financial_payroll_2026.txt', '!_confidential_contract.txt')) {
    throw 'Use one of the configured TXT canary filenames.'
}
if (-not (Test-Path -LiteralPath $CanaryPath -PathType Leaf)) {
    throw 'Create a disposable canary TXT file before running this test.'
}

[IO.File]::WriteAllText($CanaryPath, "Canary test write at $([DateTimeOffset]::UtcNow.ToString('o'))")
Write-Host "Canary written by PID $PID. Waiting $WaitSeconds seconds."
Start-Sleep -Seconds $WaitSeconds
