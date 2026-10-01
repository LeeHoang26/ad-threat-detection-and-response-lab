# ==============================================================================
# SAFE RANSOMWARE SIMULATOR FOR CANARY DETECTION & TRIAGE VALIDATION
# Author: Hoang Lee (SOC Detection & Response Engineering)
# Target: Windows 10 Endpoint (Desktop Canary Traps)
# ==============================================================================

$CurrentPID = $PID
Write-Host "[*] Ransomware Simulator started. Current PID: $CurrentPID" -ForegroundColor Red

$CanaryPath = "C:\Users\Administrator\Desktop\!_financial_payroll_2026.txt"

if (Test-Path $CanaryPath) {
    Write-Host "[!] Found Canary target: $CanaryPath" -ForegroundColor Cyan
    Write-Host "[!] Simulating file tampering & encryption payload..." -ForegroundColor Magenta
    
    # Simulate AES-256 encrypted file contents with ransom note
    $EncryptedContent = @"
--- YOUR FILES HAVE BEEN ENCRYPTED BY SIMULATED RANSOMWARE ---
Original Content Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
All your confidential company payroll records are encrypted with AES-256.
Send 0.5 BTC to unlock key: bc1q8x9w2k01p7f5m3z9r4d2y6c8v1x4e9t2a7s5d1
"@
    # Force Sysmon Event 11 (FileCreate): Remove old file if present and create encrypted canary
    if (Test-Path $CanaryPath) {
        Remove-Item -Path $CanaryPath -Force
    }
    [System.IO.File]::WriteAllText($CanaryPath, $EncryptedContent)
    Write-Host "[+] Canary file recreated & encrypted payload deployed (Sysmon Event 11 triggered)!" -ForegroundColor Green
    
    # In real malware, encryption loops continuously across the directory tree.
    # We maintain execution to verify whether SOAR successfully suspends the process.
    Write-Host "[*] Simulating subsequent directory encryption loop (validating SOAR process suspension)..." -ForegroundColor Yellow
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 1
        Write-Host "    -> Encrypting next batch of files... ($i/15s)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "[-] Canary target not found at $CanaryPath" -ForegroundColor Red
}

Write-Host "[*] Attack simulation completed." -ForegroundColor White
