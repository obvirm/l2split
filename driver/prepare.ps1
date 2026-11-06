# prepare.ps1 -- wizard setup sekali-jalan untuk l2split (dipanggil dari app,
# sudah elevated via UAC). Yang dipakai: testsigning ON + daftar RunOnce
# install + reboot (opsional).
param([string]$DriverDir = $PSScriptRoot, [switch]$Reboot)

$ErrorActionPreference = "Stop"
function Log([string]$s) {
    $d = "$env:ProgramData\l2split"
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    Add-Content -Path "$d\setup.log" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $s"
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal -ArgumentList $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "prepare.ps1 harus elevated (dipanggil lewat UAC dari app)"
    }
}
Assert-Admin
foreach ($f in @("ndislwf.inf", "ndislwf.sys", "ndislwf.cat", "install.ps1")) {
    if (-not (Test-Path (Join-Path $DriverDir $f))) {
        Log "berkas hilang: $f"
        throw "berkas hilang: $(Join-Path $DriverDir $f)"
    }
}

Log "tombol testsigning ON"
bcdedit /set testsigning on
if ($LASTEXITCODE -ne 0) {
    Log "bcdedit gagal (Secure Boot aktif?)"
    throw "bcdedit /set testsigning on gagal (exit $LASTEXITCODE) -- Secure Boot aktif? matikan dulu di BIOS"
}

$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$run = "$ps -NoProfile -ExecutionPolicy Bypass -File `"$DriverDir\install.ps1`""
Log "daftar RunOnce: $run"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" `
    -Name "l2split-install" -Value $run

Log "tombol terpasang: testsigning ON + RunOnce l2split-install"
if ($Reboot) {
    Log "reboot sekarang"
    Start-Process shutdown -ArgumentList "/r /t 5 /c ""l2split setup: reboot untuk berlaku"""
}
