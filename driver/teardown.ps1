# teardown.ps1 -- lepas driver l2split dalam satu tombol (dipanggil dari app,
# sudah elevated via UAC). Langkah: uninstall driver + testsigning OFF.
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
        throw "teardown.ps1 harus elevated"
    }
}
Assert-Admin

Log "teardown: mulai"
& "$DriverDir\uninstall.ps1" 2>&1 | ForEach-Object { Log "$_" }

Log "tombol testsigning OFF"
bcdedit /set testsigning off
if ($LASTEXITCODE -eq 0) { Log "testsigning OFF terpasang" }

if ($Reboot) {
    Log "reboot sekarang"
    Start-Process shutdown -ArgumentList "/r /t 5 /c ""l2split teardown: reboot untuk berlaku"""
}
