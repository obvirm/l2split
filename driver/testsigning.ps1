# testsigning.ps1 -- wnya-matikan mode test signing Windows.
# Driver yang tidak disertifikasi produksi hanya load saat testsigning Yes
# (ini mode resmi Windows, DISCLAIMER reboot; watermark "Test Mode" muncul
# di pojok desktop -- itu normal dan hilang saat dimatikan).
param([switch]$Off)

$ErrorActionPreference = "Stop"
function Info([string]$s) { Write-Host $s }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal -ArgumentList $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "butuh administrator"
    }
}
Assert-Admin

if ($Off) {
    Info "matikan testsigning (reboot diperlukan)"
    bcdedit /set testsigning off
} else {
    Info "hidupkan testsigning (reboot diperlukan)"
    bcdedit /set testsigning on
}
if ($LASTEXITCODE -ne 0) { throw "bcdedit gagal (exit $LASTEXITCODE)" }

$bootcfg = bcdedit /enum "{current}" | Out-String
if ($bootcfg -match "testsigning\s+Yes") {
    Info "status sekarang: Yes -- reboot untuk berlaku"
    Info "setelah reboot, jalankan: install.ps1"
} else {
    Info "status sekarang: No -- reboot untuk berlaku"
}
