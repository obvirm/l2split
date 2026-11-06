# uninstall.ps1 -- melepas driver ndislwf + binding-nya.
# Jalankan sebagai administrator. Setelah ini aplikasi tidak bisa membuka
# \\.\NDISLWF lagi sampai install.ps1 dijalankan ulang.
param()

$ErrorActionPreference = "Stop"
function Info([string]$s) { Write-Host $s }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal -ArgumentList $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "butuh administrator"
    }
}
Assert-Admin

Info "1. hentikan adapter utama + layanan"
$adapter = Get-NetAdapter | Where-Object { $_.Status -ne "Disabled" } |
           Where-Object { $_.NdisMedium -eq 0 } | Select-Object -First 1
if ($adapter) { Disable-NetAdapter -Name $adapter.Name -Confirm:$false | Out-Null }
sc.exe stop NDISLWF 2>$null | Out-Null
Start-Sleep 2

Info "2. uninstall komponen jaringan"
netcfg -v -u MS_NdisLwf 2>$null | Out-Null
sc.exe delete NDISLWF 2>$null | Out-Null

Info "3. hapus paket driver dari driver store"
$enum = pnputil -e | Out-String
[regex]::Matches($enum, "oem\d+\.inf[^\r\n]*") | ForEach-Object {
    $line = $_.Value
    if ($line -match "ndislwf\.inf") {
        $pn = [regex]::Match($line, "oem\d+\.inf").Value
        if ($pn) { pnputil -f -d $pn | Out-Null }
    }
}
Remove-Item "$env:windir\System32\DRIVERS\ndislwf.sys" -Force -EA SilentlyContinue

Info "4. hidupkan kembali adapter"
if ($adapter) { Enable-NetAdapter -Name $adapter.Name -Confirm:$false | Out-Null }
Start-Sleep 10

$left = sc.exe query NDISLWF 2>&1 | Out-String
if ($left -match "RUNNING") {
    Info "PERINGATAN: NDISLWF masih berjalan -- reboot untuk melepas sisa binding"
} else {
    Info "OK: NDISLWF tidak berjalan lagi (binding telah dilepas)"
}
Info "tombol testsigning biarkan; matikan lewat testsigning.ps1 -Off + reboot"
