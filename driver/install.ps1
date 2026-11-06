# install.ps1 -- pemasang driver ndislwf (NDISLWF.sys) untuk l2split.
# Jalankan sebagai administrator, di folder driver\ yang memuat:
#   ndislwf.inf, ndislwf.sys, ndislwf.cat
param(
    [string]$InfPath = "$PSScriptRoot\ndislwf.inf",
    [string]$SysPath = "$PSScriptRoot\ndislwf.sys",
    [string]$CatPath = "$PSScriptRoot\ndislwf.cat"
)

$ErrorActionPreference = "Stop"
function Info([string]$s) { Write-Host $s }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal -ArgumentList $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "butuh administrator (klik kanan -> Run as administrator)"
    }
}
Assert-Admin
foreach ($f in @($InfPath, $SysPath, $CatPath)) {
    if (-not (Test-Path $f)) { throw "berkas hilang: $f" }
}

Info "0. status testsigning"
$bootcfg = bcdedit /enum "{current}" | Out-String
if ($bootcfg -match "testsigning\s+Yes") {
    Info "   testsigning: Yes"
} else {
    Info "   PERINGATAN: testsigning belum aktif"
    Info "   jalankan: testsigning.ps1  (bcdedit /set testsigning on + reboot)"
    Info "   install tetap dilanjutkan, tapi driver tidak akan load sebelum itu"
}

Info "1. hentikan adapter utama + layanan lama"
$adapter = Get-NetAdapter | Where-Object { $_.Status -ne "Disabled" } |
           Where-Object { $_.NdisMedium -eq 0 } | Select-Object -First 1
if ($adapter) { Disable-NetAdapter -Name $adapter.Name -Confirm:$false | Out-Null }
sc.exe stop NDISLWF 2>$null | Out-Null
sc.exe delete NDISLWF 2>$null | Out-Null
Start-Sleep 2

Info "2. uninstall komponen lama"
netcfg -v -u MS_NdisLwf 2>$null | Out-Null

Info "3. hapus paket driver lama (jika ada)"
$enum = pnputil -e | Out-String
[regex]::Matches($enum, "oem\d+\.inf[^\r\n]*") | ForEach-Object {
    $line = $_.Value
    if ($line -match "ndislwf\.inf") {
        $pn = [regex]::Match($line, "oem\d+\.inf").Value
        if ($pn) { pnputil -f -d $pn | Out-Null }
    }
}

Info "4. import paket baru"
pnputil -i -a $InfPath

Info "5. salin biner ke System32\DRIVERS"
Copy-Item $SysPath "$env:windir\System32\DRIVERS\ndislwf.sys" -Force

Info "6. pasang komponen jaringan"
netcfg -v -l $InfPath -c s -i MS_NdisLwf

Info "7. hidupkan kembali adapter"
if ($adapter) { Enable-NetAdapter -Name $adapter.Name -Confirm:$false | Out-Null }
Start-Sleep 10

Info "8. verifikasi layanan"
$svc = sc.exe query NDISLWF
if ("$svc" -match "RUNNING") {
    Info "OK: NDISLWF berjalan -- l2split siap dipakai"
} else {
    Info "PERINGATAN: layanan tidak berjalan setelah pemasangan"
    Info ($svc | Out-String)
}

Info "9. verifikasi binding"
Get-NetAdapterBinding -ComponentID MS_NdisLwf -EA SilentlyContinue |
    Format-Table -AutoSize | Out-Host
