; Penginstal l2split — kendali penuh: pasang exe + driver (MSI) dengan UAC sekali,
; verifikasi layanan driver, dan uninstall yang benar-benar bersih.
Unicode true
SetCompressor /SOLID lzma

Name "l2split"
OutFile "D:\temp\l2bld\l2split-0.1.2-setup.exe"
InstallDir "$PROGRAMFILES64\l2split"
InstallDirRegKey HKLM "Software\l2split" "InstallDir"
RequestExecutionLevel admin
ShowInstDetails show
ShowUnInstDetails show

!include "LogicLib.nsh"

Var DID_MSI
Var DID_WV2

Section "Pasang"
  SetShellVarContext all
  SetRegView 64
  DetailPrint "Hentikan l2split yang masih berjalan (bila ada)..."
  nsExec::Exec 'taskkill /F /IM l2split.exe'
  Sleep 300
  DetailPrint "Menuang berkas ke $INSTDIR..."
  SetOutPath "$INSTDIR"
  File "D:\temp\l2tgt-clean\release\l2split.exe"
  File "D:\temp\l2tgt-clean\release\l2split_cli.exe"
  File "D:\temp\wv2\wv2setup.exe"
  SetOutPath "$INSTDIR\driver"
  File "E:\project\l2split\driver\ndis.msi"

  DetailPrint "Memeriksa komponen runtime antarmuka..."
  ClearErrors
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${If} ${Errors}
    DetailPrint "Komponen runtime antarmuka belum ada — memasang secara senyap..."
    nsExec::Exec '"$INSTDIR\wv2setup.exe" /silent /install'
    Pop $DID_WV2
    ${If} $DID_WV2 != 0
      MessageBox MB_ICONSTOP "Pemasangan komponen runtime antarmuka gagal (exit=$DID_WV2).$\nSetup dibatalkan."
      Abort
    ${EndIf}
  ${Else}
    DetailPrint "Komponen runtime antarmuka sudah ada (pv=$0)."
  ${EndIf}

  DetailPrint "Memasang driver jaringan (msiexec)..."
  nsExec::Exec 'msiexec /i "$INSTDIR\driver\ndis.msi" /qn /norestart /l*v "$INSTDIR\driver\msi-i.log"'
  Pop $DID_MSI
  ${If} $DID_MSI != 0
    ${If} $DID_MSI != 3010
      MessageBox MB_ICONSTOP "Pemasangan driver jaringan gagal (msiexec exit=$DID_MSI).$\nSetup dibatalkan tanpa mengubah pengaturan lain."
      Abort
    ${EndIf}
  ${EndIf}
  DetailPrint "Memverifikasi driver jaringan via CLI..."
  nsExec::Exec '"$INSTDIR\l2split_cli.exe" nd'
  Pop $R6
  ${If} $R6 != 0
    MessageBox MB_ICONSTOP "Driver jaringan tidak merespons setelah pemasangan (CLI exit=$R6).$\nSetup dibatalkan."
    Abort
  ${EndIf}
  WriteRegStr HKLM "Software\l2split" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "DisplayName" "l2split"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "DisplayVersion" "0.1.2"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "Publisher" "l2split project"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "UninstallString" "$INSTDIR\unins000.exe"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split" "NoRepair" 1
  WriteUninstaller "$INSTDIR\unins000.exe"
  CreateDirectory "$SMPROGRAMS\l2split"
  CreateShortCut "$SMPROGRAMS\l2split\l2split.lnk" "$INSTDIR\l2split.exe"
  DetailPrint "Driver terpasang dan terverifikasi."
SectionEnd

Function un.onInit
  ${If} ${Silent}
    Goto beres
  ${EndIf}
  MessageBox MB_ICONQUESTION|MB_YESNO "Lepas l2split beserta driver jaringannya?" IDYES beres
  Abort
  beres:
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  DetailPrint "Hentikan l2split yang masih berjalan..."
  nsExec::Exec 'taskkill /F /IM l2split.exe'
  nsExec::Exec 'taskkill /F /IM l2split_cli.exe'
  Sleep 300
  ${If} ${FileExists} "$INSTDIR\l2split_cli.exe"
    DetailPrint "Pulihkan state adapter (mode NORMAL + kosongkan filter)..."
    nsExec::Exec '"$INSTDIR\l2split_cli.exe" ndclear'
  ${EndIf}
  DetailPrint "Melepas driver jaringan (msiexec /x)..."
  nsExec::Exec 'msiexec /x "$INSTDIR\driver\ndis.msi" /qn /norestart /l*v "$INSTDIR\driver\msi-x.log"'
  Sleep 1500
  DetailPrint "Buang berkas dan kaitan registry..."
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "l2split"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\l2split"
  DeleteRegKey HKLM "Software\l2split"
  Delete "$INSTDIR\l2split.exe"
  Delete "$INSTDIR\l2split_cli.exe"
  Delete "$INSTDIR\unins000.exe"
  Delete "$INSTDIR\wv2setup.exe"
  RMDir /r "$INSTDIR\driver"
  Delete "$SMPROGRAMS\l2split\l2split.lnk"
  RMDir "$SMPROGRAMS\l2split"
  RMDir "$INSTDIR"
  DetailPrint "Selesai."
SectionEnd
