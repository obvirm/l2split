@echo off
rem driver.cmd -- menu pemasangan driver ndislwf untuk l2split.
rem Auto-elevate ke administrator lalu tampilkan pilihan.
net session >nul 2>&1
if errorlevel 1 (
    echo Butuh administrator -- minta UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
:menu
echo.
echo === l2split driver helper ===
echo 1. Pasang driver ndislwf  (install.ps1)
echo 2. Lepas driver           (uninstall.ps1)
echo 3. Test stating ON         (testsigning.ps1, butuh reboot)
echo 4. Testsinging OFF        (testsigning.ps1 -Off, butuh reboot)
echo 5. Keluar
set /p pilih=Pilihan:
if "%pilih%"=="1" powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
if "%pilih%"=="2" powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
if "%pilih%"=="3" powershell -NoProfile -ExecutionPolicy Bypass -File testsigning.ps1
if "%pilih%"=="4" powershell -NoProfile -ExecutionPolicy Bypass -File testsigning.ps1 -Off
if "%pilih%"=="5" exit /b
goto menu
