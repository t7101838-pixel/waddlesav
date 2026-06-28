@echo off
:: ============================================
::   Ultimate AV Launcher
::   Double-click this to run the antivirus
:: ============================================

:: Check if running as Administrator, if not, relaunch as Admin automatically
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator access...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit
)

:: Set execution policy and launch the script
powershell.exe -ExecutionPolicy Bypass -File "%~dp0AVMenu_Ultimate.ps1"

:: If the script closes or errors, pause so you can read any message
pause
