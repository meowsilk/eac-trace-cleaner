@echo off
REM ============================================================
REM  EAC / Fortnite / Epic Games trace cleaner - UAC launcher
REM  Double-click this file. It will self-elevate and then run
REM  EacCleaner.ps1 next to it.
REM
REM  Pass-through switches (optional):
REM    -SkipConfirm        no Y/N prompt
REM    -SkipReboot         do not auto-reboot
REM    -ClearTpm           also clear EacQuoteKey (WIPES BITLOCKER)
REM    -SkipCredentials    leave Credential Manager + DPAPI alone
REM    -SkipBrowsers       leave browser caches alone
REM    -DryRun             log actions, do not perform them
REM ============================================================

setlocal

NET SESSION >nul 2>&1
if %errorLevel% EQU 0 goto :elevated

echo Requesting administrative privileges...
REM Start-Process rejects an empty -ArgumentList, so only pass it when %* has content.
if "%*"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
) else (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -ArgumentList \"%*\" -Verb RunAs"
)
exit /b

:elevated
pushd "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0EacCleaner.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd

echo.
echo Cleaner exited with code %EXITCODE%.
echo Press any key to close this window...
pause >nul
exit /b %EXITCODE%
