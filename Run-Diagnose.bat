@echo off
REM ============================================================
REM  Cleaner diagnostic - READ-ONLY.
REM  Checks driver health, network, and trace-surface coverage.
REM  Run after the cleaner + reboot to see what broke and what
REM  stayed behind.
REM ============================================================

setlocal

NET SESSION >nul 2>&1
if %errorLevel% EQU 0 goto :elevated

echo Requesting administrative privileges...
if "%*"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
) else (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -ArgumentList \"%*\" -Verb RunAs"
)
exit /b

:elevated
pushd "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diagnose-Cleaner.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd

echo.
echo Diagnostic exited with %EXITCODE% HIGH issue(s).
echo Press any key to close...
pause >nul
exit /b %EXITCODE%
