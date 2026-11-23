@echo off
REM ============================================================
REM  Cleaner skew detector - READ-ONLY.
REM  Looks for the fingerprints a cleaner leaves behind.
REM  Run AFTER the cleaner + reboot to verify how clean the clean was.
REM
REM  Pass-through switches (optional):
REM    -MinSeverity Low   show every finding (default)
REM    -MinSeverity Medium
REM    -MinSeverity High  only the obvious tells
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Detect-CleanerSkew.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd

echo.
echo Skew detector exited with %EXITCODE% finding(s).
echo Press any key to close...
pause >nul
exit /b %EXITCODE%
