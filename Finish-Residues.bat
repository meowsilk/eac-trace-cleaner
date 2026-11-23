@echo off
REM ============================================================
REM  Finish-Residues - surgical mop-up for empty-shell leftovers
REM  that survived the main cleaner + reboot.
REM  Self-elevates. No reboot needed.
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Finish-Residues.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd

echo.
echo Mop-up exited with %EXITCODE% failure(s).
echo Press any key to close...
pause >nul
exit /b %EXITCODE%
