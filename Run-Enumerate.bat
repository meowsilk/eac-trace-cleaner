@echo off
REM ============================================================
REM  EAC trace enumerator - READ-ONLY. Does not modify anything.
REM  Produces a markdown inventory of every artifact the cleaner targets.
REM
REM  Pass-through switches (optional):
REM    -QuickScan    skip per-user iteration + dir size totals
REM    -JsonOut      also emit JSON next to the markdown
REM    -PathOnly     print existing paths, one per line
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Enumerate-EacTraces.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd

echo.
echo Enumerator exited with %EXITCODE% artifact(s) present.
echo Press any key to close...
pause >nul
exit /b %EXITCODE%
