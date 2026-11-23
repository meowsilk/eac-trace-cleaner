#Requires -Version 5.1
<#
    Finish-Residues.ps1
    -------------------
    Surgical mop-up for empty-shell directories that survived the main
    cleaner + reboot cycle. Each path listed here:

      1. takeown + icacls to get write access
      2. Remove-Item -Recurse -Force

    Default targets are the two LOW residues the diagnostic typically
    reports after a successful clean + reboot:
       - C:\ProgramData\EasyAntiCheat   (empty shell)
       - %LOCALAPPDATA%\FortniteGame   (52+ empty subdirs after reboot)

    Pass additional paths as arguments to clean extra residues.
    Launch via Finish-Residues.bat (handles UAC).
#>

[CmdletBinding()]
param([string[]]$Extra)

$ErrorActionPreference = 'Continue'

# Admin check
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Must run as Administrator. Use Finish-Residues.bat." -ForegroundColor Red
    exit 1
}

$targets = @(
    'C:\ProgramData\EasyAntiCheat',
    (Join-Path $env:LOCALAPPDATA 'FortniteGame'),
    'C:\ProgramData\EasyAntiCheat_EOS',
    'C:\ProgramData\Epic\EasyAntiCheat',
    (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat'),
    (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat_EOS'),
    'C:\Program Files (x86)\EasyAntiCheat',
    'C:\Program Files (x86)\Common Files\EasyAntiCheat',
    'C:\Windows\System32\LogFiles\EasyAntiCheat'
)
if ($Extra) { $targets += $Extra }

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " Residue mop-up" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$deleted = 0; $absent = 0; $failed = 0

foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t)) {
        Write-Host "  [SKIP] $t  (already absent)" -ForegroundColor DarkGray
        $absent++
        continue
    }

    $isFile = -not (Get-Item -LiteralPath $t -Force).PSIsContainer

    # 1) takeown
    & takeown.exe /F $t /A $(if (-not $isFile) { '/R'; '/D'; 'Y' }) 2>&1 | Out-Null
    # 2) reset DACL to inherited defaults (fixes null-DACL case where
    #    nobody has access even as owner)
    & icacls.exe $t /reset $(if (-not $isFile) { '/T' }) /C 2>&1 | Out-Null
    # 3) explicit grant to Administrators + SYSTEM (and Lian if present)
    $grants = @('Administrators:F','SYSTEM:F')
    foreach ($g in $grants) {
        & icacls.exe $t /inheritance:e /grant $g $(if (-not $isFile) { '/T' }) /C 2>&1 | Out-Null
    }
    # 4) clear special attributes (S/H/R/A) on the whole tree
    if ($isFile) {
        & attrib.exe -S -H -R -A $t 2>&1 | Out-Null
    } else {
        & attrib.exe -S -H -R -A $t /S /D 2>&1 | Out-Null
    }

    # 5) remove the tree with escalation ladder
    if ($isFile) {
        # File case -- single path, not a tree
        try { Remove-Item -LiteralPath $t -Force -ErrorAction Stop } catch {}
        if (Test-Path -LiteralPath $t) { & cmd.exe /c "del /f /q `"$t`"" 2>&1 | Out-Null }
    } else {
        try { Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction Stop } catch {}
        if (Test-Path -LiteralPath $t) {
            # robocopy /MIR from an empty source nukes stubborn ACL-weird
            # trees that Remove-Item + rmdir both refuse.
            $empty = Join-Path $env:TEMP ("_empty_" + [guid]::NewGuid())
            New-Item -ItemType Directory -Path $empty -Force | Out-Null
            & robocopy.exe $empty $t /MIR /NFL /NDL /NJH /NJS /R:0 /W:0 2>&1 | Out-Null
            & cmd.exe /c "rmdir /s /q `"$t`"" 2>&1 | Out-Null
            Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue
        }
    }

    if (Test-Path -LiteralPath $t) {
        Write-Host "  [FAIL] $t  (still present after takeown + rmdir)" -ForegroundColor Red
        $failed++
    } else {
        Write-Host "  [ OK ] $t  (deleted)" -ForegroundColor Green
        $deleted++
    }
}

Write-Host ""
Write-Host ("  Deleted: {0}  Already absent: {1}  Failed: {2}" -f $deleted, $absent, $failed) -ForegroundColor Cyan
if ($failed -gt 0) {
    Write-Host ""
    Write-Host "  !! Some paths still present. Causes:" -ForegroundColor Red
    Write-Host "     - A service re-created it after boot (check Process Explorer)" -ForegroundColor DarkGray
    Write-Host "     - An ACL we don't own (try: icacls <path> /inheritance:r /grant *S-1-5-18:F /T)" -ForegroundColor DarkGray
}
exit $failed
