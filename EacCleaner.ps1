#Requires -Version 5.1
<#
    EacCleaner.ps1
    --------------
    Windows forensic trace cleaner.

    Walks a 17-phase cleanup over on-disk and registry artifacts that
    accumulate during normal Windows use (install logs, prefetch,
    execution-history caches, event logs, browser state, credential
    stores, volume shadow copies, pagefile, hibernation). Phases are
    ordered so that locked artifacts (Amcache.hve, Shimcache, pagefile)
    are handled across the reboot gate at the end.

    User-mode only. Does not touch kernel-resident state (that clears
    naturally at reboot) or NTFS low-level structures like $MFT slack.

    Launch via Run-EacCleaner.bat (handles UAC). Reboots at the end
    unless -SkipReboot.

    Switches:
        -SkipConfirm         no Y/N prompt
        -SkipReboot          do not auto-reboot
        -ClearTpm            also clear the TPM; WIPES BITLOCKER RECOVERY
        -SkipCredentials     leave Credential Manager + DPAPI alone
        -SkipBrowsers        leave browser caches alone
        -DryRun              log what would be done, do nothing
        -WholesalePrefetch   wipe the entire Prefetch folder
        -NukeBYOVD           also purge known vulnerable-driver remnants from
                             DriverStore + Services + system32\drivers
                             (rage_drv, kdmapper, iqvw64e, gdrv, RTCore64,
                             AsrDrv, MsIo64, ...)
#>

[CmdletBinding()]
param(
    [switch]$SkipConfirm,
    [switch]$SkipReboot,
    [switch]$ClearTpm,
    [switch]$SkipCredentials,
    [switch]$SkipBrowsers,
    [switch]$DryRun,
    [switch]$WholesalePrefetch,
    [switch]$NukeBYOVD
)

# ---------- Preamble ---------------------------------------------------

$ErrorActionPreference = 'Continue'

# Log location: beside the script in a logs/ subfolder so you don't have to
# hunt in %TEMP%. Two files per run:
#   EacCleaner_<ts>.log          -- everything, with timestamps + phase tags
#   EacCleaner_<ts>_FAILURES.log -- only FAIL lines (empty if none)
$script:LogDir = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path -LiteralPath $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
$script:StampSuffix  = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile      = Join-Path $script:LogDir "EacCleaner_$script:StampSuffix.log"
$script:FailLogFile  = Join-Path $script:LogDir "EacCleaner_${script:StampSuffix}_FAILURES.log"

$script:Counts       = @{ Ok = 0; Miss = 0; Warn = 0; Err = 0 }
$script:PhaseCounts  = [ordered]@{}
$script:CurrentPhase = 'INIT'

function Get-Stamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff' }

function Log-Line {
    param([string]$Tag, [string]$Msg, [switch]$FailuresToo)
    $line = "{0} [{1}] [{2}] {3}" -f (Get-Stamp), $Tag, $script:CurrentPhase, $Msg
    Add-Content -LiteralPath $script:LogFile -Value $line
    if ($FailuresToo) {
        Add-Content -LiteralPath $script:FailLogFile -Value $line
    }
}

function Bump-PhaseCount {
    param([string]$Which)
    if (-not $script:PhaseCounts.Contains($script:CurrentPhase)) {
        $script:PhaseCounts[$script:CurrentPhase] = @{ Ok = 0; Miss = 0; Warn = 0; Err = 0 }
    }
    $script:PhaseCounts[$script:CurrentPhase][$Which]++
}

function Write-Section {
    param([string]$Name)
    $script:CurrentPhase = $Name
    $bar = '=' * 68
    Write-Host ""
    Write-Host $bar  -ForegroundColor Cyan
    Write-Host " $Name" -ForegroundColor Cyan
    Write-Host $bar  -ForegroundColor Cyan
    Add-Content -LiteralPath $script:LogFile -Value ""
    Add-Content -LiteralPath $script:LogFile -Value $bar
    Add-Content -LiteralPath $script:LogFile -Value ("$(Get-Stamp) START PHASE: $Name")
    Add-Content -LiteralPath $script:LogFile -Value $bar
}

function Write-Info {
    param([string]$m)
    Write-Host "  $m" -ForegroundColor Gray
    Log-Line 'INFO' $m
}
function Write-Ok {
    param([string]$m)
    $script:Counts.Ok++;   Bump-PhaseCount 'Ok'
    Write-Host "  [ OK   ]  $m" -ForegroundColor Green
    Log-Line 'OK  ' $m
}
function Write-Miss {
    param([string]$m)
    $script:Counts.Miss++; Bump-PhaseCount 'Miss'
    Write-Host "  [ SKIP ]  $m" -ForegroundColor DarkGray
    Log-Line 'SKIP' $m
}
function Write-Warn2 {
    param([string]$m)
    $script:Counts.Warn++; Bump-PhaseCount 'Warn'
    Write-Host "  [ WARN ]  $m" -ForegroundColor Yellow
    Log-Line 'WARN' $m
}
function Write-Err2 {
    param([string]$m)
    $script:Counts.Err++;  Bump-PhaseCount 'Err'
    Write-Host "  [ FAIL ]  $m" -ForegroundColor Red
    Log-Line 'FAIL' $m -FailuresToo
}

function Test-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-PathSafe {
    param([string]$Path, [switch]$ContentsOnly)
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Miss $Path; return }
    if ($DryRun) { Write-Info "would delete: $Path"; return }
    try {
        if ($ContentsOnly) {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $Path) {
            if ($ContentsOnly -and ((Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -eq 0)) {
                Write-Ok "cleared contents: $Path"
            } else {
                # Second attempt: takeown + icacls to beat ACL-locked residue,
                # then retry Remove-Item. Catches the "empty shell directory
                # that won't delete" case (e.g. C:\ProgramData\EasyAntiCheat
                # after its files are gone but ACLs block the rmdir).
                & takeown.exe /F $Path /A /R /D Y 2>&1 | Out-Null
                & icacls.exe $Path /grant 'Administrators:F' /T /C 2>&1 | Out-Null
                if ($ContentsOnly) {
                    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (-not (Test-Path -LiteralPath $Path)) {
                    Write-Ok "deleted (after takeown): $Path"
                    return
                }
                # Still there -- schedule every file AND every directory
                # (deepest first) for MOVEFILE_DELAY_UNTIL_REBOOT.
                $allResidue = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer } |
                    ForEach-Object { $_.FullName })
                $allDirs = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSIsContainer } |
                    Sort-Object { $_.FullName.Length } -Descending |
                    ForEach-Object { $_.FullName })
                $scheduled = 0
                foreach ($f in $allResidue) {
                    if ([PendingDelete]::ScheduleDelete($f)) { $scheduled++ }
                }
                # Directories deepest first, then the root itself
                foreach ($d in $allDirs) {
                    if ([PendingDelete]::ScheduleDelete($d)) { $scheduled++ }
                }
                if ([PendingDelete]::ScheduleDelete($Path)) { $scheduled++ }
                $firstFew = ($allResidue + $Path) | Select-Object -First 3
                $preview = if ($firstFew) { ($firstFew -join '; ') } else { '' }
                Write-Warn2 ("partial delete: {0} ({1} entry(ies) scheduled for delete-at-reboot: {2}{3})" -f `
                    $Path, $scheduled, $preview, $(if ($allResidue.Count -gt 3) { '...' } else { '' }))
            }
        } else {
            Write-Ok "deleted: $Path"
        }
    } catch {
        Write-Err2 ("failed: {0} ({1})" -f $Path, $_.Exception.Message)
    }
}

function Remove-RegKeySafe {
    param([string]$Key)
    if (-not (Test-Path -LiteralPath $Key)) { Write-Miss "reg: $Key"; return }
    if ($DryRun) { Write-Info "would reg-del: $Key"; return }
    try {
        Remove-Item -LiteralPath $Key -Recurse -Force -ErrorAction Stop
        Write-Ok "reg-del: $Key"
    } catch {
        # Fall back to reg.exe for keys PS can't own
        $regPath = $Key -replace '^Registry::',''
        $null = & reg.exe DELETE $regPath /f 2>&1
        if (-not (Test-Path -LiteralPath $Key)) { Write-Ok "reg-del: $Key (via reg.exe)" }
        else { Write-Err2 ("reg-del failed: {0} ({1})" -f $Key, $_.Exception.Message) }
    }
}

function Remove-RegValuesLike {
    param([string]$Key, [string]$Pattern)
    if (-not (Test-Path -LiteralPath $Key)) { Write-Miss "reg values: $Key"; return }
    try {
        $item = Get-Item -LiteralPath $Key -ErrorAction Stop
        $matches = $item.GetValueNames() | Where-Object { $_ -match $Pattern }
        if (-not $matches) { Write-Miss "no $Pattern values in $Key"; return }
        foreach ($name in $matches) {
            if ($DryRun) { Write-Info "would reg-del value: $Key :: $name"; continue }
            Remove-ItemProperty -LiteralPath $Key -Name $name -Force -ErrorAction SilentlyContinue
            Write-Ok "reg-del value: $Key :: $name"
        }
    } catch {
        Write-Err2 ("reg-values failed: {0} ({1})" -f $Key, $_.Exception.Message)
    }
}

function Stop-ProcessByName {
    param([string]$Name)
    $procs = Get-Process -Name $Name -ErrorAction SilentlyContinue
    if (-not $procs) { Write-Miss "proc $Name not running"; return }
    foreach ($p in $procs) {
        if ($DryRun) { Write-Info "would kill: $($p.Name) PID=$($p.Id)"; continue }
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            Write-Ok "killed $($p.Name) PID=$($p.Id)"
        } catch {
            # Child procs of parents we already killed exit on their own.
            # By the time this loop iterates to them, Stop-Process sees "no
            # such PID" -- that's SKIP, not FAIL.
            $stillThere = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
            if (-not $stillThere) {
                Write-Miss ("already exited (child of a killed parent): {0} PID={1}" -f $p.Name, $p.Id)
            } else {
                Write-Err2 ("kill failed: {0} PID={1} ({2})" -f $p.Name, $p.Id, $_.Exception.Message)
            }
        }
    }
}

function Stop-ServiceSafe {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Miss "service $Name not installed"; return }
    if ($svc.Status -eq 'Stopped') { Write-Ok "service $Name already stopped"; return }
    if ($DryRun) { Write-Info "would stop service: $Name"; return }
    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        Write-Ok "stopped service: $Name"
    } catch {
        & sc.exe stop $Name | Out-Null
        Start-Sleep -Seconds 2
        $svc.Refresh()
        if ($svc.Status -eq 'Stopped') { Write-Ok "stopped via sc.exe: $Name" }
        else { Write-Err2 ("stop failed: {0} ({1})" -f $Name, $_.Exception.Message) }
    }
}

# Load P/Invoke MoveFileEx so we can schedule locked files for
# pending-rename deletion at next boot (used for Amcache.hve etc.)
$moveSig = @"
using System;
using System.Runtime.InteropServices;
public static class PendingDelete {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);
    public const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
    public static bool ScheduleDelete(string path) {
        return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}
"@
if (-not ('PendingDelete' -as [type])) {
    Add-Type -TypeDefinition $moveSig -ErrorAction SilentlyContinue
}

function Schedule-PendingDelete {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Miss "pending-del: $Path (not present)"; return }
    if ($DryRun) { Write-Info "would schedule pending-del: $Path"; return }
    $ok = [PendingDelete]::ScheduleDelete($Path)
    if ($ok) { Write-Ok "scheduled for delete-at-reboot: $Path" }
    else     { Write-Err2 "MoveFileEx failed for $Path (err=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
}

function Take-OwnershipAndGrant {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($DryRun) { Write-Info "would takeown: $Path"; return }
    & takeown.exe /F $Path /A /R /D Y 2>&1 | Out-Null
    & icacls.exe $Path /grant Administrators:F /T /C 2>&1 | Out-Null
}

# ---------- Preflight --------------------------------------------------

Write-Section "EAC / Fortnite / Epic trace cleaner"

# System info header lands at the top of the log so you can tell WHICH
# machine + WHEN + WITH WHAT SWITCHES this run happened.
try {
    $osInfo   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osCap    = if ($osInfo) { $osInfo.Caption } else { 'unknown' }
    $osVer    = if ($osInfo) { $osInfo.Version } else { 'unknown' }
    $lastBoot = if ($osInfo) { $osInfo.LastBootUpTime } else { 'unknown' }
} catch { $osCap='unknown'; $osVer='unknown'; $lastBoot='unknown' }

Add-Content -LiteralPath $script:LogFile -Value "# === EAC Cleaner run ==="
Add-Content -LiteralPath $script:LogFile -Value ("# Started    : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-Content -LiteralPath $script:LogFile -Value ("# Host       : {0}" -f $env:COMPUTERNAME)
Add-Content -LiteralPath $script:LogFile -Value ("# User       : {0}" -f $env:USERNAME)
Add-Content -LiteralPath $script:LogFile -Value ("# OS         : {0} {1}" -f $osCap, $osVer)
Add-Content -LiteralPath $script:LogFile -Value ("# Last boot  : {0}" -f $lastBoot)
Add-Content -LiteralPath $script:LogFile -Value ("# PowerShell : {0}" -f $PSVersionTable.PSVersion)
Add-Content -LiteralPath $script:LogFile -Value ("# Script     : {0}" -f $PSCommandPath)
Add-Content -LiteralPath $script:LogFile -Value ("# Switches   : SkipConfirm={0} SkipReboot={1} ClearTpm={2} SkipCredentials={3} SkipBrowsers={4} DryRun={5} WholesalePrefetch={6} NukeBYOVD={7}" -f `
    $SkipConfirm, $SkipReboot, $ClearTpm, $SkipCredentials, $SkipBrowsers, $DryRun, $WholesalePrefetch, $NukeBYOVD)
Add-Content -LiteralPath $script:LogFile -Value ""

Write-Host "  Log file     : $script:LogFile" -ForegroundColor DarkCyan
Write-Host "  Failures log : $script:FailLogFile" -ForegroundColor DarkCyan
Write-Host "  Dry run      : $DryRun"         -ForegroundColor DarkCyan
Write-Host "  ClearTpm     : $ClearTpm"        -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Color key:" -ForegroundColor DarkCyan
Write-Host "    [ OK   ]  succeeded"        -ForegroundColor Green
Write-Host "    [ SKIP ]  not present, nothing to do" -ForegroundColor DarkGray
Write-Host "    [ WARN ]  partial / deferred to reboot" -ForegroundColor Yellow
Write-Host "    [ FAIL ]  failed (needs attention)"   -ForegroundColor Red

if (-not (Test-Admin)) {
    Write-Err2 "This script must run as Administrator. Launch via Run-EacCleaner.bat."
    exit 1
}
Write-Ok "running as Administrator"

if (-not $SkipConfirm -and -not $DryRun) {
    Write-Host ""
    Write-Host "  THIS WILL DO THE FOLLOWING ON *THIS* MACHINE:" -ForegroundColor Yellow
    Write-Host "   - Kill Fortnite, Epic Games Launcher, EasyAntiCheat processes." -ForegroundColor Yellow
    if (-not $SkipBrowsers) {
        Write-Host "   - Kill all browsers (Chrome, Edge, Brave, Opera, Firefox, WebView2)." -ForegroundColor Yellow
    }
    Write-Host "   - Kill Discord, NVIDIA/AMD overlays, Xbox Game Bar, Steam." -ForegroundColor Yellow
    Write-Host "   - Stop the EasyAntiCheat and EasyAntiCheat_EOS services." -ForegroundColor Yellow
    Write-Host "   - DELETE all EAC, Fortnite, Epic Games Launcher install data." -ForegroundColor Yellow
    Write-Host "   - Delete all Windows forensic artifacts tied to EAC/Fortnite:" -ForegroundColor Yellow
    Write-Host "       Prefetch, Amcache (scheduled), Shimcache, BAM, SRUM, USN"   -ForegroundColor Yellow
    Write-Host "       Journal, Jump Lists, WPN, ActivityHistory, Thumbcache,"      -ForegroundColor Yellow
    Write-Host "       WER, Minidumps, Diagnosis, Search index, DriverStore INFs," -ForegroundColor Yellow
    Write-Host "       Panther, CBS, Setup logs, Scheduled Tasks."                  -ForegroundColor Yellow
    if (-not $SkipCredentials) {
        Write-Host "   - DELETE Windows Credential Manager + DPAPI master keys." -ForegroundColor Red
        Write-Host "       (Wi-Fi, VPN, saved browser creds will be lost.)"       -ForegroundColor Red
    }
    if (-not $SkipBrowsers) {
        Write-Host "   - Clear Chrome / Edge / Firefox cache + cookies + history." -ForegroundColor Yellow
    }
    if ($ClearTpm) {
        Write-Host "   - CLEAR TPM EacQuoteKey. THIS WILL WIPE BITLOCKER KEYS." -ForegroundColor Red
    }
    Write-Host "   - Delete every VSS snapshot on this machine."              -ForegroundColor Yellow
    Write-Host "   - Reset network stack (winsock, TCP/IP, Wi-Fi profiles, ARP, NBT)." -ForegroundColor Yellow
    Write-Host "     (Saved Wi-Fi networks WILL be forgotten -- you re-enter passwords.)" -ForegroundColor Yellow
    Write-Host "   - Clear all Windows event logs."                            -ForegroundColor Yellow
    Write-Host "   - Schedule pagefile + hiberfile wipe and REBOOT."           -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Type the word CLEAN to proceed"
    if ($ans -ne 'CLEAN') {
        Write-Err2 "aborted by user"
        exit 2
    }
}

# ---------- PHASE 1: Kill processes -----------------------------------

Write-Section "PHASE 1 - kill target processes (EAC/FN/Epic + apps holding locks on cleanable paths)"

# EAC / Fortnite / Epic -- always killed
$gameProcs = @(
    'FortniteClient-Win64-Shipping',
    'FortniteClient-Win64-Shipping_EAC',
    'FortniteClient-Win64-Shipping_EAC_EOS',
    'FortniteLauncher',
    'EpicGamesLauncher',
    'EpicWebHelper',
    'EpicOnlineServicesUserHelper',
    'EpicOnlineServicesUIHelper',
    'EasyAntiCheat',
    'EasyAntiCheat_launcher',
    'EasyAntiCheat_EOS',
    'EasyAntiCheat_EOSSys',
    'CrashReportClient',          # UE5 crash handler - holds FortniteGame\Saved\Crashes
    'CrashReportClientEditor',
    'UnrealCEFSubProcess',
    'EosOverlayRenderer-Win64-Shipping',
    'EOSSDK-Win64-Shipping'
)
foreach ($n in $gameProcs) { Stop-ProcessByName $n }

# Apps that hold file locks on paths Phases 9/10/11 are about to delete.
# Browser kills are gated by -SkipBrowsers (if you keep browser caches,
# we don't need to kill the browsers either).
$lockingProcs = @()

if (-not $SkipBrowsers) {
    # Browsers (Phase 11 wipes cache/cookies/history/login data)
    $lockingProcs += @(
        'chrome',
        'msedge',
        'msedgewebview2',           # WebView2 runtime hosts also lock profile dirs
        'brave',
        'firefox',
        'opera',
        'opera_gx',
        'iexplore'
    )
}

# Discord (Phase 9 wipes Discord caches + logs)
$lockingProcs += @(
    'Discord',
    'DiscordCanary',
    'DiscordPTB'
)

# NVIDIA / AMD overlay stacks (Phase 9 wipes their log + cache dirs).
# NVIDIA Container names use spaces -- Get-Process handles those fine.
$lockingProcs += @(
    'nvcontainer',
    'NVIDIA Share',
    'NVIDIA Overlay',
    'NVIDIA Web Helper',
    'NVIDIA GeForce Experience Backend',
    'GfExperience',
    'AMDRSServ',
    'RadeonSoftware',
    'AMDAutoUpdate',
    'amddvr'
)

# Xbox Game Bar + Game DVR (Phase 9 wipes ~\Videos\Captures)
$lockingProcs += @(
    'GameBar',
    'GameBarPresenceWriter',
    'GameBarFTServer',
    'XboxGameOverlay',
    'XboxGamingOverlay'
)

# Steam (runs some Fortnite accounts via EOS linkage; also holds logs)
$lockingProcs += @(
    'steam',
    'steamwebhelper',
    'steamservice'
)

foreach ($n in $lockingProcs) { Stop-ProcessByName $n }

# Give the OS a moment to release handles before we start deleting.
if (-not $DryRun) { Start-Sleep -Seconds 3 }

# ---------- PHASE 2: Stop services ------------------------------------

Write-Section "PHASE 2 - stop services that lock target files"
$services = @(
    'EasyAntiCheat',
    'EasyAntiCheat_EOS',
    'EasyAntiCheat_EOSSys',
    'wsearch',       # frees C:\ProgramData\Microsoft\Search\Data\...\Windows.edb
    'DPS',           # frees C:\Windows\System32\sru\SRUDB.dat (SRUM)
    'wuauserv',      # frees SoftwareDistribution if we touch it
    'DiagTrack',     # frees C:\ProgramData\Microsoft\Diagnosis\*
    'DoSvc',         # Delivery Optimization
    'UsoSvc',        # Update Orchestrator - frees C:\ProgramData\USOShared\Logs + USOPrivate\UpdateStore
    'WaaSMedicSvc'   # Windows Update Medic - sibling of UsoSvc
)
foreach ($s in $services) { Stop-ServiceSafe $s }

# WpnUserService is a per-user service template: real names are
# WpnUserService_<HEXSID>. Have to enumerate and stop each.
Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-ServiceSafe $_.Name
}

# ---------- PHASE 3: EAC-specific install + log locations -------------

Write-Section "PHASE 3 - EAC install + log directories"
$eacDirs = @(
    'C:\ProgramData\EasyAntiCheat',
    'C:\ProgramData\EasyAntiCheat_EOS',
    'C:\ProgramData\Epic\EasyAntiCheat',
    (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat'),
    (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat_EOS'),
    'C:\Program Files (x86)\EasyAntiCheat',
    'C:\Program Files (x86)\Common Files\EasyAntiCheat',
    'C:\Windows\System32\LogFiles\EasyAntiCheat'
)
foreach ($d in $eacDirs) { Remove-PathSafe $d }

# Runtime-dropped user-mode scanner (random name in system32)
Write-Info "scanning system32 for runtime-dropped eac_usermode_*.dll"
Get-ChildItem -Path 'C:\Windows\System32' -Filter 'eac_usermode_*.dll' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-PathSafe $_.FullName }

# ---------- PHASE 4: Fortnite game data -------------------------------

Write-Section "PHASE 4 - Fortnite game data + install (incl. pbrules.bin / game.bin)"
$fnDirs = @(
    (Join-Path $env:LOCALAPPDATA 'FortniteGame'),
    'C:\Program Files\Epic Games\Fortnite',
    'C:\Program Files (x86)\Epic Games\Fortnite'
)
foreach ($d in $fnDirs) { Remove-PathSafe $d }

# Discover non-default Fortnite installs via EGS manifests.
# Each manifest JSON has an InstallLocation field (per EOS SDK layout).
$manifestDir = 'C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests'
if (Test-Path $manifestDir) {
    Get-ChildItem -LiteralPath $manifestDir -Filter '*.item' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $m = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if (($m.DisplayName -match 'Fortnite') -and $m.InstallLocation) {
                Write-Info "EGS manifest -> $($m.InstallLocation)"
                Remove-PathSafe $m.InstallLocation
            }
        } catch {}
    }
}

# Belt+suspenders: scan non-system drive roots for Fortnite install folders.
# Keeps scope narrow (root-only, not recursive) so we don't walk the whole disk.
Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
    Where-Object { $_.Root -notmatch '^C:' } | ForEach-Object {
    foreach ($cand in @(
        (Join-Path $_.Root 'Epic Games\Fortnite'),
        (Join-Path $_.Root 'Fortnite'),
        (Join-Path $_.Root 'Program Files\Epic Games\Fortnite'),
        (Join-Path $_.Root 'Program Files (x86)\Epic Games\Fortnite')
    )) {
        if (Test-Path -LiteralPath $cand) { Remove-PathSafe $cand }
    }
}

# Scrub leftover pbrules.bin / game.bin anywhere Fortnite/EAC paths might survive.
# pbrules.bin is EAC's encrypted rules blob; game.bin is the catalog logic
# lookup. Both must go.
foreach ($binName in 'pbrules.bin','rules.bin','game.bin') {
    Get-ChildItem -Path 'C:\Program Files*','C:\ProgramData\Epic','C:\ProgramData\EasyAntiCheat*' `
        -Filter $binName -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-PathSafe $_.FullName }
}

# ---------- PHASE 5: Epic Games Launcher data + install --------------

Write-Section "PHASE 5 - Epic Games Launcher data + install"
# Device/account identifiers (DeviceIdCache, GameUserSettings.ini) and
# OAuth refresh/session tokens all live under LOCALAPPDATA\EpicGamesLauncher,
# which is deleted below.
$epicDirs = @(
    'C:\ProgramData\Epic\EpicGamesLauncher',
    'C:\ProgramData\Epic\SocialBackendCache',
    'C:\ProgramData\Epic\UnrealEngineLauncher',
    'C:\ProgramData\Epic',                                      # parent, catches everything else
    (Join-Path $env:LOCALAPPDATA 'EpicGamesLauncher'),
    (Join-Path $env:LOCALAPPDATA 'EpicOnlineServices'),
    (Join-Path $env:LOCALAPPDATA 'UnrealEngine'),               # UE5 shared state across games
    (Join-Path $env:APPDATA      'Epic Games'),                 # Roaming (older launcher versions)
    (Join-Path $env:APPDATA      'EpicGamesLauncher'),          # Roaming
    'C:\Program Files (x86)\Epic Games\Launcher',
    'C:\Program Files\Epic Games\Launcher'
)
foreach ($d in $epicDirs) { Remove-PathSafe $d }

# Registry hunt: search for any Epic launcher install path hints the cleaner
# might have missed (older installs that registered via different keys).
foreach ($pathKey in @(
    'HKLM:\SOFTWARE\WOW6432Node\Epic Games\EpicGamesLauncher',
    'HKLM:\SOFTWARE\Epic Games\EpicGamesLauncher'
)) {
    if (Test-Path $pathKey) {
        $p = (Get-ItemProperty -LiteralPath $pathKey -ErrorAction SilentlyContinue).AppDataPath
        if ($p -and (Test-Path $p)) {
            Write-Info "reg-pointed Epic AppDataPath -> $p"
            Remove-PathSafe $p
        }
    }
}

# ---------- PHASE 6: EAC + Epic registry keys ------------------------

Write-Section "PHASE 6 - EAC + Epic registry keys"
$eacRegKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOSSys',
    'HKLM:\SOFTWARE\EasyAntiCheat',
    'HKLM:\SOFTWARE\WOW6432Node\EasyAntiCheat',
    'HKCU:\Software\EasyAntiCheat',
    'HKLM:\SOFTWARE\Epic Games',
    'HKLM:\SOFTWARE\WOW6432Node\Epic Games',
    'HKCU:\Software\Epic Games'
)
foreach ($k in $eacRegKeys) { Remove-RegKeySafe $k }

# LastUserShellFolders is occasionally touched during EAC install/update.
# Wipe EAC-related values but preserve the key.
$lusf = 'HKLM:\SYSTEM\Setup\LastUserShellFolders'
if (Test-Path $lusf) { Remove-RegValuesLike -Key $lusf -Pattern 'EasyAntiCheat|Epic|Fortnite' }

# Run MRU + Map Network Drive MRU (per-user explorer history)
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'

# Flush ErrRpt_* leftover values if the service key survived.
# Observed builds expose ~23 ErrRpt_* values (ErrRpt_GameCrashExitStatus,
# _LastUnloadDuration, _GameState, _ServiceState, _GameCrashExitTime,
# _LastInitTime, _GameCrashCreateTime, _LastInitSandboxId, _LastInitDeploymentId,
# plus product variants). Pattern match catches them all regardless of count.
foreach ($svcKey in @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOSSys'
)) {
    if (Test-Path $svcKey) { Remove-RegValuesLike -Key $svcKey -Pattern '^ErrRpt_' }
}

# Uninstall entries (Add/Remove Programs)
foreach ($uninstallBase in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)) {
    if (-not (Test-Path $uninstallBase)) { continue }
    Get-ChildItem $uninstallBase -ErrorAction SilentlyContinue | ForEach-Object {
        $dn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($dn -and ($dn -match 'EasyAntiCheat|Fortnite|Epic Games|Epic Online Services')) {
            Remove-RegKeySafe $_.PSPath
        }
    }
}

# TPM-bound EAC attestation keys (destructive -- optional).
# Deleting the registry entries detaches the EAC quote key from Windows'
# view but does NOT reprovision the TPM. If you need a real TPM clear
# (e.g. the key is sealed in hardware NVRAM and was being re-fetched),
# follow this with tpm.msc -> Clear TPM, or a BIOS-level TPM clear.
$tpmKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\AttestationKey'
)
if ($ClearTpm) {
    Write-Warn2 "Clearing TPM EacQuoteKey. BitLocker recovery keys bound to this TPM will be invalidated."
    foreach ($k in $tpmKeys) { Remove-RegKeySafe $k }
    # Don't call Clear-Tpm automatically -- it needs owner-auth and can
    # brick BitLocker silently. Tell the operator how to finish the job.
    Write-Warn2 "For a hardware TPM clear: tpm.msc -> Clear TPM, or BIOS TPM Clear. Script will NOT do this."
} else {
    foreach ($k in $tpmKeys) {
        if (Test-Path $k) { Write-Warn2 "TPM key present (not cleared; use -ClearTpm): $k" }
    }
}

# ---------- PHASE 7: Prefetch (targeted) ------------------------------

if ($WholesalePrefetch) {
    Write-Section "PHASE 7 - Prefetch (WHOLESALE - every .pf, as requested)"
    Get-ChildItem -Path 'C:\Windows\Prefetch' -Filter '*.pf' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-PathSafe $_.FullName }
} else {
    Write-Section "PHASE 7 - Prefetch (targeted: EAC/Fortnite/Epic only)"
    $prefetchPatterns = @(
        'EASYANTICHEAT*.pf',
        'FORTNITE*.pf',
        'EPICGAMESLAUNCHER*.pf',
        'EPICWEBHELPER*.pf',
        'EPICONLINESERVICES*.pf',
        'FORTNITECLIENT*.pf',
        'FORTNITELAUNCHER*.pf'
    )
    foreach ($pat in $prefetchPatterns) {
        Get-ChildItem -Path 'C:\Windows\Prefetch' -Filter $pat -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-PathSafe $_.FullName }
    }
}
Write-Info "clearing Prefetch\ReadyBoot (boot trace)"
Remove-PathSafe 'C:\Windows\Prefetch\ReadyBoot' -ContentsOnly
# PfSvPerfStats.bin = superfetch perf stats cache (records boot app order).
Remove-PathSafe 'C:\Windows\Prefetch\PfSvPerfStats.bin'

# ---------- PHASE 8: Forensic registry artifacts ----------------------

Write-Section "PHASE 8 - forensic registry (BAM, MUICache, Shimcache, UserAssist, Shellbags, ...)"

# BAM / DAM per-SID subkeys (list of executables run + last-run times)
foreach ($bamBase in @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings',
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
    'HKLM:\SYSTEM\CurrentControlSet\Services\dam\UserSettings'
)) {
    if (-not (Test-Path $bamBase)) { continue }
    Get-ChildItem $bamBase -ErrorAction SilentlyContinue | ForEach-Object {
        $sidKey = $_.PSPath
        if ($DryRun) { Write-Info "would wipe BAM values in $sidKey"; return }
        try {
            $item = Get-Item -LiteralPath $sidKey -ErrorAction Stop
            foreach ($valName in $item.GetValueNames()) {
                if ($valName -in @('SequenceNumber','Version')) { continue }
                Remove-ItemProperty -LiteralPath $sidKey -Name $valName -Force -ErrorAction SilentlyContinue
            }
            Write-Ok "BAM values wiped in $sidKey"
        } catch {
            Write-Err2 ("BAM wipe failed: {0} ({1})" -f $sidKey, $_.Exception.Message)
        }
    }
}

$muiCache = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
Remove-RegKeySafe $muiCache

# Shimcache (AppCompat). Registry is rebuilt at reboot from in-memory
# copy -- so we wipe the value AND trigger a reboot at the end.
$appCompatKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility'
)
foreach ($k in $appCompatKeys) {
    if (Test-Path $k) {
        Remove-RegValuesLike -Key $k -Pattern '.*'
    }
}

# UserAssist (ROT13 app launch counts, per user)
$uaBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
if (Test-Path $uaBase) {
    Get-ChildItem $uaBase -ErrorAction SilentlyContinue | ForEach-Object {
        $countKey = Join-Path $_.PSPath 'Count'
        if (Test-Path $countKey) { Remove-RegKeySafe $countKey }
    }
}

# RecentApps -- Cortana / Search's recent-app list (records Fortnite launches)
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'

# FeatureUsage -- app-execution counters Explorer maintains since Win10 1803
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage'

# TrustRecords -- Office/Explorer "we opened this" cache
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Office\16.0\Common\TrustRecords'

# AppSwitched / StuckRects3 -- taskbar launch state
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2\DesktopModernAppLaunchers'

# Shellbags (folder view history)
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\Shell\Bags'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\Shell\BagMRU'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU'
Remove-RegKeySafe 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags'
Remove-RegKeySafe 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'

Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'

# RDP connection history
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'

# App compat store flags (where a few compat fingerprints land)
Remove-RegKeySafe 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'

# ---------- PHASE 9: Forensic files ----------------------------------

Write-Section "PHASE 9 - forensic files (Amcache, SRUM, Jump Lists, WPN, ActivityHistory, Thumbcache, WER, ...)"

# Amcache.hve is locked at runtime -> schedule pending-rename deletion.
# Try a direct delete first in case the lock was released.
$amcachePaths = @(
    'C:\Windows\appcompat\Programs\Amcache.hve',
    'C:\Windows\appcompat\Programs\Amcache.hve.LOG1',
    'C:\Windows\appcompat\Programs\Amcache.hve.LOG2'
)
foreach ($p in $amcachePaths) {
    if (-not (Test-Path -LiteralPath $p)) { Write-Miss $p; continue }
    try {
        if (-not $DryRun) { Remove-Item -LiteralPath $p -Force -ErrorAction Stop }
        Write-Ok "deleted (unlocked): $p"
    } catch {
        Schedule-PendingDelete $p
    }
}

# SRUM database (Services DPS was stopped in phase 2)
Remove-PathSafe 'C:\Windows\System32\sru\SRUDB.dat'

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $jl1 = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'
    $jl2 = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'
    $rec = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    Remove-PathSafe $jl1 -ContentsOnly
    Remove-PathSafe $jl2 -ContentsOnly
    Remove-PathSafe $rec -ContentsOnly
}

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $wpn = Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\Notifications'
    Remove-PathSafe $wpn -ContentsOnly
}

# ActivityHistory / Timeline (ConnectedDevicesPlatform)
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $cdp = Join-Path $_.FullName 'AppData\Local\ConnectedDevicesPlatform'
    if (Test-Path -LiteralPath $cdp) {
        Get-ChildItem -LiteralPath $cdp -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-PathSafe (Join-Path $_.FullName 'ActivitiesCache.db')
            Remove-PathSafe (Join-Path $_.FullName 'ActivitiesCache.db-wal')
            Remove-PathSafe (Join-Path $_.FullName 'ActivitiesCache.db-shm')
        }
    }
}

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $exp = Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\Explorer'
    if (Test-Path -LiteralPath $exp) {
        Get-ChildItem -LiteralPath $exp -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-PathSafe $_.FullName }
        Get-ChildItem -LiteralPath $exp -Filter 'iconcache_*.db' -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-PathSafe $_.FullName }
    }
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\IconCache.db')
}

Remove-PathSafe 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'    -ContentsOnly
Remove-PathSafe 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'  -ContentsOnly
Remove-PathSafe 'C:\ProgramData\Microsoft\Windows\WER\Temp'           -ContentsOnly
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\WER') -ContentsOnly
}

Remove-PathSafe 'C:\Windows\Minidump' -ContentsOnly
Remove-PathSafe 'C:\Windows\Memory.dmp'
Remove-PathSafe 'C:\Windows\LiveKernelReports' -ContentsOnly

# Diagnosis / ETW traces + RtBackup (circular trace buffer)
Remove-PathSafe 'C:\ProgramData\Microsoft\Diagnosis' -ContentsOnly
Remove-PathSafe 'C:\Windows\System32\LogFiles\WMI\RtBackup' -ContentsOnly
Remove-PathSafe 'C:\ProgramData\USOShared\Logs' -ContentsOnly
Remove-PathSafe 'C:\ProgramData\USOPrivate\UpdateStore' -ContentsOnly

# Registry transaction logs (.regtrans-ms + .blf) -- replay buffers
# for in-flight hive writes. Can preserve registry state we just deleted.
Get-ChildItem 'C:\Windows\System32\config\TxR' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.regtrans-ms','.blf' } |
    ForEach-Object { Remove-PathSafe $_.FullName }

Remove-PathSafe 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows' -ContentsOnly

Remove-PathSafe 'C:\Windows\Panther'                 -ContentsOnly
Remove-PathSafe 'C:\Windows\Logs\CBS'                -ContentsOnly
Remove-PathSafe 'C:\Windows\Logs\DISM'               -ContentsOnly
Remove-PathSafe 'C:\Windows\Logs\MoSetup'            -ContentsOnly
Remove-PathSafe 'C:\Windows\Logs\SetupCl'            -ContentsOnly
Remove-PathSafe 'C:\Windows\Logs\Measured Boot'      -ContentsOnly
Remove-PathSafe 'C:\Windows\inf\setupapi.dev.log'
Remove-PathSafe 'C:\Windows\inf\setupapi.app.log'
Remove-PathSafe 'C:\Windows\inf\setupapi.setup.log'

# Scheduled Tasks that mention EAC/Fortnite/Epic
try {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match 'EasyAntiCheat|Fortnite|Epic' } |
        ForEach-Object {
            if ($DryRun) { Write-Info "would delete task: $($_.TaskPath)$($_.TaskName)" }
            else {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                Write-Ok "deleted scheduled task: $($_.TaskPath)$($_.TaskName)"
            }
        }
} catch { Write-Err2 "Get-ScheduledTask failed: $($_.Exception.Message)" }

# DriverStore FileRepository: delete any INF folder for an EAC driver.
# If -NukeBYOVD was passed we also purge known BYOVD (bring-your-own-
# vulnerable-driver) mapper remnants -- the repo's own rage_drv.sys
# family, kdmapper, iqvw64e (Intel), gdrv (Gigabyte), RTCore64 (MSI),
# AsrDrv/AsUpIO (ASRock), MsIo64/WinRing0, capcom, PhyMem, gmer.
Write-Info "scanning DriverStore for EAC driver INFs"
$driverStore = 'C:\Windows\System32\DriverStore\FileRepository'
$byovdNames = @(
    'rage_drv','kdmapper','iqvw64e','iqvw64','gdrv','RTCore64','RTCore32',
    'AsrDrv','AsUpIO','MsIo64','WinRing0','WinRing0x64','capcom','ucorew64',
    'PhyMem','phymem','gmer','AsrAppCharger','HpPortIox64','Dbutil_2_3',
    'WinFlash64','RzCommon'
)
if (Test-Path $driverStore) {
    # CRITICAL: match only the full string "easyanticheat". The bare 3-letter
    # "eac" collides with hex hashes in NVIDIA/WLAN/sdbus INF folder names
    # (compute-ACCElerator, hash fragments containing e-a-c, etc.).
    Get-ChildItem -LiteralPath $driverStore -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $hit = $false
        if ($_.Name -match '(?i)easyanticheat') { $hit = $true }
        if ($NukeBYOVD) {
            foreach ($n in $byovdNames) {
                if ($_.Name -match ('(?i)\b' + [regex]::Escape($n) + '\b')) { $hit = $true; break }
            }
        }
        if ($hit) {
            Take-OwnershipAndGrant $_.FullName
            Remove-PathSafe $_.FullName
        }
    }
    # Scrub oem*.inf whose content references EAC by its full product name
    # ONLY. Searching for 3-letter "EAC" matches thousands of legitimate INFs
    # (NVIDIA hardware IDs, hex IDs, word fragments). Never do that.
    Get-ChildItem 'C:\Windows\INF' -Filter 'oem*.inf' -ErrorAction SilentlyContinue | ForEach-Object {
        $txt = Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue -Raw
        $hit = $false
        if ($txt -and ($txt -match 'EasyAntiCheat')) { $hit = $true }
        if (-not $hit -and $NukeBYOVD -and $txt) {
            foreach ($n in $byovdNames) {
                if ($txt -match ('(?i)\b' + [regex]::Escape($n) + '\b')) { $hit = $true; break }
            }
        }
        if ($hit) {
            if (-not $DryRun) {
                & pnputil.exe /delete-driver $_.Name /uninstall /force 2>&1 | Out-Null
            }
            Write-Ok "pnputil purged: $($_.Name)"
        }
    }
}

if ($NukeBYOVD) {
    foreach ($n in $byovdNames) {
        # Service registry (what MiCreateDeviceDriver reads to load)
        foreach ($svcKey in @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\$n",
            "HKLM:\SYSTEM\CurrentControlSet\Services\$($n.ToLower())"
        )) {
            if (Test-Path $svcKey) { Remove-RegKeySafe $svcKey }
        }
        $sysFile = "C:\Windows\System32\drivers\$n.sys"
        if (Test-Path $sysFile) { Remove-PathSafe $sysFile }
    }
}

# Windows.old (prior OS install)
if (Test-Path 'C:\Windows.old') {
    Take-OwnershipAndGrant 'C:\Windows.old'
    Remove-PathSafe 'C:\Windows.old'
}

# WebCache (legacy IE / modern WinHTTP cache)
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\WebCache') -ContentsOnly
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\INetCache') -ContentsOnly
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\INetCookies') -ContentsOnly
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\History') -ContentsOnly
}

# Defender quarantine (if EAC or a cheat ever got quarantined)
Remove-PathSafe 'C:\ProgramData\Microsoft\Windows Defender\Quarantine' -ContentsOnly
Remove-PathSafe 'C:\ProgramData\Microsoft\Windows Defender\Scans\History' -ContentsOnly

# NVIDIA / AMD / Game Bar captures of Fortnite
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $vid = Join-Path $_.FullName 'Videos'
    foreach ($sub in 'Fortnite','Captures') {
        $tgt = Join-Path $vid $sub
        if (Test-Path -LiteralPath $tgt) { Remove-PathSafe $tgt }
    }
}

# NVIDIA Container service logs + GeForce Experience cache
Remove-PathSafe 'C:\ProgramData\NVIDIA Corporation\NVIDIA Container\Logs' -ContentsOnly
Get-ChildItem 'C:\ProgramData\NVIDIA Corporation' -Filter '*.log' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-PathSafe $_.FullName }
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\NVIDIA\GLCache')  -ContentsOnly
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\NVIDIA\DXCache')  -ContentsOnly
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\NVIDIA\GFExperience') -ContentsOnly
}

# Discord caches (may contain Epic account / Fortnite activity state)
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($app in 'discord','discordcanary','discordptb') {
        $root = Join-Path $_.FullName "AppData\Roaming\$app"
        if (Test-Path -LiteralPath $root) {
            Remove-PathSafe (Join-Path $root 'Cache')          -ContentsOnly
            Remove-PathSafe (Join-Path $root 'Code Cache')     -ContentsOnly
            Remove-PathSafe (Join-Path $root 'logs')           -ContentsOnly
            Remove-PathSafe (Join-Path $root 'GPUCache')       -ContentsOnly
        }
    }
}

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Temp') -ContentsOnly
}
Remove-PathSafe 'C:\Windows\Temp' -ContentsOnly
Remove-PathSafe (Join-Path $env:TEMP '*')

# ---------- PHASE 10: Credential Manager + DPAPI --------------------

if (-not $SkipCredentials) {
    Write-Section "PHASE 10 - Credential Manager + DPAPI + LSA cached logons"
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-PathSafe (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Credentials') -ContentsOnly
        Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Credentials')   -ContentsOnly
        Remove-PathSafe (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Protect')     -ContentsOnly
        Remove-PathSafe (Join-Path $_.FullName 'AppData\Local\Microsoft\Vault')         -ContentsOnly
        Remove-PathSafe (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Vault')       -ContentsOnly
    }
    # Flush in-memory vault
    if (-not $DryRun) {
        try { & cmdkey.exe /list 2>&1 | Select-String 'Target:' | ForEach-Object {
                  $t = ($_ -replace 'Target:\s*','').Trim()
                  & cmdkey.exe /delete:$t 2>&1 | Out-Null
                  Write-Ok "cmdkey /delete:$t"
              }
        } catch {}
    }

    # LSA secrets at HKLM\SECURITY\Policy\Secrets require SYSTEM elevation,
    # not just Administrator. Try anyway via reg.exe; if it fails, warn
    # the user and point at the workaround.
    Write-Info "attempting HKLM\\SECURITY\\Policy\\Secrets clear (SYSTEM-only)"
    if (-not $DryRun) {
        $null = & reg.exe DELETE 'HKLM\SECURITY\Policy\Secrets' /f 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "LSA Policy\\Secrets cleared"
        } else {
            Write-Warn2 "LSA Secrets cleared requires SYSTEM; run 'psexec -s -i cmd' then 'reg delete HKLM\\SECURITY\\Policy\\Secrets /f'"
        }
    }

    # Cached domain logons (MSV1_0): HKLM\SECURITY\Cache
    Write-Info "attempting HKLM\\SECURITY\\Cache clear (SYSTEM-only)"
    if (-not $DryRun) {
        $null = & reg.exe DELETE 'HKLM\SECURITY\Cache' /f 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Ok "LSA Cache cleared" }
    }
} else {
    Write-Section "PHASE 10 - SKIPPED (Credential Manager + DPAPI + LSA)"
}

# ---------- PHASE 11: Browser data ----------------------------------

if (-not $SkipBrowsers) {
    Write-Section "PHASE 11 - Browser caches / cookies / history"
    $browserRoots = @{
        Chrome   = 'AppData\Local\Google\Chrome\User Data'
        Edge     = 'AppData\Local\Microsoft\Edge\User Data'
        Brave    = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
        Opera    = 'AppData\Roaming\Opera Software\Opera Stable'
    }
    $cleanSubdirs = @('Cache','Code Cache','Cookies','Cookies-journal','History','History-journal',
                       'Local Storage','Session Storage','Network','GPUCache','Service Worker',
                       'IndexedDB','Login Data','Login Data-journal','Web Data')
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($b in $browserRoots.GetEnumerator()) {
            $root = Join-Path $_.FullName $b.Value
            if (-not (Test-Path -LiteralPath $root)) { continue }
            Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } |
                ForEach-Object {
                    foreach ($s in $cleanSubdirs) {
                        $tgt = Join-Path $_.FullName $s
                        if (Test-Path -LiteralPath $tgt) {
                            if ((Get-Item -LiteralPath $tgt -Force).PSIsContainer) {
                                Remove-PathSafe $tgt -ContentsOnly
                            } else {
                                Remove-PathSafe $tgt
                            }
                        }
                    }
                }
        }
        $ff = Join-Path $_.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ff) {
            Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                foreach ($s in 'cache2','storage','sessionstore-backups','startupCache','shader-cache') {
                    Remove-PathSafe (Join-Path $_.FullName $s) -ContentsOnly
                }
                foreach ($f in 'cookies.sqlite','places.sqlite','formhistory.sqlite','downloads.sqlite','webappsstore.sqlite') {
                    Remove-PathSafe (Join-Path $_.FullName $f)
                }
            }
        }
        $ffCache = Join-Path $_.FullName 'AppData\Local\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ffCache) {
            Get-ChildItem -LiteralPath $ffCache -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                foreach ($s in 'cache2','startupCache','shader-cache') {
                    Remove-PathSafe (Join-Path $_.FullName $s) -ContentsOnly
                }
            }
        }
    }
    # Flush DNS cache for good measure
    if (-not $DryRun) { & ipconfig.exe /flushdns | Out-Null; Write-Ok "ipconfig /flushdns" }
} else {
    Write-Section "PHASE 11 - SKIPPED (Browser caches)"
}

# ---------- PHASE 11b: Network stack reset ------------------------
# Full "fresh network" wipe. Not strictly required for EAC trace cleaning
# (Phase 11 already flushes DNS which is the only network-side cache EAC
# uses), but included here because the user asked to delete EVERYTHING.
# Winsock catalog, TCP/IP stack, ARP + NetBIOS caches, saved Wi-Fi profiles.
# All take effect on reboot (Phase 17).

Write-Section "PHASE 11b - Network stack reset (winsock, TCP/IP, Wi-Fi profiles, ARP, NBT)"
if (-not $DryRun) {
    # Winsock catalog -- removes any LSPs (layered service providers) injected
    # by third-party tools
    $wsOut = & netsh.exe winsock reset 2>&1
    Add-Content $script:LogFile ($wsOut -join "`r`n")
    Write-Ok "netsh winsock reset"

    $ipOut = & netsh.exe int ip reset 2>&1
    Add-Content $script:LogFile ($ipOut -join "`r`n")
    Write-Ok "netsh int ip reset"

    & arp.exe -d * 2>&1 | Out-Null
    Write-Ok "arp -d * (flushed ARP cache)"

    & nbtstat.exe -R 2>&1 | Out-Null
    Write-Ok "nbtstat -R (reloaded NetBIOS name cache)"
    & nbtstat.exe -RR 2>&1 | Out-Null
    Write-Ok "nbtstat -RR (released + refreshed name registrations)"

    # Saved Wi-Fi profiles (SSID history is a soft correlation signal)
    $wlanProfiles = & netsh.exe wlan show profiles 2>&1 |
        Select-String 'All User Profile\s+:\s+(.+)$' |
        ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
    if ($wlanProfiles) {
        foreach ($p in $wlanProfiles) {
            $null = & netsh.exe wlan delete profile name="$p" 2>&1
            Write-Ok "deleted Wi-Fi profile: $p"
        }
    } else {
        Write-Miss "no Wi-Fi profiles to delete"
    }

    & ipconfig.exe /release 2>&1 | Out-Null
    & ipconfig.exe /renew   2>&1 | Out-Null
    Write-Ok "ipconfig /release + /renew (new DHCP lease)"

    Write-Warn2 "Network stack reset applied. Full effect requires reboot (Phase 17)."
} else {
    Write-Info "would run: netsh winsock reset, netsh int ip reset, arp -d *, nbtstat -R/-RR, delete all Wi-Fi profiles, DHCP release+renew"
}

# ---------- PHASE 12: Recycle bin -----------------------------------

Write-Section "PHASE 12 - Recycle Bin"
if (-not $DryRun) {
    try {
        Clear-RecycleBin -Force -ErrorAction Stop
        Write-Ok "Recycle Bin cleared on all drives"
    } catch {
        Get-PSDrive -PSProvider FileSystem | ForEach-Object {
            $rb = Join-Path $_.Root '$Recycle.Bin'
            if (Test-Path -LiteralPath $rb) { Remove-PathSafe $rb -ContentsOnly }
        }
    }
} else { Write-Info "would clear Recycle Bin" }

# ---------- PHASE 13: VSS snapshots ---------------------------------

Write-Section "PHASE 13 - delete all Volume Shadow Copies"
if (-not $DryRun) {
    $vssOut = & vssadmin.exe delete shadows /all /quiet 2>&1
    Add-Content $script:LogFile ($vssOut -join "`r`n")
    Write-Ok "vssadmin delete shadows /all /quiet executed"
} else { Write-Info "would run: vssadmin delete shadows /all /quiet" }

# ---------- PHASE 14: NTFS USN journal ------------------------------

Write-Section 'PHASE 14 - NTFS USN journal + TxF $RmMetadata'
if (-not $DryRun) {
    # USN journal ($UsnJrnl:$J, $UsnJrnl:$Max) -- records every file op
    foreach ($drive in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used })) {
        $letter = ($drive.Root -replace '\\','')
        $usnOut = & fsutil.exe usn deletejournal /D /N $letter 2>&1
        Add-Content $script:LogFile ($usnOut -join "`r`n")
        Write-Ok "fsutil usn deletejournal /D /N $letter"
    }

    # TxF ($RmMetadata) transaction-manager log -- records transacted
    # file ops. setautoreset true marks it for reset on next mount.
    $txOut = & fsutil.exe resource setautoreset true C:\ 2>&1
    Add-Content $script:LogFile ($txOut -join "`r`n")
    Write-Ok 'fsutil resource setautoreset true C:\ ($RmMetadata will reset on reboot)'

    Write-Warn2 '$MFT / $LogFile / $INDX slack cannot be cleared without a reformat.'
    Write-Warn2 'These contain deleted-file metadata that survive this cleaner.'
} else { Write-Info "would run: fsutil usn deletejournal /D /N <each drive> + fsutil resource setautoreset true" }

# ---------- PHASE 15: Event logs (LAST -- clear logs its own event) -

Write-Section "PHASE 15 - clear all Windows event logs"
if (-not $DryRun) {
    $logs = & wevtutil.exe el 2>$null
    $count = 0
    foreach ($log in $logs) {
        $log = $log.Trim()
        if (-not $log) { continue }
        $null = & wevtutil.exe cl "$log" 2>&1
        $count++
    }
    Write-Ok "wevtutil cl ran against $count log channels"

    # Also clear the classic logs via CIM for anything wevtutil skipped
    try {
        Get-WmiObject Win32_NTEventLogFile -ErrorAction SilentlyContinue | ForEach-Object {
            $null = $_.ClearEventlog()
        }
    } catch {}
} else { Write-Info "would clear all event logs via wevtutil cl" }

# ---------- PHASE 16: Pagefile + hibernation ------------------------

Write-Section "PHASE 16 - pagefile + hibernation + swapfile"

if (-not $DryRun) {
    # Set ClearPageFileAtShutdown = 1 so pagefile is zeroed on reboot
    reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f | Out-Null
    Write-Ok "set HKLM...Memory Management\\ClearPageFileAtShutdown = 1"

    # Disable paging + hibernation (will regenerate empty on next boot
    # after re-enabling, but the simple "off" is enough to delete
    # pagefile.sys + hiberfil.sys during the coming reboot)
    & powercfg.exe /hibernate off 2>&1 | Out-Null
    Write-Ok "powercfg /hibernate off  (deletes C:\\hiberfil.sys)"

    # swapfile.sys: managed by the ModernApp platform. It cannot be
    # deleted while in use. Disable paging for ModernApps so it
    # unlinks at next boot.
    reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        /v SwapfileControl /t REG_DWORD /d 0 /f | Out-Null
    Write-Ok "set HKLM...Memory Management\\SwapfileControl = 0 (disables swapfile.sys regen)"

    # Schedule swapfile.sys for pending-rename if it's locked
    if (Test-Path 'C:\swapfile.sys') { Schedule-PendingDelete 'C:\swapfile.sys' }
    if (Test-Path 'C:\hiberfil.sys') { Schedule-PendingDelete 'C:\hiberfil.sys' }
} else {
    Write-Info "would set ClearPageFileAtShutdown=1, powercfg /hibernate off, SwapfileControl=0, schedule swap+hiber pending-delete"
}

# ---------- Final summary --------------------------------------------

Write-Section "SUMMARY"

Write-Host ("  [ OK   ]  {0,6}  operations succeeded" -f $script:Counts.Ok)    -ForegroundColor Green
Write-Host ("  [ SKIP ]  {0,6}  items not present (nothing to clean)" -f $script:Counts.Miss) -ForegroundColor DarkGray
Write-Host ("  [ WARN ]  {0,6}  warnings / partials / deferred to reboot" -f $script:Counts.Warn)  -ForegroundColor Yellow
Write-Host ("  [ FAIL ]  {0,6}  failures" -f $script:Counts.Err)               -ForegroundColor Red

Write-Host ""
Write-Host "  Per-phase breakdown:" -ForegroundColor Cyan
$header = "{0,-66}  {1,5}  {2,5}  {3,5}  {4,5}" -f 'PHASE', 'OK', 'SKIP', 'WARN', 'FAIL'
Write-Host ("  $header") -ForegroundColor Cyan
Write-Host ("  " + ('-' * 94)) -ForegroundColor DarkCyan

# Log the breakdown too
Add-Content -LiteralPath $script:LogFile -Value ''
Add-Content -LiteralPath $script:LogFile -Value "PER-PHASE SUMMARY"
Add-Content -LiteralPath $script:LogFile -Value $header
Add-Content -LiteralPath $script:LogFile -Value ('-' * 94)

foreach ($phaseName in $script:PhaseCounts.Keys) {
    $c = $script:PhaseCounts[$phaseName]
    # Truncate long phase names for column alignment
    $shortName = if ($phaseName.Length -gt 66) { $phaseName.Substring(0, 63) + '...' } else { $phaseName }
    $row = "{0,-66}  {1,5}  {2,5}  {3,5}  {4,5}" -f $shortName, $c.Ok, $c.Miss, $c.Warn, $c.Err
    # Color-code by severity: red if any FAIL, yellow if any WARN, green if any OK-only, gray otherwise
    $color = if ($c.Err -gt 0) { 'Red' } elseif ($c.Warn -gt 0) { 'Yellow' } elseif ($c.Ok -gt 0) { 'Green' } else { 'DarkGray' }
    Write-Host "  $row" -ForegroundColor $color
    Add-Content -LiteralPath $script:LogFile -Value $row
}

Add-Content -LiteralPath $script:LogFile -Value ''
Add-Content -LiteralPath $script:LogFile -Value ("TOTAL  OK={0}  SKIP={1}  WARN={2}  FAIL={3}" -f `
    $script:Counts.Ok, $script:Counts.Miss, $script:Counts.Warn, $script:Counts.Err)

if ($script:Counts.Err -gt 0) {
    Write-Host ""
    Write-Host "  !! $($script:Counts.Err) failure(s). Full list:" -ForegroundColor Red
    Write-Host "     $script:FailLogFile" -ForegroundColor Red
    Write-Host "     Common causes: file locked by a process we did not kill, SYSTEM-only key," -ForegroundColor DarkGray
    Write-Host "     or a path requiring takeown before delete." -ForegroundColor DarkGray
} else {
    # No failures -- remove the empty failures log so the folder stays tidy
    if (Test-Path -LiteralPath $script:FailLogFile) {
        Remove-Item -LiteralPath $script:FailLogFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Section "DONE"
Write-Host "  Full log         : $script:LogFile" -ForegroundColor Cyan
if ($script:Counts.Err -gt 0) {
    Write-Host "  Failures only    : $script:FailLogFile" -ForegroundColor Red
}

# ---------- PHASE 17: Reboot ----------------------------------------

if ($SkipReboot -or $DryRun) {
    Write-Host ""
    Write-Warn2 "Reboot skipped. YOU MUST reboot manually for Shimcache flush, Amcache deletion, pagefile wipe, hibernation purge, and event-log quiescence to take effect."
    exit 0
}

Write-Host ""
Write-Host "  Rebooting in 20 seconds. Save anything open. Press Ctrl+C to abort." -ForegroundColor Magenta
for ($i = 20; $i -ge 1; $i--) {
    Write-Host "`r  Reboot in $i ... " -NoNewline -ForegroundColor Magenta
    Start-Sleep -Seconds 1
}
Write-Host ""
& shutdown.exe /r /t 0 /f
exit 0
