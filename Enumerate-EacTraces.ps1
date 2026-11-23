#Requires -Version 5.1
<#
    Enumerate-EacTraces.ps1
    -----------------------
    READ-ONLY inventory of every on-disk + registry artifact the main
    cleaner targets. Does not modify anything.

    Use before cleaning to see what's there. Use after cleaning +
    reboot to confirm the surface was cleared. Diff the two reports
    for an audit trail.

    Output: %TEMP%\EacTraces_<timestamp>.md (markdown) + console summary.
    Exit code: number of artifacts still present (0 = clean).

    Switches:
        -QuickScan   skip per-user iteration + big dir size totals
        -JsonOut     also emit JSON next to the markdown
        -PathOnly    print paths that still exist, one per line, nothing else
#>

[CmdletBinding()]
param(
    [switch]$QuickScan,
    [switch]$JsonOut,
    [switch]$PathOnly
)

$ErrorActionPreference = 'Continue'
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$mdPath  = Join-Path $env:TEMP "EacTraces_$stamp.md"
$jsonPath = Join-Path $env:TEMP "EacTraces_$stamp.json"
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Category,
        [string]$Type,         # File, Dir, RegKey, Service, Process
        [string]$Path,
        [string]$Desc,
        [bool]  $Present,
        [Nullable[long]]$SizeBytes = $null,
        [Nullable[datetime]]$Modified = $null,
        [string]$Extra = $null
    )
    $null = $findings.Add([pscustomobject]@{
        Category  = $Category
        Type      = $Type
        Path      = $Path
        Desc      = $Desc
        Present   = $Present
        SizeBytes = $SizeBytes
        Modified  = $Modified
        Extra     = $Extra
    })
}

function Get-DirSize {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
        if ($null -eq $sum) { return 0 } else { return [long]$sum }
    } catch { return $null }
}

function Check-File {
    param([string]$Cat, [string]$Path, [string]$Desc)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        Add-Finding -Category $Cat -Type 'File' -Path $Path -Desc $Desc -Present $true -SizeBytes ($i.Length) -Modified ($i.LastWriteTime)
    } else {
        Add-Finding -Category $Cat -Type 'File' -Path $Path -Desc $Desc -Present $false
    }
}

function Check-Dir {
    param([string]$Cat, [string]$Path, [string]$Desc)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        $size = if ($QuickScan) { $null } else { Get-DirSize $Path }
        $children = (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count
        Add-Finding -Category $Cat -Type 'Dir' -Path $Path -Desc $Desc -Present $true -SizeBytes $size -Modified ($i.LastWriteTime) -Extra "$children entries"
    } else {
        Add-Finding -Category $Cat -Type 'Dir' -Path $Path -Desc $Desc -Present $false
    }
}

function Check-RegKey {
    param([string]$Cat, [string]$Path, [string]$Desc)
    if (Test-Path -LiteralPath $Path) {
        $valCount = 0; $subCount = 0
        try {
            $it = Get-Item -LiteralPath $Path -ErrorAction Stop
            $valCount = ($it.GetValueNames()).Count
            $subCount = $it.SubKeyCount
        } catch {}
        Add-Finding -Category $Cat -Type 'RegKey' -Path $Path -Desc $Desc -Present $true -Extra "$valCount values, $subCount subkeys"
    } else {
        Add-Finding -Category $Cat -Type 'RegKey' -Path $Path -Desc $Desc -Present $false
    }
}

function Check-Service {
    param([string]$Cat, [string]$Name, [string]$Desc)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        Add-Finding -Category $Cat -Type 'Service' -Path $Name -Desc $Desc -Present $true -Extra "status=$($svc.Status) start=$($svc.StartType)"
    } else {
        Add-Finding -Category $Cat -Type 'Service' -Path $Name -Desc $Desc -Present $false
    }
}

function Check-Process {
    param([string]$Cat, [string]$Name, [string]$Desc)
    $p = Get-Process -Name $Name -ErrorAction SilentlyContinue
    if ($p) {
        Add-Finding -Category $Cat -Type 'Process' -Path $Name -Desc $Desc -Present $true -Extra ("PIDs=" + (($p | ForEach-Object Id) -join ','))
    } else {
        Add-Finding -Category $Cat -Type 'Process' -Path $Name -Desc $Desc -Present $false
    }
}

Write-Host "Scanning... log file: $mdPath" -ForegroundColor Cyan

# -------- Running processes (sanity: are Fortnite/Epic/EAC up?) --------
foreach ($p in @(
    'FortniteClient-Win64-Shipping','FortniteClient-Win64-Shipping_EAC','FortniteClient-Win64-Shipping_EAC_EOS',
    'FortniteLauncher','EpicGamesLauncher','EpicWebHelper',
    'EasyAntiCheat','EasyAntiCheat_launcher','EasyAntiCheat_EOS','EasyAntiCheat_EOSSys'
)) { Check-Process 'Running' $p '' }

# -------- Services --------
foreach ($s in @(
    'EasyAntiCheat','EasyAntiCheat_EOS','EasyAntiCheat_EOSSys'
)) { Check-Service 'EAC-Services' $s 'EAC service entry' }

# -------- Part 1: EAC install + logs --------
Check-Dir  'EAC-Install' 'C:\ProgramData\EasyAntiCheat'                  'EAC classic persistent config + cached session'
Check-Dir  'EAC-Install' 'C:\ProgramData\EasyAntiCheat_EOS'              'EAC-EOS persistent config'
Check-Dir  'EAC-Install' 'C:\ProgramData\Epic\EasyAntiCheat'             'EAC Epic launcher-managed state'
Check-Dir  'EAC-Install' (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat')     'EAC per-user cache'
Check-Dir  'EAC-Install' (Join-Path $env:LOCALAPPDATA 'EasyAntiCheat_EOS') 'EAC-EOS per-user cache'
Check-Dir  'EAC-Install' 'C:\ProgramData\Epic\EpicGamesLauncher\Data\Logs' 'Epic launcher logs (EAC spawn records)'
Check-Dir  'EAC-Install' 'C:\Program Files (x86)\EasyAntiCheat'           'system-wide EAC install'
Check-Dir  'EAC-Install' 'C:\Program Files (x86)\Common Files\EasyAntiCheat' 'shared EAC install (older)'
Check-Dir  'EAC-Install' 'C:\Windows\System32\LogFiles\EasyAntiCheat'     'driver-side crash dumps (some builds)'

# Runtime-dropped user-mode scanner DLLs
$drops = Get-ChildItem -Path 'C:\Windows\System32' -Filter 'eac_usermode_*.dll' -ErrorAction SilentlyContinue
if ($drops) {
    foreach ($f in $drops) { Check-File 'EAC-Drops' $f.FullName 'runtime-dropped user-mode scanner' }
}

# Fortnite + Epic
Check-Dir  'Fortnite' (Join-Path $env:LOCALAPPDATA 'FortniteGame')      'Fortnite saved config + logs + crashes'
Check-Dir  'Fortnite' 'C:\Program Files\Epic Games\Fortnite'            'Fortnite install (default)'
Check-Dir  'Fortnite' 'C:\Program Files (x86)\Epic Games\Fortnite'      'Fortnite install (x86)'
Check-Dir  'Fortnite' (Join-Path $env:LOCALAPPDATA 'EpicGamesLauncher') 'Epic launcher saved data (incl. DeviceIdCache)'

Check-Dir  'Epic'     'C:\ProgramData\Epic\EpicGamesLauncher' 'Epic launcher managed state'
Check-Dir  'Epic'     'C:\ProgramData\Epic\SocialBackendCache' 'Epic social cache (account linkage)'
Check-Dir  'Epic'     (Join-Path $env:LOCALAPPDATA 'EpicOnlineServices') 'EOS SDK state'

# pbrules.bin / game.bin anywhere in Epic Games tree
foreach ($binName in 'pbrules.bin','rules.bin','game.bin') {
    Get-ChildItem -Path 'C:\Program Files*','C:\ProgramData\Epic' -Filter $binName -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { Check-File 'EAC-Bundle' $_.FullName "encrypted rules blob ($binName)" }
}

# EGS manifests -- find non-default Fortnite installs
$manifestDir = 'C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests'
if (Test-Path $manifestDir) {
    Get-ChildItem -LiteralPath $manifestDir -Filter '*.item' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $m = Get-Content -LiteralPath $_.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop
            if (($m.DisplayName -match 'Fortnite') -and $m.InstallLocation) {
                Check-Dir 'Fortnite' $m.InstallLocation "Fortnite install (from manifest $($_.Name))"
            }
        } catch {}
    }
}

# -------- Part 1: Registry locations --------
foreach ($rk in @(
    @('HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat',          'EAC service'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS',      'EAC-EOS service'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOSSys',   'EAC-EOSSys service'),
    @('HKLM:\SOFTWARE\EasyAntiCheat',                                    'EAC 64-bit install registry'),
    @('HKLM:\SOFTWARE\WOW6432Node\EasyAntiCheat',                       'EAC WOW6432Node install registry'),
    @('HKCU:\Software\EasyAntiCheat',                                    'EAC per-user cache'),
    @('HKLM:\SOFTWARE\Epic Games',                                       'Epic Games root registry'),
    @('HKLM:\SOFTWARE\WOW6432Node\Epic Games',                           'Epic Games WOW6432Node'),
    @('HKCU:\Software\Epic Games',                                       'Epic Games per-user'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey',  'TPM EacQuoteKey (attestation binding)'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\AttestationKey','TPM AttestationKey')
)) { Check-RegKey 'EAC-Registry' $rk[0] $rk[1] }

# ErrRpt_* value count (observed range: up to 23)
foreach ($svcKey in @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOSSys'
)) {
    if (Test-Path $svcKey) {
        $item = Get-Item -LiteralPath $svcKey -ErrorAction SilentlyContinue
        $err = $item.GetValueNames() | Where-Object { $_ -match '^ErrRpt_' }
        Add-Finding -Category 'EAC-Registry' -Type 'RegValueSet' -Path "$svcKey\\ErrRpt_*" `
            -Desc 'ErrRpt_* telemetry values (up to ~23 observed)' `
            -Present ($err.Count -gt 0) -Extra "$($err.Count) matching values"
    }
}

# -------- Part 2: Prefetch --------
if (Test-Path 'C:\Windows\Prefetch') {
    $pfEac  = Get-ChildItem 'C:\Windows\Prefetch' -Filter 'EASYANTICHEAT*.pf'  -EA SilentlyContinue
    $pfFn   = Get-ChildItem 'C:\Windows\Prefetch' -Filter 'FORTNITE*.pf'       -EA SilentlyContinue
    $pfEpic = Get-ChildItem 'C:\Windows\Prefetch' -Filter 'EPICGAMESLAUNCHER*.pf' -EA SilentlyContinue
    $pfAll  = Get-ChildItem 'C:\Windows\Prefetch' -Filter '*.pf' -EA SilentlyContinue
    foreach ($pf in @($pfEac + $pfFn + $pfEpic)) {
        if ($pf) { Check-File 'Prefetch' $pf.FullName "Prefetch trace" }
    }
    Add-Finding -Category 'Prefetch' -Type 'DirStats' -Path 'C:\Windows\Prefetch' `
        -Desc 'Prefetch total file count' -Present ($pfAll.Count -gt 0) -Extra "$($pfAll.Count) .pf files total"
    Check-Dir 'Prefetch' 'C:\Windows\Prefetch\ReadyBoot' 'ReadyBoot boot-trace'
}

# -------- Part 2: Forensic files --------
Check-File 'Forensic' 'C:\Windows\appcompat\Programs\Amcache.hve'       'Amcache.hve (SHA1 of every run executable)'
Check-File 'Forensic' 'C:\Windows\appcompat\Programs\Amcache.hve.LOG1'  'Amcache transaction log 1'
Check-File 'Forensic' 'C:\Windows\appcompat\Programs\Amcache.hve.LOG2'  'Amcache transaction log 2'
Check-File 'Forensic' 'C:\Windows\System32\sru\SRUDB.dat'               'SRUM per-exe network + runtime stats'

Check-RegKey 'Forensic' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' 'Shimcache (AppCompat)'
Check-RegKey 'Forensic' 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'       'BAM per-SID activity'
Check-RegKey 'Forensic' 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' 'BAM State per-SID'
Check-RegKey 'Forensic' 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' 'MUICache'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' 'UserAssist'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps' 'RecentApps (Cortana)'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage' 'FeatureUsage (app execution counters)'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\Shell\Bags'          'Shellbags'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\Shell\BagMRU'        'Shellbag MRU'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags'    'ShellNoRoam Bags'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU'  'ShellNoRoam BagMRU'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'    'TypedPaths'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'    'RecentDocs'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'    'OpenSave MRU'
Check-RegKey 'Forensic' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' 'LastVisited MRU'

# Per-user forensic files
if (-not $QuickScan) {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $u = $_.Name
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations') 'Jump Lists (auto)'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')    'Jump Lists (custom)'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\Notifications')   'WPN notification db'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Local\ConnectedDevicesPlatform')          'ActivityHistory / Timeline'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Credentials')            'Credential Manager (roaming)'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Local\Microsoft\Credentials')              'Credential Manager (local)'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Protect')                'DPAPI master keys'
        Check-Dir "User-$u" (Join-Path $_.FullName 'AppData\Local\Microsoft\Vault')                    'Vault (local)'
    }
}

# WER + Minidump + Memory.dmp
Check-Dir  'Crashes' 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'    'WER queued dumps'
Check-Dir  'Crashes' 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'  'WER archived dumps'
Check-Dir  'Crashes' 'C:\Windows\Minidump'                                 'kernel minidumps'
Check-File 'Crashes' 'C:\Windows\Memory.dmp'                               'full kernel memory dump'
Check-Dir  'Crashes' 'C:\Windows\LiveKernelReports'                        'live kernel reports'

# Diagnostic / Search / Panther / CBS / setupapi
Check-Dir  'Logs' 'C:\ProgramData\Microsoft\Diagnosis'  'Diagnosis / ETW traces'
Check-Dir  'Logs' 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows' 'Windows Search index'
Check-Dir  'Logs' 'C:\Windows\Panther'                   'Panther setup/upgrade logs'
Check-Dir  'Logs' 'C:\Windows\Logs\CBS'                  'CBS component-based servicing logs'
Check-Dir  'Logs' 'C:\Windows\Logs\DISM'                 'DISM logs'
Check-Dir  'Logs' 'C:\Windows\Logs\Measured Boot'        'Measured Boot log'
Check-File 'Logs' 'C:\Windows\inf\setupapi.dev.log'      'setupapi driver install log'
Check-File 'Logs' 'C:\Windows\inf\setupapi.app.log'      'setupapi app install log'

# DriverStore scan
$driverStore = 'C:\Windows\System32\DriverStore\FileRepository'
if (Test-Path $driverStore) {
    Get-ChildItem -LiteralPath $driverStore -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'easyanticheat|eac|rage_drv|kdmapper|iqvw64|gdrv|RTCore64|AsrDrv|AsUpIO|MsIo64|WinRing0|capcom|phymem|gmer|HpPortIox64|Dbutil_2_3' } |
        ForEach-Object { Check-Dir 'DriverStore' $_.FullName "driver INF folder (match: $($_.Name))" }
    # Scan oemN.inf for EAC references
    Get-ChildItem 'C:\Windows\INF' -Filter 'oem*.inf' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $txt = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($txt -and ($txt -match 'EasyAntiCheat|EAC|rage_drv|kdmapper|iqvw64|gdrv|RTCore64')) {
                Check-File 'DriverStore' $_.FullName 'published INF matches EAC/BYOVD pattern'
            }
        } catch {}
    }
}

# VSS snapshots
$vssList = & vssadmin.exe list shadows 2>$null
$vssCount = ($vssList | Select-String 'Contained').Count
Add-Finding -Category 'VSS' -Type 'Snapshots' -Path 'vssadmin list shadows' `
    -Desc 'Volume Shadow Copy snapshots on this machine' -Present ($vssCount -gt 0) `
    -Extra "$vssCount snapshot(s)"

# USN journal state (just report presence/size via fsutil)
try {
    $usnInfo = & fsutil.exe usn queryjournal C: 2>&1
    $present = ($LASTEXITCODE -eq 0)
    Add-Finding -Category 'USN' -Type 'NtfsJournal' -Path 'C:\$Extend\$UsnJrnl:$J' `
        -Desc 'NTFS USN change journal on C:' -Present $present `
        -Extra (($usnInfo | Select-String -Pattern 'Maximum Size|Journal ID|First USN|Next USN') -join '; ')
} catch {}

# Scheduled Tasks
try {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match 'EasyAntiCheat|Fortnite|Epic' } |
        ForEach-Object {
            Add-Finding -Category 'Tasks' -Type 'ScheduledTask' -Path ($_.TaskPath + $_.TaskName) `
                -Desc 'Scheduled task matching EAC/Fortnite/Epic' -Present $true -Extra "state=$($_.State)"
        }
} catch {}

# Pagefile + Hibernation
Check-File 'Pagefile' 'C:\pagefile.sys'  'paged memory file (contains residual process memory)'
Check-File 'Pagefile' 'C:\hiberfil.sys'  'hibernation file (contains full RAM snapshot)'
Check-File 'Pagefile' 'C:\swapfile.sys'  'modern-app swap file'

# ClearPageFileAtShutdown setting
try {
    $cps = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -ErrorAction Stop).ClearPageFileAtShutdown
    Add-Finding -Category 'Pagefile' -Type 'Setting' -Path 'HKLM\...\Memory Management\ClearPageFileAtShutdown' `
        -Desc 'whether pagefile gets zeroed at shutdown' -Present ($cps -eq 1) -Extra "value=$cps"
} catch {}

# -------- Render --------

function Human-Size {
    param([Nullable[long]]$n)
    if ($null -eq $n) { return '' }
    if ($n -lt 1024) { return "$n B" }
    if ($n -lt 1048576) { return ("{0:N1} KB" -f ($n / 1024)) }
    if ($n -lt 1073741824) { return ("{0:N1} MB" -f ($n / 1048576)) }
    return ("{0:N2} GB" -f ($n / 1073741824))
}

$present = $findings | Where-Object { $_.Present }
$absent  = $findings | Where-Object { -not $_.Present }

if ($PathOnly) {
    $present | Where-Object { $_.Type -in 'File','Dir','RegKey' } |
        Sort-Object Path | ForEach-Object { Write-Host $_.Path }
    exit $present.Count
}

# Console summary
Write-Host ""
Write-Host "=== EAC / Fortnite / Epic trace inventory ===" -ForegroundColor Cyan
Write-Host ("Total present: {0}   Total absent: {1}" -f $present.Count, $absent.Count) -ForegroundColor Cyan
$present | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-20} {1,3} present" -f $_.Name, $_.Count) -ForegroundColor Yellow
}

# Markdown
$md = @()
$md += "# EAC / Fortnite / Epic trace inventory"
$md += ""
$md += ("- Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$md += ("- Host: {0}" -f $env:COMPUTERNAME)
$md += ("- User: {0}" -f $env:USERNAME)
$md += ("- Present: {0}   Absent: {1}" -f $present.Count, $absent.Count)
$md += ""
$md += "## Summary by category"
$md += ""
$md += "| Category | Present | Absent |"
$md += "|-|-|-|"
$findings | Group-Object Category | Sort-Object Name | ForEach-Object {
    $p = ($_.Group | Where-Object { $_.Present }).Count
    $a = ($_.Group | Where-Object { -not $_.Present }).Count
    $md += "| $($_.Name) | $p | $a |"
}
$md += ""
$md += "## Present artifacts"
$md += ""
$md += "| Category | Type | Path | Size | Modified | Extra | Desc |"
$md += "|-|-|-|-|-|-|-|"
foreach ($f in ($present | Sort-Object Category, Path)) {
    $size = Human-Size $f.SizeBytes
    $mod  = if ($f.Modified) { $f.Modified.ToString('yyyy-MM-dd HH:mm') } else { '' }
    $md += "| $($f.Category) | $($f.Type) | ``$($f.Path)`` | $size | $mod | $($f.Extra) | $($f.Desc) |"
}
$md += ""
$md += "## Absent (clean) artifacts"
$md += ""
$md += "| Category | Type | Path | Desc |"
$md += "|-|-|-|-|"
foreach ($f in ($absent | Sort-Object Category, Path)) {
    $md += "| $($f.Category) | $($f.Type) | ``$($f.Path)`` | $($f.Desc) |"
}

Set-Content -LiteralPath $mdPath -Value $md -Encoding UTF8
Write-Host ""
Write-Host "Markdown report: $mdPath" -ForegroundColor Green

if ($JsonOut) {
    $findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host "JSON report:     $jsonPath" -ForegroundColor Green
}

exit $present.Count
