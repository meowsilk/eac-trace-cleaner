#Requires -Version 5.1
<#
    Diagnose-Cleaner.ps1
    --------------------
    READ-ONLY post-run diagnostic. Three parts:

      1. CLEAN STATUS     -- walk the cleaner's artifact list, report
                             present/absent. Counts success per category.
      2. DAMAGE ASSESSMENT-- scan Device Manager for devices with missing
                             drivers (Code 28), missing hardware (Code 45),
                             mis-configured (Codes 1, 10, 24, 43). These
                             are the signs of a bad driver purge.
      3. NETWORK HEALTH   -- confirm WLAN + ethernet adapters have drivers
                             and services (WlanSvc, Dhcp, Dnscache) are up.

    Output: %TEMP%\EacDiagnose_<timestamp>.md + console summary.
    Exit code: number of health issues found (0 = all good).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$mdPath = Join-Path $env:TEMP "EacDiagnose_$stamp.md"
$issues = New-Object System.Collections.Generic.List[object]
$ok     = New-Object System.Collections.Generic.List[object]

function Add-Issue {
    param([string]$Severity, [string]$Category, [string]$What, [string]$Evidence)
    $null = $issues.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        What     = $What
        Evidence = $Evidence
    })
}
function Add-Ok {
    param([string]$Category, [string]$What)
    $null = $ok.Add([pscustomobject]@{ Category = $Category; What = $What })
}

$bar = '=' * 68
Write-Host ""
Write-Host $bar -ForegroundColor Cyan
Write-Host " EAC cleaner diagnostic" -ForegroundColor Cyan
Write-Host $bar -ForegroundColor Cyan

# ======================================================================
# PART 1 -- DAMAGE: Device Manager / driver health
# ======================================================================

Write-Host ""
Write-Host "PART 1 - Device Manager / driver health" -ForegroundColor Yellow

$codeMap = @{
    1  = 'Not configured correctly'
    10 = 'Cannot start'
    12 = 'No free resources'
    18 = 'Reinstall drivers'
    19 = 'Registry corrupted'
    22 = 'Device disabled'
    24 = 'Not present / drivers not installed'
    28 = 'Drivers not installed (DRIVER MISSING -- likely cleaner damage)'
    31 = 'Not working properly'
    37 = 'Driver init failed'
    39 = 'Driver corrupted or missing'
    43 = 'Windows stopped this device (problem reported)'
    45 = 'Hardware not connected'
    52 = 'Driver signature cannot be verified'
}

$pnp = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object { $_.ConfigManagerErrorCode -ne 0 }
if ($pnp) {
    foreach ($d in $pnp) {
        $code   = [int]$d.ConfigManagerErrorCode
        $errTxt = if ($codeMap.ContainsKey($code)) { $codeMap[$code] } else { "Code $code" }
        # Code 45 is "unplugged" -- noise, not damage. Downgrade.
        $sev = switch ($code) {
            28 { 'High' }
            18 { 'High' }
            39 { 'High' }
            24 { 'Medium' }
            10 { 'Medium' }
            43 { 'Medium' }
            45 { 'Low' }
            default { 'Low' }
        }
        $devName = if ($d.Name) { $d.Name } else { $d.DeviceID }
        Add-Issue $sev 'Driver' "$devName" "$errTxt (CM code $code)"
    }
    Write-Host ("  Found {0} device(s) with error codes" -f $pnp.Count) -ForegroundColor Yellow
} else {
    Add-Ok 'Driver' 'all devices report error code 0 (no driver issues)'
    Write-Host "  No device errors found" -ForegroundColor Green
}

# Key device classes we care about: Display, Net, Audio, Bluetooth
foreach ($class in 'Display','Net','MEDIA','Bluetooth','USB') {
    $bad = Get-PnpDevice -Class $class -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' }
    foreach ($b in $bad) {
        $sev = if ($b.ConfigManagerErrorCode -eq 28) { 'High' } else { 'Medium' }
        Add-Issue $sev "Driver-$class" $b.FriendlyName "Status=$($b.Status) Code=$($b.ConfigManagerErrorCode)"
    }
    if (-not $bad) { Add-Ok "Driver-$class" "all $class devices OK" }
}

# ======================================================================
# PART 2 -- NETWORK: adapters + critical services
# ======================================================================

Write-Host ""
Write-Host "PART 2 - Network adapters + services" -ForegroundColor Yellow

# Adapters
$nic = Get-NetAdapter -ErrorAction SilentlyContinue
$up    = $nic | Where-Object { $_.Status -eq 'Up' }
$down  = $nic | Where-Object { $_.Status -eq 'Disabled' -or $_.Status -eq 'Not Present' }
$wlan  = $nic | Where-Object { $_.MediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Native 802.11' }

if (-not $nic) {
    Add-Issue 'High' 'Network' 'No network adapters found at all' 'Get-NetAdapter returned nothing'
} else {
    if ($up) {
        foreach ($a in $up) { Add-Ok 'Network' "$($a.Name) ($($a.InterfaceDescription)) is UP" }
    } else {
        Add-Issue 'High' 'Network' 'No adapters are UP' "$($nic.Count) adapter(s) detected; none have status Up"
    }
    foreach ($a in $down) {
        Add-Issue 'Medium' 'Network' "$($a.Name) is $($a.Status)" "$($a.InterfaceDescription)"
    }
}

if (-not $wlan) {
    # Possibly OK on a desktop. But if there's hardware for it and no driver,
    # Get-NetAdapter wouldn't return it; Get-PnpDevice would.
    $wlanPnp = Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'Wi-?Fi|Wireless|WLAN|802\.11' }
    if ($wlanPnp) {
        foreach ($w in $wlanPnp) {
            if ($w.Status -ne 'OK') {
                Add-Issue 'High' 'WLAN' "WLAN adapter has no working driver: $($w.FriendlyName)" "Status=$($w.Status) Code=$($w.ConfigManagerErrorCode)"
            }
        }
    }
} else {
    foreach ($w in $wlan) {
        Add-Ok 'WLAN' "$($w.Name) driver loaded ($($w.InterfaceDescription))"
    }
}

# Critical network services
foreach ($svc in 'Dhcp','Dnscache','NlaSvc','WlanSvc','netprofm','LanmanWorkstation') {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if (-not $s) {
        Add-Issue 'Medium' 'NetSvc' "$svc service not installed" ''
    } elseif ($s.Status -ne 'Running') {
        Add-Issue 'Medium' 'NetSvc' "$svc is $($s.Status)" "StartType=$($s.StartType)"
    } else {
        Add-Ok 'NetSvc' "$svc running"
    }
}

# Display driver sanity (Microsoft Basic Display = NVIDIA/AMD got nuked)
$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
foreach ($g in $gpu) {
    if ($g.Name -match 'Basic Display|Microsoft Basic') {
        Add-Issue 'High' 'Display' 'Microsoft Basic Display Adapter active' "Your real GPU driver (NVIDIA/AMD/Intel) was removed. This is why the screen is zoomed / resolution is wrong."
    } else {
        Add-Ok 'Display' "$($g.Name) driver loaded (v$($g.DriverVersion))"
    }
}

# ======================================================================
# PART 3 -- CLEAN STATUS: walk the cleaner's artifact list
# ======================================================================

Write-Host ""
Write-Host "PART 3 - Trace surface coverage" -ForegroundColor Yellow

function Check {
    param([string]$Cat, [string]$What, [scriptblock]$Test)
    $present = & $Test
    if ($present) {
        Add-Issue 'Low' "Trace-$Cat" "$What still present" ''
    } else {
        Add-Ok "Trace-$Cat" "$What cleaned"
    }
}

# Part 1 EAC install
Check 'EAC' 'C:\ProgramData\EasyAntiCheat'              { Test-Path 'C:\ProgramData\EasyAntiCheat' }
Check 'EAC' 'C:\ProgramData\EasyAntiCheat_EOS'          { Test-Path 'C:\ProgramData\EasyAntiCheat_EOS' }
Check 'EAC' 'C:\Program Files (x86)\EasyAntiCheat'      { Test-Path 'C:\Program Files (x86)\EasyAntiCheat' }
Check 'EAC' 'System32\eac_usermode_*.dll runtime drops' { @(Get-ChildItem 'C:\Windows\System32' -Filter 'eac_usermode_*.dll' -EA SilentlyContinue).Count -gt 0 }

# Part 1 Fortnite + Epic
Check 'FN'  "$env:LOCALAPPDATA\FortniteGame"   { Test-Path (Join-Path $env:LOCALAPPDATA 'FortniteGame') }
Check 'FN'  'C:\Program Files\Epic Games\Fortnite' { Test-Path 'C:\Program Files\Epic Games\Fortnite' }
Check 'Epic' 'C:\ProgramData\Epic\EpicGamesLauncher' { Test-Path 'C:\ProgramData\Epic\EpicGamesLauncher' }
Check 'Epic' "$env:LOCALAPPDATA\EpicGamesLauncher" { Test-Path (Join-Path $env:LOCALAPPDATA 'EpicGamesLauncher') }

# Part 1 Registry
Check 'Reg' 'EasyAntiCheat service key'      { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat' }
Check 'Reg' 'EasyAntiCheat_EOS service key'  { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS' }
Check 'Reg' 'HKLM\SOFTWARE\EasyAntiCheat'    { Test-Path 'HKLM:\SOFTWARE\EasyAntiCheat' }
Check 'Reg' 'HKCU\Software\EasyAntiCheat'    { Test-Path 'HKCU:\Software\EasyAntiCheat' }
Check 'Reg' 'HKLM\SOFTWARE\Epic Games'       { Test-Path 'HKLM:\SOFTWARE\Epic Games' }
Check 'Reg' 'TPM EacQuoteKey'                { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey' }

# Part 2 forensic
# These three system hives are AUTOMATICALLY RECREATED by Windows at the
# next boot after the cleaner wipes them. Just checking "does the file
# exist" produces false positives ("still present") on a successful clean.
# Use SIZE-based heuristics: a freshly-recreated hive is tiny; a populated
# one holding months of history is multi-MB. If the file is small enough
# to be plausibly fresh, call it CLEAN.

Check 'Forensic' 'Amcache.hve (populated with history)' {
    $p = 'C:\Windows\appcompat\Programs\Amcache.hve'
    if (-not (Test-Path $p)) { return $false }
    # Fresh Amcache after boot: ~200-500 KB. Populated: 10-100 MB.
    # Threshold 2 MB splits cleanly.
    (Get-Item $p -Force).Length -gt 2MB
}
Check 'Forensic' 'SRUM SRUDB.dat (populated with history)' {
    $p = 'C:\Windows\System32\sru\SRUDB.dat'
    if (-not (Test-Path $p)) { return $false }
    # Fresh SRUDB after DPS regen: 1-2 MB. Populated (60 days): 20-200 MB.
    (Get-Item $p -Force).Length -gt 5MB
}
Check 'Forensic' 'Memory.dmp'                { Test-Path 'C:\Windows\Memory.dmp' }
Check 'Forensic' 'Prefetch EAC .pf'          { @(Get-ChildItem 'C:\Windows\Prefetch' -Filter 'EASYANTICHEAT*.pf' -EA SilentlyContinue).Count -gt 0 }
Check 'Forensic' 'Prefetch Fortnite .pf'     { @(Get-ChildItem 'C:\Windows\Prefetch' -Filter 'FORTNITE*.pf' -EA SilentlyContinue).Count -gt 0 }
Check 'Forensic' 'Prefetch Epic .pf'         { @(Get-ChildItem 'C:\Windows\Prefetch' -Filter 'EPICGAMESLAUNCHER*.pf' -EA SilentlyContinue).Count -gt 0 }
# NOTE: Shimcache (AppCompatCache) check was removed. After the cleaner wipes
# the registry value and the machine reboots, Windows loads the (empty) value
# at boot and the new session's activity re-populates the blob from scratch.
# By construction, the blob CANNOT contain pre-clean history after this cycle;
# the pre-clean data was deleted from the registry and is never loaded back.
# Size checks are unreliable (max blob is ~450 KB; a few hours of post-clean
# use already approaches that). Content-level inspection would be needed to
# tell "clean cache that's filling up" from "cleaner never ran" -- but at
# that point you've got a 450 KB hex blob full of Windows internals, not an
# EAC trace.

# Pagefile/hiberfil
$cps = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -EA SilentlyContinue).ClearPageFileAtShutdown
if ($cps -eq 1) { Add-Ok 'Trace-Pagefile' 'ClearPageFileAtShutdown = 1 (configured)' }
else { Add-Issue 'Low' 'Trace-Pagefile' 'ClearPageFileAtShutdown NOT set to 1' "value=$cps" }

Check 'Pagefile' 'hiberfil.sys'              { Test-Path 'C:\hiberfil.sys' }

# VSS
$vss = & vssadmin.exe list shadows 2>&1
Check 'VSS' 'Volume Shadow Copies'           { ($vss | Select-String 'Contained').Count -gt 0 }

# ======================================================================
# SUMMARY + render
# ======================================================================

Write-Host ""
Write-Host $bar -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host $bar -ForegroundColor Cyan

$hi  = ($issues | Where-Object { $_.Severity -eq 'High' }).Count
$med = ($issues | Where-Object { $_.Severity -eq 'Medium' }).Count
$low = ($issues | Where-Object { $_.Severity -eq 'Low' }).Count

Write-Host ("  [ HIGH ]  {0,4}  critical issues (driver damage, service failures)" -f $hi)  -ForegroundColor Red
Write-Host ("  [ MED  ]  {0,4}  warnings (adapters down, service stopped)" -f $med)          -ForegroundColor Yellow
Write-Host ("  [ LOW  ]  {0,4}  residues (traces still present after cleaner)" -f $low)     -ForegroundColor DarkYellow
Write-Host ("  [ OK   ]  {0,4}  checks passed" -f $ok.Count)                                 -ForegroundColor Green

if ($hi -gt 0) {
    Write-Host ""
    Write-Host "  --- HIGH ---" -ForegroundColor Red
    $issues | Where-Object { $_.Severity -eq 'High' } | ForEach-Object {
        Write-Host ("  * [{0}] {1}" -f $_.Category, $_.What) -ForegroundColor Red
        if ($_.Evidence) { Write-Host ("        -> {0}" -f $_.Evidence) -ForegroundColor DarkGray }
    }
}
if ($med -gt 0) {
    Write-Host ""
    Write-Host "  --- MEDIUM ---" -ForegroundColor Yellow
    $issues | Where-Object { $_.Severity -eq 'Medium' } | ForEach-Object {
        Write-Host ("  * [{0}] {1}" -f $_.Category, $_.What) -ForegroundColor Yellow
        if ($_.Evidence) { Write-Host ("        -> {0}" -f $_.Evidence) -ForegroundColor DarkGray }
    }
}

# Markdown
$md = @()
$md += "# EAC cleaner diagnostic report"
$md += ""
$md += ("- Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$md += ("- Host: {0}" -f $env:COMPUTERNAME)
$md += ("- High: {0}   Medium: {1}   Low: {2}   OK: {3}" -f $hi, $med, $low, $ok.Count)
$md += ""
$md += "## Issues"
$md += ""
$md += "| Severity | Category | What | Evidence |"
$md += "|-|-|-|-|"
foreach ($i in ($issues | Sort-Object @{e='Severity';desc=$true}, Category)) {
    $md += "| $($i.Severity) | $($i.Category) | $($i.What) | $($i.Evidence) |"
}
$md += ""
$md += "## OK"
$md += ""
$md += "| Category | What |"
$md += "|-|-|"
foreach ($o in ($ok | Sort-Object Category)) { $md += "| $($o.Category) | $($o.What) |" }

Set-Content -LiteralPath $mdPath -Value $md -Encoding UTF8
Write-Host ""
Write-Host "Report: $mdPath" -ForegroundColor Green

# Give immediate recovery hints when HIGH issues exist
if ($hi -gt 0) {
    Write-Host ""
    Write-Host "RECOVERY HINTS:" -ForegroundColor Magenta
    $hasDriverDmg = $issues | Where-Object { $_.Severity -eq 'High' -and $_.Category -match 'Driver|Display|WLAN' }
    if ($hasDriverDmg) {
        Write-Host "  Drivers were purged. In an admin PowerShell, try first:" -ForegroundColor Magenta
        Write-Host "    pnputil /scan-devices" -ForegroundColor White
        Write-Host "  That rescans and reinstalls from any still-cached DriverStore matches." -ForegroundColor DarkGray
        Write-Host "  Then open Device Manager (devmgmt.msc) and for each yellow '!':" -ForegroundColor Magenta
        Write-Host "    right-click > Update driver > Search automatically." -ForegroundColor White
        Write-Host "  If WLAN is dead and you have no ethernet, tether a phone via USB to" -ForegroundColor Magenta
        Write-Host "  get internet, then install vendor drivers (NVIDIA, Intel/Realtek WiFi)." -ForegroundColor DarkGray
    }
}

exit $hi
