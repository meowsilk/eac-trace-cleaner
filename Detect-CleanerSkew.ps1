#Requires -Version 5.1
<#
    Detect-CleanerSkew.ps1
    ----------------------
    READ-ONLY. Finds the forensic fingerprints a cleaner leaves behind.

    A thorough cleaner deletes evidence; a *stealthy* cleaner deletes
    evidence AND fakes the aftermath so the system looks lived-in.
    This script highlights the gap -- it reports where the cleaner's
    own footprints survived.

    Useful two ways:
      1) Post-cleaner validation: did the clean take, or are there
         obvious tells a forensic investigator would catch?
      2) Forensic inversion: if run against a system someone else
         cleaned, what did they fail to cover?

    Output: %TEMP%\EacSkew_<timestamp>.md and console summary.
    Exit code: number of findings (0 = no obvious skew).

    Switches:
        -MinSeverity Low|Medium|High   only report findings at or above this
#>

[CmdletBinding()]
param(
    [ValidateSet('Low','Medium','High')]
    [string]$MinSeverity = 'Low'
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$mdPath = Join-Path $env:TEMP "EacSkew_$stamp.md"
$findings = New-Object System.Collections.Generic.List[object]

function Add-F {
    param(
        [string]$Severity,
        [string]$Check,
        [string]$Finding,
        [string]$Evidence
    )
    $null = $findings.Add([pscustomobject]@{
        Severity = $Severity
        Check    = $Check
        Finding  = $Finding
        Evidence = $Evidence
    })
}

# System baselines we compare against
$osInstall = (Get-CimInstance Win32_OperatingSystem).InstallDate
$osLastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$osUptimeDays = (New-TimeSpan $osLastBoot (Get-Date)).TotalDays
$osAgeDays    = (New-TimeSpan $osInstall  (Get-Date)).TotalDays

Write-Host "OS installed : $osInstall  (age: $([math]::Round($osAgeDays,1)) days)" -ForegroundColor Cyan
Write-Host "Last boot    : $osLastBoot (uptime: $([math]::Round($osUptimeDays,1)) days)" -ForegroundColor Cyan
Write-Host ""

# --- 1. Prefetch -------------------------------------------------------

$pf = 'C:\Windows\Prefetch'
if (Test-Path $pf) {
    $pfFiles = Get-ChildItem $pf -Filter '*.pf' -EA SilentlyContinue
    if ($pfFiles.Count -eq 0 -and $osAgeDays -gt 1) {
        Add-F High 'Prefetch:empty' `
            'Prefetch directory contains 0 .pf files on a Windows install older than a day.' `
            "Age=$([math]::Round($osAgeDays,1))d, files=0. Clear trace of wholesale Prefetch purge."
    } elseif ($pfFiles.Count -lt 10 -and $osAgeDays -gt 7) {
        Add-F Medium 'Prefetch:sparse' `
            'Prefetch has very few entries on an established install.' `
            "Age=$([math]::Round($osAgeDays,1))d, files=$($pfFiles.Count). Normal is 100+."
    }
    # Check if Prefetch itself was recently modified
    $pfLastMod = (Get-Item $pf).LastWriteTime
    if ($pfLastMod -gt $osLastBoot -and $osUptimeDays -lt 1 -and $pfFiles.Count -lt 20) {
        Add-F Medium 'Prefetch:post-boot-wipe' `
            'Prefetch dir was modified after last boot but has very few files -- consistent with post-boot cleaner run.' `
            "Mod=$pfLastMod, boot=$osLastBoot, files=$($pfFiles.Count)"
    }
}

# --- 2. Amcache --------------------------------------------------------

$amc = 'C:\Windows\appcompat\Programs\Amcache.hve'
if (Test-Path $amc) {
    $amcItem = Get-Item -Force $amc
    $amcAgeDays = (New-TimeSpan $amcItem.CreationTime (Get-Date)).TotalDays
    if ($amcAgeDays -lt 1 -and $osAgeDays -gt 1) {
        Add-F High 'Amcache:fresh' `
            'Amcache.hve was created in the last 24h on a Windows install >1 day old.' `
            "Amcache created=$($amcItem.CreationTime), OS installed=$osInstall. Classic cleaner footprint."
    }
    if ($amcItem.Length -lt 1MB -and $osAgeDays -gt 7) {
        Add-F Medium 'Amcache:tiny' `
            'Amcache.hve is unusually small for an established system.' `
            "Size=$($amcItem.Length) bytes, OS age=$([math]::Round($osAgeDays,1))d."
    }
} else {
    if ($osAgeDays -gt 1) {
        Add-F High 'Amcache:missing' `
            'Amcache.hve absent on a Windows install older than 1 day.' `
            "Normal: Amcache is present on every modern Windows install. Scheduled pending-delete trace."
    }
}

# Pending-rename operations (direct cleaner signature)
try {
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA Stop).PendingFileRenameOperations
    if ($pfro) {
        $keep = $pfro | Where-Object { $_ -match 'Amcache|hiberfil|swapfile|pagefile|EasyAntiCheat|Fortnite' }
        if ($keep) {
            Add-F High 'PendingFileRenameOperations' `
                'Scheduled pending-delete entries matching EAC/forensic artifacts.' `
                ("Entries: " + ($keep -join ', '))
        }
    }
} catch {}

# --- 3. Shimcache size -------------------------------------------------

try {
    $shim = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -EA Stop).AppCompatCache
    if ($shim -and $shim.Length -lt 512 -and $osAgeDays -gt 7) {
        Add-F Medium 'Shimcache:tiny' `
            'Shimcache registry blob is near-empty on an established install.' `
            "Size=$($shim.Length) bytes. Normal is 100KB+."
    }
    if (-not $shim) {
        Add-F High 'Shimcache:null' `
            'Shimcache registry value AppCompatCache is NULL. Normal installs always have a populated blob.' `
            ""
    }
} catch {
    Add-F Medium 'Shimcache:missing-value' `
        'AppCompatCache value does not exist on the AppCompatCache key.' `
        $_.Exception.Message
}

# --- 4. Event logs -----------------------------------------------------

$sysLog = Get-WinEvent -LogName System -MaxEvents 1 -EA SilentlyContinue
if (-not $sysLog) {
    Add-F High 'EventLog:System-empty' 'System event log has no readable events.' 'wevtutil cl was clearly run.'
} else {
    $oldest = (Get-WinEvent -LogName System -EA SilentlyContinue -Oldest -MaxEvents 1).TimeCreated
    if ($oldest) {
        $spanDays = (New-TimeSpan $oldest (Get-Date)).TotalDays
        if ($spanDays -lt 1 -and $osAgeDays -gt 7) {
            Add-F High 'EventLog:System-shallow' `
                'System event log only goes back less than a day on an established install.' `
                "Oldest event=$oldest, OS age=$([math]::Round($osAgeDays,1))d."
        }
    }
}

# Look for Event ID 104 (log cleared) + 1102 (security log cleared) in recent history
try {
    $cleared = Get-WinEvent -FilterHashtable @{LogName='System','Security'; Id=104,1102} -MaxEvents 10 -EA SilentlyContinue
    if ($cleared) {
        foreach ($e in $cleared) {
            Add-F High 'EventLog:cleared-event' `
                "Event $($e.Id) found: a log was cleared." `
                "$($e.TimeCreated) on channel $($e.LogName) by $($e.UserId)"
        }
    }
} catch {}

# --- 5. VSS ------------------------------------------------------------

$vss = & vssadmin.exe list shadows 2>&1
$vssCount = ($vss | Select-String 'Contained').Count
if ($vssCount -eq 0 -and $osAgeDays -gt 30) {
    Add-F Medium 'VSS:none' `
        'Zero Volume Shadow Copies on a Windows install >30 days old.' `
        "Normal: System Restore keeps some snapshots. vssadmin delete shadows was run."
}

# --- 6. USN journal ----------------------------------------------------

try {
    $usn = & fsutil.exe usn queryjournal C: 2>&1
    if ($LASTEXITCODE -eq 0) {
        $firstUsnLine = $usn | Select-String 'First USN'
        $nextUsnLine  = $usn | Select-String 'Next USN'
        if ($firstUsnLine -and $nextUsnLine) {
            $first = [int64](($firstUsnLine -split ':')[-1].Trim() -replace '0x','')
            if ($first -eq 0 -and $osAgeDays -gt 7) {
                Add-F Medium 'USN:first-zero' `
                    'USN journal First USN is 0 on an established install.' `
                    "Journal was just created. Prior journal was deleted."
            }
        }
    }
} catch {}

# --- 7. Pagefile -------------------------------------------------------

try {
    $cps = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -EA Stop).ClearPageFileAtShutdown
    if ($cps -eq 1) {
        Add-F Medium 'Pagefile:ClearAtShutdown=1' `
            'ClearPageFileAtShutdown is set to 1. Defaults to 0; this is an explicit cleaner tell.' `
            ""
    }
} catch {}

if (Test-Path 'C:\pagefile.sys') {
    $pf = Get-Item -Force 'C:\pagefile.sys'
    $pfAgeHours = (New-TimeSpan $pf.LastWriteTime (Get-Date)).TotalHours
    # If pagefile was written recently but there's been very little uptime, it was just regen'd
    if ($pfAgeHours -lt 1 -and $osUptimeDays -gt 1) {
        Add-F Low 'Pagefile:fresh-write' `
            'pagefile.sys was written in the last hour on a system with >1 day uptime.' `
            "Mod=$($pf.LastWriteTime), uptime=$([math]::Round($osUptimeDays,1))d."
    }
}

if (-not (Test-Path 'C:\hiberfil.sys')) {
    try {
        $hp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -EA SilentlyContinue).HibernateEnabled
        if ($hp -eq 0) {
            Add-F Low 'Hibernation:disabled' `
                'Hibernation is disabled (HibernateEnabled=0, hiberfil.sys absent).' `
                "Default: on. powercfg -h off was run -- common cleaner step."
        }
    } catch {}
}

# --- 8. BAM / SRUM presence -------------------------------------------

$bamBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
if (Test-Path $bamBase) {
    $bamEntries = 0
    Get-ChildItem $bamBase -EA SilentlyContinue | ForEach-Object {
        try {
            $i = Get-Item -LiteralPath $_.PSPath -EA Stop
            $bamEntries += ($i.GetValueNames() | Where-Object { $_ -notin 'SequenceNumber','Version' }).Count
        } catch {}
    }
    if ($bamEntries -lt 5 -and $osAgeDays -gt 7) {
        Add-F Medium 'BAM:sparse' `
            'Background Activity Moderator has almost no per-SID entries.' `
            "Entries=$bamEntries, OS age=$([math]::Round($osAgeDays,1))d. Normal is dozens."
    }
}

if (-not (Test-Path 'C:\Windows\System32\sru\SRUDB.dat')) {
    Add-F Medium 'SRUM:missing' 'SRUDB.dat (SRUM database) is missing.' 'Normal installs always have this. Cleaner footprint.'
}

# --- 9. Setup logs -----------------------------------------------------

foreach ($sl in 'C:\Windows\inf\setupapi.dev.log','C:\Windows\inf\setupapi.app.log') {
    if (-not (Test-Path $sl)) {
        Add-F Medium 'SetupLog:missing' "$sl is missing." 'This log is present on every normal install.'
    }
}

# --- 10. UserAssist entries -------------------------------------------

$ua = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
if (Test-Path $ua) {
    $uaCount = 0
    Get-ChildItem $ua -EA SilentlyContinue | ForEach-Object {
        $cnt = Join-Path $_.PSPath 'Count'
        if (Test-Path $cnt) {
            try { $uaCount += (Get-Item $cnt).GetValueNames().Count } catch {}
        }
    }
    if ($uaCount -lt 5 -and $osAgeDays -gt 7) {
        Add-F Medium 'UserAssist:sparse' `
            'UserAssist Count keys are near-empty on an established install.' `
            "Values=$uaCount. Normal: dozens of ROT13-encoded launch records."
    }
}

# --- 11. Service key last-write-time correlation ----------------------
# If EAC service keys are gone but Fortnite is installed, that's a tell.
$fortniteInstalled = Test-Path 'C:\Program Files\Epic Games\Fortnite\FortniteGame'
$eacPresent = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat') -or `
              (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS')
if ($fortniteInstalled -and -not $eacPresent) {
    Add-F High 'Service:stripped' `
        'Fortnite install present but EAC service keys are absent.' `
        'Fortnite ships with EAC. Missing service keys = targeted registry wipe.'
}

# --- 12. Recent reboot right after broad registry writes --------------

try {
    $recent = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6005,6006,1074,41,12,13} -MaxEvents 20 -EA SilentlyContinue
    $boots = $recent | Where-Object { $_.Id -in 6005,6009,12 }
    if ($boots.Count -gt 0) {
        $lastBoot = ($boots | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        # Was there a shutdown.exe /r /t 0 (event 1074 with "shutdown /r") recently?
        $forceReboot = $recent | Where-Object { $_.Id -eq 1074 -and $_.Message -match 'shutdown.exe' }
        if ($forceReboot) {
            Add-F Low 'Reboot:forced-recent' `
                'Recent shutdown.exe-initiated reboot.' `
                ("Last: " + ($forceReboot | Select-Object -First 1).TimeCreated)
        }
    }
} catch {}

# --- 13. Credential Manager + DPAPI ------------------------------------

$cmPaths = @(
    (Join-Path $env:APPDATA 'Microsoft\Credentials'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Credentials'),
    (Join-Path $env:APPDATA 'Microsoft\Protect')
)
$cmPresent = $cmPaths | Where-Object { Test-Path $_ -EA SilentlyContinue } |
    ForEach-Object { (Get-ChildItem $_ -Recurse -Force -EA SilentlyContinue).Count } | Measure-Object -Sum
if ($cmPresent.Sum -eq 0 -and $osAgeDays -gt 30) {
    Add-F High 'CredMgr:empty' `
        'Credential Manager + DPAPI master-key directories contain zero files.' `
        "Every normal profile has saved Wi-Fi + credentials. Classic Credential Manager wipe."
}

# --- Render ------------------------------------------------------------

$sevRank = @{ High = 3; Medium = 2; Low = 1 }
$min = $sevRank[$MinSeverity]
$filtered = $findings | Where-Object { $sevRank[$_.Severity] -ge $min } | Sort-Object { -$sevRank[$_.Severity] }, Check

Write-Host "=== Skew findings (min severity: $MinSeverity) ===" -ForegroundColor Cyan
if (-not $filtered) {
    Write-Host "  no findings at or above $MinSeverity -- system looks consistent." -ForegroundColor Green
} else {
    foreach ($f in $filtered) {
        $c = switch ($f.Severity) { 'High' { 'Red' }; 'Medium' { 'Yellow' }; default { 'Gray' } }
        Write-Host ("  [{0,-6}] {1}" -f $f.Severity, $f.Check) -ForegroundColor $c
        Write-Host ("            {0}" -f $f.Finding) -ForegroundColor DarkGray
        if ($f.Evidence) { Write-Host ("            {0}" -f $f.Evidence) -ForegroundColor DarkGray }
    }
}

$md = @()
$md += "# Cleaner skew detector report"
$md += ""
$md += ("- Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$md += ("- Host: {0}" -f $env:COMPUTERNAME)
$md += ("- OS installed: {0} ({1} days ago)" -f $osInstall, [math]::Round($osAgeDays,1))
$md += ("- Last boot: {0} ({1} days uptime)" -f $osLastBoot, [math]::Round($osUptimeDays,1))
$md += ("- Findings: {0} (min severity {1})" -f $filtered.Count, $MinSeverity)
$md += ""
$md += "## Findings"
$md += ""
$md += "| Severity | Check | Finding | Evidence |"
$md += "|-|-|-|-|"
foreach ($f in $filtered) {
    $md += "| $($f.Severity) | $($f.Check) | $($f.Finding) | $($f.Evidence) |"
}

Set-Content -LiteralPath $mdPath -Value $md -Encoding UTF8
Write-Host ""
Write-Host "Markdown report: $mdPath" -ForegroundColor Green

exit $filtered.Count
