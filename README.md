# EAC / Fortnite / Epic trace cleaner

User-mode Windows cleaner that removes the on-disk, in-registry, and
telemetry residues left behind by EasyAntiCheat, Fortnite, and Epic
Games Launcher. 17 phases, ordered around a single reboot gate so
locked artifacts (`Amcache.hve`, Shimcache, pagefile, hibernation
file) are handled correctly.

Three read-only companion scripts let you inventory before cleaning,
re-inventory after, and detect leftover cleaner footprints.

## Files

| File | Role |
|---|---|
| `Run-EacCleaner.bat`      | UAC-elevating launcher → `EacCleaner.ps1`           |
| `Run-Enumerate.bat`       | UAC-elevating launcher → `Enumerate-EacTraces.ps1` |
| `Run-Diagnose.bat`        | UAC-elevating launcher → `Diagnose-Cleaner.ps1`     |
| `Run-SkewCheck.bat`       | UAC-elevating launcher → `Detect-CleanerSkew.ps1`   |
| `Finish-Residues.bat`     | UAC-elevating launcher → `Finish-Residues.ps1`      |
| `EacCleaner.ps1`          | **The cleaner.** 17 phases, destructive, reboots.   |
| `Enumerate-EacTraces.ps1` | Read-only inventory. What's present right now.      |
| `Diagnose-Cleaner.ps1`    | Read-only post-run health check.                    |
| `Detect-CleanerSkew.ps1`  | Read-only validator — spots cleaner footprints.     |
| `Finish-Residues.ps1`     | Surgical mop-up for empty-shell leftovers.          |

## Recommended workflow

```
1. Run-Enumerate.bat                     → before.md    (inventory)
2. Run-EacCleaner.bat  (type CLEAN)      → cleans + reboots
3. (reboot completes)
4. Run-Enumerate.bat                     → after.md     (should be mostly empty)
5. Run-Diagnose.bat                      → health check (0 issues = good)
6. Run-SkewCheck.bat   -MinSeverity Low  → skew.md      (what's still obvious)
```

Diff `before.md` against `after.md` for an audit trail of exactly what left.

## What it erases

### Install + saved data

- `C:\ProgramData\EasyAntiCheat`, `_EOS`, `\Epic\EasyAntiCheat`, LocalAppData variants
- `C:\Program Files (x86)\EasyAntiCheat` + Common Files variant
- `%LOCALAPPDATA%\FortniteGame` (the Saved tree)
- `C:\Program Files\Epic Games\Fortnite` + non-C: drive installs, discovered via EGS manifests and drive-root scans
- Epic Games Launcher install + all data under `ProgramData\Epic\*`
- Leftover `pbrules.bin`, `rules.bin`, `game.bin` wherever they survive

### Registry

- Service keys: `EasyAntiCheat`, `EasyAntiCheat_EOS`, `EasyAntiCheat_EOSSys`
- Software hives: `HKLM\SOFTWARE\EasyAntiCheat`, `HKLM\SOFTWARE\Epic Games`, WOW6432Node mirrors, HKCU equivalents
- `ErrRpt_*` telemetry values on surviving service keys (pattern-matched, catches all ~23 variants)
- `LastUserShellFolders` entries matching EAC / Epic / Fortnite
- Uninstall entries whose `DisplayName` matches EAC / Epic / Fortnite / EOS

### Windows execution-history caches

| Surface | What it is |
|---|---|
| **Prefetch** | Targeted `.pf` removal for EAC/Fortnite/Epic binaries; `-WholesalePrefetch` wipes the whole folder |
| **Amcache.hve** | Program-execution history. Direct delete, falls back to `MoveFileEx(DELAY_UNTIL_REBOOT)` when locked |
| **Shimcache (`AppCompatCache`)** | Registry value wiped; the reboot forces an empty rebuild |
| **BAM / DAM** | `UserSettings` and `State\UserSettings` per SID |
| **MUICache** | Full key removal |
| **UserAssist** | All `Count` subkeys per CLSID |
| **RecentApps** | Cortana / Search's recent-app list |
| **FeatureUsage** | Explorer per-app launch counters |
| **CompatibilityAssistant Store** | Previously-seen executables list |
| **ActivityHistory / Timeline** | Per-user `ActivitiesCache.db` |

### Windows Explorer + user-shell MRUs

Shellbags (six locations), TypedPaths, OpenSaveMRU, LastVisitedPidlMRU,
RecentDocs, ComDlg32 MRUs, RunMRU, Map Network Drive MRU, WordWheelQuery,
Office TrustRecords, taskbar StartPage2, RDP connection history
(`Default` + `Servers`).

### Event logs + crash reporting

- `wevtutil cl` across every channel + WMI fallback for stubborn ones
- WER queued + archived dumps, per-user WER folders
- `LiveKernelReports`, `Minidump`, `Memory.dmp`
- `RtBackup` (ETW circular buffer)
- Panther, CBS, DISM, MoSetup, SetupCl, Measured Boot logs, `setupapi.*.log`, `.regtrans-ms` + `.blf`

### Credentials + browser state

- Credential Manager (disk store + each entry via `cmdkey /delete`)
- DPAPI master keys + Protect folder, Vault (local + roaming)
- LSA Secrets attempt (needs SYSTEM, logs the limitation)
- Chrome, Edge, Brave, Opera, Firefox: cache, cookies, history, Login Data
- Opt-out switches: `-SkipCredentials`, `-SkipBrowsers`

### NTFS + volume state

- USN journal — every drive, `fsutil usn deletejournal /D`
- TxF `$RmMetadata` — `fsutil resource setautoreset`
- Every Volume Shadow Copy — `vssadmin delete shadows /all /quiet`
- Pagefile — `ClearPageFileAtShutdown=1` set (wipes at next shutdown)
- Hibernation — `powercfg -h off` (deletes `hiberfil.sys`)
- Swapfile — `SwapfileControl=0`, scheduled pending-delete if still present

### Scheduled tasks + services

- Any scheduled task whose name or action matches `EasyAntiCheat | Fortnite | Epic`
- EAC service entries unregistered + their driver INFs removed from DriverStore via `pnputil`
- `-NukeBYOVD` extends driver scrub to known vulnerable drivers:
  `rage_drv, kdmapper, iqvw64e, gdrv, RTCore64, AsrDrv, AsUpIO, MsIo64,
  WinRing0, capcom, PhyMem, gmer, HpPortIox64, Dbutil_2_3, WinFlash64,
  RzCommon`

### Thumbnails + jump lists + misc

Thumbcache + iconcache per user, `AutomaticDestinations` + `CustomDestinations` + `Recent` per user, WPN notification db, Windows.old, Windows Search index (`Windows.edb`), Recycle Bin (all drives), NVIDIA Shadowplay + AMD ReLive capture folders (`~\Videos\Fortnite`, `~\Videos\Captures`), Discord / DiscordCanary / DiscordPTB caches + logs, ReadyBoot traces + `PfSvPerfStats.bin`.

### Network stack (optional, on by default)

- Winsock reset, TCP/IP reset
- Wi-Fi profile wipe (`netsh wlan delete profile name=*`)
- ARP cache flush, NetBIOS reload, DHCP release+renew
- DNS resolver cache flush

## How it works

### Phase order

The 17 phases are ordered around what Windows locks at runtime:

1. **Process termination** — kill FortniteClient, Launcher, EAC processes, UE5 crash handler
2. **Service shutdown** — stop EAC services, disable startup, clear ErrRpt values
3. **EAC install + log dirs** — direct `Remove-Item -Recurse -Force` + leftover-blob scrub
4. **Fortnite game data** — LocalAppData, Program Files, non-C: drives, EGS-manifest discovery
5. **Epic Games Launcher** — ProgramData\Epic\* + LOCALAPPDATA\EpicGamesLauncher
6. **Registry** — service keys, software hives, uninstall, shell MRUs, ErrRpt pattern-match
7. **Prefetch + ReadyBoot** — targeted .pf delete + PfSvPerfStats.bin
8. **Execution-history caches** — Shimcache, BAM, MUICache, UserAssist, Shellbags, etc.
9. **Logs + crash dumps + driver store** — WER, Panther, CBS, DISM, RtBackup, driver INFs
10. **Credential stores** — Credential Manager, DPAPI, Vault, LSA attempt
11. **Browsers** — Chrome/Edge/Brave/Opera/Firefox cache + cookies + history + logins
12. **Recycle Bin** — all drives
13. **VSS** — every shadow copy
14. **NTFS journals** — USN + TxF per drive
15. **Event logs** — every channel; done last because `wevtutil cl` itself logs event 104
16. **Pagefile / hibernation / swapfile** — set at-shutdown wipe + disable hibernation + pending-delete
17. **Reboot** — `shutdown /r /t 0 /f`

Logs come last because clearing a log writes its own event, so clearing
earlier would leave fresh entries behind. Pagefile/hibernation/swapfile
wiping is set before reboot so the reboot itself processes them.

### Reboot gate

Two Windows mechanisms need a reboot to actually act:

- **`PendingFileRenameOperations`** — files locked at runtime (`Amcache.hve`, `swapfile.sys`) are scheduled for `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)`. `smss.exe` processes the list before any service starts.
- **`ClearPageFileAtShutdown`** — wiping the pagefile happens at the *next shutdown*, not when the registry value is set.

Phase 17 reboots automatically unless `-SkipReboot` or `-DryRun`. If
you skip it, you **must** reboot manually — otherwise Shimcache,
`Amcache.hve`, the pagefile, and the hibernation file all stay in
their pre-run state.

### UAC flow

The `.bat` launchers test for administrator via `NET SESSION`. If not
elevated, they `Start-Process -Verb RunAs` to UAC-prompt and re-enter
themselves. The elevated instance `pushd`s the script directory and
runs the PowerShell file with `-NoProfile -ExecutionPolicy Bypass`.

### Dry-run

`-DryRun` logs every operation to `%TEMP%\EacCleaner_<timestamp>.log`
without modifying anything. Run this first.

## Switches (`EacCleaner.ps1`)

| Switch | Effect |
|---|---|
| `-SkipConfirm`       | Skip the "type CLEAN" prompt. |
| `-SkipReboot`        | Do not auto-reboot. You **must** reboot manually afterward. |
| `-ClearTpm`          | Delete `EacQuoteKey` + `AttestationKey` from TPM registry. **Wipes BitLocker recovery sealed to this TPM.** Does not reprovision the hardware TPM — use `tpm.msc` → Clear TPM for that. |
| `-SkipCredentials`   | Leave Credential Manager + DPAPI + LSA alone. Keeps saved Wi-Fi, VPN, browser creds. |
| `-SkipBrowsers`      | Leave Chrome/Edge/Brave/Opera/Firefox alone. |
| `-WholesalePrefetch` | Wipe every `.pf` in `C:\Windows\Prefetch`. |
| `-NukeBYOVD`         | Also purge known vulnerable-driver remnants from DriverStore + Services + system32\drivers. Use only if you ran a driver mapper on this box. |
| `-DryRun`            | Log what would happen, change nothing. **Run this first.** |

## What this cleaner cannot do

User-mode only. Three things are out of scope by design:

- **Kernel in-memory state.** `nt!PiDDBCacheTable`, `nt!MmUnloadedDrivers`, `ci!g_KernelHashBucketList`, ETW ring buffers. These live in kernel memory and cannot be touched from user mode. The reboot in Phase 17 clears most of this volatile state naturally.
- **Object Manager state.** Service pipe handles, named events (`\BaseNamedObjects\...`). Kernel objects; they die when the service stops (Phase 2) and the system reboots (Phase 17).
- **NTFS low-level artifacts.** `$MFT` slack, `$LogFile`, `$INDX` records. A forensic analyst with raw volume access can recover deleted-file metadata from these. **Reformat is the only clean here.** USN (`$UsnJrnl`) and TxF (`$RmMetadata`) *are* cleared in Phase 14.

## Companion scripts

### `Enumerate-EacTraces.ps1` (read-only)

Walks the same artifact list the cleaner targets and reports
presence, size, and mtime. Markdown output to `%TEMP%\EacTraces_<stamp>.md`.
Exit code = number of artifacts still present.

| Switch | Effect |
|---|---|
| `-QuickScan` | Skip per-user iteration + directory-size totals. Faster. |
| `-JsonOut`   | Emit JSON alongside the markdown. Good for diffing. |
| `-PathOnly`  | Print the path of every present artifact, one per line. Pipe-friendly. |

### `Diagnose-Cleaner.ps1` (read-only)

Three parts: trace-surface coverage (what's present after the clean),
damage assessment (Device Manager error codes — the signs of a bad
driver purge), network health (WLAN + ethernet adapters + core
services). Output `%TEMP%\EacDiagnose_<stamp>.md`. Exit code =
health issues.

### `Detect-CleanerSkew.ps1` (read-only)

Compares current system state against what an un-cleaned install
looks like and flags obvious cleaner footprints — empty Prefetch on
an established install, freshly-created Amcache.hve, pending-rename
entries targeting Amcache/hiberfil/swapfile, event ID 104/1102
recently logged, zero VSS snapshots, USN First USN == 0,
`ClearPageFileAtShutdown=1`, and a dozen more. Use after cleaning to
see what a careful observer could still spot.

| Switch | Effect |
|---|---|
| `-MinSeverity Low|Medium|High` | Only report findings at or above this. |

### `Finish-Residues.ps1`

Surgical mop-up for empty-shell directories that can survive the
pending-rename list — specifically, cases where child files were
deleted but the parent-dir entry failed because the children were
deleted first. Takeown + icacls + `Remove-Item -Recurse`. Default
targets: `C:\ProgramData\EasyAntiCheat`, `%LOCALAPPDATA%\FortniteGame`.
Pass extra paths as arguments.

## Troubleshooting

**"The script must run as Administrator."**
Use the `.bat` launchers — they UAC-prompt. If you want to run a
`.ps1` directly, elevate your shell first.

**`Amcache.hve` stayed on disk after the script.**
It's locked at runtime. Check
`HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` —
the script scheduled it. Reboot and it will delete.

**`Clear-RecycleBin` failed.**
Expected on some SKUs. The script falls back to deleting
`$Recycle.Bin` on each drive directly.

**Event log channels I don't care about keep failing to clear.**
Normal — some channels are `-Enabled $false` or owned by sessions
the script doesn't have rights to. `wevtutil cl` tries them all and
skips the ones that refuse. The ones that matter (System,
Application, Security, PnP, TaskScheduler, CodeIntegrity) clear.

**BitLocker recovery screen on reboot.**
You passed `-ClearTpm`. Enter your recovery key.

**I want to run only one phase.**
There's no single-phase flag — the phases have cross-dependencies
(service stops in Phase 2 unlock files in Phase 9). Use `-DryRun` to
see what *would* happen without doing anything.

**Empty folders survive after the reboot.**
The pending-rename sequence can leave empty parent directories when
children delete before their parents. Run `Finish-Residues.bat` to
clean them up without another full run + reboot.

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (ships with Windows)
- Administrator privileges (the `.bat` launchers UAC-prompt)

## Running

Double-click `Run-EacCleaner.bat`, accept UAC, type `CLEAN` when
prompted. Reboot is automatic after the last phase unless you pass
`-SkipReboot`.

Run `Run-EacCleaner.bat -DryRun` first to see the plan.

## Notice

Destructive. Deletes install data, credentials, browser state, event
logs, Volume Shadow Copies, and resets the network stack. Run only
on machines you own.
