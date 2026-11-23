# EAC / Fortnite / Epic trace cleaner

User-mode Windows cleaner that removes the on-disk, in-registry, and
telemetry residues left behind by EasyAntiCheat, Fortnite, and Epic
Games Launcher. 17 phases, ordered around a single reboot gate so
locked artifacts (`Amcache.hve`, Shimcache, pagefile, hibernation
file) are handled correctly.

## Files

| File | Role |
|---|---|
| `Run-EacCleaner.bat` | UAC-elevating launcher. Double-click this. |
| `EacCleaner.ps1`     | The cleaner. 17 phases, destructive, reboots at the end. |

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

### Network stack

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

Phase 17 reboots automatically at the end. If you skip the reboot,
Shimcache, `Amcache.hve`, the pagefile, and the hibernation file all
stay in their pre-run state.

### UAC flow

`Run-EacCleaner.bat` tests for administrator via `NET SESSION`. If not
elevated, it `Start-Process -Verb RunAs` to UAC-prompt and re-enters
itself. The elevated instance `pushd`s the script directory and runs
`EacCleaner.ps1` with `-NoProfile -ExecutionPolicy Bypass`.

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (ships with Windows)
- Administrator privileges (the launcher UAC-prompts)

## Running

Double-click `Run-EacCleaner.bat`, accept UAC, type `CLEAN` when
prompted. Reboot is automatic after the last phase.

## Notice

Destructive. Deletes install data, credentials, browser state, event
logs, Volume Shadow Copies, and resets the network stack. Run only
on machines you own.
