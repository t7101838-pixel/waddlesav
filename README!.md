# Ultimate AV

A local PowerShell scanning toolkit — hash-based detection, heuristics, process/registry/network
monitoring, and quarantine — run from a console menu, with no installer and no background service.

This is an independent, personal project. It is **not** affiliated with any commercial antivirus
vendor, and it is not a replacement for a maintained, professionally-supported antivirus product.
Treat it as an extra layer of visibility, not your only line of defense.

## Files

| File | Purpose |
|---|---|
| `Launch_UltimateAV.bat` | Double-click entry point. Requests admin rights, then runs the engine. |
| `AVMenu_Ultimate.ps1` | The scanning engine and interactive menu. |

Keep both files in the same folder — the launcher looks for the script next to itself.

## Verify what you downloaded

SHA-256 hashes of the current release (v4.0):

```
259c8720c4b800bcb50c13df08e3957ac5fde63a254c2c6e3054c124e32e87ca  AVMenu_Ultimate.ps1
a14e7b4698b1c1ebd279188b946bcdc7561d69e7ef1b756fbd29ce46cc817a39  Launch_UltimateAV.bat
```

On Windows (PowerShell):
```powershell
Get-FileHash .\AVMenu_Ultimate.ps1 -Algorithm SHA256
Get-FileHash .\Launch_UltimateAV.bat -Algorithm SHA256
```

## How it works

1. **Hash matching** — every scanned file's SHA-256 is checked against a local database of
   known-malicious hashes, refreshed from public threat feeds.
2. **Static heuristics** — files are inspected for traits associated with malware (entropy, PE
   header anomalies, suspicious string/API patterns) without executing them.
3. **Optional cloud lookup** — if you supply your own VirusTotal API key, unrecognized files can
   be checked against VirusTotal. Off by default; this is the only call that sends file data
   anywhere.
4. **Live monitoring** — optional modules watch running processes, memory, registry run-keys,
   DNS requests, and network connections.
5. **Quarantine, not delete** — anything flagged moves to a local quarantine folder. Nothing is
   deleted automatically; review and restore from the Quarantine Manager.

What this is *not*: no kernel driver, no always-on background service, no cloud sandbox
infrastructure.

## Features

- Hash-based scanning (local SHA-256 database)
- Heuristic analysis (entropy, PE structure)
- Optional VirusTotal lookup (key-gated, opt-in)
- Process scanner
- Memory scanner
- Registry persistence scanner
- Network connection monitor
- DNS monitor
- Real-time folder watcher
- Sandbox detonation
- Quarantine manager (review/restore/delete)
- Scheduled, unattended scans via Windows Task Scheduler

## Setup

1. Put `Launch_UltimateAV.bat` and `AVMenu_Ultimate.ps1` in the same folder.
2. Double-click `Launch_UltimateAV.bat`. Accept the administrator prompt — memory and registry
   scanning need elevated rights.
3. From the menu, run **Update Threat Intelligence DB** first, then a **Quick Scan**.

Windows may flag the script with SmartScreen since it isn't code-signed. That's expected for an
unsigned standalone script, not a sign of tampering.

## Privacy & safety

- No telemetry. Nothing about your machine, files, or scan results is sent anywhere by the
  developer.
- The only outbound network calls are to the threat-feed update source and, if configured,
  VirusTotal's API — nothing undisclosed.
- File data only leaves your machine if you've added a VirusTotal API key and a file is
  unrecognized.
- Destructive actions (killing a process, removing a registry key) prompt for confirmation in
  interactive mode, and are off by default in unattended/scheduled mode.

## Changelog

### v4.0 — 2026-06-27
- Added quarantine manager and whitelist manager menus
- Added unattended mode for scheduled/background scans
- Fixed scheduled task registration so background scans no longer hang waiting on input
- Added hosts-file integrity check

### v3.0 — 2026-06-20
- Added process memory scanning and behavior monitor
- Added DNS and network connection monitors
- Added HTML scan report export

### v1.0 — 2026-06-10
- Initial release: hash-based scanning, heuristics, quarantine, threat-DB updates

## License

MIT — see [LICENSE](LICENSE).

## Issues / contact

Open an issue on this repo, or reach out via the contact link on the project page.
