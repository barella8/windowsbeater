# WindowsBeater

WindowsBeater is a minimal, no-BS debloat and privacy hardening script for Windows 10 and 11.

It focuses on:
Removing obvious bloat
Killing telemetry and data collection
Keeping Windows usable for gaming and daily work
Providing rollback support in case you change your mind


Microsoft Store, gaming features, and normal desktop usage stay intact.

## Features

Menu-based PowerShell interface
Built-in logging
Registry rollback support
Telemetry disabled at policy + service level
Startup cleanup
Optional service optimization (Search still works)

---

## Usage
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; `
iex (irm https://raw.githubusercontent.com/barella8/windowsbeater/main/windowsbeater.ps1)

