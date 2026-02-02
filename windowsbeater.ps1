# =========================================================
# windowsbeater
# Privacy & Performance Toolkit for Windows
# Author : barella8
# Version: 1.0
# =========================================================

if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit
}

$ToolName = "windowsbeater"
$Version  = "1.0"
$Author   = "barella8"

$BaseDir  = "C:\windowsbeater"
$LogDir   = "$BaseDir\logs"
$StateDir = "$BaseDir\state"

New-Item -ItemType Directory -Force -Path $BaseDir,$LogDir,$StateDir | Out-Null
$LogFile = "$LogDir\run.log"

function Log {
    param($msg)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time | $msg" | Tee-Object -Append $LogFile
}

function Show-Banner {
$Banner = @"
                                888 
 e88'888 888,8,  ,"Y88b  ,e e,  888 
d888  '8 888 "  "8" 888 d88 88b 888 
Y888   , 888    ,ee 888 888   , 888 
 "88,e8' 888    "88 888  "YeeP" 888 
                                    
                                    
"@
    Clear-Host
    Write-Host $Banner -ForegroundColor Cyan
    Write-Host "$ToolName v$Version  |  Privacy & Performance Toolkit" -ForegroundColor DarkGray
    Write-Host "Author: $Author" -ForegroundColor DarkGray
    Write-Host ""
}

function Create-RestorePoint {
    Log "Creating restore point"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "windowsbeater Restore" -RestorePointType MODIFY_SETTINGS
}

function Debloat-Appx {
    Log "Debloating Appx packages"

    $Whitelist = @(
        "Microsoft.WindowsStore",
        "Microsoft.DesktopAppInstaller",
        "Microsoft.VCLibs",
        "Microsoft.NET.Native",
        "Microsoft.WindowsTerminal",
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsNotepad",
        "Microsoft.Windows.Photos"
    )

    Get-AppxPackage -AllUsers | ForEach-Object {
        $keep = $false
        foreach ($w in $Whitelist) {
            if ($_.Name -like "*$w*") { $keep = $true }
        }
        if (-not $keep) {
            Log "Removing Appx (user): $($_.Name)"
            Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
        }
    }

    Get-AppxProvisionedPackage -Online | ForEach-Object {
        $keep = $false
        foreach ($w in $Whitelist) {
            if ($_.DisplayName -like "*$w*") { $keep = $true }
        }
        if (-not $keep) {
            Log "Removing Appx (provisioned): $($_.DisplayName)"
            Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
        }
    }
}

function Disable-Telemetry {
    Log "Disabling telemetry"

    $reg = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            "AllowTelemetry" = 0
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" = @{
            "Enabled" = 0
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" = @{
            "TailoredExperiencesWithDiagnosticDataEnabled" = 0
        }
    }

    foreach ($path in $reg.Keys) {
        New-Item -Path $path -Force | Out-Null
        foreach ($k in $reg[$path].Keys) {
            Set-ItemProperty -Path $path -Name $k -Value $reg[$path][$k]
        }
    }

    $services = @("DiagTrack","dmwappushservice")
    foreach ($s in $services) {
        Get-Service $s -ErrorAction SilentlyContinue | ForEach-Object {
            Log "Disabling service: $s"
            Set-Service $s -StartupType Disabled
            Stop-Service $s -Force
        }
    }

    Get-ScheduledTask | Where-Object {
        $_.TaskPath -like "\Microsoft\Windows\Application Experience*" -or
        $_.TaskPath -like "\Microsoft\Windows\Customer Experience Improvement Program*"
    } | ForEach-Object {
        Log "Disabling task: $($_.TaskName)"
        Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
    }
}

function Optimize-Services {
    Log "Optimizing services"

    $ManualServices = @(
        "SysMain",
        "Fax",
        "RetailDemo",
        "MapsBroker",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )

    foreach ($s in $ManualServices) {
        Get-Service $s -ErrorAction SilentlyContinue | ForEach-Object {
            Log "Setting $s to Manual"
            Set-Service $s -StartupType Manual
        }
    }
}

function Cleanup-Startup {
    Log "Cleaning startup entries"

    $SafeList = @(
        "SecurityHealth",
        "OneDrive",
        "Windows Defender",
        "Intel",
        "Realtek",
        "NVIDIA",
        "AMD"
    )

    $keys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($key in $keys) {
        if (Test-Path $key) {
            Get-ItemProperty $key | Get-Member -MemberType NoteProperty |
            ForEach-Object {
                $name = $_.Name
                $keep = $false
                foreach ($s in $SafeList) {
                    if ($name -like "*$s*") { $keep = $true }
                }
                if (-not $keep) {
                    Log "Removing startup: $name"
                    Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Performance-Tweaks {
    Log "Applying performance tweaks"

    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61

    powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
    powercfg -setactive scheme_current

    New-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" `
        -Name "OverlayTestMode" `
        -PropertyType DWORD `
        -Value 5 `
        -Force | Out-Null
}

function Show-Menu {
    Write-Host "1. Create Restore Point"
    Write-Host "2. Debloat Windows Apps"
    Write-Host "3. Disable Telemetry"
    Write-Host "4. Optimize Services"
    Write-Host "5. Startup Cleanup"
    Write-Host "6. Performance Tweaks"
    Write-Host "7. RUN ALL"
    Write-Host "0. Exit"
}

Show-Banner
Log "=== windowsbeater v$Version started by $Author ==="

do {
    Show-Menu
    $c = Read-Host "Select"
    switch ($c) {
        "1" { Create-RestorePoint }
        "2" { Debloat-Appx }
        "3" { Disable-Telemetry }
        "4" { Optimize-Services }
        "5" { Cleanup-Startup }
        "6" { Performance-Tweaks }
        "7" {
            Create-RestorePoint
            Debloat-Appx
            Disable-Telemetry
            Optimize-Services
            Cleanup-Startup
            Performance-Tweaks
        }
        "0" { break }
    }
    Pause
    Show-Banner
} while ($true)
