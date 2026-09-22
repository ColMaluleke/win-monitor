<#
.SYNOPSIS
    Windows System Monitor - PowerShell port of sys-monitor.sh

.DESCRIPTION
    A modular PowerShell monitoring solution for Windows.
    Mirrors the functionality of the original Bash sys-monitor project:
      - System drive usage monitoring
      - RAM utilization monitoring
      - Failed logon attempt analysis (Security event log)
      - Recent error event parsing (System event log)
      - Structured JSON reports
      - Structured JSON run logs

.NOTES
    Reading the Security event log (failed logon attempts) generally
    requires an elevated (Administrator) PowerShell session. If not
    elevated, that section will report 0 and a warning will be logged.

    To automate this the way the Bash version uses cron, register it
    with Windows Task Scheduler, e.g. every 15 minutes:

        $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                     -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\win-monitor.ps1`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                     -RepetitionInterval (New-TimeSpan -Minutes 15) `
                     -RepetitionDuration ([TimeSpan]::MaxValue)
        Register-ScheduledTask -TaskName "WinMonitor" -Action $action -Trigger $trigger -RunLevel Highest
#>

#Requires -Version 5.1

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "output"
$LogDir    = Join-Path $ScriptDir "logs"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$LogFile = Join-Path $LogDir ("win-monitor-{0}.jsonl" -f (Get-Date -Format "yyyyMMdd"))

# --- JSON Log Writer -------------------------------------------------------
# Appends one JSON object per line (JSONL) to logs\win-monitor-<date>.jsonl.
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $entry = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
        level     = $Level
        message   = $Message
    }
    if ($Data) {
        $entry["data"] = $Data
    }

    ($entry | ConvertTo-Json -Depth 4 -Compress) | Add-Content -Path $LogFile -Encoding UTF8
}

# --- Disk Usage ---------------------------------------------------------
function Get-DiskUsage {
    $sysDrive = $env:SystemDrive.TrimEnd(':')
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($sysDrive):'"

    if (-not $drive -or -not $drive.Size) {
        Write-Warning "Could not read disk usage for drive ${sysDrive}:"
        Write-Log -Level ERROR -Message "Could not read disk usage" -Data @{ drive = "${sysDrive}:" }
        return 0
    }

    $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100)

    if ($usedPercent -gt 70) {
        Write-Warning "Disk usage is above 70%!"
        Write-Log -Level WARNING -Message "Disk usage is above 70%" -Data @{ disk_usage_percent = $usedPercent }
    }

    return $usedPercent
}

# --- RAM Usage -----------------------------------------------------------
function Get-RamUsage {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalKB = $os.TotalVisibleMemorySize
    $freeKB  = $os.FreePhysicalMemory

    if (-not $totalKB) {
        Write-Warning "Could not read RAM usage"
        Write-Log -Level ERROR -Message "Could not read RAM usage"
        return 0
    }

    $usedPercent = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100)

    if ($usedPercent -gt 70) {
        Write-Warning "RAM usage is above 70%!"
        Write-Log -Level WARNING -Message "RAM usage is above 70%" -Data @{ memory_usage_percent = $usedPercent }
    }

    return $usedPercent
}

# --- Failed Logon Attempts (equivalent to failed SSH attempts) ----------
function Get-FailedLogonAttempts {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = (Get-Date).AddDays(-1)
        } -ErrorAction Stop
        return ($events | Measure-Object).Count
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        return 0
    }
    catch {
        Write-Warning "Could not read Security log (run as Administrator for failed logon data): $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Could not read Security log" -Data @{ exception = $_.Exception.Message }
        return 0
    }
}

# --- Error Events in the Last Hour ---------------------------------------
function Get-ErrorEvents {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Level     = 2   # 2 = Error
            StartTime = (Get-Date).AddHours(-1)
        } -ErrorAction Stop
        return ($events | Measure-Object).Count
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        return 0
    }
    catch {
        Write-Warning "Could not read System log: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Could not read System log" -Data @{ exception = $_.Exception.Message }
        return 0
    }
}

# --- JSON Report Writer ---------------------------------------------------
function Write-Report {
    Write-Log -Level INFO -Message "win-monitor run started"

    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
    $disk      = Get-DiskUsage
    $ram       = Get-RamUsage
    $failed    = Get-FailedLogonAttempts
    $errors    = Get-ErrorEvents

    $file = Join-Path $OutputDir ("sys_report-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

    Write-Output "Disk Usage: $disk%"
    Write-Output "RAM Usage: $ram%"
    Write-Output "Failed Logon Attempts: $failed"
    Write-Output "Error Events in the Last Hour: $errors"
    Write-Output "Writing report to $file"

    $report = [ordered]@{
        timestamp = $timestamp
        system    = [ordered]@{
            disk_usage_percent   = $disk
            memory_usage_percent = $ram
        }
        security  = [ordered]@{
            failed_logon_attempts = $failed
        }
        logs      = [ordered]@{
            recent_errors = $errors
        }
    }

    $report | ConvertTo-Json -Depth 4 | Set-Content -Path $file -Encoding UTF8

    Write-Output "Report written to $file"
    Write-Log -Level INFO -Message "win-monitor run completed" -Data @{ report_file = $file }
}

# --- Main -------------------------------------------------------------
function Main {
    Write-Report
}

Main