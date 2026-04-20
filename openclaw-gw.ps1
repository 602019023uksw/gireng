# OpenClaw Gateway Windows Service Setup
# Run this script as Administrator

$ErrorActionPreference = "Stop"

# Configuration
$TaskName = "OpenClaw Gateway"
$NodePath = "C:\Program Files\nodejs\node.exe"
$OpenClawPath = "$env:APPDATA\npm\node_modules\openclaw\dist\index.js"
$WorkingDir = $env:USERPROFILE
$Description = "OpenClaw WebSocket Gateway service"

Write-Host "Setting up OpenClaw Gateway as a scheduled task..." -ForegroundColor Cyan

# Check if Node.js exists
if (-not (Test-Path $NodePath)) {
    Write-Error "Node.js not found at: $NodePath"
    exit 1
}

# Check if OpenClaw exists
if (-not (Test-Path $OpenClawPath)) {
    Write-Error "OpenClaw not found at: $OpenClawPath"
    exit 1
}

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create the action
$Action = New-ScheduledTaskAction `
    -Execute $NodePath `
    -Argument "`"$OpenClawPath`" gateway" `
    -WorkingDirectory $WorkingDir

# Create the trigger (at startup)
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Create the settings
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit 0

# Create the principal (run as current user)
$Principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Register the task
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Description $Description

Write-Host "`nTask created successfully!" -ForegroundColor Green

# Start the task now
Write-Host "Starting OpenClaw Gateway..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName

# Wait and check status
Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "Task Status: $($task.State)"

Write-Host @"
========================================
  OpenClaw Gateway Service Installed
========================================

Dashboard: http://127.0.0.1:18789/

Manage the service:
  Start:   Start-ScheduledTask -TaskName "OpenClaw Gateway"
  Stop:    Stop-ScheduledTask -TaskName "OpenClaw Gateway"
  Status:  Get-ScheduledTask -TaskName "OpenClaw Gateway"
  Remove:  Unregister-ScheduledTask -TaskName "OpenClaw Gateway" -Confirm:`$false
"@