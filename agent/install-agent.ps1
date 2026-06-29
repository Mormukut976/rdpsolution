param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$AgentToken,

    [string]$InstallPath = "$env:ProgramFiles\OpenRemote Agent"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this installer from an elevated PowerShell window."
}

$Source = Join-Path $PSScriptRoot "publish\openremote-agent.exe"
if (-not (Test-Path $Source)) {
    throw "Agent binary not found. Run: dotnet publish -c Release -r win-x64 -o publish"
}

New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
Copy-Item $Source (Join-Path $InstallPath "openremote-agent.exe") -Force

$Settings = @{
    ServerUrl = $ServerUrl.TrimEnd("/")
    AgentToken = $AgentToken
    HeartbeatSeconds = 30
} | ConvertTo-Json

$SettingsPath = Join-Path $InstallPath "agentsettings.json"
[IO.File]::WriteAllText($SettingsPath, $Settings)

icacls $SettingsPath /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(F)" | Out-Null

$Action = New-ScheduledTaskAction -Execute (Join-Path $InstallPath "openremote-agent.exe")
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$SettingsObject = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 100 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "OpenRemote Agent" `
    -Description "Reports Windows host health to the OpenRemote control plane." `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $SettingsObject `
    -Force | Out-Null

Start-ScheduledTask -TaskName "OpenRemote Agent"
Write-Host "OpenRemote Agent installed and started."
