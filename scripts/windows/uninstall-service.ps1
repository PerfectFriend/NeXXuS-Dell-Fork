# Удаление службы NeXXuS Node + firewall rule. Админ.
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NeXXuS",
    [string]$P2pPort = "4001"
)
$ErrorActionPreference = "Stop"
$winsw = Join-Path $InstallDir "WinSW.exe"
if (Test-Path $winsw) {
    & $winsw stop
    & $winsw uninstall
}
$ruleName = "NeXXuS Node P2P $P2pPort"
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName $ruleName
}
Write-Host "NeXXuSNode service removed."
