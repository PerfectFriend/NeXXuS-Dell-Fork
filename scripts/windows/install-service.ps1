# NeXXuS Node — установка Windows-службы (WinSW) + firewall rule.
# Запуск от имени администратора:
#   irm https://raw.githubusercontent.com/PerfectFriend/NeXXUs-Node/main/scripts/windows/install-service.ps1 | iex
# или локально: powershell -ExecutionPolicy Bypass -File install-service.ps1
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NeXXuS",
    [string]$P2pPort = "4001",
    [string]$WinswVersion = "2.12.0",
    [switch]$NoFirewall
)
$ErrorActionPreference = "Stop"

Write-Host "== NeXXuS node service install =="
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$env:ProgramData\NeXXuS" | Out-Null

# 1. nexxusd.exe из GitHub releases (latest), либо локальный бинарник рядом со скриптом
$exe = Join-Path $InstallDir "nexxusd.exe"
if (-not (Test-Path $exe)) {
    $local = Join-Path $PSScriptRoot "nexxusd.exe"
    if (Test-Path $local) {
        Copy-Item $local $exe
    } else {
        $url = "https://github.com/PerfectFriend/NeXXUs-Node/releases/latest/download/nexxusd-windows-x86_64.exe"
        Write-Host "Downloading nexxusd.exe from $url"
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
    }
}

# 2. WinSW
$winsw = Join-Path $InstallDir "WinSW.exe"
if (-not (Test-Path $winsw)) {
    $winswUrl = "https://github.com/winsw/winsw/releases/download/v$WinswVersion/WinSW-x64.exe"
    Write-Host "Downloading WinSW from $winswUrl"
    Invoke-WebRequest -Uri $winswUrl -OutFile $winsw -UseBasicParsing
}
Copy-Item (Join-Path $PSScriptRoot "nexxus-service.xml") (Join-Path $InstallDir "nexxus-service.xml") -Force

# 3. Регистрация службы
& $winsw install
if ($LASTEXITCODE -ne 0) { throw "WinSW install failed ($LASTEXITCODE)" }

# 4. Firewall: P2P порт открыт входящий, API (4010) — только loopback, не трогаем
if (-not $NoFirewall) {
    $ruleName = "NeXXuS Node P2P $P2pPort"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $P2pPort -Action Allow | Out-Null
        Write-Host "Firewall rule added: $ruleName"
    }
}

# 5. Старт
& $winsw start
if ($LASTEXITCODE -ne 0) { throw "WinSW start failed ($LASTEXITCODE)" }
Write-Host "Service NeXXuSNode installed and started. API: 127.0.0.1:4010 (token in $env:ProgramData\NeXXuS\api.token)"
