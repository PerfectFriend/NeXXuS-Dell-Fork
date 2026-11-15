# =============================================================================
# NeXXuS Node — автоустановка на Windows (ОДИН ФАЙЛ)
# Запуск от имени АДМИНИСТРАТОРА:
#   1) PowerShell:  Set-ExecutionPolicy Bypass -Scope Process -Force
#   2)               .\install-nexxus.ps1
# или одной строкой из интернета:
#   irm https://raw.githubusercontent.com/PerfectFriend/NeXXuS-Node-Hermes-Rust/main/install-nexxus.ps1 | iex
#
# Что делает: скачивает nexxusd.exe и WinSW, ставит службу NeXXuSNode
# (автозапуск, рестарт при падении), открывает firewall ТОЛЬКО для P2P 4001.
# API (4010) остаётся на loopback. Данные: C:\ProgramData\NeXXuS
# =============================================================================
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NeXXuS",
    [string]$P2pPort = "4001",
    [string]$Repo = "PerfectFriend/NeXXuS-Node-Hermes-Rust",
    [string]$WinswUrl = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe",
    [switch]$NoFirewall,
    [switch]$NoService   # только скачать бинарник, без службы
)
$ErrorActionPreference = "Stop"

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Нужны права администратора (запусти PowerShell от имени администратора)."
    }
}

Write-Host "== NeXXuS Node auto-install =="
Ensure-Admin
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$env:ProgramData\NeXXuS" | Out-Null

# --- 1. nexxusd.exe из релиза ---
$exe = Join-Path $InstallDir "nexxusd.exe"
$assetUrl = "https://github.com/$Repo/releases/latest/download/nexxusd-windows-x86_64.exe"
if (-not (Test-Path $exe)) {
    Write-Host "Скачиваю nexxusd.exe ..."
    Invoke-WebRequest -Uri $assetUrl -OutFile $exe -UseBasicParsing
} else {
    Write-Host "nexxusd.exe уже есть: $exe"
}
& $exe --version

if ($NoService) { Write-Host "Готово (NoService): $exe"; exit 0 }

# --- 2. WinSW ---
$winsw = Join-Path $InstallDir "WinSW.exe"
if (-not (Test-Path $winsw)) {
    Write-Host "Скачиваю WinSW ..."
    Invoke-WebRequest -Uri $WinswUrl -OutFile $winsw -UseBasicParsing
}

# --- 3. конфиг службы (пишем сами, чтобы файл был самодостаточным) ---
$xml = @"
<service>
  <id>NeXXuSNode</id>
  <name>NeXXuS Storage Node</name>
  <description>NeXXuS P2P storage node (Rust nexxusd). API 127.0.0.1:4010 token-gated, P2P :$P2pPort</description>
  <executable>$exe</executable>
  <arguments>serve</arguments>
  <workingdirectory>$InstallDir</workingdirectory>
  <env name="NEXXUS_DATA_DIR" value="$env:ProgramData\NeXXuS"/>
  <env name="NEXXUS_LISTEN" value="0.0.0.0:$P2pPort"/>
  <env name="NEXXUS_API_ADDR" value="127.0.0.1:4010"/>
  <env name="NEXXUS_TOR" value="1"/>
  <log mode="rotate" sizeThreshold="10485760" maxSize="5"/>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <stop timeout="15 sec"/>
  <startmode>Automatic</startmode>
</service>
"@
$xmlPath = Join-Path $InstallDir "nexxus-service.xml"
# WinSW читает <executable>.xml — переименуем под имя exe
$xmlPath = $exe -replace '\.exe$', '.xml'
Set-Content -Path $xmlPath -Value $xml -Encoding UTF8

# --- 4. регистрация и старт службы ---
& $winsw install
if ($LASTEXITCODE -ne 0) { throw "WinSW install failed ($LASTEXITCODE)" }

# --- 5. firewall: только P2P ---
if (-not $NoFirewall) {
    $ruleName = "NeXXuS Node P2P $P2pPort"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $P2pPort -Action Allow | Out-Null
        Write-Host "Firewall: открыт порт $P2pPort (только P2P)"
    }
}

& $winsw start
if ($LASTEXITCODE -ne 0) { throw "WinSW start failed ($LASTEXITCODE)" }

Start-Sleep 2
$svc = Get-Service NeXXuSNode -ErrorAction SilentlyContinue
Write-Host "== ГОТОВО =="
Write-Host "Служба NeXXuSNode: $($svc.Status)"
Write-Host "API: ws://127.0.0.1:4010 (токен: $env:ProgramData\NeXXuS\api.token)"
Write-Host "Управление:  & `"$winsw`" status | start | stop | restart"
Write-Host "Удаление:    & `"$winsw`" uninstall  (или uninstall-nexxus.ps1 из репозитория)"
