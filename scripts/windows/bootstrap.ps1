param(
  [switch]$InstallTools,
  [switch]$Core,
  [switch]$WebOnly
)
$ErrorActionPreference = "Stop"
Write-Host "=== AUTHLINK AIIA Suite ===" -ForegroundColor Green

function Need($cmd) { return -not (Get-Command $cmd -ErrorAction SilentlyContinue) }
if (Need "node") {
  if ($InstallTools -and (Get-Command winget -ErrorAction SilentlyContinue)) { winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements }
  else { throw "Node.js nao encontrado. Rode AUTHLINK.bat -InstallTools ou instale Node 22+." }
}
if (-not $WebOnly -and (Need "cargo")) {
  if ($InstallTools -and (Get-Command winget -ErrorAction SilentlyContinue)) { winget install Rustlang.Rustup --accept-package-agreements --accept-source-agreements }
  else { Write-Warning "Rust nao encontrado: o frontend pode rodar, mas gateway/Tauri nao." }
}
Write-Host "Instalando dependencias web..." -ForegroundColor Cyan
npm install
if ($Core) {
  if (Need "docker") { throw "Docker Desktop/Engine nao encontrado." }
  docker compose -f infra/compose/docker-compose.dev.yml up -d
}
Write-Host "Iniciando AuthLink Web em http://localhost:5173" -ForegroundColor Green
npm run dev
