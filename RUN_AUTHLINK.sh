#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

command -v node >/dev/null || { echo "Node.js 22+ is required"; exit 1; }
command -v npm >/dev/null || { echo "npm is required"; exit 1; }
command -v cargo >/dev/null || { echo "Rust/Cargo is required"; exit 1; }
command -v docker >/dev/null || { echo "Docker is required"; exit 1; }

echo "[1/3] Installing web dependencies..."
npm install

echo "[2/3] Preparing Postgres, OpenFGA, Rauthy, Vault keys, model and migrations..."
node scripts/bootstrap-local.mjs all

echo "[3/3] Starting AuthLink Gateway + Vault + Device + Web..."
exec node scripts/dev-local.mjs
