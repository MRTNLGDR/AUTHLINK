#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

command -v node >/dev/null || { echo "Node.js 22+ is required"; exit 1; }
command -v npm >/dev/null || { echo "npm is required"; exit 1; }
command -v cargo >/dev/null || { echo "Rust/Cargo is required"; exit 1; }
command -v docker >/dev/null || { echo "Docker is required"; exit 1; }

npm install
node scripts/bootstrap-local.mjs all
exec node scripts/dev-local.mjs
