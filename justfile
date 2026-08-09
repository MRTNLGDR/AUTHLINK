set shell := ["bash", "-cu"]

bootstrap:
    node scripts/bootstrap-local.mjs env
    npm install
    cargo fetch

infra-up:
    node scripts/bootstrap-local.mjs all

infra-down:
    docker compose --env-file .env.local -f infra/compose/docker-compose.dev.yml down

infra-reset:
    docker compose --env-file .env.local -f infra/compose/docker-compose.dev.yml down -v
    rm -f .env.local

infra-logs:
    docker compose --env-file .env.local -f infra/compose/docker-compose.dev.yml logs -f

status:
    docker compose --env-file .env.local -f infra/compose/docker-compose.dev.yml ps

migrate:
    node scripts/bootstrap-local.mjs all

web:
    npm run dev -w @authlink/web

gateway:
    set -a && source .env.local && set +a && cargo run -p authlink-gateway

dev:
    node scripts/dev-local.mjs

local:
    node scripts/bootstrap-local.mjs all
    node scripts/dev-local.mjs

check-web:
    npm run check -w @authlink/web

build-web:
    npm run build -w @authlink/web

check-rust:
    cargo check -p authlink-contracts -p authlink-guardian -p authlink-idp -p authlink-policy -p authlink-store -p authlink-gateway

check:
    npm run check
    cargo check -p authlink-contracts -p authlink-guardian -p authlink-idp -p authlink-policy -p authlink-store -p authlink-gateway

test:
    npm run check
    npm run build
    cargo test -p authlink-contracts -p authlink-guardian -p authlink-idp -p authlink-policy -p authlink-gateway
