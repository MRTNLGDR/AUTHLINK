set shell := ["bash", "-cu"]

bootstrap:
    npm install

web:
    npm run dev -w @authlink/web

check-web:
    npm run check -w @authlink/web

build-web:
    npm run build -w @authlink/web

gateway:
    cargo run -p authlink-gateway

check-rust:
    cargo check -p authlink-contracts -p authlink-gateway

core-up:
    docker compose -f infra/compose/docker-compose.dev.yml up -d

core-down:
    docker compose -f infra/compose/docker-compose.dev.yml down

core-logs:
    docker compose -f infra/compose/docker-compose.dev.yml logs -f

status:
    docker compose -f infra/compose/docker-compose.dev.yml ps
