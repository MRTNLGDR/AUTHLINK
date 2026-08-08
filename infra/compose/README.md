# Core local

```bash
docker compose -f infra/compose/docker-compose.dev.yml up -d
```

Serviços iniciais:
- Postgres: `localhost:54329`
- OpenFGA HTTP: `localhost:8080`
- Rauthy: `localhost:8085`

O compose é de desenvolvimento. Antes de produção: trocar secrets, fixar imagens por digest, habilitar TLS, observabilidade, backups e policies de rede.
