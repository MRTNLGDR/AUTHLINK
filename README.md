# AUTHLINK — AIIA Suite

AuthLink é a autoridade de identidade, sessão, consentimento, comunicação segura e navegação entre apps da AIIA Suite.

O produto é **mobile-first**, Rust-authoritative, local-first, privacy-by-default e zero-trust. PERZON executa a cerimônia biométrica; PEZON recebe somente a referência consentida para avatar. AuthLink não grava biometria bruta, CPF, saúde, chats ou segredos de credenciais em blockchain.

## Rodar no Windows

Pré-requisitos: Node.js 22+, Rust 1.88+, Docker Desktop.

```bat
RUN_AUTHLINK.bat
```

O launcher:

1. instala as dependências web;
2. gera `.env.local` com chaves **somente locais**;
3. sobe PostgreSQL 17, OpenFGA e Rauthy;
4. cria o store/model ReBAC do AuthLink;
5. aplica todas as migrations;
6. valida OIDC Discovery + PKCE S256;
7. inicia Gateway Rust + PWA e abre `http://localhost:5173`.

A senha admin local do Rauthy é aleatória e é mostrada pelo bootstrap. Ela fica somente no `.env.local`, que é ignorado pelo Git.

### macOS/Linux

```bash
chmod +x RUN_AUTHLINK.sh
./RUN_AUTHLINK.sh
```

### Comandos manuais

```bash
node scripts/bootstrap-local.mjs all   # infraestrutura + modelo + migrations
node scripts/dev-local.mjs             # Gateway + Web
```

Com `just`:

```bash
just bootstrap
just infra-up
just dev
```

## O que já está implementado no código

- 16 etapas de onboarding/autenticação antes do Feed;
- shell mobile-first: Feed, Chat, Apps, Match, Perfil;
- hubs de proteção: senhas, fotos, contas/redes, permissões, alertas, backup, pânico e dispositivos;
- Rust Gateway Axum;
- contratos Rust de identity ceremony/Guardian;
- Guardian determinístico, explicável e testado;
- PostgreSQL/SQLx como autoridade quando configurado;
- optimistic concurrency para onboarding;
- OIDC Discovery + Authorization Code + PKCE S256;
- tokens do IdP ficam no servidor; browser recebe sessão AuthLink opaca HttpOnly;
- logout/revogação de sessão;
- OpenFGA ReBAC;
- provisioning de ownership sem PII: `user:<uuid> owner identity:<uuid>`;
- operações Guardian protegidas por sessão + relação OpenFGA;
- migrations e testes reais em PostgreSQL no CI;
- smoke test do runtime local Postgres/OpenFGA/Rauthy.

## Estrutura

```text
apps/web/                    PWA AuthLink
apps/shell/src-tauri/        shell Tauri
crates/authlink-contracts/   contratos
crates/authlink-guardian/    risk engine
crates/authlink-idp/         OIDC/PKCE adapter
crates/authlink-policy/      OpenFGA adapter
crates/authlink-store/       SQLx/PostgreSQL
services/gateway/            API /api/v1
migrations/                  schema versionado
docs/spec-v3/                documentação unificada
docs/ui-approved/            manifesto das telas aprovadas
infra/openfga/               modelo ReBAC
infra/rauthy/bootstrap/      cliente OIDC local
infra/compose/               stack local
scripts/                     bootstrap e runtime
```

## Segurança de produção

`AUTHLINK_ENV=production` é fail-closed: o Gateway recusa iniciar sem PostgreSQL, OpenFGA e IdP OIDC alcançável. O perfil Docker deste README é **desenvolvimento local**, com HTTP localhost e configuração insegura de cookie somente para o Rauthy local. Produção exige TLS, secret manager/HSM/keystore, política de retenção, attestation nativa, threat model, RIPD/DPIA onde aplicável e releases assinados.

## Documentação

- `docs/spec-v3/AUTHLINK_DOCUMENTACAO_UNIFICADA_V3.md`
- `docs/spec-v3/AUTHLINK_V3_README_ASSEMBLY.md`
- `docs/ui-approved/APPROVED_SCREENS.md`
- `docs/legacy/AUTHLINK_SOCIAL_NETWORK_INVENTORY.md`

> Regra do projeto: upstream permissivo primeiro, adapters pequenos, ownership explícito e nenhum segundo sistema concorrente para identidade, autorização ou dados canônicos.
