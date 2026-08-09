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
2. gera `.env.local` com chaves **somente locais**, incluindo o key ring versionado do Vault;
3. sobe PostgreSQL 17, OpenFGA e Rauthy;
4. cria o store/model ReBAC do AuthLink;
5. aplica todas as migrations, inclusive envelopes criptografados do Vault;
6. valida OIDC Discovery + PKCE S256;
7. inicia **Gateway Rust + Vault Rust + PWA** e abre `http://localhost:5173`.

A senha admin local do Rauthy e a master key local inicial do Vault são aleatórias. Elas ficam somente no `.env.local`, que é ignorado pelo Git. O bootstrap preserva um key ring válido existente, portanto reiniciar o ambiente não troca silenciosamente a chave que protege itens já gravados.

Serviços locais:

- Web: `http://localhost:5173`
- Gateway: `http://localhost:8787/api/v1/health`
- Vault: `http://localhost:8788/api/v1/health`
- Rauthy: `http://localhost:8085/auth/v1/admin`
- OpenFGA Playground: `http://localhost:3000/playground`

### macOS/Linux

```bash
chmod +x RUN_AUTHLINK.sh
./RUN_AUTHLINK.sh
```

### Comandos manuais

```bash
node scripts/bootstrap-local.mjs all   # Postgres + OpenFGA + Rauthy + modelo + migrations + keys locais
node scripts/dev-local.mjs             # Gateway + Vault + Web
```

Com `just`:

```bash
just bootstrap
just infra-up
just dev
just vault       # somente o serviço Vault, usando .env.local
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
- **Vault criptográfico Rust isolado** com XChaCha20-Poly1305;
- DEK aleatória por item, master-key ring versionado e rotação por rewrap da DEK;
- AAD do Vault vinculado a tenant + identidade + item + finalidade;
- PostgreSQL do Vault guarda somente envelopes criptografados, não plaintext;
- Vault reutiliza a sessão AuthLink e exige `identity.can_read/can_manage` no OpenFGA;
- migrations e testes reais em PostgreSQL no CI;
- smoke test do runtime local Postgres/OpenFGA/Rauthy/PKCE e inicialização do Vault com chave gerada localmente.

## Estrutura

```text
apps/web/                    PWA AuthLink
apps/shell/src-tauri/        shell Tauri
crates/authlink-contracts/   contratos
crates/authlink-guardian/    risk engine
crates/authlink-idp/         OIDC/PKCE adapter
crates/authlink-policy/      OpenFGA adapter
crates/authlink-store/       SQLx/PostgreSQL
crates/authlink-vault/       envelope encryption / key ring
services/gateway/            identidade, sessão e API /api/v1
services/vault/              serviço isolado do cofre criptográfico
migrations/                  schema versionado
docs/spec-v3/                documentação e security models
docs/ui-approved/            manifesto das telas aprovadas
infra/openfga/               modelo ReBAC
infra/rauthy/bootstrap/      cliente OIDC local
infra/compose/               stack local
scripts/                     bootstrap e runtime
```

## Segurança de produção

`AUTHLINK_ENV=production` é fail-closed: o Gateway recusa iniciar sem PostgreSQL, OpenFGA e IdP OIDC alcançável. O Vault exige PostgreSQL, autorização e key ring válidos. O perfil Docker deste README é **desenvolvimento local**, com HTTP localhost e configuração insegura de cookie somente para o Rauthy local.

As master keys locais do Vault entram por secret/env apenas para desenvolvimento/CI. Produção deve usar TLS e custódia apropriada via secret manager/KMS/HSM/keystore, além de política de retenção, attestation nativa, threat model, RIPD/DPIA onde aplicável e releases assinados.

## Documentação

- `docs/spec-v3/AUTHLINK_DOCUMENTACAO_UNIFICADA_V3.md`
- `docs/spec-v3/AUTHLINK_V3_README_ASSEMBLY.md`
- `docs/spec-v3/VAULT_SECURITY_MODEL.md`
- `docs/ui-approved/APPROVED_SCREENS.md`
- `docs/legacy/AUTHLINK_SOCIAL_NETWORK_INVENTORY.md`

> Regra do projeto: upstream permissivo primeiro, adapters pequenos, ownership explícito e nenhum segundo sistema concorrente para identidade, autorização ou dados canônicos.
