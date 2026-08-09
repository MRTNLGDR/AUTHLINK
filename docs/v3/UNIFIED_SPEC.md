# AuthLink V3 — Especificação Unificada

> Status: especificação canônica de implementação para a nova geração do AuthLink.
> Perfil: mobile-first, web/desktop/mobile, Rust-authoritative, offline-capable, Zero Trust.

## 1. Missão

AuthLink é a autoridade única de identidade, sessão e segurança transversal da AIIA Suite. Ele também é a superfície social universal do usuário: Feed, Chat, Apps, Match e Perfil.

O AuthLink **não** duplica ownership dos demais domínios:

- AuthLink: identidade, sessão, passkeys, dispositivos confiáveis, papéis, consentimentos, grants, mensageria privada, social graph e launcher da suíte.
- PERZON: cerimônia biométrica, face proofing, liveness e onboarding visual.
- PEZON: avatar/gêmeo digital; recebe apenas referências e dados explicitamente consentidos.
- AIIA Vault: blobs, cofre de mídia, manifests, retenção e criptografia de arquivos.
- Lionz Bank: contas, Pix, Open Finance, tesouraria e liquidação.
- Lionz Chain: provas/âncoras, ativos e rede blockchain; nunca substitui o banco transacional do AuthLink.
- Blue Sky: saúde, rotina, hábitos, treinos e dados wellness.

## 2. Princípios inegociáveis

1. Zero Trust em toda chamada.
2. Passkey/WebAuthn + secure hardware/OS biometric é o mecanismo primário de login forte.
3. Reconhecimento facial próprio não é a única chave de autenticação bancária; é usado em proofing/liveness e como sinal adicional de risco.
4. Segredos nunca entram em logs, eventos, CSV, analytics ou prompts.
5. Dados sensíveis são segregados por domínio e finalidade.
6. Toda mutação crítica é comando tipado, idempotente e auditável.
7. Blockchain é usada como prova/auditoria quando necessário; login não depende do consenso da chain.
8. Offline/mesh transporta envelopes criptografados e grants previamente assinados; nunca cria nova permissão.
9. A UI nunca chama banco/serviço interno diretamente; usa `/api/v1`.
10. Nenhuma função desaparece no mobile; muda de prioridade, sheet ou drawer.

## 3. Navegação global

Bottom navigation mobile:

1. Feed
2. Chat
3. Apps
4. Match
5. Perfil

Topbar:

- marca AuthLink;
- busca global;
- notificações;
- indicador de sincronização/segurança;
- avatar/perfil;
- AuthLink contextual em todas as superfícies AIIA.

Desktop: mesma gramática com nav rail, viewport, inspector, activity rail e statusbar.

## 4. Design tokens

```text
root       #05070C
chrome     #070A10
canvas     #080B11
surface    #0E141D
surface2   #101823
inset      #0B1017
border     #1A2331
text       #E6ECF5
secondary  #8EA3BD
muted      #6C7C93
success    #34D399
warning    #F59E0B
danger     #F87171
info       #38BDF8
accent     #9FE82F
accent-2   #4C8DFF
```

## 5. Macrodomínios do produto

### Identity & Auth

- boot universe;
- login;
- registration;
- passkey enrollment/login;
- liveness;
- documento/OCR;
- identity confirmation;
- 2FA/TOTP/recovery;
- trusted device;
- session elevation;
- account recovery;
- biometric consent;
- device integrity signals.

### Social

- feed;
- post detail;
- composer;
- stories/updates opcionais;
- social graph;
- follow/connect;
- communities/clãs;
- reactions/comments/saves/shares;
- creator/authority verification.

### Chat

- inbox;
- 1:1;
- grupos;
- business chat;
- attachments;
- voice notes;
- calls;
- encrypted files;
- pinned messages;
- search;
- offline queue/mesh delivery.

### Match & Opportunity

- swipe/discovery;
- people/projects/opportunities;
- compatibility score;
- explainable match;
- jobs/services/projects;
- creator/expert offerings;
- bounties;
- contracts/escrow through owned domains.

### Apps

- suite launcher;
- plan entitlements;
- recents;
- deep-link secure launch;
- developer integrations;
- MCP/local/cloud providers;
- notes/modules/sequencer/workbench preserved from the legacy codebase.

### Security Hub

- protection overview;
- password/passkey vault;
- photo/media vault;
- accounts & networks;
- permissions/privacy;
- alerts/threats;
- device/session center;
- encrypted backup/recovery;
- facial vault;
- blockchain audit;
- emergency/panic mode;
- Guardian AI risk center.

### Family / Parental

- family group;
- guardian roles;
- child/teen profiles;
- screen-time rules where OS permits;
- app/site policy where platform entitlements permit;
- location sharing by explicit family purpose;
- purchase approval;
- emergency contacts;
- safety alerts.

### Knowledge

- global knowledge graph;
- public/private/paid knowledge;
- expert authority graph;
- 60-second micro-knowledge;
- step-by-step recipes/methods/workouts/processes;
- collections;
- progress;
- spaced repetition;
- course/library;
- creator monetization;
- provenance and version history.

### Health & Routine

Kept as a segregated surface/domain adapter, never mixed directly into the social profile without consent:

- habits;
- workouts;
- medications/reminders;
- measurements;
- menstrual/hormonal cycle tracking;
- male/female hormone-related routines as user-entered/wearable-integrated data;
- appointments;
- shopping lists;
- sleep/wellness;
- emergency health card;
- export/delete controls.

### Finance / Government

Through regulated adapters only:

- Open Finance consent and aggregation;
- bank account references;
- spending/cashflow summaries;
- credit/financial-health adapters where legally available;
- CPF/gov identity integration through official APIs;
- document wallet;
- Lionz Bank launch context;
- Lionz Chain proof explorer.

## 6. Backend boundaries

```text
UI/PWA/Tauri
  -> AIIA Gateway /api/v1
     -> AuthLink Session/Identity
     -> OpenFGA ReBAC
     -> Command Bus + Audit + Outbox
     -> Domain Services
     -> PostgreSQL
     -> Vault CAS
     -> Event Backbone
     -> Read Models / Realtime
```

Internal channels:

- HTTP/gRPC: immediate commands/queries;
- Kafka protocol: durable domain events;
- WebSocket: ephemeral progress/collaboration;
- Realtime: read model/database subscriptions only;
- libp2p/Iroh: mesh/offline transport;
- MLS: end-to-end group messaging layer.

## 7. Rust crates/services — target

Core:

- `authlink-contracts`
- `authlink-gateway`
- `authlink-idp-adapter`
- `authlink-session`
- `authlink-consent`
- `authlink-policy`
- `authlink-device`
- `authlink-passkey`
- `authlink-risk`
- `authlink-audit`
- `authlink-social`
- `authlink-feed`
- `authlink-match`
- `authlink-chat`
- `authlink-mesh`
- `authlink-knowledge`
- `authlink-family`
- `authlink-recovery`
- `authlink-launcher`

Adapters:

- `authlink-rauthy-adapter`
- `authlink-openfga-adapter`
- `authlink-vault-adapter`
- `authlink-perzon-adapter`
- `authlink-pezon-adapter`
- `authlink-health-adapter`
- `authlink-openfinance-adapter`
- `authlink-govbr-adapter`
- `authlink-lionz-bank-adapter`
- `authlink-lionz-chain-adapter`

## 8. Open-source LEGO policy

Preferred license classes for core distribution:

- MIT
- Apache-2.0
- BSD-2/3-Clause
- ISC
- CC0/Public Domain

MPL may be isolated at a clear file/service boundary. GPL/AGPL/source-available projects stay external/optional unless distribution obligations are explicitly accepted.

Candidate stack by capability:

- IdP/OIDC/passkeys: Rauthy; Kanidm optional profile.
- authorization: OpenFGA.
- database: PostgreSQL.
- local edge: SQLite WAL.
- REST compatibility: PostgREST behind the gateway.
- realtime: Supabase Realtime/fork as read-model transport.
- vectors: Qdrant.
- object/CAS backend: SeaweedFS or compatible object backend behind AIIA Vault.
- events: Kafka-compatible protocol.
- P2P: rust-libp2p and/or Iroh.
- encrypted group messaging: OpenMLS.
- WebRTC media: LiveKit/other permissive component after pinned-license review.
- knowledge graph standards: Oxigraph + operational ontology adapter.
- desktop/mobile shell: Tauri 2.
- web UI: React + TypeScript.
- HTTP: Axum.
- database access: SQLx.
- observability: OpenTelemetry.

## 9. Native platform reality

AuthLink cannot legally/technically read the private sandbox of every third-party app. Protection is implemented through supported OS surfaces:

- credential/passkey provider;
- biometric APIs and Secure Enclave/Keystore-backed keys;
- notification/permission surfaces where APIs permit;
- photo library access explicitly granted by user;
- VPN/DNS/content filter where platform policy and entitlement permit;
- DevicePolicy/MDM on managed Android/enterprise deployments;
- Family Controls/Screen Time APIs on supported Apple deployments;
- share extensions, document providers, autofill/credential extensions;
- account integrations via OAuth/OIDC/Open Banking/official APIs.

Any screen promising more than the OS entitlement actually permits must show the real availability state.

## 10. Universal states

Every route supports:

- loading
- empty
- error
- offline
- stale
- conflict
- read-only
- permission denied
- elevated-auth required

## 11. Definition of Done

A screen/module is only DONE when:

1. route exists;
2. mobile + desktop responsive layout works;
3. all controls are mapped to typed actions;
4. loading/empty/error/offline/permission states exist;
5. authorization is tested;
6. no direct DB call from UI;
7. secrets/PII are redacted from telemetry;
8. unit/contract/E2E tests exist;
9. visual regression passes;
10. docs/change log/license inventory are updated.
