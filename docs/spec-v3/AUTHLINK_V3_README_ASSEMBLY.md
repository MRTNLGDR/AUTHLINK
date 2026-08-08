# AuthLink V3 — README de montagem “LEGO”

> Objetivo: maximizar reutilização de open source permissivo e manter código próprio apenas onde existe valor exclusivo AIIA/AuthLink ou obrigação regulatória/plataforma.

## 1. Política de licença

### Perfil recomendado (permissivo)
Aceitar no core: **MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0/Public Domain**.  
MPL-2.0: somente serviço isolado e com compliance por arquivo.  
AGPL/GPL/source-available: não linkar ao core fechado; usar processo externo quando houver motivo forte e obrigações aceitas, ou substituir.

### Se a regra for literalmente “somente MIT/CC0”
É possível, mas **não é a melhor estratégia de pouco código**: você excluiria OpenFGA, Cosmos SDK, CometBFT, Qdrant, DataFusion, Supabase, LiveKit e vários componentes Apache-2.0. O perfil recomendado acima continua permissivo e é o que reduz mais engenharia própria.

## 2. Perfis de execução

```text
profile core
  postgres + idp + openfga + gateway + vault + qdrant + event backbone + audit

profile comms
  matrix/tuwunel (opcional) + openmls + livekit + nearby relay/mesh

profile knowledge
  open-foundry adapter + oxigraph + tantivy + qdrant + datafusion

profile developer
  AIIA Base Studio + Git/GitHub/GitLab + Supabase + MCP + providers + sequencer + notes + workbench

profile chain (SEPARADO)
  lionz-chain node + indexer + proof anchor; nunca requisito síncrono de login
```

## 3. Comandos alvo do monorepo

Estes comandos são **contratos de montagem a implementar no novo monorepo**, não alegação de que já existem no snapshot:

```bash
just bootstrap          # toolchains, hooks, local certificates, env templates
just vendor-sync        # clona/atualiza upstreams pinados e gera UPSTREAM.lock
just license-gate       # SPDX + allow-list + notices
just sbom               # CycloneDX/SPDX
just up core            # sobe plataforma base
just up comms           # sobe servidores de comunicação opcionais
just up knowledge       # sobe índice/grafo/ontology
just up dev             # developer mode existente do RAR
just dev web            # PWA React
just dev desktop        # Tauri desktop
just dev mobile-ios     # Tauri + Xcode/native plugins
just dev mobile-android # Tauri + Gradle/native plugins
just test-all           # unit/contract/integration/e2e/security/offline
```

## 4. Estrutura física

```text
AUTHLINK/
├─ apps/
│  ├─ web/                         # React PWA
│  ├─ desktop/                     # Tauri 2
│  ├─ mobile/                      # Tauri mobile shell
│  └─ authlink-ui/                 # 108 rotas + sheets
├─ crates/
│  ├─ authlink-contracts/
│  ├─ authlink-client/
│  ├─ authlink-session/
│  ├─ authlink-consent/
│  ├─ authlink-guardian/
│  ├─ authlink-mesh/
│  ├─ authlink-chat/
│  ├─ authlink-knowledge/
│  └─ aiia-offline/
├─ services/
│  ├─ gateway/
│  ├─ idp-adapter/
│  ├─ social/
│  ├─ security/
│  ├─ knowledge/
│  ├─ business/
│  └─ adapters-regulated/
├─ native/
│  ├─ ios-authlink-plugin/         # Credential Provider, FamilyControls, Wi-Fi Aware, HealthKit, App Attest
│  ├─ android-authlink-plugin/     # Credential Manager, DPC, Wi-Fi Aware/Direct, Health Connect, Play Integrity
│  ├─ windows-authlink-plugin/     # Hello/WebAuthn/DPAPI/CNG
│  └─ macos-authlink-plugin/       # Keychain/AuthServices/Secure Enclave
├─ packages/
│  ├─ design-tokens/
│  ├─ ui-react/
│  ├─ generated-clients/
│  └─ iconography/
├─ infra/
│  ├─ compose/
│  ├─ kubernetes/
│  ├─ observability/
│  └─ policy/
├─ vendor/                         # upstreams pinados, patches mínimos
├─ docs/
├─ csv/
└─ justfile
```

## 5. Ordem de montagem

1. **Congelar contratos**: IDs, owners, rotas, comandos, eventos, permissões, purpose IDs.
2. **Subir core**: PostgreSQL → IdP → OpenFGA → Gateway → Vault → event backbone → audit.
3. **Implementar passkeys e sessão** antes de rede social.
4. **Criar plugins nativos** para as capacidades que browser/Tauri não podem oferecer diretamente.
5. **Migrar UI**: 20 auth/onboarding → Feed/Chat/Apps/Profile → Security → Knowledge → Family/Health/Finance → Developer.
6. **Migrar o RAR** para Developer mode, preservando providers, MCP, modules, sequencer, notes, workbench e deploy adapters.
7. **Adicionar comms offline/nearby** com grants offline assinados e OpenMLS.
8. **Somente depois** integrar saúde/financeiro/gov com contratos, consentimentos e ambientes de homologação.
9. **Lionz Chain e Lionz Bank** entram em perfil separado, após threat model/custódia/regulação.

## 6. Regra de forks

Não faça fork permanente por padrão. Use esta ordem:

```text
library/dependency pinada > container/runtime pinado > adapter > patch pequeno > fork mantido
```

Todo upstream recebe `UPSTREAM.toml` com URL, commit/tag, licença, patches, SBOM, owner, política de update e rollback.

## 7. Auth: perfil V3 permissivo

A documentação anterior usa **Kanidm**. Para a exigência atual de licença permissiva e pouco código, V3 propõe:

- **Rauthy (Apache-2.0)** como IdP padrão de distribuição permissiva;
- **Kanidm (MPL-2.0)** como perfil enterprise/directory opcional;
- **OpenFGA** continua autorização canônica;
- passkey/WebAuthn + biometria do SO + device attestation = login forte;
- captura facial PERZON = proofing/onboarding/avatar, não substituto exclusivo de passkey.

## 8. Lionz Chain

Você **não precisa escrever uma blockchain do zero** nem colocar blockchain no login. Caminho de menor engenharia:

- app própria `lionz-chain` usando **Cosmos SDK core + CometBFT**;
- módulos próprios mínimos: identity-proof-anchor, audit-anchor, asset/token, validator/governance;
- usar somente módulos core com licença compatível e revisar o diretório `enterprise/` separadamente;
- AuthLink manda **proofs/roots**, não PII, biometria, CPF, saúde ou mensagens;
- Reth é ótima opção Rust para EVM/execution, mas não resolve sozinho a camada de consenso de uma chain soberana.

## 9. Comunicação sem Internet

Arquitetura recomendada:

```text
Discovery: BLE / Wi-Fi Aware / Wi-Fi Direct
        ↓
Local link: Network.framework / Android Wi-Fi APIs
        ↓
Peer channel: Iroh QUIC ou rust-libp2p
        ↓
Envelope E2EE: OpenMLS
        ↓
Store-and-forward: SQLite outbox/inbox + signed short-lived grants
        ↓
Reconciliation: Gateway quando Internet voltar
```

A mesh nunca concede autorização nova; apenas transporta envelopes já permitidos.

## 10. O que continuará sendo código AIIA

Não existe OSS permissivo pronto que entregue, ao mesmo tempo, sua semântica social, segurança, autoridade de conhecimento, Open Finance brasileiro e política de consentimento. O código próprio inevitável deve ficar concentrado em:

- contratos/ownership e adapters;
- Guardian risk/policies;
- feed/match/recommendation;
- consent/purpose UI e regras;
- conhecimento/autoridade/marketplace;
- plugins nativos de iOS/Android/Windows/macOS;
- adapters regulados Brasil;
- Lionz Bank/Lionz Chain modules específicos;
- design system/UX AuthLink.

A meta realista é reutilizar a maior parte da **infraestrutura** e programar só a camada diferencial e regulatória.
