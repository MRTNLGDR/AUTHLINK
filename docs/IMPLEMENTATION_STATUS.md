# Status de implementação

## Implementado nesta fundação

- monorepo Rust + Web + Tauri;
- PWA React mobile-first com shell visual AuthLink;
- rotas funcionais no cliente para Feed, Chat, Apps, Match, Perfil, Proteção Total, Vault de Senhas, Cofre de Fotos, Contas & Redes, Permissões, Alertas, Backup, Modo Pânico, Dispositivos e Integrações;
- gateway Axum com health, sessão e catálogo de capabilities;
- contratos Rust iniciais para contexto, força de autenticação, capabilities e auditoria;
- compose local com Postgres, OpenFGA e Rauthy;
- bootstrap Windows via `AUTHLINK.bat`;
- documentação V3 e inventários como fonte de escopo.

## Ainda NÃO deve ser chamado de produção/100% concluído

Exige implementação e validação real de: enrollment WebAuthn/Passkeys; OIDC Rauthy; modelo OpenFGA; banco/migrations; Vault criptográfico com keystore/HSM; plugins iOS/Android; Credential Provider; Family Controls/Device Policy; BLE/Wi-Fi Aware/Direct mesh; MLS/Matrix/LiveKit; auditoria append-only; integrações financeiras/saúde/Gov; testes E2E; threat model/DPIA; supply-chain/SBOM; assinatura e update.

A regra do projeto é não substituir essas integrações por mocks silenciosos. Interfaces podem existir antes dos adapters, mas devem reportar capacidade indisponível até o backend estar realmente conectado.
