# AuthLink V3 — Manifesto das Telas Aprovadas

Este documento congela a direção visual aprovada na conversa antes de implementação. As imagens originais permanecem no pacote de design da sessão; a implementação deve reproduzir **hierarquia, densidade, navegação e gramática**, não rasterizar a UI dentro do app.

## Linguagem aprovada

- mobile-first;
- preto profundo, superfícies discretas, neon verde controlado;
- fintech/security premium — não HUD de game;
- `#9FE82F` como accent principal;
- `#4C8DFF` como informação/secundária;
- texto branco/cinza, bordas hairline;
- fotografia humana realista quando a função pede perfil/biometria;
- cards com raio contido e glow seletivo, sem excesso;
- topbar com AuthLink, busca, notificações e avatar;
- bottom navigation persistente: **Feed · Chat · Apps · Match · Perfil**;
- CTA forte dentro da zona do polegar;
- desktop deriva da mesma UI, sem criar outro produto.

## Conjunto A — Social / produto principal

1. **Feed / Home** — saudação, identidade verificada, mensagens não lidas, apps do plano, feed misto social/oportunidades/conexões.
2. **Chat / Inbox** — todas, não lidas, grupos/fixadas, prioridade, conversas protegidas.
3. **Chat / Conversation** — E2EE, texto, documento, áudio, anexos, reunião/call.
4. **Apps do plano** — launcher, entitlement, recents, status do plano.
5. **Match / Descobrir** — pessoas/projetos/oportunidades, card humano, passar/salvar/conectar.
6. **Match detail** — compatibilidade explicável, habilidades, oferta, busca, confiança, CTA conversar/conectar.
7. **Mercado / Oportunidades** — vagas, projetos, serviços, score de match, aplicar.
8. **Perfil / Identidade** — identidade verificada, bio, skills, apps conectados, credenciais, biometria.
9. **Cursos / Aprendizado** — progresso, cursos, trilhas, biblioteca.
10. **Configurações / Plano** — plano, cobrança, softwares inclusos, uso, preferências, suporte.
11. **Notificações & atividade** — social, segurança e eventos de apps.
12. **Post detail** — conteúdo, comentários, salvar, compartilhar.
13. **Brainlink app detail** — capacidade do app e CTA de launch.

## Conjunto B — Onboarding / autenticação

1. Identidade soberana / início.
2. Escaneamento facial.
3. Prova de vida.
4. Documento oficial / OCR.
5. Confirmar identidade.
6. Passkey + 2FA.
7. Gerando identidade soberana.
8. Face protegida / avatar pronto.
9. Autenticação máxima ativada.
10. Acesso liberado.
11. Escolha do método de autenticação.
12. Entrar com Passkey.
13. Código 2FA.
14. Chave de segurança.
15. Códigos de recuperação.
16. Consentimentos.
17. Vault facial.
18. Auditoria blockchain/provas.
19. Sessões e dispositivos.
20. Tudo pronto / launch.

## Conjunto C — Security Hub

1. Proteção total.
2. Vault de senhas.
3. Cofre de fotos.
4. Contas & redes.
5. Permissões & privacidade.
6. Alertas & ameaças.
7. Backup & recuperação.
8. Modo Pânico.
9. Dispositivos & sessões.
10. Integrações & providers.
11. Facial Vault.
12. Audit viewer.
13. Recovery contacts.
14. Trusted devices.
15. Guardian AI.

## Regras de implementação

- As telas acima viram componentes e dados reais; imagens de referência ficam somente em `docs/ui/approved`.
- Nenhuma tela pode esconder função no desktop/mobile: componentes se reorganizam.
- Não usar logos de upstream como marca AuthLink.
- Rótulos de segurança precisam refletir capacidade real do SO/API.
- Não afirmar que AuthLink lê dados privados de apps terceiros sem integração/entitlement.
- Estados críticos exigem confirmação e, quando necessário, step-up auth.

## IDs de rota sugeridos

```text
/
/feed
/feed/:postId
/chat
/chat/:conversationId
/apps
/apps/:appId
/match
/match/:matchId
/market
/profile
/profile/security
/learning
/settings
/notifications
/security
/security/passwords
/security/media
/security/accounts
/security/permissions
/security/threats
/security/backup
/security/panic
/security/devices
/security/integrations
/security/facial-vault
/security/audit
/auth/start
/auth/face
/auth/liveness
/auth/document
/auth/confirm
/auth/passkey
/auth/2fa
/auth/security-key
/auth/recovery
/auth/consent
/auth/provisioning
/auth/complete
```
