# AuthLink Passkey / WebAuthn — Security Model V3

## Objetivo

A assurance `passkey` só existe quando o AuthLink valida uma **assertion WebAuthn atual**, com challenge AuthLink single-use, RP ID/origin esperados e `userVerification=required`.

Ela é diferente de:

- `oidc`: sessão autenticada pelo provedor;
- `oidc+device-possession`: sessão OIDC mais prova da chave P-256 do Trusted Device;
- `mfa`: informação genérica do IdP, insuficiente para afirmar que WebAuthn foi usado nesta operação;
- `attested-device`: reservado a attestation nativa/hardware validada;
- `passkey`: assertion WebAuthn verificada pelo AuthLink.

## Separação de autoridade

O slice usa um adapter MIT `@simplewebauthn/server` somente para a validação normativa da cerimônia WebAuthn. O adapter é stateless.

O Rust AuthLink continua sendo autoridade para:

- sessão;
- identidade;
- autorização OpenFGA;
- geração criptograficamente aleatória do challenge;
- persistência/consumo single-use do challenge;
- credential ID;
- COSE credential public key;
- sign counter;
- credential state/revogação;
- decisão de elevar `auth_strength`.

O adapter não recebe banco, cookie de sessão nem private key e não pode promover uma sessão sozinho.

## Registration

1. sessão AuthLink ativa e `identity.can_manage`;
2. Rust gera 32 bytes aleatórios e persiste challenge `register` com TTL de 120 segundos;
3. Rust entrega o challenge ao adapter para gerar `PublicKeyCredentialCreationOptions`;
4. PWA chama WebAuthn pelo navegador;
5. resposta volta ao Rust;
6. Rust consome o challenge atomicamente;
7. adapter verifica challenge, origin, RP ID, user presence e `userVerification=required`;
8. Rust persiste apenas credential ID, COSE public key, counter e metadados necessários.

**Registration não eleva a sessão para `passkey`.** Cadastro prova que uma nova credential foi criada corretamente; não deve ser confundido com uma assertion corrente usada para autenticar/step-up a sessão.

O fluxo pede resident/discoverable credential e usa `attestationType=none` por padrão para reduzir coleta de identificadores de autenticador. Por isso o AuthLink não afirma hardware attestation neste slice.

## Authentication / assertion

1. sessão AuthLink ativa e `identity.can_read`;
2. Rust busca somente credentials ativas do mesmo tenant/identity;
3. Rust gera/persiste challenge `authenticate` single-use;
4. adapter gera `PublicKeyCredentialRequestOptions` com `userVerification=required`;
5. navegador/autenticador produz a assertion;
6. Rust carrega a credential do mesmo owner antes da validação;
7. Rust consome o challenge;
8. adapter verifica assinatura WebAuthn, RP ID, origin, flags e counter contra a public key COSE armazenada;
9. Rust atualiza o counter com optimistic check;
10. somente então Rust grava `assurance_evidence.webauthn` e eleva a sessão para:
   - `passkey`, ou
   - `passkey+device-possession` quando a sessão também está ligada a Trusted Device.

## Counter

O counter armazenado pertence ao estado canônico Rust/PostgreSQL. A atualização usa o counter anterior como condição. Isso impede duas respostas concorrentes de avançarem o mesmo estado silenciosamente.

Authenticators sincronizados/multi-device podem ter comportamento de counter diferente de tokens físicos. A validação normativa fica no verifier WebAuthn, enquanto o AuthLink persiste exatamente o `newCounter` aceito pela validação.

## RP e origin

Desenvolvimento local:

- RP ID: `localhost`
- origin: `http://localhost:5173`

Produção precisa configurar host HTTPS real. O AuthLink nunca aceita origin enviado pelo cliente como autoridade; origin/RP esperados vêm da configuração do serviço.

## Private key

A private key da passkey fica no autenticador/WebAuthn. AuthLink nunca a recebe e não possui endpoint para importá-la/exportá-la.

O banco guarda:

- credential ID;
- COSE public key;
- counter;
- transports;
- AAGUID/attestation format quando presentes no resultado de registro;
- device type/backed-up conforme resultado validado.

Credential ID e AAGUID são dados de segurança/pseudônimos e devem respeitar minimização e retenção.

## Revogação

A credential pode ser marcada `revoked`; ela deixa de aparecer nas opções e de ser carregada para assertion. Revogar uma passkey não recria automaticamente outra.

## Relação com Trusted Device

Trusted Device e Passkey são evidências independentes:

- Trusted Device comprova posse da private key P-256 registrada pelo AuthLink;
- Passkey comprova uma assertion WebAuthn do autenticador;
- a sessão pode ter uma, outra ou ambas;
- a composição fica explícita no `auth_strength` e em `assurance_evidence`.

## Ameaças mitigadas

- replay de registration/authentication challenge;
- challenge transplantado entre sessão/identidade/ação;
- credential de outro owner;
- origin/RP phishing mismatch;
- elevação por simples cadastro sem assertion;
- elevação por `mfa` genérico do IdP;
- counter update concorrente silencioso;
- adapter JavaScript virando uma segunda autoridade de sessão.

## Limites deste slice

- `attestationType=none`: não há claim de hardware provenance;
- a primeira aplicação deste fluxo é step-up de uma sessão AuthLink já autenticada; login passwordless inicial pode reutilizar a mesma credential em slice posterior, com ceremony própria;
- recuperação, account recovery e credential replacement precisam política separada para não virar bypass;
- produção exige HTTPS e RP/origin estáveis.

## Provas automatizadas previstas/implementadas

- challenge PostgreSQL é single-use;
- credential é owner-scoped;
- counter optimistic update rejeita estado stale;
- registration não muda `auth_strength`;
- método Rust de assertion verificada escreve `passkey`;
- revogação remove credential das leituras ativas;
- verifier sobe stateless;
- Rust Passkey só inicia com verifier alcançável;
- runtime smoke valida RP, origin, UV required e assurance `webauthn-assertion`.
