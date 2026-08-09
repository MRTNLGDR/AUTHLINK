# AuthLink Trusted Device — Security Model V3

## Objetivo

Trusted Device aumenta a confiança de uma sessão AuthLink somente depois de uma prova criptográfica de posse. O mecanismo deste slice prova **posse de uma chave P-256 do cliente**. Ele deliberadamente não afirma hardware attestation nem passkey/WebAuthn assertion atual.

## Fronteiras de autoridade

- Gateway AuthLink cria identidade e sessão opaca.
- Device Service não emite sessão nem autentica usuário.
- Device Service aceita somente `authlink_session`, carrega a sessão canônica no PostgreSQL e aplica OpenFGA.
- PostgreSQL mantém challenge, public key, trust state e associação sessão-device.
- OpenFGA mantém relação `user:<identity_uuid> owner device:<device_uuid>`.
- private key nunca é enviada ao servidor.

## Chave do navegador

O PWA usa WebCrypto:

- algoritmo: ECDSA P-256/SHA-256;
- private key: `extractable=false`;
- persistência: structured-clone de `CryptoKey` no IndexedDB;
- exportação: somente public JWK `kty=EC`, `crv=P-256`, `x`, `y`;
- identificador do device: SHA-256 do public key SEC1, codificado base64url.

Isso reduz exposição da private key pela própria aplicação, mas não equivale a prova de Secure Enclave, TPM ou Android Keystore.

## Challenge

Cada challenge tem 32 bytes aleatórios e TTL de 120 segundos. A mensagem assinada é canônica e inclui:

`version + challenge_id + session_id + identity_id + action + nonce`

A ação é `enroll` ou `bind-session`. Consequências:

1. assinatura de outro usuário não serve;
2. challenge roubado de outra sessão não serve;
3. assinatura de enrollment não pode ser reutilizada como bind;
4. challenge é consumido atomicamente no PostgreSQL e não aceita replay;
5. challenge expirado não é aceito.

## Enrollment

Enrollment é ação explícita. O PWA não cria automaticamente uma nova chave depois de revogação.

Fluxo:

1. sessão AuthLink válida;
2. `identity.can_manage` no OpenFGA;
3. servidor gera challenge single-use;
4. browser gera chave P-256 não-exportável e assina;
5. servidor verifica a assinatura e calcula fingerprint;
6. device entra como `pending`;
7. AuthLink garante tuple OpenFGA `owner` do device;
8. PostgreSQL marca o device `trusted`;
9. sessão é ligada ao device e sobe para `oidc+device-possession`.

Se a relação OpenFGA falhar, o device não é promovido a trusted.

## Rebind

Em nova sessão, um browser que ainda possui a private key pode pedir challenge para o `device_id`, assinar e religar a sessão. Não é criada nova chave silenciosamente.

## Revogação

Revogar device:

- muda `trust_state` para `revoked`;
- grava `revoked_at`;
- revoga todas as sessões ativas ligadas ao device na mesma transação;
- o mesmo fingerprint público revogado não pode ser reativado por `upsert` silencioso.

Um novo enrollment exige nova ação explícita e, no desenho atual, uma nova chave.

## Assurance

Estados deliberadamente distintos:

- `oidc`: sessão autenticada via provedor;
- `oidc+device-possession`: OIDC + prova da private key local;
- `passkey`: reservado para assertion WebAuthn/passkey comprovada;
- `attested-device`: reservado para attestation nativa validada;
- `step-up`: reservado para política que exigiu e comprovou fator adicional.

O Rauthy v0.36 pode expor `amr=mfa`, mas isso não é suficiente para afirmar que a autenticação corrente usou uma passkey. AuthLink não eleva a sessão para passkey com base apenas nesse rótulo.

## Ameaças mitigadas

- replay do challenge;
- transplante de assinatura entre sessão/identidade/ação;
- confiança baseada somente em cookie;
- ressurreição silenciosa de chave explicitamente revogada;
- uso de device de outra identidade por lookup owner-scoped + OpenFGA;
- exposição de private key ao backend.

## Limites deste slice

- WebCrypto não comprova hardware-backed storage;
- XSS dentro da origem ainda pode abusar de uma CryptoKey enquanto a página comprometida estiver executando, mesmo sem exportá-la;
- device fingerprint é pseudônimo técnico e deve continuar tratado como dado de segurança;
- proteção contra malware/comprometimento do SO exige attestation e adapters nativos posteriores;
- passkey verdadeira exige WebAuthn assertion validada com challenge AuthLink específico.

## Provas automatizadas

- assinatura ECDSA P-256 válida;
- adulteração/requisição em contexto diferente falha;
- challenge single-use não aceita replay;
- bind só funciona com device trusted do mesmo owner;
- sessão recebe `trusted_device_id` e `oidc+device-possession` somente após trust;
- revogação do device revoga sessões ligadas;
- fingerprint revogado não é reativado silenciosamente;
- runtime smoke inicia `authlink-device-service` e verifica `ECDSA-P256-SHA256`.
