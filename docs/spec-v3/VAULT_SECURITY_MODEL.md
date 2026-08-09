# AuthLink Vault — Security Model V3

## Autoridade e fronteiras

O AuthLink Vault **não cria identidade, não autentica usuários e não emite sessões**. Ele aceita somente a sessão opaca `authlink_session` emitida pelo AuthLink Gateway, carrega essa sessão no PostgreSQL e aplica a relação OpenFGA da identidade antes de tocar em qualquer item.

- leitura/listagem: `identity.can_read`
- criação/rotação/exclusão: `identity.can_manage`
- lookup no banco: sempre `tenant_id + identity_id + item_id`
- produção: sem fallback de memória e sem bypass implícito

## Envelope encryption

Cada item recebe uma DEK aleatória de 256 bits. O payload é criptografado com XChaCha20-Poly1305 e nonce aleatório de 192 bits. A DEK é então criptografada por uma master key versionada, com outro nonce aleatório independente.

O PostgreSQL recebe somente:

- algoritmo e versão do formato;
- versão da master key usada para embrulhar a DEK;
- nonce do payload;
- ciphertext autenticado do payload;
- nonce do wrap;
- DEK criptografada.

A master key nunca é gravada na tabela `authlink.vault_item`.

## Associated Authenticated Data

O AAD do payload inclui:

`tenant_id + identity_id + item_id + purpose`

O AAD da DEK inclui:

`tenant_id + identity_id + item_id + key_version`

Consequências:

1. copiar ciphertext para outra identidade falha na autenticação;
2. trocar a finalidade registrada de um item faz a decriptação falhar;
3. trocar a versão da chave ou a DEK embrulhada sem a chave correta falha;
4. adulteração de ciphertext/nonce é detectada pelo AEAD.

## Rotação

O key ring pode manter múltiplas versões de master key. Uma versão é marcada ativa para novas gravações.

A rotação de um item:

1. decripta somente a DEK usando a versão antiga;
2. gera um novo nonce de wrap;
3. criptografa a mesma DEK com a master key ativa;
4. preserva `ciphertext_b64` e `payload_nonce_b64` sem reprocessar o payload;
5. persiste usando optimistic check da versão antiga.

Uma master key antiga só pode ser removida do secret manager depois que nenhum envelope ativo referenciar sua versão.

## Dados em memória

`MasterKey` é zerada no drop. DEKs e buffers plaintext produzidos pela camada criptográfica usam `zeroize::Zeroizing`. O serviço não inclui payload secreto em logs nem em mensagens de erro; falhas internas recebem correlation ID.

Dados devolvidos legitimamente ao cliente precisam existir temporariamente no stack HTTP para serialização/transporte. Por isso respostas do Vault usam `Cache-Control: no-store` e o serviço depende de TLS em produção.

## Limites deste slice

O contrato de key ring usa `AUTHLINK_VAULT_KEYS` para desenvolvimento/CI. Isso **não** significa que produção deve armazenar master keys em `.env`. O formato foi separado da custódia para permitir adapter posterior para HSM, KMS, Secure Enclave/TPM ou secret manager sem recriptografar o banco inteiro.

## Provas automatizadas

Os testes cobrem:

- encrypt/decrypt;
- adulteração de ciphertext;
- tentativa de decrypt por identidade diferente;
- mudança de purpose;
- master key errada;
- decrypt de versões antigas via key ring;
- rewrap para versão ativa preservando o ciphertext do payload;
- lifecycle PostgreSQL owner-scoped;
- consulta direta de `envelope::text` confirmando ausência do username/senha plaintext usado no teste;
- soft-delete e impossibilidade de leitura posterior.
