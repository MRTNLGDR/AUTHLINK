# Telas aprovadas — referência visual

As quatro telas âncora aprovadas nesta conversa definem o padrão visual do AuthLink mobile-first:

1. Feed / Home
2. Descobrir / Match
3. Mercado / Oportunidades
4. Apps do plano

Regras derivadas dessas referências:
- topbar AuthLink fixa e enxuta;
- fundo preto profundo, acento `#9FE82F`, azul apenas como estado secundário;
- cards densos, bordas finas e glow contido;
- navegação inferior `Feed · Chat · Apps · Match · Perfil`;
- conteúdo social em primeiro nível; segurança e identidade acessíveis sem dominar a experiência;
- responsivo para desktop preservando a gramática mobile-first.

## Mapeamento para código

- `#/feed` → Feed/Home aprovado
- `#/match` → Descobrir/Match aprovado
- `#/apps` → Apps do plano aprovado
- Mercado/Oportunidades será consolidado no domínio social/market sem alterar o shell aprovado.
- `#/security`, `#/passwords`, `#/photos`, `#/accounts`, `#/privacy`, `#/alerts`, `#/backup`, `#/panic`, `#/devices` e `#/integrations` seguem a mesma gramática visual.

Os mockups aprovados são referência de visual regression; o produto real deve ser gerado a partir dos componentes tipados, não por imagens estáticas.
