# VTM 5e d20 Mesa Virtual — Supabase + Vercel

## O que este pacote faz
- Preserva a interface gótica e as ferramentas existentes da mesa.
- Usa Supabase Auth (e-mail/senha) para autenticar participantes.
- Cria salas via RPC com código de 6 caracteres, senha do Narrador e senha de convite.
- Persiste o estado compartilhado no Postgres; apenas o Narrador pode atualizar o estado global.
- Sincroniza o estado e o chat via Supabase Realtime.
- Não usa servidor WebSocket próprio, nem depende de escrita em disco local, compatível com hospedagem estática da Vercel.

## Etapa 1 — preparar Supabase
1. Abra o projeto Supabase.
2. Em **Authentication → Providers**, habilite **Email**.
3. Abra **SQL Editor → New query**.
4. Cole todo o conteúdo de `01_schema.sql` e execute.
5. Em **Project Settings → API**, copie o Project URL e a chave **publishable** (ou a chave `anon` legada). Nunca use `service_role` no navegador.

## Etapa 2 — publicar na Vercel
1. Importe esta pasta para um repositório Git (GitHub/GitLab/Bitbucket) ou envie `index.html` como site estático.
2. Na Vercel, crie um projeto estático com `index.html` na raiz. Não configure build command nem output directory.
3. A página solicitará o Project URL e a chave pública na primeira abertura. Esses dados ficam no armazenamento local daquele navegador; cada participante precisa configurá-los uma vez.
4. Na mesa, clique em **Criar conta**, confirme o e-mail se o projeto exigir confirmação e depois clique em **Entrar**.
5. O Narrador cria a sala e compartilha o código e a senha de convite com 1–2 jogadores. Os jogadores criam suas próprias contas, entram e usam o código/senha.

## Limites e segurança
- A chave pública/anon pode estar no frontend; a `service_role` nunca deve estar nele.
- O SQL usa RLS e RPCs `SECURITY DEFINER` para controlar criação/entrada e evita recursão de RLS na política de membros.
- O estado global é editável apenas pelo Narrador. A propriedade granular de fichas individuais por jogador ainda é uma camada futura; nesta versão, a sincronização do estado completo é controlada pelo Narrador.
- Teste com duas contas diferentes antes de usar em uma crônica real.

## Estado de implantação
Projeto Supabase criado, esquema SQL aplicado e confirmado na lista de migrações. Projeto Vercel criado, mas o deploy ainda depende de enviar os arquivos de origem (via repositório Git conectado ou upload de arquivos) e verificar a URL publicada.