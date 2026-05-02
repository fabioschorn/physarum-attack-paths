# git-scripts

Scripts de automação Git para o **Physarum Attack Paths**.  
Padronizam commits, checkpoints de progresso e releases oficiais.

```
git-scripts/
├── commit.sh       # Commit interativo seguindo Conventional Commits
├── checkpoint.sh   # Bump de versão minor + commit + push (sem release)
└── release.sh      # Release completo: bump + tag + push → GitHub Actions
```

Execute sempre a partir da **raiz do projeto**.

---

## Quando usar cada script

```
Alteração pontual de código   →  commit.sh
Salvar progresso (marco)      →  checkpoint.sh
Publicar release com binários →  release.sh
```

| Script | Versão | Commit | Tag | Push | GitHub Actions |
|--------|--------|--------|-----|------|----------------|
| `commit.sh` | não altera | ✔ | ✗ | ✗ | ✗ |
| `checkpoint.sh` | bump minor/patch | ✔ | ✗ | ✔ | ✗ |
| `release.sh` | bump qualquer | ✔ | ✔ | ✔ | ✔ publica binários |

---

## commit.sh

Guia interativo para criar commits no padrão **Conventional Commits**.  
Executa `cargo fmt` e `cargo test` antes de commitar.

### Uso

```bash
./Utilities/git-scripts/commit.sh [FLAGS]
```

### Flags

| Flag | Comportamento |
|------|---------------|
| _(sem flags)_ | Modo interativo completo com verificações de qualidade |
| `--no-verify` | Pula `cargo fmt` e `cargo test` (commits de emergência) |
| `--help` | Exibe ajuda e sai |

### Formato gerado

```
<tipo>(<escopo>): <descrição curta>

[corpo opcional]
```

**Exemplos:**
```
feat(agent): adiciona loop de probe com RTT
fix: corrige panic no registro duplicado
chore(ci): atualiza matrix de targets no release.yml
docs(protocol): descreve campos do EdgeSnapshot
```

### Tipos disponíveis

| # | Tipo | Quando usar |
|---|------|-------------|
| 1 | `feat` | Nova funcionalidade |
| 2 | `fix` | Correção de bug |
| 3 | `docs` | Apenas documentação |
| 4 | `refactor` | Refatoração sem nova func. e sem bug fix |
| 5 | `test` | Adição ou correção de testes |
| 6 | `chore` | Build, CI/CD, dependências, configuração |
| 7 | `perf` | Melhoria de performance |
| 8 | `style` | Formatação, ponto-e-vírgula (sem mudança de lógica) |

### Fluxo interativo

```
1. Verificação de qualidade
   ├── cargo fmt --check  (oferece autocorreção se fora do padrão)
   └── cargo test --workspace

2. Seleção do tipo [1-8]

3. Escopo opcional (ex: agent, server, protocol, ci)

4. Descrição curta (minúsculas, sem ponto final)

5. Corpo opcional (detalhes adicionais)

6. Preview da mensagem

7. Staging
   ├── [S] git add -A  (todos os arquivos)
   └── [n] staging manual em outro terminal

8. Lista de arquivos no staging

9. Confirmação final → git commit
```

### Verificações de qualidade

- **`cargo fmt --check`**: detecta código fora do padrão de formatação.  
  Se fora do padrão, oferece autocorreção com `cargo fmt`.
- **`cargo test --workspace`**: executa todos os testes do workspace.  
  Se falharem, pergunta se deseja commitar mesmo assim.
- Use `--no-verify` para pular ambas as verificações quando necessário.

---

## checkpoint.sh

Salva o progresso do projeto com um **bump de versão** sem criar uma release oficial.  
Não cria tag — portanto, **não dispara o GitHub Actions**.

Ideal para marcar marcos durante o desenvolvimento (ex: "passos 6–9 implementados").

### Uso

```bash
./Utilities/git-scripts/checkpoint.sh [FLAGS]
```

### Flags

| Flag | Comportamento |
|------|---------------|
| _(sem flags)_ | Bump minor + `git add -A` + commit + push para origin |
| `--minor` | Bump minor explícito: `0.0.1 → 0.1.0` (padrão) |
| `--patch` | Bump patch: `0.0.1 → 0.0.2` |
| `--no-push` | Apenas commit local, sem push |
| `--help` | Exibe ajuda e sai |

### Exemplos

```bash
# Marco de desenvolvimento (mais comum)
./Utilities/git-scripts/checkpoint.sh

# Salvar correção pequena sem incrementar minor
./Utilities/git-scripts/checkpoint.sh --patch

# Commitar localmente sem push (offline ou rede instável)
./Utilities/git-scripts/checkpoint.sh --no-push
```

### Formato do commit gerado

```
chore: checkpoint v0.1.0
```

### Fluxo executado

```
1. Validações
   ├── git disponível
   ├── é um repositório git
   ├── branch atual detectada
   ├── há alterações para salvar
   └── remote origin configurado (ou --no-push ativado)

2. Versão
   ├── lê versão atual do Cargo.toml [workspace.package]
   └── calcula nova versão (minor ou patch)

3. cargo check --workspace
   └── aborta se houver erros de compilação

4. Exibe lista de alterações (git status --short)

5. Confirmação [S/n]

6. Execução
   ├── atualiza versão no Cargo.toml
   ├── git add -A
   ├── git commit -m "chore: checkpoint vX.Y.Z"
   └── git push origin <branch>  (se não --no-push)
```

### Diferença para release.sh

| | checkpoint.sh | release.sh |
|---|---|---|
| Cria tag git | ✗ | ✔ |
| Dispara GitHub Actions | ✗ | ✔ |
| Publica binários | ✗ | ✔ |
| Verificação | `cargo check` (rápido) | `cargo test` (completo) |
| Objetivo | salvar progresso | publicar versão oficial |

---

## release.sh

Executa o **fluxo completo de release**:  
bump de versão → commit → tag anotada → push → GitHub Actions publica binários para 5 plataformas.

### Uso

```bash
./Utilities/git-scripts/release.sh [FLAGS]
```

### Flags

| Flag | Comportamento |
|------|---------------|
| _(sem flags)_ | Menu interativo para escolher o tipo de bump |
| `--patch` | Bump automático patch: `0.0.1 → 0.0.2` |
| `--minor` | Bump automático minor: `0.0.1 → 0.1.0` |
| `--major` | Bump automático major: `0.0.1 → 1.0.0` |
| `--help` | Exibe ajuda e sai |

### Exemplos

```bash
# Modo interativo (recomendado para o primeiro uso)
./Utilities/git-scripts/release.sh

# Bug fixes — automatizado
./Utilities/git-scripts/release.sh --patch

# Nova funcionalidade — automatizado
./Utilities/git-scripts/release.sh --minor

# Breaking change — automatizado
./Utilities/git-scripts/release.sh --major
```

### Formato do commit e tag gerados

```
commit: chore: release v0.2.0
tag:    v0.2.0  (anotada, com mensagem "Release v0.2.0")
```

### Fluxo executado

```
Etapa 1 — Validações
  ├── git disponível
  ├── é um repositório git
  ├── branch atual (avisa se não for main/master)
  ├── working tree limpa (sem alterações não commitadas)
  └── remote origin configurado

Etapa 2 — Versão
  ├── lê versão atual do Cargo.toml
  ├── exibe última tag git
  ├── calcula sugestões de patch/minor/major
  └── aceita versão manual (opção 4 no menu interativo)

Etapa 3 — Testes
  └── cargo test --workspace (aborta se falhar)

Etapa 4 — Confirmação
  └── exibe resumo completo do que será executado [s/N]

Etapa 5 — Execução
  ├── atualiza versão no Cargo.toml
  ├── git add Cargo.toml
  ├── git commit -m "chore: release vX.Y.Z"
  ├── git tag -a vX.Y.Z -m "Release vX.Y.Z"
  ├── git push origin <branch>
  └── git push origin vX.Y.Z  ← dispara o GitHub Actions
```

### O que o GitHub Actions faz após o push da tag

O workflow `.github/workflows/release.yml` é acionado e:

1. **Cria** um rascunho de Release no GitHub
2. **Compila** em paralelo para 5 plataformas:

   | Plataforma | Runner | Método |
   |------------|--------|--------|
   | macOS Apple Silicon (`aarch64-apple-darwin`) | `macos-latest` | `cargo build` |
   | macOS Intel (`x86_64-apple-darwin`) | `macos-13` | `cargo build` |
   | Linux x86_64 (`x86_64-unknown-linux-gnu`) | `ubuntu-latest` | `cargo build` |
   | Linux ARM64 (`aarch64-unknown-linux-gnu`) | `ubuntu-latest` | `cross build` |
   | Windows x86_64 (`x86_64-pc-windows-msvc`) | `windows-latest` | `cargo build` |

3. **Empacota**: `.tar.gz` (Unix) ou `.zip` (Windows), incluindo `README` + `LICENSE` + `NOTICE`
4. **Publica** a Release (sai do modo draft)

> Acompanhe o progresso em: `https://github.com/<owner>/physarum-attack-paths/actions`

### Pré-requisitos para o release funcionar

- Branch `main` (ou confirmar aviso se outra branch)
- Working tree limpa — use `commit.sh` ou `checkpoint.sh` antes
- Remote `origin` configurado: `git remote add origin <url>`
- `GITHUB_TOKEN` disponível (configurado automaticamente pelo GitHub Actions)

---

## Fluxo completo de desenvolvimento

```bash
# 1. Novo trabalho: verificar ambiente
./Utilities/check-env.sh

# 2. Desenvolver...

# 3. Commitar alteração pontual
./Utilities/git-scripts/commit.sh

# 4. Marco de progresso (ex: passos 6-9 implementados)
./Utilities/git-scripts/checkpoint.sh

# 5. Quando pronto para release oficial
./Utilities/git-scripts/release.sh --minor
#    └── GitHub Actions compila e publica automaticamente
```
