# Utilities

Scripts de suporte ao desenvolvimento do **Physarum Attack Paths**.  
Todos os scripts devem ser executados a partir da **raiz do projeto**.

```
Utilities/
├── check-env.sh     # Valida o ambiente de desenvolvimento
├── build.sh         # Compila, testa e inspeciona o workspace
├── dist-local.sh    # Empacota o binário para distribuição local
└── git-scripts/     # Automação de commits, checkpoints e releases
```

---

## check-env.sh

Verifica se o ambiente local está corretamente configurado para compilar e executar o projeto.  
Execute este script **antes de qualquer outra coisa** em uma máquina nova.

### Uso

```bash
./Utilities/check-env.sh
```

Não aceita flags. Executa sempre em modo interativo (somente leitura — não modifica nada).

### O que é verificado

| # | Verificação | O que detecta |
|---|-------------|---------------|
| 1 | Sistema operacional | macOS ou Linux suportado |
| 2 | Xcode Command Line Tools | Necessário para o linker C no macOS |
| 3 | Linker C (`cc`) | Dependência indireta do compilador Rust |
| 4 | `curl` | Necessário para instalar o rustup, se ausente |
| 5 | `rustup` | Gerenciador de toolchains Rust |
| 6 | `rustc` versão ≥ 1.78 | Versão mínima exigida pelo projeto |
| 7 | `cargo` | Presente e acessível no PATH |
| 8 | PATH inclui `~/.cargo/bin` | Evita o erro "command not found" após instalar rustup |
| 9 | Toolchain ativo | Confirma que o toolchain padrão está funcional |
| 10 | `git` | Necessário para clonar e versionar |
| 11 | Estrutura do projeto | Verifica `Cargo.toml`, `crates/`, `.github/` |
| 12 | Workspace válido | `cargo metadata` confirma que o workspace compila |

### Saída

```
  [✔] git disponível
  [✔] rustc 1.95.0 (versão OK — mínimo: 1.78)
  [✘] Xcode Command Line Tools não encontrados
       → Instale com: xcode-select --install
```

Cada check exibe `✔` (verde), `✘` (vermelho com dica de correção) ou `⚠` (aviso não bloqueante).

---

## build.sh

Automatiza os passos de compilação, testes e inspeção do workspace Rust.  
Equivalente a rodar `cargo build + cargo test + cargo clippy` com output formatado.

### Uso

```bash
./Utilities/build.sh [FLAGS]
```

### Flags

| Flag | Comportamento |
|------|---------------|
| _(sem flags)_ | Build debug + testes + lista binários gerados |
| `--release` | Build otimizado (`cargo build --release`) + testes |
| `--check` | Só verifica se compila (`cargo check`), sem gerar binário |
| `--no-test` | Build sem executar testes |
| `--clippy` | Executa `cargo clippy` após o build (lint com warnings como erros) |
| `--help` | Exibe ajuda e sai |

### Exemplos

```bash
# Verificação rápida durante desenvolvimento
./Utilities/build.sh --check

# Build completo para validar antes de um commit
./Utilities/build.sh --clippy

# Gerar binário otimizado para testes de performance
./Utilities/build.sh --release --no-test
```

### O que o script faz

1. Detecta a raiz do projeto via `BASH_SOURCE`
2. Executa `cargo build` (ou `--release` / `--check`)
3. Executa `cargo test --workspace` (a menos que `--no-test` esteja ativo)
4. Executa `cargo clippy` (se `--clippy` estiver ativo)
5. Lista os binários gerados em `target/release/` ou `target/debug/` com tamanho

### Saída esperada

```
── Etapa 1 — Build
  Executando: cargo build --workspace
  [✔] Build concluído (12.4s)

── Etapa 2 — Testes
  [✔] 4/4 testes passaram

── Binários gerados
  physarum-server   11M   target/debug/physarum-server
```

---

## dist-local.sh

Simula localmente o que o GitHub Actions faz no `release.yml`:  
compila em modo release, empacota o binário com README/LICENSE/NOTICE  
e gera um `.tar.gz` pronto para distribuição — apenas para a plataforma atual.

### Uso

```bash
./Utilities/dist-local.sh [FLAGS]
```

### Flags

| Flag | Comportamento |
|------|---------------|
| _(sem flags)_ | Usa a tag git atual como versão (ou `dev` se não houver tag) |
| `--version <ver>` | Define a versão manualmente (ex: `--version v0.2.0`) |

### Exemplos

```bash
# Empacotar com versão detectada pela tag git
./Utilities/dist-local.sh

# Empacotar com versão explícita para testes
./Utilities/dist-local.sh --version v0.3.0-beta
```

### Targets suportados

| Sistema | Arquitetura | Target Rust |
|---------|-------------|-------------|
| macOS | Apple Silicon | `aarch64-apple-darwin` |
| macOS | Intel x86_64 | `x86_64-apple-darwin` |
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` |

### O que o script faz

1. **Detecta** a plataforma atual e o target Rust correspondente
2. **Detecta a versão**: argumento `--version` > tag git (`git describe --tags --exact-match`) > `dev`
3. **Build release**: `cargo build --release -p physarum-server`
4. **Empacota**: cria `dist/<nome>.tar.gz` com binário + README + LICENSE + NOTICE
5. **Verifica**: extrai o `.tar.gz` em um tmpdir e confirma que o binário é executável

### Saída

```
dist/
└── physarum-server-v0.2.0-aarch64-apple-darwin.tar.gz
```

> Para publicar para todas as plataformas, use o fluxo de release via `git-scripts/release.sh`,
> que dispara o GitHub Actions e compila para 5 targets simultaneamente.

---

## Fluxo recomendado

```
1. Máquina nova?
   ./Utilities/check-env.sh

2. Durante o desenvolvimento:
   ./Utilities/build.sh --check          # rápido, só valida compilação
   ./Utilities/build.sh --clippy         # completo, antes de commitar

3. Salvar progresso:
   ./Utilities/git-scripts/checkpoint.sh

4. Testar empacotamento local:
   ./Utilities/dist-local.sh

5. Publicar release oficial:
   ./Utilities/git-scripts/release.sh --minor
```
