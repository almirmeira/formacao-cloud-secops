# Módulo 00 — Preparação do Ambiente de Laboratório
## Google SecOps Essentials · CECyber

> **⚠️ IMPORTANTE:** Este módulo deve ser concluído **antes** de iniciar qualquer outro módulo
> ou laboratório do curso. Todo o conteúdo prático depende do ambiente configurado aqui.

---

## Visão Geral

Este módulo guia você na criação e configuração completa do ambiente de laboratório que será
utilizado ao longo dos 30h do curso Google SecOps Essentials. Ao final deste módulo, você terá:

- Uma conta Google Cloud com Google SecOps habilitado
- Um tenant Google SecOps (Chronicle) configurado e funcional
- Dados de log sintéticos do cenário "Banco Meridian" ingeridos e indexados
- Ferramentas de linha de comando instaladas e configuradas
- Permissões de IAM configuradas corretamente
- Ambiente validado e pronto para os laboratórios

**Duração estimada:** 2 horas  
**Pré-condições:** Conta Google (Gmail) ativa · Cartão de crédito para free trial (sem cobrança durante o curso)

---

## Topologia do Ambiente de Laboratório

```svg
```
<!-- Diagrama embutido como texto para referência -->
```
┌─────────────────────────────────────────────────────────────────────────┐
│                     AMBIENTE DE LABORATÓRIO - MÓDULO 00                  │
│                    Banco Meridian (Instituição Fictícia)                  │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  GOOGLE CLOUD PROJECT: cecyber-secops-lab-[SEU-ID]               │   │
│  │                                                                   │   │
│  │  ┌─────────────────────┐   ┌──────────────────────────────────┐  │   │
│  │  │  GOOGLE SECOPS       │   │  GOOGLE CLOUD STORAGE            │  │   │
│  │  │  (Chronicle)         │   │  (Bucket de Logs Sintéticos)     │  │   │
│  │  │                      │   │                                  │  │   │
│  │  │  • SIEM              │◄──│  • Windows Event Logs            │  │   │
│  │  │  • SOAR              │   │  • Linux Syslog                  │  │   │
│  │  │  • Threat Intel      │   │  • Firewall Logs                 │  │   │
│  │  │  • UEBA              │   │  • DNS Logs                      │  │   │
│  │  └─────────────────────┘   └──────────────────────────────────┘  │   │
│  │            ▲                              ▲                        │   │
│  │            │                              │                        │   │
│  │  ┌─────────────────────┐   ┌──────────────────────────────────┐  │   │
│  │  │  BINDPLANE AGENT     │   │  SCRIPTS DE INGESTÃO            │  │   │
│  │  │  (sua máquina local) │   │  (bucket → chronicle feed)      │  │   │
│  │  └─────────────────────┘   └──────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  FERRAMENTAS LOCAIS (sua máquina)                                        │
│  • Google Cloud SDK (gcloud)  • Python 3.10+  • Git  • VS Code          │
│  • Chronicle CLI              • curl / jq     • Bindplane Agent          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Pré-requisitos do Sistema

Antes de começar, verifique se sua máquina atende aos requisitos:

| Requisito          | Mínimo                     | Recomendado                 |
|:-------------------|:---------------------------|:----------------------------|
| **Sistema Operacional** | Windows 10/11, macOS 12+, Ubuntu 20.04+ | Ubuntu 22.04 LTS ou macOS 13+ |
| **RAM**            | 4 GB disponíveis           | 8 GB ou mais                |
| **Espaço em Disco**| 5 GB livres                | 10 GB livres                |
| **Navegador**      | Chrome 110+ ou Edge 110+   | Chrome (última versão)      |
| **Conexão**        | 10 Mbps estável            | 25 Mbps ou mais             |
| **Conta Google**   | Conta Gmail ativa          | Conta Gmail dedicada ao lab |

---

## Etapa 1 — Criar Conta e Projeto no Google Cloud

### 1.1 Criar conta Google Cloud

**Passo 1:** Acesse cloud.google.com e clique em "Get started for free"

**Passo 2:** Faça login com sua conta Google (Gmail)

**Passo 3:** Preencha o formulário de cadastro:
- País: Brasil
- Tipo de conta: Individual
- Dados de pagamento: necessário para ativar o trial (não haverá cobrança durante o curso)

**Passo 4:** Ao concluir, você receberá US$ 300,00 em créditos válidos por 90 dias

> **✅ Verificação:** Você deve ver o console do Google Cloud com a mensagem "Você tem US$300 em créditos gratuitos"

**O que fazer se der errado:**
- Problema: "Esta conta já usou o período de avaliação gratuita" → Use uma conta Gmail diferente ou entre em contato com o suporte CECyber para obter um tenant pré-provisionado
- Problema: Cartão recusado → Tente um cartão de débito virtual (Nubank, Inter, C6 Bank funcionam bem)

---

### 1.2 Criar o Projeto de Laboratório

**Passo 1:** No console do Google Cloud, clique no seletor de projetos (canto superior esquerdo)

**Passo 2:** Clique em "Novo projeto"

**Passo 3:** Preencha os campos:
```
Nome do projeto: cecyber-secops-lab
ID do projeto:   cecyber-secops-lab-[iniciais]-[ano]
                 Exemplo: cecyber-secops-lab-jps-2026
Organização:     (deixe em branco para conta pessoal)
Local:           (deixe em branco)
```

**Passo 4:** Clique em "Criar"

**Passo 5:** Aguarde a criação (30–60 segundos) e selecione o projeto criado

> **✅ Verificação:** O nome do projeto deve aparecer no canto superior esquerdo do console.
> Execute no Cloud Shell: `gcloud config get-value project`
> Resultado esperado: `cecyber-secops-lab-[iniciais]-[ano]`

---

## Etapa 2 — Instalar o Google Cloud SDK (gcloud CLI)

### 2.1 Instalação no Linux/macOS

**Passo 1:** Abra o terminal

**Passo 2:** Execute o instalador automático:
```bash
curl https://sdk.cloud.google.com | bash
```

**Passo 3:** Reinicie o terminal para que as variáveis de ambiente sejam carregadas:
```bash
exec -l $SHELL
```

**Passo 4:** Inicialize o SDK e faça login:
```bash
gcloud init
```

Siga as instruções interativas:
- Faça login com a conta Google usada para criar o projeto
- Selecione o projeto criado na Etapa 1
- Defina a região padrão: `us-central1`

### 2.2 Instalação no Windows

**Passo 1:** Acesse cloud.google.com/sdk/docs/install e baixe o instalador para Windows

**Passo 2:** Execute o instalador `.exe` e siga o assistente (aceite todas as configurações padrão)

**Passo 3:** Ao final da instalação, o instalador abrirá automaticamente o terminal com o comando de inicialização:
```powershell
gcloud init
```

**Passo 4:** Siga as instruções interativas (mesmo processo do Linux/macOS acima)

> **✅ Verificação:** Execute `gcloud --version`
> Resultado esperado (exemplo):
> ```
> Google Cloud SDK 460.0.0
> bq 2.1.0
> core 2024.01.10
> gcloud-crc32c 1.0.0
> gsutil 5.27
> ```

**O que fazer se der errado:**
- Erro: `command not found: gcloud` → Feche e reabra o terminal; se persistir, adicione manualmente ao PATH: `export PATH=$PATH:/path/to/google-cloud-sdk/bin`
- Erro: `ERROR: (gcloud.init) You must be logged in...` → Execute `gcloud auth login` e faça login pelo navegador

---

## Etapa 3 — Habilitar as APIs Necessárias

**Passo 1:** Com o projeto selecionado, habilite todas as APIs necessárias de uma vez:

```bash
gcloud services enable \
  chronicle.googleapis.com \
  cloudstorage.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  pubsub.googleapis.com \
  compute.googleapis.com
```

**Resultado esperado:**
```
Operation "operations/acat.XXXXX" finished successfully.
```

**Passo 2:** Verifique que todas as APIs foram habilitadas:
```bash
gcloud services list --enabled --filter="name:(chronicle OR storage OR iam)"
```

**Resultado esperado:** 3 ou mais serviços listados como `ENABLED`

> **⏱️ Tempo estimado:** 2–5 minutos para habilitação completa

**O que fazer se der errado:**
- Erro: `PERMISSION_DENIED: The caller does not have permission` → Certifique-se de que está usando a conta de proprietário do projeto: `gcloud auth list`
- Erro: `Billing account not configured` → Acesse console.cloud.google.com > Faturamento e vincule sua conta de faturamento ao projeto

---

## Etapa 4 — Provisionar o Tenant Google SecOps

> **📝 Nota:** O Google SecOps (Chronicle) requer provisionamento via solicitação formal para ambientes de produção. Para o laboratório, você utilizará o **tenant de demonstração CECyber** provisionado antecipadamente, com acesso fornecido pelo instrutor.

### 4.1 Receber credenciais de acesso ao tenant de laboratório

Você receberá por e-mail (endereço cadastrado no LMS) as seguintes informações:
```
CHRONICLE_TENANT_URL: https://[seu-tenant].chronicle.security
CHRONICLE_USERNAME:   [seu-usuario]@cecyber-lab.com
CHRONICLE_PASSWORD:   [senha-temporária]
API_KEY:             [chave-api-do-seu-tenant]
```

> **🔐 Segurança:** Nunca compartilhe essas credenciais. Cada aluno tem um tenant isolado.

### 4.2 Primeiro acesso ao Google SecOps

**Passo 1:** Abra o Chrome (recomendado) e acesse a URL do seu tenant:
```
https://[seu-tenant].chronicle.security
```

**Passo 2:** Faça login com as credenciais fornecidas

**Passo 3:** Na primeira vez, o sistema pedirá para redefinir a senha:
- Nova senha deve ter: mínimo 12 caracteres, letras maiúsculas e minúsculas, números e caracteres especiais
- Exemplo de formato seguro: `SecOps@Lab2026!`
- **Anote esta senha** — você precisará dela em todos os laboratórios

**Passo 4:** Aceite os termos de uso do tenant de demonstração

> **✅ Verificação:** Você deve ver o dashboard principal do Google SecOps com o logo "Banco Meridian SOC" no canto superior

**O que fazer se der errado:**
- E-mail de credenciais não chegou → Verifique a pasta de spam/lixo eletrônico; se não encontrar, contate o suporte CECyber via plataforma LMS
- Erro de login: "Invalid credentials" → Certifique-se de copiar a senha sem espaços extras; use Ctrl+A para selecionar tudo

---

## Etapa 5 — Configurar Variáveis de Ambiente

Configure as variáveis que serão usadas em todos os laboratórios do curso:

### Linux / macOS — adicionar ao `~/.bashrc` ou `~/.zshrc`:

```bash
# ================================================================
# CECyber — Google SecOps Lab — Variáveis de Ambiente
# Adicione ao final do arquivo ~/.bashrc (Linux) ou ~/.zshrc (macOS)
# ================================================================

# Projeto Google Cloud
export GOOGLE_PROJECT_ID="cecyber-secops-lab-[iniciais]-[ano]"
export GOOGLE_REGION="us-central1"

# Google SecOps (Chronicle)
export CHRONICLE_TENANT_URL="https://[seu-tenant].chronicle.security"
export CHRONICLE_API_KEY="[sua-api-key]"

# Bucket de logs sintéticos
export LOGS_BUCKET="gs://cecyber-secops-logs-$GOOGLE_PROJECT_ID"

# Diretório de trabalho dos labs
export LAB_DIR="$HOME/cecyber-labs/google-secops"

echo "✅ Variáveis CECyber Google SecOps carregadas"
```

**Aplicar as variáveis imediatamente:**
```bash
source ~/.bashrc
# ou
source ~/.zshrc
```

### Windows (PowerShell) — adicionar ao perfil:

```powershell
# Abra o PowerShell e edite o perfil:
notepad $PROFILE

# Adicione ao final do arquivo:
$env:GOOGLE_PROJECT_ID = "cecyber-secops-lab-[iniciais]-[ano]"
$env:GOOGLE_REGION = "us-central1"
$env:CHRONICLE_TENANT_URL = "https://[seu-tenant].chronicle.security"
$env:CHRONICLE_API_KEY = "[sua-api-key]"
$env:LOGS_BUCKET = "gs://cecyber-secops-logs-$env:GOOGLE_PROJECT_ID"
$env:LAB_DIR = "$HOME\cecyber-labs\google-secops"

Write-Host "✅ Variáveis CECyber Google SecOps carregadas" -ForegroundColor Green
```

> **✅ Verificação:**
> ```bash
> echo $CHRONICLE_TENANT_URL
> # Resultado esperado: https://[seu-tenant].chronicle.security
> ```

---

## Etapa 6 — Criar o Bucket de Logs e Estrutura de Diretórios

**Passo 1:** Crie o bucket no Google Cloud Storage para armazenar os logs sintéticos:

```bash
gsutil mb -l us-central1 $LOGS_BUCKET
```

**Resultado esperado:**
```
Creating gs://cecyber-secops-logs-cecyber-secops-lab-jps-2026/...
```

**Passo 2:** Crie a estrutura de diretórios locais para os laboratórios:

```bash
mkdir -p $LAB_DIR/{logs-sinteticos,parsers,regras-yara-l,playbooks,scripts,relatorios}
echo "✅ Estrutura de diretórios criada em $LAB_DIR"
```

**Passo 3:** Clone o repositório do curso para ter acesso a todos os scripts e dados:

```bash
cd $HOME
git clone https://github.com/almirmeira/formacao-cloud-secops.git
ln -s $HOME/formacao-cloud-secops/curso-01-google-secops $LAB_DIR/curso-ref
echo "✅ Repositório clonado e link criado"
```

> **✅ Verificação:**
> ```bash
> ls $LAB_DIR
> # Resultado esperado:
> # curso-ref  logs-sinteticos  parsers  playbooks  regras-yara-l  relatorios  scripts
> ```

---

## Etapa 7 — Carregar os Dados Sintéticos do Banco Meridian

Os dados sintéticos representam logs de 30 dias do Banco Meridian (empresa fictícia), contendo
eventos normais e anômalos que serão usados nos laboratórios.

**Passo 1:** Baixe o pacote de dados sintéticos:

```bash
cd $LAB_DIR/logs-sinteticos
curl -O https://raw.githubusercontent.com/almirmeira/formacao-cloud-secops/main/curso-01-google-secops/dados/banco-meridian-logs-sinteticos.tar.gz
```

**Passo 2:** Descompacte os logs:

```bash
tar -xzf banco-meridian-logs-sinteticos.tar.gz
ls -la
```

**Resultado esperado:**
```
drwxr-xr-x  windows-event-logs/   (≈ 50 MB)
drwxr-xr-x  linux-syslog/         (≈ 20 MB)
drwxr-xr-x  firewall-logs/        (≈ 30 MB)
drwxr-xr-x  dns-logs/             (≈ 15 MB)
drwxr-xr-x  proxy-logs/           (≈ 25 MB)
-rw-r--r--  README-dados.txt
```

**Passo 3:** Envie os logs para o bucket do Google Cloud Storage:

```bash
gsutil -m cp -r $LAB_DIR/logs-sinteticos/* $LOGS_BUCKET/
echo "✅ Upload concluído"
```

> **⏱️ Tempo estimado:** 5–10 minutos dependendo da velocidade de conexão

**Passo 4:** Verifique o upload:

```bash
gsutil ls -lR $LOGS_BUCKET | tail -5
```

**Resultado esperado:** Lista de arquivos com tamanhos e caminhos dentro do bucket

---

## Etapa 8 — Configurar o Feed de Ingestão no Google SecOps

> Esta etapa configura a ingestão dos logs sintéticos diretamente no tenant Google SecOps.

**Passo 1:** No portal do Google SecOps, acesse:
```
Menu lateral esquerdo → Settings → Ingestion → Feeds → Add new feed
```

**Passo 2:** Configure o feed de ingestão do bucket:
```
Feed name:        banco-meridian-logs-sinteticos
Source:           Google Cloud Storage
Bucket URI:       gs://cecyber-secops-logs-[seu-project-id]/
Source type:      (selecione conforme o tipo de log — ex: WINDOWS_EVENT for Windows logs)
```

**Passo 3:** Para cada tipo de log, crie um feed separado:

| Feed Name                      | Source Type          | Bucket Path             |
|:-------------------------------|:---------------------|:------------------------|
| `bm-windows-events`            | `WINDOWS_EVENT`      | `/windows-event-logs/`  |
| `bm-linux-syslog`              | `SYSLOG`             | `/linux-syslog/`        |
| `bm-firewall`                  | `GENERIC_CEF`        | `/firewall-logs/`       |
| `bm-dns`                       | `DNS`                | `/dns-logs/`            |
| `bm-proxy`                     | `SQUID`              | `/proxy-logs/`          |

**Passo 4:** Para cada feed criado, clique em "Run now" para disparar a ingestão imediatamente

**Passo 5:** Aguarde 5–15 minutos e verifique o status no painel de feeds:
```
Settings → Ingestion → Feeds → (verão o status de cada feed)
```

Status esperado: `Healthy` com número de eventos processados > 0

> **✅ Verificação via UDM Search:**
> Na interface do Google SecOps, acesse "Search" e execute:
> ```
> metadata.product_name = "Microsoft-Windows-Security-Auditing"
> ```
> Resultado esperado: eventos listados com timestamps

---

## Etapa 9 — Verificação Final do Ambiente (Health Check)

Execute o script de health check completo para confirmar que tudo está funcionando:

```bash
cat $LAB_DIR/curso-ref/modulos/modulo-00-ambiente-laboratorio/health-check.sh
```

Conteúdo do script `health-check.sh`:

```bash
#!/bin/bash
# ================================================================
# CECyber — Google SecOps Lab — Health Check Script
# Verifica se o ambiente está configurado corretamente
# ================================================================

PASS=0
FAIL=0

check() {
    if eval "$2" &>/dev/null; then
        echo "✅ PASS: $1"
        ((PASS++))
    else
        echo "❌ FAIL: $1"
        ((FAIL++))
    fi
}

echo "======================================"
echo " CECyber Google SecOps Lab Health Check"
echo "======================================"

# Verificações básicas
check "gcloud instalado"        "gcloud --version"
check "Python 3.10+"            "python3 --version | grep -E '3\.(1[0-9]|[2-9][0-9])'"
check "git instalado"           "git --version"
check "curl instalado"          "curl --version"
check "jq instalado"            "jq --version"

# Verificações Google Cloud
check "Autenticado no gcloud"   "gcloud auth print-identity-token"
check "Projeto configurado"     "[ -n '$GOOGLE_PROJECT_ID' ]"
check "Bucket acessível"        "gsutil ls $LOGS_BUCKET"

# Verificações de variáveis
check "CHRONICLE_TENANT_URL"    "[ -n '$CHRONICLE_TENANT_URL' ]"
check "CHRONICLE_API_KEY"       "[ -n '$CHRONICLE_API_KEY' ]"
check "LAB_DIR existe"          "[ -d '$LAB_DIR' ]"

# Verificação de estrutura de diretórios
check "Diretório logs-sinteticos" "[ -d '$LAB_DIR/logs-sinteticos' ]"
check "Diretório parsers"       "[ -d '$LAB_DIR/parsers' ]"
check "Repositório clonado"     "[ -d '$LAB_DIR/curso-ref' ]"

echo "======================================"
echo " Resultado: $PASS verificações OK, $FAIL falhas"
echo "======================================"

if [ $FAIL -eq 0 ]; then
    echo "🎉 Ambiente configurado com sucesso! Pronto para os laboratórios."
else
    echo "⚠️  Corrija as falhas acima antes de prosseguir."
    exit 1
fi
```

**Execute o health check:**

```bash
bash $LAB_DIR/curso-ref/modulos/modulo-00-ambiente-laboratorio/health-check.sh
```

**Resultado esperado:**
```
======================================
 CECyber Google SecOps Lab Health Check
======================================
✅ PASS: gcloud instalado
✅ PASS: Python 3.10+
✅ PASS: git instalado
✅ PASS: curl instalado
✅ PASS: jq instalado
✅ PASS: Autenticado no gcloud
✅ PASS: Projeto configurado
✅ PASS: Bucket acessível
✅ PASS: CHRONICLE_TENANT_URL
✅ PASS: CHRONICLE_API_KEY
✅ PASS: LAB_DIR existe
✅ PASS: Diretório logs-sinteticos
✅ PASS: Diretório parsers
✅ PASS: Repositório clonado
======================================
 Resultado: 14 verificações OK, 0 falhas
======================================
🎉 Ambiente configurado com sucesso! Pronto para os laboratórios.
```

---

## Guia de Troubleshooting — Problemas Mais Comuns

| Problema                                    | Causa Provável                              | Solução                                         |
|:--------------------------------------------|:--------------------------------------------|:------------------------------------------------|
| `gcloud: command not found`                 | PATH não configurado                        | `export PATH=$PATH:~/google-cloud-sdk/bin`      |
| `Bucket does not exist`                     | Etapa 6 não concluída                       | Repita o comando `gsutil mb`                    |
| `Error 403: Forbidden` no bucket            | Permissões IAM ausentes                     | Adicione role `Storage Admin` ao seu usuário    |
| `Feed status: Error` no Google SecOps       | Formato de log não reconhecido              | Verifique o `Source type` configurado no feed   |
| `Login failed` no tenant Chronicle          | Senha incorreta ou expirada                 | Use "Forgot password" ou contate suporte CECyber|
| UDM Search não retorna resultados           | Ingestão ainda em andamento                 | Aguarde 15–30 min após configurar os feeds      |
| `gsutil` sem permissão para fazer upload    | Conta errada autenticada                    | `gcloud auth revoke --all && gcloud auth login` |

---

## Cleanup — Como Destruir o Ambiente ao Final do Curso

> Execute apenas ao encerrar definitivamente o uso do ambiente de laboratório.

```bash
# 1. Remover o bucket e todos os logs
gsutil rm -r $LOGS_BUCKET
echo "✅ Bucket removido"

# 2. Desabilitar APIs para evitar cobranças
gcloud services disable chronicle.googleapis.com --force
echo "✅ API Chronicle desabilitada"

# 3. (Opcional) Excluir o projeto completo
# ATENÇÃO: Esta ação é irreversível!
# gcloud projects delete $GOOGLE_PROJECT_ID
```

> **💡 Dica:** Você pode manter o projeto ativo e apenas pausar os feeds no tenant Google SecOps
> para não consumir créditos durante o período sem uso.

---

## Resumo — O que você configurou

| Componente                       | Status Esperado |
|:---------------------------------|:---------------:|
| Google Cloud Project             | ✅ Criado        |
| APIs habilitadas (7 APIs)        | ✅ Habilitadas   |
| Google Cloud SDK (gcloud)        | ✅ Instalado     |
| Tenant Google SecOps             | ✅ Acessível     |
| Variáveis de ambiente            | ✅ Configuradas  |
| Bucket GCS criado                | ✅ Criado        |
| Logs sintéticos (Banco Meridian) | ✅ Carregados    |
| Feeds de ingestão configurados   | ✅ Ativos        |
| Health check                     | ✅ 14/14 PASS    |

---

**Parabéns!** Seu ambiente está pronto. Prossiga para o
**[Módulo 01 — Fundamentos do Google SecOps](../modulo-01-fundamentos/README.md)**

---

*Módulo 00 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
