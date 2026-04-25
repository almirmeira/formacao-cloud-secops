# Lab 02 — Pipeline DevSecOps: IaC + Container Security
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2 horas  
> **Dificuldade:** Avançado  
> **Módulos Relacionados:** Módulos 03 e 04  

---

## 1. Contexto Situacional

O time de DevOps do Banco Meridian vai lançar uma nova API financeira em containers na AWS. O CISO, após o relatório do Lab 01, determinou que nenhum novo recurso cloud pode ser criado sem passar por um pipeline de segurança. Você foi designado como Security Engineer para implementar o pipeline DevSecOps completo antes do primeiro deploy.

---

## 2. Situação Inicial

O repositório GitHub da API financeira existe mas não tem nenhum controle de segurança no pipeline. O time de desenvolvimento quer fazer o primeiro deploy na próxima semana e o CISO bloqueou o deploy até que o pipeline de segurança esteja implementado.

---

## 3. Problema Identificado

O código Terraform criará recursos AWS (ECS, S3, IAM). A imagem Docker pode ter CVEs. Secrets podem estar hardcoded. Sem o pipeline, esses problemas só serão descobertos em produção.

---

## 4. Roteiro de Atividades

1. Criar repositório GitHub com estrutura do projeto
2. Escrever Terraform com recurso intencionalmente inseguro
3. Configurar Checkov com arquivo checkov.yaml
4. Adicionar step Checkov no GitHub Actions (falha em CRITICAL/HIGH)
5. Adicionar step tfsec (warn em HIGH)
6. Criar Dockerfile para a API
7. Adicionar step de build Docker
8. Adicionar step Trivy scan na imagem (falha em CRITICAL CVE)
9. Adicionar step Syft para gerar SBOM
10. Adicionar step Cosign sign (keyless)
11. Push para GitHub Container Registry (somente se tudo passou)
12. Verificar assinatura Cosign antes do "deploy"
13. Testar o pipeline com commit inseguro (deve falhar)
14. Corrigir o Terraform e verificar que o pipeline passa
15. Verificar o relatório final no GitHub Security

---

## 5. Proposição

Ao final deste laboratório, você terá um pipeline completo `.github/workflows/security.yml` que bloqueia automaticamente qualquer IaC com findings CRITICAL, impede o push de imagens com CVEs críticas, e assina cada imagem aprovada com Cosign.

---

## 6. Script Passo a Passo

### Passo 1: Criar Repositório GitHub

**O que este passo faz:** Cria o repositório GitHub que será o ponto central do pipeline DevSecOps. A estrutura de diretórios que criamos tem uma separação deliberada de responsabilidades: `terraform/` contém o código de infraestrutura (o que o Checkov e o tfsec vão escanear), `.github/workflows/` contém as automações CI/CD (o pipeline de segurança em si), `policy/` contém as políticas OPA/Rego customizadas do Banco Meridian (regras específicas do negócio que o Checkov não tem nativamente), e `app/` contém o código da API (o que o Trivy vai escanear na imagem Docker). Essa separação limita o raio de impacto de um comprometimento: um atacante que vaza secrets do `app/` não tem acesso automático às políticas de segurança do `policy/`.

**Por que esta ordem:** O repositório precisa existir antes de qualquer outro passo. Todo o pipeline é acionado por eventos do GitHub (push, pull_request), então sem o repositório configurado nada mais funciona. A estrutura de diretórios criada aqui determina os caminhos que serão referenciados no workflow YAML do passo 6 — criar a estrutura errada agora quebraria silenciosamente o pipeline mais tarde.

**Por que repositório público neste lab:** GitHub Actions gratuito tem 2.000 minutos/mês para repositórios públicos e 500 para privados. Para o lab, usamos público para evitar custos. Em produção, o Banco Meridian usaria GitHub Enterprise com RBAC e proteção de branch obrigatória.

```bash
# Pré-requisitos
gh --version    # GitHub CLI instalado
git --version   # Git instalado

# Criar repositório no GitHub
cd ~
mkdir bancomeridian-api-lab02
cd bancomeridian-api-lab02
git init
gh repo create bancomeridian-api-lab02 --public --source=. --remote=origin

# Estrutura do projeto
mkdir -p terraform .github/workflows policy app

echo "Repositório criado e estrutura de diretórios inicializada"
```

**O que você deve ver:**
```
✓ Created repository seu-usuario/bancomeridian-api-lab02 on GitHub
  https://github.com/seu-usuario/bancomeridian-api-lab02
```

Confirme com `git remote -v` — deve mostrar `origin` apontando para o repositório GitHub recém-criado.

**Troubleshooting:** Se `gh` não estiver instalado: `brew install gh` ou `sudo apt install gh`, depois `gh auth login`.

---

### Passo 2: Criar Terraform com Recurso Inseguro

**O que este passo faz:** Cria o código de infraestrutura como código (IaC) do Banco Meridian em Terraform. A peça central deste passo é a criação proposital de um bucket S3 inseguro (`api_storage_inseguro`) ao lado de um bucket seguro (`api_storage_seguro`). Este contraste lado a lado é didático: o Checkov vai passar no bucket seguro e falhar no inseguro, permitindo que você veja exatamente o que faz a diferença entre configurações aprovadas e reprovadas no pipeline. As três violações intencionais são: ausência de bloqueio de acesso público (CKV_AWS_19), ausência de access logging (CKV_AWS_18) e ausência de criptografia KMS (CKV_AWS_145).

**Por que esta ordem:** O Terraform precisa existir antes de configurar o Checkov (passo 3), porque o Checkov é um scanner de IaC — ele precisa de algo para escanear. Se criássemos o `checkov.yaml` antes, o Checkov rodaria em um diretório vazio e o lab não demonstraria nada.

**O que o `variables.tf` representa:** Em produção, jamais se colocam valores fixos (hardcoded) no `main.tf`. O arquivo `variables.tf` simula a separação real entre configuração e código: a região, o nome do projeto e as tags padrão são parâmetros que mudam por ambiente (sandbox, staging, prod). As tags `Owner`, `CostCenter` e `Project` são exigidas pela política de governança de cloud do Banco Meridian para rastreabilidade de custos no AWS Cost Explorer.

```bash
# terraform/main.tf — com bucket inseguro para demonstrar falha do pipeline
cat > terraform/main.tf << 'TF'
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ================================================================
# BUCKET INSEGURO — para demonstração do pipeline falhando
# Este bucket INTENCIALMENTE vai falhar no Checkov:
#   CKV_AWS_19: sem block public access
#   CKV_AWS_18: sem access logging
#   CKV_AWS_145: sem criptografia KMS
# ================================================================
resource "aws_s3_bucket" "api_storage_inseguro" {
  bucket = "${var.project_name}-storage-inseguro"
  # Propositalmente sem configurações de segurança
}

# ================================================================
# BUCKET SEGURO — para demonstração do pipeline passando
# ================================================================
resource "aws_s3_bucket" "api_storage_seguro" {
  bucket = "${var.project_name}-storage-seguro"
  tags   = var.default_tags
}

resource "aws_s3_bucket_public_access_block" "api_storage_seguro" {
  bucket                  = aws_s3_bucket.api_storage_seguro.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "api_storage_seguro" {
  bucket = aws_s3_bucket.api_storage_seguro.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_logging" "api_storage_seguro" {
  bucket        = aws_s3_bucket.api_storage_seguro.id
  target_bucket = aws_s3_bucket.api_storage_seguro.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_versioning" "api_storage_seguro" {
  bucket = aws_s3_bucket.api_storage_seguro.id
  versioning_configuration { status = "Enabled" }
}
TF

# terraform/variables.tf
cat > terraform/variables.tf << 'TF'
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Nome do projeto"
  type        = string
  default     = "bancomeridian-api"
}

variable "default_tags" {
  description = "Tags padrão para todos os recursos"
  type        = map(string)
  default = {
    Owner       = "equipe-api"
    Environment = "sandbox"
    CostCenter  = "CC-001"
    Project     = "API-LAB02"
  }
}
TF

echo "Terraform criado — inclui recurso inseguro (propositalmente) para teste do pipeline"
```

---

### Passo 3: Configurar Checkov

**O que este passo faz:** Cria o arquivo de configuração central do Checkov, o scanner de IaC de código aberto da Bridgecrew (Palo Alto Networks). O `checkov.yaml` define a política de segurança do Banco Meridian para infraestrutura como código: o que é bloqueante (`hard-fail-on: CRITICAL, HIGH`) e o que é apenas aviso (`soft-fail-on: MEDIUM, LOW`). Esta divisão reflete uma decisão de risco consciente — achados CRITICAL e HIGH representam configurações que podem expor dados de clientes financeiros diretamente (ex: bucket S3 público), enquanto MEDIUM/LOW são melhorias de postura que não bloqueiam a operação mas são registradas para tratamento no ciclo seguinte.

**O que esta política verifica:** O bloco `framework` define que o Checkov vai analisar código Terraform, Dockerfiles e manifestos Kubernetes — cada um tem seu próprio conjunto de checks. O `skip-path` exclui o diretório `.terraform/` porque ele contém arquivos baixados pelos providers (binários e metadados), não código que você escreveu, e o Checkov geraria falsos positivos nesses arquivos. O `output-file-path: checkov-results/` define onde os resultados JSON serão salvos — este caminho é referenciado mais tarde no workflow do GitHub Actions para publicar o relatório como comentário no PR.

**Por que esta ordem:** O `checkov.yaml` precisa existir antes de criar o workflow do GitHub Actions (passo 6), porque o job do Checkov no workflow executa o comando `checkov -d ./terraform/` que automaticamente lê este arquivo de configuração. Criar o workflow sem o `checkov.yaml` faria o Checkov rodar com as configurações padrão, que pode ser diferente da política do Banco Meridian.

```bash
cat > checkov.yaml << 'YAML'
# checkov.yaml — configuração do Banco Meridian

# Frameworks a verificar
framework:
  - terraform
  - dockerfile
  - kubernetes

# Falha o CI em CRITICAL e HIGH
hard-fail-on:
  - CRITICAL
  - HIGH

# Apenas warn em MEDIUM e LOW (não bloqueia)
soft-fail-on:
  - MEDIUM
  - LOW

# Checks suprimidos com justificativa (nenhum no momento)
skip-check: []

# Diretórios a ignorar
skip-path:
  - .terraform/
  - terraform/.terraform/

# Output: todos os formatos
output:
  - cli
  - json

output-file-path: checkov-results/
YAML

echo "checkov.yaml configurado"
```

---

### Passo 4: Criar Dockerfile para a API

**O que este passo faz:** Cria o Dockerfile da API Financeira do Banco Meridian usando práticas de segurança de container obrigatórias para o setor financeiro. O Dockerfile segue três princípios de segurança que o Trivy e o Checkov vão verificar: (1) **multi-stage build** — o estágio de build instala dependências de compilação que não devem estar na imagem final, reduzindo a superfície de ataque; (2) **usuário não-root** — criar um usuário `appuser` sem privilégios impede que uma aplicação comprometida execute comandos como root dentro do container, o que é obrigatório pelo controle CKV_DS_4 do Checkov; (3) **healthcheck** — o ECS usa o healthcheck para decidir se a task está saudável, sem ele o ECS não consegue substituir containers com falha automaticamente.

**O que o `main.py` representa:** A API FastAPI criada aqui é uma stub mínima com dois endpoints: `/health` (para o healthcheck do ECS e do load balancer) e `/` (endpoint principal). Em um ambiente real, esta seria a API financeira completa do Banco Meridian. Para o propósito deste lab, o que importa é que a imagem seja buildável e o Trivy possa escaneá-la.

**Por que esta ordem:** O Dockerfile precisa existir antes do workflow do GitHub Actions (passo 6), porque o job de container-security referencia `./app/Dockerfile`. O `requirements.txt` com versões fixas (`fastapi==0.109.0`) é uma prática de segurança: versões sem pin (`fastapi>=0.100`) podem resolver para versões com CVEs no futuro, quebrando o scan do Trivy de forma inesperada.

```bash
cat > app/Dockerfile << 'DOCKERFILE'
# Dockerfile seguro — Banco Meridian API
# Segue boas práticas: não-root, multi-stage, imagem mínima

# Stage 1: Build
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime (imagem mínima)
FROM python:3.11-slim

# Criar usuário não-root (CKV_DS_4 — não usar root)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copiar dependências do stage de build
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser app/ .

# Usar usuário não-root
USER appuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

EXPOSE 8080

CMD ["python", "main.py"]
DOCKERFILE

# Criar requirements.txt simples
cat > app/requirements.txt << 'REQ'
fastapi==0.109.0
uvicorn==0.27.0
REQ

# Criar main.py simples
cat > app/main.py << 'PY'
from fastapi import FastAPI

app = FastAPI(title="Banco Meridian API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"message": "Banco Meridian API v1.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
PY

echo "Dockerfile e aplicação criados"
```

---

### Passo 5: Criar Política Rego para Validação Adicional

**O que este passo faz:** Cria uma política de segurança customizada em OPA Rego que o Checkov (via suporte a políticas externas) ou o Conftest podem executar além dos checks nativos. OPA (Open Policy Agent) é um motor de políticas de propósito geral que permite ao Banco Meridian escrever regras de segurança específicas do negócio em uma linguagem declarativa. Esta política implementa uma regra que verifica: todo bucket S3 declarado no plano Terraform deve ter um recurso `aws_s3_bucket_public_access_block` correspondente no mesmo plano.

**O que esta política verifica:** A lógica Rego funciona assim: para cada recurso do tipo `aws_s3_bucket` encontrado em `input.resource_changes` (o plano Terraform em formato JSON), a política verifica se existe ao menos um recurso do tipo `aws_s3_bucket_public_access_block` no mesmo plano. Se não existir, ela gera uma violação com a mensagem formatada indicando o endereço do bucket problemático. O bloco `deny[msg]` é o ponto de entrada que ferramentas como Conftest leem — qualquer mensagem nesse set causa falha.

**Por que OPA/Rego além do Checkov:** O Checkov verifica segurança técnica de infraestrutura com regras genéricas (CIS, NIST). O OPA verifica políticas de governança específicas do negócio. Eles são complementares: Checkov diz "este bucket não tem criptografia" (segurança técnica); OPA diz "este bucket não está configurado conforme as regras próprias do Banco Meridian" (governança corporativa). Um banco regulado pelo BACEN precisa de ambas as camadas.

**Por que esta ordem:** A política Rego precisa existir no diretório `policy/` antes do commit e push (passo 7), para que o pipeline possa carregá-la. Ela é colocada antes do workflow (passo 6) para que o aluno entenda o que está sendo verificado antes de ver como o workflow orquestra as verificações.

```bash
cat > policy/s3_security.rego << 'REGO'
package terraform.aws.s3

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"

    # Verifica se não tem block public access configurado
    not input.resource_changes[_].type == "aws_s3_bucket_public_access_block"

    msg := sprintf(
        "Bucket S3 '%v' não tem block public access configurado",
        [resource.address]
    )
}

deny[msg] {
    msg := violations[_]
}
REGO

echo "Política Rego criada"
```

---

### Passo 6: Criar o Workflow GitHub Actions Completo

**O que este passo faz:** Cria o arquivo de automação central do pipeline DevSecOps — o coração de todo este laboratório. O workflow orquestra quatro jobs que formam os portões de segurança do Banco Meridian: escaneamento de IaC, escaneamento de container, geração de SBOM, assinatura criptográfica e um portão de decisão final.

**Entendendo este workflow:**

- **Gatilhos (`on`):** O workflow dispara em dois eventos distintos com comportamentos diferentes. Em `pull_request` para `main`, todos os jobs de IaC rodam (Checkov + tfsec + Security Gate), mas o job de container é pulado — não faz sentido construir e publicar imagens de branches em revisão que podem mudar. Em `push` para `main` (após o merge), o job de container também roda, construindo, escaneando e publicando a imagem final aprovada.

- **Permissões (`permissions`):** O bloco de permissões segue o princípio de menor privilégio. `contents: read` permite apenas ler o código (não modificar). `security-events: write` é necessário para enviar SARIFs ao GitHub Code Scanning. `pull-requests: write` permite que o Checkov poste comentários automáticos nos PRs. `packages: write` permite fazer push ao GHCR. `id-token: write` é a permissão mais importante: habilita o OIDC para o Cosign keyless — sem ela, a assinatura criptográfica falha com erro de autenticação.

- **JOB 1 — Checkov (IaC):** É o portão primário e mais crítico. Instala o Checkov via pip, executa contra o diretório `terraform/`, e com `continue-on-error: false` garante que qualquer finding CRITICAL ou HIGH falha o job inteiro. O step de "Publicar resultado no PR" usa a API do GitHub para postar um comentário formatado na PR com a lista dos findings — isso transforma uma falha de CI abstrata em feedback acionável para o desenvolvedor. O upload do artefato com `retention-days: 90` gera evidência para auditoria.

- **JOB 2 — tfsec (IaC):** Complementar ao Checkov, o tfsec é especializado em Terraform e usa regras diferentes. A diferença crítica é `soft_fail: true` — o tfsec nunca bloqueia, apenas gera relatório SARIF que vai para o GitHub Code Scanning. Esta decisão é intencional: usar dois scanners com o mais agressivo bloqueando e o segundo como segunda opinião reduz falsos negativos sem aumentar falsos bloqueios.

- **JOB 3 — Container Security:** Só roda após o Checkov passar (`needs: [checkov]`) e só em pushes ao `main`. O fluxo dentro do job é sequencial com lógica de portão embutida: (1) Build sem push — a imagem é construída localmente no runner para o Trivy escanear sem expor uma imagem não-verificada ao registry público. (2) Trivy vulnerability scan com `exit-code: 1` — qualquer CVE CRITICAL ou HIGH aborta o job, e a imagem nunca chega ao GHCR. (3) Trivy secrets scan — detecta senhas, tokens e chaves API hardcoded na imagem. (4) Syft gera o SBOM em formato CycloneDX — o inventário de componentes exigido pela Resolução BACEN 4.893. (5) Push ao GHCR — só chega aqui se os dois scans do Trivy passaram. (6) Cosign sign com OIDC keyless — a assinatura usa a identidade do GitHub Actions como autoridade, sem precisar de chave privada gerenciada. (7) Cosign verify — verifica a própria assinatura para confirmar que o processo funcionou.

- **JOB 4 — Security Gate:** O árbitro final. Roda sempre (`if: always()`) para que, mesmo se um job anterior falhou, ele ainda execute e dê o veredicto final. Verifica o resultado do Checkov e do tfsec, e falha explicitamente se algum job crítico falhou. Este job é o que é configurado como "required status check" no branch `main` do GitHub — o merge fica fisicamente bloqueado se ele falhar.

```bash
cat > .github/workflows/security.yml << 'WORKFLOW'
# .github/workflows/security.yml
# Pipeline DevSecOps Completo — Banco Meridian
# Módulos: Checkov + tfsec + Docker Build + Trivy + Syft + Cosign

name: DevSecOps Security Pipeline

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write
  packages: write
  id-token: write

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}/api

jobs:
  # ════════════════════════════════════════════════════════
  # JOB 1: CHECKOV — IaC Security Scan
  # Falha em CRITICAL/HIGH, warn em MEDIUM/LOW
  # ════════════════════════════════════════════════════════
  checkov:
    name: "IaC: Checkov Scan"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Instalar Checkov
        run: pip install checkov

      - name: Executar Checkov
        id: checkov
        run: |
          mkdir -p checkov-results
          checkov \
            -d ./terraform/ \
            --framework terraform \
            --severity CRITICAL HIGH \
            --output json \
            --output cli \
            --output-file-path checkov-results/ \
            --soft-fail-on MEDIUM LOW
        continue-on-error: false

      - name: Publicar resultado no PR
        uses: actions/github-script@v7
        if: always() && github.event_name == 'pull_request'
        with:
          script: |
            const fs = require('fs');
            let body = '## Checkov IaC Security Scan\n\n';
            try {
              const results = JSON.parse(
                fs.readFileSync('checkov-results/results_json.json', 'utf8')
              );
              const failed = results.results?.failed_checks?.filter(c =>
                ['CRITICAL', 'HIGH'].includes(c.severity)) || [];
              body += failed.length > 0
                ? `❌ **${failed.length} findings CRITICAL/HIGH**\n\n` +
                  failed.slice(0, 10).map(c =>
                    `- \`[${c.check_id}]\` ${c.check.name} em \`${c.file_path}:${c.file_line_range[0]}\``
                  ).join('\n')
                : '✅ Sem findings CRITICAL/HIGH — IaC aprovado';
            } catch(e) {
              body += `⚠️ Erro ao processar relatório: ${e.message}`;
            }
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });

      - name: Upload resultados Checkov
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: checkov-results
          path: checkov-results/
          retention-days: 90

  # ════════════════════════════════════════════════════════
  # JOB 2: TFSEC — Terraform Security Scanner
  # Apenas warn (não bloqueia — complementar ao Checkov)
  # ════════════════════════════════════════════════════════
  tfsec:
    name: "IaC: tfsec Scan"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: ./terraform
          minimum_severity: MEDIUM
          soft_fail: true
          format: sarif
          additional_args: --no-color

      - name: Upload tfsec SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfsec.sarif
          category: tfsec

  # ════════════════════════════════════════════════════════
  # JOB 3: CONTAINER — Build + Scan + SBOM + Sign
  # Executa somente no push ao main (não em PR)
  # ════════════════════════════════════════════════════════
  container-security:
    name: "Container: Build, Scan, Sign"
    runs-on: ubuntu-latest
    needs: [checkov]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'

    steps:
      - uses: actions/checkout@v4

      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login GHCR
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # STEP 5: Build da imagem (sem push ainda)
      - name: Build imagem Docker
        uses: docker/build-push-action@v5
        with:
          context: ./app
          file: ./app/Dockerfile
          push: false
          load: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      # STEP 6: Trivy scan — falha se CRITICAL CVE
      - name: Trivy — Vulnerability Scan (falha em CRITICAL)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: sarif
          output: trivy-image.sarif
          severity: CRITICAL,HIGH
          exit-code: 1
          ignore-unfixed: false

      - name: Trivy — Secrets Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          scanners: secret
          severity: HIGH,CRITICAL
          exit-code: 1

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image

      # STEP 7: Syft — Gerar SBOM
      - name: Syft — Gerar SBOM CycloneDX
        uses: anchore/syft-action@v0.16.0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      - name: Salvar SBOM como artefato (365 dias — evidência BACEN)
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom.cyclonedx.json
          retention-days: 365

      # STEP 8: Push para GHCR (somente se scan passou)
      - name: Push imagem para GHCR
        uses: docker/build-push-action@v5
        id: push
        with:
          context: ./app
          file: ./app/Dockerfile
          push: true
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          labels: |
            org.opencontainers.image.revision=${{ github.sha }}
            security.trivy.status=passed
            security.scan.date=${{ github.run_started_at }}

      # STEP 8 (continuação): Cosign — Assinar imagem
      - name: Instalar Cosign
        uses: sigstore/cosign-installer@v3

      - name: Cosign — Assinar imagem (keyless via OIDC)
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}
          echo "Imagem assinada: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}"

      - name: Cosign — Anexar SBOM como attestation
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign attest --yes \
            --type cyclonedx \
            --predicate sbom.cyclonedx.json \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}

      # STEP 10: Verificação da assinatura antes do deploy
      - name: Cosign — Verificar assinatura (pré-deploy)
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}.*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}
          echo "✓ Assinatura verificada — imagem autorizada para deploy"

      - name: Sumário de segurança
        run: |
          echo "## Sumário do Pipeline de Segurança" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Etapa | Status |" >> $GITHUB_STEP_SUMMARY
          echo "|:------|:------:|" >> $GITHUB_STEP_SUMMARY
          echo "| Checkov IaC | ✅ Passou |" >> $GITHUB_STEP_SUMMARY
          echo "| Trivy image scan | ✅ Passou |" >> $GITHUB_STEP_SUMMARY
          echo "| Trivy secrets scan | ✅ Passou |" >> $GITHUB_STEP_SUMMARY
          echo "| SBOM gerado | ✅ CycloneDX |" >> $GITHUB_STEP_SUMMARY
          echo "| Cosign sign | ✅ Keyless OIDC |" >> $GITHUB_STEP_SUMMARY
          echo "| Cosign verify | ✅ Verificado |" >> $GITHUB_STEP_SUMMARY

  # ════════════════════════════════════════════════════════
  # JOB 4: SECURITY GATE — Decisão Final
  # ════════════════════════════════════════════════════════
  security-gate:
    name: Security Gate Final
    runs-on: ubuntu-latest
    needs: [checkov, tfsec]
    if: always()
    steps:
      - name: Verificar status dos jobs críticos
        run: |
          echo "Checkov: ${{ needs.checkov.result }}"
          echo "tfsec: ${{ needs.tfsec.result }}"

          if [[ "${{ needs.checkov.result }}" == "failure" ]]; then
            echo "❌ SECURITY GATE: FALHOU — Checkov encontrou CRITICAL/HIGH"
            echo "O PR não pode ser mergeado. Corrija os findings de IaC security."
            exit 1
          fi

          echo "✅ SECURITY GATE: APROVADO — Sem blocking findings"
WORKFLOW

echo "Workflow GitHub Actions criado: .github/workflows/security.yml"
```

---

### Passo 7: Fazer Push e Criar PR

**O que este passo faz:** Empacota todo o trabalho dos passos anteriores em um commit e abre uma Pull Request no GitHub. Este é o momento em que o pipeline de segurança entra em ação pela primeira vez. Ao abrir o PR, o GitHub automaticamente dispara o workflow definido no passo 6. O commit message segue o formato Conventional Commits (`feat:`) que permite gerar changelogs automatizados — o pipeline do Banco Meridian eventualmente usará esses prefixos para decisões de versionamento semântico.

**Por que esta ordem:** O push precisa acontecer depois de todos os arquivos estarem criados. Especificamente, o workflow só existirá no runner do GitHub Actions se estiver no repositório remoto — arquivos que só existem localmente são invisíveis para o CI. O checkout do branch `feature/devsecops-pipeline` antes do push é uma boa prática: nunca se commita diretamente no `main` em ambientes com proteção de branch habilitada.

**O que observar neste passo:** A mensagem de corpo do PR contém um aviso explícito de que o Terraform é intencionalmente inseguro. Em uma equipe real, esta transparência é essencial: o revisor do PR precisa saber que a falha do pipeline é esperada e serve para demonstrar o mecanismo de bloqueio.

```bash
# Adicionar todos os arquivos
git add .
git commit -m "feat: adicionar pipeline DevSecOps com Checkov + Trivy + Cosign

- terraform/main.tf com bucket inseguro (para testar falha do pipeline)
- Dockerfile multi-stage com usuário não-root
- Checkov configurado para falhar em CRITICAL/HIGH
- GitHub Actions workflow completo
- SBOM gerado com Syft
- Assinatura de imagem com Cosign keyless"

# Push para branch feature
git checkout -b feature/devsecops-pipeline
git push -u origin feature/devsecops-pipeline

# Criar PR
gh pr create \
  --title "feat: implementar pipeline DevSecOps completo" \
  --body "Pipeline com Checkov, tfsec, Trivy, Syft e Cosign.

**⚠️ ATENÇÃO:** Este PR contém um recurso Terraform intencionalmente inseguro para demonstrar o bloqueio do pipeline.

Esperado: Checkov deve FALHAR e bloquear o merge."
```

**Resultado esperado:**
```
https://github.com/seu-usuario/bancomeridian-api-lab02/pull/1
```

---

### Passo 8: Verificar Falha do Pipeline (Terraform Inseguro)

**O que este passo faz:** Observa o pipeline de segurança em ação bloqueando um deploy inseguro. Este é o momento mais importante do laboratório — você está vendo o pipeline fazer exatamente o que foi projetado: impedir que infraestrutura com misconfigurações críticas chegue ao ambiente de produção do Banco Meridian. O comando `gh run watch` abre um acompanhamento em tempo real dos jobs no terminal.

**Por que o tfsec aparece como SUCCESS mesmo com o bucket inseguro:** O tfsec tem `soft_fail: true` no workflow, então ele nunca falha o job mesmo que encontre problemas. Isso é intencional — o tfsec serve como segunda camada de relatório, não como portão bloqueador. A divisão de responsabilidades entre Checkov (bloqueador) e tfsec (complementar) permite que o time receba informações de duas engines com regras diferentes sem duplicar os bloqueios.

**Por que o job de container aparece como SKIPPED:** A condição `if: github.ref == 'refs/heads/main' && github.event_name == 'push'` no job de container-security significa que ele só roda quando há um push direto ao main, não em PRs. Isso é uma decisão de design: não faz sentido construir e assinar imagens de branches em revisão que ainda podem ser modificadas antes do merge.

```bash
# Aguardar execução do workflow (2-3 minutos)
gh run watch

# Verificar status
gh pr checks

# Resultado esperado:
# ❌ IaC: Checkov Scan — FAILURE
#    Findings: CKV_AWS_19, CKV_AWS_18, CKV_AWS_145
# ✓ IaC: tfsec Scan — SUCCESS (apenas warn)
# ❌ Security Gate Final — FAILURE (dependente do Checkov)
```

---

### Passo 9: Verificar Comentário Automático na PR

**O que este passo faz:** Valida que o mecanismo de feedback automático do pipeline está funcionando. Quando o Checkov encontra findings, o step "Publicar resultado no PR" (configurado no job checkov do workflow) lê o arquivo JSON de resultados, formata os achados e posta um comentário na PR usando a API do GitHub. Este mecanismo transforma uma falha de CI em feedback acionável: o desenvolvedor não precisa entrar no log do GitHub Actions para descobrir o que falhou — o comentário aparece diretamente na PR com o ID do check, a descrição e a linha exata do arquivo.

**Por que este mecanismo é importante para o Banco Meridian:** Em uma equipe com múltiplos desenvolvedores, é inviável esperar que todos conheçam os IDs dos checks do Checkov de memória. O comentário automático com `[CKV_AWS_19] S3 bucket sem block public access em terraform/main.tf:10` dá ao desenvolvedor a informação exata para buscar a documentação e corrigir. Isso reduz o MTTR (Mean Time to Remediate) de misconfigurations e diminui a fricção entre o time de segurança e o time de desenvolvimento.

```bash
# Ver comentários na PR
gh pr view --comments

# Esperado: comentário automático do GitHub Actions com os findings:
# "## Checkov IaC Security Scan
# ❌ 3 findings CRITICAL/HIGH
# - [CKV_AWS_19] S3 bucket sem block public access em terraform/main.tf:10
# - [CKV_AWS_18] S3 bucket sem access logging em terraform/main.tf:10
# - [CKV_AWS_145] S3 bucket sem criptografia KMS em terraform/main.tf:10"
```

---

### Passo 10: Corrigir o Terraform e Verificar Aprovação

**O que este passo faz:** Demonstra o ciclo completo de remediação — o desenvolvedor recebe o feedback do pipeline, corrige o código e vê o pipeline aprovar na segunda execução. As três configurações adicionadas ao bucket anteriormente inseguro resolvem exatamente os três findings do Checkov: `aws_s3_bucket_public_access_block` resolve CKV_AWS_19, `aws_s3_bucket_logging` resolve CKV_AWS_18, e `aws_s3_bucket_server_side_encryption_configuration` com `sse_algorithm = "aws:kms"` resolve CKV_AWS_145. Este é o princípio shift-left na prática: a correção ocorre em minutos, no contexto do código, antes de qualquer deploy.

**Por que usar KMS em vez de AES256:** A criptografia AES256 no S3 usa chaves gerenciadas pela AWS (SSE-S3), que estão sob controle total da AWS. A criptografia KMS usa chaves gerenciadas pelo cliente (SSE-KMS), o que significa que o Banco Meridian tem controle sobre quem pode descriptografar os dados, pode revogar acesso revogando a chave KMS, e tem logs detalhados no CloudTrail de cada operação de descriptografia. Para dados financeiros regulados pelo BACEN, o controle de chaves KMS é praticamente obrigatório.

```bash
# Editar terraform/main.tf — remover o bucket inseguro
# (O bucket inseguro era para demonstração — remova ou adicione as configurações)

# Opção 1: Remover o recurso inseguro
grep -n "inseguro" terraform/main.tf
# Deletar as linhas do bloco aws_s3_bucket inseguro

# Opção 2: Adicionar configurações de segurança ao bucket inseguro
cat >> terraform/main.tf << 'TF'

# Adicionando configurações de segurança ao bucket anteriormente inseguro
resource "aws_s3_bucket_public_access_block" "api_storage_inseguro_fix" {
  bucket                  = aws_s3_bucket.api_storage_inseguro.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "api_storage_inseguro_fix" {
  bucket = aws_s3_bucket.api_storage_inseguro.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_logging" "api_storage_inseguro_fix" {
  bucket        = aws_s3_bucket.api_storage_inseguro.id
  target_bucket = aws_s3_bucket.api_storage_inseguro.id
  target_prefix = "access-logs/"
}
TF

# Commit a correção
git add terraform/main.tf
git commit -m "fix: adicionar configurações de segurança ao bucket S3

Resolvendo findings Checkov:
- CKV_AWS_19: block public access habilitado
- CKV_AWS_18: access logging habilitado
- CKV_AWS_145: criptografia KMS habilitada"

git push

# Aguardar pipeline rerrodar
gh run watch
gh pr checks

# Resultado esperado agora:
# ✅ IaC: Checkov Scan — SUCCESS
# ✅ IaC: tfsec Scan — SUCCESS
# ✅ Security Gate Final — SUCCESS
# → PR APROVADO para merge
```

---

### Passo 11: Verificar SBOM no GitHub Security

**O que este passo faz:** Acessa e analisa o Software Bill of Materials (SBOM) gerado automaticamente pelo Syft durante o pipeline. O SBOM é o inventário completo de todos os componentes de software presentes na imagem Docker — bibliotecas Python, binários do sistema operacional, dependências transitivas — em formato CycloneDX JSON, um padrão aberto para troca de informações de segurança de software.

**Por que o SBOM importa para o Banco Meridian:** Para o Banco Meridian, este SBOM é uma evidência regulatória: a Resolução BACEN 4.893 exige que as instituições financeiras mantenham inventário dos componentes de software utilizados em sistemas críticos. O SBOM é retido por 365 dias nos GitHub Artifacts exatamente por isso. Com este inventário, o time de segurança pode verificar rapidamente se uma biblioteca específica afetada por uma CVE recém-divulgada está presente em alguma das imagens em produção — sem precisar fazer um novo scan completo.

**O que o script Python demonstra:** O script analisa o campo `components` do JSON CycloneDX e lista os primeiros 10 componentes com nome e versão. Em uma imagem Python real, você verá entradas para `fastapi`, `uvicorn`, `pydantic`, as bibliotecas do sistema Debian (como `libc6`, `openssl`) e seus metadados de versão.

```bash
# Após merge no main, verificar os artefatos criados
gh run list --limit 5

# Baixar o SBOM gerado
gh run download --name sbom-$(git rev-parse HEAD)
ls sbom.cyclonedx.json

# Analisar o SBOM
cat sbom.cyclonedx.json | python3 -c "
import json, sys
sbom = json.load(sys.stdin)
components = sbom.get('components', [])
print(f'Componentes no SBOM: {len(components)}')
print('Primeiros 10:')
for c in components[:10]:
    print(f'  - {c.get(\"name\", \"?\")}:{c.get(\"version\", \"?\")}')
"
```

---

### Passo 12: Verificar Assinatura Cosign

**O que este passo faz:** Verifica criptograficamente que a imagem publicada no GHCR foi assinada pelo pipeline autorizado do Banco Meridian. O Cosign keyless (via OIDC) funciona sem chave privada gerenciada: em vez disso, o GitHub Actions obtém um token OIDC da sua própria identidade, e o Cosign usa esse token para obter um certificado de vida curta da Sigstore Fulcio CA. A assinatura e o certificado são então registrados no Rekor — um log de transparência imutável e público, similar ao Certificate Transparency do TLS.

**O que o `cosign verify` valida:** O comando faz duas verificações simultâneas: (1) valida a assinatura criptográfica da imagem — garantindo que ela não foi modificada após a assinatura; (2) confirma que o certificado foi emitido para a identidade correta (a URL do workflow no repositório correto, via `--certificate-identity-regexp`). O segundo ponto é crucial: um atacante que copiasse uma assinatura de outro repositório não passaria nesta verificação, porque o certificado está vinculado ao repositório específico.

**O que esta verificação significa em produção:** Em um ambiente de produção do Banco Meridian, o cluster ECS ou Kubernetes teria um admission controller (como Kyverno ou OPA Gatekeeper) configurado para rejeitar qualquer deploy de imagem que não tenha uma assinatura Cosign válida do pipeline oficial. Isso significa que mesmo que um atacante comprometesse credenciais do GHCR e fizesse push de uma imagem maliciosa, ela seria rejeitada no deploy porque não teria a assinatura da identidade do pipeline autorizado.

```bash
# Instalar Cosign (se não instalado)
brew install cosign || \
  curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"

# Verificar a assinatura da imagem publicada
IMAGE="ghcr.io/$(gh api /user --jq '.login')/bancomeridian-api-lab02/api:latest"
echo "Verificando: $IMAGE"

cosign verify \
  --certificate-identity-regexp="https://github.com/$(gh api /user --jq '.login')/bancomeridian-api-lab02.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  $IMAGE | python3 -m json.tool

# Resultado esperado: JSON com informações da assinatura incluindo
# o commit SHA, repositório e timestamp
```

---

### Passo 13: Verificar GitHub Code Scanning

**O que este passo faz:** Acessa os alertas de segurança consolidados no GitHub Code Scanning, que é o SAST (Static Application Security Testing) centralizado do repositório. Os dois jobs que geram SARIF — o tfsec (Job 2) e o Trivy (Job 3) — enviam seus resultados para esta interface usando `github/codeql-action/upload-sarif`. O Code Scanning agrega os resultados de múltiplas ferramentas em uma única interface, permite atribuir alertas a responsáveis, rastrear o status de resolução (open, dismissed, fixed), e gera métricas de postura de segurança ao longo do tempo.

**Por que SARIF e não apenas logs:** O formato SARIF (Static Analysis Results Interchange Format) é um padrão aberto da OASIS que permite que qualquer ferramenta de análise estática reporte seus resultados de forma estruturada e interoperável. O GitHub Code Scanning usa SARIF para renderizar os resultados com anotações diretamente no diff do código — você vê a linha exata com o problema destacada, sem precisar interpretar logs de texto. Esta visibilidade integrada no fluxo de revisão de código é o que torna a segurança menos friccionada para os desenvolvedores.

```bash
# Ver alertas no GitHub Code Scanning (SARIF)
gh api repos/$(gh api /user --jq '.login')/bancomeridian-api-lab02/code-scanning/alerts \
  --jq '.[] | "\(.rule.description) — \(.most_recent_instance.location.path)"' | head -20
```

---

### Passo 14: Testar Trivy Scan Localmente

**O que este passo faz:** Executa o Trivy diretamente na máquina local, antes de fazer push. Este é o shift-left máximo da segurança: em vez de esperar o pipeline de CI (que leva 2-3 minutos), o desenvolvedor pode verificar a imagem e o IaC na própria workstation em segundos. O Trivy local é especialmente útil durante o desenvolvimento ativo, quando o desenvolvedor está iterando rápido e não quer esperar o CI para cada mudança pequena.

**A diferença entre os três modos do Trivy demonstrados aqui:** O `trivy image --severity HIGH,CRITICAL` escaneia as camadas da imagem Docker em busca de CVEs conhecidas nos pacotes instalados — comparando contra bases de dados como NVD, GitHub Advisory e Red Hat CVE. O `trivy image --scanners secret` usa análise de expressões regulares e entropia para detectar strings que parecem segredos (chaves AWS, tokens GitHub, senhas em formato padrão) hardcoded na imagem. O `trivy config ./terraform/` escaneia os arquivos HCL do Terraform localmente, similar ao que o Checkov faz no CI mas com as regras da engine do Trivy — útil como segunda opinião antes do push.

**Por que executar o Trivy localmente se ele já roda no CI:** O custo de uma falha no CI é alto: demora de minutos para descobrir, interrompe o fluxo de trabalho e pode bloquear outros membros da equipe que dependem do mesmo pipeline. O Trivy local cria um ciclo de feedback de segundos que economiza tempo e mantém o ritmo de desenvolvimento. Esta abordagem segue o princípio "fail fast" do DevSecOps.

```bash
# Instalar Trivy
brew install trivy || \
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan da imagem localmente (antes de enviar para CI)
docker build -t bancomeridian-api-test ./app/

# Scan de vulnerabilidades
trivy image --severity HIGH,CRITICAL --exit-code 1 bancomeridian-api-test:latest

# Scan de secrets
trivy image --scanners secret bancomeridian-api-test:latest

# Scan IaC
trivy config ./terraform/ --severity HIGH,CRITICAL
```

---

### Passo 15: Documentar o Pipeline para o CISO

**O que este passo faz:** Cria a documentação executiva do pipeline DevSecOps para o CISO do Banco Meridian — o documento que justifica o desbloqueio do deploy e serve como evidência de conformidade regulatória. O arquivo `DEVSECOPS-PIPELINE.md` tem dois públicos: o CISO e os auditores do BACEN. Para o CISO, a tabela de etapas com a coluna "Ação se Falhar" é o que importa — ela demonstra que controles blocking reais foram implementados, não apenas scanners de relatório. Para os auditores do BACEN, a tabela de Conformidade mapeia cada artigo da Resolução 4.893 para o controle técnico específico e para a evidência auditável que pode ser apresentada em uma inspeção.

**Por que commitar a documentação junto com o código:** Em DevSecOps, documentação-como-código (Docs as Code) significa que a documentação vive no mesmo repositório que o pipeline que ela descreve. Isso garante que quando o pipeline mudar, a documentação seja atualizada no mesmo PR — evitando divergência entre o que está documentado e o que está implementado. O `git commit` e `git push` da documentação criam um registro imutável de quando o pipeline foi documentado e aprovado, o que é em si uma evidência de governança.

```bash
cat > DEVSECOPS-PIPELINE.md << 'DOC'
# Pipeline DevSecOps — Banco Meridian API Financeira

## Visão Geral

Este repositório implementa um pipeline de segurança completo para o ciclo de
vida da API Financeira do Banco Meridian.

## Etapas de Segurança

| Etapa | Ferramenta | O que Verifica | Ação se Falhar |
|:------|:-----------|:---------------|:--------------:|
| IaC Scan | Checkov | Misconfigurations CRITICAL/HIGH no Terraform | BLOQUEIA merge |
| IaC Scan | tfsec | Misconfigurations de qualquer severidade | Apenas warn |
| Image Build | Docker buildx | Dockerfile lint | BLOQUEIA build |
| Image Scan | Trivy (vuln) | CVEs CRITICAL/HIGH na imagem | BLOQUEIA push |
| Image Scan | Trivy (secrets) | Secrets hardcoded na imagem | BLOQUEIA push |
| SBOM | Syft | Inventário de componentes | Apenas gera artefato |
| Push | GHCR | Somente se todos os scans passaram | — |
| Sign | Cosign | Assina com identidade do CI/CD | — |
| Verify | Cosign | Verifica assinatura pré-deploy | BLOQUEIA deploy |

## Evidências para Auditoria BACEN 4.893

- SBOM retido por 365 dias (evidência de inventário de componentes)
- SARIF no GitHub Code Scanning (evidência de testes de vulnerabilidade)
- Assinatura Cosign no Rekor (log imutável de cada deploy autorizado)
- GitHub Actions logs (auditoria de quem aprovou cada deploy)

## Conformidade

| Artigo BACEN | Controle | Evidência |
|:-------------|:---------|:----------|
| Art. 5 — Testes de vulnerabilidade | Checkov + Trivy em cada PR | GitHub Actions logs |
| Art. 6 — Monitoramento | SARIF em Code Scanning | GitHub Security |
| Art. 8 — Controle de acesso | Apenas imagens assinadas chegam ao deploy | Cosign + Rekor |
DOC

git add DEVSECOPS-PIPELINE.md
git commit -m "docs: documentar pipeline DevSecOps para evidência BACEN"
git push

echo "Documentação criada e enviada para o repositório"
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Repositório criado | URL GitHub disponível |
| 2 | Terraform com bug intencional | `grep inseguro terraform/main.tf` encontra o bloco |
| 3 | checkov.yaml configurado | Arquivo existe com `hard-fail-on: [CRITICAL, HIGH]` |
| 4 | Dockerfile criado | `docker build` sem erros |
| 5 | Política Rego criada | Arquivo `policy/s3_security.rego` existe |
| 6 | Workflow criado | `.github/workflows/security.yml` existe |
| 7 | PR criada | URL da PR visível |
| 8 | Pipeline falhou | GitHub Actions mostra Checkov com FAILURE |
| 9 | Comentário na PR | Comentário com 3 findings visível na PR |
| 10 | Terraform corrigido | Pipeline rerrodar mostra SUCCESS |
| 11 | SBOM gerado | Artefato `sbom.cyclonedx.json` nos GitHub Artifacts |
| 12 | Assinatura verificada | `cosign verify` retorna JSON com informações da assinatura |
| 13 | Code Scanning ativo | Alertas visíveis em GitHub Security |
| 14 | Trivy local | Scan local executado sem CRITICAL CVE |
| 15 | Documentação | DEVSECOPS-PIPELINE.md no repositório |

---

## 8. Gabarito Completo

### Workflow Final `.github/workflows/security.yml`

O arquivo completo está no Passo 6 deste laboratório.

**Pontos críticos do workflow:**
1. `checkov` tem `continue-on-error: false` — falha o job se encontrar CRITICAL/HIGH
2. `tfsec` tem `soft_fail: true` — nunca falha o job, apenas warn
3. Container push ocorre APENAS após scan de vulnerabilidades passar (`needs: [checkov]`)
4. Cosign sign usa `--yes` e `id-token: write` permission para keyless OIDC
5. `security-gate` job verifica o resultado dos jobs críticos e bloqueia o PR

### Status Esperado dos Jobs — PR com Terraform Inseguro

```
✗ IaC: Checkov Scan           → FAILURE
  Reason: CKV_AWS_19, CKV_AWS_18, CKV_AWS_145

✓ IaC: tfsec Scan             → SUCCESS (soft fail, apenas warn)

[SKIPPED] Container: Build, Scan, Sign → SKIPPED (precisa de push ao main)

✗ Security Gate Final         → FAILURE (dependente do Checkov)

Pull Request: ❌ BLOCKED — "Some required status checks have not passed"
```

### Status Esperado dos Jobs — Após Correção do Terraform

```
✓ IaC: Checkov Scan           → SUCCESS
✓ IaC: tfsec Scan             → SUCCESS
✓ Security Gate Final         → SUCCESS

Pull Request: ✅ READY TO MERGE
```

### Verificação da Assinatura Cosign — Output Esperado

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "ghcr.io/usuario/bancomeridian-api-lab02/api"
      },
      "image": {
        "docker-manifest-digest": "sha256:abc123..."
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "Bundle": {...},
      "Issuer": "https://token.actions.githubusercontent.com",
      "Subject": "https://github.com/usuario/bancomeridian-api-lab02/.github/workflows/security.yml@refs/heads/main",
      "githubWorkflowRef": "refs/heads/main",
      "githubWorkflowRepository": "usuario/bancomeridian-api-lab02",
      "githubWorkflowSha": "abc123..."
    }
  }
]

✅ cosign verify: sucesso — imagem assinada pelo GitHub Actions do repositório
```

### Por que cada resposta do gabarito é correta

**1. Por que `continue-on-error: false` no Checkov e não no tfsec?**

O Checkov é o portão bloqueador primário porque foi configurado com as políticas de risco do Banco Meridian (`hard-fail-on: CRITICAL, HIGH` no `checkov.yaml`). Quando `continue-on-error: false` (o padrão do GitHub Actions), qualquer saída com código diferente de zero faz o step falhar, o job falhar, e o Security Gate falhar — bloqueando o merge. O tfsec tem `soft_fail: true` porque serve como segunda opinião com uma engine diferente. Ter dois scanners com configurações de bloqueio idênticas criaria duplicidade de falsos positivos sem adicionar cobertura real. A combinação "um bloqueia, o outro avisa" é o padrão de mercado para pipelines com múltiplos scanners de IaC.

**2. Por que o job de container tem `needs: [checkov]` e não `needs: [checkov, tfsec]`?**

O `needs: [checkov]` significa que o job de container só roda se o Checkov passou. Não incluir o tfsec na dependência é intencional: o tfsec tem `soft_fail: true`, então ele sempre passa independentemente do que encontrar, e incluí-lo no `needs` seria redundante. Mais importante: se o tfsec por algum motivo falhasse tecnicamente (não por findings, mas por erro de infraestrutura do runner), isso bloquearia a construção do container desnecessariamente. A dependência deve ser apenas dos jobs que realmente bloqueiam por razões de segurança — no caso, o Checkov.

**3. Por que a permissão `id-token: write` é necessária e por que é sensível?**

O `id-token: write` permite que o GitHub Actions solicite um token OIDC da sua própria identidade de CI. O Cosign usa esse token para provar ao Fulcio (a CA da Sigstore) que está rodando em um contexto específico do GitHub Actions, em um repositório específico. Sem essa permissão, o `cosign sign` falha com erro de autenticação OIDC. A permissão é sensível porque, se um workflow malicioso de terceiros tivesse acesso a ela via `pull_request` de fork externo, poderia assinar artefatos em nome do repositório. Por isso o pipeline usa `push` ao main (não PRs de forks) como gatilho para a etapa de assinatura — a identidade do forker não tem permissão de escrever no repositório principal.

**4. Por que o SBOM é salvo com `retention-days: 365` e não por menos tempo?**

A Resolução BACEN 4.893, Art. 5, exige que as instituições financeiras mantenham registros de testes de vulnerabilidade por período compatível com os ciclos de auditoria do BACEN, que tipicamente cobrem o último ano fiscal. O SBOM é parte da evidência de que a instituição conhecia os componentes em produção em um dado momento. Se uma CVE crítica for divulgada em novembro de 2026 afetando uma biblioteca que estava em produção em novembro de 2025, o Banco Meridian precisa conseguir demonstrar ao BACEN quais sistemas tinham aquela biblioteca e quando. O SBOM de 365 dias é a evidência que responde essa pergunta durante uma inspeção regulatória.

**5. Por que o Cosign keyless é preferível a chaves privadas gerenciadas?**

O gerenciamento de chaves privadas cria riscos operacionais: a chave pode vazar, precisa ser rotacionada periodicamente, e o acesso a ela precisa ser controlado e auditado como um segredo de alta criticidade. Com o Cosign keyless via OIDC, não existe chave privada para vazar — a identidade é provada pelo token OIDC efêmero do GitHub Actions, e o certificado emitido pela Fulcio tem validade de apenas 10 minutos. O log no Rekor é imutável e público, o que significa que qualquer tentativa de assinar uma imagem com uma identidade falsa ficaria registrada publicamente e poderia ser detectada. Para o Banco Meridian, isso simplifica a gestão de PKI e cria um audit trail mais robusto do que chaves privadas tradicionais.

**6. Por que o bucket S3 seguro usa `sse_algorithm = "aws:kms"` e não `"AES256"`?**

O `AES256` (SSE-S3) usa chaves gerenciadas inteiramente pela AWS, sem visibilidade ou controle do cliente sobre as operações de criptografia. O `aws:kms` (SSE-KMS) usa o AWS Key Management Service, onde o Banco Meridian é o proprietário das chaves e pode: (a) revogar acesso a dados específicos simplesmente desabilitando a chave KMS, sem precisar mover os dados; (b) ver no CloudTrail cada operação de descriptografia com quem acessou, de qual IP e quando; (c) implementar políticas de chave granulares — por exemplo, apenas a role ECS da API pode descriptografar, e não o time de desenvolvimento diretamente. Para dados financeiros regulados, o CKV_AWS_145 do Checkov exige especificamente KMS por essas razões de controle e auditabilidade que o SSE-S3 não oferece.

**7. Por que o `security-gate` usa `if: always()` em vez do padrão?**

Por padrão, um job com `needs` só roda se todos os jobs dos quais depende passaram com sucesso. Com `if: always()`, o `security-gate` roda independentemente do resultado dos jobs anteriores — isso é essencial porque o gate precisa rodar exatamente quando algo falhou, para dar o veredicto final e gerar o log de "por que o PR foi bloqueado". Sem `if: always()`, se o Checkov falhasse, o security-gate seria pulado (SKIPPED) em vez de rodar e falhar — e um job SKIPPED não bloqueia o merge da mesma forma que um job FAILURE. O `if: always()` garante que o gate sempre dá uma resposta explícita: APROVADO ou REPROVADO, nunca simplesmente ausente.

---

*Lab 02 — Pipeline DevSecOps: IaC + Container Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
