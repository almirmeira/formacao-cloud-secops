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

O repositório GitHub da API financeira existe mas não tem nenhum controle de segurança no pipeline. O time de desenvolvimento quer fazer o primeiro deploy na próxima semana e o CISO bloqueou o deploy até que o pipeline de segurança esteja implementado. O código Terraform criará recursos AWS (ECS, S3, IAM). A imagem Docker pode ter CVEs. Secrets podem estar hardcoded. Sem o pipeline, esses problemas só serão descobertos em produção.

---

## 3. Problema Identificado

Sem controle de segurança no pipeline:
- Qualquer desenvolvedor pode criar recursos AWS inseguros via Terraform
- Imagens Docker com CVEs críticas podem chegar ao cluster Kubernetes
- Secrets hardcoded podem ser expostos no registro de imagens
- Sem SBOM, é impossível responder "quais imagens são afetadas por CVE-2024-XXXXX?"

---

## 4. Roteiro de Atividades

1. Criar repositório GitHub com estrutura do projeto
2. Escrever Terraform com recurso intencionalmente inseguro
3. Configurar Checkov com arquivo checkov.yaml
4. Criar Dockerfile multi-stage com usuário não-root
5. Criar política Rego para validação adicional
6. Criar o workflow GitHub Actions completo
7. Fazer push e criar PR
8. Verificar falha do pipeline (Terraform inseguro)
9. Verificar comentário automático na PR
10. Corrigir o Terraform e verificar aprovação
11. Verificar SBOM no GitHub Security
12. Verificar assinatura Cosign
13. Verificar GitHub Code Scanning
14. Testar Trivy scan localmente
15. Documentar o pipeline para o CISO

---

## 5. Proposição

Ao final deste laboratório, você terá um pipeline completo `.github/workflows/security.yml` que bloqueia automaticamente qualquer IaC com findings CRITICAL, impede o push de imagens com CVEs críticas, e assina cada imagem aprovada com Cosign.

---

## 6. Script Passo a Passo

### Passo 1: Criar Repositório GitHub

**O que este passo faz:** Cria o repositório GitHub que será o ponto central do pipeline DevSecOps do Banco Meridian. A estrutura de diretórios que criaremos (`terraform/`, `.github/workflows/`, `policy/`, `app/`) separa as preocupações: IaC fica em `terraform/`, as automações CI/CD ficam em `.github/workflows/`, as políticas OPA ficam em `policy/`, e o código da API fica em `app/`. Essa separação é uma prática de segurança — limita o raio de impacto se um componente for comprometido.

**Por que agora:** O repositório é a base de todo o laboratório. Todas as ferramentas (Checkov, tfsec, Trivy, Cosign) serão configuradas como etapas de um workflow do GitHub Actions que roda automaticamente a cada commit. Sem o repositório, não há pipeline.

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
Created repository seu-usuario/bancomeridian-api-lab02 on GitHub
  https://github.com/seu-usuario/bancomeridian-api-lab02
```
O `--remote=origin` significa que o repositório local já está vinculado ao GitHub — você pode confirmar com `git remote -v`. O flag `--public` é necessário para usar o GitHub Actions gratuito neste laboratório; em produção, o Banco Meridian usaria um repositório privado com GitHub Teams ou GitHub Enterprise.

**Troubleshooting:** Se `gh` não estiver instalado: `brew install gh` ou `sudo apt install gh`, depois `gh auth login`.

---

### Passo 2: Criar Terraform com Recurso Inseguro

**O que este passo faz:** Cria dois recursos Terraform — um bucket S3 intencionalmente inseguro (sem block public access, sem logging, sem criptografia KMS) e um bucket S3 seguro com todas as configurações corretas. O bucket inseguro é proposital: ele vai fazer o Checkov falhar no Passo 8, demonstrando que o pipeline bloqueia código problemático antes que chegue à AWS. Os IDs dos checks do Checkov que vão falhar estão documentados nos comentários do código (`CKV_AWS_19`, `CKV_AWS_18`, `CKV_AWS_145`).

**Por que agora:** Você precisa ter código Terraform com problema real para o pipeline ter algo para detectar e bloquear. O bucket seguro serve como referência de "como deve ser feito" e passará em todos os checks.

```bash
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

# BUCKET INSEGURO — para demonstração do pipeline falhando
# Este bucket INTENCIALMENTE vai falhar no Checkov:
#   CKV_AWS_19: sem block public access
#   CKV_AWS_18: sem access logging
#   CKV_AWS_145: sem criptografia KMS
resource "aws_s3_bucket" "api_storage_inseguro" {
  bucket = "${var.project_name}-storage-inseguro"
}

# BUCKET SEGURO — para demonstração do pipeline passando
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

**O que este passo faz:** Cria o arquivo de configuração `checkov.yaml` que define o comportamento do Checkov no pipeline. As opções mais importantes: `hard-fail-on: [CRITICAL, HIGH]` faz o pipeline falhar completamente se encontrar misconfigurations críticas ou de alta severidade; `soft-fail-on: [MEDIUM, LOW]` apenas gera avisos para problemas menores sem bloquear. Os `skip-path` evitam que o Checkov analise o diretório `.terraform/` que contém providers baixados automaticamente, não código customizado do time.

**Por que agora:** O `checkov.yaml` precisa existir antes de criar o workflow do GitHub Actions, porque o workflow o referenciará. Definir o comportamento de falha em um arquivo de configuração é melhor do que hardcodá-lo nos flags da linha de comando — centraliza a política de segurança em um único lugar versionável.

```bash
cat > checkov.yaml << 'YAML'
# checkov.yaml — configuração do Banco Meridian

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

skip-check: []

skip-path:
  - .terraform/
  - terraform/.terraform/

output:
  - cli
  - json

output-file-path: checkov-results/
YAML

echo "checkov.yaml configurado"
```

---

### Passo 4: Criar Dockerfile para a API

**O que este passo faz:** Cria o Dockerfile da API financeira do Banco Meridian usando o padrão multi-stage e usuário não-root. O multi-stage (`FROM python:3.11-slim AS builder` → `FROM python:3.11-slim`) é uma técnica de segurança: o stage de build tem as ferramentas de compilação, mas o stage final (runtime) copia apenas os binários compilados, sem ferramentas de desenvolvimento. O `useradd -r appuser` e `USER appuser` garantem que o processo principal do container nunca rode como root — isso previne que um atacante que obtenha RCE no container consiga instalar pacotes, modificar arquivos de sistema, ou tentar container escape via syscalls privilegiadas.

**Por que agora:** O Dockerfile precisa existir antes de configurar o pipeline que vai fazer o build e scan da imagem. O Checkov também analisa Dockerfiles — um com `USER root` explícito falharia no check `CKV_DS_4`.

```bash
mkdir -p app

cat > app/Dockerfile << 'DOCKERFILE'
# Dockerfile seguro — Banco Meridian API
# Boas práticas: não-root, multi-stage, imagem mínima

# Stage 1: Build
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime (sem ferramentas de build)
FROM python:3.11-slim

# Criar usuário não-root (atende CKV_DS_4)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser app/ .

USER appuser

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

EXPOSE 8080

CMD ["python", "main.py"]
DOCKERFILE

cat > app/requirements.txt << 'REQ'
fastapi==0.109.0
uvicorn==0.27.0
REQ

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

**O que este passo faz:** Cria uma política OPA/Rego que valida se todo bucket S3 no Terraform tem um recurso `aws_s3_bucket_public_access_block` correspondente. A lógica em linguagem natural: "Se existe um recurso `aws_s3_bucket` e não existe nenhum `aws_s3_bucket_public_access_block` no mesmo plano Terraform, gere uma violação". O Rego é a linguagem declarativa do Open Policy Agent — você descreve o que é uma violação, não como encontrá-la. A regra `deny[msg]` coleta todas as mensagens e as retorna ao avaliador.

**Por que agora:** O Checkov verifica misconfigurations dentro de um recurso, mas não verifica relacionamentos entre recursos. Esta política Rego cobre essa lacuna: ela verifica se o recurso de segurança complementar existe para cada bucket. Juntos, Checkov e OPA oferecem cobertura mais ampla.

```bash
cat > policy/s3_security.rego << 'REGO'
package terraform.aws.s3

# Regra: todo bucket S3 deve ter block public access configurado
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"

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

**O que este passo faz:** Cria o arquivo principal do pipeline DevSecOps — `.github/workflows/security.yml`. Este workflow orquestra 4 jobs:

**Job `checkov`** (IaC Security Scan): analisa o Terraform, **bloqueia o merge** se encontrar CRITICAL/HIGH via `continue-on-error: false`, publica comentário automático na PR com os findings, salva resultados como artefato por 90 dias.

**Job `tfsec`**: complementa o Checkov como segunda perspectiva. O `soft_fail: true` significa que o tfsec **nunca bloqueia** — apenas gera warnings no GitHub Code Scanning via SARIF.

**Job `container-security`**: executa somente em push ao main (não em PRs). Sequência: build → Trivy CVE scan (bloqueia em CRITICAL) → Trivy secrets scan (bloqueia) → Syft SBOM (salvo 365 dias como evidência BACEN) → push para GHCR → Cosign sign keyless → Cosign verify.

**Job `security-gate`**: verifica o resultado dos jobs críticos e falha o workflow se o Checkov falhou, garantindo que o status do PR apareça como bloqueado no GitHub.

**Por que agora:** Este é o passo central do laboratório. Todos os passos anteriores prepararam os arquivos que este workflow vai processar. O workflow é disparado automaticamente quando você criar a PR no Passo 7.

```bash
cat > .github/workflows/security.yml << 'WORKFLOW'
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
  # JOB 1: CHECKOV — IaC Security Scan
  # Falha em CRITICAL/HIGH, warn em MEDIUM/LOW
  checkov:
    name: "IaC: Checkov Scan"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Instalar Checkov
        run: pip install checkov

      - name: Executar Checkov (falha em CRITICAL/HIGH)
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
                ? `FALHOU: ${failed.length} findings CRITICAL/HIGH\n\n` +
                  failed.slice(0, 10).map(c =>
                    `- [${c.check_id}] ${c.check.name} em ${c.file_path}:${c.file_line_range[0]}`
                  ).join('\n')
                : 'APROVADO: Sem findings CRITICAL/HIGH';
            } catch(e) {
              body += `Erro ao processar relatório: ${e.message}`;
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

  # JOB 2: TFSEC — Terraform Security Scanner (apenas warn)
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

  # JOB 3: CONTAINER — Build + Scan + SBOM + Sign
  # Executa somente no push ao main
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

      - name: Build imagem Docker (sem push ainda)
        uses: docker/build-push-action@v5
        with:
          context: ./app
          file: ./app/Dockerfile
          push: false
          load: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

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

      - name: Instalar Cosign
        uses: sigstore/cosign-installer@v3

      - name: Cosign — Assinar imagem (keyless via OIDC)
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}

      - name: Cosign — Verificar assinatura (pré-deploy)
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}.*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}
          echo "Verificado — imagem autorizada para deploy"

  # JOB 4: SECURITY GATE — Decisão Final
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
            echo "SECURITY GATE: FALHOU — Checkov encontrou CRITICAL/HIGH"
            exit 1
          fi

          echo "SECURITY GATE: APROVADO — Sem blocking findings"
WORKFLOW

echo "Workflow GitHub Actions criado"
```

---

### Passo 7: Fazer Push e Criar PR

**O que este passo faz:** Faz commit de todos os arquivos criados, cria uma branch `feature/devsecops-pipeline` e abre uma Pull Request no GitHub. A PR é o evento que dispara o workflow — o GitHub Actions roda os jobs `checkov`, `tfsec` e `security-gate` automaticamente quando a PR é criada. A PR é criada intencionalmente com o Terraform inseguro para observar o pipeline bloquear.

**Por que agora:** Você precisa de uma PR para ver o pipeline em ação e confirmar que o bloqueio funciona antes de corrigir o código.

```bash
git add .
git commit -m "feat: adicionar pipeline DevSecOps — Terraform inseguro intencional para demo"

git checkout -b feature/devsecops-pipeline
git push -u origin feature/devsecops-pipeline

gh pr create \
  --title "feat: implementar pipeline DevSecOps completo" \
  --body "Pipeline com Checkov, tfsec, Trivy, Syft e Cosign.

AVISO: Contém Terraform intencionalmente inseguro para demonstrar o bloqueio."
```

**O que você deve ver:**
```
https://github.com/seu-usuario/bancomeridian-api-lab02/pull/1
```

---

### Passo 8: Verificar Falha do Pipeline

**O que este passo faz:** Aguarda a execução do workflow e confirma que o Checkov detectou os 3 findings CRITICAL/HIGH no arquivo Terraform inseguro. O `gh run watch` mostra o progresso em tempo real. O `gh pr checks` exibe o status final — você deve ver Checkov com `FAILURE` e Security Gate com `FAILURE`. O tfsec aparece como `SUCCESS` por ter `soft_fail: true`.

**Por que agora:** Esta é a verificação de que o bloqueio funciona. Se o Checkov não falhou, há algo errado no workflow e você precisa investigar antes de continuar.

```bash
# Aguardar execução do workflow (2-3 minutos)
gh run watch

# Verificar status final
gh pr checks
```

**O que você deve ver:**
```
FALHA: IaC: Checkov Scan    — Reason: CKV_AWS_19, CKV_AWS_18, CKV_AWS_145
OK:    IaC: tfsec Scan      — SUCCESS (apenas warn)
FALHA: Security Gate Final  — FAILURE (dependente do Checkov)
```

---

### Passo 9: Verificar Comentário Automático na PR

**O que este passo faz:** Verifica o comentário automático publicado na PR pelo GitHub Actions. O step lê o JSON do Checkov e formata uma mensagem com a lista de findings CRITICAL/HIGH: ID do check, nome descritivo, arquivo e linha. Esse comentário é o que o desenvolvedor vê quando o pipeline bloqueia o código — ele explica exatamente o que precisa ser corrigido, tornando o DevSecOps colaborativo e não apenas restritivo.

**Por que agora:** Validar que o comentário foi publicado confirma que o feedback loop está funcionando. Um pipeline que bloqueia sem explicar o motivo cria fricção desnecessária entre os times de desenvolvimento e segurança.

```bash
gh pr view --comments

# Esperado:
# "## Checkov IaC Security Scan
# FALHOU: 3 findings CRITICAL/HIGH
# - [CKV_AWS_19] S3 bucket sem block public access em terraform/main.tf:10
# - [CKV_AWS_18] S3 bucket sem access logging em terraform/main.tf:10
# - [CKV_AWS_145] S3 bucket sem criptografia KMS em terraform/main.tf:10"
```

---

### Passo 10: Corrigir o Terraform e Verificar Aprovação

**O que este passo faz:** Corrige o bucket Terraform inseguro adicionando os 3 recursos que estavam faltando. Cada recurso resolve um dos 3 checks que falhavam no Checkov: `aws_s3_bucket_public_access_block` resolve CKV_AWS_19, `aws_s3_bucket_server_side_encryption_configuration` resolve CKV_AWS_145, `aws_s3_bucket_logging` resolve CKV_AWS_18. Depois do commit e push, o GitHub Actions detecta automaticamente o novo commit na PR e reroda o pipeline.

**Por que agora:** A correção demonstra o ciclo completo do DevSecOps: detectar → reportar → corrigir → verificar. Este é o fluxo que o Banco Meridian usará em produção para todo código novo.

```bash
cat >> terraform/main.tf << 'TF'

# Correção dos findings Checkov no bucket inseguro
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

git add terraform/main.tf
git commit -m "fix: resolver findings Checkov CKV_AWS_19, CKV_AWS_18, CKV_AWS_145"
git push

gh run watch
gh pr checks

# Resultado esperado:
# OK: IaC: Checkov Scan   — SUCCESS
# OK: IaC: tfsec Scan     — SUCCESS
# OK: Security Gate Final — SUCCESS
# PR APROVADO para merge
```

---

### Passo 11: Verificar SBOM no GitHub Security

**O que este passo faz:** Após o merge no main, o job `container-security` executa e gera o SBOM (Software Bill of Materials) da imagem Docker usando o Syft. O SBOM é um inventário completo de todos os componentes de software na imagem — sistema operacional, bibliotecas Python (fastapi, uvicorn), dependências transitivas, e suas versões exatas. O formato CycloneDX é um padrão aberto suportado por ferramentas de análise. O SBOM é salvo por 365 dias como evidência — se uma CVE nova for descoberta 6 meses depois, você pode verificar quais imagens implantadas são afetadas.

**Por que agora:** O SBOM só é gerado após o merge no main (o job `container-security` tem `if: github.ref == 'refs/heads/main'`). Este passo verifica que o artefato foi gerado corretamente.

```bash
gh run list --limit 5

# Baixar o SBOM
gh run download --name sbom-$(git rev-parse HEAD)
ls sbom.cyclonedx.json

# Analisar o SBOM
cat sbom.cyclonedx.json | python3 -c "
import json, sys
sbom = json.load(sys.stdin)
components = sbom.get('components', [])
print(f'Componentes no SBOM: {len(components)}')
for c in components[:10]:
    print(f'  - {c.get(\"name\",\"?\")}:{c.get(\"version\",\"?\")}')
"
```

---

### Passo 12: Verificar Assinatura Cosign

**O que este passo faz:** Verifica localmente a assinatura Cosign da imagem publicada no GHCR. O Cosign keyless usa OIDC — em vez de gerenciar uma chave privada, a assinatura é associada à identidade do workflow do GitHub Actions (via OIDC token) e registrada no Rekor, um log de transparência imutável e público. O parâmetro `--certificate-identity-regexp` verifica que a assinatura veio exatamente do workflow deste repositório, e `--certificate-oidc-issuer` verifica que o token OIDC foi emitido pelo GitHub Actions.

**Por que agora:** A verificação da assinatura é o passo final do ciclo de Supply Chain Security. Ela garante que a imagem a ser deployada é exatamente a imagem que passou pelo pipeline de segurança — nenhum atacante pode injetar uma imagem não assinada no fluxo de deploy.

```bash
brew install cosign || \
  curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"

IMAGE="ghcr.io/$(gh api /user --jq '.login')/bancomeridian-api-lab02/api:latest"
echo "Verificando: $IMAGE"

cosign verify \
  --certificate-identity-regexp="https://github.com/$(gh api /user --jq '.login')/bancomeridian-api-lab02.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  $IMAGE | python3 -m json.tool
```

---

### Passo 13: Verificar GitHub Code Scanning

**O que este passo faz:** Consulta os alertas do GitHub Code Scanning populados pelos arquivos SARIF enviados pelos jobs `tfsec` e `trivy`. O Code Scanning é o painel de segurança nativo do GitHub — consolida findings de múltiplas ferramentas em uma interface unificada, com rastreamento de status (aberto/resolvido), filtros por severidade e branch.

**Por que agora:** O Code Scanning persiste os findings além da execução do workflow — enquanto os artifacts têm retenção de 90 dias, os alertas do Code Scanning ficam vinculados ao repositório e podem ser consultados a qualquer momento pelo time de segurança.

```bash
gh api repos/$(gh api /user --jq '.login')/bancomeridian-api-lab02/code-scanning/alerts \
  --jq '.[] | "\(.rule.description) — \(.most_recent_instance.location.path)"' | head -20
```

---

### Passo 14: Testar Trivy Scan Localmente

**O que este passo faz:** Executa o Trivy localmente para simular o que o pipeline fará — detectando CVEs e secrets antes do push. O `--exit-code 1` faz o comando retornar erro se encontrar vulnerabilidades, o que pode ser integrado em git hooks de pré-push. Testar localmente economiza tempo de pipeline e implementa o princípio "shift left" do DevSecOps: mover os controles de segurança o mais cedo possível no ciclo de desenvolvimento.

**Por que agora:** Executar o Trivy antes do commit é mais eficiente do que descobrir o problema no pipeline após o push. Um desenvolvedor que testa localmente antes de commitar fecha o ciclo de feedback em segundos em vez de minutos.

```bash
brew install trivy || \
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

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

**O que este passo faz:** Cria o arquivo `DEVSECOPS-PIPELINE.md` com a documentação completa do pipeline — uma tabela com cada etapa de segurança, o que verifica, e a ação em caso de falha. A seção "Evidências para Auditoria BACEN" mapeia cada artefato gerado para o artigo específico do BACEN 4.893 que ele atende. Este documento é o entregável formal para o CISO e para a auditoria BACEN — transforma o pipeline técnico em evidência de conformidade.

**Por que agora:** O pipeline está funcionando. Agora ele precisa ser documentado de forma que o CISO e os auditores possam entender o que ele faz, por que faz, e quais evidências ele gera. Sem documentação, o pipeline existe mas não prova conformidade.

```bash
cat > DEVSECOPS-PIPELINE.md << 'DOC'
# Pipeline DevSecOps — Banco Meridian API Financeira

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

| Artigo BACEN | Controle | Evidência Gerada |
|:-------------|:---------|:-----------------|
| Art. 5 — Testes de vulnerabilidade | Checkov + Trivy em cada PR | GitHub Actions logs + SARIF |
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

### Status Esperado dos Jobs — PR com Terraform Inseguro

```
FALHA: IaC: Checkov Scan           → FAILURE
  Reason: CKV_AWS_19, CKV_AWS_18, CKV_AWS_145

OK:    IaC: tfsec Scan             → SUCCESS (soft fail, apenas warn)

SKIP:  Container: Build, Scan, Sign → SKIPPED (somente no push ao main)

FALHA: Security Gate Final         → FAILURE (dependente do Checkov)

Pull Request: BLOCKED — "Some required status checks have not passed"
```

**Por que esta é a resposta correta:** O Checkov detecta os 3 checks que o bucket inseguro viola: `CKV_AWS_19` (sem block public access), `CKV_AWS_18` (sem access logging), `CKV_AWS_145` (sem criptografia KMS). O tfsec tem `soft_fail: true` — serve como segunda opinião no Code Scanning sem bloquear o fluxo. O job `container-security` fica SKIPPED porque tem `if: github.ref == 'refs/heads/main' && github.event_name == 'push'` — PRs não atendem essa condição.

**Erro mais comum:** Esperar que o tfsec bloqueie o PR. O tfsec está configurado com `soft_fail: true` propositalmente. Usar duas ferramentas com comportamentos diferentes (uma bloqueia, outra avisa) é uma estratégia deliberada: o Checkov garante a barreira de qualidade, o tfsec oferece visibilidade adicional sem criar fricção excessiva no processo de desenvolvimento.

---

### Status Esperado dos Jobs — Após Correção do Terraform

```
OK: IaC: Checkov Scan           → SUCCESS
OK: IaC: tfsec Scan             → SUCCESS
OK: Security Gate Final         → SUCCESS

Pull Request: READY TO MERGE
```

---

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
      "Issuer": "https://token.actions.githubusercontent.com",
      "Subject": "https://github.com/usuario/bancomeridian-api-lab02/.github/workflows/security.yml@refs/heads/main",
      "githubWorkflowRef": "refs/heads/main",
      "githubWorkflowRepository": "usuario/bancomeridian-api-lab02",
      "githubWorkflowSha": "abc123..."
    }
  }
]
```

**Por que esta é a resposta correta:** Os campos mais importantes são `Issuer` (deve ser `https://token.actions.githubusercontent.com` — confirma que foi o GitHub Actions), `Subject` (aponta para o arquivo de workflow específico e o branch `main`), e `githubWorkflowSha` (o commit SHA exato). Esses campos provam a cadeia de custódia: esta imagem foi gerada pelo workflow X, do commit Y, no branch main.

**Erro mais comum:** Tentar verificar a assinatura sem os flags `--certificate-identity-regexp` e `--certificate-oidc-issuer`. Sem esses flags o Cosign aceita qualquer assinatura válida no Rekor — incluindo assinaturas de outros repositórios. Os dois flags juntos garantem que a assinatura veio especificamente do pipeline DevSecOps do Banco Meridian.

---

*Lab 02 — Pipeline DevSecOps: IaC + Container Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
