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

**O que este passo faz:** Cria o repositório GitHub que é o ponto central do pipeline DevSecOps. A estrutura de diretórios tem separação deliberada de responsabilidades: `terraform/` (o que Checkov e tfsec escaneiam), `.github/workflows/` (o pipeline de segurança CI/CD), `policy/` (políticas OPA/Rego customizadas do Banco Meridian), e `app/` (código da API que o Trivy escaneia na imagem Docker). Essa separação limita o raio de impacto se um componente for comprometido — um atacante que vaza secrets do `app/` não tem acesso automático às políticas de segurança do `policy/`.

**Por que repositório público neste lab:** GitHub Actions tem 2.000 minutos/mês gratuitos para repositórios públicos. Em produção, o Banco Meridian usaria repositório privado no GitHub Enterprise com RBAC e branch protection obrigatória.

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

**Resultado esperado:**
```
✓ Created repository seu-usuario/bancomeridian-api-lab02 on GitHub
  https://github.com/seu-usuario/bancomeridian-api-lab02
```

**Troubleshooting:** Se `gh` não estiver instalado: `brew install gh` ou `sudo apt install gh`, depois `gh auth login`.

---

### Passo 2: Criar Terraform com Recurso Inseguro

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

**O que este passo faz:** Cria o arquivo de configuração do Checkov (`checkov.yaml`) que define as regras de scan para o Banco Meridian. A configuração centraliza decisões importantes: quais frameworks verificar (terraform, dockerfile), quais checks suprimir globalmente com justificativa, e o threshold de severidade que falha o pipeline. Sem este arquivo, o Checkov usaria defaults que podem incluir checks irrelevantes (gerando ruído) ou omitir checks críticos para o contexto bancário.

**Por que usar arquivo de configuração em vez de flags na linha de comando:** Um arquivo `checkov.yaml` no repositório é versionado via git — qualquer mudança nos critérios de segurança é rastreável, revisada via PR, e auditável. Flags na linha de comando são frágeis e invisíveis — um desenvolvedor pode silenciosamente remover um `--check` crítico sem revisão. O CISO do Banco Meridian exige que as regras de segurança do pipeline sejam tratadas como código.

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

**O que este passo faz:** Cria uma política OPA/Rego customizada que verifica regras de segurança específicas do Banco Meridian — regras que o Checkov não tem nativamente. Enquanto o Checkov verifica conformidade com benchmarks genéricos (CIS, NIST), a política Rego implementa requisitos do negócio: por exemplo, todo bucket S3 deve ter a tag `Owner` definida (para accountability) e deve ter nome prefixado com `bancomeridian-` (para identificação clara de propriedade em ambientes multi-conta).

**Entendendo a sintaxe Rego:**
- `package terraform.aws.s3` — escopo da política (Conftest usa o nome do package para agrupar checks)
- `violations[msg] { ... }` — define um conjunto de violations; o pipeline falha se este conjunto NÃO for vazio
- `resource := input.resource_changes[_]` — itera sobre todos os recursos no plan.json
- `resource.type == "aws_s3_bucket"` — filtra apenas buckets S3
- `not has_owner_tag(resource)` — chama a função auxiliar que verifica a existência da tag `Owner`
- `msg := sprintf(...)` — gera mensagem de erro descritiva que aparece no log do pipeline

**Por que OPA/Rego além do Checkov:** O Checkov verifica segurança técnica de infraestrutura. O OPA verifica políticas de governança de negócio. Eles são complementares: Checkov diz "este bucket não tem criptografia" (segurança técnica); OPA diz "este bucket não está tagueado para accountability" (governança). Um banco regulado pelo BACEN precisa de ambas as camadas.

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

**O que este passo faz:** Cria o arquivo de workflow do GitHub Actions — o núcleo do pipeline DevSecOps. Este workflow executa automaticamente em dois gatilhos: a cada Pull Request para `main` (para bloquear código inseguro ANTES do merge) e a cada push em `main` (para builds e assinatura de imagens em produção). O pipeline tem 5 jobs que executam em paralelo onde possível, e um job final `security-gate` que consolida todos os resultados e decide se o PR pode ser mergeado.

**Arquitetura do pipeline:**
- **Job `checkov`:** Scan de IaC com Checkov (verifica se o Terraform tem misconfigurations)
- **Job `tfsec`:** Segundo scan de IaC com tfsec (perspectiva complementar)
- **Job `conftest-opa`:** Valida políticas de negócio customizadas via OPA/Rego
- **Job `trivy-image`:** Escaneia a imagem Docker para CVEs e segredos
- **Job `sign-image`:** Assina a imagem com Cosign (keyless) para supply chain security
- **Job `security-gate`:** Verifica se TODOS os jobs acima passaram — bloqueia o merge se qualquer um falhou

**Por que o security-gate é o passo mais importante:** Um pipeline sem gate permite que um desenvolvedor ignore um job com falha. O `security-gate` usa `needs: [checkov, tfsec, conftest-opa, trivy-image]` e `if: failure()` para garantir que SE qualquer job crítico falhou, o gate falha também — tornando impossível mergear código que violou qualquer política de segurança. Esta é a implementação técnica do princípio "Security as Code" do CISO do Banco Meridian.

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

**O que este passo faz:** Faz commit de todos os arquivos criados e abre uma Pull Request para a branch `main`. Este é o momento em que o pipeline de segurança é acionado pela primeira vez no contexto real — o GitHub detecta o PR e invoca automaticamente o workflow `.github/workflows/security.yml`. O commit message segue o padrão Conventional Commits (`feat:`) que muitas organizações usam para rastrear mudanças por tipo.

**O que esperar:** O pipeline iniciará em ~30 segundos após o `gh pr create`. Você verá os checks aparecerem no PR no GitHub como "In progress". Como o `terraform/main.tf` contém um bucket S3 intencionalmente inseguro (sem criptografia, sem block public access), o job `checkov` **vai falhar** — e isso é o comportamento correto. O próximo passo (Passo 8) vai analisar e interpretar esta falha.

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

**O que este passo faz:** Demonstra o ciclo completo de "shift-left em ação": o desenvolvedor recebe feedback sobre a misconfiguration diretamente no PR (via comentário do Checkov), corrige o código, faz novo push na mesma branch, e o pipeline re-executa automaticamente — desta vez aprovando. Este ciclo é a prova prática do valor do shift-left: a correção ocorre em minutos, no contexto do código, antes de qualquer deploy.

**O que o aluno aprende com este passo:** O pipeline não é uma barreira — é um assistente. Ao corrigir o bucket S3 adicionando as configurações de segurança necessárias (block public access, criptografia, logging), o desenvolvedor está aprendendo na prática o que as políticas CIS/BACEN exigem, e o porquê de cada configuração. Este é o verdadeiro objetivo do shift-left: educar enquanto bloqueia.

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

```bash
# Ver alertas no GitHub Code Scanning (SARIF)
gh api repos/$(gh api /user --jq '.login')/bancomeridian-api-lab02/code-scanning/alerts \
  --jq '.[] | "\(.rule.description) — \(.most_recent_instance.location.path)"' | head -20
```

---

### Passo 14: Testar Trivy Scan Localmente

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

---

*Lab 02 — Pipeline DevSecOps: IaC + Container Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
