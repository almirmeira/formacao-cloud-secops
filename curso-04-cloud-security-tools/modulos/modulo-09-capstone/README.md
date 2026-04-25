# Módulo 09 — Capstone: Avaliação de Postura Multi-Cloud do Banco Meridian
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 6 / CCSK (integração de todos os domínios)  
> **Cenário:** Avaliação completa antes de auditoria BACEN — Banco Meridian Multi-Cloud

---

## Cenário do Capstone

O Banco Meridian está se preparando para uma auditoria do BACEN prevista para 60 dias. O CISO contratou você como Cloud Security Architect para conduzir uma avaliação de postura completa do ambiente multi-cloud:

- **AWS Production Account:** ~120 recursos (EC2, S3, RDS, Lambda, EKS)
- **Azure M365 Tenant:** Microsoft 365 E3, Azure DevOps
- **Kubernetes:** 2 clusters EKS em produção
- **GitHub:** Repositórios com Terraform para toda a infra

**Objetivo:** Gerar evidências técnicas para a auditoria do BACEN, identificar gaps críticos e propor um roadmap de remediação de 60 dias.

---

## Entregáveis do Capstone

### Entregável 1: Relatório Prowler — CSPM AWS

**Objetivo:** Escanear a conta AWS sandbox e filtrar os achados mais críticos mapeados para BACEN 4.893.

**Execução:**

```bash
# Configurar conta sandbox
export AWS_PROFILE=bancomeridian-sandbox
aws sts get-caller-identity

# Executar Prowler com compliance BACEN e CIS AWS
prowler aws \
  --profile bancomeridian-sandbox \
  --severity critical high \
  --compliance brazil_lgpd cis_aws_foundations_benchmark_v3.0 \
  --output-formats html json csv \
  --output-path ./capstone-results/prowler/ \
  --security-hub

# Filtrar apenas CRITICAL e HIGH para relatório executivo
cat capstone-results/prowler/prowler-output.json | python3 - <<'PYEOF'
import json, sys
from datetime import datetime

with open('capstone-results/prowler/prowler-output.json') as f:
    findings = json.load(f)

critical = [f for f in findings if f.get('severity') == 'critical']
high = [f for f in findings if f.get('severity') == 'high']

print(f"=== RELATÓRIO RESUMO — PROWLER BANCO MERIDIAN ===")
print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
print(f"CRITICAL: {len(critical)}")
print(f"HIGH: {len(high)}")
print()
print("TOP 10 FINDINGS CRÍTICOS:")
for i, f in enumerate(critical[:10], 1):
    print(f"{i}. [{f['check_id']}] {f['title']}")
    print(f"   Recurso: {f.get('resource_name', 'N/A')}")
    print(f"   BACEN: {f.get('compliance', {}).get('BACEN-4893', 'N/A')}")
    print()
PYEOF
```

**Mapeamento para BACEN 4.893:**

| Finding Prowler | Artigo BACEN | Impacto de Negócio | Prazo |
|:----------------|:------------:|:-------------------|:-----:|
| S3 bucket público com dados de clientes | Art. 5 + Art. 6 + LGPD Art. 46 | Multa BACEN + exposição PII | 24h |
| IAM root account sem MFA | Art. 8 | Comprometimento total da conta | 24h |
| CloudTrail desabilitado em 3 regiões | Art. 6 | Sem auditabilidade — falha na auditoria BACEN | 48h |
| RDS instance publicly accessible | Art. 5 | Banco de dados exposto | 48h |
| Security Group SSH 0.0.0.0/0 (12 instâncias) | Art. 5 | Acesso remoto não autorizado | 7 dias |
| EBS volumes sem criptografia (25 volumes) | Art. 5 + LGPD Art. 46 | Dados em disco sem proteção | 7 dias |
| IAM users sem MFA (8 usuários) | Art. 8 | Autenticação fraca | 7 dias |
| Secrets no Secrets Manager sem rotação (90d+) | Art. 8 | Credenciais potencialmente comprometidas | 30 dias |

**Relatório executivo Prowler — estrutura esperada:**

```
RELATÓRIO EXECUTIVO DE POSTURA DE SEGURANÇA CLOUD
Banco Meridian — AWS Production Account
Data: 24/04/2025

SUMÁRIO EXECUTIVO
Security Score: 58/100 (meta: 85+ para auditoria BACEN)
Findings: 4 CRITICAL | 23 HIGH | 187 MEDIUM | 1.204 LOW
Conformidade BACEN 4.893: 58% (23 de 40 controles relevantes)
Conformidade CIS AWS v3.0: 63%

RISCOS IMEDIATOS (24–48h)
1. [CRITICAL] 2 buckets S3 com dados de clientes acessíveis publicamente
   → Violação direta da LGPD Art. 46 + BACEN 4.893 Art. 5
   → Remediação: aws s3api put-public-access-block [estimativa: 30min]

2. [CRITICAL] Conta root sem MFA habilitado
   → Risco: compromisso total da conta AWS
   → Remediação: habilitar MFA virtual na conta root [estimativa: 15min]

[continuação...]

ROADMAP 30/60/90 DIAS
[30 dias] Resolver todos os CRITICAL + HIGH (27 findings)
[60 dias] Atingir 75% de conformidade BACEN
[90 dias] Atingir 85% de conformidade BACEN + implementar monitoramento contínuo
```

---

### Entregável 2: Pipeline DevSecOps

**Objetivo:** Criar repositório GitHub com Terraform e workflow que bloqueia PR se CRITICAL.

**Estrutura do repositório:**

```
bancomeridian-iac-capstone/
├── terraform/
│   ├── main.tf          (S3 bucket, IAM role, Security Group)
│   ├── variables.tf
│   └── outputs.tf
├── policy/
│   ├── s3_security.rego
│   ├── iam_least_privilege.rego
│   └── required_tags.rego
├── .github/
│   └── workflows/
│       └── security.yml  (pipeline completo)
├── .pre-commit-config.yaml
└── checkov.yaml
```

**Terraform com recurso intencialmente inseguro (para testar o pipeline):**

```hcl
# terraform/main.tf — inclui recurso inseguro para demonstrar falha do pipeline

# Recurso INSEGURO — vai falhar no Checkov (para demonstração)
resource "aws_s3_bucket" "dados_clientes_inseguro" {
  bucket = "bancomeridian-capstone-inseguro"
  # Propositalmente sem: block public access, logging, criptografia, versioning
  # CKV_AWS_19, CKV_AWS_18, CKV_AWS_145, CKV_AWS_21 vão FALHAR
}

# Recurso SEGURO — vai passar no Checkov
resource "aws_s3_bucket" "dados_clientes_seguro" {
  bucket = "bancomeridian-capstone-seguro"
  tags = {
    Owner       = "equipe-dados"
    Environment = "sandbox"
    CostCenter  = "CC-001"
  }
}

resource "aws_s3_bucket_public_access_block" "seguro" {
  bucket                  = aws_s3_bucket.dados_clientes_seguro.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_logging" "seguro" {
  bucket        = aws_s3_bucket.dados_clientes_seguro.id
  target_bucket = aws_s3_bucket.dados_clientes_seguro.id
  target_prefix = "access-logs/"
}
```

**Workflow GitHub Actions completo para o capstone:**

```yaml
# .github/workflows/security.yml
# Pipeline DevSecOps Capstone — Banco Meridian
# Integra: Checkov + Trivy + Cosign + Security Gate

name: Capstone DevSecOps Security Pipeline

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

jobs:
  iac-security:
    name: IaC Security (Checkov + Trivy Config)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Instalar Checkov
        run: pip install checkov

      - name: Checkov — Falha em CRITICAL/HIGH
        id: checkov
        run: |
          checkov -d ./terraform/ \
            --framework terraform \
            --severity CRITICAL HIGH \
            --output json \
            --output-file-path checkov-results/ \
            --soft-fail-on MEDIUM LOW
        continue-on-error: false

      - name: Trivy — Config Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: ./terraform
          severity: CRITICAL,HIGH
          exit-code: 1
          format: sarif
          output: trivy-iac.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-iac.sarif

      - name: Publicar findings no PR
        uses: actions/github-script@v7
        if: always() && github.event_name == 'pull_request'
        with:
          script: |
            const fs = require('fs');
            let body = '## Resultado do Scan de Segurança IaC\n\n';
            try {
              const results = JSON.parse(fs.readFileSync('checkov-results/results_json.json'));
              const failed = results.results.failed_checks.filter(c =>
                ['CRITICAL', 'HIGH'].includes(c.severity));
              body += failed.length > 0
                ? `❌ **${failed.length} findings CRITICAL/HIGH encontrados**\n\n` +
                  failed.map(c => `- [${c.check_id}] ${c.check.name}`).join('\n')
                : '✅ Nenhum finding CRITICAL/HIGH encontrado';
            } catch(e) { body += '⚠️ Erro ao processar relatório Checkov'; }
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });

  container-security:
    name: Container Security (Trivy Image + Cosign)
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build imagem de demonstração
        uses: docker/build-push-action@v5
        id: build
        with:
          context: .
          push: false
          load: true
          tags: ghcr.io/${{ github.repository }}/capstone-app:${{ github.sha }}

      - name: Trivy — Scan da imagem
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/${{ github.repository }}/capstone-app:${{ github.sha }}
          severity: CRITICAL,HIGH
          exit-code: 1
          format: sarif
          output: trivy-image.sarif

      - name: Syft — Gerar SBOM
        uses: anchore/syft-action@v0.16.0
        with:
          image: ghcr.io/${{ github.repository }}/capstone-app:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      - name: Push imagem (apenas se scan passou)
        uses: docker/build-push-action@v5
        id: push
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}/capstone-app:${{ github.sha }}

      - uses: sigstore/cosign-installer@v3

      - name: Cosign — Assinar imagem
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}/capstone-app@${{ steps.push.outputs.digest }}

      - name: Cosign — Verificar assinatura
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}.*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ghcr.io/${{ github.repository }}/capstone-app@${{ steps.push.outputs.digest }}

  security-gate:
    name: Security Gate Final
    needs: [iac-security, container-security]
    runs-on: ubuntu-latest
    if: always()
    steps:
      - name: Verificar resultados
        run: |
          IaC="${{ needs.iac-security.result }}"
          Container="${{ needs.container-security.result }}"
          echo "IaC security: $IaC"
          echo "Container security: $Container"
          if [[ "$IaC" == "failure" ]]; then
            echo "FALHA: IaC security encontrou CRITICAL/HIGH — merge bloqueado"
            exit 1
          fi
          echo "PASSOU: Security Gate aprovado"
```

---

### Entregável 3: Falco — Runtime Security

**Objetivo:** Demonstrar detecção de shell em container no cluster kind local.

```bash
# Pré-requisito: cluster kind com Falco (módulo 00)
kubectl get pods -n falco-system

# DEMONSTRAÇÃO 1: Shell em container de produção
# Terminal 1 — monitorar alertas Falco em tempo real
kubectl logs -n falco-system -l app.kubernetes.io/name=falco -f | \
  grep -E "Warning|Error|Critical|shell|exec"

# Terminal 2 — simular atacante com shell em container
kubectl run capstone-test --image=nginx:latest --namespace=default
sleep 5
kubectl exec -it capstone-test -- /bin/bash
# Dentro do container: executar comandos
whoami
cat /etc/passwd
curl http://169.254.169.254/latest/meta-data/  # AWS IMDS

# Verificar alertas no Terminal 1
# Esperado: alertas de "Shell em container", "Read sensitive file" e "AWS IMDS access"

# DEMONSTRAÇÃO 2: Escrita em /etc
kubectl exec -it capstone-test -- bash -c "echo 'test' > /etc/hostile-file"
# Esperado: alerta "Escrita em diretório sensível"

# Coletar evidências para relatório BACEN
kubectl logs -n falco-system -l app.kubernetes.io/name=falco \
  --since=30m \
  --output-file capstone-results/falco/falco-events.log

# Analisar eventos por tipo
cat capstone-results/falco/falco-events.log | python3 -c "
import sys, json, re
from collections import Counter
events = []
for line in sys.stdin:
    if 'Warning' in line or 'Critical' in line or 'Error' in line:
        events.append(line.strip())

print(f'Total alertas Falco: {len(events)}')
print()
for event in events[:20]:
    print(event)
"
```

**Output esperado do Falco:**

```
2025-04-24T15:30:01.234567890Z Warning evtsource=kernel rule="Terminal shell in container" 
output="Shell iniciado em container (user=root user_loginuid=-1 container_id=abc123 
container_name=capstone-test image=nginx:latest shell=bash parent=runc cmdline=bash)"
k8s.pod.name=capstone-test k8s.ns.name=default

2025-04-24T15:30:15.123456789Z Warning evtsource=kernel rule="BancoMeridian - Acesso à AWS Metadata API"
output="ALERTA CRÍTICO: Container tentando acessar AWS Instance Metadata Service!
container=capstone-test pod=capstone-test proc=curl cmdline=curl http://169.254.169.254/latest/meta-data/"
```

---

### Entregável 4: HashiCorp Vault — AppRole + Dynamic Credentials

**Objetivo:** Demonstrar eliminação de credenciais estáticas.

```bash
# Pré-requisito: Vault em modo dev (módulo 00)
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-root-token'

echo "=== CAPSTONE: CONFIGURAÇÃO VAULT ==="

# 1. Habilitar database engine
vault secrets enable database
echo "✓ Database secret engine habilitado"

# 2. Configurar PostgreSQL (conectar ao banco de teste do módulo 00)
vault write database/config/capstone-postgres \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@localhost:5432/capstone?sslmode=disable" \
  username="vault_admin" \
  password="vault_admin_password" \
  allowed_roles="app-readonly"

# 3. Criar role de banco com TTL de 1h
vault write database/roles/app-readonly \
  db_name=capstone-postgres \
  creation_statements="
    CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
  " \
  revocation_statements="REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="4h"

echo "✓ Role de banco configurada com TTL de 1h"

# 4. Configurar AppRole
vault auth enable approle
vault policy write capstone-app-policy - <<EOF
path "database/creds/app-readonly" { capabilities = ["read"] }
path "sys/leases/renew" { capabilities = ["update"] }
EOF

vault write auth/approle/role/capstone-app \
  token_policies=capstone-app-policy \
  secret_id_ttl=10m \
  token_ttl=20m

ROLE_ID=$(vault read -field=role_id auth/approle/role/capstone-app/role-id)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/capstone-app/secret-id)

echo "✓ AppRole configurado"
echo "  ROLE_ID: $ROLE_ID"
echo "  SECRET_ID (expira em 10min): $SECRET_ID"

# 5. Simular autenticação da aplicação
APP_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID")

export VAULT_TOKEN="$APP_TOKEN"
echo "✓ Aplicação autenticada com AppRole token"

# 6. Gerar credencial dinâmica
DB_CREDS=$(vault read -format=json database/creds/app-readonly)
DB_USER=$(echo $DB_CREDS | jq -r '.data.username')
DB_PASS=$(echo $DB_CREDS | jq -r '.data.password')
LEASE_ID=$(echo $DB_CREDS | jq -r '.lease_id')

echo ""
echo "=== CREDENCIAL DINÂMICA GERADA ==="
echo "Usuario: $DB_USER"
echo "Expira em: 1 hora"
echo "Lease ID: $LEASE_ID"
echo ""
echo "=== ANTES DO VAULT: senha estática hardcoded para sempre ==="
echo "=== DEPOIS DO VAULT: credencial única, expira em 1h, auditada ==="

# 7. Testar conexão
PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d capstone \
  -c "SELECT current_user, now();" 2>/dev/null && \
  echo "✓ Conexão ao banco com credencial dinâmica bem-sucedida" || \
  echo "(PostgreSQL não disponível neste ambiente — credencial gerada com sucesso)"
```

---

### Entregável 5: Relatório Executivo para Auditoria BACEN

**Estrutura do Relatório Executivo:**

```
══════════════════════════════════════════════════════════════════════════════
RELATÓRIO EXECUTIVO DE POSTURA DE SEGURANÇA CLOUD
Banco Meridian S.A.
Auditoria BACEN 4.893 — Preparação
Data: 24/04/2025
Confidencial — Uso Restrito
══════════════════════════════════════════════════════════════════════════════

1. SUMÁRIO EXECUTIVO

Conduzimos uma avaliação abrangente da postura de segurança cloud do Banco
Meridian nos ambientes AWS (conta de produção) e Azure (tenant M365).
A avaliação utilizou ferramentas open-source de referência (Prowler v4 para
CSPM, Trivy para análise de containers) e identificou oportunidades de
melhoria que, se não remediadas, representam risco regulatório para a
auditoria do BACEN prevista para 60 dias.

Resultado consolidado:
  Security Score AWS: 58/100 (meta para auditoria: 85+)
  Conformidade BACEN 4.893: 58% → Meta: 85%
  Conformidade CIS AWS v3.0: 63% → Meta: 80%
  Findings críticos: 4 (requerem ação imediata — 24h)
  Findings altos: 23 (requerem ação em 7 dias)

2. PRINCIPAIS RISCOS IDENTIFICADOS

┌─────┬──────────────────────────────┬────────────┬──────────────────┬──────────┐
│ # │ Finding │ Severidade │ Artigo BACEN │ Prazo │
├─────┼──────────────────────────────┼────────────┼──────────────────┼──────────┤
│ 1 │ 2 buckets S3 públicos com PII │ CRITICAL │ Art. 5, Art. 6 │ 24h │
│ 2 │ Root account sem MFA │ CRITICAL │ Art. 8 │ 24h │
│ 3 │ CloudTrail ausente (3 regiões)│ CRITICAL │ Art. 6 │ 48h │
│ 4 │ RDS publicamente acessível │ CRITICAL │ Art. 5 │ 48h │
│ 5 │ SSH 0.0.0.0/0 (12 instâncias) │ HIGH │ Art. 5 │ 7 dias │
└─────┴──────────────────────────────┴────────────┴──────────────────┴──────────┘

3. CONFORMIDADE BACEN 4.893 — MAPA DE CALOR

Artigo │ Descrição │ Status │ Evidência
──────────────────────────────────────────────────────────────────────────────
Art. 5 │ Testes de vulnerabilidade │ PARCIAL (63%) │ Prowler v4 HTML
Art. 6 │ Monitoramento contínuo │ PARCIAL (55%) │ CloudTrail parcial
Art. 8 │ Gestão de acessos │ PARCIAL (50%) │ IAM Analyzer
Art. 9 │ Registro de incidentes │ PARCIAL (70%) │ CloudTrail + Falco
Art. 10 │ Plano de continuidade │ SIM (85%) │ IaC + backup RDS

4. ARQUITETURA-ALVO (60 dias)

  [Ver diagrama em assets/arquitetura-alvo-bacen.png]

  Componentes implementados na arquitetura-alvo:
  ├── CSPM contínuo: Prowler v4 agendado via AWS EventBridge (semanal)
  ├── IaC security: Checkov + OPA no pipeline GitHub Actions (todos os PRs)
  ├── Container security: Trivy + Cosign em todos os deploys (Entregável 2)
  ├── Runtime: Falco nos clusters EKS (Entregável 3)
  ├── Secrets management: HashiCorp Vault com dynamic secrets (Entregável 4)
  ├── CIEM: AWS IAM Access Analyzer com Unused Access (90 dias)
  └── Monitoramento: CloudTrail → CloudWatch → alertas SecurityOps

5. ROADMAP DE REMEDIAÇÃO

IMEDIATO (24–48h) — Remediação de CRITICAL
  ☐ Bloquear acesso público nos 2 buckets S3
  ☐ Habilitar MFA na conta root AWS
  ☐ Habilitar CloudTrail nas 3 regiões ausentes
  ☐ Mover RDS para subnet privada
  Responsável: Cloud Ops Team
  Esforço estimado: 12 horas

7 DIAS — Remediação de HIGH
  ☐ Restringir Security Groups SSH para IPs corporativos (bastião)
  ☐ Habilitar MFA para 8 usuários IAM sem MFA
  ☐ Ativar criptografia em 25 volumes EBS
  Responsável: Cloud Ops + Security
  Esforço estimado: 24 horas

30 DIAS — Conformidade Básica BACEN (meta: 70%)
  ☐ Implementar Prowler scan semanal com alertas automáticos
  ☐ Implementar pipeline DevSecOps com Checkov (Entregável 2)
  ☐ Implementar Vault para eliminar credenciais estáticas top 5 sistemas
  ☐ Conduzir auditoria CIEM completa (IAM Access Analyzer)
  Responsável: Cloud Security Team
  Esforço estimado: 120 horas

60 DIAS — Pronto para Auditoria BACEN (meta: 85%)
  ☐ Implementar Falco nos clusters EKS (Entregável 3)
  ☐ Completar CIEM — remover todas as permissões excessivas
  ☐ Implementar Vault dynamic secrets para todos os microserviços críticos
  ☐ Audit trail completo: CloudTrail + Security Hub + SIEM
  ☐ Relatório final de conformidade BACEN 4.893
  Responsável: Cloud Security Team + DevOps
  Esforço estimado: 200 horas

6. BUSINESS CASE — INVESTIMENTO EM SEGURANÇA CLOUD

Custo do estado atual (risco):
  - Multa BACEN por incidente com dados de clientes: até 2% do faturamento
  - Custo de resposta a incidente (estimado): R$ 500.000–2.000.000
  - Dano reputacional: não quantificável

Custo do roadmap proposto:
  - Open-source tools: R$ 0 em licenças
  - Esforço interno (356 horas): R$ 90.000 (eng. senior R$ 250/h)
  - Consultoria opcional: R$ 40.000
  - TOTAL INVESTIMENTO: R$ 130.000

ROI: prevenir 1 incidente com vazamento de dados de clientes = ROI de 15x+

══════════════════════════════════════════════════════════════════════════════
```

---

## Gabarito Completo do Instrutor

### Gabarito Entregável 1 — Prowler

**Outputs esperados:**

```
$ prowler aws --profile bancomeridian-sandbox --severity critical high

... [scan em execução por 15-25 min] ...

Assessment Summary:
  Total checks executed: 412
  Total passed checks: 267 (64.8%)
  Total failed checks: 145 (35.2%)
  Total checks by severity:
    CRITICAL: 4 failed
    HIGH: 23 failed
    MEDIUM: 87 failed
    LOW: 31 failed

Top CRITICAL findings:
1. [CRITICAL] s3_bucket_public_access: bancomeridian-dados-clientes
   → BACEN 4.893 Art. 5, LGPD Art. 46
2. [CRITICAL] iam_root_account_mfa_enabled: root
   → BACEN 4.893 Art. 8
3. [CRITICAL] cloudtrail_enabled: regiões ap-southeast-1, eu-west-1, sa-east-1
   → BACEN 4.893 Art. 6
4. [CRITICAL] rds_instance_publicly_accessible: bancomeridian-db-prod
   → BACEN 4.893 Art. 5
```

**Relatório HTML:** disponível em `capstone-results/prowler/index.html` — deve mostrar dashboard visual com findings por severidade e por serviço AWS, com links para documentação de remediação.

### Gabarito Entregável 2 — Pipeline DevSecOps

**Status esperado no GitHub Actions ao criar PR com Terraform inseguro:**

```
✓ IaC Security / Checkov — FAILURE (encontrou CRITICAL: CKV_AWS_19, CKV_AWS_18, CKV_AWS_145)
✓ IaC Security / Trivy Config — FAILURE (encontrou HIGH findings)
✓ Security Gate — FAILURE (dependente dos jobs anteriores)

Pull request status: ❌ BLOCKED — Some required status checks have not passed
```

**Comentário automático na PR:**
```
## Resultado do Scan de Segurança IaC

❌ 3 findings CRITICAL/HIGH encontrados

- [CKV_AWS_19] Ensure S3 bucket has block public access configuration enabled
- [CKV_AWS_18] Ensure S3 bucket has access logging enabled
- [CKV_AWS_145] Ensure S3 bucket is encrypted using KMS key

O PR está bloqueado. Corrija os findings ou adicione #checkov:skip= com justificativa aprovada.
```

**Após corrigir o Terraform e criar novo commit:**
```
✓ IaC Security / Checkov — SUCCESS
✓ IaC Security / Trivy Config — SUCCESS
✓ Security Gate — SUCCESS

Pull request status: ✅ All checks passed — Ready to merge
```

### Gabarito Entregável 3 — Falco

**Alertas esperados durante as simulações:**

```
# Shell em container:
15:30:01.234 Warning Shell iniciado em container
(user=root container_id=abc123 container_name=capstone-test
image=nginx:latest shell=bash)

# Acesso ao IMDS AWS:
15:30:15.123 Critical ALERTA CRÍTICO: Container tentando acessar AWS IMDS!
(proc=curl cmdline=curl http://169.254.169.254/latest/meta-data/
pod=capstone-test ns=default)

# Escrita em /etc:
15:30:30.456 Error ALERTA: Escrita em diretório sensível no container!
(dir=/etc/hostile-file proc=bash user=root pod=capstone-test)
```

### Gabarito Entregável 4 — Vault

**Outputs esperados:**

```
$ vault write -f database/config/capstone-postgres [...]
Success! Data written to: database/config/capstone-postgres

$ vault read database/creds/app-readonly
Key                Value
---                -----
lease_id           database/creds/app-readonly/K7dQx2Abc1D3e4F5
lease_duration     1h
lease_renewable    true
password           A1B2-xKjNmQrStUv-c3d4
username           v-role-app-readonly-KjNm-1714000000

$ psql -h localhost -U "v-role-app-readonly-KjNm-1714000000" -d capstone
  current_user                          | now
---------------------------------------+----------------------------
 v-role-app-readonly-KjNm-1714000000  | 2025-04-24 15:45:01.234567

# Após 1h — tentativa de login com mesmas credenciais:
$ psql -h localhost -U "v-role-app-readonly-KjNm-1714000000" -d capstone
psql: error: connection to server on socket failed:
  FATAL:  role "v-role-app-readonly-KjNm-1714000000" does not exist
# Credencial expirou e foi removida automaticamente pelo Vault ✓
```

---

## Critérios de Avaliação do Capstone

| Entregável | Peso | Critérios de Aprovação |
|:-----------|:----:|:-----------------------|
| Relatório Prowler | 25% | Executou scan, filtrou CRITICAL/HIGH, mapeou para BACEN 4.893, relatório executivo completo |
| Pipeline DevSecOps | 30% | Workflow funcional, bloqueia PR com CRITICAL, assina imagem com Cosign |
| Falco runtime | 15% | Detectou shell em container, gerou alertas corretos |
| Vault dynamic secrets | 20% | AppRole configurado, credencial dinâmica com TTL gerada e expirada |
| Relatório executivo | 10% | Apresentável ao CISO, inclui roadmap e business case |

---

*Módulo 09 — Capstone: Avaliação de Postura Multi-Cloud do Banco Meridian*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
