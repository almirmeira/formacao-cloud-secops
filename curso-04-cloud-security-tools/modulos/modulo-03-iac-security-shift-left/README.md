# Módulo 03 — IaC Security e Shift-Left
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2h videoaulas + 2h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 3 / CCSK domínio 7  
> **Cenário:** Time de DevOps do Banco Meridian implementando segurança no pipeline de IaC

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Explicar o conceito Shift-Left e quantificar a diferença de custo de encontrar vulnerabilidades cedo vs. tarde
2. Executar Checkov, tfsec e Trivy (modo IaC) em projetos Terraform e CloudFormation
3. Escrever políticas OPA/Rego para enforçar regras de segurança em arquivos de configuração
4. Construir um workflow GitHub Actions completo com IaC scanning em pull requests
5. Configurar fail on HIGH/CRITICAL e warn on MEDIUM em pipelines CI/CD

---

## 1. Conceito Shift-Left — Por Que Encontrar Vulnerabilidades Cedo É Muito Mais Barato

### 1.1 A Regra do 10x

O custo de corrigir uma vulnerabilidade cresce drasticamente conforme avança no ciclo de vida do software:

```
CUSTO RELATIVO DE CORREÇÃO POR FASE
────────────────────────────────────────────────────────────────────
Fase de desenvolvimento (IDE, pré-commit)           → R$ 1
Fase de revisão (Pull Request, CI)                  → R$ 10
Fase de teste (QA, staging)                         → R$ 100
Fase de produção (pós-deploy)                       → R$ 1.000
Após incidente de segurança                         → R$ 10.000+
(inclui: resposta ao incidente, reputação, multas)
────────────────────────────────────────────────────────────────────
```

### 1.2 O Problema Específico de IaC Sem Segurança

```
FLUXO SEM SHIFT-LEFT (PROBLEMÁTICO)
─────────────────────────────────────────────────────────────────
Desenvolvedor escreve Terraform com S3 bucket público
         │
         ▼ (merge no main sem revisão de segurança)
CI/CD executa terraform apply
         │
         ▼ (bucket criado em produção)
S3 bucket público em produção com dados de clientes
         │
         ▼ (CSPM detecta 24h depois no próximo scan)
Finding CSPM: "Bucket público detectado"
         │
         ▼ (alguém precisa modificar o Terraform, recriar o bucket, migrar dados)
Custo: 40+ horas + risco de incidente durante janela de exposição

FLUXO COM SHIFT-LEFT (CORRETO)
─────────────────────────────────────────────────────────────────
Desenvolvedor escreve Terraform com S3 bucket público
         │
         ▼ (git commit → pre-commit hook executa Checkov)
Checkov: FAILED — CKV_AWS_19: S3 bucket missing public access block
         │
         ▼ (desenvolvedor corrige antes de fazer push)
Terraform corrigido: bucket com acesso público bloqueado
         │
         ▼ (PR criado → GitHub Actions executa Checkov + tfsec)
CI: PASSED — sem findings CRITICAL/HIGH
         │
         ▼ (merge e deploy)
S3 bucket seguro em produção desde o primeiro dia
         │
Custo: 15 minutos do desenvolvedor
```

### 1.3 Shift-Left em IaC — O Que Escanear

| Tipo de Arquivo | Ferramenta Principal | O que Detecta |
|:----------------|:--------------------:|:-------------|
| Terraform (.tf) | Checkov, tfsec, Trivy IaC, Terrascan | Misconfigurations de recursos AWS/Azure/GCP |
| CloudFormation (.yaml/.json) | Checkov, cfn-lint | Misconfigs CloudFormation-específicas |
| Kubernetes YAML | Checkov, Trivy IaC, Datree | PSS violations, RBAC issues, hostPath |
| Dockerfile | Checkov, Trivy, Hadolint | Root user, latest tag, secrets em ENV |
| Helm Charts | Checkov, Trivy IaC | Misconfigs em templates K8s |
| ARM Templates | Checkov | Misconfigs Azure Resource Manager |
| Bicep | Checkov | Misconfigs Azure Bicep |

---

## 2. Ferramentas de IaC Scanning

### 2.1 Checkov

Checkov é a ferramenta mais completa para IaC security scanning. Desenvolvida pela Bridgecrew (adquirida pela Palo Alto Networks), é open-source com mais de 1.000 checks.

**Instalação:**
```bash
pip install checkov
checkov --version
```

**Execução básica:**
```bash
# Scan de diretório Terraform
checkov -d ./terraform/

# Scan de arquivo específico
checkov -f ./terraform/main.tf

# Scan apenas por framework
checkov -d ./terraform/ --framework terraform

# Listar todos os checks disponíveis
checkov -l

# Informações sobre um check específico
checkov --check CKV_AWS_18

# Saída compacta (apenas FAILED)
checkov -d ./terraform/ --compact

# Saída em JSON
checkov -d ./terraform/ -o json

# Saída em JUnit XML (para CI/CD)
checkov -d ./terraform/ -o junitxml

# Saída em SARIF (para GitHub Code Scanning)
checkov -d ./terraform/ -o sarif

# Salvar resultado em arquivo
checkov -d ./terraform/ -o json --output-file-path /tmp/checkov-results/

# Falhar apenas em CRITICAL (não em outros)
checkov -d ./terraform/ --soft-fail-on HIGH MEDIUM LOW

# Falhar em CRITICAL e HIGH
checkov -d ./terraform/ --soft-fail-on MEDIUM LOW

# Skip de um check específico (com justificativa no código)
checkov -d ./terraform/ --skip-check CKV_AWS_20,CKV_AWS_28

# Scan de CloudFormation
checkov -d ./cloudformation/ --framework cloudformation

# Scan de Kubernetes YAML
checkov -d ./k8s-manifests/ --framework kubernetes

# Scan de Dockerfile
checkov -f ./Dockerfile --framework dockerfile

# Scan de Helm charts
checkov -d ./helm/ --framework helm

# Custom policy directory
checkov -d ./terraform/ --external-checks-dir ./custom-policies/
```

**Exemplo de Terraform com findings e supressão:**
```hcl
# terraform/s3.tf

# Bucket com problemas (sem comentários de skip)
resource "aws_s3_bucket" "dados_clientes" {
  bucket = "bancomeridian-dados-clientes"
  # CKV_AWS_19: falta block public access
  # CKV_AWS_18: falta logging
  # CKV_AWS_145: falta criptografia KMS
}

# Bucket corrigido
resource "aws_s3_bucket" "dados_clientes_seguro" {
  bucket = "bancomeridian-dados-clientes-v2"

  tags = {
    Owner       = "equipe-dados"
    Environment = "production"
    DataClass   = "Confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}

resource "aws_s3_bucket_logging" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

resource "aws_s3_bucket_versioning" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Suprimir um check com justificativa (quando necessário e aprovado)
resource "aws_s3_bucket" "website_publico" {
  bucket = "bancomeridian-website"

  #checkov:skip=CKV_AWS_19:Website público intencional - aprovado pelo CISO em 2025-04-24 ticket#SEC-0123
}
```

**Checks mais importantes do Checkov:**

| Check ID | Recurso | Descrição |
|:---------|:--------|:----------|
| CKV_AWS_19 | S3 | Block Public Access habilitado |
| CKV_AWS_18 | S3 | Access logging habilitado |
| CKV_AWS_145 | S3 | Criptografia SSE com KMS |
| CKV_AWS_21 | S3 | Versionamento habilitado |
| CKV_AWS_24 | Security Group | Sem porta 22 para 0.0.0.0/0 |
| CKV_AWS_25 | Security Group | Sem porta 3389 para 0.0.0.0/0 |
| CKV_AWS_79 | EC2 | IMDSv2 habilitado |
| CKV_AWS_8 | EC2 | EBS volume encrypted |
| CKV_AWS_28 | RDS | Backup habilitado |
| CKV_AWS_17 | RDS | Não publicly accessible |
| CKV_AWS_16 | RDS | Storage encrypted |
| CKV_AWS_57 | Lambda | Função não pública |
| CKV_AWS_111 | IAM | Sem wildcard "*" em permissions |
| CKV_AWS_120 | IAM | Password policy com MFA |

### 2.2 tfsec

tfsec é especializado em Terraform, desenvolvido em Go — muito mais rápido que Checkov para projetos grandes. Excelente integração com VS Code (extensão disponível).

**Instalação:**
```bash
# macOS/Linux
brew install tfsec
# ou
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash

# Windows
choco install tfsec

# Verificar
tfsec --version
```

**Execução:**
```bash
# Scan básico
tfsec ./terraform/

# Saída formatada
tfsec ./terraform/ --format lovely

# Saída JSON
tfsec ./terraform/ --format json

# Saída SARIF
tfsec ./terraform/ --format sarif

# Falhar apenas em HIGH e CRITICAL
tfsec ./terraform/ --minimum-severity HIGH

# Excluir checks específicos
tfsec ./terraform/ --exclude aws-s3-no-public-access-with-acl

# Scan com configuração customizada
tfsec ./terraform/ --config-file tfsec.yaml

# Verbose output
tfsec ./terraform/ --verbose

# Scan com output de passos de remediação
tfsec ./terraform/ --include-passed

# Integração VS Code: instalar extensão "tfsec"
# Mostra findings inline no código enquanto escreve
```

**Arquivo de configuração tfsec.yaml:**
```yaml
# tfsec.yaml
minimum_severity: MEDIUM

exclude:
  - aws-s3-no-public-access-with-acl  # website intencional, aprovado SEC-0123
  - aws-ec2-no-public-ip               # jumpbox aprovada SEC-0124

custom_checks:
  - action: DENY
    description: "Banco Meridian: todos os recursos devem ter tag Owner"
    errorMessage: "Resource is missing required tag 'Owner'"
    match:
      block: resource
      attribute: "tags.Owner"
      action: isAbsent
```

### 2.3 KICS — Keep Infrastructure as Code Secure

KICS (Checkmarx) é a solução open-source mais multilinguagem — suporta 35+ tipos de IaC.

```bash
# Instalar via Docker (mais fácil)
docker pull checkmarx/kics:latest

# Scan de diretório
docker run -v "$(pwd):/path" checkmarx/kics:latest scan \
  -p /path/terraform \
  -o /path/results

# Scan com múltiplos frameworks
docker run -v "$(pwd):/path" checkmarx/kics:latest scan \
  -p /path/ \
  --type "Terraform,Kubernetes,Dockerfile" \
  -o /path/results \
  --report-formats "json,html"

# Instalar binário nativo
curl -sfL 'https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh' | bash

# Scan nativo
kics scan -p ./terraform/ -o ./results/
```

### 2.4 Terrascan

Foco em compliance frameworks (CIS, NIST, PCI-DSS).

```bash
# Instalar
brew install accurics/tap/terrascan
# ou
curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz" | tar -xz
sudo install terrascan /usr/local/bin

# Scan Terraform
terrascan scan -i terraform -d ./terraform/

# Scan com policy específica
terrascan scan -i terraform -d ./terraform/ --policy-type aws

# Scan com compliance CIS
terrascan scan -i terraform -d ./terraform/ -t aws --scan-rules aws_cis_v130

# Saída JSON
terrascan scan -i terraform -d ./terraform/ -o json

# Scan K8s
terrascan scan -i k8s -f ./k8s-manifests/deployment.yaml
```

### 2.5 Trivy — Modo IaC

Trivy é a ferramenta unificada da Aqua Security que cobre containers, IaC, SBOM e secrets em um único binário.

```bash
# Instalar Trivy
brew install trivy
# ou
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan IaC (Terraform, CloudFormation, K8s, Dockerfile, Helm)
trivy config ./terraform/

# Scan com severidade mínima
trivy config ./terraform/ --severity HIGH,CRITICAL

# Scan Kubernetes manifests
trivy config ./k8s-manifests/

# Scan Dockerfile
trivy config ./Dockerfile

# Scan Helm chart
trivy config ./helm/meu-chart/

# Saída JSON
trivy config ./terraform/ --format json

# Saída SARIF
trivy config ./terraform/ --format sarif --output trivy-iac.sarif

# Scan recursivo com todos os tipos
trivy config . --include-non-failures

# Scan com policy customizada (Rego)
trivy config ./terraform/ --policy ./custom-policies/

# Exit code baseado em severity (para CI/CD)
# Exit 1 se encontrar CRITICAL/HIGH
trivy config ./terraform/ --exit-code 1 --severity HIGH,CRITICAL
```

**Vantagem do Trivy:** um único binário cobre IaC scan + image scan + SBOM + secrets scan. No pipeline CI/CD você pode usar apenas o Trivy e cobrir múltiplos domínios.

---

## 3. Policy as Code

### 3.1 OPA — Open Policy Agent

OPA é um policy engine open-source e de uso geral que permite escrever políticas em uma linguagem declarativa chamada Rego.

**Arquitetura:**
```
OPA — COMO FUNCIONA
─────────────────────────────────────────────────────────────
INPUT (JSON)          →  OPA Engine  →  DECISION (allow/deny)
(dados a verificar)       + Rego          + reason
                           policies
─────────────────────────────────────────────────────────────
Casos de uso:
  - Kubernetes Admission Control (OPA Gatekeeper)
  - CI/CD policy enforcement (Conftest)
  - API authorization
  - Terraform plan validation
  - Microservice authorization
─────────────────────────────────────────────────────────────
```

**Instalação:**
```bash
# macOS/Linux
brew install opa
# ou
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/

# Verificar
opa version
```

**Sintaxe Rego — Conceitos Fundamentais:**

```rego
# Rego é uma linguagem declarativa — você descreve O QUE deve ser verdade,
# não COMO chegar lá

package terraform.aws.security

# 1. Regras podem ser booleanas (allow/deny)
default deny = false

deny {
    input.resource_type == "aws_s3_bucket"
    input.config.acl == "public-read"
}

# 2. Mensagens de erro como conjunto (set)
violations[msg] {
    input.resource_type == "aws_s3_bucket"
    input.config.acl == "public-read"
    msg := sprintf("Bucket '%v' não pode ter ACL public-read", [input.resource_name])
}

# 3. Iteração com comprehensions
public_buckets := [name |
    resource := input.resources[name]
    resource.type == "aws_s3_bucket"
    resource.config.acl == "public-read"
]

# 4. Helpers
is_production {
    input.config.tags.Environment == "production"
}

# 5. Import e packages
import future.keywords.in
import future.keywords.every
```

### 3.2 Conftest — OPA para Arquivos de Configuração

Conftest é uma CLI que usa OPA/Rego para testar arquivos de configuração estruturados (JSON, YAML, HCL, Dockerfile, etc.).

```bash
# Instalar
brew install conftest
# ou
wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz

# Estrutura de projeto:
# ./terraform/main.tf
# ./policy/terraform.rego

# Testar Terraform com Conftest
conftest test ./terraform/ -p ./policy/

# Testar manifesto Kubernetes
conftest test ./k8s-manifests/deployment.yaml -p ./policy/

# Testar com múltiplos policy files
conftest test ./terraform/ -p ./policy/aws/ -p ./policy/global/

# Saída detalhada
conftest test ./terraform/ -p ./policy/ --output table

# Saída JSON
conftest test ./terraform/ -p ./policy/ --output json

# Usar políticas de um OCI registry (Conftest Bundle)
conftest pull ghcr.io/bancomeridian/security-policies:v1.0
conftest test ./terraform/ -p policy/
```

### 3.3 HashiCorp Sentinel

Sentinel é o motor de Policy as Code integrado ao Terraform Cloud e Enterprise — políticas aplicadas automaticamente em todos os runs do Terraform.

```python
# sentinel/require-tags.sentinel
# Política Sentinel: todos os recursos devem ter tags obrigatórias

import "tfplan/v2" as tfplan

required_tags = ["Owner", "Environment", "CostCenter"]

# Obter todos os recursos do plan
all_resources = tfplan.find_resources("*")

# Regra: verificar se cada recurso tem as tags obrigatórias
resource_has_required_tags = rule {
    all all_resources as _, resource_changes {
        all required_tags as tag {
            resource_changes.change.after.tags[tag] is not null
        }
    }
}

# Política main
main = rule {
    resource_has_required_tags
}
```

---

## 4. Cinco Políticas Rego com Comentários

### Política 1: Bloquear Security Group com Porta 22 para 0.0.0.0/0

```rego
# policy/aws/security_group_ssh.rego
#
# POLÍTICA: Bloquear Security Groups que permitem SSH (porta 22)
# de qualquer origem (0.0.0.0/0 ou ::/0)
#
# Contexto BACEN 4.893: Art. 5 — testes de controles de acesso
# Referência: CKV_AWS_24

package terraform.aws.security_group

import future.keywords.in

# Regra principal: violations é um set de mensagens de erro
# A regra "falha" quando violations não está vazio

violations[msg] {
    # Itera sobre todos os recursos do Terraform plan
    resource := input.resource_changes[_]

    # Filtra apenas recursos do tipo aws_security_group_rule ou ingress rules
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"

    # Verifica se permite acesso na porta 22
    resource.change.after.from_port <= 22
    resource.change.after.to_port >= 22

    # Verifica se o CIDR é 0.0.0.0/0 (qualquer origem IPv4)
    cidr_block := resource.change.after.cidr_blocks[_]
    cidr_block == "0.0.0.0/0"

    # Mensagem de erro com contexto
    msg := sprintf(
        "Security Group Rule '%v' permite SSH (porta 22) de 0.0.0.0/0 — risco de acesso remoto não autorizado. Use um CIDR específico (ex: VPN corporativa) ou Bastion Host.",
        [resource.address]
    )
}

# Regra alternativa para aws_security_group inline rules
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"

    # Itera sobre as regras de ingress
    ingress := resource.change.after.ingress[_]
    ingress.from_port <= 22
    ingress.to_port >= 22
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := sprintf(
        "Security Group '%v' permite SSH (porta 22) de 0.0.0.0/0 — use SSM Session Manager ou Bastion Host ao invés de SSH direto.",
        [resource.address]
    )
}

# Decisão final: deny se houver qualquer violation
deny[msg] {
    msg := violations[_]
}
```

### Política 2: Exigir Tags de Owner e Environment

```rego
# policy/global/required_tags.rego
#
# POLÍTICA: Todos os recursos AWS devem ter as tags obrigatórias:
# - Owner: responsável pelo recurso
# - Environment: ambiente (production, staging, development)
# - CostCenter: código do centro de custo para chargeback
#
# Exceções: recursos serverless como aws_iam_policy, aws_iam_role_policy
# Contexto: política interna do Banco Meridian para governança de cloud

package terraform.aws.tags

import future.keywords.in

# Tags obrigatórias para todos os recursos
required_tags := {"Owner", "Environment", "CostCenter"}

# Tipos de recursos que exigem tags (excluir recursos sem suporte a tags)
taggable_resources := {
    "aws_s3_bucket",
    "aws_instance",
    "aws_db_instance",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_eks_cluster",
    "aws_rds_cluster",
    "aws_elasticache_cluster",
    "aws_kms_key",
    "aws_sns_topic",
    "aws_sqs_queue",
    "aws_vpc",
    "aws_subnet",
}

# Valores válidos para a tag Environment
valid_environments := {"production", "staging", "development", "sandbox"}

# Regra 1: tags obrigatórias presentes
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in taggable_resources

    # Verifica tags ausentes
    tag := required_tags[_]
    not resource.change.after.tags[tag]

    msg := sprintf(
        "Recurso '%v' (%v) está faltando a tag obrigatória '%v'. Tags necessárias: %v",
        [resource.address, resource.type, tag, required_tags]
    )
}

# Regra 2: valor de Environment deve ser válido
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in taggable_resources

    # Tag Environment existe mas tem valor inválido
    env := resource.change.after.tags.Environment
    not env in valid_environments

    msg := sprintf(
        "Recurso '%v' tem tag Environment='%v' inválida. Valores aceitos: %v",
        [resource.address, env, valid_environments]
    )
}

deny[msg] {
    msg := violations[_]
}
```

### Política 3: Bloquear Bucket S3 Sem Logging

```rego
# policy/aws/s3_logging.rego
#
# POLÍTICA: Todos os buckets S3 devem ter logging habilitado
#
# Contexto BACEN 4.893: Art. 6 — monitoramento contínuo e rastreabilidade
# Contexto LGPD: Art. 37 — manutenção de registros de operações
# Referência: CKV_AWS_18

package terraform.aws.s3

import future.keywords.in

# Buckets que podem estar isentos (apenas whitelist explícita)
exempt_bucket_patterns := ["bancomeridian-logs-", "bancomeridian-audit-"]

is_exempt(bucket_name) {
    pattern := exempt_bucket_patterns[_]
    startswith(bucket_name, pattern)
}

violations[msg] {
    # Encontra todos os recursos aws_s3_bucket
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"

    bucket_name := resource.change.after.bucket

    # Verifica se NÃO há recurso aws_s3_bucket_logging associado
    logging_resources := [r |
        r := input.resource_changes[_]
        r.type == "aws_s3_bucket_logging"
        r.change.after.bucket == resource.change.after.id
    ]
    count(logging_resources) == 0

    # Verifica se não é um bucket de logs (para evitar loop)
    not is_exempt(bucket_name)

    msg := sprintf(
        "Bucket S3 '%v' não tem logging habilitado. Para conformidade com BACEN 4.893 Art. 6 e LGPD Art. 37, todos os buckets de negócio devem ter access logging para um bucket de auditoria designado.",
        [resource.address]
    )
}

deny[msg] {
    msg := violations[_]
}
```

### Política 4: Exigir Criptografia em Volumes EBS

```rego
# policy/aws/ebs_encryption.rego
#
# POLÍTICA: Todos os volumes EBS devem ter criptografia habilitada
#
# Contexto BACEN 4.893: Art. 5 — proteção de dados em repouso
# Contexto LGPD: Art. 46 — medidas de segurança de dados pessoais
# Referência: CKV_AWS_8

package terraform.aws.ebs

import future.keywords.in

# Tipos de recursos que criam volumes EBS
ebs_resource_types := {
    "aws_ebs_volume",
    "aws_instance",       # aws_instance tem root_block_device e ebs_block_device
    "aws_launch_template",
    "aws_launch_configuration",
}

# Verificar criptografia em aws_ebs_volume
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"

    # encrypted deve ser true explicitamente
    not resource.change.after.encrypted == true

    msg := sprintf(
        "Volume EBS '%v' não tem criptografia habilitada. Defina encrypted = true para proteger dados em repouso (BACEN 4.893 Art. 5 e LGPD Art. 46).",
        [resource.address]
    )
}

# Verificar criptografia no root_block_device de aws_instance
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"

    # Itera sobre os root_block_device
    root_block := resource.change.after.root_block_device[_]
    not root_block.encrypted == true

    msg := sprintf(
        "Instância EC2 '%v' tem root_block_device sem criptografia. Defina encrypted = true no bloco root_block_device.",
        [resource.address]
    )
}

# Verificar criptografia nos ebs_block_device adicionais
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"

    ebs_block := resource.change.after.ebs_block_device[_]
    not ebs_block.encrypted == true

    msg := sprintf(
        "Instância EC2 '%v' tem ebs_block_device '%v' sem criptografia.",
        [resource.address, ebs_block.device_name]
    )
}

deny[msg] {
    msg := violations[_]
}
```

### Política 5: Bloquear IAM Policies com Wildcard

```rego
# policy/aws/iam_no_wildcard.rego
#
# POLÍTICA: IAM policies não podem ter ação "*" (wildcard) na condição Effect=Allow
#
# Contexto BACEN 4.893: Art. 8 — gestão de acessos com menor privilégio
# Referência: CKV_AWS_111

package terraform.aws.iam

import future.keywords.in

# Tipos de recursos IAM que contêm policies inline ou managed
iam_resource_types := {
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
}

# Helper: verificar se um statement tem wildcard de ação
has_wildcard_action(statement) {
    statement.Effect == "Allow"
    action := statement.Action

    # Action pode ser string ou array
    is_string(action)
    action == "*"
}

has_wildcard_action(statement) {
    statement.Effect == "Allow"
    action := statement.Action[_]
    action == "*"
}

# Helper: verificar serviço com wildcard (ex: "s3:*")
has_service_wildcard(statement) {
    statement.Effect == "Allow"
    action := statement.Action[_]
    endswith(action, ":*")
    # serviços de alto risco que nunca devem ter wildcard
    high_risk_services := {"iam", "sts", "organizations", "cloudtrail", "kms"}
    parts := split(action, ":")
    parts[0] in high_risk_services
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type in iam_resource_types

    # Parse do document JSON da policy
    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    has_wildcard_action(statement)

    msg := sprintf(
        "IAM Policy '%v' contém Action='*' em um statement Allow. Isso viola o princípio de menor privilégio (BACEN 4.893 Art. 8). Use ações específicas necessárias.",
        [resource.address]
    )
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type in iam_resource_types

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    has_service_wildcard(statement)
    parts := split(statement.Action[_], ":")

    msg := sprintf(
        "IAM Policy '%v' contém '%v:*' (wildcard em serviço de alto risco). Use ações específicas para o serviço '%v'.",
        [resource.address, parts[0], parts[0]]
    )
}

deny[msg] {
    msg := violations[_]
}
```

---

## 5. Integração com CI/CD

### 5.1 GitHub Actions — Workflow Completo

```yaml
# .github/workflows/iac-security.yml
#
# Workflow: IaC Security Scanning no Pull Request
# Executa: Checkov + tfsec + relatório de findings
# Falha: em CRITICAL/HIGH (bloqueia merge)
# Warn: em MEDIUM (não bloqueia, apenas comentário)
#
# Banco Meridian — Security Team
# Referência: BACEN 4.893 Art. 5

name: IaC Security Scan

on:
  pull_request:
    branches: [ main, develop ]
    paths:
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'
      - '**/Dockerfile'
  push:
    branches: [ main ]

permissions:
  contents: read
  security-events: write  # Para upload SARIF ao GitHub Code Scanning
  pull-requests: write    # Para comentários no PR

jobs:
  checkov:
    name: Checkov IaC Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Instalar Checkov
        run: pip install checkov

      - name: Executar Checkov — Terraform (falha em CRITICAL/HIGH)
        id: checkov-terraform
        run: |
          checkov \
            -d ./terraform/ \
            --framework terraform \
            --severity CRITICAL HIGH \
            --output json \
            --output-file-path /tmp/checkov-tf/ \
            --soft-fail-on MEDIUM LOW \
            --skip-check CKV_AWS_144  # S3 replication não obrigatório em sandbox
        continue-on-error: false  # Falha o job se encontrar CRITICAL/HIGH

      - name: Executar Checkov — Kubernetes YAML
        id: checkov-k8s
        run: |
          checkov \
            -d ./k8s/ \
            --framework kubernetes \
            --severity CRITICAL HIGH \
            --output sarif \
            --output-file-path /tmp/checkov-k8s.sarif
        continue-on-error: false

      - name: Upload SARIF para GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: /tmp/checkov-k8s.sarif
          category: checkov-k8s

      - name: Publicar relatório Checkov no PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('/tmp/checkov-tf/results_json.json'));
            const failed = results.results.failed_checks;
            const critical = failed.filter(c => c.check_result.result === 'failed' &&
              ['CRITICAL', 'HIGH'].includes(c.severity));

            if (critical.length > 0) {
              const body = `## ⚠️ Checkov encontrou ${critical.length} findings CRITICAL/HIGH\n\n` +
                critical.slice(0, 10).map(c =>
                  `- **[${c.check_id}]** ${c.check.name} em \`${c.file_path}:${c.file_line_range[0]}\``
                ).join('\n') +
                (critical.length > 10 ? `\n\n...e mais ${critical.length - 10} findings.` : '');
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body
              });
            }

  tfsec:
    name: tfsec Terraform Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      - name: Executar tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: ./terraform
          minimum_severity: MEDIUM
          soft_fail: true       # warn apenas, não falha o workflow (complementa o Checkov)
          format: sarif
          additional_args: --config-file tfsec.yaml

      - name: Upload tfsec SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfsec.sarif
          category: tfsec

  trivy-iac:
    name: Trivy IaC Config Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      - name: Executar Trivy em modo config
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: './terraform'
          format: 'sarif'
          output: 'trivy-iac.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Falha se encontrar CRITICAL/HIGH

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-iac.sarif
          category: trivy-iac

  conftest-opa:
    name: Conftest OPA Policy Check
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      - name: Instalar Conftest
        run: |
          wget https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.48.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/

      - name: Executar Terraform plan (para análise Rego)
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          cd terraform
          terraform init -backend=false
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json

      - name: Executar Conftest com políticas Rego
        run: |
          conftest test terraform/tfplan.json \
            -p policy/ \
            --output table
        continue-on-error: false  # Falha se policy violations encontradas

  security-gate:
    name: Security Gate — Resumo Final
    runs-on: ubuntu-latest
    needs: [ checkov, tfsec, trivy-iac, conftest-opa ]
    if: always()

    steps:
      - name: Verificar resultado de todos os jobs
        run: |
          echo "checkov: ${{ needs.checkov.result }}"
          echo "tfsec: ${{ needs.tfsec.result }}"
          echo "trivy-iac: ${{ needs.trivy-iac.result }}"
          echo "conftest-opa: ${{ needs.conftest-opa.result }}"

          if [[ "${{ needs.checkov.result }}" == "failure" ]] || \
             [[ "${{ needs.conftest-opa.result }}" == "failure" ]]; then
            echo "SECURITY GATE: FALHOU — findings CRITICAL/HIGH ou policy violations detectados"
            echo "O PR não pode ser mergeado até que os findings sejam resolvidos ou suprimidos com justificativa."
            exit 1
          fi

          echo "SECURITY GATE: PASSOU — sem findings CRITICAL/HIGH bloqueantes"
```

### 5.2 GitLab CI — Pipeline Equivalente

```yaml
# .gitlab-ci.yml

stages:
  - iac-security

variables:
  TF_DIR: ./terraform

checkov-scan:
  stage: iac-security
  image: bridgecrew/checkov:latest
  script:
    - checkov -d $TF_DIR --framework terraform --severity CRITICAL HIGH --output junitxml --output-file-path junit-reports/
  artifacts:
    reports:
      junit: junit-reports/results_junitxml.xml
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

tfsec-scan:
  stage: iac-security
  image: aquasec/tfsec:latest
  script:
    - tfsec $TF_DIR --minimum-severity MEDIUM --format json --out tfsec-report.json
  artifacts:
    paths:
      - tfsec-report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: true  # tfsec apenas warn, não bloqueia

conftest-policies:
  stage: iac-security
  image: openpolicyagent/conftest:latest
  script:
    - terraform -chdir=$TF_DIR init -backend=false
    - terraform -chdir=$TF_DIR plan -out=tfplan.binary
    - terraform -chdir=$TF_DIR show -json tfplan.binary > tfplan.json
    - conftest test tfplan.json -p policy/ --output table
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### 5.3 Jenkinsfile — Pipeline IaC Security

```groovy
// Jenkinsfile — Pipeline IaC Security
// Banco Meridian DevSecOps

pipeline {
    agent {
        docker {
            image 'ubuntu:22.04'
        }
    }

    environment {
        AWS_DEFAULT_REGION = 'us-east-1'
    }

    stages {
        stage('Instalar Ferramentas') {
            steps {
                sh '''
                    apt-get update -q
                    pip3 install checkov
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
                    wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
                    tar xzf conftest_0.48.0_Linux_x86_64.tar.gz
                    mv conftest /usr/local/bin/
                '''
            }
        }

        stage('Checkov — IaC Scan') {
            steps {
                sh '''
                    checkov -d ./terraform/ \
                        --framework terraform \
                        --severity CRITICAL HIGH \
                        --output junitxml \
                        --output-file-path reports/ \
                        --soft-fail-on MEDIUM LOW
                '''
            }
            post {
                always {
                    junit 'reports/results_junitxml.xml'
                }
            }
        }

        stage('Trivy — Config Scan') {
            steps {
                sh '''
                    trivy config ./terraform/ \
                        --severity HIGH,CRITICAL \
                        --exit-code 1 \
                        --format json \
                        --output trivy-iac.json
                '''
            }
        }

        stage('Conftest — Policy Validation') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding',
                                   credentialsId: 'aws-audit-credentials']]) {
                    sh '''
                        cd terraform
                        terraform init -backend=false
                        terraform plan -out=tfplan.binary
                        terraform show -json tfplan.binary > ../tfplan.json
                        cd ..
                        conftest test tfplan.json -p policy/ --output table
                    '''
                }
            }
        }
    }

    post {
        failure {
            mail to: 'security@bancomeridian.com.br',
                 subject: "FALHA: IaC Security Scan — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                 body: "O scan de segurança IaC detectou findings críticos. Acesse ${env.BUILD_URL} para detalhes."
        }
    }
}
```

### 5.4 Azure DevOps — Pipeline YAML

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - terraform/**
      - k8s/**

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: pip install checkov
    displayName: Instalar Checkov

  - script: |
      checkov -d ./terraform/ \
        --framework terraform \
        --severity CRITICAL HIGH \
        --output junitxml \
        --output-file-path $(Build.ArtifactStagingDirectory)/
    displayName: Checkov IaC Scan
    continueOnError: false

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: '$(Build.ArtifactStagingDirectory)/results_junitxml.xml'
      testRunTitle: Checkov IaC Security Scan
    condition: always()

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: security-reports
    condition: always()
```

---

## 6. Configuração de Thresholds — Fail/Warn/Ignore

### 6.1 Estratégia Recomendada

```
MODELO DE THRESHOLDS — BANCO MERIDIAN

CRITICAL → FAIL (bloqueia merge/deploy)
─────────────────────────────────────────────────────
Exemplos: S3 público com dados de clientes, SSH aberto
para 0.0.0.0/0, IAM wildcard em produção
→ Requer remediação antes do merge
→ Pode ser suprimido apenas com aprovação do CISO

HIGH → FAIL em prod, WARN em dev/staging
─────────────────────────────────────────────────────
Exemplos: EBS sem criptografia, RDS sem backup
→ Em produção: bloqueia deploy
→ Em desenvolvimento: cria comentário no PR mas não bloqueia
→ Prazo de remediação: 7 dias

MEDIUM → WARN (comentário no PR, não bloqueia)
─────────────────────────────────────────────────────
Exemplos: falta de versioning em S3, IMDSv1 habilitado
→ Não bloqueia merge
→ Rastreado em backlog de segurança
→ Prazo: 30 dias

LOW → LOG (apenas registrado, sem notificação)
─────────────────────────────────────────────────────
→ Revisado mensalmente
→ Suprimível sem aprovação formal
```

### 6.2 Implementação no Checkov

```bash
# Configuração no checkov.yaml (na raiz do repositório)
```

```yaml
# checkov.yaml
# Configuração global do Checkov para o repositório Banco Meridian

# Frameworks habilitados
framework:
  - terraform
  - cloudformation
  - kubernetes
  - dockerfile
  - helm

# Severidade mínima para falhar o job
hard-fail-on:
  - CRITICAL
  - HIGH

# Severidade que gera warn mas não falha
soft-fail-on:
  - MEDIUM
  - LOW

# Checks suprimidos globalmente (com justificativa)
skip-check:
  - CKV_AWS_144  # S3 cross-region replication: não obrigatório em sandbox (aprovado SEC-0045)
  - CKV_AWS_18   # S3 logging: bucket de logs não precisa logar a si mesmo (lógica circular)

# Diretórios a ignorar
skip-path:
  - ./terraform/examples/   # exemplos de documentação, não produção
  - ./terraform/tests/      # fixtures de teste unitário

# Políticas customizadas
external-checks-dir:
  - ./policy/

# Output
output:
  - cli
  - json
  - junitxml

output-file-path: ./security-reports/
```

---

## 7. Atividades de Fixação

### Questão 1
Um desenvolvedor do Banco Meridian adicionou o seguinte bloco Terraform em uma PR:

```hcl
resource "aws_s3_bucket" "backup" {
  bucket = "bancomeridian-backup-2025"
}
```

Quais checks do Checkov esse código FALHARIA? (selecione todos que se aplicam)

**a)** CKV_AWS_19 — Block public access não configurado  
**b)** CKV_AWS_18 — Access logging não configurado  
**c)** CKV_AWS_145 — Criptografia SSE-KMS não configurada  
**d)** CKV_AWS_21 — Versionamento não configurado  

**Gabarito: a), b), c) e d)**  
Justificativa: Um bloco `aws_s3_bucket` com apenas o nome definido falha em todos os checks de segurança básicos. Block public access, logging, criptografia e versionamento são todos necessários para um bucket de backup corporativo que pode conter dados sensíveis. O Checkov verificaria todos esses checks por padrão.

---

### Questão 2
Qual é a diferença principal entre usar `--severity CRITICAL HIGH` e `--soft-fail-on MEDIUM LOW` no Checkov?

**a)** São equivalentes — ambos têm o mesmo efeito  
**b)** `--severity CRITICAL HIGH` executa apenas os checks de alta severidade; `--soft-fail-on MEDIUM LOW` executa todos mas não falha o job para MEDIUM/LOW  
**c)** `--severity` filtra os checks executados; `--soft-fail-on` executa todos os checks mas retorna exit code 0 para os severity especificados (não falhando o CI)  
**d)** `--soft-fail-on MEDIUM LOW` suprime os findings de MEDIUM e LOW do relatório  

**Gabarito: c)**  
Justificativa: `--severity` filtra quais checks são executados. `--soft-fail-on` executa todos os checks, mas ao encontrar findings nos severity listados, o Checkov retorna exit code 0 (sucesso) em vez de 1 (falha). Isso permite que o pipeline continue mesmo com findings MEDIUM/LOW, ao mesmo tempo que os registra para visibilidade.

---

### Questão 3
No contexto de Policy as Code com OPA/Rego, o que acontece quando o conjunto `deny` de uma política está vazio?

**a)** A política falha com erro de execução  
**b)** A política é considerada aprovada (allow) — o recurso satisfaz a política  
**c)** OPA retorna um erro de autorização por padrão  
**d)** A política precisa definir explicitamente `allow = true` para ser aprovada  

**Gabarito: b)**  
Justificativa: Em OPA/Rego com Conftest, a semântica padrão é: se o conjunto `deny` está vazio (nenhuma regra de deny foi ativada), o recurso passou na política. É uma abordagem "deny unless explicitly denied" — se não há violations, está aprovado.

---

### Questão 4
Um engenheiro quer configurar o workflow GitHub Actions para que:
- Findings CRITICAL/HIGH bloqueiem o merge da PR
- Findings MEDIUM apenas adicionem um comentário de aviso na PR
- A PR ainda possa ser mergeada com findings MEDIUM pendentes

Como isso deve ser implementado?

**a)** Um único job com `checkov --severity CRITICAL HIGH --soft-fail-on MEDIUM LOW`  
**b)** Dois jobs separados: um com `--severity CRITICAL HIGH` e exit-code 1; outro com `--severity MEDIUM` e continue-on-error: true  
**c)** Configurar GitHub branch protection rules com require all CI jobs to pass  
**d)** Usar apenas `checkov --severity MEDIUM LOW --soft-fail-on CRITICAL HIGH`  

**Gabarito: a)**  
Justificativa: `--severity CRITICAL HIGH --soft-fail-on MEDIUM LOW` executa todos os checks, falha o job (exit code 1) apenas para CRITICAL/HIGH, e retorna exit code 0 para MEDIUM/LOW (o job passa). Para adicionar o comentário com findings MEDIUM, você adiciona um step adicional após o Checkov que lê o JSON de saída e usa `github-script` para criar o comentário — sem afetar o exit code.

---

### Questão 5
Qual é a principal vantagem do Trivy em relação a usar Checkov + tfsec separadamente em um pipeline de IaC?

**a)** Trivy é mais rápido em qualquer cenário  
**b)** Trivy é um binário unificado que cobre IaC scan + image scan + SBOM + secrets em um único passo, reduzindo a complexidade do pipeline  
**c)** Trivy tem mais checks de IaC do que Checkov e tfsec combinados  
**d)** Trivy tem integração nativa com GitHub Actions sem necessidade de configuração adicional  

**Gabarito: b)**  
Justificativa: O principal diferencial do Trivy é a unificação. Em vez de usar Checkov para IaC + Grype para imagens + Syft para SBOM + GitLeaks para secrets — você usa apenas Trivy com diferentes flags. Isso simplifica o pipeline (menos dependências, menos manutenção) e a interface de análise (um único formato de output, uma única ferramenta para aprender).

---

## 8. Roteiros de Gravação

### Aula 3.1: Shift-Left + Checkov + tfsec (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Shift-Left na Prática: Checkov e tfsec para IaC Security |
| **Duração** | 50 minutos |
| **Formato** | Talking head + VS Code + terminal |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Neste módulo vamos falar de uma das mudanças de mentalidade mais importantes em Cloud Security: o Shift-Left. E depois de entender o conceito, vamos colocar a mão na massa com duas ferramentas que você vai usar no seu dia a dia: Checkov e tfsec.

Uma pergunta antes de começar: você já foi chamado de urgência porque alguém fez um `terraform apply` em produção e criou um S3 bucket com acesso público? Se já, este módulo é para você. Se nunca aconteceu, este módulo vai garantir que nunca aconteça.

---

**[05:00 – 18:00 | CONCEITO SHIFT-LEFT | Slides]**

*[Dica de edição: animação da linha do tempo do custo de correção]*

Shift-Left é um princípio simples: mover as atividades de segurança para a esquerda da linha do tempo de desenvolvimento — do final (produção) para o início (código).

*[Slide: custo de correção por fase]*

Olha esta curva. O custo de corrigir uma vulnerabilidade numa fase inicial de desenvolvimento é aproximadamente 1 real. Na PR, 10 reais. Em staging, 100 reais. Em produção, 1.000 reais. Após um incidente, 10.000 ou mais — sem contar multas e danos de reputação.

Não estou inventando esse número. É uma estimativa do NIST e de estudos do IBM Security. A ordem de magnitude é real.

*[Slide: fluxo com e sem shift-left]*

No fluxo sem shift-left: desenvolvedor escreve Terraform com S3 bucket público, faz push, CI/CD aplica em produção, CSPM detecta 24 horas depois no próximo scan. Resultado: 24 horas de exposição, 40 horas de trabalho para corrigir, possível notificação ao BACEN.

No fluxo com shift-left: desenvolvedor escreve o mesmo Terraform, o pre-commit hook executa Checkov, que imediatamente mostra: "CKV_AWS_19 FAILED — S3 bucket sem block public access". O desenvolvedor corrige em 15 minutos antes de fazer o push. Nenhum dado exposto, nenhum incidente.

É literalmente 100x mais barato. E o Checkov é gratuito.

---

**[18:00 – 40:00 | CHECKOV E TFSEC NA PRÁTICA | VS Code + terminal]**

*[Dica de edição: split-screen — VS Code à esquerda, terminal à direita]*

Vamos abrir o VS Code e criar um arquivo Terraform típico de um desenvolvedor sem treinamento de security.

*[Cria o arquivo terraform/s3.tf com código inseguro]*

```hcl
resource "aws_s3_bucket" "backup" {
  bucket = "bancomeridian-backup-2025"
}
```

Simples, funciona, sem erros de sintaxe. Mas do ponto de vista de segurança, tem pelo menos 4 problemas críticos. Vamos executar o Checkov para ver.

*[Terminal: executa checkov]*

```bash
checkov -f terraform/s3.tf
```

*[Mostra e comenta os resultados]*

Veja: 4 checks falhando — sem block public access, sem logging, sem criptografia, sem versionamento. Cada um com um ID de check, a descrição do problema, e um link para a documentação.

*[Corrige o código Terraform]*

Agora vou corrigir cada problema. *[Adiciona os blocos necessários ao Terraform]*

*[Executa checkov novamente, mostra PASSED]*

Perfeito. Agora vamos ver o tfsec — mais rápido e com integração muito boa com VS Code.

*[Mostra integração VS Code com tfsec — highlighting inline]*

Com a extensão tfsec no VS Code, você vê os problemas inline no código enquanto escreve, sem nem precisar rodar a ferramenta manualmente. Isso é o shift-left mais próximo possível do início: feedback imediato no editor.

---

**[40:00 – 50:00 | PRE-COMMIT HOOK | Terminal]**

*[Dica de edição: tela cheia no terminal]*

Para garantir que nenhum código inseguro saia da máquina do desenvolvedor, vamos configurar um pre-commit hook.

```bash
pip install pre-commit
cat .pre-commit-config.yaml
```

*[Mostra o .pre-commit-config.yaml]*

*[Demonstra commit sendo bloqueado pelo Checkov]*

```bash
git add terraform/s3-inseguro.tf
git commit -m "adicionar bucket de backup"
# Checkov executa, encontra CRITICAL/HIGH, bloqueia o commit
```

*[Mostra o output do hook]*

O commit foi bloqueado. O desenvolvedor vê os problemas agora, neste momento, quando o custo de correção é mínimo. Isso é shift-left na prática.

---

### Aula 3.2: OPA/Rego + GitHub Actions Pipeline (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Policy as Code com OPA/Rego e Pipeline GitHub Actions Completo |
| **Duração** | 50 minutos |
| **Formato** | Terminal + VS Code + GitHub |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Na aula anterior vimos Checkov e tfsec — ferramentas que verificam os checks built-in. Nesta aula vamos um passo além: Policy as Code com OPA Rego, que permite escrever as políticas específicas do seu negócio — as regras que não existem em nenhuma ferramenta open-source porque são específicas do Banco Meridian.

E depois vamos montar o pipeline GitHub Actions completo que executa tudo automaticamente em cada Pull Request.

---

**[05:00 – 25:00 | OPA E REGO | VS Code + terminal]**

*[Dica de edição: tela cheia no VS Code com syntax highlighting Rego]*

OPA é um policy engine open-source. A linguagem Rego é declarativa — você não descreve como verificar uma política, você descreve o que deve ser verdadeiro.

*[Mostra a estrutura básica de uma política Rego]*

Vamos escrever uma política específica do Banco Meridian: todos os recursos AWS devem ter a tag Owner. Não existe check built-in para isso no Checkov porque é uma política interna da nossa organização.

*[Escreve a política Rego ao vivo, comentando cada parte]*

*[Instala conftest, executa contra tfplan.json]*

```bash
terraform init -backend=false
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json -p policy/
```

*[Mostra violations encontradas, corrige o Terraform, reroda]*

---

**[25:00 – 48:00 | GITHUB ACTIONS PIPELINE | GitHub]*

*[Dica de edição: tela cheia no GitHub, zoom nos arquivos de workflow]*

Agora vamos montar o pipeline completo. Vou criar o arquivo `.github/workflows/iac-security.yml`.

*[Mostra e explica cada step do workflow]*

Temos 4 jobs: Checkov (falha em CRITICAL/HIGH), tfsec (apenas warn), Trivy IaC (falha em CRITICAL/HIGH), e Conftest com nossas políticas Rego customizadas.

*[Demonstra uma PR com Terraform inseguro sendo aberta]*

*[Mostra o workflow executando no GitHub Actions]*

*[Mostra o comentário automático na PR com os findings]*

*[Mostra que o merge está bloqueado pelo security gate]*

Veja: o PR está bloqueado. A única maneira de fazer o merge é ou corrigir o código ou adicionar uma supressão documentada com justificativa aprovada pelo CISO.

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

Resumindo: você viu como OPA Rego permite codificar políticas específicas do seu negócio, e como integrar tudo em um pipeline GitHub Actions que bloqueia automaticamente código inseguro.

No laboratório Lab-02, você vai construir esse pipeline completo para o Banco Meridian — com Terraform real, GitHub Actions, Checkov, tfsec, e políticas Rego customizadas. É exatamente o que você vai fazer em um ambiente de trabalho real.

---

## 9. Avaliação do Módulo 03

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
De acordo com a regra do custo de correção por fase, uma vulnerabilidade encontrada em produção custa quanto em comparação com a mesma encontrada na fase de desenvolvimento?

**a)** 2 vezes mais  
**b)** 10 vezes mais  
**c)** 100 vezes mais  
**d)** 1.000 vezes mais  

**Gabarito: d)** A regra do 10x mostra: desenvolvimento (R$ 1) → PR/review (R$ 10) → staging (R$ 100) → produção (R$ 1.000) → pós-incidente (R$ 10.000+). De desenvolvimento para produção, o custo é 1.000x maior.

---

**Questão 2 (10 pts)**  
Um desenvolvedor escreveu uma política Rego que usa a regra `deny[msg]`. O que acontece quando o conjunto `deny` resultante está vazio (nenhuma regra foi ativada)?

**a)** A ferramenta retorna um erro de compilação  
**b)** A política é considerada aprovada — o recurso passou em todos os checks  
**c)** OPA retorna "undecided" e o recurso precisa de aprovação manual  
**d)** O conftest falha com exit code 2 por política incompleta  

**Gabarito: b)** Quando `deny` é um conjunto vazio, significa que nenhuma condição de violação foi verdadeira. No framework Conftest/OPA, isso significa que o recurso passou na política.

---

**Questão 3 (10 pts)**  
Qual ferramenta é a melhor escolha para um pipeline que precisa cobrir IaC scan + image scan + SBOM em um único step?

**a)** Checkov — porque suporta todos os tipos de arquivos IaC  
**b)** Trivy — porque é um binário unificado que cobre todos esses domínios  
**c)** tfsec — porque é o mais rápido para Terraform  
**d)** KICS — porque suporta 35+ tipos de IaC  

**Gabarito: b)** Trivy é o único binário que cobre: `trivy config` (IaC), `trivy image` (container scan), `trivy sbom` (geração de SBOM), `trivy fs` (filesystem scan para secrets). Usando Trivy, um único step no CI/CD cobre múltiplos domínios.

---

**Questão 4 (10 pts)**  
Em um arquivo Terraform, como suprimir corretamente o check `CKV_AWS_19` do Checkov para um bucket S3 de website público, sem afetar outros recursos?

**a)** `# checkov:skip=CKV_AWS_19:Website público intencional — aprovado CISO 2025-04-24 SEC-0123`  
**b)** `--skip-check CKV_AWS_19` no arquivo checkov.yaml global  
**c)** `lifecycle { ignore_changes = [acl] }` no bloco Terraform  
**d)** Remover o check CKV_AWS_19 da instalação do Checkov  

**Gabarito: a)** A supressão inline via comentário `#checkov:skip=` é a prática recomendada porque: (1) está no código, junto ao recurso específico; (2) exige uma justificativa documentada; (3) é rastreável via git blame; (4) não afeta outros recursos. A opção b) afeta todos os buckets no projeto.

---

**Questão 5 (10 pts)**  
No workflow GitHub Actions do Banco Meridian, qual é o papel do step "security-gate" ao final do pipeline?

**a)** Executar um scan adicional de vulnerabilidades  
**b)** Enviar notificação por e-mail para o CISO  
**c)** Verificar o resultado de todos os jobs anteriores e falhar o workflow se qualquer job crítico falhou, consolidando a decisão de bloqueio do PR  
**d)** Gerar o relatório final em PDF para auditoria  

**Gabarito: c)** O security-gate é um job final que usa `needs: [checkov, tfsec, trivy-iac, conftest-opa]` e verifica os resultados de cada job. Ele consolida a decisão: se qualquer job crítico falhou, o gate falha e o PR permanece bloqueado. Isso garante que o desenvolvedor não pode ignorar um job específico.

---

**Questão 6 (10 pts)**  
Qual é a diferença entre HashiCorp Sentinel e OPA/Conftest para Policy as Code?

**a)** Sentinel é open-source; OPA é proprietário e pago  
**b)** Sentinel é integrado ao Terraform Cloud/Enterprise e aplica políticas em runs do Terraform; OPA/Conftest é uma solução open-source para CI/CD pipelines em qualquer contexto  
**c)** Sentinel verifica apenas Kubernetes; OPA verifica apenas Terraform  
**d)** Sentinel usa YAML; OPA usa Python  

**Gabarito: b)** Sentinel está embutido no Terraform Cloud e Enterprise — é executado automaticamente em cada run do Terraform sem necessidade de pipeline separado. OPA/Conftest é open-source e independente, podendo ser usado em qualquer CI/CD (GitHub Actions, GitLab, Jenkins) para qualquer tipo de arquivo, não apenas Terraform.

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O time de plataforma do Banco Meridian decidiu implementar um processo de "Security as Code" onde todas as políticas de segurança cloud são versionadas como código, verificadas automaticamente em CI/CD, e evidenciadas para auditoria do BACEN.

**Tarefa (2 perguntas, 20 pts cada):**

1. Escreva uma política Rego completa e funcional que verifique se todos os recursos `aws_db_instance` (RDS) no Terraform têm:
   - `encrypted = true`  
   - `deletion_protection = true`  
   - `backup_retention_period` maior que 7 (dias)  
   - Tag `Environment` presente

2. Desenhe o fluxo completo do pipeline DevSecOps do Banco Meridian (do commit ao deploy) incluindo: onde cada ferramenta se encaixa, o que bloqueia o merge, o que apenas avisa, e quais evidências são geradas para auditoria BACEN

**Gabarito:**

1. **Política Rego:**

```rego
package terraform.aws.rds

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.encrypted == true
    msg := sprintf("RDS '%v' não tem encrypted=true (BACEN Art. 5)", [resource.address])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.deletion_protection == true
    msg := sprintf("RDS '%v' não tem deletion_protection=true", [resource.address])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.backup_retention_period <= 7
    msg := sprintf("RDS '%v' tem backup_retention_period de %v dias — mínimo é 7 (BACEN Art. 10)",
        [resource.address, resource.change.after.backup_retention_period])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.tags.Environment
    msg := sprintf("RDS '%v' está faltando a tag obrigatória 'Environment'", [resource.address])
}

deny[msg] { msg := violations[_] }
```

2. **Fluxo pipeline:**
   - IDE: tfsec extensão VS Code (warn inline)
   - Pre-commit: Checkov (bloqueia commit com CRITICAL)
   - PR aberta: GitHub Actions executa Checkov + tfsec + Trivy IaC + Conftest OPA
   - Se CRITICAL/HIGH: PR bloqueada + comentário automático com findings
   - Se apenas MEDIUM/LOW: PR aprovada com comentário de aviso
   - Merge no main: trigger de deploy para staging com aprovação manual
   - Evidências geradas: JUnit XML (Checkov), SARIF (tfsec/Trivy → GitHub Code Scanning), JSON (Conftest) — todos armazenados por 5 anos para auditoria BACEN

---

*Módulo 03 — IaC Security e Shift-Left*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
