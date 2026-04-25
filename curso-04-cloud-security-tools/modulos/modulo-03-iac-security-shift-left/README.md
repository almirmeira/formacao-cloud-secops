# Módulo 03 — IaC Security e Shift-Left
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2h videoaulas + 2h laboratório + 1h live online
> **Certificação Alvo:** CCSP domínio 3 / CCSK domínio 7
> **Cenário:** Time de DevOps do Banco Meridian implementando segurança no pipeline de IaC

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Explicar o conceito de Shift-Left e quantificar o custo de encontrar vulnerabilidades em cada fase
2. Executar Checkov, tfsec e Trivy em projetos Terraform e CloudFormation, interpretando cada flag e campo do output
3. Escrever políticas OPA/Rego para verificar Terraform plans, explicando cada bloco da política
4. Construir um workflow GitHub Actions completo para IaC scanning em pull requests, com comentários em cada job
5. Configurar gates de falha diferenciados por severidade (CRITICAL bloqueia, MEDIUM avisa) nos pipelines CI/CD

---

## 1. Conceito Shift-Left — Por Que Encontrar Vulnerabilidades Cedo É Muito Mais Barato

### 1.1 A Regra do 10x

O princípio fundamental do Shift-Left é que o custo de corrigir um problema de segurança cresce dramaticamente conforme a fase em que é encontrado. Essa progressão é chamada de Regra do 10x:

```
REGRA DO 10X — CUSTO DE CORREÇÃO POR FASE

Fase de desenvolvimento (pre-commit)         → R$ 1
  └── O desenvolvedor escreve código e o check é instantâneo
      Correção: editar o arquivo. 5 minutos.

Fase de revisão (Pull Request, CI)           → R$ 10
  └── O pipeline detecta. O dev precisa fazer nova iteração.
      Correção: nova branch, novo commit, rerun do pipeline. 30 minutos.

Fase de teste (QA, staging)                 → R$ 100
  └── QA encontra. Dev precisa revisar, reabrir a issue.
      Correção: debug de ambiente, nova versão de staging. 4 horas.

Fase de produção (pós-deploy)               → R$ 1.000
  └── Produção com misconfiguration real.
      Correção: change management, aprovação, manutenção programada. 8–40 horas.

Pós-incidente de segurança                   → R$ 10.000+
  └── S3 bucket público por 72h com dados de clientes.
      Custo: notificação BACEN, análise forense, remediação de imagem,
      comunicação a clientes afetados. Potencial multa de até 2% do faturamento.
```

**O caso do Banco Meridian:**

Sem Shift-Left: um desenvolvedor escreve `terraform apply` criando um S3 bucket sem criptografia. O bucket vai para produção na sexta-feira às 18h. A auditoria do Prowler (que roda semanalmente) detecta na quinta-feira seguinte. São 6 dias de exposição, 40+ horas de trabalho para remediação via change management e possível notificação ao BACEN.

Com Shift-Left: o mesmo desenvolvedor escreve o recurso Terraform. O pre-commit hook executa Checkov em 3 segundos. Output: `CKV_AWS_145 FAILED — S3 bucket missing server-side encryption`. O desenvolvedor corrige em 15 minutos no mesmo terminal. Custo: zero exposição.

### 1.2 O Fluxo Completo com Shift-Left

```
FLUXO SEM SHIFT-LEFT (atual no Banco Meridian)

Desenvolvedor escreve Terraform com S3 bucket público
           │
           ▼
     terraform apply (deploy direto)
           │
           ▼
  S3 bucket público em PRODUÇÃO 6 dias
           │
           ▼
  Prowler detecta na varredura semanal
           │
           ▼
  Change management + aprovação + correção
           │
           ▼
  Custo: 40+ horas + risco de exposição durante janela

──────────────────────────────────────────────────────────────

FLUXO COM SHIFT-LEFT (meta do Banco Meridian)

Desenvolvedor escreve Terraform com S3 bucket público
           │
           ▼ pre-commit hook executa Checkov (3 segundos)
           │
  BLOCKED: CKV_AWS_19 FAILED — S3 bucket missing public access block
           │
           ▼ Desenvolvedor corrige no mesmo terminal
           │
           ▼ git commit → GitHub → GitHub Actions pipeline
           │
  CI executa: Checkov + tfsec + Trivy IaC + Conftest OPA
  PASSED: sem findings CRITICAL/HIGH
           │
           ▼ PR aprovado, merge autorizado
           │
           ▼
  S3 bucket seguro em produção desde o primeiro deploy
           │
  Custo: 15 minutos do desenvolvedor
```

### 1.3 Ferramentas por Tipo de IaC

| Tipo de IaC | Ferramentas de Scan | O Que Detectam |
|:-----------|:--------------------|:---------------|
| Terraform (.tf) | Checkov, tfsec, Trivy IaC, Terrascan | Misconfigurations de AWS/Azure/GCP |
| CloudFormation (.yaml/.json) | Checkov, cfn-lint | Misconfigs CloudFormation-específicas |
| Kubernetes YAML | Checkov, Trivy IaC, Datree | PSS violations, RBAC issues, hostPath |
| Dockerfile | Checkov, Trivy, Hadolint | Root user, ENV secrets, latest tag |
| Helm Charts | Checkov, Trivy IaC | Misconfigs em templates K8s |
| ARM Templates | Checkov | Misconfigs Azure Resource Manager |
| Bicep | Checkov | Misconfigs Azure Bicep |

---

## 2. Ferramentas de IaC Scanning

### 2.1 Checkov

Checkov é a ferramenta mais completa para IaC security scanning. Desenvolvida pela Bridgecrew (adquirida pela Palo Alto Networks), é open-source com mais de 1.000 checks.

**Por que Checkov para o Banco Meridian:**
Checkov é a escolha ideal quando você precisa de cobertura ampla de múltiplos tipos de IaC (Terraform + CloudFormation + K8s + Dockerfile), integração com GitHub Code Scanning via SARIF, e capacidade de escrever checks customizados em Python para políticas internas do banco. É a ferramenta com maior biblioteca de checks e melhor suporte a frameworks regulatórios.

**Instalação:**
```bash
pip install checkov
checkov --version
```

**O que este bloco de comandos faz:**

**Execução básica:**

```bash
# Scan de diretório Terraform
# -d especifica o diretório a ser escaneado recursivamente
# Checkov encontrará todos os arquivos .tf no diretório e subdiretórios
checkov -d ./terraform/

# Scan de arquivo específico
# -f aponta para um arquivo único, útil para validação rápida
checkov -f ./terraform/main.tf

# Scan apenas por framework
# --framework filtra o tipo de IaC — sem isso, Checkov tenta detectar automaticamente
checkov -d ./terraform/ --framework terraform

# Listar todos os checks disponíveis
# Útil para saber quais checks existem antes de configurar exclusões
checkov -l

# Informações sobre um check específico
# Mostra: descrição, recursos afetados, exemplo de código com falha e com pass
checkov --check CKV_AWS_18
```

**O que o comando `--soft-fail-on` faz e por que ele importa no Banco Meridian:**

```bash
# Falhar apenas em CRITICAL (não em HIGH, MEDIUM ou LOW)
# --soft-fail-on diz ao Checkov: "para essas severidades, reporte mas não retorne exit code 1"
# Exit code 0 = pipeline continua | Exit code 1 = pipeline falha
checkov -d ./terraform/ --soft-fail-on HIGH MEDIUM LOW

# Falhar em CRITICAL e HIGH (MEDIUM e LOW apenas reportam)
# Configuração recomendada para o pipeline do Banco Meridian:
# CRITICAL/HIGH bloqueiam o merge, MEDIUM/LOW apenas geram comentário no PR
checkov -d ./terraform/ --soft-fail-on MEDIUM LOW

# Skip de um check específico (com justificativa rastreável)
# ATENÇÃO: sempre documente o motivo no comentário #checkov:skip= no código
# Skip no command line (não rastreável) é má prática
checkov -d ./terraform/ --skip-check CKV_AWS_20,CKV_AWS_28
```

**Formatos de saída e quando usar cada um:**

```bash
# Saída compacta — apenas FAILED (útil em terminal para inspeção rápida)
checkov -d ./terraform/ --compact

# Saída em JSON — para processamento programático, integração com SIEM
checkov -d ./terraform/ -o json

# Saída em JUnit XML — para CI/CD que suporta relatórios de teste (Jenkins, GitLab)
checkov -d ./terraform/ -o junitxml

# Saída em SARIF — padrão da indústria para Code Scanning no GitHub
# Permite que os findings apareçam diretamente na aba "Security" do repositório GitHub
checkov -d ./terraform/ -o sarif

# Salvar resultado em arquivo (diretório)
checkov -d ./terraform/ -o json --output-file-path /tmp/checkov-results/

# Scan de CloudFormation
checkov -d ./cloudformation/ --framework cloudformation

# Scan de Kubernetes YAML
checkov -d ./k8s-manifests/ --framework kubernetes

# Scan de Dockerfile
checkov -f ./Dockerfile --framework dockerfile

# Scan de Helm charts
checkov -d ./helm/ --framework helm

# Custom policy directory — para políticas específicas do Banco Meridian
# O Checkov carregará seus checks Python customizados além dos built-in
checkov -d ./terraform/ --external-checks-dir ./custom-policies/
```

**O que este comando faz (checkov -d ./terraform/ --soft-fail-on MEDIUM LOW):**

O `checkov -d ./terraform/ --soft-fail-on MEDIUM LOW` executa uma varredura SAST (Static Application Security Testing) em todos os arquivos Terraform do diretório. O parâmetro `--soft-fail-on MEDIUM LOW` instrui o Checkov a reportar achados de severidade MEDIUM e LOW mas não falhar o pipeline por eles — apenas findings CRITICAL e HIGH causam falha (exit code 1). No contexto do Banco Meridian, isso significa que o pipeline bloqueia automaticamente qualquer IaC que tente criar recursos AWS com configurações de alto risco (por exemplo: S3 sem criptografia, IAM com permissões `*`, Security Groups expostos para 0.0.0.0/0), enquanto problemas menores são registrados mas não bloqueiam o desenvolvimento.

**Interpretando a saída do Checkov:**

```
Check: CKV_AWS_19: "Ensure the S3 bucket has access control list (ACL) disabled or uses aws_s3_bucket_acl"
    FAILED for resource: aws_s3_bucket.dados_clientes
    File: /terraform/s3.tf:3:1-5:1
    Guide: https://docs.bridgecrew.io/docs/s3_19

Check: CKV_AWS_145: "Ensure that S3 buckets are encrypted with KMS by default"
    FAILED for resource: aws_s3_bucket.dados_clientes
    File: /terraform/s3.tf:3:1-5:1

Passed checks: 47, Failed checks: 5, Skipped checks: 1

CRITICAL: 0
HIGH: 3
MEDIUM: 2
LOW: 0
```

**Interpretando a saída:**
- `Check: CKV_AWS_19:` — identificador único do check (CKV = Checkov, AWS = provider, 19 = número sequencial). Este ID é estável — você pode buscar qualquer CKV_AWS_XXX na documentação da Bridgecrew
- `FAILED for resource: aws_s3_bucket.dados_clientes` — qual recurso Terraform específico falhou
- `File: /terraform/s3.tf:3:1-5:1` — arquivo e linha (linha 3, coluna 1 até linha 5, coluna 1) onde o recurso está definido — você pode ir diretamente para essa linha no editor
- `HIGH: 3` — com a configuração `--soft-fail-on MEDIUM LOW`, esses 3 findings HIGH causarão exit code 1, bloqueando o merge do PR

**Exemplo de Terraform com findings e supressão rastreável:**

```hcl
# terraform/s3.tf

# ❌ BUCKET COM PROBLEMAS (sem comentários de skip — pipeline vai FALHAR)
resource "aws_s3_bucket" "dados_clientes" {
  bucket = "bancomeridian-dados-clientes"
  # CKV_AWS_19: falta block public access → CRITICAL
  # CKV_AWS_18: falta logging → MEDIUM
  # CKV_AWS_145: falta criptografia KMS → HIGH
  # CKV_AWS_21: falta versionamento → MEDIUM
}

# ✅ BUCKET CORRIGIDO — passa em todos os checks de segurança
resource "aws_s3_bucket" "dados_clientes_seguro" {
  bucket = "bancomeridian-dados-clientes-v2"

  # Tags obrigatórias — verificadas por política Rego customizada
  tags = {
    Owner       = "equipe-dados"
    Environment = "production"
    DataClass   = "Confidential"
    CostCenter  = "TI-0042"
  }
}

# Block Public Access — impede qualquer acesso público acidental
# CKV_AWS_19: PASS
resource "aws_s3_bucket_public_access_block" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  block_public_acls       = true  # Bloqueia novas ACLs públicas
  block_public_policy     = true  # Bloqueia bucket policies que permitem acesso público
  ignore_public_acls      = true  # Ignora ACLs públicas existentes
  restrict_public_buckets = true  # Bloqueia acesso público via policy, mesmo que ACL permita
}

# Criptografia com KMS customer-managed key
# CKV_AWS_145: PASS — SSE-KMS vs SSE-S3: KMS permite auditoria via CloudTrail de QUEM descriptografou
resource "aws_s3_bucket_server_side_encryption_configuration" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"           # KMS customer-managed key (não aws/s3 managed)
      kms_master_key_id = aws_kms_key.s3_key.arn  # Chave KMS específica do Banco Meridian
    }
    bucket_key_enabled = true  # Reduz custos de API KMS sem comprometer segurança
  }
}

# Access logging — registra cada acesso ao bucket (requerido pela LGPD Art. 37)
# CKV_AWS_18: PASS
resource "aws_s3_bucket_logging" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

# Versionamento — protege contra deleção acidental e ransomware
# CKV_AWS_21: PASS
resource "aws_s3_bucket_versioning" "dados_clientes_seguro" {
  bucket = aws_s3_bucket.dados_clientes_seguro.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ✅ EXCEÇÃO DOCUMENTADA — skip com rastreabilidade
# Website público intencional — aprovado pelo CISO, ticket SEC-0123, data 2025-04-24
# O comentário #checkov:skip= é rastreável no git history e auditável
resource "aws_s3_bucket" "website_publico" {
  bucket = "bancomeridian-website"

  #checkov:skip=CKV_AWS_19:Website público intencional - aprovado CISO em 2025-04-24 ticket#SEC-0123
}
```

**Checks mais importantes do Checkov para o Banco Meridian:**

| Check ID | Recurso | Descrição | Regulação |
|:---------|:--------|:----------|:----------|
| CKV_AWS_19 | S3 | Block Public Access habilitado | LGPD Art. 46 |
| CKV_AWS_18 | S3 | Access logging habilitado | LGPD Art. 37 |
| CKV_AWS_145 | S3 | Criptografia SSE com KMS | BACEN Art. 5 |
| CKV_AWS_21 | S3 | Versionamento habilitado | BACEN Art. 5 |
| CKV_AWS_24 | Security Group | Sem porta 22 para 0.0.0.0/0 | BACEN Art. 5 |
| CKV_AWS_25 | Security Group | Sem porta 3389 para 0.0.0.0/0 | BACEN Art. 5 |
| CKV_AWS_79 | EC2 | IMDSv2 habilitado | BACEN Art. 5 |
| CKV_AWS_8 | EC2 | EBS volume encrypted | BACEN Art. 5 |
| CKV_AWS_28 | RDS | Backup habilitado | BACEN Art. 5 |
| CKV_AWS_17 | RDS | Não publicly accessible | BACEN Art. 5 |
| CKV_AWS_16 | RDS | Storage encrypted | BACEN Art. 5 |
| CKV_AWS_57 | Lambda | Função não pública | BACEN Art. 5 |
| CKV_AWS_111 | IAM | Sem wildcard "*" em permissions | BACEN Art. 8 |
| CKV_AWS_120 | IAM | Password policy com MFA | BACEN Art. 8 |

---

### 2.2 tfsec

tfsec é especializado em Terraform, desenvolvido em Go — muito mais rápido que Checkov para projetos grandes. Excelente integração com VS Code (extensão disponível).

**Por que tfsec como complemento ao Checkov:**
tfsec é escrito em Go, o que o torna 5–10x mais rápido que Checkov para projetos Terraform grandes. É ideal para uso em pre-commit hooks onde a velocidade importa — o desenvolvedor não deve esperar mais do que 5–10 segundos para um feedback. Em pipelines CI/CD, tfsec e Checkov são complementares porque têm alguns checks diferentes.

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

**O que cada flag faz:**

```bash
# Scan básico — escaneia recursivamente o diretório ./terraform/
tfsec ./terraform/

# Saída formatada (padrão, mais legível para terminal)
tfsec ./terraform/ --format lovely

# Saída JSON — para integração com SIEM, dashboards ou scripts de relatório
tfsec ./terraform/ --format json

# Saída SARIF — para upload ao GitHub Code Scanning (aparece na aba Security do repo)
tfsec ./terraform/ --format sarif

# --minimum-severity HIGH significa: reporte e falhe apenas para HIGH e CRITICAL
# MEDIUM e LOW são registrados mas não causam exit code 1
# Configuração equivalente ao --soft-fail-on MEDIUM LOW do Checkov
tfsec ./terraform/ --minimum-severity HIGH

# Excluir checks específicos por ID
# Usar apenas quando há justificativa de negócio aprovada
tfsec ./terraform/ --exclude aws-s3-no-public-access-with-acl

# Scan com arquivo de configuração (recomendado para projetos)
# Centraliza as exceções e políticas customizadas em um arquivo versionado
tfsec ./terraform/ --config-file tfsec.yaml

# Verbose — mostra todos os checks executados, inclusive os que passaram
tfsec ./terraform/ --verbose

# Include-passed — lista todos os checks e seus resultados (útil para auditoria)
tfsec ./terraform/ --include-passed
```

**O que este arquivo de configuração faz:**

```yaml
# tfsec.yaml — Configuração central do tfsec para o repositório do Banco Meridian
#
# Este arquivo centraliza todas as exceções e configurações de segurança.
# QUALQUER exceção aqui deve ter um ticket de aprovação referenciado.
# Sem ticket documentado → exceção não é aceita na revisão de code.

minimum_severity: MEDIUM  # Reportar MEDIUM, HIGH e CRITICAL. Ignorar LOW.

exclude:
  # aws-s3-no-public-access-with-acl: bucket bancomeridian-website é público intencionalmente
  # Aprovado pelo CISO em 2025-04-24, ticket SEC-0123
  - aws-s3-no-public-access-with-acl

  # aws-ec2-no-public-ip: jumpbox de acesso temporário em sandbox
  # Aprovado pelo CISO em 2025-03-15, ticket SEC-0124
  - aws-ec2-no-public-ip

custom_checks:
  # Check customizado: política interna do Banco Meridian
  # Todo recurso AWS deve ter a tag Owner definida
  - action: DENY
    description: "Banco Meridian: todos os recursos devem ter tag Owner"
    errorMessage: "Recurso sem tag 'Owner' obrigatória — adicionar antes do deploy"
    match:
      block: resource
      attribute: "tags.Owner"
      action: isAbsent   # isAbsent = verdadeiro quando o atributo não existe
```

---

### 2.3 KICS — Keep Infrastructure as Code Secure

KICS (Checkmarx) é a solução open-source mais multilinguagem — suporta 35+ tipos de IaC. Diferencial em ambientes com grande variedade de tecnologias.

**O que este bloco de comandos faz:**

```bash
# Instalar via Docker (recomendado — sem dependências de instalação)
docker pull checkmarx/kics:latest

# Scan de diretório via Docker
# -v monta o diretório atual em /path dentro do container
# scan -p /path/terraform especifica o caminho de entrada
# -o /path/results especifica onde salvar os resultados
docker run -v "$(pwd):/path" checkmarx/kics:latest scan \
  -p /path/terraform \
  -o /path/results

# Scan com múltiplos frameworks ao mesmo tempo
# --type filtra os tipos de IaC a escanear (útil em mono-repos)
# --report-formats gera relatórios em múltiplos formatos simultaneamente
docker run -v "$(pwd):/path" checkmarx/kics:latest scan \
  -p /path/ \
  --type "Terraform,Kubernetes,Dockerfile" \
  -o /path/results \
  --report-formats "json,html"

# Instalar binário nativo (sem Docker)
curl -sfL 'https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh' | bash

# Scan nativo
kics scan -p ./terraform/ -o ./results/
```

---

### 2.4 Terrascan

Foco em compliance frameworks (CIS, NIST, PCI-DSS). Útil quando o objetivo é gerar relatórios de conformidade além de encontrar misconfigurations.

**O que cada comando faz:**

```bash
# Instalar
brew install accurics/tap/terrascan
# ou binário
curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz" | tar -xz
sudo install terrascan /usr/local/bin

# Scan Terraform — -i terraform especifica o tipo de IaC de entrada
# -d especifica o diretório
terrascan scan -i terraform -d ./terraform/

# Scan com policy específica — -t aws filtra apenas policies AWS
terrascan scan -i terraform -d ./terraform/ --policy-type aws

# --scan-rules aws_cis_v130 aplica apenas as regras do CIS AWS Benchmark v1.3
# Útil para gerar evidência de conformidade CIS especificamente
terrascan scan -i terraform -d ./terraform/ -t aws --scan-rules aws_cis_v130

# -o json gera saída estruturada para integração programática
terrascan scan -i terraform -d ./terraform/ -o json

# -i k8s muda o modo de análise para Kubernetes manifests
terrascan scan -i k8s -f ./k8s-manifests/deployment.yaml
```

---

### 2.5 Trivy — Modo IaC

Trivy é a ferramenta unificada da Aqua Security que cobre containers, IaC, SBOM e secrets em um único binário. No modo `trivy config`, ele age como scanner de IaC.

**Por que o Trivy em modo IaC é estratégico:**
O Trivy é a única ferramenta open-source que cobre com excelência tanto image scanning (módulo 04) quanto IaC scanning em um único binário. No pipeline CI/CD do Banco Meridian, usar Trivy em ambos os modos reduz o número de ferramentas a manter e unifica o formato de output. Uma única ferramenta cobrindo container vulnerabilidades + IaC misconfigurations + secrets é simpler de operar.

**O que cada flag faz:**

```bash
# Instalar Trivy
brew install trivy
# ou
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# trivy config: modo de scan de configurações (IaC)
# Diferente de trivy image (containers) ou trivy fs (filesystem)
# Suporta: Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, Azure ARM, Bicep
trivy config ./terraform/

# --severity HIGH,CRITICAL: reporte e falhe apenas para severidades especificadas
# Equivalente ao --minimum-severity HIGH do tfsec
# Importante: aqui é vírgula sem espaço (diferente do Checkov que usa espaço)
trivy config ./terraform/ --severity HIGH,CRITICAL

# Scan de manifests Kubernetes — mesma ferramenta, mesmo comando, diretório diferente
trivy config ./k8s-manifests/

# Scan de Dockerfile — trivy config analisa as instruções do Dockerfile
trivy config ./Dockerfile

# Scan de Helm chart — trivy renderiza os templates e escaneia os manifests resultantes
trivy config ./helm/meu-chart/

# --format json: saída JSON estruturada para processamento programático
trivy config ./terraform/ --format json

# --format sarif: padrão SARIF para upload ao GitHub Code Scanning
# --output trivy-iac.sarif: salva em arquivo (necessário para o upload no Actions)
trivy config ./terraform/ --format sarif --output trivy-iac.sarif

# --include-non-failures: inclui checks que passaram (útil para auditoria completa)
trivy config . --include-non-failures

# --policy ./custom-policies/: aplica políticas Rego customizadas além dos checks built-in
trivy config ./terraform/ --policy ./custom-policies/

# --exit-code 1: retorna exit code 1 (falha) quando encontra findings com as severidades especificadas
# Essencial para CI/CD — sem esta flag, Trivy sempre retorna 0 (sucesso) mesmo com findings
# Exit code 1 faz o GitHub Actions marcar o step como falha e impede o merge
trivy config ./terraform/ --exit-code 1 --severity HIGH,CRITICAL
```

**Vantagem consolidada do Trivy:** um único binário cobre IaC scan + image scan + SBOM + secrets scan. No pipeline CI/CD você pode usar apenas o Trivy e cobrir múltiplos domínios com uma ferramenta familiar.

---

## 3. Policy as Code com OPA/Rego

### 3.1 OPA — Open Policy Agent — O Motor de Políticas

OPA é um policy engine open-source e de uso geral que permite escrever políticas em uma linguagem declarativa chamada Rego. É usado pelo Kubernetes (Gatekeeper), pelo Terraform (via Conftest), e por pipelines CI/CD.

**Por que Policy as Code em vez de documentação de políticas:**
Políticas escritas em documentos Word ou wikis são lidas (quando lidas) mas não executadas automaticamente. Uma política que diz "todos os S3 buckets devem ter criptografia" em um documento não impede que um desenvolvedor crie um bucket sem criptografia. A mesma política escrita em Rego e executada no pipeline impede automaticamente, com uma mensagem de erro clara, antes do merge. Isso é o que separa uma postura de segurança declarativa (intenção) de uma postura de segurança executável (garantia).

**Arquitetura:**
```
OPA — COMO FUNCIONA NO CONTEXTO IaC
─────────────────────────────────────────────────────────────
INPUT (JSON/YAML)       →  OPA Engine  →  DECISION (allow/deny)
(Terraform plan ou         + Rego          + violations[msg]
 K8s manifest em JSON)      policies
─────────────────────────────────────────────────────────────
Casos de uso:
  - CI/CD policy enforcement (Conftest) — valida antes do merge
  - Kubernetes Admission Control (OPA Gatekeeper) — valida antes do deploy
  - Terraform plan validation — valida ANTES do apply
  - API authorization — valida cada requisição de API
  - Microservice authorization — controle de acesso entre serviços
─────────────────────────────────────────────────────────────
```

**Instalação:**
```bash
# macOS/Linux
brew install opa
# ou binário estático (sem dependências, recomendado para CI/CD)
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/

# Verificar versão
opa version
```

**Sintaxe Rego — Conceitos Fundamentais com Explicação:**

```rego
# Rego é uma linguagem declarativa — você descreve O QUE deve ser verdade,
# não COMO chegar lá (diferente de Python ou JavaScript imperativo)
# Se TODAS as condições de um bloco são verdadeiras → a regra é verdadeira

package terraform.aws.security
# package: como um namespace — organiza políticas por domínio
# Convenção: terraform.aws.security para políticas de Terraform + AWS + segurança

# 1. REGRAS BOOLEANAS (allow/deny)
# default deny = false: se nenhuma condição de deny for satisfeita, deny = false (política passou)
# Isso é o "closed world assumption" do Rego — o que não é explicitamente proibido é permitido
default deny = false

deny {
    # Todas as condições dentro do bloco devem ser verdadeiras para deny = true
    input.resource_type == "aws_s3_bucket"   # É um bucket S3?
    input.config.acl == "public-read"        # Tem ACL public-read?
    # Se ambas verdadeiras → deny = true → política falha → pipeline bloqueado
}

# 2. VIOLATIONS COM MENSAGENS DE ERRO (padrão recomendado)
# violations é um SET — cada elemento é uma mensagem de violação
# Conftest e checkov usam violations[msg] como convenção padrão
violations[msg] {
    input.resource_type == "aws_s3_bucket"
    input.config.acl == "public-read"
    # sprintf formata a string com o nome do recurso
    msg := sprintf("Bucket '%v' não pode ter ACL public-read (BACEN Art. 5)", [input.resource_name])
}

# 3. COMPREHENSIONS (iteração declarativa)
# Equivalente a uma list comprehension em Python mas declarativa
# Cria uma lista de todos os buckets com ACL pública
public_buckets := [name |
    resource := input.resources[name]       # Para cada recurso no input
    resource.type == "aws_s3_bucket"        # Que é um bucket S3
    resource.config.acl == "public-read"    # Com ACL pública
    # O nome vai para a lista pública
]

# 4. HELPERS (regras auxiliares reutilizáveis)
# is_production pode ser usada em múltiplas regras do mesmo package
is_production {
    input.config.tags.Environment == "production"
}

# 5. IMPORTS para features modernas do Rego
# future.keywords.in permite usar o operador `in` (mais legível que some x in y)
# future.keywords.every permite usar `every` para verificar que todos satisfazem uma condição
import future.keywords.in
import future.keywords.every
```

---

### 3.2 Conftest — OPA para Arquivos de Configuração

Conftest é uma CLI que usa OPA/Rego para testar arquivos de configuração estruturados (JSON, YAML, HCL, Dockerfile, etc.).

**Por que Conftest para o pipeline do Banco Meridian:**
Conftest preenche a lacuna entre escrever políticas Rego e aplicá-las no pipeline CI/CD. Enquanto OPA é um engine genérico, Conftest é uma CLI focada em "testar arquivos de configuração contra políticas Rego". O fluxo é: `terraform plan → saída JSON → conftest test → violations ou pass`. Isso permite políticas de segurança específicas do Banco Meridian que vão além do que Checkov e tfsec oferecem.

**O que cada comando faz:**

```bash
# Instalar
brew install conftest
# ou binário
wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz

# Estrutura de projeto com Conftest:
# ./terraform/main.tf       ← código Terraform
# ./policy/s3.rego          ← política para recursos S3
# ./policy/iam.rego         ← política para recursos IAM
# ./policy/tags.rego        ← política para tags obrigatórias

# Testar Terraform com Conftest
# -p ./policy/ indica o diretório onde estão as políticas Rego
# Conftest converte automaticamente o HCL Terraform para JSON antes de avaliar
conftest test ./terraform/ -p ./policy/

# Testar manifesto Kubernetes
# Funciona com qualquer arquivo YAML/JSON que o OPA pode consumir
conftest test ./k8s-manifests/deployment.yaml -p ./policy/

# Testar com múltiplos diretórios de políticas
# Útil para separar políticas globais (corporate) de políticas do projeto
conftest test ./terraform/ -p ./policy/aws/ -p ./policy/global/

# --output table: saída em tabela (mais legível para revisão humana)
conftest test ./terraform/ -p ./policy/ --output table

# --output json: saída JSON para integração com outras ferramentas
conftest test ./terraform/ -p ./policy/ --output json

# Usar políticas publicadas em OCI registry (Conftest Bundle)
# Permite centralizar políticas do Banco Meridian e distribuí-las para todos os repos
conftest pull ghcr.io/bancomeridian/security-policies:v1.0
conftest test ./terraform/ -p policy/
```

---

### 3.3 HashiCorp Sentinel

Sentinel é o motor de Policy as Code integrado ao Terraform Cloud e Enterprise — políticas aplicadas automaticamente em todos os runs do Terraform.

**Por que Sentinel em vez de OPA/Conftest:**
Sentinel é integrado nativamente ao Terraform Cloud e Enterprise. Se o Banco Meridian usa Terraform Cloud como plataforma de execução, Sentinel é a escolha natural porque as políticas são aplicadas antes de cada `terraform apply`, sem necessidade de configurar CI/CD adicional. A desvantagem: Sentinel só funciona no ecossistema Terraform HashiCorp — OPA/Conftest é agnóstico.

```python
# sentinel/require-tags.sentinel
# Política Sentinel: todos os recursos AWS devem ter tags obrigatórias
# Esta política é aplicada automaticamente pelo Terraform Cloud antes de cada apply

import "tfplan/v2" as tfplan
# tfplan/v2 é o módulo Sentinel que dá acesso ao Terraform plan como estrutura de dados

required_tags = ["Owner", "Environment", "CostCenter"]
# Lista de tags obrigatórias pela política do Banco Meridian

# Obter todos os recursos do plan (de qualquer tipo)
all_resources = tfplan.find_resources("*")

# Regra: todos os recursos devem ter as tags obrigatórias
resource_has_required_tags = rule {
    all all_resources as _, resource_changes {           # Para cada recurso no plan
        all required_tags as tag {                       # Para cada tag obrigatória
            resource_changes.change.after.tags[tag] is defined  # A tag deve existir após o apply
        }
    }
}

# Política principal
main = rule {
    resource_has_required_tags                           # Todos os recursos devem ter as tags
}
```

---

## 4. Cinco Políticas Rego com Explicação Detalhada

### Política 1: Bloquear Security Group com Porta 22 para 0.0.0.0/0

**Contexto de segurança:** Porta 22 (SSH) exposta para 0.0.0.0/0 significa que qualquer endereço IP na internet pode tentar autenticar no servidor. É o vetor mais comum de brute force e de exploração de vulnerabilidades de servidores. O Banco Meridian exige que acesso SSH seja feito via AWS SSM Session Manager (sem porta 22 necessária) ou via Bastion Host em subnet restrita.

**O que cada bloco desta política faz:**

```rego
# policy/aws/security_group_ssh.rego
#
# POLÍTICA: Bloquear Security Groups que permitem SSH (porta 22)
# de qualquer origem (0.0.0.0/0 ou ::/0)
#
# Contexto BACEN 4.893: Art. 5 — testes e avaliação de controles de acesso
# CIS AWS Benchmark: CKV_AWS_24 — control-plane check equivalente

package terraform.aws.security_group
# O package organiza esta política no namespace específico de security groups AWS

import future.keywords.in
# Importa a keyword 'in' para usar em expressões mais legíveis

violations[msg] {
    # violations é um SET — cada elemento é uma string de violação
    # Conftest exibe cada elemento como uma falha separada

    resource := input.resource_changes[_]
    # input.resource_changes: array de todos os recursos que serão criados/modificados
    # [_]: iterador anônimo — itera por todos os elementos sem nomear o índice

    resource.type == "aws_security_group_rule"
    # Filtra apenas recursos do tipo aws_security_group_rule
    # Nota: aws_security_group com regras inline é coberto pelo bloco abaixo

    resource.change.after.type == "ingress"
    # Só nos importamos com regras de entrada (ingress)
    # Regras egress (saída) têm tratamento diferente

    resource.change.after.from_port <= 22
    # A porta 22 está dentro do range?
    resource.change.after.to_port >= 22
    # from_port <= 22 AND to_port >= 22 = porta 22 está coberta pelo range

    cidr := resource.change.after.cidr_blocks[_]
    # Itera por todos os CIDRs da regra
    cidr == "0.0.0.0/0"
    # O CIDR específico é 0.0.0.0/0 (qualquer IPv4)?

    msg := sprintf(
        "Security Group Rule '%v' permite SSH (porta 22) de 0.0.0.0/0. Use SSM Session Manager (corporativa) ou Bastion Host.",
        [resource.address]
        # resource.address é o endereço Terraform: "aws_security_group_rule.ssh_rule"
    )
}

# Bloco separado para aws_security_group com regras inline (ingress {} block)
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    # aws_security_group pode ter blocos ingress {} inline ao invés de resources separados

    ingress := resource.change.after.ingress[_]
    # Itera por cada bloco ingress dentro do security group
    ingress.from_port <= 22
    ingress.to_port >= 22
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := sprintf(
        "Security Group '%v' permite SSH (porta 22) de 0.0.0.0/0 — use SSM Session Manager ou Bastion Host ao invés de SSH direto.",
        [resource.address]
    )
}

# deny é o ponto de entrada padrão para Conftest
# Cada msg em violations se torna um deny
deny[msg] {
    msg := violations[_]
}
```

---

### Política 2: Exigir Tags de Owner, Environment e CostCenter

**Contexto de segurança:** Tags não são apenas governança de custo. Para o Banco Meridian, tags são o mecanismo central de: (1) atribuição de responsabilidade — quem é o Owner do recurso e deve ser notificado quando há um finding CRITICAL; (2) controle de acesso por contexto — SCPs da AWS podem restringir ações baseadas em tags; (3) auditoria BACEN — rastrear qual sistema processou quais dados.

**O que cada bloco faz:**

```rego
# policy/aws/tags.rego
# POLÍTICA: Recursos AWS devem ter tags obrigatórias de governança
# Referência: Política de Governança Cloud BM-CLOUD-GOV-003

package terraform.aws.tags

import future.keywords.in

# Conjunto de tags obrigatórias para todos os recursos "taggeáveis"
required_tags := {"Owner", "Environment", "CostCenter"}
# Usamos SET (chaves {}) em vez de array [] para O(1) lookup

# Lista de tipos de recursos que suportam tags na AWS
# Não incluímos resources que não têm atributo tags (ex: aws_subnet_association)
taggable_resources := {
    "aws_s3_bucket",
    "aws_instance",
    "aws_db_instance",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_eks_cluster",
    "aws_rds_cluster",
    "aws_elasticache_cluster",
}

# Valores válidos para a tag Environment — impede erros de digitação como "prod" ou "Prod"
valid_environments := {"production", "staging", "development", "sandbox"}

# VIOLAÇÃO 1: Tag obrigatória ausente
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in taggable_resources
    # in: verifica se resource.type está no set taggable_resources

    tag := required_tags[_]
    # Itera por cada tag obrigatória

    not resource.change.after.tags[tag]
    # not: verdadeiro quando a expressão é falsa (tag não existe ou é null)

    msg := sprintf(
        "Recurso '%v' (tipo: %v) está faltando a tag obrigatória '%v'. Tags necessárias: %v",
        [resource.address, resource.type, tag, required_tags]
    )
}

# VIOLAÇÃO 2: Tag Environment com valor inválido
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in taggable_resources

    # A tag Environment existe mas tem valor inválido
    env := resource.change.after.tags.Environment
    # Atribuição direta: env recebe o valor da tag Environment

    not env in valid_environments
    # not in: verdadeiro quando env NÃO está em valid_environments

    msg := sprintf(
        "Recurso '%v' tem tag Environment='%v' inválida. Valores válidos: %v",
        [resource.address, env, valid_environments]
    )
}

deny[msg] {
    msg := violations[_]
}
```

---

### Política 3: Bloquear Bucket S3 Sem Logging

**Contexto de segurança:** O Access Logging do S3 registra cada requisição (GetObject, PutObject, DeleteObject) com o IP do requisitante, o usuário autenticado e o timestamp. Para o Banco Meridian, isso é requerido pelo Art. 37 da LGPD (registro de operações sobre dados pessoais) e é evidência crítica em investigações de vazamento de dados.

```rego
# policy/aws/s3_logging.rego
# POLÍTICA: Todos os buckets S3 devem ter access logging habilitado
# Referência: LGPD Art. 37 — registro de operações sobre dados pessoais

package terraform.aws.s3

import future.keywords.in

# Módulo de referência: coletamos buckets e suas configurações de logging
# Rego avalia a relação ENTRE recursos — não apenas cada recurso isoladamente

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    # Identifica cada bucket S3 no plan

    bucket_name := resource.change.after.bucket
    # Extrai o nome do bucket para usar na mensagem de erro e na verificação

    # Verifica se existe um aws_s3_bucket_logging para este bucket
    # Rego avalia toda a coleção de recursos — encontra o recurso correspondente
    not has_logging_resource(bucket_name, input.resource_changes)
    # not: verdadeiro quando o bucket NÃO tem um recurso de logging correspondente

    msg := sprintf(
        "S3 Bucket '%v' não tem access logging configurado. Requerido pela LGPD Art. 37 e BACEN Art. 6 (rastreabilidade de acessos). Adicionar recurso aws_s3_bucket_logging.",
        [bucket_name]
    )
}

# Helper function: verifica se existe aws_s3_bucket_logging referenciando este bucket
has_logging_resource(bucket_name, resources) {
    resource := resources[_]
    resource.type == "aws_s3_bucket_logging"
    # O campo 'bucket' do aws_s3_bucket_logging deve referenciar o bucket
    resource.change.after.bucket == bucket_name
    # Quando esta condição é verdadeira, has_logging_resource retorna true
}

deny[msg] {
    msg := violations[_]
}
```

---

### Política 4: Exigir Criptografia em Volumes EBS

**Contexto de segurança:** Volumes EBS sem criptografia armazenam dados em texto claro nos discos físicos da AWS. Se um snapshot for criado (acidentalmente público ou compartilhado com outra conta), os dados ficam expostos sem nenhuma proteção. Para o Banco Meridian, isso viola o Art. 5 da BACEN 4.893 e o Art. 46 da LGPD para dados de clientes.

```rego
# policy/aws/ebs_encryption.rego
# POLÍTICA: Todos os volumes EBS devem ter criptografia habilitada
# Referência: BACEN 4.893 Art. 5 + LGPD Art. 46 (proteção de dados em repouso)
# Equivalente ao check: CKV_AWS_8

package terraform.aws.ebs

import future.keywords.in

# Tipos de recursos que criam ou configuram volumes EBS
ebs_resource_types := {
    "aws_ebs_volume",           # Volume EBS standalone
    "aws_instance",             # EC2 com root_block_device e ebs_block_device
    "aws_launch_template",      # Template usado por Auto Scaling Groups
    "aws_launch_configuration", # Configuração legada de Auto Scaling
}

# VIOLAÇÃO 1: aws_ebs_volume sem encrypted = true
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"

    not resource.change.after.encrypted == true
    # not x == true: verdadeiro quando encrypted é false, null, ou não existe
    # Diferente de not x: não existe

    msg := sprintf(
        "Volume EBS '%v' não tem criptografia habilitada. Dados em repouso desprotegidos. (BACEN Art. 5, LGPD Art. 46)",
        [resource.address]
    )
}

# VIOLAÇÃO 2: aws_instance sem root_block_device encrypted
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"

    root_block := resource.change.after.root_block_device[_]
    # Itera por cada root_block_device (normalmente apenas 1)

    not root_block.encrypted == true
    # O volume root do EC2 não está criptografado

    msg := sprintf(
        "EC2 Instance '%v' tem root_block_device sem criptografia. (BACEN Art. 5)",
        [resource.address]
    )
}

deny[msg] {
    msg := violations[_]
}
```

---

### Política 5: Bloquear IAM Policies com Wildcard Action "*"

**Contexto de segurança:** Uma IAM policy com `Action: "*"` concede acesso a TODOS os serviços AWS — equivalente a superusuário em Linux. Mesmo que o `Resource` seja restrito, um atacante pode usar o acesso `*` para comprometer toda a conta. Para o Banco Meridian, isso viola diretamente o BACEN 4.893 Art. 8 (menor privilégio em acessos) e o conceito de shadow admin.

**O que cada função auxiliar desta política faz:**

```rego
# policy/aws/iam_no_wildcard.rego
# POLÍTICA: Bloquear IAM policies com Action="*" ou wildcards de alto risco
# Referência: BACEN 4.893 Art. 8 — gestão de acessos com menor privilégio
# Mapeamento MITRE: T1098 — Account Manipulation

package terraform.aws.iam

import future.keywords.in

# Alto risco: serviços que, com wildcard, permitem comprometimento total da conta
high_risk_services := {"iam", "sts", "organizations", "cloudtrail", "kms"}
# iam:* → criar usuários, roles, policies — shadow admin
# sts:* → assumir qualquer role, criar tokens de sessão
# organizations:* → administrar a organização AWS inteira
# cloudtrail:* → desabilitar auditoria, apagar logs
# kms:* → criar/deletar chaves, descriptografar qualquer dado

# Verifica se um statement tem Action: "*" (literal)
has_wildcard_action(statement) {
    statement.Effect == "Allow"            # Apenas statements de Allow importam
    statement.Action == "*"                # Action é a string literal "*"
}

# Verifica quando Action é um ARRAY e contém "*"
has_wildcard_action(statement) {
    statement.Effect == "Allow"
    action := statement.Action[_]          # Itera por cada ação no array
    action == "*"                          # Uma delas é "*"
}

# Verifica wildcards de serviço de alto risco (ex: "s3:*" não é bloqueado, mas "iam:*" sim)
has_service_wildcard(statement) {
    statement.Effect == "Allow"
    action := statement.Action[_]
    endswith(action, ":*")                 # A ação termina com ":*"
    parts := split(action, ":")            # Divide "iam:*" em ["iam", "*"]
    parts[0] in high_risk_services         # O serviço está na lista de alto risco
}

# VIOLAÇÃO 1: Action = "*" literal (pior caso)
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

    doc := json.unmarshal(resource.change.after.policy)
    # json.unmarshal converte a string JSON da policy em objeto Rego navegável
    # Necessário porque o campo 'policy' é uma string JSON, não um objeto

    statement := doc.Statement[_]
    # Itera por cada statement na policy

    has_wildcard_action(statement)
    # Chama o helper definido acima

    msg := sprintf(
        "IAM Policy '%v' contém Action='*' em um statement Allow. Isso concede acesso a TODOS os serviços AWS. (BACEN Art. 8)",
        [resource.address]
    )
}

# VIOLAÇÃO 2: Wildcard em serviços de alto risco (iam:*, sts:*, cloudtrail:*)
violations[msg] {
    resource := input.resource_changes[_]
    resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

    doc := json.unmarshal(resource.change.after.policy)
    statement := doc.Statement[_]
    has_service_wildcard(statement)

    parts := split(statement.Action[_], ":")
    service := parts[0]

    msg := sprintf(
        "IAM Policy '%v' contém '%v:*' — wildcard em serviço de alto risco. Use ações específicas (ex: 'iam:GetUser' em vez de 'iam:*'). (BACEN Art. 8)",
        [resource.address, service]
    )
}

deny[msg] {
    msg := violations[_]
}
```

---

## 5. Pipeline CI/CD — GitHub Actions Completo com Comentários

### 5.1 Workflow GitHub Actions — IaC Security Pipeline

**O que este pipeline faz, passo a passo:**

Este pipeline é acionado em todo Pull Request que modifica arquivos Terraform ou de infraestrutura. Ele tem 4 jobs paralelos: Checkov (cobertura ampla), tfsec (velocidade e VS Code integration), Trivy IaC (scan unificado) e Conftest OPA (políticas customizadas do Banco Meridian). Um 5º job — security-gate — agrega os resultados e bloqueia o merge se qualquer finding CRITICAL ou HIGH for encontrado.

```yaml
# .github/workflows/iac-security.yml
# Pipeline de segurança de IaC — Banco Meridian
# Propósito: bloquear merges de PR que introduzam misconfigurations em Terraform/K8s/Dockerfile
# Acionado em: qualquer PR que modifica terraform/, cloudformation/, k8s-manifests/ ou Dockerfiles

name: IaC Security Scan — Banco Meridian

on:
  pull_request:
    # Apenas quando arquivos de infraestrutura são modificados
    # Evita executar o scan em PRs que só modificam documentação
    paths:
      - 'terraform/**'
      - 'cloudformation/**'
      - 'k8s-manifests/**'
      - 'helm/**'
      - '**/Dockerfile'
      - '**/docker-compose.yml'

permissions:
  contents: read          # Leitura do código — necessário para checkout
  security-events: write  # Escrita em GitHub Security (SARIF upload)
  pull-requests: write    # Comentários no PR com resumo dos findings

jobs:
  # ===========================================================================
  # JOB 1: CHECKOV — Scanner com maior cobertura de checks
  # Responsabilidade: CSPM checks (AWS/Azure/GCP), IaC, K8s, Dockerfile
  # Por que Checkov aqui: 1.000+ checks, integração SARIF, suporte a custom policies
  # ===========================================================================
  checkov:
    name: Checkov IaC Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4
        # Faz checkout do branch do PR — não do main
        # Necessário para que os scanners vejam as mudanças propostas

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          # Python 3.11 tem melhor performance que 3.10 para este caso de uso

      - name: Instalar Checkov
        run: pip install checkov
        # Instala a versão mais recente do Checkov
        # Para versão fixada (recomendado em produção): pip install checkov==3.2.x

      # Este step falha o pipeline (exit code 1) se encontrar CRITICAL ou HIGH
      # MEDIUM e LOW são reportados mas não bloqueiam (--soft-fail-on MEDIUM LOW)
      - name: Executar Checkov — Terraform
        id: checkov-terraform
        run: |
          checkov \
            -d ./terraform/ \
            --framework terraform \
            --output sarif \
            --output-file-path ./checkov-terraform.sarif \
            --soft-fail-on MEDIUM LOW \
            --skip-check CKV_AWS_144  # S3 cross-region replication — não requerido no sandbox
        continue-on-error: false
        # continue-on-error: false significa que uma falha neste step para o job inteiro
        # O pipeline marcará o check do PR como falha, impedindo o merge

      # Scan de Kubernetes YAML separado — usa framework diferente
      - name: Executar Checkov — Kubernetes YAML
        id: checkov-k8s
        if: always()
        # always(): executa mesmo se o step anterior falhou
        # Queremos ver os findings de K8s mesmo quando Terraform já falhou
        run: |
          checkov \
            -d ./k8s-manifests/ \
            --framework kubernetes \
            --output sarif \
            --output-file-path ./checkov-k8s.sarif \
            --soft-fail-on MEDIUM LOW

      # Upload SARIF para GitHub Security
      # Os findings aparecem na aba Security > Code Scanning do repositório
      # e também inline nos arquivos modificados no PR
      - name: Upload SARIF Checkov (Terraform)
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        # always(): garante que o SARIF é upado mesmo quando o scan encontrou falhas
        with:
          sarif_file: ./checkov-terraform.sarif
          category: checkov-terraform
          # category: identifica a fonte do SARIF no GitHub Security (evita conflitos)

  # ===========================================================================
  # JOB 2: TFSEC — Scanner especializado em Terraform com alta velocidade
  # Responsabilidade: Terraform-specific checks, custom rules, VS Code inline
  # Por que tfsec aqui: complementa o Checkov com checks diferentes e é mais rápido
  # ===========================================================================
  tfsec:
    name: tfsec Terraform Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      # Usa a action oficial do tfsec — sem necessidade de instalação manual
      - name: Executar tfsec
        uses: aquasecurity/tfsec-action@master
        with:
          # sarif_file: onde salvar o relatório SARIF
          sarif_file: tfsec.sarif
          # format: sarif para upload ao GitHub Code Scanning
          format: sarif
          # additional_args: argumentos adicionais passados ao tfsec
          # --config-file tfsec.yaml: usa o arquivo de configuração do projeto
          # que inclui as exclusões aprovadas com tickets SEC-XXXX
          additional_args: --config-file tfsec.yaml

      - name: Upload tfsec SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfsec.sarif
          category: tfsec

  # ===========================================================================
  # JOB 3: TRIVY IAC — Scanner unificado (IaC + configurações)
  # Responsabilidade: IaC scan com política de exit code baseada em severity
  # Por que Trivy aqui: usa o mesmo binário do scan de containers (módulo 04)
  #                     facilitando manutenção e conhecimento unificado
  # ===========================================================================
  trivy-iac:
    name: Trivy IaC Config Scanner
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      # Usa a action oficial do Trivy
      - name: Executar Trivy em modo config
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'           # Modo de scan de configurações (IaC)
          scan-ref: './terraform'       # Diretório a escanear
          format: 'sarif'               # Formato de saída
          output: 'trivy-iac.sarif'     # Arquivo de saída
          severity: 'CRITICAL,HIGH'     # Apenas estas severidades
          exit-code: '1'               # Retorna exit code 1 se encontrar CRITICAL/HIGH
          # exit-code: '1' é essencial — sem ele, Trivy sempre retorna 0 (sucesso)
          # e o pipeline nunca falha, tornando o scan inútil como gate

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-iac.sarif
          category: trivy-iac

  # ===========================================================================
  # JOB 4: CONFTEST OPA — Políticas customizadas do Banco Meridian
  # Responsabilidade: políticas de segurança específicas não cobertas por checks built-in
  #   - Tags obrigatórias (Owner, Environment, CostCenter)
  #   - Restrições de região AWS
  #   - Políticas de nomenclatura de recursos
  # Por que Conftest: OPA/Rego permite políticas 100% customizadas em código versionado
  # ===========================================================================
  conftest-opa:
    name: Conftest OPA Policy Check
    runs-on: ubuntu-latest

    steps:
      - name: Checkout código
        uses: actions/checkout@v4

      # Instalar Conftest (binário Go, sem dependências de runtime)
      - name: Instalar Conftest
        run: |
          wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
          tar -xzf conftest_0.48.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/
          conftest --version

      # Instalar Terraform para gerar o plan em JSON
      - name: Instalar Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '1.7.0'

      # Gerar terraform plan e converter para JSON
      # O Conftest avalia o PLAN (o que vai acontecer), não apenas o código Terraform
      # Isso é mais preciso — inclui valores calculados que não aparecem no .tf
      - name: Gerar Terraform Plan JSON
        env:
          # Credenciais AWS mock para o init (sem backend real no CI)
          AWS_ACCESS_KEY_ID: mock_key
          AWS_SECRET_ACCESS_KEY: mock_secret
          AWS_DEFAULT_REGION: us-east-1
        run: |
          cd terraform/
          terraform init -backend=false
          # -backend=false: inicializa sem conectar ao backend real (S3 state)
          terraform plan -out=tfplan.binary
          # -out: salva o plan em formato binário
          terraform show -json tfplan.binary > ../tfplan.json
          # show -json converte o plan binário para JSON legível pelo Conftest

      # Executar políticas Rego customizadas do Banco Meridian
      - name: Executar Conftest com políticas BM
        run: |
          conftest test \
            tfplan.json \
            -p ./policy/ \
            --output table
          # --output table: saída tabular mais legível no log do GitHub Actions

  # ===========================================================================
  # JOB 5: SECURITY GATE — Agregação de resultados e decisão final
  # Responsabilidade: ler os outputs dos jobs anteriores e bloquear o PR
  #                   se qualquer finding CRITICAL/HIGH foi encontrado
  # Por que um job separado: centraliza a lógica de decisão e fornece uma
  #                           mensagem de erro clara para o desenvolvedor
  # ===========================================================================
  security-gate:
    name: Security Gate — Decisão Final
    runs-on: ubuntu-latest
    needs: [checkov, tfsec, trivy-iac, conftest-opa]
    # needs: este job só executa APÓS todos os outros terminarem (com sucesso ou falha)
    if: always()
    # if: always(): executa mesmo se algum job anterior falhou — queremos verificar o resultado

    steps:
      - name: Verificar resultado dos scans
        # Este step verifica se algum dos jobs de scan falhou
        # Se sim: exibe mensagem de erro clara e falha o pipeline
        run: |
          echo "=== SECURITY GATE — BANCO MERIDIAN ==="
          echo "Verificando resultados dos scanners de IaC..."
          echo ""

          # Verificar resultado de cada job
          # needs.<job>.result pode ser: success, failure, cancelled, skipped
          CHECKOV="${{ needs.checkov.result }}"
          TFSEC="${{ needs.tfsec.result }}"
          TRIVY="${{ needs.trivy-iac.result }}"
          CONFTEST="${{ needs.conftest-opa.result }}"

          echo "Checkov:  $CHECKOV"
          echo "tfsec:    $TFSEC"
          echo "Trivy:    $TRIVY"
          echo "Conftest: $CONFTEST"
          echo ""

          # Se qualquer scanner encontrou findings CRITICAL/HIGH → bloquear merge
          if [[ "$CHECKOV" == "failure" || "$TFSEC" == "failure" || \
                "$TRIVY" == "failure" || "$CONFTEST" == "failure" ]]; then
            echo "❌ SECURITY GATE: FALHOU"
            echo ""
            echo "Um ou mais scanners de IaC encontraram findings CRITICAL ou HIGH."
            echo "O merge desta PR está bloqueado até a resolução."
            echo ""
            echo "Para corrigir:"
            echo "  1. Verifique os findings na aba 'Security > Code Scanning' do repositório"
            echo "  2. Corrija as misconfigurations no código Terraform"
            echo "  3. Se o finding é um falso positivo, documente e use #checkov:skip= com ticket"
            echo "  4. Faça push das correções — o pipeline será re-executado automaticamente"
            echo ""
            echo "Para dúvidas: #security-alerts no Slack ou security@bancomeridian.com.br"
            exit 1
            # exit 1 falha este step → falha o job security-gate → PR não pode ser mergeado
          fi

          echo "✅ SECURITY GATE: PASSOU"
          echo "Todos os scanners concluíram sem findings CRITICAL ou HIGH."
          echo "O PR pode ser mergeado após aprovação dos revisores de código."
```

---

### 5.2 GitLab CI Pipeline Equivalente

```yaml
# .gitlab-ci.yml — Equivalente ao GitHub Actions para GitLab CI
# Estrutura de stages com relatórios de teste integrados

stages:
  - iac-security  # Stage de segurança de IaC (antes do deploy)
  - security-gate # Stage de gate final

variables:
  TF_DIR: ./terraform
  # Define o diretório Terraform como variável para reutilização

checkov-scan:
  stage: iac-security
  image: bridgecrew/checkov:latest
  # Usa a imagem Docker oficial do Checkov (sem necessidade de instalação)
  script:
    # -d: diretório a escanear
    # --severity CRITICAL HIGH: apenas estas severidades causam exit code 1
    # --output junitxml: formato suportado pelo GitLab para relatórios de teste
    # --output-file-path: onde salvar (deve ser junit-reports/ para o artifact abaixo)
    - checkov -d $TF_DIR --framework terraform --severity CRITICAL HIGH --output junitxml --output-file-path junit-reports/
  artifacts:
    reports:
      junit: junit-reports/results_junitxml.xml
      # GitLab exibe os resultados JUnit diretamente na interface do Merge Request
    when: always
    # when: always garante que os relatórios são salvos mesmo quando o scan falha
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    # Apenas em Merge Requests — equivalente ao paths: trigger do GitHub Actions

tfsec-scan:
  stage: iac-security
  image: aquasec/tfsec:latest
  script:
    # --minimum-severity MEDIUM: reporta MEDIUM+ mas não bloqueia (allow_failure abaixo)
    # --format json: salva em JSON para análise posterior
    - tfsec $TF_DIR --minimum-severity MEDIUM --format json --out tfsec-report.json
  artifacts:
    paths:
      - tfsec-report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: true
  # allow_failure: true — tfsec apenas avisa (warn), não bloqueia o pipeline
  # O Checkov acima é o gate definitivo

conftest-policies:
  stage: iac-security
  image: openpolicyagent/conftest:latest
  script:
    - terraform -chdir=$TF_DIR init -backend=false
    - terraform -chdir=$TF_DIR plan -out=tfplan.binary
    - terraform -chdir=$TF_DIR show -json tfplan.binary > tfplan.json
    - conftest test tfplan.json -p ./policy/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

### 5.3 Jenkins Pipeline (Declarativo)

```groovy
// Jenkinsfile — Pipeline declarativo para IaC Security no Jenkins
// Usado em ambientes corporativos com Jenkins já estabelecido

pipeline {
    agent { label 'linux-agent' }  // Executa em agentes Linux

    triggers {
        // Acionar em todo Pull Request via webhook do GitHub/GitLab
        githubPullRequests()
    }

    environment {
        TF_DIR = './terraform'
        // Credenciais armazenadas no Jenkins Credentials Store (não hardcoded)
        AWS_CREDS = credentials('bancomeridian-aws-audit-role')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm  // Checkout do branch do PR
            }
        }

        stage('IaC Security — Checkov') {
            steps {
                sh '''
                    # Instalar e executar Checkov
                    pip install checkov
                    checkov \
                        -d ./terraform/ \
                        --framework terraform \
                        --output junitxml \
                        --output-file-path junit-reports/ \
                        --soft-fail-on MEDIUM LOW
                '''
            }
            post {
                always {
                    // Publicar resultados JUnit na interface do Jenkins
                    junit 'junit-reports/*.xml'
                }
            }
        }

        stage('IaC Security — Trivy') {
            steps {
                sh '''
                    # trivy config = modo de scan de configurações IaC
                    # --severity HIGH,CRITICAL: apenas estas severidades
                    # --exit-code 1: retorna falha se encontrar findings
                    # --format json: salva resultado estruturado
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
                sh '''
                    # Gerar plan JSON para o Conftest avaliar
                    terraform init -chdir=${TF_DIR} -backend=false
                    terraform plan -chdir=${TF_DIR} -out=tfplan.binary
                    terraform show -chdir=${TF_DIR} -json tfplan.binary > tfplan.json

                    # Executar políticas Rego customizadas
                    conftest test tfplan.json -p ./policy/
                '''
            }
        }
    }

    post {
        failure {
            // Notificar o time de segurança por e-mail quando o pipeline falha
            mail to: 'security@bancomeridian.com.br',
                 subject: "FALHA: IaC Security Scan — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                 body: "O scan de segurança IaC detectou findings críticos. Acesse ${env.BUILD_URL} para detalhes."
        }
    }
}
```

---

### 5.4 Azure DevOps — Pipeline YAML

```yaml
# azure-pipelines.yml — Pipeline para Azure DevOps
trigger:
  branches:
    include:
      - main
      - 'feature/*'
  paths:
    include:
      - terraform/**

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
    displayName: Configurar Python 3.11

  - script: pip install checkov
    displayName: Instalar Checkov

  - script: |
      checkov -d ./terraform/ \
        --framework terraform \
        --severity CRITICAL HIGH \
        --output junitxml \
        --output-file-path $(Build.ArtifactStagingDirectory)/
    displayName: Executar Checkov
    # $(Build.ArtifactStagingDirectory): variável do Azure DevOps com o dir de artefatos

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '$(Build.ArtifactStagingDirectory)/*.xml'
    displayName: Publicar Resultados de Segurança
    condition: always()
```

---

## 6. Configuração de Severity Thresholds por Ambiente

### 6.1 Por Que Severity Thresholds Diferentes por Ambiente

No Banco Meridian, um finding CRITICAL em produção tem impacto financeiro real. O mesmo finding em ambiente de desenvolvimento pode ser tolerado por alguns dias enquanto o desenvolvedor corrige. A política diferenciada de thresholds permite velocidade de desenvolvimento sem comprometer a segurança em produção.

```
POLÍTICA DE SEVERITY THRESHOLDS — BANCO MERIDIAN

CRITICAL → BLOQUEIO IMEDIATO em todos os ambientes
  Exemplos: EBS sem criptografia, RDS sem backup
  → Em QUALQUER ambiente: falha o pipeline imediatamente
  → Deve ser corrigido antes de qualquer merge
  → Prazo de remediação: 0 dias (bloqueante)

HIGH → BLOQUEIO em produção, WARN em dev/staging
  Exemplos: Security Group com porta SSH aberta para 0.0.0.0/0
  → Em produção: bloqueia o deploy
  → Em desenvolvimento: cria comentário no PR mas não bloqueia
  → Prazo de remediação: 7 dias

MEDIUM → WARN em todos os ambientes (comentário no PR, não bloqueia)
  Exemplos: falta de versioning em S3, IMDSv1 habilitado
  → Não bloqueia merge em nenhum ambiente
  → Rastreado em backlog de segurança do time
  → Prazo de remediação: 30 dias

LOW → LOG apenas (não aparece no PR, apenas em relatório)
  → Revisado mensalmente pela equipe de segurança
  → Suprimível sem aprovação formal (apenas com ticket de backlog)
```

### 6.2 Implementação no Checkov por Ambiente

```yaml
# .checkov.yaml — Configuração central do Checkov para o repositório Banco Meridian
# Este arquivo é lido automaticamente pelo Checkov quando presente no diretório

# Frameworks a escanear — todos os tipos de IaC suportados
framework:
  - terraform
  - cloudformation
  - kubernetes
  - dockerfile
  - helm

# Findings que FALHAM o pipeline (exit code 1)
# Qualquer check com severidade CRITICAL ou HIGH bloqueia o merge
hard-fail-on:
  - CRITICAL
  - HIGH

# Findings que são REPORTADOS mas não falham o pipeline
soft-fail-on:
  - MEDIUM
  - LOW

# Exclusões aprovadas com tickets de rastreabilidade
# FORMATO OBRIGATÓRIO: ID do check + comentário com ticket SEC-XXXX
skip-check:
  - CKV_AWS_144  # S3 cross-region replication — não requerido no sandbox, ticket SEC-0145
  - CKV_AWS_18   # S3 access logging — bucket de logs não precisa de auto-logging, ticket SEC-0146

# Políticas customizadas do Banco Meridian (Rego ou Python)
external-checks-dir:
  - ./custom-policies/
```

---

## 7. Atividades de Fixação

### Questão 1

Um desenvolvedor do Banco Meridian cria um recurso `aws_s3_bucket` com apenas o nome definido (sem bloco de criptografia, logging ou versioning). Qual check do Checkov é o PRIMEIRO a falhar (mais crítico)?

**a)** CKV_AWS_19 — Block public access não habilitado
**b)** CKV_AWS_18 — Access logging não habilitado
**c)** CKV_AWS_145 — Criptografia SSE-KMS não habilitada
**d)** CKV_AWS_21 — Versionamento não habilitado

**Gabarito: a)**
Justificativa: Um `aws_s3_bucket` com apenas o nome definido falha em todos os checks de segurança básicos. O CKV_AWS_19 (Block Public Access) é geralmente classificado como CRITICAL porque um bucket público pode expor dados de clientes na internet imediatamente. CKV_AWS_145 (criptografia) é HIGH, CKV_AWS_18 (logging) é MEDIUM, e CKV_AWS_21 (versioning) é MEDIUM. A severidade do CKV_AWS_19 o torna o primeiro a bloquear o pipeline.

---

### Questão 2

Qual é o comportamento do pipeline quando se usa `--severity CRITICAL HIGH` e `--soft-fail-on MEDIUM LOW` no Checkov?

**a)** O pipeline falha para MEDIUM e LOW e ignora CRITICAL e HIGH
**b)** `--severity CRITICAL HIGH` e `--soft-fail-on MEDIUM LOW` têm comportamentos conflitantes e causam erro
**c)** Findings CRITICAL e HIGH causam exit code 1 (falha do pipeline); MEDIUM e LOW são reportados no output mas o exit code é 0 (sucesso)
**d)** Todos os findings são reportados mas nenhum causa falha de pipeline

**Gabarito: c)**
Justificativa: `--soft-fail-on MEDIUM LOW` instrui o Checkov: "para essas severidades, reporte no output mas não falhe (exit code 0)". CRITICAL e HIGH não estão no soft-fail-on, então eles causam exit code 1. No GitHub Actions, exit code 1 marca o step como falha, o que impede o merge via branch protection rules.

---

### Questão 3

Um desenvolvedor quer suprimir um check do Checkov para um recurso específico no código Terraform. Qual é a forma CORRETA e rastreável de fazer isso?

**a)** Usar `--skip-check CKV_AWS_19` na linha de comando do pipeline
**b)** Adicionar `#checkov:skip=CKV_AWS_19:justificativa com ticket SEC-XXXX` como comentário na linha do recurso no arquivo .tf
**c)** Remover o check da lista de checks habilitados no .checkov.yaml
**d)** Criar um arquivo .checkovignore com o ID do check

**Gabarito: b)**
Justificativa: O inline skip com `#checkov:skip=CKV_AWS_19:justificativa` é a forma mais rastreável porque: (1) está no git history junto com o código que suprime; (2) o motivo é documentado no próprio arquivo; (3) a revisão de code fica ciente da supressão; (4) ferramentas de auditoria como o `git log` mostram quem suprimiu e quando. Skip via command line (`--skip-check`) não é rastreável por recurso — suprime globalmente para todos os recursos.

---

### Questão 4

Um engenheiro quer configurar o workflow GitHub Actions para que:
- Findings CRITICAL/HIGH bloqueiem o merge da PR
- Findings MEDIUM apenas adicionem um comentário de aviso na PR
- A PR ainda possa ser mergeada com findings MEDIUM pendentes

**a)** Um único job com `checkov --severity CRITICAL HIGH --soft-fail-on MEDIUM LOW`
**b)** Dois jobs separados: job-1 com `--severity CRITICAL HIGH` (exit-on-error: true) e job-2 com `--severity MEDIUM` (continue-on-error: true) + GitHub branch protection rules exigindo apenas job-1
**c)** Um único job com `checkov --severity MEDIUM LOW CRITICAL HIGH`
**d)** `--severity CRITICAL HIGH --soft-fail-on MEDIUM LOW` executa (exit code 1) apenas para CRITICAL/HIGH, com exit 0 para MEDIUM/LOW output

**Gabarito: b) e d) ambas corretas, mas d) é a implementação mais simples.**
Justificativa: A opção d) descreve o comportamento correto com um único job: `--soft-fail-on MEDIUM LOW` faz o Checkov reportar MEDIUM/LOW mas retornar exit code 0 — o GitHub Actions vê o step como "passed". Apenas CRITICAL/HIGH retornam exit code 1 e bloqueiam. Para adicionar um comentário de PR sobre os MEDIUM, pode-se usar um segundo job que executa Checkov com `--severity MEDIUM` e posta o output como comentário no PR.

---

### Questão 5

No workflow GitHub Actions do Banco Meridian, o job `security-gate` usa `needs: [checkov, tfsec, trivy-iac, conftest-opa]` e `if: always()`. Por que esse job é necessário?

**a)** Para executar qualquer ação que não possa ser executada nos outros jobs
**b)** Para centralizar a lógica de decisão final em um único ponto, garantindo que o merge seja bloqueado se QUALQUER um dos scanners falhar, e fornecendo uma mensagem de erro unificada e clara para o desenvolvedor
**c)** Para enviar os relatórios de segurança por e-mail automaticamente
**d)** Para executar os scanners de forma sequencial em vez de paralela

**Gabarito: b)**
Justificativa: Sem o security-gate, cada scanner falha o seu próprio job, mas o PR pode ser confuso para o desenvolvedor — ele vê 4 jobs vermelhos sem uma mensagem centralizada. O security-gate agrega, fornece uma mensagem de erro clara com instruções de correção, e é o único job que o branch protection rule precisa exigir (em vez de exigir os 4 jobs de scanner individualmente).

---

### Questão 6

O HashiCorp Sentinel se diferencia do OPA/Conftest para uso no Banco Meridian em qual aspecto principal?

**a)** Sentinel suporta mais linguagens de IaC do que OPA/Conftest
**b)** Sentinel é integrado nativamente ao Terraform Cloud e Enterprise, aplicando políticas antes de cada `terraform apply` sem necessidade de pipeline CI/CD adicional — mas é limitado ao ecossistema HashiCorp; OPA/Conftest é agnóstico de plataforma e se integra a qualquer CI/CD
**c)** Sentinel é gratuito e OPA tem licença paga
**d)** Sentinel tem melhor suporte a AWS; OPA tem melhor suporte a Azure e GCP

**Gabarito: b)**
Justificativa: Sentinel é nativo ao Terraform Cloud/Enterprise — políticas são aplicadas por padrão em todos os runs sem configuração adicional de CI/CD. A desvantagem: só funciona com Terraform HashiCorp. OPA/Conftest é agnóstico — funciona com qualquer CI/CD (GitHub Actions, Jenkins, GitLab CI, Azure DevOps) e com qualquer tipo de arquivo de configuração (YAML, JSON, HCL, Dockerfile). Para o Banco Meridian, que tem pipelines em múltiplos sistemas, OPA/Conftest é mais adequado. Se o banco usar Terraform Cloud Enterprise, Sentinel é adicional e complementar.

---

## 8. Gabarito — Questões de Análise Avançada

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O pipeline DevSecOps do Banco Meridian foi configurado, mas o time encontrou os seguintes problemas:
1. O Checkov está falhando em 47 recursos por falta da tag `Owner` — mas os desenvolvedores dizem que essa tag não é responsabilidade deles, é do IaC central
2. Uma política Rego (Conftest) está gerando falso positivo: o bucket do website público `bancomeridian-website` está falhando no check de Block Public Access
3. O pipeline demora 12 minutos para executar, atrasando o feedback para os desenvolvedores
4. Um finding CRITICAL de IAM policy com `iam:*` está bloqueando o deploy de um sistema legado que realmente precisa dessa permissão (aprovado pelo CISO)

**Questão 1 (10 pts):** Como resolver o problema das tags — corrigir o pipeline, a política ou o processo?

**Gabarito Q1:**
A solução correta é separar responsabilidades via tag inheritance no Terraform. Criar um módulo Terraform central `bancomeridian-base-tags` que define as tags obrigatórias e é importado por todos os módulos. O check de tags deve verificar que o módulo central está sendo usado, não que cada desenvolvedor adicionou as tags manualmente. Alternativa: usar Default Tags via `provider "aws" { default_tags { tags = { ... } } }` no bloco de provider, que aplica tags automaticamente a todos os recursos sem que o desenvolvedor precise especificá-las.

**Questão 2 (10 pts):** Como tratar o falso positivo do bucket público?

**Gabarito Q2:**
Correto: adicionar `#checkov:skip=CKV_AWS_19:Website público intencional — aprovado CISO 2025-04-24 ticket SEC-0123` como comentário inline no código Terraform do bucket. Na política Rego (Conftest), adicionar uma exceção baseada no nome do bucket: `not bucket_name in bancomeridian_public_websites` onde `bancomeridian_public_websites := {"bancomeridian-website"}`. A exceção deve ser versionada no código e aprovada via PR review pelo time de segurança.

**Questão 3 (10 pts):** Como reduzir o tempo de 12 minutos para menos de 5 minutos?

**Gabarito Q3:**
Estratégias:
- Paralelização: Checkov, tfsec e Trivy já rodam em paralelo — verificar se há dependências desnecessárias entre jobs
- Cache de dependências: cachear o ambiente Python com `actions/cache` para evitar `pip install checkov` a cada run (salva 1–2 min)
- Filtro por arquivos modificados: usar `actions/changed-files` para executar apenas os scanners relevantes (se apenas Kubernetes YAML mudou, pular o scan Terraform)
- Pre-commit hooks: executar Checkov localmente no pre-commit, antes do push — 80% dos problemas são detectados em segundos no terminal do dev, sem precisar do CI/CD pipeline

**Questão 4 (10 pts):** Como permitir o sistema legado com `iam:*` sem comprometer a política geral?

**Gabarito Q4:**
Correto: criar uma exceção documentada e time-limited. O recurso IAM do sistema legado deve ter:
1. `#checkov:skip=CKV_AWS_111:Sistema legado pré-aprovado — CISO ticket SEC-CISO-0099 — rever até 2025-12-31`
2. Um issue de backlog com prazo de migração para uso de permissões específicas
3. A role deve ter o menor conjunto de permissões HIGH RISK bloqueada mesmo dentro do `iam:*` — usar Permissions Boundary para limitar o escopo real

Errado: adicionar `CKV_AWS_111` ao `skip-check` global do `.checkov.yaml` — isso remove o check para TODOS os recursos, não apenas para o sistema legado.

---

## 9. Roteiros de Gravação

### Aula 3.1: Shift-Left + Checkov + tfsec (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Shift-Left na Prática: Checkov e tfsec para IaC Security |
| **Duração** | 50 minutos |
| **Formato** | Talking head + screen share (terminal + VS Code) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Neste módulo vamos falar sobre uma mudança fundamental de abordagem em segurança: o Shift-Left. A ideia é simples — encontrar problemas de segurança mais cedo no ciclo de desenvolvimento. Mais cedo significa mais barato, mais rápido de corrigir e, no caso de um banco como o Banco Meridian, sem exposição de dados de clientes.

Vamos ver na prática como implementar isso com Checkov e tfsec — duas das melhores ferramentas open-source de IaC security.

---

**[05:00 – 18:00 | CONCEITO SHIFT-LEFT | Slides]**

*[Dica de edição: slide animado mostrando o custo subindo dramaticamente da esquerda para a direita]*

A Regra do 10x é o argumento de negócio mais poderoso para justificar investimento em segurança de IaC. Desenvolvimento: R$ 1. Produção: R$ 1.000. Pós-incidente: R$ 10.000+.

Para o Banco Meridian: um bucket S3 público em produção por 24 horas de exposição, 40 horas de trabalho para corrigir via change management, possível notificação ao BACEN. Com Shift-Left, o pre-commit hook detecta em 3 segundos e o desenvolvedor corrige em 15 minutos no terminal.

*[Mostra o diagrama de fluxo com e sem shift-left]*

---

**[18:00 – 42:00 | CHECKOV E TFSEC NA PRÁTICA | Screen share — terminal + VS Code]**

*[Dica de edição: tela cheia no terminal, fonte maior, zoom nos comandos e outputs]*

Vamos para o terminal. Vou demonstrar o Checkov em um projeto Terraform real.

```bash
# Instalar e verificar
pip install checkov
checkov --version

# Scan de diretório Terraform
checkov -d ./terraform/
```

*[Mostra o output do scan, aponta para os campos: Check ID, FAILED, resource, file:line]*

Veja esse output. O Checkov me diz: "CKV_AWS_19 FAILED — aws_s3_bucket.dados_clientes — linha 3 do s3.tf". Isso é exatamente a informação que o desenvolvedor precisa para corrigir sem precisar abrir documentação.

```bash
# Falhar apenas em CRITICAL/HIGH
checkov -d ./terraform/ --soft-fail-on MEDIUM LOW
```

*[Mostra a diferença no output — apenas CRITICAL e HIGH causam exit code 1]*

*[Abre VS Code, mostra a extensão tfsec funcionando inline]*

No VS Code com a extensão tfsec, você vê o problema sublinhado em vermelho enquanto escreve. Não precisa nem salvar o arquivo — o feedback é instantâneo. Isso é shift-left no seu extremo.

---

**[42:00 – 50:00 | PRE-COMMIT HOOK | Terminal]**

*[Configura pre-commit com Checkov e demonstra blocagem de commit]*

```bash
pip install pre-commit
cat .pre-commit-config.yaml
git add terraform/s3-inseguro.tf
git commit -m "adiciona bucket de backup"
# Checkov executa, encontra CRITICAL/HIGH, bloqueia o commit
```

*[Mostra a mensagem de erro do pre-commit]*

O commit foi bloqueado antes de chegar ao GitHub. Zero exposição. Zero PR necessário. O problema ficou no terminal do desenvolvedor, que pode corrigir imediatamente.

---

### Aula 3.2: OPA/Rego + GitHub Actions Pipeline (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Policy as Code com OPA/Rego e Pipeline GitHub Actions Completo |
| **Duração** | 50 minutos |
| **Formato** | Talking head + screen share (terminal + GitHub Actions) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Na aula anterior você viu como o Checkov e o tfsec detectam problemas conhecidos de configuração. Mas e as políticas específicas do Banco Meridian? Como garantir que todos os recursos têm a tag `Owner`? Como impedir que alguém crie recursos em regiões proibidas? Isso vai além dos checks built-in — você precisa escrever sua própria política.

É aqui que entra o OPA com Rego — Policy as Code. Vamos ver como escrever políticas e integrá-las ao pipeline GitHub Actions completo.

---

**[05:00 – 25:00 | OPA/REGO NA PRÁTICA | Terminal]**

*[Dica de edição: tela cheia no terminal, fonte maior]*

```bash
# Instalar OPA
brew install opa

# Criar primeira política Rego
cat > policy/tags.rego << 'REGO'
package terraform.aws.tags
violations[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.tags.Owner
  msg := sprintf("Bucket '%v' sem tag Owner", [resource.address])
}
deny[msg] { msg := violations[_] }
REGO

# Gerar Terraform plan JSON
terraform init -backend=false
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# Testar política
conftest test tfplan.json -p policy/
```

*[Mostra violations sendo geradas, corrige o Terraform, roda novamente e mostra PASS]*

---

**[25:00 – 48:00 | GITHUB ACTIONS PIPELINE | GitHub + Terminal]**

*[Abre o workflow YAML no VS Code, explica cada seção]*

Vamos ver o pipeline completo. Ele tem 4 jobs paralelos: Checkov, tfsec, Trivy e Conftest. Um 5º job — o security-gate — agrega os resultados e é o único ponto de decisão.

*[Demonstra um PR com código Terraform inseguro sendo bloqueado pelo pipeline]*

*[Mostra o resultado visual no GitHub — PR com "Required checks failed" em vermelho]*

*[Corrige o código, faz novo push, mostra o pipeline passando em verde]*

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

Você agora tem o kit completo de IaC Security: Checkov e tfsec para checks built-in, OPA/Rego para políticas customizadas, e o pipeline GitHub Actions que integra tudo. No Lab 02, você vai implementar esse pipeline do zero em um repositório GitHub real com Terraform do Banco Meridian. Nos vemos lá!

---

## 10. Avaliação do Módulo 03

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**
De acordo com a Regra do 10x, por que corrigir um problema de segurança em IaC em produção é 1.000x mais caro do que no desenvolvimento?

**a)** Porque em produção a ferramenta de scan custa 1.000x mais para executar
**b)** Porque a Regra do 10x diz que o custo dobra a cada fase, e desenvolvimento → CI → staging → produção são 3 doublings (2^3 = 8, não 1.000)
**c)** Porque a regra mostra que desenvolvimento custa R$ 1, CI custa R$ 10, staging R$ 100, produção R$ 1.000 — a diferença em produção inclui processo de change management, aprovações formais, possível janela de manutenção, risco de exposição durante o tempo de correção, e potencial notificação a reguladores como o BACEN
**d)** 1.000 vezes mais caro apenas para vulnerabilidades CRITICAL — LOW e MEDIUM têm custo igual em todas as fases

**Gabarito: c)**
Justificativa: A Regra do 10x mostra: desenvolvimento (R$ 1) → PR/review (R$ 10) → staging (R$ 100) → produção (R$ 1.000) → pós-incidente (R$ 10.000+). Em produção, o custo extra vem de: change management formal, aprovações, janela de manutenção programada, possível downtime, risco de exposição durante a janela de correção, e potencial notificação ao BACEN e investigação regulatória.

---

**Questão 2 (10 pts)**
Um desenvolvedor escreveu uma política Rego que usa a regra `deny[msg]`. O que acontece quando o conjunto `deny` é vazio?

**a)** A ferramenta retorna um erro de compilação porque deny não pode ser vazio
**b)** A política é considerada aprovada — o recurso passou em todos os checks porque nenhuma condição de violação foi verdadeira
**c)** OPA retorna "undecided" quando nenhuma regra é satisfeita
**d)** O conftest falha com exit code 2 por política incompleta

**Gabarito: b)**
Justificativa: Em Rego, quando `deny` é um conjunto vazio, significa que nenhuma condição de violação foi verdadeira. No framework Conftest/OPA, isso significa que a política passou — o recurso está conforme. Esse é o "closed world assumption" do Rego: o que não é explicitamente violado é considerado permitido. Não há erro de compilação — um conjunto vazio é um resultado válido.

---

**Questão 3 (10 pts)**
Um engenheiro está configurando o Checkov no pipeline IaC e precisa suprimir o check `CKV_AWS_144` apenas para um recurso específico que é uma exceção aprovada. Qual é a forma correta e auditável de fazer isso?

**a)** Adicionar `CKV_AWS_144` ao skip-check global no `.checkov.yaml`
**b)** Adicionar `#checkov:skip=CKV_AWS_144:motivo com ticket de aprovação` como comentário inline no recurso Terraform específico
**c)** Usar `--skip-check CKV_AWS_144` na linha de comando do pipeline
**d)** Remover o check da lista de checks a executar via API da Bridgecrew

**Gabarito: b)**
Justificativa: O inline skip com `#checkov:skip=CKV_AWS_144:justificativa` é a forma mais auditável porque está no git history junto com o código, o motivo é documentado, e a revisão de PR fica ciente. Skip global no `.checkov.yaml` ou via `--skip-check` na CLI remove o check para TODOS os recursos, perdendo cobertura para novos recursos que podem genuinamente precisar do check.

---

**Questão 4 (10 pts)**
No workflow GitHub Actions do Banco Meridian, qual é a diferença entre `continue-on-error: true` e `continue-on-error: false` em um step de scan?

**a)** `continue-on-error: true` executa o próximo step somente se o atual passou; `false` sempre executa o próximo
**b)** `continue-on-error: true` permite que o pipeline continue mesmo se o step retornar exit code 1 (a falha é registrada mas não bloqueia); `false` (padrão) para o job quando o step falha, marcando o check do PR como falha e impedindo o merge
**c)** Não há diferença funcional — ambos têm o mesmo comportamento
**d)** `continue-on-error: true` é usado apenas em steps de notificação, não em steps de scan

**Gabarito: b)**
Justificativa: `continue-on-error: true` é usado quando você quer que um step seja executado mas não bloqueie o pipeline em caso de falha — por exemplo, um step de scan de MEDIUM que apenas reporta mas não bloqueia. `continue-on-error: false` (padrão) significa que uma falha no step para o job e marca o PR check como falha. Para o security-gate do Banco Meridian, os steps de scan CRITICAL/HIGH devem ter `continue-on-error: false`.

---

**Questão 5 (10 pts)**
No workflow GitHub Actions do Banco Meridian, o step "security-gate" verifica os resultados dos jobs anteriores. Por que é preferível ter este job separado em vez de cada scanner bloquear diretamente?

**a)** Para economizar tempo de execução executando os scanners em paralelo
**b)** Para que cada scanner bloqueie e o desenvolvedor precise verificar múltiplas mensagens de erro
**c)** Para centralizar a decisão de bloqueio em um único ponto, fornecendo uma mensagem de erro unificada, instruções claras de correção, e simplificando o branch protection rule (que precisa exigir apenas o security-gate em vez dos 4 jobs de scanner)
**d)** Para permitir que o merge aconteça mesmo quando há falhas nos scanners

**Gabarito: c)**
Justificativa: O security-gate centraliza a decisão em um ponto. Vantagens: (1) o branch protection rule exige apenas 1 check obrigatório em vez de 4; (2) a mensagem de erro é unificada e clara para o desenvolvedor; (3) se um scanner flakear (falha intermitente de infra), pode-se re-run apenas o security-gate sem re-executar todos os scanners; (4) lógica de decisão mais sofisticada (ex: "fail se 2 ou mais scanners falharem") pode ser implementada aqui.

---

**Questão 6 (10 pts)**
Qual é a principal limitação do HashiCorp Sentinel em relação ao OPA/Conftest para o Banco Meridian?

**a)** Sentinel não suporta Terraform — apenas funciona com CloudFormation
**b)** Sentinel é integrado nativamente ao Terraform Cloud e Enterprise, mas é limitado ao ecossistema HashiCorp — não se integra com GitHub Actions, Jenkins ou GitLab CI de forma nativa como o OPA/Conftest
**c)** Sentinel tem uma linguagem de policy mais difícil que Rego
**d)** Sentinel é pago e OPA é gratuito — a diferença é apenas de custo

**Gabarito: b)**
Justificativa: Sentinel funciona apenas dentro do Terraform Cloud e Enterprise — as políticas são aplicadas automaticamente pelo Terraform Cloud antes de cada apply. Mas o Banco Meridian tem pipelines em diferentes sistemas. OPA/Conftest é agnóstico de plataforma — funciona com qualquer CI/CD e com qualquer arquivo de configuração. Para organizações que usam Terraform Cloud Enterprise, Sentinel e OPA/Conftest são complementares: Sentinel aplica as políticas "garantidas" no plan, e Conftest verifica no PR antes mesmo de chegar ao Terraform Cloud.

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O time de DevOps do Banco Meridian acabou de implementar o pipeline de IaC Security. Rafael (Security Engineer) revisou o pipeline e pediu para você:

1. Escrever uma política Rego completa e funcional que verifique se todos os recursos `aws_db_instance` (RDS) têm: `encrypted = true`, `deletion_protection = true`, `backup_retention_period` maior que 7 dias, e tag `Environment` presente

2. Desenhar o fluxo completo do pipeline DevSecOps do Banco Meridian para um desenvolvedor que faz uma alteração em um arquivo Terraform — desde o `git commit` até o deploy em produção, incluindo todos os gates de segurança

**Gabarito Q1 — Política Rego Completa:**

```rego
package terraform.aws.rds

import future.keywords.in

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.encrypted == true
    msg := sprintf("RDS '%v': encrypted=true é obrigatório. Dados de clientes em banco sem criptografia violam BACEN Art. 5 e LGPD Art. 46.", [resource.address])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.deletion_protection == true
    msg := sprintf("RDS '%v': deletion_protection=true é obrigatório. Banco de dados de produção deve ser protegido contra deleção acidental.", [resource.address])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    backup_period := resource.change.after.backup_retention_period
    backup_period <= 7
    msg := sprintf("RDS '%v': backup_retention_period=%v é insuficiente. Mínimo: 7 dias (recomendado: 30 dias para RDS de produção).", [resource.address, backup_period])
}

violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.tags.Environment
    msg := sprintf("RDS '%v': tag 'Environment' obrigatória ausente.", [resource.address])
}

deny[msg] {
    msg := violations[_]
}
```

**Gabarito Q2 — Fluxo do Pipeline DevSecOps:**

```
git commit → pre-commit hook (Checkov local, 3 segundos)
    ↓ PASS
git push → GitHub PR criado
    ↓
GitHub Actions pipeline (paralelo):
    ├── Checkov (CRITICAL/HIGH bloqueantes)
    ├── tfsec (CRITICAL/HIGH bloqueantes)
    ├── Trivy IaC (CRITICAL/HIGH bloqueantes)
    └── Conftest OPA (políticas customizadas BM)
         ↓ Todos os jobs completam (com sucesso ou falha)
    security-gate (agrega resultados)
    ↓ PASS ou FAIL
    ↓ PASS: PR disponível para revisão de código
Code Review (desenvolvedor + security team)
    ↓ APROVADO
Merge para main
    ↓
Pipeline de deploy (terraform apply em staging)
    ↓ DEPLOY STAGING
Testes de integração + CSPM scan com Prowler
    ↓ PASS
Aprovação manual do CISO (para mudanças HIGH RISK)
    ↓
terraform apply em produção
    ↓
Runtime monitoring: Falco (comportamento) + Prowler (postura)
```

---

*Módulo 03 — IaC Security e Shift-Left*
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*
*CECyber — Educação Corporativa em Cibersegurança*
