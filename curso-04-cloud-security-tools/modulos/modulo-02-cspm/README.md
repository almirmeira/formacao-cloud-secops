# Módulo 02 — CSPM: Cloud Security Posture Management
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2h videoaulas + 2h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 3 e 6 / CCSK domínio 5  
> **Cenário:** Banco Meridian avaliando postura de segurança cloud antes de auditoria BACEN

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Definir CSPM e distingui-lo do CWPP com precisão
2. Mapear frameworks de conformidade (CIS, NIST, LGPD, BACEN) para checks de CSPM
3. Executar Prowler v4 em AWS, Azure e GCP com saída em múltiplos formatos
4. Executar ScoutSuite para análise multi-provider e interpretar o relatório HTML
5. Descrever a proposta de valor de plataformas CNAPP comerciais (Wiz, Prisma Cloud, Orca)
6. Estruturar um relatório de postura de segurança para apresentação ao CISO

---

## 1. CSPM — O Que É e Como Funciona

### 1.1 Definição e Escopo

**CSPM (Cloud Security Posture Management)** é a categoria de ferramentas responsável por avaliar continuamente a configuração dos recursos cloud contra padrões de segurança estabelecidos (benchmarks, frameworks regulatórios) e identificar desvios — misconfigurations, exposições públicas, controles ausentes, não conformidades com políticas corporativas.

**O que CSPM faz:**
- Conecta às APIs dos provedores cloud (AWS, Azure, GCP) via credenciais de leitura
- Enumera todos os recursos em todas as contas/subscriptions/projetos
- Executa checks de configuração contra frameworks (CIS, NIST, LGPD, BACEN)
- Gera findings com severidade, descrição e recomendação de remediação
- Monitora drift — quando uma configuração muda e sai do padrão

**O que CSPM NÃO faz:**
- Não analisa o conteúdo dos workloads (isso é CWPP)
- Não gerencia identidades e permissões em profundidade (isso é CIEM)
- Não protege em tempo real (é reativo, não preventivo como OPA Gatekeeper)

### 1.2 Diferença Fundamental: CSPM vs CWPP

| Dimensão | CSPM | CWPP |
|:---------|:-----|:-----|
| **O que analisa** | Configuração dos serviços cloud (plano de controle) | Conteúdo e comportamento dos workloads (plano de dados) |
| **Exemplo de finding** | "Bucket S3 tem acesso público habilitado" | "Container tem CVE-2021-44228 (Log4Shell)" |
| **Quando detecta** | Quando a configuração é criada/alterada | Durante o build (image scan) ou runtime (Falco) |
| **Acesso necessário** | Read-only nas APIs cloud (IAM, S3, EC2...) | Acesso ao filesystem/network do workload |
| **Ferramenta open-source** | Prowler, ScoutSuite | Trivy, Falco, Grype |
| **Impacto em produção** | Zero (leitura de API apenas) | Mínimo (scan) a requer agente (runtime) |

---

## 2. Frameworks de Conformidade

### 2.1 CIS Benchmarks

O Center for Internet Security (CIS) publica benchmarks específicos para cada provedor cloud. São o padrão mais amplamente aceito para avaliação de postura cloud.

**CIS AWS Foundations Benchmark v3.0 (2024):**
- Capítulo 1: IAM (34 controles) — MFA, políticas de senha, chaves de acesso antigas
- Capítulo 2: Storage (7 controles) — S3 bucket ACLs, logging, criptografia
- Capítulo 3: Logging (11 controles) — CloudTrail, Config, VPC Flow Logs
- Capítulo 4: Monitoramento (16 controles) — CloudWatch alarms para eventos críticos
- Capítulo 5: Networking (7 controles) — Security Groups, VPC, NACLs

**CIS Azure Foundations Benchmark v2.0 (2023):**
- Capítulo 1: Identity and Access Management (IAM)
- Capítulo 2: Microsoft Defender for Cloud
- Capítulo 3: Storage Accounts
- Capítulo 4: Database Services
- Capítulo 5: Logging and Monitoring
- Capítulo 6: Networking
- Capítulo 7: Virtual Machines
- Capítulo 8: Key Vault
- Capítulo 9: AppService

**CIS Kubernetes Benchmark v1.8 (2023):**
- Capítulo 1: Control Plane Components (API server, etcd, Controller Manager, Scheduler)
- Capítulo 2: etcd
- Capítulo 3: Control Plane Configuration
- Capítulo 4: Worker Nodes (kubelet, configuration files)
- Capítulo 5: Kubernetes Policies (RBAC, Pod Security, CNI)

### 2.2 NIST CSF e SP 800-53

O **NIST Cybersecurity Framework (CSF) 2.0** tem 6 funções:
- **GOVERN** (novo no 2.0): políticas, papéis e responsabilidades
- **IDENTIFY**: inventário de ativos, avaliação de risco
- **PROTECT**: controles de acesso, criptografia, configuração segura
- **DETECT**: monitoramento contínuo, detecção de anomalias
- **RESPOND**: resposta a incidentes, comunicação
- **RECOVER**: recuperação, lições aprendidas

**Mapeamento CSPM → NIST CSF:**

| Função NIST | Checks CSPM Relevantes |
|:------------|:----------------------|
| IDENTIFY | Inventário de recursos, descoberta de shadow IT cloud, classificação de dados |
| PROTECT | Criptografia em repouso/trânsito, MFA habilitado, acesso público bloqueado |
| DETECT | Logging habilitado, CloudTrail ativo, alertas configurados |

### 2.3 LGPD e BACEN — Mapeamento para Checks CSPM

| Requisito Regulatório | Artigo | Check CSPM Correspondente |
|:----------------------|:------:|:--------------------------|
| Criptografia de dados pessoais em repouso | LGPD Art. 46 | S3 SSE habilitado, RDS encrypted, EBS volumes encrypted |
| Controle de acesso a dados pessoais | LGPD Art. 46 | S3 bucket ACL público, IAM policies over-permissive |
| Logging de acesso | LGPD Art. 37 | CloudTrail ativo, S3 access logging, RDS audit logs |
| Testes de vulnerabilidade periódicos | BACEN 4.893 Art. 5º | Execução regular de CSPM scans com relatórios |
| Gestão de acessos privilegiados | BACEN 4.893 Art. 8º | IAM users com MFA, console access sem MFA, root account usage |
| Monitoramento contínuo | BACEN 4.893 Art. 6º | CloudWatch alarms, Config rules, Security Hub habilitado |

---

## 3. Prowler v4

### 3.1 Arquitetura do Prowler v4

Prowler é a principal ferramenta open-source de CSPM. A versão 4 foi reescrita em Python com arquitetura modular.

```
ARQUITETURA PROWLER v4
──────────────────────────────────────────────────────────────
                         CLI / Python SDK
                              │
                    ┌─────────▼─────────┐
                    │   Prowler Core     │
                    │   (Orchestrator)   │
                    └─────────┬─────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
   ┌──────▼──────┐    ┌───────▼──────┐   ┌───────▼──────┐
   │  AWS Provider│    │Azure Provider│   │  GCP Provider │
   │  (boto3)    │    │ (azure-sdk)  │   │(google-cloud) │
   └──────┬──────┘    └───────┬──────┘   └───────┬──────┘
          │                   │                   │
   ┌──────▼──────────────────────────────────────▼──────┐
   │                   Checks Library                    │
   │   400+ checks organizados por serviço e framework  │
   └──────────────────────────┬──────────────────────────┘
                              │
   ┌──────────────────────────▼──────────────────────────┐
   │                    Output Formatters                  │
   │          JSON  │  CSV  │  HTML  │  OCSF  │  Stdout   │
   └──────────────────────────────────────────────────────┘
```

**Checks disponíveis por categoria (Prowler v4):**

| Categoria | Nº de Checks | Exemplos |
|:----------|:------------:|:---------|
| IAM | 85+ | root_mfa_enabled, access_keys_rotated, unused_credentials |
| S3 | 45+ | bucket_public_access, bucket_encryption, bucket_versioning |
| EC2 | 60+ | security_group_unrestricted_ssh, ebs_encryption, imds_v2 |
| RDS | 35+ | rds_instance_encrypted, rds_publicly_accessible, rds_backup |
| CloudTrail | 15+ | cloudtrail_enabled, cloudtrail_log_validation, cloudtrail_s3_bucket_public |
| Config | 10+ | config_enabled, config_recorder_running |
| Kubernetes (EKS) | 25+ | eks_control_plane_logging, eks_cluster_publicly_accessible |
| Azure | 100+ | storage_account_encryption, sql_database_auditing |
| GCP | 80+ | gcs_bucket_public, compute_instance_public_ip |

### 3.2 Como Executar Prowler — AWS

**Pré-requisitos:**
```bash
# Instalar Prowler v4
pip install prowler

# Verificar versão
prowler --version
# Output: Prowler 4.x.x

# Configurar credenciais AWS
aws configure
# Ou usar variáveis de ambiente
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

# Permissões mínimas necessárias:
# SecurityAudit (AWS managed policy) + ViewOnlyAccess
```

**Execução básica:**
```bash
# Scan completo na AWS (pode demorar 20-40 min)
prowler aws

# Scan com saída HTML (recomendado para relatórios)
prowler aws --output-formats html json csv

# Scan apenas checks críticos e altos
prowler aws --severity critical high

# Scan de um check específico
prowler aws --check s3_bucket_public_access

# Scan por serviço
prowler aws --service s3 iam ec2

# Scan filtrado por compliance framework (BACEN 4.893)
prowler aws --compliance brazil_lgpd

# Scan em conta específica com role assumption
prowler aws --role arn:aws:iam::123456789:role/ProwlerAudit

# Scan com envio para AWS Security Hub
prowler aws --security-hub

# Scan com output em diretório específico
prowler aws --output-path /tmp/prowler-results/

# Scan com múltiplas contas (Organizations)
prowler aws --organizations-role arn:aws:iam::MANAGEMENT_ACCOUNT:role/ProwlerOrgs
```

**Exemplos de outputs:**

```json
// Exemplo de finding JSON (prowler-output.json)
{
  "metadata": {
    "event_code": "prowler-aws-s3_bucket_public_access-us-east-1-bancomeridian-dados-clientes",
    "timestamp": "2025-04-24T14:30:00Z",
    "version": "1.0"
  },
  "finding": {
    "uid": "prowler-aws-s3_bucket_public_access-us-east-1",
    "title": "S3 Bucket 'bancomeridian-dados-clientes' has public access enabled",
    "desc": "The S3 bucket bancomeridian-dados-clientes has public access enabled which could expose sensitive data.",
    "severity": "critical",
    "status": "FAIL",
    "status_extended": "Bucket bancomeridian-dados-clientes has public access enabled.",
    "risk": "Exposure of sensitive customer data (PII/PCI) to the internet.",
    "remediation": {
      "desc": "Disable public access for S3 bucket using Block Public Access settings.",
      "code": {
        "cli": "aws s3api put-public-access-block --bucket bancomeridian-dados-clientes --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
      },
      "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    },
    "compliance": {
      "CIS-AWS-Foundations-Benchmark_v3.0.0": ["2.1.5"],
      "BACEN-4893": ["Art.5", "Art.6"],
      "LGPD": ["Art.46"]
    }
  },
  "resources": [
    {
      "uid": "arn:aws:s3:::bancomeridian-dados-clientes",
      "name": "bancomeridian-dados-clientes",
      "type": "AwsS3Bucket",
      "region": "us-east-1"
    }
  ]
}
```

### 3.3 Como Executar Prowler — Azure

```bash
# Autenticação Azure (usar Service Principal para CI/CD)
az login
# ou
az login --service-principal -u $APP_ID -p $PASSWORD --tenant $TENANT_ID

# Scan completo Azure
prowler azure --sp-env-auth

# Scan com subscription específica
prowler azure --sp-env-auth --subscription-ids "00000000-xxxx-xxxx-xxxx-000000000000"

# Scan com framework específico
prowler azure --sp-env-auth --compliance cis_microsoft_azure_foundations_benchmark_v2.0

# Variáveis de ambiente para Service Principal
export AZURE_CLIENT_ID="..."
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

### 3.4 Como Executar Prowler — GCP

```bash
# Autenticação GCP
gcloud auth application-default login
# ou service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Scan completo GCP
prowler gcp

# Scan de projeto específico
prowler gcp --project-ids "bancomeridian-prod"

# Scan com framework CIS GCP
prowler gcp --compliance cis_gcp_foundations_benchmark_v2.0
```

### 3.5 Como Executar Prowler — Kubernetes

```bash
# Prowler também suporta scan de clusters K8s
# Requer kubeconfig configurado
prowler kubernetes

# Scan de namespace específico
prowler kubernetes --context prod-cluster

# Com compliance CIS K8s
prowler kubernetes --compliance cis_kubernetes_benchmark_v1.8
```

### 3.6 Integração com AWS Security Hub

```bash
# Ativar integração Security Hub (uma vez)
prowler aws --security-hub

# Todos os findings são enviados como ASFF (Amazon Security Finding Format)
# Visível no console Security Hub em:
# Security Hub → Findings → filtre por Product: Prowler
```

---

## 4. ScoutSuite

### 4.1 Arquitetura e Funcionamento

ScoutSuite é uma ferramenta open-source da NCC Group para auditoria de segurança multi-cloud. Seu diferencial é gerar um relatório HTML interativo e rico em contexto.

```
FLUXO SCOUTSUITE
─────────────────────────────────────────────────
1. Autenticação → API cloud (read-only)
2. Enumeration → coleta todos os recursos e configurações
3. Analysis → aplica regras de segurança aos dados coletados
4. Report → gera HTML estático interativo
─────────────────────────────────────────────────
```

**Instalação e execução:**

```bash
# Instalar ScoutSuite
pip3 install scoutsuite

# Scan AWS
scout aws

# Scan AWS com profile específico
scout aws --profile bancomeridian-audit

# Scan Azure
scout azure --tenant $TENANT_ID --user-account

# Scan GCP
scout gcp --user-account --project $PROJECT_ID

# Scan com relatório salvo em diretório específico
scout aws --report-dir /tmp/scoutsuite-report/

# Após execução, abrir relatório:
# firefox scoutsuite-report/scoutsuite-results/scoutsuite_results_aws*.html
```

**Estrutura do Relatório HTML ScoutSuite:**
- Painel de resumo: total de findings por severidade e por serviço
- Navegação por serviço (IAM, S3, EC2, RDS, VPC...)
- Para cada finding: descrição, recurso afetado, evidência, recomendação
- Visualização de grafo de relacionamentos entre recursos
- Exportação para JSON para análise programática

---

## 5. CloudSploit (Aqua)

CloudSploit é uma engine open-source de checks de segurança cloud desenvolvida pela Aqua Security. Diferencial: você pode escrever checks customizados em JavaScript/Node.js.

```bash
# Instalar
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install

# Configurar credenciais AWS (arquivo config.js)
cp config_example.js config.js
# Editar config.js com suas credenciais

# Executar scan AWS
node index.js --provider aws --console json

# Executar com output CSV
node index.js --provider aws --csv /tmp/results.csv

# Criar check customizado (exemplo)
# plugins/aws/s3/bucketPublicAccessBlock.js
```

**Exemplo de check customizado CloudSploit:**

```javascript
// plugins/aws/s3/bancomeridianDataClassification.js
// Check customizado: verifica se buckets com 'dados' no nome têm tags de classificação

var async = require('async');
var helpers = require('../../../lib/helpers/aws');

module.exports = {
    title: 'Banco Meridian — Classificação de Dados em S3',
    category: 'S3',
    description: 'Buckets com dados devem ter tag DataClassification',
    more_info: 'Política interna do Banco Meridian exige classificação de dados em todos os buckets S3 que armazenam dados de clientes.',
    link: 'https://docs.bancomeridian.com.br/politica-dados',
    recommended_action: 'Adicionar tag DataClassification=Confidential ao bucket',
    apis: ['S3:listBuckets', 'S3:getBucketTagging'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, 'Unable to list S3 buckets: ' + helpers.addError(listBuckets), region);
            return callback(null, results, source);
        }

        listBuckets.data.forEach(function(bucket) {
            if (bucket.Name && bucket.Name.toLowerCase().includes('dados')) {
                var tags = helpers.addSource(cache, source, ['s3', 'getBucketTagging', region, bucket.Name]);
                var hasClassificationTag = tags && tags.data && tags.data.TagSet &&
                    tags.data.TagSet.some(t => t.Key === 'DataClassification');

                if (!hasClassificationTag) {
                    helpers.addResult(results, 2, // 2 = WARN
                        'Bucket ' + bucket.Name + ' não tem tag DataClassification',
                        region, 'arn:aws:s3:::' + bucket.Name);
                } else {
                    helpers.addResult(results, 0, // 0 = PASS
                        'Bucket ' + bucket.Name + ' tem tag DataClassification',
                        region, 'arn:aws:s3:::' + bucket.Name);
                }
            }
        });

        callback(null, results, source);
    }
};
```

---

## 6. Plataformas CNAPP Comerciais — Visão Conceitual

### 6.1 Wiz

**Proposta de valor central:** Agentless scanning com Security Graph que correlaciona todos os dados de cloud.

**Arquitetura:**
```
WIZ — COMO FUNCIONA
─────────────────────────────────────────────────────────────────
Seus ambientes cloud (AWS / Azure / GCP / K8s)
         │
         │ APIs read-only (sem agente instalado)
         ▼
    WIZ PLATFORM (SaaS)
         │
    ┌────┴────┐
    │ Security│  ← grafo de relacionamentos entre todos os recursos
    │  Graph  │    (VMs, identidades, dados, rede, configs)
    └────┬────┘
         │
    ┌────▼─────────────────────────────────────────────────────┐
    │  CAPACIDADES                                             │
    │                                                          │
    │  CSPM: misconfigurations em AWS/Azure/GCP/K8s           │
    │  CWPP: vulnerabilidades em VMs e containers (sem agente) │
    │  CIEM: permissões excessivas, toxic combinations         │
    │  DSPM: dados sensíveis em buckets e bancos               │
    │  ASPM (Wiz Code): segurança no pipeline de desenvolvimento│
    │                                                          │
    │  DIFERENCIAL: Toxic Combinations                         │
    │  "Essa VM está exposta + tem Log4Shell + role de admin"  │
    └──────────────────────────────────────────────────────────┘
```

**Pontos fortes:**
- Agentless — sem impacto operacional, deploy em dias
- Security Graph — correlação única no mercado
- Cobertura ampla: AWS, Azure, GCP, OCI, K8s, código
- Interface intuitiva — CISO consegue usar sem treinamento técnico profundo
- Magic Quadrant Gartner: líder em CNAPP desde 2023

**Limitações:**
- Preço elevado (estimativa: USD 100–150k/ano para ambientes médios)
- Sem proteção de runtime real (Falco-based, não native)
- SaaS — dados processados fora da infraestrutura do cliente

---

### 6.2 Prisma Cloud (Palo Alto Networks)

**Proposta de valor central:** Plataforma mais completa do mercado, cobrindo code to cloud com CWPP real e agente instalado.

**Módulos:**
- **Prisma Cloud Code Security**: scan de IaC, secrets em código, SBOM — integrado ao IDE e CI/CD
- **Prisma Cloud CSPM**: postura cloud multi-provider, +2.000 políticas
- **Prisma Cloud CWPP**: proteção de workloads com agente (microsegmentação, runtime, container security)
- **Prisma Cloud CIEM**: análise de identidades e permissões
- **Prisma Cloud Application Security**: SAST, SCA integrados

**Pontos fortes:**
- Cobertura mais completa: do código até runtime com agente
- Microsegmentação de rede entre containers
- Compliance automático: 100+ frameworks built-in
- Integração nativa com XSOAR (SOAR da Palo Alto) para automação de resposta
- Excelente para ambientes regulamentados (financeiro, saúde)

**Limitações:**
- Complexidade de configuração e operação mais alta
- Curva de aprendizado longa
- Preço baseado em créditos (difícil de prever)

---

### 6.3 Orca Security

**Proposta de valor central:** SideScanning™ — tecnologia única que lê snapshots de disco para análise profunda sem agente.

**Como SideScanning™ funciona:**
```
SIDESCAN PROCESS
─────────────────────────────────────────────────────────
1. Orca lê metadados cloud (API read-only)
2. Cria snapshot efêmero do volume EBS/disco da VM
3. Monta o snapshot em ambiente isolado (Orca cloud)
4. Lê filesystem completo: OS packages, app files, configs, secrets
5. Desmonta e deleta o snapshot
6. Resultado: análise completa sem agente, sem impacto em produção
─────────────────────────────────────────────────────────
```

**Pontos fortes:**
- Visibilidade profunda sem agente (ver dentro do OS)
- Attack path analysis visual muito clara
- Interface limpa e acessível
- Bom para organizações que não podem usar agentes (compliance restrictions)
- Preço intermediário no mercado CNAPP

**Limitações:**
- Não tem runtime protection real (pós-snapshot)
- Menor cobertura de K8s comparado a Wiz
- Disponibilidade de região de dados pode ser limitada

---

### 6.4 Microsoft Defender for Cloud

**Proposta de valor central:** Ferramenta nativa Azure com expansão multi-cloud, integrada ao Microsoft Sentinel.

**Planos:**
- **Foundational CSPM** (gratuito): inventário de segurança, Secure Score
- **Defender CSPM** (pago): attack path analysis, governance, DSPM
- **Defender for Servers**: proteção de VMs Windows/Linux
- **Defender for Containers**: segurança de containers e K8s
- **Defender for Databases**: proteção de Azure SQL, CosmosDB, PostgreSQL

**Multi-cloud:**
```bash
# Conectar conta AWS ao Defender for Cloud
# Via AWS connector (CloudFormation ou Terraform)
# Isso habilita:
# - Recomendações de segurança para recursos AWS
# - Conformidade CIS AWS, NIST
# - Integração com Microsoft Sentinel para alertas
```

**Pontos fortes:**
- Gratuito para Azure (Foundational CSPM)
- Integração nativa com Microsoft Sentinel (SIEM) e SOAR
- Microsoft Secure Score — métrica unificada de postura
- Governança integrada — assign owner, due date para remediation
- Ideal para ambientes Microsoft-first (Azure + M365)

**Limitações:**
- Cobertura AWS/GCP mais superficial que ferramentas nativas
- Interface fragmentada para usuários não-Microsoft
- Runtime protection para containers menos madura que Sysdig/Aqua

---

## 7. Como Apresentar um Relatório CSPM ao CISO

### 7.1 O Problema com Relatórios CSPM Brutos

Um scan Prowler de uma conta AWS média gera entre 2.000 e 10.000 findings. Apresentar 10.000 linhas para o CISO não é um relatório — é um data dump.

O CISO precisa responder a três perguntas:
1. Estamos em risco agora? (severidade atual)
2. Onde estão os maiores riscos? (priorização por impacto de negócio)
3. O que precisamos fazer e quando? (roadmap de remediação)

### 7.2 Estrutura do Relatório Executivo

```
RELATÓRIO EXECUTIVO DE POSTURA DE SEGURANÇA CLOUD
Banco Meridian — AWS Production Account
Data: 24/04/2025 | Executado por: [nome] | Ferramenta: Prowler v4.3.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. RESUMO EXECUTIVO (1 página)
   ├── Overall Security Score: 62/100 (abaixo de 70 — risco)
   ├── Findings por severidade:
   │   ├── CRITICAL: 3 (requer ação em 24h)
   │   ├── HIGH: 27 (requer ação em 7 dias)
   │   ├── MEDIUM: 189 (requer ação em 30 dias)
   │   └── LOW: 1.847 (monitorar, sem prazo urgente)
   ├── Maior risco identificado: 2 S3 buckets com dados de clientes acessíveis publicamente
   └── Conformidade com BACEN 4.893: 58% (meta: 85%)

2. TOP 5 RISCOS CRÍTICOS (com impacto de negócio)
   Cada item inclui:
   - Nome do finding
   - Recurso afetado
   - Impacto de negócio (ex: "Multa BACEN + exposição de dados de X clientes")
   - Esforço de remediação (horas estimadas)
   - Responsável recomendado

3. CONFORMIDADE REGULATÓRIA
   ├── BACEN 4.893: 58% → mapa de calor por artigo
   ├── CIS AWS Foundations: 67%
   └── LGPD: 71%

4. ROADMAP DE REMEDIAÇÃO (30/60/90 dias)
   Com owners, esforço estimado e business impact de cada grupo

5. MÉTRICAS DE TENDÊNCIA (se execuções anteriores disponíveis)
   "Em 30 dias: -15 findings CRITICAL, +8% em conformidade BACEN"
```

### 7.3 Priorização por Impacto de Negócio (não por quantidade)

```python
# Script Python para priorizar findings Prowler por impacto de negócio
import json

# Carregar output JSON do Prowler
with open('prowler-output.json') as f:
    findings = json.load(f)

# Fatores de priorização
BUSINESS_IMPACT = {
    'external_exposure': 10,    # recurso exposto externamente
    'data_store': 8,            # S3 bucket, RDS, DynamoDB com dados
    'production': 7,            # tag Environment=production
    'bacen_compliance': 9,      # impacta conformidade BACEN
}

def calculate_priority_score(finding):
    score = 0
    severity_weights = {'critical': 100, 'high': 70, 'medium': 30, 'low': 10}
    score += severity_weights.get(finding.get('severity', 'low'), 0)

    # Checar fatores de negócio
    resource_name = finding.get('resource_name', '').lower()
    if 'prod' in resource_name or 'production' in resource_name:
        score += BUSINESS_IMPACT['production']
    if any(t in resource_name for t in ['dados', 'data', 'clientes', 'pii', 'pci']):
        score += BUSINESS_IMPACT['data_store']
    if 'public' in finding.get('title', '').lower():
        score += BUSINESS_IMPACT['external_exposure']
    if 'BACEN' in str(finding.get('compliance', {})):
        score += BUSINESS_IMPACT['bacen_compliance']

    return score

# Ordenar por prioridade
prioritized = sorted(findings, key=calculate_priority_score, reverse=True)

# Top 10 findings mais críticos pelo negócio
for i, f in enumerate(prioritized[:10], 1):
    print(f"{i}. [{f['severity'].upper()}] {f['title']}")
    print(f"   Recurso: {f.get('resource_name', 'N/A')}")
    print(f"   Score: {calculate_priority_score(f)}")
    print()
```

---

## 8. Tabela Comparativa — Prowler vs ScoutSuite vs Wiz vs Prisma Cloud

| Dimensão | Prowler v4 | ScoutSuite | Wiz | Prisma Cloud |
|:---------|:----------:|:----------:|:---:|:------------:|
| **Tipo** | Open-source | Open-source | Comercial SaaS | Comercial SaaS |
| **AWS** | ✓ Excelente | ✓ Bom | ✓ Excelente | ✓ Excelente |
| **Azure** | ✓ Bom | ✓ Bom | ✓ Excelente | ✓ Excelente |
| **GCP** | ✓ Bom | ✓ Bom | ✓ Excelente | ✓ Excelente |
| **Kubernetes** | ✓ Básico | ✗ Não | ✓ Excelente | ✓ Excelente |
| **CWPP** | ✗ Não | ✗ Não | ✓ Agentless | ✓ Com agente |
| **CIEM** | Parcial | ✗ Não | ✓ Completo | ✓ Completo |
| **Número de checks** | 400+ | 200+ | 3.000+ | 2.500+ |
| **Relatório HTML** | ✓ Básico | ✓ Excelente | ✓ Dashboard | ✓ Dashboard |
| **Security Hub integration** | ✓ Nativo | ✗ Não | ✓ | ✓ |
| **Compliance frameworks** | 50+ | 20+ | 100+ | 100+ |
| **BACEN 4.893** | ✓ Built-in | Parcial | ✓ Customizável | ✓ Customizável |
| **LGPD** | ✓ Built-in | ✗ Não | ✓ Customizável | ✓ Customizável |
| **Custo** | Gratuito | Gratuito | USD 80–150k/ano | USD 60–100k/ano |
| **Tempo de setup** | 30 min | 30 min | 2–4 semanas | 4–8 semanas |
| **Monitoramento contínuo** | ✗ Requer agendamento | ✗ Requer agendamento | ✓ Nativo | ✓ Nativo |
| **API REST** | ✓ | ✗ Não | ✓ GraphQL | ✓ REST |
| **Suporte** | Comunidade | Comunidade | Enterprise SLA | Enterprise SLA |

---

## 9. Atividades de Fixação

### Questão 1
Um analista de segurança executou o Prowler v4 e encontrou o seguinte finding: "EC2 Security Group sg-0abc123 allows unrestricted SSH access (0.0.0.0/0 on port 22)". Qual categoria de ferramenta gerou esse finding e qual é o risco associado?

**a)** CWPP — risco de CVE no OS da instância  
**b)** CSPM — risco de acesso remoto não autorizado à instância via internet  
**c)** CIEM — risco de permissão IAM excessiva na role da instância  
**d)** CASB — risco de exfiltração de dados via SSH  

**Gabarito: b)**  
Justificativa: Security Group é uma configuração de recurso AWS (não algo dentro do workload), portanto é um finding de CSPM. A porta 22 (SSH) exposta para 0.0.0.0/0 permite que qualquer endereço IP na internet tente se autenticar no servidor — risco de acesso remoto não autorizado por brute force ou exploração de credenciais.

---

### Questão 2
Qual é o comando Prowler v4 correto para executar um scan completo AWS focado apenas em findings de severidade CRITICAL e HIGH, gerando saída em HTML e JSON, em uma conta usando role assumption?

```bash
# Qual das alternativas abaixo está correta?
a) prowler aws --severity critical high --output-formats html json --role arn:aws:iam::123456789:role/ProwlerAudit
b) prowler aws --level critical --format html json --assume-role arn:aws:iam::123456789:role/ProwlerAudit
c) prowler scan aws --critical --html --json --iam-role arn:aws:iam::123456789:role/ProwlerAudit
d) prowler aws --findings critical high --export html,json --role-arn arn:aws:iam::123456789:role/ProwlerAudit
```

**Gabarito: a)**  
Justificativa: A sintaxe correta do Prowler v4 usa `--severity critical high` para filtrar por severidade, `--output-formats html json` para múltiplos formatos de saída, e `--role` para especificar a ARN da role a ser assumida.

---

### Questão 3
O CISO do Banco Meridian pediu um relatório de conformidade com a Resolução BACEN 4.893. Qual framework de compliance embutido no Prowler v4 é o mais relevante para atender esse pedido?

**a)** `--compliance cis_aws_foundations_benchmark_v3.0`  
**b)** `--compliance nist_sp_800_53_revision_5_aws`  
**c)** `--compliance brazil_lgpd`  
**d)** `--compliance soc2_type_ii`  

**Gabarito: c)**  
Justificativa: O framework `brazil_lgpd` no Prowler v4 inclui mapeamentos para regulações financeiras brasileiras incluindo BACEN 4.893, pois a resolução faz referência à proteção de dados pessoais. Para um relatório específico de conformidade com BACEN, esse é o framework mais relevante disponível nativamente. Nota: a equipe do Prowler também mantém checks específicos para LGPD que cobrem os artigos da BACEN 4.893 relevantes para cloud security.

---

### Questão 4
Qual é a principal vantagem do SideScanning™ da Orca Security em relação à abordagem tradicional de agente instalado (como a do Prisma Cloud CWPP)?

**a)** SideScanning™ gera menos falsos positivos porque acessa o código-fonte diretamente  
**b)** SideScanning™ lê snapshots efêmeros do disco sem instalar agente, reduzindo impacto operacional e cobrindo workloads imutáveis  
**c)** SideScanning™ é mais rápido porque não precisa de API calls para a AWS  
**d)** SideScanning™ é mais preciso em detecção de runtime threats porque roda no kernel  

**Gabarito: b)**  
Justificativa: SideScanning™ cria snapshots efêmeros do volume de disco, monta em ambiente isolado, lê o filesystem completo (pacotes, configurações, segredos) sem instalar nenhum agente no sistema operacional da VM. Vantagens: sem overhead operacional, cobre containers imutáveis que não permitem agentes, funciona em instâncias que não podem ser modificadas por requisitos de compliance.

---

### Questão 5
Uma equipe de segurança recebe um relatório Prowler com 8.500 findings. Como deve ser a abordagem correta de priorização para apresentar ao CISO?

**a)** Apresentar todos os 8.500 findings ordenados por severidade (CRITICAL → LOW)  
**b)** Priorizar apenas os 3 findings CRITICAL, ignorando todos os outros temporariamente  
**c)** Priorizar por combinação de severidade técnica + impacto de negócio (recursos expostos externamente, recursos com dados de clientes, recursos em produção com mapeamento BACEN)  
**d)** Priorizar pelos recursos mais antigos, pois são os com maior acúmulo de dívida de segurança  

**Gabarito: c)**  
Justificativa: A priorização correta combina a severidade técnica com o contexto de negócio. Um finding MEDIUM em um bucket S3 público com dados de clientes do Banco Meridian é mais urgente do que um CRITICAL em uma conta de sandbox sem dados sensíveis. O CISO precisa saber: qual risco pode me dar uma multa do BACEN ou vazamento de dados hoje?

---

## 10. Roteiros de Gravação

### Aula 2.1: CSPM Conceito + Prowler (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | CSPM: Conceito, Frameworks de Conformidade e Prowler v4 na Prática |
| **Duração** | 50 minutos |
| **Formato** | Talking head + screen share (terminal) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Olá, seja bem-vindo ao Módulo 2. Agora vamos mergulhar na primeira categoria de ferramenta que você vai usar no dia a dia como profissional de cloud security: o CSPM.

Se você passou pelo Módulo 1, já sabe que CSPM significa Cloud Security Posture Management e que ele resolve o problema das misconfigurations — aquelas configurações erradas de recursos cloud que expõem sua organização a ataques ou a penalidades regulatórias.

Nesta aula vamos ver: o que é CSPM em detalhe, como ele se diferencia do CWPP, quais são os frameworks de conformidade que ele verifica, e vamos colocar a mão na massa com o Prowler v4 — a ferramenta open-source mais usada no mundo para CSPM.

Prepare o terminal, porque vamos executar scans reais.

---

**[05:00 – 18:00 | CSPM E FRAMEWORKS | Slides]**

*[Dica de edição: tela cheia nos slides, destaque os artigos da lei quando mencionar]*

Deixa eu te mostrar por que CSPM existe. Em 2017, um estudo do Gartner estimou que 95% dos incidentes de segurança cloud até 2025 seriam causados por erro do cliente — não por vulnerabilidade do provedor cloud. E a maioria desses erros são misconfigurations: coisas como buckets S3 públicos, Security Groups com porta aberta para o mundo, bancos de dados sem criptografia.

O CSPM automatiza a detecção desses erros. Ele conecta nas APIs cloud com permissões de leitura e verifica continuamente se cada recurso está configurado de acordo com os benchmarks de segurança.

*[Slide: tabela de frameworks]*

Fala de frameworks: o principal é o CIS — Center for Internet Security. Eles publicam benchmarks específicos para AWS, Azure, GCP, K8s — com centenas de controles técnicos verificáveis automaticamente. O Prowler implementa todos esses controles.

Para quem trabalha no setor financeiro brasileiro, o que mais importa é o mapeamento para BACEN 4.893. O Prowler tem um framework Brazil LGPD que cobre os artigos relevantes da resolução. Quando você roda `prowler aws --compliance brazil_lgpd`, você recebe um relatório que mostra exatamente quais artigos da resolução você está cumprindo e quais está violando.

*[Slide: diferença CSPM vs CWPP]*

Antes de entrar no Prowler, deixa eu clarificar a diferença com CWPP porque isso confunde muita gente.

CSPM olha para a configuração do serviço — o plano de controle. "Esse S3 bucket está configurado com acesso público?" Isso é uma chamada de API para perguntar ao S3 como ele está configurado.

CWPP olha para o que está dentro do workload — o plano de dados. "Que CVEs existem nesse container?" Isso requer analisar os pacotes instalados dentro da imagem Docker.

São perguntas diferentes, sobre objetos diferentes, respondidas com técnicas diferentes.

---

**[18:00 – 42:00 | PROWLER NA PRÁTICA | Screen share — terminal]**

*[Dica de edição: tela cheia no terminal, fonte maior, zoom nos comandos]*

Agora vamos para o terminal. Vou mostrar o Prowler v4 em ação.

*[Mostra terminal]*

Primeiro, vamos instalar. O Prowler v4 é um pacote Python.

```bash
pip install prowler
prowler --version
```

*[Aguarda output]*

Perfeito. Agora vou configurar as credenciais AWS. Para um ambiente de produção, você usaria um IAM Role com permissões mínimas — SecurityAudit + ViewOnlyAccess. Para demonstração, vou usar variáveis de ambiente.

```bash
export AWS_PROFILE=bancomeridian-audit
aws sts get-caller-identity
```

*[Mostra o output com Account ID]*

Certo, estamos autenticados na conta sandbox do Banco Meridian. Agora vamos executar o primeiro scan. Vou filtrar por CRITICAL e HIGH para não esperarmos muito.

```bash
prowler aws --severity critical high --output-formats html json
```

*[Deixa rodar, comenta enquanto progride]*

Enquanto o Prowler roda, deixa eu te explicar o que está acontecendo. Ele está fazendo chamadas de API para cada serviço AWS — IAM, S3, EC2, RDS, CloudTrail, VPC — em todas as regiões habilitadas. Para cada recurso encontrado, ele executa os checks relevantes. O número de chamadas de API pode ser grande, mas o impacto em produção é zero porque são todas chamadas de leitura.

*[Prowler termina, mostra summary]*

Veja o resumo: 3 findings CRITICAL, 27 HIGH. Vamos abrir o relatório HTML para ver em detalhe.

*[Abre browser com relatório HTML]*

*[Navega pelo relatório, mostra os CRITICAL findings, explica cada um]*

Veja esse: bucket S3 com acesso público. Nome: bancomeridian-dados-clientes. Isso é crítico porque o nome sugere que tem dados de clientes, e está completamente público na internet. Qualquer pessoa com o URL pode baixar esses dados.

*[Mostra o finding em JSON]*

O finding em JSON tem o mapeamento de compliance. Veja: mapeado para CIS 2.1.5, BACEN 4.893 Art. 5 e LGPD Art. 46. Quando você apresentar isso ao CISO, você tem a ligação direta com a regulação — não é apenas um achado técnico, é uma violação regulatória.

---

**[42:00 – 50:00 | RECAPITULAÇÃO]**

*[Volta para talking head]*

Nesta aula vimos: o que é CSPM e como se diferencia do CWPP, os principais frameworks de conformidade (CIS, NIST, BACEN, LGPD), e como executar o Prowler v4 com scans reais na AWS.

Na próxima aula, vamos ver o ScoutSuite com seu relatório HTML rico, e depois vou te mostrar como as plataformas CNAPP comerciais — Wiz, Prisma Cloud, Orca — elevam o CSPM para outro nível com correlação e attack path analysis. E vamos falar sobre o que não pode faltar quando você apresenta um relatório para o CISO.

Nos vemos na Aula 2.2!

---

### Aula 2.2: ScoutSuite + Plataformas Comerciais + Apresentação ao CISO (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | ScoutSuite, Plataformas CNAPP Comerciais e Como Apresentar ao CISO |
| **Duração** | 50 minutos |
| **Formato** | Screen share (browser/terminal) + slides + talking head |

---

**[00:00 – 03:00 | ABERTURA | Talking head]**

Na aula anterior você viu o Prowler em ação. Agora vamos completar o panorama das ferramentas de CSPM: veremos o ScoutSuite com seu relatório HTML altamente visual, vou te mostrar como as plataformas CNAPP comerciais como Wiz e Prisma Cloud elevam o CSPM para outro nível, e encerraremos com uma habilidade crítica que separa bons analistas de excelentes: como transformar um dump de 10.000 findings em um relatório executivo que o CISO consegue agir.

---

**[03:00 – 20:00 | SCOUTSUITE | Screen share]**

*[Dica de edição: tela cheia no terminal e depois no browser]*

ScoutSuite é diferente do Prowler em um aspecto importante: o foco é gerar um relatório HTML rico e navegável, excelente para auditorias e para comunicação com stakeholders não técnicos.

*[Terminal: execução ScoutSuite]*

```bash
pip3 install scoutsuite
scout aws --profile bancomeridian-audit --report-dir /tmp/scout-report
```

*[Aguarda e comenta]*

ScoutSuite coleta todos os dados de configuração cloud e os armazena localmente em JSON. Depois aplica as regras de segurança e gera o relatório HTML estático.

*[Abre browser]*

Veja o relatório. Diferente do Prowler, o ScoutSuite tem uma navegação por serviço muito intuitiva. Você clica em S3 e vê todos os seus buckets com a situação de segurança de cada um. Clica em IAM e vê todos os usuários, com indicação clara de quais não têm MFA habilitado.

*[Navega pelo relatório, destaca visualizações]*

Esse tipo de relatório é perfeito para reuniões de revisão de postura de segurança porque stakeholders não técnicos conseguem entender intuitivamente.

---

**[20:00 – 38:00 | PLATAFORMAS COMERCIAIS | Slides]**

*[Dica de edição: use screenshots ilustrativas dos consoles]*

Agora, plataformas comerciais. Vou mostrar de forma conceitual porque vocês não têm acesso a elas neste laboratório — mas é importante entender o que elas oferecem além do open-source.

*[Slide: Wiz]*

O Wiz é hoje o líder do Quadrante Mágico Gartner de CNAPP. O que ele faz de diferente? O Security Graph.

Imagine um grafo onde cada nó é um recurso do seu cloud: VMs, buckets S3, roles IAM, security groups, dados em bancos de dados. As arestas do grafo representam relacionamentos: "essa VM tem essa role IAM", "esse security group está associado a essa VPC", "essa VPC tem acesso a esse bucket S3".

Quando o Wiz encontra uma VM com porta exposta, uma CVE no OS, e uma role IAM com acesso a dados sensíveis — ele conecta esses três nós no grafo e te mostra o caminho de ataque completo. Isso é o que chamamos de toxic combination.

*[Slide: comparativo comercial]*

Prisma Cloud tem uma proposta diferente: a cobertura mais completa, do código ao runtime. Com agente instalado, ele detecta comportamento malicioso em runtime — um processo abrindo uma shell, uma conexão de rede para C&C. E com o módulo Code Security, ele scanneia o código-fonte antes mesmo do merge no repositório.

*[Slide: Defender for Cloud]*

O Defender for Cloud é o CNAPP da Microsoft. Se você está em um ambiente Microsoft-first — Azure + Microsoft 365 — ele é imbatível porque a integração com o Sentinel, com o Entra ID, com o Intune é nativa. Para organizações financeiras que usam Azure como provedor principal, é frequentemente a escolha óbvia.

---

**[38:00 – 48:00 | APRESENTANDO AO CISO | Slides + template]**

*[Dica de edição: volta para talking head + slides de template]*

Última parte, e talvez a mais importante do ponto de vista prático: como você transforma 10.000 findings do Prowler em algo que o CISO consegue apresentar ao Conselho do Banco Meridian?

*[Slide: estrutura do relatório executivo]*

Um relatório executivo de postura CSPM tem 4 seções principais.

Primeiro: o resumo em uma página. O CISO precisa ver o Security Score, o número de CRITICAL/HIGH, os 3 maiores riscos em uma linha cada, e o status de conformidade BACEN. Uma página, período.

*[Slide: top 5 riscos com impacto de negócio]*

Segundo: os top 5 riscos, cada um com impacto de negócio. Não "bucket S3 com acesso público" — isso não diz nada. "Bucket bancomeridian-dados-clientes com 4,2 GB de dados de clientes exposto publicamente na internet — risco de multa BACEN de até 2% do faturamento bruto do último ano e exposição de dados de 340.000 clientes." Isso tem peso. Isso motiva ação.

*[Slide: roadmap de remediação]*

Terceiro: roadmap de remediação em 30/60/90 dias. Os CRITICAL devem ser resolvidos em 24–48 horas. Os HIGH em 7 dias. Cada item com owner definido, esforço estimado em horas e impacto esperado na postura.

E quarto: métricas de tendência — se você tem dados de scans anteriores, mostrar a evolução é poderoso. "Em 30 dias, remediamos 15 findings CRITICAL e subimos nossa conformidade BACEN de 58% para 72%." Isso é progresso mensurável.

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

Encerrando: você agora tem o panorama completo de CSPM — ferramentas open-source Prowler e ScoutSuite, o que as plataformas comerciais adicionam, e como comunicar isso de forma executiva.

No laboratório Lab-01, você vai executar o Prowler em uma conta AWS sandbox real, filtrar os findings mais críticos, mapeá-los para BACEN 4.893, e produzir um relatório executivo. Esse laboratório vai preparar você para fazer exatamente o que um CISO pediria antes de uma auditoria do BACEN.

Nos vemos no laboratório!

---

## 11. Avaliação do Módulo 02

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
Qual é a diferença fundamental entre as abordagens de Prowler e ScoutSuite para CSPM?

**a)** Prowler suporta apenas AWS; ScoutSuite suporta multi-cloud  
**b)** Prowler foca em checks com saídas estruturadas (JSON/CSV) para integração com Security Hub; ScoutSuite foca em relatório HTML visual e navegável para análise interativa  
**c)** Prowler usa agente instalado; ScoutSuite usa API read-only  
**d)** Prowler é pago; ScoutSuite é open-source  

**Gabarito: b)** Prowler v4 tem saídas estruturadas em JSON/CSV/HTML com integração ao AWS Security Hub, OCSF e outros — ideal para automação e pipelines. ScoutSuite gera um relatório HTML estático rico e navegável com contexto visual por serviço — ideal para auditorias e comunicação com stakeholders.

---

**Questão 2 (10 pts)**  
O comando `prowler aws --compliance brazil_lgpd` retorna findings mapeados para qual framework regulatório?

**a)** Apenas LGPD (Lei 13.709/2018), sem incluir regulações do BACEN  
**b)** CIS AWS Foundations Benchmark com anotações em português  
**c)** LGPD e regulações financeiras brasileiras associadas, incluindo BACEN 4.893 e CMN 4.658  
**d)** ISO 27001:2022 adaptado para o contexto brasileiro  

**Gabarito: c)** O framework `brazil_lgpd` do Prowler inclui mapeamentos para o conjunto de regulações de proteção de dados brasileiras, que inclui LGPD, BACEN 4.893 e CMN 4.658 — relevante especialmente para instituições financeiras.

---

**Questão 3 (10 pts)**  
No contexto da plataforma Wiz, o que é o "Security Graph"?

**a)** Um gráfico de tendência mostrando a evolução do Security Score ao longo do tempo  
**b)** Um grafo de relacionamentos entre todos os recursos cloud que permite identificar caminhos de ataque e toxic combinations  
**c)** Um mapa de calor de conformidade com frameworks regulatórios  
**d)** Um diagrama de rede mostrando os VPCs e Security Groups configurados  

**Gabarito: b)** O Security Graph do Wiz é um grafo onde nós são recursos cloud (VMs, roles IAM, buckets, SGs) e arestas são relacionamentos entre eles. Isso permite identificar que uma VM exposta tem uma role IAM com acesso a dados sensíveis — o caminho de ataque completo — em vez de findings isolados.

---

**Questão 4 (10 pts)**  
Um analista de segurança quer que o Prowler envie automaticamente todos os findings para o AWS Security Hub assim que o scan terminar. Qual flag deve usar?

**a)** `prowler aws --send-to-security-hub`  
**b)** `prowler aws --security-hub`  
**c)** `prowler aws --output security-hub`  
**d)** `prowler aws --integration aws-security-hub`  

**Gabarito: b)** A flag correta do Prowler v4 é `--security-hub`. Ela faz o Prowler enviar findings no formato ASFF (Amazon Security Finding Format) diretamente para o AWS Security Hub.

---

**Questão 5 (10 pts)**  
Por que apresentar ao CISO todos os 8.500 findings de um scan Prowler sem priorização é considerado uma má prática?

**a)** Porque o CISO não tem acesso técnico para interpretar os findings  
**b)** Porque o CISO precisa de contexto de impacto de negócio, não de volume de problemas técnicos — sem priorização, não é possível tomar decisões de investimento e remediação  
**c)** Porque findings de severidade LOW nunca são relevantes para a gestão  
**d)** Porque o Prowler gera muitos falsos positivos que precisam ser filtrados antes  

**Gabarito: b)** Um relatório não priorizado transfere a carga cognitiva de priorização para o CISO, que não tem contexto técnico suficiente. O papel do analista é transformar dados técnicos em insight de negócio: "esses 3 findings representam risco de multa BACEN e devem ser resolvidos esta semana com X horas de esforço".

---

**Questão 6 (10 pts)**  
Qual é a principal vantagem do Microsoft Defender for Cloud em relação ao Wiz para organizações com ambiente Azure-first?

**a)** Defender for Cloud tem mais checks de CIS Benchmark do que o Wiz  
**b)** Defender for Cloud é integrado nativamente com Microsoft Sentinel, Entra ID e Microsoft 365, sem necessidade de conectores externos  
**c)** Defender for Cloud é mais barato do que o Wiz em todos os casos  
**d)** Defender for Cloud suporta mais provedores cloud do que o Wiz  

**Gabarito: b)** A integração nativa com o ecossistema Microsoft é o diferencial do Defender for Cloud. Alertas do Defender alimentam automaticamente o Microsoft Sentinel. Identidades do Entra ID são diretamente correlacionadas. Postura M365 é visível no mesmo console. Para organizações Microsoft-first, isso elimina integrações customizadas que outras ferramentas exigiriam.

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** Uma auditoria interna do Banco Meridian identificou que a equipe de Cloud Operations criou 12 recursos AWS nos últimos 6 meses sem seguir nenhum processo de revisão de segurança. O CISO agiu e contratou você para:

1. Executar um scan CSPM completo na conta AWS de produção
2. Identificar os 5 findings mais críticos com mapeamento para BACEN 4.893
3. Estimar o prazo e responsáveis para remediação de cada finding
4. Propor uma solução para prevenir que isso aconteça novamente

**Tarefa (4 perguntas, 10 pts cada):**

1. Descreva o comando Prowler v4 exato que você executaria, incluindo: região, compliance framework, formatos de saída e integração com Security Hub
2. Liste 5 tipos de findings CRITICAL/HIGH que são mais comuns em recursos AWS criados sem processo de segurança, com mapeamento para BACEN 4.893
3. Crie uma tabela de remediação com finding, impacto de negócio, prazo, responsável e esforço estimado
4. Proponha uma solução preventiva usando ferramentas do ecossistema do Curso 4 (não apenas CSPM)

**Gabarito:**

1. **Comando Prowler:**
```bash
prowler aws \
  --profile bancomeridian-producao \
  --region us-east-1 sa-east-1 \
  --compliance brazil_lgpd cis_aws_foundations_benchmark_v3.0 \
  --severity critical high medium \
  --output-formats html json csv \
  --security-hub \
  --output-path /tmp/audit-bacen-$(date +%Y%m%d)/
```

2. **5 findings comuns:**
   - S3 bucket com acesso público — BACEN Art. 5 + LGPD Art. 46 — dados de clientes expostos
   - IAM user sem MFA habilitado — BACEN Art. 8 — autenticação fraca em conta privilegiada
   - Security Group com porta 22/3389 aberta para 0.0.0.0/0 — BACEN Art. 5 — acesso remoto não autorizado
   - CloudTrail desabilitado em região — BACEN Art. 6 — sem auditoria de ações na conta
   - RDS instance sem criptografia em repouso — BACEN Art. 5 + LGPD Art. 46 — dados em banco sem proteção

3. **Tabela de remediação:**

| Finding | Impacto de Negócio | Prazo | Responsável | Esforço |
|:--------|:-------------------|:-----:|:-----------:|:-------:|
| S3 público com dados clientes | Multa BACEN + vazamento de dados | 24h | Cloud Ops + CISO | 2h |
| IAM user root sem MFA | Comprometimento total da conta | 24h | Cloud Admin | 1h |
| SSH 0.0.0.0/0 em produção | Acesso remoto não autorizado | 48h | Cloud Ops | 1h |
| CloudTrail desabilitado | Sem evidência para auditoria BACEN | 48h | Cloud Ops | 2h |
| RDS sem criptografia | Dados de clientes sem proteção | 7 dias | Cloud Ops + DBA | 4h |

4. **Solução preventiva:** IaC security com Checkov (módulo 3) nos pipelines de CI/CD para bloquear Terraform com misconfigurations antes do deploy. Admission Controllers no Kubernetes (Kyverno — módulo 5) para políticas preventivas. CloudFormation Guard ou AWS Config Rules para infraestrutura não-IaC.

---

*Módulo 02 — CSPM: Cloud Security Posture Management*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
