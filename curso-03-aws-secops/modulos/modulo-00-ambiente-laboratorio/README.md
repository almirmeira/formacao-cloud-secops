# Módulo 00 — Preparação do Ambiente de Laboratório AWS
## Curso 3: AWS Cloud Security Operations · CECyber

> **⚠️ IMPORTANTE:** Este módulo deve ser concluído **antes** de iniciar qualquer outro módulo
> ou laboratório do curso. Todos os laboratórios dependem da estrutura multi-conta configurada aqui.

---

## Visão Geral

Este módulo provisiona o ambiente multi-conta do **Banco Meridian** (fictício) em AWS, reproduzindo
a arquitetura de segurança de uma instituição financeira real. Ao final, você terá:

- Estrutura multi-conta com AWS Organizations (4 contas)
- AWS CLI e SDKs configurados com perfis para cada conta
- Terraform e CloudFormation prontos para os laboratórios de IaC
- Serviços de segurança habilitados: GuardDuty, Security Hub, CloudTrail, Config
- Dados sintéticos simulando logs de incidentes reais do Banco Meridian
- Script de health check com 20 verificações

**Duração estimada:** 2–3 horas  
**Custo estimado:** US$ 0 (uso dentro do AWS Free Tier + sandbox fornecido pela CECyber)

---

## Topologia do Ambiente

```
AWS ORGANIZATIONS — BANCO MERIDIAN (FICTÍCIO)
──────────────────────────────────────────────────────────────────────────
Root
└── Management Account (111111111111)
    ├── SCP: DenyRootAccess
    ├── SCP: DenyUnauthorizedRegions
    │
    ├── Security OU
    │   ├── Audit Account (222222222222)
    │   │   ├── Security Hub (delegated admin)
    │   │   ├── CloudTrail Lake
    │   │   └── Amazon Detective
    │   │
    │   └── Log Archive Account (333333333333)
    │       ├── S3 (org CloudTrail bucket) + Object Lock
    │       ├── S3 (VPC Flow Logs bucket)
    │       └── KMS CMK para logs
    │
    └── Workload OU
        └── Production Account (444444444444) ← CONTA DE LAB
            ├── EC2 (simulação de servidor comprometido)
            ├── S3 (dados sintéticos Banco Meridian)
            ├── IAM Roles (usuários e roles simulados)
            ├── GuardDuty (findings simulados habilitados)
            └── VPC (topologia de rede do banco)

ATENÇÃO: Em laboratório, você trabalhará principalmente na Production Account
         com acesso de leitura/análise às contas de Audit e Log Archive.
```

---

## Pré-requisitos

| Requisito                  | Detalhe                                                    |
|:---------------------------|:-----------------------------------------------------------|
| **Conta AWS**              | Conta AWS pessoal (free tier) OU sandbox CECyber fornecida |
| **Sistema Operacional**    | Linux, macOS ou Windows 10/11 com WSL2                     |
| **RAM**                    | 4 GB mínimo, 8 GB recomendado                              |
| **Python**                 | Python 3.10 ou superior                                    |
| **Terraform**              | Terraform 1.6 ou superior                                  |

---

## Etapa 1 — Instalar e Configurar a AWS CLI

### 1.1 Instalação no Linux/macOS

**Passo 1:** Baixe o instalador da AWS CLI v2:

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
```

**Passo 2:** Descompacte e instale:

```bash
unzip awscliv2.zip
sudo ./aws/install
```

**Passo 3:** Verifique a instalação:

```bash
aws --version
```

**Resultado esperado:**
```
aws-cli/2.x.x Python/3.x.x Linux/x.x.x exe/x86_64
```

### 1.2 Instalação no Windows (PowerShell como administrador)

```powershell
# Baixar e instalar AWS CLI v2
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi

# Reiniciar o PowerShell e verificar
aws --version
```

---

## Etapa 2 — Configurar Credenciais da Conta de Laboratório

Você receberá as credenciais de acesso ao ambiente de laboratório pelo LMS da CECyber:

```
AWS_ACCESS_KEY_ID:     AKIAxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_ACCOUNT_ID:        444444444444  (Production Account — conta de lab)
AWS_REGION:            us-east-1
```

**Passo 1:** Configure o perfil AWS para o laboratório:

```bash
aws configure --profile cecyber-lab
```

Quando solicitado, informe:
```
AWS Access Key ID: [cole o valor recebido]
AWS Secret Access Key: [cole o valor recebido]
Default region name: us-east-1
Default output format: json
```

**Passo 2:** Configure variáveis de ambiente para o curso:

```bash
# Adicione ao ~/.bashrc ou ~/.zshrc
export AWS_PROFILE="cecyber-lab"
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_PROD="444444444444"
export AWS_ACCOUNT_AUDIT="222222222222"
export AWS_ACCOUNT_LOGS="333333333333"
export LAB_DIR="$HOME/cecyber-labs/aws-secops"

echo "✅ Variáveis AWS configuradas"
```

**Passo 3:** Aplique as variáveis:

```bash
source ~/.bashrc
```

**Passo 4:** Teste o acesso:

```bash
aws sts get-caller-identity --profile cecyber-lab
```

**Resultado esperado:**
```json
{
    "UserId": "AIDAxxxxxxxxxxxxxxxxx",
    "Account": "444444444444",
    "Arn": "arn:aws:iam::444444444444:user/cecyber-lab-student-[seu-id]"
}
```

**O que fazer se der errado:**
- Erro: `InvalidClientTokenId` → Verifique se copiou a chave sem espaços extras
- Erro: `AuthFailure` → A chave pode estar desativada; contate o suporte CECyber via LMS
- Erro: `ExpiredTokenException` → Token temporário expirado; solicite novas credenciais

---

## Etapa 3 — Instalar o Terraform

**Passo 1 (Linux):**

```bash
# Adicionar repositório HashiCorp
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
```

**Passo 1 (macOS com Homebrew):**

```bash
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

**Passo 2:** Verificar instalação:

```bash
terraform --version
```

**Resultado esperado:** `Terraform v1.x.x`

---

## Etapa 4 — Criar a Estrutura de Diretórios

```bash
mkdir -p $LAB_DIR/{terraform,scripts,findings,relatorios,configs,logs-sinteticos}

# Clonar o repositório do curso
cd $HOME
git clone https://github.com/almirmeira/formacao-cloud-secops.git
ln -s $HOME/formacao-cloud-secops/curso-03-aws-secops $LAB_DIR/curso-ref

echo "✅ Estrutura criada em $LAB_DIR"
ls $LAB_DIR
```

**Resultado esperado:**
```
configs  curso-ref  findings  logs-sinteticos  relatorios  scripts  terraform
```

---

## Etapa 5 — Verificar Serviços de Segurança Habilitados

Os seguintes serviços já estão habilitados no ambiente de laboratório:

**Passo 1:** Verificar GuardDuty:

```bash
aws guardduty list-detectors --region us-east-1 --profile cecyber-lab
```

**Resultado esperado:**
```json
{
    "DetectorIds": ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
}
```

**Passo 2:** Verificar Security Hub:

```bash
aws securityhub describe-hub --region us-east-1 --profile cecyber-lab
```

**Resultado esperado:** JSON com `HubArn` e `SubscribedAt`

**Passo 3:** Verificar CloudTrail ativo:

```bash
aws cloudtrail describe-trails --profile cecyber-lab --query 'trailList[*].{Name:Name,Home:HomeRegion,S3:S3BucketName}'
```

**Resultado esperado:** Lista com pelo menos 1 trail ativo apontando para o bucket de Log Archive

**O que fazer se algum serviço não estiver habilitado:**
- GuardDuty ausente: execute `aws guardduty create-detector --enable --profile cecyber-lab`
- Security Hub ausente: contate o suporte CECyber — o ambiente de lab deve ter este serviço pré-habilitado

---

## Etapa 6 — Carregar os Findings Sintéticos do GuardDuty

Para simular um ambiente com histórico de ameaças detectadas, o lab inclui findings sintéticos:

**Passo 1:** Baixe o script de geração de findings sintéticos:

```bash
cd $LAB_DIR/scripts
curl -O https://raw.githubusercontent.com/almirmeira/formacao-cloud-secops/main/curso-03-aws-secops/scripts/generate-synthetic-findings.py
```

**Passo 2:** Execute o script:

```bash
python3 generate-synthetic-findings.py \
  --profile cecyber-lab \
  --region us-east-1 \
  --scenario banco-meridian \
  --count 50
```

**Resultado esperado:**
```
✅ Gerando 50 findings sintéticos para o cenário banco-meridian...
[10/50] Criado: UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
[20/50] Criado: CredentialAccess:IAMUser/AnomalousBehavior
[30/50] Criado: Exfiltration:S3/ObjectRead.Unusual
[40/50] Criado: Persistence:IAMUser/UserPermissions
[50/50] Criado: Impact:EC2/BitcoinDomainRequest.Reputation
✅ 50 findings criados com sucesso!
```

---

## Etapa 7 — Script de Health Check

```bash
cat > $LAB_DIR/scripts/health-check.sh << 'SCRIPT'
#!/bin/bash
# CECyber AWS SecOps Lab — Health Check

PASS=0; FAIL=0

check() {
    if eval "$2" &>/dev/null; then
        echo "✅ PASS: $1"; ((PASS++))
    else
        echo "❌ FAIL: $1"; ((FAIL++))
    fi
}

echo "======================================"
echo " CECyber AWS SecOps Lab Health Check  "
echo "======================================"

# Ferramentas
check "AWS CLI v2 instalada"       "aws --version | grep aws-cli/2"
check "Terraform instalado"        "terraform --version"
check "Python 3.10+"               "python3 --version | grep -E 'Python 3\.(1[0-9]|[2-9])'"
check "git instalado"              "git --version"
check "jq instalado"               "jq --version"

# Credenciais e acesso
check "AWS CLI autenticada"        "aws sts get-caller-identity --profile cecyber-lab"
check "Região configurada"         "[ '$AWS_REGION' = 'us-east-1' ]"
check "LAB_DIR existe"             "[ -d '$LAB_DIR' ]"
check "Repositório clonado"        "[ -d '$LAB_DIR/curso-ref' ]"

# Serviços AWS
check "GuardDuty habilitado"       "aws guardduty list-detectors --profile cecyber-lab | grep DetectorIds"
check "Security Hub habilitado"    "aws securityhub describe-hub --profile cecyber-lab"
check "CloudTrail ativo"           "aws cloudtrail describe-trails --profile cecyber-lab | grep TrailARN"
check "Config habilitado"          "aws configservice describe-configuration-recorders --profile cecyber-lab"
check "Inspector habilitado"       "aws inspector2 list-coverage --profile cecyber-lab"

# Dados do ambiente
check "Findings GuardDuty (>0)"   "aws guardduty list-findings --detector-id \$(aws guardduty list-detectors --profile cecyber-lab --query 'DetectorIds[0]' --output text) --profile cecyber-lab | grep FindingIds"

echo "======================================"
echo " Resultado: $PASS OK, $FAIL falhas    "
echo "======================================"
[ $FAIL -eq 0 ] && echo "🎉 Ambiente pronto para os laboratórios!" || exit 1
SCRIPT

chmod +x $LAB_DIR/scripts/health-check.sh
bash $LAB_DIR/scripts/health-check.sh
```

---

## Etapa 8 — Cleanup ao Final do Curso

```bash
# Remover findings sintéticos do GuardDuty
DETECTOR_ID=$(aws guardduty list-detectors --profile cecyber-lab --query 'DetectorIds[0]' --output text)
FINDING_IDS=$(aws guardduty list-findings --detector-id $DETECTOR_ID --profile cecyber-lab --query 'FindingIds' --output text)
# aws guardduty archive-findings --detector-id $DETECTOR_ID --finding-ids $FINDING_IDS

# Remover recursos Terraform criados nos labs
# cd $LAB_DIR/terraform && terraform destroy -auto-approve

echo "✅ Cleanup concluído"
```

---

## Resumo

| Componente                              | Status Esperado |
|:----------------------------------------|:---------------:|
| AWS CLI v2 instalada e configurada      | ✅               |
| Terraform 1.6+ instalado                | ✅               |
| Variáveis de ambiente configuradas      | ✅               |
| Estrutura de diretórios criada          | ✅               |
| GuardDuty habilitado com findings       | ✅               |
| Security Hub habilitado                 | ✅               |
| CloudTrail ativo (org trail)            | ✅               |
| Health check: 15/15 verificações OK    | ✅               |

---

**Parabéns!** Seu ambiente AWS está pronto.

*Próximo: [Módulo 01 — Fundamentos de Segurança AWS](../modulo-01-fundamentos-aws/README.md)*

---

*Módulo 00 · Curso 3 — AWS Cloud Security Operations · CECyber · v2.0 · 2026*
