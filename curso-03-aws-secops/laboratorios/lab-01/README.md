# Lab 01 — Organizations e SCPs: Governança Multi-Conta

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 01 — Fundamentos AWS Security
**Nível:** Intermediário

---

## Contexto

Você foi designado como Security Engineer do Banco Meridian para implementar a estrutura de governança multi-conta em AWS Organizations. A organização atualmente tem 4 contas AWS mas sem estrutura de OUs ou SCPs — todos os usuários têm permissões amplas sem controles preventivos.

Seu objetivo é criar a estrutura organizacional correta, as OUs adequadas e as 4 SCPs preventivas críticas, garantindo que cada SCP seja testada e validada.

---

## Pré-requisitos

- Conta AWS com AWS Organizations habilitado (Management Account)
- AWS CLI configurado com credenciais da Management Account
- Python 3.8+ e Boto3 instalados
- Acesso ao console AWS (https://console.aws.amazon.com)

---

## Seção 1 — Exploração do Ambiente Atual

**Objetivo:** Entender o estado atual da organização antes de qualquer mudança.

**Passo 1.1** — Verificar estrutura atual da organização:

```bash
# Listar a estrutura atual
aws organizations describe-organization
aws organizations list-roots
aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text)
```

**Resultado Esperado:**
```json
{
  "Organization": {
    "MasterAccountId": "111111111111",
    "AvailablePolicyTypes": [
      {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
    ]
  }
}
```

**Troubleshooting:**
- Se `AvailablePolicyTypes` estiver vazio: habilitar SCPs no console Organizations → Policies → Service control policies → Enable
- Se receber `AWSOrganizationsNotInUseException`: a organização não foi criada ainda — criar em Organizations → Create organization

---

**Passo 1.2** — Listar todas as contas atuais:

```bash
aws organizations list-accounts \
  --query 'Accounts[].{Nome:Name,ID:Id,Email:Email,Status:Status}' \
  --output table
```

**Resultado Esperado:**

```
ID             Nome              Email                        Status
111111111111   Meridian-Mgmt     mgmt@bancomeridian.com.br    ACTIVE
222222222222   Meridian-Audit    audit@bancomeridian.com.br   ACTIVE
333333333333   Meridian-Logs     logs@bancomeridian.com.br    ACTIVE
444444444444   Meridian-Prod     prod@bancomeridian.com.br    ACTIVE
```

---

## Seção 2 — Criação das OUs

**Objetivo:** Criar a hierarquia de Organizational Units.

**Passo 2.1** — Obter o ID do Root:

```bash
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Root ID: $ROOT_ID"
```

**Passo 2.2** — Criar as 4 OUs principais:

```bash
# OU: Security
OU_SECURITY=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Security" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Security criada: $OU_SECURITY"

# OU: Production
OU_PRODUCTION=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Production" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Production criada: $OU_PRODUCTION"

# OU: Development
OU_DEVELOPMENT=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Development" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Development criada: $OU_DEVELOPMENT"

# OU: Sandbox
OU_SANDBOX=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Sandbox" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Sandbox criada: $OU_SANDBOX"
```

**Resultado Esperado:** 4 mensagens confirmando criação das OUs com IDs no formato `ou-xxxx-xxxxxxxx`.

**Passo 2.3** — Mover contas para as OUs corretas:

```bash
# Mover Audit Account para OU Security
aws organizations move-account \
  --account-id 222222222222 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_SECURITY

# Mover Log Archive Account para OU Security
aws organizations move-account \
  --account-id 333333333333 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_SECURITY

# Mover Production Account para OU Production
aws organizations move-account \
  --account-id 444444444444 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_PRODUCTION
```

**Verificação:**

```bash
# Confirmar que as contas foram movidas corretamente
aws organizations list-children \
  --parent-id $OU_SECURITY \
  --child-type ACCOUNT \
  --query 'Children[].Id'
# Esperado: ["222222222222", "333333333333"]

aws organizations list-children \
  --parent-id $OU_PRODUCTION \
  --child-type ACCOUNT \
  --query 'Children[].Id'
# Esperado: ["444444444444"]
```

**Troubleshooting:**
- `AccountNotFoundException`: verificar se o Account ID está correto
- `SourceParentNotFoundException`: a conta pode já estar em uma OU diferente — usar `list-parents` para encontrar o parent atual

---

## Seção 3 — Criação das SCPs

**Objetivo:** Criar as 4 SCPs preventivas críticas do Banco Meridian.

**Passo 3.1** — Criar arquivo JSON de cada SCP:

```bash
# SCP 1: DenyRootAccess
cat > /tmp/scp-deny-root.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
EOF

# SCP 2: DenyNonApprovedRegions
cat > /tmp/scp-deny-regions.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*", "iam:*", "route53:*", "support:*",
        "sts:*", "globalaccelerator:*", "waf:*", "budgets:*",
        "organizations:*", "account:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["sa-east-1", "us-east-1", "us-east-2"]
        }
      }
    }
  ]
}
EOF

# SCP 3: DenyUnencryptedS3
cat > /tmp/scp-deny-unencrypted-s3.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3PutWithoutEncryption",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]
        }
      }
    }
  ]
}
EOF

# SCP 4: DenyDisableCloudTrail
cat > /tmp/scp-protect-cloudtrail.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailModification",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"
      ],
      "Resource": "*"
    }
  ]
}
EOF
```

**Passo 3.2** — Criar as SCPs na organização:

```bash
# Criar SCP 1
SCP_ROOT_ID=$(aws organizations create-policy \
  --name "DenyRootAccess" \
  --description "Nega uso da conta root em todas as member accounts - BACEN 4.893" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-root.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyRootAccess: $SCP_ROOT_ID"

# Criar SCP 2
SCP_REGIONS_ID=$(aws organizations create-policy \
  --name "DenyNonApprovedRegions" \
  --description "Bloqueia uso de regiões nao aprovadas pelo Banco Meridian" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-regions.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyNonApprovedRegions: $SCP_REGIONS_ID"

# Criar SCP 3
SCP_S3_ID=$(aws organizations create-policy \
  --name "DenyUnencryptedS3" \
  --description "Exige criptografia em todos os objetos S3 - BACEN 4.893 Art.6" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-unencrypted-s3.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyUnencryptedS3: $SCP_S3_ID"

# Criar SCP 4
SCP_CT_ID=$(aws organizations create-policy \
  --name "ProtectCloudTrail" \
  --description "Protege CloudTrail de desabilitacao ou modificacao" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-protect-cloudtrail.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP ProtectCloudTrail: $SCP_CT_ID"
```

**Resultado Esperado:** 4 IDs de SCPs no formato `p-xxxxxxxx`.

---

## Seção 4 — Aplicação das SCPs às OUs

**Objetivo:** Anexar as SCPs nas OUs corretas.

**Passo 4.1** — Aplicar SCPs na Root e nas OUs:

```bash
# DenyRootAccess — aplicar na Root (afeta TODAS as contas membro)
aws organizations attach-policy \
  --policy-id $SCP_ROOT_ID \
  --target-id $ROOT_ID

# DenyNonApprovedRegions — aplicar na Root
aws organizations attach-policy \
  --policy-id $SCP_REGIONS_ID \
  --target-id $ROOT_ID

# DenyUnencryptedS3 — aplicar na Root
aws organizations attach-policy \
  --policy-id $SCP_S3_ID \
  --target-id $ROOT_ID

# ProtectCloudTrail — aplicar na Root
aws organizations attach-policy \
  --policy-id $SCP_CT_ID \
  --target-id $ROOT_ID
```

**Passo 4.2** — Verificar políticas aplicadas:

```bash
aws organizations list-policies-for-target \
  --target-id $ROOT_ID \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].{Nome:Name,ID:Id}' \
  --output table
```

**Resultado Esperado:**

```
Nome                    ID
FullAWSAccess           p-FullAWSAccess
DenyRootAccess          p-xxxxxxxx
DenyNonApprovedRegions  p-yyyyyyyy
DenyUnencryptedS3       p-zzzzzzzz
ProtectCloudTrail       p-aaaaaaaa
```

---

## Seção 5 — Testes de Validação das SCPs

**Objetivo:** Confirmar que cada SCP está bloqueando as ações proibidas.

**Passo 5.1** — Testar DenyNonApprovedRegions (na conta Production):

```bash
# Na conta Production (444444444444):
# Tentar criar instância EC2 em ap-southeast-1 (Singapura — não aprovada)
aws ec2 describe-instances --region ap-southeast-1

# Resultado Esperado:
# An error occurred (UnauthorizedAccess) when calling the DescribeInstances operation:
# Explicit deny in a service control policy
```

**Passo 5.2** — Testar DenyUnencryptedS3:

```bash
# Tentar fazer upload sem criptografia
echo "teste" > /tmp/teste.txt
aws s3 cp /tmp/teste.txt s3://test-bucket-meridian/teste.txt

# Resultado Esperado:
# upload failed: An error occurred (AccessDenied) when calling the PutObject operation

# Tentar com SSE-S3 (deve funcionar)
aws s3 cp /tmp/teste.txt s3://test-bucket-meridian/teste-encrypted.txt \
  --sse AES256

# Resultado Esperado: upload: /tmp/teste.txt to s3://test-bucket-meridian/teste-encrypted.txt
```

**Passo 5.3** — Testar ProtectCloudTrail:

```bash
# Tentar parar o CloudTrail
aws cloudtrail stop-logging --name "test-trail"

# Resultado Esperado:
# An error occurred (AccessDeniedException): Explicit deny in a service control policy
```

**Troubleshooting:**
- SCP não está bloqueando: verificar se FullAWSAccess ainda está aplicado na Root — isso é necessário para que as SCPs de deny funcionem (SCPs são barreiras, não concessões)
- Erro de permissão IAM (não SCP): verificar se o usuário de teste tem a permissão IAM básica para a ação

---

## Seção 6 — Policy Simulator com SCPs

**Passo 6.1** — Usar o IAM Policy Simulator para verificar o efeito das SCPs:

```bash
# Verificar se SCP bloqueia DeleteTrail
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/admin-test \
  --action-names cloudtrail:DeleteTrail \
  --resource-arns "*" \
  --query 'EvaluationResults[0].{Acao:EvalActionName,Decisao:EvalDecision,Razao:EvalDecisionDetails}'
```

**Resultado Esperado:**

```json
{
  "Acao": "cloudtrail:DeleteTrail",
  "Decisao": "explicitDeny",
  "Razao": {"ServiceControlPolicyDecisionDetail": {"AllowedByOrganizations": false}}
}
```

---

## Seção 7 — Documentação e Relatório

**Passo 7.1** — Gerar relatório de conformidade das SCPs:

```python
import boto3
import json
from datetime import datetime

def gerar_relatorio_scps():
    organizations = boto3.client('organizations')
    
    relatorio = {
        'data_geracao': datetime.utcnow().isoformat(),
        'organizacao': organizations.describe_organization()['Organization']['Id'],
        'scps': []
    }
    
    # Listar todas as SCPs
    paginator = organizations.get_paginator('list_policies')
    for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
        for policy in page['Policies']:
            policy_detail = organizations.describe_policy(PolicyId=policy['Id'])['Policy']
            
            # Listar targets (onde está aplicada)
            targets = organizations.list_targets_for_policy(
                PolicyId=policy['Id']
            )['Targets']
            
            relatorio['scps'].append({
                'nome': policy['Name'],
                'id': policy['Id'],
                'descricao': policy['Description'],
                'aplicada_em': [t['Name'] for t in targets]
            })
    
    print(json.dumps(relatorio, indent=2, ensure_ascii=False))
    return relatorio

gerar_relatorio_scps()
```

---

## Seção 8 — Cleanup (Ambiente de Lab)

**Passo 8.1** — Remover SCPs e OUs criadas (apenas para ambientes de lab):

```bash
# Desanexar SCPs antes de excluir
aws organizations detach-policy --policy-id $SCP_ROOT_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_REGIONS_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_S3_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_CT_ID --target-id $ROOT_ID

# Deletar SCPs
aws organizations delete-policy --policy-id $SCP_ROOT_ID
aws organizations delete-policy --policy-id $SCP_REGIONS_ID
aws organizations delete-policy --policy-id $SCP_S3_ID
aws organizations delete-policy --policy-id $SCP_CT_ID

# Mover contas de volta para Root antes de excluir OUs
aws organizations move-account --account-id 222222222222 --source-parent-id $OU_SECURITY --destination-parent-id $ROOT_ID
aws organizations move-account --account-id 333333333333 --source-parent-id $OU_SECURITY --destination-parent-id $ROOT_ID
aws organizations move-account --account-id 444444444444 --source-parent-id $OU_PRODUCTION --destination-parent-id $ROOT_ID

# Deletar OUs (apenas após remover todas as contas e OUs filhas)
aws organizations delete-organizational-unit --organizational-unit-id $OU_SECURITY
aws organizations delete-organizational-unit --organizational-unit-id $OU_PRODUCTION
aws organizations delete-organizational-unit --organizational-unit-id $OU_DEVELOPMENT
aws organizations delete-organizational-unit --organizational-unit-id $OU_SANDBOX
```

---

## Gabarito — SCPs Funcionais Completas

### SCP Final: DenyRootAccess

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

**Aplicar em:** Root (afeta todas as contas exceto Management Account)

### SCP Final: DenyNonApprovedRegions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*", "iam:*", "route53:*", "support:*",
        "sts:*", "globalaccelerator:*", "waf:*", "budgets:*",
        "organizations:*", "account:*", "cur:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["sa-east-1", "us-east-1", "us-east-2"]
        }
      }
    }
  ]
}
```

**Resultado Esperado no Teste:** Qualquer ação de serviço regional em ap-southeast-1 retorna `Explicit deny in a service control policy`.
