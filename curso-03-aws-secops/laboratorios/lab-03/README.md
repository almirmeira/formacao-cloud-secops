# Lab 03 — GuardDuty Organization-Wide: Deploy e Análise de Findings

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 03 — Amazon GuardDuty
**Nível:** Intermediário/Avançado

---

## Contexto

Você precisa habilitar o Amazon GuardDuty em todas as contas do Banco Meridian com delegated administration para a Audit Account, e depois analisar 5 findings simulados que representam ameaças reais. Para cada finding, você vai identificar o risco, investigar usando o Detective e CloudTrail, e propor a resposta correta.

---

## Pré-requisitos

- AWS Organizations configurado com OUs (Lab 01 concluído)
- Acesso às contas Management (111111111111) e Audit (222222222222)
- AWS CLI e console disponíveis

---

## Seção 1 — Deploy GuardDuty Organization-Wide

**Passo 1.1** — Habilitar GuardDuty na Management Account:

```bash
# Habilitar detector na Management Account
DETECTOR_MGMT=$(aws guardduty create-detector \
  --enable \
  --region sa-east-1 \
  --query 'DetectorId' \
  --output text)

echo "Detector Management Account: $DETECTOR_MGMT"

# Configurar delegated administrator
aws guardduty enable-organization-admin-account \
  --admin-account-id 222222222222 \
  --region sa-east-1

echo "Delegated Admin configurado para conta Audit (222222222222)"
```

**Passo 1.2** — Na Audit Account, configurar auto-enable:

```bash
# Assumir role na Audit Account
AUDIT_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/OrganizationAccountAccessRole \
  --role-session-name GuardDutyAdmin \
  --query 'Credentials' \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['SessionToken'])")

# Obter detector ID da Audit Account
DETECTOR_AUDIT=$(aws guardduty list-detectors \
  --region sa-east-1 \
  --query 'DetectorIds[0]' \
  --output text)

echo "Detector Audit Account: $DETECTOR_AUDIT"

# Configurar auto-enable para todas as features em novas contas
aws guardduty update-organization-configuration \
  --detector-id $DETECTOR_AUDIT \
  --auto-enable ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "MALWARE_PROTECTION", "AutoEnable": "ALL"},
    {"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "ALL"},
    {"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]' \
  --region sa-east-1

echo "Auto-enable configurado"
```

**Passo 1.3** — Verificar membros:

```bash
aws guardduty list-members \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --query 'Members[].{Conta:AccountId,Status:RelationshipStatus,Features:DetectorId}' \
  --output table
```

**Resultado Esperado:**

```
Conta         Status     Features
444444444444  Enabled    Enabled
333333333333  Enabled    Enabled
```

**Troubleshooting:**
- Conta não aparece como membro: verificar se a conta está na organização correta
- `DetectorAlreadyExists`: o detector já existe — usar `list-detectors` para obter o ID existente

---

## Seção 2 — Gerar Sample Findings

**Passo 2.1** — Gerar findings de exemplo:

```bash
# Gerar TODOS os tipos de sample findings
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-types \
    "CryptoCurrency:EC2/BitcoinTool.B" \
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" \
    "Exfiltration:S3/AnomalousBehavior" \
    "Recon:EC2/PortProbeUnprotectedPort" \
    "Malware:EC2/MaliciousFile"

echo "Sample findings gerados — aguardar 30 segundos"
sleep 30
```

**Passo 2.2** — Listar os findings gerados:

```bash
aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "sample": {
        "Equals": ["true"]
      }
    }
  }' \
  --query 'FindingIds' \
  --output text
```

---

## Seção 3 — Análise do Finding 1: CryptoCurrency EC2

**Passo 3.1** — Obter detalhes do finding de cryptomining:

```bash
# Filtrar o finding de cryptomining
CRYPTO_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["CryptoCurrency:EC2/BitcoinTool.B"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

# Obter detalhes completos
aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $CRYPTO_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Conta:AccountId,
    Regiao:Region,
    Instancia:Resource.InstanceDetails.InstanceId,
    IP_Destino:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,
    Descricao:Description
  }' \
  --output json
```

**Análise Esperada:**

| Campo | Valor | Interpretação |
|---|---|---|
| Tipo | `CryptoCurrency:EC2/BitcoinTool.B` | Instância comunicando com domínio/IP de pool de mineração |
| Severidade | HIGH (7.5) | Comprometimento confirmado — resposta imediata |
| Instância | `i-XXXXXXXXX` | Instância afetada |
| IP Destino | IP de pool de criptomoeda | Servidor de mineração conhecido |

**Resposta Correta para Cryptomining:**

```bash
# 1. Isolar instância imediatamente
echo "AÇÃO: Criar SG de quarentena e mover instância"

# 2. Criar snapshot de evidência
echo "AÇÃO: aws ec2 create-snapshot --volume-id <VOL_ID> --description 'Evidência Forense - Cryptomining'"

# 3. Analisar via CloudTrail Lake
echo "QUERY: SELECT * FROM EDS WHERE resources[0].arn LIKE '%<INSTANCE_ID>%' AND eventTime > timestamp '48 hours ago' ORDER BY eventTime DESC"
```

---

## Seção 4 — Análise do Finding 2: IAM Credential Exfiltration

**Passo 4.1** — Obter detalhes do finding de exfiltração de credenciais:

```bash
CRED_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $CRED_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Usuario:Resource.AccessKeyDetails.UserName,
    AccessKeyId:Resource.AccessKeyDetails.AccessKeyId,
    IP_Externo:Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4,
    Pais:Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryName,
    API_Chamada:Service.Action.AwsApiCallAction.Api
  }' \
  --output json
```

**Checklist de Resposta:**

- [ ] Desabilitar access key comprometida: `aws iam update-access-key --status Inactive`
- [ ] Verificar quais ações foram executadas: CloudTrail Lake query por `accessKeyId`
- [ ] Verificar se novos usuários foram criados: CloudTrail query por `CreateUser`
- [ ] Verificar acesso a dados sensíveis: S3 Data Events com o mesmo `accessKeyId`
- [ ] Verificar se há novas access keys criadas pela identidade comprometida

---

## Seção 5 — Análise do Finding 3: S3 Exfiltration

**Passo 5.1** — Analisar finding de exfiltração via S3:

```bash
S3_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Exfiltration:S3/AnomalousBehavior"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $S3_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Bucket:Resource.S3BucketDetails[0].Name,
    Operacao:Service.Action.S3BucketAction.RequestParameters.RequestMethod,
    API:Service.Action.AwsApiCallAction.Api,
    Descricao:Description
  }' \
  --output json
```

**Questões de Investigação:**

1. Qual era o volume normal de downloads desse bucket? (comparar com baseline ML do GuardDuty)
2. Quais objetos específicos foram acessados? (S3 Data Events no CloudTrail)
3. O IP de origem é interno ou externo?
4. Há outros buckets acessados pelo mesmo IP/identidade?

---

## Seção 6 — Análise do Finding 4: Port Probe (LOW)

**Passo 6.1** — Analisar e criar suppression rule:

```bash
PORT_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

# Verificar o IP de origem do probe
aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $PORT_FINDING_ID \
  --query 'Findings[0].Service.Action.PortProbeAction.PortProbeDetails[0].RemoteIpDetails'
```

**Passo 6.2** — Criar suppression rule para scanners autorizados:

```bash
# Criar suppression rule para o scanner de vulnerabilidades Qualys
aws guardduty create-filter \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --name "AuthorizedVulnerabilityScanner-Qualys" \
  --description "Suprimir port probes do scanner Qualys autorizado - IP: 203.0.113.50" \
  --action ARCHIVE \
  --rank 1 \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Equals": ["Recon:EC2/PortProbeUnprotectedPort"]
      },
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4": {
        "Equals": ["203.0.113.50"]
      }
    }
  }'

echo "Suppression rule criada para Qualys"
```

**Troubleshooting:**
- `BadRequestException`: verificar sintaxe do JSON das finding criteria
- A suppression rule aplica apenas a findings FUTUROS — findings existentes precisam ser arquivados manualmente

---

## Seção 7 — Configurar EventBridge para Resposta Automática

**Passo 7.1** — Criar regra EventBridge para findings HIGH:

```bash
# Criar SNS topic para notificações (se não existir)
SNS_ARN=$(aws sns create-topic \
  --name MeridianSecurityAlerts-HIGH \
  --region sa-east-1 \
  --query 'TopicArn' \
  --output text)

aws sns subscribe \
  --topic-arn $SNS_ARN \
  --protocol email \
  --notification-endpoint "secops@bancomeridian.com.br"

# Criar regra EventBridge
aws events put-rule \
  --name "MeridianGuardDutyHighSeverity" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}]
    }
  }' \
  --state ENABLED \
  --description "Roteamento de findings GuardDuty HIGH para SNS" \
  --region sa-east-1

# Adicionar SNS como target
aws events put-targets \
  --rule "MeridianGuardDutyHighSeverity" \
  --region sa-east-1 \
  --targets '[{
    "Id": "SNSHighAlert",
    "Arn": "'$SNS_ARN'",
    "InputTransformer": {
      "InputPathsMap": {
        "severity": "$.detail.severity",
        "type": "$.detail.type",
        "account": "$.account",
        "region": "$.region"
      },
      "InputTemplate": "\"[ALERTA GuardDuty HIGH] Tipo: <type> | Severidade: <severity> | Conta: <account> | Região: <region>\""
    }
  }]'

echo "EventBridge rule configurada"
```

---

## Seção 8 — Relatório de Findings e Análise

```python
import boto3
import json
from datetime import datetime, timezone

def analisar_findings_guardduty(detector_id, region='sa-east-1'):
    gd = boto3.client('guardduty', region_name=region)
    
    # Listar todos os findings ativos (exceto sample)
    response = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'service.archived': {'Equals': ['false']},
                'sample': {'Equals': ['false']}
            }
        },
        SortCriteria={'AttributeName': 'severity', 'OrderBy': 'DESC'},
        MaxResults=50
    )
    
    finding_ids = response.get('FindingIds', [])
    
    if not finding_ids:
        print("Nenhum finding ativo encontrado (excluindo samples)")
        return
    
    findings = gd.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']
    
    # Agrupar por severidade
    por_severidade = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
    
    for f in findings:
        sev = f.get('Severity', 0)
        if sev >= 7.0:
            por_severidade['HIGH'].append(f)
        elif sev >= 4.0:
            por_severidade['MEDIUM'].append(f)
        else:
            por_severidade['LOW'].append(f)
    
    print(f"\n=== Relatório GuardDuty — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ===")
    print(f"Total de findings ativos: {len(findings)}")
    print(f"HIGH: {len(por_severidade['HIGH'])}")
    print(f"MEDIUM: {len(por_severidade['MEDIUM'])}")
    print(f"LOW: {len(por_severidade['LOW'])}")
    
    print("\n--- Findings HIGH (resposta imediata) ---")
    for f in por_severidade['HIGH']:
        print(f"  [HIGH] {f['Type']} | Conta: {f['AccountId']} | {f['CreatedAt']}")
    
    print("\n--- Findings MEDIUM (investigar em 24h) ---")
    for f in por_severidade['MEDIUM']:
        print(f"  [MED] {f['Type']} | Conta: {f['AccountId']}")

# Exemplo de uso (requer DETECTOR_ID real)
# analisar_findings_guardduty('DETECTOR_ID_AQUI')
print("Script de análise pronto — executar com detector_id real")
```

---

## Gabarito — Respostas Corretas para os 5 Findings

| Finding | Tipo | Severidade | Resposta Correta | Urgência |
|---|---|---|---|---|
| 1 — Cryptomining | `CryptoCurrency:EC2/BitcoinTool.B` | HIGH | Isolar EC2, snapshot forense, análise de vetor inicial, terminate | IMEDIATA (minutos) |
| 2 — Cred Exfiltration | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | HIGH | Revogar credenciais, deny policy, CloudTrail investigation | IMEDIATA (minutos) |
| 3 — S3 Exfiltration | `Exfiltration:S3/AnomalousBehavior` | HIGH | Bloquear acesso S3, identificar dados expostos, notificar DPO | IMEDIATA (horas) |
| 4 — Port Probe | `Recon:EC2/PortProbeUnprotectedPort` | LOW | Verificar SGs; criar suppression se scanner autorizado | SEMANAL |
| 5 — Malware EC2 | `Malware:EC2/MaliciousFile` | HIGH | Isolar EC2 (snapshot já feito pelo GuardDuty), analisar hash do arquivo | IMEDIATA (minutos) |

**Critérios de Aprovação:**
- Seções 1-5 concluídas com findings analisados corretamente: APROVADO
- Suppression rule criada com critérios específicos: APROVADO
- EventBridge rule configurada e SNS ativo: APROVADO
