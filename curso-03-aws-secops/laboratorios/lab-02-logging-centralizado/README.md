# Lab 02 — Logging Centralizado: CloudTrail + CloudTrail Lake

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 02 — Logging e Monitoramento
**Nível:** Intermediário

---

## Contexto

O Banco Meridian ainda não tem logging centralizado. Cada conta gera seus próprios logs sem entrega centralizada. Você vai implementar o CloudTrail Organization Trail com S3 na conta Log Archive, configurar o CloudTrail Lake com retenção de 7 anos, e executar as 5 queries SQL de segurança críticas.

---

## Pré-requisitos

- Management Account com Organizations habilitado
- Conta Log Archive (333333333333) já criada
- AWS CLI configurado para múltiplas contas
- Acesso ao console de CloudTrail na Management Account

---

## Seção 1 — Preparação da Conta Log Archive

**Passo 1.1** — Criar o bucket S3 para logs (na conta Log Archive):

```bash
# Assumir role na conta Log Archive
aws sts assume-role \
  --role-arn arn:aws:iam::333333333333:role/OrganizationAccountAccessRole \
  --role-session-name LogArchiveSetup \
  --query 'Credentials.{AK:AccessKeyId,SAK:SecretAccessKey,ST:SessionToken}' \
  --output json

# Configurar temporariamente as credenciais
export AWS_ACCESS_KEY_ID=<AK>
export AWS_SECRET_ACCESS_KEY=<SAK>
export AWS_SESSION_TOKEN=<ST>

# Criar o bucket
aws s3api create-bucket \
  --bucket meridian-logs-333333333333 \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

echo "Bucket criado: meridian-logs-333333333333"
```

**Resultado Esperado:** Confirmação de criação do bucket.

**Passo 1.2** — Habilitar versioning e configurar segurança:

```bash
# Versioning
aws s3api put-bucket-versioning \
  --bucket meridian-logs-333333333333 \
  --versioning-configuration Status=Enabled

# Block Public Access
aws s3api put-public-access-block \
  --bucket meridian-logs-333333333333 \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Default encryption (SSE-S3 por enquanto — depois habilitar KMS)
aws s3api put-bucket-encryption \
  --bucket meridian-logs-333333333333 \
  --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": true}]}'

echo "Segurança do bucket configurada"
```

**Passo 1.3** — Aplicar Bucket Policy para CloudTrail:

```bash
cat > /tmp/bucket-policy-cloudtrail.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::meridian-logs-333333333333"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::meridian-logs-333333333333/AWSLogs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceOrgID": "o-XXXXXXXXXX"
        }
      }
    },
    {
      "Sid": "DenyDeleteAndModify",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject", "s3:DeleteBucket",
        "s3:DeleteObjectVersion", "s3:PutLifecycleConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::meridian-logs-333333333333",
        "arn:aws:s3:::meridian-logs-333333333333/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::333333333333:role/LogArchiveAdminRole"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket meridian-logs-333333333333 \
  --policy file:///tmp/bucket-policy-cloudtrail.json

echo "Bucket policy aplicada"
```

**Troubleshooting:**
- `MalformedPolicy`: verificar o JSON — usar `python3 -m json.tool` para validar
- Substituir `o-XXXXXXXXXX` pelo Organization ID real: `aws organizations describe-organization --query 'Organization.Id'`

---

## Seção 2 — Criar Organization Trail

**Passo 2.1** — Criar o trail (na Management Account):

```bash
# Voltar para credenciais da Management Account
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Criar organization trail
aws cloudtrail create-trail \
  --name "meridian-org-trail" \
  --s3-bucket-name "meridian-logs-333333333333" \
  --is-organization-trail \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events \
  --region sa-east-1

echo "Organization Trail criado"
```

**Resultado Esperado:**
```json
{
  "Name": "meridian-org-trail",
  "S3BucketName": "meridian-logs-333333333333",
  "IsMultiRegionTrail": true,
  "IsOrganizationTrail": true,
  "LogFileValidationEnabled": true
}
```

**Passo 2.2** — Habilitar Data Events para S3 e Lambda:

```bash
aws cloudtrail put-event-selectors \
  --trail-name "meridian-org-trail" \
  --advanced-event-selectors '[
    {
      "Name": "S3DataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    },
    {
      "Name": "LambdaDataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
      ]
    }
  ]' \
  --region sa-east-1
```

**Passo 2.3** — Iniciar o trail:

```bash
aws cloudtrail start-logging --name "meridian-org-trail"

# Verificar status
aws cloudtrail get-trail-status \
  --name "meridian-org-trail" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
```

**Resultado Esperado:** `{"IsLogging": true, "LatestDeliveryTime": "..."}`

---

## Seção 3 — Criar CloudWatch Metric Filters

**Passo 3.1** — Criar log group para CloudTrail:

```bash
aws logs create-log-group \
  --log-group-name "/meridian/cloudtrail/org-trail" \
  --region sa-east-1

aws logs put-retention-policy \
  --log-group-name "/meridian/cloudtrail/org-trail" \
  --retention-in-days 365
```

**Passo 3.2** — Atualizar trail para entregar logs ao CloudWatch:

```bash
# Criar role para CloudTrail escrever no CloudWatch
aws cloudtrail update-trail \
  --name "meridian-org-trail" \
  --cloud-watch-logs-log-group-arn "arn:aws:logs:sa-east-1:111111111111:log-group:/meridian/cloudtrail/org-trail:*" \
  --cloud-watch-logs-role-arn "arn:aws:iam::111111111111:role/CloudTrail_CloudWatchLogs_Role"
```

**Passo 3.3** — Criar Metric Filter para uso de Root:

```bash
aws logs put-metric-filter \
  --log-group-name "/meridian/cloudtrail/org-trail" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}' \
  --metric-transformations \
    "metricName=RootAccountUsageCount,metricNamespace=MeridianSecurity,metricValue=1,defaultValue=0"

# Criar alarme CloudWatch
aws cloudwatch put-metric-alarm \
  --alarm-name "CRITICO-RootAccountUsage" \
  --alarm-description "USO DA CONTA ROOT DETECTADO - Investigar imediatamente" \
  --metric-name "RootAccountUsageCount" \
  --namespace "MeridianSecurity" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:sa-east-1:111111111111:MeridianSecurityAlerts" \
  --treat-missing-data notBreaching

echo "Metric Filter e Alarme criados"
```

---

## Seção 4 — Criar CloudTrail Lake Event Data Store

**Passo 4.1** — Criar o Event Data Store da organização:

```bash
# Criar Event Data Store
EDS_RESPONSE=$(aws cloudtrail create-event-data-store \
  --name "MeridianOrgEventDataStore" \
  --organization-enabled \
  --multi-region-enabled \
  --termination-protection-enabled \
  --retention-period 2557 \
  --advanced-event-selectors '[
    {
      "Name": "ManagementEvents",
      "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]
    },
    {
      "Name": "S3DataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    }
  ]' \
  --region sa-east-1)

EDS_ARN=$(echo $EDS_RESPONSE | python3 -c "import json,sys; print(json.load(sys.stdin)['EventDataStoreArn'])")
echo "Event Data Store criado: $EDS_ARN"
echo "Aguardando ativação (2-3 minutos)..."
sleep 180

aws cloudtrail get-event-data-store \
  --event-data-store $EDS_ARN \
  --query 'Status'
```

**Resultado Esperado após ~3 minutos:** `"ENABLED"`

---

## Seção 5 — Executar Queries SQL de Segurança

**Objetivo:** Executar as 5 queries SQL de segurança críticas no CloudTrail Lake.

**Passo 5.1** — Query de criação de usuário IAM fora do pipeline:

```bash
EDS_ID=$(echo $EDS_ARN | sed 's/.*event-data-store\///')

aws cloudtrail start-query \
  --query-statement "
    SELECT
        eventTime,
        userIdentity.arn,
        userIdentity.type,
        sourceIPAddress,
        requestParameters.userName AS novo_usuario
    FROM ${EDS_ID}
    WHERE
        eventName = 'CreateUser'
        AND eventSource = 'iam.amazonaws.com'
        AND eventTime > timestamp '2026-01-01 00:00:00'
    ORDER BY eventTime DESC
    LIMIT 20
  " \
  --region sa-east-1

# Guardar QueryId e verificar resultado
```

**Passo 5.2** — Query de tentativas de desabilitar CloudTrail:

```bash
aws cloudtrail start-query \
  --query-statement "
    SELECT
        eventTime,
        userIdentity.arn,
        sourceIPAddress,
        eventName,
        errorCode,
        errorMessage
    FROM ${EDS_ID}
    WHERE
        eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
        AND eventSource = 'cloudtrail.amazonaws.com'
        AND eventTime > timestamp '2026-01-01 00:00:00'
    ORDER BY eventTime DESC
  " \
  --region sa-east-1
```

**Passo 5.3** — Query de Security Group aberto para 0.0.0.0/0:

```bash
aws cloudtrail start-query \
  --query-statement "
    SELECT
        eventTime,
        userIdentity.arn,
        sourceIPAddress,
        awsRegion,
        requestParameters.groupId AS sg_id,
        requestParameters
    FROM ${EDS_ID}
    WHERE
        eventName = 'AuthorizeSecurityGroupIngress'
        AND eventSource = 'ec2.amazonaws.com'
        AND eventTime > timestamp '2026-01-01 00:00:00'
    ORDER BY eventTime DESC
    LIMIT 50
  " \
  --region sa-east-1
```

**Passo 5.4** — Verificar resultado de uma query:

```bash
QUERY_ID="<ID_DA_QUERY>"
aws cloudtrail get-query-results \
  --event-data-store $EDS_ARN \
  --query-id $QUERY_ID \
  --region sa-east-1 \
  --query 'QueryResultRows[:5]'
```

**Troubleshooting:**
- Query com status `FAILED`: verificar sintaxe SQL; substituir `${EDS_ID}` pelo ID correto do Event Data Store
- `QueryRunning`: aguardar; queries no Lake podem levar 30s-5min dependendo do volume
- Sem resultados: normal em ambiente de lab recém-criado — verificar período da query (`eventTime > timestamp '...'`)

---

## Seção 6 — VPC Flow Logs

**Passo 6.1** — Habilitar VPC Flow Logs:

```bash
# Obter VPC ID da conta Production
VPC_ID=$(aws ec2 describe-vpcs \
  --region sa-east-1 \
  --query 'Vpcs[?IsDefault==`false`].VpcId | [0]' \
  --output text)

# Habilitar Flow Logs para S3 (conta Log Archive)
aws ec2 create-flow-logs \
  --region sa-east-1 \
  --resource-ids $VPC_ID \
  --resource-type VPC \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination "arn:aws:s3:::meridian-logs-333333333333/VPCFlowLogs/" \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'

echo "VPC Flow Logs habilitados para $VPC_ID"
```

**Passo 6.2** — Query de análise de tráfego suspeito no CloudWatch Logs Insights:

```bash
# Analisar Flow Logs — Top IPs externos por bytes
aws logs start-query \
  --log-group-name "/aws/vpc/flowlogs/meridian-prod" \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, srcAddr, dstAddr, bytes, action
    | filter dstAddr not like /^10\./ and action = "ACCEPT"
    | stats sum(bytes) as totalBytes by dstAddr
    | sort totalBytes desc
    | limit 10
  '
```

---

## Seção 7 — Validação do Log File Integrity

**Passo 7.1** — Verificar log file validation:

```bash
# Verificar que a validação está habilitada
aws cloudtrail get-trail \
  --name "meridian-org-trail" \
  --query 'Trail.LogFileValidationEnabled'
# Esperado: true

# Validar integridade de um digest file
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:sa-east-1:111111111111:trail/meridian-org-trail" \
  --start-time "2026-04-01T00:00:00Z" \
  --end-time "2026-04-30T23:59:59Z" \
  --verbose
```

**Resultado Esperado:** Saída listando cada log file com status `valid` ou `INVALID` (indica adulteração).

---

## Seção 8 — Relatório Final de Conformidade de Logging

```python
import boto3
import json
from datetime import datetime, timezone

def verificar_conformidade_logging():
    cloudtrail = boto3.client('cloudtrail', region_name='sa-east-1')
    s3 = boto3.client('s3')
    
    relatorio = {
        'data': datetime.now(timezone.utc).isoformat(),
        'conformidade': {}
    }
    
    # Verificar trails
    trails = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
    trail_org = next((t for t in trails if t.get('IsOrganizationTrail')), None)
    
    relatorio['conformidade']['organization_trail_existe'] = trail_org is not None
    if trail_org:
        relatorio['conformidade']['multi_region'] = trail_org.get('IsMultiRegionTrail', False)
        relatorio['conformidade']['log_validation'] = trail_org.get('LogFileValidationEnabled', False)
        relatorio['conformidade']['s3_bucket'] = trail_org.get('S3BucketName', 'N/A')
        
        status = cloudtrail.get_trail_status(Name=trail_org['TrailARN'])
        relatorio['conformidade']['trail_ativo'] = status.get('IsLogging', False)
    
    # Verificar bucket de logs
    bucket = 'meridian-logs-333333333333'
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        relatorio['conformidade']['bucket_criptografado'] = True
    except:
        relatorio['conformidade']['bucket_criptografado'] = False
    
    try:
        bl = s3.get_public_access_block(Bucket=bucket)
        config = bl['PublicAccessBlockConfiguration']
        relatorio['conformidade']['block_public_access'] = all(config.values())
    except:
        relatorio['conformidade']['block_public_access'] = False
    
    # Score final
    checks = list(relatorio['conformidade'].values())
    score = sum(1 for c in checks if c is True) / len(checks) * 100
    relatorio['score_conformidade'] = f"{score:.1f}%"
    
    print(json.dumps(relatorio, indent=2, ensure_ascii=False))
    return relatorio

verificar_conformidade_logging()
```

---

## Gabarito

### Verificação Final — Todos os Itens Devem Estar Presentes:

| Item | Comando de Verificação | Resultado Esperado |
|---|---|---|
| Organization Trail ativo | `aws cloudtrail get-trail-status --name meridian-org-trail --query IsLogging` | `true` |
| Log file validation | `aws cloudtrail get-trail --name meridian-org-trail --query Trail.LogFileValidationEnabled` | `true` |
| Multi-region | `aws cloudtrail get-trail --name meridian-org-trail --query Trail.IsMultiRegionTrail` | `true` |
| Organization trail | `aws cloudtrail get-trail --name meridian-org-trail --query Trail.IsOrganizationTrail` | `true` |
| Bucket Block Public Access | `aws s3api get-public-access-block --bucket meridian-logs-333333333333` | Todos `true` |
| Bucket encriptado | `aws s3api get-bucket-encryption --bucket meridian-logs-333333333333` | `AES256` ou `aws:kms` |
| CloudTrail Lake Event Data Store | `aws cloudtrail list-event-data-stores --query 'EventDataStores[0].Status'` | `ENABLED` |
| CloudWatch Metric Filter | `aws logs describe-metric-filters --log-group-name /meridian/cloudtrail/org-trail` | `RootAccountUsage` presente |
| CloudWatch Alarm | `aws cloudwatch describe-alarms --alarm-names CRITICO-RootAccountUsage` | Estado `OK` ou `ALARM` |
| VPC Flow Logs | `aws ec2 describe-flow-logs --query 'FlowLogs[0].FlowLogStatus'` | `ACTIVE` |
