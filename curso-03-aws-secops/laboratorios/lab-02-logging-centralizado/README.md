# Lab 02 — Logging Centralizado: CloudTrail + CloudTrail Lake

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 02 — Logging e Monitoramento
**Nível:** Intermediário

---

## Seção 1 — Contexto Situacional

O Banco Meridian opera quatro contas AWS há três anos. Durante esse tempo, o CloudTrail foi habilitado de forma independente em cada conta — cada uma com seu próprio bucket S3, sem padronização. O resultado é um ambiente de logging fragmentado onde:

- A conta Production tem CloudTrail ativo, mas os logs ficam no S3 da própria Production — o mesmo time que opera produção pode excluir seus próprios logs
- A conta de Desenvolvimento não tem CloudTrail habilitado
- A conta de Auditoria não tem acesso aos logs das outras contas
- O time de segurança precisa fazer login em cada conta separadamente para investigar incidentes

Durante uma investigação de incidente real no mês passado, levou 4 horas para o time de segurança coletar logs de 3 contas diferentes — tempo crítico perdido enquanto o incidente estava em andamento.

O BACEN (Resolução 4.893, Art. 10) exige que logs de auditoria sejam imutáveis, centralizados e com retenção mínima de 5 anos para dados financeiros. O Banco Meridian está em não conformidade com esse requisito.

---

## Seção 2 — Situação Inicial

É terça-feira, 15 de abril de 2026, 10h30. Mariana acabou de concluir a reunião semanal com o CISO e chega até você:

> "Bom dia. O CISO pediu para priorizar a implementação de logging centralizado esta semana. Na semana passada, o Carlos tentou investigar aquela atividade suspeita na conta de Dev e ficou 3 horas sem conseguir acessar os logs — simplesmente não existiam. Se o BACEN fizer uma auditoria surpresa agora, tomamos uma multa."

Você abre o console AWS e verifica o estado atual:

**Estado atual do CloudTrail:**

```
CLOUDTRAIL — BANCO MERIDIAN (Estado Atual — 15/04/2026)
─────────────────────────────────────────────────────────────
Conta: Meridian-Mgmt (111111111111)
  CloudTrail: DESABILITADO
  Logs: Nenhum

Conta: Meridian-Audit (222222222222)
  CloudTrail: DESABILITADO
  Logs: Nenhum

Conta: Meridian-Logs (333333333333)
  CloudTrail: DESABILITADO
  Logs: Nenhum (esta conta é o Log Archive — irônico)

Conta: Meridian-Prod (444444444444)
  CloudTrail: HABILITADO (Management Events apenas)
  Logs: s3://prod-trail-logs-444 (na própria conta Production)
  Retenção: Indefinida (sem Object Lock)
  Criptografia: Nenhuma
  Data Events: DESABILITADOS
─────────────────────────────────────────────────────────────
Conformidade BACEN 4.893 Art.10: NÃO CONFORME
```

Carlos envia uma mensagem no Slack às 10h47:

> "Cara, encontrei uma nova instância EC2 em us-east-2 que ninguém reconhece. Tentei verificar quem criou no CloudTrail mas não tenho acesso ao bucket de logs da Production. Precisa de alguém com permissão de S3 na Production para investigar — vai demorar."

Este é exatamente o problema. O objetivo deste laboratório é construir a solução.

---

## Seção 3 — Problema Identificado

**11h05 — Você identifica o escopo completo do problema:**

A investigação rápida que você faz no console confirma que a situação é pior do que parecia:

1. **Ausência de Organization Trail:** cada conta ou não tem CloudTrail, ou tem um trail local. Não há visibilidade centralizada
2. **Data Events desabilitados na Production:** se alguém acessou dados sensíveis no S3, não há registro do `GetObject` ou `PutObject` — apenas das operações de controle
3. **Logs na mesma conta dos recursos:** os logs da Production estão num bucket da própria Production — se um atacante comprometer a conta, pode excluir os logs
4. **Sem retenção definida:** os logs da Production não têm Object Lock — podem ser excluídos a qualquer momento, por qualquer admin
5. **Sem Log File Validation:** não há como provar que os logs existentes não foram adulterados

**Impacto do problema identificado (MITRE ATT&CK T1562.008 — Disable Cloud Logs):**

```
Risco atual: Um atacante que comprometa a conta Production pode:
1. StopLogging → desabilitar o CloudTrail imediatamente
2. DeleteObject → excluir os logs existentes do S3
3. Operar durante dias sem qualquer registro

Com o logging centralizado na conta Log Archive:
1. SCP bloqueia StopLogging nas member accounts
2. Logs no Log Archive têm Object Lock — imutáveis mesmo para root
3. Qualquer tentativa de modificar o trail gera alerta imediato
```

Você abre o ticket **SECOPS-2048 — Implementar CloudTrail Organization Trail com logging centralizado** e começa a trabalhar.

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Implementar o CloudTrail Organization Trail com entrega centralizada na conta Log Archive, configurar o CloudTrail Lake para análise SQL, e estabelecer alertas em tempo real para eventos críticos de segurança.

**Atividades deste laboratório:**

1. Preparar a conta Log Archive: criar bucket S3 com segurança máxima (SSE-KMS, Block Public Access, Versioning)
2. Aplicar Bucket Policy que permite ao CloudTrail entregar logs de toda a organização
3. Criar o CloudTrail Organization Trail com Data Events habilitados
4. Criar log group no CloudWatch e conectar ao trail
5. Criar Metric Filter para detecção de uso de root account
6. Criar o CloudTrail Lake Event Data Store com retenção de 7 anos
7. Executar as 5 queries SQL de segurança críticas
8. Habilitar VPC Flow Logs na conta Production
9. Validar integridade dos logs com Log File Validation
10. Gerar relatório de conformidade para o ticket SECOPS-2048

---

## Seção 5 — Proposição do Desafio

Ao final do laboratório, você apresentará para Mariana uma demonstração de 5 minutos mostrando:

1. No CloudTrail Lake, a query que identifica quem criou a instância EC2 suspeita em us-east-2
2. Um alarme CloudWatch disparando quando o root é usado em qualquer conta
3. O relatório de conformidade mostrando Score 100% nos 10 itens verificados

**Critério de aprovação:** o relatório de conformidade gerado pelo script Python deve mostrar todos os checks como `true` e score de 100%.

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

## Seção 8 — Gabarito Completo

### Passo 1 — Gabarito: Bucket S3 do Log Archive

**Configuração correta do bucket:**
```bash
aws s3api create-bucket \
  --bucket meridian-logs-333333333333 \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

aws s3api put-public-access-block \
  --bucket meridian-logs-333333333333 \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-versioning \
  --bucket meridian-logs-333333333333 \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket meridian-logs-333333333333 \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
```

**Por que esta é a resposta correta:** O bucket precisa de quatro controles independentes: Block Public Access (impede acesso público acidental), Versioning (requisito para Object Lock e recuperação de versões), Encriptação (BACEN 4.893 exige dados em repouso criptografados) e Bucket Policy restritiva (permite apenas o CloudTrail escrever, impede escrita de outras fontes).

**Output esperado de verificação:**
```bash
aws s3api get-bucket-versioning --bucket meridian-logs-333333333333
# {"Status": "Enabled"}   ← Versioning ativo — pré-requisito para Object Lock

aws s3api get-public-access-block --bucket meridian-logs-333333333333
# Todos os quatro campos devem ser true
```

**Erros comuns neste passo:**
- Criar bucket sem Versioning antes de tentar habilitar Object Lock: Object Lock exige Versioning ativo no momento da criação do bucket — não pode ser habilitado depois
- Esquecer o `LocationConstraint` para sa-east-1: sem isso, o bucket vai para us-east-1 por padrão

---

### Passo 2 — Gabarito: Bucket Policy para CloudTrail Organization Trail

**Configuração correta da Bucket Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::meridian-logs-333333333333",
      "Condition": {
        "StringEquals": {"aws:SourceOrgID": "o-abc123xyz"}
      }
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
          "aws:SourceOrgID": "o-abc123xyz"
        }
      }
    },
    {
      "Sid": "DenyDeleteAndModify",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:DeleteObject", "s3:DeleteBucket", "s3:PutBucketPolicy"],
      "Resource": [
        "arn:aws:s3:::meridian-logs-333333333333",
        "arn:aws:s3:::meridian-logs-333333333333/*"
      ]
    }
  ]
}
```

**Por que esta é a resposta correta:** A condição `aws:SourceOrgID` é crítica — sem ela, qualquer conta AWS poderia escrever no bucket de logs do Banco Meridian, corrompendo a trilha de auditoria. O `DenyDeleteAndModify` é a segunda camada de proteção além do Object Lock.

**Erros comuns neste passo:**
- Esquecer `aws:SourceOrgID`: o CloudTrail funciona, mas qualquer conta AWS pode gravar no bucket — risco de poluição de logs
- Usar `aws:SourceAccount` em vez de `aws:SourceOrgID`: `SourceAccount` cobre apenas uma conta; `SourceOrgID` cobre toda a organização
- Esquecer o `GetBucketAcl`: o CloudTrail verifica o ACL do bucket antes de escrever — sem essa permissão, a entrega de logs falha silenciosamente

---

### Passo 3 — Gabarito: Criação do CloudTrail Organization Trail

**Configuração correta:**
```bash
aws cloudtrail create-trail \
  --name "meridian-org-trail" \
  --s3-bucket-name "meridian-logs-333333333333" \
  --is-organization-trail \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --cloud-watch-logs-log-group-arn "arn:aws:logs:sa-east-1:111111111111:log-group:/meridian/cloudtrail/org-trail:*" \
  --cloud-watch-logs-role-arn "arn:aws:iam::111111111111:role/CloudTrail_CloudWatchLogs_Role" \
  --region sa-east-1
```

**Por que esta é a resposta correta:** Os três flags são obrigatórios para o cenário do Banco Meridian:
- `--is-organization-trail`: cobre todas as contas da organização com um único trail
- `--is-multi-region-trail`: captura eventos de todas as regiões — sem isso, atividade em us-east-1 não seria registrada
- `--enable-log-file-validation`: gera digest SHA-256 de cada arquivo de log, permitindo provar que os logs não foram adulterados — requisito forense e de compliance

**Output esperado:**
```json
{
  "TrailARN": "arn:aws:cloudtrail:sa-east-1:111111111111:trail/meridian-org-trail",
  "IsOrganizationTrail": true,
  "LogFileValidationEnabled": true,
  "IsMultiRegionTrail": true
}
```

**Erros comuns neste passo:**
- `InsufficientSnsTopicPolicyException`: a role CloudTrail_CloudWatchLogs_Role não tem permissão de criar log streams no CloudWatch — verificar a trust policy da role
- `S3BucketDoesNotExistException`: bucket criado em região diferente — verificar com `aws s3 ls | grep meridian-logs`
- Trail criado mas sem entregas: verificar se o `start-logging` foi executado após a criação

---

### Passo 4 — Gabarito: CloudWatch Metric Filter

**Configuração correta:**
```bash
aws logs put-metric-filter \
  --log-group-name "/meridian/cloudtrail/org-trail" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}' \
  --metric-transformations \
    "metricName=RootAccountUsageCount,metricNamespace=MeridianSecurity,metricValue=1,defaultValue=0"
```

**Por que esta é a resposta correta:** O filtro tem três condições compostas com `&&`:
1. `userIdentity.type = "Root"`: identifica a conta root
2. `invokedBy NOT EXISTS`: exclui ações iniciadas por serviços AWS (que podem usar root internamente)
3. `eventType != "AwsServiceEvent"`: exclui eventos gerados automaticamente pela AWS

Sem as condições 2 e 3, o alarme dispara falsos positivos para operações legítimas de serviços AWS, gerando fadiga de alertas.

**Output esperado:**
```json
{
  "metricName": "RootAccountUsageCount",
  "metricNamespace": "MeridianSecurity",
  "metricValue": "1",
  "defaultValue": 0
}
```

**Erros comuns neste passo:**
- `InvalidParameterException` no filter-pattern: o padrão usa sintaxe especial de CloudWatch — verificar aspas e colchetes
- Alarme não dispara em testes: verificar se o trail está entregando logs ao CloudWatch Logs (pode haver delay de até 15 minutos)

---

### Passo 5 — Gabarito: Query CloudTrail Lake para Instância Suspeita

**Query correta para identificar quem criou a instância em us-east-2:**
```sql
SELECT
    eventTime,
    userIdentity.arn,
    userIdentity.type,
    sourceIPAddress,
    awsRegion,
    requestParameters.instancesSet.items[0].imageId AS ami_id,
    responseElements.instancesSet.items[0].instanceId AS instance_id
FROM <EDS_ID>
WHERE
    eventName = 'RunInstances'
    AND awsRegion = 'us-east-2'
    AND eventTime > timestamp '2026-04-14 00:00:00'
ORDER BY eventTime DESC
LIMIT 10
```

**Por que esta é a resposta correta:** `RunInstances` é o evento gerado quando uma instância EC2 é criada. Os campos `requestParameters.instancesSet` e `responseElements.instancesSet` permitem identificar a AMI usada e o ID da instância criada. O filtro por `awsRegion = 'us-east-2'` e período recente confirma o evento específico investigado.

**Output esperado com anotações:**
```json
[{
  "eventTime": "2026-04-14T23:47:32Z",    // Hora UTC — coincide com alerta
  "userIdentity.arn": "arn:aws:iam::444444444444:user/dev-pipeline-ci",  // Quem criou
  "sourceIPAddress": "172.16.10.5",        // IP interno do pipeline CI
  "awsRegion": "us-east-2",               // Região não aprovada — confirmado
  "ami_id": "ami-0123456789abcdef0",      // AMI usada
  "instance_id": "i-0prod456xyz"          // ID da instância encontrada
}]
```

**Erros comuns neste passo:**
- `QueryRunning` por mais de 10 minutos: o Event Data Store pode ainda estar indexando logs novos — aguardar ou reduzir o período da query
- Sem resultados: verificar se o EDS inclui a conta Production (444444444444) e se Data Events estão habilitados

---

### Verificação Final — Checklist de Conformidade

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
