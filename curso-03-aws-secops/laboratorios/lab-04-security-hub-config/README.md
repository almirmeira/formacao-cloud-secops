# Lab 04 — Security Hub + Config + Auto-Remediation

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 04 — Postura de Segurança
**Nível:** Intermediário/Avançado

---

## Contexto

O Banco Meridian precisa implementar conformidade contínua alinhada ao BACEN 4.893. Você vai: (1) configurar o Security Hub com os standards CIS e FSBP, (2) criar 3 Config rules customizadas alinhadas ao BACEN, (3) configurar auto-remediation para a rule de S3 público, e (4) deployar o conformance pack completo.

---

## Seção 1 — Configurar Security Hub

**Passo 1.1** — Habilitar Security Hub:

```bash
# Habilitar Security Hub na conta Audit (administração centralizada)
aws securityhub enable-security-hub \
  --region sa-east-1 \
  --enable-default-standards \
  --tags '{"Environment": "Production", "ManagedBy": "SecurityTeam"}'

echo "Security Hub habilitado"
```

**Passo 1.2** — Habilitar standards adicionais:

```bash
# Obter ARNs dos standards disponíveis
aws securityhub describe-standards \
  --region sa-east-1 \
  --query 'Standards[].{Nome:Name,ARN:StandardsArn}' \
  --output table

# Habilitar CIS AWS Foundations Benchmark v2.0
aws securityhub batch-enable-standards \
  --region sa-east-1 \
  --standards-subscription-requests '[
    {
      "StandardsArn": "arn:aws:securityhub:sa-east-1::standards/cis-aws-foundations-benchmark/v/2.0.0"
    },
    {
      "StandardsArn": "arn:aws:securityhub:sa-east-1::standards/pci-dss/v/3.2.1"
    }
  ]'

echo "Standards habilitados — aguardar 5 minutos para avaliação inicial"
```

**Passo 1.3** — Verificar Security Score após avaliação:

```bash
# Aguardar avaliação inicial (pode levar até 30 minutos para avaliação completa)
sleep 300

# Verificar score atual
aws securityhub get-finding-aggregator \
  --finding-aggregator-arn "arn:aws:securityhub:sa-east-1:222222222222:finding-aggregator/default" \
  --region sa-east-1 2>/dev/null || echo "Finding Aggregator ainda nao configurado"

# Listar controles com falha (top 10)
aws securityhub get-enabled-standards \
  --region sa-east-1 \
  --query 'StandardsSubscriptions[].{Standard:StandardsArn,Status:StandardsStatus}' \
  --output table
```

**Troubleshooting:**
- `InvalidAccessException`: Security Hub já está habilitado — usar `describe-hub` para verificar
- Standards não aparecem: aguardar até 10 minutos após habilitação

---

## Seção 2 — Configurar AWS Config

**Passo 2.1** — Criar bucket de Config na conta Log Archive:

```bash
# Criar bucket de Config (ou usar o bucket de logs existente com prefixo)
aws s3api create-bucket \
  --bucket meridian-config-333333333333 \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

# Block Public Access
aws s3api put-public-access-block \
  --bucket meridian-config-333333333333 \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Bucket Policy para Config
cat > /tmp/config-bucket-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ConfigAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::meridian-config-333333333333"
    },
    {
      "Sid": "ConfigWrite",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::meridian-config-333333333333/AWSLogs/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket meridian-config-333333333333 \
  --policy file:///tmp/config-bucket-policy.json
```

**Passo 2.2** — Configurar Configuration Recorder:

```bash
# Criar Configuration Recorder
aws configservice put-configuration-recorder \
  --configuration-recorder '{
    "name": "default",
    "roleARN": "arn:aws:iam::444444444444:role/AWSServiceRoleForConfig",
    "recordingGroup": {
      "allSupported": true,
      "includeGlobalResourceTypes": true
    }
  }' \
  --region sa-east-1

# Criar Delivery Channel
aws configservice put-delivery-channel \
  --delivery-channel '{
    "name": "default",
    "s3BucketName": "meridian-config-333333333333",
    "snsTopicARN": "arn:aws:sns:sa-east-1:444444444444:MeridianConfigChanges",
    "configSnapshotDeliveryProperties": {
      "deliveryFrequency": "TwentyFour_Hours"
    }
  }' \
  --region sa-east-1

# Iniciar o recorder
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region sa-east-1

echo "Config recorder iniciado"
```

---

## Seção 3 — Criar 3 Config Rules Customizadas (BACEN 4.893)

**Passo 3.1** — Config Rule 1: Verificar se instâncias EC2 têm tag CostCenter:

```bash
# Criar função Lambda para a rule customizada
cat > /tmp/lambda-config-tag.py << 'EOF'
import boto3
import json

def handler(event, context):
    config = boto3.client('config')
    
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event.get('configurationItem', {})
    
    if configuration_item.get('configurationItemStatus') == 'ResourceDeleted':
        return
    
    resource_id = configuration_item.get('resourceId')
    resource_type = configuration_item.get('resourceType')
    
    if resource_type != 'AWS::EC2::Instance':
        return
    
    # Verificar tags
    tags = {t['key']: t['value'] for t in configuration_item.get('tags', [])}
    
    compliance = 'COMPLIANT' if 'CostCenter' in tags and tags['CostCenter'] else 'NON_COMPLIANT'
    annotation = f"Tag CostCenter {'presente' if compliance == 'COMPLIANT' else 'ausente ou vazia'}"
    
    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': resource_type,
            'ComplianceResourceId': resource_id,
            'ComplianceType': compliance,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }],
        ResultToken=event['resultToken']
    )
    
    print(f"Avaliado: {resource_id} -> {compliance}")
EOF

# Criar Lambda
zip /tmp/lambda-config-tag.zip /tmp/lambda-config-tag.py

aws lambda create-function \
  --function-name MeridianConfigTagCheck \
  --runtime python3.12 \
  --handler lambda-config-tag.handler \
  --zip-file fileb:///tmp/lambda-config-tag.zip \
  --role "arn:aws:iam::444444444444:role/LambdaConfigRole" \
  --timeout 60 \
  --region sa-east-1

# Dar permissão ao Config para invocar a Lambda
aws lambda add-permission \
  --function-name MeridianConfigTagCheck \
  --action lambda:InvokeFunction \
  --statement-id ConfigPermission \
  --principal config.amazonaws.com \
  --region sa-east-1

# Criar Config Rule
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "bacen-ec2-costcenter-tag-required",
    "Description": "BACEN 4.893 - Instâncias EC2 devem ter tag CostCenter",
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "arn:aws:lambda:sa-east-1:444444444444:function:MeridianConfigTagCheck",
      "SourceDetails": [{
        "EventSource": "aws.config",
        "MessageType": "ConfigurationItemChangeNotification"
      }]
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::EC2::Instance"]
    }
  }' \
  --region sa-east-1

echo "Config Rule 1 criada: bacen-ec2-costcenter-tag-required"
```

**Passo 3.2** — Config Rule 2: Verificar se KMS rotation está habilitada:

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "bacen-kms-cmk-rotation-enabled",
    "Description": "BACEN 4.893 Art.6 - CMKs devem ter rotação automática habilitada",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "CMK_BACKING_KEY_ROTATION_ENABLED"
    }
  }' \
  --region sa-east-1

echo "Config Rule 2 criada: bacen-kms-cmk-rotation-enabled"
```

**Passo 3.3** — Config Rule 3: Verificar S3 Block Public Access no nível de conta:

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "bacen-s3-account-level-public-access-block",
    "Description": "BACEN 4.893 Art.10 - S3 Block Public Access deve estar habilitado no nível da conta",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"
    },
    "MaximumExecutionFrequency": "One_Hour"
  }' \
  --region sa-east-1

echo "Config Rule 3 criada: bacen-s3-account-level-public-access-block"
```

**Verificação:**

```bash
# Listar todas as Config rules criadas
aws configservice describe-config-rules \
  --config-rule-names \
    bacen-ec2-costcenter-tag-required \
    bacen-kms-cmk-rotation-enabled \
    bacen-s3-account-level-public-access-block \
  --region sa-east-1 \
  --query 'ConfigRules[].{Nome:ConfigRuleName,Owner:Source.Owner,Status:ConfigRuleState}' \
  --output table
```

---

## Seção 4 — Auto-Remediation para S3 Público

**Passo 4.1** — Verificar o SSM Automation document disponível:

```bash
# Verificar documento de remediação AWS gerenciado
aws ssm describe-document \
  --name "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock" \
  --query 'Document.{Nome:Name,Plataforma:TargetType}' \
  --region sa-east-1
```

**Passo 4.2** — Criar role de remediação:

```bash
# Criar policy inline para a role de remediação
cat > /tmp/ssm-remediation-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "config:PutEvaluations",
        "ssm:GetAutomationExecution",
        "ssm:StartAutomationExecution"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-role \
  --role-name MeridianConfigRemediationRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ssm.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name MeridianConfigRemediationRole \
  --policy-name S3RemediationPolicy \
  --policy-document file:///tmp/ssm-remediation-policy.json
```

**Passo 4.3** — Configurar auto-remediation para s3-bucket-public-read-prohibited:

```bash
# Criar Config rule gerenciada de S3 público
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Description": "Verifica se buckets S3 tem Block Public Access habilitado",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
  }' \
  --region sa-east-1

# Configurar auto-remediation
aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock",
    "Parameters": {
      "AutomationAssumeRole": {
        "StaticValue": {
          "Values": ["arn:aws:iam::444444444444:role/MeridianConfigRemediationRole"]
        }
      },
      "BucketName": {
        "ResourceValue": {"Value": "RESOURCE_ID"}
      }
    },
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]' \
  --region sa-east-1

echo "Auto-remediation configurada para s3-bucket-public-read-prohibited"
```

---

## Seção 5 — Deploy do Conformance Pack BACEN 4.893

**Passo 5.1** — Criar o arquivo YAML do conformance pack:

```bash
# Copiar o conformance pack do módulo 4 para um arquivo
cat > /tmp/conformance-pack-bacen.yaml << 'EOF'
Parameters:
  MaxAccessKeyAge:
    Default: "90"
    Type: String

Resources:
  RootAccountNoAccessKeys:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-iam-root-access-key-check
      Source:
        Owner: AWS
        SourceIdentifier: IAM_ROOT_ACCESS_KEY_CHECK

  MFAEnabledForConsoleAccess:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-mfa-enabled-console
      Source:
        Owner: AWS
        SourceIdentifier: MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS

  CloudTrailEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-cloudtrail-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENABLED

  VPCFlowLogsEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-vpc-flow-logs
      Source:
        Owner: AWS
        SourceIdentifier: VPC_FLOW_LOGS_ENABLED

  RestrictedSSH:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-restricted-ssh
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED

  S3BucketEncryptionRequired:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-s3-default-encryption
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED

  GuardDutyEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-guardduty-enabled
      Source:
        Owner: AWS
        SourceIdentifier: GUARDDUTY_ENABLED_CENTRALIZED
EOF

# Deploy do conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name "BACEN4893-BancoMeridian" \
  --template-body file:///tmp/conformance-pack-bacen.yaml \
  --delivery-s3-bucket "meridian-config-333333333333" \
  --region sa-east-1

echo "Conformance Pack deployado — aguardar avaliação inicial (5-10 min)"
```

**Passo 5.2** — Verificar status do conformance pack:

```bash
aws configservice describe-conformance-pack-status \
  --conformance-pack-names "BACEN4893-BancoMeridian" \
  --region sa-east-1 \
  --query 'ConformancePackStatusDetails[0].{Nome:ConformancePackName,Status:ConformancePackState,Mensagem:ConformancePackStatusReason}'
```

**Resultado Esperado:** `"Status": "CREATE_COMPLETE"`

---

## Seção 6 — Teste da Auto-Remediation

**Passo 6.1** — Criar bucket S3 público para testar a remediação:

```bash
# Criar bucket de teste (NÃO usar em conta de produção real)
TIMESTAMP=$(date +%s)
TEST_BUCKET="meridian-test-public-$TIMESTAMP"

aws s3api create-bucket \
  --bucket $TEST_BUCKET \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

# Desabilitar Block Public Access (tornando público)
aws s3api delete-public-access-block \
  --bucket $TEST_BUCKET

echo "Bucket de teste criado sem Block Public Access: $TEST_BUCKET"
echo "Aguardando Config detectar NON_COMPLIANT (2-10 minutos)..."
```

**Passo 6.2** — Monitorar a remediação:

```bash
# Verificar status de conformidade após alguns minutos
sleep 300

aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "s3-bucket-public-read-prohibited" \
  --compliance-types NON_COMPLIANT \
  --region sa-east-1 \
  --query 'EvaluationResults[?EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId==`'$TEST_BUCKET'`]'

# Verificar se a remediação foi executada
aws configservice describe-remediation-execution-statuses \
  --config-rule-name "s3-bucket-public-read-prohibited" \
  --region sa-east-1 \
  --query 'RemediationExecutionStatuses[0].{Status:State,Bucket:ResourceKey.ResourceId}'
```

**Resultado Esperado após remediação:**
- Status: `SUCCEEDED`
- Block Public Access habilitado automaticamente no bucket de teste

---

## Seção 7 — Painel de Conformidade BACEN

```python
import boto3
from datetime import datetime

def painel_conformidade_bacen(account_id, region='sa-east-1'):
    config = boto3.client('config', region_name=region)
    
    # Obter compliance summary do conformance pack
    response = config.get_conformance_pack_compliance_summary(
        ConformancePackNames=['BACEN4893-BancoMeridian']
    )
    
    summary = response.get('ConformancePackComplianceSummaryList', [])
    
    print("=" * 60)
    print(f"PAINEL BACEN 4.893 — Conta {account_id}")
    print(f"Data: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)
    
    for pack in summary:
        compliance = pack.get('ConformancePackComplianceSummary', {})
        total = compliance.get('TotalCount', 0)
        compliant = compliance.get('CompliantCount', 0)
        non_compliant = compliance.get('NonCompliantCount', 0)
        
        pct = (compliant / total * 100) if total > 0 else 0
        
        print(f"\nConformance Pack: {pack['ConformancePackName']}")
        print(f"Score: {pct:.1f}%")
        print(f"  COMPLIANT:     {compliant:4d} regras")
        print(f"  NON_COMPLIANT: {non_compliant:4d} regras")
        print(f"  TOTAL:         {total:4d} regras")
        
        if non_compliant > 0:
            print(f"\n  ACAO REQUERIDA: {non_compliant} regras precisam de remediação")
    
    print("\n" + "=" * 60)

painel_conformidade_bacen('444444444444')
```

---

## Seção 8 — Cleanup

```bash
# Remover conformance pack
aws configservice delete-conformance-pack \
  --conformance-pack-name "BACEN4893-BancoMeridian" \
  --region sa-east-1

# Remover auto-remediation
aws configservice delete-remediation-configuration \
  --config-rule-name "s3-bucket-public-read-prohibited" \
  --region sa-east-1

# Remover Config rules customizadas
for RULE in bacen-ec2-costcenter-tag-required bacen-kms-cmk-rotation-enabled bacen-s3-account-level-public-access-block s3-bucket-public-read-prohibited; do
  aws configservice delete-config-rule \
    --config-rule-name $RULE \
    --region sa-east-1
  echo "Removida: $RULE"
done

# Remover bucket de teste
aws s3 rb s3://$TEST_BUCKET --force
```

---

## Gabarito — Conformance Pack YAML Completo

O conformance pack YAML completo está no Módulo 04, Seção 3 do material do curso. Todos os 14 controles mapeados ao BACEN 4.893.

**Critérios de Aprovação:**
- Security Hub habilitado com CIS e PCI DSS: APROVADO
- 3 Config rules criadas e avaliando recursos: APROVADO
- Auto-remediation configurada e testada (bucket público remediado): APROVADO
- Conformance Pack deployado com status `CREATE_COMPLETE`: APROVADO
