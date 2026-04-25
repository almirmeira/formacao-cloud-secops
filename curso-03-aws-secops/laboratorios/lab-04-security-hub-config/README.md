# Lab 04 — Security Hub + Config + Auto-Remediation

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 04 — Postura de Segurança
**Nível:** Intermediário/Avançado

---

## Seção 1 — Contexto Situacional

O Banco Meridian foi notificado de uma revisão de conformidade pelo BACEN agendada para daqui a 45 dias. O auditor pediu evidências de que os controles de segurança estão sendo monitorados de forma contínua e que desvios são detectados e corrigidos automaticamente — não apenas pontualmente em auditorias anuais.

O desafio é que o Banco Meridian não tem nenhum framework de conformidade contínua implementado. O Security Hub não está habilitado. O AWS Config está habilitado em apenas uma conta. Não existe nenhuma evidência automática de conformidade com o CIS AWS Foundations Benchmark ou com as exigências do BACEN.

O CISO declarou que a implementação de conformidade contínua é a principal prioridade da semana.

---

## Seção 2 — Situação Inicial

É quinta-feira, 17 de abril de 2026, 09h00. Você recebe o e-mail do CISO com o checklist da auditoria BACEN. Os primeiros três itens do checklist são:

```
CHECKLIST BACEN 4.893 — AUDITORIA AGENDADA
──────────────────────────────────────────────────────────────
 [FALHA] Art. 6 §2 — Evidência de criptografia obrigatória em repouso
         → AWS Config rule: AUSENTE
         → Security Hub control: AUSENTE

 [FALHA] Art. 10 §1 — Monitoramento contínuo de conformidade de controles
         → Security Hub: DESABILITADO
         → Dashboard de postura: INEXISTENTE

 [FALHA] Art. 7 §3 — Controle de acesso a recursos críticos
         → IAM Access Analyzer: DESABILITADO na maioria das contas
         → Config rule para MFA: AUSENTE
──────────────────────────────────────────────────────────────
 Status geral: NÃO CONFORME
 Prazo para regularização: 45 dias
```

Mariana comenta no stand-up às 09h15:

> "O relatório saiu ontem. Dos 89 controles do CIS v2.0, temos apenas 23 com evidência — os outros 66 simplesmente não têm monitoramento. Para a auditoria BACEN, precisamos no mínimo do Security Hub com os standards ativos e de Config rules para os controles críticos."

Carlos verifica o estado atual do Security Hub via CLI:

```bash
aws securityhub describe-hub --region sa-east-1
# Error: "ResourceNotFoundException" — Security Hub não está habilitado
```

> "Pois é — nem habilitado está. Vamos ter que começar do zero."

**Estado atual do Security Hub:**

```
SECURITY HUB — BANCO MERIDIAN (Estado Atual)
────────────────────────────────────────────────────────────
 Security Hub:         DESABILITADO em todas as contas
 Standards ativos:     Nenhum
 Config Rules ativas:  3 (apenas as defaults — insuficiente)
 Findings processados: 0 (sem dados históricos)
 Security Score:       N/A
────────────────────────────────────────────────────────────
```

---

## Seção 3 — Problema Identificado

**09h45 — Análise das três lacunas críticas para a auditoria:**

**Lacuna 1 — Ausência de visibilidade unificada de postura:**
O Security Hub é o único serviço AWS que agrega findings de GuardDuty, Inspector, Macie, Config e IAM Access Analyzer em um único painel com score de segurança. Sem ele, o time de segurança precisa acessar cada serviço individualmente — impossível de demonstrar para um auditor.

**Lacuna 2 — Ausência de avaliação contínua de conformidade:**
O AWS Config avalia configurações de recursos em tempo real. Quando um desenvolvedor cria um bucket S3 público, uma Config rule pode detectar isso em segundos e acionar remediação automática. Sem isso, o bucket público pode existir por semanas até ser descoberto numa varredura manual.

**Lacuna 3 — Ausência de conformance packs alinhados ao BACEN:**
O AWS Config oferece conformance packs — coleções de Config rules mapeadas a frameworks específicos. Existe um conformance pack para o NIST que serve como base para o mapeamento ao BACEN 4.893. Sem isso, cada regra precisa ser criada manualmente.

**Mapeamento MITRE ATT&CK:**
- **T1562.007 (Disable or Modify Cloud Firewall)** — detectável via Config rule `restricted-incoming-traffic`
- **T1530 (Data from Cloud Storage Object)** — detectável via Config rule `s3-bucket-public-read-prohibited`
- **T1078.004 (Valid Accounts: Cloud Accounts)** — detectável via Config rule `iam-root-access-key-check`

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Implementar conformidade contínua com Security Hub (3 standards), AWS Config (3 rules customizadas e 1 conformance pack), e auto-remediation para S3 público.

**Atividades deste laboratório:**

1. Habilitar Security Hub com standards CIS v2.0, FSBP e PCI-DSS
2. Configurar Security Hub como delegated admin da Audit Account
3. Criar Config Recorder e Delivery Channel na conta Production
4. Criar 3 Config rules customizadas alinhadas ao BACEN 4.893
5. Configurar auto-remediation via SSM Automation para bucket S3 público
6. Deployar conformance pack baseado no NIST
7. Criar Security Hub Custom Action para escalar findings ao CISO
8. Gerar relatório de score de conformidade

---

## Seção 5 — Proposição do Desafio

Mariana vai testar sua implementação criando propositalmente um bucket S3 público após você finalizar a configuração. Você precisa demonstrar:

1. O finding aparece no Security Hub em menos de 15 minutos após a criação do bucket
2. A auto-remediation do Config aciona o SSM Automation que bloqueia o acesso público automaticamente
3. O finding é marcado como `RESOLVED` no Security Hub após a remediação

**Critério de aprovação:** O bucket criado por Mariana deve ter o acesso público bloqueado automaticamente, sem intervenção manual, e o finding correspondente deve estar `RESOLVED` no Security Hub.

---

## Seção de Implementação — Configurar Security Hub

### Passo 1.1 — Habilitar Security Hub na conta Audit

**O que este passo faz:** Habilita o Security Hub na conta Audit (222222222222), que atuará como administrador delegado centralizado para o Banco Meridian. O parâmetro `--enable-default-standards` ativa automaticamente o AWS Foundational Security Best Practices (FSBP) — o standard base com mais de 300 controles. As tags aplicadas permitem rastrear este recurso nos relatórios de conformidade. Após habilitação, o Security Hub leva até 30 minutos para a avaliação inicial completa de todos os recursos da conta.

**Por que esta ordem:** O Security Hub deve ser habilitado antes de configurar standards adicionais (Passo 1.2) e antes de configurar a agregação multi-conta. Uma vez habilitado, começa a receber findings do GuardDuty, Inspector e Config imediatamente.

**Por que isso importa para o Banco Meridian:** O Security Hub é a resposta direta ao primeiro item do checklist BACEN da Mariana: "Art. 10 §1 — Monitoramento contínuo de conformidade de controles → Security Hub: DESABILITADO". Com o Security Hub habilitado e populado com findings das 4 contas, o Banco Meridian passa de "Dashboard de postura: INEXISTENTE" para evidência auditável em formato ASFF (Amazon Security Finding Format) para o auditor do BACEN.

**Permissão IAM necessária:** `securityhub:EnableSecurityHub` e `securityhub:BatchEnableStandards` na conta Audit.

```bash
# Habilitar Security Hub na conta Audit (administração centralizada)
aws securityhub enable-security-hub \
  --region sa-east-1 \
  --enable-default-standards \
  --tags '{"Environment": "Production", "ManagedBy": "SecurityTeam"}'

echo "Security Hub habilitado"
```

### Passo 1.2 — Habilitar standards adicionais: CIS v2.0 e PCI DSS

**O que este passo faz:** Habilita dois standards adicionais de conformidade no Security Hub: o CIS AWS Foundations Benchmark v2.0 (89 controles de configuração segura) e o PCI DSS v3.2.1 (controles para proteção de dados de cartão de pagamento). O primeiro comando lista os standards disponíveis para confirmar os ARNs corretos, evitando o erro de ARN inválido. O comando `batch-enable-standards` aceita múltiplos standards em uma única chamada, iniciando a avaliação de todos simultaneamente.

**Por que esta ordem:** Os standards devem ser habilitados após o Security Hub estar ativo (Passo 1.1). A avaliação inicial leva de 5 a 30 minutos — quanto mais recursos na conta, mais tempo leva.

**Por que isso importa para o Banco Meridian:** O CIS AWS Foundations Benchmark é o padrão de referência mais citado em auditorias de segurança AWS no Brasil. Controles específicos como CIS 1.4 (sem access keys de root), CIS 3.1 (CloudTrail em todas as regiões) e CIS 5.2 (sem SSH para 0.0.0.0/0) são verificados automaticamente. O PCI DSS v3.2.1 é mandatório para o Banco Meridian pois o banco processa transações com cartões de pagamento — o Finding Hub do PCI DSS mostra diretamente quais controles estão falhando, com o controle PCI específico mapeado.

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

### Passo 1.3 — Verificar Security Score após avaliação inicial

**O que este passo faz:** Consulta o status dos standards habilitados e os controles com falha. O Security Hub leva de 5 a 30 minutos para a avaliação inicial de todos os recursos — o comando `sleep 300` aguarda 5 minutos antes de consultar. O `get-enabled-standards` lista os standards ativos e seu status. Uma avaliação inicial com score 50-75% é normal para uma conta AWS recém-configurada.

**O que você deve ver:** Os standards devem aparecer com `Status: READY` (não mais `PENDING`). Um score abaixo de 70% indica muitos controles falhando — o restante deste lab os corrigirá progressivamente.

**O que fazer se der errado:**
- `InvalidAccessException`: Security Hub já está habilitado — `aws securityhub describe-hub` para verificar
- Standards com status `PENDING`: aguardar mais 10 minutos — a avaliação de todas as contas da organização pode levar até 30 minutos

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

### Passo 2.1 — Criar bucket S3 para entrega do AWS Config na conta Log Archive

**O que este passo faz:** Cria o bucket S3 na conta Log Archive (333333333333) que receberá os snapshots de configuração e histórico de mudanças do AWS Config de todas as contas da organização. Os snapshots de configuração são arquivos JSON que representam o estado de todos os recursos AWS em um determinado momento — uma "fotografia" da infraestrutura. O histórico de mudanças registra cada alteração de configuração: quem criou, modificou ou excluiu cada recurso, e qual era o estado antes e depois.

**Por que esta ordem:** O bucket deve existir ANTES da configuração do Delivery Channel (Passo 2.2). O Config verifica a existência e permissões do bucket no momento da configuração.

**Por que isso importa para o Banco Meridian:** O AWS Config é o "CFTV de configuração" da infraestrutura — sem ele, é impossível responder à pergunta "qual era o estado do Security Group da instância comprometida 48 horas antes do incidente?". Para investigações forenses e relatórios BACEN, o Config fornece a linha do tempo de mudanças de configuração que complementa a linha do tempo de API calls do CloudTrail.

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

### Passo 2.2 — Configurar Configuration Recorder e Delivery Channel

**O que este passo faz:** Três comandos complementares: (1) `put-configuration-recorder` cria o gravador de configuração com `allSupported: true` (registra todos os tipos de recurso AWS suportados) e `includeGlobalResourceTypes: true` (inclui recursos IAM, Route53 e CloudFront, que são globais e não têm região); (2) `put-delivery-channel` define onde os snapshots de configuração e mudanças são entregues — bucket S3 da conta Log Archive e tópico SNS para notificações em tempo real; (3) `start-configuration-recorder` inicia efetivamente o registro. Sem o `start-configuration-recorder`, o recorder existe mas não grava nada.

**Por que esta ordem:** O bucket S3 e a bucket policy (Passo 2.1) devem existir antes do Delivery Channel. O `start-configuration-recorder` deve ser o último dos três — iniciar o recorder antes de ter o delivery channel configurado resulta em erros de entrega.

**Por que isso importa para o Banco Meridian:** O AWS Config é o mecanismo de "CFTV de configuração" da infraestrutura AWS — cada mudança de recurso gera um Configuration Item com o estado antes e depois. Durante investigações, o Config permite responder: "qual era o Security Group da instância comprometida no momento do ataque?". Para o BACEN 4.893 Art. 7, o Config é a evidência de monitoramento contínuo de integridade de configuração exigida pela norma.

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

### Passo 3.1 — Config Rule 1 (Custom Lambda): Tag CostCenter obrigatória em instâncias EC2

**O que este passo faz:** Cria uma Config Rule customizada via Lambda para verificar se todas as instâncias EC2 têm a tag `CostCenter` preenchida. A função Lambda recebe o `configurationItem` de cada instância EC2 avaliada, extrai as tags e retorna `COMPLIANT` se a tag `CostCenter` estiver presente e não vazia, ou `NON_COMPLIANT` caso contrário. A regra usa o trigger `ConfigurationItemChangeNotification` — avalia cada instância no momento em que é criada ou modificada.

**Por que esta ordem:** A Lambda deve ser criada e o ZIP de deployment empacotado antes de criar a Config Rule. A role IAM deve incluir `config:PutEvaluations` para que a Lambda possa reportar o resultado. O `aws lambda publish-version` é necessário para que a Config Rule referencie uma versão estável.

**Por que isso importa para o Banco Meridian:** Instâncias EC2 sem tag `CostCenter` são shadow IT — recursos criados fora do processo aprovado de IaC que não têm responsável financeiro identificado. Além da governança de custos, recursos sem tag não passam pelo processo de revisão de segurança, podendo ter configurações inseguras por padrão.

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

### Passo 3.2 — Config Rule 2 (Managed): KMS Key Rotation obrigatória

**O que este passo faz:** Cria a Config Rule gerenciada `kms-cmk-not-scheduled-for-deletion` usando a rule gerenciada pela AWS `KMS_CMK_NOT_SCHEDULED_FOR_DELETION`. Rules gerenciadas são avaliadas pela AWS com lógica interna — não requerem Lambda customizada. Este comando cria a regra com avaliação do tipo `CHANGE_TRIGGERED` para recursos `AWS::KMS::Key`, avaliando cada CMK do Banco Meridian no momento de sua criação ou modificação.

**Por que isso importa para o Banco Meridian:** CMKs (Customer Managed Keys) do KMS criptografam os buckets S3 de logs, os snapshots EBS e os segredos do Secrets Manager do Banco Meridian. A rotação anual automática (`EnableKeyRotation: true`) garante que mesmo que uma chave antiga seja comprometida, os dados mais recentes são protegidos por uma chave diferente. Uma CMK sem rotação habilitada em ambiente financeiro é um controle faltante que o auditor BACEN identificaria imediatamente.

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

### Passo 4.1 — Verificar o SSM Automation document disponível

**O que este passo faz:** Confirma a existência do documento SSM Automation `AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock` — um documento gerenciado pela AWS que habilita automaticamente os quatro bloqueios de acesso público (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) em um bucket S3 identificado como NON_COMPLIANT pela Config Rule `s3-bucket-public-read-prohibited`. O `describe-document` retorna os parâmetros aceitos pelo documento — usados na configuração da remediação do Passo 4.3.

**Por que esta ordem:** Confirmar que o documento existe antes de configurar a remediação evita o erro `InvalidDocument`. Documentos SSM Automation gerenciados pela AWS são específicos por região.

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

### Passo 4.3 — Configurar auto-remediation para s3-bucket-public-read-prohibited

**O que este passo faz:** Dois comandos em sequência: (1) cria a Config Rule gerenciada `s3-bucket-public-read-prohibited` que avalia todos os buckets S3 da conta para verificar se o Block Public Access está habilitado; (2) associa a regra ao documento SSM Automation com `Automatic: true` — qualquer bucket detectado como NON_COMPLIANT receberá remediação automática sem intervenção humana. O `ResourceId: RESOURCE_ID` é um placeholder dinâmico que o Config substitui pelo nome real do bucket no momento da execução.

**Por que isso importa para o Banco Meridian:** Um bucket S3 criado acidentalmente com acesso público em ambiente financeiro é um incidente de dados. Com auto-remediação, o gap de exposição vai de horas (detectar + escalar + corrigir manualmente) para minutos (Config detecta → SSM Automation aplica Block Public Access automaticamente → Security Hub finding fechado). O BACEN 4.893 Art. 10 exige controles que previnam exposição pública de dados financeiros — esta auto-remediação é a implementação preventiva desse requisito.

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

### Passo 5.1 — Criar o arquivo YAML e implantar o Conformance Pack

**O que este passo faz:** Cria o arquivo YAML do Conformance Pack com as Config Rules alinhadas ao BACEN 4.893 e o implanta via `put-conformance-pack`. O Conformance Pack funciona como um template CloudFormation gerenciado pelo Config: o YAML define quais regras criar (com parâmetros como `MaxAccessKeyAge: "90"` para rotação de chaves em 90 dias), e o Config cria e gerencia essas regras automaticamente. A diferença em relação a criar regras individualmente: o pack mantém todas as regras versionadas e sincronizadas — alterar o YAML e reimplantar atualiza todas as regras de uma vez.

**Por que esta ordem:** A implantação do Conformance Pack deve ocorrer após o Config estar funcionando e o bucket de delivery configurado. O pack precisa do bucket de delivery para armazenar os resultados da avaliação.

**O que você deve ver:** `Status: DEPLOYMENT_SUCCESSFUL` após alguns minutos. As regras do pack aparecem no console do Config com o prefixo do nome do Conformance Pack.

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

### Passo 6.1 — Criar bucket S3 público para testar o ciclo completo de remediação

**O que este passo faz:** Cria intencionalmente um bucket S3 com Block Public Access desabilitado — a violação que o Config deve detectar automaticamente. Este é o teste end-to-end do pipeline: Config detecta NON_COMPLIANT → EventBridge roteia → SSM Automation aplica Block Public Access → Config reavalia → COMPLIANT → Security Hub fecha o finding. O bucket de teste tem timestamp no nome para unicidade e deve ser excluído após o teste.

**Por que esta ordem:** O teste só faz sentido após toda a cadeia de remediação estar ativa: Config Rule `s3-bucket-public-read-prohibited` (Passo 4.3), remediação automática configurada, e EventBridge ativo. Testar em qualquer ponto anterior ao ciclo completo não validaria o pipeline end-to-end que será usado em produção.

**O que você deve ver:** Após 5 a 15 minutos, o `get-public-access-block` do bucket deve retornar os quatro campos como `true` — sem nenhuma ação manual. O Security Hub deve mostrar o finding do bucket evoluindo de `FAILED` para `PASSED`. Este é o comportamento esperado que a Mariana testará durante a apresentação do lab.

**O que fazer se der errado:**
- Config não detecta em 15 minutos: verificar se o Configuration Recorder está ativo (`aws configservice get-configuration-recorder-status`)
- Remediação não ocorre: verificar se a auto-remediação está configurada com `Automatic: true` (Passo 4.3)
- SSM Automation falha: verificar o log de execução do SSM em Systems Manager → Automation → Execution History

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
