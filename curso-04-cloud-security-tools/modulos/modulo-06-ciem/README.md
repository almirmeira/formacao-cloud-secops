# Módulo 06 — CIEM: Cloud Infrastructure Entitlement Management
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h videoaula + 1h laboratório  
> **Certificação Alvo:** CCSP domínio 3 e 5 / CCSK domínio 6  
> **Cenário:** Equipe de GRC do Banco Meridian auditando identidades e permissões na AWS

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Explicar por que o gerenciamento de entitlements em cloud é diferente do IAM on-premises
2. Identificar permissões excessivas usando AWS IAM Access Analyzer
3. Conduzir uma auditoria CIEM passo a passo em uma conta AWS
4. Implementar just-in-time access básico com SSO e aprovação
5. Aplicar o modelo de menor privilégio usando policy generation baseada em CloudTrail

---

## 1. Por Que CIEM é Diferente do IAM On-Premises

### 1.1 O Problema de Escala

Em ambientes on-premises:
- Usuários: dezenas a centenas
- Serviços: dezenas
- Permissões: gerenciáveis manualmente
- Mudanças: lentas, através de processo formal

Em ambientes cloud:
- Usuários + non-human identities: milhares
- Serviços: centenas (cada Lambda, cada EC2, cada K8s pod é uma identidade)
- Permissões: criadas automaticamente por IaC, acumuladas ao longo do tempo
- Mudanças: instantâneas, via API, frequentemente sem revisão de segurança

```
ESCALA: ON-PREMISES VS CLOUD
──────────────────────────────────────────────────────────────────────────────
ON-PREMISES (empresa 500 funcionários)
  Identidades: ~600 (500 humanas + 100 serviços)
  Permissões: gerenciáveis com equipe de 2 pessoas de IAM

CLOUD (mesma empresa, após migração)
  Identidades humanas: ~600
  Non-human identities:
    - EC2 Instance Profiles: 80+
    - Lambda Execution Roles: 200+
    - ECS Task Roles: 50+
    - K8s ServiceAccounts: 300+
    - CI/CD Machine Users: 20+
    - Cross-account roles: 40+
  TOTAL: ~1.200 identidades NÃO-HUMANAS

  95% dessas identidades têm mais permissões do que precisam
  (pesquisa CyberArk, 2024)
──────────────────────────────────────────────────────────────────────────────
```

### 1.2 Conceitos-Chave de CIEM

| Conceito | Definição | Exemplo |
|:---------|:----------|:--------|
| **Least privilege** | Identidade tem apenas as permissões necessárias para sua função | Lambda de leitura tem somente `s3:GetObject`, não `s3:*` |
| **Excessive permissions** | Identidade tem mais permissões do que usa na prática | Role com `s3:*` que usa apenas `s3:GetObject` e `s3:PutObject` |
| **Toxic combinations** | Combinação de permissões que cria risco maior do que a soma das partes | Role com `iam:CreateUser` + `iam:AttachUserPolicy` + `sts:AssumeRole` |
| **Standing access** | Acesso permanente a recursos de alto risco (never expires) | DBA com acesso permanente ao banco de produção |
| **Just-in-time access** | Acesso concedido sob demanda com aprovação, com TTL curto | DBA solicita acesso ao banco, aprovado pelo CISO, expira em 4h |
| **Permissions creep** | Acúmulo gradual de permissões que nunca são removidas | Dev que muda de time mas mantém as permissões do time anterior |
| **Shadow admin** | Identidade com permissões equivalentes a admin sem ter o nome admin | Role com `iam:*` mas chamada de "lambda-execution-role" |

---

## 2. Ferramentas de CIEM por Cloud Provider

### 2.1 AWS IAM Access Analyzer

**Dois analyzers distintos (frequentemente confundidos):**

**External Access Analyzer:**
- Detecta quando recursos AWS são acessíveis de fora da conta/organização
- Analisa: S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, SNS topics
- Exemplo de finding: "IAM Role `api-role` pode ser assumida por qualquer conta AWS" (permissão cross-account excessiva)

**Unused Access Analyzer (mais relevante para CIEM):**
- Detecta permissões e credenciais não utilizadas nos últimos 90 dias
- Analisa: unused permissions, unused access keys, unused passwords, unused roles
- Exemplo de finding: "IAM User `dev-johndoe` tem permissão `ec2:TerminateInstances` que nunca foi usada nos últimos 90 dias"

**O que este comando faz:** Cria dois analisadores distintos do IAM Access Analyzer — um para detectar exposição externa (recursos acessíveis fora da conta) e outro para detectar permissões não utilizadas nos últimos 90 dias.
**Por que isso importa:** No Banco Meridian, com mais de 1.200 identidades não-humanas acumuladas ao longo de anos de migrações, é impossível auditar manualmente cada role. Os analisadores automatizam a detecção de dois dos maiores vetores de risco: exposição não intencional a terceiros e permissões que nunca deveriam ter sido concedidas.

```bash
# Habilitar External Access Analyzer via CLI
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-external-access \
  --type ACCOUNT \
  --region us-east-1

# Habilitar Unused Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-unused-access \
  --type ACCOUNT_UNUSED_ACCESS \
  --configuration '{"unusedAccessAge": 90}' \
  --region us-east-1

# Listar findings do External Access Analyzer
aws accessanalyzer list-findings \
  --analyzer-name bancomeridian-external-access \
  --query 'findings[?status==`ACTIVE`].[id,resource,resourceType,condition]' \
  --output table

# Listar findings de Unused Access (permissões não usadas)
aws accessanalyzer list-findings-v2 \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:ACCOUNT:analyzer/bancomeridian-unused-access \
  --filter '{"findingType": {"contains": ["UnusedPermission"]}}' \
  --output json

# Gerar política mínima baseada em uso real do CloudTrail
# (Policy Generation — usa os últimos 90 dias de CloudTrail como base)
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{"principalArn": "arn:aws:iam::ACCOUNT:role/api-pagamentos-role"}' \
  --cloud-trail-details '{
    "accessRole": "arn:aws:iam::ACCOUNT:role/AccessAnalyzerCloudTrailRole",
    "startTime": "2025-01-24T00:00:00Z",
    "endTime": "2025-04-24T00:00:00Z",
    "trails": [{"allRegions": true}]
  }'

# Verificar status da geração
aws accessanalyzer get-generated-policy \
  --job-id JOB_ID_RETORNADO_ACIMA

# Listar todos os recursos acessíveis publicamente
aws accessanalyzer list-findings \
  --analyzer-name bancomeridian-external-access \
  --filter '{"condition": {"contains": ["aws:PrincipalOrgID"]}}' \
  --query 'findings[].resource' \
  --output text
```

**Exemplo de finding de Unused Access Analyzer:**
```json
{
  "id": "abcd1234-...",
  "type": "UnusedPermission",
  "resourceType": "AWS::IAM::Role",
  "resource": "arn:aws:iam::123456789:role/api-pagamentos-role",
  "createdAt": "2025-04-24T10:00:00Z",
  "analyzedAt": "2025-04-24T10:00:00Z",
  "status": "ACTIVE",
  "findingDetails": {
    "unusedPermissions": {
      "actions": [
        {
          "action": "ec2:DescribeInstances",
          "lastAccessed": null
        },
        {
          "action": "s3:DeleteObject",
          "lastAccessed": null
        },
        {
          "action": "iam:ListUsers",
          "lastAccessed": null
        }
      ]
    }
  }
}
```

### 2.2 Entra Permissions Management (Azure)

Solução CIEM multi-cloud da Microsoft (adquirida da CloudKnox). Disponível como add-on do Microsoft Entra ID.

**Funcionalidades principais:**
- **Permissions Creep Index (PCI):** score de 0–100 mostrando o nível de permissões excessivas por identidade
- **Cross-cloud:** analisa AWS + Azure + GCP na mesma interface
- **Activity triggers:** alerta quando identidades realizam ações perigosas (ex: criar usuário IAM)
- **On-demand permissions:** JIT access integrado

**O que este comando faz:** Cria um aplicativo no Entra ID para integração com o Entra Permissions Management e consulta o Permissions Creep Index (PCI) de todas as identidades via Microsoft Graph API.
**Por que isso importa:** Para o Banco Meridian operar em múltiplas nuvens, uma visão unificada de permissões excessivas em AWS, Azure e GCP num único painel elimina os pontos cegos que surgem quando cada equipe gerencia suas permissões em silos separados.

```bash
# Configurar Entra Permissions Management via CLI (Azure)
az ad app create --display-name "EntraPermissionsManagement"

# Verificar PCI (Permissions Creep Index) via Graph API
az rest --method get \
  --url "https://graph.microsoft.com/beta/identityGovernance/permissionsManagement/permissionsCreepIndexDistributions"
```

### 2.3 GCP Policy Intelligence

**O que este comando faz:** Consulta o serviço de recomendações do GCP para obter sugestões de redução de permissões IAM baseadas em uso histórico real, e aplica automaticamente as recomendações aprovadas.
**Por que isso importa:** No GCP, o Policy Intelligence analisa o comportamento de cada service account e sugere a remoção de permissões não utilizadas. Para o Banco Meridian, isso significa substituir service accounts com roles amplas como `roles/editor` por roles customizadas com apenas as permissões efetivamente exercidas nos últimos 90 dias.

```bash
# Recomendações de IAM baseadas em uso real
gcloud recommender recommendations list \
  --project=bancomeridian-prod \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format=json

# IAM Insights — identidades com permissões excessivas
gcloud recommender insights list \
  --project=bancomeridian-prod \
  --insight-type=google.iam.policy.Insight \
  --location=global

# Aplicar recomendação (reduzir permissões)
gcloud recommender recommendations apply \
  projects/bancomeridian-prod/locations/global/recommenders/google.iam.policy.Recommender/recommendations/RECOMMENDATION_ID \
  --project=bancomeridian-prod \
  --location=global \
  --etag=ETAG_FROM_RECOMMENDATION
```

---

## 3. Just-in-Time Access

### 3.1 Conceito e Benefícios

**Standing access (modelo ruim):**
```
DBA João → Permissão permanente de read/write no banco de produção
↓
João muda de função para dev frontend
↓
Permissão continua existindo (ninguém removeu)
↓
3 meses depois: João é comprometido via phishing
↓
Atacante usa credenciais de João para acessar banco de produção
→ Acesso que ninguém deveria ter, mas estava lá
```

**Just-in-time access (modelo correto):**
```
DBA João precisa acessar banco de produção para investigar incidente
↓
João solicita acesso via portal de JIT (ticket ou chat)
↓
CISO recebe notificação e aprova
↓
Sistema concede permissão temporária com TTL de 4 horas
↓
João resolve o problema
↓
Após 4 horas: permissão revogada automaticamente
→ Janela de exposição: 4 horas vs. permanente
```

### 3.2 Implementação JIT Básico com AWS SSO + Aprovação

**O que este comando faz:** Cria um Permission Set no AWS IAM Identity Center com duração de sessão de 4 horas (TTL), associa ao usuário sob demanda, e em seguida revoga o acesso quando o TTL expira ou a tarefa é concluída.
**Por que isso importa:** No Banco Meridian, DBAs e administradores de nuvem nunca deveriam ter acesso permanente a bancos de produção. O JIT via SSO elimina o risco de standing access — se um administrador for comprometido via phishing fora do horário de trabalho, o atacante não encontrará nenhuma permissão ativa para explorar.

```bash
# Arquitetura JIT com AWS IAM Identity Center (SSO)
#
# 1. Criar Permission Set de alto privilégio (ex: DatabaseAdmin)
aws sso-admin create-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --name DatabaseAdmin \
  --description "Acesso temporário ao banco de dados de produção" \
  --session-duration PT4H    # TTL: 4 horas

# 2. Associar permission set com a conta alvo
aws sso-admin create-account-assignment \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --target-id ACCOUNT_ID \
  --target-type AWS_ACCOUNT \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx \
  --principal-type USER \
  --principal-id USER_ID

# 3. Após o TTL, revogar o assignment
aws sso-admin delete-account-assignment \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --target-id ACCOUNT_ID \
  --target-type AWS_ACCOUNT \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx \
  --principal-type USER \
  --principal-id USER_ID
```

**O que este código faz:** Implementa um fluxo completo de JIT access via Lambda — recebe a solicitação de acesso pelo Slack, envia para aprovação do CISO no canal #security-approvals, e após aprovação cria o assignment SSO com TTL, além de agendar automaticamente a revogação via EventBridge.
**Por que isso importa:** Automatizar o fluxo de aprovação elimina a dependência de processos manuais e lentos que frequentemente resultam em acesso permanente por conveniência. O Banco Meridian consegue demonstrar para o BACEN que cada acesso privilegiado tem aprovação registrada, duração limitada e revogação automática documentada no audit trail.

```python
# Lambda function para automação de JIT com aprovação via Slack
# (simplified example)
import boto3
import json
import os

sso_client = boto3.client('sso-admin')

def lambda_handler(event, context):
    """
    Fluxo:
    1. Usuário envia mensagem no Slack: "Preciso de acesso DBA por 4h — incidente #123"
    2. Slack chama este Lambda via webhook
    3. Lambda envia mensagem para canal #security-approvals com botão "Aprovar"
    4. CISO clica "Aprovar"
    5. Lambda cria account assignment com TTL de 4h
    6. Lambda agenda Lambda de revogação via EventBridge
    """
    body = json.loads(event['body'])
    action_type = body.get('type')

    if action_type == 'block_actions':
        # Usuário aprovou via Slack
        action = body['actions'][0]
        if action['action_id'] == 'approve_jit':
            request_data = json.loads(action['value'])
            grant_jit_access(
                user_id=request_data['user_id'],
                permission_set_arn=request_data['permission_set_arn'],
                account_id=request_data['account_id'],
                duration_hours=request_data['duration_hours']
            )
            schedule_revocation(request_data)

    return {'statusCode': 200}

def grant_jit_access(user_id, permission_set_arn, account_id, duration_hours):
    sso_client.create_account_assignment(
        InstanceArn=os.environ['SSO_INSTANCE_ARN'],
        TargetId=account_id,
        TargetType='AWS_ACCOUNT',
        PermissionSetArn=permission_set_arn,
        PrincipalType='USER',
        PrincipalId=user_id
    )
    print(f"JIT access granted: user={user_id}, duration={duration_hours}h")

def schedule_revocation(request_data):
    events_client = boto3.client('events')
    from datetime import datetime, timedelta
    import uuid

    revocation_time = datetime.utcnow() + timedelta(hours=request_data['duration_hours'])
    cron_expr = f"cron({revocation_time.minute} {revocation_time.hour} {revocation_time.day} {revocation_time.month} ? {revocation_time.year})"

    events_client.put_rule(
        Name=f"jit-revoke-{uuid.uuid4().hex[:8]}",
        ScheduleExpression=cron_expr,
        State='ENABLED'
    )
```

---

## 4. Auditoria CIEM Passo a Passo

### 4.1 Metodologia Completa

```
AUDITORIA CIEM — BANCO MERIDIAN
Metodologia em 5 Etapas
──────────────────────────────────────────────────────────────────────────────

ETAPA 1: INVENTÁRIO DE IDENTIDADES E PERMISSÕES
─────────────────────────────────────────────────
Objetivo: Saber exatamente quem/o-que existe e o que pode fazer

Comandos:
```

**O que este comando faz:** Obtém o relatório completo de autorização da conta AWS, extraindo para cada usuário IAM o nome, data de criação, último uso de senha e presença de dispositivos MFA. Em paralelo, gera o relatório de credenciais nativo do IAM e identifica chaves de acesso com mais de 90 dias sem rotação.
**Por que isso importa:** O Banco Meridian não pode auditar o que não enxerga. Este inventário inicial revela o gap entre identidades criadas e identidades ativamente gerenciadas — em muitos casos, usuários de ex-colaboradores ou de projetos encerrados permanecem ativos por anos, criando backdoors não intencionais que violam diretamente o BACEN 4.893 Art. 8.

```bash
# Listar todos os IAM users com data de criação e último uso
aws iam get-account-authorization-details \
  --query 'UserDetailList[*].{
    User:UserName,
    Created:CreateDate,
    LastUsed:PasswordLastUsed,
    HasMFA:MFADevices
  }' \
  --output table

# Listar todos os IAM roles com suas trust policies
aws iam list-roles --query 'Roles[*].{
  Role:RoleName,
  Created:CreateDate,
  TrustPolicy:AssumeRolePolicyDocument.Statement[0].Principal
}' --output json

# Listar credenciais de acesso não rotacionadas
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d | \
  python3 -c "
import sys, csv
reader = csv.DictReader(sys.stdin)
for row in reader:
    if row.get('access_key_1_last_rotated', 'N/A') != 'N/A':
        from datetime import datetime, timezone
        last = datetime.fromisoformat(row['access_key_1_last_rotated'].replace('Z','+00:00'))
        age_days = (datetime.now(timezone.utc) - last).days
        if age_days > 90:
            print(f\"{row['user']}: key age {age_days} days\")
"
```

```
ETAPA 2: IDENTIFICAÇÃO DE PERMISSÕES EXCESSIVAS
────────────────────────────────────────────────────
Objetivo: Encontrar gaps entre permissões concedidas e permissões usadas
```

**O que este comando faz:** Habilita o Unused Access Analyzer com lookback de 90 dias e lista todas as ações IAM que foram concedidas a roles mas nunca efetivamente executadas no período. Em seguida, varre todas as roles em busca de nomes de políticas que sugerem permissões administrativas amplas.
**Por que isso importa:** No Banco Meridian, a prática comum de conceder `AmazonS3FullAccess` para uma Lambda que só precisa de `s3:GetObject` cria uma superfície de ataque 20 vezes maior que o necessário. Identificar essas permissões excessivas é o primeiro passo para a remediação baseada em dados reais de uso — não em estimativas.

```bash
# Habilitar Unused Access Analyzer (se não habilitado ainda)
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-unused-90d \
  --type ACCOUNT_UNUSED_ACCESS \
  --configuration '{"unusedAccessAge": 90}'

# Listar todas as permissões não usadas nos últimos 90 dias
aws accessanalyzer list-findings-v2 \
  --analyzer-arn $(aws accessanalyzer list-analyzers \
    --query 'analyzers[?type==`ACCOUNT_UNUSED_ACCESS`].arn' \
    --output text) \
  --filter '{"findingType": {"contains": ["UnusedPermission"]}}' \
  --output json | \
  jq -r '.findings[] | "\(.resource) → \(.findingDetails.unusedPermissions.actions[].action)"'

# Identificar roles com permissões de admin não usadas
aws iam list-roles --output json | jq -r '.Roles[].RoleName' | while read role; do
  policies=$(aws iam list-attached-role-policies --role-name "$role" \
    --query 'AttachedPolicies[].PolicyName' --output text)
  if echo "$policies" | grep -qi "admin\|poweruser\|fullaccess"; then
    echo "ROLE COM PERMISSÕES ELEVADAS: $role (policies: $policies)"
  fi
done
```

```
ETAPA 3: PRIORIZAÇÃO POR RISCO
──────────────────────────────────────
Critérios de priorização:
  1. Acesso externo (cross-account, público) → CRÍTICO
  2. Shadow admins (permissões iam:* ou *:*) → CRÍTICO
  3. Contas humanas sem MFA → ALTO
  4. Credenciais de serviço antigas (>90 dias) → ALTO
  5. Permissões não usadas em roles de produção → MÉDIO
  6. Permissões não usadas em roles de desenvolvimento → BAIXO
```

**O que este comando faz:** Varre as políticas inline de todas as roles IAM em busca de statements com `Action: "*"`, `Action: "iam:*"` ou `Action: "sts:*"` — as "combinações tóxicas" que transformam uma role aparentemente inofensiva em um shadow admin com poderes equivalentes ao AdministratorAccess.
**Por que isso importa:** No Banco Meridian, uma role chamada `lambda-processamento-boletos` com `iam:CreateUser` não levanta suspeitas imediatas — o nome sugere uma função inofensiva. Mas se essa role também tiver `iam:AttachUserPolicy` e `sts:AssumeRole`, um atacante que a comprometer pode criar um novo usuário administrador e manter persistência permanente no ambiente, mesmo após a revogação da role original.

```bash
# Script de priorização — identifica shadow admins
aws iam list-roles --output json | jq -r '.Roles[].RoleName' | while read role; do
  # Buscar policies inline
  aws iam list-role-policies --role-name "$role" \
    --output json | jq -r '.PolicyNames[]' | while read policy_name; do
    policy_doc=$(aws iam get-role-policy \
      --role-name "$role" \
      --policy-name "$policy_name" \
      --query 'PolicyDocument' --output json)

    # Verificar se tem Action=* ou iam:* permitido
    if echo "$policy_doc" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for stmt in doc.get('Statement', []):
    if stmt.get('Effect') == 'Allow':
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if a in ['*', 'iam:*', 'sts:*']:
                print('SHADOW ADMIN DETECTADO')
                sys.exit(0)
" 2>/dev/null | grep -q "SHADOW ADMIN"; then
      echo "SHADOW ADMIN: Role $role tem permissão perigosa na policy $policy_name"
    fi
  done
done
```

```
ETAPA 4: REMEDIAÇÃO COM MÍNIMO DE PERMISSÕES
──────────────────────────────────────────────────
Estratégia: usar Policy Generation para criar política mínima baseada em uso real
```

**O que este comando faz:** Inicia o processo de Policy Generation do IAM Access Analyzer, que analisa 90 dias de eventos do CloudTrail para a role especificada e gera automaticamente uma política IAM contendo apenas as ações que foram efetivamente executadas no período. Em seguida, cria a nova política mínima e substitui a política excessiva existente.
**Por que isso importa:** A Policy Generation é a diferença entre remediação baseada em opinião ("acho que essa role precisa só de S3") e remediação baseada em evidência ("o CloudTrail mostra que essa role usou exatamente 3 ações S3 nos últimos 90 dias"). Para o Banco Meridian, isso elimina o argumento de "melhor não mexer por precaução" e permite reduzir permissões com confiança de que nenhuma funcionalidade legítima será quebrada.

```bash
# Iniciar geração de política mínima para uma role
# (Requer que CloudTrail esteja ativo com log completo nos últimos 90 dias)
JOB_ID=$(aws accessanalyzer start-policy-generation \
  --policy-generation-details '{
    "principalArn": "arn:aws:iam::123456789:role/api-pagamentos-role"
  }' \
  --cloud-trail-details '{
    "accessRole": "arn:aws:iam::123456789:role/AccessAnalyzerCloudTrailRole",
    "startTime": "2025-01-24T00:00:00Z",
    "endTime": "2025-04-24T00:00:00Z",
    "trails": [{"allRegions": true}]
  }' \
  --query 'jobId' --output text)

echo "Job ID: $JOB_ID"

# Aguardar conclusão (pode levar alguns minutos)
aws accessanalyzer get-generated-policy \
  --job-id $JOB_ID \
  --query 'generatedPolicyResult.generatedPolicies[0].policy' \
  --output text | python3 -m json.tool

# Criar nova política mínima
MINIMAL_POLICY=$(aws accessanalyzer get-generated-policy \
  --job-id $JOB_ID \
  --query 'generatedPolicyResult.generatedPolicies[0].policy' \
  --output text)

aws iam create-policy \
  --policy-name api-pagamentos-minimal-policy-v2 \
  --policy-document "$MINIMAL_POLICY"

# Desanexar política antiga e anexar a nova mínima
aws iam detach-role-policy \
  --role-name api-pagamentos-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws iam attach-role-policy \
  --role-name api-pagamentos-role \
  --policy-arn arn:aws:iam::123456789:policy/api-pagamentos-minimal-policy-v2
```

```
ETAPA 5: MONITORAMENTO CONTÍNUO
─────────────────────────────────────
Configurar alertas para detectar novas permissões excessivas
```

**O que este comando faz:** Cria um filtro de métrica no CloudWatch Logs que monitora o CloudTrail em busca de eventos de criação de políticas IAM com wildcards (`Action: "*"`), e configura um alarme que notifica imediatamente o time de segurança via SNS quando esse padrão é detectado.
**Por que isso importa:** Sem monitoramento contínuo, a auditoria CIEM é um evento pontual — as permissões excessivas removidas hoje serão recriadas no próximo sprint por um desenvolvedor que não conhece as políticas de segurança. Para o Banco Meridian, esse alarme fecha o ciclo: qualquer tentativa de criar uma política com wildcard dispara um alerta em menos de 5 minutos, transformando a segurança de IAM de reativa para preventiva.

```bash
# Criar CloudWatch alarm para novas permissões administrativas
# Requer CloudTrail ativo com log group no CloudWatch Logs

# Filter pattern para detectar criação de políticas com wildcards
aws logs put-metric-filter \
  --log-group-name CloudTrail/ManagementEvents \
  --filter-name iam-wildcard-policy-creation \
  --filter-pattern '{($.eventSource = "iam.amazonaws.com") && 
    (($.eventName = "CreatePolicy") || ($.eventName = "PutRolePolicy") || 
    ($.eventName = "PutUserPolicy")) &&
    ($.requestParameters.policyDocument = "*\"Action\":\"*\"*")}' \
  --metric-transformations metricName=WildcardPolicyCreated,metricNamespace=SecurityMetrics,metricValue=1

# Criar alarm para notificação imediata
aws cloudwatch put-metric-alarm \
  --alarm-name WildcardIAMPolicyCreated \
  --alarm-description "Alerta: política IAM com wildcard criada — revisar imediatamente" \
  --metric-name WildcardPolicyCreated \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789:security-alerts
```

---

## 5. Atividades de Fixação

### Questão 1
O que o Unused Access Analyzer do AWS IAM Access Analyzer detecta especificamente?

**a)** Recursos AWS acessíveis publicamente na internet  
**b)** Permissões IAM, credenciais de acesso e roles que não foram utilizadas nos últimos 90 dias (ou período configurado)  
**c)** Usuários IAM que tentaram acessar recursos sem permissão  
**d)** Instâncias EC2 que não receberam nenhum tráfego de rede  

**Gabarito: b)**  
Justificativa: O Unused Access Analyzer especificamente monitora INATIVIDADE de permissões. Ele usa dados do CloudTrail para determinar quais ações de IAM foram efetivamente usadas e quais foram apenas concedidas mas nunca exercitadas. Isso é diferente do External Access Analyzer que detecta acesso externo.

---

### Questão 2
Qual é a diferença fundamental entre "standing access" e "just-in-time access" em um contexto CIEM?

**a)** Standing access é mais seguro porque é permanentemente monitorado  
**b)** Standing access é permanente (não expira); just-in-time access é concedido sob demanda com aprovação e expira após TTL configurado  
**c)** São termos diferentes para o mesmo conceito  
**d)** Standing access é para humanos; just-in-time é para identidades não-humanas  

**Gabarito: b)**  
Justificativa: Standing access é acesso sempre presente — o DBA sempre tem acesso ao banco, mesmo quando não está trabalhando. Isso é um risco: se o DBA for comprometido a qualquer momento, o atacante tem acesso permanente. JIT access concede permissão apenas quando necessário, com aprovação, e revoga automaticamente após o TTL — reduzindo a janela de exposição de permanente para horas.

---

### Questão 3
Um role AWS foi identificado com `Action: iam:CreateUser`, `iam:AttachUserPolicy` e `sts:AssumeRole`. Por que essa combinação é considerada uma "toxic combination" de CIEM?

**a)** Porque essas ações criam muitas chamadas de API e aumentam o custo  
**b)** Porque um atacante que compromete esse role pode: criar um novo usuário IAM, dar permissões admin para ele, e depois usar esse usuário para manter persistência — mesmo se o role comprometido for revogado  
**c)** Porque essas ações violam diretamente a política de senha do IAM  
**d)** Porque a combinação causa conflito lógico nas políticas IAM  

**Gabarito: b)**  
Justificativa: Individualmente, cada uma dessas permissões pode ter justificativa. Combinadas, representam um caminho de ataque completo de persistência: `iam:CreateUser` cria um backdoor de usuário → `iam:AttachUserPolicy` dá permissões administrativas ao backdoor → `sts:AssumeRole` pode ser usado para mover-se lateralmente. Isso é uma toxic combination — o risco combinado é muito maior que a soma das partes individuais.

---

### Questão 4
O comando `aws accessanalyzer start-policy-generation` usa dados de qual serviço AWS para gerar a política mínima recomendada?

**a)** AWS Config — para analisar o histórico de mudanças de configuração  
**b)** CloudTrail — para analisar quais ações IAM foram efetivamente executadas nos últimos 90 dias  
**c)** GuardDuty — para filtrar ações suspeitas das legítimas  
**d)** Security Hub — para correlacionar com outros findings de segurança  

**Gabarito: b)**  
Justificativa: A Policy Generation do IAM Access Analyzer usa dados do CloudTrail para descobrir quais ações foram efetivamente realizadas por um principal (role, user) em um período. Ele então gera uma política IAM que inclui apenas as ações que foram usadas, com os recursos específicos acessados — eliminando todas as permissões concedidas mas nunca exercitadas.

---

### Questão 5
Qual métrica do Entra Permissions Management (Azure) quantifica o nível de permissões excessivas de uma identidade em uma escala de 0 a 100?

**a)** Security Score  
**b)** Permissions Creep Index (PCI)  
**c)** Access Risk Rating (ARR)  
**d)** Identity Risk Score (IRS)  

**Gabarito: b)**  
Justificativa: O Permissions Creep Index (PCI) é a métrica proprietária do Entra Permissions Management que calcula o nível de permissões excessivas em escala de 0 a 100. Um PCI de 0 significa que a identidade usa 100% de suas permissões. Um PCI de 100 significa que as permissões concedidas são massivamente maiores que as utilizadas — o máximo de permissions creep. É uma forma de quantificar o risco de CIEM de cada identidade.

---

## 6. Roteiro de Gravação — Aula 6.1: CIEM — Least Privilege em Cloud (55 min)

### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | CIEM: Gerenciamento de Entitlements e Least Privilege em Cloud |
| **Duração** | 55 minutos |
| **Formato** | Talking head + terminal (AWS CLI) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Bem-vindo ao Módulo 6. Se você trabalha em cloud security e ainda não ouviu falar de CIEM — Cloud Infrastructure Entitlement Management — prepare-se para descobrir o que é, na minha visão, a categoria de ferramenta mais subestimada e mais importante do ecossistema cloud security.

Por quê? Porque dados do CyberArk de 2024 mostram que 95% das identidades non-humanas em ambientes cloud têm mais permissões do que precisam. Isso significa que em 95% dos compromissos de container ou Lambda que você vai ver, o atacante vai ter acesso a muito mais do que o serviço precisaria para funcionar.

---

**[05:00 – 18:00 | O PROBLEMA DE ESCALA | Slides + diagrama]**

*[Dica de edição: diagrama animado mostrando a explosão de identidades em cloud]*

Deixa eu te mostrar o problema com um exemplo concreto.

O Banco Meridian tem 500 funcionários. No datacenter on-premises, eles tinham aproximadamente 600 identidades — 500 humanas e 100 serviços. Dois especialistas de IAM conseguiam gerenciar isso.

Depois de migrar para cloud, com microsserviços em Kubernetes, funções Lambda, pipelines de CI/CD... o time de cloud estimou que têm aproximadamente 1.200 identidades não-humanas só na AWS. Cada Lambda tem uma execution role. Cada ECS task tem uma task role. Cada pod K8s com IRSA tem uma ServiceAccount vinculada a uma role. E ninguém foi revisando essas roles ao longo do tempo.

*[Slide: "95% com permissões excessivas"]*

E o problema não é só o número — é que as pessoas tendem a dar permissões excessivas por comodidade ou precaução. "Melhor dar S3 full access agora, se precisar de mais tarde já está lá." O acúmulo gradual dessas permissões ao longo do tempo é o que chamamos de Permissions Creep.

---

**[18:00 – 38:00 | AWS IAM ACCESS ANALYZER NA PRÁTICA | Terminal]*

*[Dica de edição: tela cheia no terminal AWS CLI]*

Vamos trabalhar com o IAM Access Analyzer, que é a ferramenta nativa AWS para CIEM. Ela tem dois analyzers distintos — vou mostrar os dois.

*[Habilitando External Access Analyzer]*

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-external-access \
  --type ACCOUNT
```

*[Mostrando findings de acesso externo — roles cross-account abertas demais]*

Olha esse finding: uma role IAM que pode ser assumida por qualquer conta AWS, não apenas pelas contas da organização. Isso é um risco — qualquer conta AWS no mundo poderia tentar assumir essa role.

*[Habilitando Unused Access Analyzer]*

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-unused-90d \
  --type ACCOUNT_UNUSED_ACCESS \
  --configuration '{"unusedAccessAge": 90}'
```

*[Mostrando findings de permissões não usadas]*

Agora veja esse resultado. A role `api-pagamentos-role` tem essas 3 permissões que nunca foram usadas nos últimos 90 dias: `ec2:DescribeInstances`, `s3:DeleteObject` e `iam:ListUsers`. Por que uma role de API de pagamentos precisa listar usuários IAM? Não precisa. Isso são permissões excessivas — candidates para remoção.

*[Iniciando Policy Generation]*

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{"principalArn": "arn:aws:iam::ACCOUNT:role/api-pagamentos-role"}' \
  --cloud-trail-details '{...}'
```

*[Mostrando a política mínima gerada]*

Olha o resultado: o IAM Access Analyzer analisou 90 dias de CloudTrail e gerou uma política com apenas as ações que foram efetivamente usadas — `s3:GetObject`, `s3:PutObject` e `rds:DescribeDBInstances`. 3 permissões em vez de 50. Isso é o princípio de menor privilégio na prática.

---

**[38:00 – 50:00 | JUST-IN-TIME ACCESS | Slides + conceito]*

*[Explica a comparação standing access vs JIT com os exemplos do módulo]*

*[Mostra o fluxo da implementação Lambda de JIT]*

---

**[50:00 – 55:00 | ENCERRAMENTO | Talking head]**

O módulo de hoje foi sobre CIEM — Cloud Infrastructure Entitlement Management. Você viu como cloud cria uma escala de identidades que torna o IAM on-premises irreconhecível, por que permissões excessivas são a norma e não a exceção, e como o AWS IAM Access Analyzer automatiza a identificação e remediação desses excessos.

No laboratório Lab-06, você vai conduzir uma auditoria CIEM completa — habilitar o Unused Access Analyzer, identificar permissões excessivas em roles de uma conta sandbox, gerar políticas mínimas com Policy Generation, e aplicar as correções.

---

## 7. Avaliação do Módulo 06

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
A diferença entre o External Access Analyzer e o Unused Access Analyzer do AWS IAM Access Analyzer é:

**a)** External detecta acessos de fora da conta/organização; Unused detecta permissões não utilizadas  
**b)** External é gratuito; Unused tem custo adicional  
**c)** External analisa recursos; Unused analisa apenas usuários  
**d)** External é automático; Unused requer execução manual  

**Gabarito: a)** São dois analyzers com funções completamente distintas: External Access Analyzer detecta quando recursos AWS (roles, S3 buckets, KMS keys) são acessíveis de fora da conta ou organização. Unused Access Analyzer detecta permissões IAM, credenciais e roles que não foram utilizadas no período configurado (padrão 90 dias).

---

**Questão 2 (10 pts)**  
Qual comando AWS CLI lista todas as permissões IAM não utilizadas nos últimos 90 dias usando o Unused Access Analyzer?

**a)** `aws iam list-unused-permissions --days 90`  
**b)** `aws accessanalyzer list-findings-v2 --analyzer-arn ARN --filter '{"findingType": {"contains": ["UnusedPermission"]}}'`  
**c)** `aws cloudtrail lookup-events --unused-only`  
**d)** `aws iam generate-credential-report --unused-only`  

**Gabarito: b)** O comando correto usa `accessanalyzer list-findings-v2` com um filtro para o tipo de finding `UnusedPermission`. O IAM Access Analyzer não expõe os findings via `aws iam` — é uma API separada do serviço accessanalyzer.

---

**Questão 3 (10 pts)**  
Por que o "Permissions Creep Index" (PCI) do Entra Permissions Management varia de 0 a 100, sendo 100 o mais arriscado?

**a)** 100 indica que a identidade tem 100 permissões excessivas  
**b)** 100 indica que a razão entre permissões concedidas e permissões utilizadas é máxima — a identidade tem muitas permissões, mas usa poucas  
**c)** 100 indica que a identidade foi comprometida  
**d)** 100 indica que a identidade tem acesso público  

**Gabarito: b)** O PCI é uma medida normalizada da diferença entre permissões concedidas e permissões utilizadas. PCI=0 significa que a identidade usa todas as suas permissões (minimal permissions creep). PCI=100 significa que as permissões concedidas são massivamente maiores que as utilizadas — o máximo de permissions creep.

---

**Questão 4 (10 pts)**  
Para a feature de Policy Generation do IAM Access Analyzer funcionar, qual pré-requisito é mandatório?

**a)** AWS Config deve estar habilitado com todas as regras de conformidade  
**b)** CloudTrail deve estar habilitado e registrando eventos de gerenciamento (management events) nas regiões analisadas  
**c)** GuardDuty deve estar habilitado para filtrar comportamentos suspeitos  
**d)** IAM deve ter pelo menos 6 meses de histórico de usuários  

**Gabarito: b)** Policy Generation usa dados do CloudTrail para descobrir quais ações IAM foram executadas por um principal no período. Sem CloudTrail ativo, não há dados de uso para analisar. O CloudTrail deve capturar management events (que incluem chamadas IAM) em todas as regiões onde a identidade opera.

---

**Questão 5 (10 pts)**  
Um IAM Role com `"Action": "*"` e `"Effect": "Allow"` é tecnicamente equivalente a:

**a)** A role `ReadOnlyAccess` — pode apenas listar recursos  
**b)** A role `AdministratorAccess` — pode realizar qualquer ação em qualquer serviço AWS  
**c)** Nenhuma permissão concreta — precisa de um Resource especificado  
**d)** A role `PowerUserAccess` — pode fazer tudo exceto gerenciar IAM  

**Gabarito: b)** `Action: "*"` com `Effect: Allow` e (tipicamente) `Resource: "*"` é o equivalente exato do `AdministratorAccess` — a permissão mais ampla possível na AWS. Uma identidade com essa política pode criar/modificar/deletar qualquer recurso em qualquer serviço AWS. É a "shadow admin" por excelência — a role pode ter um nome inocente mas tem poder administrativo total.

---

**Questão 6 (10 pts)**  
Na metodologia de auditoria CIEM, qual é a ordem correta das 5 etapas?

**a)** Remediação → Inventário → Priorização → Identificação → Monitoramento  
**b)** Inventário → Identificação de excessos → Priorização → Remediação → Monitoramento contínuo  
**c)** Priorização → Inventário → Identificação → Monitoramento → Remediação  
**d)** Monitoramento → Inventário → Identificação → Priorização → Remediação  

**Gabarito: b)** A metodologia correta é sequencial: primeiro é necessário saber o que existe (inventário), depois identificar quais permissões são excessivas, priorizar por impacto de negócio (acesso externo e shadow admins são mais urgentes), remediar com políticas mínimas, e finalmente estabelecer monitoramento contínuo para detectar novas permissões excessivas antes que se acumulem novamente.

---

*Módulo 06 — CIEM: Cloud Infrastructure Entitlement Management*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
