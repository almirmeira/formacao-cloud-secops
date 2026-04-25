# Módulo 09 — Segurança Multi-Conta

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 3 horas (1h videoaula + 1h laboratório)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 1 e 5

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Estruturar delegated administration para GuardDuty, Security Hub, Config e Macie
2. Implementar IAM Identity Center com Permission Sets e Account Assignments
3. Configurar SCIM sync e MFA enforcement no IAM Identity Center
4. Projetar cross-account roles seguras com External ID para terceiros
5. Estruturar o Log Archive Account com imutabilidade e separação de funções
6. Mapear responsabilidades entre contas Security e Audit

---

## 1. Delegated Administration por Serviço

### Mapa de Delegated Administration

| Serviço | Delegated Admin Recomendado | O que o Admin Delegado Pode Fazer |
|---|---|---|
| **Amazon GuardDuty** | Audit Account (222222222222) | Ver findings de todas as contas, configurar supressão, gerenciar features org-wide |
| **AWS Security Hub** | Audit Account (222222222222) | Agregar findings, gerenciar standards, criar custom actions |
| **AWS Config** | Audit Account (222222222222) | Criar Aggregator multi-conta, ver conformidade de todas as contas |
| **Amazon Macie** | Audit Account (222222222222) | Criar discovery jobs org-wide, ver findings de dados sensíveis |
| **Amazon Inspector** | Audit Account (222222222222) | Ver vulnerabilidades de todas as contas, priorizar remediação |
| **IAM Access Analyzer** | Management Account | Analyzer organizacional — ver achados de todas as contas |
| **AWS Firewall Manager** | Dedicated Security Account | Gerenciar WAF, Shield, SGs de forma centralizada |
| **Control Tower** | Management Account | Não delegável — permanece na Management Account |

### Configurar Delegated Admin para GuardDuty

```bash
# Na Management Account
aws guardduty enable-organization-admin-account \
  --admin-account-id 222222222222 \
  --region sa-east-1

# Repetir para todas as regiões onde GuardDuty está habilitado
for region in sa-east-1 us-east-1 us-east-2; do
  aws guardduty enable-organization-admin-account \
    --admin-account-id 222222222222 \
    --region $region
done

# Na Audit Account — configurar auto-enable para todas as contas
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region sa-east-1)

aws guardduty update-organization-configuration \
  --detector-id $DETECTOR_ID \
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
```

---

## 2. IAM Identity Center (ex-SSO)

### Arquitetura

```
Azure AD / Okta (Identity Provider)
        │ SCIM sync
        ▼
IAM Identity Center (Management Account)
        │
        ├── Permission Sets
        │   ├── SecurityAuditReadOnly — GuardDuty, Security Hub, Config (leitura)
        │   ├── SecurityResponder — EC2 isolamento, IAM key disable
        │   ├── DeveloperPowerUser — EC2, S3, Lambda (sem IAM)
        │   ├── DatabaseAdmin — RDS, DynamoDB (sem S3 public)
        │   └── BillingAdmin — Cost Explorer, Budgets apenas
        │
        └── Account Assignments
            ├── SecurityAuditReadOnly → Audit Account (todos os analistas)
            ├── SecurityAuditReadOnly → Production Account (time de segurança)
            ├── SecurityResponder → Production Account (SR de plantão)
            └── DeveloperPowerUser → Dev/Test Account (time de dev)
```

### Permission Sets — Exemplos Completos

**Permission Set: SecurityAuditReadOnly**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityServicesReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:Get*", "guardduty:List*",
        "securityhub:Get*", "securityhub:List*", "securityhub:Describe*",
        "config:Get*", "config:List*", "config:Describe*",
        "cloudtrail:Get*", "cloudtrail:List*", "cloudtrail:Describe*",
        "inspector2:Get*", "inspector2:List*",
        "macie2:Get*", "macie2:List*",
        "access-analyzer:Get*", "access-analyzer:List*",
        "iam:Get*", "iam:List*", "iam:Generate*",
        "ec2:Describe*",
        "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock",
        "logs:GetLogEvents", "logs:FilterLogEvents", "logs:Describe*",
        "cloudwatch:Get*", "cloudwatch:List*", "cloudwatch:Describe*",
        "detective:Get*", "detective:List*", "detective:Search*"
      ],
      "Resource": "*"
    }
  ]
}
```

**Permission Set: SecurityResponder**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IRResponseActions",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSnapshot", "ec2:ModifyInstanceAttribute",
        "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags", "ec2:Describe*",
        "iam:UpdateAccessKey", "iam:ListAccessKeys",
        "iam:PutUserPolicy", "iam:TagUser",
        "wafv2:GetIPSet", "wafv2:UpdateIPSet",
        "sns:Publish",
        "s3:PutPublicAccessBlock", "s3:GetPublicAccessBlock",
        "s3:PutBucketTagging"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["sa-east-1", "us-east-1"]
        }
      }
    }
  ]
}
```

### Configuração de SCIM com Azure AD

```bash
# Passos no console IAM Identity Center:
# 1. Identity Center → Settings → Identity source → Change
# 2. Selecionar: External identity provider
# 3. Copiar: Service provider metadata (URL + certificado)
# 4. Configurar no Azure AD:
#    - Criar Enterprise App "AWS IAM Identity Center"
#    - Provisioning → Automatic → Enter tenant URL + secret token do IAC
#    - Attribute mapping: UPN → userName, DisplayName → displayName, Department → title
# 5. Habilitar provisioning → usuários/grupos sincronizados automaticamente

# Verificar sincronização
aws identitystore list-users \
  --identity-store-id d-xxxxx \
  --query 'Users[].{Nome:DisplayName,Email:Emails[0].Value}'
```

### MFA Enforcement

```bash
# Habilitar MFA obrigatório para todos os usuários
aws sso-admin put-mfa-assignment-enforcement \
  --instance-arn "arn:aws:sso:::instance/ssoins-xxxxx" \
  --mfa-enforcement-mode REQUIRE_MFA_TYPE_TOTP_OR_SECURITY_KEY
```

---

## 3. Cross-Account Roles Seguras

### Padrão com External ID para Terceiros

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::TERCEIRO_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "BancoMeridian-AuditFirm-Deloitte-2026-XK9Z4M"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24"
          ]
        }
      }
    }
  ]
}
```

**Três camadas de proteção:**
1. External ID único e secreto (proteção contra confused deputy)
2. MFA obrigatório (mesmo com External ID, precisa de MFA)
3. Restrição por IP (apenas do IP do escritório da auditoria)

---

## 4. Estrutura de Security OU

### Diagrama ASCII — Governança Multi-Conta do Banco Meridian

```
AWS Organizations — Banco Meridian
═══════════════════════════════════════════════════════════════════════════════════

Management Account (111111111111)
├── IAM Identity Center (SSO)
├── AWS Organizations + SCPs
├── Control Tower
└── AWS Config Aggregator Master

OU: Security
├── Audit Account (222222222222)
│   ├── GuardDuty Admin Delegado
│   ├── Security Hub Admin Delegado
│   ├── Config Admin Delegado
│   ├── Amazon Detective
│   ├── Amazon Macie Admin Delegado
│   ├── Inspector Admin Delegado
│   ├── AWS Firewall Manager Admin Delegado
│   └── EventBridge (regras centrais de IR)
│
└── Log Archive Account (333333333333)
    ├── S3: meridian-logs-333 (CloudTrail org-wide)
    │   ├── Object Lock: COMPLIANCE, 7 anos
    │   ├── SSE-KMS (CMK local)
    │   ├── MFA Delete habilitado
    │   ├── Block Public Access: 4/4 habilitados
    │   └── Lifecycle: Glacier após 1 ano
    │
    ├── S3: meridian-config-333 (Config delivery)
    ├── CloudTrail Lake Event Data Store (7 anos)
    └── KMS CMK (para todos os logs)

OU: Production
└── Production Account (444444444444)
    ├── Workloads de produção
    ├── GuardDuty Membro (findings → Audit)
    ├── Config Rule (conformidade → Audit Aggregator)
    └── Security Hub Membro (findings → Audit)

OU: Development
└── Dev/Test Account (555555555555)
    ├── SCPs mais permissivas (ex: sem bloqueio de regiões)
    ├── GuardDuty Membro
    └── Config Rule (com regras específicas de dev)

OU: Sandbox
└── Sandbox Account (666666666666)
    ├── SCPs máximas (sandbox completamente isolado)
    ├── SCP: sem criação de usuário IAM
    ├── SCP: orçamento máximo $500/mês
    └── Sem acesso cross-account
```

---

## 5. Log Archive Account — Configuração Completa

```bash
# Criar bucket de logs com Object Lock ANTES de habilitar CloudTrail
aws s3api create-bucket \
  --bucket meridian-logs-333333333333 \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

# Habilitar Object Lock NO MOMENTO DA CRIAÇÃO
# (não pode ser habilitado depois em bucket existente com objetos)
aws s3api put-object-lock-configuration \
  --bucket meridian-logs-333333333333 \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'

# Habilitar versioning (obrigatório para Object Lock)
aws s3api put-bucket-versioning \
  --bucket meridian-logs-333333333333 \
  --versioning-configuration Status=Enabled

# Habilitar Block Public Access
aws s3api put-public-access-block \
  --bucket meridian-logs-333333333333 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Habilitar default encryption com CMK
aws s3api put-bucket-encryption \
  --bucket meridian-logs-333333333333 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:sa-east-1:333333333333:key/mrk-logs-cmk"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Configurar lifecycle para mover para Glacier após 1 ano
aws s3api put-bucket-lifecycle-configuration \
  --bucket meridian-logs-333333333333 \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "MoveToGlacierAfter1Year",
      "Status": "Enabled",
      "Transitions": [{
        "Days": 365,
        "StorageClass": "GLACIER"
      }],
      "Filter": {"Prefix": "AWSLogs/"}
    }]
  }'

# Habilitar MFA Delete (requer autenticação MFA para deletar versões)
aws s3api put-bucket-versioning \
  --bucket meridian-logs-333333333333 \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::333333333333:mfa/admin serial-number-token"
```

---

## 6. Separação de Funções — Quem Administra o Quê

| Função | Conta de Trabalho | Acesso a Contas | Responsabilidade |
|---|---|---|---|
| **CISO** | Management Account via IAM Identity Center | Read-only em todas | Aprovação de políticas, relatórios regulatórios |
| **Security Engineer** | Audit Account (admin delegado) | Read+Write em Audit; Read em Production | Gerenciar GuardDuty, Security Hub, Config, Detective |
| **SOC Analyst (plantão)** | Audit Account (read-only) | Read-only em todas via Identity Center | Monitorar findings, executar resposta via SSM Automation |
| **IR Analyst** | Audit Account (SecurityResponder) | Actions específicas em Production via cross-account role | Executar contenção, análise forense |
| **Log Administrator** | Log Archive Account apenas | Somente Log Archive | Gerenciar retenção, verificar integridade de logs |
| **Developer** | Dev/Test Account | Apenas Dev/Test via Identity Center | Desenvolver e testar features |
| **DBA** | Production Account (somente durante janela de manutenção) | Apenas Production DB | Manutenção de banco de dados |

---

## 7. Atividades de Fixação

**1.** Por que a Management Account do Banco Meridian não deve ter workloads de produção?

a) Limitação técnica da AWS
b) A Management Account não pode ser restringida por SCPs, tornando-a o alvo mais valioso e perigoso se comprometida
c) A Management Account é sempre muito cara para workloads
d) Regulação BACEN proíbe

**Gabarito: B** — SCPs não se aplicam à Management Account. Se a Management Account for comprometida, o atacante tem controle irrestrito sobre toda a organização: pode remover SCPs, adicionar contas, remover contas, modificar guardrails, assumir qualquer role em qualquer conta. Ao não ter workloads de produção, limitamos drasticamente quem tem acesso à Management Account e reduzimos a superfície de ataque. A Management Account deve ser acessada APENAS para tarefas organizacionais (criar contas, criar OUs, gerenciar SCPs, Control Tower).

---

**2.** Quais são os requisitos técnicos para habilitar S3 Object Lock em um bucket que já existe com objetos?

a) Simplesmente habilitar Object Lock nas configurações do bucket
b) Object Lock não pode ser habilitado em buckets existentes com objetos — é necessário criar um novo bucket com Object Lock e migrar os objetos
c) Habilitar versioning primeiro, depois Object Lock
d) Contatar o suporte AWS para habilitação retroativa

**Gabarito: B** — Object Lock só pode ser habilitado em um bucket no momento da criação (via console ou API). Para buckets existentes: criar novo bucket com Object Lock em modo Compliance, copiar objetos para o novo bucket (os objetos copiados herdam o Object Lock padrão do bucket), verificar integridade, remover acesso ao bucket antigo. Isso deve ser planejado cuidadosamente em ambientes de produção.

---

**3.** O IAM Identity Center está configurado com SCIM sync do Azure AD. Um funcionário foi desligado do Banco Meridian às 17h. Qual é o impacto imediato no acesso AWS?

a) Nenhum — o acesso AWS precisa ser removido manualmente
b) O SCIM desabilita o usuário no IAM Identity Center automaticamente; todas as sessões ativas expiram em até 1 hora (duração máxima de sessão SSO)
c) O acesso é removido imediatamente — sessões ativas são encerradas instantaneamente
d) Depende de sincronização manual do time de TI

**Gabarito: B** — SCIM sync: quando o usuário é desabilitado no Azure AD (offboarding), o SCIM sincroniza essa mudança para o IAM Identity Center em minutos. O usuário não consegue fazer login. Sessões ATIVAS continuam até expirar (máximo configurável, geralmente 1-8 horas). Para revogação imediata de sessões ativas: na conta do usuário, revogar sessões via Lambda/SSM Automation. Isso é diferente de IAM users, onde as credenciais têm que ser desabilitadas manualmente.

---

**4.** Você precisa dar acesso de auditoria a uma empresa terceirizada (Deloitte) à conta Production do Banco Meridian por 30 dias. Quais são os 4 controles de segurança que você deve implementar?

a) Criar usuário IAM temporário com senha única
b) 1) Role cross-account com External ID, 2) MFA obrigatório no trust policy, 3) Restrição por IP do escritório da Deloitte, 4) Permissions boundary limitando escopo máximo
c) Compartilhar credenciais via Secrets Manager
d) Criar VPN site-to-site para o escritório da Deloitte

**Gabarito: B** — Os 4 controles: (1) Cross-account role com External ID exclusivo (gerado em conjunto com a Deloitte, secreto) — protege contra confused deputy. (2) MFA na trust policy via condição `aws:MultiFactorAuthPresent: true` — mesmo com External ID, precisa de MFA. (3) Restrição por IP na trust policy (`aws:SourceIp`) — apenas do range de IPs do escritório da Deloitte. (4) Permissions boundary na role — garante que mesmo que a Deloitte crie subpermissões, não excede o escopo de auditoria. Adicional: monitorar via CloudTrail Lake todas as ações durante o período, e revogar a role após 30 dias.

---

**5.** Descreva a separação de funções entre a Audit Account e o Log Archive Account do Banco Meridian. Por que essa separação é necessária?

a) São equivalentes — podem ser consolidadas em uma única conta
b) Audit Account hospeda ferramentas de análise (GuardDuty, Security Hub, Detective); Log Archive Account hospeda apenas armazenamento imutável de logs. A separação impede que um analista de segurança modifique ou exclua os logs que está investigando
c) A separação é apenas por organização — sem implicação de segurança
d) Log Archive Account é a conta de backup da Audit Account

**Gabarito: B** — Separação de funções (Separation of Duties): o analista de segurança que investiga um incidente na Audit Account não deve ter permissão para modificar ou excluir os logs de evidência no Log Archive Account. Se um insider malicioso (ou um analista comprometido) tentasse cobrir rastros, precisaria comprometer DUAS contas diferentes (Audit + Log Archive) com SCPs e Object Lock independentes. O Log Archive Account tem SCP que proíbe a exclusão de logs e geralmente é acessado apenas pelo serviço CloudTrail, não por humanos.

---

## 8. Roteiro de Gravação

### Aula 9.1 — Multi-Account Security e IAM Identity Center (55 min)

**Abertura (3 min):**
"Boa tarde! Chegamos ao Módulo 9 — o penúltimo módulo antes do capstone. Hoje vamos conectar todos os pontos: como governamos uma organização com múltiplas contas, como gerenciamos identidades centralizadas com IAM Identity Center, e como estruturamos o acesso seguro entre contas.

O Banco Meridian tem 6 contas AWS. Mas empresas maiores têm centenas ou milhares de contas. O desafio de identidade e governança nesses ambientes é enorme. IAM Identity Center e Organizations são as ferramentas que resolvem isso."

**Bloco 1 — Delegated Administration (10 min):**
"[Mostrar tabela de delegated administration]

A grande maioria dos serviços de segurança AWS suporta delegated administration via Organizations. Isso significa que você ESCOLHE qual conta administra o serviço para toda a organização.

Para o Banco Meridian, toda a administração de segurança vai para a Audit Account. Dessa forma: (1) Analistas de segurança trabalham na Audit Account — nunca precisam de acesso direto às contas de produção. (2) Findings de todas as contas aparecem no painel da Audit Account. (3) Se a conta Production for comprometida, o atacante não tem acesso à conta Audit para desabilitar GuardDuty ou Security Hub.

[Demo ao vivo — habilitar delegated admin para Security Hub]
1. Management Account — Security Hub — Settings — Delegate administration
2. Account ID: 222222222222 (Audit)
3. Confirm

Agora, qualquer Security Hub admin na Audit Account vê findings de todas as contas."

**Bloco 2 — IAM Identity Center (20 min):**
"[Abrir console IAM Identity Center]

Identity Center é o SSO nativo da AWS. Um login único acessa todas as contas e todos os serviços com as permissões corretas.

[Configurar Identity Source: External IdP]

Para o Banco Meridian, usamos Azure AD como IdP (a maioria das empresas). O SCIM sync garante que quando um funcionário é contratado ou demitido no AD, o acesso AWS é provisionado ou revogado automaticamente.

[Criar Permission Sets]

Permission Sets são templates de permissão. Criei 5 para o Banco Meridian:
1. SecurityAuditReadOnly — para analistas de SOC
2. SecurityResponder — para SR de plantão com ações de contenção
3. DeveloperPowerUser — para desenvolvimento
4. DatabaseAdmin — para DBAs
5. BillingAdmin — apenas para FinOps

[Account Assignments]

Agora mapeio: quem acessa qual conta com qual Permission Set. O analista de SOC tem SecurityAuditReadOnly em TODAS as contas. O dev tem DeveloperPowerUser apenas na conta de Dev/Test.

[Mostrar o portal SSO do usuário]

O usuário faz login em myapps.microsoft.com (Azure AD) → é redirecionado para o portal IAM Identity Center → vê apenas as contas e roles que tem acesso → clica e assume a sessão com token temporário. Zero access keys de longo prazo."

**Bloco 3 — Log Archive Account (10 min):**
"[Mostrar diagrama da estrutura do Log Archive]

O Log Archive é a conta mais protegida da organização. Ela armazena as evidências de auditoria. Se um atacante conseguir deletar logs, pode apagar todas as evidências de seus ataques.

Nossa proteção:
1. SCP na OU Security proibindo DeleteObject e DeleteBucket
2. Object Lock em modo Compliance — nem root pode deletar
3. MFA Delete — qualquer delete de versão requer MFA físico
4. Acesso cross-account apenas para escrita (CloudTrail pode escrever, ninguém pode excluir)

[Demo ao vivo] Tentar excluir um objeto do bucket de logs — mostrar que é bloqueado pelo Object Lock."

**Bloco 4 — Separação de Funções e Recap (12 min):**
"[Mostrar tabela de separação de funções]

Um princípio crítico: nenhuma pessoa ou role deve ter permissões suficientes para tanto comprometer um sistema quanto cobrir as evidências desse comprometimento.

O analista de segurança pode investigar usando a Audit Account. Mas ele não pode modificar os logs no Log Archive Account. Se ele tentar acessar logs diretamente, não tem permissão.

O administrador do Log Archive pode gerenciar o bucket de logs. Mas ele não tem acesso às ferramentas de análise na Audit Account e não tem permissão para ver o conteúdo dos outros serviços de segurança.

Essa separação é o que garante que um insider malicioso ou uma conta comprometida não possa tanto atacar quanto apagar as evidências.

[Recap] Módulos 1-9 completados. Construímos do zero a arquitetura de segurança completa do Banco Meridian: governança com Organizations e SCPs, visibilidade com CloudTrail e CloudWatch, detecção com GuardDuty, postura com Security Hub e Config, investigação com Detective, proteção de dados com KMS e Macie, rede com VPC + WAF + Network Firewall, automação com EventBridge + Lambda, e agora governança multi-conta.

No próximo módulo, o Capstone — vamos colocar tudo em prática com um incidente real."

---

## 9. Avaliação do Módulo

**Questão 1 (2 pontos):** O Banco Meridian contratou uma empresa de consultoria de segurança para fazer um assessment de 60 dias na conta Production. Descreva como configurar o acesso seguro usando IAM Identity Center em vez de criar usuários IAM temporários.

**Gabarito:** (1) Criar um Identity Store Group no Identity Center: `ConsultoriaSeguranca-ExtAccess`. (2) Adicionar os consultores como usuários externos no Identity Store. (3) Criar Permission Set `ExternalSecurityAudit` com política read-only de segurança. (4) Account Assignment: grupo `ConsultoriaSeguranca-ExtAccess` → Permission Set `ExternalSecurityAudit` → conta Production. (5) Configurar MFA enforcement para esse grupo. (6) Configurar session duration máxima de 8h (forçar re-autenticação). (7) Após 60 dias: remover o Account Assignment ou desabilitar os usuários. Vantagem sobre IAM temporário: credenciais são temporárias por design, sem access keys de longo prazo, auditável no CloudTrail com identidade clara do Identity Center.

---

**Questão 2 (2 pontos):** Em uma organização com 50 contas AWS, como o AWS Config Aggregator centraliza a visão de conformidade na conta Audit?

**Gabarito:** Config Aggregator é configurado na conta Audit (admin delegado ou via Organizations). Ele coleta: Configuration Items de todos os recursos em todas as contas e regiões, avaliações de Config rules de todas as contas, conformidade de Conformance Packs. Dados são agregados automaticamente — sem necessidade de configuração em cada conta membro (quando usando Organizations). Na Audit Account, a visão mostra: "Em 50 contas, 1.243 recursos são NON_COMPLIANT na regra restricted-ssh". Com drill-down por conta, por recurso, por regra. O Aggregator não executa remediações — é apenas visibilidade. Para remediação multi-conta, usar SSM Automation com target multi-conta ou Firewall Manager.

---

**Questão 3 (2 pontos):** Por que o SCIM sync do Azure AD para IAM Identity Center não garante revogação IMEDIATA de acesso quando um usuário é demitido?

**Gabarito:** O SCIM sync desabilita o usuário no Identity Center quase imediatamente (minutos). Isso impede NOVOS logins. Porém, sessões AWS ATIVAS (tokens STS temporários já emitidos) continuam válidas até expirar, que pode ser de 1 a 12 horas (configurável via Permission Set session duration). Para revogação imediata: (1) Reduzir session duration para 1 hora nas Permission Sets críticas. (2) Criar automação: quando usuário é desabilitado no Identity Center, Lambda busca todas as sessões ativas via `sso-admin:ListAccountAssignments` e chama `iam:UpdateAccessKey` para revogar tokens. (3) Nas sessões assumidas via role: anexar política inline de Deny All com condição de TokenIssueTime. A combinação de SCIM rápido + session duration curto + revogação ativa é a abordagem completa.

---

**Questão 4 (2 pontos):** Qual é a diferença entre uma SCP aplicada na OU Security e uma bucket policy no Log Archive? Por que ambas são necessárias?

**Gabarito:** SCP na OU Security: aplica a TODAS as identidades em TODAS as contas na OU Security. Previne que qualquer ação de delete/modify seja executada nas contas de Log Archive ou Audit, mesmo por admins dessas contas. Não específica por recurso — é uma barreira geral. Bucket Policy no Log Archive: específica para o bucket de logs. Permite que apenas o serviço CloudTrail escreva, nega todas as ações de delete/modify para qualquer principal. Mais granular que a SCP. Por que ambas: defense in depth. SCP protege no nível de conta. Bucket Policy protege no nível de recurso. Para um atacante deletar os logs, precisaria: (1) comprometer a Management Account para remover a SCP, (2) comprometer a conta Log Archive com privilégios suficientes para modificar a bucket policy, (3) contornar o Object Lock (impossível em modo Compliance). Três camadas independentes.

---

**Questão 5 (2 pontos):** Descreva como você usaria o AWS Firewall Manager para garantir que WAF com as regras padrão do Banco Meridian esteja habilitado em todos os ALBs de todas as contas da organização.

**Gabarito:** (1) Designar conta de segurança como admin do Firewall Manager via Organizations. (2) Criar Security Policy no Firewall Manager: tipo WAF, scope = todos os ALBs em todas as contas da organização. (3) Configurar a Web ACL base com as regras mandatórias: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, Rate Limiting, IP Reputation. (4) Habilitar Auto-remediation: se um ALB não está associado à Web ACL, Firewall Manager automaticamente associa. (5) Configurar notification: se recurso fora de conformidade, notificar via SNS. Resultado: qualquer novo ALB criado em qualquer conta é automaticamente protegido pelo WAF padrão do Banco Meridian dentro de minutos. Admins de cada conta não conseguem remover ou modificar as regras mandatórias (controladas centralmente pelo Firewall Manager).
