# Módulo 01 — Fundamentos AWS Security

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 1, 2 e 5

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Explicar o modelo de responsabilidade compartilhada AWS por categoria de serviço
2. Aplicar os sete pilares do AWS Well-Architected Framework — Security Pillar
3. Estruturar uma hierarquia de contas AWS Organizations com OUs adequadas
4. Criar e auditar Service Control Policies (SCPs) preventivas
5. Configurar o AWS Control Tower com guardrails mandatórios e recomendados
6. Implementar políticas IAM seguindo o princípio do menor privilégio
7. Interpretar achados do IAM Access Analyzer

---

## 1. Modelo de Responsabilidade Compartilhada AWS

O modelo de responsabilidade compartilhada define o que a AWS gerencia ("segurança **da** nuvem") e o que o cliente gerencia ("segurança **na** nuvem"). A fronteira varia conforme o tipo de serviço.

### Tabela Completa por Serviço

| Camada de Responsabilidade | EC2 (IaaS) | RDS (PaaS gerenciado) | S3 (Armazenamento gerenciado) | Lambda (FaaS) | EKS (Kubernetes gerenciado) |
|---|---|---|---|---|---|
| **Hardware físico** | AWS | AWS | AWS | AWS | AWS |
| **Hipervisor e firmware** | AWS | AWS | AWS | AWS | AWS |
| **Rede física e DC** | AWS | AWS | AWS | AWS | AWS |
| **Sistema operacional host** | AWS | AWS | AWS | AWS | AWS |
| **Sistema operacional guest** | **Cliente** | AWS | N/A | AWS | AWS (nodes managed) |
| **Patches de SO** | **Cliente** | AWS | N/A | AWS | AWS (nodes managed) |
| **Runtime de aplicação** | **Cliente** | AWS | N/A | AWS | **Cliente** (containers) |
| **Configuração de rede (VPC/SGs)** | **Cliente** | **Cliente** | **Cliente** | **Cliente** | **Cliente** |
| **Criptografia de dados em repouso** | **Cliente** | **Cliente** | **Cliente** | **Cliente** | **Cliente** |
| **Criptografia em trânsito** | **Cliente** | **Cliente** | **Cliente** | **Cliente** | **Cliente** |
| **Gerenciamento de identidade (IAM)** | **Cliente** | **Cliente** | **Cliente** | **Cliente** | **Cliente** |
| **Controle de acesso ao bucket/recurso** | N/A | N/A | **Cliente** | **Cliente** | **Cliente** |
| **Configuração de backup** | **Cliente** | **Cliente** (enable) | **Cliente** | N/A | **Cliente** |
| **Monitoramento e logging** | **Cliente** | **Cliente** | **Cliente** | **Cliente** | **Cliente** |
| **Código da aplicação** | **Cliente** | **Cliente** | N/A | **Cliente** | **Cliente** |
| **Dependências/pacotes** | **Cliente** | N/A | N/A | **Cliente** | **Cliente** |

**Regra prática:** quanto mais gerenciado o serviço, mais responsabilidades a AWS assume na infraestrutura. O cliente **sempre** é responsável por dados, identidade, controle de acesso e configuração de rede.

---

## 2. AWS Well-Architected Framework — Security Pillar

O Security Pillar do AWS Well-Architected Framework define sete áreas de design fundamentais para construir sistemas seguros na nuvem.

### 7 Áreas de Design

| # | Área | Objetivo | Serviços AWS Principais |
|---|---|---|---|
| **1** | **Identity and Access Management** | Garantir que apenas identidades autorizadas acessem recursos | IAM, IAM Identity Center, Cognito, Organizations, SCPs |
| **2** | **Detection** | Identificar atividade maliciosa, mudanças não autorizadas e anomalias | CloudTrail, GuardDuty, Security Hub, Config, Macie |
| **3** | **Infrastructure Protection** | Proteger redes, sistemas e serviços computacionais | VPC, SGs, NACLs, WAF, Shield, Network Firewall, Inspector |
| **4** | **Data Protection** | Proteger dados em repouso e em trânsito | KMS, CloudHSM, S3 Encryption, Secrets Manager, Macie |
| **5** | **Incident Response** | Preparar e responder a eventos de segurança | Detective, EventBridge, Lambda, SSM, Step Functions |
| **6** | **Application Security** | Incorporar segurança no desenvolvimento de aplicações | Inspector, CodeGuru, CodePipeline (SAST/DAST), Secrets Manager |
| **7** | **Governance and Compliance** | Estabelecer controles, políticas e conformidade contínua | Config, Control Tower, Security Hub, Audit Manager, Organizations |

### Princípios de Design do Security Pillar

1. **Implemente uma base de identidade forte** — use princípio de menor privilégio, elimine credenciais de longo prazo, exija MFA
2. **Habilite rastreabilidade** — monitore, gere alertas e audite ações e mudanças em tempo real
3. **Aplique segurança em todas as camadas** — defesa em profundidade (edge network → VPC → subnet → instância → OS → aplicação → código)
4. **Automatize as melhores práticas de segurança** — software-defined security, infraestrutura como código, automação de resposta
5. **Proteja dados em trânsito e em repouso** — classifique dados, use encryption by default
6. **Mantenha pessoas afastadas dos dados** — reduza ou elimine o acesso direto aos dados de produção
7. **Prepare-se para eventos de segurança** — runbooks de IR, simulações de incidentes, mecanismos de isolamento

---

## 3. AWS Organizations

O AWS Organizations permite gerenciar múltiplas contas AWS como uma unidade, aplicar políticas centralizadas e consolidar faturamento.

### Conceitos Fundamentais

| Conceito | Descrição |
|---|---|
| **Organization** | Container raiz que agrupa todas as contas |
| **Root** | Nó raiz da hierarquia de OUs; SCPs aplicadas aqui afetam todas as contas |
| **Management Account** | Conta principal que criou a organização; nunca deve ter workloads |
| **Member Account** | Qualquer conta que não seja a Management Account |
| **Organizational Unit (OU)** | Agrupamento lógico de contas; permite aplicar SCPs por função |
| **Service Control Policy (SCP)** | Barreira máxima de permissões aplicada a OUs ou contas |

### Diagrama ASCII — Estrutura do Banco Meridian

**O que este diagrama representa:** A hierarquia de contas AWS do Banco Meridian é composta por quatro contas com funções distintas. A conta Management (111111111111) é o ponto de controle central; as contas Audit (222222222222) e Log Archive (333333333333) ficam isoladas na OU Security; a conta Production (444444444444) fica na OU homônima. Essa separação garante que um comprometimento em produção não propague-se para os logs de auditoria.

**Por que isso importa para o Banco Meridian:** O BACEN 4.893 e os padrões CIS AWS Foundations exigem segregação de ambientes e trilha de auditoria imutável. Com quatro contas separadas, o banco garante que a conta de logs nunca seja modificada por quem opera produção, atendendo ao requisito de não repúdio e rastreabilidade de operações financeiras sensíveis.

```
AWS Organizations — Banco Meridian (Management Account: 111111111111)
│
├── Root
│   │
│   ├── OU: Security
│   │   ├── Conta: Audit (222222222222)
│   │   └── Conta: Log Archive (333333333333)
│   │
│   ├── OU: Production
│   │   └── Conta: Production (444444444444)
│   │
│   ├── OU: Development
│   │   └── Conta: Dev/Test (555555555555)
│   │
│   └── OU: Sandbox
│       └── Conta: Sandbox (666666666666)
│
└── [SCPs aplicadas na Root afetam TODAS as contas]
```

---

## 4. Service Control Policies (SCPs)

As SCPs definem a barreira máxima de permissões para contas em uma OU. Mesmo que uma política IAM conceda uma permissão, a SCP pode negá-la.

### Estratégias: Allow List vs Deny List

| Estratégia | Como funciona | Quando usar |
|---|---|---|
| **Deny List (recomendada)** | Começa com FullAWSAccess e adiciona negações explícitas | Ambientes estabelecidos; fácil de manter |
| **Allow List** | Remove FullAWSAccess e permite apenas ações específicas | Ambientes altamente restritivos (sandbox, regulatório) |

**Importante:** SCPs não afetam o Management Account. Aplique controles de segurança extras na Management Account via outros mecanismos.

### SCP 1 — DenyRootAccess

**O que este comando faz:** Esta SCP aplica uma negação explícita para qualquer ação executada pelo principal raiz (`root`) de qualquer conta member da organização. Ela é avaliada antes de qualquer política IAM e não pode ser sobrescrita por permissões individuais. Ao usar o wildcard `"Action": "*"`, cobre absolutamente todas as APIs AWS, impedindo o uso da conta root para operações do dia a dia.

**Por que isso importa para o Banco Meridian:** Em um banco tier 2 com quatro contas AWS, o uso inadvertido da conta root representa risco crítico: credenciais root não podem ser rastreadas por papéis individuais, não podem ser limitadas por SCPs (a própria SCP não afeta a Management Account) e têm acesso irrestrito à faturamento, encerramento de conta e recuperação de credenciais. O BACEN 4.893 exige controles de acesso privilegiado; bloquear root via SCP é o controle preventivo mais eficaz para as member accounts.

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

**Propósito:** Impede o uso da conta root em todas as member accounts. A conta root não deve ser usada para operações do dia a dia.

### SCP 2 — DenyRegionsNotApproved

**O que este comando faz:** Esta SCP nega qualquer operação em regiões AWS que não estejam na lista de aprovadas (São Paulo `sa-east-1`, Virgínia `us-east-1` e Ohio `us-east-2`). O uso de `NotAction` — em vez de `Action` — garante que serviços globais como IAM, CloudFront, Route 53 e Organizations, que não possuem endpoint regional, continuem funcionando normalmente. A condição `StringNotEquals` inverte a lógica: a negação se aplica a todas as regiões que não estão na lista.

**Por que isso importa para o Banco Meridian:** Regulamentações bancárias brasileiras e a política de soberania de dados do BACEN exigem que dados de clientes e operações financeiras residam em regiões aprovadas. Sem este controle, um desenvolvedor ou atacante poderia provisionar recursos em qualquer região do mundo (incluindo jurisdições sem tratado de cooperação judicial com o Brasil), tornando a auditoria e o response a incidentes muito mais complexos. A região `sa-east-1` (São Paulo) garante latência mínima e conformidade com a LGPD.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*",
        "iam:*",
        "route53:*",
        "support:*",
        "sts:*",
        "globalaccelerator:*",
        "waf:*",
        "budgets:*",
        "cur:*",
        "organizations:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "sa-east-1",
            "us-east-1",
            "us-east-2"
          ]
        }
      }
    }
  ]
}
```

**Propósito:** Restringe operações às regiões aprovadas pelo Banco Meridian (São Paulo, Virgínia, Ohio). Serviços globais como IAM e CloudFront são explicitamente excluídos via `NotAction`.

### SCP 3 — DenyUnencryptedS3

**O que este comando faz:** Esta SCP bloqueia duas operações distintas: (1) `s3:PutObject` sem o cabeçalho de criptografia server-side (`x-amz-server-side-encryption`) especificando SSE-KMS ou SSE-S3 (AES256); (2) `s3:CreateBucket` sem qualquer configuração de criptografia. O resultado é que nenhum objeto pode ser gravado sem criptografia e nenhum bucket pode ser criado sem política de criptografia — mesmo que o usuário possua permissões IAM plenas.

**Por que isso importa para o Banco Meridian:** A Resolução BACEN 4.893 determina que dados de clientes e transações financeiras sejam armazenados com criptografia adequada. Em um banco com dados de cartões, extratos e informações cadastrais, um bucket S3 sem criptografia representa exposição direta a requisitos de notificação de vazamento (LGPD Art. 48) e multas regulatórias. Esta SCP garante conformidade técnica de forma preventiva — não depende de treinamento ou boa vontade dos times de desenvolvimento.

```json
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
          "s3:x-amz-server-side-encryption": [
            "aws:kms",
            "AES256"
          ]
        }
      }
    },
    {
      "Sid": "DenyS3CreateBucketWithoutEncryption",
      "Effect": "Deny",
      "Action": "s3:CreateBucket",
      "Resource": "*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    }
  ]
}
```

**Propósito:** Garante que todo objeto armazenado no S3 use criptografia server-side (SSE-KMS ou SSE-S3), alinhado ao requisito BACEN 4.893.

### SCP 4 — RequireMFAForSensitiveActions

**O que este comando faz:** Esta SCP usa a condição `BoolIfExists: aws:MultiFactorAuthPresent: false` para negar as ações listadas sempre que a sessão não tiver sido autenticada com MFA. O `BoolIfExists` é importante: ele avalia a condição apenas se a chave existir na requisição; se a chave não existir (ex.: em chamadas via roles de serviço), a condição não se aplica. As ações cobertas são todas as que modificam identidades, políticas ou chaves de acesso — o núcleo de um ataque de escalonamento de privilégios.

**Por que isso importa para o Banco Meridian:** Em ambientes financeiros, o comprometimento de uma credencial IAM sem MFA pode resultar em criação de backdoors, escalada de privilégios e exfiltração de dados. Esta SCP implementa o controle preventivo de autenticação multifator para operações críticas, alinhando-se ao controle AC-17 do NIST SP 800-53 e às recomendações do CIS AWS Foundations Benchmark. Para o Banco Meridian com quatro contas, isso impede que um atacante com acesso inicial crie novas roles ou chaves de acesso sem passar pelo segundo fator.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIAMModificationsWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "organizations:LeaveOrganization"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**Propósito:** Exige MFA para modificações críticas de IAM. Protege contra comprometimento de credenciais sem MFA executando mudanças privilegiadas.

### SCP 5 — DenyDisableCloudTrail

**O que este comando faz:** Esta SCP bloqueia as quatro ações que um atacante utilizaria para apagar rastros após um comprometimento: parar o logging (`StopLogging`), excluir a trilha (`DeleteTrail`), alterar configurações da trilha (`UpdateTrail`) e modificar os event selectors que definem quais eventos são registrados (`PutEventSelectors`). A condição `StringNotEquals` cria uma exceção para um único ARN — a role administrativa dedicada — garantindo que operações legítimas ainda sejam possíveis.

**Por que isso importa para o Banco Meridian:** O CloudTrail é a espinha dorsal de auditoria do banco: sem ele, não há rastreabilidade de quem fez o quê em qual conta. Atacantes sofisticados habitualmente desabilitam logging como primeira ação pós-comprometimento. Para o Banco Meridian, a perda do CloudTrail impossibilitaria a resposta a incidentes forense, violaria o requisito de trilha de auditoria do BACEN 4.893 e poderia comprometer investigações regulatórias. Esta SCP transforma o CloudTrail em um controle imutável para todas as contas member.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailModification",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::111111111111:role/CloudTrailAdminRole"
          ]
        }
      }
    }
  ]
}
```

**Propósito:** Previne que atacantes (ou insiders) desabilitem o CloudTrail para cobrir rastros. Apenas a role dedicada de administração pode modificar trails.

---

## 5. AWS Control Tower

O Control Tower automatiza a criação de landing zones seguras e aplica guardrails de governança em múltiplas contas.

### Componentes Principais

| Componente | Função |
|---|---|
| **Landing Zone** | Ambiente multi-conta pré-configurado com estrutura de OUs, contas e políticas base |
| **Account Factory** | Provisionamento automatizado de novas contas via Service Catalog ou AFT (Terraform) |
| **Guardrails** | Controles preventivos (SCPs) e detectivos (Config rules) aplicados às OUs |
| **Audit Account** | Conta dedicada para auditoria; recebe notificações de violação de guardrails |
| **Log Archive Account** | Conta dedicada que centraliza logs de CloudTrail e Config de todas as contas |

### Guardrails: Mandatórios vs Recomendados

| Tipo | Comportamento | Exemplos |
|---|---|---|
| **Mandatórios** | Sempre habilitados, não podem ser desabilitados | Não permitir mudanças nas contas de log; não desabilitar CloudTrail |
| **Recomendados** | Habilitados por padrão, podem ser desabilitados | Detectar bucket S3 público; detectar MFA não habilitado |
| **Opcionais** | Desabilitados por padrão, podem ser habilitados | Detectar instância EC2 sem tag; detectar EBS não criptografado |

---

## 6. IAM Deep Dive

### Tipos de Políticas IAM

| Tipo de Política | Onde é Anexada | Scope | Exemplo de Uso |
|---|---|---|---|
| **Identity-based Policy** | User, Group, Role | Define o que a identidade pode fazer | Política de administrador de S3 |
| **Resource-based Policy** | Recurso (S3, KMS, SQS...) | Define quem pode acessar o recurso | Bucket policy S3 para acesso cross-account |
| **Permissions Boundary** | User ou Role | Define o máximo de permissões que pode ser concedido | Limitar devs a criar roles apenas com boundary |
| **Session Policy** | Sessão STS AssumeRole | Restringe permissões temporárias de uma sessão | Acesso temporário restrito a um prefixo S3 |
| **SCP (Organizations)** | OU ou Conta | Barreira máxima para member accounts | Bloquear regiões não aprovadas |
| **Resource Control Policy (RCP)** | OU ou Conta | Controla quem pode acessar recursos na conta | Exigir VPC Endpoint para acesso ao S3 |

### IAM Roles — Tipos e Casos de Uso

| Tipo de Role | Descrição | Trust Principal | Exemplo |
|---|---|---|---|
| **AWS Service Role** | Role usada por serviços AWS | Serviço AWS (ex: `ec2.amazonaws.com`) | EC2 acessa S3 |
| **Service-Linked Role** | Role gerenciada pela AWS para integração de serviço | Serviço AWS específico | GuardDuty cria role automaticamente |
| **Cross-Account Role** | Role assumida por conta diferente | Conta AWS externa + External ID | Time de auditoria acessa conta de prod |
| **Identity Provider Role** | Role assumida via federação SAML/OIDC | IdP (Okta, Azure AD) | SSO corporativo |
| **Instance Profile** | Wrapper de role para EC2 | `ec2.amazonaws.com` | Aplicação em EC2 acessa DynamoDB |

### Exemplo: Cross-Account Role com External ID

**O que este documento faz:** Esta trust policy define quem pode assumir a role criada na conta de destino. O bloco `Principal` especifica que apenas a role `AuditRole` na conta Audit (222222222222) pode fazer a chamada `sts:AssumeRole`. A condição `StringEquals` com `sts:ExternalId` exige que o solicitante forneça um token secreto previamente combinado. Sem esse token, mesmo que a conta correta tente assumir a role, a AWS negará a operação.

**Por que isso importa para o Banco Meridian:** O Banco Meridian pode contratar empresas de auditoria externa que usam uma única conta AWS para atender múltiplos clientes. Sem o External ID, a empresa de auditoria poderia usar sua role para acessar a conta do banco a pedido de outro cliente mal-intencionado — o chamado "confused deputy problem". O External ID `BancoMeridian-Audit-2026-XY9Z` funciona como uma senha de sessão: garante que apenas o contexto legítimo do banco, com o segredo compartilhado, consiga o acesso, protegendo os dados financeiros de acessos cross-tenant indevidos.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::222222222222:role/AuditRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "BancoMeridian-Audit-2026-XY9Z"
        }
      }
    }
  ]
}
```

**External ID:** Protege contra o "confused deputy problem". O External ID deve ser um valor único e secreto combinado entre o cliente e o provedor externo.

### Exemplo: Permissions Boundary

**O que este documento faz:** Esta Permissions Boundary define dois blocos: o primeiro (`AllowSpecificServices`) lista os serviços que a identidade pode usar; o segundo (`DenyPrivilegeEscalation`) nega explicitamente todas as ações IAM que permitiriam criar novas identidades ou elevar privilégios. Mesmo que a política identity-based da role ou usuário conceda `iam:CreateRole`, o boundary nega — e a AWS sempre aplica o resultado mais restritivo. O boundary atua como um teto que não pode ser ultrapassado, independentemente do que as políticas identity-based permitam.

**Por que isso importa para o Banco Meridian:** Em um banco com times de desenvolvimento que criam funções Lambda e roles de execução, o risco de escalonamento de privilégios é real. Um desenvolvedor com permissão de criar roles poderia criar uma role com `AdministratorAccess` e usá-la para acessar dados de produção. Ao aplicar este boundary em todas as roles criadas por desenvolvedores, o Banco Meridian garante que nenhuma identidade criada pelo time de dev possa ter permissões além do escopo de S3, DynamoDB, Lambda e logs — mesmo que o desenvolvedor tente contornar as políticas.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSpecificServices",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:*",
        "lambda:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPrivilegeEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:CreateAccessKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**Propósito:** Impede que desenvolvedores criem identidades com permissões além do boundary, mesmo que possuam permissões IAM na política identity-based.

### IAM Access Analyzer

O IAM Access Analyzer identifica recursos compartilhados com entidades externas e achados de acesso não intencional.

| Tipo de Achado | Descrição | Severidade |
|---|---|---|
| **Public Access** | Recurso acessível publicamente (bucket S3, KMS key, SQS queue) | Alto |
| **Cross-Account Access** | Recurso acessível por conta AWS externa não esperada | Médio |
| **Unused Access** | Role/usuário/access key sem uso nos últimos 90 dias | Informativo |
| **External Principal** | Acesso concedido a principal fora da zona de confiança | Alto |
| **Policy Generation** | Sugere política de menor privilégio baseada em CloudTrail | N/A |

#### Como Calcular Permissões Mínimas (Policy Generation)

1. Habilite o CloudTrail na conta (necessário para analisar atividade real)
2. No IAM Access Analyzer, selecione **Gerar política**
3. Especifique o IAM user ou role alvo
4. Defina o período de análise (máximo 90 dias)
5. O Access Analyzer gera uma política baseada nas ações realmente executadas
6. Revise, ajuste e substitua a política permissiva original

---

## 7. Exemplos de IAM Policies Completos

### Policy 1 — Analista de Segurança (Read-Only Security)

**O que este documento faz:** Esta política concede permissões de leitura (`Get*`, `List*`, `Describe*`) para os principais serviços de segurança da AWS: GuardDuty, Security Hub, CloudTrail, Config, IAM, IAM Access Analyzer, Inspector e Macie. O uso de wildcards nas ações de leitura é uma prática aceita nesse contexto porque não concede nenhum poder de modificação — todos os verbos são passivos. A política cobre apenas operações de consulta, garantindo que o analista possa investigar sem risco de alterar configurações.

**Por que isso importa para o Banco Meridian:** O time de segurança do Banco Meridian (conta Audit — 222222222222) precisa de visibilidade em tempo real sobre todas as contas da organização sem ter poder de modificação. Esta política implementa o princípio de menor privilégio para o papel de analista: acesso de leitura amplo nos serviços de detecção e auditoria, sem nenhuma capacidade de alterar configurações de segurança, criar identidades ou modificar recursos de produção. Isso atende ao requisito de segregação de funções (SoD) exigido em ambientes regulados pelo BACEN.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:Get*",
        "guardduty:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:Describe*",
        "config:Get*",
        "config:List*",
        "config:Describe*",
        "iam:Get*",
        "iam:List*",
        "iam:Generate*",
        "access-analyzer:Get*",
        "access-analyzer:List*",
        "inspector2:Get*",
        "inspector2:List*",
        "macie2:Get*",
        "macie2:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Policy 2 — Resposta a Incidentes (IR Role)

**O que este documento faz:** Esta política para a role de Incident Response tem dois blocos com finalidades distintas. O primeiro (`IRReadAccess`) concede leitura ampla sem restrição de região: descrever instâncias EC2, buscar logs do CloudWatch Logs, acessar objetos S3, consultar CloudTrail e usar o Amazon Detective para investigação forense. O segundo (`IRResponseActions`) concede ações de contenção e remediação — como criar snapshot de volume, modificar atributos de instância, revogar regras de Security Group e manipular access keys — mas restringe essas ações às regiões onde o banco opera (`sa-east-1` e `us-east-1`), evitando ações acidentais em outras regiões.

**Por que isso importa para o Banco Meridian:** Em um incidente de segurança, cada segundo conta. A role de IR precisa de permissões suficientes para conter o ataque (isolar instâncias, revogar credenciais comprometidas, criar evidências forenses) sem ter acesso permanente a esses poderes. Ao separar leitura irrestrita de resposta restrita por região, o Banco Meridian garante que o time de IR possa agir rapidamente nas regiões de produção sem risco de impacto acidental em outras regiões. Esta política também é compatível com as SCPs ativas, respeitando os limites geográficos aprovados pelo banco.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IRReadAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:Get*",
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "s3:GetObject",
        "s3:ListBucket",
        "cloudtrail:LookupEvents",
        "detective:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IRResponseActions",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSnapshot",
        "ec2:ModifyInstanceAttribute",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "iam:DetachRolePolicy",
        "iam:DetachUserPolicy"
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

---

## 8. Atividades de Fixação

**1.** Uma SCP com `"Effect": "Deny"` e `"Action": "s3:DeleteBucket"` está aplicada na OU Production. O administrador da conta tem uma política IAM com `"Effect": "Allow"` para `s3:DeleteBucket`. O que acontece quando ele tenta excluir um bucket?

a) A ação é permitida porque a política IAM do administrador tem `Allow`
b) A ação é negada porque a SCP tem precedência sobre políticas IAM
c) A ação é permitida porque o administrador tem permissão explícita
d) A ação depende do bucket policy do S3

**Gabarito: B** — SCPs funcionam como barreira máxima. Mesmo com Allow no IAM, o Deny explícito da SCP prevalece (exceto para a Management Account).

---

**2.** O IAM Access Analyzer do Banco Meridian encontrou um achado indicando que o bucket `s3://meridian-relatorios-financeiros` tem acesso público de leitura. Qual a prioridade de resposta e a ação imediata?

a) Baixa prioridade; analisar em 30 dias
b) Alta prioridade; ativar S3 Block Public Access imediatamente
c) Média prioridade; criar ticket para o time de desenvolvimento
d) Alta prioridade; excluir o bucket imediatamente

**Gabarito: B** — Bucket público com dados financeiros é risco crítico. S3 Block Public Access deve ser habilitado imediatamente, seguido de análise de exposição de dados.

---

**3.** Você precisa criar uma role para uma aplicação em EC2 acessar o DynamoDB apenas na tabela `meridian-transacoes`. Qual é a forma correta de limitar o acesso?

a) Criar usuário IAM com AccessKey para a aplicação
b) Criar uma role com Instance Profile e Resource ARN específico na política
c) Compartilhar credenciais root via Secrets Manager
d) Criar um bucket S3 para armazenar as credenciais

**Gabarito: B** — Instance Profiles são o mecanismo correto para EC2. As credenciais são temporárias e rotacionadas automaticamente. A política deve referenciar o ARN específico da tabela DynamoDB.

---

**4.** Qual das seguintes SCPs implementa corretamente o bloqueio de regiões não aprovadas SEM impactar serviços globais como IAM e CloudFront?

a) `"Action": "ec2:*", "Resource": "*", "Condition": StringNotEquals region`
b) `"NotAction": ["iam:*","cloudfront:*","route53:*"], "Resource": "*", "Condition": StringNotEquals region`
c) `"Action": "*", "Resource": "*", "Condition": StringNotEquals region`
d) `"Action": ["ec2:*","s3:*","rds:*"], "Resource": "*"` sem condição

**Gabarito: B** — O uso de `NotAction` com a lista de serviços globais é o padrão correto para garantir que serviços regionais sejam bloqueados sem afetar serviços globais necessários.

---

**5.** O que é um "Permissions Boundary" e como ele difere de uma SCP?

a) São equivalentes; ambos definem a barreira máxima de permissões
b) Permissions Boundary se aplica a usuários/roles individuais; SCP se aplica a contas/OUs
c) SCP se aplica a usuários individuais; Permissions Boundary se aplica a OUs
d) Permissions Boundary só funciona em organizações; SCP funciona em qualquer conta

**Gabarito: B** — Permissions Boundary é uma política IAM que limita o máximo de permissões de uma identidade específica dentro de uma conta. SCP limita o máximo de permissões para todas as identidades dentro de uma conta ou OU.

---

## 9. Roteiro de Gravação

### Aula 1.1 — Organizations, SCPs e Control Tower (50 min)

**Abertura (2 min):**
"Olá, pessoal! Sou [nome] e bem-vindos ao Módulo 1 do Curso de AWS Cloud Security Operations. Hoje vamos começar pelos fundamentos que sustentam toda a arquitetura de segurança AWS: o modelo de responsabilidade compartilhada, o Well-Architected Security Pillar, e como o AWS Organizations com SCPs e Control Tower formam a espinha dorsal da governança multi-conta. Vamos usar como contexto o Banco Meridian, nossa empresa-cenário ao longo de todo o curso."

**Bloco 1 — Modelo de Responsabilidade Compartilhada (8 min):**
"Vamos começar com a pergunta mais importante em qualquer conversa de segurança AWS: o que é meu e o que é da AWS? O modelo de responsabilidade compartilhada divide as responsabilidades entre a AWS e o cliente. A AWS cuida da segurança **da** nuvem — hardware, hipervisor, infraestrutura física. Você cuida da segurança **na** nuvem — dados, identidade, configuração, código.

[Mostrar tabela de responsabilidades]

Percebam que a linha de divisão muda conforme o serviço. No EC2, você tem responsabilidade pelo sistema operacional. No Lambda, a AWS gerencia o runtime. Mas em todos os casos, você é responsável pelos seus dados e pelo controle de acesso.

No Banco Meridian, esse conceito é crítico. Se o cliente armazenar dados de conta bancária num bucket S3 público, a falha é **do cliente**, não da AWS — mesmo que a AWS opere a infraestrutura S3."

**Bloco 2 — Well-Architected Security Pillar (7 min):**
"O AWS Well-Architected Framework tem 6 pilares, e o Security Pillar define 7 áreas de design. Vamos passá-las rapidamente e depois aprofundar cada uma ao longo do curso.

[Percorrer as 7 áreas com exemplos práticos do Banco Meridian para cada uma]

O que preciso que vocês gravem: cada decisão arquitetural que tomarem deve ser avaliada sob essas 7 lentes. Uma feature nova de open banking — como eu protejo os dados? Como eu detecto acesso não autorizado? Como eu respondo a um incidente?"

**Bloco 3 — AWS Organizations (10 min):**
"AWS Organizations é o ponto de controle central para ambientes multi-conta. No Banco Meridian temos quatro contas: Management, Audit, Log Archive e Production.

[Mostrar diagrama ASCII da estrutura]

A Management Account é especial — ela nunca deve ter workloads de produção. É dela que partem as SCPs, o Control Tower, o Organizations. Se ela for comprometida, toda a organização está comprometida.

OUs são agrupamentos lógicos. Coloco o Audit e o Log Archive na OU Security porque eles têm políticas específicas de proteção. A Production fica isolada com políticas mais restritivas.

A regra de ouro: **nunca use a Management Account para rodar aplicações**."

**Bloco 4 — Service Control Policies (15 min):**
"SCPs são a ferramenta mais poderosa de governança preventiva no AWS Organizations. Elas definem o teto máximo de permissões que qualquer identidade em uma conta pode ter.

[Abrir console AWS Organizations — aba Policies — SCPs]

Vou criar a DenyRootAccess. [Mostrar JSON da SCP] Essa política diz: qualquer ação, em qualquer recurso, é negada se o principal for a conta root. Simples e poderosa.

[Criar DenyRegionsNotApproved]
Aqui temos um padrão importante: uso NotAction em vez de Action. Por quê? Porque IAM, CloudFront, Route 53 são serviços globais — eles não têm uma 'região' de deploy. Se eu bloqueasse action:* para regiões não aprovadas, quebraria o IAM. Com NotAction, digo 'tudo exceto esses serviços deve respeitar a restrição de região'.

[Criar DenyUnencryptedS3]
Essa SCP alinha com o BACEN 4.893 — dados sensíveis devem ser criptografados. Qualquer PutObject sem header de criptografia é negado.

Dica para a prova SCS-C02: memorizem a diferença entre Allow List e Deny List para SCPs. Deny List começa com FullAWSAccess e adiciona negações. É mais fácil de manter. Allow List remove tudo e permite apenas o necessário — mais restritiva, mais trabalhosa."

**Bloco 5 — Control Tower (8 min):**
"Control Tower automatiza tudo que acabamos de configurar manualmente. Landing zone, OUs base, contas Audit e Log Archive, guardrails preventivos e detectivos — tudo provisionado em cliques.

[Mostrar console Control Tower]

Guardrails Mandatórios nunca podem ser desabilitados. Eles garantem que o CloudTrail nunca seja desabilitado nas contas gerenciadas e que os logs nunca sejam alterados.

Guardrails Recomendados — eu recomendo habilitar todos para o Banco Meridian. Detecção de S3 público, MFA não configurado, EBS não criptografado.

Account Factory: quando o Banco Meridian precisar criar uma nova conta para um projeto específico, o Account Factory garante que essa conta nasça já com todas as políticas, roles e configurações de segurança aplicadas. Zero configuração manual."

**Fechamento (0 min):**
"Na próxima aula, vamos mergulhar no IAM — políticas, roles, o princípio do menor privilégio e o IAM Access Analyzer. Até lá!"

---

### Aula 1.2 — IAM Deep Dive e Access Analyzer (50 min)

**Abertura (2 min):**
"Bem-vindos de volta! Na aula anterior construímos a fundação organizacional. Agora vamos ao controle de identidade — o IAM. Se as SCPs são as paredes externas, o IAM é a fechadura de cada porta."

**Bloco 1 — Tipos de Políticas IAM (10 min):**
"Há 6 tipos de política no IAM, e entender quando usar cada um é fundamental tanto para a prova SCS-C02 quanto para o dia a dia de operações.

[Percorrer tabela de tipos de políticas]

A confusão mais comum: qual é a diferença entre uma Identity-based Policy e uma Permissions Boundary?

Identity-based: define o que a identidade CAN do. É o conjunto de permissões.
Permissions Boundary: define o máximo que a identidade PODE ter. É o teto.

Para ter acesso a uma ação, a identidade precisa que a ação seja permitida na Identity-based Policy E dentro do Permissions Boundary (E não negada por SCP).

[Mostrar diagrama de avaliação de políticas AWS]

O processo de avaliação: SCP → Resource Policy → Identity Policy → Permissions Boundary → Session Policy. Deny explícito em qualquer camada vence tudo."

**Bloco 2 — IAM Roles (10 min):**
"Roles são a espinha dorsal da segurança AWS moderna. Nunca use Access Keys quando uma Role resolve.

[Mostrar exemplo de criação de Instance Profile para EC2]

A trust policy define QUEM pode assumir a role. A permissions policy define O QUE a role pode fazer. Separe sempre essas duas preocupações.

[Mostrar exemplo de cross-account role com External ID]

O External ID resolve o 'confused deputy problem'. Imagine que você contratou uma empresa de auditoria terceirizada. Ela pede para você criar uma role para o account deles. Sem External ID, essa empresa poderia assumir sua role de qualquer outra conta de cliente deles. Com External ID, apenas o contexto correto consegue assumir."

**Bloco 3 — Princípio do Menor Privilégio (10 min):**
"Least privilege é simples de entender e difícil de implementar. O objetivo: cada identidade deve ter exatamente as permissões que precisa para sua função, nada a mais.

Na prática, o que vejo nas empresas: roles com AdministratorAccess em produção porque 'foi mais fácil na época'. Esse é o caminho para o breach.

Como calcular permissões mínimas:
1. Habilite CloudTrail — ele registra cada API call
2. Use IAM Access Analyzer Policy Generation — analisa 90 dias de CloudTrail e gera a política mínima
3. Revise a política gerada — às vezes inclui ações one-time que podem ser removidas
4. Aplique e monitore — algum sistema vai quebrar; ajuste cirurgicamente

[Demonstração ao vivo da Policy Generation no console]"

**Bloco 4 — IAM Access Analyzer (10 min):**
"Access Analyzer tem três funções principais: detectar acesso externo não intencional, identificar acessos não utilizados e gerar políticas de menor privilégio.

[Mostrar console Access Analyzer — External Access Analyzer]

Vou criar um analyzer organizacional — ele analisa todas as contas da organização. Um analyzer só de conta analisa só a conta local.

[Mostrar um achado de bucket S3 público]

Achado: `s3://meridian-backup-dev` tem acesso público. Vejo o nível de acesso (leitura), o recurso afetado, a condição que permite. Posso arquivar se for intencional (bucket de site estático, por exemplo) ou remediar imediatamente.

[Mostrar Unused Access Analyzer]

Esse analyzer encontra roles, usuários e access keys sem uso. No Banco Meridian, encontrei 3 access keys com mais de 180 dias sem uso. Red flag — devo revogar essas chaves imediatamente."

**Bloco 5 — Demo Hands-on e Consolidação (8 min):**
"[Demo ao vivo] Vou criar do zero a estrutura IAM para o time de segurança do Banco Meridian:
1. Role SecurityAuditRole com permissions boundary
2. Política read-only para serviços de segurança
3. Cross-account role para acesso do time de auditoria à conta Production
4. Verificar com Policy Simulator que as permissões estão corretos"

**Fechamento (0 min):**
"Nas próximas aulas, vamos para o logging centralizado — CloudTrail, CloudTrail Lake e a arquitetura de logging multi-conta do Banco Meridian. Os fundamentos que vimos hoje são a base para tudo que vem à frente."

---

## 10. Avaliação do Módulo

**Questão 1 (2 pontos):** Descreva o modelo de responsabilidade compartilhada da AWS para o serviço EC2. Quais são as responsabilidades da AWS e quais são do cliente para uma instância EC2 rodando um servidor web com banco de dados?

**Gabarito:** AWS é responsável por: hardware físico, data center, hipervisor, rede física, sistema operacional host. Cliente é responsável por: sistema operacional guest (patches, hardening), configuração de rede (VPC, Security Groups), criptografia de dados (EBS encryption), gestão de identidade (IAM roles, credenciais), configuração de backup, monitoramento e logging, código da aplicação, dependências/pacotes.

---

**Questão 2 (2 pontos):** O Banco Meridian detectou que a conta de desenvolvimento está provisionando instâncias EC2 nas regiões us-west-2 (Oregon) e eu-west-1 (Irlanda), regiões não aprovadas pela política de segurança. Como você resolveria isso usando SCPs? Escreva a SCP completa.

**Gabarito:** Criar uma SCP DenyNonApprovedRegions com `"Effect": "Deny"`, `"NotAction": ["iam:*","cloudfront:*","route53:*","support:*","sts:*"]`, `"Resource": "*"`, `"Condition": {"StringNotEquals": {"aws:RequestedRegion": ["sa-east-1","us-east-1","us-east-2"]}}`. Aplicar na OU Development.

---

**Questão 3 (2 pontos):** Explique a diferença entre uma Permissions Boundary e uma SCP. Em qual cenário você usaria uma Permissions Boundary em vez de (ou além de) uma SCP?

**Gabarito:** SCP: barreira máxima de permissões no nível de conta/OU dentro do AWS Organizations. Afeta todas as identidades na conta. Permissions Boundary: barreira máxima para uma identidade IAM específica (user ou role) dentro de uma conta. Cenário de uso de Permissions Boundary: quando se delega a criação de roles para desenvolvedores (ex: para um projeto de microserviços), mas se quer garantir que as roles criadas por eles nunca excedam um conjunto de permissões predefinido. SCP não resolveria porque ela bloqueia na conta, não na identidade individual.

---

**Questão 4 (2 pontos):** Um auditor externo do Banco Meridian precisa ter acesso read-only à conta de Production (444444444444) para revisar configurações de segurança. Como você implementaria esse acesso de forma segura usando IAM?

**Gabarito:** 1. Na conta Production, criar uma role `ExternalAuditRole` com trust policy permitindo a conta da auditoria (com External ID) e permissions policy de SecurityAudit (AWS Managed) ou custom read-only. 2. Na conta da auditoria, criar uma policy permitindo `sts:AssumeRole` com o ARN da role e o External ID. 3. Fornecer ao auditor o ARN da role e o External ID (secreto). 4. O auditor faz `aws sts assume-role --role-arn arn:aws:iam::444444444444:role/ExternalAuditRole --external-id <ID>` para obter credenciais temporárias.

---

**Questão 5 (2 pontos):** O IAM Access Analyzer do Banco Meridian gerou um achado do tipo "Unused Access" para a role `LambdaProcessamentoBoletos` que não é usada há 120 dias. Descreva o processo de investigação e as ações que você tomaria.

**Gabarito:** 1. Investigar no CloudTrail: últimas ações executadas pela role, quem a assume, quando. 2. Verificar se o Lambda associado ainda existe e se está em uso. 3. Se o Lambda foi descontinuado: desativar a role (não deletar imediatamente), monitorar por 30 dias. 4. Se sem incidentes, excluir a role. 5. Se o Lambda ainda existe mas a role não é usada: investigar se o Lambda está broken (erro de permissão). 6. Documentar a investigação e o resultado no JIRA/ITSM.
