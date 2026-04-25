# Módulo 04 — Postura de Segurança e Conformidade

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 3 (Security and Compliance)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Configurar o Security Hub com múltiplos standards de conformidade
2. Criar conformance packs customizados para BACEN 4.893 no AWS Config
3. Implementar AWS Config rules gerenciadas e customizadas via Lambda
4. Usar Amazon Inspector para scanning de vulnerabilidades em EC2, ECR e Lambda
5. Integrar Security Hub, Config e GuardDuty para visão unificada de postura
6. Configurar auto-remediation via SSM Automation disparado por Config rules

---

## 1. AWS Security Hub

### Standards Disponíveis

| Standard | Versão | Controles | Foco | Relevância para Banco Meridian |
|---|---|---|---|---|
| **AWS Foundational Security Best Practices** | 1.0 | ~300+ | Práticas básicas de segurança AWS | Alta — linha de base para todos os recursos |
| **CIS AWS Foundations Benchmark** | 2.0 | 89 | Configurações seguras de acordo com CIS | Alta — benchmark amplamente adotado |
| **NIST Special Publication 800-53** | 5.0 | ~200 | Framework de controles do NIST | Alta — alinhamento com NIST |
| **PCI DSS** | 3.2.1 | ~65 | Segurança de dados de cartão de pagamento | Alta — Banco Meridian processa pagamentos |
| **ISO 27001** | 2022 | ~100 | Sistema de gestão de segurança da informação | Média — certificação corporativa |

### Arquitetura Multi-Conta do Security Hub

```
Audit Account (222222222222) — Security Hub Administrator
├── Agrega findings de todas as contas membro
├── Painel unificado de conformidade
├── Custom Actions para resposta
└── Findings exportados via EventBridge

Contas Membro (444, 333, 555...)
├── Security Hub habilitado com todos os standards
├── Findings enviados automaticamente para a conta Audit
└── GuardDuty + Inspector + Config integrados como fontes
```

### Custom Actions no Security Hub

Custom Actions permitem executar ações manuais em findings a partir do console. No contexto do Banco Meridian, o analista de SOC pode selecionar um finding HIGH no Security Hub, clicar em "Ações → Escalar para CISO", e uma Lambda function é invocada automaticamente enviando o e-mail de escalonamento com todos os detalhes do finding para o CISO. Isso elimina o processo manual de copiar informações do console para um e-mail, reduz o tempo de escalonamento de minutos para segundos, e garante que todos os campos relevantes do finding sejam incluídos.

**O que este código faz:** A função Lambda `handler` recebe o evento do Security Hub (que contém os findings selecionados pelo analista), extrai os campos-chave de cada finding, formata um e-mail estruturado com informações de severidade, conta, recurso afetado e ID do finding, e envia via Amazon SES para o e-mail do CISO. A resposta `statusCode: 200` confirma o processamento bem-sucedido.

```python
# Lambda acionada por Custom Action "Escalar para CISO"
import json
import boto3

def handler(event, context):
    """
    Processa Custom Action do Security Hub para escalar finding para o CISO.
    """
    ses = boto3.client('ses', region_name='sa-east-1')
    findings = event['detail']['findings']

    for finding in findings:
        titulo = finding['Title']
        severidade = finding['Severity']['Label']
        conta = finding['AwsAccountId']
        recurso = finding['Resources'][0]['Id'] if finding['Resources'] else 'N/A'

        email_body = f"""
ESCALADA DE SEGURANÇA — Banco Meridian
{'='*50}
Título: {titulo}
Severidade: {severidade}
Conta AWS: {conta}
Recurso Afetado: {recurso}
Gerado em: {finding['CreatedAt']}
Finding ID: {finding['Id']}

Ação necessária: Revisar imediatamente conforme Plano de Resposta a Incidentes.

Este é um email automático do sistema Security Hub.
        """

        ses.send_email(
            Source='secops@bancomeridian.com.br',
            Destination={'ToAddresses': ['ciso@bancomeridian.com.br']},
            Message={
                'Subject': {'Data': f'[{severidade}] Security Hub Finding — {titulo[:50]}'},
                'Body': {'Text': {'Data': email_body}}
            }
        )

    return {'statusCode': 200, 'body': f'Escalonado {len(findings)} finding(s)'}
```

---

## 2. AWS Config

### Componentes do AWS Config

| Componente | Função |
|---|---|
| **Configuration Recorder** | Registra o estado atual e as mudanças de configuração dos recursos AWS |
| **Delivery Channel** | Define onde os snapshots de configuração e as mudanças são entregues (S3 + SNS) |
| **Config Rules** | Avalia a conformidade dos recursos com as regras definidas |
| **Configuration Items** | Registro point-in-time da configuração de um recurso |
| **Configuration Snapshots** | Snapshot completo de todos os recursos registrados |
| **Conformance Packs** | Coleção de Config rules e remediações como um pacote YAML |

### 10 Config Rules Críticas

| # | Config Rule | O que Verifica | Status Esperado | Impacto se NON_COMPLIANT |
|---|---|---|---|---|
| 1 | `s3-bucket-public-read-prohibited` | Nenhum bucket S3 tem leitura pública habilitada | COMPLIANT | Exposição de dados confidenciais |
| 2 | `iam-root-access-key-check` | A conta root não tem access keys ativas | COMPLIANT | Credencial de alto risco exposta |
| 3 | `restricted-ssh` | SGs não permitem SSH (porta 22) para 0.0.0.0/0 | COMPLIANT | Superfície de ataque de força bruta SSH |
| 4 | `cloud-trail-enabled` | CloudTrail está habilitado e entregando logs | COMPLIANT | Perda de visibilidade de auditoria |
| 5 | `multi-factor-auth-enabled-for-iam-console-access` | Todos os usuários IAM com acesso ao console têm MFA | COMPLIANT | Risco de comprometimento sem MFA |
| 6 | `ebs-snapshot-public-restorable-check` | Nenhum snapshot EBS está configurado como público | COMPLIANT | Exposição de dados de disco |
| 7 | `guardduty-enabled-centralized` | GuardDuty está habilitado em todas as contas membro | COMPLIANT | Perda de detecção de ameaças |
| 8 | `securityhub-enabled` | Security Hub está habilitado | COMPLIANT | Perda de visibilidade de postura |
| 9 | `vpc-flow-logs-enabled` | VPC Flow Logs estão habilitados para todas as VPCs | COMPLIANT | Perda de visibilidade de tráfego de rede |
| 10 | `kms-cmk-not-scheduled-for-deletion` | Nenhuma KMS CMK está agendada para exclusão | COMPLIANT | Perda de acesso a dados criptografados |

---

## 3. Conformance Pack para BACEN 4.893

A Resolução BCB 4.893 exige controles de segurança para o Sistema Financeiro Nacional. Este conformance pack mapeia os principais controles.

**O que é um Conformance Pack:** Um conformance pack é uma coleção de Config rules (e opcionalmente Remediações) agrupadas em um único template YAML. Em vez de criar cada Config rule individualmente no console, você faz o deploy de um conformance pack que cria todas as regras de uma vez. O benefício para o Banco Meridian é duplo: (1) cada regra está documentada com o artigo específico do BACEN que ela atende, facilitando a demonstração de conformidade para auditores; (2) o conformance pack pode ser deployado em múltiplas contas simultaneamente via Organizations.

**Como interpretar o resultado:** Após o deploy, o AWS Config avalia automaticamente cada recurso da conta contra cada regra. O resultado é um score de conformidade (porcentagem de recursos COMPLIANT em relação ao total). O auditor do BACEN pode solicitar evidência desse score como prova de avaliação contínua de controles.

```yaml
# conformance-pack-bacen-4893.yaml
# Conformance Pack customizado para alinhamento ao BACEN 4.893
# Banco Meridian — Versão 1.0 — 2026

Parameters:
  MaxAccessKeyAge:
    Default: "90"
    Type: String
    Description: Número máximo de dias para rotação de access keys IAM

  RetentionPeriodDays:
    Default: "2557"
    Type: String
    Description: Período de retenção de logs em dias (7 anos - BACEN)

Resources:

  # Art. 4 — Controles de acesso privilegiado
  RootAccountNoAccessKeys:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-iam-root-access-key-check
      Description: "BACEN 4.893 Art.4 - Conta root nao deve ter access keys ativas"
      Source:
        Owner: AWS
        SourceIdentifier: IAM_ROOT_ACCESS_KEY_CHECK

  MFAEnabledForConsoleAccess:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-mfa-enabled-console
      Description: "BACEN 4.893 Art.4 - MFA obrigatorio para acesso ao console"
      Source:
        Owner: AWS
        SourceIdentifier: MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS

  AccessKeyRotation:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-access-key-rotation
      Description: "BACEN 4.893 Art.4 - Access Keys devem ser rotacionadas a cada 90 dias"
      Source:
        Owner: AWS
        SourceIdentifier: ACCESS_KEYS_ROTATED
      InputParameters:
        maxAccessKeyAge: !Ref MaxAccessKeyAge

  # Art. 6 — Criptografia de dados em repouso
  S3BucketEncryptionRequired:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-s3-default-encryption
      Description: "BACEN 4.893 Art.6 - Buckets S3 devem ter criptografia por padrao"
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED

  EBSEncryptionByDefault:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-ebs-encryption-by-default
      Description: "BACEN 4.893 Art.6 - EBS deve ter criptografia por padrao habilitada"
      Source:
        Owner: AWS
        SourceIdentifier: EC2_EBS_ENCRYPTION_BY_DEFAULT

  RDSEncryptionRequired:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-rds-storage-encrypted
      Description: "BACEN 4.893 Art.6 - Instancias RDS devem ter storage criptografado"
      Source:
        Owner: AWS
        SourceIdentifier: RDS_STORAGE_ENCRYPTED

  # Art. 7 — Registro e monitoramento (logging)
  CloudTrailEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-cloudtrail-enabled
      Description: "BACEN 4.893 Art.7 - CloudTrail deve estar habilitado e ativo"
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENABLED

  CloudTrailLogValidation:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-cloudtrail-log-validation
      Description: "BACEN 4.893 Art.7 - Validacao de integridade de logs CloudTrail"
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED

  VPCFlowLogsEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-vpc-flow-logs
      Description: "BACEN 4.893 Art.7 - VPC Flow Logs devem estar habilitados"
      Source:
        Owner: AWS
        SourceIdentifier: VPC_FLOW_LOGS_ENABLED

  # Art. 8 — Proteção perimetral e controle de acesso de rede
  RestrictedSSH:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-restricted-ssh
      Description: "BACEN 4.893 Art.8 - SSH nao deve estar aberto para 0.0.0.0/0"
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED

  RestrictedRDP:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-restricted-rdp
      Description: "BACEN 4.893 Art.8 - RDP nao deve estar aberto para 0.0.0.0/0"
      Source:
        Owner: AWS
        SourceIdentifier: RESTRICTED_INCOMING_TRAFFIC
      InputParameters:
        blockedPort1: "3389"

  # Art. 9 — Detecção e resposta a incidentes
  GuardDutyEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-guardduty-enabled
      Description: "BACEN 4.893 Art.9 - GuardDuty deve estar habilitado"
      Source:
        Owner: AWS
        SourceIdentifier: GUARDDUTY_ENABLED_CENTRALIZED

  SecurityHubEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-securityhub-enabled
      Description: "BACEN 4.893 Art.9 - Security Hub deve estar habilitado"
      Source:
        Owner: AWS
        SourceIdentifier: SECURITYHUB_ENABLED

  # Art. 10 — Proteção de dados sensíveis
  S3BucketPublicReadProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-s3-public-read-prohibited
      Description: "BACEN 4.893 Art.10 - Buckets S3 nao devem ter acesso publico de leitura"
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED

  S3BucketPublicWriteProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-s3-public-write-prohibited
      Description: "BACEN 4.893 Art.10 - Buckets S3 nao devem ter acesso publico de escrita"
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

  SecretsManagerRotationEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: bacen-secrets-rotation-enabled
      Description: "BACEN 4.893 Art.10 - Segredos do Secrets Manager devem ter rotacao automatica"
      Source:
        Owner: AWS
        SourceIdentifier: SECRETSMANAGER_ROTATION_ENABLED_CHECK
```

---

## 4. Amazon Inspector

### Tipos de Scanning

| Tipo | Recursos Escaneados | O que Detecta | Trigger |
|---|---|---|---|
| **EC2 Instance Scanning** | Instâncias EC2 com SSM Agent | CVEs no SO, pacotes desatualizados, network reachability | Contínuo (ao instalar pacote, ao abrir porta) |
| **ECR Container Scanning** | Imagens em registries ECR | CVEs em camadas da imagem, pacotes desatualizados | Ao fazer push de nova imagem |
| **Lambda Function Scanning** | Funções Lambda | CVEs em dependências (package.json, requirements.txt) | Ao fazer deploy de nova versão |
| **Lambda Code Scanning** | Código de funções Lambda | Vulnerabilidades de código (SAST) | Ao fazer deploy de nova versão |

### Findings do Inspector e CVSS Score

O Inspector usa CVSS (Common Vulnerability Scoring System) para classificar vulnerabilidades:

| CVSS Score | Severidade | Ação |
|---|---|---|
| 9.0 – 10.0 | CRITICAL | Patching em 24 horas |
| 7.0 – 8.9 | HIGH | Patching em 7 dias |
| 4.0 – 6.9 | MEDIUM | Patching em 30 dias |
| 0.1 – 3.9 | LOW | Patching no próximo ciclo |

---

## 5. Diagrama de Fluxo: Config → Remediação Automática

```
┌────────────────────────────────────────────────────────────────────────┐
│  FLUXO DE AUTO-REMEDIAÇÃO — Banco Meridian                            │
└────────────────────────────────────────────────────────────────────────┘

  1. Recurso Criado/Modificado
         │
         ▼
  2. AWS Config — Configuration Item Gerado
         │
         ▼
  3. Config Rule Avaliação
         │
    ┌────┴─────┐
    │          │
  COMPLIANT  NON_COMPLIANT
    │          │
    │          ▼
    │  4. Config SNS Notification
    │          │
    │          ▼
    │  5. EventBridge Rule Match
    │          │
    │          ▼
    │  6. SSM Automation Document Executado
    │          │
    │     ┌────┴──────────────────────────────┐
    │     │  Exemplo: s3-bucket-public-read    │
    │     │  SSM Document: RemoveS3PublicAccess│
    │     │  Ações:                            │
    │     │  a) aws s3api put-public-access-   │
    │     │     block --restrict-public-buckets│
    │     │  b) Registrar no Security Hub      │
    │     │  c) Notificar dono do bucket       │
    │     └────────────────────────────────────┘
    │          │
    └──────────┤
               ▼
  7. Config Rule Reavaliação → COMPLIANT
         │
         ▼
  8. Security Hub Achado Resolvido
         │
         ▼
  9. Ticket ITSM Fechado Automaticamente
```

### SSM Automation para S3 Block Public Access

```yaml
# ssm-document-s3-remediation.yaml
schemaVersion: "0.3"
description: "Auto-remediation: Habilitar S3 Block Public Access quando Config detecta violacao"
assumeRole: "{{AutomationAssumeRole}}"

parameters:
  BucketName:
    type: String
    description: "Nome do bucket S3 a ser remediado"
  AutomationAssumeRole:
    type: String
    description: "ARN da role SSM para executar a automação"

mainSteps:
  - name: BlockPublicAccess
    action: "aws:executeAwsApi"
    inputs:
      Service: s3
      Api: PutPublicAccessBlock
      Bucket: "{{BucketName}}"
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
    outputs:
      - Name: Result
        Selector: "$.ResponseMetadata.HTTPStatusCode"
        Type: Integer

  - name: VerifyRemediation
    action: "aws:executeAwsApi"
    inputs:
      Service: s3
      Api: GetPublicAccessBlock
      Bucket: "{{BucketName}}"
    outputs:
      - Name: BlockPublicAcls
        Selector: "$.PublicAccessBlockConfiguration.BlockPublicAcls"
        Type: Boolean

  - name: NotifySecurityTeam
    action: "aws:executeAwsApi"
    inputs:
      Service: sns
      Api: Publish
      TopicArn: "arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-MEDIUM"
      Subject: "Auto-Remediação: S3 Block Public Access habilitado"
      Message: |
        Auto-remediation executada pelo AWS Config:
        Bucket: {{BucketName}}
        Ação: S3 Block Public Access habilitado (todos os 4 blocos)
        Horário: {{automation:EXECUTION_TIME}}
        Revisar: Verificar se algum workload legítimo foi impactado
```

---

## 6. Integração Security Hub + Config + GuardDuty

### Visão Unificada de Postura

```
                FONTES DE FINDINGS
    ┌──────────┬────────────┬──────────┬────────────┐
    │GuardDuty │  Inspector │  Config  │  Macie     │
    │ (threats)│  (vulns)   │(posture) │  (PII/PCI) │
    └──────────┴────────────┴──────────┴────────────┘
                        │
                        ▼ (ASFF format)
           ┌────────────────────────────┐
           │      AWS Security Hub      │
           │  Aggregation + Scoring     │
           │  Compliance Standards      │
           │  Trend Analysis            │
           └────────────┬───────────────┘
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
         EventBridge  Reports  Dashboards
         (automation) (PDF/CSV) (QuickSight)
```

---

## 7. Atividades de Fixação

**1.** O Conformance Pack BACEN 4.893 do Banco Meridian reportou 15 contas com a Config rule `bacen-access-key-rotation` em NON_COMPLIANT. O que isso significa e qual é o processo de remediação?

a) As contas têm access keys com mais de 90 dias sem rotação; revogar todas imediatamente
b) As contas têm access keys com mais de 90 dias; investigar, notificar donos, rotacionar ordenadamente
c) O Config está mal configurado; reverter o conformance pack
d) Access keys são desnecessárias; deletar todas e usar apenas roles

**Gabarito: B** — NON_COMPLIANT significa que há access keys com mais de 90 dias (parâmetro configurado). O processo: (1) Exportar lista de access keys NON_COMPLIANT com donos e datas. (2) Notificar equipes responsáveis para rotacionar. (3) Para access keys de sistemas automatizados: criar nova key, atualizar sistema, desativar antiga, testar, revogar antiga. (4) Para access keys sem uso real: revogar imediatamente. (5) Considerar migrar para roles onde possível.

---

**2.** Qual é a diferença entre uma Config Rule do tipo `CHANGE_TRIGGERED` e do tipo `PERIODIC`?

a) CHANGE_TRIGGERED avalia na criação; PERIODIC avalia na exclusão
b) CHANGE_TRIGGERED avalia quando o recurso muda; PERIODIC avalia em intervalos fixos independente de mudanças
c) São equivalentes; apenas nomes diferentes para o mesmo comportamento
d) CHANGE_TRIGGERED é para recursos EC2; PERIODIC é para recursos IAM

**Gabarito: B** — CHANGE_TRIGGERED: a avaliação é disparada quando um Configuration Item é criado, modificado ou deletado para o recurso configurado. Ideal para: regras de conformidade em tempo real (ex: detectar SG aberto no momento da criação). PERIODIC: avalia em intervalos fixos (1h, 3h, 6h, 12h, 24h), independente de mudanças. Ideal para: verificações que dependem de estado externo ao recurso (ex: verificar se access keys foram usadas recentemente, o que depende de dados do CloudTrail e não do recurso IAM em si).

---

**3.** O Amazon Inspector gerou um finding CRITICAL (CVSS 9.8) para a CVE-2021-44228 (Log4Shell) em 12 instâncias EC2 da conta Production do Banco Meridian. Qual é o SLA de remediação e as ações imediatas?

a) 30 dias; aplicar patch no próximo janela de manutenção
b) 7 dias; aplicar patch conforme calendário planejado
c) 24 horas; isolar instâncias expostas, aplicar workaround imediato, planejar patching
d) 90 dias; esperar fornecedor lançar correção oficial

**Gabarito: C** — CVSS 9.8 (CRITICAL) tem SLA de 24 horas. Log4Shell permite Remote Code Execution não autenticado. Ações: (1) Identificar quais instâncias estão expostas externamente (via Network Reachability do Inspector). (2) Para instâncias expostas: aplicar workaround imediato (`-Dlog4j2.formatMsgNoLookups=true`). (3) Isolar instâncias que não podem ser patcheadas imediatamente. (4) Aplicar patch para versão Log4j >= 2.17.1 em todas as instâncias. (5) Verificar se houve exploração via GuardDuty e CloudTrail.

---

**4.** Como você configuraria o Security Hub para agregar findings de todas as contas do Banco Meridian em um único painel na conta Audit?

a) Configurar CloudTrail organization trail — os findings são incluídos automaticamente
b) Na conta Audit, habilitar Security Hub como admin delegado via Organizations; contas membro são adicionadas automaticamente
c) Criar um S3 bucket central e configurar cada Security Hub regional para exportar para ele
d) Instalar um agente em cada conta para enviar findings para a conta Audit

**Gabarito: B** — Security Hub suporta delegated administration via Organizations. Na Management Account: `aws securityhub enable-organization-admin-account --admin-account-id 222222222222`. Na Audit Account (admin delegado): configurar auto-enable para novas contas e habilitar para contas existentes. Todos os findings são automaticamente agregados na conta Admin Delegado, sem necessidade de agentes ou configurações manuais por conta.

---

**5.** Você quer criar uma Config Rule customizada que verifique se todas as instâncias EC2 têm a tag `CostCenter` preenchida. Qual é o tipo de rule a usar?

a) Managed Rule — existe a rule `required-tags` gerenciada pela AWS
b) Custom Lambda Rule — criar uma Lambda com o logic de verificação de tags
c) Custom Guard Rule — usar AWS CloudFormation Guard
d) A e C são válidos — tanto Managed Rule quanto Guard Rule resolvem

**Gabarito: D** — A Config rule gerenciada `required-tags` verifica a presença de tags específicas. Também é possível usar AWS CloudFormation Guard (Guard Rules) para regras customizadas sem Lambda. Ambas são abordagens válidas. Para o caso simples de verificar tag `CostCenter`, `required-tags` managed rule com parâmetro `tag1Key=CostCenter` é mais simples e sem custo de Lambda.

---

## 8. Roteiro de Gravação

### Aula 4.1 — Security Hub e Standards (50 min)

**Abertura (2 min):**
"Boa tarde! Chegamos ao módulo de postura de segurança. Até agora, construímos controles preventivos (SCPs), visibilidade (logging) e detecção de ameaças (GuardDuty). Hoje adicionamos a camada de conformidade e gestão de postura com Security Hub e AWS Config. Esses serviços respondem à pergunta: 'Meu ambiente está configurado da forma que deveria estar?'"

**Bloco 1 — Security Hub: Conceito e Configuração (10 min):**
"Security Hub é o CSPM (Cloud Security Posture Management) nativo da AWS. Ele agrega findings de GuardDuty, Inspector, Macie, Config e integrações de terceiros (Palo Alto, CrowdStrike, etc.) em um único painel.

[Abrir console Security Hub — Overview]

Vejam o Security Score no topo — esse número vai de 0 a 100. Representa o percentual de controles passando nos standards habilitados. Para o Banco Meridian, nosso target é > 90%.

[Mostrar o painel de Findings]

Cada finding no Security Hub tem um formato padronizado: ASFF (Amazon Security Finding Format). Isso permite correlação entre findings de diferentes fontes. Um finding do GuardDuty e um finding do Config sobre o mesmo recurso podem ser correlacionados automaticamente."

**Bloco 2 — Standards e Controles (15 min):**
"[Habilitar standards ao vivo]
1. CIS AWS Foundations Benchmark v2.0 — 89 controles
2. AWS Foundational Security Best Practices — 300+ controles
3. PCI DSS 3.2.1 — essencial para o Banco Meridian

[Abrir CIS Benchmark — mostrar controles por categoria]

Controles que frequentemente falham no início:
- 1.4: Não ter access keys de root
- 1.14: Todos os usuários IAM com MFA habilitado
- 3.1: CloudTrail habilitado em todas as regiões
- 3.10: Object Lock habilitado no bucket de logs

[Fazer drill-down em um controle com FAILED]

Cada controle mostra: o que está sendo avaliado, os recursos que estão falhando, a remediação recomendada. No caso de múltiplas contas, vemos quais contas estão falhando."

**Bloco 3 — Custom Actions e Integrações (10 min):**
"[Criar Custom Action ao vivo]
1. Security Hub — Settings — Custom actions — Create
2. Action ID: EscalarCISO
3. Description: Escalar finding para o CISO via email
4. Criar regra EventBridge que mapeia essa Custom Action para Lambda

Agora, quando um analista de segurança seleciona um finding HIGH e clica em 'Actions → EscalarCISO', o Lambda é invocado e envia email ao CISO automaticamente."

**Bloco 4 — Aggregation Multi-Região e Multi-Conta (13 min):**
"[Configurar Finding Aggregation]

Para o Banco Meridian, temos recursos em sa-east-1 e us-east-1. Os findings de us-east-1 precisam aparecer no painel da Audit em sa-east-1.

Security Hub — Settings — Regions — Finding aggregation — Enable

Selecionar linked regions: us-east-1. Todos os findings de us-east-1 agora aparecem consolidados na região principal.

[Recap do módulo] Temos:
- CIS + FSBP + PCI DSS habilitados
- Admin delegado na Audit Account
- Finding Aggregation multi-região
- Custom Action para escalar para CISO"

**Fechamento (0 min):**
"Na próxima aula, AWS Config, Inspector e auto-remediação via SSM."

---

### Aula 4.2 — AWS Config, Inspector e Auto-Remediação (50 min)

**Abertura (2 min):**
"Boa tarde! Na aula anterior, Security Hub deu a visão unificada de postura. Hoje vamos às ferramentas operacionais: Config para conformidade de recursos, Inspector para vulnerabilidades, e a automação que fecha o ciclo: remediação automática via SSM."

**Bloco 1 — AWS Config (15 min):**
"Config responde: 'O recurso X está configurado corretamente agora? E estava correto há 30 dias?'

[Configurar Configuration Recorder ao vivo]
1. Config — Settings — Manage
2. Record all resources: All resource types
3. S3 bucket: meridian-logs-333333333333/config
4. SNS topic: Config-Changes-Notification
5. IAM role: AWSConfigRole (service-linked)

[Criar Config Rule ao vivo — restricted-ssh]
Config — Rules — Add rule — restricted-ssh
Trigger: Configuration changes — EC2 SecurityGroup

[Mostrar resultado após alguns segundos]
Vemos os Security Groups avaliados: COMPLIANT (nenhuma regra SSH aberta) ou NON_COMPLIANT (tem 0.0.0.0/0:22).

[Criar Config Rule customizada via Lambda — requisito de tag CostCenter]
Custom Lambda Rule: para cada EC2 instance, verificar se tem tag CostCenter preenchida.

[Mostrar o código Python da Lambda]"

**Bloco 2 — Conformance Pack BACEN 4.893 (10 min):**
"[Deploy do conformance pack ao vivo]
1. Config — Conformance packs — Deploy
2. Template source: Upload YAML
3. Upload o arquivo conformance-pack-bacen-4893.yaml
4. Nome: BACEN4893-BancoMeridian

[Aguardar avaliação — 2-5 minutos]

[Mostrar resultado] Dashboard do conformance pack mostra:
- Total de regras: 15
- Total de recursos avaliados: 847
- COMPLIANT: 782 (91.7%)
- NON_COMPLIANT: 65 (7.7%)

Os 65 NON_COMPLIANT são o nosso backlog de remediação. Para cada um, temos a regra BACEN mapeada, o recurso afetado e a remediação recomendada."

**Bloco 3 — Amazon Inspector (10 min):**
"[Habilitar Inspector ao vivo]
Inspector — Get started — Activate Inspector
Selecionar: EC2 scanning + ECR scanning + Lambda scanning

[Mostrar painel após alguns minutos]
Finding summary: CRITICAL: 12, HIGH: 47, MEDIUM: 183, LOW: 521

[Abrir finding CRITICAL — Log4Shell]
CVE-2021-44228, CVSS 9.8. Instâncias afetadas: 3. Network Reachability: Publicly accessible.

Esse 'Network Reachability' é ouro — Inspector combina a análise de vulnerabilidade com a análise de topologia de rede. Me diz que não só a vulnerabilidade existe, mas que a instância está acessível pela internet. Isso eleva drasticamente a prioridade.

[Mostrar integração Inspector → Security Hub]
Os findings do Inspector aparecem automaticamente no Security Hub como findings CRITICAL."

**Bloco 4 — Auto-Remediação SSM (13 min):**
"[Configurar Auto-Remediation ao vivo para s3-bucket-public-read-prohibited]
1. Config — Rules — s3-bucket-public-read-prohibited — Actions — Manage remediation
2. Remediation method: Automatic remediation
3. SSM document: AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock
4. Parameters: AutomationAssumeRole: arn:aws:iam::...ConfigRemediationRole
5. Maximum automatic attempts: 3
6. Retry wait time: 60 seconds

[Testar] Criar bucket S3 sem Block Public Access. Aguardar 1-2 minutos. Observar:
- Config Rule detecta NON_COMPLIANT
- SSM Automation executa automaticamente
- Block Public Access habilitado
- Config Rule reavalia → COMPLIANT
- Security Hub finding resolvido automaticamente

Esse é o ciclo completo. Zero intervenção humana para um achado de configuração comum e de baixo risco."

---

## 9. Avaliação do Módulo

**Questão 1 (2 pontos):** O Banco Meridian precisa demonstrar conformidade com o CIS AWS Foundations Benchmark v2.0 para uma auditoria regulatória. O Security Hub reporta Score de 67%. Quais são as 3 primeiras categorias de controles a focar para aumentar rapidamente o score?

**Gabarito:** As categorias com maior impacto geralmente são: (1) IAM — controles de MFA, access keys de root, senha policy. Costumam ser numerosos e fáceis de corrigir. (2) Logging — CloudTrail habilitado em todas as regiões, log file validation, KMS encryption. Alta cobertura de controles. (3) Network — Security Groups sem 0.0.0.0/0 em portas sensíveis (22, 3389). Cada SG não conforme é 1 failing resource. Focar em remediações de alta cobertura (que consertam muitos recursos de uma vez, como habilitar MFA para todos os usuários, ou aplicar Config rule com auto-remediation para SGs públicos) aumenta o score mais rapidamente.

---

**Questão 2 (2 pontos):** Explique como o AWS Config detecta "configuration drift" em recursos da infraestrutura do Banco Meridian e por que isso é importante para segurança.

**Gabarito:** Configuration drift: discrepância entre o estado desejado (definido por IaC/política) e o estado atual do recurso. AWS Config registra o estado de cada recurso em cada mudança (Configuration Item). Ao comparar o estado atual com o estado anterior ou com uma baseline desejada, Config detecta drift. Importância para segurança: (1) Um Security Group pode ser modificado manualmente por um sysadmin fora do processo IaC — Config detecta a mudança e, com regras, pode alertar ou remediar automaticamente. (2) Uma role IAM pode ter uma política permissiva adicionada — Config registra a mudança e pode disparar alerta. (3) Para forense: reconstruir o estado de um recurso em um momento específico do passado (ex: "como estava o SG na época do incidente?").

---

**Questão 3 (2 pontos):** Uma Config rule customizada para o Banco Meridian deve verificar se todos os buckets S3 com tag `DataClassification=Confidential` têm Object Lock habilitado. Descreva como você implementaria essa regra.

**Gabarito:** Usar Custom Lambda Rule. 1. Criar Lambda function em Python com Boto3: para cada bucket S3, verificar tag `DataClassification=Confidential`; se tag presente, chamar `s3.get_object_lock_configuration(Bucket=nome)`; retornar COMPLIANT se Object Lock habilitado em modo Compliance, NON_COMPLIANT caso contrário. 2. Criar Config Rule: tipo Custom Lambda, trigger = Configuration changes em `AWS::S3::Bucket`, Lambda ARN apontando para a função criada. 3. Config invocará a Lambda para cada bucket S3, passando o Configuration Item como input. 4. Lambda retorna evaluation result via `config.put_evaluations()`. 5. (Opcional) Adicionar auto-remediation via SSM Automation que habilita Object Lock (requer versioning habilitado primeiro).

---

**Questão 4 (2 pontos):** O Inspector identificou uma vulnerabilidade CRITICAL em um pacote Python (`boto3==1.18.0`) em uma função Lambda de processamento de pagamentos. Como você priorizaria e remediaria este achado?

**Gabarito:** 1. Verificar a CVE específica: qual a exploitability? Requer acesso local ou é remotamente explorável? Para Lambda, "remotamente explorável" significa via payload de requisição à função. 2. Verificar se boto3 1.18.0 tem CVE real (geralmente não é crítico — verificar no NVD). 3. Processo de remediação: atualizar `requirements.txt` para `boto3>=1.35.0` (versão segura), rebuild do pacote Lambda, deploy via pipeline CI/CD. 4. Não atualizar diretamente em produção — deploy via ambiente de staging primeiro. 5. Após deploy, Inspector automaticamente reavalia e fecha o finding. 6. Documentar no Security Hub com nota de remediação. Para a prova: o ponto-chave é que Lambda Scanning do Inspector analisa as dependências listadas no requirements.txt/package.json do deployment package.

---

**Questão 5 (2 pontos):** Qual é a diferença entre um Conformance Pack e um conjunto de Config Rules individuais? Quando você usaria cada abordagem?

**Gabarito:** **Config Rules individuais:** criadas uma a uma, gerenciadas separadamente, úteis para regras específicas de um workload ou time. Sem gestão unificada. **Conformance Pack:** conjunto de Config Rules + remediações empacotadas em um template YAML (CloudFormation), deployáveis como uma unidade, versionáveis em código, com painel consolidado de conformidade. Quando usar Conformance Pack: para conjuntos de regras mapeadas a um framework específico (BACEN, CIS, PCI DSS), quando você precisa demonstrar conformidade como um todo e não regra por regra, quando precisa deployar o mesmo conjunto em múltiplas contas/regiões via StackSets. Quando usar rules individuais: para regras de negócio específicas sem framework externo associado, para testes antes de incluir em um conformance pack.
