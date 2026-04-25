# Curso 3 — AWS Cloud Security Operations

**Programa de Formação Security Operations em Nuvem · CECyber**

[![CH Total](https://img.shields.io/badge/Carga%20Horária-40h-blue)](#informações-gerais)
[![Vídeo](https://img.shields.io/badge/Videoaulas-16h-orange)](#ementa-modular-detalhada)
[![Lab](https://img.shields.io/badge/Laboratórios-16h-green)](#laboratórios-hands-on)
[![Live](https://img.shields.io/badge/Live%20Online-8h-purple)](#sessões-live-online)
[![Certificação](https://img.shields.io/badge/Certificação-SCS--C02-FF9900)](#certificação-alinhada)
[![Nível](https://img.shields.io/badge/Nível-Intermediário%2FAvançado-yellow)](#informações-gerais)

---

## Descrição

Formação aprofundada em **operações de segurança no Amazon Web Services**, cobrindo o stack completo de serviços nativos de detecção, resposta, postura e proteção de dados. O curso forma profissionais aptos a projetar e operar uma **arquitetura multi-conta segura**, com logging centralizado, detecção automatizada e resposta orquestrada.

O curso está alinhado ao **AWS Well-Architected Security Pillar** e prepara diretamente para o exame **AWS Certified Security – Specialty (SCS-C02)**. Todos os laboratórios são executados no contexto do **Banco Meridian** (empresa fictícia) — uma instituição financeira multi-conta em AWS com workloads em múltiplas regiões.

---

## Informações Gerais

| Campo                       | Detalhes                                                                        |
|:----------------------------|:--------------------------------------------------------------------------------|
| **Carga Horária Total**     | 40 horas                                                                        |
| **Distribuição**            | 16h videoaulas (40%) + 16h laboratórios (40%) + 8h live online (20%)            |
| **Modalidade**              | EAD híbrido (plataforma LMS + sessões ao vivo via Zoom/Teams)                  |
| **Duração Sugerida**        | 7 semanas (ritmo de ~6h/semana)                                                 |
| **Público-Alvo**            | Analistas e engenheiros de SOC, arquitetos de segurança, DevOps/SRE em ambientes AWS, profissionais de TI/Cloud em transição para segurança |
| **Pré-requisitos**          | AWS Cloud Practitioner (CLF-C02) ou equivalente; familiaridade com IAM, VPC e EC2; conhecimentos de CLI e Python desejáveis |
| **Nível**                   | Intermediário                                                                   |
| **Certificação Alinhada**   | AWS Certified Security – Specialty (SCS-C02) — preparação direta                |
| **Material Incluso**        | Videoaulas em HD, apostila, repositório Terraform/CloudFormation de laboratórios, runbooks de IR, acesso a conta AWS sandbox, certificado digital |
| **Aprovação**               | 70% de aproveitamento global                                                    |

---

## Objetivos de Aprendizagem

Ao concluir o curso, o participante será capaz de:

1. **Projetar** arquitetura de logging centralizado multi-conta com AWS Organizations e Control Tower
2. **Implantar e operar** detecção de ameaças com Amazon GuardDuty em escala organizacional
3. **Gerenciar postura** de segurança com Security Hub, AWS Config e Amazon Inspector
4. **Conduzir investigações** forenses com Amazon Detective e análise de CloudTrail Lake
5. **Implementar proteção** de dados com Macie, KMS, Secrets Manager e CloudHSM
6. **Automatizar resposta** a incidentes com EventBridge, Lambda e Systems Manager
7. **Preparar-se** para o exame AWS Certified Security – Specialty (SCS-C02)

---

## Estrutura do Curso

```
curso-03-aws-secops/
│
├── README.md                                ← Este arquivo
│
├── modulos/
│   ├── modulo-00-ambiente-laboratorio/      ← Setup multi-conta AWS (obrigatório)
│   ├── modulo-01-fundamentos-aws/           ← Responsabilidade compartilhada, IAM (2h+2h+1h)
│   ├── modulo-02-logging-monitoring/        ← CloudTrail, CloudWatch, VPC Flow Logs (2h+2h+1h)
│   ├── modulo-03-guardduty/                 ← Detecção de ameaças GuardDuty (2h+2h+1h)
│   ├── modulo-04-security-posture/          ← Security Hub, Config, Inspector (2h+2h+1h)
│   ├── modulo-05-incident-investigation/    ← Detective, CloudTrail Lake (1h+2h+1h)
│   ├── modulo-06-data-protection/           ← KMS, Secrets Manager, Macie (2h+1h)
│   ├── modulo-07-network-security/          ← WAF, Shield, Network Firewall (2h+2h+1h)
│   ├── modulo-08-automacao-response/        ← EventBridge, Lambda, SSM (2h+2h+1h)
│   ├── modulo-09-multi-account/             ← Organizations, IAM Identity Center (1h+1h)
│   └── modulo-10-capstone/                  ← IR Exercise multi-conta (1h live)
│
├── laboratorios/
│   ├── lab-01-organizations-scps/           ← Multi-conta + SCPs preventivos (2h)
│   ├── lab-02-logging-centralizado/         ← CloudTrail org trail + CloudTrail Lake (2h)
│   ├── lab-03-guardduty-org-wide/           ← GuardDuty analysis + findings simulados (2h)
│   ├── lab-04-security-hub-config/          ← Conformance pack CIS + BACEN (2h)
│   ├── lab-05-detective-investigation/      ← Reconstrução de timeline de comprometimento (2h)
│   ├── lab-06-auto-remediation/             ← EventBridge → Lambda auto-remediation (2h)
│   ├── lab-07-waf-customizado/              ← Proteção OWASP Top 10 + rate limiting (2h)
│   └── lab-capstone/                        ← Ataque multi-vetor completo (2h + 2h live)
│
└── avaliacao-final/
    └── README.md                             ← 40 questões múltipla escolha + estudo de caso
```

---

## Ementa Modular Detalhada

| Mód. | Conteúdo Programático                                                               | Vídeo | Lab  | Live |
|:----:|:------------------------------------------------------------------------------------|:-----:|:----:|:----:|
|  00  | Setup do ambiente: estrutura multi-conta, AWS CLI, SDKs, Terraform, conta sandbox   | —     | 2h   | —    |
|  01  | Fundamentos AWS Security: responsabilidade compartilhada, Well-Architected Security Pillar, AWS Organizations, SCPs, Control Tower. IAM deep dive: policies, roles, permission boundaries, Access Analyzer | 2h | 2h | 1h |
|  02  | Logging & Monitoring: CloudTrail (management, data e insights events), CloudTrail Lake, CloudWatch, VPC Flow Logs, Route 53 DNS logs. Arquitetura de logging centralizado multi-conta | 2h | 2h | 1h |
|  03  | Amazon GuardDuty: finding types (Recon, InstanceCompromise, IAM, S3, EKS, Malware, RuntimeMonitoring, Lambda). Deploy organization-wide, suppressão, Malware Protection para EC2 e S3 | 2h | 2h | 1h |
|  04  | Security Posture Management: AWS Security Hub (standards CIS, NIST, PCI DSS, BACEN custom), findings aggregation, custom actions. AWS Config (rules, conformance packs). Amazon Inspector (EC2, ECR, Lambda) | 2h | 2h | 1h |
|  05  | Incident Investigation: Amazon Detective (behavior graphs, VPC flow analysis), CloudTrail Lake queries SQL. Investigação forense de privilege escalation via IAM e AssumeRole | 1h | 2h | 1h |
|  06  | Data Protection: AWS KMS (CMK, key policies, grants, envelope encryption), AWS Secrets Manager vs Parameter Store, CloudHSM, Amazon Macie (PII/PCI discovery em S3) | 2h | 1h | —    |
|  07  | Network Security: VPC design, Security Groups, NACLs, VPC endpoints, AWS WAF (managed rules, rate limiting, Bot Control, OWASP), AWS Shield, Network Firewall, Route 53 Resolver DNS Firewall | 2h | 2h | 1h |
|  08  | Automação e Response: EventBridge + Lambda para auto-remediation, Security Hub custom actions, Systems Manager Automation runbooks, Step Functions para fluxos de IR complexos | 2h | 2h | 1h |
|  09  | Multi-Account Security: AWS Organizations governance, IAM Identity Center (SSO), delegated administration, cross-account roles, Security OU, Log Archive account, Audit account | 1h | 1h | —    |
|  10  | Capstone — Incident Response Exercise: ataque multi-vetor (initial access via credencial vazada → role assumption → persistência → exfiltração). Relatório NIST SP 800-61 | —  | —  | 1h  |
|      | **TOTAL (40h)**                                                                      | **16h** | **16h** | **8h** |

---

## Laboratórios Hands-On

| Lab   | Nome                                      | Duração | Módulo | MITRE ATT&CK                           |
|:-----:|:------------------------------------------|:-------:|:------:|:---------------------------------------|
|  01   | Organizations & SCPs                      |   2h    |   01   | Prevenção de T1078.004, T1562.008       |
|  02   | Logging Centralizado Multi-Conta          |   2h    |   02   | Detecção de T1562.002 (log tampering)   |
|  03   | GuardDuty Org-Wide: Análise de Findings   |   2h    |   03   | T1496, T1552.005, T1537                 |
|  04   | Security Hub + Config: Conformance BACEN  |   2h    |   04   | Postura de segurança e compliance        |
|  05   | Detective Investigation: Comprometimento EC2 | 2h   |   05   | T1548.005, T1078.004 (AssumeRole)       |
|  06   | Auto-Remediation: EventBridge → Lambda    |   2h    |   08   | Resposta a T1552.005 (IAM key exposed)  |
|  07   | WAF Customizado: OWASP Top 10             |   2h    |   07   | T1190 (Exploit Public-Facing App)       |
| Caps. | Ataque Multi-Vetor Completo               | 2h+2h   |   10   | Kill chain completa — APT              |

---

## Topologia do Ambiente de Laboratório

```
AWS ORGANIZATIONS — BANCO MERIDIAN (FICTÍCIO)
─────────────────────────────────────────────────────────────────────────
Management Account
├── Security OU
│   ├── Audit Account         (Security Hub, CloudTrail Lake aggregation)
│   └── Log Archive Account   (S3 centralizado, KMS encryption)
├── Workload OU
│   ├── Production Account    (EC2, RDS, EKS — workloads principais)
│   └── Development Account   (Sandbox de laboratório)
└── Shared Services OU
    └── Network Account       (Transit Gateway, VPC centralizada, WAF)

SERVIÇOS DE SEGURANÇA HABILITADOS:
─────────────────────────────────────────────────────────────────────────
Detecção:      GuardDuty (org-wide) · Inspector (todos os workloads)
Postura:       Security Hub (delegated admin no Audit Account)
Logging:       CloudTrail (org trail) · CloudWatch · VPC Flow Logs
Investigação:  Amazon Detective · CloudTrail Lake
Proteção:      AWS WAF · Shield Standard/Advanced · Network Firewall
Identidade:    IAM Identity Center · Permission Sets · Access Analyzer
Dados:         Macie (S3 scanning) · KMS (CMK por workload) · Secrets Manager
Automação:     EventBridge → Lambda → SSM Automation
```

---

## Ferramentas e Tecnologias

```
Detecção e Resposta (Native AWS)
├── Amazon GuardDuty (SIEM nativo, ML-based)
├── AWS Security Hub (aggregation + CSPM)
├── Amazon Detective (investigation graphs)
├── Amazon Inspector (vulnerability scanning)
└── Amazon Macie (data classification)

Logging e Auditoria
├── AWS CloudTrail (management, data, insights events)
├── CloudTrail Lake (SQL analytics sobre logs históricos)
├── Amazon CloudWatch (métricas, logs, alarmes)
├── VPC Flow Logs (tráfego de rede)
└── Route 53 Resolver DNS Logs

Identidade e Acesso
├── AWS IAM (policies, roles, permission boundaries)
├── AWS IAM Access Analyzer (exposure analysis)
├── AWS IAM Identity Center (SSO multi-conta)
└── AWS Organizations + Control Tower + SCPs

Proteção de Dados
├── AWS KMS (CMK, envelope encryption)
├── AWS Secrets Manager (rotation automática)
├── AWS CloudHSM (HSM dedicado)
└── Amazon Macie (PII/PCI discovery)

Segurança de Rede
├── AWS WAF (managed rules + custom rules)
├── AWS Shield (Advanced para proteção DDoS)
├── AWS Network Firewall (stateful packet inspection)
└── Route 53 Resolver DNS Firewall

Automação e Response
├── Amazon EventBridge (event routing)
├── AWS Lambda (serverless response)
├── AWS Systems Manager (Automation runbooks)
└── AWS Step Functions (IR workflows complexos)

IaC e DevSecOps
├── Terraform (infraestrutura dos labs)
├── CloudFormation (StackSets para multi-conta)
└── AWS CDK (automação avançada)
```

---

## Avaliação

| Componente                                       | Peso |
|:-------------------------------------------------|:----:|
| Quizzes integrados às videoaulas                 |  15% |
| Laboratórios guiados e desafios                  |  35% |
| Projeto: arquitetura SecOps multi-conta + 3 automações | 20% |
| Simulado AWS Security Specialty                  |  15% |
| Capstone de Incident Response                    |  15% |

**Aprovação:** 70% de aproveitamento global. Certificado digital inclui indicação de preparação
para o exame AWS Certified Security – Specialty (SCS-C02).

Para a **avaliação final de curso** (realizada após o Capstone), consulte:
[avaliacao-final/README.md](avaliacao-final/README.md)

---

## Sessões Live Online (8h)

| Sessão | Conteúdo                                                       | Duração | Módulo |
|:------:|:---------------------------------------------------------------|:-------:|:------:|
|   1    | Abertura + setup do ambiente + Fundamentos AWS Security         |  1h30   |  01    |
|   2    | Lab ao vivo: GuardDuty findings simulados + Security Hub        |  1h30   |  03/04 |
|   3    | Lab ao vivo: Automação de response com EventBridge e Lambda     |  1h30   |  08    |
|   4    | Lab ao vivo: Detective investigation + mentoria de checkpoint   |  1h30   |  05    |
|   5    | Defesa do Capstone + relatório NIST SP 800-61 + encerramento   |  2h     |  10    |

---

## Preparação para AWS Security Specialty (SCS-C02)

### Domínios do Exame e Cobertura do Curso

| Domínio                                   | Peso    | Módulos do Curso               |
|:------------------------------------------|:-------:|:-------------------------------|
| 1. Threat Detection and Incident Response | 14%     | Módulos 03, 05, 08, Capstone   |
| 2. Security Logging and Monitoring         | 18%     | Módulos 02, 04, 05             |
| 3. Infrastructure Security                | 20%     | Módulos 01, 07, 09             |
| 4. Identity and Access Management         | 16%     | Módulos 01, 09                 |
| 5. Data Protection                        | 18%     | Módulo 06                      |
| 6. Management and Security Governance      | 14%     | Módulos 01, 04, 09             |

---

## Cenário do Curso: Banco Meridian em AWS (Fictício)

O **Banco Meridian** opera uma arquitetura **multi-conta em AWS** com 4 contas:

| Conta                | ID (fictício) | Função                                              |
|:---------------------|:------------:|:----------------------------------------------------|
| **Management**       | 111111111111 | Root da organização, SCPs, Control Tower            |
| **Audit**            | 222222222222 | Security Hub delegated admin, CloudTrail Lake        |
| **Log Archive**      | 333333333333 | S3 centralizado com Object Lock para logs            |
| **Production**       | 444444444444 | Workloads: EKS (core banking), EC2, RDS, S3          |

---

## Ementa Modular Expandida

### Módulo 01 — Fundamentos de Segurança AWS (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- Modelo de Responsabilidade Compartilhada: o que a AWS protege (hardware, rede global, hipervisor) e o que é responsabilidade do cliente (IAM, dados, SO, rede VPC)
- AWS Well-Architected Framework — Security Pillar: 7 áreas de design (IAM, detecção, proteção de infra, proteção de dados, resposta a incidentes, governança, proteção de rede)
- AWS Organizations: estrutura organizacional, Organizational Units (OUs), delegated administration, consolidated billing
- Service Control Policies (SCPs): diferença entre permission policies e SCPs, SCP inheritance, casos de uso (bloqueio de regiões, prevenção de desabilitar logs, força de MFA)
- IAM deep dive: policies (identity-based vs resource-based), roles vs users, permission boundaries, ABAC (Attribute-Based Access Control com tags), conditions (`aws:RequestedRegion`, `aws:SecureTransport`, `aws:MultiFactorAuthPresent`)
- IAM Access Analyzer: analisadores para contas e organizações, findings de acesso externo e público, policy validation, unused permissions analysis
- AWS Security Reference Architecture (SRA): padrão recomendado pela AWS para estrutura de contas

**Laboratório (2h):** Criar política SCP que bloqueia operações fora de sa-east-1 e us-east-1; criar IAM role com permission boundary; usar IAM Access Analyzer para identificar recursos expostos externamente; configurar IAM Identity Center com dois permission sets (SOCReadOnly e SOCAdmin).

---

### Módulo 02 — Logging e Monitoramento (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- AWS CloudTrail: tipos de eventos (management events, data events, Insights events), trilha org-wide, log file integrity validation, log encryption com KMS, CloudTrail Insights (anomaly detection)
- CloudTrail Lake: Event Data Stores, queries SQL, integração com EventBridge, análise de logs históricos sem mover dados para S3/Athena
- Amazon CloudWatch: Log Groups e Log Streams, Metric Filters, Alarmes, Contributor Insights, Container Insights, Application Insights
- VPC Flow Logs: campos do registro (version 2 vs 5), destinos (S3, CloudWatch Logs, Kinesis Firehose), análise com Athena e CloudWatch Logs Insights
- Route 53 Resolver DNS Logs: DNS query logging para VPCs, detecção de DGA (Domain Generation Algorithms) e C2 via DNS
- Arquitetura de logging centralizado: conta Log Archive com S3 Object Lock (WORM compliance), replicação cross-region, retenção diferenciada por tipo de log
- Athena para análise de CloudTrail: particionamento por data/conta/região para performance e custo

**Laboratório (2h):** Criar trilha CloudTrail org-wide com criptografia KMS e integridade de logs; configurar VPC Flow Logs para conta de produção; criar Event Data Store no CloudTrail Lake e executar queries SQL para detectar chamadas à API suspeitas; configurar CloudWatch Alarm para uso de root account.

---

### Módulo 03 — Amazon GuardDuty (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- Arquitetura do GuardDuty: fontes de dados nativas (CloudTrail, VPC Flow Logs, DNS logs, S3 data events, EKS audit logs, RDS login activity, Lambda network activity, EC2 runtime monitoring)
- Categorias de findings e exemplos reais:
  - **Backdoor:** `Backdoor:EC2/C&CActivity.B!DNS`, `Backdoor:EC2/XORDDOS`
  - **Credential Access:** `CredentialAccess:IAMUser/AnomalousBehavior`, `UnauthorizedAccess:IAMUser/TorIPCaller`
  - **DefenseEvasion:** `DefenseEvasion:IAMUser/AnomalousBehavior` (CloudTrail desabilitado)
  - **Discovery:** `Discovery:IAMUser/AnomalousBehavior`, `Discovery:S3/BucketEnumeration`
  - **Exfiltration:** `Exfiltration:S3/ObjectRead.Unusual`
  - **Impact:** `CryptoCurrency:EC2/BitcoinTool.B!DNS` (crypto mining)
  - **InitialAccess:** `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/RDPBruteForce`
  - **Malware:** `Execution:EC2/MaliciousFile` (Malware Protection)
- Deploy organization-wide: conta master, member accounts, delegated administrator
- Trusted IP lists e Threat Lists personalizadas (formato TXT, S3 privado)
- Filtros e supressão de falsos positivos: auto-archive rules por region, instanceId, finding type
- Malware Protection: EBS volume scanning, retained snapshots, malware report em S3
- Integração com Security Hub, EventBridge e Lambda para resposta automatizada

**Laboratório (2h):** Habilitar GuardDuty org-wide com conta Audit como delegated admin; simular findings usando o GuardDuty Sample Findings Generator; criar auto-archive rule para suprimir falsos positivos; configurar EventBridge rule + Lambda para enviar finding HIGH/CRITICAL para canal Teams; analisar finding de crypto mining e rastrear instância EC2.

---

### Módulo 04 — Gestão de Postura de Segurança (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- AWS Security Hub: consolidação de findings (ASFF — Amazon Security Finding Format), Security Standards disponíveis (CIS AWS Foundations Benchmark v3.0, AWS Foundational Security Best Practices v1.0, NIST SP 800-53 Rev. 5, PCI DSS v3.2.1), aggregation regions, custom actions, insight
- Mapeamento BACEN 4.893 para controles Security Hub: Artigo 9 (logging), Artigo 10 (acesso), Artigo 13 (continuidade)
- AWS Config: Configuration Recorder, Delivery Channel, managed rules (100+), custom Lambda rules, conformance packs (template YAML de múltiplas regras), remediation actions (automática via SSM)
- Amazon Inspector: scanning de vulnerabilidades em EC2 (Package Vulnerability + Network Reachability), ECR (container scanning automatizado no push), Lambda (scanning de funções e layers). Inspector Score (baseado no CVSS com contexto AWS), prioritização por Network Exposure
- Correlação Security Hub ↔ Config ↔ Inspector: uma vulnerabilidade encontrada pelo Inspector vira finding no Security Hub com severidade padronizada pelo ASFF

**Laboratório (2h):** Habilitar Security Hub org-wide com delegated admin; configurar AWS Config com regras fundamentais de segurança (s3-bucket-public-read-prohibited, iam-root-access-key-check, cloudtrail-enabled); criar conformance pack customizado alinhado ao BACEN 4.893; habilitar Amazon Inspector na conta de produção e analisar findings de EC2 e ECR.

---

### Módulo 05 — Investigação de Incidentes (1h vídeo + 2h lab + 1h live)

**Tópicos:**
- Amazon Detective: behavior graphs (AWS accounts, IAM roles, EC2 instances, users, S3 buckets), finding groups, EKS cluster findings, time-based análise de atividade anômala, contribution analysis, geolocation de IPs
- Técnicas de análise de CloudTrail para IR:
  - Reconstrução de timeline de comprometimento
  - Identificação de credential theft (GetSessionToken, AssumeRole suspeito)
  - Detecção de privilege escalation via PassRole, CreatePolicy, AttachUserPolicy
  - Rastreamento de data exfiltration via S3 GetObject em lote
- CloudTrail Lake como ferramenta de investigação: queries SQL para reconstrução de eventos, correlação entre chamadas de API por SessionToken, identificação de `errorCode` que indicam reconnaissance
- Preservação de evidências: snapshot de EBS, hash S3 com S3 Object Lock, exportação de logs para conta isolada
- AWS Security Incident Response Guide: fases PICERL adaptadas para AWS (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned)
- Técnicas de contenção em AWS: snapshot de EC2 comprometido, isolamento de security group (ingress/egress block), revogação de credenciais IAM temporárias (invalidate session), bloqueio de usuário IAM

**Laboratório (2h — desafio):** Dado um conjunto de logs de CloudTrail fornecidos, identificar: (a) IP de origem do ataque inicial, (b) credencial comprometida, (c) resources acessados após o comprometimento, (d) se houve privilege escalation e qual técnica foi usada, (e) dados exfiltrados. Usar Detective e CloudTrail Lake para responder as perguntas e montar timeline do incidente.

---

### Módulo 06 — Proteção de Dados (2h vídeo + 1h lab)

**Tópicos:**
- AWS KMS: Customer Managed Keys (CMK) vs AWS Managed Keys vs AWS Owned Keys, key policies (separação de controle entre key admin e key user), grants para acesso programático temporário, multi-region keys (cross-region disaster recovery), automatic key rotation, envelope encryption (plaintext data key + encrypted data key), KMS integração nativa com 100+ serviços AWS
- AWS Secrets Manager: criação e uso de secrets, automatic rotation via Lambda (RDS, Redshift, DocumentDB nativamente; custom Lambda rotation para outros), cross-account access, integração com ECS (task definition secret injection), EKS (External Secrets Operator), Lambda (via SDK ou extension layer), versioning de secrets
- AWS CloudHSM: casos de uso (quando HSM dedicado é exigido pelo regulador), cluster de HSMs, integração com EC2 via PKCS#11 / JCE / OpenSSL, diferença para KMS (controle total das chaves vs gerenciamento compartilhado), FIPS 140-2 Level 3
- Amazon Macie: classification jobs em S3, sensitive data identifiers (managed: PII, PCI, PHI; custom: regex e palavras-chave), bucket inventory e postura de segurança (public access, encryption, cross-account access), findings (SensitiveData e Policy findings), integração com Security Hub

**Laboratório (1h):** Criar CMK para criptografar bucket S3; configurar Secrets Manager com rotation automática de senha RDS; executar Macie classification job em bucket com dados fictícios de clientes do Banco Meridian (CPFs e cartões de crédito gerados por biblioteca faker); analisar Macie findings no Security Hub.

---

### Módulo 07 — Segurança de Rede (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- Amazon VPC hardening: design de subnets (public, private, isolated), Security Groups (stateful, rules por protocolo/porta/CIDR/SG), NACLs (stateless, regras numeradas, deny explícito), VPC Endpoints (Gateway para S3/DynamoDB, Interface para 100+ serviços), VPC PrivateLink para expor serviços sem internet, VPC Reachability Analyzer
- AWS WAF v2: Web ACLs, rule groups (managed da AWS e marketplace, custom rules), rate-based rules (limitação por IP/header/cookie), Bot Control (bot detection e challenge), Fraud Control (Account Takeover Protection, Account Creation Fraud Prevention), CAPTCHA e Challenge actions, logging para Kinesis Firehose/CloudWatch/S3
- AWS Shield: Standard (proteção automática para recursos AWS) vs Advanced (proteção dedicada L3/L4/L7, SLA financeiro, DDoS Response Team, relatórios de ataque), casos de uso para proteção de ALB, CloudFront, Route 53, Global Accelerator
- AWS Network Firewall: stateful rules (Suricata IDS/IPS), stateless rules, centralized inspection architecture com Transit Gateway, firewall policies e rule groups, análise de tráfego norte-sul e leste-oeste, integração com CloudWatch e S3 para logs
- Route 53 Resolver DNS Firewall: domain lists (managed pela AWS para botnets, malware, phishing), custom domain lists, regras BLOCK/ALERT/ALLOW, proteção contra DNS tunneling e DGA domains

**Laboratório (2h):** Criar WAF Web ACL com AWS Managed Rules + regra de rate limiting customizada; simular requisições maliciosas (SQL injection, XSS) e verificar bloqueio; configurar Network Firewall em arquitetura centralizada com TGW; habilitar DNS Firewall com managed domain list para malware; verificar alertas no CloudWatch.

---

### Módulo 08 — Automação e Response (2h vídeo + 2h lab + 1h live)

**Tópicos:**
- Amazon EventBridge: event buses, rules, event patterns (match por source, detail-type, detail), scheduled rules (cron/rate), API destinations (webhooks externos), targets (Lambda, SNS, SQS, SSM, Step Functions), event replay, AWS Health events para resposta a problemas de serviço
- AWS Lambda para IR: funções de resposta em Python com Boto3 (isolamento de EC2 via security group, revogação de credenciais IAM, desabilitação de usuário, snapshot de EBS para evidência, notificação Teams/Slack/PagerDuty), ambiente de execução, variáveis de ambiente com Secrets Manager, function URL
- AWS Systems Manager: Session Manager (acesso sem SSH/RDP, sem security group inbound), Automation runbooks (AWS-managed e custom), Patch Manager (patch baseline, maintenance windows, compliance), State Manager (drift detection), Inventory
- AWS Step Functions: state machines para fluxos de IR multi-step (paralelos e sequenciais), error handling e retry, Express vs Standard workflows, integração com SDK (100+ serviços), uso para playbooks de IR com aprovação humana (wait for callback pattern)
- Padrão de automação de IR na AWS: GuardDuty finding → EventBridge rule → Step Function workflow → Lambda actions (isolate, snapshot, notify, ticket) → aprovação humana (SNS email) → erradicação

**Laboratório (2h):** Construir pipeline completo de resposta automatizada: GuardDuty finding (simulado) → EventBridge rule → Step Function → Lambda isolamento de EC2 + snapshot de EBS + notificação Slack + criação de ticket ServiceNow (mock). Configurar approval step para ações destrutivas.

---

### Módulo 09 — Segurança Multi-Conta (1h vídeo + 1h lab)

**Tópicos:**
- AWS Organizations avançado: delegated administration para GuardDuty, Security Hub, Macie, Inspector, Config, CloudTrail, IAM Access Analyzer, Detective; tag policies; backup policies; Service Control Policies (SCPs) para prevenção (guardrails preventivos): bloquear regiões, exigir MFA na console, impedir desabilitar logging, impedir saída de conta da org
- IAM Identity Center (SSO): provisionamento automático de usuários (SCIM), permission sets mapeados para roles, attribute-based access control com atributos do identity provider, access portal, CLI SSO integration (`aws sso login`)
- Estrutura de contas recomendada (AWS SRA):
  - Management Account: apenas para org-level resources
  - Security OU: Audit Account (delegated admin) + Log Archive Account (WORM logs)
  - Shared Services OU: Network Account, Identity Account
  - Workloads OUs: Prod, Staging, Sandbox por linha de negócio
- Cross-account access patterns: role chaining, external ID para third-party, conditions com `aws:PrincipalOrgID`
- Log Archive Account: S3 Bucket Policies negando delete, S3 Object Lock (Governance/Compliance mode), replicação cross-region, Glacier Instant Retrieval para logs antigos, custo estimado por volume de logs

**Laboratório (1h):** Configurar delegated administration do Security Hub para conta Audit; criar permission set no IAM Identity Center mapeando para role SecurityAuditor; verificar acesso cross-account ao Security Hub; criar SCP que impede criação de IAM users (força uso do Identity Center).

---

## Alinhamento MITRE ATT&CK for Cloud

| Tática              | Técnica / Sub-técnica                                       | Serviço AWS de Detecção         | Lab / Módulo   |
|:--------------------|:------------------------------------------------------------|:--------------------------------|:---------------|
| Initial Access      | T1190 — Exploit Public-Facing Application                   | WAF, GuardDuty                  | Lab 07         |
| Initial Access      | T1078.004 — Valid Accounts: Cloud Accounts                  | GuardDuty, CloudTrail           | Capstone       |
| Persistence         | T1098.001 — Additional Cloud Credentials                    | CloudTrail, GuardDuty           | Mod 05         |
| Persistence         | T1136.003 — Create Cloud Account                            | CloudTrail, Config              | Mod 01         |
| Privilege Escalation| T1548.005 — Abuse Elevation Control (PassRole)              | CloudTrail Lake, Detective      | Lab 04, Capstone |
| Defense Evasion     | T1562.008 — Disable or Modify Cloud Logs                    | GuardDuty, CloudTrail Insights  | Mod 02         |
| Discovery           | T1580 — Cloud Infrastructure Discovery                      | GuardDuty, CloudTrail           | Mod 03         |
| Discovery           | T1087.004 — Account Discovery: Cloud Account                | CloudTrail                      | Lab 04         |
| Credential Access   | T1552.005 — Cloud Instance Metadata API                     | GuardDuty (MetadataApiCall)     | Mod 03         |
| Lateral Movement    | T1550.001 — Use Alternate Auth Material (IAM assume)        | CloudTrail, Detective           | Lab 04         |
| Collection          | T1530 — Data from Cloud Storage Object                      | Macie, GuardDuty, CloudTrail    | Mod 06, Capstone |
| Exfiltration        | T1537 — Transfer Data to Cloud Account                      | GuardDuty (S3 findings)         | Capstone       |
| Impact              | T1496 — Resource Hijacking (crypto mining)                  | GuardDuty (CryptoCurrency)      | Mod 03         |

---

## Exemplos de Código — Scripts de Automação

### Lambda: Isolar EC2 comprometida (Boto3 Python)

```python
import boto3
import json
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Função Lambda para isolamento automático de EC2 comprometida.
    Triggered por GuardDuty finding via EventBridge.
    
    Ações realizadas:
    1. Identificar a instância EC2 do finding
    2. Criar um security group de isolamento (sem ingress/egress)
    3. Substituir os security groups da instância pelo de isolamento
    4. Criar snapshot de EBS para preservação de evidência
    5. Adicionar tag de status na instância
    """
    
    ec2 = boto3.client('ec2')
    sns = boto3.client('sns')
    
    # Extrair detalhes do finding do GuardDuty
    finding = event.get('detail', {})
    finding_id = finding.get('id', 'N/A')
    finding_type = finding.get('type', 'N/A')
    severity = finding.get('severity', 0)
    
    # Extrair instance ID do finding
    resource = finding.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')
    
    if not instance_id:
        logger.error("Nenhuma instância EC2 encontrada no finding")
        return {'statusCode': 400, 'body': 'No instance ID in finding'}
    
    logger.info(f"Iniciando isolamento da instância {instance_id} | Finding: {finding_type} | Severity: {severity}")
    
    try:
        # Obter VPC da instância
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        instance = instance_info['Reservations'][0]['Instances'][0]
        vpc_id = instance['VpcId']
        
        # Criar security group de isolamento (sem regras = sem tráfego)
        isolation_sg_name = f"ISOLATED-{instance_id}-{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
        sg_response = ec2.create_security_group(
            GroupName=isolation_sg_name,
            Description=f"SECURITY INCIDENT ISOLATION - Instance: {instance_id} - Finding: {finding_type}",
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': 'Name', 'Value': isolation_sg_name},
                    {'Key': 'Purpose', 'Value': 'IncidentResponse'},
                    {'Key': 'SourceInstance', 'Value': instance_id},
                    {'Key': 'GuardDutyFinding', 'Value': finding_id}
                ]
            }]
        )
        isolation_sg_id = sg_response['GroupId']
        logger.info(f"Security group de isolamento criado: {isolation_sg_id}")
        
        # Substituir security groups da instância pelo de isolamento
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        logger.info(f"Instância {instance_id} isolada — SGs substituídos por {isolation_sg_id}")
        
        # Criar snapshots de todos os volumes EBS para preservação de evidência
        snapshots = []
        for volume in instance.get('BlockDeviceMappings', []):
            volume_id = volume['Ebs']['VolumeId']
            snapshot = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"FORENSIC SNAPSHOT - Incident Response - Instance {instance_id}",
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f"forensic-{instance_id}-{volume_id}"},
                        {'Key': 'Purpose', 'Value': 'ForensicEvidence'},
                        {'Key': 'IncidentFinding', 'Value': finding_id}
                    ]
                }]
            )
            snapshots.append(snapshot['SnapshotId'])
            logger.info(f"Snapshot criado: {snapshot['SnapshotId']} para volume {volume_id}")
        
        # Taggear a instância com status de incidente
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'IncidentStatus', 'Value': 'ISOLATED'},
                {'Key': 'IncidentFinding', 'Value': finding_id},
                {'Key': 'IncidentTime', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'ForensicSnapshots', 'Value': ','.join(snapshots)}
            ]
        )
        
        # Notificar equipe de SOC via SNS
        sns_topic_arn = 'arn:aws:sns:sa-east-1:444444444444:soc-alerts-meridian'
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"[INCIDENT RESPONSE] EC2 Isolada — {finding_type}",
            Message=json.dumps({
                'acao': 'ISOLAMENTO_EC2',
                'instancia': instance_id,
                'vpc': vpc_id,
                'isolation_sg': isolation_sg_id,
                'snapshots': snapshots,
                'finding_type': finding_type,
                'finding_id': finding_id,
                'severidade': severity,
                'timestamp': datetime.utcnow().isoformat(),
                'proximo_passo': 'Investigar logs do CloudTrail e iniciar análise forense dos snapshots'
            }, indent=2)
        )
        
        return {
            'statusCode': 200,
            'body': {
                'instance_id': instance_id,
                'isolation_sg': isolation_sg_id,
                'snapshots': snapshots,
                'status': 'ISOLATED'
            }
        }
        
    except Exception as e:
        logger.error(f"Erro ao isolar instância {instance_id}: {str(e)}")
        raise
```

---

### CloudTrail Lake SQL — Detectar Privilege Escalation via PassRole

```sql
/* Detectar possível privilege escalation via PassRole + criação de recursos
   Técnica MITRE: T1548.005 — Abuse Elevation Control Mechanism: Temp Elevated Cloud Access */

SELECT
    eventTime,
    userIdentity.arn AS callerArn,
    userIdentity.sessionContext.sessionIssuer.arn AS assumedFromRole,
    eventName,
    requestParameters,
    responseElements,
    sourceIPAddress,
    awsRegion,
    errorCode,
    errorMessage
FROM <EVENT_DATA_STORE_ARN>
WHERE
    eventTime > '2026-04-24 00:00:00'
    AND (
        /* PassRole para outro serviço ou usuário */
        (eventName = 'PassRole' AND eventSource = 'iam.amazonaws.com')
        OR
        /* Criação de policy inline com permissões amplas */
        (eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy')
         AND requestParameters LIKE '%"Action":"*"%')
        OR
        /* Attach de policy AdministratorAccess */
        (eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
         AND requestParameters LIKE '%AdministratorAccess%')
        OR
        /* Criação de chave de acesso para usuário que não é a própria identidade */
        (eventName = 'CreateAccessKey'
         AND requestParameters NOT LIKE CONCAT('%', userIdentity.userName, '%'))
    )
ORDER BY eventTime ASC
LIMIT 200
```

---

## Referências e Leituras Recomendadas

| Tipo         | Título / Recurso                                                                              | Onde acessar                                |
|:-------------|:----------------------------------------------------------------------------------------------|:--------------------------------------------|
| Documentação | AWS Security Documentation Hub                                                                | docs.aws.amazon.com/security                |
| Guia         | AWS Security Incident Response Guide (2023)                                                   | docs.aws.amazon.com/whitepapers             |
| Guia         | AWS Well-Architected Framework — Security Pillar Whitepaper                                   | docs.aws.amazon.com/wellarchitected         |
| Guia         | AWS Security Reference Architecture (SRA) — prescriptive guidance                            | docs.aws.amazon.com/prescriptive-guidance   |
| Certificação | Guia de estudo AWS SCS-C02 (Security Specialty)                                               | aws.amazon.com/certification/security       |
| Livro        | "AWS Security" — Dylan Shields (Manning, 2023)                                                | manning.com                                 |
| Site         | Hacking the Cloud — técnicas de ataque cloud com defesa                                       | hackingthe.cloud                            |
| Blog         | AWS Security Blog                                                                             | aws.amazon.com/blogs/security               |
| Ferramenta   | Prowler v3 — AWS/Azure/GCP Security Assessment                                                | github.com/prowler-cloud/prowler            |
| Ferramenta   | ScoutSuite — Multi-Cloud Security Auditing                                                    | github.com/nccgroup/ScoutSuite              |
| Ferramenta   | Pacu — AWS Exploitation Framework (red team autorizado)                                       | github.com/RhinoSecurityLabs/pacu           |
| Relatório    | Unit 42 Cloud Threat Report — semestral (Palo Alto)                                           | unit42.paloaltonetworks.com                 |
| Relatório    | CrowdStrike Global Threat Report — anual                                                      | crowdstrike.com/global-threat-report        |
| Framework    | MITRE ATT&CK for Cloud — IaaS AWS Matrix                                                     | attack.mitre.org/matrices/enterprise/cloud  |
| Regulatório  | Resolução BACEN 4.893/2021 — Política de Segurança Cibernética para IFs                      | bcb.gov.br/estabilidadefinanceira           |
| Regulatório  | CMN 4.658/2018 — Serviços de Processamento e Armazenamento em Nuvem                          | bcb.gov.br/estabilidadefinanceira           |
| Regulatório  | LGPD — Lei 13.709/2018                                                                       | lgpd.gov.br                                |

---

*Próximo passo: [Módulo 00 — Preparação do Ambiente de Laboratório AWS](modulos/modulo-00-ambiente-laboratorio/README.md)*

---

*Curso 3 · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
