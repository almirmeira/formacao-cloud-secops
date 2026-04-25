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

*Próximo passo: [Módulo 00 — Preparação do Ambiente de Laboratório AWS](modulos/modulo-00-ambiente-laboratorio/README.md)*

---

*Curso 3 · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
