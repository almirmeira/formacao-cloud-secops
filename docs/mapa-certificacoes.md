# Mapa de Certificações — Formação Cloud SecOps

**CECyber · Programa de Formação Security Operations em Nuvem**

---

## Como Usar Este Documento

Este documento mapeia cada módulo dos 4 cursos da formação para os domínios e capítulos oficiais das principais certificações de segurança cloud e cibersegurança do mercado.

**Para quem está se preparando para uma certificação específica**, use as seções dedicadas (SC-200, SCS-C02, etc.) para identificar quais módulos do curso cobrem cada domínio do exame.

**Para quem faz a formação sem um exame específico em mente**, use a tabela geral para entender que sua formação está alinhada com múltiplas certificações — você sai preparado para ao menos uma certificação por curso.

**Legenda de cobertura:**

| Símbolo | Significado                                                   |
|:-------:|:--------------------------------------------------------------|
| PP      | Preparação Primária — módulo cobre extensamente este domínio  |
| PS      | Preparação Secundária — módulo cobre parcialmente este domínio |
| R       | Referência — domínio mencionado como contexto no módulo       |

---

## Tabela Geral — Formação × Certificações

| Domínio / Certificação                        | Curso 1 Google SecOps | Curso 2 Azure SecOps | Curso 3 AWS SecOps | Curso 4 Cloud Tools |
|:----------------------------------------------|:---------------------:|:--------------------:|:-----------------:|:-------------------:|
| **Microsoft SC-200**                           |                       |                      |                   |                     |
| LP1: Mitigate threats using Microsoft Defender | —                     | PP (Mod 06, 08)      | —                 | R                   |
| LP2: Mitigate threats using Defender for Cloud | —                     | PP (Mod 07)          | R                 | PS (Mod 02)         |
| LP3: Mitigate threats using Microsoft Sentinel | R                     | PP (Mod 02–05, 09)   | —                 | —                   |
| LP4: Create detections using KQL              | R                     | PP (Mod 03, 04)      | —                 | —                   |
| LP5: Perform threat hunting in Microsoft Sentinel | —                 | PP (Mod 09)          | —                 | —                   |
| **AWS Security Specialty SCS-C02**            |                       |                      |                   |                     |
| D1: Threat Detection & Incident Response      | PS                    | R                    | PP (Mod 03, 05, 08) | R                 |
| D2: Security Logging & Monitoring             | PS                    | R                    | PP (Mod 02, 04, 09) | R                 |
| D3: Infrastructure Security                   | —                     | R                    | PP (Mod 01, 07, 09) | PS (Mod 05)       |
| D4: Identity and Access Management            | —                     | PS (Mod 08)          | PP (Mod 01, 09)   | PS (Mod 06)         |
| D5: Data Protection                           | —                     | R                    | PP (Mod 06)       | PS (Mod 07)         |
| D6: Management & Security Governance          | R                     | PS (Mod 07)          | PP (Mod 04, 08, 09) | PS (Mod 01)       |
| **Google Cloud Professional Security Engineer** |                     |                      |                   |                     |
| D1: Configuring access within a cloud solution | R                    | PS                   | PS                | PP (Mod 06)         |
| D2: Configuring network security              | R                     | R                    | PS (Mod 07)       | PS (Mod 05)         |
| D3: Ensuring data protection                  | R                     | R                    | PS (Mod 06)       | PP (Mod 07)         |
| D4: Managing operations within a cloud solution | PP (Mod 06, 07)    | PS                   | PS                | R                   |
| D5: Ensuring compliance                       | PS (Mod 01)           | PS (Mod 07)          | PS (Mod 04)       | PP (Mod 01)         |
| D6: Managing incident response               | PP (Mod 06, 07)       | PP (Mod 05, 10)      | PP (Mod 05, 08)   | R                   |
| **CCSP (ISC²)**                               |                       |                      |                   |                     |
| D1: Cloud Concepts, Architecture, Design      | PS                    | PS                   | PS                | PP (Mod 01, 08)     |
| D2: Cloud Data Security                       | R                     | R                    | PP (Mod 06)       | PP (Mod 06, 07, 08) |
| D3: Cloud Platform & Infrastructure Security  | R                     | PP (Mod 01, 07)      | PP (Mod 01, 07)   | PP (Mod 02–06)      |
| D4: Cloud Application Security               | R                     | R                    | R                 | PP (Mod 03, 04, 05) |
| D5: Cloud Security Operations                 | PP (todos os mod)     | PP (todos os mod)    | PP (todos os mod) | PP (Mod 09)         |
| D6: Legal, Risk & Compliance                  | PS (Mod 01)           | PS (Mod 07)          | PS (Mod 04)       | PS (Mod 01, 08)     |
| **CISSP — Domínio Cloud Security**            |                       |                      |                   |                     |
| D1: Security & Risk Management               | PS                    | PS                   | PS                | PS                  |
| D2: Asset Security                            | R                     | R                    | PP (Mod 06)       | PP (Mod 06, 07)     |
| D3: Security Architecture & Engineering       | R                     | PP (Mod 01)          | PP (Mod 01, 09)   | PP (Mod 01, 05)     |
| D5: Identity & Access Management             | R                     | PP (Mod 08)          | PP (Mod 01, 09)   | PP (Mod 06)         |
| D7: Security Operations                       | PP (todos os mod)     | PP (todos os mod)    | PP (todos os mod) | PP (Mod 09)         |
| D8: Software Development Security             | R                     | R                    | R                 | PP (Mod 03, 04)     |
| **CompTIA CySA+**                             |                       |                      |                   |                     |
| D1: Threat and Vulnerability Management       | PP (Mod 03, 04)       | PP (Mod 04, 06)      | PP (Mod 03, 04)   | PP (Mod 02, 04)     |
| D2: Software & Systems Security              | R                     | R                    | PS                | PP (Mod 03, 04, 05) |
| D3: Security Operations & Monitoring          | PP (Mod 02, 06)       | PP (Mod 02, 05, 09)  | PP (Mod 02, 08)   | PS (Mod 01)         |
| D4: Incident Response                         | PP (Mod 06, 07)       | PP (Mod 05, 10)      | PP (Mod 05, 08)   | R                   |
| D5: Compliance & Assessment                   | PS (Mod 01)           | PS (Mod 07)          | PS (Mod 04)       | PP (Mod 01)         |
| **CompTIA CASP+**                             |                       |                      |                   |                     |
| D1: Security Architecture                     | R                     | PP (Mod 01)          | PP (Mod 01, 09)   | PP (Mod 01, 08)     |
| D2: Security Operations                       | PP (todos os mod)     | PP (todos os mod)    | PP (todos os mod) | PP (Mod 09)         |
| D3: Security Engineering                      | R                     | PS                   | PS                | PP (Mod 03–07)      |
| D4: Governance, Risk & Compliance             | PS                    | PS (Mod 07)          | PS (Mod 04, 09)   | PP (Mod 01)         |

---

## Microsoft SC-200 — Mapa Detalhado

**Certificação:** Microsoft Certified: Security Operations Analyst Associate
**Exame:** SC-200
**Validade:** 1 ano (recertificação anual exigida)
**Preço:** USD 165

### Learning Paths e Módulos da Formação

#### Learning Path 1 — Mitigate threats using Microsoft 365 Defender

| Tópico Oficial SC-200                                    | Peso Estimado | Módulos da Formação          |
|:---------------------------------------------------------|:-------------:|:-----------------------------|
| Defender for Endpoint — onboarding, configuração         | 15%           | Mod 06 (MDE), Mod 00 (lab)  |
| Defender for Identity — instalação de sensor, alertas ADI | 8%           | Mod 06 (MDI)                 |
| Defender for Office 365 — anti-phishing, ATP, Safe Links | 8%           | Mod 06 (MDO)                 |
| Microsoft Defender for Cloud Apps — policies, connectors | 8%           | Mod 06 (MDA)                 |
| Microsoft 365 Defender — advanced hunting, incidents     | 12%           | Mod 06 (Advanced Hunting)    |

#### Learning Path 2 — Mitigate threats using Microsoft Defender for Cloud

| Tópico Oficial SC-200                                    | Peso Estimado | Módulos da Formação          |
|:---------------------------------------------------------|:-------------:|:-----------------------------|
| Enable Defender for Cloud plans                          | 5%            | Mod 07                       |
| Understand Secure Score e recomendações                  | 8%            | Mod 07 (Secure Score)        |
| Regulatory Compliance no Defender for Cloud              | 7%            | Mod 07 (LGPD/BACEN/CIS)      |
| Defender for Servers, Storage, SQL, Containers           | 8%            | Mod 07 (CWPP plans)          |
| Multi-cloud (AWS, GCP via Arc)                           | 5%            | Mod 07 (multi-cloud)         |

#### Learning Path 3 — Mitigate threats using Microsoft Sentinel

| Tópico Oficial SC-200                                    | Peso Estimado | Módulos da Formação          |
|:---------------------------------------------------------|:-------------:|:-----------------------------|
| Design e deploy do Sentinel (workspace, cost, connectors) | 10%          | Mod 02, Mod 00               |
| Data connectors (M365 Defender, Entra ID, Azure Activity) | 8%          | Mod 02 (Conectores)          |
| Analytics rules (Scheduled, NRT, Fusion, Anomaly)        | 12%           | Mod 04 (Analytics Rules)     |
| SOAR — Logic Apps, automation rules                      | 10%           | Mod 05 (SOAR)                |
| Workbooks e Dashboards                                   | 5%            | Mod 02 + Mod 09              |

#### Learning Path 4 — Create detections and perform investigations using KQL

| Tópico Oficial SC-200                                    | Peso Estimado | Módulos da Formação          |
|:---------------------------------------------------------|:-------------:|:-----------------------------|
| KQL fundamentals (where, project, extend, summarize)     | 8%            | Mod 03 (Aula 3.1)           |
| KQL avançado (join, union, bin, arg_max, mv-expand)      | 10%           | Mod 03 (Aula 3.1 + 3.2)     |
| ASIM (Advanced Security Information Model)               | 5%            | Mod 03 (ASIM)                |
| KQL para detecção de ameaças (sign-in, lateral movement) | 12%           | Mod 03 (queries SOC)         |
| Entity mapping e investigation graph no Sentinel         | 5%            | Mod 04 + Mod 09              |

#### Learning Path 5 — Perform threat hunting in Microsoft Sentinel

| Tópico Oficial SC-200                                    | Peso Estimado | Módulos da Formação          |
|:---------------------------------------------------------|:-------------:|:-----------------------------|
| Hunting hypotheses e metodologia                         | 5%            | Mod 09 (metodologia)         |
| Hunting queries e bookmarks                              | 8%            | Mod 09 (queries hunting)     |
| Jupyter Notebooks no Sentinel                            | 5%            | Mod 09 (notebooks)           |
| Livestream hunting e MHR (Microsoft Hunter Reports)      | 5%            | Mod 09 + Live 4              |

---

## AWS Security Specialty SCS-C02 — Mapa Detalhado

**Certificação:** AWS Certified Security – Specialty
**Exame:** SCS-C02
**Validade:** 3 anos
**Preço:** USD 300

### Domínios e Módulos da Formação

| Domínio               | Título Oficial                                          | Peso no Exame | Módulos da Formação |
|:---------------------:|:--------------------------------------------------------|:-------------:|:--------------------|
| D1                    | Threat Detection and Incident Response                  | 14%           | Mod 03, 05, 08, 10  |
| D2                    | Security Logging and Monitoring                         | 18%           | Mod 02, 04, 09      |
| D3                    | Infrastructure Security                                 | 20%           | Mod 01, 07, 09      |
| D4                    | Identity and Access Management                          | 16%           | Mod 01, 09          |
| D5                    | Data Protection                                         | 18%           | Mod 06              |
| D6                    | Management and Security Governance                      | 14%           | Mod 04, 08, 09      |

#### Domínio 1 — Threat Detection and Incident Response (14%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Habilitar e configurar GuardDuty, criar filtering rules         | Mod 03                    |
| Investigar findings do GuardDuty usando Detective               | Mod 05                    |
| Automatizar resposta a findings com EventBridge + Lambda        | Mod 08                    |
| Implementar plano de resposta a incidentes (PICERL)             | Mod 05                    |
| Analisar logs do CloudTrail para reconstruir timeline           | Mod 02, 05                |
| Isolar EC2 comprometida, criar snapshot para forense            | Mod 05, 08                |

#### Domínio 2 — Security Logging and Monitoring (18%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Configurar CloudTrail com log file integrity e criptografia KMS | Mod 02                    |
| Configurar VPC Flow Logs para análise de rede                   | Mod 02                    |
| Criar CloudWatch Metric Filters e Alarms para eventos críticos  | Mod 02                    |
| Consolidar logs em conta Log Archive com S3 Object Lock         | Mod 09                    |
| Usar CloudTrail Lake para queries de investigação               | Mod 02, 05                |
| Configurar Security Hub e interpretar findings                  | Mod 04                    |

#### Domínio 3 — Infrastructure Security (20%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Design de VPC segura (subnets, endpoints, NACLs, SGs)           | Mod 07                    |
| Configurar AWS WAF com managed rules e regras customizadas      | Mod 07                    |
| Implementar AWS Network Firewall com regras Suricata            | Mod 07                    |
| Configurar Shield Advanced para DDoS protection                 | Mod 07                    |
| Usar VPC Endpoints para acesso privado a serviços AWS           | Mod 07                    |
| Implementar SCPs para guardrails em AWS Organizations           | Mod 01, 09                |

#### Domínio 4 — Identity and Access Management (16%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Design de IAM policies com least privilege e conditions         | Mod 01                    |
| Usar IAM roles cross-account com External ID                    | Mod 01, 09                |
| Configurar permission boundaries e ABAC com tags                | Mod 01                    |
| Usar IAM Access Analyzer para findings de acesso externo        | Mod 01, Lab 05            |
| Configurar IAM Identity Center (SSO) com permission sets        | Mod 09                    |
| Identificar e mitigar privilege escalation via PassRole         | Mod 05                    |

#### Domínio 5 — Data Protection (18%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Criar e gerenciar CMKs no AWS KMS com key policies              | Mod 06                    |
| Configurar criptografia em repouso para S3, RDS, EBS, EFS       | Mod 06                    |
| Implementar Secrets Manager com rotation automática             | Mod 06                    |
| Usar Macie para descoberta de dados sensíveis em S3             | Mod 06                    |
| Configurar CloudHSM para requisitos FIPS 140-2 Level 3          | Mod 06                    |
| Forçar criptografia em trânsito (SSL/TLS) via policies          | Mod 07                    |

#### Domínio 6 — Management and Security Governance (14%)

| Task no Exame                                                   | Módulo da Formação        |
|:----------------------------------------------------------------|:--------------------------|
| Usar AWS Config com conformance packs para compliance           | Mod 04                    |
| Configurar Amazon Inspector para vulnerability management       | Mod 04                    |
| Implementar automação de remediação com Config + SSM            | Mod 04, 08                |
| Configurar GuardDuty e Security Hub org-wide via Organizations  | Mod 03, 04, 09            |
| Usar Step Functions para orquestrar playbooks de IR             | Mod 08                    |

---

## Google Cloud Professional Cloud Security Engineer — Mapa Detalhado

**Certificação:** Google Cloud Professional Cloud Security Engineer
**Exame:** Disponível em português
**Validade:** 2 anos
**Preço:** USD 200

| Domínio | Tema Oficial                                                      | Peso Estimado | Cursos/Módulos |
|:-------:|:------------------------------------------------------------------|:-------------:|:---------------|
| D1      | Configuring access within a cloud solution environment            | ~15%          | C3 Mod 01, C4 Mod 06 |
| D2      | Configuring network security                                      | ~15%          | C3 Mod 07, C4 Mod 05 |
| D3      | Ensuring data protection                                          | ~20%          | C3 Mod 06, C4 Mod 07 |
| D4      | Managing operations in a cloud solution environment               | ~25%          | C1 todos, C3 Mod 03-05 |
| D5      | Ensuring compliance                                               | ~15%          | C3 Mod 04, C4 Mod 01 |
| D6      | Managing incident response                                        | ~10%          | C1 Mod 07, C3 Mod 05, 08 |

**Nota:** O Curso 1 da formação é sobre Google SecOps (Chronicle), que é a principal ferramenta de Managed Security Service da Google Cloud. A formação cobre os aspectos operacionais de segurança do Google Cloud, mas para cobertura completa da certificação Professional Cloud Security Engineer recomenda-se complementar com o curso oficial Google Cloud Skills Boost (Cloud Security Fundamentals e Cloud Security Architecture paths).

---

## CCSP (ISC²) — Mapa Detalhado

**Certificação:** Certified Cloud Security Professional (ISC²)
**Exame:** 150 questões adaptativas, 4 horas
**Validade:** 3 anos (45 CPEs/ano)
**Preço:** USD 599

| Domínio | Tema Oficial CCSP                                                 | Peso no Exame | Cursos/Módulos da Formação |
|:-------:|:------------------------------------------------------------------|:-------------:|:---------------------------|
| D1      | Cloud Concepts, Architecture, and Design                          | 17%           | C4 Mod 01, 08              |
| D2      | Cloud Data Security                                               | 20%           | C3 Mod 06, C4 Mod 07, 08   |
| D3      | Cloud Platform and Infrastructure Security                        | 17%           | C2 Mod 01, 07; C3 Mod 01, 07; C4 Mod 02–06 |
| D4      | Cloud Application Security                                        | 17%           | C4 Mod 03, 04, 05          |
| D5      | Cloud Security Operations                                         | 16%           | C1 todos; C2 todos; C3 todos |
| D6      | Legal, Risk and Compliance                                        | 13%           | C2 Mod 07; C3 Mod 04; C4 Mod 01 + refs. BACEN/LGPD |

### CCSP — Tópicos por Domínio

**Domínio 1 — Cloud Concepts, Architecture, and Design:**
- Service models (IaaS, PaaS, SaaS, FaaS) → referenciado em todos os cursos
- Deployment models (Public, Private, Hybrid, Multi-cloud, Community) → C3 Mod 09, C4 Mod 08
- Cloud computing characteristics (on-demand, broad network access, resource pooling) → C4 Mod 01
- Cloud reference architectures (NIST, CSA STAR) → C4 Mod 01
- Cloud design patterns (availability, data management, resiliency) → C3 Mod 09

**Domínio 2 — Cloud Data Security:**
- Cloud data lifecycle (Create, Store, Use, Share, Archive, Destroy) → C3 Mod 06, C4 Mod 07
- Data discovery, classification, labeling, data flows → C3 Mod 06 (Macie), C4 Mod 08 (DSPM)
- Encryption, tokenization, masking → C3 Mod 06 (KMS/CloudHSM), C2 Mod 08
- Key management → C3 Mod 06 (KMS), C2 Mod 08 (Key Vault), C4 Mod 07 (Vault/SM)
- Data retention, deletion, archiving → C3 Mod 09 (Log Archive), C2 Mod 02

**Domínio 3 — Cloud Platform and Infrastructure Security:**
- Physical environment (responsabilidade do provider) → C4 Mod 01
- Compute, network, storage virtualization → C3 Mod 01, C2 Mod 01
- Container security → C4 Mod 04, 05
- Vulnerability management → C3 Mod 04 (Inspector), C2 Mod 07 (Defender for Cloud)
- Network security (virtual networks, access controls, firewall) → C2 Mod 07, C3 Mod 07

**Domínio 4 — Cloud Application Security:**
- Cloud Secure Software Development Lifecycle (SSDLC) → C4 Mod 03 (Shift-Left)
- Identity and access management for apps → C4 Mod 07 (Secrets), C3 Mod 01 (IAM)
- Dependency/supply chain management (SBOM, SCA) → C4 Mod 04 (Syft, Cosign)
- IaC security (Checkov, tfsec, OPA) → C4 Mod 03

**Domínio 5 — Cloud Security Operations:**
- Building and implementing a cloud SOC → C1 todos, C2 todos, C3 todos
- Monitoring and logging → C1 Mod 02, C2 Mod 02, C3 Mod 02
- Incident management → C1 Mod 06-07, C2 Mod 05-10, C3 Mod 05-10
- Threat intelligence → C1 Mod 05, C2 Mod 04 (TI integration)
- SOAR → C1 Mod 06, C2 Mod 05

**Domínio 6 — Legal, Risk and Compliance:**
- Legal requirements cloud e Brasil → docs/referencias-especialistas.md (BACEN, LGPD)
- Privacy regulations (LGPD, GDPR) → C3 Mod 04 (Inspector/Config), C4 Mod 08 (CASB/DSPM)
- Audit e assurance (SOC 2 Type II, ISO 27001) → C4 Mod 01
- Risk management → C4 Mod 09 (Capstone: business case)

---

## CISSP — Cloud Security no CBK

**Certificação:** Certified Information Systems Security Professional (ISC²)
**Exame:** 125–175 questões CAT, 4 horas
**Validade:** 3 anos (120 CPEs totais = 40 CPEs/ano)
**Experiência exigida:** 5 anos em ao menos 2 domínios do CBK

### Domínios Relevantes para Cloud Security

| Domínio CISSP | Tema                                                 | Relevância Cloud | Cursos/Módulos |
|:-------------:|:-----------------------------------------------------|:----------------:|:---------------|
| D1            | Security and Risk Management                         | Média            | C4 Mod 09 (business case/risk) |
| D2            | Asset Security                                       | Alta             | C3 Mod 06 (data), C4 Mod 07-08 |
| D3            | Security Architecture and Engineering                | Alta             | C2 Mod 01 (MCRA), C3 Mod 01 (Well-Arch), C4 Mod 01-08 |
| D4            | Communication and Network Security                   | Alta             | C2 Mod 07, C3 Mod 07, C4 Mod 05 |
| D5            | Identity and Access Management (IAM)                 | Alta             | C2 Mod 08, C3 Mod 01/09, C4 Mod 06 |
| D6            | Security Assessment and Testing                      | Média-Alta       | C3 Mod 04, C4 Mod 02/03 |
| D7            | Security Operations                                  | Alta             | C1 todos, C2 todos, C3 todos |
| D8            | Software Development Security                        | Média-Alta       | C4 Mod 03, 04, 05 |

**Tópicos específicos do CISSP CBK relacionados a Cloud:**
- Cloud computing concepts e modelos (D3 — Crypto e arquitetura)
- Cloud-specific threats (VM escape, hypervisor attacks, data co-mingling) → C4 Mod 01
- Data security em cloud (encryption at rest/transit, data residency) → C3 Mod 06
- IAM em ambientes cloud (federated identity, ABAC) → C3 Mod 01, C2 Mod 08
- DevSecOps e pipeline security → C4 Mod 03
- SOAR e automação de resposta → C1 Mod 06, C2 Mod 05, C3 Mod 08

---

## CompTIA CySA+ — Mapa Detalhado

**Certificação:** CompTIA Cybersecurity Analyst (CySA+)
**Exame:** CS0-003
**Validade:** 3 anos (renew ou exame)
**Preço:** USD 392

| Domínio | Tema Oficial                                  | Peso  | Cursos/Módulos |
|:-------:|:----------------------------------------------|:-----:|:---------------|
| D1      | Security Operations (33%)                     | 33%   | C1 Mod 02/06, C2 Mod 02/05/09, C3 Mod 02/08 |
| D2      | Vulnerability Management (30%)                | 30%   | C3 Mod 04, C4 Mod 02/03/04 |
| D3      | Incident Response and Management (20%)        | 20%   | C1 Mod 06-07, C2 Mod 05-10, C3 Mod 05-10 |
| D4      | Reporting and Communication (17%)             | 17%   | C1 Avaliação Final (relatório), C3 Mod 05 |

**Alinhamento específico Curso 1 (Google SecOps) com CySA+:**
- Domínio 1 (Security Operations): SIEM operations, log analysis, alert triage → Mod 02, 04, 06
- Domínio 2 (Vulnerability Management): UEBA como detecção comportamental → Mod 04
- Domínio 3 (Incident Response): Playbooks SOAR, fases PICERL → Mod 06, 07
- Domínio 4 (Reporting): Relatório de incidente, métricas MTTD/MTTR → Mod 06, 07

---

## CompTIA CASP+ — Mapa Detalhado

**Certificação:** CompTIA Advanced Security Practitioner (CASP+)
**Exame:** CAS-004
**Validade:** 3 anos (renew ou exame)
**Preço:** USD 512

| Domínio | Tema Oficial                                     | Peso  | Cursos/Módulos |
|:-------:|:-------------------------------------------------|:-----:|:---------------|
| D1      | Security Architecture (29%)                      | 29%   | C2 Mod 01, C3 Mod 01/09, C4 Mod 01/08 |
| D2      | Security Operations (30%)                        | 30%   | C1 todos, C2 todos, C3 todos |
| D3      | Security Engineering and Cryptography (26%)      | 26%   | C3 Mod 06, C4 Mod 03-07 |
| D4      | Governance, Risk, and Compliance (15%)           | 15%   | C2 Mod 07, C3 Mod 04, C4 Mod 01 + BACEN/LGPD |

---

## Matriz de Experiência Prática Acumulada

Ao concluir os 4 cursos da formação, o profissional terá experiência prática documentada com:

| Tipo de Experiência                                    | Horas Práticas | Cursos |
|:-------------------------------------------------------|:--------------:|:-------|
| Operação de SIEM em ambiente real (Google SecOps/Sentinel/AWS) | ~30h    | C1, C2, C3 |
| Detecção e engenharia de regras (YARA-L, KQL, GuardDuty) | ~18h       | C1, C2, C3 |
| Resposta a incidentes (SOAR, Lambda, Step Functions)    | ~12h           | C1, C2, C3 |
| Threat hunting proativo                                 | ~8h            | C1, C2 |
| Avaliação de postura (CSPM/CWPP tools)                  | ~12h           | C3, C4 |
| IaC Security (Checkov, tfsec, OPA, Cosign)              | ~6h            | C4     |
| Container Security (Trivy, Falco, K8s)                  | ~6h            | C4     |
| Secrets Management (Vault, SM, Key Vault)               | ~4h            | C4     |
| Multi-cloud architecture e governance                   | ~6h            | C3 Mod 09, C4 Mod 08 |

---

*Última atualização: 2026-04-24 · CECyber · Programa de Formação Security Operations em Nuvem*
