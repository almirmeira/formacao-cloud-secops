# Curso 2 — Microsoft Sentinel & Defender: SecOps no Azure

**Programa de Formação Security Operations em Nuvem · CECyber**

[![CH Total](https://img.shields.io/badge/Carga%20Horária-40h-blue)](#informações-gerais)
[![Vídeo](https://img.shields.io/badge/Videoaulas-16h-orange)](#modelo-pedagógico)
[![Lab](https://img.shields.io/badge/Laboratórios-16h-green)](#laboratórios-hands-on)
[![Live](https://img.shields.io/badge/Live%20Online-8h-purple)](#sessões-live-online)
[![Certificação](https://img.shields.io/badge/Certificação-SC--200-lightblue)](#certificação-alinhada)
[![Nível](https://img.shields.io/badge/Nível-Intermediário%2FAvançado-yellow)](#informações-gerais)

---

## Descrição

Formação intensiva em operações de segurança no ecossistema Microsoft, com foco em **Microsoft Sentinel** (SIEM/SOAR nativo na nuvem), **Microsoft Defender XDR** (proteção de endpoint, identidade, e-mail e aplicações), **Microsoft Defender for Cloud** (CSPM/CWPP multi-cloud) e **Microsoft Entra ID** (identidade e proteção). O curso prepara profissionais para detectar ameaças em ambientes Microsoft 365 e Azure, construir detecções em KQL, orquestrar respostas automatizadas com Logic Apps e conduzir investigações forenses no Microsoft 365 Defender.

O curso é construído sobre o **cenário fictício do Banco Meridian**, uma instituição financeira brasileira que opera infraestrutura híbrida com Azure, Microsoft 365 E5 e workloads em múltiplas nuvens. Os laboratórios reproduzem incidentes reais mapeados ao MITRE ATT&CK e ao contexto regulatório brasileiro (BACEN 4.893, LGPD).

A certificação alvo é a **SC-200: Microsoft Security Operations Analyst**, exame oficial da Microsoft.

---

## Informações Gerais

| Campo                       | Detalhes                                                                                      |
|:----------------------------|:----------------------------------------------------------------------------------------------|
| **Carga Horária Total**     | 40 horas                                                                                      |
| **Distribuição**            | 16h videoaulas (40%) + 16h laboratórios (40%) + 8h live online (20%)                         |
| **Modalidade**              | EAD híbrido (plataforma LMS + sessões ao vivo via Zoom/Teams)                                |
| **Duração Sugerida**        | 6–7 semanas (ritmo de ~6h/semana)                                                             |
| **Público-Alvo**            | Analistas de SOC, engenheiros de segurança Azure, administradores M365, threat hunters, incident responders |
| **Pré-requisitos**          | Curso 1 (Google SecOps) OU conhecimento equivalente de SIEM; fundamentos de Azure (AZ-900) ou M365 (MS-900); familiaridade com MITRE ATT&CK |
| **Nível**                   | Intermediário / Avançado                                                                      |
| **Certificação Alinhada**   | Microsoft SC-200: Security Operations Analyst Associate                                       |
| **Material Incluso**        | Videoaulas em HD, apostila PDF, KQL Query Library, playbooks prontos para uso, repositório GitHub, tenant M365 E5 de laboratório, certificado digital |
| **Aprovação**               | 70% de aproveitamento global                                                                  |

---

## Objetivos de Aprendizagem

Ao concluir o curso, o participante será capaz de:

1. **Arquitetar soluções de segurança** usando o ecossistema Microsoft (Sentinel, Defender XDR, Defender for Cloud, Entra ID) e aplicar o modelo Zero Trust ao ambiente de uma organização financeira
2. **Implantar e configurar o Microsoft Sentinel** com conectores de dados, regras analíticas e automação, seguindo boas práticas de custo e performance
3. **Escrever queries KQL** avançadas para detecção de ameaças, correlação de eventos e análise forense, incluindo uso de ASIM (Advanced Security Information Model)
4. **Construir detecções mapeadas ao MITRE ATT&CK** usando regras Scheduled, NRT, Fusion e Anomaly, com watchlists e Threat Intelligence integrada
5. **Orquestrar respostas automatizadas** com Logic Apps (playbooks SOAR) e automation rules, integrando-os a ServiceNow, Jira, Teams e plataformas EDR
6. **Investigar incidentes** com Microsoft Defender XDR (MDE, MDI, MDO, MDA) e conduzir threat hunting proativo com Advanced Hunting e notebooks Jupyter
7. **Gerenciar postura de segurança** com Microsoft Defender for Cloud, interpretar o Secure Score e mapear controles ao BACEN, LGPD e CIS Benchmarks

---

## Estrutura do Curso

```
curso-02-azure-secops/
│
├── README.md                                  ← Este arquivo
│
├── modulos/
│   ├── modulo-00-ambiente-laboratorio/        ← INÍCIO AQUI: tenant M365 E5 + Azure + Sentinel
│   ├── modulo-01-arquitetura-seguranca-ms/    ← Zero Trust, MCRA, Sentinel, Defender XDR (1h vídeo + 1h live)
│   ├── modulo-02-sentinel-deployment/         ← Deploy Sentinel, conectores, DCR, Content Hub (2h vídeo + 2h lab)
│   ├── modulo-03-kql/                         ← KQL: consultas para SOC, ASIM, biblioteca (3h vídeo + 3h lab + 1h live)
│   ├── modulo-04-detection-engineering/       ← Regras analíticas, MITRE, Watchlists, TI (2h vídeo + 2h lab + 1h live)
│   ├── modulo-05-soar-logic-apps/             ← Playbooks Logic Apps, automation rules (2h vídeo + 2h lab + 1h live)
│   ├── modulo-06-defender-xdr/                ← MDE, MDI, MDO, MDA, advanced hunting (2h vídeo + 2h lab + 1h live)
│   ├── modulo-07-defender-for-cloud/          ← CSPM, CWPP, Secure Score, LGPD/BACEN, multi-cloud (2h vídeo + 2h lab + 1h live)
│   ├── modulo-08-entra-id-protection/         ← Risk policies, Conditional Access, PIM (1h vídeo + 1h lab)
│   ├── modulo-09-threat-hunting/              ← Hunting proativo, hipóteses MITRE, Jupyter (1h vídeo + 1h lab + 1h live)
│   └── modulo-10-capstone/                    ← SOC Simulation: phishing→exfiltração (1h lab + 1h live)
│
├── laboratorios/
│   ├── lab-01/                                ← Deploy Sentinel com ARM/Bicep (2h)
│   ├── lab-02/                                ← KQL: investigação de sign-in anomalies (2h)
│   ├── lab-03/                                ← Detection Engineering: password spray (2h)
│   ├── lab-04/                                ← Playbook SOAR: phishing automatizado (2h)
│   ├── lab-05/                                ← Defender XDR: lateral movement (2h)
│   ├── lab-06/                                ← Defender for Cloud: CSPM multi-cloud (2h)
│   └── lab-capstone/                          ← Kill chain completa: Banco Meridian (2h lab + 2h live)
│
└── avaliacao-final/
    └── README.md                              ← Avaliação Final (40 questões + estudo de caso)
```

---

## Ementa Modular Detalhada

| Mód. | Conteúdo Programático                                                                                                                                          | Vídeo | Lab  | Live |
|:----:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----:|:----:|:----:|
|  00  | Preparação do Ambiente de Laboratório: tenant M365 E5 trial, workspace Sentinel, conectores básicos, usuários de teste do Banco Meridian                       | —     | 2h   | —    |
|  01  | Arquitetura de Segurança Microsoft: modelo Zero Trust (identidade, dispositivo, rede, aplicação, dados, infra), MCRA, Sentinel vs SIEM on-prem, Defender XDR, Defender for Cloud, Entra ID, Purview | 1h | — | 1h |
|  02  | Microsoft Sentinel — Implantação e Conectores: workspace Log Analytics, capacidade vs Pay-As-You-Go, data connectors nativos (AAD, MDE, M365, Azure Activity, Syslog, CEF), DCR (Data Collection Rules), Content Hub, Solutions | 2h | 2h | — |
|  03  | KQL — Kusto Query Language: operadores fundamentais (where, project, extend, summarize, join, union, bin, arg_max, mv-expand), tabelas principais do Sentinel (SigninLogs, SecurityEvent, AuditLogs, OfficeActivity), ASIM (Advanced Security Information Model), biblioteca de queries operacionais | 3h | 3h | 1h |
|  04  | Detection Engineering: tipos de regras (Scheduled, NRT, Fusion, Anomaly, TI Map), entity mapping, alert grouping, MITRE ATT&CK tagging, Watchlists, Threat Intelligence (TAXII/STIX), tuning de falsos positivos | 2h | 2h | 1h |
|  05  | SOAR com Logic Apps: playbooks triggered by incident vs alert, automation rules, connectors (ServiceNow, Jira, Microsoft Teams, MDE, Exchange Online), fluxos condicionais, loops, actions de resposta (isolamento de host, reset de senha, bloqueio de IP) | 2h | 2h | 1h |
|  06  | Microsoft Defender XDR: Microsoft Defender for Endpoint (MDE), Microsoft Defender for Identity (MDI), Microsoft Defender for Office 365 (MDO), Microsoft Defender for Cloud Apps (MDA), Advanced Hunting (tabelas DeviceEvents, IdentityLogonEvents, EmailEvents), attack disruption | 2h | 2h | 1h |
|  07  | Microsoft Defender for Cloud: CSPM (Cloud Security Posture Management), CWPP (Cloud Workload Protection), Secure Score, recomendações de hardening, mapa de conformidade LGPD/BACEN/CIS, proteção multi-cloud AWS e GCP com Arc | 2h | 2h | 1h |
|  08  | Microsoft Entra ID Protection: políticas de risco de usuário e sign-in, Conditional Access (CA) baseado em risco, Privileged Identity Management (PIM), Access Reviews, SSPR, Entra ID Governance | 1h | 1h | —   |
|  09  | Threat Hunting Proativo: metodologia hipótese → investigação → conclusão, mapeamento de hipóteses ao MITRE ATT&CK, Microsoft Sentinel Notebooks (Jupyter), bookmarks, hunting queries, relatório de hunting | 1h | 1h | 1h  |
|  10  | Capstone — SOC Simulation: ataque completo phishing → credential theft → lateral movement → data exfiltration no Banco Meridian; detecção, triagem, investigação e resposta com todo o ecossistema Microsoft | — | 1h | 1h  |
|      | **TOTAL (40h)**                                                                                                                                                | **16h** | **18h** | **8h** |

> Nota: 2h do Módulo 00 (ambiente) estão incluídas nas 16h de laboratório; o total real de horas de laboratório em módulos numerados é 16h.

---

## Laboratórios Hands-On

| Lab  | Título                                              | Módulo | Duração | Tipo           | Ferramentas                                 |
|:----:|:----------------------------------------------------|:------:|:-------:|:---------------|:--------------------------------------------|
| 01   | Deploy do Microsoft Sentinel com Infraestrutura como Código | 02 | 2h | Guiado | ARM, Bicep, Azure CLI, Log Analytics        |
| 02   | KQL: Investigando Anomalias de Login no Banco Meridian | 03  | 2h | Guiado + Desafio | KQL, Sentinel Logs, SigninLogs, ASIM     |
| 03   | Detection Engineering: Detectando Password Spray com Regras Analíticas | 04 | 2h | Guiado | Sentinel Analytics Rules, MITRE ATT&CK T1110.003 |
| 04   | Playbook SOAR: Resposta Automatizada a Phishing | 05   | 2h | Guiado | Logic Apps, MDE, Exchange Online, Teams     |
| 05   | Defender XDR: Investigando Lateral Movement | 06      | 2h | Desafio | MDE, MDI, Advanced Hunting, Attack Story    |
| 06   | Defender for Cloud: Postura CSPM e Conformidade BACEN | 07 | 2h | Guiado | Defender for Cloud, Regulatory Compliance, Secure Score |
| Capstone | Kill Chain Completa: Operação Meridian Shield | 10  | 2h lab + 2h live | Desafio Avançado | Todo o ecossistema Microsoft |

---

## Ferramentas e Tecnologias

| Categoria              | Ferramenta / Serviço                                                                 |
|:-----------------------|:-------------------------------------------------------------------------------------|
| **SIEM/SOAR**          | Microsoft Sentinel, Log Analytics Workspace, Logic Apps                              |
| **XDR**                | Microsoft Defender for Endpoint (MDE), Microsoft Defender for Identity (MDI), Microsoft Defender for Office 365 (MDO), Microsoft Defender for Cloud Apps (MDA) |
| **CSPM/CWPP**          | Microsoft Defender for Cloud, Azure Security Center (legado)                         |
| **Identidade**         | Microsoft Entra ID (Azure AD), Entra ID Protection, PIM, Conditional Access          |
| **Conformidade**       | Microsoft Purview, Compliance Manager                                                |
| **Linguagem de Consulta** | KQL (Kusto Query Language), ASIM                                                  |
| **IaC**                | Azure Resource Manager (ARM), Bicep, Terraform (básico)                             |
| **CLI e Automação**    | Azure CLI, Azure PowerShell, Microsoft Graph API                                     |
| **Integração**         | ServiceNow, Jira Software, Microsoft Teams, Azure DevOps                            |
| **Frameworks**         | MITRE ATT&CK, Zero Trust, MCRA, CIS Benchmark for Azure, NIST CSF                  |

---

## Avaliação

| Componente                         | Peso  | Descrição                                                                         |
|:-----------------------------------|:-----:|:----------------------------------------------------------------------------------|
| Quizzes de módulo                  | 10%   | Questões de fixação ao final de cada módulo (avaliação formativa)                 |
| Laboratórios (entregáveis)         | 20%   | Relatório de lab + scripts submetidos ao repositório                              |
| Avaliação Final — Múltipla Escolha | 56%   | 40 questões cobrindo todos os módulos (80% da prova)                              |
| Avaliação Final — Estudo de Caso   | 14%   | Cenário inédito: análise e proposta de solução (20% da prova)                     |
| **Critério de Aprovação**          | **70%** | Nota mínima de 70% no aproveitamento global                                    |

---

## Sessões Live Online

| Sessão | Módulo(s) | Tema                                                                           | Duração |
|:------:|:---------:|:-------------------------------------------------------------------------------|:-------:|
| Live 1 | 01        | Arquitetura Zero Trust e posicionamento do Sentinel no SOC moderno             | 2h      |
| Live 2 | 03 + 04   | KQL avançado ao vivo + Detection Engineering: construindo regras juntos        | 2h      |
| Live 3 | 05 + 06   | Playbooks Logic Apps ao vivo + Defender XDR: investigação de caso real         | 2h      |
| Live 4 | 09 + 10   | Threat Hunting com notebooks Jupyter + Capstone SOC Simulation final           | 2h      |

---

## Cenário do Curso — Banco Meridian

O **Banco Meridian** é uma instituição financeira brasileira de médio porte (fictícia), com sede em São Paulo, 3.200 funcionários e presença em 12 estados. O banco opera infraestrutura híbrida:

- **Microsoft 365 E5** para produtividade (Exchange Online, SharePoint, Teams)
- **Azure** como principal plataforma de nuvem (VMs, AKS, Key Vault, Storage)
- **Workloads AWS** para backup e recuperação de desastres (conta secundária)
- **Active Directory** on-premises sincronizado com Entra ID via Azure AD Connect
- **SOC interno** com 8 analistas (4 L1, 3 L2, 1 L3) e um CISO reportando ao Board

**Usuários fictícios de teste utilizados nos laboratórios:**

| Nome                   | Cargo                        | Usuário UPN                              | Departamento          |
|:-----------------------|:-----------------------------|:-----------------------------------------|:----------------------|
| Ana Beatriz Costa      | Analista de SOC L2           | ana.costa@bancomeridian.com.br           | Segurança da Informação |
| Carlos Eduardo Matos   | Engenheiro de Plataforma Azure | carlos.matos@bancomeridian.com.br      | Cloud e Infraestrutura  |
| Fernanda Lima          | Gerente de Operações         | fernanda.lima@bancomeridian.com.br       | Operações Bancárias   |
| Roberto Alves          | Analista Financeiro          | roberto.alves@bancomeridian.com.br       | Contabilidade         |
| Diego Nunes            | Administrador de Sistemas    | diego.nunes@bancomeridian.com.br         | TI Corporativa        |

**Desafios de segurança do Banco Meridian abordados no curso:**

1. **Phishing direcionado** (spear phishing) contra executivos — simulado no Lab 04 e Capstone
2. **Credential stuffing** em contas de funcionários remotos — simulado no Lab 02 e 03
3. **Lateral movement** após comprometimento de estação de trabalho — simulado no Lab 05
4. **Exfiltração de dados de clientes** via cloud storage — simulado no Capstone
5. **Configurações incorretas** em recursos Azure expostos — simulado no Lab 06
6. **Acesso privilegiado indevido** via PIM bypass — simulado no Módulo 08

---

## Alinhamento MITRE ATT&CK

Os laboratórios e detecções do curso cobrem as seguintes técnicas e sub-técnicas do MITRE ATT&CK:

| Tática                     | Técnica / Sub-técnica                               | Lab / Módulo |
|:---------------------------|:----------------------------------------------------|:-------------|
| Initial Access             | T1566.001 — Spear Phishing com Attachment           | Lab 04, Capstone |
| Credential Access          | T1110.003 — Password Spraying                       | Lab 03       |
| Credential Access          | T1078 — Valid Accounts                              | Lab 02, Capstone |
| Lateral Movement           | T1021.006 — WinRM                                  | Lab 05       |
| Lateral Movement           | T1550.002 — Pass the Hash                          | Lab 05       |
| Defense Evasion            | T1078.004 — Cloud Accounts                         | Mod 07       |
| Exfiltration               | T1567.002 — Exfil to Cloud Storage                 | Capstone     |
| Persistence                | T1098.003 — Add Cloud Account Credentials          | Mod 08       |
| Privilege Escalation       | T1134.001 — Token Impersonation/Theft               | Mod 06       |
| Discovery                  | T1087.004 — Cloud Account Discovery                | Mod 03, 06   |

---

## Referências e Leituras Recomendadas

| Tipo         | Título / Recurso                                                                              | Onde acessar                          |
|:-------------|:----------------------------------------------------------------------------------------------|:--------------------------------------|
| Documentação | Microsoft Sentinel Documentation                                                              | learn.microsoft.com/azure/sentinel    |
| Documentação | Microsoft Defender XDR Documentation                                                          | learn.microsoft.com/microsoft-365/security |
| Certificação | SC-200 Study Guide — Microsoft Learning Path                                                  | learn.microsoft.com/certifications/sc-200 |
| Livro        | "Microsoft Sentinel in Action" — Richard Diver & Yuri Diogenes                               | Microsoft Press / Amazon              |
| Livro        | "Cybersecurity — Attack and Defense Strategies" — Yuri Diogenes & Erdal Ozkaya              | Packt Publishing                      |
| Blog         | Microsoft Security Blog                                                                       | microsoft.com/security/blog           |
| Blog         | Kevin Beaumont — GoodMorningCyberWar                                                          | doublepulsar.com                      |
| Relatório    | Microsoft Digital Defense Report (MDDR) — anual                                               | microsoft.com/security/business/mddr  |
| Framework    | Microsoft Cybersecurity Reference Architectures (MCRA)                                        | aka.ms/mcra                           |
| KQL          | KQL Quick Reference Card                                                                      | learn.microsoft.com/azure/data-explorer/kql-quick-reference |
| GitHub       | Sentinel Community — repositório oficial de queries e playbooks                               | github.com/Azure/Azure-Sentinel       |
