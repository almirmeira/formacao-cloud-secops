# Curso 1 — Google SecOps Essentials

**Programa de Formação Security Operations em Nuvem · CECyber**

[![CH Total](https://img.shields.io/badge/Carga%20Horária-30h-blue)](#informações-gerais)
[![Vídeo](https://img.shields.io/badge/Videoaulas-12h-orange)](#modelo-pedagógico)
[![Lab](https://img.shields.io/badge/Laboratórios-12h-green)](#laboratórios-hands-on)
[![Live](https://img.shields.io/badge/Live%20Online-6h-purple)](#sessões-live-online)
[![Certificação](https://img.shields.io/badge/Certificação-Google%20Cloud%20Security%20Eng.-lightblue)](#certificação-alinhada)
[![Nível](https://img.shields.io/badge/Nível-Intermediário-yellow)](#informações-gerais)

---

## Descrição

Formação prática na plataforma **Google Security Operations** (Google SecOps — antigo Chronicle + Siemplify), cobrindo SIEM, SOAR, UEBA e Threat Intelligence Mandiant. O curso prepara profissionais para **ingerir telemetria em escala**, escrever detecções com YARA-L 2.0, conduzir threat hunting sobre o Unified Data Model (UDM) e orquestrar respostas automatizadas via playbooks SOAR.

O curso é construído em torno de um **cenário realista de instituição financeira brasileira** (Banco Meridian — empresa fictícia), com laboratórios que simulam incidentes reais e utilizam dados sintéticos que reproduzem padrões de ataque mapeados ao MITRE ATT&CK.

---

## Informações Gerais

| Campo                       | Detalhes                                                                        |
|:----------------------------|:--------------------------------------------------------------------------------|
| **Carga Horária Total**     | 30 horas                                                                        |
| **Distribuição**            | 12h videoaulas (40%) + 12h laboratórios (40%) + 6h live online (20%)            |
| **Modalidade**              | EAD híbrido (plataforma LMS + sessões ao vivo via Zoom/Teams)                  |
| **Duração Sugerida**        | 5 semanas (ritmo de ~6h/semana)                                                 |
| **Público-Alvo**            | Analistas de SOC, engenheiros de detecção, threat hunters, arquitetos de SIEM, profissionais de TI/Cloud migrando para segurança |
| **Pré-requisitos**          | Fundamentos de logs (Windows, Linux, firewall), noções de redes TCP/IP e MITRE ATT&CK; desejável experiência prévia com qualquer SIEM |
| **Nível**                   | Intermediário                                                                   |
| **Certificação Alinhada**   | Google Cloud Certified — Professional Cloud Security Engineer / Google SecOps Analyst Training |
| **Material Incluso**        | Videoaulas em HD, apostila PDF, scripts e queries, repositório GitHub, acesso a tenant de laboratório, certificado digital |
| **Aprovação**               | 70% de aproveitamento global                                                    |

---

## Objetivos de Aprendizagem

Ao concluir o curso, o participante será capaz de:

1. **Compreender a arquitetura** do Google SecOps e posicioná-la frente a outros SIEMs de mercado (Splunk, Sentinel, QRadar)
2. **Ingerir logs** de múltiplas fontes e normalizá-los para o Unified Data Model (UDM) usando parsers nativos e CBN
3. **Escrever regras de detecção** YARA-L 2.0 mapeadas ao MITRE ATT&CK (single-event e multi-event)
4. **Conduzir threat hunting** proativo utilizando UDM Search, Risk Analytics e UEBA
5. **Construir playbooks SOAR** para casos de uso comuns (phishing, conta comprometida, malware)
6. **Integrar inteligência** Mandiant e VirusTotal às operações de detecção e resposta
7. **Medir performance** operacional usando métricas MTTD e MTTR

---

## Estrutura do Curso

```
curso-01-google-secops/
│
├── README.md                              ← Este arquivo
│
├── modulos/
│   ├── modulo-00-ambiente-laboratorio/    ← INÍCIO AQUI: setup do ambiente
│   ├── modulo-01-fundamentos/             ← Arquitetura Google SecOps (2h vídeo + 1h live)
│   ├── modulo-02-ingestao-udm/           ← Ingestão e UDM (2h vídeo + 2h lab)
│   ├── modulo-03-yara-l-detection/       ← Detection Engineering YARA-L (3h vídeo + 3h lab + 1h live)
│   ├── modulo-04-threat-hunting-ueba/    ← Threat Hunting e UEBA (2h vídeo + 2h lab + 1h live)
│   ├── modulo-05-threat-intelligence/    ← Threat Intelligence integrada (1h vídeo + 1h lab)
│   ├── modulo-06-soar-playbooks/         ← SOAR e Playbooks (2h vídeo + 2h lab + 1h live)
│   └── modulo-07-capstone/               ← Capstone final (2h lab + 2h live)
│
├── laboratorios/
│   ├── lab-01-parser-cbn/                ← Parser CBN customizado (2h)
│   ├── lab-02-yara-l-multi-event/        ← YARA-L multi-event: password spray (3h)
│   ├── lab-03-hunting-c2-beaconing/      ← Hunting de C2 Beaconing (2h)
│   ├── lab-04-playbook-soar-phishing/    ← Playbook SOAR de Phishing (2h)
│   └── lab-05-capstone/                  ← Capstone: kill chain bancária (2h + 2h live)
│
└── avaliacao-final/
    └── README.md                          ← Avaliação final do curso (40 questões + estudo de caso)
```

---

## Ementa Modular Detalhada

| Mód. | Conteúdo Programático                                                              | Vídeo | Lab  | Live |
|:----:|:-----------------------------------------------------------------------------------|:-----:|:----:|:----:|
|  00  | Preparação do Ambiente de Laboratório: tenant Google SecOps, ferramentas, dados sintéticos | —  | 2h  | —   |
|  01  | Fundamentos do Google SecOps: arquitetura da plataforma (SIEM, SOAR, TI), modelo de retenção, pricing ingestion-based, comparação com Splunk, Sentinel e QRadar | 2h | — | 1h |
|  02  | Ingestão e UDM: forwarders, feeds, webhooks, Bindplane. Parsers nativos e CBN (Configuration-Based Normalization). Unified Data Model: estrutura e mapeamento | 2h | 2h | — |
|  03  | YARA-L 2.0 — Detection Engineering: sintaxe, events, match, condition, outcome. Rules single-event vs multi-event, retrohunt vs live rules, tuning e supressão | 3h | 3h | 1h |
|  04  | Threat Hunting e UEBA: UDM Search, pivoting, timeline, context-aware analytics, Risk Analytics. Identificação de comportamentos anômalos | 2h | 2h | 1h |
|  05  | Threat Intelligence integrada: Mandiant Threat Intel, Applied Threat Intelligence, VirusTotal Augment, feeds IOC customizados | 1h | 1h | — |
|  06  | SOAR — Playbooks e Automação: cases, alerts, entities, actions. Playbook designer visual. Casos de uso: phishing, conta comprometida, malware. Métricas MTTD e MTTR | 2h | 2h | 1h |
|  07  | Capstone — Operação Resposta Cibernética: simulação end-to-end no CECyber Play Labs. Cenário APT contra instituição financeira fictícia | — | 2h | 2h |
|      | **TOTAL (30h)**                                                                     | **12h** | **14h** | **6h** |

---

## Laboratórios Hands-On

| Lab  | Nome                               | Duração | Módulo Relacionado | MITRE ATT&CK                |
|:----:|:-----------------------------------|:-------:|:------------------:|:----------------------------|
|  01  | Parser CBN Customizado             |   2h    |        02          | T1059, T1190                |
|  02  | YARA-L Multi-Event: Password Spray |   3h    |        03          | T1110.003 — Credential Stuffing |
|  03  | Hunting de C2 Beaconing            |   2h    |        04          | T1071.001 — Web Protocols   |
|  04  | Playbook SOAR de Phishing          |   2h    |        06          | T1566.001 — Spearphishing   |
|  05  | Capstone — Kill Chain Bancária     |  2h+2h  |        07          | Kill Chain completa — APT   |

### Detalhes dos Laboratórios

**Lab 01 — Parser CBN Customizado (2h)**
Desenvolvimento de parser para log proprietário de sistema de home banking com extração
completa para UDM. O aluno aprende a mapear campos proprietários ao schema UDM e a
testar o parser com logs reais.

**Lab 02 — YARA-L Multi-Event: Password Spray (3h)**
Criação de regra de detecção de password spray (T1110.003) com janela temporal, threshold
configurável e supressão de contas de serviço legítimas.

**Lab 03 — Hunting de C2 Beaconing (2h)**
Identificação de padrões de comunicação periódica (beaconing) via UDM Search e análise
estatística de intervalos de tempo — técnica APT real.

**Lab 04 — Playbook SOAR de Phishing (2h)**
Automação completa: ingestão do report de phishing → extração de IOCs → enriquecimento
via VirusTotal/Mandiant → contenção via EDR → notificação ao usuário.

**Lab 05 — Capstone: Kill Chain Bancária (4h total)**
Kill chain completa sobre logs sintéticos de cenário bancário: initial access → credential
theft → lateral movement → data exfiltration. Entrega de relatório de incidente. Defesa em
sessão live online.

---

## Ferramentas e Tecnologias

```
Google Security Operations (Chronicle SIEM + SOAR)
├── SIEM: Ingestão, UDM, YARA-L, Risk Analytics
├── SOAR: Cases, Playbooks, Actions, Automation
└── TI: Mandiant Threat Intelligence, Applied TI

Integração e Ingestão
├── Bindplane OP Agent
├── Google Cloud Pub/Sub
└── Forwarders, Webhooks, Feeds

Threat Intelligence
├── Mandiant Threat Intelligence
├── VirusTotal Enterprise (Augment)
└── Feeds IOC customizados (STIX/TAXII)

Ferramentas Auxiliares
├── MITRE ATT&CK Navigator
├── CECyber Play Labs (ambiente proprietário)
└── Google Cloud SDK (gcloud CLI)
```

---

## Avaliação

| Componente                              | Peso |
|:----------------------------------------|:----:|
| Quizzes integrados às videoaulas        |  20% |
| Laboratórios guiados e desafios         |  40% |
| Participação em lives e mentorias       |  10% |
| Capstone no CECyber Play Labs           |  30% |

**Aprovação:** 70% de aproveitamento global.

A **avaliação final do curso** é realizada após o Capstone e inclui:
- 40 questões de múltipla escolha (80%) — cobrindo todos os módulos
- Estudo de caso prático (20%) — cenário inédito com rubrica de avaliação

Consulte: [avaliacao-final/README.md](avaliacao-final/README.md)

---

## Sessões Live Online (6h)

| Sessão | Conteúdo                                                    | Duração | Módulo |
|:------:|:------------------------------------------------------------|:-------:|:------:|
|   1    | Abertura + onboarding do ambiente + Fundamentos Google SecOps |  1h30  |   01   |
|   2    | Lab ao vivo: YARA-L 2.0 — escrita e teste de regras         |  1h30  |   03   |
|   3    | Lab ao vivo: Threat Hunting + mentoria de checkpoint         |  1h30  |   04   |
|   4    | Defesa do Capstone + encerramento + perguntas               |  1h30  |   07   |

---

## Cenário do Curso: Banco Meridian (Fictício)

Todos os laboratórios e o capstone são ambientados no **Banco Meridian** — uma instituição
financeira fictícia de médio porte (tier 2), com:
- 2.800 funcionários e 12 filiais em 6 estados brasileiros
- Stack tecnológico: Microsoft 365, Azure AD, sistema de core banking legado, VMware
- Ambiente de nuvem híbrido: workloads em GCP + on-premises
- Time de SOC com 4 analistas (L1, L2) e 1 engenheiro de detecção
- Sujeito à Resolução BACEN 4.893 e às normas CIS/NIST

---

*Próximo passo: [Módulo 00 — Preparação do Ambiente de Laboratório](modulos/modulo-00-ambiente-laboratorio/README.md)*
