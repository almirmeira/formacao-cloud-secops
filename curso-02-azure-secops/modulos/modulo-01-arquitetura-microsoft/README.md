# Módulo 01 — Arquitetura Microsoft Security

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                |
|:-------------------------|:------------------------------------------------------------------------|
| **Carga Horária**        | 2 horas (1h videoaula + 1h live online)                                 |
| **Formato**              | 1 aula gravada + 1 sessão live de revisão e Q&A                         |
| **Pré-requisito**        | Módulo 00 concluído (ambiente configurado)                              |
| **Certificação Alvo**    | SC-200 — Domínio 1: Mitigate threats using Microsoft Sentinel           |
| **Cenário**              | Banco Meridian — apresentação da arquitetura de segurança a ser implantada |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Explicar o modelo de responsabilidade compartilhada Microsoft para IaaS, PaaS e SaaS
2. Descrever os princípios do Zero Trust e como a Microsoft os implementa nos seus produtos
3. Interpretar a Microsoft Cybersecurity Reference Architecture (MCRA) e usá-la no planejamento
4. Posicionar corretamente os produtos Microsoft Security: Sentinel, Defender XDR, Defender for Cloud, Entra ID e Purview
5. Explicar o fluxo de dados de alerta entre os produtos e como eles se integram
6. Comparar o stack Microsoft Security com alternativas do mercado (CrowdStrike+Splunk; Palo Alto+Chronicle)

---

## 1. Modelo de Responsabilidade Compartilhada Microsoft

### 1.1 Conceito Fundamental

A segurança em nuvem é uma **responsabilidade compartilhada** entre o provedor (Microsoft Azure) e o cliente. A divisão varia conforme o modelo de serviço contratado: IaaS, PaaS ou SaaS.

A falha em compreender esse modelo é uma das principais causas de brechas de segurança em nuvem. Quando um cliente assume que a Microsoft cuida de tudo — ou quando a Microsoft assume que o cliente cuida de algo — surgem lacunas de proteção.

### 1.2 Divisão por Modelo de Serviço

| Responsabilidade                    | On-Premises | IaaS (VM Azure) | PaaS (App Service) | SaaS (M365) |
|:------------------------------------|:-----------:|:---------------:|:------------------:|:-----------:|
| Datacenters físicos                 | Cliente     | Microsoft       | Microsoft          | Microsoft   |
| Rede física e hardware              | Cliente     | Microsoft       | Microsoft          | Microsoft   |
| Hypervisor                          | Cliente     | Microsoft       | Microsoft          | Microsoft   |
| Sistema Operacional (host)          | Cliente     | Microsoft       | Microsoft          | Microsoft   |
| Sistema Operacional (guest/VM)      | Cliente     | **Cliente**     | Microsoft          | Microsoft   |
| Middleware e runtime                | Cliente     | **Cliente**     | **Compartilhado**  | Microsoft   |
| Aplicação                           | Cliente     | **Cliente**     | **Cliente**        | Microsoft   |
| Dados e conteúdo                    | Cliente     | **Cliente**     | **Cliente**        | **Cliente** |
| Identidades (contas de usuário)     | Cliente     | **Cliente**     | **Cliente**        | **Cliente** |
| Dispositivos dos usuários finais    | Cliente     | **Cliente**     | **Cliente**        | **Cliente** |
| Rede e gateway (configuração)       | Cliente     | **Cliente**     | **Compartilhado**  | **Cliente** |

**Legenda:** Célula em negrito = responsabilidade total ou majoritária do Cliente.

### 1.3 Implicações Práticas para o Banco Meridian

O Banco Meridian opera em três camadas simultâneas:

- **IaaS**: VMs Azure rodando o sistema legado de core bancário → o banco é responsável por patches do SO, configuração de firewall da VM, hardening do guest OS
- **PaaS**: Azure SQL Database para dados transacionais → Microsoft gerencia o motor do banco; o banco é responsável pelos dados, acessos e criptografia
- **SaaS**: Microsoft 365 E3 para e-mail e colaboração → Microsoft gerencia a plataforma; o banco é responsável por configurar políticas de acesso, DLP, MFA e proteção de identidade

**Consequência direta**: O Microsoft Sentinel não protege automaticamente o banco. O banco precisa conectar as fontes de dados, criar regras de detecção e configurar respostas. A Microsoft fornece a plataforma e inteligência de ameaças; a operação é responsabilidade do cliente.

---

## 2. Zero Trust: Princípios e Implementação Microsoft

### 2.1 O Fim do Modelo de Perímetro

O modelo de segurança tradicional baseado em perímetro ("castle and moat") assumia que tudo dentro da rede corporativa era confiável. Com a adoção de nuvem, trabalho remoto, BYOD e microsserviços distribuídos, esse modelo tornou-se obsoleto.

O ataque à SolarWinds (2020), o comprometimento do Active Directory da Microsoft (2023/Storm-0558) e inúmeros incidentes de lateral movement mostram que atores sofisticados conseguem estabelecer presença interna e se mover sem acionar alertas tradicionais baseados em perímetro.

### 2.2 Os Três Princípios do Zero Trust

**1. Verify Explicitly (Verificar Explicitamente)**

Sempre autentique e autorize com base em todos os pontos de dados disponíveis:
- Identidade do usuário e credenciais
- Localização do usuário (país, IP, rede)
- Conformidade e integridade do dispositivo
- Serviço ou carga de trabalho sendo acessada
- Classificação dos dados
- Anomalias de comportamento (UEBA)

**2. Use Least Privilege (Menor Privilégio)**

Limite o acesso a apenas o necessário para a tarefa, no momento exato em que for necessário:
- Just-In-Time (JIT): acesso concedido apenas durante a janela necessária
- Just-Enough-Access (JEA): permissões exatamente suficientes
- Risk-based adaptive policies: elevação dinâmica de segurança quando o risco aumenta
- Proteção de dados: criptografia, rastreamento e restrição de dados sensíveis

**3. Assume Breach (Assumir Comprometimento)**

Opere como se o attacker já estivesse dentro. Minimize o raio de explosão:
- Segmentação de acesso por rede, usuário, dispositivo e aplicação
- Encriptação de todo o tráfego (even interno)
- Analytics para detecção de comportamento anômalo
- Automação de resposta para conter rapidamente

### 2.3 Microsoft Zero Trust Deployment Guide

A Microsoft publicou o **Zero Trust Deployment Guide** (aka.ms/ZTGuide) com 6 áreas de implantação, ordenadas por prioridade para a maioria das organizações:

| Área                    | Produto(s) Microsoft              | Banco Meridian — ação prioritária                           |
|:------------------------|:----------------------------------|:------------------------------------------------------------|
| **Identidade**          | Entra ID, Entra ID Protection     | MFA obrigatório para todos; Conditional Access baseado em risco |
| **Dispositivos**        | Microsoft Intune, MDE             | Onboarding de endpoints; compliance policy; block non-compliant |
| **Aplicações**          | Microsoft Defender for Cloud Apps | Descoberta de shadow IT; session policies; app governance   |
| **Dados**               | Microsoft Purview, AIP            | Classificação e rotulagem de dados; DLP; CASB               |
| **Infraestrutura**      | Defender for Cloud, Defender for Servers | Secure Score; vulnerability management; CSPM     |
| **Redes**               | Azure Firewall, NSG, Azure VPN    | Micro-segmentação; inspecting east-west traffic             |

### 2.4 Zero Trust Maturity Model (CISA)

O modelo de maturidade CISA Zero Trust define 5 pilares em 3 estágios:

```
ESTÁGIO         │ TRADICIONAL        │ AVANÇADO           │ OTIMIZADO
────────────────┼────────────────────┼────────────────────┼────────────────────
Identidade      │ MFA básico         │ Identity governance │ Continuous validation
Dispositivos    │ MDM básico         │ Compliance checks   │ Real-time remediation
Redes           │ Macro-segmentação  │ Micro-segmentação   │ Encrypted all traffic
Aplicações      │ SSO básico         │ App-level authz     │ Inline CASB + DLP
Dados           │ Encrypt at rest    │ DLP + classification│ Automated labeling
```

---

## 3. Microsoft Cybersecurity Reference Architecture (MCRA)

### 3.1 O que é a MCRA

A **Microsoft Cybersecurity Reference Architecture** (MCRA) é um conjunto de diagramas e guias arquiteturais que mostram as capacidades de segurança da Microsoft e como elas se interconectam. É o mapa definitivo do ecossistema de segurança Microsoft.

A MCRA é mantida pelo time de segurança da Microsoft (aka.ms/MCRA) e atualizada regularmente com novos produtos e integrações.

### 3.2 Estrutura da MCRA

A MCRA é organizada em camadas funcionais:

**Camada 1 — Planos de Controle (Control Planes)**
- Microsoft Entra (identidade e acesso)
- Microsoft Intune (gerenciamento de dispositivos)
- Microsoft Purview (governança de dados)

**Camada 2 — Detecção e Resposta Estendida (XDR + SIEM/SOAR)**
- Microsoft Defender XDR (MDE + MDI + MDO + MDA)
- Microsoft Sentinel (SIEM/SOAR nativo na nuvem)
- Microsoft Defender for Cloud (CSPM/CWPP)

**Camada 3 — Proteção de Infraestrutura**
- Azure Firewall, Azure DDoS Protection
- Azure Front Door, Azure WAF
- Azure Key Vault, HSM
- Microsoft Defender for Cloud (Defender Plans)

**Camada 4 — Inteligência de Ameaças**
- Microsoft Threat Intelligence Center (MSTIC)
- Entra ID Protection (risco baseado em machine learning)
- Fusion (correlação de ataques multi-estágio)

### 3.3 Como Usar a MCRA no Planejamento de Segurança

**Passo 1 — Inventário de capacidades atuais**: Use a MCRA como checklist. Identifique quais capacidades o Banco Meridian já tem (licenças M365 E3 → E5) e quais precisam ser adquiridas.

**Passo 2 — Identificação de lacunas**: Compare o estado atual com o desejado. O banco tem Entra ID P1 (E3), mas precisa de P2 para Entra ID Protection e PIM.

**Passo 3 — Sequenciamento de implantação**: Use a MCRA para definir ordem. Identidade primeiro (Entra ID), depois dispositivos (MDE), depois SIEM (Sentinel), depois automação (Logic Apps).

**Passo 4 — Validação de cobertura de ameaças**: Mapear TTPs do MITRE ATT&CK às capacidades de detecção disponíveis no stack escolhido.

---

## 4. Posicionamento dos Produtos Microsoft Security

### 4.1 Mapa de Produtos

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     MICROSOFT SECURITY ECOSYSTEM                                 │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    MICROSOFT SENTINEL (SIEM/SOAR)                        │    │
│  │         Correlação · Analytics Rules · Hunting · Playbooks              │    │
│  └──────────┬──────────────┬─────────────────┬───────────────┬─────────────┘    │
│             │              │                  │               │                   │
│  ┌──────────▼──┐  ┌────────▼──────┐  ┌───────▼─────┐  ┌─────▼──────────┐       │
│  │ DEFENDER    │  │ DEFENDER      │  │ DEFENDER    │  │ DEFENDER FOR   │       │
│  │ FOR         │  │ FOR           │  │ FOR CLOUD   │  │ CLOUD APPS     │       │
│  │ ENDPOINT    │  │ IDENTITY      │  │ APPS (MDA)  │  │ (CSPM/CWPP)    │       │
│  │ (MDE)       │  │ (MDI)         │  │             │  │                │       │
│  └─────────────┘  └───────────────┘  └─────────────┘  └────────────────┘       │
│                                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                    MICROSOFT DEFENDER XDR                                 │   │
│  │              (Portal unificado de investigação e resposta)                │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                   │
│  ┌─────────────┐  ┌─────────────────────────┐  ┌──────────────────────────┐    │
│  │ ENTRA ID    │  │ MICROSOFT PURVIEW        │  │  MICROSOFT INTUNE        │    │
│  │ (IAM/IdP)   │  │ (Compliance/DLP/Purview) │  │  (MDM/MAM)               │    │
│  └─────────────┘  └─────────────────────────┘  └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Microsoft Sentinel — SIEM/SOAR Nativo na Nuvem

**O que é**: Plataforma de SIEM (Security Information and Event Management) e SOAR (Security Orchestration, Automation and Response) construída nativamente no Azure.

**Casos de uso principais**:
- Ingestão e correlação de eventos de segurança de múltiplas fontes
- Detecção de ameaças com regras analíticas (KQL + ML)
- Investigação de incidentes (timeline, entities, graph)
- Automatização de respostas (Logic Apps/playbooks)
- Threat hunting proativo
- Compliance reporting

**Diferencial**: É escalável, sem infraestrutura para gerenciar (serverless), e integra nativamente com todo o stack Microsoft. A precificação é baseada em volume de dados ingeridos (GB/dia).

**No Banco Meridian**: Hub central do SOC. Recebe alertas de Defender XDR, Defender for Cloud, Entra ID, Azure Activity, M365 e fontes externas (AWS CloudTrail, syslog de firewalls Fortinet).

### 4.3 Microsoft Defender XDR — Telemetria Cross-Domain

**O que é**: Plataforma unificada de detecção e resposta que correlaciona sinais de 4 produtos Defender em um único painel de investigação.

**Componentes**:

| Produto                                   | Sigla | O que protege                                     |
|:------------------------------------------|:-----:|:--------------------------------------------------|
| Microsoft Defender for Endpoint            | MDE   | Endpoints Windows, macOS, Linux, iOS, Android     |
| Microsoft Defender for Identity            | MDI   | Active Directory on-premises e Entra ID           |
| Microsoft Defender for Office 365          | MDO   | Exchange Online, SharePoint, Teams, OneDrive      |
| Microsoft Defender for Cloud Apps          | MDA   | Aplicações SaaS (shadow IT, session control)      |

**Diferencial**: O XDR correlaciona um ataque que começa por phishing (MDO), usa uma identidade comprometida (MDI), move-se lateralmente via endpoint (MDE) e exfiltra dados via SaaS (MDA) — tudo num único incidente.

### 4.4 Microsoft Defender for Cloud — CSPM e CWPP

**O que é**: Plataforma de Cloud Security Posture Management (CSPM) e Cloud Workload Protection Platform (CWPP).

- **CSPM**: Avalia continuamente a postura de segurança da infraestrutura Azure/AWS/GCP. Gera um **Secure Score** e recomendações priorizadas por impacto.
- **CWPP**: Protege cargas de trabalho específicas (servidores, containers, SQL, storage, Key Vault) com planos Defender dedicados.

**Diferencial**: Cobertura multi-cloud nativa (Azure + AWS + GCP) e integração com Sentinel para exportação contínua de findings.

### 4.5 Microsoft Entra ID — IAM Centralizado

**O que é**: Serviço de Identidade e Gerenciamento de Acesso (IAM) da Microsoft. Sucessor do Azure Active Directory.

**Capacidades relevantes para segurança**:
- MFA e Conditional Access (políticas baseadas em risco, localização, dispositivo)
- Entra ID Protection: detecção de sign-ins suspeitos com machine learning
- Privileged Identity Management (PIM): JIT access para funções privilegiadas
- Access Reviews: auditoria periódica de permissões
- External Identities: gestão de parceiros e clientes (B2B/B2C)

**No Banco Meridian**: Toda autenticação de funcionários, aplicações e parceiros passa pelo Entra ID. É a fonte primária de log de identidade no Sentinel (tabela `SigninLogs` e `AuditLogs`).

### 4.6 Microsoft Purview — Compliance e DLP

**O que é**: Plataforma unificada de governança, risco e compliance. Cobre:
- Information Protection: classificação e rotulagem de dados (labels de sensibilidade)
- Data Loss Prevention (DLP): políticas para prevenir vazamento de dados
- Compliance Manager: avaliações de compliance automatizadas (LGPD, BACEN, ISO 27001, PCI DSS)
- Insider Risk Management: detecção de ameaças internas baseada em comportamento
- eDiscovery e Auditoria: investigações legais e registros de atividade

**No contexto BACEN 4.893**: O Purview é a ferramenta central para comprovar conformidade regulatória, pois gera relatórios de compliance e mantém logs de acesso a dados sensíveis.

---

## 5. Como os Produtos se Integram: Fluxo de Dados

### 5.1 Diagrama de Fluxo de Dados

```
FONTES DE TELEMETRIA
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                                │
│  [Entra ID]  [MDE]  [MDI]  [MDO]  [MDA]  [Azure Activity]  [Firewall Logs]  │
│       │         │      │      │      │           │                  │          │
└───────┼─────────┼──────┼──────┼──────┼───────────┼──────────────────┼─────────┘
        │         │      │      │      │           │                  │
        ▼         ▼      ▼      ▼      ▼           ▼                  ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                  MICROSOFT DEFENDER XDR PORTAL                               │
│          (Correlação cross-domain · Incident Unification)                    │
│                                                                                │
│  Alert A (MDO: phishing) + Alert B (Entra ID: suspicious login)              │
│  + Alert C (MDE: credential dump) → INCIDENT: "BEC Campaign"                │
└─────────────────────────────┬────────────────────────────────────────────────┘
                               │ Conector Defender XDR
                               ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MICROSOFT SENTINEL (SIEM/SOAR)                            │
│                                                                                │
│  1. Ingestão → Log Analytics Workspace                                       │
│  2. Analytics Rules → correlação adicional com outros logs                   │
│  3. Incident criado (ou enriquecido) com entities (User, Host, IP)           │
│  4. Automation Rule dispara → Playbook (Logic App)                           │
│  5. Playbook executa: revoga sessão → notifica Teams → abre ticket            │
│  6. Case fechado com timeline e evidências                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Fluxo Detalhado: Do Alerta ao Case Fechado

**Passo 1 — Geração do Alerta (fonte)**
Um alert é gerado por qualquer produto conectado. Exemplo: MDE detecta execução de mimikatz em estação de trabalho do analista `rafael.torres`.

**Passo 2 — Correlação XDR**
O Defender XDR verifica se há outros alertas relacionados na mesma janela de tempo para as mesmas entidades. Encontra: login suspeito do mesmo usuário no Entra ID + e-mail de phishing no MDO que originou a infecção. Agrupa num único **Incidente**.

**Passo 3 — Ingestão no Sentinel**
O conector `Microsoft Defender XDR` no Sentinel sincroniza automaticamente os incidentes e os alertas individuais. O Sentinel cria ou atualiza o Incident com as entidades mapeadas.

**Passo 4 — Analytics Rules Adicionais**
O Sentinel pode disparar suas próprias regras sobre os dados brutos ingeridos. Uma regra KQL detecta que o mesmo endpoint fez DNS lookup para domínio na watchlist de C2. Novo alerta adicionado ao mesmo incidente.

**Passo 5 — SOAR: Automation Rule**
Uma Automation Rule detecta que o incidente tem severidade `High` e entidade `Account` → dispara playbook `Conta-Comprometida-Resposta`.

**Passo 6 — Playbook Logic App executa**
- Revoga sessões ativas via Microsoft Graph API
- Adiciona usuário ao grupo `SOC-Quarantine`
- Envia mensagem no canal `#alertas-soc` no Teams
- Cria ticket no ServiceNow com todos os detalhes
- Adiciona tag `SOAR-Responded` ao incidente no Sentinel

**Passo 7 — Investigação e Closure**
Analista SOC revisa o incidente no Sentinel, valida as ações do playbook, executa hunting queries adicionais, documenta descobertas e fecha o incidente como `True Positive — Resolved`.

---

## 6. Comparativo: Microsoft Security vs Concorrentes

### 6.1 Microsoft vs CrowdStrike + Splunk

| Dimensão                        | Microsoft (Sentinel + Defender)       | CrowdStrike Falcon + Splunk             |
|:--------------------------------|:--------------------------------------|:----------------------------------------|
| **SIEM**                        | Microsoft Sentinel (nativo Azure)     | Splunk Enterprise/Cloud                 |
| **EDR/XDR**                     | Defender for Endpoint + XDR           | CrowdStrike Falcon Insight XDR          |
| **Proteção de Identidade**      | Entra ID Protection + MDI             | CrowdStrike Falcon Identity Protection  |
| **Proteção de E-mail**          | Defender for Office 365               | Requer integração externa (Proofpoint)  |
| **CSPM**                        | Defender for Cloud                    | CrowdStrike CNAPP (Horizon)             |
| **Threat Intelligence**         | MSTIC integrado nativamente           | CrowdStrike Intel + Splunk ThreatStream |
| **Linguagem de Query**          | KQL (nativo Sentinel)                 | SPL (Splunk Processing Language)        |
| **Integração Microsoft 365**    | Nativa e profunda                     | Requer conectores/APIs                  |
| **Custo base (médio mercado)**  | Consumo por GB ingerido               | Licença por endpoint + GB ingerido      |
| **Curva de aprendizado**        | KQL e portal Azure                    | SPL complexo + gestão de infraestrutura |
| **Ponto forte**                 | Integração total com ecossistema MS   | EDR de classe mundial, detecção leve    |
| **Ponto fraco**                 | Custo pode escalar com volume alto    | Silos entre SIEM e EDR; SPL complexo    |

### 6.2 Microsoft vs Palo Alto + Chronicle

| Dimensão                        | Microsoft (Sentinel + Defender)       | Palo Alto (Cortex) + Google Chronicle  |
|:--------------------------------|:--------------------------------------|:----------------------------------------|
| **SIEM**                        | Microsoft Sentinel                    | Google Chronicle SIEM                   |
| **XDR**                         | Defender XDR                          | Cortex XDR                              |
| **SOAR**                        | Logic Apps (Sentinel)                 | XSOAR (Cortex)                          |
| **Firewall NGFW**               | Azure Firewall (básico)               | PAN-OS (classe mundial)                 |
| **Zero Trust Network**          | Azure AD App Proxy + Entra            | Prisma Access (SASE)                    |
| **Threat Intelligence**         | MSTIC                                 | Unit 42 (Palo Alto)                     |
| **Custo**                       | Pay-per-GB ingestão                   | Flat rate (Chronicle) + Cortex licença  |
| **Ponto forte**                 | Integração Microsoft; um único vendor | NGFW líder; Chronicle escala infinita   |
| **Ponto fraco**                 | NGFW nativo limitado                  | Silos entre Chronicle e Cortex XDR     |

### 6.3 Por que o Banco Meridian Escolheu Microsoft

O Banco Meridian já opera Microsoft 365 E3 para 2.800 funcionários. A migração para E5 Security adiciona:
- Defender XDR completo (MDE P2 + MDI + MDO P2 + MDA)
- Entra ID P2 (Entra ID Protection + PIM)
- Purview Compliance

O custo incremental para ir de E3 para E5 Security (ou E5 completo) é significativamente menor que a aquisição de um stack alternativo, considerando que toda a infraestrutura Microsoft já está implantada. Além disso, a integração nativa elimina a necessidade de construir pipelines de ingestão complexos para as 2.800 contas de usuário que já geram logs no Entra ID.

---

## 7. Diagrama ASCII da Arquitetura Microsoft Security Integrada

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║              BANCO MERIDIAN — ARQUITETURA MICROSOFT SECURITY                    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║   FONTES DE DADOS                    COLETA                    ANÁLISE           ║
║   ─────────────────                  ───────                   ───────           ║
║                                                                                  ║
║   ┌─────────────┐                                                                ║
║   │ M365 E5     │──── SigninLogs ───────────────────────────────────────────┐   ║
║   │ Entra ID    │──── AuditLogs ────────────────────────────────────────┐   │   ║
║   └─────────────┘                                                        │   │   ║
║                                                                           │   │   ║
║   ┌─────────────┐                                                         │   │   ║
║   │ MDE         │──── DeviceEvents ────────────────────────────────────┐  │   │   ║
║   │ 2800 endpts │──── DeviceNetworkEvents ──────────────────────────┐  │  │   │   ║
║   └─────────────┘                                                    │  │  │   │   ║
║                                                                       │  │  │   │   ║
║   ┌─────────────┐                                                     │  │  │   │   ║
║   │ MDO         │──── EmailEvents ─────────────────────────────────┐  │  │  │   │   ║
║   │ Exchange    │──── UrlClickEvents ──────────────────────────┐   │  │  │  │   │   ║
║   └─────────────┘                                               │   │  │  │  │   │   ║
║                                                                  │   │  │  │  │   │   ║
║   ┌─────────────┐                                                │   │  │  │  │   │   ║
║   │ Azure       │──── AzureActivity ──────────────────────────┐ │   │  │  │  │   │   ║
║   │ Subscriptn  │──── SecurityAlert ────────────────────────┐ │ │   │  │  │  │   │   ║
║   └─────────────┘                                            │ │ │   │  │  │  │   │   ║
║                                                               │ │ │   │  │  │  │   │   ║
║   ┌─────────────┐   Log Analytics  ┌────────────────────┐    │ │ │   │  │  │  │   │   ║
║   │ Fortinet FW │──── CEF/Syslog ─►│   WORKSPACE        │◄───┘ │ │   │  │  │  │   │   ║
║   │ (legado)    │                  │   LOG ANALYTICS    │◄─────┘ │   │  │  │  │   │   ║
║   └─────────────┘                  │                    │◄───────┘   │  │  │  │   │   ║
║                                    │   meridian-secops  │◄───────────┘  │  │  │   │   ║
║   ┌─────────────┐                  │   (East US)        │◄──────────────┘  │  │   │   ║
║   │ AWS         │──── CloudTrail ─►│                    │◄─────────────────┘  │   │   ║
║   │ (analytics) │                  │                    │◄────────────────────┘   │   ║
║   └─────────────┘                  └────────────┬───────┘◄────────────────────────┘   ║
║                                                  │                                      ║
║                                                  ▼                                      ║
║                                   ┌─────────────────────────┐                          ║
║                                   │   MICROSOFT SENTINEL     │                          ║
║                                   │                          │                          ║
║                                   │  Analytics Rules (KQL)   │                          ║
║                                   │  Incidents + Entities    │                          ║
║                                   │  Hunting Queries         │                          ║
║                                   │  Workbooks (Dashboards)  │                          ║
║                                   └────────────┬────────────┘                          ║
║                                                 │                                       ║
║                               ┌─────────────────┼──────────────────┐                  ║
║                               ▼                  ▼                  ▼                  ║
║                    ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐       ║
║                    │ AUTOMATION RULES │  │  WORKBOOKS   │  │  THREAT HUNTING  │       ║
║                    │ + PLAYBOOKS      │  │  (Reporting) │  │  (Notebooks)     │       ║
║                    │ (Logic Apps)     │  └──────────────┘  └──────────────────┘       ║
║                    └──────────┬───────┘                                                ║
║                               │                                                        ║
║              ┌────────────────┼────────────────────────────┐                          ║
║              ▼                ▼                             ▼                          ║
║   ┌──────────────────┐  ┌─────────────────┐  ┌────────────────────────┐              ║
║   │ REVOKE SESSION   │  │ NOTIFY TEAMS    │  │ OPEN TICKET            │              ║
║   │ BLOCK USER       │  │ SEND EMAIL      │  │ SERVICENOW / JIRA      │              ║
║   │ ISOLATE ENDPOINT │  │ PAGE ON-CALL    │  │ DOCUTAR EVIDÊNCIAS     │              ║
║   └──────────────────┘  └─────────────────┘  └────────────────────────┘              ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Atividades de Fixação

### Questão 1
Qual é a principal diferença entre a responsabilidade de segurança do cliente num modelo IaaS versus SaaS no Azure?

a) No IaaS, o cliente gerencia apenas os dados; no SaaS, o cliente gerencia o sistema operacional  
b) No IaaS, o cliente é responsável pelo SO guest, middleware e aplicação; no SaaS, o cliente é responsável apenas pelos dados, identidades e dispositivos  
c) No IaaS, a Microsoft gerencia tudo; no SaaS, o cliente gerencia tudo  
d) Não há diferença prática entre IaaS e SaaS em termos de responsabilidade de segurança  

**Gabarito: B**
Justificativa: No modelo IaaS (como uma VM Azure), o cliente assume responsabilidade pelo sistema operacional convidado (patching, configuração, hardening), pelo middleware instalado, pela aplicação e pelos dados. A Microsoft gerencia o hardware físico, a rede física e o hypervisor. No SaaS (como Microsoft 365), a Microsoft gerencia toda a plataforma; o cliente responde apenas pelos dados que coloca na plataforma, pelas identidades que acessa a plataforma e pelos dispositivos usados para acessar.

---

### Questão 2
O princípio Zero Trust "Assume Breach" implica que uma organização deve:

a) Assumir que todos os fornecedores de nuvem já sofreram breach e evitar usar qualquer nuvem  
b) Instalar antivírus em todos os endpoints e considerar que isso é suficiente  
c) Operar como se um attacker já tivesse acesso interno, implementando micro-segmentação, encriptação de tráfego interno e analytics comportamental  
d) Revogar todos os acessos remotos e exigir que funcionários trabalhem apenas no escritório  

**Gabarito: C**
Justificativa: "Assume Breach" significa projetar controles de segurança partindo da premissa que o attacker já está dentro. Isso implica: (1) minimizar o raio de explosão com micro-segmentação; (2) encriptar todo tráfego, inclusive interno (não confiar na rede interna); (3) usar analytics para detectar movimento lateral; (4) automatizar resposta para conter rapidamente. Não significa abandonar a nuvem nem proibir acesso remoto.

---

### Questão 3
O Banco Meridian precisa detectar ataques de lateral movement usando Active Directory (Kerberoasting, Golden Ticket). Qual produto Microsoft é o mais adequado?

a) Microsoft Defender for Endpoint (MDE)  
b) Microsoft Defender for Office 365 (MDO)  
c) Microsoft Defender for Identity (MDI)  
d) Microsoft Defender for Cloud Apps (MDA)  

**Gabarito: C**
Justificativa: O MDI é o produto especializado em proteção de identidade para Active Directory on-premises e Entra ID. Ele analisa o tráfego Kerberos, NTLM e LDAP para detectar ataques específicos como Kerberoasting (solicitação excessiva de TGS), Golden Ticket (TGT forjado), Pass-the-Hash, lateral movement via DCSync, etc. O MDE protege endpoints; MDO protege e-mail; MDA protege aplicações SaaS.

---

### Questão 4
No fluxo de integração do Microsoft Sentinel com o Defender XDR, qual é a sequência correta?

a) Sentinel detecta o alerta → Defender XDR correlaciona → Logic App responde → Incident fechado  
b) Fonte gera telemetria → Defender XDR correlaciona em incidente → Sentinel ingere via conector → Analytics Rules enriquecem → Automation Rule dispara playbook → Resposta automatizada  
c) Logic App coleta logs → Sentinel processa → Defender XDR responde → Incident criado  
d) Azure Monitor coleta logs → Sentinel filtra → Defender XDR fecha o incidente automaticamente  

**Gabarito: B**
Justificativa: A sequência correta é: (1) A fonte (MDE, MDO, MDI, Entra ID) gera o alerta/telemetria; (2) O Defender XDR correlaciona alertas relacionados em um único Incidente; (3) O Sentinel ingere esse incidente via conector bidirecional Microsoft Defender XDR; (4) Analytics Rules adicionais do Sentinel podem enriquecer o incidente com correlações de outras fontes; (5) Uma Automation Rule detecta o incidente e dispara um Playbook (Logic App); (6) O Logic App executa ações de resposta (revogar sessão, notificar, criar ticket).

---

### Questão 5
Qual é a principal vantagem do Microsoft Defender for Cloud em ambiente multi-cloud no contexto do Banco Meridian?

a) Substitui completamente as ferramentas de segurança nativas da AWS  
b) Fornece uma visão unificada de postura de segurança (CSPM) e proteção de workloads (CWPP) para Azure, AWS e GCP num único painel, com Secure Score consolidado  
c) Migra automaticamente todos os workloads da AWS para o Azure  
d) Permite usar políticas do Azure Resource Policy diretamente em contas AWS  

**Gabarito: B**
Justificativa: O Defender for Cloud é uma plataforma multi-cloud nativa que permite onboarding de contas AWS e projetos GCP sem agente (via conector). Depois do onboarding, fornece: CSPM com avaliação de postura e Secure Score para recursos AWS/GCP/Azure; recomendações de segurança baseadas em CIS, NIST, PCI DSS e BACEN; CWPP com planos Defender para servidores, containers e bancos de dados em qualquer nuvem; export contínuo de findings para o Sentinel. Não substitui as ferramentas AWS, mas adiciona uma camada de visibilidade centralizada.

---

## 9. Roteiro de Gravação

### Aula 1.1 — Arquitetura Microsoft Security (55 minutos)

---

**[PRÉ-PRODUÇÃO — INSTRUÇÕES AO EDITOR]**
- Formato: talking head (instrutor) + slides + screen share do portal Azure
- Resolução: 1920×1080, 30fps
- Introdução com animação do logo CECyber: 5 segundos
- Música de fundo suave apenas nos primeiros 30 segundos e nos últimos 15 segundos
- Corte direto entre seções (sem fade)

---

**[0:00 — ABERTURA | 3 minutos]**

*[Câmera no instrutor, slide de título ao fundo]*

"Olá, pessoal! Bem-vindos ao Módulo 1 do Curso de Microsoft Sentinel e Defender — SecOps no Azure.

Sou [nome do instrutor], e nesta aula vamos construir juntos o mapa mental da arquitetura de segurança Microsoft. Antes de colocar a mão na massa nos laboratórios, precisamos entender como as peças se encaixam.

Ao final desta aula, você vai conseguir responder: Por que o banco precisa do Sentinel se já tem o Defender XDR? Como o Entra ID se conecta ao Sentinel? Qual produto cuida de quê? Essas perguntas parecem simples, mas confundem até profissionais experientes.

Vamos começar pelo fundamento — quem é responsável por quê quando usamos a nuvem Microsoft."

*[DICA DE EDIÇÃO: adicionar lower third com nome do instrutor e título da aula]*

---

**[3:00 — BLOCO 1: RESPONSABILIDADE COMPARTILHADA | 10 minutos]**

*[Transição para slides, instrutor permanece em picture-in-picture no canto inferior direito]*

"Imaginem que vocês alugaram um apartamento. O prédio, a estrutura, a segurança do condomínio — isso é responsabilidade do proprietário. Mas trancar a porta do seu apartamento, guardar seus documentos em lugar seguro, não deixar estranhos entrar — isso é responsabilidade de vocês.

A nuvem funciona assim. E a divisão de responsabilidade muda dependendo do tipo de serviço que você usa.

*[Mostrar tabela de responsabilidade compartilhada]*

No modelo IaaS — como uma máquina virtual Azure — você controla o sistema operacional. Você aplica patches, você configura o firewall da VM, você hardena o servidor. Se você não fizer isso, a Microsoft não fará por você.

No PaaS — como o Azure SQL Database — a Microsoft gerencia o motor do banco de dados, mas os dados dentro são seus. A criptografia dos dados, quem pode acessar, como os acessos são auditados — isso é sua responsabilidade.

No SaaS — como o Microsoft 365 que o Banco Meridian usa com 2.800 funcionários — a Microsoft gerencia a plataforma inteira. Mas quem configurou o MFA para todos esses usuários? Quem definiu as políticas de Conditional Access? Quem está monitorando os logins suspeitos? Vocês. O cliente.

Por isso existe o Microsoft Sentinel. A Microsoft não monitora os logs da sua organização automaticamente. Você precisa ativar o monitoramento, criar as regras de detecção e responder aos incidentes.

*[DICA DE EDIÇÃO: animar a tabela aparecendo linha por linha conforme o instrutor explica]*

Vamos agora falar do framework que une tudo isso."

---

**[13:00 — BLOCO 2: ZERO TRUST | 12 minutos]**

*[Slide: diagrama Zero Trust]*

"Zero Trust. Vocês já ouviram esse termo em todo lugar. Mas o que significa na prática?

O modelo tradicional de segurança era o castelo com fosso. Você criava um perímetro — o firewall, a VPN — e assumia que tudo dentro era seguro. O problema? Quando um attacker passa o fosso, ele tem acesso a tudo. E hoje, com trabalho remoto, SaaS, dispositivos pessoais, o 'perímetro' praticamente desapareceu.

*[Mostrar os três princípios]*

Zero Trust tem três princípios. O primeiro: Verify Explicitly — verifique sempre. Não basta o usuário ter a senha. O Entra ID precisa verificar: qual dispositivo está sendo usado? Está atualizado? É de uma localização normal? O acesso é para um recurso sensível? Todos esses fatores pesam na decisão de conceder acesso.

O segundo: Use Least Privilege — menor privilégio. Dê às pessoas apenas o acesso que elas precisam, pelo tempo que precisam. O PIM — Privileged Identity Management — implementa isso no Azure: um administrador só tem poderes de Global Admin quando solicita, aprova e dentro de uma janela de tempo. Fora isso, tem acesso normal.

O terceiro: Assume Breach — assuma que já foram comprometidos. Este é o mais importante para o SOC. Não projete a segurança assumindo que o attacker está fora. Projete como se ele já estivesse dentro. Isso significa: segmentar a rede para limitar o movimento lateral, encriptar tráfego interno, monitorar comportamento anômalo dentro da rede.

*[DICA DE EDIÇÃO: tela cheia nos slides neste bloco, instrutor volta após os princípios]*

O Microsoft Sentinel implementa o terceiro pilar na prática. Ele assume que algo mal aconteceu e caça evidências."

---

**[25:00 — BLOCO 3: MCRA E PRODUTOS | 15 minutos]**

*[Screen share: abrir PDF da MCRA ou diagrama]*

"Agora vamos ao mapa do ecossistema — a Microsoft Cybersecurity Reference Architecture, ou MCRA.

*[Mostrar o diagrama MCRA]*

Olhem este diagrama. À primeira vista parece intimidador — dezenas de produtos conectados. Mas vou mostrar como ler isso de forma organizada.

Comecem pelo centro: o Microsoft Sentinel. Ele é o hub. Todo sinal de segurança do ecossistema Microsoft chega aqui.

À esquerda: as fontes de identidade. O Entra ID gera logs de autenticação — quem logou, de onde, com qual dispositivo. O MDI monitora o Active Directory on-premises. Todos esses logs alimentam o Sentinel.

Na parte superior: proteção de endpoints e e-mail. O MDE monitora cada endpoint — cada notebook, desktop, servidor. O MDO protege o Exchange Online, SharePoint, Teams. Alertas desses produtos vão para o portal Defender XDR, que os correlaciona, e depois para o Sentinel.

À direita: infraestrutura cloud. O Defender for Cloud monitora o Azure e contas AWS/GCP. Logs do Azure Activity, Azure Policy, Azure Diagnostics chegam ao Sentinel.

Na parte inferior: automação. Quando o Sentinel detecta um incidente, ele pode disparar um Logic App — um playbook — que executa ações automaticamente.

*[Zoom no diagrama em cada área conforme menciona]*

Para o Banco Meridian, o fluxo seria: um funcionário tem a conta comprometida por phishing. O MDO detecta o e-mail malicioso. O Entra ID Protection detecta o login anômalo. O MDE detecta execução maliciosa no endpoint. Os três alertas chegam ao Defender XDR, que os agrupa num único incidente. O Sentinel ingere esse incidente, enriquece com dados adicionais de outras fontes, e dispara um playbook que revoga a sessão do usuário, notifica o SOC no Teams e abre um ticket no ServiceNow.

Tudo isso em menos de 5 minutos. Sem intervenção humana para as ações iniciais de contenção.

*[DICA DE EDIÇÃO: círculos animados destacando cada produto no diagrama conforme mencionado]*"

---

**[40:00 — BLOCO 4: COMPARATIVO E CONTEXTO | 8 minutos]**

*[Slide: tabela comparativa]*

"Vocês vão se deparar com clientes que usam CrowdStrike com Splunk, ou Palo Alto com Chronicle. Vamos entender quando o stack Microsoft faz mais sentido e quando não.

*[Mostrar tabela comparativa]*

O stack Microsoft tem uma vantagem enorme quando a organização já usa Microsoft 365. O Banco Meridian tem 2.800 contas Entra ID. Cada login já gera um log. Cada e-mail processado já gera telemetria no MDO. A questão não é se vai gerar dados — é se vai analisá-los.

Para organizações Microsoft-first, como a maioria dos bancos e seguradoras brasileiras, o stack Microsoft tem o menor custo de integração. Você já pagou pelo M365; adicionar E5 Security adiciona Defender XDR e Purview. O Sentinel é cobrado separadamente por volume de dados ingeridos.

O CrowdStrike Falcon tem um EDR genuinamente excelente — muitos consideram o melhor do mercado para detecção de endpoint. Mas se você já tem MDE P2 incluído no M365 E5, comprar CrowdStrike adiciona custo sem benefício proporcional para a maioria dos cenários.

O Splunk tem uma query language — SPL — extremamente poderosa e uma comunidade enorme. Mas o KQL do Sentinel é mais simples de aprender e os logs da Microsoft já chegam formatados. Para uma equipe iniciando SOC, o Sentinel tem curva de aprendizado mais suave.

Chronicle da Google tem uma proposta interessante de custo flat rate — você paga um valor fixo independente do volume de dados. Para organizações com volume muito alto, pode fazer sentido. Mas para o Banco Meridian, com um volume moderado e stack Microsoft, o Sentinel é a escolha natural.

*[DICA DE EDIÇÃO: animar a tabela comparativa aparecendo por colunas]*"

---

**[48:00 — RECAPITULAÇÃO E CHAMADA PARA O PRÓXIMO MÓDULO | 5 minutos]**

*[Instrutor em tela cheia, slides ao fundo]*

"Vamos recapitular o que vimos hoje.

Primeiro: a responsabilidade compartilhada. Mesmo usando o Microsoft 365, o Banco Meridian é responsável por configurar MFA, políticas de acesso e monitorar os logs. A Microsoft cuida da plataforma; a operação de segurança é responsabilidade de vocês.

Segundo: os três pilares Zero Trust — verificar explicitamente, menor privilégio e assumir comprometimento. Esse framework guia todas as decisões que tomaremos no curso.

Terceiro: os produtos. Sentinel é o hub de SIEM/SOAR. Defender XDR correlaciona sinais de MDE, MDI, MDO e MDA. Defender for Cloud cuida da postura de segurança da infraestrutura. Entra ID é a base de identidade. Purview cuida de compliance e DLP.

Quarto: a integração. Esses produtos não existem em silos — eles são projetados para se comunicar. Um ataque que começa por phishing no e-mail culmina num incidente unificado no Sentinel, investigado no portal XDR, e respondido por um playbook Logic App.

No próximo módulo, vamos parar de falar de teoria e colocar a mão na massa. Vamos implantar o Microsoft Sentinel do zero no ambiente do Banco Meridian, conectar as primeiras fontes de dados e verificar que os logs estão chegando.

Antes disso, respondam as questões de fixação no módulo — elas cobrem exatamente o conteúdo desta aula e são do nível SC-200.

Até o próximo módulo!"

*[DICA DE EDIÇÃO: encerrar com tela de agradecimento e link para o próximo módulo]*

---

## 10. Avaliação do Módulo

### Questões de Avaliação

**Q1.** O Banco Meridian usa Azure SQL Database (PaaS) para armazenar dados de clientes. Sobre a responsabilidade de segurança, é correto afirmar que:

a) A Microsoft é totalmente responsável pela segurança dos dados, pois gerencia o PaaS  
b) O banco é responsável pela criptografia dos dados em repouso e em trânsito, pela gestão de acesso e pela auditoria, enquanto a Microsoft gerencia o motor do banco de dados  
c) O banco não precisa se preocupar com compliance de dados em PaaS  
d) A Microsoft aplica automaticamente patches de segurança nos dados do cliente  

**Resposta: B** — No PaaS, o cliente (banco) é responsável pelos dados, pelas identidades que acessam os dados, pela configuração de acesso e pela conformidade regulatória (BACEN 4.893, LGPD). A Microsoft gerencia o motor do SGBD, o sistema operacional do host, a rede física e o hardware.

---

**Q2.** O CISO do Banco Meridian quer implementar o princípio de "menor privilégio" para os administradores de sistemas. Qual produto Microsoft implementa Just-in-Time access para funções privilegiadas?

a) Microsoft Sentinel  
b) Entra ID Protection  
c) Privileged Identity Management (PIM)  
d) Microsoft Defender for Cloud  

**Resposta: C** — O PIM (Privileged Identity Management), parte do Entra ID P2, implementa JIT access: administradores são elegíveis a funções privilegiadas mas precisam solicitar ativação, que pode requerer aprovação e MFA adicional. O acesso é concedido por uma janela de tempo limitada (ex.: 1–8 horas). Isso implementa tanto menor privilégio quanto assume breach.

---

**Q3.** Um analista SOC investiga um incidente que combina: phishing por e-mail → download de malware → login com credenciais roubadas → accesso a SharePoint → download de arquivos sensíveis. Qual produto do Defender XDR detectaria a etapa de download de malware no endpoint do usuário?

a) Microsoft Defender for Identity (MDI)  
b) Microsoft Defender for Office 365 (MDO)  
c) Microsoft Defender for Endpoint (MDE)  
d) Microsoft Defender for Cloud Apps (MDA)  

**Resposta: C** — O MDE monitora cada endpoint e detecta execução de malware, técnicas de evasão, comportamento suspeito de processos, downloads maliciosos e execução de payloads. MDO detecta o e-mail de phishing inicial; MDI detecta movimentação lateral via AD; MDA detecta o download anômalo de arquivos do SharePoint.

---

**Q4.** O que diferencia o Microsoft Sentinel de um SIEM tradicional on-premises como o IBM QRadar?

a) O Sentinel não suporta queries SQL, limitando análises avançadas  
b) O Sentinel é um serviço gerenciado sem infraestrutura para provisionar, escalável automaticamente, com custo baseado em volume ingerido e integração nativa ao ecossistema Azure/Microsoft 365  
c) O Sentinel só funciona com fontes de dados Microsoft, sem suporte a syslog/CEF  
d) O Sentinel não tem capacidade de SOAR; Logic Apps são um produto separado não integrado  

**Resposta: B** — O Sentinel é SaaS/PaaS sem servidores para gerenciar. Escala automaticamente. O custo é baseado em GB/dia ingeridos (com commitment tiers) ou pay-as-you-go. Integra nativamente com Entra ID, MDE, MDO, Azure Activity sem necessidade de parsers customizados. Suporta também syslog, CEF, TAXII, REST APIs para fontes não-Microsoft. A capacidade SOAR está integrada nativamente via Logic Apps e Automation Rules.

---

**Q5.** O Banco Meridian está considerando usar AWS para workloads analíticas além do Azure. O CISO quer uma visão unificada de postura de segurança. Qual recurso do Defender for Cloud permite isso?

a) Azure Policy exportada para AWS via Terraform  
b) Onboarding de contas AWS no Defender for Cloud usando o conector nativo, habilitando CSPM multi-cloud com Secure Score unificado  
c) Microsoft Sentinel monitora automaticamente contas AWS sem necessidade de configuração  
d) O Defender for Cloud não suporta AWS; é necessário comprar Defender for AWS separadamente  

**Resposta: B** — O Defender for Cloud tem conectores nativos para AWS e GCP que usam agentless scanning para CSPM. Após o onboarding, os recursos AWS aparecem no painel do Defender for Cloud com avaliações de postura, recomendações baseadas em CIS AWS Benchmark e Microsoft Cloud Security Benchmark, e contribuem para o Secure Score. Os findings podem ser exportados continuamente para o Sentinel.

---

**Questão Dissertativa (20 pontos)**

O Banco Meridian opera com M365 E3 (sem segurança avançada) e uma equipe SOC de 3 analistas. O CISO recebeu aprovação para upgrade para M365 E5 Security e aquisição do Microsoft Sentinel. Descreva a sequência lógica de implantação usando os conceitos da MCRA e Zero Trust, justificando por que cada produto deve ser implantado antes do próximo.

**Gabarito Esperado (rubrica):**

A resposta deve cobrir: (1) Começar por Entra ID P2 — habilitar MFA para todos, configurar Conditional Access com políticas de risco, ativar PIM para admins → fundação de identidade Zero Trust (5 pts); (2) Onboardar endpoints no MDE P2 — telemetria de endpoint é essencial para o SIEM (5 pts); (3) Ativar MDO P2 — configurar Safe Links, Safe Attachments, políticas anti-phishing; e-mail é vetor #1 de ataque (3 pts); (4) Implantar o Sentinel e conectar as fontes habilitadas — neste ponto já há telemetria útil de Entra ID, MDE e MDO (5 pts); (5) Criar automation rules e primeiros playbooks básicos — resposta automatizada desde o início (2 pts).

Deve justificar a sequência: identidade primeiro porque é a base de autenticação de tudo; endpoints antes do SIEM porque sem telemetria o SIEM não tem dados; SIEM antes de automação porque a automação depende de incidentes do SIEM.
