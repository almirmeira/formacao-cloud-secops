# Módulo 08 — CASB, SSE, DSPM e Comparativo CNAPP
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h videoaula + 1h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 6 / CCSK domínio 4 e 5  
> **Cenário:** CISO do Banco Meridian avaliando plataformas CNAPP comerciais

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Descrever os casos de uso de CASB, SSE e DSPM com exemplos práticos
2. Distinguir entre as principais plataformas CNAPP comerciais (Wiz, Prisma Cloud, Orca, Defender)
3. Estruturar uma RFP mínima para avaliação de plataforma CNAPP
4. Calcular o TCO de uma solução CNAPP vs stack open-source
5. Definir critérios objetivos para um PoC de plataforma CNAPP

---

## 1. CASB — Cloud Access Security Broker

### 1.1 Por Que CASB Existe

O problema fundamental do CASB é o shadow IT em SaaS. Em 2024, um estudo da Netskope indicou que empresas de médio porte usam em média 2.500 aplicações SaaS distintas — mas os departamentos de TI aprovaram formalmente menos de 200. Isso significa que 2.300+ aplicações não passaram por revisão de segurança, não têm contratos de processamento de dados (LGPD), e não têm monitoramento de DLP.

Para o Banco Meridian, um analista pode estar uploadando planilhas com dados de clientes para o Google Sheets pessoal. Outro pode estar usando ChatGPT para processar documentos confidenciais. Um terceiro pode ter instalado uma extensão de Chrome que exfiltra cookies de sessão.

### 1.2 Casos de Uso de CASB

| Use Case | Descrição | Exemplo Banco Meridian |
|:---------|:----------|:-----------------------|
| **Shadow IT Discovery** | Descobre todas as apps SaaS sendo usadas, aprovadas ou não | "Temos 340 apps em uso; apenas 45 aprovadas pelo TI" |
| **Data Loss Prevention** | Detecta e bloqueia upload de dados sensíveis | Bloquear upload de planilha com CPFs para Google Drive pessoal |
| **ATP — Advanced Threat Protection** | Detecta malware em arquivos sincronizados via SaaS | Arquivo malicioso sendo distribuído via SharePoint |
| **Session Control** | Acesso condicional com limitações em dispositivos não gerenciados | Só leitura no Outlook Web se acessado de dispositivo pessoal |
| **SSPM — SaaS Security Posture** | Avalia configurações de segurança dos tenants SaaS (M365, Salesforce) | "Microsoft 365 tenant com Legacy Authentication habilitado" |

### 1.3 Arquitetura CASB

```
CASB — MODOS DE OPERAÇÃO
──────────────────────────────────────────────────────────────────────────────
MODO 1: Inline Proxy (Forward Proxy)
  User → [CASB Proxy] → Internet/SaaS
  Vê: todo o tráfego web em tempo real
  Bloqueia: em tempo real (URL, conteúdo, DLP)
  Requer: configuração de proxy no device ou dispositivo gerenciado

MODO 2: API-Based (CASB + SaaS API)
  CASB API ──→ Microsoft 365 API / Salesforce API / Box API
  Vê: atividades já realizadas (post-facto)
  Bloqueia: pode remover arquivos, revogar compartilhamentos
  Requer: OAuth connection com o tenant SaaS
  Não requer modificação no endpoint

MODO 3: Reverse Proxy (Session Control)
  User → IdP (Entra ID) → [CASB Reverse Proxy] → SaaS App
  Vê: sessão completa do usuário na aplicação
  Bloqueia: em tempo real, com granularidade de ação (download/upload/copy)
  Requer: routing via IdP, não transparente para o usuário
──────────────────────────────────────────────────────────────────────────────
```

### 1.4 Ferramentas CASB

**Netskope:**
```
Netskope é o líder de mercado em CASB puro e SSE.
Pontos fortes:
  - NewEdge: rede de PoPs proprietária com latência baixa (diferencial vs Zscaler)
  - Inline proxy + API dual-mode para o mesmo tenant
  - SSPM integrado: avalia configurações de segurança do Microsoft 365, Salesforce
  - Data classification em trânsito via ML (não apenas regex)
  - Cloud Threat Exchange: compartilhamento de IOCs entre clientes Netskope

Arquitetura de deployment:
  - Netskope Client (endpoint agent) para dispositivos corporativos
  - Browser proxy PAC file para BYOD
  - API connections para SaaS críticos (M365, Box, Google Workspace)
  - IPSec/GRE tunnel para branch offices
```

**Zscaler Internet Access (ZIA):**
```
ZIA é o forward proxy cloud-based mais adotado no mundo.
Pontos fortes:
  - Rede global de data centers (150+ PoPs)
  - Deep SSL inspection escalável
  - Cloud-native: sem appliances on-premises
  - Integrado nativamente com Zscaler Private Access (ZPA = ZTNA)
  - SandboxAI: análise dinâmica de malware em sandbox

Diferencial vs Netskope:
  - Melhor integração ZTNA (ZIA + ZPA da mesma plataforma)
  - Mais adotado em enterprises grandes com foco em substituição de proxy on-premises
```

**Microsoft Defender for Cloud Apps:**
```
CASB nativo do ecossistema Microsoft.
Pontos fortes:
  - Integração profunda com Microsoft 365 (Exchange, SharePoint, Teams, OneDrive)
  - Session policies via Conditional Access (sem configuração de proxy adicional)
  - Custo: incluído no E5 da Microsoft (sem licença adicional para M365-focused)
  - Shadow IT discovery integrado com Microsoft Defender for Endpoint
  - Microsoft Purview DLP: integração nativa com labels de sensibilidade

Limitação:
  - Cobertura de apps não-Microsoft é mais superficial que Netskope/Zscaler
```

---

## 2. SSE — Security Service Edge

### 2.1 A Morte da VPN Tradicional

```
POR QUE VPN TRADICIONAL NÃO FUNCIONA EM CLOUD
──────────────────────────────────────────────────────────────────────────────
MODELO VPN TRADICIONAL:
  Usuário → VPN → Rede Corporativa → Aplicação

  Problemas:
  1. Acesso a REDE, não a APLICAÇÃO — após VPN, acesso lateral total
  2. Performance: tráfego para cloud passa pela HQ antes de chegar na AWS
  3. Escalabilidade: concentrador VPN vira gargalo para trabalho remoto
  4. Ausência de contexto: não verifica estado do device, identidade contínua
  5. Latência: Tokyo → HQ São Paulo → AWS São Paulo (desnecessário)

MODELO SSE/ZTNA:
  Usuário → Identity Provider + Device Check → SSE Broker → Aplicação específica

  Benefícios:
  1. Acesso a APLICAÇÃO específica, não à rede
  2. Tráfego vai direto do usuário para a app (sem backhaul)
  3. Verifica continuamente: identidade + dispositivo + comportamento
  4. Microsegmentação: dev só acessa apps de dev, não de produção
  5. Funciona em qualquer rede (wifi público, 4G, etc.)
──────────────────────────────────────────────────────────────────────────────
```

### 2.2 Principais Soluções SSE

**Zscaler Private Access (ZPA):**
- App Connectors no datacenter/cloud conectam ao Zscaler Exchange (broker)
- Usuário com Zscaler Client → autentica no IdP → ZPA Broker verifica política → estabelece túnel para App Connector
- App nunca precisa de IP público — firewall inbound fechado
- Zero trust: política granular por aplicação, usuário, grupo, dispositivo, hora

**Netskope SASE:**
- Convergência de CASB + SSE em uma plataforma + SD-WAN
- SASE = Secure Access Service Edge (Gartner 2019)
- Branch offices, remote users e cloud conectados ao mesmo broker Netskope

**Prisma Access (Palo Alto Networks):**
- GlobalProtect cloud infrastructure
- Substitui VPN GlobalProtect on-premises com versão cloud
- Integração com Palo Alto NGFW rules
- IPSec tunnels para branch offices

**Cloudflare One:**
- ZTNA + CASB + SWG + Magic WAN (SD-WAN)
- Zero trust: Cloudflare Access (ZTNA)
- Gateway: web filtering + DLP
- Menor custo entre os grandes players
- Muito adotado por startups e mid-market

---

## 3. DSPM — Data Security Posture Management

### 3.1 O Novo Campo de DSPM

DSPM é um campo emergente (Gartner Magic Quadrant inaugural em 2023) que resolve o problema fundamental da segurança de dados em cloud: você não pode proteger dados que não sabe que tem.

```
O PROBLEMA QUE DSPM RESOLVE
──────────────────────────────────────────────────────────────────────────────
ANTES DO DSPM:
  "Onde estão os dados de CPF dos nossos clientes?"
  Resposta: "Creio que no banco de dados principal..."
  Realidade: também em 17 buckets S3, 3 Azure Blob containers,
  2 bancos de dados de teste, 1 data lake de analytics, e em 300GB
  de logs não estruturados exportados por um desenvolvedor em 2022.

  Para o BACEN/LGPD: você não pode notificar sobre vazamento de dados
  que não sabia que tinha. Mas as multas se aplicam igualmente.

COM DSPM:
  - Scan automático de todos os data stores cloud (S3, RDS, BigQuery, etc.)
  - Classificação automática: PII, PCI, dados de saúde, dados confidenciais
  - Risco por data store: "bucket X tem 45.000 CPFs + está público"
  - Controles ausentes: "banco de dados Y tem dados de cartão sem criptografia"
  - Lineage: "esses dados vieram do sistema legado Z via pipeline de ETL"
──────────────────────────────────────────────────────────────────────────────
```

### 3.2 Como DSPM Difere do DLP

| Dimensão | DLP (Data Loss Prevention) | DSPM (Data Security Posture) |
|:---------|:--------------------------:|:----------------------------:|
| **Foco** | Dados em movimento (email, upload, clipboard) | Dados em repouso (buckets, bancos, data lakes) |
| **Quando** | Tempo real, ao vazar | Preventivo, antes de vazar |
| **O que detecta** | Tentativa de exfiltração | Repositórios de dados com postura fraca |
| **Onde** | Endpoint + proxy | Cloud APIs (S3, Azure, GCP) |
| **Ação** | Bloquear + alertar | Alertar + recomendar remediação |
| **Maturidade** | Tecnologia de 20 anos | Emergente (2022–2025) |
| **Integração** | DLP + CASB | CNAPP + data governance |

### 3.3 Soluções DSPM

**Wiz DSPM:**
- Nativo ao Wiz CNAPP (não requer produto separado no tier superior)
- Descoberta automática de todos os data stores na conta AWS/Azure/GCP
- Classificação por ML (não apenas regex)
- Risco contextual: dados sensíveis + misconfiguration + acesso excessivo = toxic combination de dados
- Correção em-linha: botão "Fix" diretamente na interface Wiz

**Varonis:**
- Foco em data access governance (quem acessa o quê nos dados)
- Cobertura ampla: cloud + file shares + M365 + Active Directory
- Behavior analytics: detecta acesso anormal a dados (insider threat)
- Data classification engine maduro (empresa de 20 anos em DLP/DG)

**Dig Security (adquirida pela Palo Alto):**
- Cloud-native DSPM from-scratch
- Agentless scan via cloud APIs
- Data lineage e provenance
- Foco em compliance automático (LGPD, GDPR, HIPAA)

**Cyera:**
- Automatic data classification em português (suporte a LGPD)
- API-only (agentless)
- Shadow data discovery: dados que a organização não sabia que tinha
- Privacidade por design: foco em campos específicos (CPF, CNPJ, dados bancários)

---

## 4. Comparativo CNAPP Vendors 2025

### 4.1 Tabela Técnica e Econômica Completa

| Dimensão | Wiz | Prisma Cloud (Palo Alto) | Orca Security | Defender for Cloud (Microsoft) | Lacework |
|:---------|:---:|:------------------------:|:-------------:|:-------------------------------:|:--------:|
| **CSPM** | Excelente | Excelente | Excelente | Excelente (Azure-first) | Bom |
| **CWPP** | Bom (agentless) | Excelente (com agente) | Bom (agentless) | Bom | Bom |
| **CIEM** | Excelente | Excelente | Bom | Bom | Bom |
| **DSPM** | Excelente | Bom | Bom | Básico | Não nativo |
| **IaC Security** | Wiz Code | Excelente | Básico | Básico | Não nativo |
| **Runtime** | Via parceiro (Falco) | Excelente (agente) | Não nativo | Bom (Defender Sensors) | Bom |
| **Container K8s** | Excelente | Excelente | Bom | Bom | Bom |
| **AWS** | Excelente | Excelente | Excelente | Bom (via connector) | Excelente |
| **Azure** | Excelente | Excelente | Excelente | Excelente (nativo) | Bom |
| **GCP** | Excelente | Excelente | Bom | Bom (via connector) | Bom |
| **Attack Path** | Excelente (Security Graph) | Bom | Excelente (visual) | Bom | Bom |
| **Toxic Combinations** | Excelente | Bom | Bom | Básico | Bom |
| **Integrações SIEM** | Splunk, Sentinel, XSIAM | XSOAR, Splunk, Sentinel | Splunk, Sentinel | Sentinel (nativo), Splunk | Splunk, Sentinel |
| **Compliance Frameworks** | 100+ | 100+ | 80+ | 80+ | 50+ |
| **BACEN 4.893** | Customizável | Customizável | Customizável | Customizável | Customizável |
| **API** | GraphQL completa | REST completa | REST | REST | REST |
| **Terraform Provider** | Sim | Sim | Sim | Sim | Sim |
| **Agentless** | Totalmente | Parcial (CSPM agentless, CWPP requer agente) | Totalmente | Parcial | Parcial |
| **Setup Time** | 2–4 semanas | 4–8 semanas | 2–3 semanas | 1–2 semanas (Azure) | 2–4 semanas |
| **Curva de Aprendizado** | Baixa (UI intuitiva) | Alta | Baixa | Média | Média |
| **Modelo de Preço** | Por workload/mês | Por crédito | Por asset/mês | Pay-as-you-go + planos | Por workload + data |
| **Preço 200 workloads (est.)** | USD 80–150k/ano | USD 60–100k/ano | USD 50–80k/ano | USD 20–60k/ano | USD 50–80k/ano |
| **Clientes típicos** | Mid-market + Enterprise tech | Enterprise, regulated | Mid-market | Microsoft-first | DevOps-heavy |
| **Presença no Brasil** | Crescente (escritório SP) | Forte (Palo Alto Brasil) | Limitada | Forte (Microsoft Brasil) | Limitada |

### 4.2 Pontos Fortes e Fracos Detalhados

**Wiz:**

Pontos fortes:
- Security Graph é genuinamente único — nenhum concorrente tem correlação equivalente
- Agentless completo — deploy em dias, sem impacto em produção
- Interface mais intuitiva do mercado — CISO sem background técnico consegue usar
- DSPM mais maduro entre os CNAPP vendors
- Wiz Code (ASPM) para shift-left, integrando com IDEs e CI/CD
- Crescimento mais rápido da história do software enterprise (USD 0 a USD 500M ARR em 4 anos)

Pontos fracos:
- Sem runtime protection nativo (parceria com Falco via Wiz Runtime)
- Preço é o mais alto do mercado
- Dados processados fora da infraestrutura do cliente (impacto em CMN 4.658)
- Sem região de dados no Brasil ainda (problema para BACEN)

---

**Prisma Cloud (Palo Alto Networks):**

Pontos fortes:
- Cobertura mais completa: único que tem CWPP com agente real + microsegmentação
- Code Security shift-left: IDE plugins, GitHub integration, primeiro a cobrir "code to cloud"
- Compliance automático: mais de 100 frameworks built-in incluindo LGPD customizável
- Integração com XSOAR para automação de resposta a incidentes
- Suporte enterprise maduro (Palo Alto Brasil com equipe local)

Pontos fracos:
- Complexidade: requer especialistas Prisma Cloud para implementação e operação
- Curva de aprendizado longa (3–6 meses até proficiência)
- Preço baseado em créditos é difícil de prever (surpresas na fatura)
- Interface fragmentada: ainda tem vestígios de múltiplas aquisições (Demisto, Twistlock, Aporeto)

---

**Orca Security:**

Pontos fortes:
- SideScanning™ é tecnologia genuinamente única para visibilidade profunda sem agente
- Attack path analysis visual muito clara e fácil de apresentar para stakeholders
- Interface limpa e acessível — onboarding mais rápido que Wiz e Prisma
- Preço intermediário com boa cobertura de features

Pontos fracos:
- Sem runtime protection (SideScanning é snapshot, não tempo real)
- Menor cobertura de K8s comparado a Wiz e Prisma
- Menor ecosistema de integrações que os líderes
- Presença limitada no Brasil

---

**Microsoft Defender for Cloud:**

Pontos fortes:
- Para ambientes Microsoft-first: integração incomparável (Entra ID, Sentinel, Intune, M365)
- Modelo de preço mais acessível (Foundational CSPM gratuito para Azure)
- Microsoft Secure Score: KPI unificado de postura facilmente apresentável
- Governance integrada: assign owner + due date para cada recomendação
- Suporte Microsoft Brasil = garantia de conformidade com CMN 4.658 (dados no Brasil)

Pontos fracos:
- Cobertura AWS/GCP mais superficial (via connectors, não nativa)
- Runtime protection para containers menos madura que Sysdig/Aqua
- Menos relevante para organizações não-Microsoft
- DSPM ainda imaturo comparado ao Wiz

---

**Lacework:**

Pontos fortes:
- Excelente para detecção de anomalias comportamentais (ML-based behavioral analysis)
- Forte cobertura de K8s e containers
- Bem-integrado com DevOps toolchain (Terraform, GitHub Actions)
- Polygraph™: visualização de comportamentos normais vs anômalos

Pontos fracos:
- DSPM e Code Security ausentes ou muito básicos
- Menor mindshare no mercado brasileiro
- Menos checks de compliance que os líderes
- Volatilidade: múltiplas mudanças de estratégia desde 2022

---

## 5. Framework para Decisão de Compra

### 5.1 RFP Mínima para CNAPP

```
RFP MÍNIMA — PLATAFORMA CNAPP
BANCO MERIDIAN — 2025
──────────────────────────────────────────────────────────────────────────────

SEÇÃO 1: ESCOPO E CONTEXTO
  - Ambiente: AWS (80%), Azure (20%), Kubernetes (50 clusters)
  - Workloads: 500 VMs, 2.000 containers, 100 funções Lambda
  - Requisito de compliance: BACEN 4.893, CMN 4.658, LGPD
  - Localização de dados: Brasil (CMN 4.658 Art. 16)
  - Integração requerida: Microsoft Sentinel (SIEM), ServiceNow (ITSM)

SEÇÃO 2: REQUISITOS TÉCNICOS MANDATÓRIOS (knock-out criteria)
  ☐ CSPM multi-cloud: AWS + Azure
  ☐ CWPP: scan de imagens Docker sem agente
  ☐ CIEM: análise de permissões excessivas em IAM
  ☐ Compliance BACEN 4.893 built-in ou customizável
  ☐ Dados processados em data center no Brasil ou equivalente para CMN 4.658
  ☐ API REST/GraphQL documentada para automação
  ☐ Integração com Microsoft Sentinel via webhook ou connector nativo
  ☐ SLA: 99,9% uptime

SEÇÃO 3: REQUISITOS TÉCNICOS DESEJÁVEIS
  ☐ DSPM para classificação automática de dados sensíveis
  ☐ IaC security integrado (Terraform scan)
  ☐ Attack path analysis visual
  ☐ Toxic combinations correlation
  ☐ Runtime protection (agentless preferível)
  ☐ Verifyimages / Cosign integration
  ☐ Relatórios BACEN automáticos (PDF/HTML)

SEÇÃO 4: REQUISITOS DE NEGÓCIO
  ☐ Modelo de preço previsível (não por crédito)
  ☐ Referência de cliente no setor financeiro brasileiro
  ☐ Suporte local em português (pt-BR) ou horário comercial Brasil
  ☐ Treinamento incluído (mínimo 3 usuários)
  ☐ Cláusulas de LGPD / BACEN no contrato de processamento de dados

SEÇÃO 5: CRITÉRIOS DE AVALIAÇÃO
  Técnicos (60%):
    - Profundidade de detecção em AWS: 25%
    - Qualidade do attack path analysis: 15%
    - Qualidade dos relatórios de compliance BACEN: 10%
    - Performance e tempo de scan: 10%

  Negócio (40%):
    - TCO (3 anos): 20%
    - Suporte e presença local: 10%
    - Referências no setor financeiro: 10%
──────────────────────────────────────────────────────────────────────────────
```

### 5.2 Critérios de PoC

```
PLANO DE POC — CNAPP BANCO MERIDIAN (30 dias)

SEMANA 1: Setup e Onboarding
  - Conectar conta AWS sandbox (read-only)
  - Conectar tenant Azure dev
  - Configurar integrações: Sentinel, ServiceNow
  - KPI inicial: tempo de onboarding até primeiro finding

SEMANA 2: CSPM e CIEM
  - Executar scan completo da conta AWS sandbox
  - Comparar findings com Prowler (benchmark)
  - Avaliar qualidade de CIEM: identificar shadow admins
  - KPI: % de findings do Prowler que o vendor também encontra

SEMANA 3: Attack Path e Correlação
  - Intencionalmente criar misconfigurations no sandbox
  - Verificar se vendor detecta e correlaciona corretamente
  - Apresentar attack path ao CISO
  - KPI: clareza e acionabilidade do attack path

SEMANA 4: Compliance e Relatórios
  - Gerar relatório de compliance BACEN 4.893
  - Avaliar qualidade e adequação do relatório para auditoria
  - Verificar integração com Sentinel: qualidade dos alertas
  - KPI: quality score do relatório BACEN (avaliado pelo CISO)

CRITÉRIOS DE APROVAÇÃO:
  - Detecting >80% dos findings do Prowler baseline
  - Attack path claro para o cenário de toxic combination do sandbox
  - Relatório BACEN apresentável sem necessidade de edição manual
  - Dados em data center Brasil confirmado
  - Integração Sentinel funcionando dentro de 15 minutos
```

### 5.3 Cálculo de TCO (3 anos)

```
MODELO TCO — BANCO MERIDIAN (500 workloads)

OPÇÃO A: CNAPP COMERCIAL (estimativa Wiz)
──────────────────────────────────────────────────────────────
Licença: USD 100.000/ano × 3 = USD 300.000
Implementação (consultoria, onboarding): USD 20.000
Treinamento (3 pessoas, certificação): USD 15.000
Operação (0,3 FTE — 15% do tempo de 2 analistas): USD 30.000/ano × 3 = USD 90.000
──────────────────────────────────────────────────────────────
TCO 3 anos: USD 425.000

OPÇÃO B: STACK OPEN-SOURCE (Prowler + Trivy + Falco + OPA + Vault)
──────────────────────────────────────────────────────────────
Infra AWS para as ferramentas: USD 8.000/ano × 3 = USD 24.000
Implementação e integração (consultoria inicial): USD 40.000
1 FTE dedicado 50% do tempo: USD 80.000/ano × 3 = USD 240.000
Treinamento contínuo: USD 5.000/ano × 3 = USD 15.000
──────────────────────────────────────────────────────────────
TCO 3 anos: USD 319.000

DIFERENÇA: USD 106.000 a mais para o CNAPP comercial em 3 anos

MAS: CNAPP comercial entrega:
  - Attack path analysis (open-source não tem)
  - Monitoramento contínuo 24/7 (open-source requer agendamento)
  - Compliance reports automáticos para BACEN
  - Correlação de findings entre categorias
  - Tempo de detecção: minutos vs horas

RECOMENDAÇÃO: se a equipe de segurança tem < 3 pessoas, o TCO favorece CNAPP
comercial mesmo sendo mais caro em absoluto — porque a opção B requer uma
pessoa qualificada a tempo parcial, e o custo oculto é a falta de correlação.
```

---

## 6. Atividades de Fixação

### Questão 1
Um colaborador do Banco Meridian usa Gmail pessoal no laptop corporativo para enviar planilhas de Excel com dados de clientes por e-mail para um parceiro externo. Qual componente de segurança detectaria e potencialmente bloquearia isso?

**a)** CSPM — verifica a configuração do Google Workspace do colaborador  
**b)** CASB com DLP inline — inspeciona o tráfego do Gmail detectando dados sensíveis (CPFs, números de conta) e bloqueia ou alerta  
**c)** CIEM — analisa as permissões do colaborador no Gmail  
**d)** DSPM — descobre os dados no Gmail e classifica  

**Gabarito: b)**  
Justificativa: CASB com proxy inline inspeciona o tráfego web (incluindo HTTPS do Gmail pessoal) via deep packet inspection/SSL inspection. O módulo de DLP detecta padrões de dados sensíveis (CPFs, números de conta) nos arquivos sendo enviados e pode bloquear ou redirecionar para quarentena, dependendo da política configurada.

---

### Questão 2
Qual é a diferença fundamental entre o Wiz e o Prisma Cloud CWPP em relação à proteção de workloads?

**a)** Wiz usa agent em todos os workloads; Prisma Cloud é agentless  
**b)** Wiz é agentless via API cloud (sem acesso dentro do workload em tempo real); Prisma Cloud CWPP instala agente no OS que monitora o workload em runtime com microsegmentação de rede  
**c)** São idênticos em funcionalidade de CWPP  
**d)** Wiz tem runtime protection nativa; Prisma Cloud não tem  

**Gabarito: b)**  
Justificativa: A diferença arquitetural é fundamental. Wiz usa apenas APIs cloud (sem agente) — ótimo para escaneamento de vulnerabilidades mas sem visibilidade de runtime real. Prisma Cloud CWPP instala o Prisma Cloud Defender (agente) no OS, que provê: microsegmentação de rede entre containers, runtime protection contra processos suspeitos, e visibilidade de comportamento em tempo real.

---

### Questão 3
Por que o Microsoft Defender for Cloud é preferível para um banco que opera 90% na Azure com Microsoft 365?

**a)** Porque é mais barato em todos os casos  
**b)** Porque a integração nativa com Entra ID, Sentinel, M365 e o fato de ter dados no Brasil (Azure Brazil South) elimina os problemas de CMN 4.658 e reduz drasticamente a complexidade operacional  
**c)** Porque tem mais checks de CIS Benchmark que qualquer outro CNAPP  
**d)** Porque é o único CNAPP com suporte a BACEN 4.893  

**Gabarito: b)**  
Justificativa: Para uma organização Microsoft-first, o Defender for Cloud tem integração incomparável: identidades do Entra ID aparecem diretamente nos findings, alertas alimentam o Sentinel automaticamente, postura do M365 é visível no mesmo console. E fundamentalmente para bancos brasileiros: os dados ficam na Azure Brazil South (garantindo CMN 4.658 sem necessidade de aprovação especial do BACEN).

---

### Questão 4
O que é o SideScanning™ da Orca Security e qual é sua principal limitação?

**a)** Um agente leve que roda em cada container para análise de rede — limitação: overhead de CPU  
**b)** Uma tecnologia que cria snapshots efêmeros dos volumes de disco para análise profunda sem agente — limitação: análise é estática (snapshot), sem proteção de runtime em tempo real  
**c)** Uma API que intercepta chamadas de sistema no kernel — limitação: requer modificação do kernel  
**d)** Um scanner de rede que analisa tráfego de saída — limitação: não vê dados em repouso  

**Gabarito: b)**  
Justificativa: SideScanning™ cria snapshots efêmeros dos volumes EBS/discos, os monta em ambiente isolado da Orca, analisa o filesystem completo (pacotes, configs, secrets), e depois deleta o snapshot. Vantagem: profundidade sem agente. Limitação crítica: é uma foto, não um filme. Não detecta comportamentos anômalos em runtime — apenas o estado da imagem em um momento específico.

---

### Questão 5
No cálculo de TCO de 3 anos para 500 workloads, qual fator torna o CNAPP comercial frequentemente justificável economicamente, mesmo sendo mais caro em custo de licença?

**a)** Licenças CNAPP incluem treinamento gratuito ilimitado  
**b)** O custo oculto do stack open-source — principalmente o FTE qualificado dedicado à manutenção e integração, que pode superar o custo da licença comercial — além da falta de correlação entre ferramentas que aumenta o tempo de detecção e resposta  
**c)** CNAPP comercial elimina completamente a necessidade de analistas de segurança  
**d)** CNAPP comercial inclui seguro de cyber liability  

**Gabarito: b)**  
Justificativa: O stack open-source não é "gratuito" — requer 0,5–1 FTE de engenheiro sênior dedicado à manutenção, integração, atualização e operação. A horas de engenheiro sênior de segurança são caras. Além disso, a falta de correlação entre ferramentas open-source aumenta o MTTD (Mean Time to Detect) e o MTTR (Mean Time to Respond) — o custo de um incidente não detectado a tempo pode superar anos de licença de CNAPP comercial.

---

## 7. Roteiro de Gravação — Aula 8.1: CASB + SSE + DSPM + Comparativo CNAPP (55 min)

### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | CASB, SSE, DSPM e Como Escolher um CNAPP Comercial |
| **Duração** | 55 minutos |
| **Formato** | Talking head + slides + demos conceituais |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Chegamos ao oitavo módulo e vamos fechar o panorama de ferramentas de cloud security com as categorias que ainda não cobrimos: CASB para controle de acesso a SaaS, SSE como substituto da VPN, DSPM para visibilidade de dados em repouso, e vamos encerrar com um comparativo detalhado das principais plataformas CNAPP do mercado.

Este módulo é especialmente relevante para quem vai ter uma conversa com o CISO sobre investimento em tooling de segurança cloud.

---

**[05:00 – 20:00 | CASB E SSE | Slides]**

*[Dica de edição: slides com animação dos modos de operação do CASB]*

Vamos começar pelo CASB. O problema que ele resolve é o shadow IT — as centenas de aplicações SaaS que seus colaboradores usam sem que o TI saiba.

*[Mostra diagrama dos modos de operação: inline, API, reverse proxy]*

*[Explica cada modo com o contexto do Banco Meridian]*

Depois do CASB, vamos falar de SSE — e especificamente de por que VPN tradicional é um problema de segurança em um mundo de cloud e trabalho remoto.

*[Mostra o diagrama de comparação VPN vs SSE/ZTNA]*

---

**[20:00 – 30:00 | DSPM | Slides]**

*[Explica o problema fundamental: dados que você não sabe que tem]*

*[Mostra a diferença DSPM vs DLP na tabela]*

*[Conta o cenário fictício do Banco Meridian com 17 buckets S3 inesperados]*

---

**[30:00 – 50:00 | COMPARATIVO CNAPP | Slides]*

*[Apresenta a tabela comparativa completa]*

*[Para cada vendor, 2–3 minutos destacando o diferencial principal e a limitação principal]*

*[Demonstra o framework de decisão RFP + PoC]*

---

**[50:00 – 55:00 | ENCERRAMENTO | Talking head]**

No próximo módulo, o Módulo 9, vamos fazer o capstone — a avaliação final integrando tudo que aprendemos no curso, com o cenário completo do Banco Meridian.

---

## 8. Avaliação do Módulo 08

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
Qual é a diferença entre o modo inline proxy e o modo API-based de um CASB?

**a)** Inline proxy é mais seguro; API-based é mais rápido  
**b)** Inline proxy intercepta o tráfego em tempo real e pode bloquear instantaneamente; API-based usa APIs do SaaS para análise post-facto e pode remover/revogar mas não bloqueia em tempo real  
**c)** Inline proxy funciona apenas para aplicações aprovadas; API-based funciona para shadow IT  
**d)** São idênticos em funcionalidade, apenas diferentes em performance  

**Gabarito: b)** Inline proxy atua no caminho do tráfego — pode bloquear antes do upload completar. API-based conecta via OAuth na API do SaaS (ex: Graph API do Microsoft 365) e analisa atividades já realizadas — pode remover um arquivo compartilhado externamente, mas o upload já ocorreu. Para DLP em tempo real, inline é necessário.

---

**Questão 2 (10 pts)**  
O ZTNA (Zero Trust Network Access) como parte do SSE resolve qual problema específico da VPN tradicional?

**a)** VPN é mais lenta; ZTNA é mais rápida  
**b)** VPN concede acesso à rede inteira após autenticação; ZTNA concede acesso à aplicação específica + verifica continuamente identidade, dispositivo e contexto  
**c)** VPN requer hardware on-premises; ZTNA é cloud-only  
**d)** VPN não suporta MFA; ZTNA tem MFA integrado  

**Gabarito: b)** O problema fundamental da VPN é que ela é binária: autenticou → tem acesso à rede inteira (lateral movement garantido se comprometida). ZTNA é granular: cada aplicação requer verificação separada de identidade + compliance do dispositivo + contexto (hora, local, comportamento). Um usuário comprometido via ZTNA não consegue acessar outros sistemas na mesma sessão.

---

**Questão 3 (10 pts)**  
Por que DSPM é considerado um requisito crescente para conformidade com LGPD no Brasil?

**a)** LGPD exige explicitamente o uso de ferramentas DSPM certificadas  
**b)** LGPD exige que as organizações saibam onde estão seus dados pessoais, implementem controles adequados e possam notificar sobre vazamentos — impossível sem saber que os dados existem em determinados repositórios cloud  
**c)** DSPM é necessário apenas para empresas acima de 100 funcionários  
**d)** LGPD proíbe armazenamento de dados fora do Brasil, e DSPM verifica a localização dos dados  

**Gabarito: b)** A LGPD (Art. 46–48) exige "medidas técnicas e administrativas aptas a proteger os dados pessoais". A ANPD pode questionar: "Você sabe onde estão todos os dados pessoais dos seus titulares?" Sem DSPM, a resposta honesta é "não completamente". Um banco com dados espalhados em 17 buckets S3 que não sabe que existem não consegue implementar controles adequados nem notificar sobre vazamentos de dados que não sabia que tinha.

---

**Questão 4 (10 pts)**  
No contexto da CMN 4.658/2018 (regulação BACEN para cloud em IFs), qual vendor CNAPP tem a menor fricção para conformidade por parte de bancos brasileiros?

**a)** Wiz — por ser o líder de mercado com mais checks  
**b)** Microsoft Defender for Cloud — por ter dados processados nativamente na Azure Brazil South, eliminando a necessidade de aprovação especial do BACEN  
**c)** Orca Security — por ser o mais barato  
**d)** Prisma Cloud — por ter mais frameworks de compliance  

**Gabarito: b)** A CMN 4.658 Art. 16 restringe processamento de dados de clientes fora do Brasil sem aprovação prévia do BACEN. O Microsoft Defender for Cloud processa dados na Azure Brazil South (sa-east-1 equivalente da Microsoft). Wiz e Orca são SaaS e podem processar dados em regiões sem data center no Brasil, o que cria fricção regulatória para bancos brasileiros.

---

**Questão 5 (10 pts)**  
Um banco brasileiro com 80% de workloads na Azure está escolhendo entre Wiz e Microsoft Defender for Cloud. Qual critério é o mais relevante para essa decisão específica?

**a)** Número total de checks de CIS Benchmark  
**b)** A combinação de localização de dados (CMN 4.658), integração nativa com Microsoft Sentinel e Entra ID (redução de complexidade), e custo (Foundational CSPM gratuito para Azure) que favorece o Defender for Cloud para esse perfil  
**c)** A popularidade global do vendor  
**d)** Qual vendor tem o maior número de clientes no Brasil  

**Gabarito: b)** Para 80% Azure, o Defender for Cloud tem vantagens estruturais sobre o Wiz: (1) conformidade CMN 4.658 sem fricção regulatória; (2) integração nativa Sentinel/Entra elimina conectores externos; (3) Foundational CSPM gratuito para Azure reduz o TCO drasticamente. O Wiz tem vantagens em correlação e DSPM, mas para o perfil descrito o Defender tem ROI mais claro.

---

**Questão 6 (10 pts)**  
No PoC de CNAPP do Banco Meridian, qual métrica define se o vendor passa na semana de CSPM?

**a)** O vendor encontra todos os resources do sandbox em menos de 1 hora  
**b)** O vendor detecta mais de 80% dos findings identificados pelo Prowler como benchmark na conta sandbox  
**c)** O vendor gera um relatório PDF automático  
**d)** O vendor tem a interface mais bonita entre os testados  

**Gabarito: b)** O critério técnico objetivo para CSPM é: o vendor deve detectar pelo menos 80% dos findings que o Prowler (ferramenta gratuita e de referência) encontra na mesma conta. Isso garante que a plataforma comercial tem cobertura técnica mínima e não tem um baseline de detecção inferior ao que você consegue de graça.

---

*Módulo 08 — CASB, SSE, DSPM e Comparativo CNAPP*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
