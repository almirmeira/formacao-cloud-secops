# Módulo 01 — Panorama e Taxonomia das Ferramentas de Cloud Security
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h videoaula + 1h live online  
> **Certificação Alvo:** CCSP (ISC²) domínio 6 / CCSK (CSA) domínio 3  
> **Cenário:** Banco Meridian iniciando avaliação do stack de segurança cloud

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Nomear e definir precisamente cada categoria da taxonomia Gartner de Cloud Security Tools (2025)
2. Explicar o problema de segurança específico que cada categoria resolve
3. Descrever a convergência do mercado para CNAPP e as razões estratégicas por trás dela
4. Conduzir uma análise Build vs Buy para ferramentas de segurança cloud
5. Aplicar os critérios de seleção de ferramentas ao contexto regulatório brasileiro (BACEN 4.893, LGPD)

---

## 1. Taxonomia Gartner de Cloud Security Tools — 2025

O mercado de segurança cloud evoluiu de ferramentas pontuais para um ecossistema complexo de categorias especializadas. Entender essa taxonomia é o ponto de partida para qualquer avaliação de postura de segurança.

### 1.1 CNAPP — Cloud-Native Application Protection Platform

**Definição precisa:** Plataforma integrada que combina múltiplas capacidades de segurança cloud (CSPM, CWPP, CIEM, IaC security, code security) em uma única solução com dados correlacionados. O termo foi cunhado pelo Gartner em 2021.

**Problema que resolve:** A proliferação de ferramentas pontuais criou silos de segurança. Times têm 12+ consoles diferentes sem correlação entre os dados. Um atacante explora combinações de misconfigurations + permissões excessivas + vulnerabilidades de imagem — mas cada ferramenta vê apenas um pedaço. O CNAPP enxerga a cadeia completa.

**Exemplos:**
- Comerciais: Wiz, Prisma Cloud (Palo Alto), Orca Security, Lacework, Defender for Cloud (Microsoft)
- Open-source: combinação de Prowler + Trivy + Falco + Checkov (não é um CNAPP verdadeiro, mas cobre as categorias)

**Capacidade diferencial:** Toxic combinations — identifica quando uma instância EC2 tem uma misconfiguration + uma CVE crítica + uma role IAM excessiva ao mesmo tempo. Individualmente, cada finding teria prioridade média; combinados, são críticos.

---

### 1.2 CSPM — Cloud Security Posture Management

**Definição precisa:** Ferramenta que avalia continuamente a configuração dos recursos cloud contra benchmarks de segurança (CIS, NIST, LGPD, BACEN) e identifica desvios — misconfigurations, exposições públicas, falta de criptografia, controles ausentes.

**Problema que resolve:** Operadores de cloud erram ao configurar recursos. Um S3 bucket público, um Security Group com porta 22 aberta para 0.0.0.0/0, um banco de dados sem backup habilitado — são misconfigurations que exporão dados do Banco Meridian a uma multa do BACEN ou a um vazamento. CSPM automatiza a detecção contínua desses erros.

**Foco:** Plano de controle (configuração), não plano de dados (o que roda dentro).

**Exemplos:**
- Open-source: Prowler v4, ScoutSuite, CloudSploit (Aqua)
- Comerciais: Wiz (CSPM como parte do CNAPP), Prisma Cloud, Orca, Defender for Cloud

---

### 1.3 CWPP — Cloud Workload Protection Platform

**Definição precisa:** Protege o que está rodando dentro das instâncias — VMs, containers, funções serverless. Inclui vulnerability management (CVEs no OS e nas dependências), runtime protection, integrity monitoring e controle de aplicações.

**Problema que resolve:** Uma VM bem configurada (sem misconfigurations — CSPM clean) pode ter uma aplicação com Log4Shell. Uma imagem Docker pode ter 200 CVEs no OS base. CWPP olha para dentro da carga de trabalho.

**Diferença do CSPM:** CSPM = "sua casa está trancada?" (configuração). CWPP = "o que está acontecendo dentro da casa?" (conteúdo e comportamento).

**Exemplos:**
- Open-source: Trivy (scan), Falco (runtime), Grype, Syft
- Comerciais: Sysdig Secure, Aqua Security, Prisma Cloud Compute, Defender for Containers

---

### 1.4 CIEM — Cloud Infrastructure Entitlement Management

**Definição precisa:** Gerencia identidades e permissões em ambientes cloud — identifica permissões excessivas, unused permissions, shadow admins, e riscos de movimentação lateral via identidades.

**Problema que resolve:** Em cloud, existem muito mais identidades do que em ambientes on-premises: cada Lambda, cada EC2, cada pod K8s tem uma identidade. 95% dessas identidades têm mais permissões do que precisam. Um atacante que compromete qualquer uma delas pode se mover lateralmente ou escalar privilégios. CIEM identifica esse excesso.

**Conceitos-chave:**
- Effective permissions: o que uma identidade realmente pode fazer (levando em conta todas as policies, SCPs, permission boundaries)
- Permissions creep: acúmulo gradual de permissões que nunca são removidas
- Non-human identities (NHI): service accounts, instance profiles, workload identities

**Exemplos:**
- AWS: IAM Access Analyzer
- Azure: Entra Permissions Management
- GCP: Policy Intelligence
- Comerciais multi-cloud: Wiz CIEM, Ermetic (Tenable), CyberArk Cloud Entitlements Manager

---

### 1.5 CASB — Cloud Access Security Broker

**Definição precisa:** Ponto de controle de segurança posicionado entre usuários e aplicações cloud (SaaS, IaaS, PaaS). Monitora, controla e protege o acesso a aplicações cloud corporativas e pessoais.

**Problema que resolve:** Colaboradores do Banco Meridian usam centenas de aplicações SaaS — algumas aprovadas pelo TI, muitas não (shadow IT). Dados sensíveis de clientes podem ser uploadados para um Google Drive pessoal ou compartilhados via WeTransfer. CASB detecta e bloqueia esse vazamento.

**Capacidades:** Shadow IT discovery, DLP (Data Loss Prevention), ATP (Advanced Threat Protection), session control, conditional access, SSPM (SaaS Security Posture Management).

**Exemplos:**
- Comerciais: Netskope, Zscaler Internet Access (ZIA), Microsoft Defender for Cloud Apps, Cisco Umbrella, Broadcom Symantec CloudSOC

---

### 1.6 SSE — Security Service Edge

**Definição precisa:** Convergência de CASB + SWG (Secure Web Gateway) + ZTNA (Zero Trust Network Access) entregues como serviço cloud. Substitui a VPN corporativa tradicional com acesso baseado em identidade e contexto.

**Problema que resolve:** VPNs tradicionais dão acesso à rede inteira após autenticação — um atacante que compromete um endpoint tem acesso a tudo. SSE/ZTNA permite acesso apenas às aplicações específicas de que o usuário precisa, verificando identidade, dispositivo e contexto a cada sessão.

**Exemplos:**
- Comerciais: Zscaler Private Access (ZPA), Netskope SASE, Prisma Access (Palo Alto), Cloudflare One, Cisco Umbrella

---

### 1.7 KSPM — Kubernetes Security Posture Management

**Definição precisa:** CSPM especializado para clusters Kubernetes — avalia configurações de clusters, namespaces, pods e recursos K8s contra CIS Kubernetes Benchmark e outras políticas de segurança.

**Problema que resolve:** Kubernetes tem uma superfície de ataque muito específica: API server exposto, pods privilegiados, RBAC mal configurado, segredos em variáveis de ambiente. KSPM automatiza a detecção desses problemas específicos de K8s.

**Exemplos:**
- Open-source: kube-bench (CIS benchmark), kube-hunter (penetration testing), OPA Gatekeeper (preventivo)
- Comerciais: Wiz (KSPM integrado), Prisma Cloud, Sysdig Secure

---

### 1.8 DSPM — Data Security Posture Management

**Definição precisa:** Descobre, classifica e monitora dados sensíveis espalhados em ambientes cloud (buckets S3, Azure Blob, BigQuery, bancos de dados, data lakes) — identificando dados expostos, mal classificados ou sem controles adequados.

**Problema que resolve:** Uma organização não pode proteger o que não sabe que tem. O Banco Meridian pode ter PII de clientes em um bucket S3 criado por um desenvolvedor há 3 anos, esquecido, sem criptografia e sem logging. DSPM descobre esses repositórios de dados "esquecidos" e avalia o risco.

**Exemplos:**
- Comerciais: Wiz DSPM, Varonis, Dig Security, Cyera, BigID

---

### 1.9 ASPM — Application Security Posture Management

**Definição precisa:** Agrega e correlaciona findings de múltiplas ferramentas de segurança de aplicações (SAST, DAST, SCA, IaC scan, secret scan) em uma visão unificada, priorizando por risco de negócio.

**Problema que resolve:** Times de segurança recebem dezenas de milhares de findings de múltiplas ferramentas. Sem correlação, é impossível priorizar. ASPM normaliza, deduplica e prioriza esses findings, conectando vulnerabilidades de código ao contexto de produção.

**Exemplos:**
- Comerciais: Wiz Code, Apiiro, Armo, Ox Security, Legit Security

---

## 2. Por que as Categorias Existem — A Evolução Histórica

```
LINHA DO TEMPO DA SEGURANÇA CLOUD
───────────────────────────────────────────────────────────────────────────────

2010–2015: CLOUD NASCENTE
  → Primeira onda de migração para cloud
  → Times usavam ferramentas de segurança on-premises (não funcionavam bem)
  → Problema: "Quem mudou aquele Security Group?"
  → Solução emergente: CSPM (varredura de configuração)

2015–2018: CONTAINERS E DEVOPS
  → Docker e Kubernetes explodem em adoção
  → Containers têm CVEs, imagens baixadas sem verificação
  → Problema: "Que CVEs existem nessa imagem de produção?"
  → Solução emergente: CWPP + Image scanners

2018–2020: EXPLOSÃO DE IDENTIDADES
  → Microsserviços = centenas de service accounts
  → Cada Lambda, pod, EC2 com uma role IAM
  → Problema: "Essa role tem muito mais acesso do que deveria"
  → Solução emergente: CIEM

2020–2022: SHADOW IT E SaaS
  → Pandemia acelerou adoção de SaaS corporativo e pessoal
  → Dados sensíveis saindo via apps não aprovadas
  → Problema: "Colaboradores estão usando Dropbox pessoal com dados de clientes"
  → Solução emergente: CASB + SSE

2022–2025: CONVERGÊNCIA → CNAPP
  → 12+ consoles diferentes, sem correlação
  → Attackers exploram combinações de problemas
  → Problema: "Temos 50.000 findings. Qual é realmente crítico?"
  → Solução: CNAPP — plataforma unificada com correlation engine
```

---

## 3. A Convergência para CNAPP

### 3.1 O Problema das Ferramentas Pontuais

Um ambiente cloud típico de uma fintech brasileira tem, em média:
- 1 ferramenta de CSPM
- 1 ferramenta de image scanning
- 1 ferramenta de DAST
- 1 ferramenta de secrets scanning
- 1 ferramenta de SAST
- 1 ferramenta de runtime protection
- 1 ferramenta de CIEM

Cada ferramenta tem seu próprio console, seu próprio formato de findings, sua própria priorização. Não há correlação entre elas.

### 3.2 O Conceito de "Toxic Combination"

O poder do CNAPP está na correlação. Considere este cenário real:

```
FINDING INDIVIDUAL (cada ferramenta vê um pedaço):
  CSPM:    EC2 instance com porta 8080 exposta para 0.0.0.0/0 → MEDIUM
  CWPP:    EC2 instance com Log4Shell (CVE-2021-44228) → HIGH
  CIEM:    Role IAM da EC2 tem s3:* e iam:* → HIGH

TOXIC COMBINATION (CNAPP correlaciona):
  A MESMA EC2 está exposta + tem Log4Shell + tem role de admin IAM
  → Se comprometida, o atacante tem acesso a todos os S3 buckets e pode criar novos usuários IAM
  → CRÍTICO — precisa de remediação IMEDIATA
```

### 3.3 Razões Estratégicas para a Convergência

| Razão | Descrição |
|:------|:----------|
| **Redução de sprawl** | Uma plataforma vs 6–8 ferramentas: menos contratos, menos treinamento, menos integrações |
| **Correlação de dados** | Findings isolados vs attack path analysis que conecta os pontos |
| **Priorização inteligente** | Risk-based prioritization em vez de flood de findings sem contexto |
| **Cobertura do ciclo** | Code → Build → Deploy → Runtime cobertos na mesma plataforma |
| **ROI** | TCO de 1 plataforma CNAPP pode ser menor que 5 ferramentas pontuais |

---

## 4. Build vs Buy — Análise de TCO para Cloud Security Tools

### 4.1 Quando Construir com Open-Source

**Faz sentido quando:**
- Organização tem equipe de segurança madura (5+ engenheiros dedicados)
- Orçamento de segurança é limitado mas há capacidade de engenharia
- Necessidade de customização profunda (políticas muito específicas do negócio)
- Requisito regulatório de soberania de dados (não pode enviar dados para SaaS externo)

**Stack open-source equivalente ao CNAPP:**

| Função | Ferramenta | Esforço de Integração |
|:-------|:-----------|:---------------------:|
| CSPM | Prowler v4 | Médio |
| Image scan | Trivy | Baixo |
| IaC scan | Checkov | Baixo |
| Runtime | Falco | Alto |
| CIEM | IAM Access Analyzer (nativo AWS) | Baixo |
| Policy | OPA Gatekeeper | Alto |
| SBOM | Syft | Baixo |
| Orquestração | Defect Dojo + scripts | Muito Alto |

**Custo real do open-source (organização com 200 recursos cloud):**

```
CUSTO ANUAL ESTIMADO — STACK OPEN-SOURCE
───────────────────────────────────────────────────────
Infra para rodar as ferramentas (EC2, armazenamento):  R$ 24.000/ano
Engenheiro dedicado para manutenção (50% do tempo):   R$ 80.000/ano
Integrações e automações:                              R$ 30.000/ano
Treinamento e atualização:                             R$ 10.000/ano
─────────────────────────────────────────────────────
TOTAL:                                                 R$ 144.000/ano
(Não inclui o custo de oportunidade de não ter correlação entre ferramentas)
```

### 4.2 Quando Comprar Plataforma Comercial

**Faz sentido quando:**
- Organização tem equipe pequena de segurança (1–3 pessoas)
- Velocidade de time-to-value é crítica (auditoria chegando, precisa de postura visível rápido)
- Cobertura multi-cloud é necessária (AWS + Azure + GCP na mesma visão)
- Compliance com frameworks múltiplos (CIS + SOC2 + BACEN + LGPD simultaneamente)

**Custo estimado de plataformas CNAPP comerciais (referência 2025):**

| Plataforma | Modelo de Preço | Estimativa Anual (200 workloads) |
|:-----------|:----------------|:---------------------------------|
| Wiz | Por workload/mês | USD 80.000–120.000 |
| Prisma Cloud | Por crédito | USD 60.000–100.000 |
| Orca Security | Por asset/mês | USD 50.000–80.000 |
| Defender for Cloud | Pay-as-you-go + planos | USD 30.000–70.000 |
| Lacework | Por GB de dados + workloads | USD 60.000–90.000 |

### 4.3 Framework de Decisão Build vs Buy

```
FLUXO DE DECISÃO — BUILD VS BUY

Início: Preciso de cloud security tooling
   │
   ├─→ Tenho auditoria do BACEN nos próximos 6 meses?
   │      Sim → BUY (time-to-value crítico)
   │
   ├─→ Minha equipe tem < 3 engenheiros de segurança?
   │      Sim → BUY (capacidade operacional insuficiente)
   │
   ├─→ Preciso de cobertura multi-cloud (AWS + Azure)?
   │      Sim → considere BUY (integração nativa é vantagem)
   │
   ├─→ Tenho requisito de soberania de dados?
   │      Sim → BUILD (dados não saem da minha infra)
   │
   ├─→ Tenho equipe madura e orçamento limitado?
   │      Sim → BUILD com open-source (Prowler + Trivy + Falco)
   │
   └─→ Todos os outros casos → análise de TCO detalhada
```

---

## 5. Critérios de Seleção de Ferramentas de Cloud Security

Ao avaliar qualquer ferramenta para o Banco Meridian ou qualquer organização, use este framework de 7 critérios:

### 5.1 Critérios Técnicos

| Critério | O que Avaliar | Peso |
|:---------|:-------------|:----:|
| **Cobertura de cloud providers** | AWS + Azure + GCP native? Kubernetes? SaaS? | Alto |
| **Profundidade de checks** | Quantos checks? Framework coverage (CIS, NIST, LGPD)? | Alto |
| **Integrações SIEM/SOAR** | Splunk, Microsoft Sentinel, Google SecOps, XSOAR, Shuffle? | Médio |
| **False positive rate** | Qual a taxa de falsos positivos? Customizável? | Alto |
| **Agent vs Agentless** | Agentless é preferível (menor overhead operacional) | Médio |
| **API e automação** | API REST completa? Terraform provider? SDK? | Médio |
| **Performance** | Tempo de scan, impacto em produção, frequência máxima | Médio |

### 5.2 Critérios de Negócio

| Critério | O que Avaliar | Peso |
|:---------|:-------------|:----:|
| **Custo total (TCO)** | Licença + infra + operação + treinamento | Alto |
| **Suporte** | SLA, idioma (pt-BR disponível?), tier de suporte | Médio |
| **Maturidade do vendor** | Anos no mercado, base de clientes, quadrante Gartner | Médio |
| **Referências no Brasil** | Clientes brasileiros, especialmente no setor financeiro | Alto |
| **Roadmap** | Alinhamento do roadmap com necessidades futuras | Baixo |
| **Dados no Brasil** | Região de dados disponível no Brasil? LGPD compliance? | Alto |

---

## 6. Contexto Regulatório Brasileiro — Como a Regulação Influencia a Escolha de Ferramentas

### 6.1 Resolução BACEN 4.893/2021

**Impacto direto na seleção de ferramentas:**

A Resolução 4.893 exige que Instituições Financeiras (IFs) mantenham:
- Política de segurança da informação documentada
- Registro de incidentes com evidência de detecção
- Testes periódicos de vulnerabilidade
- Gestão de acessos privilegiados
- Monitoramento contínuo

**Como isso mapeia para ferramentas:**

| Requisito BACEN 4.893 | Ferramenta Indicada | Evidência Gerada |
|:----------------------|:--------------------|:-----------------|
| Art. 5º - Testes de vulnerabilidade periódicos | Prowler + Trivy | Relatório PDF/HTML com findings |
| Art. 6º - Monitoramento contínuo | CSPM com alertas | Logs de eventos e alertas em SIEM |
| Art. 8º - Gestão de acessos | CIEM (IAM Access Analyzer) | Relatório de permissões excessivas |
| Art. 9º - Incidentes: registro e reporte | Falco → SIEM → SOAR | Logs de eventos com timestamp |
| Art. 10º - Plano de continuidade | Checkov + IaC review | Políticas de DR como código |

### 6.2 CMN 4.658/2018

Resolução específica para serviços de processamento e armazenamento de dados em cloud por IFs.

**Requisito crítico:** Art. 16 — dados de clientes não podem ser armazenados fora do território nacional sem aprovação prévia do BACEN. Isso impacta diretamente:
- Escolha de região de dados das ferramentas CNAPP (deve ser sa-east-1 ou Brazil South)
- Ferramentas SaaS que processam dados de configuração devem ter contrato de processamento de dados

### 6.3 LGPD (Lei 13.709/2018)

**Impacto:**
- DSPM é quase mandatório para organizações que processam dados pessoais em cloud
- Qualquer ferramenta que scaneie dados em buckets S3 ou bancos de dados precisa de base legal
- Relatórios de CSPM/CWPP podem conter dados pessoais — precisam de controles de acesso

---

## 7. Diagrama ASCII — Ecossistema de Ferramentas de Cloud Security

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              ECOSSISTEMA DE CLOUD SECURITY TOOLS — 2025                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────┐    ║
║  │                         C N A P P                                   │    ║
║  │          (Cloud-Native Application Protection Platform)             │    ║
║  │                                                                     │    ║
║  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │    ║
║  │  │  C S P M │  │  C W P P │  │  C I E M │  │  I a C   │           │    ║
║  │  │ Postura  │  │ Workload │  │ Entitle- │  │ Security │           │    ║
║  │  │  Cloud   │  │ Runtime  │  │  ments   │  │  Scan    │           │    ║
║  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │    ║
║  │                                                                     │    ║
║  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │    ║
║  │  │  K S P M │  │  D S P M │  │  A S P M │  │ Secrets  │           │    ║
║  │  │  K8s     │  │  Data    │  │   App    │  │  Mgmt    │           │    ║
║  │  │ Security │  │ Security │  │ Security │  │  (Vault) │           │    ║
║  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │    ║
║  └─────────────────────────────────────────────────────────────────────┘    ║
║                                                                              ║
║  ┌──────────────────────────────┐  ┌─────────────────────────────────┐      ║
║  │     ACESSO E IDENTIDADE      │  │    PROTEÇÃO DE BORDA (SSE)      │      ║
║  │                              │  │                                 │      ║
║  │  ┌──────────┐  ┌──────────┐  │  │  ┌──────────┐  ┌──────────┐   │      ║
║  │  │   CIEM   │  │   PAM    │  │  │  │   CASB   │  │   ZTNA   │   │      ║
║  │  │ (cloud)  │  │ (híbrido)│  │  │  │  SaaS    │  │  VPN     │   │      ║
║  │  └──────────┘  └──────────┘  │  │  │  Shadow  │  │  Replace │   │      ║
║  └──────────────────────────────┘  │  └──────────┘  └──────────┘   │      ║
║                                    └─────────────────────────────────┘      ║
║                                                                              ║
║  PLATAFORMAS CLOUD (WHERE THESE TOOLS OPERATE)                              ║
║  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐            ║
║  │    AWS     │  │   Azure    │  │    GCP     │  │ Kubernetes │            ║
║  └────────────┘  └────────────┘  └────────────┘  └────────────┘            ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Tabela Comparativa das Categorias

| Categoria | Foco Principal | Problema que Resolve | Exemplos Open-Source | Exemplos Comerciais | Integração com BACEN 4.893 |
|:----------|:--------------|:---------------------|:--------------------:|:-------------------:|:--------------------------|
| **CNAPP** | Plataforma unificada | Silos de segurança, falta de correlação | Combinação de ferramentas | Wiz, Prisma Cloud, Orca | Visão unificada para relatórios |
| **CSPM** | Configuração de recursos cloud | Misconfigurations, exposições | Prowler, ScoutSuite | Wiz, Prisma Cloud | Art. 5º — testes de vulnerabilidade |
| **CWPP** | Workloads em execução | CVEs em VMs/containers, runtime threats | Trivy, Falco, Grype | Sysdig, Aqua | Art. 9º — monitoramento |
| **CIEM** | Identidades e permissões | Permissões excessivas, privilege escalation | IAM Access Analyzer | Wiz CIEM, Ermetic | Art. 8º — gestão de acessos |
| **CASB** | Acesso a SaaS | Shadow IT, DLP, dados vazando | — | Netskope, Zscaler ZIA | Art. 6º — monitoramento contínuo |
| **SSE/ZTNA** | Acesso à rede | VPN tradicional, lateral movement | Headscale (WireGuard) | Zscaler ZPA, Cloudflare One | Art. 6º — controle de acesso |
| **KSPM** | Clusters Kubernetes | Misconfigs K8s, pods privilegiados | kube-bench, OPA | Wiz, Prisma Cloud | Art. 5º — testes de vulnerabilidade |
| **DSPM** | Dados em cloud | PII exposta, dados não classificados | — | Wiz DSPM, Varonis | LGPD Art. 46 — segurança de dados |
| **ASPM** | Postura de aplicações | Flood de findings sem priorização | Defect Dojo | Wiz Code, Apiiro | Art. 5º — gestão de vulnerabilidades |
| **Secrets Mgmt** | Credenciais e segredos | Hardcoded secrets, rotação manual | HashiCorp Vault, Infisical | AWS Secrets Manager, Azure KV | Art. 8º — gestão de acessos |

---

## 9. Atividades de Fixação

### Questão 1
O Banco Meridian recebeu um alerta: um desenvolvedor criou um bucket S3 com dados de clientes sem criptografia e sem restrição de acesso público. Qual categoria de ferramenta de cloud security é mais indicada para detectar esse tipo de problema continuamente?

**a)** CWPP — Cloud Workload Protection Platform  
**b)** CASB — Cloud Access Security Broker  
**c)** CSPM — Cloud Security Posture Management  
**d)** CIEM — Cloud Infrastructure Entitlement Management  

**Gabarito: c)**  
Justificativa: CSPM monitora continuamente a configuração dos recursos cloud (como S3 buckets) contra benchmarks de segurança. Um bucket público sem criptografia é uma misconfiguration de configuração — exatamente o domínio do CSPM. CWPP protege o workload dentro da instância (não a configuração do serviço). CASB protege o acesso a aplicações SaaS. CIEM gerencia identidades e permissões.

---

### Questão 2
Um atacante comprometeu uma instância EC2 e está executando comandos dentro de um container em produção. Qual ferramenta de código aberto é mais indicada para detectar esse comportamento em tempo real?

**a)** Prowler  
**b)** Falco  
**c)** Checkov  
**d)** kube-bench  

**Gabarito: b)**  
Justificativa: Falco é uma ferramenta de runtime security que usa eBPF/kernel modules para detectar comportamentos suspeitos em containers e VMs em tempo real — como execução de shell em container, escrita em diretórios sensíveis, ou conexões de rede inesperadas. Prowler é CSPM (configuração). Checkov é IaC scanner (antes do deploy). kube-bench verifica conformidade CIS em clusters K8s (não monitora runtime).

---

### Questão 3
Qual é o principal diferencial de uma plataforma CNAPP em relação ao uso de ferramentas pontuais de CSPM + CWPP + CIEM separadas?

**a)** CNAPP tem mais checks individuais do que ferramentas especializadas  
**b)** CNAPP é sempre mais barato do que ferramentas open-source  
**c)** CNAPP correlaciona findings de múltiplas categorias para identificar toxic combinations  
**d)** CNAPP substitui a necessidade de SIEM e SOAR  

**Gabarito: c)**  
Justificativa: A principal vantagem do CNAPP é a correlação. Uma misconfiguration + uma CVE + uma permissão excessiva na mesma instância individualmente podem ser MEDIUM, mas correlacionadas formam um caminho de ataque crítico (toxic combination). Ferramentas pontuais não se comunicam entre si. CNAPP não é necessariamente mais barato nem substitui SIEM/SOAR.

---

### Questão 4
O artigo 16 da Resolução CMN 4.658/2018 impacta diretamente qual aspecto da seleção de ferramentas de cloud security para bancos brasileiros?

**a)** O modelo de licenciamento (por workload vs por usuário)  
**b)** A localização geográfica onde os dados escaneados são processados e armazenados  
**c)** O número máximo de checks que a ferramenta pode executar  
**d)** A obrigatoriedade de usar apenas ferramentas open-source  

**Gabarito: b)**  
Justificativa: A CMN 4.658 restringe o armazenamento e processamento de dados de clientes fora do território nacional sem aprovação do BACEN. Ferramentas SaaS de cloud security (CNAPP, CSPM) que processam dados de configuração ou conteúdo dos workloads precisam ter seus data centers localizados no Brasil (região sa-east-1 da AWS ou Brazil South do Azure), ou ter um contrato de processamento de dados aprovado.

---

### Questão 5
Uma startup de fintech com equipe de segurança de 2 pessoas precisa implementar segurança cloud básica com orçamento limitado. Qual stack open-source mínimo viável cobre CSPM + CWPP + IaC security?

**a)** Vault + Consul + Nomad  
**b)** Prowler + Trivy + Checkov  
**c)** OPA Gatekeeper + kube-bench + Falco  
**d)** Netskope + Zscaler + Prisma Cloud  

**Gabarito: b)**  
Justificativa: Prowler (CSPM — scans configuração AWS/Azure/GCP), Trivy (CWPP — scans imagens de container e IaC), e Checkov (IaC security — scans Terraform/CloudFormation antes do deploy). Essa combinação cobre as três categorias mais críticas com ferramentas gratuitas e de fácil configuração inicial. OPA Gatekeeper + kube-bench + Falco é um bom stack mas focado em K8s, não cobre CSPM e IaC para nuvem em geral. Vault/Consul/Nomad é infraestrutura, não security tooling. Netskope/Zscaler/Prisma Cloud são soluções comerciais caras.

---

## 10. Roteiro de Gravação — Aula 1.1: Panorama e Taxonomia Gartner (55 min)

### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Panorama e Taxonomia Gartner de Cloud Security Tools 2025 |
| **Duração** | 55 minutos |
| **Formato** | Talking head + slides + diagrama interativo |
| **Ferramentas** | Slides com diagrama animado das categorias |

---

### ROTEIRO COMPLETO — em primeira pessoa

---

**[00:00 – 02:00 | ABERTURA | Talking head | Corte rápido após apresentação]**

Olá e seja muito bem-vindo ao Curso 4 do programa de Formação em Security Operations em Nuvem da CECyber. Eu sou [nome do instrutor], e neste primeiro módulo vamos estabelecer o mapa mental que vai guiar todo o curso.

Se você chegou até aqui, provavelmente já ouviu termos como CSPM, CWPP, CNAPP, CASB, SSE… e talvez tenha ficado se perguntando: isso é tudo a mesma coisa? São ferramentas diferentes? Por onde começo?

A resposta curta é: são categorias distintas de ferramentas que resolvem problemas diferentes de segurança cloud. E nesta aula, vou te mostrar um mapa completo desse ecossistema — a taxonomia oficial do Gartner para 2025 — para que você entenda exatamente o que cada categoria faz, por que ela existe, e quando você precisa dela.

Ao final desta aula, você vai conseguir olhar para qualquer ferramenta de cloud security e saber imediatamente em qual categoria ela se encaixa e qual problema ela resolve.

Bora lá.

---

**[02:00 – 08:00 | CONTEXTO HISTÓRICO | Slides com linha do tempo | Tela cheia]**

*[Dica de edição: use animação de linha do tempo entrando da esquerda para a direita]*

Antes de entrar nas categorias, deixa eu te mostrar por que elas existem. O mercado de segurança cloud não surgiu com essas categorias todas de uma vez — elas foram surgindo em resposta a problemas reais que foram aparecendo ao longo da adoção de cloud.

Em 2010 a 2015, as empresas estavam começando a migrar para a nuvem. O principal problema era simples: alguém mudava uma configuração de Security Group, deixava uma porta 22 aberta para o mundo, e ninguém sabia até acontecer um incidente. A resposta foi o CSPM — ferramentas que varrem continuamente as configurações dos recursos cloud e alertam quando algo está fora do padrão.

*[Aponta para o diagrama de linha do tempo]*

Entre 2015 e 2018, Docker e Kubernetes explodiram em adoção. As imagens de container vinham com dezenas ou centenas de CVEs no sistema operacional base. O problema mudou: não era mais só "a configuração está errada", era "tem uma vulnerabilidade grave rodando em produção nesse container". Surgiu o CWPP — ferramentas que olham para dentro dos workloads em execução.

De 2018 a 2020, a proliferação de microsserviços criou outro problema: cada Lambda, cada pod Kubernetes, cada EC2 tem uma identidade, uma role IAM com permissões. E 95% dessas identidades têm muito mais acesso do que precisam. Se um atacante comprometer qualquer uma delas, pode se mover lateralmente por toda a infraestrutura. Surgiu o CIEM para gerenciar esse caos de entitlements.

A pandemia de 2020 acelerou outro problema: colaboradores usando dezenas de aplicações SaaS não aprovadas, carregando dados sensíveis de clientes para Dropbox pessoal ou WeTransfer. O CASB surgiu para dar visibilidade e controle sobre esse shadow IT.

E chegamos em 2022–2025, onde o problema ficou ainda mais complexo: as empresas tinham 8, 10, 12 ferramentas diferentes, cada uma com seu próprio console, sem nenhuma correlação entre elas. Um atacante explora a combinação de uma misconfiguration + uma CVE + uma permissão excessiva — e cada ferramenta isolada via apenas um pedaço do quebra-cabeça. Surgiu o CNAPP, a plataforma unificada que conecta todos esses pontos.

---

**[08:00 – 25:00 | TAXONOMIA COMPLETA | Slides com diagrama animado | Tela cheia]**

*[Dica de edição: para cada categoria, fade in do card no diagrama enquanto fala sobre ela]*

Agora vamos ver cada categoria em detalhe. Tenho aqui um diagrama do ecossistema completo — vou percorrer cada uma.

**CSPM — Cloud Security Posture Management**

*[Clique: aparece card CSPM no diagrama]*

CSPM é a base de tudo. Pensa assim: o CSPM é o auditor de configuração da sua nuvem. Ele vai em todos os seus recursos — EC2, S3, RDS, Azure VMs, GCP Storage — e verifica se cada um está configurado corretamente de acordo com os benchmarks de segurança: CIS, NIST, e no caso do Banco Meridian, também BACEN 4.893 e LGPD.

Um S3 bucket público? CSPM encontra. Uma regra de Security Group com porta 22 aberta para 0.0.0.0/0? CSPM encontra. Um banco de dados sem backup habilitado? CSPM encontra. Isso é configuração — e configuração é o domínio do CSPM.

A ferramenta open-source mais usada para CSPM é o Prowler, versão 4. Vamos trabalhar muito com ele nos laboratórios. No mundo comercial, toda grande plataforma CNAPP inclui CSPM como componente central.

**CWPP — Cloud Workload Protection Platform**

*[Clique: aparece card CWPP]*

Se o CSPM olha para a configuração dos serviços, o CWPP olha para o que está rodando dentro. A analogia: CSPM verifica se a porta da sua casa está trancada. CWPP verifica o que está acontecendo dentro da casa.

CWPP cobre duas grandes áreas: vulnerability management — escanear imagens de container e VMs em busca de CVEs em pacotes do OS e dependências de aplicação — e runtime protection — detectar comportamentos maliciosos enquanto o workload está em execução.

Para image scanning vamos usar Trivy. Para runtime protection, o Falco. Ambos open-source e excelentes.

**CIEM — Cloud Infrastructure Entitlement Management**

*[Clique: aparece card CIEM]*

Esse é o que mais pega as pessoas de surpresa. Em cloud, o problema de identidade é radicalmente diferente do on-premises. Em um datacenter tradicional, você tem um número gerenciável de usuários e serviços. Em cloud, você tem centenas de service accounts, instance profiles, Lambda execution roles, pod identities — cada uma com permissões que foram sendo acumuladas ao longo do tempo.

O princípio de menor privilégio é quase impossível de manter manualmente nessa escala. E as consequências de permissões excessivas são enormes: um atacante que compromete qualquer uma dessas identidades pode se mover lateralmente ou escalar privilégios.

CIEM automatiza o processo de identificar quem tem permissão para fazer o quê, comparar com o que realmente foi usado nos últimos 90 dias, e recomendar a redução para o mínimo necessário. A AWS tem o IAM Access Analyzer que faz parte disso de forma nativa. Vamos explorar no laboratório 6.

**CASB — Cloud Access Security Broker**

*[Clique: aparece card CASB]*

CASB resolve um problema muito humano: as pessoas vão usar aplicações SaaS, aprovadas ou não. O CASB senta entre o usuário e as aplicações cloud, monitorando o que está sendo acessado e o que está sendo transferido.

Shadow IT discovery — saber que seus colaboradores estão usando 340 aplicações SaaS, sendo que o TI aprovou apenas 40. Data Loss Prevention — detectar e bloquear quando alguém tenta fazer upload de um arquivo com dados de clientes para um repositório pessoal.

As principais soluções são Netskope, Zscaler Internet Access, e Microsoft Defender for Cloud Apps.

**SSE — Security Service Edge**

*[Clique: aparece card SSE]*

SSE é a evolução natural do CASB, convergindo com SWG e ZTNA. O problema que resolve: VPNs tradicionais são binárias — ou você está dentro da rede (e tem acesso a tudo) ou está fora. Isso não faz sentido em um mundo de cloud e trabalho remoto.

SSE implementa Zero Trust Network Access: acesso baseado em identidade, dispositivo, aplicação específica e contexto — não em "estar dentro da rede". Um colaborador autentica, comprova que o dispositivo está saudável, e ganha acesso apenas à aplicação específica de que precisa, por aquela sessão.

**KSPM — Kubernetes Security Posture Management**

*[Clique: aparece card KSPM]*

KSPM é CSPM especializado para Kubernetes. K8s tem uma superfície de ataque muito específica: API server exposto, pods com hostPath mounts, RBAC mal configurado, secrets em variáveis de ambiente, namespaces sem NetworkPolicy.

O kube-bench executa os checks do CIS Kubernetes Benchmark e mostra exatamente o que está fora do padrão. O OPA Gatekeeper e o Kyverno atuam de forma preventiva, bloqueando recursos que violam políticas antes mesmo de serem criados.

**DSPM — Data Security Posture Management**

*[Clique: aparece card DSPM]*

Mais novo do que os anteriores, o DSPM resolve um problema fundamental: você não pode proteger dados que não sabe que tem. O DSPM descobre automaticamente onde seus dados sensíveis estão espalhados em cloud — S3 buckets, Azure Blob Storage, BigQuery, bancos de dados — classifica o tipo de dado (PII, PCI, dados de saúde) e avalia o risco de cada repositório.

Para instituições financeiras com LGPD, esse é cada vez mais crítico.

**ASPM — Application Security Posture Management**

*[Clique: aparece card ASPM]*

Por último, ASPM agrega e normaliza findings de múltiplas ferramentas de AppSec — SAST, DAST, SCA, IaC scan, secrets scanning — dando uma visão unificada priorizada por risco de negócio, não por volume de vulnerabilidades. Se você tem 50.000 findings, ASPM te diz qual é realmente crítico no contexto de produção.

---

**[25:00 – 35:00 | CONVERGÊNCIA PARA CNAPP | Slides + whiteboard | Tela cheia]**

*[Dica de edição: use um quadro branco virtual para desenhar a correlação ao vivo]*

Agora que você conhece todas as categorias, vamos falar sobre por que o mercado está convergindo para o CNAPP.

Imagine que você é o CISO do Banco Meridian. Você tem uma equipe de 4 analistas. Cada analista está olhando para um console diferente: um para Prowler, um para Trivy, um para IAM Access Analyzer, um para Falco. Cada ferramenta gera seus próprios alertas.

Um dia, você recebe esses três alertas — em ferramentas diferentes, sem correlação:

*[Mostra slide com os três alertas separados]*

- Prowler: EC2 instance i-0abc123 com porta 8080 exposta → MEDIUM
- Trivy: imagem Docker na i-0abc123 tem CVE-2021-44228 Log4Shell → HIGH  
- IAM Access Analyzer: role anexada à i-0abc123 tem permissão s3:* e iam:* → HIGH

Individualmente, cada um desses findings tem prioridade média ou alta. Mas a pergunta crítica é: esses três problemas estão na mesma instância?

Se sim, você tem uma toxic combination: a instância está exposta, tem uma CVE exploitável remotamente, e se comprometida, dá ao atacante acesso a todos os S3 buckets e a capacidade de criar usuários IAM. Isso é crítico — precisa ser remediado hoje, antes do fim do dia.

*[Mostra slide com as ferramentas conectadas]*

Isso é o que o CNAPP faz: correlaciona automaticamente findings de múltiplas categorias para identificar essas combinações tóxicas. Sem correlação, você tem 50.000 findings. Com correlação, você tem 3 findings verdadeiramente críticos para remediar hoje.

---

**[35:00 – 45:00 | BUILD VS BUY | Slides com tabela | Tela cheia]**

*[Dica de edição: use efeito de split-screen para comparar os dois lados]*

Uma pergunta que todo arquiteto de segurança enfrenta: devo construir minha própria stack de ferramentas open-source ou comprar uma plataforma CNAPP comercial?

A resposta honesta é: depende do seu contexto. Mas vou te dar um framework para pensar nisso.

*[Mostra tabela de critérios]*

Se você tem uma auditoria do BACEN chegando em 6 meses, a resposta é quase sempre comprar — o time-to-value de uma plataforma comercial é de semanas, não meses. Você não tem tempo de montar um stack open-source, integrá-lo, treinar a equipe.

Se você tem uma equipe de segurança com menos de 3 pessoas, a resposta também tende para comprar — você não tem capacidade operacional para manter um stack open-source complexo.

Mas se você tem requisito de soberania de dados — dados que não podem sair da sua infraestrutura — a resposta pode ser construir, porque você não consegue usar um SaaS externo.

E se você tem uma equipe madura e orçamento limitado, construir com open-source pode fazer sentido econômico. Mas cuidado: o custo de um engenheiro dedicado a manter a stack open-source pode superar o custo da licença comercial.

Vou mostrar números reais de TCO mais adiante no módulo. Por ora, o ponto principal é: essa não é uma decisão técnica — é uma decisão de negócio que considera tempo, capacidade, orçamento e requisitos regulatórios.

---

**[45:00 – 50:00 | CONTEXTO REGULATÓRIO BRASILEIRO | Slides | Tela cheia]**

*[Dica de edição: destaque visual nos artigos da lei]*

Para fechar, um ponto que não pode ser ignorado se você trabalha no setor financeiro brasileiro: a regulação.

A Resolução BACEN 4.893 de 2021 é a referência principal para segurança de TI em Instituições Financeiras. Ela exige testes periódicos de vulnerabilidade — que é exatamente o que Prowler e Trivy entregam. Ela exige monitoramento contínuo — Falco e CSPM. Ela exige gestão de acessos privilegiados — CIEM.

A CMN 4.658 de 2018 tem um artigo crítico para a seleção de ferramentas: dados de clientes não podem ser processados fora do Brasil sem aprovação prévia do BACEN. Isso significa que quando você escolher uma ferramenta CNAPP SaaS, precisa verificar se ela tem data center no Brasil ou se o contrato de processamento de dados está adequado para LGPD e BACEN.

Não escolha uma ferramenta de segurança cloud sem verificar esses requisitos regulatórios. Essa é uma diferença importante entre o contexto brasileiro e o global.

---

**[50:00 – 55:00 | RECAPITULAÇÃO E PRÓXIMOS PASSOS | Talking head]**

*[Dica de edição: volte para talking head, tom mais relaxado]*

Muito bem, vamos recapitular o que vimos hoje.

Vimos a taxonomia completa de 9 categorias de ferramentas de cloud security — CNAPP, CSPM, CWPP, CIEM, CASB, SSE, KSPM, DSPM e ASPM — cada uma resolvendo um problema específico que foi surgindo à medida que a adoção de cloud evoluiu.

Entendemos por que o mercado está convergindo para CNAPP: a correlação entre categorias é o que transforma 50.000 findings individuais em 3 toxic combinations verdadeiramente críticas.

Discutimos o framework Build vs Buy, lembrando que é uma decisão de negócio, não apenas técnica.

E vimos como a regulação brasileira — BACEN 4.893 e CMN 4.658 — influencia diretamente a seleção de ferramentas, especialmente em relação à localização de dados.

No próximo módulo, vamos mergulhar fundo no CSPM — como funciona, como executar o Prowler v4 na prática, e como apresentar um relatório de postura de segurança para o CISO.

Antes de ir, faça as atividades de fixação — são 5 questões que vão solidificar esses conceitos. E no laboratório prático, você vai mapear a taxonomia para o ambiente específico do Banco Meridian.

Até o próximo módulo!

---

## 11. Avaliação do Módulo 01

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
Qual é a principal diferença entre CSPM e CWPP?

**a)** CSPM monitora configurações de recursos cloud; CWPP protege workloads em execução  
**b)** CSPM é mais caro que CWPP; por isso empresas pequenas escolhem CWPP  
**c)** CSPM é open-source e CWPP é sempre comercial  
**d)** CSPM funciona apenas na AWS; CWPP funciona em multi-cloud  

**Gabarito: a)** CSPM = configuração (plano de controle). CWPP = conteúdo e comportamento do workload (plano de dados). A diferença é o objeto de análise: "como o recurso está configurado" vs "o que está acontecendo dentro do recurso".

---

**Questão 2 (10 pts)**  
Uma organização quer identificar automaticamente quais service accounts AWS têm permissões que não foram usadas nos últimos 90 dias para aplicar o princípio de menor privilégio. Qual categoria de ferramenta resolve isso?

**a)** CASB  
**b)** DSPM  
**c)** CIEM  
**d)** KSPM  

**Gabarito: c)** CIEM — Cloud Infrastructure Entitlement Management — é especificamente a categoria que gerencia identidades e entitlements em cloud, incluindo a análise de permissões não utilizadas (unused access analysis) para implementação de least privilege.

---

**Questão 3 (10 pts)**  
O conceito de "toxic combination" é um diferencial central das plataformas CNAPP. O que esse conceito significa?

**a)** Uma vulnerabilidade com score CVSS acima de 9.0 em um sistema de produção crítico  
**b)** A correlação de múltiplos findings individuais de baixo/médio risco que juntos formam um caminho de ataque crítico  
**c)** Uma misconfiguration que afeta simultaneamente mais de um provedor de cloud  
**d)** A combinação de ferramentas open-source que substituem uma plataforma CNAPP comercial  

**Gabarito: b)** Toxic combination é a correlação entre findings de diferentes categorias (ex: misconfiguration + CVE + permissão excessiva na mesma instância) que individualmente seriam médios/altos mas juntos formam um caminho de ataque crítico que requer remediação imediata.

---

**Questão 4 (10 pts)**  
Qual artigo da Resolução CMN 4.658/2018 é mais relevante para a seleção de ferramentas CNAPP SaaS por instituições financeiras brasileiras?

**a)** Art. 3º — define os tipos de serviços de processamento em nuvem  
**b)** Art. 16 — restringe o armazenamento e processamento de dados de clientes fora do território nacional sem autorização prévia do BACEN  
**c)** Art. 7º — estabelece os requisitos mínimos de autenticação  
**d)** Art. 12 — define os SLAs mínimos de disponibilidade  

**Gabarito: b)** Art. 16 da CMN 4.658 é o artigo que impacta diretamente a escolha de ferramentas: qualquer CNAPP SaaS que processe dados de clientes precisa ter data center no Brasil ou aprovação prévia do BACEN. Isso elimina ou complica o uso de várias ferramentas estrangeiras que não têm região no Brasil.

---

**Questão 5 (10 pts)**  
Um banco brasileiro com equipe de segurança de 2 pessoas e auditoria BACEN programada para 4 meses precisa implementar cloud security tooling. Qual decisão Build vs Buy é mais adequada?

**a)** Build — montar stack completo open-source (Prowler + Trivy + Falco + OPA) porque é gratuito  
**b)** Buy — adquirir plataforma CNAPP comercial porque o time-to-value é compatível com o prazo da auditoria e a equipe pequena não suporta operação de stack open-source  
**c)** Híbrido — comprar CSPM comercial e usar Falco open-source para runtime  
**d)** Nenhuma — esperar a auditoria passar antes de investir em ferramentas  

**Gabarito: b)** Com equipe de 2 pessoas, prazo de 4 meses e auditoria do BACEN, a decisão correta é Buy. Uma plataforma CNAPP comercial tem time-to-value de semanas (não meses), equipe pequena não consegue operar e manter stack open-source de 5+ ferramentas, e a auditoria exige evidências de monitoramento contínuo que a plataforma comercial entrega mais rapidamente.

---

**Questão 6 (10 pts)**  
KSPM (Kubernetes Security Posture Management) é melhor descrito como:

**a)** Uma ferramenta de monitoramento de performance de clusters Kubernetes  
**b)** Um CSPM especializado que avalia configurações de clusters K8s contra benchmarks como CIS Kubernetes Benchmark  
**c)** Uma solução de runtime protection exclusiva para containers  
**d)** Um gerenciador de segredos integrado ao Kubernetes  

**Gabarito: b)** KSPM é CSPM especializado para K8s. Enquanto CSPM geral avalia recursos AWS/Azure/GCP, KSPM avalia especificamente recursos Kubernetes — configuração de API server, RBAC, PSS, NetworkPolicy — contra benchmarks como CIS Kubernetes Benchmark (executado pelo kube-bench).

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O Banco Meridian acaba de fazer uma aquisição e incorporou uma empresa de pagamentos que opera 100% na AWS. Essa empresa nunca investiu formalmente em cloud security. A auditoria do BACEN está prevista para daqui a 8 meses.

**Tarefa (4 perguntas, 10 pts cada):**

1. Mapeie as 5 categorias de ferramentas mais críticas para esse cenário específico e justifique cada escolha
2. Para cada categoria, indique uma ferramenta open-source e uma comercial viável
3. Dado o prazo de 8 meses e a necessidade de evidências para o BACEN, recomende Buy ou Build para cada categoria com justificativa
4. Identifique pelo menos 2 requisitos da Resolução BACEN 4.893 que cada categoria de ferramenta ajudará a evidenciar

**Gabarito:**

1. **Categorias críticas:**
   - **CSPM** — empresa nunca teve auditoria de configuração; buckets públicos, SGs abertos e não conformidades são prováveis
   - **CWPP (image scan)** — workloads desconhecidos com CVEs acumuladas
   - **CIEM** — permissões excessivas acumuladas ao longo do tempo sem revisão
   - **IaC Security** — não há garantia de que a infraestrutura foi criada com segurança
   - **Secrets Management** — hardcoded secrets são comuns em empresas sem processo formal

2. **Ferramentas:**
   - CSPM: Prowler (open) / Wiz ou Orca (comercial)
   - CWPP: Trivy (open) / Sysdig (comercial)
   - CIEM: IAM Access Analyzer (open/nativo) / Wiz CIEM (comercial)
   - IaC Security: Checkov (open) / Prisma Cloud Code Security (comercial)
   - Secrets Mgmt: HashiCorp Vault (open) / AWS Secrets Manager (comercial)

3. **Buy ou Build:**
   - Prazo de 8 meses é viável para Build se a equipe for ≥ 3 pessoas
   - Para evidências de auditoria: CSPM e CIEM devem ser priorizados (podem ser open-source com configuração inicial em 2–3 semanas)
   - Se equipe for pequena: Buy plataforma CNAPP (Wiz ou Orca) cobre CSPM + CWPP + CIEM em uma solução

4. **Mapeamento BACEN 4.893:**
   - CSPM → Art. 5º (testes de vulnerabilidade periódicos) + Art. 6º (monitoramento contínuo)
   - CWPP → Art. 5º (testes) + Art. 9º (registro de incidentes com evidência de detecção)
   - CIEM → Art. 8º (gestão de acessos privilegiados)
   - IaC Security → Art. 10º (plano de continuidade — infraestrutura como código revisada)
   - Secrets Mgmt → Art. 8º (gestão de credenciais e acessos)

---

*Módulo 01 — Panorama e Taxonomia das Ferramentas de Cloud Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
