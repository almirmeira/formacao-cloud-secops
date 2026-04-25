# Módulo 01 — Panorama e Taxonomia das Ferramentas de Cloud Security
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h videoaula + 1h live online
> **Certificação Alvo:** CCSP (ISC²) domínio 6 / CCSK (CSA) domínio 3
> **Cenário:** Banco Meridian iniciando avaliação de segurança cloud

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Definir com precisão cada categoria da taxonomia Gartner de Cloud Security Tools (2025)
2. Explicar o problema de segurança que cada categoria resolve, com exemplos práticos do Banco Meridian
3. Descrever a convergência para CNAPP e por que ela acontece agora
4. Conduzir uma análise Build vs Buy de ferramentas de cloud security com TCO realista
5. Aplicar critérios de seleção considerando o contexto regulatório brasileiro (BACEN 4.893, LGPD)

---

## 1. Taxonomia Gartner Cloud Security Tools — 2025

A taxonomia de ferramentas de cloud security foi consolidada pelo Gartner ao longo de uma década de evolução. Cada categoria surgiu como resposta a um problema específico que emergiu conforme a adoção de cloud cresceu. Entender a origem de cada categoria é fundamental para saber qual ferramenta usar em qual situação.

### 1.1 CNAPP — Cloud-Native Application Protection Platform

**Definição:** Plataforma unificada que converge CSPM, CWPP, CIEM, IaC security e code security em uma única console com correlação de dados. O termo foi cunhado pelo Gartner em 2021.

**Problema que resolve:** O problema da combinação tóxica. Um ambiente cloud típico pode ter uma EC2 com misconfiguration (Security Group aberto), uma CVE crítica no OS (Log4Shell), e uma role IAM excessivamente permissiva — tudo no mesmo servidor. Com ferramentas isoladas, você vê três findings separados. Com CNAPP, você vê um único alerta: "Esta EC2 está exposta + tem CVE exploitável remotamente + role IAM de admin — risco crítico imediato de comprometimento total."

**Por que é relevante para o Banco Meridian:** A auditoria do BACEN exige evidências de monitoramento contínuo (Art. 6) e avaliação de controles (Art. 5). Com CNAPP, o Banco Meridian consegue um console único com cobertura AWS + Azure + GCP, correlação de riscos e relatórios de conformidade prontos para auditoria.

**Exemplos comerciais:** Wiz, Prisma Cloud (Palo Alto Networks), Orca Security, Microsoft Defender for Cloud

---

### 1.2 CSPM — Cloud Security Posture Management

**Definição:** Categoria de ferramentas que avalia continuamente a configuração dos recursos cloud contra benchmarks de segurança estabelecidos (CIS, NIST, LGPD, BACEN), identificando misconfigurations, exposições públicas e desvios de política.

**Problema que resolve:** A misconfiguration acidental. Um S3 bucket público expondo dados de clientes, um Security Group com porta 22 aberta para 0.0.0.0/0, um banco de dados RDS sem criptografia — cada uma dessas configurações pode levar o Banco Meridian a uma multa do BACEN ou a um vazamento de dados. CSPM automatiza a detecção contínua desses erros sem precisar acessar o conteúdo dos dados.

**Foco:** Plano de controle — analisa as configurações via API, não o conteúdo dos workloads.

**Diferença crítica com CWPP:** CSPM pergunta "como esse recurso está configurado?" enquanto CWPP pergunta "o que está rodando dentro desse recurso e tem CVEs?".

**Exemplos open-source:** Prowler v4, ScoutSuite, CloudSploit
**Exemplos comerciais (integrados em CNAPP):** Wiz, Prisma Cloud, Orca, Defender for Cloud

---

### 1.3 CWPP — Cloud Workload Protection Platform

**Definição:** Categoria que protege os workloads em execução — VMs, containers, serverless functions — analisando vulnerabilidades (CVEs no OS e dependências) e comportamentos anômalos em runtime.

**Problema que resolve:** As vulnerabilidades dentro dos workloads. Um container pode estar rodando com uma versão de nginx que tem Log4Shell. O servidor pode ter pacotes de sistema desatualizados com CVEs críticas. Isso não é visível via API do provedor cloud (CSPM não detecta) — requer análise do filesystem ou monitoramento de syscalls.

**Duas dimensões do CWPP:**
- **Pré-deploy (static):** scan de imagens de container e pacotes de VMs para CVEs antes de ir para produção (Trivy, Grype, Snyk Container)
- **Runtime:** monitoramento comportamental em tempo real durante a execução (Falco com eBPF, Sysdig Secure, Aqua Security)

**Exemplos open-source:** Trivy, Falco, Grype, Syft (SBOM)
**Exemplos comerciais:** Sysdig Secure, Aqua Security, Prisma Cloud CWPP

---

### 1.4 CIEM — Cloud Infrastructure Entitlement Management

**Definição:** Categoria especializada no gerenciamento de identidades e permissões em ambientes cloud, onde cada Lambda, cada EC2, cada pod Kubernetes é uma identidade com permissões. O CIEM analisa o que cada identidade pode realmente fazer (effective permissions), identifica excessos e toxic combinations.

**Problema que resolve:** A explosão de identidades não-humanas. Uma empresa de médio porte tem 1.200+ identidades não-humanas em cloud (EC2 instance profiles, Lambda roles, K8s service accounts, CI/CD machine users). Pesquisas indicam que 95% dessas identidades têm mais permissões do que usam na prática. Uma role "inofensiva" com `iam:CreateUser` + `iam:AttachUserPolicy` é um shadow admin que pode comprometer toda a conta.

**Conceitos-chave:**
- **Effective permissions:** o que uma identidade realmente pode fazer considerando todas as policies, SCPs e boundaries
- **Permissions creep:** acúmulo gradual de permissões que nunca são removidas
- **Non-human identities (NHI):** service accounts, instance profiles, workload identities

**Exemplos:**
- AWS: IAM Access Analyzer (unused access + external access)
- Azure: Entra Permissions Management
- GCP: Policy Intelligence
- Comerciais multi-cloud: Wiz CIEM, Ermetic (Tenable), CyberArk Cloud Entitlements Manager

---

### 1.5 CASB — Cloud Access Security Broker

**Definição:** Ponto de controle de segurança entre os usuários da empresa e as aplicações cloud (SaaS, IaaS, PaaS). Monitora e controla o acesso a aplicações aprovadas e não aprovadas (shadow IT).

**Problema que resolve:** O shadow IT e a exfiltração de dados via SaaS. Um analista do Banco Meridian pode estar enviando planilhas com dados de clientes para o Google Sheets pessoal, ou usando o ChatGPT para resumir documentos confidenciais. Sem CASB, isso é invisível para o TI.

**Capacidades principais:** Shadow IT discovery, DLP (Data Loss Prevention), ATP (Advanced Threat Protection), session control, conditional access, SSPM (SaaS Security Posture Management).

**Exemplos comerciais:** Zscaler Internet Access (ZIA), Microsoft Defender for Cloud Apps, Netskope, Palo Alto Prisma Access

---

### 1.6 SSE — Security Service Edge / ZTNA — Zero Trust Network Access

**Definição:** SSE é o modelo de segurança de acesso à rede baseado em Zero Trust, substituindo VPN tradicional. ZTNA é o componente de acesso a aplicações do SSE.

**Problema que resolve:** A VPN como perímetro de segurança. VPN concede acesso a toda a rede uma vez autenticado — um dispositivo comprometido tem acesso lateral ilimitado. ZTNA verifica identidade, postura do dispositivo e contexto (localização, horário) para cada sessão de acesso, para cada aplicação específica.

**Exemplos comerciais:** Zscaler Private Access (ZPA), Netskope SASE, Prisma Access (Palo Alto), Cloudflare One, Cisco Umbrella

---

### 1.7 KSPM — Kubernetes Security Posture Management

**Definição:** Especialização do CSPM para clusters Kubernetes. Avalia configurações de clusters, namespaces, pods e recursos K8s contra CIS Kubernetes Benchmark e outras políticas de segurança.

**Problema que resolve:** As misconfigurations específicas de K8s que CSPM geral não detecta — pods privilegiados, ausência de NetworkPolicy, ServiceAccounts com cluster-admin, PSS violations, hostPath mounts perigosos.

**Exemplos open-source:** kube-bench (CIS Kubernetes Benchmark), kube-hunter (penetration testing), OPA Gatekeeper
**Exemplos comerciais:** Wiz (KSPM integrado), Prisma Cloud, Sysdig Secure

---

### 1.8 DSPM — Data Security Posture Management

**Definição:** Categoria focada em descobrir, classificar e proteger dados em ambientes cloud — buckets S3, Azure Blob, BigQuery, bancos de dados, data lakes.

**Problema que resolve:** Saber onde estão os dados sensíveis. O Banco Meridian pode ter 500 buckets S3 — mas em quais estão CPFs de clientes? Dados de cartão de crédito? DSPM descobre e classifica automaticamente, identificando dados sensíveis em lugares inesperados.

**Exemplos comerciais:** Wiz DSPM, Varonis, Dig Security, Cyera, BigID

---

### 1.9 ASPM — Application Security Posture Management

**Definição:** Categoria mais recente que consolida findings de segurança de aplicações (SAST, DAST, SCA, container scan) em uma única visão com priorização baseada em contexto de runtime.

**Problema que resolve:** O flood de findings de ferramentas isoladas de AppSec. Um SAST pode gerar 10.000 findings — mas quais desses achados estão em código que realmente vai para produção? Quais são reachable por um atacante externo? ASPM correlaciona com dados de runtime para priorizar o que importa.

---

## 2. Linha do Tempo — Evolução das Ferramentas

```
LINHA DO TEMPO: COMO CADA CATEGORIA NASCEU

2010–2015: CLOUD NASCENTE
→ Primeira onda de migração para cloud
→ Times usavam ferramentas de segurança on-premises (que não funcionavam bem)
→ Problema: "Quem mudou aquele Security Group?"
→ Solução emergente: CSPM

2015–2018: CONTAINERS E DEVOPS
→ Docker e Kubernetes explodem em adoção
→ Containers vinham com dezenas ou centenas de CVEs no sistema operacional base
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
→ 12+ consoles diferentes, sem correlação entre eles
→ Atacantes exploram combinações de problemas (misconfiguration + CVE + permissão)
→ Problema: "Temos 50.000 findings. Qual é realmente crítico?"
→ Solução: CNAPP — plataforma unificada com correlação
```

---

## 3. A Convergência para CNAPP

### 3.1 O Problema das Ferramentas Pontuais

Um ambiente cloud típico de uma fintech brasileira tem, em média:
- 1 ferramenta CSPM
- 1 ferramenta de image scanning (CWPP)
- 1 ferramenta de runtime security
- 1 ferramenta de secrets scanning
- 1 ferramenta de IaC security
- 1 ferramenta de CIEM

Isso são 6 consoles diferentes, 6 sets de alertas não correlacionados, 6 contratos para gerenciar. E o mais crítico: **zero correlação** entre os findings.

### 3.2 O Problema da Combinação Tóxica

Considere este cenário real do Banco Meridian:

```
CSPM detecta: EC2 api-pagamentos tem Security Group com porta 8080 exposta para 0.0.0.0/0 → MEDIUM
CWPP detecta: EC2 api-pagamentos tem Log4Shell (CVE-2021-44228) → HIGH
CIEM detecta: Role IAM da EC2 tem s3:* e iam:CreateUser → HIGH
```

Três ferramentas isoladas: 1 finding MEDIUM + 2 findings HIGH. Parece gerenciável.

**Mas a realidade é:**
A MESMA EC2 está exposta na internet (porta 8080) + tem Log4Shell exploitável remotamente + a role IAM permite ao atacante acessar TODOS os S3 buckets e criar usuários IAM na conta.

Se um atacante explorar o Log4Shell pela porta 8080 exposta, ele tem em mãos as credenciais IAM da role com `s3:*` e `iam:CreateUser`. Em minutos, pode exfiltrar todos os dados de clientes e criar um usuário backdoor com acesso permanente.

**CNAPP conecta esses três nós e gera um único alerta:** "Toxic combination — CRITICAL IMEDIATO" com o caminho de ataque completo.

### 3.3 Razões Estratégicas da Convergência

| Razão | Descrição |
|:------|:----------|
| **Redução de sprawl** | Uma plataforma vs 6–8 ferramentas: menos contratos, menos treinamento, menos integrações |
| **Correlação de dados** | Findings isolados vs attack path analysis que conecta os pontos |
| **Priorização inteligente** | Risk-based prioritization em vez de flood de findings sem contexto |
| **Cobertura do ciclo** | Code → Build → Deploy → Runtime cobertos na mesma plataforma |
| **ROI** | TCO de 1 plataforma CNAPP pode ser menor do que manter 5 ferramentas separadas |

---

## 4. Build vs Buy — Análise de TCO Cloud Security Tools

### 4.1 Quando Construir com Open-Source

**Faz sentido quando:**
- Organização tem equipe de segurança madura (5+ engenheiros dedicados)
- Orçamento limitado de security tools (startup, empresa de pequeno porte)
- Necessidade de customização alta (políticas proprietárias, integrações específicas)
- Apenas um ou dois provedores cloud (não multi-cloud complexo)

**Custo real do open-source (estimativa para 200 recursos cloud):**

```
CUSTO ANUAL ESTIMADO — STACK OPEN-SOURCE (Prowler + Trivy + Falco + Checkov)

Infraestrutura (EC2, armazenamento, K8s nodes para Falco): R$ 24.000/ano
Engenheiro dedicado para manutenção (50% do tempo de um sênior): R$ 80.000/ano
Integrações e automações customizadas: R$ 30.000/ano
Treinamento e atualização contínua: R$ 10.000/ano
─────────────────────────────────────────────────────
TOTAL: ~R$ 144.000/ano
```

### 4.2 Quando Comprar Plataforma Comercial

**Faz sentido quando:**
- Velocidade time-to-value é crítica (auditoria próxima, incidente recente)
- Cobertura multi-cloud é necessária (AWS + Azure + GCP em visão unificada)
- Compliance com frameworks múltiplos (CIS + SOC2 + BACEN + LGPD + PCI-DSS)
- Equipe de segurança pequena (1–3 pessoas cobrindo multi-cloud)

**Custo estimado de plataformas CNAPP comerciais (referência 2025):**

| Plataforma | Estimativa anual (USD) | Inclui |
|:-----------|:----------------------:|:-------|
| Wiz | 80.000–150.000 | CSPM + CWPP + CIEM + DSPM + KSPM |
| Prisma Cloud | 60.000–120.000 | Code to Cloud completo |
| Orca Security | 50.000–90.000 | CSPM + CWPP agentless |
| Defender for Cloud | Variável por plano | Grátis (Foundational CSPM Azure) + pago |

**Árvore de decisão:**

```
Tem auditoria regulatória em menos de 90 dias?
│ Sim → BUY (time-to-value é crítico)
│
Ambiente multi-cloud (AWS + Azure + GCP)?
│ Sim → BUY (complexidade justifica)
│
Equipe de segurança com menos de 3 engenheiros?
│ Sim → BUY (custo de manutenção inviabiliza open-source)
│
Orçamento limitado + equipe técnica madura?
│ Sim → BUILD com open-source (Prowler + Trivy + Falco + Checkov)
│
Todos os outros casos → Análise de TCO detalhada
```

---

## 5. Critérios de Seleção de Ferramentas de Cloud Security

### 5.1 Critérios Técnicos

| Critério | O que Avaliar | Peso |
|:---------|:-------------|:----:|
| **Cobertura de cloud providers** | AWS + Azure + GCP nativo? Kubernetes? SaaS? | Alto |
| **Profundidade de checks** | Quantos checks? Framework coverage (CIS, NIST, LGPD)? | Alto |
| **Integrações SIEM/SOAR** | Splunk, Microsoft Sentinel, Google SecOps, XSOAR, Shuffle? | Médio |
| **False positive rate** | Taxa de falsos positivos em avaliações independentes? | Alto |
| **Agent vs Agentless** | Impacto operacional do deployment? | Médio |
| **Latência de detecção** | Tempo entre misconfiguration e alerta? | Alto |

### 5.2 Critérios de Conformidade Regulatória Brasileira

Para o Banco Meridian, os critérios regulatórios são determinantes na seleção de ferramentas.

**BACEN 4.893 — Controles exigidos:**
- Registro de incidentes com evidência de detecção
- Testes periódicos de vulnerabilidade
- Gestão de acessos privilegiados
- Monitoramento contínuo

| Requisito BACEN 4.893 | Ferramenta Indicada | Evidência Gerada |
|:----------------------|:--------------------|:-----------------|
| Art. 5º — Testes de vulnerabilidade periódicos | Prowler + Trivy | Relatórios HTML/JSON com timestamp |
| Art. 6º — Monitoramento contínuo | CSPM com alertas | Logs de alertas em SIEM |
| Art. 8º — Gestão de acessos | CIEM (IAM Access Analyzer) | Relatório de permissões com least privilege |
| Art. 9º — Incidentes: registro e reporte | Falco → SIEM → SOAR | Eventos de segurança com contexto forense |
| Art. 10º — Plano de continuidade | IaC security | Políticas como código com versionamento |

### 5.3 CMN 4.658/2018

Resolução sobre uso de cloud por instituições financeiras (IFs).

**Requisito crítico:** Art. 16 — dados de clientes não podem ser armazenados fora do território nacional sem aprovação prévia do BACEN.

**Impacto na seleção de ferramentas:**
- Ferramentas CNAPP SaaS que processam dados de configuração dos workloads devem ter PoP no Brasil (região sa-east-1 AWS ou Brazil South do Azure)
- Plataformas que só têm PoP nos EUA podem representar problema regulatório

### 5.4 LGPD (Lei 13.709/2018)

**Impacto:** DSPM se torna quase mandatório para organizações que processam dados pessoais em cloud. Qualquer CSPM ou CIEM que identifica dados de clientes em recursos mal configurados auxilia diretamente no cumprimento da LGPD.

---

## 6. Mapa Visual: Cada Ferramenta no Seu Problema

```
MAPA DE FERRAMENTAS × PROBLEMAS × REGULAÇÃO

               CÓDIGO    BUILD     RUNTIME    ACESSO      DADOS      SaaS
               (IaC)     (Container)          (Identity)  (Storage)  (Apps)
               ────────  ─────────  ─────────  ──────────  ─────────  ─────
Problema       Misconfig  CVE in    Comporta   Excesso     PII em     Shadow
               no Terraform image   Malicioso  permissões  bucket     IT

Ferramenta     Checkov    Trivy     Falco      IAM Acces   DSPM       CASB
open-source    tfsec      Grype     eBPF       Analyzer    (limitado)
               Conftest   Syft (SBOM)

Ferramenta     Wiz Code   Sysdig    Sysdig     Wiz CIEM    Wiz DSPM   Netskope
comercial      Prisma Code Aqua     Aqua       Ermetic     Varonis    Zscaler ZIA

Regulação      BACEN      BACEN     BACEN      BACEN       LGPD       LGPD
BACEN/LGPD     Art. 10    Art. 5    Art. 9     Art. 8      Art. 46    Art. 6
```

---

## 7. Tabela Consolidada — Todas as Categorias

| Categoria | O que Protege | Problema Resolvido | Open-source | Comercial | Regulação |
|:----------|:-------------|:-------------------|:------------|:---------|:----------|
| **CNAPP** | Tudo integrado | Silos de segurança, falta de correlação | — | Wiz, Prisma Cloud, Orca | Múltipla |
| **CSPM** | Configuração de recursos cloud | Misconfigurations, exposições públicas | Prowler, ScoutSuite | Wiz, Prisma Cloud | BACEN Art. 5 |
| **CWPP** | Workloads em execução | CVEs em VMs/containers, runtime threats | Trivy, Falco, Grype | Sysdig, Aqua | BACEN Art. 9 |
| **CIEM** | Identidades e permissões | Escalation IAM, shadow admins | IAM Access Analyzer | Wiz CIEM, Ermetic | BACEN Art. 8 |
| **CASB** | Acesso a SaaS | Shadow IT, DLP, exfiltração | — | Netskope, Zscaler ZIA | BACEN Art. 6 |
| **SSE/ZTNA** | Acesso à rede | VPN lateral movement | Headscale | Zscaler ZPA, Cloudflare | BACEN Art. 6 |
| **KSPM** | Clusters Kubernetes | Misconfigs K8s, pods privilegiados | kube-bench, OPA | Wiz, Prisma Cloud | BACEN Art. 5 |
| **DSPM** | Dados em cloud | PII exposto, classificação ausente | — | Wiz DSPM, Varonis | LGPD Art. 46 |
| **ASPM** | Segurança de aplicações | Flooding de findings sem priorização | DefectDojo | Wiz Code, Apiiro | Múltipla |

---

## 8. Glossário

| Sigla | Expansão |
|:------|:---------|
| CASB | Cloud Access Security Broker |
| CIEM | Cloud Infrastructure Entitlement Management |
| CNAPP | Cloud-Native Application Protection Platform |
| CSPM | Cloud Security Posture Management |
| CWPP | Cloud Workload Protection Platform |
| DSPM | Data Security Posture Management |
| KSPM | Kubernetes Security Posture Management |
| SBOM | Software Bill of Materials |
| SSE | Security Service Edge |
| ZTNA | Zero Trust Network Access |

---

## 9. Atividades de Fixação

### Questão 1

Um S3 bucket do Banco Meridian foi configurado sem Block Public Access. Qual categoria de ferramenta detecta esse problema?

**a)** CWPP — porque monitora o conteúdo dos workloads em runtime
**b)** CSPM — porque monitora a configuração de recursos cloud contra benchmarks de segurança
**c)** CIEM — porque envolve permissões de identidades
**d)** CASB — porque é uma aplicação cloud acessível externamente

**Gabarito: b)**
Justificativa: CSPM monitora a configuração dos recursos cloud (como S3 buckets) contra benchmarks de segurança. Um bucket público sem criptografia é um finding de CSPM. CWPP analisaria o conteúdo dentro do bucket ou CVEs de workloads que acessam o bucket.

---

### Questão 2

Qual ferramenta open-source é mais adequada para detectar comportamentos maliciosos em tempo real dentro de containers em execução no Kubernetes?

**a)** Trivy — porque faz scan de vulnerabilidades em imagens de container
**b)** Checkov — porque analisa configurações de IaC e Kubernetes YAML
**c)** Falco — porque usa eBPF para monitorar syscalls em runtime e detectar comportamentos anômalos
**d)** kube-bench — porque executa testes de configuração contra CIS Kubernetes Benchmark

**Gabarito: c)**
Justificativa: Falco usa eBPF (ou kernel module) para interceptar syscalls em tempo real e detectar comportamentos maliciosos — shell interativo em container, acesso ao IMDS AWS, escrita em diretórios sensíveis. Trivy faz scan estático de imagens (antes do deploy). kube-bench avalia configurações do cluster. Checkov analisa YAML de IaC.

---

### Questão 3

A CMN 4.658 exige que dados de clientes de instituições financeiras não sejam armazenados fora do Brasil sem aprovação do BACEN. Qual é o impacto dessa regulação na seleção de ferramentas CNAPP?

**a)** Nenhum — ferramentas de segurança não processam dados de clientes
**b)** A ferramenta CNAPP deve ter licenciamento registrado no BACEN
**c)** Ferramentas SaaS de cloud security que processam dados de configuração devem ter PoP no Brasil (sa-east-1 AWS ou Brazil South Azure) ou aprovação específica do BACEN
**d)** A obrigatoriedade de usar apenas ferramentas open-source hospedadas no Brasil

**Gabarito: c)**
Justificativa: A CMN 4.658 restringe armazenamento e processamento de dados de clientes fora do território nacional sem aprovação do BACEN. Ferramentas SaaS de cloud security (CNAPP, CSPM) que processam dados de configuração dos workloads — potencialmente incluindo metadados de dados de clientes — precisam ter seu processamento no Brasil (região sa-east-1 ou Brazil South) ou ter aprovação específica. Ferramentas que só têm PoP nos EUA podem representar problema regulatório.

---

### Questão 4

O Banco Meridian precisa implementar uma stack de segurança cloud open-source para cobrir CSPM, CWPP e IaC security, com orçamento limitado. Qual combinação é a mais adequada?

**a)** Wiz + Netskope + Prisma Cloud
**b)** Trivy + OPA Gatekeeper + kube-bench + Falco
**c)** Prowler (CSPM) + Trivy (CWPP + IaC) + Checkov (IaC) + Falco (runtime)
**d)** Netskope + Zscaler + Prisma Cloud

**Gabarito: c)**
Justificativa: Prowler (CSPM — scans de configuração AWS/Azure/GCP), Trivy (CWPP — scans de imagens de container + IaC), Checkov (IaC security — scans de Terraform/CloudFormation/K8s YAML) e Falco (runtime security — eBPF) formam uma stack open-source completa cobrindo CSPM, CWPP e IaC security. Todas são gratuitas e amplamente adotadas.

---

### Questão 5

Por que um ataque que combina misconfiguration (Security Group aberto) + CVE explorável remotamente + permissão IAM excessiva é mais crítico do que cada problema isolado?

**a)** Porque cada problema tem severidade HIGH individualmente, totalizando CRITICAL
**b)** Porque a combinação cria um caminho de ataque completo: o atacante entra pela misconfiguration, explora a CVE para RCE, e usa as permissões IAM excessivas para lateral movement e persistência — comprometimento total a partir de um único ponto de entrada
**c)** Porque ferramentas de segurança tradicionais não detectam cada problema individualmente
**d)** Porque o custo de remediação é maior quando há múltiplos problemas

**Gabarito: b)**
Justificativa: Cada problema isolado pode ser tolerable. Mas a combinação cria um attack path: (1) Security Group aberto permite que o atacante alcance o serviço externamente; (2) CVE explorável permite RCE (Remote Code Execution) no servidor; (3) permissão IAM excessiva permite que o atacante, agora com acesso ao servidor, use as credenciais AWS para acessar S3 buckets com dados de clientes e criar backdoors. CNAPP detecta essa toxic combination — ferramentas isoladas não.

---

## 10. Roteiros de Gravação

### Aula 1.1: Panorama e Taxonomia (55 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Panorama das Ferramentas de Cloud Security: Do CSPM ao CNAPP |
| **Duração** | 55 minutos |
| **Formato** | Talking head + slides animados + mapa visual |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Bem-vindo ao Curso 4 da nossa Formação Cloud SecOps, aqui na CECyber. Eu sou o instrutor responsável por este curso e nestes próximos módulos você vai aprender a usar as ferramentas que os melhores times de cloud security do mundo usam no dia a dia.

Neste módulo de abertura, vamos construir o mapa completo das ferramentas de cloud security. Não é memorizar siglas — é entender por que cada ferramenta existe, qual problema ela resolve, e quando usar cada uma. Porque sem esse mapa, você vai usar a ferramenta errada para o problema errado.

Nosso cenário será o Banco Meridian — um banco fictício de médio porte, com 2.800 funcionários, ambiente híbrido em AWS, Azure e GCP, regulado pelo BACEN. Um ambiente real, com problemas reais.

---

**[05:00 – 25:00 | TAXONOMIA GARTNER | Slides animados]**

*[Dica de edição: slides animam categoria por categoria, cada uma surgindo com o "problema que resolve" em destaque]*

A resposta curta para "por que temos tantas categorias de ferramentas" é: cada categoria surgiu para resolver um problema específico que apareceu conforme a adoção de cloud cresceu.

Vou te contar a história cronologicamente.

Entre 2010 e 2015, na primeira onda de migração para cloud, o problema era simples: "Quem mudou aquele Security Group?" Os times tentavam usar ferramentas de segurança on-premises — ferramentas que não foram feitas para cloud e que não entendiam APIs de provedor. Surgiu o CSPM para monitorar continuamente a configuração dos recursos cloud contra benchmarks de segurança. Um S3 bucket público? CSPM encontra. Security Group com porta 22 aberta para o mundo? CSPM encontra.

*[Avança slide]*

Entre 2015 e 2018, Docker e Kubernetes explodiram em adoção. Containers vinham com dezenas ou centenas de CVEs no sistema operacional base. O problema mudou: não era mais só "a configuração está errada", era "tem uma vulnerabilidade grave rodando em produção nesse container". Surgiu o CWPP — Cloud Workload Protection Platform — para analisar o que está dentro dos workloads.

*[Avança slide]*

De 2018 a 2020, a proliferação de microsserviços criou outro problema: cada Lambda, cada pod Kubernetes, cada EC2 tem uma identidade, uma role IAM com permissões. E 95% dessas identidades têm muito mais acesso do que precisam. Surgiu o CIEM para gerenciar entitlements.

A pandemia de 2020 acelerou outro problema: colaboradores usando dezenas de aplicações SaaS não aprovadas, carregando dados sensíveis de clientes para Dropbox pessoal ou WeTransfer. O CASB surgiu para dar visibilidade e controle sobre esse shadow IT.

E chegamos em 2022–2025, onde o problema ficou mais complexo: as empresas tinham 8, 10, 12 ferramentas diferentes, cada uma com seu próprio console, sem nenhuma correlação entre elas. E os atacantes passaram a explorar combinações de problemas — uma misconfiguration mais uma CVE mais uma permissão excessiva criando um caminho de ataque completo. Surgiu o CNAPP — a plataforma unificada.

---

**[25:00 – 45:00 | MAPEAMENTO DETALHADO | Slides + whiteboard virtual]**

*[Dica de edição: quadro branco virtual onde cada categoria vai sendo colocada em seu "quadrante" do mapa]*

Deixa eu te mostrar o mapa com todas as categorias e onde cada uma atua no ciclo de vida cloud.

*[Explica cada categoria usando o mapa visual da seção 6]*

*[08:00 – 25:00: explica CSPM com o exemplo de S3 bucket e Security Group]*

O CSPM é a base. Ele faz chamadas de API read-only para todos os seus recursos — EC2, S3, RDS, Azure VMs, GCP Storage — e verifica se cada um está configurado de acordo com os benchmarks de segurança: CIS, NIST, e no caso do Banco Meridian, também BACEN 4.893 e LGPD.

Um S3 bucket público? CSPM encontra. Security Group com porta 22 aberta para 0.0.0.0/0? CSPM encontra. Um banco de dados sem backup habilitado? CSPM encontra. Se é um problema de configuração de recurso cloud — CSPM.

A ferramenta open-source mais usada para CSPM é o Prowler, versão 4. Vamos trabalhar com ela no Módulo 2 e no Lab 01.

*[Avança para CWPP]*

O CWPP olha para dentro dos workloads. A diferença fundamental: CSPM pergunta "como esse recurso está configurado?" — CWPP pergunta "o que está rodando dentro desse recurso e tem vulnerabilidades?".

Trivy é o scanner open-source mais usado para imagens de container. Falco usa eBPF para monitorar comportamentos em runtime. Veremos ambos em detalhe nos Módulos 3 e 4.

*[Avança para CIEM, CASB, KSPM, DSPM]*

---

**[45:00 – 52:00 | CONVERGÊNCIA CNAPP | Slides]**

*[Dica de edição: animação mostrando 6 ferramentas se fundindo em uma plataforma CNAPP]*

Agora vou te mostrar por que a convergência para CNAPP acontece — e por que com 50.000 findings você tem um problema de outra natureza.

*[Mostra o exemplo de toxic combination da seção 3.2]*

Imagine: o Wiz encontra uma EC2 no ambiente de produção do Banco Meridian. Ele faz a correlação no Security Graph e vê: essa EC2 tem uma porta exposta para 0.0.0.0/0 (CSPM). O OS tem Log4Shell não patchado (CWPP). A role IAM tem `s3:*` e `iam:CreateUser` (CIEM).

Com ferramentas separadas: 1 finding MEDIUM + 2 findings HIGH. Na fila normal de backlog.

Com CNAPP: 1 alerta CRITICAL URGENTE — "toxic combination" — porque o Wiz conectou os três dots e calculou o caminho de ataque completo. Em minutos, um atacante pode entrar pela porta exposta, usar Log4Shell para RCE, roubar as credenciais IAM e exfiltrar todos os dados de clientes.

Isso é o valor central do CNAPP.

---

**[52:00 – 55:00 | RECAPITULAÇÃO | Talking head]**

Nesta aula construímos o mapa completo. Cada categoria de ferramenta existe para resolver um problema específico que surgiu em uma fase de maturidade diferente da adoção de cloud.

Nas próximas aulas, vamos mergulhar fundo em cada categoria — começando pelo CSPM no Módulo 2, onde você vai executar o Prowler v4 na prática e aprender a apresentar um relatório de postura de segurança para o CISO.

Faça as atividades de fixação — são 5 questões de conceitos fundamentais. E nos vemos no Módulo 2!

---

## 11. Avaliação do Módulo 01

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**
Qual é a diferença fundamental entre CSPM e CWPP?

**a)** CSPM é open-source e CWPP é apenas comercial
**b)** CSPM monitora a configuração dos recursos cloud (plano de controle) — uma porta aberta, um bucket público; CWPP monitora vulnerabilidades e comportamentos dentro dos workloads (plano de dados) — CVEs em OS, shell malicioso em container
**c)** CSPM suporta apenas AWS; CWPP suporta multi-cloud
**d)** CSPM e CWPP são sinônimos com fornecedores diferentes

**Gabarito: b)**
Justificativa: A diferença é o objeto de análise. CSPM analisa a configuração dos serviços cloud via API — o plano de controle. "Esse S3 bucket está configurado com acesso público?" — chamada de API para S3. CWPP analisa o conteúdo e comportamento dentro dos workloads — o plano de dados. "Que CVEs existem nesse container?" — requer acesso ao filesystem da imagem ou monitoramento de syscalls.

---

**Questão 2 (10 pts)**
O Banco Meridian tem orçamento limitado, equipe de 2 engenheiros de segurança, auditoria do BACEN em 30 dias e ambiente apenas na AWS. Qual abordagem de seleção de ferramentas faz mais sentido?

**a)** Contratar plataforma CNAPP comercial — o time-to-value é crítico para uma auditoria em 30 dias
**b)** Construir stack open-source — Prowler + Trivy + Falco para economizar orçamento
**c)** Não fazer nada até depois da auditoria
**d)** Usar apenas AWS Security Hub nativo, sem ferramentas adicionais

**Gabarito: a)**
Justificativa: Com auditoria em 30 dias, o time-to-value de uma plataforma CNAPP comercial é decisivo. Setup em dias vs semanas para open-source. Uma plataforma comercial entrega relatórios de conformidade BACEN prontos para apresentação. Com equipe pequena de 2 pessoas, a manutenção de uma stack open-source consumiria uma parcela grande do tempo disponível, comprometendo a capacidade de remediação.

---

**Questão 3 (10 pts)**
No contexto da CNAPP, o que é uma "toxic combination"?

**a)** Combinação de ferramentas de segurança incompatíveis no mesmo ambiente
**b)** Correlação de múltiplos findings isolados que, juntos, criam um caminho de ataque completo e crítico — ex: misconfiguration + CVE + permissão IAM excessiva no mesmo recurso
**c)** Configuração de Security Group com múltiplas portas abertas simultaneamente
**d)** Uso de múltiplos provedores cloud sem uma estratégia unificada de segurança

**Gabarito: b)**
Justificativa: Toxic combination é o conceito central que justifica o CNAPP. Individualmente: um Security Group aberto (MEDIUM), uma CVE HIGH, uma role IAM excessiva (HIGH). Juntos, no mesmo recurso: o atacante pode entrar pela porta exposta, usar a CVE para RCE, e usar a role IAM para comprometimento total. CNAPP correlaciona os três para gerar um único alerta CRITICAL com o caminho de ataque.

---

**Questão 4 (10 pts)**
A auditoria do BACEN avalia conformidade com a Resolução 4.893. Qual combinação de categorias de ferramentas cobre os artigos 5º (testes de vulnerabilidade), 6º (monitoramento contínuo) e 8º (gestão de acessos)?

**a)** CASB (Art. 5) + SSE (Art. 6) + DSPM (Art. 8)
**b)** CSPM/CWPP (Art. 5) + CSPM com alertas contínuos (Art. 6) + CIEM (Art. 8)
**c)** IaC Security (Art. 5) + CASB (Art. 6) + CSPM (Art. 8)
**d)** KSPM (Art. 5) + DSPM (Art. 6) + CWPP (Art. 8)

**Gabarito: b)**
Justificativa: Art. 5 — testes de vulnerabilidade → CSPM (Prowler para misconfigurations) + CWPP (Trivy para CVEs em containers). Art. 6 — monitoramento contínuo → CSPM com scans periódicos e alertas, CloudWatch alarms, Security Hub. Art. 8 — gestão de acessos → CIEM (IAM Access Analyzer para identificar permissões excessivas e gerar política de menor privilégio).

---

**Questão 5 (10 pts)**
Um banco digital brasileiro com 5 milhões de clientes e 1.200 microserviços tem 95% das suas roles IAM com permissões que nunca foram usadas nos últimos 180 dias. Qual categoria de ferramenta resolve esse problema?

**a)** CSPM — porque monitora configurações de recursos cloud
**b)** CWPP — porque monitora workloads em execução
**c)** CIEM — porque analisa identidades, permissões efetivas e identifica entitlements excessivos em escala
**d)** CASB — porque controla acesso a aplicações SaaS

**Gabarito: c)**
Justificativa: CIEM (Cloud Infrastructure Entitlement Management) é a categoria especificamente projetada para gerenciar entitlements em escala cloud. Em um ambiente com 1.200 microserviços, cada um com sua role IAM, o CIEM analisa quais permissões cada role realmente usou (via CloudTrail) e gera uma política de menor privilégio. IAM Access Analyzer da AWS, por exemplo, tem um módulo "Unused Access" que identifica permissões não usadas em 90 dias.

---

**Questão 6 (10 pts)**
O que o KSPM (Kubernetes Security Posture Management) faz que um CSPM geral não faz?

**a)** KSPM é uma ferramenta de runtime security usando eBPF, diferente do CSPM que é estático
**b)** KSPM é um CSPM especializado que avalia configurações específicas de recursos Kubernetes — RBAC, PSS (Pod Security Standards), NetworkPolicy, hostPath mounts — contra o CIS Kubernetes Benchmark, que CSPM geral não cobre
**c)** KSPM é exclusivamente uma solução de runtime protection para containers
**d)** KSPM gerencia segredos integrado ao Kubernetes via Vault

**Gabarito: b)**
Justificativa: KSPM é um CSPM especializado para K8s. Enquanto CSPM geral avalia recursos AWS/Azure/GCP (S3, EC2, Security Groups), KSPM avalia especificamente recursos Kubernetes — se pods estão rodando como root, se há NetworkPolicy de default-deny, se RBAC tem ClusterRoles com wildcards, se PSS está configurado no nível correto para cada namespace. Ferramentas como kube-bench implementam os controles do CIS Kubernetes Benchmark que CSPM geral ignora.

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O novo CISO do Banco Meridian foi contratado com o mandato de implementar uma estratégia de segurança cloud em 90 dias. O ambiente atual é: AWS (principal), Azure (M365 e serviços legados), GCP (BigQuery e analytics), 50+ microserviços em Kubernetes, 300+ IAM roles, auditoria BACEN programada para daqui a 6 meses.

**Tarefa (4 partes, 10 pts cada):**

1. Mapeie quais categorias de ferramentas são necessárias e por quê, considerando o ambiente do Banco Meridian
2. Proponha a ordem de implementação (quick wins primeiro) com justificativa
3. Indique se cada categoria deve ser open-source ou comercial, com justificativa de TCO
4. Mapeie cada ferramenta selecionada para os artigos relevantes do BACEN 4.893

**Gabarito:**

1. **Categorias necessárias:**
   - CSPM: multi-cloud (AWS + Azure + GCP) — Prowler ou plataforma comercial
   - CWPP: 50+ microserviços em K8s com risco de CVEs — Trivy + Falco
   - IaC Security: todos os recursos devem ser criados via IaC — Checkov/tfsec no pipeline
   - CIEM: 300+ IAM roles, maioria com excesso de permissões — IAM Access Analyzer
   - KSPM: cluster K8s necessita de controles específicos — kube-bench + Kyverno

2. **Ordem de implementação (90 dias):**
   - Dias 1–15: CSPM com Prowler (quick win, evidência para BACEN Art. 5 e 6)
   - Dias 15–30: IaC Security no pipeline CI/CD (Checkov — prevenção futura)
   - Dias 30–45: CWPP — Trivy no pipeline de containers (scan de imagens)
   - Dias 45–60: CIEM — IAM Access Analyzer (BACEN Art. 8 — gestão de acessos)
   - Dias 60–75: KSPM — kube-bench + Kyverno (BACEN Art. 5 — testes de vulnerabilidade)
   - Dias 75–90: Falco runtime (BACEN Art. 9 — detecção de incidentes)

3. **Open-source vs comercial:**
   Com auditoria em 6 meses e ambiente multi-cloud complexo, recomendação híbrida:
   - Plataforma CNAPP comercial (Wiz ou Prisma Cloud) para CSPM multi-cloud + CIEM — TCO justificado pela cobertura AWS+Azure+GCP em um console e pelo time-to-value
   - Ferramentas open-source no pipeline: Checkov, Trivy, Falco — custo zero, integração nativa com CI/CD

4. **Mapeamento BACEN 4.893:**
   - CSPM → Art. 5 (testes de vulnerabilidade) + Art. 6 (monitoramento contínuo)
   - CWPP → Art. 5 (avaliação de controles — CVE scanning) + Art. 9 (detecção de incidentes — Falco)
   - CIEM → Art. 8 (gestão de acessos com menor privilégio)
   - IaC Security → Art. 10 (plano de continuidade — infraestrutura como código)
   - Secrets Management → Art. 8 (gestão de credenciais privilegiadas)

---

*Módulo 01 — Panorama e Taxonomia das Ferramentas de Cloud Security*
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*
*CECyber — Educação Corporativa em Cibersegurança*
