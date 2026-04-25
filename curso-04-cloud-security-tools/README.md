# Curso 4 — Ferramentas de Cloud Security: CNAPP, IaC e DevSecOps

**Programa de Formação Security Operations em Nuvem · CECyber**

[![CH Total](https://img.shields.io/badge/Carga%20Horária-30h-blue)](#informações-gerais)
[![Vídeo](https://img.shields.io/badge/Videoaulas-12h-orange)](#ementa-modular-detalhada)
[![Lab](https://img.shields.io/badge/Laboratórios-12h-green)](#laboratórios-hands-on)
[![Live](https://img.shields.io/badge/Live%20Online-6h-purple)](#sessões-live-online)
[![Certificação](https://img.shields.io/badge/Certificação-CCSP%20%2F%20CCSK-lightblue)](#certificação-alinhada)
[![Nível](https://img.shields.io/badge/Nível-Intermediário%20a%20Avançado-yellow)](#informações-gerais)

---

## Descrição

Curso **transversal e vendor-agnóstico** sobre o ecossistema completo de ferramentas de Cloud Security. Abrange desde plataformas consolidadas de CNAPP (Wiz, Prisma Cloud, Orca, Defender for Cloud) até ferramentas open-source de shift-left security (Checkov, Trivy, Falco, OPA, Vault).

O curso prepara arquitetos e engenheiros para **avaliar, implantar e operar** o stack completo de segurança em pipelines DevSecOps e ambientes multi-cloud (AWS + Azure + GCP). Inclui análise técnica e econômica (TCO/ROI) de plataformas comerciais de CNAPP — competência essencial para decisões de arquitetura e aquisição em organizações maduras.

---

## Informações Gerais

| Campo                       | Detalhes                                                                         |
|:----------------------------|:---------------------------------------------------------------------------------|
| **Carga Horária Total**     | 30 horas                                                                         |
| **Distribuição**            | 12h videoaulas (40%) + 12h laboratórios (40%) + 6h live online (20%)             |
| **Modalidade**              | EAD híbrido (plataforma LMS + sessões ao vivo via Zoom/Teams)                   |
| **Duração Sugerida**        | 5 semanas (ritmo de ~6h/semana)                                                  |
| **Público-Alvo**            | Arquitetos de segurança, engenheiros DevSecOps, cloud engineers, analistas de segurança cloud, CISOs técnicos |
| **Pré-requisitos**          | Conhecimentos básicos de ao menos um cloud provider (AWS, Azure ou GCP), fundamentos de containers/Kubernetes, familiaridade com Git e CI/CD |
| **Nível**                   | Intermediário a Avançado                                                          |
| **Certificação Alinhada**   | CCSP (ISC²), CCSK (CSA), CISSP (domínio Cloud Security); vendor-specific (Wiz Certified, Palo Alto PCCSE) |
| **Material Incluso**        | Videoaulas em HD, apostila, repositório GitHub com pipelines DevSecOps funcionais, matriz comparativa de vendors, certificado digital |
| **Aprovação**               | 70% de aproveitamento global                                                     |

---

## Objetivos de Aprendizagem

Ao concluir o curso, o participante será capaz de:

1. **Mapear e classificar** ferramentas de Cloud Security segundo a taxonomia Gartner (CNAPP, CSPM, CWPP, CIEM, CASB, SSE, KSPM, DSPM, ASPM)
2. **Avaliar** tecnicamente e economicamente (TCO/ROI) plataformas CNAPP comerciais
3. **Implementar** shift-left security em pipelines CI/CD com IaC scanning e Policy as Code
4. **Implantar** runtime protection para containers e Kubernetes com Falco (eBPF)
5. **Gerenciar entitlements** (CIEM) em ambientes multi-cloud com princípio do menor privilégio
6. **Operar** HashiCorp Vault para gestão de secrets em nível empresarial
7. **Avaliar postura** multi-cloud com ferramentas CSPM open-source e comerciais

---

## Estrutura do Curso

```
curso-04-cloud-security-tools/
│
├── README.md                                   ← Este arquivo
│
├── modulos/
│   ├── modulo-00-ambiente-laboratorio/          ← Setup do lab: Docker, K8s, Terraform, Vault
│   ├── modulo-01-panorama-cloud-security/       ← Taxonomia Gartner: CNAPP, CSPM, CWPP... (1h+1h live)
│   ├── modulo-02-cspm/                          ← Prowler, ScoutSuite + demos CNAPP (2h+2h+1h live)
│   ├── modulo-03-iac-security-shift-left/       ← Checkov, tfsec, OPA, GitHub Actions (2h+2h+1h live)
│   ├── modulo-04-cwpp-container-security/       ← Trivy, SBOM, Cosign, Falco eBPF (2h+2h+1h live)
│   ├── modulo-05-kubernetes-security/           ← RBAC, PSS, admission controllers (1h+1h)
│   ├── modulo-06-ciem/                          ← Entitlement management, least privilege (1h+1h)
│   ├── modulo-07-secrets-management/            ← HashiCorp Vault + cloud-native (2h+2h+1h live)
│   ├── modulo-08-casb-sse-dspm-cnapp/          ← CASB/SSE, DSPM, comparativo CNAPP (1h+1h+1h live)
│   └── modulo-09-capstone/                      ← Avaliação postura multi-cloud (1h lab + 1h live)
│
├── laboratorios/
│   ├── lab-01-cspm-open-source/                 ← Prowler: 400+ checks em conta AWS (2h)
│   ├── lab-02-pipeline-devsecops/               ← GitHub Actions + Checkov + Trivy + Cosign (2h)
│   ├── lab-03-runtime-security/                 ← Falco no K8s: detecção de shell em container (2h)
│   ├── lab-04-admission-control/                ← Kyverno: políticas de segurança K8s (1h)
│   ├── lab-05-hashicorp-vault/                  ← Vault HA + PKI + dynamic secrets + K8s (2h)
│   ├── lab-06-ciem-analysis/                    ← Excessive permissions + least-privilege (1h)
│   └── lab-capstone/                            ← Avaliação completa multi-cloud (2h + 1h live)
│
└── avaliacao-final/
    └── README.md                                 ← 40 questões + análise de caso multi-cloud
```

---

## Ementa Modular Detalhada

| Mód. | Conteúdo Programático                                                                | Vídeo | Lab  | Live |
|:----:|:-------------------------------------------------------------------------------------|:-----:|:----:|:----:|
|  00  | Setup do ambiente: Docker, kind (K8s local), Terraform, AWS CLI, Azure CLI, Vault dev | —    | 2h   | —    |
|  01  | Panorama de Cloud Security Tools: taxonomia Gartner (CNAPP, CSPM, CWPP, CIEM, CASB, SSE, KSPM, DSPM, ASPM). Critérios de seleção, build vs buy, integração com SIEM/SOAR, contexto regulatório brasileiro | 1h | — | 1h |
|  02  | CSPM — Cloud Security Posture Management: frameworks (CIS, NIST CSF, ISO 27001, LGPD, BACEN). Open-source: Prowler (AWS/Azure/GCP/K8s), ScoutSuite, CloudSploit. Demo de plataformas comerciais (Wiz, Prisma Cloud, Orca, Defender for Cloud) | 2h | 2h | 1h |
|  03  | IaC Security (Shift-Left): Checkov, tfsec, KICS, Terrascan, Trivy IaC. Integração CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps). Policy as Code: OPA + Rego, HashiCorp Sentinel, Conftest | 2h | 2h | 1h |
|  04  | CWPP — Container Security: image scanning (Trivy, Grype, Snyk, Clair), SBOM com Syft, signing com Cosign (Sigstore). Runtime protection: Falco (eBPF), Sysdig, Aqua. Pipeline scan + sign + verify | 2h | 2h | 1h |
|  05  | Kubernetes Security (KSPM): Pod Security Standards (PSS), NetworkPolicy, RBAC, admission controllers. OPA Gatekeeper vs Kyverno. CIS Kubernetes Benchmark com kube-bench | 1h | 1h | —    |
|  06  | CIEM — Entitlement Management: conceitos (least privilege, excessive permissions, toxic combinations). AWS IAM Access Analyzer, Entra Permissions Management, GCP Policy Intelligence, Wiz CIEM. Just-in-time access | 1h | 1h | —    |
|  07  | Secrets Management: HashiCorp Vault (auth methods, secret engines KV/database/PKI, policies, dynamic secrets, lease/renewal). Cloud-native (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager). Integração K8s (External Secrets, Vault Agent) | 2h | 2h | 1h |
|  08  | CASB, SSE, DSPM e CNAPP: use cases (shadow IT, DLP, ATP, data classification). Netskope, Zscaler, Prisma Access, Defender for Cloud Apps. DSPM. Comparativo comercial de CNAPP vendors (TCO, ROI) | 1h | 1h | 1h |
|  09  | Capstone — Avaliação de Postura Multi-Cloud: ambiente real (anonimizado). Entrega: findings, roadmap de remediação, arquitetura-alvo, business case | — | 1h | 1h |
|      | **TOTAL (30h)**                                                                       | **12h** | **12h** | **6h** |

---

## Laboratórios Hands-On

| Lab   | Nome                                       | Duração | Módulo | Ferramentas Utilizadas                    |
|:-----:|:-------------------------------------------|:-------:|:------:|:------------------------------------------|
|  01   | CSPM Open-Source: Prowler em conta AWS      |   2h    |   02   | Prowler, AWS CLI, Python                  |
|  02   | Pipeline DevSecOps completo                 |   2h    |   03   | GitHub Actions, Checkov, tfsec, Trivy, Cosign |
|  03   | Runtime Security com Falco                  |   2h    |   04   | Falco (eBPF), kind, Kubernetes            |
|  04   | Admission Control com Kyverno               |   1h    |   05   | Kyverno, kubectl, kind                    |
|  05   | HashiCorp Vault: PKI + Dynamic Secrets      |   2h    |   07   | Vault, PostgreSQL, External Secrets, K8s  |
|  06   | CIEM Analysis: Least Privilege Policy       |   1h    |   06   | AWS IAM Access Analyzer, AWS CLI          |
| Caps. | Avaliação Multi-Cloud (AWS + Azure)         | 2h+1h   |   09   | Prowler, ScoutSuite, Checkov, relatório técnico |

---

## Taxonomia de Ferramentas por Categoria (Gartner)

```
CLOUD SECURITY TOOLS LANDSCAPE — TAXONOMIA GARTNER (2025)
─────────────────────────────────────────────────────────────────────────────

CNAPP (Cloud-Native Application Protection Platform)
  Plataformas que integram CSPM + CWPP + CIEM + KSPM em um único produto
  ├── Comerciais: Wiz · Palo Alto Prisma Cloud · Orca Security · Lacework
  └── Cloud-Native: Defender for Cloud · AWS Security Hub · GCP SCC

CSPM (Cloud Security Posture Management)
  Identificação e correção de misconfigurações em cloud
  ├── Open-Source: Prowler · ScoutSuite · CloudSploit · cs-suite
  └── Comerciais: Wiz · Prisma Cloud · Orca · Lacework

CWPP (Cloud Workload Protection Platform)
  Proteção de workloads (VMs, containers, serverless)
  ├── Container/Image: Trivy · Grype · Snyk Container · Clair
  ├── Runtime: Falco (eBPF) · Sysdig Secure · Aqua Security · Twistlock
  └── SBOM: Syft · CycloneDX · SPDX · Cosign (Sigstore)

CIEM (Cloud Infrastructure Entitlement Management)
  Gestão de permissões e entitlements em ambientes cloud
  ├── AWS: IAM Access Analyzer · CloudTrail Insights
  ├── Azure: Entra Permissions Management
  ├── GCP: Policy Intelligence · Recommender
  └── Multi-cloud: Wiz CIEM · Ermetic · CloudKnox

KSPM (Kubernetes Security Posture Management)
  Postura de segurança em clusters Kubernetes
  ├── Open-Source: kube-bench · kubescape · Trivy (K8s)
  └── Comerciais: Prisma Cloud · Wiz · Sysdig Secure

CASB (Cloud Access Security Broker)
  Controle de acesso e segurança em SaaS/cloud corporativo
  └── Netskope · Zscaler · Microsoft Defender for Cloud Apps · Cisco Umbrella

SSE (Security Service Edge)
  Arquitetura Zero Trust Network Access substituindo VPNs
  └── Zscaler ZIA/ZPA · Netskope SASE · Prisma Access · Cloudflare One

DSPM (Data Security Posture Management)
  Descoberta, classificação e proteção de dados em cloud
  └── Wiz DSPM · Varonis · Dig Security · Cyera · Securiti

IaC Security (Shift-Left)
  Segurança integrada ao pipeline de infraestrutura como código
  ├── Scanners: Checkov · tfsec · KICS · Terrascan · Trivy IaC
  └── Policy as Code: OPA + Rego · HashiCorp Sentinel · Conftest

Secrets Management
  Gestão centralizada de credenciais, chaves e certificados
  ├── Open-Source: HashiCorp Vault
  └── Cloud-Native: AWS Secrets Manager · Azure Key Vault · GCP Secret Manager
```

---

## Ferramentas e Tecnologias

### Open-Source / Free

| Categoria   | Ferramenta           | Uso no Curso                                      |
|:------------|:---------------------|:--------------------------------------------------|
| CSPM        | Prowler              | Scan de 400+ checks em AWS/Azure/GCP/K8s          |
| CSPM        | ScoutSuite           | Auditoria multi-cloud com relatório HTML           |
| IaC         | Checkov              | Scan de Terraform, CloudFormation, Kubernetes YAML |
| IaC         | tfsec                | Análise estática de código Terraform               |
| IaC         | Trivy (IaC mode)     | Scan de IaC + containers + SBOMs                  |
| Container   | Grype                | Vulnerability scanning de imagens OCI              |
| SBOM        | Syft                 | Geração de Software Bill of Materials              |
| Signing     | Cosign (Sigstore)    | Assinatura e verificação de imagens container      |
| Runtime     | Falco                | Runtime security com eBPF em Linux/K8s            |
| K8s         | kube-bench           | CIS Kubernetes Benchmark check                    |
| K8s         | Kyverno              | Policy engine e admission controller              |
| Policy      | OPA (Gatekeeper)     | Policy as Code com Rego                           |
| Secrets     | HashiCorp Vault      | Gestão enterprise de secrets                       |

### Plataformas Comerciais (Visão Geral e Demos)

| Categoria   | Plataforma             | Abordagem no Curso                              |
|:------------|:-----------------------|:------------------------------------------------|
| CNAPP       | Wiz                    | Demo + análise comparativa TCO/ROI              |
| CNAPP       | Palo Alto Prisma Cloud | Demo + PCCSE certification path                 |
| CNAPP       | Orca Security          | Demo + arquitetura SideScanning™                |
| CNAPP       | Lacework               | Demo + anomaly detection                        |
| CSPM        | Microsoft Defender for Cloud | Análise nativa no Azure                   |
| Runtime     | Sysdig Secure          | Demo + Falco enterprise                         |
| Runtime     | Aqua Security          | Demo + container lifecycle                      |
| CASB/SSE    | Netskope               | Demo + CASB use cases                           |
| CASB/SSE    | Zscaler                | Demo + Zero Trust architecture                  |

---

## Avaliação

| Componente                                      | Peso |
|:------------------------------------------------|:----:|
| Quizzes integrados às videoaulas                |  15% |
| Laboratórios guiados e desafios                 |  35% |
| Pipeline DevSecOps completo (individual)         |  20% |
| Análise comparativa de CNAPP vendors (artigo técnico) | 15% |
| Capstone em grupo                               |  15% |

**Aprovação:** 70% de aproveitamento global. Certificado digital inclui preparação para CCSP, CCSK
e CISSP (domínio de Cloud Security).

---

## Sessões Live Online (6h)

| Sessão | Conteúdo                                                        | Duração | Módulo |
|:------:|:----------------------------------------------------------------|:-------:|:------:|
|   1    | Abertura + Setup + Panorama do mercado CNAPP/CSPM               |  1h30   |  01/02 |
|   2    | Lab ao vivo: Pipeline DevSecOps — Checkov + Trivy + Cosign       |  1h30   |   03   |
|   3    | Lab ao vivo: Falco runtime security + Kyverno admission control  |  1h30   |  04/05 |
|   4    | Defesa do Capstone + comparativo CNAPP + encerramento           |  1h30   |   09   |

---

## Mapeamento para Certificações

### CCSP (ISC²) — 6 Domínios

| Domínio CCSP                            | Módulos do Curso |
|:----------------------------------------|:----------------:|
| 1. Cloud Concepts, Architecture (17%)   | 01, 02           |
| 2. Cloud Data Security (20%)            | 06, 07, 08       |
| 3. Cloud Platform & Infrastructure (17%) | 02, 03, 04, 05  |
| 4. Cloud Application Security (17%)     | 03, 04           |
| 5. Security Operations (16%)            | 02, 05, 06       |
| 6. Legal, Risk and Compliance (13%)     | 01, 02, 08       |

### CCSK (CSA) — Domínios Relevantes

| Domínio CCSK                              | Módulos do Curso |
|:------------------------------------------|:----------------:|
| Infrastructure Security                   | 02, 03, 04       |
| Virtualization and Containers             | 04, 05           |
| Incident Response                         | 01, 02           |
| Application Security                      | 03               |
| Data Security and Encryption              | 06, 07           |
| Identity and Access Management            | 06               |

---

## Ementa Modular Expandida

### Módulo 01 — Panorama de Cloud Security Tools (1h vídeo + 1h live)

Visão completa do mercado e taxonomia de ferramentas segundo o Gartner Magic Quadrant e o relatório Hype Cycle for Cloud Security. Análise das categorias CNAPP, CSPM, CWPP, CIEM, CASB, SSE, KSPM, DSPM e ASPM com exemplos de vendors em cada categoria. Critérios técnicos e econômicos para seleção de ferramentas: cobertura multi-cloud, latência de detecção, integração com SIEM/SOAR, modelo de licenciamento (por ativo, por usuário, por workload), suporte ao contexto regulatório brasileiro (BACEN, LGPD). Análise do modelo "build vs buy": quando investir em stack open-source vs plataforma comercial integrada. Tendências de mercado: convergência CNAPP, agentless scanning, eBPF como substituto de agentes kernel, graph-based security (mapeamento de caminhos de ataque).

---

### Módulo 02 — CSPM: Cloud Security Posture Management (2h vídeo + 2h lab + 1h live)

**Open-source em profundidade:**
- **Prowler v3/v4**: arquitetura (providers, services, checks, reports), execução em linha de comando contra AWS/Azure/GCP/Kubernetes, output em JSON/HTML/CSV/SARIF, integração com GitHub Actions e Security Hub via ASFF, checks customizados em Python
- **ScoutSuite**: análise de serviços cloud com relatório HTML interativo, comparação de provider APIs, limitações de acesso via roles
- **CloudSploit**: scanning agnóstico de cloud, integração CI/CD, API mode

**Demos comerciais (visão geral técnica sem hands-on):**
- **Wiz**: graph-based security, Toxic Combinations (combinações de risks que formam paths de ataque), sensor-less cloud scanning, DSPM integrado
- **Palo Alto Prisma Cloud**: Bridgecrew para IaC + runtime, compliance frameworks pré-definidos, integração com XSIAM
- **Orca Security**: SideScanning™ (zero-agent), full-stack visibility, Business Risk Scoring
- **Microsoft Defender for Cloud**: integração nativa Azure + multi-cloud via Arc, Secure Score, regulatory compliance dashboard

Mapeamento de controles CSPM para regulatórios brasileiros: BACEN 4.893 Art. 9 (gestão de vulnerabilidades), LGPD Art. 46 (medidas técnicas e administrativas), CIS Foundations Benchmark AWS/Azure/GCP.

**Laboratório (2h):** Executar Prowler v4 contra conta AWS de laboratório; analisar 400+ findings; categorizar por criticidade; criar relatório customizado; mapear top 10 findings para controles BACEN 4.893 e propor roadmap de remediação.

---

### Módulo 03 — IaC Security: Shift-Left (2h vídeo + 2h lab + 1h live)

**Por que shift-left?** Custo de correção de vulnerabilidades: $1 (desenvolvimento) vs $10 (pre-prod) vs $100 (produção) vs $1000+ (incidente em produção). Integração de segurança no pipeline desde o primeiro commit.

**Ferramentas de IaC scanning:**
- **Checkov**: suporte a Terraform, CloudFormation, Kubernetes YAML, Helm, Bicep, ARM, Ansible, Dockerfile; rules built-in (600+); regras customizadas em Python ou YAML; output SARIF para GitHub; integração com Bridgecrew SaaS
- **tfsec**: foco em Terraform, regras em Rego ou Go, severidade por ID de regra, integração com pre-commit hook
- **KICS**: Keeping Infrastructure as Code Secure da Checkmarx; suporte multi-plataforma; output SARIF; free
- **Terrascan**: políticas OPA/Rego para Terraform/K8s/Helm; integração AC/CD
- **Trivy (IaC mode)**: `trivy config ./terraform/` — scan rápido e integrado com scanning de container/SBOM

**Policy as Code:**
- **OPA + Rego**: estrutura de decisão (allow/deny), data files (.json), policies modulares, integração como admission webhook no K8s (OPA Gatekeeper), teste com `opa test`
- **Conftest**: usa Rego para validar qualquer formato de configuração (Kubernetes YAML, Terraform plan JSON, Docker Compose)
- **HashiCorp Sentinel**: Policy as Code nativa do Terraform Cloud/Enterprise; policies em linguagem Sentinel; mocked data para testes

**Pipeline GitHub Actions completo:**
```yaml
# Exemplo do pipeline abordado no lab:
# commit → checkov scan → tfsec → trivy config → OPA policy check →
# → trivy image scan → cosign sign → deploy (se tudo passar)
```

**Laboratório (2h):** Configurar pipeline GitHub Actions completo com Checkov + tfsec + Trivy + OPA policy check; introduzir deliberadamente 3 misconfigurações no Terraform (S3 público, security group 0.0.0.0/0, KMS não habilitado) e verificar que o pipeline falha; corrigir e fazer pipeline passar; adicionar regra OPA customizada para bloquear recursos sem tag `Environment`.

---

### Módulo 04 — CWPP: Container Security (2h vídeo + 2h lab + 1h live)

**Ciclo de vida do container e onde aplicar segurança:**
```
Build → Scan Image → Sign Image → Push Registry → Verify Signature → Deploy → Runtime Monitor
```

**Image Scanning:**
- **Trivy**: `trivy image nginx:latest` — scan de OS packages, linguagens (pip, npm, gem, composer), secrets, Dockerfile misconfig, SBOM; integração com ECR/ACR/GCR via `trivy registry`; output JSON/SARIF/table
- **Grype**: Anchore's vulnerability scanner; base GRYPE_DB (atualizada diariamente); comparação de performance vs Trivy
- **Snyk Container**: integração IDE e CI/CD; fix PRs automáticos; licença comercial para teams

**SBOM (Software Bill of Materials):**
- **Syft**: geração de SBOM em SPDX, CycloneDX, Syft JSON; `syft nginx:latest -o spdx-json > nginx.sbom.json`
- Por que SBOM importa: Log4Shell (2021) — organizações sem SBOM não sabiam se eram vulneráveis. Com SBOM: query em segundos
- Requisitos regulatórios emergentes: US Executive Order 14028 (EO) exige SBOM para software vendido ao governo federal americano

**Supply Chain Security:**
- **Cosign + Sigstore**: assinatura de imagens com chaves efêmeras (keyless signing via OIDC), verificação `cosign verify`; integração com Rekor (transparency log); Fulcio (certificate authority)
- **SLSA Framework** (Supply-chain Levels for Software Artifacts): levels 1-4, provenance attestations

**Runtime Protection:**
- **Falco (eBPF)**: arquitetura (kernel eBPF probe vs kernel module vs eBPF user-space), regras Falco (condition + output + priority), integração com Falcosidekick para outputs (Slack, Teams, ElasticSearch, AWS Lambda, Datadog), Falco Talon para resposta automatizada
- **Sysdig Secure**: Falco enterprise + image scanning + postura K8s + forense de containers
- **Aqua Security**: lifecycle protection, VM scanning, função serverless protection

**Laboratório (2h):** Scan de imagem com Trivy; geração de SBOM com Syft; assinatura de imagem com Cosign (keyless); deploy de Falco em kind (Kubernetes local); testar regras padrão do Falco (shell em container, leitura de /etc/shadow, conexão reversa); criar regra Falco customizada para detectar `kubectl exec` suspeito.

---

### Módulo 05 — Kubernetes Security (KSPM) (1h vídeo + 1h lab)

**Pod Security Standards (PSS)**: perfis Privileged, Baseline e Restricted; aplicação via namespace labels (`pod-security.kubernetes.io/enforce: restricted`); migração de PodSecurityPolicy (deprecated) para PSS.

**NetworkPolicy**: modelo de default-deny; ingress e egress rules; seletores por namespace e labels; limitações (não é um firewall L7 — use Cilium ou Istio para isso); exemplos práticos para isolamento de namespaces de produção.

**RBAC (Role-Based Access Control)**: Roles vs ClusterRoles; RoleBindings vs ClusterRoleBindings; service accounts; auditar RBAC com `kubectl auth can-i`; erros comuns (`cluster-admin` desnecessário, wildcard `*` em resources/verbs).

**Admission Controllers**: tipos (Validating, Mutating); OPA Gatekeeper: Constraint Framework, ConstraintTemplates em Rego, exemplos (exigir limites de CPU/memória, proibir imagens `:latest`, exigir labels obrigatórias); Kyverno: policies como Kubernetes resources (mais simples que Rego), generate policies, mutate policies.

**kube-bench**: CIS Kubernetes Benchmark automatizado; execução como Job no cluster; interpretação de findings; priorização por score de risco.

**Laboratório (1h):** Aplicar PSS Restricted em namespace de produção; criar NetworkPolicy de default-deny + allow específico para um serviço; instalar Kyverno e aplicar política que proíbe imagens sem digest SHA e sem labels obrigatórias; executar kube-bench e analisar top 5 findings.

---

### Módulo 06 — CIEM: Entitlement Management (1h vídeo + 1h lab)

**Conceitos fundamentais:**
- Excesso de permissões (overentitlement): em média, as identidades cloud usam apenas 5% das permissões que têm
- Toxic combinations: combinação de permissões que individualmente parecem inofensivas mas juntas permitem privilege escalation (ex: `iam:CreateAccessKey` + `iam:AttachUserPolicy`)
- Just-in-time (JIT) access: provisionar acesso no momento certo, com duração limitada (ex: PIM no Azure, AWS IAM Identity Center temporary elevations)

**Ferramentas por cloud:**
- **AWS IAM Access Analyzer**: findings de acesso externo (recursos compartilhados com accounts externas), acesso público, permissões não usadas (Unused Access Analyzer). Policy validation. Geração automática de policies de least privilege baseada em CloudTrail
- **Microsoft Entra Permissions Management** (CIEM): visibilidade de permissões em AWS/Azure/GCP; Permission Creep Index (PCI); recomendações de right-sizing de permissões
- **GCP Policy Intelligence**: recommender (remove permissões não usadas nos últimos 90 dias), IAM Insights, Policy Simulator
- **Wiz CIEM**: graph-based visualization de entitlements, effective permissions (considerando SCPs, resource policies, etc.), toxic combinations

**Laboratório (1h):** Usar IAM Access Analyzer para encontrar findings de acesso externo e público em conta AWS de lab; usar `aws iam generate-service-last-accessed-details` para identificar permissões não utilizadas; gerar policy de least privilege; comparar policy atual vs gerada; documentar excess permissions removidas.

---

### Módulo 07 — Secrets Management (2h vídeo + 2h lab + 1h live)

**HashiCorp Vault — Aprofundamento:**
- Arquitetura: Vault server, storage backend (Consul, Integrated Raft, S3), audit devices, auth methods, secret engines
- Auth methods: AWS IAM, Kubernetes (service account JWT), LDAP, OIDC, AppRole (para CI/CD)
- Secret engines: KV v2 (versionado), database (dynamic credentials para PostgreSQL/MySQL/Oracle com TTL), PKI (CA interna, emissão de certificados com TTL curto), Transit (encryption as a service), SSH (OTP e CA)
- Dynamic credentials: vault gera credenciais de banco de dados sob demanda com TTL (ex: 1h); a credencial expira automaticamente; auditoria por lease ID. Elimina credenciais estáticas no código
- Vault Agent + Vault Injector: sidecar que injeta secrets como arquivos ou variáveis de ambiente no pod K8s sem modificar o código da aplicação
- External Secrets Operator (ESO): sincroniza secrets de qualquer backend (Vault, AWS SM, Azure KV) para K8s Secrets nativos
- Alta disponibilidade: Vault HA com Raft Integrated Storage; backup/restore; unsealing automático com AWS KMS/Azure Key Vault

**Cloud-native secrets:**
- **AWS Secrets Manager**: rotation automática com Lambda (nativa para RDS/Redshift/DocumentDB); cross-account via resource policy; integração nativa com ECS, EKS (ESO), Lambda (extension layer); pricing por secret/chamada de API
- **Azure Key Vault**: keys, secrets e certificates; soft delete e purge protection; managed identities; integração com AKS (CSI driver), VMSS, App Service; Azure Key Vault Firewall (rede)
- **GCP Secret Manager**: versioning, replicação automática multi-region, CMEK com Cloud KMS; integração com Cloud Run, GKE (Workload Identity), Cloud Functions

**Laboratório (2h):** Instalar Vault em modo HA com Raft storage em Kubernetes (via Helm); configurar auth method Kubernetes; criar secret engine database (dynamic credentials para PostgreSQL); deploy de aplicação demo que usa Vault Agent para injeção de credenciais; configurar External Secrets Operator apontando para AWS Secrets Manager; verificar rotação de credenciais; configurar auditoria de acesso no Vault.

---

### Módulo 08 — CASB, SSE, DSPM e Comparativo CNAPP (1h vídeo + 1h lab + 1h live)

**CASB (Cloud Access Security Broker):**
- Casos de uso: Shadow IT discovery, DLP (Data Loss Prevention) em SaaS, ATP (Advanced Threat Protection) para cloud apps, UEBA em SaaS, compliance enforcement (LGPD, PCI)
- Netskope: steering modes (Proxy, API, Reverse Proxy), app traffic steering com NPA (Netskope Private Access), DLP com ML, Threat Protection
- Zscaler ZIA/ZPA: arquitetura zero-trust (nunca expose app no internet), ZTNA para apps privados, SSL inspection, CASB integrado
- Microsoft Defender for Cloud Apps (MDA): integração nativa M365/Azure, app governance, session controls via Conditional Access

**SSE (Security Service Edge):**
- Arquitetura SASE: SD-WAN + SSE; diferença entre SSE e SASE; quem precisa de cada um
- Componentes SSE: SWG (Secure Web Gateway), ZTNA (Zero Trust Network Access), CASB, FWaaS (Firewall as a Service)
- Zscaler vs Netskope vs Prisma Access vs Cloudflare One: comparativo técnico de arquitetura, latência, cobertura PoPs, modelo de licenciamento

**DSPM (Data Security Posture Management):**
- Descoberta automática de dados sensíveis em cloud storage (S3, Azure Blob, GCS, Snowflake, BigQuery, RDS)
- Classificação: PII, PCI, PHI, dados financeiros — relevância LGPD/GDPR
- Wiz DSPM, Varonis, Dig Security, Cyera: comparativo de abordagens (agentless scan, data flow analysis)
- Diferença entre Macie (AWS-native, S3 only) e DSPM (multi-cloud, multi-store)

**Comparativo CNAPP — Análise TCO/ROI:**

| Critério                      | Wiz         | Prisma Cloud | Orca        | Defender for Cloud |
|:------------------------------|:-----------:|:------------:|:-----------:|:------------------:|
| Cobertura multi-cloud         | AWS/Az/GCP/K8s | AWS/Az/GCP/K8s | AWS/Az/GCP | AWS/Az/GCP (Arc) |
| Modelo de scanning            | Agentless   | Agentless + Agent | Agentless | Agentless + Agent |
| CIEM integrado                | Sim         | Sim          | Parcial     | Partial (via MEPF) |
| KSPM                          | Sim         | Sim          | Sim         | Sim (via Arc)       |
| IaC security (Shift-left)     | Sim (via Wiz CLI) | Sim (Bridgecrew) | Parcial | Sim (Defender DevOps) |
| DSPM                          | Sim         | Limitado     | Sim         | Limitado           |
| Modelo de preço               | Por workload| Por crédito  | Por asset   | Por servidor/workload |
| Integração Sentinel/SIEM      | REST API    | REST API     | REST API    | Nativa             |

**Laboratório (1h):** Análise de relatório de postura de segurança Wiz (mockup/demo) de ambiente multi-cloud; comparar findings com ScoutSuite (open-source) do mesmo ambiente; calcular TCO simplificado: custo de licença CNAPP vs custo de equivalente open-source (horas de engenheiro × custo médio hora); propor recomendação de make-or-buy para o Banco Meridian fictício.

---

### Módulo 09 — Capstone: Avaliação de Postura Multi-Cloud (1h lab + 1h live)

**Cenário:** O Banco Meridian contratou sua equipe para realizar uma avaliação completa de postura de segurança cloud em 4 horas, cobrindo contas AWS e tenant Azure. Ao final, você deve entregar um relatório executivo com findings priorizados, roadmap de remediação em 3 horizontes (30/60/90 dias) e uma arquitetura-alvo de ferramentas de segurança com business case financeiro.

**Entregáveis do Capstone:**
1. **Relatório de postura** (PDF ou Markdown): top 20 findings priorizados por criticidade e impacto de negócio
2. **Roadmap de remediação**: tabela com finding, remediação proposta, responsável, prazo e custo estimado
3. **Arquitetura-alvo**: diagrama com stack de ferramentas recomendadas (open-source + comercial)
4. **Business case**: custo de ferramentas recomendadas vs custo estimado de uma violação de dados

---

## Referências e Leituras Recomendadas

| Tipo         | Recurso                                                                              | Onde acessar                              |
|:-------------|:-------------------------------------------------------------------------------------|:------------------------------------------|
| Relatório    | Gartner Magic Quadrant for CNAPP — anual                                            | gartner.com (acesso pago)                 |
| Relatório    | Gartner Hype Cycle for Cloud Security — anual                                       | gartner.com (acesso pago)                 |
| Blog         | OWASP Cloud Security Project                                                        | owasp.org/cloud-security                  |
| Docs         | Falco Documentation — eBPF Runtime Security                                         | falco.org/docs                            |
| Docs         | HashiCorp Vault Documentation                                                       | developer.hashicorp.com/vault             |
| Docs         | Checkov Documentation                                                               | checkov.io/docs                           |
| Docs         | Prowler Cloud v4 Documentation                                                      | docs.prowler.com                          |
| Docs         | Cosign + Sigstore                                                                   | docs.sigstore.dev                         |
| Livro        | "Container Security" — Liz Rice                                                     | O'Reilly                                  |
| Livro        | "Kubernetes Security and Observability" — Brendan Creane, Amit Gupta                | O'Reilly                                  |
| Site         | SLSA Framework (Supply-chain Levels for Software Artifacts)                         | slsa.dev                                  |
| Framework    | CIS Benchmarks (AWS, Azure, GCP, Kubernetes, Docker)                               | cisecurity.org/cis-benchmarks             |
| Framework    | NIST Cybersecurity Framework 2.0                                                    | nist.gov/cyberframework                   |
| Certificação | CCSP (ISC²) — Official Study Guide                                                  | isc2.org/certifications/ccsp             |
| Certificação | CCSK (Cloud Security Alliance)                                                      | cloudsecurityalliance.org/education/ccsk  |

---

*Próximo passo: [Módulo 00 — Preparação do Ambiente de Laboratório](modulos/modulo-00-ambiente-laboratorio/README.md)*

---

*Curso 4 · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
