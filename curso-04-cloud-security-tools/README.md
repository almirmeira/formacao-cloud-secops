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

*Próximo passo: [Módulo 00 — Preparação do Ambiente de Laboratório](modulos/modulo-00-ambiente-laboratorio/README.md)*

---

*Curso 4 · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
