# Trilhas de Formação — Guia Completo
## Programa de Formação Security Operations em Nuvem · CECyber

---

## Visão Geral

Os quatro cursos do programa podem ser cursados de três formas:

1. **Isoladamente** — cada curso tem valor independente e prepara para uma certificação específica
2. **Em trilha temática** — combinações pré-definidas para objetivos específicos de carreira
3. **Como programa completo** — os quatro cursos em sequência, formação de liderança em Cloud Security

---

## Trilha 1 — SecOps Single-Cloud (30h a 40h)

### Para quem é

Organizações que padronizaram em **um único provedor de nuvem** e precisam capacitar o time de SOC para operar as ferramentas nativas de segurança desse provider.

Também indicada para **profissionais em transição de carreira** que precisam se aprofundar em um provider específico antes de expandir para multi-cloud.

### Opções

| Opção | Curso | CH | Certificação Alvo | Perfil Recomendado |
|:-----:|:------|:--:|:----------------:|:-------------------|
| **A** | Google SecOps Essentials | 30h | Google Cloud Security Eng. | Times GCP-first, organizações com Chronicle |
| **B** | Microsoft Sentinel & Defender | 40h | Microsoft SC-200 ⭐ | Organizações com M365, bancos brasileiros |
| **C** | AWS Cloud Security Operations | 40h | AWS Security Specialty | Times AWS-first, e-commerce, fintechs |

> **⭐ Recomendação para instituições financeiras brasileiras:** Opção B (Sentinel & Defender), dada a alta penetração de M365 E5 no setor financeiro e a aderência nativa do Defender for Cloud aos requisitos da Resolução BACEN 4.893.

### Duração e Ritmo

```
Trilha A (Google): 30h → 5 semanas a 6h/semana
Trilha B (Azure):  40h → 7 semanas a 6h/semana
Trilha C (AWS):    40h → 7 semanas a 6h/semana
```

---

## Trilha 2 — SecOps Multi-Cloud (80h a 110h)

### Para quem é

Organizações que operam em **múltiplos provedores de nuvem** — típico de grandes bancos, seguradoras e grupos financeiros brasileiros que usam AWS para workloads críticos e Azure/M365 para produtividade e identidade.

Também indicada para times de SOC em **fusion centers** ou **operações multi-subsidiária** que precisam visibilidade e resposta unificada em múltiplos clouds.

### Configurações

| Configuração | Cursos | CH Total | Perfil |
|:-------------|:-------|:--------:|:-------|
| **Azure + AWS** (padrão) | Curso 2 + Curso 3 | 80h | Bancos e seguradoras |
| **Azure + AWS + Google** (expandida) | Cursos 2 + 3 + 1 | 110h | Fusion centers, grupos financeiros grandes |
| **Azure + Google** | Curso 2 + Curso 1 | 70h | Organizações GCP + M365 |

### Sequência Recomendada

```
INÍCIO
  │
  ▼
Curso 2 — Azure SecOps (40h)
  Semanas 1–7
  Foco: Sentinel, KQL, Defender XDR, SC-200
  │
  ▼
Curso 3 — AWS SecOps (40h)
  Semanas 8–14
  Foco: GuardDuty, Security Hub, IR em AWS, SCS-C02
  │
  ▼ (opcional)
Curso 1 — Google SecOps (30h)
  Semanas 15–19
  Foco: Chronicle, YARA-L, SOAR, GCP Security
  │
  ▼
FIM — Profissional preparado para ambientes multi-cloud
```

> **Nota:** O Curso 2 antes do Curso 3 é recomendado porque o Microsoft Defender for Cloud também cobre AWS e GCP — ao estudar Curso 2 primeiro, o aluno já terá visão do ambiente AWS pela ótica do Defender for Cloud antes de mergulhar nos serviços nativos AWS no Curso 3.

---

## Trilha 3 — Cloud Security Architect (60h a 140h)

### Para quem é

**Arquitetos de segurança e líderes técnicos** que precisam:
- Avaliar e recomendar stacks de segurança em nuvem
- Tomar decisões de build vs buy entre ferramentas de CNAPP
- Governar a segurança em ambientes multi-cloud
- Se preparar para papéis de Head of Cloud Security ou pipeline de CISO

### Configurações

| Configuração | Cursos | CH | Certificações |
|:-------------|:-------|:--:|:--------------|
| **Especialista em Ferramentas** | Curso 4 + 1 curso SecOps | 60–70h | CCSP/CCSK + SC-200 ou SCS-C02 |
| **Architect completo** | Cursos 4 + 2 + 3 | 110h | CCSP + SC-200 + SCS-C02 |
| **Head of Cloud Security** | 4 cursos (completo) | 140h | CCSP + CCSK + SC-200 + SCS-C02 + GCP |

### Sequência Recomendada para Formação Completa (140h)

```
Semanas 1–5:   Curso 1 — Google SecOps (30h)
               SIEM/SOAR/TI — bases de detecção

Semanas 6–12:  Curso 2 — Azure SecOps (40h)
               Sentinel + Defender + SC-200

Semanas 13–19: Curso 3 — AWS SecOps (40h)
               GuardDuty + Security Hub + SCS-C02

Semanas 20–24: Curso 4 — Cloud Security Tools (30h)
               CNAPP + IaC + DevSecOps + CCSP/CCSK

Semana 25+:    Exames de Certificação
               SC-200 → SCS-C02 → GCP Security Eng. → CCSP
```

---

## Formatos Comerciais

### Turma Aberta (B2C)

Ideal para **profissionais autônomos** que querem investir no próprio desenvolvimento ou empresas que financiam formações individuais.

| Aspecto | Detalhes |
|:--------|:---------|
| **Calendário** | Datas fixas publicadas no portal CECyber |
| **Vagas** | 15–20 por turma (garantia de qualidade nas lives) |
| **Acesso** | Plataforma LMS CECyber + lives no horário publicado |
| **Validade do acesso** | 12 meses após a matrícula |
| **Certificado** | Digital com QR Code de validação |

### In-Company (B2B)

Para **organizações** que contratam formação fechada para seus times internos.

| Aspecto | Detalhes |
|:--------|:---------|
| **Turma** | Fechada, com contexto real do cliente |
| **Personalização** | Cenários de capstone adaptados ao stack do cliente |
| **Regulatório** | Conteúdo específico BACEN, SUSEP, ANPD conforme setor |
| **Laboratórios** | Possibilidade de usar tenants reais da organização |
| **Acompanhamento** | Relatório de progresso semanal para gestores |
| **Instrutor** | Mesmo profissional do início ao fim |

### Trilha Executiva (C-Level)

Para **CISOs, CROs, CTOs e board members** que precisam de visão estratégica sem mergulho técnico profundo.

| Aspecto | Detalhes |
|:--------|:---------|
| **Carga horária** | 8–16h extraídas dos cursos técnicos |
| **Foco** | Governança, riscos, investimento, decisão de aquisição |
| **Formato** | Lives exclusivas sem laboratório aprofundado |
| **Certificado** | Participação (não inclui certificação técnica) |
| **Linguagem** | Business-oriented: ROI, TCO, risk exposure, compliance gaps |

---

## Parcerias Estratégicas

### Fabricantes de Cloud

| Parceiro | Articulação |
|:---------|:-----------|
| **Microsoft** | Co-selling SC-200; acesso a conteúdo oficial Learning Path; tenant M365 E5 para labs |
| **Amazon AWS** | Alinhamento ao AWS Skill Builder; sandbox accounts para labs; SCS-C02 vouchers |
| **Google Cloud** | Alinhamento ao Google Cloud Skills Boost; tenant Chronicle para labs |

### Certificações Profissionais

| Parceiro | Articulação |
|:---------|:-----------|
| **CompTIA** | Caminho complementar CySA+ e CASP+; parceria existente CECyber |
| **EC-Council** | Extensão de CEH, CHFI e CTIA aplicada a cenários cloud |
| **ISC²** | Preparação para CCSP e CISSP (domínio de Cloud Security) |
| **CSA** | Alinhamento ao CCSK v5 e ao Cloud Security Guidance |

### Setor Financeiro

| Parceiro | Articulação |
|:---------|:-----------|
| **FEBRABAN** | Aderência ao guia de segurança cibernética FEBRABAN |
| **IBEF** | Disseminação para profissionais de finanças |
| **ABBC** | Bancos de pequeno e médio porte (foco na BACEN 4.893) |

---

## Como Escolher a Trilha Certa

### Perguntas Guia

1. **Qual é o cloud provider principal da minha organização?**
   - Um só: Trilha 1 (Single-Cloud) com o curso do seu provider
   - Múltiplos: Trilha 2 (Multi-Cloud)

2. **Qual é o objetivo de carreira?**
   - Analista de SOC operacional: Trilha 1 ou 2
   - Engenheiro de Detecção: Trilha 1 ou 2 com foco nos módulos de Detection Engineering
   - Arquiteto de Segurança: Trilha 3 — Architect
   - Liderança técnica (Head/CISO): Programa Completo (140h)

3. **Qual é a certificação alvo?**
   - SC-200: Curso 2 obrigatório
   - SCS-C02: Curso 3 obrigatório
   - CCSP/CCSK: Curso 4 obrigatório + complemento com experiência
   - GCP Security Engineer: Curso 1 + experiência GCP

4. **Qual é o tempo disponível?**
   - 5–7 semanas: Trilha 1 (um curso)
   - 14–19 semanas: Trilha 2 (dois cursos)
   - 25+ semanas: Programa completo (com tempo para certificações)

---

*Trilhas de Formação · Programa Security Operations em Nuvem · CECyber · v2.0 · 2026*
