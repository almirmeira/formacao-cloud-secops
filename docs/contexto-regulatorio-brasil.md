# Contexto Regulatório Brasileiro para Cloud Security
## Programa de Formação Security Operations em Nuvem · CECyber

---

## Introdução

O Brasil possui um dos ecossistemas regulatórios de cibersegurança mais desenvolvidos da América
Latina, especialmente no setor financeiro. Profissionais que operam segurança em nuvem no Brasil
precisam compreender não apenas as melhores práticas técnicas internacionais, mas também as
obrigações legais e regulatórias que determinam requisitos mínimos de controles, prazos de resposta
a incidentes e obrigações de notificação.

Este documento apresenta as principais normas relevantes para Cloud Security no Brasil, explicando
suas exigências específicas e como elas se conectam ao conteúdo dos 4 cursos do programa.

---

## 1. Resolução BACEN 4.893/2021 — Política de Segurança Cibernética

### O que é

A Resolução CMN 4.893 de 26 de fevereiro de 2021 regulamenta a **política de segurança cibernética**
e os requisitos para contratação de serviços de processamento e armazenamento de dados para
**instituições financeiras (IFs)** autorizadas a funcionar pelo Banco Central do Brasil.

### Exigências Principais para Cloud Security

| Artigo  | Exigência                                                                     | Impacto para Cloud SecOps          |
|:-------:|:------------------------------------------------------------------------------|:-----------------------------------|
| Art. 2º | IF deve ter política de segurança cibernética aprovada pela diretoria         | Governance e CISO responsibilities |
| Art. 4º | Programa de testes de penetração anuais mínimos                               | Red team e vulnerability management|
| Art. 5º | Incidente relevante: notificar BACEN em até 72h da identificação              | Incident response e SIEM alerting  |
| Art. 6º | Manter registro de incidentes por pelo menos 5 anos                           | Log retention (CloudTrail Lake, Sentinel) |
| Art. 7º | Testes e verificações periódicas de efetividade dos controles                 | Security Hub, Config, Inspector    |
| Art. 8º | Due diligence de segurança para contratação de serviços em nuvem              | CSPM e avaliação de provedores     |
| Art. 14 | Relatório anual de segurança cibernética ao Banco Central                     | Reporting e métricas de SOC        |

### Definição de "Incidente Relevante" (para fins de notificação)

A BACEN considera relevante um incidente que:
- Afete 0,1% ou mais da base de clientes (ou 1.000 clientes, o que for maior)
- Comprometa dados pessoais de clientes em volume significativo
- Resulte em indisponibilidade de serviços essenciais por mais de 4 horas

### Conexão com os Módulos do Programa

| Módulo/Curso                                     | Requisito BACEN Relacionado           |
|:-------------------------------------------------|:--------------------------------------|
| Curso 2, Módulo 07 (Defender for Cloud)          | Art. 8º — due diligence de provedores |
| Curso 3, Módulo 04 (Security Hub + Config)       | Art. 7º — testes de efetividade       |
| Todos os cursos, Módulo Capstone                 | Art. 5º — IR e notificação            |
| Curso 3, Módulo 02 (CloudTrail Lake)             | Art. 6º — retenção de logs (5 anos)   |

---

## 2. Resolução CMN 4.658/2018 — Contratação de Serviços em Nuvem

### O que é

A Resolução CMN 4.658 de 26 de abril de 2018 estabelece condições para a **contratação de
serviços de processamento e armazenamento de dados e de computação em nuvem** por instituições
financeiras.

### Exigências Principais

| Exigência                                       | Detalhes                                                          |
|:------------------------------------------------|:------------------------------------------------------------------|
| **Due diligence do provedor**                   | IF deve verificar que o provedor tem controles de segurança adequados |
| **Localização dos dados**                       | Dados de clientes podem ser armazenados no exterior, mas IF mantém responsabilidade |
| **Auditabilidade**                              | Provedor deve permitir auditoria (direta ou por terceiro autorizado) |
| **Plano de contingência**                       | Estratégia de saída e portabilidade de dados com prazo definido   |
| **Notificação ao BACEN**                        | Comunicação prévia de contratação de provedores cloud "relevantes" |
| **Controle de acesso**                          | Segregação de funções e controle de acesso privilegiado           |

### Relevância para Cloud SecOps

Esta resolução é a razão pela qual bancos brasileiros têm rigorosos processos de avaliação de
segurança de provedores cloud (AWS, Azure, GCP). O time de Cloud SecOps deve conhecer esses
requisitos para:
- Configurar corretamente os controles exigidos em ambientes cloud
- Preparar evidências de conformidade para auditorias do BACEN
- Configurar o Security Hub / Defender for Cloud com os padrões brasileiros relevantes

---

## 3. LGPD — Lei Geral de Proteção de Dados (Lei 13.709/2018)

### O que é

A Lei 13.709/2018 — **Lei Geral de Proteção de Dados Pessoais (LGPD)** — é a principal lei
brasileira de privacidade, inspirada no GDPR europeu. Vigente desde 2020 com aplicação das sanções
desde 2021.

### Artigos Mais Relevantes para Cloud Security

| Artigo  | Dispositivo                                                                   | Impacto Técnico                      |
|:-------:|:------------------------------------------------------------------------------|:-------------------------------------|
| Art. 46 | Controlador e operador devem adotar medidas de segurança adequadas            | CSPM, CWPP, criptografia             |
| Art. 48 | Notificação de vazamento ao titular e à ANPD em prazo razoável               | Incident response < 72h              |
| Art. 49 | Sistemas utilizados devem ser controlados e auditáveis                        | Logging, CloudTrail, Sentinel        |
| Art. 50 | Adoção de boas práticas de governança e política de segurança                 | Framework de segurança               |

### LGPD e Cloud Security: Conexão Técnica

```
DADOS PESSOAIS NA NUVEM (LGPD)
─────────────────────────────────────────────────────────────────
Tipo de Dado Pessoal        Controles Técnicos Exigidos
────────────────────        ─────────────────────────────────────
Dados comuns                • Criptografia em repouso (KMS, AES-256)
                            • Controle de acesso (IAM + RBAC)
                            • Logging de acesso (CloudTrail, Sentinel)

Dados sensíveis (art. 11)   • Controles mais rigorosos
(saúde, raça, biometria)    • Data Loss Prevention (Macie, Purview)
                            • Classificação de dados (DSPM)
                            • Segregação de ambientes

Tratamento para             • DPA (Data Processing Agreement)
terceiros (operador)        • Cláusulas contratuais específicas
                            • Auditabilidade do operador
─────────────────────────────────────────────────────────────────
```

### Amazon Macie e LGPD

O Amazon Macie (Curso 3, Módulo 06) é particularmente relevante para LGPD, pois:
- Identifica automaticamente CPF, CNPJ, dados de cartão de crédito e outros PIIs em buckets S3
- Gera relatórios de exposição de dados pessoais para fins de inventário LGPD
- Detecta buckets S3 com dados pessoais acessíveis publicamente

---

## 4. Marco Civil da Internet (Lei 12.965/2014)

### Relevância para Cloud Security

| Dispositivo                                    | Impacto para Cloud SecOps                          |
|:-----------------------------------------------|:---------------------------------------------------|
| Guarda de registros de conexão por 1 ano       | Retenção de VPC Flow Logs e logs de rede           |
| Guarda de logs de aplicação por 6 meses        | Retenção de logs de aplicação em CloudWatch/Sentinel |
| Entrega de logs a autoridades mediante ordem   | Procedimentos de resposta a autoridades (Legal Hold) |
| Responsabilidade de provedores de conexão      | Segregação de responsabilidades com ISPs           |

---

## 5. Resolução SUSEP 4.553 — Seguradoras

A Resolução SUSEP 4.553/2022 aplica requisitos similares à BACEN 4.893 para o **setor de seguros**,
exigindo que seguradoras, resseguradoras e entidades de previdência complementar mantenham políticas
de segurança cibernética e reportem incidentes à SUSEP.

**Relevância:** Seguradoras que utilizam AWS, Azure ou GCP devem configurar os mesmos controles
técnicos descritos nos Cursos 2 e 3, adaptando os conformance packs do Security Hub e do
Defender for Cloud para incluir os requisitos da SUSEP.

---

## 6. Referência Cruzada: Normas × Serviços Cloud

| Norma Brasileira   | AWS                               | Azure / Microsoft 365              | Google Cloud                    |
|:-------------------|:----------------------------------|:-----------------------------------|:--------------------------------|
| BACEN 4.893        | Security Hub (BACEN conformance pack), GuardDuty, CloudTrail | Sentinel + Defender for Cloud, Purview compliance | Chronicle SIEM, Security Command Center |
| CMN 4.658          | AWS Artifact (relatórios de conformidade), Shared Responsibility | Azure Compliance Manager, Microsoft Trust Center | Google Cloud Compliance Reports |
| LGPD               | Amazon Macie, AWS KMS, S3 Object Lock | Microsoft Purview (Information Protection), Azure Information Protection | Cloud DLP, Cloud KMS |
| Marco Civil        | CloudWatch Logs (retenção 1–6 anos), CloudTrail Lake | Log Analytics Workspace (retenção configurável), Sentinel | Cloud Logging (retenção configurável) |

---

## 7. Como o Programa Aborda o Contexto Regulatório Brasileiro

O contexto regulatório brasileiro é **integrado transversalmente** em todos os cursos:

| Curso | Integração Regulatória                                                          |
|:-----:|:--------------------------------------------------------------------------------|
|   1   | Cenário Banco Meridian sujeito à BACEN 4.893; playbooks SOAR incluem notificação ao BACEN |
|   2   | Defender for Cloud com standards BACEN; Sentinel com watchlists de compliance LGPD |
|   3   | Security Hub conformance pack BACEN customizado; Macie para compliance LGPD; GuardDuty para IR BACEN |
|   4   | Prowler com checks BACEN; avaliação de postura inclui critérios regulatórios brasileiros |

### Cenário Padrão: Banco Meridian e BACEN 4.893

O Banco Meridian (empresa fictícia usada em todos os labs) está sujeito à BACEN 4.893. Isso
significa que, em todos os cenários de incidente, o aluno deve:

1. **Detectar** o incidente via SIEM/GuardDuty em tempo hábil
2. **Classificar** se o incidente se enquadra como "relevante" (pelo critério BACEN)
3. **Notificar internamente** a cadeia: SOC → CISO → DPO → CEO → Jurídico
4. **Notificar o Banco Central** em até 72 horas se o incidente for relevante
5. **Documentar** todo o processo para o relatório anual de segurança cibernética

---

## 8. Leitura Complementar Recomendada

| Documento                                                       | Fonte       | Acesso                              |
|:----------------------------------------------------------------|:-----------:|:-------------------------------------|
| Resolução CMN 4.893/2021                                        | BACEN       | bcb.gov.br/legislacao               |
| Resolução CMN 4.658/2018                                        | BACEN       | bcb.gov.br/legislacao               |
| Lei 13.709/2018 (LGPD)                                         | ANPD        | anpd.gov.br                          |
| Guia de Segurança em Nuvem ANPD                                 | ANPD        | anpd.gov.br/publicacoes              |
| Marco Civil da Internet                                         | CGI.br      | cgibr.br                            |
| CERT.BR — Relatório de Incidentes                               | NIC.br      | cert.br/stats                        |
| Cartilha de Segurança para Internet CERT.BR                     | NIC.br      | cartilha.cert.br                     |
| FEBRABAN — Guia de Segurança Cibernética para o Setor Financeiro | FEBRABAN   | febraban.org.br                      |

---

*Contexto Regulatório Brasileiro · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
