# Lab Capstone — Operação Guaraná: Resposta a APT

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas (incluindo apresentação live)                                  |
| **Módulo de referência** | Módulo 10 — Capstone                                                   |
| **Pré-requisito**        | TODOS os labs anteriores (01, 03, 04, 05, 06) concluídos              |
| **Nível**                | Avançado                                                               |

---

## Instruções de Execução

Este lab capstone integra TODO o conhecimento dos módulos anteriores. Ele deve ser executado **individualmente ou em dupla**, com apresentação oral dos resultados na sessão live.

### Cenário Completo

O cenário de ataque completo está documentado no **Módulo 10** (modulo-10-capstone/README.md). Antes de iniciar este lab, leia o Módulo 10 na íntegra.

### O que você deve fazer

1. **Investigar o incidente** usando o ambiente do lab com os dados simulados do ataque
2. **Criar as 5 analytics rules** que teriam detectado o ataque mais cedo
3. **Executar as queries de hunting** para reconstruir a timeline
4. **Produzir os 4 entregáveis** descritos no Módulo 10

---

## Seção 1 — Contexto Situacional

Ver **Módulo 10, seção "O Incidente: Cadeia de Ataque Completa"** para o contexto completo.

**Resumo**: O Grupo Lazarus-BR comprometeu a conta de `ana.lima@bancomeridian-lab.onmicrosoft.com` via AiTM phishing e executou um ataque de 6 fases ao longo de 31 horas.

---

## Seção 2 — Situação Inicial

O ambiente do lab contém:
- Todos os dados simulados das 6 fases do ataque injetados no workspace
- Incidente HIGH aberto no Sentinel: "Operação Guaraná — Comprometimento AiTM"
- Nenhuma analytics rule ativa para os vetores de ataque utilizados

---

## Seção 3 — Problema Identificado

6 fases de ataque ocorreram sem detecção automática:
1. Spearphishing com AiTM entregue
2. Token OAuth roubado
3. 3.247 arquivos exfiltrados
4. Regra de encaminhamento de e-mail criada
5. Service principal com permissões perigosas registrado
6. Acesso persistente via refresh token OAuth

---

## Seção 4 — Roteiro de Atividades

1. Analisar o incidente aberto no Sentinel
2. Executar as 6 queries de investigação (Módulo 10, Seções "Evidências")
3. Criar a timeline MITRE ATT&CK (Entregável 1)
4. Criar as 5 analytics rules do Módulo 10 (Entregável 2)
5. Executar o playbook de conta comprometida no usuário ana.lima
6. Escrever o relatório executivo (Entregável 3)
7. Preencher o plano de remediação (Entregável 4)
8. Preparar apresentação para a sessão live (15 minutos)

---

## Seção 5 — Proposição

Ao final deste lab:
- Timeline MITRE ATT&CK completa e precisa (6 fases mapeadas)
- 5 analytics rules KQL funcionais criadas no Sentinel
- Relatório executivo de 2 páginas para o CISO
- Plano de remediação priorizado com 10 ações
- Apresentação preparada para a live de 15 minutos

---

## Seção 6 — Script de Investigação

### Queries de Investigação a Executar

**Fase 1 — E-mail de phishing**:
```kql
EmailEvents
| where TimeGenerated >= datetime(2025-04-07 10:00)
| where RecipientEmailAddress == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where SenderFromDomain contains "microsoftsuporte"
| project TimeGenerated, SenderFromAddress, Subject, DeliveryAction, ThreatTypes
```

**Fase 2 — Login com token roubado**:
```kql
SigninLogs
| where TimeGenerated >= datetime(2025-04-07 10:25)
| where UserPrincipalName == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where Location !contains "BR"
| project TimeGenerated, IPAddress, Location, 
          AuthenticationRequirement, DeviceDetail, RiskLevelDuringSignIn
```

**Fase 3 — Exfiltração OneDrive** (referência ao Módulo 10):
```kql
// Usar query da Seção "Fase 3" do Módulo 10
// Resultado: pico de downloads entre Seg 10:45 e Ter 18:00
```

**Fase 4 — Regra de e-mail**:
```kql
OfficeActivity
| where TimeGenerated >= datetime(2025-04-08 08:00)
| where UserId == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where Operation == "New-InboxRule"
| project TimeGenerated, UserId, ClientIP, Parameters
```

**Fase 5 — OAuth App**:
```kql
AuditLogs
| where TimeGenerated >= datetime(2025-04-08 14:00)
| where OperationName in ("Add application", "Add app role assignment to service principal")
| where InitiatedBy.user.userPrincipalName == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| project TimeGenerated, OperationName, TargetResources
```

**Timeline Completa**:
```kql
// Usar a query de Timeline do Módulo 10 para montar a sequência completa
let user = "ana.lima@bancomeridian-lab.onmicrosoft.com";
union
    (EmailEvents | where RecipientEmailAddress == user | project TimeGenerated, Phase = "Fase 1 - Phishing"),
    (SigninLogs | where UserPrincipalName == user | where Location !contains "BR" | project TimeGenerated, Phase = "Fase 2 - Token Theft"),
    (OfficeActivity | where UserId == user | where Operation == "FileDownloaded" | where ClientIP == "5.2.67.44" | project TimeGenerated, Phase = "Fase 3 - Exfiltration"),
    (OfficeActivity | where UserId == user | where Operation == "New-InboxRule" | project TimeGenerated, Phase = "Fase 4 - Email Forward"),
    (AuditLogs | where InitiatedBy.user.userPrincipalName == user | where OperationName contains "application" | project TimeGenerated, Phase = "Fase 5 - OAuth App")
| sort by TimeGenerated asc
```

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                             | Verificação                                          |
|:-----:|:-----------------------------------------------------|:-----------------------------------------------------|
| 1     | Investigar o incidente no Sentinel                   | Incidente aberto, alertas e entities identificados   |
| 2     | Executar as 6 queries de investigação               | Resultados documentados para cada fase               |
| 3     | Criar timeline MITRE ATT&CK                          | Tabela completa com 6 fases e TTPs                   |
| 4     | Criar as 5 analytics rules                           | Todas as 5 rules em Analytics → Active rules         |
| 5     | Executar playbook no ana.lima                        | Sessões revogadas; comentário no incidente           |
| 6-7   | Produzir relatório e plano de remediação             | 2 entregáveis documentados                           |
| 8     | Preparar apresentação de 15 min                      | Apresentação cobrindo todos os 4 entregáveis        |

---

## Seção 8 — Gabarito e Rubrica de Avaliação

### Gabarito Completo

**O gabarito completo está no Módulo 10**, seção "Gabarito Completo do Instrutor".

### Rubrica de Avaliação

| Critério                               | Peso | Pontos Máximos |
|:---------------------------------------|:----:|:--------------:|
| Timeline MITRE ATT&CK (6 fases)        | 20%  | 20 pontos      |
| 5 Analytics rules funcionais           | 30%  | 30 pontos      |
| Relatório executivo (clareza + completude) | 20% | 20 pontos   |
| Plano de remediação priorizado         | 20%  | 20 pontos      |
| Apresentação oral (live session)       | 10%  | 10 pontos      |
| **Total**                              | **100%** | **100 pontos** |

**Mínimo para aprovação**: 70 pontos

---

## Instruções de Entrega

**Entrega antes da live session**:
1. Enviar os 4 entregáveis documentados ao instrutor via email/LMS
2. Formato: documento Word, PDF ou Markdown
3. Prazo: 1 hora antes da sessão live

**Na sessão live**:
1. Apresentação de 15 minutos
2. Demo ao vivo de 2 das 5 analytics rules no Sentinel
3. Q&A de 5 minutos com o instrutor

**Critérios de excelência** (90+ pontos):
- Timeline identifica IOCs específicos (IPs, domínios, AppIDs)
- Analytics rules incluem entity mapping e MITRE tagging completos
- Relatório executivo usa linguagem de negócio (sem jargão técnico excessivo)
- Plano de remediação distingue ações imediatas/curto/longo prazo com justificativa de negócio
