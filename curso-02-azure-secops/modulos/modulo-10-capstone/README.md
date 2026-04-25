# Módulo 10 — Capstone: Operação Guaraná

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 2 horas (1h laboratório + 1h live de apresentação e defesa)                 |
| **Formato**              | Trabalho individual ou dupla + apresentação ao vivo                        |
| **Pré-requisito**        | Todos os módulos anteriores (01–09) concluídos                              |
| **Certificação Alvo**    | SC-200 — Prova simulada; todos os domínios                                  |
| **Cenário**              | APT simulado contra o Banco Meridian — investigação e resposta completa     |

---

## Contexto: A Ameaça

O **Grupo Lazarus-BR** (ator de ameaça fictício) é um grupo APT com foco em instituições financeiras da América Latina. Nos últimos 6 meses, o grupo realizou ataques bem-sucedidos contra 3 bancos tier-2 brasileiros, com prejuízos estimados em R$ 45 milhões. O modus operandi identificado pelo FS-ISAC:

1. Reconhecimento via LinkedIn e redes sociais (funcionários de TI e financeiro)
2. Spearphishing com AiTM (Adversary-in-the-Middle) para bypass de MFA
3. Roubo de token OAuth e acesso persistente via app registration
4. Exfiltração lenta de dados ao longo de semanas (low & slow)
5. Transferências fraudulentas via acesso ao sistema SWIFT/core banking

O CISO do Banco Meridian recebeu um alerta do FS-ISAC às 07h42 de uma segunda-feira. Você, como analista SOC L3, é o responsável pela investigação.

---

## O Incidente: Cadeia de Ataque Completa

### Fase 1 — Spearphishing com AiTM (Segunda, 10h23)

**O que aconteceu**: `ana.lima@bancomeridian.com.br` (Gerente de TI) recebeu um e-mail de `ana.lima@microsoftsuporte-br.com` (domínio typosquatted) com assunto "Ação necessária: revise o acesso da sua equipe ao Microsoft 365". O e-mail continha um link que apontava para um proxy AiTM configurado para roubar o token OAuth após autenticação legítima.

**Evidências no Sentinel**:
```kql
EmailEvents
| where TimeGenerated >= datetime(2025-04-07 10:00)
| where RecipientEmailAddress == "ana.lima@bancomeridian.com.br"
| where SenderFromDomain contains "microsoftsuporte"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, DeliveryAction, ThreatTypes
```

**Resultado esperado**: 1 e-mail, DeliveryAction = "Delivered" (passou pelo filtro), ThreatTypes = "" (ainda não classificado como phishing na hora da entrega).

### Fase 2 — Roubo de Token OAuth (Segunda, 10h31)

**O que aconteceu**: Ana Lima clicou no link e fez login legítimo com MFA no proxy AiTM. O proxy roubou o token de sessão e o usou de um servidor na Romênia (IP: 5.2.67.44).

**Evidências no Sentinel**:
```kql
SigninLogs
| where TimeGenerated >= datetime(2025-04-07 10:25)
| where UserPrincipalName == "ana.lima@bancomeridian.com.br"
| where IPAddress == "5.2.67.44"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AuthenticationRequirement, ConditionalAccessStatus,
          RiskLevelDuringSignIn, DeviceDetail
```

**Resultado esperado**: 1 login bem-sucedido; AuthenticationRequirement = "singleFactorAuthentication" (token não exigiu MFA pois já estava autenticado); Location = "RO" (Romênia); DeviceDetail.deviceId vazio.

### Fase 3 — Exfiltração de OneDrive (Segunda 10h45 — Terça 18h00)

**O que aconteceu**: Usando o token roubado, o atacante acessou o OneDrive de Ana Lima e baixou 3.247 arquivos ao longo de 31 horas — lentamente para evitar detecção por threshold simples de volume.

**Evidências no Sentinel**:
```kql
OfficeActivity
| where TimeGenerated between (datetime(2025-04-07 10:40) .. datetime(2025-04-08 18:00))
| where UserId == "ana.lima@bancomeridian.com.br"
| where Operation == "FileDownloaded"
| where ClientIP == "5.2.67.44"
| summarize TotalFiles = count(), 
            UniqueFileTypes = dcount(SourceFileExtension),
            SitesAccessed = dcount(SiteUrl)
            by bin(TimeGenerated, 1h), ClientIP
```

**Resultado esperado**: ~100 downloads/hora por 31 horas = 3.247 arquivos total. Volume baixo por hora para evitar detecção por threshold simples.

### Fase 4 — Regra de Encaminhamento de E-mail (Terça, 08h14)

**O que aconteceu**: O atacante criou uma regra de encaminhamento de e-mail para `lazarus-collection@proton.me`, encaminhando automaticamente todos os e-mails recebidos por Ana Lima que contivessem "swift", "bacen", "transferência", "aprovação".

**Evidências no Sentinel**:
```kql
OfficeActivity
| where TimeGenerated >= datetime(2025-04-08 08:00)
| where UserId == "ana.lima@bancomeridian.com.br"
| where Operation == "New-InboxRule"
| project TimeGenerated, UserId, ClientIP, 
          Parameters = parse_json(Parameters)
```

**Resultado esperado**: Operação New-InboxRule; Parameters deve mostrar o critério de filtro e o endereço de encaminhamento externo.

### Fase 5 — Escalada via Service Principal (Terça, 14h33)

**O que aconteceu**: O atacante usou as permissões de Gerente de TI de Ana Lima para registrar um novo aplicativo OAuth no Entra ID com permissões `Mail.ReadWrite.All` e `Directory.ReadWrite.All`. Em seguida, adicionou esse service principal ao grupo "Azure AD Admins".

**Evidências no Sentinel**:
```kql
AuditLogs
| where TimeGenerated >= datetime(2025-04-08 14:00)
| where OperationName in ("Add application", "Add app role assignment to service principal")
| where InitiatedBy.user.userPrincipalName == "ana.lima@bancomeridian.com.br"
| project TimeGenerated, OperationName,
          AppName = tostring(TargetResources[0].displayName),
          Permissions = tostring(TargetResources[0].modifiedProperties)
```

### Fase 6 — Persistência via OAuth App (Terça, 15h17)

**O que aconteceu**: Com o service principal agora com permissões de diretório, o atacante obteve tokens OAuth de longa duração (refresh tokens de 90 dias) que persistiriam mesmo após o reset de senha de Ana Lima.

**Evidências no Sentinel**:
```kql
// Verificar atividade do app suspeito
CloudAppEvents
| where TimeGenerated >= datetime(2025-04-08 15:00)
| where ApplicationId in ("AppID-do-app-malicioso")
| summarize 
    Actions = make_set(ActionType, 20),
    AccessedUsers = dcount(AccountObjectId),
    LastSeen = max(TimeGenerated)
    by ApplicationId, ApplicationDisplayName
```

---

## Entregáveis do Capstone

### Entregável 1 — Timeline MITRE ATT&CK

Construa uma tabela completa mapeando cada fase do ataque aos TTPs MITRE ATT&CK:

| Timestamp         | Fase               | Técnica MITRE                    | Tática         | Evidência                          |
|:------------------|:-------------------|:---------------------------------|:---------------|:-----------------------------------|
| Seg 10:23         | Spearphishing AiTM | T1566.002 (Spearphishing Link)   | Initial Access | EmailEvents — email de typosquatted domain |
| Seg 10:31         | Token Theft        | T1557 (AiTM) / T1539            | Credential Access | SigninLogs — SFA login sem device |
| Seg 10:45–Ter 18h | OneDrive Exfil     | T1530 (Data from Cloud Storage) | Collection / Exfiltration | OfficeActivity FileDownloaded |
| Ter 08:14         | E-mail Forwarding  | T1114.003 (Email Forwarding Rule) | Collection   | OfficeActivity New-InboxRule      |
| Ter 14:33         | OAuth App Reg.     | T1550.001 (OAuth Tokens)         | Persistence    | AuditLogs Add application         |
| Ter 15:17         | Persistent Access  | T1528 (Steal App Access Token)   | Credential Access | CloudAppEvents app token usage  |

### Entregável 2 — 5 Analytics Rules de Detecção

Crie as analytics rules KQL que teriam detectado este ataque mais cedo:

**Rule 1: AiTM Token Theft Detection** (detecta Fase 2)
```kql
// Basear na Rule 4 do Módulo 04 (Token Theft / AiTM)
// Ajustar para detectar login sem device ID de país nunca usado pelo usuário
SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| where isempty(tostring(parse_json(tostring(DeviceDetail)).deviceId))
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize HasMFAHistory = count() by UserPrincipalName
) on UserPrincipalName
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AuthenticationRequirement, RiskLevelDuringSignIn
```

**Rule 2: Anomalous OneDrive Volume Download** (detecta Fase 3)
```kql
// Adaptar Rule 5 do Módulo 04 (Exfiltração SharePoint)
// Adicionar critério: mesmo IP que login suspeito
let suspiciousIPs = SigninLogs
| where TimeGenerated > ago(2h)
| where RiskLevelDuringSignIn in ("medium", "high")
| distinct IPAddress;

OfficeActivity
| where TimeGenerated > ago(2h)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| where ClientIP in (suspiciousIPs)
| summarize Downloads = count() by UserId, ClientIP, bin(TimeGenerated, 30m)
| where Downloads >= 50
```

**Rule 3: Email Forwarding Rule to External Domain** (detecta Fase 4)
```kql
// Analytics rule específica para inbox forwarding rules
OfficeActivity
| where TimeGenerated > ago(5m)
| where Operation == "New-InboxRule" or Operation == "Set-InboxRule"
| extend RuleParams = parse_json(Parameters)
// Verificar se há encaminhamento para domínio externo
| where tostring(RuleParams) contains "ForwardTo" 
    or tostring(RuleParams) contains "ForwardAsAttachmentTo"
// Excluir domínios internos
| where not (tostring(RuleParams) contains "bancomeridian.com.br")
| project TimeGenerated, UserId, ClientIP, Parameters
```

**Rule 4: Suspicious OAuth App Registration** (detecta Fase 5)
```kql
// Usar Rule 3 do Módulo 04 (Service Principal + Role)
// Adaptar para incluir detecção de novo app com permissões perigosas
AuditLogs
| where TimeGenerated > ago(5m)
| where OperationName in ("Add application", "Add delegated permission grant", 
                           "Add app role assignment to service principal")
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.ReadWrite", "Mail.ReadWrite.All",
                              "Directory.ReadWrite.All", "Files.ReadWrite.All")
| project TimeGenerated, OperationName, 
          InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
          AppName = tostring(TargetResources[0].displayName),
          Permissions
```

**Rule 5: Impossible Travel — Download Correlation** (detecta correlação Fases 2+3)
```kql
// Correlação: login de IP estrangeiro SEGUIDO de download massivo do mesmo IP
let suspiciousLogins = SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0
| where Location !contains "BR"
| where AuthenticationRequirement == "singleFactorAuthentication"
| project LoginTime = TimeGenerated, UserPrincipalName, SuspiciousIP = IPAddress;

OfficeActivity
| where TimeGenerated > ago(2h)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| join kind=inner suspiciousLogins 
    on $left.UserId == $right.UserPrincipalName,
       $left.ClientIP == $right.SuspiciousIP
| summarize Downloads = count() by UserId, ClientIP, LoginTime
| where Downloads >= 20
```

### Entregável 3 — Relatório Executivo

O relatório executivo deve ter no máximo 2 páginas e cobrir:

```
RELATÓRIO DE INCIDENTE — CONFIDENCIAL
Banco Meridian — SOC
Data: [data da investigação]
Incidente: BancM-2025-0023 — Comprometimento de Conta via AiTM

1. RESUMO EXECUTIVO (5 linhas)
   - O que aconteceu (linguagem não técnica)
   - Impacto para o negócio
   - Status atual da ameaça
   - Ações tomadas
   - Próximos passos

2. LINHA DO TEMPO
   [Tabela simplificada com as 6 fases]

3. DADOS COMPROMETIDOS
   - 3.247 arquivos do OneDrive de Ana Lima (período: Seg 10:45 — Ter 18:00)
   - E-mails encaminhados: estimativa [X] e-mails com palavras-chave swift/bacen
   - Dados de diretório AD via service principal de alta permissão

4. VULNERABILIDADES EXPLORADAS
   - Ausência de detecção de AiTM no momento da entrega (MDO não classificou como phishing)
   - Conditional Access não bloqueia SFA para aplicações críticas (recomendação: Módulo 8)
   - Ausência de analytics rule para detecção de regra de encaminhamento externa

5. AÇÕES TOMADAS (SOC)
   - [O que o playbook automatizou]
   - [O que foi feito manualmente]

6. RECOMENDAÇÕES
   a. Imediatas (próximas 24-48h): [3 ações]
   b. Curto prazo (1-4 semanas): [3 ações]
   c. Longo prazo (1-3 meses): [3 ações]
```

### Entregável 4 — Plano de Remediação

| Prioridade | Ação                                                              | Produto              | Responsável | Prazo   |
|:----------:|:------------------------------------------------------------------|:--------------------:|:-----------:|:-------:|
| Crítica    | Revogar TODAS as sessões de Ana Lima e forçar reset de senha      | Entra ID             | SOC         | Imediato|
| Crítica    | Revogar e deletar o OAuth app registrado (Fase 5)                 | Entra ID             | SOC         | Imediato|
| Crítica    | Remover a regra de encaminhamento de e-mail                       | Exchange Online      | SOC         | Imediato|
| Alta       | Bloquear IP 5.2.67.44 e range /24 no firewall e CA policy         | Entra ID / Fortinet  | SOC + TI    | 2h      |
| Alta       | Criar analytics rules para as 5 detecções identificadas           | Sentinel             | SOC L3      | 24h     |
| Alta       | Ativar MDO para classificar domínios typosquatted                 | MDO                  | SOC + TI    | 24h     |
| Média      | Habilitar CA policy: bloquear SFA para aplicações críticas        | Entra ID             | SOC + Segurança | 48h |
| Média      | Revisar todos os OAuth apps registrados nos últimos 90 dias       | Entra ID             | Segurança   | 1 semana|
| Baixa      | Treinamento de phishing awareness para gerentes de TI             | Purview              | RH + TI     | 1 mês   |
| Baixa      | Implementar FIDO2 hardware keys para contas privilegiadas         | Entra ID             | TI          | 3 meses |

---

## Gabarito Completo do Instrutor

### Seção 1: Análise das Evidências

**Fase 1 — Spearphishing**

O e-mail passou pelo MDO porque o domínio `microsoftsuporte-br.com` era recente (menos de 24h) e ainda não estava nos feeds de threat intelligence. Isso é o "gap de detecção de domínio novo" — o MDO não consegue classificar domínios que nunca apareceram antes.

*Lição*: Habilitar "Zero-hour auto purge" e integrar feeds de TI de typosquatting monitoring (ex.: dnstwist) ao Sentinel via TAXII.

**Fase 2 — AiTM Token Theft**

Os sinais diagnósticos:
- `AuthenticationRequirement == "singleFactorAuthentication"` — o token não exigiu MFA (foi roubado após MFA ser completado no proxy)
- `DeviceDetail.deviceId` vazio — token emitido para dispositivo não registrado
- País = "RO" (Romênia) — país nunca usado por Ana Lima

*Por que o CA não bloqueou?* A Conditional Access policy estava configurada para exigir MFA em médio risco. O risk sign-in foi calculado como "Low" inicialmente porque o IP romeno ainda não estava na lista negra do MSTIC. O token teve claim de MFA do proxy — o CA "viu" MFA completado.

*Correção*: Adicionar condição CA para bloquear SFA para aplicações críticas MESMO com MFA claim, se o device não for registrado e compliant.

**Fase 3 — Exfiltração Low & Slow**

O atacante baixou ~100 arquivos/hora por 31 horas. Uma threshold simples de "mais de 500 downloads em 24h" teria detectado às 5h de atividade. Mas o banco não tinha tal rule configurada.

*Por que não detectou por si só?* Threshold baseado em hora por hora não era suficiente — cada hora estava abaixo de qualquer threshold razoável para uma gerente de TI. A detecção requer comparação com a baseline histórica do usuário (Rule de anomalia de volume do Módulo 04).

*Quanto foi exfiltrado?* 3.247 arquivos. Se cada arquivo tem em média 500KB = ~1.6 GB. Em termos de dados sensíveis: arquitetura de rede, políticas de segurança, planilhas de sistemas, dados de clientes VIP, credenciais de aplicações legadas.

**Fase 4 — Email Forwarding Rule**

A regra foi criada no Exchange via API do Graph, usando o token OAuth válido de Ana Lima. Os e-mails com palavras-chave "swift", "bacen", "transferência" eram encaminhados para `lazarus-collection@proton.me`.

Durante as próximas 48h antes da detecção, estimativa de 23 e-mails foram encaminhados contendo detalhes de transações SWIFT pendentes.

*Impacto regulatório*: Vazamento de dados de operações SWIFT é notificável ao BACEN (Res. 4.893, Art. 23) dentro de 72h.

**Fase 5 e 6 — OAuth App e Persistência**

O app OAuth registrado com permissões de alto privilégio era o mecanismo de persistência. Mesmo que a senha de Ana Lima fosse resetada, o atacante poderia continuar operando através do service principal enquanto o app não fosse revogado.

*Por que `Directory.ReadWrite.All` é especialmente perigoso?* Com essa permissão, o service principal poderia criar novos usuários, modificar grupos, e até adicionar novas contas de administrador — tornando a limpeza muito mais complexa.

### Seção 2: Análise das Analytics Rules

**Rule 1 — AiTM Token Theft**: Detectaria Fase 2 em ~30 minutos após o login suspeito. Com alert grouping por Account, um único incidente seria criado mesmo que o atacante fizesse múltiplos logins.

**Rule 2 — Anomalous OneDrive Volume**: Detectaria Fase 3 aproximadamente 4-5 horas após início da exfiltração (precisaria do baseline de 30 dias para calcular o múltiplo). Com threshold de 5x baseline diário/hora, o alerta dispararia quando a taxa de download excedesse 5x a média horária histórica de Ana Lima (~5 downloads/hora × 5 = 25 downloads/hora — threshold atingido na 1ª hora de exfiltração intensa).

**Rule 3 — Email Forwarding External**: Detectaria Fase 4 dentro de 5 minutos. Esta rule deveria ser NRT (Near Real-Time) dada a criticidade — regra de encaminhamento externa é quase sempre maliciosa quando criada de forma automatizada.

**Rule 4 — OAuth App Registration**: Detectaria Fase 5 dentro de 5 minutos após o registro do app. MITRE T1550.001 é uma das técnicas mais críticas — qualquer app com `Mail.ReadWrite.All` ou `Directory.ReadWrite.All` deve gerar alerta imediato.

**Rule 5 — Impossible Travel + Download Correlation**: Esta é a rule mais sofisticada — correlaciona Fases 2 e 3 em um único incidente. Detectaria mais tarde que as rules individuais, mas fornece um incidente mais rico com a correlação já feita.

### Seção 3: Rubrica de Avaliação

| Critério                               | Peso | Pontos Máximos |
|:---------------------------------------|:----:|:--------------:|
| Timeline MITRE ATT&CK completo e preciso | 20% | 20 pontos      |
| 5 Analytics rules funcionais em KQL    | 30% | 30 pontos      |
| Relatório executivo claro e completo   | 20% | 20 pontos      |
| Plano de remediação priorizado         | 20% | 20 pontos      |
| Apresentação oral (Live)               | 10% | 10 pontos      |
| **Total**                              | **100%** | **100 pontos** |

**Nota mínima para aprovação**: 70 pontos (70%)

**Critérios de excelência** (90+ pontos):
- Timeline identifica os IOCs específicos em cada fase
- Analytics rules incluem entity mapping, MITRE tagging e alert grouping configurados
- Relatório executivo usa linguagem de negócio, não técnica, para o público-alvo (CISO/Diretoria)
- Plano de remediação distingue ações imediatas, curto e longo prazo com justificativa

---

## Instruções para a Sessão Live

### Formato da Apresentação (15 minutos por grupo)

```
[0:00 — 2:00] — Apresentação da equipe e resumo executivo
[2:00 — 5:00] — Timeline MITRE (mostrar a tabela)
[5:00 — 9:00] — Demo ao vivo de 2 analytics rules no Sentinel
[9:00 — 12:00] — Plano de remediação (prioridades top 3)
[12:00 — 15:00] — Q&A do instrutor
```

### Perguntas Típicas do Instrutor na Q&A

1. "Por que vocês priorizaram esta remediação em vez daquela? Qual o raciocínio?"
2. "Se o CISO pede um número: qual o impacto financeiro estimado deste incidente?"
3. "A rule X que vocês criaram geraria quantos falso-positivos por semana? Como reduzir?"
4. "Se o atacante ainda tem o refresh token OAuth (Fase 6), a remediação está completa?"
5. "Quais são os requisitos de notificação ao BACEN para este incidente?"
