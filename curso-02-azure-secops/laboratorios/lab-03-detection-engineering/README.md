# Lab 03 — Detection Engineering: Criando 5 Analytics Rules

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 04 — Detection Engineering                                      |
| **Pré-requisito**        | Lab 01 concluído (Sentinel com connectors ativos)                      |
| **Nível**                | Intermediário                                                          |

---

## Seção 1 — Contexto Situacional

Na semana passada, o SOC do **Banco Meridian** identificou manualmente uma tentativa de password spray no tenant M365. O ataque foi descoberto somente porque um analista estava revisando relatórios de login por curiosidade — não havia nenhum alerta automático.

O CISO ficou alarmado: *"Quantos outros ataques passaram despercebidos porque não tínhamos detecção configurada?"* Ele solicita que você crie **5 analytics rules** que cubram os principais vetores de ataque observados contra bancos brasileiros, baseadas nas TTPs do grupo APT identificado na inteligência do FS-ISAC.

---

## Seção 2 — Situação Inicial

**Estado do ambiente**:
- Sentinel operacional (Lab 01 concluído)
- Data connectors: Entra ID, Defender XDR, Azure Activity, Office 365 conectados
- Analytics rules ativas: apenas as 3 do Lab 01 (Content Hub)
- Watchlists: vazias (a serem criadas no lab)
- Dados disponíveis: pelo menos 48h de SigninLogs, AuditLogs e OfficeActivity

---

## Seção 3 — Problema Identificado

Um relatório do FS-ISAC alertou que o Grupo Lazarus-BR (APT fictício) está usando as seguintes TTPs contra bancos brasileiros:

1. **Password spray** via Entra ID (T1110.003) — baixa taxa por conta para evitar bloqueio
2. **Impossible travel** após roubo de credenciais (T1078) — login de dois países na mesma hora
3. **Service principal abuse** (T1098) — adição de SP malicioso a role privilegiada
4. **AiTM token theft** (T1557) — bypass de MFA via proxy intermediário
5. **SharePoint exfiltration** (T1530) — download massivo antes de saída do funcionário

O banco precisa de **detecção automática** para todas essas TTPs antes do próximo ciclo de ataque.

---

## Seção 4 — Roteiro de Atividades

1. Criar watchlist `service-accounts` com 3 contas de serviço de teste
2. Criar watchlist `frequent-travelers` com 1 usuário de teste
3. Criar analytics rule de Impossible Travel (Scheduled)
4. Criar analytics rule de Password Spray (NRT)
5. Criar analytics rule de Service Principal em Role Privilegiada (NRT)
6. Criar analytics rule de AiTM Token Theft (Scheduled)
7. Criar analytics rule de SharePoint Exfiltration (Scheduled)
8. Criar automation rule de triagem automática
9. Verificar todas as rules e testar triggers

---

## Seção 5 — Proposição

Ao final deste laboratório, o Banco Meridian terá:
- 2 watchlists de contextualização criadas e populadas
- 5 analytics rules cobrindo as principais TTPs do setor bancário
- 1 automation rule de triagem automática
- Mapeamento MITRE ATT&CK completo para as detecções
- Capacidade de detectar os ataques do relatório FS-ISAC em menos de 30 minutos

---

## Seção 6 — Script Passo a Passo

### Passo 1: Criar Watchlist Service Accounts

**Sentinel → Watchlists → New**

```
Name: service-accounts
Alias: service-accounts
Source: Local file

Conteúdo do CSV (criar arquivo localmente):
```

```csv
UserPrincipalName,ServiceType,Owner,Department
svc-backup@bancomeridian-lab.onmicrosoft.com,Backup,TI,Infrastructure
svc-monitoring@bancomeridian-lab.onmicrosoft.com,Monitoring,TI,Operations
svc-etl@bancomeridian-lab.onmicrosoft.com,ETL Processing,Data Engineering,Analytics
```

```
Search key: UserPrincipalName
→ Review + Create → Create
```

**Resultado esperado**: Watchlist com 3 registros visível em Watchlists.

**Verificação**:
```kql
_GetWatchlist('service-accounts')
| project UserPrincipalName, ServiceType
// Deve retornar 3 linhas
```

---

### Passo 2: Criar Watchlist Frequent Travelers

**Sentinel → Watchlists → New**

```csv
UserPrincipalName,Department,Countries
admin@bancomeridian-lab.onmicrosoft.com,Diretoria,"BR,US,AR"
```

Alias: `frequent-travelers`, Search key: `UserPrincipalName`

---

### Passo 3: Criar Analytics Rule — Impossible Travel

**Sentinel → Analytics → Create → Scheduled query rule**

**Aba 1 — General**:
```
Name: Banco Meridian - Impossible Travel - Login de Dois Países em 1h
Description: Detecta quando o mesmo usuário faz login em dois países diferentes
             com intervalo menor que 1 hora. Indica possível roubo de credencial
             ou uso de proxy/VPN anônimo.
Tactics: Initial Access, Credential Access
Techniques: T1078 (Valid Accounts)
Severity: High
Status: Enabled
```

**Aba 2 — Set rule logic**:
```kql
// Copiar a query completa do Módulo 04, Seção 6, Rule 1
let excludedAccounts = _GetWatchlist('service-accounts') | project UserPrincipalName;
let frequentTravelers = _GetWatchlist('frequent-travelers') | project UserPrincipalName;

let recentLogins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| where UserPrincipalName !in (excludedAccounts)
| where UserPrincipalName !in (frequentTravelers)
| where isnotempty(Location)
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| where isnotempty(Country)
| project TimeGenerated, UserPrincipalName, IPAddress, Country,
          AppDisplayName, DeviceDetail, RiskLevelDuringSignIn;

recentLogins
| join kind=inner (recentLogins) on UserPrincipalName
| where Country != Country1
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) < 60
| where TimeGenerated > TimeGenerated1
| extend
    TimeDiffMinutes = abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)),
    Login1_Country = Country1,
    Login1_IP = IPAddress1,
    Login2_Country = Country,
    Login2_IP = IPAddress
| project UserPrincipalName, Login1_Country, Login1_IP, 
          Login2_Country, Login2_IP, TimeDiffMinutes
```

**Query scheduling**:
```
Run every: 30 minutes
Lookup data from last: 1 hour
```

**Alert threshold**: "> 0 results"

**Event grouping**: "Group all events into a single alert"

**Entity mapping**:
```
Account: Name → UserPrincipalName
IP: Address → Login2_IP
```

**Custom details**:
```
Login1_Country → Login1_Country
Login2_Country → Login2_Country
TimeDiffMinutes → TimeDiffMinutes
```

**Clicar em Review + Create**

**Resultado esperado**: Rule aparece em Analytics → Active rules com status "Enabled".

---

### Passo 4: Criar Analytics Rule — Password Spray (NRT)

**Sentinel → Analytics → Create → NRT query rule**

```
Name: Banco Meridian - Password Spray - Múltiplas Contas de Mesmo IP
Severity: High
Tactics: Credential Access
Techniques: T1110.003 (Password Spraying)
```

**Query**:
```kql
let timeWindow = 1h;
let minAccounts = 5;        // Ajustado para ambiente de lab (prod usar 10)
let maxAttemptsPerAccount = 3;

SigninLogs
| where TimeGenerated > ago(timeWindow)
| where ResultType != 0
| where ResultDescription !contains "MFA"
| where isnotempty(IPAddress)
| where IPAddress !startswith "10."
| where IPAddress !startswith "192.168."
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 20),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress
| where UniqueAccounts >= minAccounts
| where FailedAttempts / UniqueAccounts <= maxAttemptsPerAccount
| extend AttackDurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
```

**Entity mapping**:
```
IP: Address → IPAddress
```

**Custom details**:
```
UniqueAccounts → UniqueAccounts
AccountList → AccountList
```

**Clicar em Review + Create**

---

### Passo 5: Criar Analytics Rule — Service Principal em Role Privilegiada

**Sentinel → Analytics → Create → NRT query rule**

```
Name: Banco Meridian - Service Principal Adicionado a Role Privilegiada
Severity: High
Tactics: Persistence, Privilege Escalation
Techniques: T1098 (Account Manipulation), T1548 (Abuse Elevation)
```

**Query**:
```kql
let privilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "Application Administrator", "Cloud Application Administrator"
]);

AuditLogs
| where TimeGenerated > ago(15m)
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
| extend TargetType = tostring(TargetResources[0].type)
| extend TargetDisplayName = tostring(TargetResources[0].displayName)
| where TargetType == "ServicePrincipal"
| extend RoleName = tostring(parse_json(tostring(TargetResources[1].modifiedProperties))[0].newValue)
| where RoleName has_any (privilegedRoles)
| extend InitiatorUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project TimeGenerated, OperationName, InitiatorUPN, TargetDisplayName, RoleName
```

**Entity mapping**:
```
Account (Initiator): Name → InitiatorUPN
Account (Target SP): Name → TargetDisplayName
```

---

### Passo 6: Criar Analytics Rule — AiTM Token Theft

**Sentinel → Analytics → Create → Scheduled query rule**

```
Name: Banco Meridian - Possível AiTM Token Theft - Login SFA sem Device
Severity: High
Tactics: Initial Access, Credential Access
Techniques: T1557 (AiTM), T1539 (Steal Web Session Cookie)
Run every: 30 minutes
Lookup: 2 hours
```

**Query**:
```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ConditionalAccessStatus == "success"
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize LastMFALogin = max(TimeGenerated) by UserPrincipalName
) on UserPrincipalName
| extend DeviceId = tostring(parse_json(tostring(DeviceDetail)).deviceId)
| where isempty(DeviceId) or DeviceId == "00000000-0000-0000-0000-000000000000"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AuthenticationRequirement, RiskLevelDuringSignIn, LastMFALogin
```

---

### Passo 7: Criar Analytics Rule — SharePoint Exfiltration

**Sentinel → Analytics → Create → Scheduled query rule**

```
Name: Banco Meridian - Exfiltração Anômala via SharePoint/OneDrive
Severity: Medium
Tactics: Collection, Exfiltration
Techniques: T1530 (Data from Cloud Storage)
Run every: 1 hour
Lookup: 1 hour
```

**Query**:
```kql
let baseline = OfficeActivity
| where TimeGenerated between (ago(30d) .. ago(1h))
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| where RecordType in ("SharePointFileOperation", "OneDrive")
| summarize AvgDailyDownloads = count() / 30.0 by UserId;

let recentActivity = OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| where RecordType in ("SharePointFileOperation", "OneDrive")
| summarize RecentDownloads = count(), 
            IPs = make_set(ClientIP, 5) by UserId;

recentActivity
| join kind=leftouter baseline on UserId
| extend AvgDailyDownloads = coalesce(AvgDailyDownloads, 0.0)
| where AvgDailyDownloads > 0
| extend Multiplier = RecentDownloads / max_of(AvgDailyDownloads, 1.0)
| where Multiplier >= 5
| project UserId, RecentDownloads, AvgDailyDownloads = round(AvgDailyDownloads, 1),
          Multiplier = round(Multiplier, 1), IPs
```

---

### Passo 8: Criar Automation Rule de Triagem

**Sentinel → Automation → Create → Automation rule**

```
Name: Triagem-High-Account-Incidents
Trigger: When incident is created
Conditions:
  - Incident severity: Equals: High
  - Incident contains entities of type: Account

Actions (em ordem):
  1. Assign owner: [seu usuário de lab]
  2. Add tags: account-incident, high-priority
  3. Change status: Active
```

---

### Passo 9: Verificação Completa

Execute a query de verificação final:

```kql
// Verificar todas as analytics rules criadas no lab
// Substitua [seu-workspace-id] pelo ID do workspace
_SentinelHealth
| where TimeGenerated > ago(1h)
| where SentinelResourceKind == "AnalyticsRule"
| where SentinelResourceName has_any (
    "Impossible Travel", "Password Spray", "Service Principal",
    "AiTM", "SharePoint"
)
| project TimeGenerated, SentinelResourceName, Status = SentinelResourceType
```

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                               | Verificação                               |
|:-----:|:-------------------------------------------------------|:------------------------------------------|
| 1-2   | Criar watchlists de contextualização                   | `_GetWatchlist('service-accounts')` retorna 3 linhas |
| 3     | Criar rule Scheduled com self-join                     | Rule aparece em Analytics Rules — Active  |
| 4     | Criar rule NRT com aggregation                         | Rule NRT na lista com ícone NRT           |
| 5     | Criar rule para service principal abuse                | Rule NRT com MITRE mapeado                |
| 6     | Criar rule de token theft com join histórico           | Rule Scheduled 30min lookback 2h          |
| 7     | Criar rule de anomalia de volume com baseline          | Rule Scheduled 1h com custom details      |
| 8     | Criar automation rule de triagem                       | Rule em Automation → Automation rules     |
| 9     | Verificar todo o ambiente                              | Todas as 5 rules em status Enabled        |

---

## Seção 8 — Gabarito Completo

### Lista Completa das Rules Criadas

| # | Nome                                         | Tipo      | Scheduling | Entities mapeadas | MITRE          |
|:-:|:---------------------------------------------|:---------:|:----------:|:-----------------:|:--------------:|
| 1 | Impossible Travel                            | Scheduled | 30min/1h   | Account, IP       | T1078          |
| 2 | Password Spray                               | NRT       | ~1min/1h   | IP                | T1110.003      |
| 3 | Service Principal em Role Privilegiada       | NRT       | ~1min/15m  | Account (×2)      | T1098, T1548   |
| 4 | AiTM Token Theft                             | Scheduled | 30min/2h   | Account, IP       | T1557, T1539   |
| 5 | SharePoint Exfiltração Anômala               | Scheduled | 1h/1h      | Account           | T1530          |

### Verificação das Watchlists

```kql
// Verificar as duas watchlists
union (
    _GetWatchlist('service-accounts') | extend WatchlistName = "service-accounts"
), (
    _GetWatchlist('frequent-travelers') | extend WatchlistName = "frequent-travelers"
)
| project WatchlistName, UserPrincipalName
```

### Queries KQL Finais para cada Rule

As 5 queries completas estão documentadas no Módulo 04, Seção 6. Para referência rápida:

**Validação de que todas as rules estão rodando sem erros**:
```kql
// Verificar health das analytics rules
_SentinelHealth
| where TimeGenerated > ago(24h)
| where SentinelResourceKind == "AnalyticsRule"
| summarize count() by Status = SentinelResourceType, ResourceName = SentinelResourceName
| sort by Status asc
```

### Desafio Extra (Opcional)

Para alunos que terminaram antes do tempo:

1. Criar uma **6ª analytics rule** detectando criação de regra de encaminhamento de e-mail para domínio externo (hint: `OfficeActivity | where Operation == "New-InboxRule"`)

2. Testar a rule de **Password Spray** gerando tentativas de login malsucedidas com um script PowerShell:
```powershell
# Script para gerar tentativas de login (APENAS no ambiente de lab)
# NÃO executar em produção
$users = @(
    "user1@bancomeridian-lab.onmicrosoft.com",
    "user2@bancomeridian-lab.onmicrosoft.com",
    "user3@bancomeridian-lab.onmicrosoft.com",
    "user4@bancomeridian-lab.onmicrosoft.com",
    "user5@bancomeridian-lab.onmicrosoft.com"
)

foreach ($user in $users) {
    $body = @{
        grant_type    = "password"
        client_id     = "1950a258-227b-4e31-a9cf-717495945fc2"  # PowerShell app ID
        username      = $user
        password      = "WrongPassword123!"
        scope         = "https://graph.microsoft.com/.default"
    }
    
    try {
        Invoke-RestMethod -Uri "https://login.microsoftonline.com/bancomeridian-lab.onmicrosoft.com/oauth2/v2.0/token" `
                          -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" `
                          -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    
    Start-Sleep -Seconds 5
}
Write-Host "Script concluído. Aguardar 10 minutos e verificar alertas no Sentinel."
```

3. Verificar se o alerta foi gerado:
```kql
SecurityAlert
| where TimeGenerated > ago(30m)
| where AlertName contains "Password Spray"
| project TimeGenerated, AlertName, Description, Entities
```
