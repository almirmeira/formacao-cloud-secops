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

**O que este passo faz:** Cria uma watchlist que cataloga as contas de serviço legítimas do Banco Meridian (backup, monitoramento e ETL). Uma watchlist é uma lista de referência consultada pelas queries KQL das analytics rules — ela permite que a regra de "Service Principal em Role Privilegiada" exclua automaticamente os service principals conhecidos e legítimos, reduzindo drasticamente os falsos positivos. Sem esta watchlist, cada vez que o processo de backup (`svc-backup`) fizer uma operação IAM legítima, um analista seria acordado às 3h da manhã com um falso alerta.

**Por que criamos a watchlist ANTES das analytics rules:** As queries KQL das rules referenciam `_GetWatchlist('service-accounts')`. Se tentarmos salvar uma rule que referencia uma watchlist que ainda não existe, ela falhará na validação ou gerará erros de referência nula durante a avaliação. As watchlists são a fundação de dados de contexto — precisam existir antes da lógica de detecção que as consome.

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

**O que confirma que funcionou:** A watchlist aparece em Sentinel → Watchlists com status "Succeeded" e exibe "3 items" na coluna Source Rows. Para validar via KQL, execute a query abaixo em Logs — ela deve retornar exatamente 3 linhas, uma para cada conta de serviço cadastrada:

```kql
_GetWatchlist('service-accounts')
| project UserPrincipalName, ServiceType
// Deve retornar 3 linhas
```

---

### Passo 2: Criar Watchlist Frequent Travelers

**O que este passo faz:** Cria uma segunda watchlist listando os usuários do Banco Meridian que viajam internacionalmente com frequência por razões legítimas de negócio (diretores, executivos com agendas internacionais). Esta lista é consumida pela regra de Impossible Travel para excluir os usuários que genuinamente fazem login de múltiplos países — sem ela, cada viagem do CEO geraria um alerta de alta severidade que consumiria tempo do analista sem valor operacional.

**Por que esta watchlist vem antes da regra de Impossible Travel:** A analytics rule do Passo 3 referencia `_GetWatchlist('frequent-travelers')` na sua lógica de exclusão. Criar as duas watchlists em sequência (Passos 1 e 2) antes de qualquer rule garante que toda a camada de contexto esteja disponível quando as rules forem criadas e imediatamente ativadas.

**Sentinel → Watchlists → New**

```csv
UserPrincipalName,Department,Countries
admin@bancomeridian-lab.onmicrosoft.com,Diretoria,"BR,US,AR"
```

Alias: `frequent-travelers`, Search key: `UserPrincipalName`

**O que confirma que funcionou:** A watchlist `frequent-travelers` aparece em Sentinel → Watchlists com status "Succeeded" e exibe "1 item" na coluna Source Rows. Execute a query de validação abaixo — ela deve retornar 1 linha com o usuário da diretoria e os países permitidos:

```kql
_GetWatchlist('frequent-travelers')
| project UserPrincipalName, Department, Countries
// Deve retornar 1 linha
```

---

### Passo 3: Criar Analytics Rule — Impossible Travel

**O que este passo faz:** Cria uma regra agendada (Scheduled) que detecta quando o mesmo usuário autentica com sucesso em dois países diferentes com menos de 60 minutos de intervalo — um cenário fisicamente impossível sem a ajuda de proxies, VPNs anônimas ou credenciais comprometidas. A query usa uma auto-junção (self-join) da tabela `SigninLogs` para comparar pares de logins do mesmo usuário e calcular se a diferença de país e o intervalo de tempo são suspeitos. As watchlists criadas nos Passos 1 e 2 são aplicadas para filtrar contas de serviço e viajantes frequentes antes da comparação.

**Por que esta é a primeira analytics rule a ser criada:** O Impossible Travel é a detecção com maior impacto imediato para o cenário do FS-ISAC — o relatório de inteligência indica que o Lazarus-BR usa credenciais roubadas para acesso remoto, e logins de países incomuns são o sinal mais precoce desse padrão. Além disso, a lógica de self-join desta regra é a mais complexa do lab, servindo como referência para as demais.

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

**O que confirma que funcionou:** A rule "Banco Meridian - Impossible Travel - Login de Dois Países em 1h" aparece em Sentinel → Analytics → Active rules com status "Enabled" e ícone de relógio (Scheduled). Na coluna "Last run", após até 30 minutos, aparece um timestamp e o status "Succeeded" — indicando que a query foi executada sem erros de sintaxe KQL ou referência de watchlist.

---

### Passo 4: Criar Analytics Rule — Password Spray (NRT)

**O que este passo faz:** Cria uma regra do tipo NRT (Near-Real-Time) que detecta o padrão característico de password spray: um mesmo endereço IP tentando autenticar em muitas contas diferentes com poucas tentativas por conta. O atacante do Grupo Lazarus-BR usa esta técnica deliberadamente para evitar o bloqueio por conta (que ocorre após 5-10 falhas consecutivas na mesma conta). A query agrega falhas de login por IP e avalia dois critérios simultaneamente: mínimo de 5 contas únicas atacadas E média de no máximo 3 tentativas por conta — a "assinatura matemática" do spray.

**Por que esta rule usa o tipo NRT em vez de Scheduled:** Password spray é uma ameaça com janela de ataque curta — o atacante frequentemente conclui o ciclo de spray em minutos antes de trocar de IP. Uma rule Scheduled com intervalo de 30 minutos poderia perder ou atrasar a detecção. O NRT avalia a query praticamente em tempo real (latência de ~1 minuto), permitindo que o SOC bloqueie o IP ainda durante o ataque. Esta é a segunda rule a ser criada porque a detecção de credenciais comprometidas (Impossible Travel) deve estar ativa antes da detecção do vetor de comprometimento inicial.

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

**O que confirma que funcionou:** A rule aparece em Sentinel → Analytics → Active rules com status "Enabled" e o ícone NRT (raio/lightning) que diferencia visualmente das rules Scheduled. A coluna "Type" exibe "NRT" e a coluna "Last run" começa a ser atualizada em menos de 2 minutos após a criação, pois rules NRT iniciam imediatamente.

---

### Passo 5: Criar Analytics Rule — Service Principal em Role Privilegiada

**O que este passo faz:** Cria uma regra NRT que monitora o AuditLog do Entra ID em busca de operações de atribuição de role onde o alvo é um Service Principal (não um usuário humano) e a role atribuída é privilegiada (Global Administrator, Security Administrator, etc.). Este é o padrão de persistência do Lazarus-BR: após obter acesso inicial, o grupo registra um novo Service Principal e concede a ele uma role privilegiada para manter acesso persistente mesmo que as credenciais do usuário humano sejam revogadas. A query extrai o tipo do objeto alvo e o nome da role dos campos JSON aninhados do AuditLogs.

**Por que esta rule usa NRT e janela de 15 minutos:** A adição de um Service Principal a uma role privilegiada é um evento de altíssima criticidade que não tolera latência de detecção. Em 15 minutos, um Service Principal com role de Global Administrator já pode ter criado backdoors adicionais, exportado credenciais ou desabilitado políticas de Conditional Access. O NRT garante que o alerta chegue ao analista enquanto o atacante ainda está no ambiente. Esta rule vem após as de credenciais (Passos 3 e 4) porque representa a fase de persistência — posterior ao acesso inicial.

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

**O que confirma que funcionou:** A rule aparece em Sentinel → Analytics com status "Enabled" e tipo "NRT". O mapeamento MITRE ATT&CK deve aparecer preenchido com T1098 e T1548 na coluna "Tactics" da listagem. Para validar o mapeamento de entidades, clique na rule criada e acesse a aba "Entity mapping" — devem aparecer dois mapeamentos de Account (Initiator e Target SP), o que permite ao Sentinel correlacionar automaticamente incidentes envolvendo os mesmos service principals.

---

### Passo 6: Criar Analytics Rule — AiTM Token Theft

**O que este passo faz:** Cria uma regra Scheduled que detecta o padrão de roubo de token via ataque AiTM (Adversary-in-the-Middle): um usuário que normalmente autentica com MFA (nos últimos 7 dias) de repente faz login com autenticação de fator único (SFA) sem um device registrado. Isso indica que o atacante está usando um token de sessão roubado por proxy — o token já passou pelo MFA legítimo, então o Entra ID aceita a autenticação como válida, mas o sinal de "SFA sem device" delata a anomalia. A query cruza logins recentes (2h) com o histórico de 7 dias via join para identificar esta mudança de padrão.

**Por que esta rule usa tipo Scheduled em vez de NRT:** Ao contrário do password spray (evento pontual e rápido), a detecção de AiTM requer correlação com dados históricos — a query precisa olhar 7 dias de histórico de MFA do usuário para estabelecer o baseline. Queries com joins contra grandes volumes de dados históricos são mais adequadas para execução Scheduled (30 minutos) do que NRT, que tem restrições de complexidade e volume de dados consultados. Esta rule vem após as de acesso inicial e persistência porque representa uma técnica de evasão sofisticada que pressupõe que o atacante já passou pela autenticação básica.

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

**O que confirma que funcionou:** A rule aparece em Sentinel → Analytics com tipo "Scheduled", severidade "High" e agendamento "Every 30 minutes / 2 hours lookback". Na coluna "MITRE tactics", os campos "Initial Access" e "Credential Access" devem estar visíveis. Após a primeira execução (até 30 minutos), a coluna "Last run" exibe o timestamp e "Succeeded" — confirmando que o join contra 7 dias de SigninLogs foi executado sem timeout ou erro de sintaxe.

---

### Passo 7: Criar Analytics Rule — SharePoint Exfiltration

**O que este passo faz:** Cria uma regra Scheduled que detecta exfiltração de dados via SharePoint/OneDrive usando comparação de volume com baseline histórico. A lógica calcula a média diária de downloads de cada usuário nos últimos 30 dias (excluindo a última hora, que é a janela de análise) e compara com o volume da última hora. Se um usuário baixar 5x ou mais do que sua média diária em uma única hora, gera um alerta. Este padrão é típico de funcionários em processo de demissão copiando dados antes de sair, ou de atacantes que comprometeram uma conta e estão exfiltrando documentos corporativos em massa.

**Por que esta é a última analytics rule a ser criada:** A regra de exfiltração representa a fase final da cadeia de ataque (Collection → Exfiltration no MITRE ATT&CK) — ela detecta o objetivo final do atacante após acesso inicial, evasão de MFA e persistência. A sequência de criação segue a ordem da kill chain: primeiro detectamos o acesso (Passos 3-4), depois a persistência (Passo 5), depois a evasão (Passo 6) e por último o objetivo final (Passo 7). Além disso, esta rule usa dados do Office 365 (OfficeActivity) — diferente das anteriores que usavam SigninLogs e AuditLogs — validando que o data connector Office 365 está funcionando corretamente.

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

**O que confirma que funcionou:** A rule aparece em Sentinel → Analytics com tipo "Scheduled", severidade "Medium" e agendamento "Every 1 hour / 1 hour lookback". A severidade "Medium" (diferente das "High" anteriores) deve aparecer corretamente na listagem. Para confirmar que o data connector Office 365 tem dados suficientes para o baseline, execute manualmente a subquery de baseline em Logs — se retornar linhas, o connector está ativo há mais de 1 hora e a regra terá dados para comparação.

---

### Passo 8: Criar Automation Rule de Triagem

**O que este passo faz:** Cria uma automation rule que executa automaticamente três ações de triagem sempre que um incidente de alta severidade envolvendo entidades do tipo Account é criado no Sentinel: atribui o incidente ao analista de plantão, adiciona tags de classificação para facilitar filtragem e muda o status de "New" para "Active". Esta automação elimina o trabalho manual repetitivo de triagem inicial, garantindo que todo incidente de alta severidade com conta seja imediatamente atribuído e marcado — mesmo que o analista esteja respondendo a outro incidente simultaneamente. No contexto do Banco Meridian, todas as 5 analytics rules criadas podem gerar incidentes que passarão por esta triagem automática.

**Por que a automation rule vem DEPOIS das analytics rules:** A automation rule é disparada por incidentes gerados pelas analytics rules. Se criássemos a automation rule antes, ela não teria incidentes para processar durante o lab — pois as rules ainda não existiriam. A ordem correta é: criar as fontes de incidentes (analytics rules) e depois criar o orquestrador de resposta (automation rule).

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

**O que confirma que funcionou:** A automation rule aparece em Sentinel → Automation → Automation rules com status "Enabled". A ordem das 3 ações (Assign owner → Add tags → Change status) deve estar visível no resumo da rule. Para testar a automação sem esperar um incidente real, crie manualmente um incidente de severidade High com uma entidade Account em Sentinel → Incidents → Create — após alguns segundos, o incidente deve mostrar o owner atribuído, as tags adicionadas e o status "Active".

---

### Passo 9: Verificação Completa

**O que este passo faz:** Executa uma query de saúde do Sentinel para confirmar que todas as 5 analytics rules criadas estão operacionais, sem erros de execução. A tabela `_SentinelHealth` registra o resultado de cada execução de analytics rule — se uma rule tem erro de KQL, referência de watchlist inválida ou problema de permissão, o status aparece como "Failed" aqui. Esta verificação final garante que o ambiente do Banco Meridian está efetivamente protegido e não apenas "configurado no papel".

**Por que esta verificação encerra o lab:** O Passo 9 é o critério de aceitação de todo o trabalho anterior. Um analista pode criar todas as rules sem erros de validação no portal, mas se uma watchlist tiver alias incorreto ou se um data connector estiver desconectado, as rules executarão com zero resultados ou falharão silenciosamente. Esta query de saúde detecta exatamente esses cenários e dá confiança ao SOC de que a cobertura de detecção está ativa.

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

**O que confirma que funcionou:** A query retorna 5 linhas (uma por analytics rule) com status "Succeeded" para todas. Se alguma rule aparecer com status "Failed", anote o nome e consulte a seção de troubleshooting: os erros mais comuns são alias de watchlist incorreto (verificar ortografia exata) ou connector desconectado (verificar em Data connectors). O lab está concluído quando todas as 5 rules mostram "Succeeded" e a automation rule está "Enabled" em Sentinel → Automation.

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

**Por que esta é a resposta correta — tabela de regras:**

- **Impossible Travel como Scheduled (30min/1h):** A janela de lookup de 1h é proposital — logins com menos de 1h de diferença são o limiar para "fisicamente impossível" mesmo com voos domésticos curtos. Um intervalo maior (ex.: 4h) geraria falsos negativos em ataques rápidos; um intervalo menor (ex.: 10min) seria irrealista. O agendamento de 30min garante detecção antes que o atacante possa causar dano significativo dentro da sessão.

- **Password Spray como NRT:** A natureza rápida do spray (ciclo completo em minutos) exige latência mínima de detecção. NRT (~1min) vs. Scheduled 30min pode ser a diferença entre bloquear o IP durante o ataque ou descobrir o comprometimento horas depois. O lookback de 1h na query é suficiente para capturar o padrão sem consumir recursos excessivos.

- **Service Principal como NRT (15min):** Um Service Principal com Global Administrator é uma backdoor imediata e irrevogável se não detectada. O lookback de 15min é propositalmente curto — apenas eventos muito recentes precisam ser avaliados, pois operações de atribuição de role são raras e qualquer instância é suspeita se o alvo for ServicePrincipal.

- **AiTM como Scheduled com lookback de 7d:** A detecção de anomalia de autenticação requer baseline histórico. Sem os 7 dias de histórico de MFA, não há como distinguir "usuário que nunca usou MFA" (conta nova ou isenta) de "usuário que normalmente usa MFA mas desta vez não usou" (sinal de AiTM). O lookback longo é o custo necessário para esta detecção de alta fidelidade.

- **SharePoint como Scheduled (1h/1h) com Severity Medium:** O baseline de 30 dias e a janela de análise de 1h são o equilíbrio entre sensibilidade e precisão. Severity Medium (não High) é intencional — exfiltração via SharePoint pode ter causas legítimas (projeto de grande entrega, backup pessoal autorizado) e merece investigação, não resposta imediata de contenção.

---

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

**Por que esta é a resposta correta — verificação de watchlists:** A query usa `union` para verificar as duas watchlists em uma única execução, retornando 4 linhas no total (3 de service-accounts + 1 de frequent-travelers). Se qualquer watchlist retornar 0 linhas, o alias está incorreto — verifique se o alias foi digitado exatamente como `service-accounts` e `frequent-travelers` (com hífen, sem espaço, sem maiúsculas). Um alias incorreto faz com que `_GetWatchlist()` retorne uma tabela vazia sem gerar erro, causando rules que "funcionam" mas nunca excluem as contas legítimas.

---

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

**Por que esta é a resposta correta — validação de health:** A query usa `_SentinelHealth` (não `SecurityAlert` nem `Incidents`) porque registra o resultado de execução de cada rule independentemente de ter gerado alertas. Uma rule pode executar com sucesso e retornar 0 resultados (sem atividade suspeita no período) — isso é diferente de uma rule que falha na execução. O `summarize count() by Status` agrupa por resultado (Succeeded/Failed) para facilitar a identificação de rules com problema sem precisar ler cada linha individualmente.

---

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

---

### Erros Comuns Neste Lab

**Erro 1: Watchlist retorna 0 linhas na query KQL**
- **Causa provável:** Alias digitado incorretamente (ex.: `ServiceAccounts` em vez de `service-accounts`, ou `service_accounts` com underscore)
- **Como corrigir:** Vá em Sentinel → Watchlists, clique na watchlist e confirme o valor exato do campo "Alias". O alias é case-sensitive nas queries KQL. Edite a watchlist se necessário.

**Erro 2: Analytics rule em status "Failed" no _SentinelHealth**
- **Causa provável A:** Data connector desconectado (SigninLogs ou OfficeActivity sem dados)
- **Causa provável B:** Watchlist referenciada na query ainda não foi criada
- **Como corrigir:** Verifique em Sentinel → Data connectors se o status é "Connected". Execute a subquery manualmente em Logs para isolar qual parte da query falha.

**Erro 3: Rule NRT não aparece na lista após salvar**
- **Causa provável:** Erro de validação silencioso ao salvar — o portal às vezes aceita o clique em "Create" mas descarta a rule se houver campo obrigatório vazio
- **Como corrigir:** Volte em Analytics → Create → NRT e verifique se o campo "Name" está preenchido e se pelo menos uma tática MITRE foi selecionada. Rules sem nome ou sem tática podem ser rejeitadas silenciosamente.

**Erro 4: Query de Impossible Travel retorna resultados inesperados (zero ou muitos)**
- **Causa provável — zero resultados:** Ambiente de lab com poucos logins nos últimos 60 minutos; aguardar atividade orgânica ou gerar logins de teste com dois IPs de países diferentes
- **Causa provável — muitos resultados:** Watchlist `frequent-travelers` com alias incorreto, não excluindo o usuário admin que faz logins de múltiplos países em demos
- **Como corrigir:** Execute cada subquery (`excludedAccounts`, `frequentTravelers`, `recentLogins`) separadamente em Logs para identificar onde o filtro falha.

**Erro 5: Automation rule não é disparada em incidentes de teste**
- **Causa provável:** A condition "Incident contains entities of type: Account" requer que o incidente tenha entidade Account mapeada — se as analytics rules não tiverem entity mapping configurado, os incidentes não terão entidades e a automation rule não será disparada
- **Como corrigir:** Confirme que as rules de Passos 3, 4 e 5 têm entity mapping de Account configurado (conforme Passo 3 — "Account: Name → UserPrincipalName"). Incidentes gerados por rules sem entity mapping não acionarão a automation rule de triagem.
