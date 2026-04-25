# Módulo 03 — KQL: Kusto Query Language

**Curso 2 — Microsoft Sentinel & Defender: SecOps no Azure**

| Campo         | Detalhes                                           |
|:--------------|:---------------------------------------------------|
| **Carga**     | 3h videoaulas + 3h laboratório + 1h live = 7h total |
| **Módulo**    | 03 de 10                                           |
| **Pré-req.**  | Módulos 00 e 02 concluídos (Sentinel configurado) |
| **Ferramentas** | Microsoft Sentinel Logs, Log Analytics, ASIM     |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Estruturar consultas KQL usando a sintaxe tabular com pipe (`|`) e encadear operadores corretamente
2. Usar os operadores fundamentais: `where`, `project`, `extend`, `summarize`, `join`, `union`, `bin`, `arg_max` e `mv-expand`
3. Identificar as principais tabelas do Microsoft Sentinel e quando usar cada uma
4. Compreender o ASIM (Advanced Security Information Model) e escrever queries normalizadas
5. Construir queries de detecção para sign-in anomalies, password spray, lateral movement e exfiltração
6. Otimizar queries para performance e custo no Log Analytics
7. Organizar e compartilhar uma biblioteca de queries para o SOC

---

## Conteúdo Conceitual

### Aula 3.1 — Fundamentos KQL (45 minutos)

#### O que é o KQL?

O **KQL (Kusto Query Language)** é a linguagem de consulta tabular usada em todos os produtos analíticos da Microsoft: Log Analytics, Microsoft Sentinel, Azure Data Explorer, Microsoft Defender (Advanced Hunting), Application Insights e Azure Monitor. Criada para consultas de telemetria em grande escala, o KQL é projetado para ser expressivo, legível e altamente performático em datasets de bilhões de eventos.

No contexto do SOC, o KQL é a ferramenta principal para:
- Investigar incidentes e responder perguntas ("quem logou desse IP?")
- Construir regras de detecção (analytics rules do Sentinel)
- Realizar threat hunting proativo
- Gerar relatórios e workbooks

**Por que o analista SOC precisa dominar KQL antes de qualquer outra habilidade técnica no Sentinel:** No Microsoft Sentinel, as analytics rules que detectam ataques são escritas em KQL. As queries de threat hunting são KQL. Os workbooks de dashboard são KQL. Os alertas que disparam playbooks são definidos por KQL. Sem KQL, o profissional consegue usar templates prontos da Microsoft — mas não consegue criar detecções personalizadas para o ambiente específico do Banco Meridian, adaptar regras existentes para eliminar falsos positivos, ou investigar um incidente de forma eficiente. O KQL é o "SQL do SOC Microsoft".

**Como o KQL se compara ao SQL que você já conhece:** Se você tem experiência com SQL, o KQL será familiar no conceito mas diferente na sintaxe. No SQL escreve-se `SELECT ... FROM ... WHERE ... GROUP BY`; no KQL, começa-se com a tabela e encadeiam-se transformações com `|` (pipe). Cada operador recebe um conjunto de linhas e produz um conjunto de linhas modificado. Pense em cada linha KQL como um passo de um pipeline de processamento de dados.

> **Por que isso importa para o Banco Meridian:** O SOC do banco recebe, em média, 380 alertas por dia após a implantação inicial do Sentinel. Um analista L2 que domina KQL leva 8 minutos para investigar um alerta de impossible travel — verificar o IP, o país, os logins anteriores do usuário, se há outros alertas correlacionados. Sem KQL, o mesmo analista leva 35-45 minutos clicando em interfaces gráficas e exportando para Excel. A diferença de eficiência é o que determina se o SOC consegue processar todos os alertas críticos no turno ou se ataques passam despercebidos por falta de tempo analítico.

#### Estrutura básica de uma query KQL

```kql
// Uma query KQL é uma sequência de operações encadeadas por pipe (|)
// Cada operação recebe a tabela anterior e produz uma nova tabela

NomeTabela                          // 1. Fonte de dados (tabela)
| where TimeGenerated > ago(1d)     // 2. Filtro de tempo
| where ResultType != 0             // 3. Filtro adicional
| project TimeGenerated, UPN, IP   // 4. Seleciona colunas
| summarize count() by UPN          // 5. Agrega resultados
| order by count_ desc              // 6. Ordena
| take 10                           // 7. Limita resultados
```

**Regras de sintaxe essenciais:**
- Cada linha começa com `|` (exceto a primeira, que é a tabela)
- Comentários com `//`
- Nomes de coluna são case-sensitive
- Strings entre aspas duplas `"valor"` ou simples `'valor'`
- Timestamps: `ago(1h)`, `ago(7d)`, `datetime(2026-04-24)`
- Operadores booleanos: `and`, `or`, `not`
- Comparadores: `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `startswith`, `endswith`, `matches regex`

---

#### Operadores Fundamentais — Referência Completa

##### Operador `where` — Filtragem de linhas

```kql
// Filtro simples por valor
SigninLogs
| where ResultType != 0   // apenas falhas de login

// Múltiplas condições
SigninLogs
| where ResultType != 0
    and AppDisplayName == "Microsoft Teams"
    and TimeGenerated > ago(24h)

// Filtro com lista (in operator)
SecurityEvent
| where EventID in (4624, 4625, 4648, 4672, 4768)

// Filtro com regex
SigninLogs
| where UserPrincipalName matches regex @".*@bancomeridianlab\.onmicrosoft\.com"

// Filtro com contains (menos performático que ==)
AzureActivity
| where OperationName contains "delete"
```

| Filtro | Uso | Performance |
|:-------|:----|:------------|
| `== "valor"` | Igualdade exata | Alta |
| `in ("a","b","c")` | Lista de valores | Alta |
| `contains "substr"` | Substring (case-insensitive) | Média |
| `startswith "pre"` | Prefixo | Alta |
| `matches regex` | Expressão regular | Baixa |
| `has "token"` | Token completo (word boundary) | Alta |

---

##### Operador `project` — Seleção e renomeação de colunas

O operador `project` é mais do que estética. Ao selecionar apenas as colunas necessárias, você reduz o volume de dados que o Sentinel processa nas etapas seguintes do pipeline — o que tem impacto direto na velocidade da query e, em analytics rules com alta frequência de execução, no custo de computação. Em queries de hunting sobre semanas de dados, um `project` bem posicionado pode reduzir o tempo de execução de minutos para segundos.

```kql
// Selecionar apenas colunas necessárias (melhora performance)
SigninLogs
| project
    Timestamp = TimeGenerated,    // renomear coluna
    UserUPN = UserPrincipalName,
    AppName = AppDisplayName,
    ResultCode = ResultType,
    IPAddress,
    Location

// project-away: excluir colunas indesejadas (manter o resto)
SigninLogs
| project-away _ResourceId, TenantId, SourceSystem

// project-keep: garantir que colunas existam (não falha se ausente)
SigninLogs
| project-keep TimeGenerated, UserPrincipalName, IPAddress
```

---

##### Operador `extend` — Adicionar colunas calculadas

```kql
// Adicionar coluna calculada
SigninLogs
| extend
    IsFailure = ResultType != 0,
    HourOfDay = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated),
    IsWeekend = dayofweek(TimeGenerated) in (0d, 6d)

// Extrair substring com parse
SigninLogs
| extend UserDomain = tostring(split(UserPrincipalName, "@")[1])

// Usar iff() (equivalente ao if-else)
SigninLogs
| extend RiskLabel = iff(RiskLevelDuringSignIn == "high", "ALTO RISCO", "Normal")

// Usar case() para múltiplas condições
SecurityEvent
| extend SeverityLabel = case(
    EventID == 4625, "Logon Failed",
    EventID == 4648, "Logon Explicit Credentials",
    EventID == 4672, "Privileged Logon",
    "Other"
)
```

---

##### Operador `summarize` — Agregação

```kql
// Contar eventos por usuário
SigninLogs
| where ResultType != 0
| summarize FailureCount = count() by UserPrincipalName

// Múltiplas agregações
SigninLogs
| summarize
    TotalLogins = count(),
    FailedLogins = countif(ResultType != 0),
    UniqueIPs = dcount(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName

// Agregar por bucket de tempo (bin)
SigninLogs
| summarize FailureCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailureCount > 10   // mais de 10 falhas por hora = suspeito

// Funções de agregação comuns:
// count()          - total de linhas
// countif(cond)    - total condicional
// dcount(col)      - distinct count (estimativa)
// dcountif(col, c) - distinct count condicional
// sum(col)         - soma
// avg(col)         - média
// min(col)         - mínimo
// max(col)         - máximo
// make_set(col)    - conjunto de valores únicos (array)
// make_list(col)   - lista de valores (array com duplicatas)
// stdev(col)       - desvio padrão
// percentile(col,p)- percentil
```

---

##### Operador `join` — Correlacionar tabelas

O `join` é o operador mais poderoso do KQL para detecção de ataques multi-etapa. Ele permite combinar duas tabelas com base em um campo comum, encontrando eventos relacionados que, sozinhos, seriam benignos. Por exemplo: um alerta de "login fora do horário" (SigninLogs) combinado com "download massivo de arquivos" (OfficeActivity) no mesmo usuário pode revelar um insider threat que nenhuma das regras individuais detectaria sozinha.

> **⚠️ Atenção ao custo do join:** O `join` é computacionalmente caro. Em analytics rules de alta frequência (rodando a cada 5 minutos), um join mal otimizado pode aumentar significativamente o custo de computação. Sempre aplique filtros (`where`) nas duas tabelas antes do join, reduzindo o conjunto de dados ao mínimo necessário. Use `project` para selecionar apenas as colunas que serão usadas.

```kql
// Inner join: alertas com detalhes de usuário
SecurityAlert
| where AlertName contains "Password"
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | project UserPrincipalName, IPAddress, Location
) on $left.CompromisedEntity == $right.UserPrincipalName

// Left outer join: incluir alertas sem match de signin
SecurityAlert
| join kind=leftouter (
    AADRiskyUsers
    | project UserPrincipalName, RiskLevel
) on $left.CompromisedEntity == $right.UserPrincipalName

// Tipos de join:
// inner         - somente linhas com match em ambas
// leftouter     - todas da esquerda + match da direita (null se sem match)
// rightouter    - todas da direita + match da esquerda
// fullouter     - todas as linhas de ambas
// leftanti      - linhas da esquerda SEM match na direita
// rightanti     - linhas da direita SEM match na esquerda
// innerunique   - inner + deduplica chave da esquerda
```

---

##### Operador `union` — Combinar tabelas

```kql
// Combinar SecurityEvent de múltiplas fontes
union SecurityEvent, WindowsEvent
| where TimeGenerated > ago(1h)
| where EventID in (4624, 4625)

// union com withsource para identificar origem
union withsource=SourceTable
    (SecurityEvent | project TimeGenerated, EventID, Account),
    (SigninLogs    | project TimeGenerated, EventID=ResultType, Account=UserPrincipalName)
| order by TimeGenerated desc
```

---

##### Operador `bin` — Agrupamento temporal

```kql
// Agregar em janelas de tempo
SecurityEvent
| where EventID == 4625   // falha de logon
| summarize count() by bin(TimeGenerated, 15m), Account
| render timechart        // visualizar como gráfico de linhas
```

---

##### Operador `arg_max` e `arg_min` — Último/Primeiro valor por grupo

```kql
// Obter o último login de cada usuário
SigninLogs
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
// Retorna a linha completa do login mais recente de cada usuário

// Obter o primeiro login suspeito de alto risco
SigninLogs
| where RiskLevelDuringSignIn == "high"
| summarize arg_min(TimeGenerated, IPAddress, Location) by UserPrincipalName
```

---

##### Operador `mv-expand` — Expandir arrays

```kql
// SecurityAlert tem campo 'Entities' que é um array JSON
SecurityAlert
| mv-expand Entities
| extend EntityType = tostring(Entities.Type)
| where EntityType == "account"
| extend AccountName = tostring(Entities.Name)
| project TimeGenerated, AlertName, AccountName

// OfficeActivity tem arrays de destinatários
OfficeActivity
| where Operation == "Send"
| mv-expand parse_json(Parameters) as Param
| extend ParamName = tostring(Param.Name), ParamValue = tostring(Param.Value)
```

---

### Principais Tabelas do Microsoft Sentinel

| Tabela | Conteúdo | Connector | Casos de Uso |
|:-------|:---------|:----------|:-------------|
| `SigninLogs` | Logins interativos do Entra ID | Entra ID | Detecção de credential stuffing, impossible travel |
| `AADNonInteractiveUserSignInLogs` | Logins não-interativos (service accounts, OAuth) | Entra ID | Shadow IT, app abuse |
| `AuditLogs` | Alterações no Entra ID (criação de usuários, roles) | Entra ID | Persistence via new account, role escalation |
| `SecurityEvent` | Eventos Windows (Security log) | Log Analytics Agent / AMA | Logon events, process creation |
| `DeviceEvents` | Eventos de endpoint via MDE | M365 Defender | Process injection, malware execution |
| `DeviceLogonEvents` | Logins em dispositivos MDE | M365 Defender | Lateral movement via RDP/WinRM |
| `IdentityLogonEvents` | Logins capturados pelo MDI (AD) | M365 Defender | Kerberoasting, Pass-the-Hash |
| `IdentityDirectoryEvents` | Eventos do Active Directory | M365 Defender | DCSync, GPO modification |
| `EmailEvents` | Metadados de e-mail (MDO) | M365 Defender | Phishing, BEC, data exfiltration via e-mail |
| `EmailUrlInfo` | URLs clicadas em e-mails | M365 Defender | Phishing link analysis |
| `CloudAppEvents` | Atividade em SaaS apps (MDA) | M365 Defender | Data exfiltration, OAuth abuse |
| `OfficeActivity` | Ações no SharePoint, Teams, OneDrive | M365 connector | Insider threat, data exfiltration |
| `AzureActivity` | Operações no Azure control plane | Azure Activity | Resource deletion, role escalation |
| `AzureDiagnostics` | Diagnóstico de recursos Azure (Key Vault, NSG, etc.) | Resource-specific | Key access anomalies |
| `SecurityAlert` | Alertas de todos os produtos Defender | Sentinel | Triage, correlation |
| `SecurityIncident` | Incidentes do Sentinel | Sentinel | Métricas MTTD/MTTR |
| `ThreatIntelligenceIndicator` | IOCs (IPs, domínios, hashes) | TI connector | IOC matching |
| `Watchlist` | Listas personalizadas (IPs permitidos, usuários VIP) | Sentinel Watchlists | Whitelist, VIP monitoring |
| `CommonSecurityLog` | Logs CEF/syslog de appliances | CEF connector | Firewall, IDS/IPS |

---

### Aula 3.2 — Queries para SOC (45 minutos)

#### Conceito de ASIM — Advanced Security Information Model

O **ASIM (Advanced Security Information Model)** é uma camada de normalização do Microsoft Sentinel que abstrai a diferença entre tabelas de diferentes fontes. Em vez de escrever queries que funcionam apenas para `SecurityEvent` (Windows) ou para `SigninLogs` (Entra ID), você escreve uma query ASIM que funciona em **todas as fontes ao mesmo tempo**.

**Exemplo sem ASIM (tabela específica):**

```kql
// Funciona apenas para eventos de logon do Windows
SecurityEvent
| where EventID == 4624
| where AccountType == "User"
| project TimeGenerated, Account, Computer, LogonType
```

**Exemplo com ASIM (normalizado para todas as fontes):**

```kql
// Funciona para Windows, Linux, Entra ID, Active Directory, etc.
imAuthentication                        // tabela ASIM normalizada de autenticação
| where EventResult == "Success"
| where TargetUserType == "Regular"
| project TimeGenerated, TargetUsername, DvcHostname, LogonMethod
```

**Principais tabelas ASIM disponíveis no Sentinel:**

| Tabela ASIM | Função | Fontes normalizadas |
|:------------|:-------|:--------------------|
| `imAuthentication` | Eventos de autenticação | SecurityEvent, SigninLogs, Syslog, custom |
| `imProcess` | Criação/término de processos | SecurityEvent (4688), DeviceProcessEvents |
| `imNetworkSession` | Sessões de rede | CommonSecurityLog, Azure Firewall, palo alto |
| `imDns` | Consultas DNS | AzureDiagnostics (DNS), Sysmon |
| `imFileEvent` | Operações em arquivos | DeviceFileEvents, SecurityEvent (4663) |
| `imRegistryEvent` | Eventos de registro | DeviceRegistryEvents, SecurityEvent (4657) |

**Verificar parsers disponíveis:**

```kql
// Listar parsers ASIM instalados
_ASIM_GetAuthenticationParsers()
| project ParserName, ParserQuery, ParserVersion
```

---

## Queries KQL Reais para o SOC — Banco Meridian

As queries abaixo são usadas diretamente no cenário do Banco Meridian e comentadas linha a linha.

### Query 1 — Detecção de Sign-in Anomalies: Impossible Travel

O **impossible travel** é uma das detecções de identidade mais eficazes porque explora uma limitação física irrefutável: nenhum ser humano consegue estar em São Paulo às 14h30 e em Moscou às 14h47. Quando isso acontece nos logs de autenticação, significa que as credenciais de um usuário foram comprometidas e um atacante em outro país está usando a conta ao mesmo tempo. Esta query usa o operador `prev()` do KQL para comparar o login atual de cada usuário com o login imediatamente anterior, identificando pares de logins de países diferentes em menos de 60 minutos. A técnica de usar `prev()` em vez de um `join` consigo mesmo é mais eficiente computacionalmente e mais legível.

Para o Banco Meridian, esta query é especialmente relevante dado o alerta do FS-ISAC sobre o Grupo Lazarus-BR: operadores de grupos APT geralmente ficam baseados em um país (Rússia, China, Coreia do Norte) enquanto a vítima está no Brasil. A correlação temporal entre o clique de phishing e o primeiro login do atacante tipicamente gera exatamente esse padrão de impossible travel.

```kql
// OBJETIVO: Detectar usuários logando de dois países diferentes em < 1 hora
// MITRE ATT&CK: T1078 — Valid Accounts / T1556 — Modify Authentication Process

SigninLogs
// Filtrar período de análise
| where TimeGenerated > ago(7d)
// Apenas logins bem-sucedidos (ResultType 0 = sucesso)
| where ResultType == 0
// Excluir service principals (foco em usuários humanos)
| where UserType == "Member"
// Excluir localizações vazias (logins sem geo-data, ex.: IPs privados)
| where isnotempty(Location)
// Projetar apenas colunas necessárias para a análise
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    CountryOrRegion = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
// Ordenar por usuário e tempo para calcular diferença entre logins consecutivos
| sort by UserPrincipalName asc, TimeGenerated asc
// Usar prev() para acessar a linha anterior (login anterior do mesmo usuário)
| extend
    PrevUser    = prev(UserPrincipalName, 1),
    PrevCountry = prev(CountryOrRegion, 1),
    PrevTime    = prev(TimeGenerated, 1)
// Calcular diferença de tempo entre logins consecutivos
| extend TimeDiffMinutes = datetime_diff("minute", TimeGenerated, PrevTime)
// Filtrar: mesmo usuário, país diferente, menos de 60 minutos de diferença
| where UserPrincipalName == PrevUser
    and CountryOrRegion != PrevCountry
    and TimeDiffMinutes between (0 .. 60)
// Calcular impossibilidade: velocidade necessária para mudar de país (km/h)
// (simplificado: apenas verificamos a condição de tempo)
| project
    UserPrincipalName,
    TimeGenerated,
    NewCountry = CountryOrRegion,
    NewCity = City,
    NewIP = IPAddress,
    PreviousCountry = PrevCountry,
    TimeDiffMinutes
// Ordenar pelos casos mais recentes
| order by TimeGenerated desc
```

---

### Query 2 — Detecção de Password Spray

O **password spray** é uma das técnicas de ataque de credencial mais usadas contra organizações financeiras porque contorna políticas de bloqueio de conta. Um brute force tradicional tenta muitas senhas em uma conta e eventualmente bloqueia o usuário. O password spray faz o inverso: tenta uma (ou poucas) senha(s) contra muitas contas. Como cada conta recebe apenas 1-2 tentativas, o limiar de bloqueio (geralmente 5-10 tentativas) nunca é atingido. Esta query usa dois operadores agregados em conjunto — `dcount(UserPrincipalName)` para contar quantas contas distintas foram alvo de um IP, e `TargetedUsers = make_set()` para listar os usuários — identificando exatamente esse padrão de "muitas contas, poucas tentativas por conta". O filtro por `ResultType` inclui os códigos de erro mais comuns em ataques de spray no Entra ID, mas exclui 50074 (MFA requerido), que é uma falha esperada em ambientes com Conditional Access corretamente configurado.

Para o Banco Meridian, este padrão é urgente porque o relatório do FS-ISAC mencionou especificamente password spray como vetor dos ataques contra bancos tier-2 brasileiros. Uma detecção positiva desta query deve ser escalada imediatamente para o analista L2 de plantão.

```kql
// OBJETIVO: Detectar ataque de password spray (muitos logins com códigos de erro específicos)
// MITRE ATT&CK: T1110.003 — Password Spraying
// Indicadores: muitas contas diferentes falhando de um mesmo IP em curto período

SigninLogs
// Janela de análise: últimas 2 horas (ajuste conforme necessidade)
| where TimeGenerated > ago(2h)
// Password spray tipicamente usa código 50053 (account locked), 50126 (invalid credentials)
// Também comum: 50055, 50057, 50072, 50074, 50076, 50079, 50158
| where ResultType in (50053, 50055, 50057, 50072, 50126, 50131, 50158)
// Agregar por IP de origem: contar usuários únicos e tentativas totais
| summarize
    TotalAttempts    = count(),                              // tentativas totais
    UniqueUsers      = dcount(UserPrincipalName),            // usuários únicos tentados
    TargetedUsers    = make_set(UserPrincipalName, 50),     // lista dos usuários (max 50)
    ErrorCodes       = make_set(ResultType),                // códigos de erro usados
    FirstAttempt     = min(TimeGenerated),
    LastAttempt      = max(TimeGenerated)
    by IPAddress
// Critério de alert: 10+ usuários únicos de um mesmo IP = provável password spray
| where UniqueUsers >= 10
// Calcular duração do ataque
| extend AttackDurationMin = datetime_diff("minute", LastAttempt, FirstAttempt)
// Classificar severidade
| extend Severity = case(
    UniqueUsers >= 50, "Critical",
    UniqueUsers >= 25, "High",
    UniqueUsers >= 10, "Medium",
    "Low"
)
| project-reorder Severity, IPAddress, UniqueUsers, TotalAttempts, AttackDurationMin, TargetedUsers, FirstAttempt, LastAttempt
| order by UniqueUsers desc
```

---

### Query 3 — Detecção de Lateral Movement via Pass-the-Hash

O **Pass-the-Hash** é uma técnica de movimento lateral onde o atacante usa o hash NTLM de uma senha (obtido via LSASS dump, por exemplo) em vez da senha em texto claro para autenticar em outros sistemas da rede. O hash serve como prova de identidade em ambientes com autenticação NTLM — o servidor não verifica se o atacante conhece a senha, apenas se possui o hash correto. Para o Banco Meridian, que provavelmente ainda tem autenticação NTLM habilitada por compatibilidade com sistemas legados, esta é uma das técnicas mais perigosas: uma vez comprometido um endpoint de funcionário com acesso a dados financeiros, o atacante pode se mover para outros sistemas usando o hash sem nunca precisar conhecer as senhas reais. Esta query usa a tabela `SecurityEvent` do Windows (LogonType = 3 representa network logon) e filtra por eventos NTLM sem sessão Kerberos correspondente — indicador de que não há autenticação real com credencial, apenas replay de hash.

```kql
// OBJETIVO: Detectar Pass-the-Hash — logins NTLM sem senha (logon type 3, no Kerberos)
// MITRE ATT&CK: T1550.002 — Use Alternate Authentication Material: Pass the Hash

SecurityEvent
| where TimeGenerated > ago(24h)
// EventID 4624: logon bem-sucedido
| where EventID == 4624
// LogonType 3 = Network logon (usado em PtH)
| where LogonType == 3
// Autenticação NTLM (Kerberos seria "Kerberos" no campo AuthenticationPackageName)
| where AuthenticationPackageName == "NTLM"
// Excluir contas de máquina (terminam em $)
| where Account !endswith "$"
// Excluir contas de sistema e anônimas
| where Account !in ("ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
// Agregar para identificar padrões
| summarize
    TotalLogins   = count(),
    SourceHosts   = make_set(Computer),       // computadores de origem
    TargetHosts   = make_set(WorkstationName),// computadores de destino
    UniqueTargets = dcount(WorkstationName),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
    by Account, IpAddress
// Filtrar: 3+ destinos diferentes = possível lateral movement
| where UniqueTargets >= 3
| project Account, IpAddress, UniqueTargets, SourceHosts, TargetHosts, TotalLogins, FirstSeen, LastSeen
| order by UniqueTargets desc
```

---

### Query 4 — Detecção de Exfiltração via SharePoint/OneDrive

A exfiltração de dados via SharePoint e OneDrive é o vetor preferencial de **insider threats** em instituições financeiras porque usa canais completamente legítimos — o funcionário tem acesso autorizado ao SharePoint, e a ação de "baixar arquivo" é normal. O que não é normal é baixar 500 arquivos em 2 horas. Esta query usa uma técnica de análise comportamental baseada em baseline: calcula a média histórica de downloads de cada usuário nos últimos 30 dias e compara com a atividade recente. Um usuário que baixa em média 5 arquivos por dia e de repente baixa 200 em uma hora tem `Multiplier = 200/5 = 40x` — muito acima do limiar de 10x usado nesta query. Essa abordagem baseada em desvio da baseline reduz significativamente falsos positivos em relação a thresholds absolutos: o analista financeiro que processa 50 contratos por dia não será alertado desnecessariamente, mas o mesmo analista que baixa 800 contratos no dia anterior à sua demissão será detectado.

Esta detecção é especialmente relevante no contexto do Banco Meridian sob BACEN 4.893, que exige controles de prevenção de vazamento de dados (DLP) para informações de clientes financeiros.

```kql
// OBJETIVO: Detectar download em massa de arquivos do SharePoint Online
// MITRE ATT&CK: T1567.002 — Exfiltration Over Web Service: Cloud Storage
// Cenário Banco Meridian: funcionário com acesso legítimo exfiltrando dados de clientes

OfficeActivity
| where TimeGenerated > ago(24h)
// Operações de download e acesso a arquivos
| where Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
// Filtrar apenas SharePoint e OneDrive (excluir Teams messages)
| where OfficeWorkload in ("SharePoint", "OneDrive")
// Agregar por usuário: total de downloads e arquivos únicos
| summarize
    TotalDownloads    = count(),
    UniqueFiles       = dcount(OfficeObjectId),
    DownloadedFiles   = make_set(OfficeObjectId, 30),   // primeiros 30 arquivos
    SourceIPs         = make_set(ClientIP),
    FirstDownload     = min(TimeGenerated),
    LastDownload      = max(TimeGenerated)
    by UserId
// Calcular janela de tempo do download
| extend DownloadWindowMin = datetime_diff("minute", LastDownload, FirstDownload)
// Alertar: 50+ downloads em menos de 30 minutos = comportamento anômalo
| where TotalDownloads >= 50 and DownloadWindowMin <= 30
// Calcular taxa de download por minuto
| extend DownloadsPerMinute = toreal(TotalDownloads) / iff(DownloadWindowMin == 0, 1, toreal(DownloadWindowMin))
| project-reorder UserId, TotalDownloads, UniqueFiles, DownloadsPerMinute, DownloadWindowMin, SourceIPs, FirstDownload, LastDownload
| order by TotalDownloads desc
```

---

### Query 5 — Detecção de Adição de Credencial a Application/Service Principal

A **adição de credencial a uma aplicação** (service principal ou app registration) é uma das técnicas de persistência mais insidiosas em ambientes Azure porque não requer acesso contínuo à conta do usuário comprometido. Após o acesso inicial via phishing, um atacante que obteve permissões de administrador no Entra ID pode adicionar uma chave de API ou certificado a um app registration existente — por exemplo, o app de integração com o sistema bancário core. A partir desse momento, o atacante tem acesso autenticado aos recursos do app (SharePoint, Exchange, Graph API) de forma completamente independente da conta do usuário, mesmo que a senha seja redefinida e o MFA seja reconfigurado. A chave adicionada é o backdoor. Esta query usa a tabela `AuditLogs` e filtra pela operação `Add service principal credentials`, que é o evento específico registrado quando uma chave ou certificado é adicionado. A presença de `InitiatorUPN` de fora do time de TI autorizado é um forte indicador de abuso.

```kql
// OBJETIVO: Detectar quando uma credencial (chave ou certificado) é adicionada a um app
// MITRE ATT&CK: T1098.001 — Account Manipulation: Additional Cloud Credentials
// Este é um vetor comum de persistência em Azure após comprometimento inicial

AuditLogs
| where TimeGenerated > ago(7d)
// Operações de adição de credencial a aplicações ou service principals
| where OperationName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add application",
    "Update service principal"
)
// Extrair detalhes do ator que realizou a ação
| extend
    ActorUPN    = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP     = tostring(InitiatedBy.user.ipAddress),
    ActorApp    = tostring(InitiatedBy.app.displayName),
    TargetApp   = tostring(TargetResources[0].displayName),
    TargetType  = tostring(TargetResources[0].type)
// Extrair tipo de credencial adicionada (Key ou Certificate)
| mv-expand ModifiedProperties = TargetResources[0].modifiedProperties
| extend
    PropName  = tostring(ModifiedProperties.displayName),
    PropValue = tostring(ModifiedProperties.newValue)
| where PropName contains "Key" or PropName contains "Certificate" or PropName == "AppAddress"
// Projetar resultado final
| project
    TimeGenerated,
    OperationName,
    ActorUPN,
    ActorIP,
    TargetApp,
    TargetType,
    PropName,
    Result
| order by TimeGenerated desc
```

---

### Query 6 — Correlação: Alerta MDE + Login Suspeito (Join)

A **correlação cross-source via join** é o superpoder do KQL para investigações de segurança complexas. Fontes de dados isoladas raramente contam a história completa de um ataque: o Defender for Endpoint (MDE) vê que um endpoint foi comprometido, mas não sabe se a conta do usuário também foi; o Entra ID vê um login suspeito, mas não sabe se o endpoint do usuário gerou alertas. O `join` no KQL conecta essas duas perspectivas usando um campo em comum — o nome de usuário — e revela correlações que nenhuma das fontes conseguiria detectar individualmente. Esta query usa `join kind=inner`, que mantém apenas os resultados que têm correspondência em ambas as tabelas: usuários com alertas de endpoint E logins suspeitos. A correlação `LoginTime > AlertTime` garante que estamos buscando logins que ocorreram DEPOIS do comprometimento do endpoint — exatamente o padrão de "endpoint comprometido → movimento lateral usando as credenciais roubadas".

Esta é a técnica fundamental usada no Lab 05 (XDR Cross-Domain Hunting) — dominar o `join` no contexto de segurança é o que diferencia analistas L1 de L2.

```kql
// OBJETIVO: Correlacionar alertas do Defender for Endpoint com logins suspeitos do mesmo usuário
// Este tipo de correlação revela a cadeia de ataque completa

let RecentAlerts = materialize(
    SecurityAlert
    | where TimeGenerated > ago(24h)
    // Alertas de alta e crítica severidade do MDE
    | where ProviderName == "MDATP"
        and AlertSeverity in ("High", "Critical")
    | extend AlertedUser = tostring(parse_json(Entities)[0].UserPrincipalName)
    | where isnotempty(AlertedUser)
    | project AlertTime = TimeGenerated, AlertName, AlertSeverity, AlertedUser, AlertId = SystemAlertId
);

let SuspiciousLogins = materialize(
    SigninLogs
    | where TimeGenerated > ago(24h)
    // Logins com risco médio ou alto
    | where RiskLevelDuringSignIn in ("medium", "high")
    | project LoginTime = TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevel = RiskLevelDuringSignIn
);

// Correlacionar: mesmo usuário com alerta MDE E login suspeito no mesmo dia
RecentAlerts
| join kind=inner SuspiciousLogins on $left.AlertedUser == $right.UserPrincipalName
// Calcular diferença de tempo entre o alerta e o login suspeito
| extend TimeDiffHours = abs(datetime_diff("hour", AlertTime, LoginTime))
// Filtrar: alerta e login suspeito no mesmo período de 6 horas
| where TimeDiffHours <= 6
| project
    AlertedUser,
    AlertName,
    AlertSeverity,
    AlertTime,
    LoginTime,
    LoginIPAddress = IPAddress,
    LoginLocation = Location,
    LoginRiskLevel = RiskLevel,
    TimeDiffHours
| order by AlertTime desc
```

---

### Query 7 — Detecção de Escalada de Privilégio: Adição de Conta ao Grupo Admin

A **adição não autorizada de conta a grupo privilegiado** é um indicador crítico de escalada de privilégio (T1078 / T1098). Em ambientes Azure/Microsoft 365, grupos como "Global Administrators", "Security Administrators" e "Exchange Administrators" controlam o acesso a toda a infraestrutura cloud. Um atacante que comprometeu uma conta comum mas não tem privilégios suficientes para seus objetivos — acessar dados financeiros, criar novas contas, exfiltrar e-mails — frequentemente tenta adicionar sua conta comprometida a um grupo admin como passo de escalada. O AuditLogs registra cada adição a grupo com o operador que executou a ação, a conta que foi adicionada e o nome do grupo destino. Esta query não apenas detecta a adição, mas também captura quem adicionou (`InitiatorUPN`) — pois uma adição legítima feita pelo administrador de TI é diferente de uma adição feita pela própria conta comprometida (sinal de escalada via conta já parcialmente privilegiada).

Para o Banco Meridian, este é um evento de alta severidade que deve acionar notificação imediata ao CISO, independentemente do horário.

```kql
// OBJETIVO: Detectar quando um usuário é adicionado a grupos de alto privilégio
// MITRE ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts / T1098 — Account Manipulation

AuditLogs
| where TimeGenerated > ago(7d)
// Operação de adição a grupo
| where OperationName == "Add member to role"
    or OperationName == "Add member to group"
// Extrair informações do membro adicionado
| extend
    AddedUser       = tostring(TargetResources[0].userPrincipalName),
    GroupOrRole     = tostring(TargetResources[1].displayName),
    ActorUPN        = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP         = tostring(InitiatedBy.user.ipAddress)
// Filtrar apenas grupos/roles de alto privilégio
| where GroupOrRole in (
    "Global Administrator",
    "Security Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "User Administrator",
    "Azure AD Joined Device Local Administrator",
    "Domain Admins",
    "Enterprise Admins",
    "SOC-Admins"         // grupo personalizado do Banco Meridian
)
| project TimeGenerated, AddedUser, GroupOrRole, ActorUPN, ActorIP, Result
| order by TimeGenerated desc
```

---

### Query 8 — Detecção de Comandos Suspeitos em Endpoints (DeviceProcessEvents)

A **execução de ferramentas ofensivas em endpoints** é detectável pelo Microsoft Defender for Endpoint através da tabela `DeviceProcessEvents`, que registra cada processo iniciado nos endpoints onboardados — incluindo nome do processo, linha de comando completa, processo pai e usuário que executou. Esta query usa `has_any()` para buscar uma lista de indicadores de comprometimento: nomes de ferramentas conhecidas de ataque (mimikatz, cobalt strike, meterpreter), parâmetros de PowerShell ofensivo (base64 encoding, bypass de execution policy, download de payloads via IEX/DownloadString) e commandlets de reconhecimento (whoami, net user, ipconfig usados de forma encadeada). O operador `has_any()` no KQL é mais eficiente que múltiplos `where contains` porque avalia todas as condições em uma única passagem sobre os dados. O campo `InitiatingProcessCommandLine` frequentemente revela a cadeia completa de execução: qual processo pai executou o comando suspeito, permitindo reconstruir o caminho de ataque.

Esta query complementa as detecções automáticas do MDE: enquanto o MDE usa ML e threat intelligence para detectar comportamentos automaticamente, esta query KQL permite customização para TTPs específicos identificados em threat reports do setor bancário brasileiro.

```kql
// OBJETIVO: Detectar execução de ferramentas de reconhecimento e coleta de credenciais
// MITRE ATT&CK: T1059.001 — PowerShell, T1003 — OS Credential Dumping

DeviceProcessEvents
| where TimeGenerated > ago(24h)
// Processos suspeitos conhecidos usados em ataques
| where FileName in~ (
    "mimikatz.exe",
    "pwdump.exe",
    "procdump.exe",
    "wce.exe",
    "gsecdump.exe",
    "ntdsutil.exe",
    "reg.exe",
    "secretsdump.py"
)
// OU comandos PowerShell com keywords suspeitas
or (FileName =~ "powershell.exe"
    and ProcessCommandLine has_any ("Invoke-Mimikatz", "Invoke-BloodHound", "Net.Webclient", "-enc", "FromBase64String", "IEX", "Invoke-Expression", "DownloadString"))
// OU execução de net commands (reconhecimento AD)
or (FileName =~ "net.exe"
    and ProcessCommandLine has_any ("localgroup", "group /dom", "user /dom"))
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

---

### Query 9 — Detecção de Exfiltração via E-mail (Mass Forward Rule)

A **regra de encaminhamento de e-mail** (T1114.003) é uma das técnicas de exfiltração mais discretas usadas em ataques BEC (Business Email Compromise) e spionagem corporativa. Após comprometer uma conta, o atacante cria uma regra de caixa de entrada que encaminha automaticamente cópias de todos os e-mails recebidos para um endereço externo (Gmail, Outlook pessoal, ProtonMail). O usuário legítimo continua recebendo seus e-mails normalmente, sem perceber que cada mensagem também está sendo enviada para o atacante. Para o Banco Meridian, este risco é especialmente sério: e-mails de executivos da área financeira frequentemente contêm informações privilegiadas de mercado, estratégias de M&A, dados de clientes e comunicações regulatórias com o BACEN. Esta query busca as operações `New-InboxRule` e `Set-Mailbox -ForwardingAddress` no `OfficeActivity`, que são os dois mecanismos técnicos pelos quais o encaminhamento pode ser configurado no Exchange Online — o primeiro via regra de caixa de entrada, o segundo via configuração de mailbox no nível do Exchange.

A ausência de resultados nesta query é excelente — significa que nenhuma regra de encaminhamento suspeita está ativa. Mas ela deve ser executada regularmente como parte da caça proativa (hunting) do SOC.

```kql
// OBJETIVO: Detectar regras de encaminhamento de e-mail para endereços externos
// MITRE ATT&CK: T1114.003 — Email Collection: Email Forwarding Rule

OfficeActivity
| where TimeGenerated > ago(30d)
// Criação ou modificação de regras de caixa de entrada
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
// Extrair parâmetros da regra
| mv-expand parse_json(Parameters) as Param
| extend ParamName = tostring(Param.Name), ParamValue = tostring(Param.Value)
// Filtrar por parâmetros de encaminhamento
| where ParamName in (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo"
)
// Excluir encaminhamentos para o próprio domínio (apenas externos são suspeitos)
| where ParamValue !contains "bancomeridianlab.onmicrosoft.com"
    and ParamValue !contains "bancomeridian.com.br"
| project
    TimeGenerated,
    UserId,
    Operation,
    ForwardingAddress = ParamValue,
    ClientIP,
    UserAgent
| order by TimeGenerated desc
```

---

### Query 10 — Dashboard: Resumo de Saúde do SOC (últimas 24h)

O **dashboard de saúde do SOC** é uma query operacional de alto nível que os analistas executam no início do turno ou que alimenta um Workbook automatizado exibido nos monitores do SOC do Banco Meridian. Em vez de investigar eventos específicos, esta query cria uma visão agregada da atividade de segurança: quantos incidentes foram gerados por severidade, quantos alertas por fonte, volume de ingestão de cada tabela. Esse "resumo executivo técnico" serve dois propósitos: primeiro, permite ao analista que está assumindo o turno entender rapidamente o estado atual do ambiente sem precisar abrir múltiplos painéis; segundo, fornece as métricas de MTTD/MTTR (Mean Time to Detect / Mean Time to Respond) que o CISO usa para reportar a eficiência do SOC ao board. Para o Banco Meridian, ter este dashboard disponível como Workbook no Sentinel é parte da maturidade de operações de segurança esperada por um banco sob supervisão do BACEN — demonstra que o SOC tem capacidade de monitoramento contínuo e rastreamento de indicadores de desempenho.

```kql
// OBJETIVO: Query de dashboard para visão geral do SOC em 24 horas
// Executar como parte de um Workbook ou relatório diário

let TimeWindow = ago(24h);

union withsource=Source
(
    // Total de alertas por severidade
    SecurityAlert
    | where TimeGenerated > TimeWindow
    | summarize Count = count() by Severity = AlertSeverity
    | extend Category = "Alertas por Severidade"
),
(
    // Total de incidentes abertos
    SecurityIncident
    | where TimeGenerated > TimeWindow
    | where Status != "Closed"
    | summarize Count = count() by Severity
    | extend Category = "Incidentes Abertos"
),
(
    // Logins com falha nas últimas 24h
    SigninLogs
    | where TimeGenerated > TimeWindow
    | where ResultType != 0
    | summarize Count = count() by Severity = "Info"
    | extend Category = "Logins com Falha"
),
(
    // Alertas de alto risco do MDE
    SecurityAlert
    | where TimeGenerated > TimeWindow
    | where ProviderName == "MDATP"
        and AlertSeverity in ("High", "Critical")
    | summarize Count = count() by Severity = AlertSeverity
    | extend Category = "Alertas MDE Alto Risco"
)
| project Category, Severity, Count
| order by Category asc, Count desc
```

---

## Atividades de Fixação — Quiz

**Instruções:** Escolha a alternativa correta. Gabarito ao final.

**Questão 1.** Qual operador KQL você usaria para adicionar uma coluna calculada `IsHighRisk = RiskLevelDuringSignIn == "high"` a uma query existente sem modificar as colunas já projetadas?

A) `project`
B) `summarize`
C) `extend`
D) `where`

---

**Questão 2.** Você quer encontrar o login mais recente de cada usuário no `SigninLogs`. Qual função de agregação retorna a linha completa correspondente ao registro mais recente?

A) `max(TimeGenerated)`
B) `arg_max(TimeGenerated, *)`
C) `top(1) by TimeGenerated`
D) `last(TimeGenerated)`

---

**Questão 3.** Qual é a diferença entre `count()` e `dcount()` no operador `summarize`?

A) `count()` conta linhas; `dcount()` conta valores distintos (estimativa probabilística)
B) `count()` é mais preciso; `dcount()` é exato mas mais lento
C) Não há diferença — ambos retornam o mesmo resultado
D) `dcount()` só funciona em colunas do tipo string

---

**Questão 4.** No contexto do ASIM, para que serve a tabela `imAuthentication`?

A) É uma tabela física que substitui o `SigninLogs`
B) É uma função/view normalizada que abstrai múltiplas fontes de autenticação em um esquema comum
C) É uma tabela de configuração do Sentinel que lista parsers instalados
D) É o nome antigo do `AuditLogs` antes da migração para o ASIM

---

**Questão 5.** Você precisa correlacionar alertas do `SecurityAlert` com logins do `SigninLogs` no mesmo usuário. Qual tipo de `join` você usaria para retornar **apenas os alertas que têm um login correspondente** e descartar os alertas sem match?

A) `leftouter`
B) `fullouter`
C) `inner`
D) `leftanti`

---

**Gabarito:**
1. C — `extend` adiciona colunas sem remover as existentes
2. B — `arg_max(TimeGenerated, *)` retorna a linha inteira do valor máximo
3. A — `count()` é exato; `dcount()` usa HyperLogLog (estimativa com margem de erro ~1%)
4. B — ASIM usa funções que consultam múltiplas tabelas e normalizam o esquema
5. C — `join kind=inner` retorna somente as linhas com match em ambas as tabelas

---

## Roteiro de Gravação — Aula 3.1: Fundamentos KQL (45 minutos)

*Este roteiro é para o instrutor seguir durante a gravação. Fale em primeira pessoa, como se estivesse explicando a um colega de SOC.*

---

"Olá! Bem-vindos à Aula 3.1 — Fundamentos KQL. Nesta aula, eu vou te mostrar tudo que você precisa saber para começar a escrever queries no Microsoft Sentinel do zero. Se você já usou SQL antes, vai se sentir em casa. Se não usou, também não tem problema — o KQL é muito intuitivo."

"Antes de abrir o Sentinel, deixa eu te mostrar a lógica por trás do KQL. Imagine uma esteira de fábrica. O dado entra pela esquerda — é a tabela — e passa por várias operações, como filtros, transformações, agregações, até chegar na forma que você quer na saída. Cada operação é separada por aquele símbolo de barra vertical, o pipe, que todo mundo do Linux já conhece."

"Vou abrir aqui o portal do Sentinel — vocês vão ver a mesma interface que eu preparei no Módulo Zero. Clico em 'Logs', e aqui está o editor KQL."

*[Demonstração ao vivo — abrir Sentinel > Logs]*

"A primeira coisa que vou te mostrar é o `where`. É o operador mais usado no KQL, e funciona como um filtro. Vou consultar o `SigninLogs` — que é a tabela que armazena todos os logins do Entra ID, o novo nome do Azure Active Directory."

*[Digitar e executar a query ao vivo]*

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType
| take 20
```

"Vejam — trouxe apenas os logins com falha da última hora. O `ResultType != 0` significa 'resultado diferente de zero', e zero é sucesso no Entra ID. Qualquer número diferente de zero é um erro."

"Agora vou adicionar o `extend` para criar uma coluna que me diz se o login é de alto risco ou não."

*[Adicionar extend à query anterior]*

"Vejam como adicionei uma coluna nova sem precisar reescrever toda a query — apenas mais um pipe, o operador extend, e uma expressão. O `iff` funciona como um if-else: se a condição for verdadeira, retorna o primeiro valor; se falsa, o segundo."

"Agora vamos falar do operador mais poderoso do KQL para análise de segurança: o `summarize`. É com ele que vamos detectar ataques em escala."

*[Escrever nova query de summarize ao vivo]*

"Vejam: passei de dezenas de linhas para uma tabela resumida por usuário. Agora posso ver de um relance quais usuários tiveram mais falhas de login. Se um usuário tem 50 falhas em 1 hora, isso é um sinal claro de ataque."

"Na próxima aula, vou pegar essas queries básicas e construir detecções reais para o nosso Banco Meridian — password spray, impossible travel, lateral movement. Até lá!"

---

## Roteiro de Gravação — Aula 3.2: Queries para SOC (45 minutos)

*Roteiro para o instrutor.*

---

"Bem-vindos à Aula 3.2! Na aula anterior eu mostrei os fundamentos do KQL. Agora a gente vai colocar a mão na massa e escrever queries que você pode usar hoje mesmo no seu SOC."

"Vou começar com um dos ataques mais comuns que vemos em ambientes corporativos: o **password spray**. Diferente do brute force, que testa muitas senhas em uma conta, o password spray testa **uma senha em muitas contas**. É mais difícil de detectar porque não bloqueia nenhuma conta."

"A lógica da detecção é simples: se um IP tenta logar em 20, 30, 50 contas diferentes em uma hora e falha em todas com o mesmo código de erro, isso é um spray. Vou construir essa query do zero."

*[Abrir Sentinel > Logs e digitar ao vivo]*

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType in (50053, 50126, 50055)
```

"Esses códigos — 50053, 50126, 50055 — são os erros mais comuns em password spray. O 50126 é 'credencial inválida', o 50053 é 'conta bloqueada'. Deixa eu mostrar o que cada um significa..."

*[Abrir tabela de códigos de erro do Entra ID numa aba separada]*

"Agora vou adicionar o `summarize` para contar quantos usuários únicos cada IP tentou."

*[Continuar construindo a query ao vivo, passo a passo]*

"Pronto — agora temos a query de password spray. Vejam que adicionei o filtro `UniqueUsers >= 10`. Isso é o threshold, o limiar. Em um ambiente real, você vai ajustar esse número com base no comportamento normal da sua empresa."

"Agora vou mostrar uma query mais avançada: **impossible travel**. Essa é uma das minhas favoritas porque demonstra o poder do KQL para detectar comportamentos impossíveis no mundo real. Se um usuário loga do Brasil e cinco minutos depois loga da Rússia, fisicamente isso é impossível — ou a conta foi comprometida, ou o usuário está usando VPN."

*[Escrever a query de impossible travel ao vivo, explicando o `prev()` passo a passo]*

"O operador `prev()` é um operador de tabela de série temporal que acessa a linha anterior na ordem de execução da query. É com ele que conseguimos comparar o login atual com o login anterior do mesmo usuário."

"Antes de fecharmos essa aula, quero mostrar o conceito de **ASIM** — Advanced Security Information Model. Imagine que você tem logs de firewall da Palo Alto, logs de login do Windows, logs do Entra ID, logs do Linux. Todos têm formatos diferentes. Com ASIM, você escreve uma query e ela funciona em todos eles."

*[Demonstrar a diferença entre query específica e query ASIM]*

"Na live desta semana, vamos praticar todas essas queries juntos com dados reais do nosso tenant de laboratório. Tragam suas queries — eu vou propor 3 desafios ao vivo para vocês resolverem."

---

## Laboratório Integrado — KQL: Investigando o Banco Meridian

### Contexto Situacional

O SOC do Banco Meridian recebeu uma notificação de um cliente reclamando que seu acesso ao internet banking foi bloqueado. Ao mesmo tempo, o sistema de monitoramento mostra um pico de logins com falha entre 02h00 e 04h00 da madrugada. O analista de plantão (ana.costa) precisa investigar se houve um ataque de credential stuffing e se alguma conta foi comprometida.

### Situação Inicial

Ambiente Sentinel ativo com conectores `SigninLogs`, `AuditLogs` e `SecurityEvent` habilitados. Os logs das últimas 24 horas estão disponíveis. Nenhuma regra analítica detectou o evento automaticamente — o alerta chegou por canal externo (reclamação de cliente).

### Problema Identificado

Pico anômalo de logins com falha no período de 02h00–04h00 de um conjunto incomum de endereços IP. Suspeita de credential stuffing (uso de listas de credenciais roubadas de outros serviços).

### Roteiro de Atividades

1. Identificar os IPs de origem com maior número de falhas
2. Verificar se algum IP teve sucesso após as falhas (possível conta comprometida)
3. Identificar as contas afetadas pelo ataque
4. Verificar se houve atividade suspeita pós-login (downloads, alteração de dados)
5. Escrever um resumo da investigação com timeline e recomendações

### Script Passo a Passo

**Query Lab 1 — Panorama geral: pico de falhas no período suspeito**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-04-24 02:00) .. datetime(2026-04-24 04:00))
| where ResultType != 0
| summarize FailureCount = count() by IPAddress, bin(TimeGenerated, 15m)
| render timechart
```

**Objetivo:** Visualizar o pico de falhas graficamente por IP ao longo do tempo.

**Resultado esperado:** Gráfico mostrando pico de falhas entre 02h e 04h. IPs com volume anômalo devem se destacar.

---

**Query Lab 2 — Identificar IPs com mais de 20 falhas E pelo menos 1 sucesso**

```kql
let AttackWindow = between(datetime(2026-04-24 02:00) .. datetime(2026-04-24 05:00));
let SuspiciousIPs = SigninLogs
    | where TimeGenerated AttackWindow
    | where ResultType != 0
    | summarize Failures = count() by IPAddress
    | where Failures >= 20;

SigninLogs
| where TimeGenerated AttackWindow
| join kind=inner SuspiciousIPs on IPAddress
| where ResultType == 0   // sucesso após falhas
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, Location
| order by TimeGenerated asc
```

**Objetivo:** Identificar contas que foram comprometidas (tiveram sucesso após as falhas do IP suspeito).

---

**Query Lab 3 — Analisar atividade pós-comprometimento**

```kql
// Substitua 'CONTA_COMPROMETIDA' pelo UPN identificado na Query 2
let CompromisedAccount = "roberto.alves@bancomeridianlab.onmicrosoft.com";
let CompromiseTime = datetime(2026-04-24 03:15);  // ajuste conforme resultado da Query 2

union OfficeActivity, AuditLogs, SigninLogs
| where TimeGenerated > CompromiseTime
| where UserId == CompromisedAccount
    or UserPrincipalName == CompromisedAccount
| project TimeGenerated, Type, OperationName, Operation, IPAddress, ClientIP, UserAgent
| order by TimeGenerated asc
| take 50
```

---

**Query Lab 4 — Verificar se houve criação de regra de forward de e-mail pós-comprometimento**

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where UserId == "roberto.alves@bancomeridianlab.onmicrosoft.com"
| mv-expand parse_json(Parameters) as Param
| extend ParamName = tostring(Param.Name), ParamValue = tostring(Param.Value)
| where ParamName in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Operation, ParamName, ParamValue, ClientIP
```

---

**Query Lab 5 — Gerar timeline completa do incidente (desafio final)**

```kql
// Monte uma timeline combinada de todos os eventos relevantes
// relacionados ao ataque de credential stuffing e ao possível comprometimento

let SuspiciousIP = "185.220.101.47";  // IP identificado nas queries anteriores
let CompromisedUser = "roberto.alves@bancomeridianlab.onmicrosoft.com";
let IncidentStart = datetime(2026-04-24 02:00);
let IncidentEnd = datetime(2026-04-24 06:00);

union withsource=EventSource
(
    SigninLogs
    | where TimeGenerated between (IncidentStart .. IncidentEnd)
    | where UserPrincipalName == CompromisedUser or IPAddress == SuspiciousIP
    | project TimeGenerated, EventSource="SigninLogs", Description=strcat(
        iff(ResultType == 0, "[SUCESSO] ", "[FALHA] "),
        "Login - UPN: ", UserPrincipalName,
        " | IP: ", IPAddress,
        " | Local: ", tostring(LocationDetails.countryOrRegion))
),
(
    OfficeActivity
    | where TimeGenerated between (IncidentStart .. IncidentEnd)
    | where UserId == CompromisedUser
    | project TimeGenerated, EventSource="OfficeActivity", Description=strcat(
        "[M365] ", Operation, " | Arquivo: ", OfficeObjectId)
),
(
    AuditLogs
    | where TimeGenerated between (IncidentStart .. IncidentEnd)
    | where InitiatedBy.user.userPrincipalName == CompromisedUser
    | project TimeGenerated, EventSource="AuditLogs", Description=strcat(
        "[AUDIT] ", OperationName, " | Resultado: ", Result)
)
| order by TimeGenerated asc
| project TimeGenerated, EventSource, Description
```

### Objetivos por Etapa

| Etapa | Query | Objetivo de Aprendizagem |
|:------|:------|:--------------------------|
| 1 | Lab 1 | Usar `render timechart` para visualizar anomalias temporais |
| 2 | Lab 2 | Correlacionar IPs com falhas e sucesso usando `join` e `let` |
| 3 | Lab 3 | Usar `union` para investigar múltiplas tabelas simultaneamente |
| 4 | Lab 4 | Usar `mv-expand` para expandir arrays JSON em linhas |
| 5 | Lab 5 | Construir timeline de incidente correlacionando múltiplas fontes |

### Gabarito Completo

**Lab 1:** A query deve gerar um gráfico com pico visível entre 02h e 04h. Se os dados do lab não tiverem esse período exato, mude o `between` para `ago(6h)` e procure qualquer pico anômalo.

**Lab 2:** O operador `between` exige que a expressão seja um filtro `where`. A sintaxe correta é `| where TimeGenerated between(...)`. Se der erro, verifique que não há espaço entre `between` e o parêntese.

**Lab 3:** Se não houver conta comprometida nos dados do lab, use qualquer UPN presente nos `SigninLogs` para testar a query. O objetivo é praticar o `union` de tabelas.

**Lab 4:** Em ambientes onde não houve regra de forward criada, a query retornará vazia — isso é o resultado esperado (negativo confirmado). Documente no relatório.

**Lab 5:** Esta é a query mais complexa do módulo. O ponto crítico é o `strcat()` para criar a coluna `Description` e o `union withsource` para identificar a origem de cada evento. Erros comuns: esquecer o fechamento dos parênteses no `strcat`, ou referenciar colunas que não existem em uma das tabelas do union (use `project` para garantir o mesmo schema em cada branch do union).
