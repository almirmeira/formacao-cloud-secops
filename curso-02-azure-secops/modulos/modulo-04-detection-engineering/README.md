# Módulo 04 — Detection Engineering no Microsoft Sentinel

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 5 horas (2h videoaulas + 2h laboratório + 1h live online)                   |
| **Formato**              | 2 aulas gravadas + Lab 03 + sessão live de revisão de detecções             |
| **Pré-requisito**        | Módulos 01, 02 e 03 (KQL) concluídos                                        |
| **Certificação Alvo**    | SC-200 — Domínio 3: Configure detection and perform investigations           |
| **Cenário**              | Banco Meridian — construindo o catálogo de detecções após os primeiros alertas |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Diferenciar os tipos de analytics rules: Scheduled, NRT, Fusion, Anomaly e ML Behavior Analytics
2. Criar analytics rules completas com KQL, entity mapping, MITRE tagging e alert grouping
3. Configurar watchlists e usá-las em queries de detecção
4. Integrar threat intelligence com o Sentinel para matching automático de IOCs
5. Criar automation rules para pré-triagem automática de incidentes
6. Implementar as 5 analytics rules de alto impacto para o cenário bancário

---

## 1. Tipos de Analytics Rules

### 1.1 Visão Geral

O Sentinel possui 5 tipos de analytics rules, cada um com propósito e latência diferentes:

| Tipo                          | Latência     | Fonte de dados         | Criado por       | Caso de uso                                           |
|:------------------------------|:------------:|:----------------------:|:----------------:|:------------------------------------------------------|
| **Scheduled**                 | 5min – 14d   | Qualquer tabela KQL    | Usuário          | Detecções customizadas baseadas em KQL                |
| **NRT (Near Real-Time)**      | ~1 minuto    | Qualquer tabela KQL    | Usuário          | Detecções de alta urgência (account lockout, malware) |
| **Fusion**                    | Automático   | Múltiplas fontes       | Microsoft        | Correlação de ataques multi-estágio via ML            |
| **Anomaly (UEBA)**            | Diária       | Behavior Analytics     | Microsoft/UEBA   | Desvios comportamentais de usuários e entidades       |
| **ML Behavior Analytics**     | Automático   | Entra ID + AuditLogs   | Microsoft        | Detecção baseada em ML de anomalias de identidade     |

### 1.2 Analytics Rules do Tipo Scheduled

O tipo mais comum e flexível. Executa uma query KQL em intervalos definidos e gera um alerta quando o resultado não é vazio (ou quando atinge um threshold configurado).

**Parâmetros principais**:
- **Query**: KQL que define o que detectar
- **Query scheduling**: frequência de execução (5min a 14 dias) e janela de dados consultados
- **Alert threshold**: número mínimo de resultados para gerar alerta (default: 0)
- **Event grouping**: agrupar eventos em um alerta ou um alerta por evento
- **Alert details**: nome dinâmico, descrição, severidade

**Quando usar**: A maioria das detecções personalizadas. Permite correlação complexa de múltiplas tabelas com joins, agregações e funções KQL avançadas.

**Limitação**: Latência mínima de 5 minutos. Para ameaças que exigem resposta em segundos, usar NRT.

### 1.3 Analytics Rules do Tipo NRT (Near Real-Time)

Regras NRT executam aproximadamente a cada minuto, com latência de ingestão incluída. São ideais para:
- Detecção de malware (onde cada segundo conta para contenção)
- Bloqueio de conta após múltiplas falhas (brute force em andamento)
- Tentativas de login com credenciais vazadas
- Criação de conta de administrador não autorizada

**Limitações das NRT**:
- Query deve retornar resultados em menos de 30 segundos
- Não suportam `join`, `union` ou operadores de série temporal complexos
- Não suportam janela de look-back maior que 10 minutos
- Não suportam `summarize` com múltiplas dimensões

### 1.4 Fusion: Correlação de Ataques Multi-Estágio

O Fusion é o motor de ML do Sentinel que correlaciona automaticamente sinais de múltiplas fontes para detectar ataques multi-estágio. Não requer configuração — a Microsoft mantém os modelos.

**Exemplos de cenários detectados pelo Fusion**:
- Phishing → credential theft → lateral movement → data exfiltration
- Malware infection → privilege escalation → persistence → C2 communication
- Credential spray → success → suspicious resource access → anomalous download

**Como funciona**: O Fusion analisa alertas de baixa severidade que isoladamente parecem benignos, mas em conjunto formam um padrão de ataque. O resultado é um incidente de alta fidelidade com toda a cadeia de ataque documentada.

**Para o Banco Meridian**: O Fusion detectaria automaticamente o cenário "Operação Guaraná" do Capstone — AiTM phishing → token theft → OneDrive download → email forwarding rule → OAuth app registration.

### 1.5 Anomaly: UEBA (User Entity Behavior Analytics)

O UEBA analisa o comportamento de usuários e entidades (hosts, aplicações) para criar uma baseline e detectar desvios.

**O que o UEBA monitora**:
- Horários de login (usuário que nunca trabalha de madrugada → login às 3h)
- Países de acesso (usuário sempre de São Paulo → login de Ucrânia)
- Volume de dados acessados (analista que acessa 50 documentos/dia → acessa 2.000)
- Recursos acessados (usuário de TI acessando sistema de RH pela primeira vez)
- Pares de comunicação (host que nunca acessou determinado servidor)

**Configuração**: O UEBA requer habilitação separada no Sentinel (Settings → UEBA) e coleta de logs de pelo menos 7 dias para criar a baseline inicial (14 dias para baseline estável).

---

## 2. Anatomia de uma Analytics Rule

### 2.1 Estrutura Completa

Uma analytics rule do tipo Scheduled tem os seguintes componentes:

```
ANALYTICS RULE
├── General
│   ├── Name: "Impossible Travel — Login de Dois Países em 1h"
│   ├── Description: "Detecta quando o mesmo usuário faz login..."
│   ├── Status: Enabled/Disabled
│   └── Severity: High/Medium/Low/Informational
│
├── Set rule logic
│   ├── Rule query (KQL)
│   ├── Alert enrichment
│   │   ├── Entity mapping (Account, Host, IP, URL, FileHash, Process)
│   │   └── Custom details (campos adicionais no alerta)
│   ├── Query scheduling
│   │   ├── Run every: 5 minutes / 1 hour / 1 day
│   │   └── Lookup data from: last 1 hour / 14 days
│   ├── Alert threshold: > 0 results
│   └── Event grouping: Group all events into a single alert / One alert per row
│
├── Incident settings
│   ├── Incident creation: Enabled
│   └── Alert grouping: Group related alerts into incidents (by entity, time window)
│
├── Automated response
│   └── Automation rules to attach
│
└── Review and create
    └── MITRE ATT&CK: mapping de Tactics e Techniques
```

### 2.2 Query Scheduling — Conceitos

**Run every**: frequência de execução. Uma rule que roda a cada hora consome menos compute, mas tem latência maior.

**Lookup data from**: janela de dados analisada em cada execução. Uma rule que roda a cada hora com lookup de 1 hora analisa dados diferentes a cada execução. Uma rule que roda a cada hora com lookup de 24h há sobreposição — os mesmos eventos podem gerar alertas duplicados se não usar deduplicação.

**Combinação recomendada para evitar gaps e duplicações**:
- Run every: 1 hora
- Lookup data from: 1 hora + 10 minutos de buffer (para latência de ingestão)

### 2.3 Entity Mapping

O entity mapping transforma campos de um alerta em entidades estruturadas. Entidades são fundamentais porque:
- Permitem correlação automática entre incidentes (dois incidentes com a mesma entidade são vinculados)
- Habilitam investigação de entidade (ver todo o histórico de uma conta ou host)
- São a base para UEBA e Fusion
- Permitem que playbooks identifiquem automaticamente o alvo de uma ação

**Tipos de entidades disponíveis**:

| Entidade    | Campos típicos mapeados                              | Exemplo                                  |
|:------------|:-----------------------------------------------------|:-----------------------------------------|
| Account     | Name, UPNSuffix, ObjectGuid, SID                     | rafael.torres, @bancomeridian.com.br     |
| Host        | HostName, NetBiosName, FQDN, DnsDomain               | WKST-0042, bancomeridian.com.br          |
| IP          | Address                                              | 200.150.30.45                            |
| URL         | Url                                                  | https://malicious.example.com/payload    |
| FileHash    | Algorithm (MD5/SHA1/SHA256), Value                   | sha256:abc123...                         |
| Process     | ProcessId, CommandLine, ImageFile                    | powershell.exe -enc ...                  |
| CloudApp    | AppId, Name                                          | Office 365, Dropbox                      |
| Mailbox     | MailboxPrimaryAddress                                | rafael.torres@bancomeridian.com.br       |

---

## 3. Watchlists: Contextualização de Detecções

### 3.1 O que são Watchlists

Watchlists são listas de referência armazenadas no Sentinel que podem ser consultadas em KQL durante a execução de analytics rules. Permitem contextualizar alertas sem precisar hardcodar valores nas queries.

**Casos de uso no Banco Meridian**:

| Watchlist                    | Conteúdo                                                  | Uso                                               |
|:-----------------------------|:----------------------------------------------------------|:--------------------------------------------------|
| `ip-allowlist`               | IPs dos escritórios e filiais do banco                    | Suprimir alertas de "login de localização nova" de IPs conhecidos |
| `vip-users`                  | UPNs da diretoria e board                                 | Elevar severidade de alertas envolvendo VIPs      |
| `service-accounts`           | Contas de serviço não-humanas                             | Suprimir comportamentos esperados de automação    |
| `privileged-roles`           | Role IDs de admin global, security admin, etc.            | Detectar adição não autorizada de roles           |
| `known-c2-domains`           | Domínios de C2 de threat intel interna                   | Matching automático de DNS lookups suspeitos      |
| `frequent-travelers`         | Funcionários que viajam internacionalmente                | Suprimir impossible travel para esses usuários    |

### 3.2 Criando e Usando uma Watchlist

**Criação via CSV**:
```csv
UserPrincipalName,Department,Country
ceo@bancomeridian.com.br,Diretoria,BR
coo@bancomeridian.com.br,Diretoria,BR
ciso@bancomeridian.com.br,Segurança,BR
rafael.torres@bancomeridian.com.br,TI,BR
```

**Carregamento no Sentinel**:
```
Sentinel → Watchlists → New → 
  Name: vip-users
  Alias: vip-users (usado no KQL)
  CSV file: upload
  Search key: UserPrincipalName
```

**Uso em KQL**:
```kql
// Analytics rule que detecta login de VIP de país estrangeiro
// e escala severidade automaticamente

let vipUsers = _GetWatchlist('vip-users') | project UserPrincipalName;
let ipAllowlist = _GetWatchlist('ip-allowlist') | project IPAddress;

SigninLogs
| where TimeGenerated > ago(1h)
| where UserPrincipalName in (vipUsers)                    // Apenas VIPs
| where IPAddress !in (ipAllowlist)                        // De IP não-permitido
| where Location !contains "BR"                            // Fora do Brasil
| where ResultType == 0                                    // Login bem-sucedido
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          DeviceDetail, RiskLevelDuringSignIn
```

---

## 4. Threat Intelligence: Integração e IOC Matching

### 4.1 Fontes de Threat Intelligence no Sentinel

**TAXII Connector**: Conecta feeds de threat intelligence compatíveis com TAXII 2.0/2.1 (padrão STIX). Exemplos: AlienVault OTX, MISP, ThreatConnect, ISAC do setor bancário.

**Upload direto de IOCs via API**: Para feeds proprietários ou inteligência gerada internamente.

**Microsoft Threat Intelligence**: Integrado nativamente ao Sentinel — sem configuração. Inclui IOCs do MSTIC que são usados automaticamente em analytics rules do pacote Microsoft.

### 4.2 Configurando o TAXII Connector

```
Sentinel → Data connectors → Threat Intelligence - TAXII → Open connector page

Servidores de exemplo:
- AlienVault OTX: https://otx.alienvault.com/taxii/root
  Collection: adversary

- CISA AIS: https://ais2.cisa.gov/taxii2
  Collection: stix (requer cadastro)

- Financeiro BR (exemplo):
  URL: https://ti.febraban.org.br/taxii2  
  Collection: financial-sector
  Username: [credencial fornecida pelo FEBRABAN]
  Password: [credencial]
  Import interval: 1 hour
```

### 4.3 Analytics Rule de IOC Matching

Após configurar o TAXII connector, os IOCs chegam na tabela `ThreatIntelligenceIndicator`. Criar uma rule para matching automático:

```kql
// TI Matching: Detecta comunicação com IPs de C2 conhecidos
// MITRE ATT&CK: T1071 (Application Layer Protocol), T1041 (Exfil over C2)

let timeframe = 1h;
let lookback = 14d;

// Buscar IPs maliciosos do feed de TI ativos nos últimos 14 dias
let maliciousIPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(lookback)
| where Active == true
| where IndicatorType == "networktraffic" or IndicatorType == "domainname" or IndicatorType == "url"
| where NetworkIP != "" or NetworkDestinationIP != ""
| summarize by NetworkIP, NetworkDestinationIP, ThreatType, Description, ConfidenceScore;

// Correlacionar com logs de rede (CommonSecurityLog / DeviceNetworkEvents)
CommonSecurityLog
| where TimeGenerated > ago(timeframe)
| where DeviceAction !in ("deny", "drop", "block")    // Apenas tráfego permitido
| join kind=inner maliciousIPs on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP,
          DestinationPort, Protocol, DeviceAction,
          ThreatType, Description, ConfidenceScore
```

---

## 5. Automation Rules: Pré-Triagem Automática

### 5.1 Diferença entre Automation Rules e Playbooks

| Característica        | Automation Rule                            | Playbook (Logic App)                        |
|:----------------------|:-------------------------------------------|:--------------------------------------------|
| **Complexidade**      | Simples (condições e ações diretas)        | Complexo (fluxo lógico completo)            |
| **Execução**          | Instantânea, no Sentinel                   | Assíncrona, no Logic Apps engine            |
| **Ações disponíveis** | Assign, Change status, Add tag, Run playbook | Qualquer ação (Graph API, REST, SQL, etc.) |
| **Latência**          | Milissegundos                              | Segundos a minutos                          |
| **Caso de uso**       | Triagem, roteamento, supressão             | Resposta ativa, notificações, enriquecimento |

### 5.2 Cenários de Automation Rules para o Banco Meridian

```
AUTOMATION RULE 1: Triagem de Incidentes de Baixa Severidade
─────────────────────────────────────────────────────────────
Trigger: Incident created
Condition: Severity == Low AND Status == New
Actions:
  1. Assign to: SOC-L1-Triage (grupo de analistas L1)
  2. Add tags: ["auto-triaged", "L1-review"]
  3. Change status: Active (para aparecer na fila de trabalho)

AUTOMATION RULE 2: Escalar Incidentes de VIP Automaticamente
─────────────────────────────────────────────────────────────
Trigger: Incident created
Condition: Title contains "VIP" OR Tag contains "vip-user"
Actions:
  1. Change severity: High
  2. Assign to: SOC-L3-Senior
  3. Run playbook: Notify-CISO-Teams

AUTOMATION RULE 3: Suprimir Falso-Positivo Conhecido
─────────────────────────────────────────────────────
Trigger: Incident created
Condition: Alert provider == "Microsoft Defender for Endpoint"
           AND Title == "Test alert - Suspicious PowerShell"
Actions:
  1. Change status: Closed
  2. Classification: BenignPositive — Suspicious but expected
  3. Comment: "Suprimido automaticamente: teste de validação MDEThreatSimulator"
```

---

## 6. Analytics Rules Completas com KQL

### Rule 1 — Impossible Travel (Login de Dois Países em Menos de 1 Hora)

```kql
// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RULE: Impossible Travel
// Descrição: Detecta quando o mesmo usuário faz login em dois países
//            diferentes com intervalo menor que o tempo de viagem possível
// MITRE ATT&CK: T1078 (Valid Accounts) — Initial Access
// Tabela: SigninLogs
// Scheduling: Run every 30m | Lookback 1h
// Severity: High
// ═══════════════════════════════════════════════════════════════════

// Excluir contas de serviço e usuários frequentes viajantes
let excludedAccounts = _GetWatchlist('service-accounts') | project UserPrincipalName;
let frequentTravelers = _GetWatchlist('frequent-travelers') | project UserPrincipalName;

// Calcular logins por usuário na última 1h, agrupando por país
let recentLogins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0                                    // Apenas logins bem-sucedidos
| where UserPrincipalName !in (excludedAccounts)
| where UserPrincipalName !in (frequentTravelers)
| where isnotempty(Location)
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| where isnotempty(Country)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, 
          AppDisplayName, DeviceDetail, RiskLevelDuringSignIn;

// Auto-join para encontrar pares de logins do mesmo usuário em países diferentes
recentLogins
| join kind=inner (recentLogins) on UserPrincipalName
| where Country != Country1                                // Países diferentes
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) < 60  // Dentro de 1h
| where TimeGenerated > TimeGenerated1                     // Evitar duplicatas (A->B e B->A)
| extend
    TimeDiffMinutes = abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)),
    Login1_Time = TimeGenerated1,
    Login1_Country = Country1,
    Login1_IP = IPAddress1,
    Login2_Time = TimeGenerated,
    Login2_Country = Country,
    Login2_IP = IPAddress
| project
    UserPrincipalName,
    Login1_Time, Login1_Country, Login1_IP,
    Login2_Time, Login2_Country, Login2_IP,
    TimeDiffMinutes,
    AppDisplayName,
    RiskLevelDuringSignIn
| sort by TimeDiffMinutes asc
```

**Configurações da Rule**:
- Entity mapping: Account → UserPrincipalName; IP → Login2_IP
- Custom details: Login1_Country, Login2_Country, TimeDiffMinutes
- MITRE: Tactics: InitialAccess, Credential Access; Technique: T1078
- Alert grouping: Group by Account entity, 5 hours window

---

### Rule 2 — Password Spray via Entra ID Sign-in Logs

```kql
// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RULE: Password Spray Attack
// Descrição: Um único IP tenta autenticar em múltiplas contas com
//            falha, padrão típico de password spray (baixa taxa por conta)
// MITRE ATT&CK: T1110.003 (Password Spraying) — Credential Access
// Tabela: SigninLogs
// Scheduling: Run every 15m | Lookback 1h
// Severity: High
// ═══════════════════════════════════════════════════════════════════

let timeWindow = 1h;
let minAccounts = 10;           // Mínimo de contas tentadas do mesmo IP
let maxAttemptsPerAccount = 3;  // Password spray tenta poucas vezes por conta

SigninLogs
| where TimeGenerated > ago(timeWindow)
| where ResultType != 0                                    // Apenas falhas de autenticação
| where ResultDescription !contains "MFA"                 // Excluir falhas de MFA (diferente de spray)
| where isnotempty(IPAddress)
| where IPAddress !startswith "10."                       // Excluir IPs internos
| where IPAddress !startswith "192.168."
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 20),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    ErrorCodes = make_set(ResultType, 5),
    AppList = make_set(AppDisplayName, 5)
    by IPAddress, Location
| where UniqueAccounts >= minAccounts                      // IP tentou muitas contas diferentes
| where FailedAttempts / UniqueAccounts <= maxAttemptsPerAccount  // Poucas tentativas por conta
| extend
    AttackDurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt),
    AttemptsPerMinute = todouble(FailedAttempts) / max_of(datetime_diff('minute', LastAttempt, FirstAttempt), 1)
| sort by UniqueAccounts desc
```

**Configurações da Rule**:
- Entity mapping: IP → IPAddress
- Custom details: UniqueAccounts, AccountList, AttackDurationMinutes
- MITRE: Tactics: CredentialAccess; Technique: T1110.003
- Alert name format: `Password Spray from {{IPAddress}} — {{UniqueAccounts}} accounts targeted`
- Alert grouping: Group by IP entity, 2 hours window

---

### Rule 3 — Service Principal Adicionado a Role Privilegiada

```kql
// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RULE: Privileged Role Assignment to Service Principal
// Descrição: Uma service principal (conta de app) foi adicionada a
//            uma role de alto privilégio no Entra ID
//            Técnica usada em ataques de escalada via OAuth/App Registration
// MITRE ATT&CK: T1098 (Account Manipulation), T1548 (Abuse Elevation)
//               Persistence, PrivilegeEscalation
// Tabela: AuditLogs
// Scheduling: Run every 5m | Lookback 15m (NRT candidate)
// Severity: High
// ═══════════════════════════════════════════════════════════════════

// Roles privilegiadas que devem ser monitoradas
let privilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Account Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Privileged Authentication Administrator",
    "Authentication Administrator"
]);

AuditLogs
| where TimeGenerated > ago(15m)
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
// Extrair detalhes do target resource
| extend
    TargetType = tostring(TargetResources[0].type),
    TargetDisplayName = tostring(TargetResources[0].displayName),
    TargetId = tostring(TargetResources[0].id)
// Apenas service principals (não usuários humanos)
| where TargetType == "ServicePrincipal"
// Extrair o nome da role da propriedade modificada
| extend
    RoleName = tostring(parse_json(tostring(TargetResources[1].modifiedProperties))[0].newValue),
    InitiatorUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName),
    InitiatorIP = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where RoleName has_any (privilegedRoles)
| project
    TimeGenerated,
    OperationName,
    InitiatorUPN,
    InitiatorIP,
    TargetDisplayName,          // Nome da service principal
    TargetId,                    // Object ID da service principal
    RoleName,                    // Role atribuída
    CorrelationId
```

**Configurações da Rule**:
- Entity mapping: Account (Initiator) → InitiatorUPN; Account (Target SP) → TargetDisplayName; IP → InitiatorIP
- Custom details: RoleName, TargetId
- MITRE: Tactics: Persistence, PrivilegeEscalation; Techniques: T1098, T1548
- Alert grouping: Disabled (cada evento é único e deve gerar incidente separado)

---

### Rule 4 — Token Theft / AiTM Phishing Pattern

```kql
// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RULE: AiTM Token Theft Pattern
// Descrição: Detecta padrão de roubo de token OAuth via Adversary-in-the-Middle
//            Sinais: (1) Login com token sem MFA claim após sessão com MFA
//            (2) Login de novo IP/Country com mesma sessão
//            (3) Ausência de DeviceId registrado no token
// MITRE ATT&CK: T1557 (AiTM), T1539 (Steal Web Session Cookie)
//               InitialAccess, CredentialAccess
// Tabela: SigninLogs
// Scheduling: Run every 30m | Lookback 2h
// Severity: High
// ═══════════════════════════════════════════════════════════════════

SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0                                    // Login bem-sucedido
// Indicadores de AiTM:
// 1. SessionId presente mas DeviceId ausente ou genérico
// 2. AuthenticationRequirement == "singleFactorAuthentication" 
//    mas token tem claim de sessão anterior com MFA
// 3. Token issued sem MFA mesmo sendo conta com CA policy de MFA
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ConditionalAccessStatus == "success"               // CA passou (bypass de MFA)
// Verificar se a conta tem histórico de MFA (se sim, este é suspeito)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize LastMFALogin = max(TimeGenerated) by UserPrincipalName
) on UserPrincipalName
// Usuário tem histórico de MFA mas logou sem MFA
| where isnotempty(LastMFALogin)
// Verificar se é de IP/Location incomum
| extend
    DeviceId = tostring(parse_json(tostring(DeviceDetail)).deviceId),
    IsCompliant = tostring(parse_json(tostring(DeviceDetail)).isCompliant),
    Browser = tostring(parse_json(tostring(DeviceDetail)).browser),
    OS = tostring(parse_json(tostring(DeviceDetail)).operatingSystem)
// Flag: device ID vazio (cookie roubado, sem device registrado)
| where isempty(DeviceId) or DeviceId == "00000000-0000-0000-0000-000000000000"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    Browser, OS,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskState,
    LastMFALogin,
    SessionContext = tostring(AADTenantId)
```

**Configurações da Rule**:
- Entity mapping: Account → UserPrincipalName; IP → IPAddress
- Custom details: LastMFALogin, Browser, OS, AuthenticationRequirement
- MITRE: Tactics: InitialAccess, CredentialAccess; Techniques: T1557, T1539
- Alert name: `Possible AiTM Token Theft — {{UserPrincipalName}} — No MFA Device`
- Severity: High

---

### Rule 5 — Exfiltração de Dados via SharePoint Incomum

```kql
// ═══════════════════════════════════════════════════════════════════
// ANALYTICS RULE: Anomalous SharePoint/OneDrive Data Exfiltration
// Descrição: Usuário baixa volume incomum de arquivos do SharePoint/OneDrive
//            em período curto, comparado com sua baseline de 30 dias
// MITRE ATT&CK: T1530 (Data from Cloud Storage) — Exfiltration
// Tabela: OfficeActivity
// Scheduling: Run every 1h | Lookback 1h
// Severity: Medium → High (se >10x baseline)
// ═══════════════════════════════════════════════════════════════════

// Calcular baseline de downloads por usuário nos últimos 30 dias
let baseline = OfficeActivity
| where TimeGenerated between (ago(30d) .. ago(1h))
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| where RecordType in ("SharePointFileOperation", "OneDrive")
| summarize
    BaselineDownloads = count(),
    AvgDailyDownloads = count() / 30.0,
    BaselineSites = dcount(SiteUrl)
    by UserId;

// Calcular downloads na última hora
let recentActivity = OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| where RecordType in ("SharePointFileOperation", "OneDrive")
| summarize
    RecentDownloads = count(),
    UniqueSites = dcount(SiteUrl),
    UniqueFiles = dcount(SourceFileName),
    SiteList = make_set(SiteUrl, 10),
    FileList = make_set(SourceFileName, 20),
    IPs = make_set(ClientIP, 5)
    by UserId;

// Comparar com baseline — alertar quando >5x a média diária numa hora
recentActivity
| join kind=leftouter baseline on UserId
| extend
    AvgDailyDownloads = coalesce(AvgDailyDownloads, 0.0),
    BaselineDownloads = coalesce(BaselineDownloads, 0)
| where AvgDailyDownloads > 0                              // Apenas usuários com histórico
| extend Multiplier = RecentDownloads / max_of(AvgDailyDownloads, 1.0)
| where Multiplier >= 5                                    // 5x ou mais que a média diária
| extend Severity = case(
    Multiplier >= 20, "High",
    Multiplier >= 10, "Medium",
    "Low"
)
| project
    UserId,
    RecentDownloads,
    AvgDailyDownloads = round(AvgDailyDownloads, 1),
    Multiplier = round(Multiplier, 1),
    UniqueSites,
    UniqueFiles,
    SiteList,
    IPs,
    Severity
| sort by Multiplier desc
```

**Configurações da Rule**:
- Entity mapping: Account → UserId
- Custom details: RecentDownloads, Multiplier, SiteList, Severity
- MITRE: Tactics: Exfiltration, Collection; Technique: T1530
- Alert name: `Anomalous SharePoint Download — {{UserId}} — {{Multiplier}}x Baseline`

---

## 7. Atividades de Fixação

### Questão 1
Para detectar um brute force ativo com alta taxa de tentativas (>10/segundo), qual tipo de analytics rule é mais adequado?

a) Scheduled (run every 1h)  
b) NRT (Near Real-Time) com lookback de 5 minutos  
c) Fusion (ML automático)  
d) Anomaly (UEBA diária)  

**Gabarito: B** — NRT executa aproximadamente a cada minuto, com latência total de ~1-2 minutos desde o evento. Para um brute force ativo onde cada segundo conta (o atacante pode comprometer a conta em minutos), a detecção precisa ser quase em tempo real. A rule Scheduled (opção A) teria latência de até 1h. Fusion (C) e Anomaly/UEBA (D) não são configuráveis pelo usuário e têm latência de horas/dias.

---

### Questão 2
Uma analytics rule Scheduled tem configuração "Run every 1 hour, Lookup data from last 1 hour". Se a query detecta uma conta comprometida às 14h37, quando o alerta será gerado?

a) Imediatamente às 14h37  
b) Na próxima execução agendada, que pode ser às 15h00 (até 23 minutos de atraso)  
c) Às 15h37 (1 hora após o evento)  
d) O alerta não é gerado porque a janela de lookback de 1h não cobre eventos passados  

**Gabarito: B** — Rules Scheduled executam em intervalos fixos definidos pelo "Run every". Se a rule está agendada para rodar a cada hora (ex.: 14h00, 15h00, 16h00...) e o evento ocorreu às 14h37, o próximo disparo será às 15h00. Nessa execução, o lookback de 1h vai de 14h00 a 15h00, cobrindo o evento das 14h37. A latência máxima para "Run every 1h" é ~1h (evento ocorreu logo após a execução anterior). Para reduzir latência, usar "Run every 15min" com lookback de 15min + 5min de buffer.

---

### Questão 3
Uma watchlist chamada `service-accounts` foi criada com os UPNs das contas de serviço do banco. Qual KQL correto para excluir essas contas de uma analytics rule?

a) `| where UserPrincipalName !in (service-accounts)`  
b) `| where UserPrincipalName !in (_GetWatchlist('service-accounts') | project UserPrincipalName)`  
c) `| where Watchlist['service-accounts'] != UserPrincipalName`  
d) `| join kind=anti (WatchlistItems | where WatchlistAlias == 'service-accounts') on UserPrincipalName`  

**Gabarito: B** — A função `_GetWatchlist('alias')` retorna os itens da watchlist como uma tabela KQL. O operador `!in` verifica se o valor não está presente na lista. A combinação `!in (_GetWatchlist('nome') | project campo)` é o padrão idiomático correto. A opção A incorreta (sem aspas e sem _GetWatchlist). A opção C usa sintaxe inválida. A opção D é tecnicamente funcional mas verbosa e propensa a erros.

---

### Questão 4
Entity mapping foi configurado numa analytics rule com "Account" mapeado para o campo `UserPrincipalName` da query. Qual é o benefício imediato desta configuração?

a) O alerta será enviado por e-mail ao usuário identificado automaticamente  
b) O campo UserPrincipalName passará a aparecer em negrito na query  
c) O Sentinel criará um link entre este incidente e outros incidentes que envolvem a mesma conta, habilitando investigação de entidade e correlação automática  
d) O usuário será bloqueado automaticamente pelo Entra ID Protection  

**Gabarito: C** — Entity mapping transforma um campo de texto numa entidade estruturada reconhecida pelo Sentinel. Com a entidade Account mapeada, o Sentinel: (1) vincula automaticamente incidentes que compartilham a mesma conta; (2) permite navegar para o painel de investigação da entidade (histórico de atividade, score de risco, outros incidentes); (3) habilita a UEBA a correlacionar comportamento; (4) permite que playbooks e automation rules usem a entidade como condição (ex.: "se o incidente tem entidade Account de alta severidade"). Não envia e-mail (A) nem bloqueia o usuário automaticamente (D).

---

### Questão 5
O Banco Meridian tem uma automation rule para fechar automaticamente incidentes com título "Test Alert". Um atacante cria uma analytics rule com título "Test Alert" que detecta seus próprios acessos maliciosos. O que acontece?

a) A automation rule fecha os incidentes maliciosos, efetivamente ocultando o ataque — vulnerabilidade de supressão  
b) O Sentinel detecta a intenção maliciosa e bloqueia a automation rule  
c) Nada — automation rules não interagem com analytics rules de usuário  
d) Os incidentes são fechados mas aparecem em um relatório separado de "auto-closed"  

**Gabarito: A** — Este é um exemplo de uma vulnerabilidade real em lógicas de supressão mal projetadas. Automation rules que suprimem baseadas apenas no título do alerta podem ser abusadas se um atacante ganhar acesso para criar analytics rules. A boa prática é usar condições mais específicas (combinação de título + analytics rule ID + produto) e revisar periodicamente automation rules de supressão. Automation rules de supressão devem ser usadas com critério e auditadas regularmente.

---

## 8. Roteiros de Gravação

### Aula 4.1 — Tipos de Rules e Analytics Rules Scheduled (50 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Ambiente: workspace com pelo menos 7 dias de dados de SigninLogs
- Preparar: 2 analytics rules pré-configuradas para demonstrar (não ativar antes da gravação)
- Ter aberto em abas: portal Sentinel, editor KQL, MITRE ATT&CK matrix

---

**[0:00 — ABERTURA | 3 minutos]**

"Chegamos ao momento mais empolgante do curso — Detection Engineering. Aqui a teoria encontra a prática real. Vamos transformar queries KQL em detecções automáticas que protegem o Banco Meridian 24 horas por dia.

Este módulo é onde a maioria dos analistas SOC passa a maior parte do tempo. E quando feito bem, é o que faz a diferença entre detectar um ataque em minutos versus em dias."

---

**[3:00 — BLOCO 1: TIPOS DE RULES | 12 minutos]**

*[Slide: tabela de tipos de rules]*

"Existem 5 tipos de analytics rules no Sentinel. Preciso que vocês entendam cada um porque a escolha errada significa ou latência alta demais ou limitações técnicas que impedem a detecção.

O tipo mais comum é a Scheduled. Ela executa uma query KQL em intervalos regulares — de 5 minutos a 14 dias. A maioria das nossas detecções será Scheduled porque permite queries complexas com joins, agregações, e janelas de tempo longas.

O NRT é o Near Real-Time. Executa aproximadamente a cada minuto. Para ameaças que exigem contenção imediata — malware rodando, conta sendo bloqueada por brute force em andamento. Mas tem limitações: não suporta `join`, não suporta lookback maior que 10 minutos.

O Fusion é o motor de ML da Microsoft. Não configuramos — a Microsoft mantém. Ele correlaciona automaticamente alertas de baixa fidelidade em incidentes de alta fidelidade. Para ver o Fusion funcionando, olhem em Analytics → Active rules → Fusion.

O UEBA analisa comportamento. Funciona por exclusão — aprende o que é normal e alerta quando algo foge do padrão. Precisa de 14 dias de baseline para ser eficaz.

*[Screen share: Sentinel → Analytics]*

Vou para o Sentinel agora. Em Analytics, vejo três abas: Active rules (rules em execução), Rule templates (templates do Content Hub), e Anomalies (UEBA).

Clico em 'Create' → 'Scheduled query rule'. Aqui está a interface completa que vamos usar na maior parte do módulo."

---

**[15:00 — BLOCO 2: CRIANDO A RULE DE IMPOSSIBLE TRAVEL | 20 minutos]**

*[Screen share: criação da rule no portal]*

"Vou criar a primeira rule — Impossible Travel. Este é um padrão clássico de conta comprometida: o usuário faz login em São Paulo às 14h e em Moscou às 14h45. Fisicamente impossível.

**Step 1: General settings**

Nome: `Banco Meridian - Impossible Travel - Login de Dois Países em 1h`

Descrição: `Detecta quando o mesmo usuário autentica com sucesso em dois países diferentes com intervalo menor que 1 hora, indicando possível roubo de credencial ou uso de VPN/proxy.`

Tactics: Initial Access, Credential Access
Techniques: T1078 (Valid Accounts)
Severity: High

**Step 2: Rule query**

*[Colar a query da documentação e explicar linha a linha]*

```kql
let excludedAccounts = _GetWatchlist('service-accounts') | project UserPrincipalName;
let frequentTravelers = _GetWatchlist('frequent-travelers') | project UserPrincipalName;

let recentLogins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
...
```

Linha 1: busco a watchlist de contas de serviço. Não quero que um job automatizado que roda de dois servidores em países diferentes gere falso positivo.

Linha 2: a watchlist de viajantes frequentes. O VP de vendas que viaja todo mês para Argentina não deve gerar alerta cada vez que vai.

Linha 5: o auto-join — a parte mais elegante da query. Faço um join da tabela com ela mesma pelo UserPrincipalName, buscando logins do mesmo usuário em países diferentes.

*[DICA DE EDIÇÃO: zoom na query, seta animada mostrando o self-join]*

**Step 3: Entity mapping**

Account → UserPrincipalName. Isso vai linkar este incidente a outros incidentes que envolvem o mesmo usuário.
IP → Login2_IP (o IP do segundo login, que é o suspeito).

**Step 4: Scheduling**

Run every: 30 minutes
Lookback: 1 hour + 10min buffer = 1h10min (para cobrir latência de ingestão)

**Step 5: Alert grouping**

Agrupar por entidade Account, janela de 5 horas. Isso evita que o mesmo usuário sob ataque gere dezenas de incidentes em sequência — eles são agrupados em um único incidente.

Review + Create.

*[Verificar que a rule foi criada e está ativa]*

A rule está ativa. Em 30 minutos, ela executará pela primeira vez. Se houver um impossible travel nos últimos 30 minutos no tenant, um incidente será criado."

---

**[35:00 — BLOCO 3: WATCHLISTS NA PRÁTICA | 10 minutos]**

"Antes de criar a segunda rule, vou criar as watchlists que ela precisa.

*[Screen share: Sentinel → Watchlists → New]*

Watchlist: `service-accounts`
- Alias: service-accounts (nome usado no KQL)
- CSV file:

```csv
UserPrincipalName,ServiceType,Owner
svc-backup@bancomeridian.com.br,Backup,TI
svc-monitoring@bancomeridian.com.br,Monitoring,TI
svc-etl@bancomeridian.com.br,ETL,Data
```

Search key: UserPrincipalName

Crio também a `frequent-travelers` com os viajantes.

Agora, vou mostrar como testar a watchlist no editor KQL antes de usar em uma rule:

```kql
_GetWatchlist('service-accounts')
| project UserPrincipalName, ServiceType
```

Perfeito — retorna os dados como uma tabela KQL. Posso usar em joins e filtros."

---

**[45:00 — ENCERRAMENTO | 5 minutos]**

"Criamos nossa primeira analytics rule completa — com entidade mapeada, watchlist, scheduling e MITRE tagging. Na próxima aula, vamos criar mais 4 rules cobrindo password spray, token theft, privilégio escalado e exfiltração.

Antes da próxima aula, leiam a seção sobre NRT no repositório — vamos criar uma NRT rule na próxima sessão."

---

### Aula 4.2 — NRT, Fusion, Entity Mapping Avançado e Watchlists (50 minutos)

---

**[0:00 — ABERTURA | 2 minutos]**

"Na última aula criamos nossa primeira Scheduled rule. Hoje vamos completar o catálogo — NRT rule para password spray, a rule de privilege escalation com service principal, e vamos mergulhar fundo em entity mapping e como ele transforma a capacidade de investigação do SOC."

---

**[2:00 — BLOCO 1: NRT — PASSWORD SPRAY | 15 minutos]**

*[Screen share: criar NRT rule]*

"Analytics → Create → NRT query rule.

Por que NRT para password spray? Porque um spray ativo pode comprometer uma conta em 5-10 minutos. Se minha rule roda a cada hora, chego tarde demais.

*[Explicar a query de password spray linha a linha]*

O truque desta query é o ratio: `FailedAttempts / UniqueAccounts`. Em um brute force tradicional, o atacante foca em uma conta — ratio alto por conta. Em password spray, o atacante tenta a mesma senha em muitas contas — ratio baixo por conta, mas muitas contas tentadas.

**Limitação do NRT que precisa respeitar**: não posso usar `join`. Então a query é mais simples que a Scheduled. Sem correlação com baseline, sem watchlist join. Compenso com thresholds conservadores.

*[Criar e salvar a rule]*"

---

**[17:00 — BLOCO 2: ENTITY MAPPING AVANÇADO | 18 minutos]**

*[Screen share: editar uma rule existente para mostrar entity mapping]*

"Vou abrir a rule de Impossible Travel que criamos na última aula e mostrar o entity mapping em detalhe.

*[Abrir a rule em edição → Rule logic → Entity mapping]*

Aqui estão as entidades disponíveis: Account, Host, IP, URL, FileHash, Process, CloudApp, Mailbox.

Para uma rule de login suspeito, mapeio:
- Account: UserPrincipalName (o usuário)
- IP: IPAddress (o IP suspeito)

Mas posso mapear múltiplas entidades. Para a rule de exfiltração do SharePoint:
- Account: UserId
- URL: SiteUrl (o site do SharePoint acessado)

Agora, por que entity mapping importa para investigação? Vou demonstrar.

*[Abrir um incidente → Entity section]*

No incidente, vejo as entidades. Clico no usuário `rafael.torres@bancomeridian.com.br`. Abre o painel de investigação de entidade: todos os incidentes nos últimos 180 dias envolvendo esse usuário, timeline de atividade, score de risco, alertas relacionados.

*[DICA DE EDIÇÃO: gravação em tela cheia neste momento — é um momento de 'wow' para o aluno]*

Sem entity mapping, esse usuário seria apenas uma string numa tabela. Com entity mapping, ele é um objeto investigável com todo o contexto histórico."

---

**[35:00 — BLOCO 3: AUTOMATION RULES | 12 minutos]**

*[Screen share: Sentinel → Automation]*

"Automation rules são o primeiro nível de resposta automática — simples, mas poderosas para triagem.

Vou criar uma automation rule para o Banco Meridian que:
1. Quando um incidente High é criado
2. Com a entidade Account
3. Automaticamente assign para o grupo SOC-L3-Senior

*[Criar automation rule no portal]*

New automation rule → nome: `Escalate-High-Severity-Account-Incidents`

Trigger: When incident is created
Conditions: 
- Incident severity → Equals → High
- Incident contains entities → Account

Actions:
- Assign owner: SOC-L3-Senior
- Add tags: high-priority, account-incident
- Change status: Active

Create.

Esta rule simples economiza decisões manuais de triagem — todo incidente High com conta vai direto para L3 sem passar pela fila de L1."

---

**[47:00 — ENCERRAMENTO | 3 minutos]**

"Completamos o módulo de Detection Engineering. Criamos 5 analytics rules cobrindo os principais vetores de ataque para o Banco Meridian, aprendemos a usar watchlists para reduzir falso-positivos, configuramos entity mapping para facilitar investigação, e criamos automation rules para triagem automática.

No Lab 03, vocês vão replicar exatamente essas 5 rules no ambiente de vocês e testar cada uma. O gabarito está no repositório com as queries completas.

Na sessão live, vamos revisar as rules que vocês criaram, discutir edge cases e ajustar thresholds."

---

## 9. Avaliação do Módulo

**Q1.** Uma analytics rule NRT tem qual limitação que a impede de detectar impossible travel (login em dois países diferentes com join na mesma tabela)?

a) NRT não suporta a tabela SigninLogs  
b) NRT não suporta operações de `join` e tem lookback máximo de 10 minutos  
c) NRT não suporta entity mapping  
d) NRT só funciona com dados do MDE  

**Resposta: B** — Regras NRT têm restrições técnicas para garantir que executem em menos de 1 minuto: não suportam `join` (que pode ser computacionalmente custoso), `union` complexo, ou lookback maior que 10 minutos. A detecção de impossible travel requer um self-join da tabela SigninLogs, portanto deve ser implementada como Scheduled rule (mesmo com latência maior de 30min é aceitável para o caso de uso).

---

**Q2.** O alert grouping de uma analytics rule está configurado como "Group all events into a single alert". Para um password spray que atinge 50 contas, isso significa que:

a) 50 alertas serão gerados, um por conta atingida  
b) Nenhum alerta será gerado — apenas quando o número exceder 50 alertas  
c) Um único alerta será gerado contendo os dados de todas as 50 contas tentadas  
d) O alert grouping não afeta o número de alertas, apenas a severidade  

**Resposta: C** — "Group all events into a single alert" significa que todos os resultados da query em uma execução são consolidados em UM único alerta. Isso é ideal para o password spray: a query retorna 50 linhas (uma por conta tentada) mas gera apenas 1 alerta com todos os dados. A alternativa "One alert per row" geraria 50 alertas, o que pode criar ruído desnecessário para o analista. Use "Group all" quando os resultados são faces do mesmo ataque; use "Per row" quando cada resultado é um incidente independente.

---

**Q3.** Qual é a função KQL correta para consultar uma watchlist chamada `vip-users` e obter o campo `UserPrincipalName`?

a) `Watchlist('vip-users') | project UserPrincipalName`  
b) `_GetWatchlist('vip-users') | project UserPrincipalName`  
c) `WatchlistItems | where Alias == 'vip-users' | project UserPrincipalName`  
d) `Sentinel.Watchlist['vip-users'].UserPrincipalName`  

**Resposta: B** — A função built-in `_GetWatchlist('alias')` é a forma nativa de consultar watchlists em KQL no Sentinel. Retorna uma tabela com todas as colunas do CSV importado. O alias é o nome curto definido na criação da watchlist. As outras opções usam sintaxe inválida.

---

**Q4.** Por que a analytics rule de Password Spray usa `FailedAttempts / UniqueAccounts <= 3` como critério adicional além de `UniqueAccounts >= 10`?

a) Para garantir que apenas tentativas de dentro da rede corporativa sejam detectadas  
b) Para diferenciar password spray (poucas tentativas por conta, muitas contas) de brute force tradicional (muitas tentativas em uma conta), evitando confundir as duas técnicas  
c) Porque o Sentinel tem um limite máximo de 3 eventos por regra  
d) Para calcular a probabilidade de sucesso do atacante  

**Resposta: B** — Password spray (T1110.003) é caracterizado por tentar uma (ou poucas) senha(s) em muitas contas — evita o bloqueio por tentativas excessivas numa única conta. Brute force (T1110.001) tenta muitas senhas em poucas contas. O critério `FailedAttempts / UniqueAccounts <= 3` garante que a média de tentativas por conta seja baixa (spray), enquanto `UniqueAccounts >= 10` garante que sejam muitas contas (spray). Um brute force de uma conta com 200 tentativas teria ratio de 200/1 = 200, muito acima de 3, e não dispararia esta rule.

---

**Q5.** O Fusion detectou um incidente: "Multi-stage attack: Phishing → Credential Theft → Lateral Movement". O analista não configurou nenhuma rule específica para Fusion. Isso é esperado?

a) Não — o Fusion deve ser configurado manualmente pelo analista para cada padrão  
b) Sim — o Fusion é um motor de ML mantido pela Microsoft que correlaciona alertas automaticamente sem configuração do usuário  
c) Não — o Fusion requer ativação de todas as analytics rules do Content Hub primeiro  
d) Sim, mas o incidente Fusion substitui os incidentes individuais dos alertas base  

**Resposta: B** — O Fusion é um recurso gerenciado pela Microsoft no Sentinel. Os modelos de ML são atualizados automaticamente. O usuário precisa apenas: (1) ter o Fusion habilitado (Analytics → Active rules → Fusion → está habilitado por padrão); (2) ter as fontes de dados conectadas (Entra ID, MDE, MDO, etc.). O Fusion correlaciona os alertas gerados por essas fontes automaticamente, sem necessidade de criar queries ou rules específicas para os padrões de ataque.
