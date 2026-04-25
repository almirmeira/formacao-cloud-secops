# Módulo 09 — Threat Hunting Proativo no Microsoft Sentinel

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 3 horas (1h videoaula + 1h laboratório + 1h live online)                    |
| **Formato**              | 1 aula gravada + Lab prático + sessão live de hunting session               |
| **Pré-requisito**        | Módulos 01–08 concluídos; KQL intermediário                                 |
| **Certificação Alvo**    | SC-200 — Domínio 3: Perform hunting and investigations                      |
| **Cenário**              | Banco Meridian — proAtivamente caçando TTPs antes que gerem alertas         |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Diferenciar threat hunting reativo (alertas) de proativo (hipóteses) no Sentinel
2. Criar hipóteses de hunting baseadas em MITRE ATT&CK, threat reports e inteligência interna
3. Criar, salvar e compartilhar hunting queries no Sentinel
4. Usar bookmarks para preservar evidências durante a investigação
5. Usar Livestream para monitoramento em tempo real de uma hipótese
6. Criar notebooks Jupyter no Sentinel para análise avançada com Python

---

## 1. Reactive vs Proactive: A Diferença Filosófica

### 1.1 Abordagem Reativa (Alert-Driven)

Na abordagem reativa, o analista **espera o alerta**:

```
EVENTO OCORRE → ANALYTICS RULE DETECTA → ALERTA GERADO → INCIDENTE CRIADO → ANALISTA INVESTIGA
```

**Problema**: O alert-driven por definição chega depois do fato. Uma analytics rule detecta o que você configurou para detectar. Um atacante sofisticado que usa técnicas não cobertas pelas suas rules passa despercebido por dias, semanas ou meses (dwell time).

**O dwell time médio global (MTDM — Mean Time to Detect via alerts) é de 16-24 dias** segundo relatórios como o Mandiant M-Trends. Isso significa que em média, um atacante fica 16-24 dias no ambiente antes de ser detectado pelas analytics rules.

### 1.2 Abordagem Proativa (Hypothesis-Driven)

No threat hunting proativo, o analista **parte de uma hipótese**:

```
HIPÓTESE → QUERY DE HUNTING → ANÁLISE DE RESULTADOS → EVIDÊNCIAS (Bookmarks) → NOVA DETECÇÃO OU INCIDENTE
```

Exemplo de hipótese: "O Banco Meridian pode ter contas de serviço com Kerberoasting vulnerability que um attacker está explorando sem que tenhamos detection para isso"

O analista cria queries específicas para testar essa hipótese, analisa os resultados, e se encontrar evidências, ou:
- Cria um novo incidente e inicia resposta
- Cria uma nova analytics rule para detectar automaticamente o padrão encontrado

### 1.3 O Framework de Hunting

```
1. INTEL → Qual ameaça é relevante para bancos brasileiros agora?
   - Threat reports: Mandiant, CrowdStrike Intelligence, MSTIC
   - ISACs: FS-ISAC (Financial Services), FEBRABAN
   - IOCs recentes: IPs, domínios, hashes de campanhas ativas

2. HIPÓTESE → Formulação específica e testável
   - "O GRUPO APT-XX usa PowerShell encoded commands para LOLBins"
   - "Há exfiltração de dados via DNS tunneling nos logs do Fortinet"
   - "Service accounts estão sendo usadas fora do horário normal"

3. QUERY → KQL que busca evidências da hipótese
   - Baseada em TTPs MITRE específicas
   - Usa dados disponíveis no workspace

4. ANÁLISE → Revisão cuidadosa dos resultados
   - Distinguir ruído de sinal
   - Comparar com baseline normal
   - Correlacionar com outros logs

5. RESPOSTA → O que fazer com o que encontramos?
   - True Positive: abrir incidente, responder
   - False Positive: ajustar hipótese ou query
   - New Detection: criar analytics rule
   - No evidence: documentar hipótese testada
```

---

## 2. Hunting Queries no Sentinel

### 2.1 Interface de Hunting

```
Sentinel → Threat management → Hunting

Interface: 3 abas
├── Queries: todas as queries disponíveis (built-in + custom)
├── Bookmarks: evidências marcadas durante hunting
└── Livestream: monitoramento em tempo real
```

### 2.2 Criando e Salvando uma Hunting Query

Salvar uma hunting query no Sentinel é um passo fundamental que transforma a investigação individual numa capacidade coletiva da equipe. Quando uma query é salva com nome descritivo, tags MITRE e mapeamento de entidades, qualquer analista do SOC pode reproduzi-la durante uma investigação futura. Hunting queries bem documentadas também são o ponto de partida para criar Analytics Rules — se a query encontrou algo valioso desta vez, provavelmente encontrará novamente.

**O que configurar em cada campo e por quê:**
- **Name:** Use um prefixo como "Hunting -" para distinguir de analytics rules. Inclua a TTP ou o comportamento buscado.
- **Description:** Explique a hipótese que a query testa, não apenas o que ela faz tecnicamente. Exemplo: "Busca logins de contas de serviço fora do horário, assumindo que service accounts legítimas só operam em horário comercial — a exceção pode indicar uso de credenciais roubadas."
- **MITRE ATT&CK:** Necessário para que a query apareça filtrada por tática/técnica na interface de hunting. Facilita encontrar todas as queries relacionadas a uma Tática específica durante uma investigação guiada por MITRE.
- **Entity mappings:** Permitem que resultados da query sejam vinculados automaticamente a entidades (usuários, hosts, IPs) no gráfico de incidente do Sentinel.

```
Sentinel → Hunting → Queries → New query

Campos:
  Name: "Hunting - Service Account Activity Outside Business Hours"
  Description: "Detecta contas de serviço com atividade fora do horário 8h-19h BRT"
  Custom query: [KQL]
  
  MITRE ATT&CK:
    Tactics: Discovery, Credential Access
    Techniques: T1078.001 (Valid Accounts: Default Accounts)
  
  Entity mappings: Account → UPN
  
Save
```

### 2.3 Bookmarks: Preservando Evidências

Quando uma hunting query retorna resultados suspeitos, o analista pode criar um **Bookmark** para preservar a evidência:

```
Resultado da query → Selecionar linha(s) suspeita(s) → Add bookmark

Campos do bookmark:
  Bookmark name: "Conta svc-etl logando às 3h47 de IP externo"
  Notes: "Login incomum de conta de serviço. IP 200.150.30.45 - verificar no VirusTotal"
  Tags: hunting, service-account, suspicious-login
  MITRE: T1078.001
  
→ Criar incidente a partir do bookmark: "Criar incidente de investigação"
```

Bookmarks ficam armazenados na aba "Bookmarks" do Hunting e podem ser vinculados a incidentes. Eles são a ponte entre uma descoberta de hunting e um incidente formal de resposta.

### 2.4 Livestream: Monitoramento em Tempo Real

O Livestream executa uma query continuamente e notifica quando novos resultados aparecem. Útil quando:
- Você identificou um padrão de ataque em andamento e quer monitorar em tempo real
- Está testando uma nova analytics rule antes de ativá-la formalmente
- Quer ser notificado imediatamente quando uma condição específica ocorrer

```
Sentinel → Hunting → Queries → [selecionar query] → Add to Livestream

O Livestream fica ativo na aba "Livestream" e notifica quando a query
tem novos resultados. Latência: ~1 minuto (similar ao NRT rule).
```

---

## 3. Notebooks Jupyter no Sentinel

### 3.1 Para que Servem os Notebooks

Os **Notebooks Jupyter** no Sentinel permitem análise avançada usando Python, pandas e bibliotecas especializadas em segurança. São ideais para:

- Análise de grandes volumes de dados que excedem o que o KQL resolve elegantemente
- Visualizações avançadas (grafos de relacionamento, heatmaps de atividade)
- Machine learning customizado (clustering de IPs suspeitos, anomalia detection)
- Análise de threat intelligence (MISP, STIX, TAXII integration)
- Correlação com dados externos (OSINT, threat feeds)

**Quando um Notebook Jupyter é mais adequado que uma query KQL:** O KQL é excelente para queries estruturadas, filtros e agregações. Mas para análises que exigem estatística avançada (zscore, distribuições, correlações), aprendizado de máquina não supervisionado (clustering para encontrar usuários comportamentalmente similares e identificar outliers), ou visualizações complexas (gráficos de rede mostrando caminhos de lateral movement), Python + pandas é a ferramenta certa. No Banco Meridian, o Notebook é usado para análises mensais de baseline — uma vez identificada a baseline, as detecções baseadas nela são implementadas como Analytics Rules KQL.

> **⚠️ Atenção:** Notebooks Jupyter no Sentinel requerem autenticação com uma conta que tenha permissão de leitura no workspace. Para investigações sensíveis (insider threat, investigação de executivos), use uma conta de serviço dedicada com acesso apenas ao período relevante, para manter a cadeia de custódia e evitar que um notebook acidentalmente sobrescreva dados.

### 3.2 MSTIC Libraries

A Microsoft Threat Intelligence Center (MSTIC) mantém bibliotecas Python open source para Sentinel:

| Biblioteca         | Função                                                                    |
|:-------------------|:--------------------------------------------------------------------------|
| `msticpy`          | Core library — conecta ao workspace, faz queries, análise de TI          |
| `msticnb`          | Notebooks prontos para investigação de identidade, rede, host            |
| `msticpy.analysis` | ML: anomalia detection, clustering, entity graph                         |

### 3.3 Exemplo de Notebook Python para Hunting

```python
# Hunting Notebook: Anomalia de Login por Hora
# Objetivo: Identificar usuários com atividade de login anômala
# usando zscore para detectar desvios da baseline

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy import stats
import msticpy as mp

# Conectar ao workspace Sentinel
mp.init_notebook(namespace=globals())
ws_config = mp.WorkspaceConfig(workspace="meridian-secops-prod")
qry_prov = mp.QueryProvider("AzureSentinel", workspace=ws_config)
qry_prov.connect(connection_str=ws_config.code_connect_str)

# Query KQL via Python
signin_data = qry_prov.exec_query("""
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| extend Hour = hourofday(TimeGenerated)
| summarize LoginCount = count() by UserPrincipalName, Hour
""")

# Calcular zscore por usuário para cada hora
def find_anomalies(df):
    df['zscore'] = stats.zscore(df['LoginCount'])
    return df[df['zscore'].abs() > 2.5]  # 2.5 sigma = ~1.2% da distribuição normal

anomalies = signin_data.groupby('UserPrincipalName').apply(find_anomalies)
anomalies = anomalies[anomalies['Hour'].between(0, 7)]  # Apenas anomalias noturnas

# Visualização
fig, ax = plt.subplots(figsize=(15, 6))
pivot = signin_data.pivot_table(values='LoginCount', index='UserPrincipalName', 
                                 columns='Hour', fill_value=0)
import seaborn as sns
sns.heatmap(pivot.head(30), annot=False, cmap='YlOrRd', ax=ax)
ax.set_title('Heatmap de Logins por Usuário e Hora (30 dias) — Banco Meridian')
plt.tight_layout()

# Resultado: usuários com atividade noturna anômala
print("Usuários com atividade anômala entre 0h-7h:")
print(anomalies[['UserPrincipalName', 'Hour', 'LoginCount', 'zscore']].to_string())
```

---

## 4. Repositório Comunitário: Sentinel Community

O repositório **Azure/Azure-Sentinel** no GitHub tem mais de 1.000 hunting queries, 500 analytics rules, 200 workbooks e 100 playbooks contribuídos pela comunidade global.

**Como usar**:
```bash
# Clonar o repositório
git clone https://github.com/Azure/Azure-Sentinel.git

# Hunting queries em:
./Hunting Queries/

# Por produto:
./Hunting Queries/AzureActiveDirectory/
./Hunting Queries/Microsoft 365 Defender/
./Hunting Queries/Endpoint/
```

**Importar uma hunting query do GitHub para o Sentinel**:
```
Sentinel → Hunting → Import → Upload .yaml file
(ou via REST API para importação em massa)
```

---

## 5. As 5 Hipóteses de Hunting com Queries KQL

### Hipótese 1 — Golden Ticket (Kerberos Anomalias)

```
HIPÓTESE: Um atacante que obteve o hash krbtgt está usando Golden Tickets
para acessar recursos do AD sem necessidade de autenticação normal.
Sinal: TGTs com vida útil muito longa (Golden Tickets podem ter 10+ anos)
ou para contas que não deveriam ter TGTs válidos.
MITRE: T1558.001
```

```kql
// ═══════════════════════════════════════════════════════════════════
// HUNTING: Golden Ticket Detection
// Anomalia: Ticket Kerberos com vida útil anômala ou para conta suspeita
// Fonte: IdentityLogonEvents (MDI) + SecurityEvent (Windows)
// ═══════════════════════════════════════════════════════════════════

// Método 1: Detectar via IdentityLogonEvents (MDI sensor no DC)
IdentityLogonEvents
| where TimeGenerated > ago(7d)
| where Protocol == "Kerberos"
| where ActionType == "LogonSuccess"
// Golden Ticket geralmente tem TicketOptions incomuns
| where isnotempty(TicketOptions)
// Analisar vida útil do ticket (TGT normal: 10h; Golden: pode ser 10 anos = 87600h)
| extend TicketLifetimeHours = toint(TicketOptions)
| where TicketLifetimeHours > 24    // Tickets com vida útil > 24h são suspeitos
| summarize
    AnomalousTickets = count(),
    Accounts = make_set(AccountName, 20),
    TargetDCs = make_set(TargetDeviceName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, IPAddress
| sort by AnomalousTickets desc
```

---

### Hipótese 2 — Pass-the-Hash (NTLM Anomalias)

```
HIPÓTESE: Um atacante está usando hashes NTLM extraídos via LSASS
para autenticar lateralmente sem conhecer a senha em texto claro.
Sinal: Autenticações NTLM de hosts que não costumam usar NTLM,
ou NTLM de admin domain accounts de workstations.
MITRE: T1550.002
```

```kql
// ═══════════════════════════════════════════════════════════════════
// HUNTING: Pass-the-Hash via NTLM Anomalies
// Fonte: SecurityEvent (Event 4624 com LogonType 3 e AuthPackage NTLM)
// ═══════════════════════════════════════════════════════════════════

// Baseline: quais hosts normalmente usam NTLM para LogonType 3 (rede)?
let normalNTLMHosts = SecurityEvent
| where TimeGenerated between (ago(30d) .. ago(1d))    // Últimos 30 dias exceto hoje
| where EventID == 4624
| where LogonType == 3    // Network logon
| where AuthenticationPackageName == "NTLM"
| distinct Computer;

// Detectar NTLM LogonType 3 hoje de hosts que não estão na baseline
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
// Filtrar: apenas admin domain accounts (nomes de conta com padrão de admin)
| where SubjectUserName has_any ("admin", "adm", "svc", "service")
   or TargetUserName has_any ("administrator", "admin", "da_", "DA_")
| where Computer !in (normalNTLMHosts)    // Host não usa NTLM normalmente
| summarize
    NTLMAuthCount = count(),
    TargetAccounts = make_set(TargetUserName, 10),
    SourceIPs = make_set(IpAddress, 10),
    TargetHosts = make_set(TargetServerName, 10)
    by Computer
| where NTLMAuthCount >= 3    // Pelo menos 3 autenticações suspeitas
| sort by NTLMAuthCount desc
```

---

### Hipótese 3 — Living-off-the-Land (LOLBins)

```
HIPÓTESE: Um atacante está usando binários legítimos do Windows
para executar código malicioso, evitando detecção por AV/EDR.
Exemplos: certutil para download, mshta para execução, regsvr32 para DLL.
MITRE: T1218 (Signed Binary Proxy Execution)
```

```kql
// ═══════════════════════════════════════════════════════════════════
// HUNTING: LOLBins (Living-off-the-Land Binaries)
// Fonte: DeviceProcessEvents (MDE) + SecurityEvent 4688
// Objetivo: Detectar uso de LOLBins com argumentos suspeitos
// ═══════════════════════════════════════════════════════════════════

// Lista de LOLBins conhecidos e patterns suspeitos
let lolbinPatterns = dynamic([
    // certutil: download remoto
    "certutil.exe.*-urlcache",
    "certutil.exe.*-decode",
    "certutil.exe.*-encode",
    "certutil.exe.*http",
    // mshta: execução de script remoto
    "mshta.exe.*http",
    "mshta.exe.*vbscript",
    // regsvr32: COM scriptlet
    "regsvr32.exe.*/s.*/u.*/i:http",
    "regsvr32.exe.*scrobj",
    // wscript/cscript: script engines
    "wscript.exe.*http",
    "cscript.exe.*http",
    // bitsadmin: download
    "bitsadmin.exe.*/transfer",
    // PowerShell: encoded command / download
    "powershell.*-encodedcommand",
    "powershell.*downloadstring",
    "powershell.*invoke-expression",
    "powershell.*-windowstyle.*hidden",
    // rundll32: DLL execution
    "rundll32.exe.*javascript",
    "rundll32.exe.*vbscript"
]);

DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where isnotempty(ProcessCommandLine)
| where ProcessCommandLine matches regex @"(?i)(certutil|mshta|regsvr32|wscript|cscript|bitsadmin|rundll32|powershell).*"
// Verificar se o comando contém pattern suspeito
| extend SuspiciousPattern = case(
    ProcessCommandLine contains_cs "-urlcache" and FileName =~ "certutil.exe", "certutil-download",
    ProcessCommandLine contains_cs "-decode" and FileName =~ "certutil.exe", "certutil-decode",
    ProcessCommandLine contains_cs "http" and FileName =~ "mshta.exe", "mshta-remote-script",
    ProcessCommandLine contains_cs "-EncodedCommand" and FileName =~ "powershell.exe", "ps-encoded",
    ProcessCommandLine contains_cs "DownloadString" and FileName =~ "powershell.exe", "ps-download",
    ProcessCommandLine contains_cs "/transfer" and FileName =~ "bitsadmin.exe", "bitsadmin-download",
    ProcessCommandLine contains_cs "javascript" and FileName =~ "rundll32.exe", "rundll32-javascript",
    ""
)
| where isnotempty(SuspiciousPattern)
| project TimeGenerated, DeviceName, AccountDomain, AccountName,
          FileName, ProcessCommandLine, SuspiciousPattern,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

---

### Hipótese 4 — OAuth Persistent Access

```
HIPÓTESE: Um atacante registrou uma aplicação OAuth no tenant do Banco Meridian
com permissões elevadas, usando-a para manter acesso persistente mesmo após
o reset de senha do usuário comprometido.
MITRE: T1550.001 (Web Session Cookie), T1528 (Steal Application Access Token)
```

```kql
// ═══════════════════════════════════════════════════════════════════
// HUNTING: OAuth App com Acesso Persistente Suspeito
// Fonte: AuditLogs + OfficeActivity + CloudAppEvents
// Objetivo: Identificar apps OAuth criadas recentemente com atividade
//           suspeita pós-autorização
// ═══════════════════════════════════════════════════════════════════

let recentAppRegistrations = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add application", "Update application", 
                           "Add service principal", "Add OAuth2PermissionGrant")
| extend
    AppName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id),
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress)
| project RegistrationTime = TimeGenerated, AppName, AppId, Actor, ActorIP, OperationName;

// Verificar atividade das apps após registro
recentAppRegistrations
| join kind=leftouter (
    OfficeActivity
    | where TimeGenerated > ago(30d)
    | where RecordType == "MicrosoftFlow" or RecordType == "SharePointFileOperation"
    | summarize
        ActivitiesCount = count(),
        UniqueUsers = dcount(UserId),
        Operations = make_set(Operation, 10),
        LastActivity = max(TimeGenerated)
        by AppDisplayName = Application
) on $left.AppName == $right.AppDisplayName
// Também verificar no CloudAppEvents
| join kind=leftouter (
    CloudAppEvents
    | where TimeGenerated > ago(30d)
    | summarize
        CloudActivities = count(),
        LastCloudActivity = max(TimeGenerated)
        by ApplicationName = Application
) on $left.AppName == $right.ApplicationName
| project
    RegistrationTime,
    AppName,
    Actor,
    ActorIP,
    ActivitiesCount = coalesce(ActivitiesCount, 0),
    CloudActivities = coalesce(CloudActivities, 0),
    Operations,
    LastActivity
| where ActivitiesCount > 0 or CloudActivities > 0    // Apenas apps com atividade
| sort by ActivitiesCount desc
```

---

### Hipótese 5 — DNS-over-HTTPS Exfiltration

```
HIPÓTESE: Um processo malicioso está exfiltrando dados usando DNS-over-HTTPS (DoH),
que parece tráfego HTTPS normal para destinos como 1.1.1.1 ou 8.8.8.8,
mas está codificando dados em queries DNS.
MITRE: T1048.003 (Exfiltration over Alternative Protocol: DoH)
```

```kql
// ═══════════════════════════════════════════════════════════════════
// HUNTING: DNS-over-HTTPS Exfiltration Indicators
// Fonte: DeviceNetworkEvents (MDE) + CommonSecurityLog (Fortinet)
// Sinal: Volume alto de conexões HTTPS para conhecidos DoH resolvers
//        de um processo que não deveria usar DNS
// ═══════════════════════════════════════════════════════════════════

// IPs conhecidos de DoH resolvers (que podem ser abusados para exfiltração)
let dohResolvers = dynamic([
    "1.1.1.1",        // Cloudflare DoH
    "1.0.0.1",        // Cloudflare DoH 2
    "8.8.8.8",        // Google DoH
    "8.8.4.4",        // Google DoH 2
    "9.9.9.9",        // Quad9 DoH
    "149.112.112.112", // Quad9 DoH 2
    "208.67.222.222",  // OpenDNS DoH
    "94.140.14.14",    // AdGuard DoH
    "2606:4700:4700::1111",  // Cloudflare IPv6
    "2606:4700:4700::1001"   // Cloudflare IPv6
]);

DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIP in (dohResolvers)
| where RemotePort == 443    // HTTPS (DoH usa porta 443)
| where ActionType == "ConnectionSuccess"
// Processos que NÃO deveriam usar DoH (sistemas, não browsers)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "firefox.exe", "msedge.exe", "safari.exe",
    "brave.exe", "opera.exe",           // Browsers legítimos
    "svchost.exe",                       // Windows DNS resolver pode usar DoH legitimamente
    "dnscrypt-proxy.exe"                 // DNS client legítimo
)
| summarize
    DoHConnections = count(),
    BytesSent = sum(LocalPort),    // Aproximação de volume
    TargetResolvers = make_set(RemoteIP, 5),
    FirstConnection = min(TimeGenerated),
    LastConnection = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where DoHConnections >= 5    // Pelo menos 5 conexões suspeitas
| sort by DoHConnections desc
```

---

## 6. Atividades de Fixação

### Questão 1
Qual é a principal vantagem do threat hunting proativo sobre a detecção reativa baseada em alertas?

a) O hunting proativo é mais rápido que analytics rules  
b) O hunting proativo pode descobrir atacantes que usam técnicas não cobertas pelas analytics rules existentes, reduzindo o dwell time de semanas para dias ou horas  
c) O hunting proativo substitui completamente as analytics rules  
d) O hunting proativo é mais barato porque não usa o workspace  

**Gabarito: B** — Analytics rules detectam o que foi configurado para detectar. Um atacante sofisticado que estuda as detecções do alvo e evita os padrões conhecidos pode permanecer não detectado por semanas. O threat hunting parte de hipóteses sobre o que o atacante PODERIA estar fazendo e procura evidências dessas ações nos logs — mesmo sem uma rule configurada. Quando o hunting encontra evidências, o resultado é uma nova detecção ou uma nova analytics rule, melhorando permanentemente a postura de detecção.

---

### Questão 2
Um analista encontrou 3 eventos suspeitos durante hunting: um login de conta de serviço às 3h, uma conexão de rede incomum, e um arquivo criado num diretório de sistema. Como preservar essas evidências para investigação formal?

a) Copiar os resultados para um arquivo Excel local  
b) Criar Bookmarks para cada evento no Sentinel, vinculando-os a um novo incidente de investigação  
c) Aumentar o retention period do workspace  
d) Criar uma analytics rule para cada evento  

**Gabarito: B** — Bookmarks são o mecanismo nativo do Sentinel para preservar evidências durante hunting. Permitem: marcar linhas específicas dos resultados da query com nome, notas e MITRE tagging; vincular múltiplos bookmarks a um único incidente de investigação; manter o contexto da discovery (qual query encontrou, em qual timestamp, qual analista investigou). Copiar para Excel (A) perde o contexto, não é auditável e os dados ficam fora do Sentinel. Analytics rules (D) são para detecção futura, não para preservar evidências de uma descoberta passada.

---

### Questão 3
A hipótese de hunting para Pass-the-Hash usa a combinação EventID 4624 + LogonType 3 + AuthenticationPackageName == "NTLM". Por que a combinação dos três campos é necessária?

a) Por limitação técnica do KQL — filtros simples não funcionam no SecurityEvent  
b) LogonType 3 isola autenticações de rede (excluindo logins interativos que são esperados com NTLM); NTLM isola autenticações não-Kerberos (suspeito em domínios modernos que preferem Kerberos); a combinação foca em autenticações remotas NTLM que são o padrão de Pass-the-Hash  
c) Apenas para reduzir o volume de resultados  
d) EventID 4624 sem LogonType é o mesmo que incluir todas as falhas de autenticação  

**Gabarito: B** — Cada filtro elimina falsos positivos: EventID 4624 = apenas logins bem-sucedidos (4625 são falhas, diferentes do PtH); LogonType 3 = rede (PtH é sempre remoto via rede; logins interativos locais ou de console não são PtH); NTLM = protocolo de autenticação usado no PtH (Kerberos requer a senha ou ticket válido; NTLM aceita o hash). Juntos, os três filtros isolam especificamente autenticações remotas bem-sucedidas usando NTLM — o assinatura mais específica de Pass-the-Hash disponível nos logs de evento Windows.

---

### Questão 4
Um analista usa Livestream no Sentinel para monitorar em tempo real uma hipótese de C2 communication. Após 30 minutos sem resultados, o analista conclui que não há C2 activity. Esta conclusão é válida?

a) Sim — 30 minutos sem alertas significa que o ambiente está limpo  
b) Não necessariamente — C2 beacons podem ter intervalos de horas ou dias; 30 minutos de Livestream sem resultados não exclui a hipótese; o hunting deve usar janelas de lookback maiores (7-30 dias) para análise histórica  
c) Sim — o Livestream é mais preciso que analytics rules  
d) Não — o Livestream não funciona para detecção de C2  

**Gabarito: B** — Esta é uma armadilha comum. C2 frameworks modernos (Cobalt Strike, Brute Ratel, Sliver) usam beacon intervals configuráveis: um implante pode fazer check-in a cada 4 horas com jitter de 50%, tornando-o praticamente invisível numa janela de 30 minutos de monitoramento. O Livestream é útil para monitorar um padrão ativo em andamento (ex.: scan de rede em tempo real), não para concluir ausência de atividade. Para hunting de C2, analise janelas de 7-30 dias com queries históricas, procurando padrões regulares de conexão (beacons periódicos), domínios de curta vida (DGA), ou volume de dados incomum por processo.

---

### Questão 5
Qual é a diferença entre usar um Bookmark para preservar uma evidência versus criar um Incidente a partir do Bookmark?

a) Bookmarks são automáticos; incidentes são manuais  
b) Bookmark preserva a evidência sem afetar o fluxo de trabalho SOC — é uma marcação para referência futura; criar um Incidente a partir do Bookmark formaliza a investigação, a atribui a um analista, a categoriza por severidade e a inclui na fila de trabalho SOC  
c) Bookmarks são para evidências de baixa severidade; incidentes são para alta severidade  
d) Não há diferença — bookmark e incidente são sinônimos no Sentinel  

**Gabarito: B** — Bookmarks são como "notas adesivas" na investigação — preservam evidências específicas (linhas de log, timestamps, IPs) com contexto e tags sem gerar trabalho formal. Um analista pode criar dezenas de bookmarks explorando uma hipótese antes de decidir se há algo real. Quando a evidência é suficiente para justificar uma investigação formal, o analista "cria um incidente a partir do bookmark" — esse incidente entra na fila SOC com severidade, responsável atribuído e SLA aplicável. A separação permite hunting exploratório sem poluir a fila de incidentes com hipóteses não confirmadas.

---

## 7. Roteiro de Gravação

### Aula 9.1 — Threat Hunting no Microsoft Sentinel (55 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Ambiente: workspace com 30 dias de dados (mínimo 14 para baseline UEBA)
- Preparar: 2 hunting queries customizadas pré-salvas para demonstrar
- Ter: pelo menos um resultado suspeito nos dados históricos (simular se necessário)
- Aberto: portal Sentinel → Hunting, GitHub Azure-Sentinel

---

**[0:00 — ABERTURA | 3 minutos]**

"Módulo 9 — Threat Hunting. Este é onde o analista deixa de ser reativo e se torna proativo. Em vez de esperar o alerta, você vai à caça do atacante que está se escondendo nos seus logs.

A realidade é que todo ambiente tem atacantes que passaram pelas camadas de proteção sem gerar alertas. A questão não é 'fomos atacados?' mas 'quando fomos atacados?' O threat hunting proativo encurta o tempo de descoberta de semanas para horas."

---

**[3:00 — BLOCO 1: INTERFACE DE HUNTING | 10 minutos]**

*[Screen share: Sentinel → Threat management → Hunting]*

"Abro o módulo de Hunting no Sentinel. Três abas: Queries, Bookmarks, Livestream.

*[Mostrar as queries disponíveis]*

Aqui estão todas as queries disponíveis — built-in da Microsoft e as que criamos. Posso filtrar por produto (MDE, MDI, MDO), por MITRE tactic, ou por data de atualização.

*[Filtrar por 'Credential Access']*

Estas são queries para hunting de técnicas de roubo de credencial. Vou abrir a de Kerberoasting.

*[Abrir a query e executar]*

Esta query busca por requisições excessivas de tickets Kerberos TGS. A lógica: uma ferramenta de Kerberoasting solicita um TGS para cada SPN que quer atacar offline. O volume anômalo de requisições de TGS de um único host em curto tempo é o sinal.

Executei. Aqui estão os resultados. Um host fez 23 requisições de TGS em 15 minutos. Isso é suspeito — vou criar um Bookmark.

*[Selecionar a linha e criar bookmark]*

Bookmark criado com nome: 'Possível Kerberoasting — WKST-0099 — 23 TGS requests'. Anotei na descrição o próximo passo: verificar processos executados em WKST-0099 no mesmo horário."

---

**[13:00 — BLOCO 2: CRIANDO UMA HUNTING QUERY CUSTOMIZADA | 15 minutos]**

*[Screen share: Sentinel → Hunting → New query]*

"Vou criar uma hunting query customizada para o Banco Meridian — baseada em inteligência específica sobre ataques a bancos brasileiros.

A hipótese: grupos de ransomware que atacam bancos brasileiros usam LOLBins, especificamente certutil.exe para download de payloads. Quero verificar se há uso de certutil com argumento -urlcache nos últimos 30 dias.

*[Preencher o formulário de nova query]*

Nome: 'Banco Meridian - LOLBin certutil Download Suspeito'
Query:
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine contains "-urlcache" 
   or ProcessCommandLine contains "-decode"
| project TimeGenerated, DeviceName, AccountName, 
          ProcessCommandLine, InitiatingProcessFileName
```

MITRE: Tactic - Defense Evasion, Technique: T1218.001

Save.

*[Executar a query e mostrar resultado]*

Resultado: 2 eventos. Um é um administrador legítimo verificando um certificado — verifiquei pelo contexto. O outro é de um usuário comum baixando algo de um IP externo com certutil. Isso precisa de investigação.

*[Criar bookmark para o evento suspeito]*

Bookmark: 'certutil download suspeito — usuario.comum baixou de 200.150.30.45'. Vinculo a um novo incidente de investigação."

---

**[28:00 — BLOCO 3: LIVESTREAM E HIPÓTESES DE HUNTING | 15 minutos]**

*[Screen share: Sentinel → Hunting → Livestream]*

"O Livestream é como colocar uma câmera num corredor específico. Você sabe onde o atacante pode passar e quer ser notificado quando ele aparecer.

*[Selecionar a query de LOLBins e adicionar ao Livestream]*

Clico em Add to Livestream. A query agora está rodando em tempo real. Se certutil for executado com argumentos suspeitos em qualquer endpoint nos próximos minutos, serei notificado aqui.

*[Mostrar a aba Livestream com a query ativa]*

Para o Banco Meridian, manter Livestreams ativas para as hipóteses de maior risco atual — baseadas no threat landscape do setor bancário brasileiro.

Agora vou falar sobre o framework de hipóteses. Antes de criar a query, preciso da hipótese. De onde vem a hipótese?

*[Slide: fontes de hipóteses]*

1. MSTIC Blog: a Microsoft publica relatórios de grupos APT. Buscar no blog 'grupos que atacam bancos Sul-Americanos'
2. FS-ISAC: Financial Services ISAC — compartilha TTPs de ataques ao setor financeiro
3. CISA Advisories: alertas do governo americano sobre ransomware e APT
4. Análise interna: o que encontramos em huntings anteriores? O que os playbooks remediaram?

Cada fonte gera hipóteses específicas e testáveis. A boa hipótese especifica: QUEM (qual tipo de ator), O QUÊ (qual técnica MITRE), POR QUÊ (por que seria relevante para o Banco Meridian), e COMO (qual log capturaria essa evidência)."

---

**[43:00 — BLOCO 4: NOTEBOOKS JUPYTER | 10 minutos]**

*[Screen share: Sentinel → Notebooks]*

"Para análises que excedem o KQL — análise estatística, machine learning, visualizações avançadas — o Sentinel tem notebooks Jupyter integrados.

*[Abrir um notebook]*

Vejo um notebook pré-construído de investigação de conta suspeita. Ele usa a biblioteca msticpy para conectar ao workspace e executar análises.

*[Mostrar a estrutura do notebook sem executar]*

Este notebook: conecta ao workspace, busca todos os logins da conta investigada, calcula estatísticas de baseline, e plota um heatmap de atividade por hora do dia e dia da semana.

Uma anomalia que heatmaps revelam facilmente: um usuário que trabalha de segunda a sexta, 9h-18h, aparece com atividade na madrugada de sábado. Visualmente óbvio. Numa tabela KQL com centenas de linhas, mais difícil de ver.

Para analistas com Python: a library msticpy é open source. Recomendo explorar os notebooks do repositório GitHub Azure-Sentinel/Notebooks."

---

**[53:00 — ENCERRAMENTO | 2 minutos]**

"Concluímos o módulo de Threat Hunting. A mudança de mentalidade é a principal mensagem: não espere os alertas virem até você — vá atrás das evidências que os alertas ainda não cobrem.

Na sessão live, faremos uma hunting session ao vivo no ambiente do curso. Trarão suas hipóteses para testar. O objetivo é que cada participante encontre pelo menos uma anomalia real nos dados do ambiente.

No Lab, reproduzam as 5 queries desta documentação no ambiente de vocês e tentem confirmar ou refutar cada hipótese."

---

## 8. Avaliação do Módulo

**Q1.** Um grupo APT publicou um relatório de threat intelligence descrevendo o uso de `mshta.exe` para executar scripts HTA remotamente como técnica de initial access. Qual é o próximo passo no framework de hunting?

a) Criar imediatamente uma analytics rule para bloquear mshta.exe em todos os endpoints  
b) Formular uma hipótese testável: "O grupo APT pode ter usado mshta.exe com URL remota no Banco Meridian nas últimas semanas" → criar hunting query com `DeviceProcessEvents | where FileName =~ "mshta.exe" and ProcessCommandLine contains "http"` e analisar resultados históricos  
c) Ignorar o relatório — o banco não é o alvo mencionado  
d) Desinstalar mshta.exe de todos os endpoints  

**Resposta: B** — O threat intelligence alimenta a hipótese de hunting. A sequência correta: (1) ler o relatório e extrair os IOCs e TTPs específicos (mshta.exe + URL remota); (2) formular hipótese verificável para o ambiente específico do banco; (3) criar query baseada nas TTPs descritas; (4) analisar resultados históricos (últimos 30-90 dias); (5) se encontrar evidências, criar incidente; (6) criar analytics rule para detecção automática futura. Desinstalar mshta.exe (D) pode quebrar funcionalidades legítimas — é uma decisão que requer análise de impacto antes de implementar.

---

**Q2.** Qual é o propósito principal do `msticpy` nos notebooks Jupyter do Sentinel?

a) Substituir o KQL como linguagem de query principal  
b) Fornecer bibliotecas Python para conectar ao workspace Sentinel, executar queries, enriquecer dados com threat intelligence, e aplicar análises avançadas (ML, visualizações, graph analysis)  
c) Automatizar a criação de analytics rules  
d) Traduzir queries KQL para SQL  

**Resposta: B** — O `msticpy` é uma biblioteca Python open source mantida pelo MSTIC que fornece: conectores para múltiplos data sources (Azure Sentinel, Splunk, QRadar, Elastic); funções de enriquecimento de TI (VirusTotal, ThreatConnect, AlienVault OTX); análise de entidades; visualizações de timeline e grafos; análise de rede; algoritmos de ML para clustering e detecção de anomalias. É o "toolkit" do analista avançado que quer ir além do que o KQL puro oferece, especialmente para correlações complexas e visualizações que o portal do Sentinel não gera nativamente.

---

**Q3.** Durante hunting com a hipótese de DOH exfiltration, a query retornou 15 resultados de `chrome.exe` se conectando a `1.1.1.1:443`. Por que esses resultados foram excluídos da lista de suspeitos?

a) Porque Chrome.exe nunca usa DoH  
b) Porque a query filtrou explicitamente browsers conhecidos que legitimamente usam DoH, e Chrome.exe faz parte dessa lista de exclusão  
c) Porque conexões para 1.1.1.1 não são suspeitas  
d) Porque resultados de aplicações comuns são ignorados por padrão no Sentinel  

**Resposta: B** — A query de DOH exfiltration inclui um filtro `where InitiatingProcessFileName !in~ (browsers conhecidos)`. Chrome, Firefox, Edge e outros browsers modernos têm suporte nativo a DNS-over-HTTPS como feature de privacidade — é comportamento legítimo esperado. Incluí-los resultaria em centenas de resultados irrelevantes. O foco da hipótese é processos que NÃO são browsers — ex.: um malware que usa DoH para exfiltração de dados, ou uma ferramenta de C2 que usa DoH para comunicação com o servidor de comando.

---

**Q4.** Um analista criou um Bookmark durante hunting e depois esqueceu de verificar. Qual é o impacto?

a) O Bookmark expira automaticamente após 7 dias e os dados são perdidos  
b) O Bookmark persiste no Sentinel indefinidamente mas não gera automação — o analista precisa revisitá-lo manualmente ou vincular a um incidente para que entre no fluxo de trabalho SOC  
c) O Sentinel gera automaticamente um incidente a partir de Bookmarks não revisados  
d) Outros analistas não podem ver os Bookmarks de outros usuários  

**Resposta: B** — Bookmarks persistem no Sentinel até serem deletados manualmente — não expiram. Por padrão, são visíveis para toda a equipe (todos na mesma workspace podem ver todos os bookmarks). O problema real é que Bookmarks sem incidente vinculado não entram na fila de trabalho SOC — eles ficam "invisíveis" no fluxo de operações diárias. Boa prática: ao criar um Bookmark de evidência confirmada, imediatamente criar ou vincular a um incidente. Bookmarks apenas para notas de investigação exploratória podem ficar sem incidente, mas devem ser revisados regularmente.

---

**Q5.** A hipótese de Golden Ticket usa a condição `TicketLifetimeHours > 24`. Por que este threshold?

a) Porque 24 é o número de horas num dia e é fácil de lembrar  
b) Porque TGTs Kerberos legítimos têm vida útil máxima de 10h (padrão Active Directory); Golden Tickets forjados frequentemente têm vida útil muito mais longa (atacantes configuram para 10 anos = 87.600h); qualquer TGT com vida útil > 24h é fora do padrão normal  
c) Porque 24 horas é o período de retenção mínimo do Log Analytics  
d) Porque o MDI só detecta tickets com mais de 24 horas  

**Resposta: B** — O Active Directory por padrão configura Maximum Lifetime for User Ticket (TGT) como 10 horas (Group Policy → Computer Configuration → Windows Settings → Security Settings → Account Policies → Kerberos Policy). Um Golden Ticket forjado não passa pelo KDC para renovação — o atacante simplesmente cria um ticket com a vida útil que quiser usando o hash krbtgt. Para evitar detecção, alguns atacantes configuram 10 anos; outros tentam se passar por um ticket normal mas cometem o erro de usar valores acima de 10h. O threshold de 24h é conservador para cobrir anomalias sem ser excessivamente ruidoso.
