# Módulo 05 — SOAR com Logic Apps no Microsoft Sentinel

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 5 horas (2h videoaulas + 2h laboratório + 1h live online)                   |
| **Formato**              | 2 aulas gravadas + Lab 04 + sessão live de playbook workshop                |
| **Pré-requisito**        | Módulos 01–04 concluídos                                                    |
| **Certificação Alvo**    | SC-200 — Domínio 4: Configure security orchestration, automation and response |
| **Cenário**              | Banco Meridian — automatizando resposta a incidentes do SOC                 |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Descrever a arquitetura SOAR no Sentinel: incidents, entities, automation rules e playbooks
2. Criar Logic Apps com triggers de incident e alert, e conectores de segurança
3. Implementar ações de resposta: revogar sessões, bloquear usuário, isolar endpoint
4. Integrar playbooks com ServiceNow, Jira, Teams e PagerDuty
5. Projetar automation rules para roteamento e triagem automática de incidentes
6. Medir e reportar MTTD e MTTR com workbooks do Sentinel

---

## 1. Arquitetura SOAR no Microsoft Sentinel

### 1.1 Visão Geral

O SOAR no Sentinel opera em duas camadas:

```
CAMADA 1 — AUTOMATION RULES (simple, fast, in-platform)
┌───────────────────────────────────────────────────────────────────┐
│ Trigger: incident created / updated / closed                      │
│ Conditions: severity, title, tag, entity type                     │
│ Actions: assign, tag, change severity, change status, run playbook│
│ Latência: milissegundos                                           │
└───────────────────────────────────────────────────────────────────┘
                              ↓ (pode disparar)
CAMADA 2 — PLAYBOOKS / LOGIC APPS (complex, orchestrated)
┌───────────────────────────────────────────────────────────────────┐
│ Trigger: Sentinel incident trigger / alert trigger / entity trigger│
│ Actions: Graph API, REST APIs, Connectors (Teams, ITSM, etc.)     │
│ Logic: conditions, loops, variables, parallel branches            │
│ Latência: segundos a minutos                                      │
└───────────────────────────────────────────────────────────────────┘
```

### 1.2 Fluxo de Dados no SOAR

```
SENTINEL INCIDENT CREATED
          │
          ▼
AUTOMATION RULE (avalia condições)
    ├─ Severity == High AND Entity == Account
    │         │
    │         ▼
    │   Assign to SOC-L3
    │   Add tag: "account-incident"
    │   Run Playbook: "Conta-Comprometida-Resposta"
    │
    └─ Severity == Low → Assign to SOC-L1 (sem playbook)

          │ (se playbook disparado)
          ▼
LOGIC APP EXECUTA:
    1. GET incident details (entidades, alertas)
    2. GET user details (Graph API)
    3. Condition: IsVIP?
       ├─ YES: notify CISO channel
       └─ NO: notify SOC channel
    4. Revoke user sessions (Graph API)
    5. Reset user password (Graph API)
    6. Isolate endpoint (MDE API)
    7. Create ServiceNow ticket
    8. Post Teams message with incident link
    9. Add comment to Sentinel incident with all actions taken
```

### 1.3 Quando o Incident foi Criado?

É importante entender quando um incident é criado no Sentinel:

- **Via analytics rule**: quando a query KQL retorna resultados → alerta → incidente
- **Via Defender XDR sync**: incidente do XDR é sincronizado automaticamente
- **Manualmente**: analista cria incidente a partir de alertas soltos
- **Via ARM API**: sistemas externos criam incidentes via REST

---

## 2. Logic Apps: Triggers Disponíveis

### 2.1 Tipos de Triggers no Sentinel

| Trigger                      | Quando dispara                                         | O que recebe                                      |
|:-----------------------------|:-------------------------------------------------------|:--------------------------------------------------|
| **Incident trigger**         | Quando um automation rule executa o playbook           | Objeto incident completo (entities, alerts, etc.) |
| **Alert trigger**            | Quando uma analytics rule gera um alerta              | Objeto alert (sem contexto de incidente)          |
| **Entity trigger (manual)**  | Quando analista aciona manualmente sobre uma entidade | Entidade específica (Account, Host, IP)           |

**Recomendação**: Sempre que possível, usar o **Incident trigger**. Ele fornece o contexto mais rico: entidades mapeadas, alertas correlacionados, severidade, descrição. O Alert trigger é útil apenas quando você quer responder antes do incidente ser criado (raro).

### 2.2 Estrutura do Objeto Incident

```json
{
  "incidentInfo": {
    "incidentId": "a1b2c3d4-e5f6-...",
    "title": "Banco Meridian - Impossible Travel",
    "severity": "High",
    "status": "New",
    "incidentUrl": "https://portal.azure.com/#blade/..."
  },
  "entities": [
    {
      "kind": "Account",
      "properties": {
        "accountName": "rafael.torres",
        "upnSuffix": "bancomeridian.com.br",
        "objectGuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    },
    {
      "kind": "Ip",
      "properties": {
        "address": "200.150.30.45"
      }
    }
  ],
  "workspaceId": "/subscriptions/.../workspaces/meridian-secops-prod"
}
```

### 2.3 Conectores de Segurança Disponíveis

| Conector                          | Ações disponíveis                                                 |
|:----------------------------------|:------------------------------------------------------------------|
| **Microsoft Sentinel**            | Get incident, Update incident, Add comment, List entities        |
| **Microsoft Entra ID**            | Get user, Disable user, Revoke sessions, Reset password          |
| **Microsoft Defender for Endpoint** | Get device, Isolate device, Run scan, Collect investigation pkg |
| **Microsoft Teams**               | Post message, Create channel, @mention user                      |
| **Microsoft Graph Security**      | Get alerts, Update alert, Get security scores                    |
| **ServiceNow**                    | Create incident, Update incident, Get incident                   |
| **Jira**                          | Create issue, Update issue, Add comment                          |
| **PagerDuty**                     | Create incident, Trigger event, Get on-call users               |
| **HTTP (Generic)**                | Qualquer API REST (para conectores não disponíveis nativamente)  |

---

## 3. Ações de Resposta: Revogar Sessões e Bloquear Usuário

### 3.1 Revogar Sessões via Microsoft Graph API

Revogar sessões é a ação de contenção mais importante em casos de conta comprometida. Quando um attacker rouba um token OAuth ou uma senha, ele tem acesso contínuo mesmo se a senha for trocada — os tokens ativos continuam válidos até expirar naturalmente (normalmente 1-24 horas). A revogação de sessão invalida todos os tokens imediatamente, cortando o acesso do attacker em segundos.

**Por que fazer isso via API em vez de clicar no portal:** No cenário do Banco Meridian com 8 incidentes simultâneos, um analista que precisa manualmente abrir o portal, navegar até o usuário, clicar em "Revoke Sessions" para cada usuário comprometido está levando 3-5 minutos por usuário. Com o playbook automatizado, a mesma ação acontece em menos de 5 segundos do momento em que o incidente é criado — antes mesmo do analista ser notificado.

```json
// HTTP Action no Logic App
{
  "method": "POST",
  "uri": "https://graph.microsoft.com/v1.0/users/@{items('For_each_account')?['properties']?['objectGuid']}/revokeSignInSessions",
  "authentication": {
    "type": "ManagedServiceIdentity",
    "audience": "https://graph.microsoft.com"
  }
}
```

**O que acontece**: Todos os tokens de acesso do usuário são invalidados imediatamente. O usuário é desconectado de todas as sessões ativas (Exchange, SharePoint, Teams, Azure Portal, aplicações). Para voltar a acessar, precisará se autenticar novamente — e com MFA se a Conditional Access policy exigir.

**Pré-requisito**: O Logic App precisa de uma Managed Identity com permissão `User.ReadWrite.All` no Microsoft Graph.

### 3.2 Bloquear Usuário (Disable Account)

Bloquear o usuário (desabilitar a conta) é uma ação mais drástica que revogar sessões. Use quando:
- A investigação confirma que a conta foi definitivamente comprometida
- O usuário pode ser um insider threat ativo
- O attacker pode ter alterado a senha ou métodos de MFA, o que neutralizaria a revogação de sessões

**Impacto operacional no Banco Meridian:** Bloquear uma conta imediatamente paralisa o trabalho do funcionário. Para o analista financeiro que está no meio de um fechamento de balanço, isso pode causar impacto de negócio significativo. Por isso, em muitos SOCs, o playbook automático executa apenas a revogação de sessões (menos impactante) e adiciona um comentário no incidente solicitando que um analista humano decida sobre o bloqueio completo. Automatize o bloqueio apenas para contas de alto risco (contas técnicas, service accounts, usuários com acesso privilegiado).

```json
// HTTP PATCH para desabilitar o usuário no Entra ID
{
  "method": "PATCH",
  "uri": "https://graph.microsoft.com/v1.0/users/@{items('For_each_account')?['properties']?['objectGuid']}",
  "body": {
    "accountEnabled": false
  },
  "authentication": {
    "type": "ManagedServiceIdentity",
    "audience": "https://graph.microsoft.com"
  }
}
```

**Atenção**: Bloquear a conta impede qualquer autenticação. Para funcionários ativos, usar com cuidado. O playbook deve ter aprovação humana antes de bloquear contas definitivamente — apenas revogar sessões para resposta inicial.

### 3.3 Isolar Endpoint via MDE

```json
// HTTP POST para isolar dispositivo via MDE API
{
  "method": "POST",
  "uri": "https://api.securitycenter.microsoft.com/api/machines/@{variables('DeviceId')}/isolate",
  "body": {
    "Comment": "Isolamento automatizado por playbook Sentinel - Incidente @{triggerBody()?['incidentInfo']?['incidentId']}",
    "IsolationType": "Selective"
  },
  "authentication": {
    "type": "ManagedServiceIdentity",
    "audience": "https://api.securitycenter.microsoft.com"
  }
}
```

**Tipos de isolamento MDE**:
- `Full`: bloqueia toda comunicação de rede exceto MDE management
- `Selective`: mantém conexões gerenciadas (SCCM, MDE) mas bloqueia internet e LAN

---

## 4. Lógica Condicional em Playbooks

### 4.1 Exemplo: Verificar se é VIP Antes de Agir

```
Condition: Is VIP User?
├── Data: @{contains(variables('VIPList'), triggerBody()['entities'][0]['properties']['upnSuffix'])}
│
├── YES (true branch):
│   ├── Post to Teams: #canal-alertas-criticos
│   ├── Send email to CISO
│   ├── Revoke sessions ONLY (sem bloquear conta)
│   └── Create ServiceNow P1 ticket
│
└── NO (false branch):
    ├── Post to Teams: #canal-soc-operacional
    ├── Revoke sessions
    ├── Add to SOC-Quarantine group
    └── Create ServiceNow P2 ticket
```

### 4.2 Verificar Severidade do Incidente

```
Condition: Is High Severity?
├── Data: @{equals(triggerBody()['incidentInfo']['severity'], 'High')}
│
├── HIGH:
│   ├── Parallel branch 1: Revoke sessions
│   ├── Parallel branch 2: Notify Teams (SOC + Manager)
│   └── Parallel branch 3: Create ITSM ticket (Priority 1)
│
└── MEDIUM:
    ├── Add comment to incident with enrichment
    ├── Assign to SOC analyst
    └── Create ITSM ticket (Priority 2)
```

---

## 5. Integração com Ferramentas Externas

### 5.1 Microsoft Teams — Notificação com Adaptive Card

```json
// Logic App: Post adaptive card to Teams channel
{
  "type": "AdaptiveCard",
  "version": "1.4",
  "body": [
    {
      "type": "TextBlock",
      "text": "🚨 ALERTA SOC — BANCO MERIDIAN",
      "weight": "Bolder",
      "size": "Large",
      "color": "Attention"
    },
    {
      "type": "FactSet",
      "facts": [
        { "title": "Incidente:", "value": "@{triggerBody()?['incidentInfo']?['title']}" },
        { "title": "Severidade:", "value": "@{triggerBody()?['incidentInfo']?['severity']}" },
        { "title": "Usuário:", "value": "@{variables('AffectedUser')}" },
        { "title": "IP suspeito:", "value": "@{variables('SuspiciousIP')}" },
        { "title": "Ações tomadas:", "value": "Sessões revogadas, ticket criado" }
      ]
    }
  ],
  "actions": [
    {
      "type": "Action.OpenUrl",
      "title": "Investigar no Sentinel",
      "url": "@{triggerBody()?['incidentInfo']?['incidentUrl']}"
    }
  ]
}
```

### 5.2 ServiceNow — Criar Ticket de Incidente

```json
// Logic App: Create ServiceNow incident
{
  "short_description": "[SOC] @{triggerBody()?['incidentInfo']?['title']}",
  "description": "Incidente detectado pelo Microsoft Sentinel.\n\nSeveridade: @{triggerBody()?['incidentInfo']?['severity']}\nUsuário afetado: @{variables('AffectedUser')}\nIP suspeito: @{variables('SuspiciousIP')}\n\nLink Sentinel: @{triggerBody()?['incidentInfo']?['incidentUrl']}",
  "urgency": "2",
  "impact": "2",
  "category": "Security",
  "subcategory": "Incident Response",
  "assignment_group": "SOC-Responders",
  "caller_id": "soc-automation"
}
```

### 5.3 Jira — Criar Issue de Segurança

```json
// Logic App: Create Jira issue
{
  "fields": {
    "project": { "key": "SEC" },
    "summary": "[Sentinel] @{triggerBody()?['incidentInfo']?['title']}",
    "description": {
      "type": "doc",
      "version": 1,
      "content": [
        {
          "type": "paragraph",
          "content": [
            {
              "type": "text",
              "text": "Incidente Sentinel ID: @{triggerBody()?['incidentInfo']?['incidentId']}"
            }
          ]
        }
      ]
    },
    "issuetype": { "name": "Security Incident" },
    "priority": { "name": "High" },
    "assignee": { "accountId": "@{variables('SOCLeadAccountId')}" },
    "labels": ["sentinel", "auto-created", "@{toLower(triggerBody()?['incidentInfo']?['severity'])}"]
  }
}
```

---

## 6. Diagramas de Fluxo dos 3 Playbooks Principais

### 6.1 Playbook 1 — Conta Comprometida

```
TRIGGER: Sentinel Incident (Severity: High, Entity: Account)
│
├─ [1] GET Incident Details
│       └─ Extrair: UserPrincipalName, IPAddress, IncidentTitle
│
├─ [2] GET User Details via Graph API
│       └─ Extrair: DisplayName, Department, Manager, JobTitle, IsVIP
│
├─ [3] Condition: IsVIP?
│       ├─ YES → Set NotifyChannel = "#alertas-executivos"
│       └─ NO  → Set NotifyChannel = "#soc-operacional"
│
├─ [4] PARALLEL ACTIONS:
│       ├─ [4a] Revoke Sign-In Sessions (Graph API)
│       │        └─ POST /users/{id}/revokeSignInSessions
│       │
│       ├─ [4b] Force Password Reset (Graph API)  
│       │        └─ PATCH /users/{id} { "passwordProfile": { "forceChangePasswordNextSignIn": true } }
│       │
│       ├─ [4c] Add User to Security Group "SOC-Investigation"
│       │        └─ POST /groups/{quarantine-group-id}/members/$ref
│       │
│       └─ [4d] Post Teams Message (Adaptive Card)
│                └─ Notificar canal com detalhes + link Sentinel
│
├─ [5] Create Jira Ticket
│       └─ Project: SEC, Type: Security Incident, Priority: High
│
├─ [6] Add Comment to Sentinel Incident
│       └─ "Playbook executado: sessões revogadas, senha resetada, usuário em quarentena. Ticket Jira: SEC-XXXX"
│
└─ [7] Update Incident Status: Active (para analista revisar)
```

### 6.2 Playbook 2 — Phishing Confirmado

```
TRIGGER: Sentinel Incident (Título contém "Phishing Confirmed")
│
├─ [1] GET Incident Details
│       └─ Extrair: SenderEmail, SenderDomain, EmailSubject, RecipientList
│
├─ [2] Block Sender Domain no Exchange Online
│       └─ New-TenantBlockedSenderAddress -SenderAddress @domain
│       └─ (via PowerShell em Logic App com Exchange connector)
│
├─ [3] Purge Phishing Email das Caixas de Entrada
│       └─ Search-Mailbox -TargetMailbox "Discovery Mailbox" -SearchQuery "From:@{SenderEmail}"
│       └─ New-ComplianceSearchAction -Action Purge -PurgeType HardDelete
│
├─ [4] Add Domain to Watchlist "known-phishing-domains"
│       └─ POST /watchlists/{id}/watchlistItems
│       └─ { "itemsKeyValue": { "Domain": "@{SenderDomain}", "DateAdded": "..." } }
│
├─ [5] Send Notification Email to Affected Recipients
│       └─ "Alerta: um e-mail de phishing enviado para você foi removido..."
│
├─ [6] Post Teams: #soc-operacional
│       └─ "Phishing bloqueado e removido. Domínio adicionado à watchlist."
│
└─ [7] Add Comment to Incident + Close (if all actions succeeded)
```

### 6.3 Playbook 3 — Malware Detectado pelo MDE

```
TRIGGER: Sentinel Incident (Alert from MDE, Severity: High/Critical)
│
├─ [1] GET Incident Details
│       └─ Extrair: DeviceName, DeviceId, UserLoggedIn, MalwareName
│
├─ [2] GET Device Details via MDE API
│       └─ GET /api/machines/{id}
│       └─ Extrair: IpAddresses, OsVersion, LastSeen, HealthStatus
│
├─ [3] Isolate Device (MDE API)
│       └─ POST /api/machines/{id}/isolate
│       └─ { "Comment": "Auto-isolamento Sentinel playbook", "IsolationType": "Selective" }
│
├─ [4] Collect Investigation Package (MDE API)
│       └─ POST /api/machines/{id}/collectInvestigationPackage
│       └─ Aguardar coleta e obter URL do pacote
│
├─ [5] Create IR Case in ServiceNow
│       └─ Short description: "MALWARE em @{DeviceName} — @{MalwareName}"
│       └─ Priority: 1 (Critical)
│       └─ Assignment: IR-Team
│       └─ Attachments: link para investigation package
│
├─ [6] Notify SOC via Teams
│       └─ Canal: #incidentes-criticos
│       └─ Card com: Device, User, Malware, link do pacote forense, link ServiceNow
│       └─ @mention: on-call analyst
│
├─ [7] Notify Manager of Affected User via Email
│       └─ "Seu subordinado está sendo investigado por incidente de malware..."
│
└─ [8] Add Comment to Sentinel + Update Status: In Progress
```

---

## 7. MTTD e MTTR: Métricas de SOC

### 7.1 Definições

**MTTD — Mean Time to Detect**: Tempo médio entre um evento ocorrer e ser detectado pelo SOC (alerta gerado no Sentinel).

**MTTR — Mean Time to Respond**: Tempo médio entre a detecção e a contenção/resolução do incidente.

### 7.2 Calculando MTTD e MTTR via KQL

```kql
// MTTD — Tempo entre o evento e a criação do alerta
// Aproximação: diferença entre o TimeGenerated mais antigo dos alertas
// e o CreatedTime do incidente

SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend 
    DetectionLatency = datetime_diff('minute', CreatedTime, FirstActivityTime),
    ResolutionTime = datetime_diff('minute', ClosedTime, CreatedTime)
| where DetectionLatency > 0
| summarize
    MTTD_avg_minutes = avg(DetectionLatency),
    MTTD_p50 = percentile(DetectionLatency, 50),
    MTTD_p95 = percentile(DetectionLatency, 95),
    MTTR_avg_minutes = avg(ResolutionTime),
    MTTR_p50 = percentile(ResolutionTime, 50),
    MTTR_p95 = percentile(ResolutionTime, 95),
    TotalIncidents = count(),
    TruePositives = countif(Classification == "TruePositive"),
    FalsePositives = countif(Classification == "FalsePositive"),
    FPRate = round(100.0 * countif(Classification == "FalsePositive") / count(), 1)
    by Severity
| sort by Severity asc

// MTTR por responsável (para identificar gargalos por analista)
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| where isnotempty(Owner)
| extend OwnerEmail = tostring(parse_json(Owner).email)
| extend ResolutionMinutes = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize 
    AvgResolutionMinutes = avg(ResolutionMinutes),
    IncidentCount = count()
    by OwnerEmail, Severity
| sort by AvgResolutionMinutes asc
```

### 7.3 Workbook de Métricas de SOC

O Content Hub inclui o workbook **SOC Efficiency Workbook** que exibe:
- MTTD e MTTR por período
- Taxa de falso positivo por analytics rule
- Volume de incidentes por severidade
- Incidentes por analista e por tempo de resolução
- Coverage MITRE ATT&CK

---

## 8. Atividades de Fixação

### Questão 1
Um playbook usa o "Incident trigger" do Sentinel. Qual é a forma correta de extrair o UserPrincipalName da primeira entidade Account do incidente?

a) `@{triggerBody()['user']['email']}`  
b) `@{triggerBody()?['entities'][0]?['properties']?['upnSuffix']}`  
c) Uma combinação de `accountName` + `upnSuffix`: `@{triggerBody()?['entities'][0]?['properties']?['accountName']}@{triggerBody()?['entities'][0]?['properties']?['upnSuffix']}`  
d) `@{triggerBody()['incidentInfo']['affectedUser']}`  

**Gabarito: C** — O objeto `entities` retorna uma lista de objetos de entidade. Para entidades do tipo Account, os campos relevantes são `accountName` (parte antes do @) e `upnSuffix` (domínio). O UPN completo precisa ser concatenado: `rafael.torres` + `@` + `bancomeridian.com.br` = `rafael.torres@bancomeridian.com.br`. As opções A e D usam campos inexistentes; B retorna apenas o sufixo (o domínio), não o UPN completo.

---

### Questão 2
Por que um playbook de resposta a incidentes deve adicionar um comentário ao incidente do Sentinel ao final da execução?

a) Porque é obrigatório pela documentação da Microsoft  
b) Para garantir que o analista saiba quais ações automáticas já foram executadas, evitando ações duplicadas (ex.: revogar sessão duas vezes) e documentando o trail de evidências  
c) Para aumentar o número de eventos no workspace e melhorar a visibilidade  
d) Porque sem o comentário o incidente não pode ser fechado  

**Gabarito: B** — Documentar as ações do playbook no incidente é fundamental para rastreabilidade (audit trail) e para que analistas humanos saibam o estado atual. Se um analista abre um incidente e não vê que as sessões já foram revogadas, pode revogar novamente (causando confusão para o usuário legítimo) ou perder tempo verificando o que já foi feito. O comentário deve incluir: ações executadas, timestamps, resultados (sucesso/falha), e IDs de tickets criados. Isso também é importante para demonstrar conformidade regulatória (BACEN 4.893 art. 19).

---

### Questão 3
Qual é a diferença entre "Incident trigger" e "Alert trigger" em um Logic App integrado ao Sentinel?

a) O Incident trigger é mais rápido; o Alert trigger tem latência maior  
b) O Incident trigger dispara quando uma automation rule executa o playbook sobre um incidente, fornecendo contexto completo com entities; o Alert trigger dispara quando uma analytics rule gera um alerta individual, antes da criação do incidente  
c) O Alert trigger suporta mais conectores do que o Incident trigger  
d) Não há diferença prática entre os dois triggers  

**Gabarito: B** — Incident trigger: disparado via automation rules sobre incidentes existentes, com o objeto incident completo incluindo entidades mapeadas, alertas correlacionados, severity, status. Alert trigger: disparado diretamente por analytics rules quando um alerta é gerado, antes da correlação em incidente. O Alert trigger tem menos contexto (sem entidades mapeadas de outros alertas, sem correlation). Recomendação: usar Incident trigger na maioria dos casos; Alert trigger apenas quando a resposta deve acontecer antes da correlação (ex.: resposta imediata a malware mesmo antes de correlação com outros alertas).

---

### Questão 4
O playbook de Conta Comprometida executa 4 ações em paralelo (revogar sessões, resetar senha, adicionar ao grupo de quarentena, notificar Teams). Se a ação "resetar senha" falhar (ex.: senha temporária rejeitada pela política), o que acontece com as outras 3 ações paralelas?

a) Todas as 4 ações são canceladas automaticamente para garantir consistência  
b) Por padrão, cada branch paralela é independente — as outras 3 ações continuam, mas a falha da ação de reset de senha precisa ser tratada com um bloco Scope com "Configure run after: Failed"  
c) O Logic App tenta a ação novamente por 3 vezes antes de continuar  
d) As branches paralelas interrompem somente se a ação crítica falhar (revogar sessões)  

**Gabarito: B** — Em Logic Apps, branches paralelas são independentes por padrão. Se uma falha, as outras continuam. A boa prática é usar blocos Scope com "Configure run after" para tratar erros em cada branch e adicionar um passo final que verifica o status de todas as branches e atualiza o comentário no Sentinel com: "Ações executadas: sessões revogadas ✓, senha resetada ✗ (erro: senha não atende política), quarentena ✓, Teams notificado ✓". Isso garante resposta parcial mesmo com falhas e documenta o que foi e o que não foi feito.

---

### Questão 5
Como calcular o MTTR (Mean Time to Respond) dos incidentes do Sentinel nos últimos 30 dias?

a) Usando a tabela SecurityAlert com o campo AlertName  
b) Usando a tabela SecurityIncident com os campos CreatedTime e ClosedTime, calculando datetime_diff entre eles  
c) Consultando o Logic Apps execution history via Azure Monitor  
d) O MTTR não pode ser calculado via KQL; requer exportação para Excel  

**Gabarito: B** — A tabela `SecurityIncident` no Log Analytics contém todos os campos necessários para calcular MTTR: `CreatedTime` (quando o incidente foi detectado/criado) e `ClosedTime` (quando foi resolvido). O MTTR é calculado com `datetime_diff('minute', ClosedTime, CreatedTime)`. Filtrando por `Status == "Closed"` e usando `avg()` para média ou `percentile()` para distribuição. Isso permite segmentar o MTTR por severidade, analista, tipo de incidente, etc.

---

## 9. Roteiros de Gravação

### Aula 5.1 — Logic Apps: Triggers e Estrutura de Playbook (45 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Preparar: Logic App vazio criado no resource group rg-meridian-secops
- Ter aberto: portal Azure, Sentinel Incidents, editor de Logic Apps
- Ter um incidente de teste criado no Sentinel para demonstração

---

**[0:00 — ABERTURA | 3 minutos]**

"Módulo 5 — SOAR. Esse é o módulo que transforma o SOC de reativo para proativo. Com playbooks bem construídos, as primeiras ações de resposta acontecem em segundos, não em horas. E o analista acorda com o trabalho inicial já feito.

Hoje vamos criar nosso primeiro playbook do zero — o playbook de Conta Comprometida. Ao final desta aula, você terá um Logic App que revoga sessões, reseta senha, notifica o Teams e cria um ticket automaticamente."

---

**[3:00 — BLOCO 1: LOGIC APPS — FUNDAMENTOS | 10 minutos]**

*[Slide: arquitetura SOAR no Sentinel]*

"Um playbook no Sentinel é implementado como um Azure Logic App. O Logic App é um serviço de orquestração low-code/no-code da Microsoft que permite conectar APIs, serviços e sistemas com lógica de controle de fluxo.

Por que Logic Apps e não Azure Functions? Functions são código puro — flexível, mas requer desenvolvimento. Logic Apps são visuais — mais acessíveis para analistas SOC sem background de desenvolvimento, e têm conectores prontos para Teams, ServiceNow, Jira, Defender.

*[Screen share: portal Azure → Logic Apps]*

Vou abrir o Logic App Designer. Já tenho um Logic App criado — meridian-conta-comprometida. Clico em 'Designer' para ver a interface visual.

O fluxo é uma sequência de blocos: Trigger → Actions → Conditions → More Actions.

O primeiro bloco é sempre o Trigger. Clico em 'When Microsoft Sentinel incident creation rule is triggered' — este é o nosso Incident trigger."

---

**[13:00 — BLOCO 2: CONSTRUINDO O PLAYBOOK | 25 minutos]**

*[Screen share: construção no Logic App Designer]*

"Vou construir o playbook passo a passo.

**Passo 1: Trigger**
Já configurado — Incident trigger.

**Passo 2: For each entity (Account)**
Adiciono uma ação 'For each'. Array: `@{triggerBody()?['entities']}`.
Dentro do For each, adiciono uma Condition: `entityType equals Account`.
Isso garante que o playbook só atua em entidades do tipo Account.

**Passo 3: GET User Details**
Dentro do branch Account, adiciono uma ação HTTP:
- Method: GET
- URI: `https://graph.microsoft.com/v1.0/users/@{items('For_each_entities')?['properties']?['accountName']}@@{items('For_each_entities')?['properties']?['upnSuffix']}`
- Authentication: Managed Identity

*[Mostrar como configurar a Managed Identity no Logic App]*

**Passo 4: Revogar Sessões**
HTTP POST para Graph API revokeSignInSessions.
Adicionar tratamento de erro: se falhar, adicionar nota ao incidente mas continuar.

**Passo 5: Post no Teams**
Adiciono o conector do Microsoft Teams → Post message in chat or channel.
Canal: #soc-operacional
Mensagem: conteúdo dinâmico com incidente title, severity, e user.

*[Mostrar o Dynamic Content picker no Logic Apps]*

**Passo 6: Criar ticket Jira**
HTTP POST para Jira API. Mostro o body JSON com os campos dinâmicos.

**Passo 7: Adicionar comentário no Sentinel**
'Add comment to incident' → comentário documentando todas as ações.

**Passo 8: Save e Test**
Salvo o Logic App. Para testar, vou ao Sentinel → um incidente de teste → Run playbook manualmente.

*[Executar o playbook e mostrar o resultado]*

Perfeito! O Run History mostra todas as ações executadas, com status de sucesso/falha para cada passo."

---

**[38:00 — BLOCO 3: AUTOMATION RULE PARA DISPARAR O PLAYBOOK | 5 minutos]**

*[Screen share: Sentinel → Automation → Automation Rules]*

"O playbook está criado. Agora preciso de uma automation rule para dispará-lo automaticamente quando o incidente certo aparecer.

Nova automation rule:
- Trigger: When incident is created
- Conditions: Severity == High AND Contains entities of type Account
- Action: Run playbook → meridian-conta-comprometida

Isso fecha o ciclo: incidente criado → automation rule avalia → playbook disparado → ações executadas em segundos."

---

**[43:00 — ENCERRAMENTO | 2 minutos]**

"Criamos o playbook completo de Conta Comprometida e o conectamos ao ciclo de automação do Sentinel. Na próxima aula, vamos criar os outros dois playbooks — Phishing e Malware — e aprender a medir o impacto do SOAR com as métricas MTTD e MTTR."

---

### Aula 5.2 — Automation Rules e Playbooks Avançados (45 minutos)

---

**[0:00 — ABERTURA | 2 minutos]**

"Continuando o Módulo 5. Na última aula construímos o playbook de conta comprometida do zero. Hoje vamos abordar os playbooks de phishing e malware, aprofundar em automation rules avançadas, e aprender a medir o ROI do nosso SOAR com métricas de SOC."

---

**[2:00 — BLOCO 1: PLAYBOOK PHISHING | 15 minutos]**

*[Screen share: Logic App Designer — playbook phishing]*

"O playbook de phishing é mais desafiador porque envolve operações em múltiplos sistemas: Exchange Online para bloquear sender, Purview para purgar e-mails, e watchlist do Sentinel para adicionar o domínio.

*[Construir playbook de phishing conforme diagrama da documentação]*

Uma ação que chama atenção: Purge de e-mails. Esta ação usa o PowerShell do Exchange Online via Logic App. Precisamos de uma connection com permissão de acesso ao Exchange.

Demonstro como criar a connection Exchange Online no Logic App e como usar a ação 'Send an HTTP request to Exchange' para executar comandos de Compliance Search e Purge.

*[Mostrar a execução do playbook de phishing com e-mail de teste]*"

---

**[17:00 — BLOCO 2: PLAYBOOK MALWARE — ISOLAMENTO DE ENDPOINT | 12 minutos]**

*[Screen share: Logic App Designer — playbook malware]*

"O isolamento de endpoint via MDE é uma das ações mais poderosas do SOAR. Em segundos, um endpoint comprometido fica totalmente isolado da rede, sem que o analista precise fazer nada manualmente.

A API do MDE permite: isolar, coletar pacote de investigação, iniciar varredura, executar query de live response — tudo via HTTP.

*[Demonstrar a chamada API de isolamento]*

Importante: o Managed Identity do Logic App precisa da permissão Machine.Isolate no MDE. Vou mostrar como adicionar isso nas permissões do app registration.

*[Mostrar a configuração das permissões no Entra ID → App Registration]*"

---

**[29:00 — BLOCO 3: AUTOMATION RULES AVANÇADAS | 10 minutos]**

*[Screen share: Sentinel → Automation → Automation Rules]*

"Automation rules são mais poderosas do que parecem. Vou mostrar 3 configurações avançadas para o Banco Meridian.

**Rule 1: Supressão de Falso-Positivo Conhecido**

Uma analytics rule de login fora do horário comercial gera alertas toda vez que o sistema de backup roda às 2h. Até ajustar a rule, posso criar uma automation rule que fecha automaticamente incidentes com aquele título específico e classifica como BenignPositive.

**Rule 2: Escalada Automática por VIP**

Se o incidente contém a tag 'vip-user' (adicionada por outra automation rule baseada em watchlist), escalar automaticamente para High e atribuir ao SOC L3.

**Rule 3: Coordenação de Playbooks**

Uma automation rule que roda 3 playbooks em sequência: primeiro enriquecimento (busca reputação do IP), depois decisão (block ou investigate), depois notificação. A sequência é garantida pela ordem das ações na automation rule."

---

**[39:00 — BLOCO 4: MÉTRICAS DE SOC — MTTD E MTTR | 5 minutos]**

*[Screen share: Sentinel → Workbooks]*

"Vou mostrar o workbook de métricas SOC instalado pelo Content Hub.

*[Abrir SOC Efficiency Workbook]*

Aqui vejo: MTTD médio dos últimos 30 dias (quanto tempo entre evento e detecção), MTTR por severidade (quanto tempo para resolver), taxa de falso positivo por analytics rule (quais rules precisam de ajuste), e cobertura MITRE ATT&CK.

*[Mostrar a query KQL que calcula o MTTD na seção anterior da documentação]*

Esta query do repositório retorna o MTTD e MTTR segmentado por severidade. Incluo ela num workbook personalizado para o CISO receber um relatório mensal automaticamente."

---

**[44:00 — ENCERRAMENTO | 1 minuto]**

"Com isso, concluímos o módulo de SOAR. Criamos 3 playbooks completos, configuramos automation rules avançadas, e aprendemos a medir o impacto com métricas de SOC. No Lab 04, vocês vão criar o playbook de conta comprometida no ambiente de vocês e testá-lo contra um incidente real."

---

## 10. Avaliação do Módulo

**Q1.** Ao criar um Logic App para resposta a incidentes, por que o "Incident trigger" é preferível ao "Alert trigger" na maioria dos casos?

a) O Incident trigger é mais rápido  
b) O Incident trigger fornece o objeto incidente completo com entidades mapeadas e alertas correlacionados, permitindo decisões mais ricas; o Alert trigger fornece apenas o alerta individual  
c) O Alert trigger não suporta conexão com o Microsoft Graph  
d) O Incident trigger não requer configuração de permissões  

**Resposta: B** — O Incident trigger recebe o objeto completo do incidente com todas as entidades mapeadas (Account, Host, IP), os alertas correlacionados, severity, status e outros metadados ricos. Isso permite decisões lógicas como "se o incidente contém uma entidade Account, revogue as sessões dessa conta". O Alert trigger recebe apenas o alerta individual, sem o contexto de correlação.

---

**Q2.** Um Logic App precisa chamar a API do Microsoft Graph para revogar sessões de um usuário. Qual é a forma mais segura de autenticação para o Logic App?

a) Hardcodar as credenciais de um conta de serviço no próprio Logic App  
b) Usar um Managed Identity do Logic App com a permissão Graph User.ReadWrite.All atribuída no Entra ID  
c) Solicitar ao usuário que forneça suas credenciais via formulário  
d) Usar a chave de API do Key Vault armazenada como variável de ambiente  

**Resposta: B** — Managed Identity é a forma mais segura: não há credenciais armazenadas no Logic App (não há secret para vazar), o acesso é auditável no Entra ID, e as permissões são granulares. A opção A (hardcode) é uma grave vulnerabilidade — qualquer pessoa com acesso ao Logic App vê as credenciais. A opção D (Key Vault) é melhor que A mas ainda usa um secret que precisa ser rotacionado. Managed Identity é a best practice atual para todos os serviços Azure que precisam autenticar em APIs Microsoft.

---

**Q3.** Uma automation rule tem as seguintes condições: Severity == High AND Analytics rule name contains "Impossible Travel". Qual é o objetivo desta combinação?

a) Detectar apenas logins impossíveis de países frios  
b) Aplicar ações específicas (ex.: revogar sessões imediatamente) apenas para incidentes de alto risco originados da rule de impossible travel, sem afetar outros incidentes de alta severidade  
c) Bloquear automaticamente a analytics rule de Impossible Travel se gerar muitos alertas  
d) Criar um segundo incidente com severity Critical quando o travel é muito suspeito  

**Resposta: B** — Combinar severity com o nome da rule permite criar ações muito específicas. Um playbook de "revogar sessões imediatamente" faz sentido para impossible travel (conta claramente comprometida) mas pode ser agressivo demais para outros incidentes High (ex.: anomalia de download que pode ter uma explicação legítima). Automation rules específicas por tipo de incidente permitem respostas graduadas e proporcionais ao risco.

---

**Q4.** O MTTR do Banco Meridian para incidentes de alta severidade é de 4 horas. Após implementar os 3 playbooks (conta comprometida, phishing, malware), qual seria o impacto esperado no MTTR?

a) O MTTR aumentaria porque os playbooks geram mais alertas para investigar  
b) O MTTR diminuiria significativamente porque as primeiras ações de contenção (revogar sessões, isolar endpoint, bloquear sender) são executadas automaticamente em segundos, reduzindo o tempo que o attacker tem acesso  
c) O MTTR seria zero porque os playbooks resolvem tudo automaticamente  
d) O MTTR não seria afetado — playbooks apenas documentam o incidente  

**Resposta: B** — SOAR não elimina a necessidade de investigação humana, mas drasticamente reduz o MTTR ao executar ações de contenção imediatas. Antes do SOAR: o analista precisa descobrir o incidente, entender o contexto, decidir a ação, executar manualmente (revogar sessões no Entra ID, criar ticket, notificar o manager) — pode levar 2-4 horas em SOCs com múltiplos incidentes. Com SOAR: em 30-60 segundos, sessões já estão revogadas, endpoint isolado, ticket criado. O analista ainda precisa investigar e confirmar, mas o dano já foi limitado.

---

**Q5.** Como o Sentinel mede automaticamente o MTTD (Mean Time to Detect) usando a tabela SecurityIncident?

a) `SecurityIncident | summarize avg(CreatedTime)` — média de todos os timestamps  
b) Comparando o campo `FirstActivityTime` (quando o evento de ameaça ocorreu) com `CreatedTime` (quando o incidente foi criado no Sentinel), usando `datetime_diff`  
c) O MTTD não pode ser calculado no Sentinel — requer exportação para SIEM externo  
d) Usando o campo `DetectionLatency` que é calculado automaticamente pelo Sentinel  

**Resposta: B** — A tabela `SecurityIncident` tem o campo `FirstActivityTime` que representa o timestamp do evento mais antigo nos alertas correlacionados (quando o comportamento malicioso começou) e `CreatedTime` que é quando o Sentinel criou o incidente. O MTTD é a diferença entre esses dois: `datetime_diff('minute', CreatedTime, FirstActivityTime)`. Isso mede quanto tempo passou entre o início do ataque (ex.: primeiro login suspeito) e a detecção (alerta gerado no Sentinel).
