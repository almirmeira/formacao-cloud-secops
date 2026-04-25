# Lab 01 — Deploy do Microsoft Sentinel

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 02 — Microsoft Sentinel: Deployment e Fontes de Dados           |
| **Ambiente**             | Sandbox Azure fornecida pelo CECyber Labs                              |
| **Nível**                | Básico-Intermediário                                                   |

---

## Seção 1 — Contexto Situacional

O **Banco Meridian** (banco fictício, tier 2, 2.800 funcionários) acabou de receber aprovação do board para implementar um SOC centralizado. A empresa já opera Microsoft 365 E5 para todos os funcionários, e o CISO quer aproveitar o investimento existente para implantar o **Microsoft Sentinel** como SIEM/SOAR nativo.

Você foi designado como **Security Engineer** responsável pela implantação inicial. O CISO exige que o SOC esteja operacional em 48 horas com pelo menos 6 fontes de dados conectadas e primeiros alertas configurados.

---

## Seção 2 — Situação Inicial

**Estado do ambiente ao iniciar o lab**:
- Subscription Azure disponível: `Banco-Meridian-Sandbox`
- Resource Group vazio: `rg-meridian-secops`
- Tenant M365 E5 ativo com 5 usuários de teste pré-criados
- Domínio: `bancomeridian-lab.onmicrosoft.com`
- Sem Sentinel habilitado
- Sem data connectors configurados
- Sem analytics rules ativas

**Credenciais de acesso ao ambiente**:
Fornecidas pelo instrutor via portal CECyber Labs.

---

## Seção 3 — Problema Identificado

O banco não tem **visibilidade** sobre o que acontece nos sistemas Microsoft 365. Os logs de autenticação (quem logou, de onde, quando) existem no Entra ID mas ninguém os consulta sistematicamente. Não há alertas automáticos para atividades suspeitas como logins de países estrangeiros ou tentativas de autenticação incomuns.

O CISO recebeu um relatório do FS-ISAC alertando que bancos tier-2 brasileiros estão sendo alvo de ataques de password spray e AiTM phishing. Sem um SIEM operacional, o banco não teria como detectar esses ataques.

---

## Seção 4 — Roteiro de Atividades

1. Criar o workspace Log Analytics na região Brazil South
2. Habilitar o Microsoft Sentinel no workspace
3. Configurar a retenção de dados por tabela (compliance BACEN 5 anos)
4. Conectar o data connector Microsoft Entra ID
5. Conectar o data connector Microsoft Defender XDR
6. Conectar o data connector Azure Activity
7. Conectar o data connector Office 365
8. Instalar a solução Microsoft Entra ID via Content Hub
9. Ativar 3 analytics rules do pacote Content Hub
10. Validar ingestão de dados via KQL

---

## Seção 5 — Proposição

Ao final deste laboratório, o Banco Meridian terá:
- Um workspace Log Analytics configurado corretamente com retenção de 5 anos
- Microsoft Sentinel habilitado e operacional
- 4 fontes de dados conectadas gerando telemetria
- 3 analytics rules ativas que detectam comportamentos suspeitos
- Capacidade de consultar logs de autenticação e atividade via KQL

---

## Seção 6 — Script Passo a Passo

### Passo 1: Criar o Workspace Log Analytics

**Portal Azure → Create a resource → pesquisar "Log Analytics workspace" → Create**

```
Preencher o formulário:
├── Subscription: Banco-Meridian-Sandbox
├── Resource Group: rg-meridian-secops
├── Name: meridian-secops-prod
├── Region: Brazil South
└── Pricing Tier: Pay-as-you-go (PerGB2018)
```

Clicar em **Review + Create** → **Create**

**Resultado esperado**: Workspace criado em 2-3 minutos. Verificar no portal que o resource aparece em `rg-meridian-secops`.

**Troubleshooting**:
- Se Brazil South não estiver disponível: usar East US 2 (segunda opção preferida)
- Se receber erro de quotas: contatar o instrutor para ajuste da sandbox

---

### Passo 2: Habilitar o Microsoft Sentinel

1. Navegar para o workspace criado: **meridian-secops-prod**
2. No menu lateral, localizar **Microsoft Sentinel**
3. Clicar em **Add Microsoft Sentinel**
4. Selecionar o workspace **meridian-secops-prod**
5. Clicar em **Add**

**Resultado esperado**: O Sentinel é habilitado em 2-3 minutos. O portal redireciona automaticamente para o Overview do Sentinel.

**Verificação**:
```powershell
# PowerShell: verificar que o Sentinel está habilitado
Get-AzSentinelWorkspace -ResourceGroupName "rg-meridian-secops" -WorkspaceName "meridian-secops-prod"
# Deve retornar o objeto com o workspace ID
```

**Troubleshooting**:
- Erro "already exists": o Sentinel já pode estar habilitado — verificar navegando diretamente
- Erro de permissão: você precisa de pelo menos Contributor na subscription

---

### Passo 3: Configurar Retenção por Tabela

**Portal Azure → meridian-secops-prod → Tables**

Configurar as seguintes tabelas para retenção estendida (BACEN 4.893):

```
Para cada tabela abaixo, clicar na tabela → Edit → ajustar valores:

SigninLogs:
  Interactive retention: 90 days
  Total retention period: 1825 days (5 anos)
  [Apply]

AuditLogs:
  Interactive retention: 90 days
  Total retention period: 1825 days
  [Apply]

SecurityEvent:
  Interactive retention: 90 days
  Total retention period: 1825 days
  [Apply]

AzureActivity:
  Interactive retention: 90 days
  Total retention period: 1825 days
  [Apply]
```

**Verificação**:
```powershell
# Verificar retenção configurada
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName "rg-meridian-secops" -Name "meridian-secops-prod"
Write-Output "Workspace retention: $($ws.RetentionInDays) days"
```

**Resultado esperado**: Cada tabela mostra Interactive: 90d, Total: 1825d (5 anos).

**Troubleshooting**:
- Tabelas aparecem somente após a primeira ingestão de dados — algumas podem não estar disponíveis ainda. Configure as que estiverem disponíveis e retorne após a ingestão para as demais.

---

### Passo 4: Conectar Microsoft Entra ID

**Sentinel → Data connectors → Pesquisar "Microsoft Entra ID" → Open connector page**

1. Verificar pré-requisitos: conta precisa de **Security Administrator** ou **Global Administrator**
2. Na seção "Configuration", selecionar:
   - ✓ Sign-in Logs
   - ✓ Audit Logs
   - ✓ Non-Interactive User Sign-In Logs
   - ✓ Service Principal Sign-In Logs
3. Clicar em **Apply Changes**

**Resultado esperado**: Status do conector muda para "Connected" em até 15 minutos.

**Verificação após 15 minutos**:
```kql
SigninLogs
| where TimeGenerated > ago(30m)
| count
// Deve retornar pelo menos 1 registro
```

**Troubleshooting**:
- Se o conector aparecer como "Disconnected" após 20 minutos: verificar se a conta tem permissão de Global Admin ou Security Admin no tenant M365
- Se o count retornar 0: aguardar mais 15 minutos e tentar novamente. Logins precisam ocorrer para gerar logs.

---

### Passo 5: Conectar Microsoft Defender XDR

**Sentinel → Data connectors → Pesquisar "Microsoft Defender XDR" → Open connector page**

**ATENÇÃO — Configuração crítica**:

1. Na seção "Configuration":
   - ✓ **Turn off all Microsoft incident creation rules for these products** (OBRIGATÓRIO)
   - Esto evita duplicação de incidentes
2. Selecionar os produtos:
   - ✓ Microsoft Defender for Endpoint
   - ✓ Microsoft Defender for Identity
   - ✓ Microsoft Defender for Office 365
   - ✓ Microsoft Defender for Cloud Apps
3. Selecionar as tabelas avançadas:
   - ✓ DeviceEvents
   - ✓ DeviceProcessEvents
   - ✓ DeviceNetworkEvents
   - ✓ EmailEvents
   - ✓ IdentityLogonEvents
4. Clicar em **Apply Changes**

**Resultado esperado**: Status "Connected". Incidentes do Defender XDR começam a aparecer no Sentinel.

**Verificação**:
```kql
// Verificar se incidentes chegaram
SecurityIncident
| where TimeGenerated > ago(1h)
| count
```

**Troubleshooting**:
- Se não aparecerem incidentes: verificar se há alertas ativos no portal security.microsoft.com; sem alertas, sem incidentes sincronizados
- Se aparecerem incidentes duplicados: verificar se a opção "Turn off all Microsoft incident creation rules" foi ativada

---

### Passo 6: Conectar Azure Activity

**Sentinel → Data connectors → Pesquisar "Azure Activity" → Open connector page**

1. Clicar em **Launch Azure Policy Assignment Wizard**
2. Na tela de Policy Assignment:
   - Scope: Subscription Banco-Meridian-Sandbox
   - Assignment name: "Azure Activity to Sentinel"
3. Na aba **Parameters**: selecionar o workspace `meridian-secops-prod`
4. Na aba **Remediation**: ✓ Create a remediation task
5. Clicar em **Review + Create → Create**

**Resultado esperado**: Em 5-10 minutos, logs de operações Azure começam a chegar na tabela `AzureActivity`.

**Verificação**:
```kql
AzureActivity
| where TimeGenerated > ago(1h)
| summarize count() by OperationName
| top 10 by count_
```

**Troubleshooting**:
- Se não houver dados: a remediação automática pode demorar até 30 minutos. Aguardar e tentar novamente.

---

### Passo 7: Conectar Office 365

**Sentinel → Data connectors → Pesquisar "Office 365" → Open connector page**

1. Na seção "Configuration":
   - ✓ Exchange
   - ✓ SharePoint
   - ✓ Teams
2. Clicar em **Apply Changes**

**Resultado esperado**: Logs de atividade de Exchange, SharePoint e Teams chegam na tabela `OfficeActivity`.

**Verificação**:
```kql
OfficeActivity
| where TimeGenerated > ago(2h)
| summarize count() by RecordType
```

**Troubleshooting**:
- Alguns workloads (especialmente Teams) podem demorar até 24h para ingestão inicial
- Exchange geralmente tem dados em 15-20 minutos se há atividade de e-mail

---

### Passo 8: Instalar Solução via Content Hub

**Sentinel → Content Hub → Pesquisar "Microsoft Entra ID"**

1. Selecionar **Microsoft Entra ID** (publicado pela Microsoft)
2. Clicar em **Install**
3. Aguardar a instalação (~3 minutos)
4. Clicar em **Manage** para visualizar o conteúdo instalado

**Resultado esperado**: 30+ analytics rules, 15 workbooks e 20+ hunting queries instalados.

---

### Passo 9: Ativar 3 Analytics Rules

**Sentinel → Analytics → Rule templates → filtrar por "Microsoft Entra ID"**

**Rule 1: Suspicious Sign-In to Privileged Account**

1. Localizar a rule "Suspicious Sign-In to Privileged Account"
2. Clicar na rule → **Create rule**
3. Verificar a query KQL (não modificar no lab)
4. **Query scheduling**: Run every 1h, Lookback 1h
5. Severity: High
6. **Review + Create**

**Rule 2: Brute Force Attack against Azure Active Directory (AD) User Account**

1. Localizar e selecionar a rule
2. Criar rule com configurações padrão
3. Revisar o threshold padrão (ajustar se necessário para o lab: baixar para 5 tentativas)

**Rule 3: MFA Rejected by User**

1. Localizar "MFA Rejected by User"
2. Criar rule com configurações padrão
3. Esta rule detecta quando um usuário recebe e REJEITA uma notificação de MFA — sinal de MFA fatigue attack

**Resultado esperado**: 3 rules aparecem em **Analytics → Active rules** com status "Enabled".

**Verificação**:
```kql
// Verificar se as rules estão sendo executadas
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize count() by AlertName
```

---

### Passo 10: Validação Final de Ingestão

Execute a query de validação completa:

```kql
// Dashboard de validação de ingestão
// Executa no editor de Logs do Sentinel

union withsource=TableName (
    SigninLogs | project TableName = "SigninLogs", TimeGenerated
),
(
    AuditLogs | project TableName = "AuditLogs", TimeGenerated
),
(
    AzureActivity | project TableName = "AzureActivity", TimeGenerated
),
(
    OfficeActivity | project TableName = "OfficeActivity", TimeGenerated
),
(
    SecurityEvent | project TableName = "SecurityEvent", TimeGenerated
)
| where TimeGenerated > ago(2h)
| summarize 
    EventCount = count(),
    LastEvent = max(TimeGenerated)
    by TableName
| sort by LastEvent desc
```

**Resultado esperado**:

| TableName     | EventCount | LastEvent           |
|:--------------|:----------:|:--------------------|
| SigninLogs    | ≥ 50       | Dentro de 1h        |
| AuditLogs     | ≥ 5        | Dentro de 2h        |
| AzureActivity | ≥ 10       | Dentro de 1h        |
| OfficeActivity| ≥ 1        | Dentro de 2h (pode variar) |

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo de Aprendizagem                                          | Verificação                           |
|:-----:|:------------------------------------------------------------------|:--------------------------------------|
| 1-2   | Criar e configurar workspace + Sentinel                           | Sentinel Overview aparece sem erros   |
| 3     | Aplicar retenção de dados para compliance BACEN                   | SigninLogs mostra 1825 dias total     |
| 4     | Conectar fonte de identidade primária (Entra ID)                  | SigninLogs retorna registros          |
| 5     | Conectar telemetria XDR com configuração correta                  | SecurityIncident sincronizado         |
| 6-7   | Conectar fontes de atividade Azure e M365                         | AzureActivity e OfficeActivity ativos |
| 8     | Usar o Content Hub para instalar soluções prontas                 | 30+ templates disponíveis             |
| 9     | Ativar analytics rules de detecção                                | 3 rules em status Enabled             |
| 10    | Validar o ambiente completo com KQL                               | Query de validação retorna dados      |

---

## Seção 8 — Gabarito Completo

### Verificação Final — Estado Esperado do Ambiente

Após completar todos os passos, o ambiente deve ter:

**1. Workspace e Sentinel**:
```powershell
# Verificar workspace
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName "rg-meridian-secops" -Name "meridian-secops-prod"
$ws.RetentionInDays  # Deve ser 90
$ws.Location         # Deve ser "brazilsouth"
```

**2. Data Connectors — Verificação KQL**:
```kql
// Verificar todos os connectors com dados nas últimas 24h
let sources = datatable(TableName: string, ConnectorName: string) [
    "SigninLogs", "Microsoft Entra ID",
    "AuditLogs", "Microsoft Entra ID",
    "AzureActivity", "Azure Activity",
    "OfficeActivity", "Office 365"
];
sources
| join kind=inner (
    union withsource=T (SigninLogs | where TimeGenerated > ago(24h) | project T = "SigninLogs"),
           (AuditLogs | where TimeGenerated > ago(24h) | project T = "AuditLogs"),
           (AzureActivity | where TimeGenerated > ago(24h) | project T = "AzureActivity"),
           (OfficeActivity | where TimeGenerated > ago(24h) | project T = "OfficeActivity")
    | summarize LastEvent = max(TimeGenerated) by T
) on $left.TableName == $right.T
| project ConnectorName, TableName, LastEvent, Status = "Connected ✓"
```

**3. Analytics Rules Ativas — 3 rules esperadas**:
```kql
// Verificar rules ativas
_SentinelHealth
| where TimeGenerated > ago(1d)
| where SentinelResourceName == "Analytics rules"
| summarize count() by SentinelResourceKind
// Deve mostrar pelo menos 3 rules Enabled
```

**4. Configuração de Retenção — KQL de Auditoria**:
```kql
// Verificar se tabelas têm dados sendo ingeridos regularmente
let hoje = now();
union SigninLogs, AuditLogs, AzureActivity, OfficeActivity
| where TimeGenerated > ago(24h)
| summarize 
    EventsLast24h = count(),
    OldestEvent = min(TimeGenerated),
    NewestEvent = max(TimeGenerated)
    by Type
| extend DataAgeMinutes = datetime_diff('minute', hoje, NewestEvent)
| sort by DataAgeMinutes asc
```

### Erros Comuns e Soluções

| Erro                                         | Causa Provável                                 | Solução                                          |
|:---------------------------------------------|:-----------------------------------------------|:-------------------------------------------------|
| Connector aparece "Disconnected"             | Permissão insuficiente no tenant               | Verificar que a conta tem Security Admin no M365 |
| SigninLogs vazia                             | Nenhum login ocorreu após habilitar o connector| Fazer logout e login com uma conta de teste      |
| OfficeActivity sem dados                     | Connector recente — dados demoram mais         | Aguardar 30-60 min e executar alguma ação no M365|
| Analytics rules não aparecem após Content Hub| Instalação incompleta                          | Clicar em "Manage" na solução para ver o status  |
| Incidentes duplicados                        | Opção "Turn off Microsoft rules" não marcada   | Editar o conector XDR e marcar a opção           |
