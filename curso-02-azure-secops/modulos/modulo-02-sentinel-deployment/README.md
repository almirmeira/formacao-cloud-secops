# Módulo 02 — Microsoft Sentinel: Deployment e Fontes de Dados

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 4 horas (2h videoaulas + 2h laboratório)                                    |
| **Formato**              | 2 aulas gravadas + Lab 01 (hands-on)                                        |
| **Pré-requisito**        | Módulo 01 concluído; acesso ao ambiente Azure do Lab 00                     |
| **Certificação Alvo**    | SC-200 — Domínio 2: Configure a Microsoft Sentinel environment              |
| **Cenário**              | Banco Meridian — implantando o SOC a partir do zero em 48h                  |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Projetar e criar um workspace Log Analytics com as configurações corretas para um cenário bancário
2. Implantar o Microsoft Sentinel via portal, ARM template, Bicep e Terraform
3. Configurar os 15 data connectors mais importantes e validar ingestão
4. Criar e entender Data Collection Rules (DCR) com filtragem e transformação
5. Usar o Content Hub para instalar soluções, workbooks e analytics rules
6. Aplicar boas práticas de design de workspace para ambientes bancários regulados

---

## 1. Workspace Log Analytics: Design e Arquitetura

### 1.1 O que é o Log Analytics Workspace

O **Log Analytics Workspace** é o repositório de dados central do Microsoft Sentinel. É um recurso Azure que armazena todos os logs, eventos e alertas ingeridos. O Sentinel é habilitado *sobre* um workspace Log Analytics existente.

Toda query KQL executada no Sentinel consulta tabelas dentro do workspace. Todo data connector envia dados para tabelas específicas dentro do workspace. O custo do Sentinel é diretamente proporcional ao volume de dados ingeridos no workspace.

### 1.2 Modelos de Design: Workspace Dedicado vs Compartilhado

#### Workspace Dedicado por Ambiente

```
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│  WORKSPACE: prod-secops  │  │ WORKSPACE: dev-secops    │  │ WORKSPACE: dr-secops    │
│  (Sentinal habilitado)   │  │ (sem Sentinel)           │  │ (Sentinel habilitado)   │
│                           │  │                          │  │                          │
│  Fontes:                  │  │  Fontes:                 │  │  Fontes:                 │
│  - Entra ID Prod          │  │  - Entra ID Dev          │  │  - Entra ID DR           │
│  - Azure Subs Prod        │  │  - Azure Subs Dev        │  │  - Azure Subs DR         │
│  - MDE (endpoints prod)   │  │  - MDE (endpoints dev)   │  │                          │
└─────────────────────────┘  └─────────────────────────┘  └─────────────────────────┘
```

**Quando usar**: Organizações com requisitos regulatórios de separação de dados; multi-tenant MSP; separação de responsabilidades entre equipes.

**Prós**: Isolamento de dados; controle de custos por ambiente; diferentes políticas de retenção.
**Contras**: Queries cross-workspace mais complexas; custos duplicados de connectors.

#### Workspace Centralizado (Recomendado para Banco Meridian)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    WORKSPACE: meridian-secops-prod                               │
│                    (Sentinel habilitado)                                         │
│                                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │ Entra ID     │  │ MDE          │  │ MDO          │  │ Azure Activity   │    │
│  │ SigninLogs   │  │ DeviceEvents │  │ EmailEvents  │  │ AzureActivity    │    │
│  │ AuditLogs    │  │ DeviceAlerts │  │ UrlClicks    │  │ AuditLogs        │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────────┘    │
│                                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │ Syslog       │  │ CEF          │  │ AWS           │  │ SecurityEvents  │    │
│  │ (Linux/FW)   │  │ (Fortinet)   │  │ CloudTrail    │  │ (Windows AD)    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Quando usar**: Equipe SOC centralizada; correlação entre todos os ambientes; simplificação operacional.

**Prós**: Queries correlacionam dados de todas as fontes; único painel; menor overhead operacional.
**Contras**: Custo cresce com volume total; menor isolamento.

### 1.3 Retenção de Dados e Tiers

| Tier                     | Custo relativo        | Latência de query | Caso de uso                                     |
|:-------------------------|:---------------------:|:-----------------:|:------------------------------------------------|
| **Interactive (Hot)**    | Alto                  | Milissegundos     | Dados dos últimos 90 dias (padrão); investigações ativas |
| **Basic Logs**           | Baixo (~33% do Hot)   | Segundos          | Logs verbosos de alto volume (verbose DeviceEvents); não suportam alertas |
| **Archive**              | Muito baixo (~10%)    | Minutos           | Dados retidos para compliance (BACEN 4.893 exige 5 anos) |
| **Restore**              | Médio + archive       | 24h para ativar   | Restaurar dados de archive para investigação forense |

**Configuração de retenção recomendada para Banco Meridian:**

```
Tabela                │ Interactive │ Archive │ Total
──────────────────────┼─────────────┼─────────┼────────
SigninLogs            │ 90 dias     │ 4 anos  │ 5 anos
AuditLogs             │ 90 dias     │ 4 anos  │ 5 anos
SecurityEvent         │ 90 dias     │ 4 anos  │ 5 anos
DeviceEvents          │ 30 dias     │ 2 anos  │ 2,5 anos
EmailEvents           │ 90 dias     │ 2 anos  │ 2,5 anos
Syslog                │ 30 dias     │ 1 ano   │ 1,5 anos
AzureActivity         │ 90 dias     │ 4 anos  │ 5 anos
```

*Fundamentação regulatória*: Resolução BACEN 4.893/2021 art. 19 exige que incidentes relevantes sejam registrados e mantidos por, no mínimo, 5 anos.

### 1.4 Commitment Tiers (Preço por Volume)

| Commitment Tier   | GB/dia comprometido | Desconto s/ Pay-as-you-go |
|:------------------|:-------------------:|:-------------------------:|
| Pay-as-you-go     | Sem compromisso     | 0% (preço base)           |
| 100 GB/dia        | 100 GB              | ~15%                      |
| 200 GB/dia        | 200 GB              | ~20%                      |
| 300 GB/dia        | 300 GB              | ~25%                      |
| 400 GB/dia        | 400 GB              | ~28%                      |
| 500 GB/dia        | 500 GB              | ~31%                      |
| 1000 GB/dia       | 1.000 GB            | ~35%                      |
| 2000 GB/dia       | 2.000 GB            | ~40%                      |
| 5000 GB/dia       | 5.000 GB            | ~50%                      |

*Nota*: Comprometer um tier garante desconto. Se exceder o tier, o excedente é cobrado ao preço Pay-as-you-go. O Sentinel aplica um desconto de 50% sobre a ingestão de dados para tabelas do Microsoft 365 Defender quando o workspace está vinculado ao mesmo tenant (Microsoft Defender XDR benefit).

### 1.5 Estimativa de Volume para Banco Meridian

| Fonte                      | Volume estimado/dia |
|:---------------------------|:-------------------:|
| Entra ID (SigninLogs)      | ~2 GB               |
| MDE (DeviceEvents)         | ~8 GB               |
| MDO (EmailEvents)          | ~1,5 GB             |
| Azure Activity             | ~0,5 GB             |
| SecurityEvent (DCs)        | ~3 GB               |
| CEF/Syslog (Fortinet)      | ~2 GB               |
| AWS CloudTrail             | ~0,5 GB             |
| **Total estimado**         | **~17,5 GB/dia**    |

*Recomendação*: Commitment tier de 200 GB/dia com 3 meses de monitoramento para ajuste fino. Usar DCR para filtrar eventos de baixo valor antes da ingestão.

---

## 2. Deployment do Microsoft Sentinel

### 2.1 Via Portal Azure (Manual)

```
1. Portal Azure → "Create a resource" → "Microsoft Sentinel"
2. "Create a new workspace" (ou selecionar existente)
   - Resource Group: rg-meridian-secops
   - Workspace Name: meridian-secops-prod
   - Region: Brazil South (ou East US 2 se não disponível na região)
   - Pricing Tier: Pay-As-You-Go (ajustar após validar volume)
3. "Review + Create" → "Create"
4. Aguardar provisionamento (2-5 minutos)
5. No workspace criado → "Microsoft Sentinel" → "Add Microsoft Sentinel"
6. Selecionar o workspace → "Add"
```

### 2.2 Via ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspaceName": {
      "type": "string",
      "defaultValue": "meridian-secops-prod"
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]"
    },
    "retentionInDays": {
      "type": "int",
      "defaultValue": 90
    }
  },
  "resources": [
    {
      "type": "Microsoft.OperationalInsights/workspaces",
      "apiVersion": "2022-10-01",
      "name": "[parameters('workspaceName')]",
      "location": "[parameters('location')]",
      "properties": {
        "sku": {
          "name": "PerGB2018"
        },
        "retentionInDays": "[parameters('retentionInDays')]",
        "features": {
          "searchVersion": 1,
          "enableLogAccessUsingOnlyResourcePermissions": true
        }
      }
    },
    {
      "type": "Microsoft.SecurityInsights/onboardingStates",
      "apiVersion": "2022-12-01-preview",
      "name": "default",
      "scope": "[concat('Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]",
      "dependsOn": [
        "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
      ],
      "properties": {}
    }
  ]
}
```

### 2.3 Via Bicep

```bicep
// sentinel-workspace.bicep
// Implantação do Microsoft Sentinel para o Banco Meridian

@description('Nome do workspace Log Analytics')
param workspaceName string = 'meridian-secops-prod'

@description('Localização dos recursos')
param location string = resourceGroup().location

@description('Retenção de dados em dias (90 = padrão; até 730 no tier interativo)')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('SKU do workspace')
@allowed(['PerGB2018', 'CapacityReservation'])
param sku string = 'PerGB2018'

@description('Capacidade reservada em GB/dia (0 = Pay-as-you-go)')
param capacityReservationLevel int = 0

// Workspace Log Analytics
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: sku
      capacityReservationLevel: sku == 'CapacityReservation' ? capacityReservationLevel : null
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: 50 // limite de segurança; ajustar para produção
    }
  }
}

// Habilitar Microsoft Sentinel no workspace
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2022-12-01-preview' = {
  name: 'default'
  scope: workspace
  properties: {}
}

// Outputs
output workspaceId string = workspace.id
output workspaceName string = workspace.name
output sentinelWorkspaceResourceId string = workspace.id
```

### 2.4 Via Terraform

```hcl
# sentinel.tf
# Provisionamento do Microsoft Sentinel — Banco Meridian
# Versão do provider: azurerm >= 3.70.0

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.70.0"
    }
  }
  
  backend "azurerm" {
    resource_group_name  = "rg-meridian-terraform-state"
    storage_account_name = "stmeridiante"
    container_name       = "tfstate"
    key                  = "sentinel.tfstate"
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# Resource Group
resource "azurerm_resource_group" "secops" {
  name     = "rg-meridian-secops"
  location = "brazilsouth"
  
  tags = {
    environment = "production"
    project     = "secops"
    owner       = "SOC"
    costcenter  = "IT-Security"
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "meridian-secops-prod"
  location            = azurerm_resource_group.secops.location
  resource_group_name = azurerm_resource_group.secops.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  # Limite diário de ingestão (segurança de custo)
  daily_quota_gb = 50

  tags = azurerm_resource_group.secops.tags
}

# Habilitar Microsoft Sentinel
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel.id
}

# Retenção personalizada por tabela (exemplo: SigninLogs)
resource "azurerm_log_analytics_workspace_table" "signinlogs" {
  workspace_id      = azurerm_log_analytics_workspace.sentinel.id
  name              = "SigninLogs"
  retention_in_days = 90
  total_retention_in_days = 1825 # 5 anos (90 dias hot + restante archive)
}

# Diagnóstico de custo — alerta quando >80% do limite diário
resource "azurerm_monitor_metric_alert" "workspace_cap" {
  name                = "sentinel-daily-cap-alert"
  resource_group_name = azurerm_resource_group.secops.name
  scopes              = [azurerm_log_analytics_workspace.sentinel.id]
  description         = "Alerta quando o workspace atinge 80% do limite diário de ingestão"

  criteria {
    metric_namespace = "Microsoft.OperationalInsights/workspaces"
    metric_name      = "DataIngestion"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 40 # 80% de 50 GB
  }

  action {
    action_group_id = var.soc_action_group_id
  }
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.sentinel.id
}

output "workspace_customer_id" {
  value = azurerm_log_analytics_workspace.sentinel.workspace_id
}
```

---

## 3. Data Connectors: Os 15 Mais Importantes

### 3.1 Tabela Completa dos Data Connectors

| #  | Conector                              | Tipo            | Tabelas Geradas                               | Licença Mínima    |
|:---|:--------------------------------------|:---------------:|:----------------------------------------------|:-----------------:|
| 1  | Microsoft Entra ID                    | REST API (S2S)  | SigninLogs, AuditLogs, AADNonInteractiveUserSigninLogs, AADServicePrincipalSigninLogs | Entra ID P1 |
| 2  | Microsoft Defender XDR                | S2S (Nativo)    | SecurityAlert, SecurityIncident, DeviceEvents, EmailEvents, IdentityLogonEvents | M365 E5 / Defender XDR |
| 3  | Microsoft Defender for Endpoint       | S2S (Nativo)    | DeviceAlertEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents | MDE P2 |
| 4  | Microsoft Defender for Identity       | S2S (Nativo)    | IdentityLogonEvents, IdentityDirectoryEvents, IdentityQueryEvents | MDI |
| 5  | Microsoft Defender for Office 365     | S2S (Nativo)    | EmailEvents, EmailAttachmentInfo, EmailUrlInfo | MDO P2 |
| 6  | Microsoft Defender for Cloud          | S2S (Nativo)    | SecurityAlert, SecurityRecommendation         | Defender for Cloud |
| 7  | Azure Activity                        | REST API / DCR  | AzureActivity                                 | Qualquer Azure     |
| 8  | Azure Active Directory Identity Prot. | S2S (Nativo)    | SecurityAlert (risk events)                   | Entra ID P2        |
| 9  | Office 365 (Exchange/SharePoint)      | REST API (S2S)  | OfficeActivity                                | M365 E3+           |
| 10 | Windows Security Events (AMA)         | AMA via DCR     | SecurityEvent, WindowsEvent                   | Log Analytics agent|
| 11 | Syslog (Linux)                        | AMA via DCR     | Syslog                                        | AMA agent          |
| 12 | Common Event Format (CEF)             | AMA via DCR     | CommonSecurityLog                             | AMA + forwarder    |
| 13 | AWS CloudTrail                        | REST API (Pull) | AWSCloudTrail                                 | Permissão AWS IAM  |
| 14 | Google Cloud Platform                 | REST API (Pull) | GCPAuditLogs, GCPIAMPolicy                    | Permissão GCP SA   |
| 15 | Threat Intelligence (TAXII)           | TAXII 2.0/2.1   | ThreatIntelligenceIndicator                   | TI feed URL+auth   |

**Legendas de tipo**:
- **S2S (Service-to-Service)**: Conexão direta entre tenants Microsoft sem agente
- **REST API**: Sentinel chama uma API ou recebe eventos via webhook
- **AMA via DCR**: Azure Monitor Agent + Data Collection Rule (substitui o MMA legado)
- **Pull**: Sentinel busca logs periodicamente na plataforma de origem

### 3.2 Connectors Microsoft (Detalhamento)

#### Conector: Microsoft Entra ID

**Habilitação**:
```
Sentinel → Data connectors → Microsoft Entra ID → Open connector page
→ Marcar: "Sign-in Logs", "Audit Logs", "Non-Interactive User Sign-In Logs"
→ "Apply Changes"
```

**Verificação pós-habilitação (aguardar 15 minutos)**:
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| count
```

#### Conector: Microsoft Defender XDR

Este conector é o mais importante. Sincroniza incidentes, alertas e telemetria avançada de MDE, MDI, MDO e MDA.

**Configurações críticas**:
- Ativar "Automatic incident creation": o XDR cria incidentes no Sentinel automaticamente
- Ativar "Turn off all Microsoft incident creation rules": evitar duplicação (Sentinel NÃO deve criar incidentes separados para alertas do XDR; o XDR já os correlaciona)
- Selecionar as tabelas avançadas: DeviceEvents, DeviceProcessEvents, EmailEvents, etc.

### 3.3 Connectors AWS CloudTrail

**Requisitos**:
- Conta AWS com CloudTrail habilitado
- Role IAM com permissões: `cloudtrail:GetTrail`, `cloudtrail:ListTrails`, `s3:GetObject`, `s3:ListBucket`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`

**Arquitetura de ingestão**:
```
CloudTrail → S3 Bucket → SQS Queue → Sentinel AWS Connector → AWSCloudTrail table
```

**Configuração no Sentinel**:
```
Data Connectors → Amazon Web Services S3 → Open connector page
→ External ID: [copiar do portal]
→ ARN da role IAM criada na AWS
→ SQS URL do bucket CloudTrail
→ "Add"
```

### 3.4 Connector CEF/Syslog para Fortinet (Banco Meridian)

O Banco Meridian usa firewalls Fortinet FortiGate (sistema legado). A ingestão é via CEF sobre syslog.

**Arquitetura**:
```
FortiGate (syslog UDP/TCP 514)
        ↓
Linux Forwarder VM (rsyslog + AMA)
        ↓ (AMA via DCR)
Log Analytics Workspace → CommonSecurityLog table
```

**Configuração do FortiGate**:
```
config log syslogd setting
  set status enable
  set server "10.0.1.20"    # IP do Linux forwarder
  set port 514
  set facility local7
  set format cef
end
```

---

## 4. Data Collection Rules (DCR)

### 4.1 O que são DCRs e por que importam

As **Data Collection Rules** são o mecanismo moderno de coleta de dados no Azure Monitor e Log Analytics. Elas definem:
- **O quê** coletar (quais logs, quais tabelas, quais campos)
- **De onde** coletar (quais VMs, quais recursos)
- **Para onde** enviar (qual workspace, qual tabela)
- **Como transformar** os dados antes de ingerir (filtrar campos, renomear, descartar eventos desnecessários)

As DCRs substituem o antigo Microsoft Monitoring Agent (MMA) e permitem filtragem *antes* da ingestão, reduzindo custos significativamente.

### 4.2 Arquitetura de DCR

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            FLUXO DE DCR                                         │
│                                                                                   │
│  [Fonte]         [DCR]                           [Destino]                       │
│                                                                                   │
│  VM Windows  ──► DCR: Win-Security-Events                                        │
│  (AMA)          │  Data Source: Windows Event Log                               │
│                 │  Filter: Security Events 4624, 4625, 4672, 4688               │
│                 │  Transformation: drop(EventID == 4634)                        │
│                 └──► workspace/SecurityEvent                                    │
│                                                                                   │
│  VM Linux    ──► DCR: Linux-Syslog                                               │
│  (AMA)          │  Data Source: Syslog                                          │
│                 │  Filter: facility=auth,authpriv,kern severity>=warning        │
│                 └──► workspace/Syslog                                           │
│                                                                                   │
│  CEF Fwd.    ──► DCR: CEF-Fortinet                                               │
│  (AMA)          │  Data Source: CommonSecurityLog                               │
│                 │  Filter: DeviceVendor == "Fortinet"                           │
│                 └──► workspace/CommonSecurityLog                                │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Criando uma DCR com Transformação via Bicep

```bicep
// dcr-windows-security.bicep
// DCR para coletar apenas eventos de segurança críticos do Windows
// Exclui EventID 4634 (logoff) para reduzir volume de ingestão

resource dcrWindowsSecurity 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'dcr-meridian-windows-security'
  location: 'brazilsouth'
  properties: {
    description: 'Coleta eventos de segurança Windows com filtragem de ruído'
    
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: [
            // Apenas eventos críticos de segurança
            'Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4656 or EventID=4672 or EventID=4688 or EventID=4698 or EventID=4720 or EventID=4726 or EventID=4728 or EventID=4732 or EventID=4738 or EventID=4740 or EventID=4756 or EventID=4767 or EventID=4771 or EventID=4776 or EventID=4798 or EventID=4799)]]'
          ]
        }
      ]
    }
    
    destinations: {
      logAnalytics: [
        {
          name: 'sentinelWorkspace'
          workspaceResourceId: '/subscriptions/${subscription().subscriptionId}/resourceGroups/rg-meridian-secops/providers/Microsoft.OperationalInsights/workspaces/meridian-secops-prod'
        }
      ]
    }
    
    dataFlows: [
      {
        streams: ['Microsoft-SecurityEvent']
        destinations: ['sentinelWorkspace']
        transformKql: '''
          source
          | where EventID != 4634     // Exclui logoff (alto volume, baixo valor)
          | where EventID != 4648     // Exclui credential validation (ruído em DCs)
          | project TimeGenerated, EventID, Computer, Account, SubjectUserName, 
                    TargetUserName, IpAddress, LogonType, ProcessName, CommandLine
        '''
        outputStream: 'Microsoft-SecurityEvent'
      }
    ]
  }
}
```

### 4.4 Transformações Úteis para Reduzir Custos

```kql
// Exemplo de transformação KQL numa DCR
// Remove eventos de alta frequência e baixo valor de segurança

source
// Remove eventos de logoff (EventID 4634) — alto volume, geralmente irrelevante
| where EventID != 4634
// Remove sucesso de logoff de contas de serviço com nome padrão
| where not (EventID == 4624 and LogonType == 5 and TargetUserName endswith "$")
// Mantém todos os eventos de falha de autenticação
// Mantém todos os eventos de criação de processos (4688)
// Remove noise do Windows Defender Antivirus (EventID 5001)
| where EventID != 5001
// Projeta apenas as colunas necessárias (reduz tamanho do evento)
| project TimeGenerated, EventID, Computer, Account, SubjectUserName,
          TargetUserName, IpAddress, LogonType, ProcessName, 
          CommandLine, PrivilegeList, LogonProcessName
```

---

## 5. Content Hub: Soluções, Workbooks e Analytics Packages

### 5.1 O que é o Content Hub

O **Content Hub** é o marketplace de conteúdo de segurança do Sentinel. Contém mais de 200 soluções mantidas pela Microsoft e pela comunidade, organizadas por:
- **Produto** (Microsoft Entra ID, Palo Alto, Fortinet)
- **Categoria** (Identity, Endpoint, Network, Cloud)
- **Tipo de conteúdo** (Analytics rules, Workbooks, Hunting queries, Playbooks)

### 5.2 Soluções Recomendadas para Banco Meridian

| Solução                              | Conteúdo incluído                                          | Prioridade |
|:-------------------------------------|:-----------------------------------------------------------|:----------:|
| Microsoft Entra ID                   | 30+ analytics rules, 15 workbooks, 20+ hunting queries     | Alta       |
| Microsoft 365 Defender               | 50+ rules, unified incident queue, MITRE coverage         | Alta       |
| Defender for Cloud                   | 20+ rules, CSPM workbook, regulatory compliance           | Alta       |
| Azure Activity                       | 25+ rules, Azure operations workbook                      | Alta       |
| Fortinet FortiGate                   | CEF parser, 15+ rules, network workbook                   | Alta       |
| UEBA (User Entity Behavior Analytics)| Anomaly rules, user investigation workbook                | Média      |
| Threat Intelligence                  | TI matching rules, IOC workbook, TAXII connector          | Média      |
| MITRE ATT&CK                         | Coverage workbook, tactic-based hunting                   | Média      |
| AWS                                  | CloudTrail parser, 20+ rules, AWS activity workbook       | Baixa*     |

*Baixa prioridade na fase inicial; aumentar após onboarding do AWS CloudTrail.

### 5.3 Instalando uma Solução via Content Hub

```
Sentinel → Content Hub → Pesquisar "Microsoft Entra ID"
→ Selecionar "Microsoft Entra ID" (Microsoft)
→ "View details" → "Install"
→ Aguardar instalação (1-5 minutos)
→ "Manage" para ver e ativar analytics rules instaladas
```

**Importante**: A instalação apenas *disponibiliza* o conteúdo. Analytics rules precisam ser **ativadas** manualmente para começar a gerar alertas.

---

## 6. Schema das Tabelas Mais Importantes

### 6.1 SigninLogs — Autenticações Entra ID

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| UserPrincipalName       | string      | UPN do usuário (rafael.torres@bancomeridian.com.br)    |
| UserId                  | string      | ID único do usuário no Entra ID                        |
| AppDisplayName          | string      | Aplicação acessada (Office 365, Azure Portal)          |
| IPAddress               | string      | IP do cliente                                          |
| Location                | string      | Localização geográfica (cidade/país)                   |
| ResultType              | int         | 0 = Sucesso; outros = código de erro                   |
| ResultDescription       | string      | Descrição do resultado                                 |
| ConditionalAccessStatus | string      | success, failure, notApplied                          |
| RiskLevelDuringSignIn   | string      | none, low, medium, high                               |
| RiskState               | string      | none, confirmedSafe, remediated, atRisk                |
| DeviceDetail            | dynamic     | deviceId, operatingSystem, browser, isCompliant        |
| NetworkLocationDetails  | dynamic     | Detalhes de rede (IP trust type)                      |
| AuthenticationDetails   | dynamic     | Métodos de autenticação usados                        |
| IsInteractive           | bool        | Login interativo ou silencioso                        |
| ClientAppUsed           | string      | Browser, móvel, legacy protocol                       |

### 6.2 AuditLogs — Atividades Administrativas Entra ID

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| OperationName           | string      | Operação executada (Add user, Reset password)          |
| InitiatedBy             | dynamic     | Quem iniciou (user ou serviço)                         |
| TargetResources         | dynamic     | Objeto modificado (usuário, grupo, app)                |
| Result                  | string      | success, failure                                       |
| ResultDescription       | string      | Detalhes do resultado                                  |
| Category                | string      | UserManagement, GroupManagement, Policy, etc.         |
| LoggedByService         | string      | B2C, Core Directory, PIM, etc.                        |
| CorrelationId           | string      | ID de correlação para rastrear operações relacionadas  |

### 6.3 SecurityEvent — Eventos Windows (via AMA)

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| EventID                 | int         | ID do evento Windows (4624=logon, 4688=processo)       |
| Computer                | string      | Hostname do computador                                 |
| Account                 | string      | Conta que iniciou o evento (DOMAIN\user)               |
| SubjectUserName         | string      | Usuário sujeito do evento                              |
| TargetUserName          | string      | Usuário alvo da ação                                   |
| LogonType               | int         | 2=interativo, 3=rede, 5=serviço, 10=remoto             |
| IpAddress               | string      | IP de origem (para logons de rede)                     |
| ProcessName             | string      | Processo que iniciou a ação (para 4688)                |
| CommandLine             | string      | Linha de comando completa (para 4688)                  |
| PrivilegeList           | string      | Privilégios usados (para 4672)                         |

### 6.4 Syslog — Logs Linux

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| Computer                | string      | Hostname do servidor Linux                             |
| Facility                | string      | auth, authpriv, kern, daemon, user, syslog             |
| SeverityLevel           | string      | debug, info, notice, warning, error, critical, alert   |
| HostName                | string      | Nome do host que gerou o log                           |
| ProcessName             | string      | Processo que gerou o log (sshd, sudo, cron)            |
| ProcessID               | int         | PID do processo                                        |
| SyslogMessage           | string      | Mensagem completa do log                               |

### 6.5 CommonSecurityLog — CEF (Fortinet, Palo Alto, etc.)

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| DeviceVendor            | string      | Fabricante do dispositivo (Fortinet, Palo Alto)        |
| DeviceProduct           | string      | Produto (FortiGate, PAN-OS)                            |
| DeviceAction            | string      | Ação executada (permit, deny, drop)                    |
| SourceIP                | string      | IP de origem do tráfego                                |
| DestinationIP           | string      | IP de destino do tráfego                               |
| SourcePort              | int         | Porta de origem                                        |
| DestinationPort         | int         | Porta de destino                                       |
| Protocol                | string      | Protocolo (TCP, UDP, ICMP)                             |
| Activity                | string      | Descrição da atividade                                 |
| SimplifiedDeviceAction  | string      | Simplified action for common use                       |
| AdditionalExtensions    | string      | Campos CEF adicionais específicos do produto           |

### 6.6 OfficeActivity — Microsoft 365

| Campo                   | Tipo        | Descrição                                              |
|:------------------------|:-----------:|:-------------------------------------------------------|
| TimeGenerated           | datetime    | Momento do evento                                      |
| UserId                  | string      | E-mail do usuário                                      |
| Operation               | string      | Operação (FileAccessed, FileCopied, MailSent, etc.)    |
| RecordType              | string      | ExchangeItem, SharePointFile, AzureActiveDirectory     |
| ItemType                | string      | Tipo do item (File, Folder, Email)                     |
| ObjectId                | string      | URL ou caminho do objeto acessado                      |
| ClientIP                | string      | IP do cliente                                          |
| UserAgent               | string      | Browser/aplicativo usado                               |
| Workload                | string      | Exchange, SharePoint, OneDrive, Teams                  |
| SiteUrl                 | string      | URL do site SharePoint/OneDrive                        |
| SourceFileName          | string      | Nome do arquivo                                        |

---

## 7. Boas Práticas de Design de Workspace

### 7.1 Recomendações para Ambientes Bancários

**1. Um workspace por tenant de produção**
O Banco Meridian deve ter um único workspace de produção. Múltiplos workspaces dificultam correlação cruzada e aumentam custos de connectors.

**2. Separar dados de desenvolvimento**
Criar workspace separado `meridian-secops-dev` sem Sentinel habilitado para testes de analytics rules e DCRs antes de promover para produção.

**3. Aplicar RBAC granular**
```
Security Reader:  consulta de logs e investigação (SOC L1)
Security Analyst: + criação de analytics rules (SOC L2/L3)
Security Operator: + execução de playbooks
Sentinel Contributor: + configuração de connectors e workbooks
Sentinel Owner: controle total (CISO, Tech Lead)
```

**4. Alertas de custo**
Configurar Azure Budget com alerta em 80% do orçamento mensal. Configurar Daily Cap no workspace (não recomendado para produção — pode interromper ingestão de logs críticos; usar apenas em dev).

**5. Workspace com restrição geográfica**
Para compliance BACEN/LGPD: usar region Brazil South (São Paulo) para garantir que dados de cidadãos brasileiros permaneçam no Brasil. Verificar data residency dos logs do M365 (pode exigir tenant em Brazil South).

**6. Evitar mistura de dados de diferentes clientes**
Para MSPs que gerenciam múltiplos bancos: usar workspaces separados por cliente com Azure Lighthouse para acesso centralizado. Não misturar dados de diferentes organizações no mesmo workspace.

### 7.2 Checklist de Workspace para Banco Meridian

```
[ ] Workspace criado em Brazil South
[ ] Retenção configurada por tabela (90 dias hot, 5 anos total para compliance)
[ ] Daily cap configurado (apenas em dev; remover em prod)
[ ] RBAC configurado com grupos AD sincronizados pelo Entra ID
[ ] Budget alert configurado (80% do limite mensal)
[ ] Commitment tier selecionado após 30 dias de monitoramento de volume
[ ] DCRs criadas para filtrar eventos desnecessários antes da ingestão
[ ] Diagnostic settings do workspace habilitado (auditoria de quem consultou o quê)
[ ] Private Endpoint configurado se exigido pela política de rede do banco
```

---

## 8. Atividades de Fixação

### Questão 1
O Banco Meridian precisa manter logs de autenticação (SigninLogs) por 5 anos para atender à Resolução BACEN 4.893. Qual é a configuração correta de retenção no Log Analytics Workspace?

a) Configurar 5 anos (1825 dias) no tier Interactive (Hot) para todos os dados  
b) Configurar 90 dias no tier Interactive e adicionar 1735 dias no tier Archive, totalizando 1825 dias  
c) Criar um Storage Account separado e exportar os logs manualmente via script  
d) O Log Analytics só suporta retenção de até 2 anos; usar Azure Blob Storage para o restante  

**Gabarito: B** — O Log Analytics suporta até 730 dias no tier Interactive e permite configurar Archive (Auxiliary Logs) para estender a retenção total até 12 anos. Para 5 anos com custo otimizado: 90 dias Interactive (consulta rápida para investigações recentes) + 1.735 dias Archive (retenção de compliance, restaurável quando necessário). O tier Archive custa ~10% do tier Interactive, tornando a solução econômica.

---

### Questão 2
Qual é a principal vantagem das Data Collection Rules (DCR) em relação ao Microsoft Monitoring Agent (MMA) legado?

a) As DCRs suportam mais sistemas operacionais do que o MMA  
b) As DCRs permitem filtrar e transformar dados ANTES da ingestão no workspace, reduzindo volume ingerido e custo  
c) As DCRs são mais fáceis de instalar que o agente MMA  
d) As DCRs eliminam a necessidade de qualquer agente nos servidores Linux  

**Gabarito: B** — A transformação em DCR (campo `transformKql`) processa os dados no pipeline antes de chegarem ao workspace. Isso significa que eventos de baixo valor (ex.: EventID 4634 logoff, que pode ser 30-40% do volume de Security Events) são descartados antes de serem cobrados. Com MMA, todos os eventos eram ingeridos e só então filtrados nas queries — você pagava por tudo. As DCRs também permitem projetar apenas colunas necessárias, reduzindo ainda mais o tamanho dos eventos.

---

### Questão 3
O Banco Meridian está configurando o data connector do Microsoft Defender XDR no Sentinel. A opção "Turn off all Microsoft incident creation rules" deve ser:

a) Desabilitada, para que o Sentinel crie incidentes adicionais para cada alerta do XDR  
b) Habilitada, para evitar duplicação: o XDR já correlaciona alertas em incidentes; o Sentinel deve usar esses incidentes em vez de criar novos  
c) Irrelevante — o Sentinel e o XDR gerenciam incidentes completamente independentes  
d) Habilitada apenas se o banco tiver menos de 100 GB/dia de ingestão  

**Gabarito: B** — Quando o conector Microsoft Defender XDR está configurado, o XDR já correlaciona automaticamente alertas de MDE, MDI, MDO e MDA em incidentes unificados. Se o Sentinel também criar incidentes para cada alerta individual, o resultado são incidentes duplicados: um do XDR (correlacionado, rico) e vários do Sentinel (por alerta, fragmentado). Habilitar "Turn off all Microsoft incident creation rules" garante que apenas os incidentes do XDR sejam usados no Sentinel, evitando duplicação e confusão para os analistas.

---

### Questão 4
Qual é o schema correto para identificar logins de alto risco no Entra ID a partir da tabela SigninLogs?

a) `SigninLogs | where ResultType == "HighRisk"`  
b) `SigninLogs | where RiskLevelDuringSignIn in ("medium", "high") and ResultType == 0`  
c) `SecurityEvent | where EventID == 4625 and RiskLevel == "high"`  
d) `AuditLogs | where Category == "SignIn" and RiskState == "atRisk"`  

**Gabarito: B** — Na tabela `SigninLogs`, o campo `RiskLevelDuringSignIn` contém o nível de risco avaliado pelo Entra ID Protection no momento do login: "none", "low", "medium", "high". O campo `ResultType == 0` indica login bem-sucedido. Portanto, a query filtra logins bem-sucedidos de alto ou médio risco — exatamente o que uma analytics rule de detecção de conta comprometida precisa. As outras opções usam tabelas incorretas (SecurityEvent é para eventos Windows locais, não Entra ID).

---

### Questão 5
O Banco Meridian tem firewalls Fortinet FortiGate que precisam enviar logs para o Sentinel via CEF. Qual é a arquitetura correta?

a) FortiGate → Azure Event Hub → Sentinel (conector Event Hub)  
b) FortiGate (syslog CEF) → Linux VM com AMA + DCR → Log Analytics Workspace (CommonSecurityLog)  
c) FortiGate → Storage Account → Sentinel (conector Blob Storage)  
d) FortiGate → FortiAnalyzer → Microsoft API → Sentinel (conector REST)  

**Gabarito: B** — A arquitetura correta para CEF é: o FortiGate envia logs em formato CEF via syslog (UDP/TCP 514) para um servidor Linux intermediário (forwarder). Esse servidor tem o Azure Monitor Agent (AMA) instalado, que encaminha os logs para o Log Analytics Workspace via DCR configurada para CEF/CommonSecurityLog. Não usar Storage Account (latência alta), nem Event Hub (arquitetura diferente, usada para streaming), nem FortiAnalyzer como intermediário (introduz dependência adicional).

---

## 9. Roteiros de Gravação

### Aula 2.1 — Workspace Log Analytics e Data Connectors (45 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Formato: screen share do portal Azure (90%) + talking head (10%)
- Tenant de demonstração: tenant do laboratório CECyber
- Preparar: workspace `meridian-secops-demo` pré-criado com Sentinel habilitado
- Ter dados ingeridos (pelo menos 24h antes da gravação para SigninLogs aparecerem)

---

**[0:00 — ABERTURA | 2 minutos]**

"Bem-vindos ao Módulo 2! Hoje vamos sair da teoria e começar a construir. Nesta aula, vamos implantar o Microsoft Sentinel do zero, entender como o workspace funciona por dentro e conectar as primeiras fontes de dados.

O cenário é o seguinte: o CISO do Banco Meridian aprovou o projeto. Temos 48 horas para ter o SOC operacional. Vamos começar agora."

---

**[2:00 — BLOCO 1: CRIANDO O WORKSPACE | 8 minutos]**

*[Screen share: Portal Azure]*

"Abro o portal Azure — portal.azure.com — e vou em 'Create a resource'. Pesquiso 'Microsoft Sentinel'.

*[Executar no portal]*

Clico em 'Create'. O Sentinel precisa de um workspace Log Analytics. Posso criar um novo ou usar um existente. No caso do banco, vamos criar um workspace dedicado para segurança — separado dos workspaces de monitoramento de aplicação.

Configurações: Resource Group: rg-meridian-secops. Nome: meridian-secops-prod. Região: Brazil South. Por que Brazil South? Porque os dados de log de funcionários brasileiros precisam permanecer no Brasil — isso é uma exigência da LGPD e uma boa prática BACEN.

*[DICA DE EDIÇÃO: mostrar o preenchimento de cada campo com zoom no formulário]*

Pricing Tier: PerGB2018 — é o modelo pay-as-you-go. Vamos manter assim por 30 dias para medir o volume antes de decidir sobre commitment tier.

Retention: 90 dias. Vamos configurar retenção por tabela depois.

Review + Create → Create. Aguardar o provisionamento.

Enquanto cria, vou mostrar o que acabou de acontecer: um workspace Log Analytics que é o banco de dados do nosso SIEM. Toda query que vamos escrever nos próximos módulos vai consultar tabelas dentro desse workspace."

---

**[10:00 — BLOCO 2: HABILITANDO O SENTINEL | 5 minutos]**

"Workspace criado. Agora habilitar o Sentinel. Vou no workspace criado → Microsoft Sentinel (no menu lateral) → Add Microsoft Sentinel → seleciono o workspace → Add.

*[Screen share mostrando o processo]*

Pronto. Em 2 minutos o Sentinel está habilitado. O portal do Sentinel aparece agora. Vou mostrar as seções principais: Overview (dashboard), Incidents, Analytics, Automation, Hunting, Workbooks, Data connectors.

O workspace está vazio — nenhum dado ainda. Vamos corrigir isso."

---

**[15:00 — BLOCO 3: CONECTANDO FONTES DE DADOS | 20 minutos]**

"Vou para Data Connectors. São mais de 200 conectores disponíveis. Para o Banco Meridian, vamos ativar 6 hoje.

**Conector 1: Microsoft Entra ID**

*[Screen share: Data connectors → pesquisar Entra ID]*

Abro o conector, clico em 'Open connector page'. Vejo as instruções de pré-requisito: preciso de permissão Global Admin ou Security Admin no tenant.

Seleciono: Sign-in Logs ✓, Audit Logs ✓, Non-Interactive Sign-In Logs ✓. Apply Changes.

O que acabou de acontecer? O Sentinel começou a puxar os logs de autenticação de 2.800 usuários do Banco Meridian. Em 15 minutos, dados chegam na tabela SigninLogs.

**Conector 2: Microsoft Defender XDR**

Este é o mais crítico. Conecta MDE, MDI, MDO e MDA simultaneamente.

*[Screen share: configurar o conector Defender XDR]*

Ponto importante: aqui preciso ativar 'Turn off all Microsoft incident creation rules'. Vou explicar por quê. O Defender XDR já correlaciona alertas de 4 produtos em incidentes unificados. Se eu deixar o Sentinel criar incidentes separados para cada alerta, o analista vai ver o mesmo ataque dividido em 5 incidentes diferentes. Com essa opção ativada, o Sentinel usa os incidentes que o XDR já criou — correlacionados, completos.

Seleciono também as tabelas avançadas: DeviceEvents, EmailEvents, IdentityLogonEvents.

**Conector 3: Azure Activity**

Simples — dois cliques. Conecta os logs de todas as operações no Azure (criar VM, alterar NSG, deletar recurso). Vai para a tabela AzureActivity. Essencial para detectar comprometimento de conta de administrador Azure.

**Conector 4: Office 365**

Conecta Exchange Online, SharePoint e Teams. Vai para a tabela OfficeActivity. Fundamental para detectar regras de encaminhamento de e-mail maliciosas e exfiltração via SharePoint.

**Conector 5: AWS CloudTrail** (brevemente — demo completo no Lab 06)

Mostro a configuração brevemente. Precisa de role IAM na AWS. Vou passar rapidamente porque o Lab 06 faz isso em detalhe.

**Conector 6: CEF via AMA** (Fortinet)

Este é o mais complexo. Precisa de um servidor Linux intermediário. Mostro a arquitetura: FortiGate → Linux forwarder com AMA → Sentinel.

*[DICA DE EDIÇÃO: adicionar diagrama animado do fluxo CEF antes da configuração]*

Vou mostrar o comando de instalação do AMA no Linux forwarder:

```bash
# Na VM Linux forwarder (Ubuntu 20.04)
wget https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_installer.py
sudo python3 cef_installer.py [workspace-id] [primary-key]
```

*[PAUSA PARA DICA DE EDIÇÃO: mostrar tela do portal e diagrama simultaneamente em split screen]*"

---

**[35:00 — BLOCO 4: VALIDANDO INGESTÃO | 8 minutos]**

"Passaram 20 minutos desde que ativamos os conectores. Vamos verificar se os dados chegaram.

Vou em Logs → abro o editor de queries KQL.

```kql
// Verificar ingestão das últimas 2 horas
union SigninLogs, AuditLogs, AzureActivity, OfficeActivity, CommonSecurityLog
| where TimeGenerated > ago(2h)
| summarize count() by Type
| sort by count_ desc
```

*[Executar a query no portal]*

Perfeito! SigninLogs já tem dados. AzureActivity também. CEF/CommonSecurityLog ainda não — faz sentido, precisamos configurar o FortiGate para enviar para o forwarder.

No próximo bloco, vamos falar de Data Collection Rules e como otimizar o que estamos ingerindo para controlar custos."

---

**[43:00 — ENCERRAMENTO | 2 minutos]**

"Recapitulando: criamos o workspace, habilitamos o Sentinel, conectamos 5 fontes de dados e validamos que a ingestão está funcionando. O SOC começa a ter visibilidade.

Na próxima aula, vamos falar de Data Collection Rules — como filtrar ruído ANTES da ingestão para controlar custos — e do Content Hub, onde instalamos analytics rules prontas criadas pela Microsoft.

Façam o Lab 01 para praticar tudo isso no ambiente de vocês. O gabarito está no repositório do curso."

---

### Aula 2.2 — DCR e Content Hub (45 minutos)

---

**[0:00 — ABERTURA | 2 minutos]**

"Continuando o Módulo 2. Na última aula conectamos as fontes de dados. Agora temos um problema interessante: estamos ingerindo muito ruído. Eventos de logoff a cada segundo, processos do sistema a cada minuto. Isso eleva o custo sem agregar valor ao SOC.

Data Collection Rules é a solução. Vamos aprender a filtrar dados antes de ingeri-los e depois explorar o Content Hub para instalar análises prontas."

---

**[2:00 — BLOCO 1: DCR NA PRÁTICA | 18 minutos]**

*[Screen share: Azure Monitor → Data Collection Rules]*

"Abro o Azure Monitor, não o Sentinel — as DCRs são um recurso do Azure Monitor, usadas pelo Sentinel via workspace.

Vou criar uma DCR para coletar eventos de segurança dos domain controllers do Banco Meridian.

New DCR → nome: dcr-meridian-dc-security → plataforma: Windows.

Data Sources → Windows Event Logs → Custom (XPath). Aqui está a mágica. Em vez de coletar TODOS os eventos de Security, vou especificar exatamente quais EventIDs me interessam:

```
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4726)]]
```

Isso significa: logon sucesso (4624), logon falhou (4625), uso de privilégio especial (4672), criação de processo (4688), criação de usuário (4720), deleção de usuário (4726).

O EventID 4634 — logoff — que pode ser 30% do volume, não está na lista. Não precisamos de cada logoff registrado.

Destination → nosso workspace meridian-secops-prod.

Transformation KQL: adiciono uma transformação adicional para remover eventos gerados pela própria conta de serviço do AMA:

```kql
source
| where SubjectUserName != 'MeridiamSvc-AMA'
| where SubjectUserName !endswith '$'
```

*[Demonstrar criação no portal e depois associar às VMs dos DCs]*

Depois de criar a DCR, associo ela às VMs que são domain controllers. A DCR é aplicada por associação — um mesmo servidor pode ter múltiplas DCRs."

---

**[20:00 — BLOCO 2: CONTENT HUB | 15 minutos]**

*[Screen share: Sentinel → Content Hub]*

"Agora o Content Hub. Isso aqui é como um app store para o nosso SIEM.

Vou instalar a solução Microsoft Entra ID — é a mais completa. 30 analytics rules, 15 workbooks, 20 hunting queries. Tudo criado e mantido pela Microsoft.

*[Clicar em Install]*

Aguardar instalação. Enquanto instala, vou mostrar o que está vindo: vou em 'Manage' para ver o preview do conteúdo.

Instalação concluída. Agora preciso ativar as analytics rules. Vou em Analytics → Templates. Aqui estão todas as rules que foram instaladas, mas ainda não ativas.

Vou ativar 3 rules do pacote Entra ID:
1. Suspicious Sign-In After Password Change — detecta login suspeito logo após mudança de senha (padrão de conta comprometida)
2. Bulk User Account Deletion — múltiplos usuários deletados num curto período
3. Sign-In from Unknown Location — login de país nunca antes usado pelo usuário

Para cada uma: selecionar → Create rule → revisar a KQL query → ajustar parâmetros se necessário → Review + Create.

*[DICA DE EDIÇÃO: acelerar a gravação da criação da segunda e terceira rule — 2x speed]*

Observação importante: as rules do Content Hub são pontos de partida. Vocês vão querer revisá-las e customizá-las para o contexto do Banco Meridian. Por exemplo, a rule de 'unknown location' pode gerar muito falso positivo para um banco com filiais em vários estados. Vamos aprender a ajustar essas rules no Módulo 4 de Detection Engineering."

---

**[35:00 — BLOCO 3: VERIFICAÇÃO FINAL | 8 minutos]**

"Vamos fazer um check final do que configuramos. Vou ao Overview do Sentinel.

*[Screen share: Sentinel Overview]*

Já aparecem as primeiras métricas: eventos ingeridos nas últimas 24h, tamanho dos dados, conectores ativos, analytics rules ativas.

Vou em Incidents. Se alguma das rules que ativamos detectou algo, aparecerá aqui. Em ambientes reais, nas primeiras horas você terá uma avalanche de incidentes — muitos são falso-positivos que precisam de ajuste.

A última etapa antes de encerrar o módulo: verificar os conectores que estão com status de 'Connected' vs 'Disconnected'.

*[Data Connectors → Status summary]*

Ótimo. Entra ID, Defender XDR, Azure Activity e Office 365 — todos connected. CEF ainda aparece como disconnected porque precisamos configurar o FortiGate para enviar logs para o forwarder — faremos isso no Lab 01.

No Lab 01, vocês vão fazer tudo isso no ambiente de vocês, seguindo o passo a passo detalhado no repositório. Boa sorte!"

---

## 10. Avaliação do Módulo

### Questões de Avaliação

**Q1.** O Banco Meridian está planejando o design do workspace Log Analytics. Com 2.800 funcionários, múltiplas filiais e ambientes de desenvolvimento e produção, qual é a abordagem recomendada?

a) Um workspace por filial bancária para isolamento geográfico  
b) Um workspace centralizado de produção com Sentinel habilitado e um workspace separado para desenvolvimento sem Sentinel  
c) Um workspace por produto (um para Entra ID, um para MDE, um para MDO)  
d) Usar apenas o workspace padrão criado automaticamente pelo Azure  

**Resposta: B** — Um workspace centralizado de produção permite correlação cruzada entre todas as fontes, simplifica operações SOC e reduz custos de connectors. O workspace de desenvolvimento separado permite testar analytics rules e DCRs sem impactar a produção. Criar workspaces por filial ou por produto fragmente os dados e impossibilita correlação — um ataque de lateral movement que começa em uma filial e se move para outra não seria detectado.

---

**Q2.** Uma DCR para coletar Security Events Windows usa a seguinte XPath query: `Security!*[System[(EventID=4624 or EventID=4688)]]`. O que essa configuração coleta?

a) Apenas falhas de autenticação (EventID 4624 = logon failure)  
b) Logons bem-sucedidos (EventID 4624) e criação de processos (EventID 4688)  
c) Todos os eventos do canal Security, filtrados para excluir 4624 e 4688  
d) Logons de rede (EventID 4688) e tentativas de Kerberos (EventID 4624)  

**Resposta: B** — EventID 4624 é o evento de logon bem-sucedido (Account Logon Success); EventID 4688 é o evento de criação de processo (Process Creation). Ambos são fundamentais para detecção de ameaças: 4624 detecta acessos anômalos; 4688 (com linha de comando auditada) detecta execução de ferramentas maliciosas. Nota: para que 4688 inclua linha de comando, é necessário habilitar auditoria avançada via Group Policy.

---

**Q3.** O Content Hub instalou uma analytics rule "Suspicious Sign-In from New Country". Após ativar, o SOC recebe 50 alertas por dia, todos referentes a funcionários que viajam frequentemente a serviço. Como tratar isso corretamente?

a) Desativar a rule — ela gera muitos falso-positivos  
b) Modificar a rule para excluir usuários em um Watchlist de "frequent travelers" usando a função `_GetWatchlist()`  
c) Aumentar o threshold de frequência de detecção de 1 para 50 por dia  
d) Mover os alertas para severity "Informational" sem fazer investigação  

**Resposta: B** — Watchlists são a solução correta para este cenário. Criar uma watchlist "frequent-travelers" com os UPNs dos funcionários que viajam regularmente. Modificar a analytics rule para incluir um join ou where clause: `| where UserPrincipalName !in (_GetWatchlist('frequent-travelers') | project UserPrincipalName)`. Isso mantém a detecção ativa para todos os outros usuários enquanto suprime alertas esperados. Desativar a rule (opção A) cria uma lacuna de detecção; aumentar o threshold (C) é uma gambiarra; mover para Informational sem investigar (D) viola boas práticas SOC.

---

**Q4.** Qual é a diferença entre o tier "Interactive" e o tier "Archive" no Log Analytics?

a) Interactive é para dashboards em tempo real; Archive é para queries históricas — ambos com o mesmo custo  
b) Interactive permite queries KQL ad hoc com latência de milissegundos e custo alto; Archive é para retenção de compliance com custo ~10% do Interactive e queries com latência de minutos (requer Restore para análise intensiva)  
c) Interactive suporta dados até 90 dias; Archive suporta dados até 2 anos  
d) Interactive é o único tier que suporta analytics rules; Archive não permite criação de alertas  

**Resposta: B** — Interactive (Hot) é o tier padrão para dados consultados frequentemente: queries rápidas (milissegundos/segundos), suporte a analytics rules e alertas, custo mais alto. Archive é para dados que precisam ser retidos por compliance mas raramente consultados: custo ~10% do Interactive, queries via Restore (que ativa o dado por alguns dias em Hot). Analytics rules e alertas não funcionam sobre dados Archive — eles só funcionam no tier Interactive. Para compliance BACEN (5 anos), a configuração ideal é 90 dias Interactive + restante em Archive.

---

**Q5.** Ao configurar o conector Microsoft Defender XDR no Sentinel, qual configuração é crítica para evitar duplicação de incidentes?

a) Selecionar apenas as tabelas de MDE e ignorar MDO e MDI  
b) Ativar "Turn off all Microsoft incident creation rules" para que apenas os incidentes correlacionados pelo XDR sejam usados, evitando que o Sentinel crie incidentes duplicados para cada alerta individual  
c) Configurar o conector em modo "read-only" para não modificar dados  
d) Criar analytics rules personalizadas no Sentinel para cada produto Defender antes de ativar o conector  

**Resposta: B** — O Defender XDR já tem seu próprio motor de correlação que agrupa alertas de MDE, MDI, MDO e MDA em incidentes unificados. Se o Sentinel tiver suas próprias "Microsoft incident creation rules" ativas, ele criará incidentes adicionais para cada alerta individualmente, resultando em duplicação: um incidente rico e correlacionado do XDR + vários incidentes fragmentados do Sentinel. Ativar "Turn off all Microsoft incident creation rules" resolve isso, fazendo o Sentinel usar os incidentes do XDR como fonte única de verdade.
