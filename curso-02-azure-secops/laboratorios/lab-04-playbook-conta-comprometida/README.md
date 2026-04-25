# Lab 04 — Playbook: Resposta Automatizada a Conta Comprometida

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 05 — SOAR com Logic Apps                                        |
| **Pré-requisito**        | Labs 01 e 03 concluídos                                                |
| **Nível**                | Intermediário                                                          |

---

## Seção 1 — Contexto Situacional

O Microsoft Sentinel do **Banco Meridian** gerou um alerta de alta severidade às 09h42 da manhã: a analytics rule "Banco Meridian - Impossible Travel" detectou que o usuário `rafael.torres@bancomeridian-lab.onmicrosoft.com` (Analista de TI) fez login em São Paulo às 09h15 e em Moscou às 09h38 — diferença de 23 minutos.

O incidente foi criado automaticamente no Sentinel. O SOC está com 8 incidentes abertos simultaneamente. Sem automação, um analista levaria 20-30 minutos para manualmente revogar sessões, notificar o gerente e criar o ticket. Com o playbook que vamos criar, tudo isso será feito em menos de 60 segundos.

---

## Seção 2 — Situação Inicial

**Estado do ambiente**:
- Sentinel operacional com analytics rules ativas (Lab 03)
- Incidente HIGH aberto: "Banco Meridian - Impossible Travel - rafael.torres"
- Sem playbooks configurados
- Sem automation rules associadas a incidentes

---

## Seção 3 — Problema Identificado

Sem automação, quando rafael.torres tem a conta comprometida:
- O atacante permanece com sessão ativa enquanto o analista investiga
- Não há notificação automática para o gerente de rafael.torres
- Não há registro formal do incidente no sistema ITSM
- O tempo médio de contenção é de 20-40 minutos (MTTR alto)

O objetivo deste lab é criar um playbook que execute a contenção inicial em menos de 1 minuto.

---

## Seção 4 — Roteiro de Atividades

1. Criar o Logic App com trigger de incidente do Sentinel
2. Configurar a Managed Identity com permissões Graph API
3. Implementar ação de revogação de sessões via HTTP (Graph API)
4. Implementar ação de notificação via Microsoft Teams
5. Implementar ação de adição ao grupo de quarentena
6. Implementar ação de comentário no incidente Sentinel
7. Criar automation rule para disparar o playbook automaticamente
8. Testar o playbook manualmente e validar todas as ações

---

## Seção 5 — Proposição

Ao final deste laboratório:
- Logic App criado com fluxo completo de resposta a conta comprometida
- Managed Identity configurada com permissões Graph API necessárias
- Playbook executando: revogação de sessão, notificação Teams, comentário no incidente
- Automation rule vinculando incidentes High com entidade Account ao playbook
- MTTR para conta comprometida reduzido de ~30min para <1min para ações de contenção

---

## Seção 6 — Script Passo a Passo

### Passo 1: Criar o Logic App

**Portal Azure → Create a resource → Logic App → Create**

```
Tipo: Consumption (pay-per-execution; ideal para lab)
Resource group: rg-meridian-secops
Logic App name: meridian-conta-comprometida-resposta
Region: Brazil South (ou East US se Brazil South não disponível)
```

Clicar em **Review + Create → Create**

Aguardar criação (~2 min). Após criação, clicar em **Go to resource**.

Em seguida, clicar em **Logic app designer**.

Selecionar o template: **Blank Logic App**

---

### Passo 2: Configurar o Trigger do Sentinel

No Logic App Designer, no campo de busca de triggers:
1. Pesquisar "Microsoft Sentinel"
2. Selecionar **When a Microsoft Sentinel Incident creation rule is triggered**
3. Criar uma connection com o workspace:
   - Connection name: `sentinel-meridian-connection`
   - Subscription: Banco-Meridian-Sandbox
   - Workspace: meridian-secops-prod
4. Clicar em **Create**

**Resultado esperado**: Bloco de trigger aparece com o ícone do Sentinel.

---

### Passo 3: Habilitar Managed Identity e Configurar Permissões

**Portal Azure → meridian-conta-comprometida-resposta → Identity**

1. Na aba **System assigned**: Status → **On** → Save
2. Copiar o **Object ID** da Managed Identity gerada

**Conceder permissão ao Microsoft Graph**:
```powershell
# Executar no Azure Cloud Shell ou PowerShell com MicrosoftGraph module
# Substituir <OBJECT_ID> pelo Object ID copiado acima

$objectId = "<OBJECT_ID>"
$graphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$permissionNames = @("User.ReadWrite.All", "Directory.Read.All", "GroupMember.ReadWrite.All")

# Buscar o service principal do Microsoft Graph
$graphSP = Get-MgServicePrincipal -Filter "AppId eq '$graphAppId'"

# Para cada permissão necessária
foreach ($permName in $permissionNames) {
    $perm = $graphSP.AppRoles | Where-Object { $_.Value -eq $permName }
    
    if ($perm) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $objectId `
            -PrincipalId $objectId `
            -ResourceId $graphSP.Id `
            -AppRoleId $perm.Id
        Write-Host "Permissão concedida: $permName"
    }
}
```

**Verificação**:
```powershell
# Verificar permissões concedidas à Managed Identity
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objectId | 
    Select-Object PrincipalDisplayName, AppRoleId
```

**Resultado esperado**: 3 permissões (User.ReadWrite.All, Directory.Read.All, GroupMember.ReadWrite.All) concedidas.

---

### Passo 4: Implementar a Ação de For Each Entity

No Logic App Designer, após o trigger:

1. Clicar em **+ New step**
2. Pesquisar "Control" → selecionar **For each**
3. Em "Select an output from previous steps": escolher `Entities` do trigger
4. Dentro do For each, adicionar uma **Condition**:
   - Left: `@{items('For_each')?['kind']}`
   - Operator: is equal to
   - Right: `Account`

---

### Passo 5: Implementar Revogação de Sessão

Dentro do branch **True** (Account entity) do Condition:

1. Clicar em **Add an action**
2. Pesquisar "HTTP" → selecionar **HTTP**
3. Configurar:

```
Method: POST
URI: https://graph.microsoft.com/v1.0/users/@{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}/revokeSignInSessions

Authentication: Managed Identity
Audience: https://graph.microsoft.com
```

Renomear a ação para: `Revogar Sessoes - Graph API`

---

### Passo 6: Implementar Notificação no Teams

Após a ação de revogação:

1. Clicar em **Add an action**
2. Pesquisar "Microsoft Teams" → selecionar **Post message in a chat or channel**
3. Configurar:
   - Post in: Channel
   - Team: SOC-Meridian (selecionar o time do Teams do lab)
   - Channel: Geral (ou #alertas-soc se disponível)
   - Message: 

```
🚨 ALERTA SOC — CONTA COMPROMETIDA

Incidente: @{triggerBody()?['object']?['properties']?['title']}
Severidade: @{triggerBody()?['object']?['properties']?['severity']}
Usuário afetado: @{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}

Ações automatizadas executadas:
✓ Sessões revogadas via Graph API
⏳ Aguardando investigação do analista

Link do incidente Sentinel: @{triggerBody()?['object']?['properties']?['incidentUrl']}
```

---

### Passo 7: Implementar Comentário no Incidente

Após o Teams:

1. Clicar em **Add an action**
2. Pesquisar "Microsoft Sentinel" → selecionar **Add comment to incident (V3)**
3. Configurar:
   - Subscription: Banco-Meridian-Sandbox
   - Resource group: rg-meridian-secops
   - Workspace: meridian-secops-prod
   - Incident ARM id: `@{triggerBody()?['object']?['id']}`
   - Incident comment: 

```
[AUTOMAÇÃO PLAYBOOK] - @{utcNow()}

Playbook "meridian-conta-comprometida-resposta" executado.

Ações tomadas:
1. ✓ Sessões Entra ID revogadas para @{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}
2. ✓ Notificação enviada ao canal Teams #alertas-soc
3. ⚠️ Senha não foi resetada automaticamente - requer aprovação do analista

Próximo passo recomendado: Verificar atividade pós-compromisso no Advanced Hunting.
```

---

### Passo 8: Salvar e Testar o Logic App

1. Clicar em **Save** (barra superior do designer)
2. Verificar que não há erros de configuração (ícones vermelhos indicam problemas)
3. Para testar manualmente:

**Sentinel → Incidents → selecionar o incidente de rafael.torres → Run playbook**

Selecionar: `meridian-conta-comprometida-resposta`

4. Aguardar execução (~30-60 segundos)
5. Verificar o resultado no Logic App:

**Portal Azure → meridian-conta-comprometida-resposta → Overview → Run history**

**Resultado esperado**: Execução com status "Succeeded". Cada ação mostra verde.

---

### Passo 9: Verificar Efeitos do Playbook

**Verificação 1 — Sessão revogada**:
```powershell
# Verificar se sessões foram revogadas
Get-MgUser -UserId "rafael.torres@bancomeridian-lab.onmicrosoft.com" |
    Select-Object UserPrincipalName, SignInSessionsValidFromDateTime
# O campo SignInSessionsValidFromDateTime deve ter sido atualizado agora
```

**Verificação 2 — Comentário no incidente**:
```
Sentinel → Incidents → rafael.torres incident → Comments
# Deve mostrar o comentário automático do playbook
```

**Verificação 3 — Notificação Teams**:
```
Teams → canal configurado → verificar mensagem do Logic App
```

---

### Passo 10 (Avançado): Criar Automation Rule

**Sentinel → Automation → Automation rules → Create**

```
Name: Auto-Playbook-Alta-Severidade-Conta
Order: 1 (executa antes das outras automation rules)
Trigger: When incident is created

Conditions:
  - Incident severity: Equals: High
  - Incident contains entities of type: Account

Actions:
  - Assign owner: seu usuário
  - Add tag: playbook-executed
  - Run playbook: meridian-conta-comprometida-resposta

Expiration: Never
Status: Enabled
```

**Resultado esperado**: Próximo incidente High com Account como entidade ativará o playbook automaticamente.

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                            | Verificação                                            |
|:-----:|:----------------------------------------------------|:-------------------------------------------------------|
| 1-2   | Criar Logic App com trigger Sentinel                | Designer abre sem erros com bloco Sentinel             |
| 3     | Configurar Managed Identity + permissões Graph      | 3 permissões concedidas no PowerShell                  |
| 4     | Implementar iteração sobre entidades Account        | For each configurado com condition Account             |
| 5     | Implementar revogação de sessão via Graph API       | HTTP action POST para revokeSignInSessions             |
| 6     | Implementar notificação Teams                       | Mensagem aparece no canal configurado                  |
| 7     | Implementar comentário no incidente                 | Comentário aparece no incidente Sentinel               |
| 8-9   | Testar e validar todas as ações                     | Run History mostra "Succeeded" em todas as ações       |
| 10    | Vincular automation rule ao playbook                | Automation rule criada e habilitada                    |

---

## Seção 8 — Gabarito: Código ARM do Logic App Completo

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2016-06-01/Microsoft.Logic.json",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspace_name": {
      "type": "string",
      "defaultValue": "meridian-secops-prod"
    },
    "teams_channel_id": {
      "type": "string",
      "defaultValue": "19:general@thread.tacv2"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Logic/workflows",
      "name": "meridian-conta-comprometida-resposta",
      "apiVersion": "2017-07-01",
      "location": "[resourceGroup().location]",
      "identity": {
        "type": "SystemAssigned"
      },
      "properties": {
        "state": "Enabled",
        "definition": {
          "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
          "contentVersion": "1.0.0.0",
          "triggers": {
            "Microsoft_Sentinel_incident": {
              "type": "ApiConnectionWebhook",
              "inputs": {
                "body": {
                  "callback_url": "@{listCallbackUrl()}"
                },
                "host": {
                  "connection": {
                    "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                  }
                },
                "path": "/incident-creation"
              }
            }
          },
          "actions": {
            "For_each_entities": {
              "type": "Foreach",
              "foreach": "@triggerBody()?['object']?['properties']?['relatedEntities']",
              "actions": {
                "Is_Account_Entity": {
                  "type": "If",
                  "expression": {
                    "and": [
                      {
                        "equals": [
                          "@items('For_each_entities')?['kind']",
                          "Account"
                        ]
                      }
                    ]
                  },
                  "actions": {
                    "Revogar_Sessoes_Graph_API": {
                      "type": "Http",
                      "inputs": {
                        "method": "POST",
                        "uri": "https://graph.microsoft.com/v1.0/users/@{concat(items('For_each_entities')?['properties']?['accountName'],'@',items('For_each_entities')?['properties']?['upnSuffix'])}/revokeSignInSessions",
                        "authentication": {
                          "type": "ManagedServiceIdentity",
                          "audience": "https://graph.microsoft.com"
                        }
                      }
                    },
                    "Notificar_Teams": {
                      "runAfter": {
                        "Revogar_Sessoes_Graph_API": ["Succeeded", "Failed"]
                      },
                      "type": "ApiConnection",
                      "inputs": {
                        "body": {
                          "messageBody": "<h2>ALERTA SOC — CONTA COMPROMETIDA</h2><p><b>Usuário:</b> @{concat(items('For_each_entities')?['properties']?['accountName'],'@',items('For_each_entities')?['properties']?['upnSuffix'])}</p><p><b>Severidade:</b> @{triggerBody()?['object']?['properties']?['severity']}</p><p>Sessões revogadas automaticamente.</p>",
                          "recipient": {
                            "channelId": "[parameters('teams_channel_id')]"
                          }
                        },
                        "host": {
                          "connection": {
                            "name": "@parameters('$connections')['teams']['connectionId']"
                          }
                        },
                        "method": "post",
                        "path": "/beta/teams/conversation/message/poster/Flow bot/location/@{encodeURIComponent('Channel')}"
                      }
                    },
                    "Comentar_Incidente": {
                      "runAfter": {
                        "Notificar_Teams": ["Succeeded", "Failed"]
                      },
                      "type": "ApiConnection",
                      "inputs": {
                        "body": {
                          "incidentArmId": "@triggerBody()?['object']?['id']",
                          "message": "[PLAYBOOK] Executado em @{utcNow()}. Sessões revogadas. Teams notificado."
                        },
                        "host": {
                          "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                          }
                        },
                        "method": "post",
                        "path": "/Incidents/Comment"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  ]
}
```

### Pontos de Atenção do Gabarito

1. **Erro mais comum**: A Managed Identity não tem permissão Graph antes de testar → o Passo 3 deve ser executado antes do Passo 8.

2. **Erro de connection no Teams**: O conector Teams requer autenticação com uma conta que tem acesso ao Teams. Usar a conta de lab fornecida pelo CECyber.

3. **Token expired na ação Graph API**: Managed Identity gera tokens automaticamente — se der erro 401, verificar se as permissões foram concedidas corretamente no Passo 3.

4. **Sessão não revogada**: O Microsoft Graph pode demorar até 5 minutos para propagar a revogação. Verificar no Entra ID → User → Active Sessions após 5 minutos.

### Verificação Final em KQL

```kql
// Verificar se o playbook gerou comentários nos incidentes
SecurityIncident
| where TimeGenerated > ago(2h)
| where Comments has "PLAYBOOK"
| project TimeGenerated, IncidentNumber, Title, Severity, Comments
```
