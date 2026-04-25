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

**O que este passo faz:** Um Logic App é o motor de automação que executa as ações de resposta quando o Sentinel dispara um alerta. Funciona como um fluxo de trabalho visual: trigger → ações sequenciais. Escolhemos o tipo **Consumption** (pay-per-execution) porque playbooks de SOAR disparam sob demanda — não continuamente. Para o Banco Meridian, que recebe ~20 alertas críticos por dia, o custo com Consumption é 90% menor do que o tipo Standard.

**Por que criamos o Logic App antes de tudo:** A Managed Identity (identidade que permitirá ao Logic App chamar o Graph API) só existe após a criação do recurso. Sem o Logic App criado, não há identidade para configurar. A ordem importa: Logic App → Managed Identity → permissões Graph → conexão Sentinel → ações.

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

**O que este passo faz:** O trigger é o "ouvinte" — define quando o playbook será invocado automaticamente. Ao selecionar **When a Microsoft Sentinel Incident creation rule is triggered**, o Logic App registra-se no Sentinel como um playbook disponível para automação. A cada novo incidente criado (ou quando uma Automation Rule o acionar), o Sentinel chamará este Logic App enviando o payload completo do incidente como entrada.

**Por que este trigger específico:** O Sentinel tem dois triggers para Logic Apps: "alert creation" e "incident creation". Usamos "incident creation" porque os incidentes agregam múltiplos alertas correlacionados — o playbook assim recebe contexto completo (entidades, táticas MITRE, alertas relacionados), não apenas um alerta isolado. Isso é crítico para a lógica de "For Each Entity" que virá nos próximos passos.

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

**O que este passo faz:** Ativa a Managed Identity do Logic App — uma identidade gerenciada pelo Azure AD que permite ao Logic App autenticar-se em outros serviços Azure e Microsoft Graph sem guardar credenciais. Ao conceder as permissões `User.ReadWrite.All` e `GroupMember.ReadWrite.All` ao Microsoft Graph, habilitamos o Logic App a chamar a API de revogação de sessão (`revokeSignInSessions`) e adicionar usuários ao grupo de quarentena — as duas ações de contenção centrais do playbook.

**Por que Managed Identity em vez de Service Principal ou usuário de serviço:** Managed Identity elimina o risco de vazamento de credenciais, que é um dos principais vetores de ataque em ambientes cloud. Credenciais de Service Principal (client_secret) têm prazo de expiração e precisam de rotação manual. Managed Identity recebe tokens automaticamente do Azure AD com prazo muito curto (< 1h) — sem credencial estática para vazar. Para o Banco Meridian, regulado pelo BACEN 4.893, o uso de Managed Identity é alinhado com o princípio de menor privilégio e controle de acesso baseado em identidade.

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

**O que este passo faz:** Um incidente do Sentinel pode conter múltiplas entidades (usuários, IPs, hosts). O **For Each Entity** itera sobre cada entidade do incidente e filtra apenas as do tipo `Account` — ou seja, usuários. Para o incidente de rafael.torres, o incidente tem 3 entidades: o usuário, o IP de São Paulo e o IP de Moscou. Queremos agir apenas no usuário, não nos IPs.

**Por que filtrar pelo kind "Account":** A ação de revogação de sessão usa o UPN (User Principal Name) do usuário. Tentar executar `revokeSignInSessions` para uma entidade do tipo `IP` causaria erro na chamada Graph API. O filtro garante que as ações de resposta sejam aplicadas apenas nas entidades corretas.

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

**O que este passo faz:** Executa uma chamada à Microsoft Graph API para revogar **todos** os tokens de sessão ativos do usuário comprometido. Quando um atacante faz Impossible Travel (login em São Paulo às 09h15 e Moscou às 09h38), ele usou credenciais válidas — mas após o roubo de credencial, ele mantém um token de sessão ativo. `revokeSignInSessions` invalida todos os tokens, forçando re-autenticação e quebrando a sessão do atacante imediatamente.

**O que acontece na prática:** Após este POST para o Graph, o rafael.torres verá um prompt de re-login na próxima ação no M365. O atacante em Moscou também será deslogado. A ação é reversível — se for falso positivo, o usuário simplesmente faz login novamente.

**Por que Managed Identity em vez de Service Principal:** Managed Identity elimina o gerenciamento de secrets/credenciais. O Logic App recebe um token curto prazo automaticamente do Azure AD para chamar o Graph. Sem Managed Identity, seria necessário armazenar client_secret em um Key Vault e renovar periodicamente.

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

**O que este passo faz:** Envia uma notificação estruturada ao canal do SOC no Microsoft Teams com os detalhes do incidente e a ação tomada. Esta notificação é o mecanismo de "loop fechado" que mantém o time do SOC informado sobre respostas automatizadas — sem ela, o analista que monitora o Teams não saberia que uma sessão foi revogada, podendo até tentar manualmente a mesma ação e gerar duplicidade.

**Por que Teams em vez de e-mail:** O Teams é o canal de comunicação em tempo real do SOC do Banco Meridian. E-mail tem latência alta (SMTP pode demorar minutos) e não oferece threading de conversas. O Teams usa webhooks com latência de segundos. Além disso, o Sentinel tem conector nativo Teams que simplifica a configuração sem necessidade de webhook personalizado.

**Por que a notificação vem APÓS a revogação e não antes:** A notificação deve refletir o que FOI feito, não o que será feito. Notificar antes da ação e depois a ação falhar criaria confusão — o analista acreditaria que a sessão foi revogada quando não foi. A sequência correta é: agir → confirmar → notificar.

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

**O que este passo faz:** Adiciona um comentário estruturado ao incidente do Sentinel documentando automaticamente cada ação tomada pelo playbook. Este comentário é fundamental para a rastreabilidade: qualquer analista que abrir o incidente posteriormente saberá exatamente o que foi feito, quando e com qual resultado — sem precisar vasculhar logs ou perguntar ao colega.

**Por que isto importa para auditoria e BACEN:** A Resolução 4.893 exige que todas as ações de resposta a incidentes sejam documentadas. Um comentário automático no incidente cria evidência imutável com timestamp UTC de que a resposta foi executada. Este é um dos registros que o auditor do BACEN revisará durante uma avaliação de capacidade de resposta a incidentes.

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

**O que este passo faz:** Salva o Logic App e executa o primeiro teste manual usando um incidente real do Sentinel. O teste end-to-end valida toda a cadeia: trigger Sentinel → iteração sobre entidades → chamada Graph API → notificação Teams → comentário no incidente. O "Run History" é a evidência de que cada ação foi executada com sucesso — é este histórico que o analista L2 mostrará ao CISO para confirmar que o playbook está operacional.

**Por que testar com um incidente real em vez de mock:** O Logic App usa conexões OAuth (Sentinel, Teams, Graph) que só funcionam com o contexto de um incidente real. Testar com JSON manualmente funciona para lógica de transformação, mas não para validar que as permissões Graph foram configuradas corretamente.

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

**O que este passo faz:** Confirma, com evidências técnicas, que cada ação do playbook produziu o efeito de segurança pretendido no ambiente real. As verificações não são opcionais — elas são a diferença entre "o Logic App executou sem erro" e "a conta do rafael.torres está efetivamente contida". Um Logic App pode executar com status "Succeeded" mas a ação falhar silenciosamente (por exemplo, se a permissão Graph `User.ReadWrite.All` não foi concedida corretamente, a chamada de revogação retorna 401 e o Logic App pode configurado para `continue on error`).

**Por que verificar com PowerShell e não apenas com o portal:** O portal Azure às vezes tem delay de cache — um usuário pode aparecer como "ativo" no portal por alguns minutos após a revogação. O PowerShell via Microsoft Graph SDK consulta diretamente o plano de dados, sem cache, retornando o estado real. Para evidências de audit trail (importante para o BACEN), sempre use a API/PowerShell.

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

**O que este passo faz:** Liga o playbook ao pipeline de alertas do Sentinel, eliminando a necessidade de intervenção manual. Com esta Automation Rule, toda vez que um incidente de severidade High envolvendo uma entidade Account for criado, o Sentinel invocará automaticamente o playbook `meridian-conta-comprometida-resposta` em menos de 30 segundos — antes mesmo de o analista ver o alerta.

**Por que Order: 1:** As Automation Rules são executadas em ordem numérica. Colocar esta regra em Order 1 garante que a resposta automatizada ocorra antes de qualquer outra automação (triagem, atribuição, enriquecimento). Isso minimiza o MTTR (Mean Time to Respond) — no caso do Banco Meridian, o objetivo é isolar a conta comprometida antes do atacante conseguir fazer exfiltração de dados.

**Por que este é o passo final:** A Automation Rule só pode referenciar um Logic App após ele ter sido salvo, testado e estar em estado "Running". Criar a Automation Rule com um playbook com erros resultaria em falhas silenciosas em cada incidente.

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

## Seção 8 — Gabarito Completo

### Checklist de Verificação — O que Confirma que Cada Passo Funcionou Corretamente

**Passo 1 (Logic App criado):** O Logic App existe no resource group `rg-meridian-secops` e o designer abre sem erros. Um erro comum aqui é criar o Logic App como "Standard" (conta com plano de serviço) em vez de "Consumption" (pay-per-execution). Para o lab, "Consumption" é o correto — "Standard" tem funcionalidades diferentes e custo diferente.

**Passo 2 (Trigger Sentinel):** O bloco trigger aparece no designer com o ícone do Sentinel (escudo azul) e o campo de workspace preenchido com `meridian-secops-prod`. Se o trigger aparecer com ícone de aviso laranja, há problema de permissão — a conta usada para criar a connection deve ter papel de Sentinel Responder ou superior no workspace.

**Passo 3 (Managed Identity):** A verificação definitiva é o PowerShell retornar 3 linhas, uma para cada permissão. Se retornar 0, a permissão não foi concedida — verifique se o `$objectId` está correto (é o Object ID do System Assigned Identity, não o Application ID do Logic App). Uma maneira alternativa de verificar: Portal Azure → Entra ID → Enterprise Applications → buscar pelo nome do Logic App → Permissions → Grant admin consent.

**Passo 5 (Revogação de sessão):** A confirmação técnica é via KQL no Sentinel:
```kql
SigninLogs
| where UserPrincipalName == "rafael.torres@bancomeridian-lab.onmicrosoft.com"
| where TimeGenerated > ago(1h)
| where ResultType != 0
| project TimeGenerated, ResultType, ResultDescription, IPAddress
```
Se o usuário tentar fazer login após a revogação, o ResultType será `70011` ("The token has been revoked") ou `70008` ("Refresh token expired"). Isso confirma que a revogação foi efetiva.

**Passo 6 (Teams):** A mensagem aparece no canal do Teams em menos de 30 segundos após a execução do playbook. Se não aparecer, verifique: (1) a connection do Teams está autenticada com uma conta que é membro do time; (2) o ID do canal está correto (use o ID da URL do Teams, não o nome do canal).

**Passo 7 (Comentário no incidente):** O comentário aparece na aba "Comments" do incidente no Sentinel com o prefixo "[AUTOMAÇÃO PLAYBOOK]" e timestamp UTC. Se não aparecer, verifique se a Managed Identity tem papel de "Microsoft Sentinel Responder" no workspace (além das permissões Graph).

**Variações aceitáveis:**
- A notificação Teams pode ser substituída por e-mail (Microsoft 365 Outlook connector) se o tenant de lab não tiver Teams configurado
- O comentário no incidente pode ter formatação diferente, mas deve conter: timestamp, nome do usuário afetado, ações executadas
- A automation rule pode ter critérios adicionais (ex.: tag específica) sem invalidar o resultado

**Erros comuns e como identificar:**

| Erro | Sintoma | Solução |
|:-----|:--------|:--------|
| `403 Forbidden` na chamada Graph | Run History: HTTP action com ícone vermelho | Verificar permissões da Managed Identity — User.ReadWrite.All deve aparecer em Enterprise Apps → Permissions |
| `Logic App connection invalid` | Trigger com ícone de aviso | Re-autenticar a connection do Sentinel no designer |
| Teams message não aparece | Run History verde mas sem mensagem | O canal ID está incorreto ou a conta não tem acesso ao time |
| Automation rule não dispara | Incidente criado mas playbook não executa | Verificar se a severity e o tipo de entidade da automation rule correspondem ao incidente de teste |

### Gabarito: Código ARM do Logic App Completo

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
