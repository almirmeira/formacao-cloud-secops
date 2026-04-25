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

**Por que criamos o Logic App ANTES de configurar permissões:** A Managed Identity (que concede permissões ao Logic App para chamar o Microsoft Graph) só existe após a criação do recurso. Sem o Logic App criado, não há identidade para registrar no Entra ID, e portanto nenhuma permissão pode ser concedida. Criar o recurso primeiro é um pré-requisito hard para o Passo 3. A ordem importa: Logic App → Managed Identity → permissões Graph → conexão Sentinel → ações.

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

**O que confirma que funcionou:** Após criação (~2 min), o Logic App aparece no resource group `rg-meridian-secops` com status "Running". O Logic App Designer abre exibindo a tela de seleção de templates e você consegue selecionar "Blank Logic App" sem erros ou telas de carregamento infinito.

---

### Passo 2: Configurar o Trigger do Sentinel

**O que este passo faz:** O trigger é o "ouvinte" — define quando o playbook será invocado automaticamente. Ao selecionar **When a Microsoft Sentinel Incident creation rule is triggered**, o Logic App registra-se no Sentinel como um playbook disponível para automação. A cada novo incidente criado (ou quando uma Automation Rule o acionar), o Sentinel chamará este Logic App enviando o payload completo do incidente como entrada, incluindo título, severidade, URL e lista de entidades.

**Por que este trigger específico e por que configurá-lo ANTES das ações:** O Sentinel tem dois triggers para Logic Apps: "alert creation" e "incident creation". Usamos "incident creation" porque os incidentes agregam múltiplos alertas correlacionados — o playbook recebe contexto completo (entidades, táticas MITRE, alertas relacionados), não apenas um alerta isolado. Isso é crítico para a lógica de "For Each Entity" que virá nos próximos passos. Além disso, as expressões dinâmicas das ações seguintes (como `triggerBody()?['object']?['properties']?['title']`) só ficam disponíveis para seleção no designer depois que o trigger está configurado.

No Logic App Designer, no campo de busca de triggers:
1. Pesquisar "Microsoft Sentinel"
2. Selecionar **When a Microsoft Sentinel Incident creation rule is triggered**
3. Criar uma connection com o workspace:
   - Connection name: `sentinel-meridian-connection`
   - Subscription: Banco-Meridian-Sandbox
   - Workspace: meridian-secops-prod
4. Clicar em **Create**

**O que confirma que funcionou:** O bloco de trigger aparece no designer com o ícone laranja do Microsoft Sentinel, sem sinalizações de erro (ícone vermelho). Ao clicar no bloco, a aba de configuração exibe o workspace `meridian-secops-prod` selecionado. Quando você clicar em "Add a step" abaixo do trigger e abrir o seletor de conteúdo dinâmico em qualquer ação, variáveis como `Incident title`, `Incident severity` e `Entities` aparecem disponíveis — isso confirma que o trigger está reconhecido pelo designer.

---

### Passo 3: Habilitar Managed Identity e Configurar Permissões

**O que este passo faz:** A Managed Identity é uma identidade gerenciada pelo Azure — funciona como um "cartão de acesso" do Logic App dentro do ecossistema Microsoft. Em vez de armazenar credenciais hardcoded para chamar o Microsoft Graph, o Logic App usa sua própria identidade para obter tokens de acesso automaticamente, sem expiração manual. As três permissões concedidas têm papéis específicos: `User.ReadWrite.All` permite revogar sessões e redefinir senhas de usuários; `Directory.Read.All` permite consultar informações do usuário comprometido no Entra ID; `GroupMember.ReadWrite.All` permite adicionar o usuário ao grupo de quarentena.

**Por que configuramos as permissões ANTES de construir as ações (Passos 5-7):** Sem as permissões concedidas à Managed Identity, as chamadas ao Microsoft Graph retornarão erro `403 Forbidden` — mesmo que o código da ação HTTP esteja correto. Garantir as permissões neste momento evita que o aluno conclua toda a configuração e só descubra o problema no teste final (Passo 8), o que dificulta o diagnóstico. O Passo 3 é o "alicerce de autorização" de todo o playbook.

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

**O que confirma que funcionou:** O script PowerShell exibe "Permissão concedida: X" para as 3 permissões sem erros de acesso. O comando de verificação retorna 3 linhas, uma para cada permissão. Como validação adicional no Portal Azure: Entra ID → Enterprise Applications → buscar pelo nome do Logic App → Permissions — as 3 permissões do tipo "Application" aparecem listadas. Se o portal mostrar apenas 1 ou 2, reexecutar o loop para as permissões faltantes.

---

### Passo 4: Implementar a Ação de For Each Entity

**O que este passo faz:** Um incidente do Sentinel pode conter múltiplas entidades — no caso de rafael.torres, o incidente de Impossible Travel carrega 3 entidades: o usuário, o IP de São Paulo e o IP de Moscou. O loop **For Each** itera sobre todas elas e a **Condition** filtra apenas as entidades do tipo `Account` (usuário). Isso garante que as ações de contenção — revogação de sessão e adição ao grupo de quarentena — sejam aplicadas somente às contas de usuário, nunca a IPs ou dispositivos que também estejam no incidente.

**Por que implementamos o For Each ANTES das ações de contenção:** As ações dos Passos 5, 6 e 7 precisam do contexto de cada entidade Account para extrair o nome de usuário (`accountName`) e o domínio (`upnSuffix`) que formarão o UPN `rafael.torres@bancomeridian-lab.onmicrosoft.com`. Sem o loop e a condição, o Logic App não saberia sobre qual usuário agir — as expressões dinâmicas dos passos seguintes referenciam diretamente `items('For_each')`, que só existe dentro do contexto do loop.

No Logic App Designer, após o trigger:

1. Clicar em **+ New step**
2. Pesquisar "Control" → selecionar **For each**
3. Em "Select an output from previous steps": escolher `Entities` do trigger
4. Dentro do For each, adicionar uma **Condition**:
   - Left: `@{items('For_each')?['kind']}`
   - Operator: is equal to
   - Right: `Account`

**O que confirma que funcionou:** O bloco "For each" aparece no designer conectado ao trigger, com o campo "Select an output" preenchido com a variável dinâmica `Entities` (não um texto livre). Dentro do For each, o bloco "Condition" exibe corretamente a expressão de filtro por `kind = Account`, com dois branches visíveis: "True" (onde as ações de contenção serão adicionadas) e "False" (que pode ser deixado vazio para esta versão do playbook).

---

### Passo 5: Implementar Revogação de Sessão

**O que este passo faz:** Este é o passo de contenção mais crítico do playbook — equivale a "trocar a fechadura" enquanto o invasor ainda está dentro. A ação HTTP chama o endpoint `revokeSignInSessions` da Microsoft Graph API, que invalida imediatamente todos os tokens de refresh do usuário no Entra ID. Na prática, rafael.torres (e o atacante em Moscou que controlou a conta) será desconectado de todos os aplicativos Microsoft 365 — Outlook, Teams, SharePoint, OneDrive — em até 5 minutos. O uso de **Managed Identity** para autenticação garante que nenhuma credencial pessoal esteja exposta no código do playbook.

**Por que este passo vem logo após a identificação da entidade Account, e não depois da notificação:** A revogação de sessão deve acontecer o mais cedo possível no fluxo — qualquer segundo com sessão ativa é uma janela de exfiltração de dados para o atacante. Notificar a equipe ou comentar no incidente antes de revogar significaria alertar o SOC de uma ameaça que ainda está ativa. A sequência correta no SOAR é sempre: identificar → conter → notificar → registrar.

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

**O que confirma que funcionou:** No Run History do Logic App (após o teste no Passo 8), a ação "Revogar Sessoes - Graph API" exibirá status verde com código de resposta HTTP `200 OK` e body `{"value": true}` — o Microsoft Graph retorna `true` quando a revogação é bem-sucedida. Um código `403` indica problema de permissão (revisar Passo 3); um código `401` indica que o campo Audience está incorreto ou a Managed Identity está desabilitada; `404` indica que o UPN do usuário não foi montado corretamente pela expressão `concat`.

---

### Passo 6: Implementar Notificação no Teams

**O que este passo faz:** Após a contenção (sessão revogada), o SOC precisa saber imediatamente o que aconteceu — quem foi afetado, qual a severidade e quais ações já foram tomadas automaticamente. A mensagem enviada ao canal Teams serve como notificação em tempo real para os analistas que não estão com o painel do Sentinel aberto, além de criar um registro visual no histórico do canal que facilita a correlação durante o turno. O uso de variáveis dinâmicas (`triggerBody`, `items('For_each')`) garante que cada mensagem seja específica ao incidente, sem texto fixo genérico.

**Por que notificamos APÓS revogar a sessão e não antes:** Notificar antes de conter criaria um intervalo em que o analista sabe do incidente mas o atacante ainda tem acesso ativo. A ordem correta no SOAR é sempre: conter primeiro, comunicar depois. Além disso, a mensagem inclui a confirmação "Sessões revogadas via Graph API", o que só é honesto se a revogação já tiver sido tentada. Posicionar a notificação após o Passo 5 garante que o analista receba um status factual, não uma promessa futura.

Após a ação de revogação:

1. Clicar em **Add an action**
2. Pesquisar "Microsoft Teams" → selecionar **Post message in a chat or channel**
3. Configurar:
   - Post in: Channel
   - Team: SOC-Meridian (selecionar o time do Teams do lab)
   - Channel: Geral (ou #alertas-soc se disponível)
   - Message:

```
ALERTA SOC — CONTA COMPROMETIDA

Incidente: @{triggerBody()?['object']?['properties']?['title']}
Severidade: @{triggerBody()?['object']?['properties']?['severity']}
Usuário afetado: @{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}

Ações automatizadas executadas:
- Sessões revogadas via Graph API
- Aguardando investigação do analista

Link do incidente Sentinel: @{triggerBody()?['object']?['properties']?['incidentUrl']}
```

**O que confirma que funcionou:** Após o teste (Passo 8), uma mensagem aparece no canal Teams configurado com os dados reais do incidente de rafael.torres: título, severidade "High" e o UPN `rafael.torres@bancomeridian-lab.onmicrosoft.com`. Se a mensagem aparecer com valores em branco ou com o texto literal `@{triggerBody()...}` sem expansão, há erro de sintaxe na expressão dinâmica — verificar se as chaves `@{}` foram inseridas corretamente e não como texto livre.

---

### Passo 7: Implementar Comentário no Incidente

**O que este passo faz:** O comentário automático no incidente Sentinel cria um registro de auditoria imutável dentro do próprio SIEM — documenta exatamente o que o playbook executou, em que horário e para qual usuário. Isso é fundamental por duas razões: primeiro, para o analista que irá investigar o incidente encontrar um resumo claro do que já foi feito automaticamente (sem precisar consultar logs externos); segundo, para auditorias de conformidade — o Banco Meridian precisa demonstrar ao BACEN (Resolução 4.893) que ações de resposta a incidentes são rastreadas e documentadas com timestamp. O `utcNow()` garante o registro de horário preciso independente do fuso horário do analista.

**Por que o comentário é o último passo do fluxo principal:** O comentário funciona como o "encerramento formal" das ações automatizadas — deve refletir com fidelidade tudo que foi feito. Se fosse posicionado antes das notificações ou da revogação, documentaria ações que ainda não ocorreram, gerando inconsistência no registro de auditoria. A ordem: revogar → notificar → documentar garante que o comentário seja sempre um reflexo fiel do que efetivamente aconteceu naquela execução.

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
[AUTOMACAO PLAYBOOK] - @{utcNow()}

Playbook "meridian-conta-comprometida-resposta" executado.

Acoes tomadas:
1. Sessoes Entra ID revogadas para @{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}
2. Notificacao enviada ao canal Teams #alertas-soc
3. ATENCAO: Senha nao foi resetada automaticamente - requer aprovacao do analista

Proximo passo recomendado: Verificar atividade pos-compromisso no Advanced Hunting.
```

**O que confirma que funcionou:** Acessar **Sentinel → Incidents → selecionar o incidente de rafael.torres → aba Comments**: o comentário do playbook aparece com o timestamp UTC do momento da execução e os dados corretos do usuário. A ausência do comentário após 5 minutos indica falha na ação — verificar no Run History se a ação "Add comment to incident" exibe erro; o código `403` indica que a connection `sentinel-meridian-connection` não tem role "Microsoft Sentinel Contributor" no workspace.

---

### Passo 8: Salvar e Testar o Logic App

**O que este passo faz:** Salvar consolida a definição JSON do fluxo no Azure e ativa o webhook do trigger — a partir deste momento, o Logic App está tecnicamente pronto para receber chamadas do Sentinel. O teste manual via "Run playbook" no portal do Sentinel simula exatamente o que aconteceria com um incidente real, permitindo inspecionar cada ação em sequência no Run History antes de ativar a automation rule automática (Passo 10). Testar manualmente primeiro é a prática recomendada em ambientes SOAR: identifica problemas de permissão, expressões dinâmicas incorretas ou conexões mal configuradas sem o risco de interferir em incidentes reais do SOC.

**Por que testamos ANTES de criar a automation rule (Passo 10):** A automation rule fará o playbook disparar automaticamente em todos os incidentes futuros com severidade High. Se o playbook tiver um bug — por exemplo, permissão Graph ausente ou expressão dinâmica incorreta —, ele falhará silenciosamente a cada incidente, comprometendo a resposta automática sem alertar o analista. Validar manualmente garante que apenas playbooks funcionais sejam colocados em automação.

1. Clicar em **Save** (barra superior do designer)
2. Verificar que não há erros de configuração (ícones vermelhos em qualquer bloco indicam problemas a corrigir antes de prosseguir)
3. Para testar manualmente:

**Sentinel → Incidents → selecionar o incidente de rafael.torres → Run playbook**

Selecionar: `meridian-conta-comprometida-resposta`

4. Aguardar execução (~30-60 segundos)
5. Verificar o resultado no Logic App:

**Portal Azure → meridian-conta-comprometida-resposta → Overview → Run history**

**O que confirma que funcionou:** O Run History exibe a execução com status "Succeeded" (ícone verde). Ao clicar na execução, cada ação do fluxo — For each, Condition, Revogar Sessoes, Post Teams, Add comment — mostra status verde individualmente. O tempo total de execução deve ser inferior a 60 segundos. Uma execução com status "Failed" em vermelho indica qual ação específica falhou; clicar na ação com erro exibe o código HTTP e a mensagem de erro exata para diagnóstico preciso.

---

### Passo 9: Verificar Efeitos do Playbook

**O que este passo faz:** Verificar os efeitos fora do Logic App — no Entra ID, no canal Teams e no incidente do Sentinel — confirma que as chamadas de API produziram resultado real, não apenas que o Logic App executou sem erros técnicos. Um HTTP 200 no Run History significa que o Graph aceitou a requisição; verificar `SignInSessionsValidFromDateTime` confirma que a revogação foi propagada no diretório. Esta verificação de ponta a ponta é o critério definitivo de sucesso do playbook — a diferença entre "o código rodou" e "a conta foi efetivamente protegida".

**Por que este passo vem após o teste e não durante:** Os efeitos da revogação de sessão podem levar até 5 minutos para se propagar no Entra ID. Verificar imediatamente após o Passo 8 pode mostrar o estado anterior (não revogado), gerando falsa impressão de falha. Aguardar a conclusão da execução e então verificar garante leituras precisas e evita diagnósticos incorretos.

**Verificação 1 — Sessão revogada**:
```powershell
# Verificar se sessões foram revogadas
Get-MgUser -UserId "rafael.torres@bancomeridian-lab.onmicrosoft.com" |
    Select-Object UserPrincipalName, SignInSessionsValidFromDateTime
# O campo SignInSessionsValidFromDateTime deve ter sido atualizado para o horário do teste
```

**O que confirma que funcionou (Verificação 1):** O campo `SignInSessionsValidFromDateTime` exibe um timestamp recente — próximo ao horário em que o playbook foi executado. Isso indica que todos os tokens emitidos antes desse momento foram invalidados. Se o campo mostrar uma data antiga (de dias ou semanas atrás), a revogação não foi aplicada — revisar o Passo 5 e confirmar que o HTTP body retornou `{"value": true}` no Run History.

**Verificação 2 — Comentário no incidente**:
```
Sentinel → Incidents → rafael.torres incident → Comments
# Deve mostrar o comentário automático do playbook
```

**O que confirma que funcionou (Verificação 2):** A aba Comments do incidente exibe a mensagem `[AUTOMACAO PLAYBOOK]` com timestamp UTC e os detalhes das ações executadas. O comentário é imutável — aparecerá para qualquer analista que abrir o incidente, independente do turno ou horário.

**Verificação 3 — Notificação Teams**:
```
Teams → canal configurado → verificar mensagem do Logic App
```

**O que confirma que funcionou (Verificação 3):** A mensagem aparece no canal com os dados corretos do incidente: título "Banco Meridian - Impossible Travel", severidade "High" e UPN `rafael.torres@bancomeridian-lab.onmicrosoft.com`. A ausência da mensagem indica problema de autenticação no conector Teams — verificar se a conta usada para criar a connection é membro do time SOC-Meridian no Teams.

---

### Passo 10 (Avançado): Criar Automation Rule

**O que este passo faz:** A automation rule fecha o ciclo de automação — transforma o playbook de uma resposta manual (que o analista precisa acionar no Passo 8) em uma resposta verdadeiramente automática. A partir desta configuração, qualquer incidente criado no Sentinel com severidade High que contenha uma entidade do tipo Account disparará o playbook em menos de 1 minuto, sem intervenção humana. As condições (severidade High + entidade Account) são filtros de segurança que evitam que o playbook revogue sessões de usuários em alertas de baixa relevância ou incidentes sem usuário identificado.

**Por que criamos a automation rule SOMENTE APÓS validar o playbook nos Passos 8-9:** A automation rule opera em produção — incidentes reais do Banco Meridian. Ativar a automação com um playbook não validado pode causar revogações de sessão incorretas em falsos positivos, notificações Teams ruidosas e registros de auditoria incoerentes. A sequência correta é: construir → testar manualmente → validar efeitos → automatizar.

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

**O que confirma que funcionou:** A automation rule aparece na lista em **Sentinel → Automation → Automation rules** com status "Enabled" e Order 1. Para validar o funcionamento end-to-end, criar um novo incidente de teste no Sentinel com severidade High e entidade Account — o incidente receberá automaticamente a tag `playbook-executed` e o comentário do playbook será adicionado em até 2 minutos, sem nenhuma ação manual do analista.

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
                          "messageBody": "ALERTA SOC - CONTA COMPROMETIDA. Usuario: @{concat(items('For_each_entities')?['properties']?['accountName'],'@',items('For_each_entities')?['properties']?['upnSuffix'])}. Severidade: @{triggerBody()?['object']?['properties']?['severity']}. Sessoes revogadas automaticamente.",
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
                          "message": "[PLAYBOOK] Executado em @{utcNow()}. Sessoes revogadas. Teams notificado."
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

**1. Erro mais comum — Managed Identity sem permissão Graph antes do teste**

O Passo 3 deve ser executado antes do Passo 8. Sem as permissões `User.ReadWrite.All` e `GroupMember.ReadWrite.All` concedidas via PowerShell no Passo 3, o Microsoft Graph retorna `403 Forbidden` ao endpoint `revokeSignInSessions` — mesmo que o token seja válido, ele não possui o escopo de permissão necessário para a operação.

**Por que esta é a resposta correta:** A Managed Identity é o mecanismo de autenticação sem credenciais do Logic App. Permissões no Entra ID são pré-condição para chamadas Graph bem-sucedidas — conceder permissões após um erro 403 resolve o problema na próxima execução, mas a sequência correta é sempre garantir o alicerce de autorização antes de testar. A ordem Passo 3 → Passo 8 é obrigatória.

**O que verificar:** No Run History, clicar na ação "Revogar Sessoes - Graph API" com status vermelho. Se o body da resposta contiver `"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges..."}`, a permissão não foi concedida corretamente. Reexecutar o script PowerShell do Passo 3 e aguardar 2-3 minutos para propagação no Entra ID antes de tentar executar o playbook novamente.

---

**2. Erro de connection no Teams — conta sem acesso ao time**

O conector Teams requer autenticação com uma conta que tem acesso ao time SOC-Meridian no Teams. Usar a conta de lab fornecida pelo CECyber.

**Por que esta é a resposta correta:** O conector Microsoft Teams no Logic App usa OAuth delegado — autentica como um usuário real, não como a Managed Identity. A conta utilizada para criar a connection precisa ser membro do time "SOC-Meridian" no Teams e ter licença Microsoft Teams ativa. Contas de trial recém-criadas ou contas sem licença Teams atribuída retornarão erro de autorização mesmo que o token de autenticação seja gerado com sucesso. A conta de lab do CECyber já tem as permissões necessárias pré-configuradas para o ambiente do laboratório.

**O que verificar:** Em **Portal Azure → meridian-conta-comprometida-resposta → API connections**, verificar se a connection Teams exibe status "Connected" com ícone verde. Se exibir "Unauthorized" ou "Invalid credentials", deletar a connection, clicar em "Add a connection" na ação Teams e reautenticar com a conta de lab do CECyber. Confirmar que essa conta tem acesso ao time SOC-Meridian no Teams antes de recriar a connection.

---

**3. Erro 401 na ação Graph API — token não gerado corretamente**

Managed Identity gera tokens automaticamente — se der erro 401, verificar se as permissões foram concedidas corretamente no Passo 3 e se o campo Audience está configurado sem barra final.

**Por que esta é a resposta correta:** Ao contrário de tokens OAuth de usuário (que expiram e precisam de refresh manual), tokens de Managed Identity são gerenciados automaticamente pelo Azure. Um erro `401 Unauthorized` (distinto do `403 Forbidden`) indica especificamente que o token não está sendo gerado corretamente — o que geralmente ocorre em dois cenários: a Managed Identity está desabilitada (Status = Off no Identity blade) ou o campo "Audience" na ação HTTP está configurado incorretamente, como `https://graph.microsoft.com/` (com barra final — uma barra extra causa falha de validação do token pela Microsoft).

**O que verificar:** No Passo 5, clicar na ação HTTP e confirmar que Authentication está como "Managed Identity" e Audience como `https://graph.microsoft.com` (exatamente, sem espaços ou barra final). Verificar também em **Portal Azure → Identity** que Status está "On" e que o Object ID está preenchido com um GUID válido. Se ambos estiverem corretos e o erro 401 persistir, aguardar 5 minutos — a propagação da Managed Identity no Entra ID pode levar alguns minutos após a habilitação inicial no Passo 3.

---

**4. Sessão não revogada imediatamente — propagação assíncrona**

O Microsoft Graph pode demorar até 5 minutos para propagar a revogação pelos serviços Microsoft 365. Verificar no Entra ID após o intervalo de propagação, não imediatamente após o teste.

**Por que esta é a resposta correta:** A revogação de sessão via Graph API é uma operação assíncrona no backend da Microsoft. O endpoint `revokeSignInSessions` retorna `{"value": true}` imediatamente — indicando que a revogação foi enfileirada com sucesso —, mas a propagação pelos serviços Microsoft 365 (Exchange Online, SharePoint, Teams, OneDrive) pode levar de 1 a 5 minutos, pois cada serviço precisa invalidar seus próprios caches de token de acesso. O campo `SignInSessionsValidFromDateTime` no Entra ID é o indicador definitivo de que a revogação foi registrada no plano de controle.

**O que verificar:** Aguardar 5 minutos após a execução do playbook e então executar:
```powershell
Get-MgUser -UserId "rafael.torres@bancomeridian-lab.onmicrosoft.com" |
    Select-Object SignInSessionsValidFromDateTime
```
O timestamp deve corresponder ao horário da execução do playbook. Se `SignInSessionsValidFromDateTime` não mudou após 5 minutos, verificar no Run History se o HTTP body retornou `{"value": true}` — um retorno `{"value": false}` indica que não havia sessões ativas para revogar (resultado também válido em ambiente de lab onde o usuário não fez login recente), não necessariamente um erro de configuração do playbook.

---

### Verificação Final em KQL

```kql
// Verificar se o playbook gerou comentários nos incidentes
SecurityIncident
| where TimeGenerated > ago(2h)
| where Comments has "PLAYBOOK"
| project TimeGenerated, IncidentNumber, Title, Severity, Comments
```

**Por que esta query confirma o funcionamento do playbook:** A tabela `SecurityIncident` no Log Analytics registra o estado de cada incidente ao longo do tempo, incluindo comentários adicionados. A presença de registros com `Comments has "PLAYBOOK"` prova que a ação "Add comment to incident (V3)" do Logic App foi executada com sucesso e que o comentário foi persistido no workspace do Sentinel. Esta é a validação de auditoria mais robusta disponível — mesmo que o portal visual do Sentinel demore para atualizar o cache da aba Comments, a query KQL consulta diretamente o Log Analytics e reflete o estado real dos dados.

**O que verificar:** A query deve retornar ao menos uma linha com o incidente de rafael.torres, com o campo `Comments` contendo o texto `[AUTOMACAO PLAYBOOK]` e o timestamp UTC da execução. Se a query não retornar resultados após 10 minutos da execução do playbook, confirmar que o workspace `meridian-secops-prod` está selecionado corretamente no escopo do Log Analytics e verificar se a connection do Sentinel no Logic App usa a role "Microsoft Sentinel Contributor" ou superior — roles de leitura apenas ("Microsoft Sentinel Reader") não têm permissão para gravar comentários no incidente.
