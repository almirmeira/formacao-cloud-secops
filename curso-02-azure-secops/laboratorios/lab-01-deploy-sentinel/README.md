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

```
┌─────────────────────────────────────────────────────────────────┐
│  SOC BANCO MERIDIAN — SEGUNDA-FEIRA, 07:45                       │
│  Analistas em turno: Felipe Andrade (L2), Patricia Souza (L1)    │
│                                                                   │
│  PAINEL DE ALERTAS:                                              │
│  [—] Nenhum alerta ativo — 0 incidentes abertos                 │
│                                                                   │
│  DATA CONNECTORS ATIVOS:  0 / 4 esperados                       │
│  ANALYTICS RULES ATIVAS:  0                                      │
│  ÚLTIMA INGESTÃO:         nunca                                  │
│                                                                   │
│  STATUS DO SENTINEL:      NÃO HABILITADO                         │
└─────────────────────────────────────────────────────────────────┘

"Felipe, o CISO acabou de encaminhar um relatório do FS-ISAC. Três bancos
 tier-2 foram comprometidos por AiTM phishing na última semana. Nosso Sentinel
 ainda não está em ar. O board aprovou o orçamento há dois dias — precisamos
 estar operacionais hoje." — Patricia Souza, Analista L1
```

**Estado do ambiente ao iniciar o lab**:
- Subscription Azure disponível: `Banco-Meridian-Sandbox`
- Resource Group vazio: `rg-meridian-secops`
- Tenant M365 E5 ativo com 5 usuários de teste pré-criados
- Domínio: `bancomeridian-lab.onmicrosoft.com`
- Microsoft Sentinel: **NÃO habilitado**
- Data connectors: **NENHUM configurado** — os logs existem no Entra ID, mas não chegam ao Sentinel
- Analytics rules: **ZERO ativas** — sem detecção automática de qualquer ataque
- Alertas automáticos: **NENHUM**

O ambiente é um blank slate. Tudo que existe é a subscription Azure com permissões para criar recursos. Os próximos 2 horas determinarão se o banco tem ou não visibilidade sobre o que acontece em seus sistemas Microsoft.

**Credenciais de acesso ao ambiente**:
Fornecidas pelo instrutor via portal CECyber Labs.

---

## Seção 3 — Problema Identificado

```
Patricia Souza recebe um e-mail às 08:12 do CISO:

"Patricia, Felipe — recebi do FS-ISAC um relatório classificado indicando que
o Grupo Lazarus-BR está executando ataques AiTM (Adversary-in-the-Middle) e
password spray contra bancos tier-2 brasileiros. Banco Ipê, Banco Caiçara e
Banco Litoral foram comprometidos nas últimas 2 semanas. Todos usam M365.

Precisamos saber: se esse grupo tentar nos atacar agora, nós detectaríamos?

A resposta honesta, infelizmente, é NÃO. Não temos como saber.

Quero o Sentinel em operação hoje. Quero um relatório de status às 17h."
```

**Diagnóstico técnico do problema:**

O Banco Meridian tem, neste momento, **zero visibilidade** operacional sobre atividades suspeitas em seus sistemas Microsoft 365. Isso significa:

1. **Logs existem mas não são monitorados**: O Entra ID gera automaticamente logs de autenticação (SigninLogs) para todos os 2.800 funcionários. Esses logs registram cada login, o IP de origem, o país, o dispositivo. Mas sem o Sentinel, esses logs ficam no Entra ID por 30 dias e são deletados — ninguém os consulta em tempo real.

2. **Ataques em andamento são invisíveis**: Um attacker fazendo password spray agora — tentando a senha `Banco2024!` em 200 contas — não geraria nenhum alerta. Os logs existiriam, mas sem regra de detecção, ninguém saberia.

3. **Risco BACEN**: A Resolução 4.893 exige que bancos mantenham registros de acesso por 5 anos e reportem incidentes ao BACEN em até 1 dia útil. Sem um SIEM, o banco não consegue cumprir nenhum desses requisitos de forma eficiente.

4. **Janela de oportunidade do attacker**: Cada hora sem monitoramento é uma hora em que um attacker pode entrar, se mover lateralmente e extrair dados sem ser detectado. O relatório do FS-ISAC indica que o Grupo Lazarus-BR leva em média 4 horas do phishing inicial até o acesso a dados sensíveis.

**O que precisamos criar nas próximas 2 horas para mudar esse cenário.**

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

**O que este passo faz:** O workspace Log Analytics é o repositório central de dados do Microsoft Sentinel — é onde todos os logs ingeridos ficam armazenados e onde o KQL é executado. Pense nele como o banco de dados que sustenta tudo: cada query, cada alerta, cada dashboard consome dados desse workspace. Sem ele, o Sentinel não existe. Escolher a região Brazil South é deliberado: a legislação BACEN e a LGPD exigem que dados de cidadãos e operações financeiras brasileiras sejam preferencialmente armazenados em território nacional. Um workspace em East US, por exemplo, significaria que logs de autenticação dos 2.800 funcionários do Banco Meridian trafegam para fora do Brasil.

**Por que agora:** O workspace deve ser o primeiro recurso criado porque todos os demais — o próprio Sentinel, os data connectors, as tabelas de retenção — dependem de sua existência. Criar o Sentinel sem workspace é impossível.

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

**O que você deve ver:** Workspace criado em 2-3 minutos. Verificar no portal que o resource aparece em `rg-meridian-secops` com Region = Brazil South. Se a região aparecer diferente, o workspace foi criado no local errado e precisará ser recriado — dados não podem ser migrados entre regiões.

**O que fazer se der errado:**
- Se Brazil South não estiver disponível: usar East US 2 (segunda opção preferida)
- Se receber erro de quotas: contatar o instrutor para ajuste da sandbox

---

### Passo 2: Habilitar o Microsoft Sentinel

**O que este passo faz:** Habilitar o Sentinel sobre o workspace Log Analytics é o ato de ativar a camada de SIEM/SOAR. O Sentinel não é um serviço independente — ele é uma extensão do Log Analytics que adiciona capacidades de detecção (analytics rules), investigação (incidents, entity behavior), hunting e resposta automatizada (playbooks). Internamente, o Sentinel registra um resource provider no Azure (`Microsoft.SecurityInsights`) e cria metadados de configuração dentro do workspace. Após este passo, o workspace passa a ter uma fila de incidentes, suporte a analytics rules e o Content Hub disponível.

**Por que agora:** O Sentinel precisa do workspace existente antes de ser habilitado. E ele precisa estar habilitado antes de qualquer data connector ser configurado — conectar fontes de dados sem o Sentinel ativo faz os logs chegarem ao workspace, mas sem capacidade de detecção ou gestão de incidentes.

1. Navegar para o workspace criado: **meridian-secops-prod**
2. No menu lateral, localizar **Microsoft Sentinel**
3. Clicar em **Add Microsoft Sentinel**
4. Selecionar o workspace **meridian-secops-prod**
5. Clicar em **Add**

**O que você deve ver:** O Sentinel é habilitado em 2-3 minutos. O portal redireciona automaticamente para o Overview do Sentinel, com painéis de incidentes, alertas e saúde dos conectores — todos zerados, pois nenhuma fonte de dados foi conectada ainda.

**Verificação:**
```powershell
# PowerShell: verificar que o Sentinel está habilitado
Get-AzSentinelWorkspace -ResourceGroupName "rg-meridian-secops" -WorkspaceName "meridian-secops-prod"
# Deve retornar o objeto com o workspace ID
```

**O que fazer se der errado:**
- Erro "already exists": o Sentinel já pode estar habilitado — verificar navegando diretamente
- Erro de permissão: você precisa de pelo menos Contributor na subscription

---

### Passo 3: Configurar Retenção por Tabela

**O que este passo faz:** Por padrão, o Log Analytics retém dados por 30 dias no armazenamento interativo (pesquisável via KQL) e depois os descarta. Para o Banco Meridian, isso é inadequado sob dois aspectos regulatórios críticos: (1) a Resolução BACEN 4.893, art. 19, exige que logs de acesso a sistemas de informação financeira sejam mantidos por no mínimo 5 anos; (2) a CMN 4.658 exige rastreabilidade de acessos. Este passo configura cada tabela crítica para retenção de 1.825 dias (5 anos), sendo 90 dias em armazenamento interativo de baixo custo (busca instantânea por KQL) e o restante em armazenamento de arquivo (recuperável em minutos quando necessário para auditorias). Sem esta configuração, um auditor do BACEN que pedir logs de um incidente ocorrido há 18 meses receberá uma resposta de "dados não disponíveis" — o que configura descumprimento regulatório.

**Por que agora:** A retenção deve ser configurada antes de qualquer dado começar a chegar. O Sentinel aplica a política de retenção a dados novos, não retroativamente a dados já armazenados. Se você configurar depois de 30 dias de operação, os primeiros 30 dias de logs podem já ter sido descartados.

**Portal Azure → meridian-secops-prod → Tables**

Configurar as seguintes tabelas para retenção estendida (BACEN 4.893 e CMN 4.658):

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

**O que você deve ver:** Cada tabela editada exibe Interactive: 90d, Total: 1825d (5 anos). O custo de armazenamento de arquivo é significativamente menor que o de armazenamento interativo — aproximadamente 1/10 do preço. Isso torna a retenção de 5 anos economicamente viável mesmo para bancos de médio porte como o Meridian.

**O que fazer se der errado:**
- Tabelas aparecem somente após a primeira ingestão de dados — algumas podem não estar disponíveis ainda. Configure as que estiverem disponíveis e retorne após a ingestão para as demais.
- Se o campo "Total retention period" não aparecer, a subscription pode não ter a feature de archive habilitada — verificar com o instrutor.

---

### Passo 4: Conectar Microsoft Entra ID

**O que este passo faz:** O conector Microsoft Entra ID é o mais crítico do ambiente do Banco Meridian — é ele que alimenta o Sentinel com os logs de autenticação de todos os 2.800 funcionários. Sem este conector, ataques de credential stuffing, password spray, AiTM phishing e impossible travel são completamente invisíveis. Ao habilitar os quatro tipos de log (Sign-in interativos, Audit, não-interativos e de Service Principal), o Sentinel passa a receber: cada tentativa de login (bem-sucedida ou falha), com IP de origem, país, dispositivo, aplicativo acessado e código de resultado; cada alteração de configuração no Entra ID (criação de usuário, adição a grupo, reset de MFA); e cada autenticação de aplicação ou serviço. Esse volume de telemetria é a base sobre a qual todas as analytics rules de identidade serão construídas nos módulos seguintes.

**Por que agora:** O conector de identidade deve ser configurado antes das analytics rules, porque as rules consultam tabelas como `SigninLogs` e `AuditLogs` que só existem após a conexão. Além disso, o Sentinel começa a receber dados históricos desde o momento da conexão — quanto antes conectar, mais histórico estará disponível para as regras de detecção baseadas em baseline (como impossible travel e detecção de anomalias).

**Sentinel → Data connectors → Pesquisar "Microsoft Entra ID" → Open connector page**

1. Verificar pré-requisitos: conta precisa de **Security Administrator** ou **Global Administrator**
2. Na seção "Configuration", selecionar:
   - ✓ Sign-in Logs
   - ✓ Audit Logs
   - ✓ Non-Interactive User Sign-In Logs
   - ✓ Service Principal Sign-In Logs
3. Clicar em **Apply Changes**

**O que você deve ver:** Status do conector muda para "Connected" em até 15 minutos. A tabela `SigninLogs` começa a aparecer no Log Analytics com eventos reais de autenticação do tenant.

**Verificação após 15 minutos:**
```kql
SigninLogs
| where TimeGenerated > ago(30m)
| count
// Deve retornar pelo menos 1 registro
```

**O que fazer se der errado:**
- Se o conector aparecer como "Disconnected" após 20 minutos: verificar se a conta tem permissão de Global Admin ou Security Admin no tenant M365
- Se o count retornar 0: aguardar mais 15 minutos e tentar novamente — logins precisam ocorrer para gerar registros em `SigninLogs`

---

### Passo 5: Conectar Microsoft Defender XDR

**O que este passo faz:** O conector Microsoft Defender XDR unifica o ecossistema de detecção Microsoft dentro do Sentinel. Ele sincroniza incidentes criados no portal security.microsoft.com (Defender XDR) para o Sentinel, e opcionalmente ingere tabelas avançadas de telemetria de endpoint (DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents) e e-mail (EmailEvents). Para o Banco Meridian, isso significa que um analista pode investigar um incidente que começou como phishing no Defender for Office 365, passou por comprometimento de identidade no Defender for Identity e culminou em execução de código no endpoint — tudo dentro do Sentinel, sem precisar trocar de portal. A opção "Turn off all Microsoft incident creation rules" é especialmente importante: sem ela, o Defender XDR cria incidentes na sua plataforma E o Sentinel cria incidentes separados para os mesmos eventos, resultando em duplicatas que confundem os analistas e distorcem as métricas de MTTD/MTTR.

**Por que agora:** Configurar o XDR connector logo após o Entra ID garante que o Sentinel receba telemetria de endpoint e e-mail desde o início. Incidentes do Defender XDR que chegam ao Sentinel antes das analytics rules customizadas estarem prontas servem como "primeiros alertas" enquanto o SOC está sendo construído — ou seja, o banco já tem algum nível de detecção mesmo durante o período de configuração.

**Sentinel → Data connectors → Pesquisar "Microsoft Defender XDR" → Open connector page**

**ATENÇÃO — Configuração crítica:**

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

**O que você deve ver:** Status "Connected". Incidentes do Defender XDR começam a aparecer no Sentinel. As tabelas avançadas como `DeviceEvents` e `EmailEvents` passam a ter dados disponíveis para queries KQL.

**Verificação:**
```kql
// Verificar se incidentes chegaram
SecurityIncident
| where TimeGenerated > ago(1h)
| count
```

**O que fazer se der errado:**
- Se não aparecerem incidentes: verificar se há alertas ativos no portal security.microsoft.com — sem alertas no XDR, não há incidentes para sincronizar
- Se aparecerem incidentes duplicados: verificar se a opção "Turn off all Microsoft incident creation rules" foi ativada — editar o conector e marcar a opção

---

### Passo 6: Conectar Azure Activity

**O que este passo faz:** O conector Azure Activity captura todos os eventos do plano de controle do Azure — criação e exclusão de recursos, mudanças de configuração, atribuição de roles, modificações em Network Security Groups (NSGs), ativação de políticas. Para o Banco Meridian, isso é crítico para detectar ataques de escalada de privilégio na nuvem: um atacante que comprometeu uma conta de desenvolvedor e tenta se tornar Contributor ou Owner na subscription gerará eventos no AzureActivity. Além disso, a exclusão acidental ou maliciosa de recursos críticos (VMs, Key Vaults, workspaces) fica registrada aqui. O mecanismo de conexão via Azure Policy é diferente dos outros conectores: em vez de uma configuração direta, uma política de diagnóstico é aplicada via Azure Policy a toda a subscription, garantindo que qualquer novo resource group criado no futuro também envie logs automaticamente — sem necessidade de reconfiguração.

**Por que agora:** Configurar o Azure Activity agora garante que operações de administração do ambiente de lab — incluindo a criação dos próprios recursos deste lab — sejam auditadas. É uma boa prática de segurança: o Banco Meridian deve ter visibilidade de todas as operações administrativas na sua subscription desde o primeiro dia.

**Sentinel → Data connectors → Pesquisar "Azure Activity" → Open connector page**

1. Clicar em **Launch Azure Policy Assignment Wizard**
2. Na tela de Policy Assignment:
   - Scope: Subscription Banco-Meridian-Sandbox
   - Assignment name: "Azure Activity to Sentinel"
3. Na aba **Parameters**: selecionar o workspace `meridian-secops-prod`
4. Na aba **Remediation**: ✓ Create a remediation task
5. Clicar em **Review + Create → Create**

**O que você deve ver:** Em 5-10 minutos, logs de operações Azure começam a chegar na tabela `AzureActivity`. Operações como "Create or Update Workspace" (criação do próprio workspace neste lab) devem aparecer entre os primeiros eventos.

**Verificação:**
```kql
AzureActivity
| where TimeGenerated > ago(1h)
| summarize count() by OperationName
| top 10 by count_
```

**O que fazer se der errado:**
- Se não houver dados: a remediação automática pode demorar até 30 minutos. Aguardar e tentar novamente — a policy assignment precisa de tempo para propagar na subscription.

---

### Passo 7: Conectar Office 365

**O que este passo faz:** O conector Office 365 alimenta a tabela `OfficeActivity` com eventos de atividade nos três principais workloads do Microsoft 365: Exchange Online (envio/recebimento de e-mails, regras de caixa de entrada, acesso a caixas alheias), SharePoint Online (download, upload, compartilhamento de arquivos, criação de sites) e Microsoft Teams (mensagens, criação de canais, adição de membros externos). Para o Banco Meridian, essa telemetria é fundamental para dois cenários de insider threat frequentes em instituições financeiras: a detecção de encaminhamento de e-mail para endereços externos (T1114.003), onde um funcionário ou atacante cria regras para copiar toda a correspondência corporativa; e a detecção de download em massa de arquivos do SharePoint (T1213.002), onde arquivos de clientes ou estratégias confidenciais são exfiltrados antes de uma demissão ou em apoio a um concorrente. Esses eventos não aparecem nos logs de autenticação do Entra ID — eles são exclusivos do `OfficeActivity`.

**Por que agora:** Configurar o conector M365 em paralelo com os demais garante que eventos de e-mail e SharePoint sejam correlacionáveis com eventos de autenticação desde o início. Uma investigação de insider threat que depende de correlacionar "login suspeito" (SigninLogs) com "download de arquivos" (OfficeActivity) só é possível se ambas as fontes tiverem histórico simultâneo.

**Sentinel → Data connectors → Pesquisar "Office 365" → Open connector page**

1. Na seção "Configuration":
   - ✓ Exchange
   - ✓ SharePoint
   - ✓ Teams
2. Clicar em **Apply Changes**

**O que você deve ver:** Logs de atividade de Exchange, SharePoint e Teams chegam na tabela `OfficeActivity`. Cada tipo de workload gera eventos com `RecordType` diferente: ExchangeItem, SharePointFileOperation, MicrosoftTeams.

**Verificação:**
```kql
OfficeActivity
| where TimeGenerated > ago(2h)
| summarize count() by RecordType
```

**O que fazer se der errado:**
- Alguns workloads (especialmente Teams) podem demorar até 24h para ingestão inicial — isso é comportamento normal da Microsoft, não um erro de configuração
- Exchange geralmente tem dados em 15-20 minutos se há atividade de e-mail no tenant

---

### Passo 8: Instalar Solução via Content Hub

**O que este passo faz:** O Content Hub é o marketplace de conteúdo de segurança do Microsoft Sentinel. A solução "Microsoft Entra ID" publicada pela própria Microsoft contém dezenas de analytics rules pré-construídas, workbooks de visualização e hunting queries prontas para uso — todo baseado em anos de expertise do time de segurança da Microsoft e da comunidade global de analistas SOC. Em vez de criar detecções do zero, o Banco Meridian herda imediatamente um catálogo de detecções para os principais padrões de ataque contra identidades Microsoft: brute force, MFA fatigue, impossible travel, sign-in com IP de VPN anonimizador, roubo de token, entre outros. Isso é equivalente a contratar uma equipe especializada de detection engineers por alguns minutos de instalação — o valor real está em adaptar e calibrar essas regras para o ambiente específico do banco nos módulos seguintes.

**Por que agora:** O Content Hub deve ser instalado antes de ativar as analytics rules, pois ele é justamente a fonte dos templates de regra. Sem a solução instalada, o painel de analytics rules terá muito menos opções disponíveis.

**Sentinel → Content Hub → Pesquisar "Microsoft Entra ID"**

1. Selecionar **Microsoft Entra ID** (publicado pela Microsoft)
2. Clicar em **Install**
3. Aguardar a instalação (~3 minutos)
4. Clicar em **Manage** para visualizar o conteúdo instalado

**O que você deve ver:** 30+ analytics rules templates, 15 workbooks e 20+ hunting queries instalados e disponíveis em seus respectivos painéis. O painel "Analytics → Rule templates" passará a listar essas regras filtradas por "Microsoft Entra ID".

---

### Passo 9: Ativar 3 Analytics Rules

**O que este passo faz:** Analytics rules são o coração da detecção automática no Sentinel. Elas executam queries KQL em intervalos regulares e geram alertas (e incidentes) quando encontram padrões suspeitos nos dados. Ativar as três rules a seguir é a diferença entre ter um workspace com dados e ter um SOC funcionando: sem rules ativas, os logs de 2.800 funcionários chegam e ficam no banco de dados sem nenhuma análise. Com as rules ativas, qualquer padrão de ataque correspondente gera um incidente automaticamente na fila do SOC.

As três rules escolhidas cobrem os vetores mais relevantes para o contexto de AiTM phishing e credential attacks que o CISO mencionou no relatório do FS-ISAC:

- **Suspicious Sign-In to Privileged Account**: detecta logins bem-sucedidos em contas com roles administrativas vindos de IPs novos, países incomuns ou dispositivos não registrados. Um attacker que comprometeu a conta de um administrador e tenta acessar o Azure Portal geraria este alerta.

- **Brute Force Attack**: detecta múltiplas tentativas de senha falhadas na mesma conta. Um attacker tentando adivinhar a senha de um funcionário usando uma lista de senhas comuns (credential stuffing) dispara esta regra. O threshold padrão é conservador — recomenda-se baixar para 5 tentativas no ambiente de lab para facilitar a visualização do comportamento.

- **MFA Rejected by User**: detecta quando um usuário recebe e rejeita uma notificação push de MFA. Isso é o indicador mais claro de MFA fatigue attack: o attacker já tem a senha correta e envia dezenas de notificações push esperando que o usuário aprove por exaustão ou engano. Cada rejeição ativa é um sinal de que alguém com a senha está tentando entrar.

**Por que agora:** As rules precisam de dados para funcionar — ativá-las antes de ter os connectors seria inútil. Agora que os quatro connectors estão ativos e produzindo telemetria, as rules têm dados para analisar e podem gerar incidentes a partir deste momento.

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

**O que você deve ver:** As 3 rules aparecem em **Analytics → Active rules** com status "Enabled". O campo "Last run" ficará vazio até a primeira execução (até 1 hora após a ativação). O campo "Next run" indica o agendamento configurado.

**Verificação:**
```kql
// Verificar se as rules estão sendo executadas e gerando alertas
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize count() by AlertName
```

**O que fazer se der errado:**
- Se a rule não aparecer nos templates: verificar se a solução "Microsoft Entra ID" foi instalada pelo Content Hub no Passo 8
- Se a rule criar mas ficar em status "Disabled": editar a rule e mudar o Status para Enabled manualmente

---

### Passo 10: Validação Final de Ingestão

**O que este passo faz:** A validação final não é apenas uma formalidade — é a prova técnica de que o ambiente está funcionando conforme especificado. A query de validação usa `union` para consultar todas as tabelas críticas em uma única execução, retornando um painel de saúde do workspace: quantos eventos chegaram por tabela e quando foi o último evento. Este resultado é o "relatório de status às 17h" que o CISO solicitou no início do lab. Mais do que uma confirmação interna, esta query representa a linha de base do ambiente: o analista Felipe Andrade pode executá-la a qualquer momento para saber instantaneamente se algum conector deixou de funcionar (tabela com contagem zerada ou LastEvent muito antigo).

**Por que agora:** A validação vem no final porque só faz sentido após todos os passos anteriores estarem completos. Executar antes dos connectors estarem ativos retornaria 0 em todas as linhas — sem diagnóstico útil. Executada agora, ela confirma que o lab atingiu o objetivo proposto: 4 fontes de dados ativas com dados fluindo para o Sentinel do Banco Meridian.

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

### Como Interpretar os Resultados de Cada Passo

**Passo 1 (Workspace + Sentinel):** O workspace `meridian-secops-prod` na região Brazil South é confirmado quando o portal exibe o painel Overview do Sentinel sem erros. O fato de estar em Brazil South é confirmado na URL do workspace: `https://portal.azure.com/#resource/subscriptions/.../resourceGroups/rg-meridian-secops/providers/Microsoft.OperationalInsights/workspaces/meridian-secops-prod/overview` — a região está no campo Location da resource. Este passo confirma que o repositório de dados existe e o Sentinel está habilitado para analisá-lo.

**Passo 3 (Retenção BACEN):** O comando PowerShell `$ws.RetentionInDays` retornar `90` confirma a retenção interativa. A retenção de 1825 dias (5 anos) para SigninLogs é confirmada na interface Portal → workspace → Tables → SigninLogs → Total retention period. Este número é crítico para compliance: um auditor do BACEN pedirá logs de um incidente ocorrido há 18 meses. Se a retenção for de 90 dias (padrão), você não terá esses logs.

**Passo 4 (Entra ID Connector):** A confirmação de sucesso não é apenas "Connected" no portal — é a presença de dados reais. Execute `SigninLogs | count` no Log Analytics. Se retornar 0, o connector está conectado mas sem dados (possível problema de permissão ou ausência de logins). Cada login que ocorrer no tenant a partir deste momento gerará um registro em SigninLogs dentro de 5-15 minutos.

**Passo 9 (Analytics Rules):** A analytics rule está funcionando corretamente quando aparece em `Analytics → Active rules` com Status = `Enabled`. A confirmação definitiva vem 24-48 horas depois, quando a rule executa sua primeira avaliação com dados reais e ou gera alertas ou fica em silêncio (comportamento normal quando não há atividade suspeita).

**Variações aceitáveis:**
- OfficeActivity pode demorar 24-48h para começar a aparecer após a conexão — isso é comportamento normal da Microsoft, não um erro
- SecurityEvent pode estar vazia se não houver VMs no resource group — isso é esperado
- A query de validação do Passo 10 pode mostrar contagens baixas (1-5 eventos) nas primeiras horas — o volume aumenta conforme atividade normal do tenant ocorre

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
