# Lab 02 — KQL Analytics: Investigação e Detecção com Kusto Query Language

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 03 — KQL para SecOps                                            |
| **Pré-requisito**        | Lab 01 concluído (Sentinel operacional com dados nos últimos 48h)      |
| **Nível**                | Iniciante-Intermediário                                                |

---

## Seção 1 — Contexto Situacional

O **Banco Meridian** implantou o Microsoft Sentinel na semana passada (Lab 01). O workspace `meridian-secops-prod` está recebendo logs do Entra ID, Office 365 e Defender XDR. Os dados chegam — mas ninguém sabe consultá-los.

O analista Felipe Andrade precisa treinar a equipe de 3 analistas L1 recém-contratados. O primeiro desafio: um funcionário relatou ter recebido uma ligação suspeita alegando ser do suporte de TI pedindo sua senha. É um possível ataque de engenharia social ou vishing preparando um acesso não autorizado. Felipe quer que a equipe aprenda a investigar usando KQL — e que a investigação real sirva como treinamento prático.

---

## Seção 2 — Situação Inicial

```
┌─────────────────────────────────────────────────────────────────────────┐
│  WORKSPACE meridian-secops-prod — QUINTA, 14:30                         │
│                                                                          │
│  DADOS DISPONÍVEIS:                                                     │
│  SigninLogs:       48h de logs ✓  (3.200+ eventos)                      │
│  AuditLogs:        48h de logs ✓  (780+ eventos)                        │
│  OfficeActivity:   24h de logs ✓  (1.100+ eventos)                      │
│  SecurityAlert:    48h de alertas  (12 alertas, nenhum crítico)          │
│                                                                          │
│  ANALYTICS RULES ATIVAS:   0  (configuradas no Lab 03)                  │
│  ANALYTICS RULES KQL:      n/a (estamos aprendendo KQL agora)           │
│                                                                          │
│  RELATO:  patricia.souza@bancomeridian-lab.onmicrosoft.com               │
│           recebeu ligação às 13:45 alegando ser "suporte Microsoft"      │
│           pedindo credenciais. Ela não forneceu — mas ficou desconfiada. │
└─────────────────────────────────────────────────────────────────────────┘

"Pessoal, isso é treinamento e investigação real ao mesmo tempo. Alguém pode
 ter tentado comprometer a Patricia hoje. Vamos usar o KQL para investigar.
 Vou mostrar os fundamentos e depois vamos caçar evidências juntos."
 — Felipe Andrade, L2 Senior
```

**Estado do ambiente:**
- Workspace Log Analytics `meridian-secops-prod` com dados das últimas 48h
- Connectors ativos: Entra ID (SigninLogs, AuditLogs), Office 365 (OfficeActivity), Microsoft Defender XDR (SecurityAlert)
- Nenhuma analytics rule ativa — as detecções ainda serão criadas no Lab 03
- Acesso ao portal: `portal.azure.com → Log Analytics → meridian-secops-prod → Logs`

---

## Seção 3 — Problema Identificado

```
"Patricia, você consegue descrever a ligação?"

"Ele sabia meu nome e meu setor. Disse que havia um 'alerta de segurança'
 na minha conta e que precisava da minha senha para resolver. Desliguei, mas
 fiquei preocupada."

"Bom que você desligou. Agora precisamos investigar: alguém tentou logar
 na sua conta depois disso? Tentaram acessar seus e-mails? Mudaram alguma
 configuração?"
 — Diálogo entre Felipe e Patricia Souza
```

**O problema técnico que o KQL resolve:**

O relato da Patricia indica um ataque de engenharia social — possivelmente um vishing que antecede uma tentativa de acesso não autorizado. O attacker pode ter obtido informações suficientes para tentar:
1. Um ataque de credential stuffing usando a senha que a Patricia *quase* revelou
2. Um reset de senha usando informações pessoais coletadas
3. Um ataque de MFA fatigue — enviar múltiplas solicitações de MFA esperando que o usuário aprove por cansaço

Sem KQL, a investigação seria clicar em cada log manualmente. Com KQL, respondemos em minutos.

---

## Seção 4 — Roteiro de Atividades

| Passo | Atividade | Tempo Estimado |
|:-----:|:----------|:--------------:|
| 1 | Acessar o Log Analytics Workspace e entender o ambiente | 10 min |
| 2 | Query básica: ver os últimos 50 eventos de SigninLogs | 5 min |
| 3 | Filtrar por usuário: todos os logins de patricia.souza hoje | 10 min |
| 4 | Investigar logins falhos: identificar IPs e países suspeitos | 15 min |
| 5 | Verificar alterações de conta: consultar AuditLogs | 10 min |
| 6 | Verificar atividade de e-mail: consultar OfficeActivity | 10 min |
| 7 | Correlação: usuário + alertas de segurança correlacionados | 15 min |
| 8 | Agregação: resumo de logins por país nos últimos 7 dias | 10 min |
| 9 | Criar Hunting Query salva com mapeamento MITRE | 15 min |
| 10 | Exportar resultados e documentar evidências | 10 min |

**Total estimado:** 1h50min + 10 min de margem para perguntas

---

## Seção 5 — Proposição

Ao final deste laboratório, a equipe do SOC do Banco Meridian terá:
- Domínio dos 8 operadores KQL fundamentais para SecOps (where, project, summarize, join, render, distinct, extend, sort)
- Capacidade de investigar qualquer incidente de identidade usando SigninLogs e AuditLogs
- Capacidade de correlacionar eventos de e-mail com autenticação usando OfficeActivity
- Uma Hunting Query salva no Sentinel com mapeamento MITRE ATT&CK
- Relatório de investigação do incidente da Patricia Souza com conclusão técnica

---

## Seção 6 — Script Passo a Passo

### Passo 1: Acessar o Log Analytics e Entender o Ambiente

**Por que este passo é necessário:** Antes de escrever qualquer query, é fundamental verificar que os dados estão disponíveis e entender a estrutura do workspace. Um erro muito comum de analistas iniciantes é passar horas depurando uma query KQL que "não retorna nada" quando o problema real é que o data connector não está ativo ou os dados ainda não chegaram ao workspace. Este diagnóstico inicial economiza muito tempo.

**Portal Azure → Log Analytics workspaces → meridian-secops-prod → Logs**

Fechar a janela "Example Queries" que abre automaticamente. Você estará na interface de query em branco.

**Query de diagnóstico — verificar tabelas disponíveis:**

```kql
// Lista todas as tabelas com dados nas últimas 48h e o número de registros
union withsource=TableName *
| where TimeGenerated > ago(48h)
| summarize RegistrosDisponiveis = count() by TableName
| sort by RegistrosDisponiveis desc
| project TableName, RegistrosDisponiveis
```

**Interpretando o resultado:**

A query acima retorna uma linha para cada tabela com dados disponíveis. O que observar:
- `SigninLogs`: deve ter centenas a milhares de registros (cada autenticação gera um registro)
- `AuditLogs`: dezenas a centenas de registros (alterações de configuração, criação/exclusão de usuários)
- `OfficeActivity`: centenas de registros se o M365 foi recentemente conectado
- `SecurityAlert`: poucos registros se nenhuma rule foi ativada ainda
- Tabelas com 0 não aparecem na lista — se `SigninLogs` não aparecer, o connector não está ativo

> **⚠️ Atenção:** Se `SigninLogs` aparecer com contagem muito baixa (< 10 registros), pode ser que o tenant de lab tenha pouca atividade simulada. Nesse caso, expanda o filtro de tempo de `48h` para `7d` nas queries seguintes.

> **💡 Dica do instrutor:** O `union withsource=TableName *` é a primeira query que um analista deve executar em qualquer workspace desconhecido. Ela mapeia exatamente com que dados você pode trabalhar — uma espécie de "inventário" do workspace.

---

### Passo 2: Query Básica — Primeiros 50 Registros de SigninLogs

**Por que este passo é necessário:** O SigninLogs é a tabela mais importante para investigação de identidade. Cada tentativa de autenticação — bem-sucedida ou falha — gera um registro. Antes de filtrar por usuário ou IP, precisamos entender a estrutura da tabela: quais colunas existem, que tipo de dado cada coluna armazena, quais valores de ResultType indicam sucesso versus falha.

```kql
// Ver estrutura e exemplos dos dados de autenticação
SigninLogs
| take 50
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,          // Cidade e país do login
    ResultType,        // 0 = sucesso, outros = falha (ver tabela de códigos)
    ResultDescription, // Descrição legível do resultado
    AppDisplayName,    // Aplicativo que foi acessado
    DeviceDetail       // Informações do dispositivo (JSON)
```

**Interpretando o resultado:**

| Campo | O que significa |
|:------|:----------------|
| `TimeGenerated` | Timestamp UTC do evento. Lembre: Brasil está UTC-3 (horário padrão) ou UTC-2 (horário de verão) |
| `UserPrincipalName` | E-mail do usuário que tentou autenticar |
| `IPAddress` | IP de origem da tentativa. IPs 10.x.x.x e 192.168.x.x são redes internas |
| `Location` | Cidade e país codificados em JSON. Pode usar `tostring(Location.city)` para extrair |
| `ResultType = 0` | Login bem-sucedido |
| `ResultType != 0` | Falha. Os códigos mais comuns: 50126 (senha incorreta), 50053 (conta bloqueada), 50074 (MFA necessário), 70011 (token revogado) |
| `AppDisplayName` | "Microsoft Teams", "Office 365", "Azure Portal" — indica o serviço acessado |

> **💡 Dica do instrutor:** No KQL, `take 50` não garante os 50 mais recentes — pega os primeiros 50 encontrados pelo engine. Para os mais recentes, use `| sort by TimeGenerated desc | take 50`. Em investigações, sempre ordene por tempo para entender a sequência de eventos.

---

### Passo 3: Filtrar por Usuário — Todos os Logins de patricia.souza Hoje

**Por que este passo é necessário:** Após o relato da Patricia, a primeira pergunta a responder é: "houve alguma tentativa de acesso à conta dela desde o horário da ligação (13:45 hoje)?". Um filtro por UserPrincipalName e período temporal específico responde isso diretamente. Não precisamos analisar os 3.200 eventos do workspace — apenas os que são relevantes para a investigação.

```kql
// Todos os eventos de autenticação de Patricia hoje
SigninLogs
| where TimeGenerated > ago(12h)
| where UserPrincipalName == "patricia.souza@bancomeridian-lab.onmicrosoft.com"
| sort by TimeGenerated desc
| project
    TimeGenerated,
    ResultType,
    ResultDescription,
    IPAddress,
    tostring(LocationDetails.city) as Cidade,
    tostring(LocationDetails.countryOrRegion) as Pais,
    AppDisplayName,
    tostring(DeviceDetail.operatingSystem) as SistemaOperacional
```

**Interpretando o resultado:**

O que procurar nos resultados:
- Registros com `ResultType != 0` após 13:45 → indício de tentativas de acesso não autorizadas
- IPs distintos dos que Patricia usa normalmente → possível acesso de terceiros
- País diferente de `Brazil` → muito suspeito se Patricia não estava viajando
- `AppDisplayName = "Azure Portal"` → tentativa de acesso administrativo
- Múltiplos falhos em sequência rápida → brute force ou credential stuffing

> **⚠️ Atenção:** O campo `ResultDescription` para código `50126` é "Invalid username or password or Invalid on-premises username or password." — note que o texto diz "invalid username OR password". Por motivos de segurança, o Entra ID não especifica qual dos dois está incorreto, para não ajudar o attacker a descobrir se o usuário existe.

> **Por que isso importa para o Banco Meridian:** Se encontrarmos logins falhos de um IP estrangeiro após 13:45, combinados com o relato do vishing, temos evidência de um ataque coordenado: o engenheiro social coleta informações e imediatamente um cúmplice tenta o acesso usando essas informações. A correlação temporal (hora da ligação × hora da tentativa de acesso) é a evidência mais poderosa.

---

### Passo 4: Investigar Logins Falhos — IPs e Países Suspeitos

**Por que este passo é necessário:** Logins falhos são o sinal mais importante de ataques de credential stuffing e password spray. Uma única falha pode ser erro humano — 5 falhas do mesmo IP em 5 minutos, com senhas diferentes, é um ataque. Precisamos agregar os dados para identificar padrões, não apenas ver registros individuais.

```kql
// Todos os logins falhos do tenant nas últimas 24h, agrupados por IP
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| where ResultType != 50074  // Excluir "MFA required" — não é falha de credencial
| where ResultType != 50076  // Excluir "MFA required for app" — idem
| summarize
    TentativasFalhas = count(),
    ContasAlvo = dcount(UserPrincipalName),
    PrimeiraTentativa = min(TimeGenerated),
    UltimaTentativa = max(TimeGenerated),
    ListaContas = make_set(UserPrincipalName),
    Erros = make_set(ResultDescription)
    by IPAddress, tostring(LocationDetails.countryOrRegion) as Pais
| sort by TentativasFalhas desc
| project IPAddress, Pais, TentativasFalhas, ContasAlvo, PrimeiraTentativa, UltimaTentativa, ListaContas
```

**Interpretando o resultado:**

| Padrão | Interpretação |
|:-------|:--------------|
| `ContasAlvo > 5` e `TentativasFalhas < 10` | Password Spray: poucas tentativas por conta para evitar bloqueio (T1110.003) |
| `ContasAlvo = 1` e `TentativasFalhas > 10` | Brute Force: muitas tentativas em uma conta (T1110.001) |
| `Pais = "RU"` ou `"CN"` ou desconhecido | Alto risco — IPs de países sem relação com o negócio do banco |
| `PrimeiraTentativa` próximo ao horário do vishing | Evidência de ataque coordenado com a engenharia social |

**Variações aceitáveis da query:** Você pode substituir `24h` por `1h` para focar no período após a ligação. Também pode adicionar `| where UserPrincipalName == "patricia.souza@..."` para focar apenas na Patricia.

---

### Passo 5: Verificar Alterações de Conta — Consultar AuditLogs

**Por que este passo é necessário:** Se um attacker conseguiu acesso à conta da Patricia, ele pode ter feito alterações para manter o acesso: adicionar um método de MFA secundário, criar uma regra de encaminhamento de e-mail, alterar o número de celular de recuperação. O AuditLogs registra todas essas mudanças de configuração.

```kql
// Todas as alterações relacionadas à Patricia nas últimas 24h
AuditLogs
| where TimeGenerated > ago(24h)
| where TargetResources has "patricia.souza"
    or InitiatedBy has "patricia.souza"
| sort by TimeGenerated desc
| project
    TimeGenerated,
    OperationName,      // O que foi feito (ex: "Update user", "Add member to group")
    Result,             // success / failure
    tostring(InitiatedBy.user.userPrincipalName) as Quem,
    TargetResources     // Objeto afetado (JSON com detalhes)
```

**Interpretando o resultado:**

Operações que merecem atenção imediata:
- `"Add authentication method"` → attacker adicionando segundo MFA para manter acesso
- `"Update user"` com `phoneNumber` modificado → alteração de método de recuperação
- `"Add member to role"` → escalada de privilégio
- `"Update user"` iniciado por um IP desconhecido em vez de pelo próprio usuário ou pelo administrador do banco

> **💡 Dica do instrutor:** Se o campo `InitiatedBy` mostrar `"Microsoft Substrate"` ou `"Microsoft Graph"` como iniciador, não é uma ação humana — é automação ou serviço Microsoft. Não confunda com attacker.

---

### Passo 6: Verificar Atividade de E-mail — Consultar OfficeActivity

**Por que este passo é necessário:** Após comprometer uma conta, uma das primeiras ações de um attacker é criar uma regra de encaminhamento de e-mail para receber cópias de todos os e-mails da vítima. O OfficeActivity registra operações no Exchange Online, incluindo criação de regras de encaminhamento (T1114.003).

```kql
// Verificar criação de regras de e-mail e operações suspeitas
OfficeActivity
| where TimeGenerated > ago(24h)
| where UserId has "patricia.souza"
| sort by TimeGenerated desc
| project
    TimeGenerated,
    Operation,          // Tipo de operação
    UserId,
    ClientIP,
    ResultStatus,
    Parameters          // Detalhes da operação (JSON) — procurar "ForwardTo"
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",      // Forwarding a nível de mailbox
    "UpdateInboxRules"
)
```

**Interpretando o resultado:**

A ausência de resultados nesta query é o resultado ideal — significa que nenhuma regra de encaminhamento foi criada. Se aparecer qualquer linha com `Operation = "New-InboxRule"`, inspecione o campo `Parameters` para ver o endereço de encaminhamento. Um encaminhamento para `@bancomeridian.com.br` pode ser legítimo (conta de backup). Um encaminhamento para `@gmail.com`, `@outlook.com` ou qualquer domínio externo é altamente suspeito.

---

### Passo 7: Correlação — Usuário + Alertas de Segurança

**Por que este passo é necessário:** O Sentinel pode ter alertas de outros produtos (Defender for Endpoint, Entra ID Protection) sobre a Patricia que ainda não foram correlacionados manualmente. A correlação via KQL entre SecurityAlert e SigninLogs pode revelar o quadro completo do ataque.

```kql
// Correlacionar alertas de segurança com logins suspeitos
let usuarioAlvo = "patricia.souza@bancomeridian-lab.onmicrosoft.com";
let periodoAnalise = 24h;

// Alertas de segurança relacionados à Patricia
let alertas = SecurityAlert
| where TimeGenerated > ago(periodoAnalise)
| where Entities has usuarioAlvo
| project
    AlertaTimestamp = TimeGenerated,
    AlertaNome = AlertName,
    AlertaSeveridade = AlertSeverity,
    AlertaTaticas = Tactics;

// Logins suspeitos da Patricia
let loginsSuspeitos = SigninLogs
| where TimeGenerated > ago(periodoAnalise)
| where UserPrincipalName == usuarioAlvo
| where ResultType != 0
| project
    LoginTimestamp = TimeGenerated,
    IPAddress,
    tostring(LocationDetails.countryOrRegion) as Pais,
    ResultDescription;

// Unir alertas e logins em uma única timeline
alertas
| union (loginsSuspeitos | extend AlertaTimestamp = LoginTimestamp)
| sort by AlertaTimestamp asc
```

> **💡 Dica do instrutor:** O uso de `let` para criar variáveis é uma das características mais poderosas do KQL para análises complexas. Em vez de escrever subconsultas aninhadas (como em SQL), KQL permite pré-calcular resultados intermediários com `let` e reutilizá-los de forma legível. Isso também melhora a performance — a subexpressão é calculada uma vez e reutilizada, não recalculada a cada referência.

---

### Passo 8: Agregação — Resumo de Logins por País nos Últimos 7 Dias

**Por que este passo é necessário:** Um login único de um IP estrangeiro pode ser uma VPN corporativa legítima. Mas nenhum login de um país específico nos últimos 7 dias seguido de um login hoje desse país é muito mais suspeito. Esta query de baseline ajuda a contextualizar se um IP é anômalo para o padrão histórico do usuário.

```kql
// Baseline de logins por país para todos os usuários — últimos 7 dias
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Apenas logins bem-sucedidos
| summarize
    TotalLogins = count(),
    PrimeiroLogin = min(TimeGenerated),
    UltimoLogin = max(TimeGenerated)
    by UserPrincipalName, tostring(LocationDetails.countryOrRegion) as Pais
| sort by UserPrincipalName asc, TotalLogins desc
| where Pais != "Brazil"  // Focar em logins internacionais
| project UserPrincipalName, Pais, TotalLogins, PrimeiroLogin, UltimoLogin
```

**Interpretando o resultado:**

Esta query cria um "mapa de países" para cada usuário. Um usuário que aparece com `TotalLogins = 3` para `Pais = "United States"` provavelmente viaja a trabalho com frequência — um login dos EUA não é anômalo para ele. Um usuário que aparece apenas com `Pais = "Brazil"` e de repente tem um login da Rússia hoje é muito mais suspeito.

**Por que isso importa para o Banco Meridian:** Esta query, executada regularmente, pode alimentar uma watchlist de `frequent-travelers` que será usada nas analytics rules do Lab 03 para suprimir falsos positivos de impossible travel para viajantes frequentes legítimos.

---

### Passo 9: Criar Hunting Query Salva com Mapeamento MITRE

**Por que este passo é necessário:** A query do Passo 4 (logins falhos por IP) é valiosa para investigações futuras. Ao salvá-la como Hunting Query no Sentinel com mapeamento MITRE, ela fica disponível para toda a equipe e aparece automaticamente quando o SOC filtra por técnica T1110 (Brute Force) no painel de hunting.

**Sentinel → Hunting → Queries → New query**

Preencher os campos:

```
Nome: Hunting - Logins Falhos Agrupados por IP e País
Descrição: Identifica padrões de brute force e password spray detectando IPs com múltiplas
           tentativas de autenticação falhada em várias contas. Base para detecção T1110.
           Calibrar threshold de ContasAlvo conforme baseline do ambiente.

Custom query:
```

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| where ResultType !in (50074, 50076)
| summarize
    TentativasFalhas = count(),
    ContasAlvo = dcount(UserPrincipalName),
    PrimeiraTentativa = min(TimeGenerated),
    UltimaTentativa = max(TimeGenerated),
    ListaContas = make_set(UserPrincipalName, 10)
    by IPAddress, tostring(LocationDetails.countryOrRegion) as Pais
| where TentativasFalhas >= 5
| sort by ContasAlvo desc, TentativasFalhas desc
| project IPAddress, Pais, TentativasFalhas, ContasAlvo, PrimeiraTentativa, UltimaTentativa, ListaContas
```

```
MITRE ATT&CK:
  Tactics: Credential Access
  Techniques:
    - T1110 (Brute Force)
    - T1110.003 (Password Spraying)
    - T1110.004 (Credential Stuffing)

Entity mapping:
  IP: Address → IPAddress
```

Clicar em **Create and run**. O Sentinel salva e executa a query imediatamente.

**O que confirma que funcionou:** A query aparece na lista de Hunting Queries com os ícones MITRE de "Credential Access". Ao clicar em "Run all queries", ela é executada junto com as outras. Bookmarks podem ser criados em qualquer linha de resultado que mereça atenção.

---

### Passo 10: Exportar Resultados e Documentar Evidências

**Por que este passo é necessário:** Investigações de segurança são documentos legais. Se o incidente da Patricia resultar em ação disciplinar contra um funcionário ou em processo criminal contra o attacker, as evidências coletadas precisam estar documentadas com precisão (timestamp, query usada, resultados obtidos, analista responsável). O Sentinel oferece mecanismos de bookmark e exportação para isso.

**Para qualquer linha de resultado suspeita encontrada durante o lab:**

```
Marcar a linha → clicar em "Add bookmark"

Preencher:
  Bookmark name: [data] - [descrição concisa do que foi encontrado]
  Tags: investigacao-patricia, vishing-2025-04-25
  Notes: [explicar por que esta linha é relevante para a investigação]
  
MITRE ATT&CK:
  Tactic + Technique correspondente ao que foi encontrado
```

**Para exportar um relatório sumário:**

```kql
// Query de sumário executivo para o relatório de investigação
SigninLogs
| where TimeGenerated > ago(12h)
| where UserPrincipalName == "patricia.souza@bancomeridian-lab.onmicrosoft.com"
| summarize
    TotalLogins = count(),
    LoginsBemSucedidos = countif(ResultType == 0),
    LoginsFalhos = countif(ResultType != 0),
    PaisesDistintos = dcount(tostring(LocationDetails.countryOrRegion)),
    IPsDistintos = dcount(IPAddress)
| extend StatusInvestigacao = iff(LoginsFalhos > 0, "REVISAR — logins falhos detectados", "Nenhuma atividade suspeita")
```

---

## Seção 7 — Objetivos por Etapa

| Etapa | KQL Dominado | Capacidade de Investigação |
|:-----:|:-------------|:--------------------------|
| Passo 2 | `take`, `project`, `sort` | Navegar em logs brutos e selecionar colunas relevantes |
| Passo 3 | `where` com igualdade e `ago()` | Filtrar eventos por usuário e período |
| Passo 4 | `summarize`, `dcount`, `make_set` | Agregar dados para identificar padrões |
| Passo 5 | `has`, `or`, operadores de texto | Consultar logs de auditoria de alterações |
| Passo 6 | `in` com múltiplos valores | Filtrar por lista de operações específicas |
| Passo 7 | `let` + `union` | Correlacionar múltiplas tabelas sem join |
| Passo 8 | Aggregation com múltiplas dimensões | Construir baselines de comportamento |
| Passo 9 | Entity mapping, MITRE tagging | Criar hunting queries reutilizáveis para a equipe |
| Passo 10 | `iff()`, `countif()` | Gerar relatórios sumários para stakeholders |

---

## Seção 8 — Gabarito Completo

### Conclusão Esperada da Investigação — Patricia Souza

Após executar as 10 queries do lab, o resultado esperado é:

**Cenário A — Nenhuma atividade suspeita:**
- SigninLogs: todos os logins de patricia.souza do Brasil, sem falhas após 13:45
- AuditLogs: sem alterações de conta nas últimas 24h
- OfficeActivity: sem criação de regras de encaminhamento
- SecurityAlert: sem alertas sobre a Patricia
- Conclusão: a tentativa de vishing não teve continuidade técnica detectável. Manter monitoramento por 48h e treinar a Patricia sobre MFA fatigue.

**Cenário B — Atividade suspeita detectada (dados simulados do lab):**
- SigninLogs: logins falhos de IP estrangeiro após 13:45
- AuditLogs: adição de método de autenticação não reconhecido
- OfficeActivity: criação de regra de encaminhamento para domínio externo
- Conclusão: conta comprometida. Ativar playbook de resposta (Lab 04): revogar sessões, resetar senha, remover regra de encaminhamento, notificar CISO.

### Por que cada resultado confirma que o passo funcionou corretamente

**Passo 1 (diagnóstico):** A query retorna pelo menos 3 tabelas com dados (`SigninLogs`, `AuditLogs`, `OfficeActivity`). Se retornar apenas 1 tabela, os connectors do Lab 01 não estão funcionando corretamente — revisar o Lab 01 antes de continuar.

**Passo 3 (filtro por usuário):** A query retorna resultados apenas para `UserPrincipalName = patricia.souza@...`. Se retornar linhas de outros usuários, o filtro `where` está incorreto (verifique aspas, maiúsculas/minúsculas — KQL é case-insensitive para operadores mas case-sensitive para valores de string em comparações de igualdade).

**Passo 4 (aggregation):** A query retorna pelo menos 1 linha por IP. Se retornar 0 linhas, ou não há logins falhos no período (bom sinal para o banco) ou o filtro `ResultType != 0` está bloqueando casos válidos (verifique se o ambiente tem atividade de teste nos últimos 24h).

**Passo 9 (hunting query salva):** A confirmação definitiva é aparecer na lista de Hunting Queries e ser executável pelo botão "Run all queries" sem erro de sintaxe. O mapeamento MITRE é confirmado quando os ícones de tática aparecem ao lado do nome da query.

### Erros Comuns e Como Identificar

| Erro | Sintoma | Solução |
|:-----|:--------|:--------|
| Query não retorna dados | 0 linhas em todas as queries | Verificar se o período `ago(48h)` abrange dados disponíveis — use `ago(7d)` como teste |
| `make_set()` retorna `[""]` | Campo de lista vazio | O campo referenciado pode ser nulo em alguns registros — adicionar `where isnotempty(UserPrincipalName)` antes do summarize |
| `tostring(LocationDetails.city)` retorna vazio | Cidade = "" para alguns IPs | IPs privados não têm geolocalização — adicionar `| where IPAddress !startswith "10." and IPAddress !startswith "192.168."` |
| Hunting query salva não aparece no painel | Busca por nome não encontra | Verificar se foi salvo como "Hunting Query" e não como "Analytics Rule" — são abas diferentes no Sentinel |
| `OfficeActivity` retorna 0 linhas | Tabela vazia mesmo com connector ativo | Latência normal de até 24h para dados do Office 365 chegarem — aguardar ou usar período `ago(7d)` |

### Referência Rápida: Códigos de ResultType mais Comuns

| Código | Significado | Relevância para SOC |
|:------:|:-----------|:--------------------|
| 0 | Login bem-sucedido | Normal |
| 50126 | Credencial inválida (usuário/senha) | Indicador de brute force |
| 50053 | Conta bloqueada | Possível brute force bem-sucedido em bloquear |
| 50074 | MFA necessário | Normal com Conditional Access — não é ataque |
| 50076 | MFA necessário para app | Idem |
| 70011 | Token revogado | Login após revogação — possível attacker tentando usar token antigo |
| 90072 | Usuário não encontrado no tenant | Enumeração de usuários (T1087) |
| 50058 | Sessão silenciosa não possível | Geralmente legítimo — cliente precisando de MFA |
