# Lab Capstone — Operação Guaraná: Resposta a APT

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas (incluindo apresentação live)                                  |
| **Módulo de referência** | Módulo 10 — Capstone                                                   |
| **Pré-requisito**        | TODOS os labs anteriores (01, 03, 04, 05, 06) concluídos              |
| **Nível**                | Avançado                                                               |

---

## Instruções de Execução

Este lab capstone integra TODO o conhecimento dos módulos anteriores. Ele deve ser executado **individualmente ou em dupla**, com apresentação oral dos resultados na sessão live.

### Cenário Completo

O cenário de ataque completo está documentado no **Módulo 10** (modulo-10-capstone/README.md). Antes de iniciar este lab, leia o Módulo 10 na íntegra.

### O que você deve fazer

1. **Investigar o incidente** usando o ambiente do lab com os dados simulados do ataque
2. **Criar as 5 analytics rules** que teriam detectado o ataque mais cedo
3. **Executar as queries de hunting** para reconstruir a timeline
4. **Produzir os 4 entregáveis** descritos no Módulo 10

---

## Seção 1 — Contexto Situacional

Ver **Módulo 10, seção "O Incidente: Cadeia de Ataque Completa"** para o contexto completo.

**Resumo**: O Grupo Lazarus-BR comprometeu a conta de `ana.lima@bancomeridian-lab.onmicrosoft.com` via AiTM phishing e executou um ataque de 6 fases ao longo de 31 horas.

---

## Seção 2 — Situação Inicial

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PAINEL SOC — BANCO MERIDIAN — QUARTA, 09:15                               │
│                                                                              │
│  INCIDENTE CRÍTICO ABERTO:  "Operação Guaraná — Comprometimento AiTM"      │
│  Severidade: ████████████████████ HIGH                                      │
│  Aberto:     2025-04-07 10:28 UTC  (ONTEM às 07:28 horário de Brasília)   │
│  Duração:    31 horas sem resposta                                          │
│  Atribuído:  NÃO ATRIBUÍDO                                                 │
│                                                                              │
│  ALERTAS CORRELACIONADOS:  6 alertas de 4 fontes diferentes                │
│  ENTIDADES IDENTIFICADAS:  ana.lima@bancomeridian-lab.onmicrosoft.com      │
│                             IP: 185.234.218.55 (Rússia)                    │
│                             AppID: 4f3d9e2b-8c1a (OAuth app malicioso)     │
│                                                                              │
│  ANALYTICS RULES ATIVAS:   0 rules cobriam estes vetores de ataque         │
│  STATUS DA ANA:             Conta ativa, sessões ativas, e-mails sendo     │
│                              encaminhados para externo (AGORA)             │
└──────────────────────────────────────────────────────────────────────────────┘

"Cheguei aqui 30 minutos atrás e vi esse incidente que estava aberto há 31 horas
 sem resposta. Ana Lima parece ter sido a primeira vítima — mas olhando os logs,
 o attacker já se moveu para mais dois sistemas. O e-mail dela ainda está sendo
 encaminhado para um endereço externo agora mesmo.
 
 Você vai liderar esta investigação. Temos três objetivos simultâneos: conter o
 dano (o encaminhamento de e-mail precisa parar imediatamente), reconstruir
 exatamente o que aconteceu, e garantir que isso nunca mais passe despercebido
 por 31 horas. Você tem a sala."
 — Felipe Andrade, L2 Senior, passando o bastão
```

O ambiente do lab contém:
- Todos os dados simulados das 6 fases do ataque injetados no workspace
- Incidente HIGH aberto no Sentinel: "Operação Guaraná — Comprometimento AiTM"
- Nenhuma analytics rule ativa para os vetores de ataque utilizados
- **A conta de ana.lima está ativa** — o playbook de contenção ainda não foi executado
- **Regra de encaminhamento de e-mail está ativa** — e-mails da ana.lima estão sendo encaminhados para `attacker@external-domain.ru` em tempo real

---

## Seção 3 — Problema Identificado

6 fases de ataque ocorreram sem detecção automática:
1. Spearphishing com AiTM entregue
2. Token OAuth roubado
3. 3.247 arquivos exfiltrados
4. Regra de encaminhamento de e-mail criada
5. Service principal com permissões perigosas registrado
6. Acesso persistente via refresh token OAuth

---

## Seção 4 — Roteiro de Atividades

1. Analisar o incidente aberto no Sentinel
2. Executar as 6 queries de investigação (Módulo 10, Seções "Evidências")
3. Criar a timeline MITRE ATT&CK (Entregável 1)
4. Criar as 5 analytics rules do Módulo 10 (Entregável 2)
5. Executar o playbook de conta comprometida no usuário ana.lima
6. Escrever o relatório executivo (Entregável 3)
7. Preencher o plano de remediação (Entregável 4)
8. Preparar apresentação para a sessão live (15 minutos)

---

## Seção 5 — Proposição

Ao final deste lab:
- Timeline MITRE ATT&CK completa e precisa (6 fases mapeadas)
- 5 analytics rules KQL funcionais criadas no Sentinel
- Relatório executivo de 2 páginas para o CISO
- Plano de remediação priorizado com 10 ações
- Apresentação preparada para a live de 15 minutos

---

## Seção 6 — Script de Investigação

### Queries de Investigação a Executar

**O que este passo faz (visão geral):** Esta seção constrói, fase por fase, a cadeia de evidências do ataque da Operação Guaraná. Cada query consulta uma tabela diferente do Microsoft Sentinel — EmailEvents, SigninLogs, OfficeActivity e AuditLogs — e juntas constroem a narrativa forense completa. A ordem de execução segue a kill chain do atacante: primeiro o vetor de entrada, depois o movimento dentro do ambiente, depois a persistência.

**Por que executar as queries nesta ordem:** A investigação forense segue o princípio de "anchor and expand" — você parte de um evento âncora conhecido (o e-mail de phishing) e expande para eventos subsequentes usando os artefatos encontrados (o IP do atacante, o usuário comprometido). Executar fora de ordem — por exemplo, começar pela Fase 5 (OAuth App) sem entender a Fase 1 — torna impossível distinguir atividade maliciosa de atividade legítima, pois sem o contexto do comprometimento inicial qualquer registro de aplicação OAuth pareceria normal.

---

**Fase 1 — E-mail de phishing**:

**O que este passo faz:** Consulta a tabela `EmailEvents` (Microsoft Defender for Office 365) para localizar o e-mail de phishing que iniciou o ataque. O filtro por `SenderFromDomain` com "microsoftsuporte" captura o domínio de typosquatting utilizado pelo Grupo Lazarus-BR — um domínio que imita suporte da Microsoft mas termina em `.ru`. Este é o ponto zero da linha do tempo: sem confirmar que o e-mail foi entregue e aberto, toda a investigação subsequente é especulação.

**Por que esta é a primeira query:** O e-mail de phishing é o único evento que ocorreu antes da conta ser comprometida — é o único ponto da cadeia onde o atacante estava completamente fora do ambiente. Confirmar a entrega (DeliveryAction = Delivered) e o tipo de ameaça (ThreatTypes) estabelece que não houve comprometimento por outros vetores (ex.: credencial vazada em breach externo), o que importa para o relatório ao BACEN.

```kql
EmailEvents
| where TimeGenerated >= datetime(2025-04-07 10:00)
| where RecipientEmailAddress == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where SenderFromDomain contains "microsoftsuporte"
| project TimeGenerated, SenderFromAddress, Subject, DeliveryAction, ThreatTypes
```

**O que confirma que funcionou:** A query deve retornar pelo menos 1 linha com `DeliveryAction = Delivered` (o e-mail chegou à caixa de entrada) e `ThreatTypes` contendo "Phish". Se `DeliveryAction = Blocked`, o ataque teria sido impedido pelo Defender for Office 365 — mas os logs posteriores mostram que o acesso ocorreu, portanto o e-mail foi entregue. O timestamp desta linha é o T=0 da sua timeline MITRE ATT&CK.

---

**Fase 2 — Login com token roubado**:

**O que este passo faz:** Consulta `SigninLogs` para identificar o primeiro login bem-sucedido do atacante usando o token OAuth roubado via proxy AiTM. O filtro `Location !contains "BR"` é o sinal de anomalia crítico: a conta de ana.lima nunca realizou logins fora do Brasil antes deste incidente. A combinação de IP russo + autenticação sem MFA completada (o token já passou pelo MFA no proxy) é a assinatura técnica do ataque AiTM.

**Por que este passo vem imediatamente após a Fase 1:** O login com token roubado ocorreu apenas 5 minutos após a entrega do e-mail (10:28 → 10:33). Esta sequência confirma que a vítima clicou no link imediatamente — informação relevante para o relatório e para o treinamento de conscientização. O IP `185.234.218.55` encontrado aqui será o IOC pivot para investigar as fases subsequentes.

```kql
SigninLogs
| where TimeGenerated >= datetime(2025-04-07 10:25)
| where UserPrincipalName == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where Location !contains "BR"
| project TimeGenerated, IPAddress, Location, 
          AuthenticationRequirement, DeviceDetail, RiskLevelDuringSignIn
```

**O que confirma que funcionou:** A query retorna pelo menos 1 linha com `IPAddress = 185.234.218.55`, `Location` contendo "Russia" ou equivalente, e `AuthenticationRequirement = singleFactorAuthentication` — confirmando o bypass de MFA característico do AiTM. Se `DeviceDetail` mostrar device desconhecido (GUID vazio ou zeros), reforça que não é um device legítimo de ana.lima.

---

**Fase 3 — Exfiltração OneDrive** (referência ao Módulo 10):

**O que este passo faz:** Consulta `OfficeActivity` para mapear o volume e o período da exfiltração de arquivos. O Módulo 10 contém a query completa com o pivot pelo IP `5.2.67.44` — IP de saída diferente do login, indicando que o atacante usou infraestrutura separada para a exfiltração (prática comum de APTs para dificultar correlação). O resultado esperado é um pico de 3.247 operações `FileDownloaded` entre segunda 10:45 e terça 18:00.

**Por que esta fase ocorre horas após o login:** Os atacantes frequentemente fazem reconhecimento silencioso antes de iniciar a exfiltração em massa — enumerando pastas, identificando documentos de alto valor (contratos, dados de clientes, credenciais). A exfiltração em si ocorre em horário comercial para se camuflar no tráfego legítimo de downloads de funcionários. Este padrão é documentado no relatório FS-ISAC que originou a inteligência sobre o Grupo Lazarus-BR.

```kql
// Usar query da Seção "Fase 3" do Módulo 10
// Resultado: pico de downloads entre Seg 10:45 e Ter 18:00
```

**O que confirma que funcionou:** A query do Módulo 10 deve retornar registros com `Operation = FileDownloaded` e `ClientIP = 5.2.67.44` totalizando aproximadamente 3.247 eventos. A distribuição temporal deve mostrar o padrão de "exfiltração durante horário comercial" — não um burst único, mas downloads distribuídos ao longo de horas para evitar detecção por volume.

---

**Fase 4 — Regra de e-mail**:

**O que este passo faz:** Consulta `OfficeActivity` por operações de criação de regras de inbox (Operation = "New-InboxRule"). Esta é a evidência da persistência de coleta de informações: mesmo que a sessão do atacante fosse encerrada após a exfiltração inicial, a regra de encaminhamento continuaria enviando todos os e-mails futuros de ana.lima para `attacker@external-domain.ru`. Esta query confirma que a exfiltração não terminou com a sessão — ela está acontecendo **agora**, enquanto você investiga.

**Por que esta fase vem após a exfiltração:** A criação da regra de encaminhamento ocorreu no dia seguinte à exfiltração inicial (2025-04-08 vs 2025-04-07), confirmando que o atacante retornou ao ambiente e estabeleceu mecanismo de coleta passiva e persistente. Este comportamento mapeia para a tática "Persistence" no MITRE ATT&CK — o atacante estava se preparando para manter acesso mesmo após uma eventual detecção e reset de senha.

```kql
OfficeActivity
| where TimeGenerated >= datetime(2025-04-08 08:00)
| where UserId == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| where Operation == "New-InboxRule"
| project TimeGenerated, UserId, ClientIP, Parameters
```

**O que confirma que funcionou:** A query retorna 1 linha com `Operation = New-InboxRule` e o campo `Parameters` contendo o endereço de destino `attacker@external-domain.ru`. A presença deste registro confirma que a ação de contenção imediata (Etapa 5 do Roteiro de Atividades — executar o playbook) é urgente: cada e-mail recebido por ana.lima desde 2025-04-08 08:12 foi copiado para o atacante.

---

**Fase 5 — OAuth App**:

**O que este passo faz:** Consulta `AuditLogs` para identificar o registro de uma aplicação OAuth maliciosa e a concessão de permissões excessivas (`Mail.Read`, `Files.ReadWrite.All`) pela conta comprometida de ana.lima. Este é o passo de persistência técnica mais grave: um OAuth App com essas permissões pode acessar e-mails e arquivos da conta indefinidamente, mesmo após o reset de senha da conta humana — pois o app tem seu próprio token de acesso independente das credenciais do usuário.

**Por que esta é a última fase investigada antes da timeline completa:** O registro do OAuth App (Fase 5) representa a conversão de acesso temporário (sessão/token) em acesso permanente (application). Investigar esta fase por último permite que o analista confirme que existe um segundo vetor de acesso persistente além da regra de e-mail (Fase 4). Ambos precisam ser revogados — esquecer o OAuth App enquanto reseta a senha é um erro comum que deixa o atacante com acesso após a "contenção".

```kql
AuditLogs
| where TimeGenerated >= datetime(2025-04-08 14:00)
| where OperationName in ("Add application", "Add app role assignment to service principal")
| where InitiatedBy.user.userPrincipalName == "ana.lima@bancomeridian-lab.onmicrosoft.com"
| project TimeGenerated, OperationName, TargetResources
```

**O que confirma que funcionou:** A query retorna 2 linhas: uma com `OperationName = Add application` (criação do app) e outra com `Add app role assignment to service principal` (concessão de permissões). O campo `TargetResources` da segunda linha deve conter o AppID `4f3d9e2b-8c1a` e as permissões concedidas. Se `TargetResources` aparecer vazio ou truncado, expanda com `| extend Details = tostring(TargetResources)` para visualizar o JSON completo.

---

**Timeline Completa**:

**O que este passo faz:** Executa uma query `union` que consolida eventos de 4 tabelas diferentes (EmailEvents, SigninLogs, OfficeActivity, AuditLogs) em uma única linha do tempo ordenada cronologicamente. Esta query é o "produto final" da fase de investigação — ela responde à pergunta central do incidente: "O que aconteceu, em que ordem, e por quanto tempo?" O resultado desta query é o insumo direto para o Entregável 1 (Timeline MITRE ATT&CK).

**Por que executar a timeline apenas após as queries individuais:** As queries das Fases 1 a 5 são a validação de que cada tabela tem os dados esperados e que os filtros estão corretos. A query de timeline combina esses filtros validados — executá-la sem antes confirmar as queries individuais é como somar números sem verificar cada parcela. Se a timeline mostrar fases faltando, você saberá exatamente qual query individual investigar.

```kql
// Usar a query de Timeline do Módulo 10 para montar a sequência completa
let user = "ana.lima@bancomeridian-lab.onmicrosoft.com";
union
    (EmailEvents | where RecipientEmailAddress == user | project TimeGenerated, Phase = "Fase 1 - Phishing"),
    (SigninLogs | where UserPrincipalName == user | where Location !contains "BR" | project TimeGenerated, Phase = "Fase 2 - Token Theft"),
    (OfficeActivity | where UserId == user | where Operation == "FileDownloaded" | where ClientIP == "5.2.67.44" | project TimeGenerated, Phase = "Fase 3 - Exfiltration"),
    (OfficeActivity | where UserId == user | where Operation == "New-InboxRule" | project TimeGenerated, Phase = "Fase 4 - Email Forward"),
    (AuditLogs | where InitiatedBy.user.userPrincipalName == user | where OperationName contains "application" | project TimeGenerated, Phase = "Fase 5 - OAuth App")
| sort by TimeGenerated asc
```

**O que confirma que funcionou:** A query retorna pelo menos 5 grupos de eventos (um por fase) ordenados cronologicamente, com a Fase 1 como o registro mais antigo (2025-04-07 ~10:28) e a Fase 5 como o mais recente (~14:33 do dia seguinte). Se alguma fase aparecer ausente, verifique se o filtro da query individual correspondente retorna resultados — o problema está no filtro, não na timeline em si.

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                             | Verificação                                          |
|:-----:|:-----------------------------------------------------|:-----------------------------------------------------|
| 1     | Investigar o incidente no Sentinel                   | Incidente aberto, alertas e entities identificados   |
| 2     | Executar as 6 queries de investigação               | Resultados documentados para cada fase               |
| 3     | Criar timeline MITRE ATT&CK                          | Tabela completa com 6 fases e TTPs                   |
| 4     | Criar as 5 analytics rules                           | Todas as 5 rules em Analytics → Active rules         |
| 5     | Executar playbook no ana.lima                        | Sessões revogadas; comentário no incidente           |
| 6-7   | Produzir relatório e plano de remediação             | 2 entregáveis documentados                           |
| 8     | Preparar apresentação de 15 min                      | Apresentação cobrindo todos os 4 entregáveis        |

---

## Seção 8 — Gabarito e Rubrica de Avaliação

### Gabarito da Timeline MITRE ATT&CK — Resposta Esperada

| # | Fase | Timestamp (UTC) | TTP MITRE | Técnica | IOC Identificado |
|:-:|:-----|:----------------|:----------|:--------|:-----------------|
| 1 | Spearphishing entregue | 2025-04-07 10:28 | T1566.002 | Phishing - Link | remetente: `suporte@microsoftsuporte.ru`, IP: `185.234.218.55` |
| 2 | Login com token roubado (AiTM) | 2025-04-07 10:33 | T1539 + T1078 | Token Theft + Valid Accounts | IP: `185.234.218.55`, país: RU, sem MFA completado |
| 3 | Exfiltração OneDrive | 2025-04-07 10:45–18:00 | T1567.002 | Exfiltração via Cloud Storage | 3.247 arquivos, IP: `5.2.67.44`, destino externo desconhecido |
| 4 | Regra de encaminhamento criada | 2025-04-08 08:12 | T1114.003 | Email Forwarding Rule | regra: `SubjectContains ['']` → `attacker@external-domain.ru` |
| 5 | OAuth App malicioso registrado | 2025-04-08 14:33 | T1098.001 | Account Manipulation - Additional Cloud Credentials | AppID: `4f3d9e2b-8c1a`, permissões: `Mail.Read`, `Files.ReadWrite.All` |
| 6 | Refresh token para persistência | 2025-04-08 14:35 | T1528 | Steal Application Access Token | Refresh token com validade de 90 dias, acesso persistente mesmo sem sessão ativa |

**Por que esta é a resposta correta:** Uma timeline de incidente de segurança serve como documento forense e como narrativa para o CISO. Ela precisa atender a três critérios simultâneos: (1) precisão cronológica — cada fase deve ter seu timestamp extraído das fontes de log, não estimado; (2) rastreabilidade técnica — cada fase deve identificar o mecanismo específico (AiTM bypass, não apenas "login suspeito"), pois isso é o que orienta a remediação técnica; (3) cobertura de IOCs — cada fase deve ter pelo menos um indicador de comprometimento concreto para permitir threat hunting em outros sistemas.

**Erros comuns:**
- **Confundir T1539 (Token Theft) com T1557 (AiTM):** T1539 é o resultado (roubo do token), T1557 é o método (o proxy intermediário). O ataque da Operação Guaraná usa T1557 como método para obter T1539 — a timeline precisa de ambos na Fase 2.
- **Marcar a Fase 6 (refresh token) como o mesmo evento da Fase 5 (OAuth App):** São eventos distintos — o OAuth app (T1098.001) cria o mecanismo de acesso; o refresh token (T1528) é o artefato persistente que permite acesso futuro. Se reportar apenas o OAuth app, o plano de remediação pode revogar o app mas deixar o token ativo.
- **Usar timestamps aproximados em vez de extraídos dos logs:** O e-mail de phishing chegou às 10:28, não "por volta das 10:30". Para fins regulatórios (BACEN 4.893), timestamps precisos são exigidos no relatório de incidente.
- **Omitir a Fase 3 por ser a mais volumosa:** Alguns alunos tentam consolidar as 3.247 operações de download em "1 evento de exfiltração". O correto é representar o período completo (10:45–18:00) e o volume total, pois isso determina o escopo de notificação ao BACEN.

**Variações aceitáveis:** Os timestamps podem variar 5-10 minutos entre tabelas (SigninLogs vs AuditLogs têm latências ligeiramente diferentes). O IOC pode ser referenciado de múltiplas tabelas — qualquer forma de identificação única e verificável é válida.

---

### Gabarito das 5 Analytics Rules — Especificações Mínimas

| Rule | Nome | Tipo | Técnica Coberta | Entity Mappings |
|:-----|:-----|:-----|:----------------|:----------------|
| 1 | AiTM Token Theft Detection | Scheduled, 30min | T1539, T1557 | Account + IP |
| 2 | OAuth App com Permissões Excessivas | NRT | T1098.001 | Account + AppId |
| 3 | Email Forwarding Rule para Externo | NRT | T1114.003 | Account + MailAddress |
| 4 | Volume Anômalo de Download OneDrive | Scheduled, 1h | T1567.002 | Account + FileCount |
| 5 | Refresh Token sem MFA Reconfirmação | Scheduled, 4h | T1528 | Account + IP |

**Por que estas 5 rules em específico — e por que cada uma é a resposta correta:**

**Rule 1 (AiTM Token Theft — Scheduled 30min):** É esta e não uma NRT porque o AiTM gera uma sequência de eventos ao longo de minutos (autenticação legítima → bypass → login do atacante), e a correlação temporal precisa de uma janela de lookback de pelo menos 30-60 minutos para capturar a sequência completa. Uma NRT com janela de 15 minutos pode perder o evento do lado do atacante se o login legítimo da vítima ocorreu fora do window.

**Rule 2 (OAuth App — NRT):** É NRT porque a concessão de permissões a um OAuth app malicioso é um evento único e imediato — não há sequência temporal a correlacionar. A latência de 1-5 minutos da NRT vs. 30 minutos de uma Scheduled rule pode ser a diferença entre detectar o app antes ou depois de o refresh token já ter sido gerado (Fase 6 ocorreu apenas 2 minutos após a Fase 5).

**Rule 3 (Email Forwarding — NRT):** É NRT pelo mesmo motivo da Rule 2: a criação de uma regra de inbox é um evento atômico. Detectar em 5 minutos vs. 30 minutos significa que menos e-mails são encaminhados antes da contenção. Cada minuto de atraso pode significar mais um e-mail com dados sensíveis chegando ao atacante.

**Rule 4 (Volume de Download — Scheduled 1h):** É Scheduled porque a anomalia de volume requer uma linha de base histórica — a query calcula o percentil 90 dos últimos 30 dias e detecta quando o dia atual excede 5x esse baseline. Este cálculo exige acesso a dados históricos, que só são eficientes em modo Scheduled com lookback de 1h para a detecção e 30d para o baseline.

**Rule 5 (Refresh Token — Scheduled 4h):** É Scheduled com lookback de 4h porque o refresh token pode ser usado de forma discreta e intermitente — não gera volume de eventos, e sim eventos espaçados. Uma Scheduled que verifica a cada 4 horas é suficiente para detectar uso do token dentro de um turno de trabalho, que é o critério de resposta esperado pelo SOC do Banco Meridian.

**Erros comuns:**
- **Criar todas as 5 rules como Scheduled:** Funciona, mas demonstra não entender a diferença de latência entre tipos. Rules 2 e 3 NRT são justificadas pelo tempo-crítico da detecção.
- **Omitir entity mapping em qualquer rule:** Sem entity mapping, os incidentes gerados pelas rules não têm entidades mapeadas, o que impede a automation rule de triagem de funcionar (ela filtra por "Incident contains entities Account"). Além disso, sem entity mapping, o Sentinel não consegue correlacionar incidentes relacionados ao mesmo usuário automaticamente.
- **Criar rule para AiTM usando apenas Location !contains "BR":** Este filtro sem exclusão de frequent travelers ou service accounts gera false positives para funcionários que viajam legitimamente e para IPs de VPN corporativa. A rule precisa excluir a watchlist `frequent-travelers` criada anteriormente.
- **Nomear as rules sem o prefixo "Banco Meridian -":** Convenção de nomenclatura é avaliada — em um SOC real, rules sem naming convention ficam impossíveis de gerenciar quando há centenas de regras ativas.

---

### Gabarito do Relatório Executivo — Estrutura Esperada

**Seção 1 — Resumo Executivo (máximo 1 parágrafo):**
O Banco Meridian sofreu um ataque de AiTM phishing em [data] que resultou na exfiltração de 3.247 arquivos e no estabelecimento de acesso persistente à conta de [usuário]. O incidente ficou sem detecção por 31 horas. Com implementação das 5 analytics rules propostas, este tipo de ataque seria detectado em menos de 5 minutos.

**Por que esta é a resposta correta para o relatório executivo:** O CISO do Banco Meridian precisa de três informações nesta ordem: (1) o que aconteceu em linguagem de impacto de negócio (arquivos exfiltrados = risco regulatório + reputacional), (2) por quanto tempo o banco ficou exposto sem saber (31 horas = gap de detecção documentado), e (3) o que será diferente no futuro (5 analytics rules que reduzem o tempo para 5 minutos). Um relatório que começa com detalhes técnicos — KQL, IPs, AuditLogs — perde o executivo na primeira página.

**Erros comuns:**
- **Incluir código KQL no corpo do relatório:** Código vai no apêndice técnico, não na narrativa executiva. O CISO precisa entender o impacto, não validar a query.
- **Usar "AiTM" ou "T1539" sem definição:** Todo acrônimo técnico precisa ser definido na primeira ocorrência. "Ataque AiTM (adversário intermediário que contorna autenticação multifator)" é aceitável; "AiTM attack" sem contexto não é.
- **Listar recomendações sem prazo e responsável:** "Implementar MFA mais forte" não é uma ação — "Habilitar Conditional Access para bloquear logins de IPs não-BR em 48h (responsável: IAM Team)" é uma ação. Recomendações sem responsável não são executadas.
- **Não quantificar o impacto regulatório:** "Pode ter violado dados de clientes" é insuficiente. O relatório deve indicar se a notificação ao BACEN (Art. 12 da Resolução 4.893) é necessária e em que prazo — essa é frequentemente a informação mais crítica para o CISO no contexto do setor financeiro brasileiro.

---

### Gabarito do Plano de Remediação — 10 Ações Priorizadas

| # | Ação | Prazo | Responsável | Custo Estimado |
|:-:|:-----|:------|:------------|:---------------|
| 1 | Revogar todas as sessões de ana.lima e resetar senha | IMEDIATO | SOC L2 | 0 |
| 2 | Remover a regra de encaminhamento de e-mail | IMEDIATO | SOC L2 | 0 |
| 3 | Revogar o OAuth App malicioso `4f3d9e2b-8c1a` | IMEDIATO | SOC L2 | 0 |
| 4 | Implementar as 5 analytics rules KQL | 24h | SOC L2/L3 | Custo compute |
| 5 | Habilitar Conditional Access: bloquear logins sem MFA de países não-BR | 48h | IAM Team | Incluído E5 |
| 6 | Treinar todos os 2.800 funcionários em phishing AiTM | 30 dias | T&C / CISO | ~R$8.000 |
| 7 | Implementar Microsoft Defender for Office 365 P2 Safe Links | 7 dias | IAM Team | Incluído E5 |
| 8 | Configurar User Risk Policy: bloquear usuários de risco alto | 7 dias | IAM Team | Incluído E5 |
| 9 | Criar playbook automático de contenção de conta comprometida | 15 dias | SOC + Dev | Mínimo |
| 10 | Notificar BACEN sobre o incidente (Resolução 4.893, Art. 12) | 24h | CISO + Jurídico | 0 |

**Por que as ações 1-3 são IMEDIATAS e por que esta é a resposta correta:** As três primeiras ações bloqueiam os três vetores de acesso persistente ativos neste momento. Revogar a senha sem remover a regra de encaminhamento (ação 2) deixa o atacante recebendo os e-mails mesmo sem sessão ativa — erro crítico frequente em respostas a incidentes AiTM. Revogar o OAuth App (ação 3) revoga o access token associado; sem esta ação, o app `4f3d9e2b-8c1a` continua com acesso a `Mail.Read` e `Files.ReadWrite.All` indefinidamente.

**Por que a ação #10 é obrigatória e urgente:** A Resolução BACEN 4.893 Art. 12 exige que incidentes relevantes (que impactem dados de clientes ou a continuidade de serviços financeiros) sejam reportados ao BACEN em até 1 dia útil. A exfiltração de 3.247 arquivos pode incluir dados de clientes — assume-se que sim até prova em contrário. Omitir essa notificação tem penalidades regulatórias muito mais graves que o próprio incidente.

**Erros comuns no plano de remediação:**
- **Listar a notificação ao BACEN (ação 10) como última prioridade:** A ordem recomendada já a coloca como urgente (24h), mas alunos frequentemente a colocam no final "quando o incidente estiver resolvido". O prazo legal de 1 dia útil corre desde o momento em que o banco tem conhecimento do incidente — não desde a conclusão da investigação. Atrasar a notificação aguardando análise completa é uma violação regulatória.
- **Omitir o reset do refresh token como ação separada:** Alguns planos mencionam apenas "revogar o OAuth App" sem especificar a revogação dos tokens emitidos anteriormente (ação via Microsoft Entra ID → Enterprise Applications → Permissions → Revoke). O app pode ser removido mas tokens emitidos continuam válidos até expirar (90 dias para refresh tokens).
- **Colocar treinamento de conscientização (ação 6) antes de controles técnicos (ações 4-8):** Treinamento é uma ação de médio prazo eficaz mas lenta — leva semanas para alcançar todos os funcionários. Controles técnicos (Conditional Access, Safe Links, analytics rules) reduzem o risco imediatamente. O plano deve refletir que controles técnicos são a linha de defesa primária, e treinamento é a camada de reforço.

---

### Rubrica de Avaliação

| Critério                               | Peso | Pontos Máximos | O que distingue excelente de satisfatório |
|:---------------------------------------|:----:|:--------------:|:------------------------------------------|
| Timeline MITRE ATT&CK (6 fases)        | 20%  | 20 pontos      | Excelente: IOCs específicos em cada fase, T-numbers corretos com sub-técnicas; Satisfatório: apenas táticas sem IOCs ou sem sub-técnicas |
| 5 Analytics rules funcionais           | 30%  | 30 pontos      | Excelente: entity mapping + MITRE tag + custom details em todas, NRT usada onde apropriado; Satisfatório: rules funcionam mas sem mapeamentos ou tipo errado |
| Relatório executivo (clareza + completude) | 20% | 20 pontos   | Excelente: linguagem de negócio, sem código, com impacto quantificado e menção à obrigação BACEN; Satisfatório: tecnicamente correto mas com jargão ou sem menção regulatória |
| Plano de remediação priorizado         | 20%  | 20 pontos      | Excelente: ações IMEDIATO/24h/7d/30d distintas, todos os 3 vetores de acesso persistente bloqueados, notificação BACEN presente; Satisfatório: ações corretas mas sem distinção de prazo ou faltando a revogação do refresh token |
| Apresentação oral (live session)       | 10%  | 10 pontos      | Excelente: demo ao vivo funciona, linguagem acessível para CISO, consegue explicar "por que 31 horas sem detecção" sem jargão; Satisfatório: slides sem demo |
| **Total**                              | **100%** | **100 pontos** | |

**Mínimo para aprovação**: 70 pontos

---

## Instruções de Entrega

**Entrega antes da live session**:
1. Enviar os 4 entregáveis documentados ao instrutor via email/LMS
2. Formato: documento Word, PDF ou Markdown
3. Prazo: 1 hora antes da sessão live

**Na sessão live**:
1. Apresentação de 15 minutos
2. Demo ao vivo de 2 das 5 analytics rules no Sentinel
3. Q&A de 5 minutos com o instrutor

**Critérios de excelência** (90+ pontos):
- Timeline identifica IOCs específicos (IPs, domínios, AppIDs)
- Analytics rules incluem entity mapping e MITRE tagging completos
- Relatório executivo usa linguagem de negócio (sem jargão técnico excessivo)
- Plano de remediação distingue ações imediatas/curto/longo prazo com justificativa de negócio
