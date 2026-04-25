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

**Por que confirma que é correto:** Uma timeline correta deve:
1. Estar em ordem cronológica com timestamps precisos
2. Identificar o mecanismo técnico de cada fase (não apenas "acesso indevido")
3. Mapear para técnicas MITRE específicas (T-number, não apenas táticas)
4. Listar pelo menos 1 IOC concreto por fase (IP, domínio, AppID, hash)
5. Mostrar a progressão lógica: cada fase habilita a próxima

**Variações aceitáveis:** A ordem exata dos timestamps pode variar 5-10 minutos dependendo de qual log foi consultado (SigninLogs vs AuditLogs vs EmailEvents têm latências ligeiramente diferentes). O IOC pode ser referenciado de múltiplas tabelas — qualquer forma de identificação única do evento é válida.

---

### Gabarito das 5 Analytics Rules — Especificações Mínimas

| Rule | Nome | Tipo | Técnica Coberta | Entity Mappings |
|:-----|:-----|:-----|:----------------|:----------------|
| 1 | AiTM Token Theft Detection | Scheduled, 30min | T1539, T1557 | Account + IP |
| 2 | OAuth App com Permissões Excessivas | NRT | T1098.001 | Account + AppId |
| 3 | Email Forwarding Rule para Externo | NRT | T1114.003 | Account + MailAddress |
| 4 | Volume Anômalo de Download OneDrive | Scheduled, 1h | T1567.002 | Account + FileCount |
| 5 | Refresh Token sem MFA Reconfirmação | Scheduled, 4h | T1528 | Account + IP |

**Por que estas 5 rules em específico:** Cada rule cobre um ponto de detecção em que o ataque da Operação Guaraná poderia ter sido interrompido:
- Rule 1: Teria detectado a Fase 2 (login sem MFA de IP russo) em 1-3 minutos — mais de 30 horas antes do incidente ser descoberto
- Rule 2: Teria detectado a Fase 5 (OAuth app com Mail.Read) em menos de 5 minutos
- Rule 3: Teria detectado a Fase 4 (email forwarding) em menos de 5 minutos
- Rule 4: Teria detectado a Fase 3 (3.247 downloads) dentro de 1 hora do início
- Rule 5: Teria detectado o refresh token persistente na Fase 6 antes do encerramento do turno

---

### Gabarito do Relatório Executivo — Estrutura Esperada

**Seção 1 — Resumo Executivo (máximo 1 parágrafo):**
O Banco Meridian sofreu um ataque de AiTM phishing em [data] que resultou na exfiltração de 3.247 arquivos e no estabelecimento de acesso persistente à conta de [usuário]. O incidente ficou sem detecção por 31 horas. Com implementação das 5 analytics rules propostas, este tipo de ataque seria detectado em menos de 5 minutos.

**O que NÃO deve aparecer no relatório executivo para um CISO:**
- Código KQL bruto (vai para o apêndice técnico, não na narrativa)
- Siglas sem explicação (se usar "AiTM", definir "ataque de intermediário que bypassa MFA")
- Recomendações sem prazo e responsável
- Impacto estimado em número de arquivos sem contextualizar o que representam para o negócio

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

**Por que a ação #10 é obrigatória e urgente:** A Resolução BACEN 4.893 Art. 12 exige que incidentes relevantes (que impactem dados de clientes ou a continuidade de serviços financeiros) sejam reportados ao BACEN em até 1 dia útil. A exfiltração de 3.247 arquivos pode incluir dados de clientes — assume-se que sim até prova em contrário. Omitir essa notificação tem penalidades regulatórias muito mais graves que o próprio incidente.

---

### Rubrica de Avaliação

| Critério                               | Peso | Pontos Máximos | O que distingue excelente de satisfatório |
|:---------------------------------------|:----:|:--------------:|:------------------------------------------|
| Timeline MITRE ATT&CK (6 fases)        | 20%  | 20 pontos      | Excelente: IOCs específicos em cada fase; Satisfatório: apenas táticas sem IOCs |
| 5 Analytics rules funcionais           | 30%  | 30 pontos      | Excelente: entity mapping + MITRE tag + custom details em todas; Satisfatório: rules funcionam mas sem mapeamentos |
| Relatório executivo (clareza + completude) | 20% | 20 pontos   | Excelente: linguagem de negócio, sem código, com impacto quantificado; Satisfatório: tecnicamente correto mas com jargão |
| Plano de remediação priorizado         | 20%  | 20 pontos      | Excelente: inclui notificação BACEN, prazos realistas, responsáveis e custo; Satisfatório: ações corretas sem priorização |
| Apresentação oral (live session)       | 10%  | 10 pontos      | Excelente: demo ao vivo funciona, linguagem acessível para CISO; Satisfatório: slides sem demo |
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
