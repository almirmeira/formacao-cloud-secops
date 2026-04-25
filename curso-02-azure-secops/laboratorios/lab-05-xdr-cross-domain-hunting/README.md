# Lab 05 — Advanced Hunting Cross-Domain no Defender XDR

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 06 — Microsoft Defender XDR                                     |
| **Pré-requisito**        | Labs 01, 03 e 04 concluídos; acesso ao portal security.microsoft.com  |
| **Nível**                | Intermediário-Avançado                                                 |

---

## Seção 1 — Contexto Situacional

O **Banco Meridian** recebeu uma denúncia anônima pelo canal de compliance: "Um funcionário do departamento de Contratos pode estar vazando planilhas de clientes premium para concorrentes". O denunciante forneceu apenas um nome: `marcela.ferreira` (Analista de Contratos).

O time de compliance encaminhou para o SOC. Como há suspeita de acesso malicioso a dados, você precisa investigar usando **Advanced Hunting cross-domain** no Defender XDR — correlacionando dados de e-mail (MDO), identidade (Entra ID) e endpoint (MDE) para construir a cadeia de evidências.

Esta investigação é sensível — envolve privacidade de funcionário. A investigação deve ser documentada formalmente e as evidências preservadas.

---

## Seção 2 — Situação Inicial

```
┌──────────────────────────────────────────────────────────────────────┐
│  PORTAL COMPLIANCE — BANCO MERIDIAN — TERÇA, 10:15                  │
│  Canal de denúncia anônima — Referência: COMP-2025-0312             │
│                                                                      │
│  DENÚNCIA RECEBIDA — ALTA PRIORIDADE                                │
│  Funcionário envolvido: marcela.ferreira (Analista de Contratos)    │
│  Descrição: "Suspeita de envio de planilhas de clientes premium      │
│             para endereço externo."                                  │
│                                                                      │
│  STATUS DA INVESTIGAÇÃO SOC: INICIADA                               │
│  Analista responsável: [você]                                       │
│  Prazo compliance: 48 horas para resposta inicial                   │
└──────────────────────────────────────────────────────────────────────┘

"Recebi do compliance uma denúncia sobre a marcela.ferreira. Precisamos investigar.
 Sem evidências técnicas, não há base para ação disciplinar. Você tem 48 horas.
 Use o Advanced Hunting — não toque na conta dela, não bloqueie nada ainda.
 Só investigue e preserve evidências. Se confirmar, o RH e o jurídico entram."
 — Felipe Andrade, Analista L2 Senior / Supervisor do turno
```

**Estado do ambiente**:
- Acesso ao portal security.microsoft.com configurado
- M365 E5 com MDE, MDO e Entra ID ativos
- Usuário de teste `marcela.ferreira@bancomeridian-lab.onmicrosoft.com` criado com dados de teste
- Atividade simulada de acesso a arquivos nos últimos 7 dias (injetada pelo ambiente de lab)
- **Sentinel:** operacional com o workspace `meridian-secops-prod` (Labs 01 e 03 concluídos)
- **Incidente Sentinel:** nenhum alerta ativo para marcela.ferreira — a investigação é proativa baseada na denúncia, não em um alerta automático

**Nota do instrutor**: O ambiente de lab contém atividade simulada de `marcela.ferreira` que inclui: e-mails recebidos de domínio externo suspeito, download de arquivos do SharePoint, e upload para serviço cloud externo. Você encontrará evidências reais ao executar as queries.

**O que é o Advanced Hunting do Defender XDR e por que usá-lo neste caso:**

O Advanced Hunting é o motor de investigação proativa do portal security.microsoft.com. Ele acessa tabelas com telemetria granular dos últimos 30 dias de todos os produtos Microsoft Defender:
- `EmailEvents`: todos os e-mails enviados/recebidos, remetentes, assuntos, IPs
- `EmailUrlInfo`: URLs em e-mails que foram clicadas
- `DeviceFileEvents`: criação, modificação, cópia, download de arquivos nos endpoints
- `DeviceNetworkEvents`: conexões de rede estabelecidas pelos dispositivos
- `IdentityLogonEvents`: autenticações de identidade correlacionadas pelo MDI

A razão de usar o Advanced Hunting do XDR (e não diretamente o Sentinel) é que ele tem telemetria de endpoint mais granular (cada operação de arquivo individual) que o Sentinel não recebe por padrão. Para uma investigação de insider threat que depende de evidências de acesso a arquivos específicos, o XDR é o ambiente correto.

---

## Seção 3 — Problema Identificado

A denúncia sugere possível Business Email Compromise (BEC) ou insider threat. Os sinais possíveis:
- E-mails suspeitos de domínios externos
- Download anômalo de arquivos do SharePoint/OneDrive
- Upload para storage cloud não corporativo (Dropbox, Google Drive, WeTransfer)

Sem uma investigação estruturada em Advanced Hunting, é impossível confirmar ou descartar a suspeita. O compliance precisa de evidências técnicas para a decisão disciplinar.

---

## Seção 4 — Roteiro de Atividades

1. Investigar e-mails suspeitos recebidos por marcela.ferreira (MDO)
2. Verificar cliques em URLs suspeitas (MDO — EmailUrlInfo)
3. Correlacionar logins pós-suspeitos com anomalias de IP/location (Entra ID)
4. Investigar downloads de arquivos do SharePoint/OneDrive (MDE — DeviceFileEvents)
5. Correlacionar downloads com uploads para serviços externos
6. Verificar comunicação de rede para destinos suspeitos (MDE — DeviceNetworkEvents)
7. Construir a timeline completa do incidente
8. Criar bookmarks para as evidências encontradas e vincular a um incidente

---

## Seção 5 — Proposição

Ao final deste laboratório:
- Timeline completa da atividade suspeita de marcela.ferreira construída
- Evidências preservadas em Bookmarks no Sentinel
- Cadeia de evidências: e-mail → download → upload → destino externo
- Relatório técnico de evidências preparado para o compliance
- Incidente formal criado no Sentinel com todas as evidências vinculadas

---

## Seção 6 — Script Passo a Passo

### Passo 1: Acessar o Advanced Hunting

**Por que este passo é necessário:** Antes de iniciar qualquer investigação, é fundamental verificar se os dados estão disponíveis no ambiente de hunting. Muitos analistas iniciam investigações e ficam frustrados com queries que retornam zero resultados — não porque o suspeito não fez nada, mas porque o dado não chegou ao sistema. Este passo diagnóstico economiza tempo e define o escopo real da investigação disponível.

**security.microsoft.com → Hunting → Advanced hunting**

**Verificação do ambiente**:
```kql
// Verificar se há dados disponíveis para marcela.ferreira
let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";
union
    (EmailEvents | where RecipientEmailAddress == user | summarize count() by tipo = "EmailEvents"),
    (IdentityLogonEvents | where AccountUpn == user | summarize count() by tipo = "IdentityLogonEvents"),
    (DeviceLogonEvents | where AccountUpn == user | summarize count() by tipo = "DeviceLogonEvents")
| project tipo, count_
```

**Resultado esperado**: Dados em pelo menos 2 tabelas.

---

### Passo 2: Investigar E-mails Suspeitos (MDO)

```kql
// Investigação 1: E-mails de domínios externos suspeitos para marcela.ferreira
// Últimos 30 dias

let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";
let internalDomain = "bancomeridian-lab.onmicrosoft.com";

EmailEvents
| where TimeGenerated > ago(30d)
| where RecipientEmailAddress == user
// Excluir e-mails do próprio domínio
| where SenderFromDomain != internalDomain
| where SenderFromDomain != "microsoft.com"
// Classificar por ameaça
| extend ThreatCategory = case(
    ThreatTypes has "Phish", "PHISHING",
    ThreatTypes has "Malware", "MALWARE",
    DeliveryAction == "Quarantined", "QUARANTINED",
    "Clean"
)
| project TimeGenerated, SenderFromAddress, SenderFromDomain, 
          Subject, DeliveryAction, ThreatCategory, ThreatTypes,
          NetworkMessageId
| sort by TimeGenerated desc
```

**O que procurar nos resultados**: Domínios recentes (< 30 dias), nomes parecidos com parceiros do banco (typosquatting), assuntos relacionados a documentos ou pagamentos.

**Resultado esperado no lab**: 2-3 e-mails de domínios suspeitos nas últimas 2 semanas.

---

### Passo 3: Verificar Cliques em URLs (MDO)

```kql
// Investigação 2: URLs clicadas por marcela.ferreira
let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";

EmailUrlInfo
| where TimeGenerated > ago(30d)
// Correlacionar com e-mails recebidos pelo usuário
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(30d)
    | where RecipientEmailAddress == user
    | project NetworkMessageId, RecipientEmailAddress
) on NetworkMessageId
// Verificar URLs com indicadores de phishing
| where Url !contains "microsoft.com"
       and Url !contains "office.com"
       and Url !contains "sharepoint.com"
       and Url !contains "microsoftonline.com"
| project TimeGenerated, Url, UrlChain, ThreatTypes, NetworkMessageId
| sort by TimeGenerated desc
```

**Anote**: URLs externas encontradas. Verificar no VirusTotal ou URLScan.io se parecerem suspeitas.

---

### Passo 4: Verificar Logins Pós-Suspeitos

```kql
// Investigação 3: Logins de marcela.ferreira com sinais de risco
let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";

IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where AccountUpn == user
| where ActionType == "LogonSuccess"
// Logins com risk ou de localização incomum
| extend Country = tostring(split(Location, ", ")[1])
| summarize 
    LoginCount = count(),
    LastLogin = max(TimeGenerated),
    Countries = make_set(Country, 10),
    IPs = make_set(IPAddress, 10),
    Apps = make_set(Application, 10)
    by bin(TimeGenerated, 1d), Country, IPAddress
| sort by TimeGenerated desc
```

**Anote**: IPs que aparecem somente recentemente ou de localização incomum para a usuária.

---

### Passo 5: Investigar Downloads de Arquivos do SharePoint

```kql
// Investigação 4: Downloads de arquivos do SharePoint pelo endpoint de marcela
let user = "marcela.ferreira";  // Usar apenas o nome sem domínio para DeviceEvents

DeviceFileEvents
| where TimeGenerated > ago(30d)
| where InitiatingProcessAccountName =~ user
// Downloads de aplicações corporativas (Edge, Chrome acessando SharePoint)
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "OneDriveSetup.exe")
       or FolderPath contains "Downloads"
// Filtrar tipos de arquivo sensíveis
| where FileName endswith ".xlsx" 
       or FileName endswith ".xls"
       or FileName endswith ".csv"
       or FileName endswith ".pdf"
       or FileName endswith ".docx"
       or FileName endswith ".zip"
| summarize
    FileCount = count(),
    Files = make_set(FileName, 30),
    TotalSize = sum(FileSize),
    UniqueExtensions = dcount(tostring(split(FileName, ".")[-1]))
    by bin(TimeGenerated, 1h), DeviceName
| where FileCount >= 5    // Pelo menos 5 arquivos em 1h
| sort by TimeGenerated desc
```

**Resultado esperado no lab**: Pico de downloads em um período específico.

---

### Passo 6: Verificar Upload para Serviços Externos

```kql
// Investigação 5: Conexões de rede para serviços de storage externo
let user = "marcela.ferreira";
let cloudStorageDomains = dynamic([
    "dropbox.com", "drive.google.com", "box.com", "wetransfer.com",
    "1drv.ms", "mega.nz", "mediafire.com", "sendspace.com",
    "filemail.com", "transfernow.net", "onedrive.com"
]);

DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where InitiatingProcessAccountName =~ user
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (cloudStorageDomains)
   or RemoteIPType == "FriendlyName" and RemoteIP has_any (cloudStorageDomains)
// Filtrar apenas uploads (HTTP POST/PUT geralmente > 50KB)
| where RemotePort == 443    // HTTPS
| project TimeGenerated, DeviceName, InitiatingProcessFileName, 
          RemoteUrl, RemoteIP, LocalPort
| sort by TimeGenerated desc
```

---

### Passo 7: Construir a Timeline Completa

```kql
// Timeline Completa — Correlação de todas as fontes
let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";
let userShort = "marcela.ferreira";
let investigationPeriod = 30d;

union
    // E-mails suspeitos
    (EmailEvents
     | where TimeGenerated > ago(investigationPeriod)
     | where RecipientEmailAddress == user
     | where SenderFromDomain !contains "bancomeridian-lab"
     | project TimeGenerated, EventType = "Email Received", 
               Description = strcat("E-mail de: ", SenderFromAddress, " | Assunto: ", Subject),
               Source = "MDO"),
    
    // Logins
    (IdentityLogonEvents
     | where TimeGenerated > ago(investigationPeriod)
     | where AccountUpn == user
     | where ActionType == "LogonSuccess"
     | project TimeGenerated, EventType = "Login", 
               Description = strcat("Login de: ", IPAddress, " (", Location, ")"),
               Source = "Entra ID"),
    
    // Downloads de arquivo
    (DeviceFileEvents
     | where TimeGenerated > ago(investigationPeriod)
     | where InitiatingProcessAccountName =~ userShort
     | where FolderPath contains "Downloads"
     | where FileName endswith_cs ".xlsx" or FileName endswith_cs ".csv"
     | project TimeGenerated, EventType = "File Download",
               Description = strcat("Arquivo: ", FileName, " (", FileSize, " bytes)"),
               Source = "MDE"),
    
    // Conexões externas
    (DeviceNetworkEvents
     | where TimeGenerated > ago(investigationPeriod)
     | where InitiatingProcessAccountName =~ userShort
     | where RemoteUrl has_any ("dropbox", "google.com/drive", "wetransfer")
     | project TimeGenerated, EventType = "External Upload",
               Description = strcat("Upload para: ", RemoteUrl),
               Source = "MDE Network")

| sort by TimeGenerated asc
| project TimeGenerated, Source, EventType, Description
```

**Anote** a timeline completa. Identifique a sequência: email → login → download → upload.

---

### Passo 8: Criar Bookmarks e Incidente

**Para cada evidência relevante encontrada nas queries acima**:

1. Selecionar a linha (checkbox à esquerda)
2. Clicar em **Add bookmark**
3. Preencher:
   - Name: descrição breve (ex: "Email suspeito de domínio externo - 15/04")
   - Notes: contexto do que a evidência mostra
   - MITRE ATT&CK: selecionar as técnicas relevantes
4. Clicar em **Create**

**Criar incidente a partir dos bookmarks**:

1. Ir para **Hunting → Bookmarks**
2. Selecionar todos os bookmarks criados
3. Clicar em **Create incident**
4. Título: "Investigação Insider Threat — marcela.ferreira"
5. Severity: Medium (suspeita não confirmada)
6. Assigned to: seu usuário

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                                    | Verificação                                   |
|:-----:|:------------------------------------------------------------|:----------------------------------------------|
| 1     | Verificar dados disponíveis no ambiente                     | Query retorna pelo menos 2 tabelas com dados   |
| 2-3   | Investigar e-mails e cliques suspeitos                      | Pelo menos 1 e-mail suspeito identificado      |
| 4     | Correlacionar logins com anomalias                          | Timeline de logins construída                  |
| 5     | Identificar downloads anômalos de SharePoint                | Pico de downloads no período de interesse     |
| 6     | Encontrar uploads para serviços externos                    | Pelo menos 1 conexão para cloud storage externo|
| 7     | Construir timeline cross-domain correlacionando 3+ fontes   | Timeline com eventos de MDO + Entra ID + MDE   |
| 8     | Preservar evidências em Bookmarks e criar incidente         | Incidente criado com bookmarks vinculados      |

---

## Seção 8 — Gabarito

### Sequência de Evidências Esperadas no Lab

A atividade simulada para `marcela.ferreira` inclui:

**Dia -14**: Recebeu e-mail de `recrutamento@vagasfinanceirasbr.com` (domínio criado há 3 dias) com link para "formulário de atualização cadastral".

**Dia -14**: Clicou no link do e-mail — URL registrada no EmailUrlInfo como `http://vagasfinanceirasbr.com/form?token=xxx`.

**Dia -13**: Login às 22h de IP `200.100.50.33` (Belo Horizonte — usuária trabalha em São Paulo).

**Dia -13 às 22h15**: Download de 47 arquivos .xlsx e .csv em 90 minutos da pasta `/sites/contratos/clientes-premium/`.

**Dia -13 às 23h55**: 3 conexões HTTPS para `api.dropboxapi.com` de 45 minutos de duração.

**Dia -7**: Criou regra de encaminhamento de e-mail para `ferreira_m_external@gmail.com`.

### Queries Finais com Resultados

```kql
// Query de validação final — deve retornar a timeline completa
let user = "marcela.ferreira@bancomeridian-lab.onmicrosoft.com";
union
    (EmailEvents | where RecipientEmailAddress == user | where SenderFromDomain contains "vaga" | project TimeGenerated, Type = "Phishing Email"),
    (IdentityLogonEvents | where AccountUpn == user | where IPAddress == "200.100.50.33" | project TimeGenerated, Type = "Suspicious Login"),
    (DeviceFileEvents | where InitiatingProcessAccountName =~ "marcela.ferreira" | where FolderPath contains "contratos" | where TimeGenerated > datetime_ago(14d) | project TimeGenerated, Type = "File Download"),
    (DeviceNetworkEvents | where InitiatingProcessAccountName =~ "marcela.ferreira" | where RemoteUrl contains "dropbox" | project TimeGenerated, Type = "External Upload"),
    (OfficeActivity | where UserId == user | where Operation == "New-InboxRule" | project TimeGenerated, Type = "Email Forwarding Rule")
| sort by TimeGenerated asc
| project TimeGenerated, Type
// Esperado: 5 tipos de evidência na sequência cronológica correta
```

### Construção do Relatório Técnico

Com base nas evidências, o relatório técnico para compliance deve incluir:

```
RELATÓRIO TÉCNICO — INVESTIGAÇÃO Marcela Ferreira
Data: [data da investigação]
Analista: [nome]
Classificação: CONFIDENCIAL

1. RESUMO
   Investigação iniciada por denúncia anônima. Evidências técnicas confirmam:
   - Conta comprometida via phishing (não exfiltração intencional pela funcionária)
   - Evidências sugerem que um terceiro não autorizado acessou a conta

2. TIMELINE DE EVIDÊNCIAS
   [tabela da Seção 6, Passo 7]

3. EVIDÊNCIAS DIGITAIS PRESERVADAS
   - 5 Bookmarks no Microsoft Sentinel (IDs: [listar])
   - Incidente Sentinel: [número]

4. ANÁLISE
   O padrão de atividade (phishing → login noturno → download em massa → upload externo)
   é consistente com comprometimento de conta por terceiro, não exfiltração intencional.

5. RECOMENDAÇÕES
   a. Forçar reset de senha imediatamente
   b. Revogar sessões ativas
   c. Verificar todos os e-mails encaminhados para o endereço externo
   d. Notificar usuária e RH sobre o comprometimento
   e. Verificar integridade dos 47 arquivos acessados
```

---

### Erros Comuns e Como Identificar

| Problema | Sintoma | Causa Provável | Solução |
|:---------|:--------|:---------------|:--------|
| Query retorna 0 resultados para EmailEvents | Tabela vazia mesmo com atividade simulada | MDO não está conectado ao workspace de Advanced Hunting ou dados ainda não ingeridos | Verificar em security.microsoft.com → Settings → Microsoft 365 Defender → Connected services se MDO está ativo |
| `AccountUpn` não funciona em IdentityLogonEvents | Erro `Column not found` | Tabela usa `AccountUpn` mas versão do conector pode ter nomes diferentes | Tentar `AccountName` ou `AccountId` — usar `getschema IdentityLogonEvents` para ver as colunas disponíveis |
| Timeline do Passo 7 retorna duplicatas | Evento único aparece múltiplas vezes | `union` em tabelas com sobreposição de dados | Adicionar `| distinct TimeGenerated, Source, EventType, Description` ao final da query |
| Bookmark não vincula ao incidente correto | Bookmark criado mas não aparece no incidente | Incidente foi criado antes dos bookmarks, sem vinculação automática | Em Sentinel → Incidents → [incidente] → Bookmarks → Add para vincular manualmente |
| `DeviceFileEvents` muito lento | Query leva mais de 2 minutos | Filtro de tempo amplo (30d) sem filtro de dispositivo ou usuário suficiente | Adicionar `| where DeviceName == "NOTEBOOK-MARCELA"` ou reduzir `ago(30d)` para `ago(7d)` |

### Interpretação do MITRE ATT&CK para as Evidências Encontradas

A cadeia de ataque do cenário Marcela Ferreira mapeia para as seguintes técnicas MITRE:

| Fase | TTP | Técnica |
|:-----|:----|:--------|
| Acesso inicial | T1566.002 | Phishing - Link malicioso |
| Coleta de credencial | T1539 | Roubo de sessão web (token) |
| Descoberta | T1083 | Enumeração de arquivos |
| Coleta | T1213.002 | SharePoint (Data from Information Repositories) |
| Exfiltração | T1567.002 | Exfiltração para Cloud Storage |
| Persistência | T1114.003 | Email Forwarding Rule |

Este mapeamento deve constar no relatório técnico e nos bookmarks para facilitar futuras correlações em threat hunting e analytics rules.
