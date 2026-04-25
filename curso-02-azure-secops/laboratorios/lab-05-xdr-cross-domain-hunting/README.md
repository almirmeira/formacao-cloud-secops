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

**O que este passo faz:** A investigação começa pelos e-mails porque 90% dos ataques de comprometimento de conta iniciam por phishing. A query analisa todos os e-mails recebidos por marcela.ferreira nos últimos 30 dias, excluindo domínios internos e classificando por categoria de ameaça. Para uma investigação de insider threat que pode, na verdade, ser um comprometimento de conta externo, entender quais e-mails chegaram e de quais domínios é o primeiro passo para determinar se a funcionária foi vítima de phishing (não responsável pelo vazamento) ou se o acesso foi deliberado. Os campos `ThreatTypes` e `DeliveryAction` revelam o que o Defender for Office 365 já sabia sobre esses e-mails no momento da entrega — se havia um e-mail classificado como Phish que foi entregue na caixa de entrada, isso é uma evidência crítica de comprometimento externo.

**Por que agora:** Esta é a primeira query porque e-mails são o vetor de entrada mais provável. O resultado desta análise vai definir o período de interesse (quando o phishing chegou) que guiará todas as queries subsequentes.

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

**O que este passo faz:** Saber que um e-mail suspeito chegou à caixa de entrada é importante, mas saber que o usuário clicou em uma URL maliciosa é a prova de que o ataque teve sucesso na fase de entrega. A tabela `EmailUrlInfo` registra cada URL presente em e-mails e, quando o Safe Links está habilitado, registra também o status da verificação de segurança. Para a investigação de Marcela Ferreira, esta query responde a pergunta mais crítica: ela clicou no link do e-mail suspeito? Se sim, temos o momento exato do comprometimento e o endereço do site de phishing. Esse dado é o ponto de pivô para toda a análise subsequente — a partir do horário do clique, buscamos o login que se seguiu, os downloads que ocorreram e os uploads externos.

**Por que agora:** Com os e-mails suspeitos identificados no Passo 2, precisamos agora verificar se eles foram clicados. A correlação via `NetworkMessageId` garante que estamos olhando apenas as URLs dos e-mails recebidos por Marcela — não URLs aleatórias do ambiente.

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

**O que este passo faz:** Com e-mails suspeitos e possíveis cliques identificados nos passos anteriores, esta query mapeia o padrão de autenticação de Marcela nos últimos 30 dias usando a tabela `IdentityLogonEvents` (fornecida pelo Microsoft Defender for Identity e pelo Entra ID, conforme o conector configurado). Ao agregar logins por país e IP de origem, o objetivo é identificar anomalias geográficas: se Marcela sempre logou de São Paulo e de repente aparece um login da Ucrânia ou de um VPN anônimo, isso é um sinal forte de comprometimento de conta. A coluna `Countries = make_set(Country, 10)` cria uma lista dos países de origem de cada dia, tornando imediatamente visível quando um dia específico tem um país fora do padrão histórico. Este passo responde à pergunta: "Algum atacante usou as credenciais de Marcela para autenticar na conta?"

**Por que agora:** Este passo vem após os e-mails e cliques porque o login suspeito é a consequência natural de um phishing bem-sucedido. Sem os passos 2 e 3 estabelecendo a hipótese de comprometimento, essa query seria uma busca genérica. Com eles, estamos confirmando ou refutando a hipótese com dados de autenticação reais.

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

**O que este passo faz:** Com o login suspeito confirmado no Passo 4, esta query investiga o que o atacante (ou Marcela, se for insider threat) fez após obter acesso à conta. A tabela `DeviceFileEvents` do MDE registra criação, modificação e exclusão de arquivos no nível de endpoint — não o que foi acessado na nuvem, mas o que efetivamente foi gravado no disco local. Downloads de arquivos do SharePoint via browser (Chrome, Edge) ou via OneDrive sync geram eventos em `DeviceFileEvents` com `FolderPath` contendo "Downloads" ou "OneDrive" e o processo iniciador sendo o browser. Para o Banco Meridian, um download de dezenas de arquivos Excel com dados de contratos de crédito, ou documentos PDF de propostas comerciais, é o sinal de que dados confidenciais saíram do controle da organização para o dispositivo físico de onde podem ser facilmente exfiltrados via USB, e-mail pessoal ou serviço de storage externo. O campo `SHA256` presente nos resultados permite verificar os arquivos contra bases de malware (VirusTotal) e confirmar quais arquivos específicos foram baixados.

**Por que agora:** Este passo segue naturalmente a confirmação do login suspeito: depois de entrar na conta, a ação mais frequente de um atacante ou insider threat é baixar dados de valor. Verificar downloads imediatamente após confirmar o acesso suspeito revela a extensão do comprometimento.

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

**O que este passo faz:** Após identificar downloads em massa de arquivos corporativos no SharePoint (Passo 5), esta query verifica a destinação: os arquivos foram enviados para serviços de armazenamento externos não autorizados? A tabela `DeviceNetworkEvents` registra conexões TCP/IP de nível de endpoint realizadas pelo MDE — diferente dos logs de aplicação do OfficeActivity, aqui vemos conexões de rede brutas, incluindo uploads para Dropbox, Google Drive, Mega, WeTransfer e outros serviços que o Banco Meridian não sanciona para uso com dados corporativos. Para compliance com a BACEN 4.893 e a política de prevenção de vazamento de dados (DLP) do banco, qualquer upload de dados financeiros para serviços pessoais de armazenamento é uma violação grave, independentemente de ser por ataque externo ou decisão do funcionário. O filtro por `RemotePort == 443` garante que estamos capturando conexões HTTPS — praticamente todos os serviços de storage usam HTTPS para uploads.

**Por que agora:** Este passo é o elo final da cadeia de exfiltração: e-mail phishing → clique → login comprometido → download de arquivos → upload externo. Sem verificar o upload, poderíamos concluir que dados foram acessados mas não vazados. Com este passo, temos a evidência completa do vazamento.

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

### Passo 7: Construir a Timeline Cross-Domain Completa

**O que este passo faz:** Esta query consolida evidências de três domínios diferentes (e-mail via MDO, autenticação via Entra ID, endpoint via MDE) em uma única timeline cronológica. É o passo de síntese da investigação — o equivalente digital de montar um quadro de evidências conectando todos os fatos descobertos. A timeline cross-domain é o que transforma observações isoladas em uma narrativa coerente de ataque: às 14h30 chegou o e-mail de phishing (MDO), às 14h47 houve um clique na URL (MDO), às 15h02 ocorreu o login de IP estrangeiro (Entra ID), às 15h15 iniciaram-se os downloads de arquivos Excel (MDE), às 16h30 começaram os uploads para o Dropbox (MDE Network). Essa narrativa é o que o CISO precisa para tomar uma decisão e o que o jurídico precisa para suportar qualquer ação legal.

**Por que agora:** A timeline só pode ser construída após todos os dados individuais terem sido coletados e o período de interesse estar definido. Executar antes dos passos 2-6 produziria uma timeline incompleta ou confusa.

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

**O que você deve ver:** A timeline mostra uma narrativa coerente de ataque: e-mail → login → download → upload, todos com timestamps que se seguem logicamente. A coluna `Source` permite distinguir de qual produto Defender cada evidência veio (MDO, Entra ID, MDE), demonstrando o valor do Advanced Hunting cross-domain: uma única query consolida evidências que estariam espalhadas em quatro portais diferentes.

**O que fazer se der errado:**
- Se `DeviceFileEvents` retornar vazio: verificar se o endpoint de Marcela está onboarded no MDE
- Se os timestamps não estiverem alinhados: lembrar de ajustar para o fuso horário UTC-3 (Brasil Standard Time) ao interpretar os dados

---

### Passo 8: Criar Bookmarks e Incidente

**O que este passo faz:** Bookmarks são mecanismos de preservação de evidências digitais no Microsoft Sentinel. Quando um analista encontra uma linha de resultado de query que representa uma evidência de um ataque, criar um bookmark significa fixar aquele dado — incluindo o timestamp, os valores dos campos relevantes, a query que o gerou e as notas do analista — em um local auditável e permanente. Esse processo é equivalente ao "preservação da cadeia de custódia" em forense digital: garante que a evidência não seja alterada, perdida ou contextualizada de forma incorreta. Para o Banco Meridian, que precisa demonstrar conformidade com a BACEN 4.893 (que exige rastreabilidade de incidentes), os bookmarks compõem o registro formal da investigação. Criar um incidente a partir dos bookmarks transforma a investigação informal em um ticket oficial no sistema de gestão de incidentes do SOC, com owner, severity e status definidos.

**Por que agora:** A criação de bookmarks e do incidente formal deve ser o último passo, depois de toda a evidência estar coletada e analisada. Criar bookmarks prematuramente pode resultar em evidências fragmentadas sem o contexto completo da investigação.

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
