# Módulo 06 — Microsoft Defender XDR

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 5 horas (2h videoaulas + 2h laboratório + 1h live online)                   |
| **Formato**              | 2 aulas gravadas + Lab 05 + sessão live de Advanced Hunting                 |
| **Pré-requisito**        | Módulos 01–05 concluídos; acesso ao portal security.microsoft.com          |
| **Certificação Alvo**    | SC-200 — Domínio 5: Mitigate threats using Microsoft Defender XDR          |
| **Cenário**              | Banco Meridian — investigando comprometimento BEC com Advanced Hunting      |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Descrever a arquitetura do Microsoft Defender XDR e como MDE, MDI, MDO e MDA se integram
2. Onboardar endpoints no MDE e configurar telemetria básica
3. Identificar ataques de identidade com MDI (Kerberoasting, Golden Ticket, lateral movement)
4. Configurar proteções avançadas de e-mail com MDO (Safe Links, Safe Attachments, ZAP)
5. Executar Advanced Hunting queries cross-domain correlacionando múltiplas tabelas
6. Entender o Automatic Attack Disruption e como o XDR contém ataques em andamento

---

## 1. Microsoft Defender XDR: Visão Geral

### 1.1 O que é o Defender XDR

O **Microsoft Defender XDR** (Extended Detection and Response) é uma plataforma unificada de proteção, detecção e resposta que correlaciona sinais de múltiplos produtos Defender em uma única fila de investigação.

Antes do XDR, cada produto Defender gerava alertas isolados:
- MDE → portal security.microsoft.com/mde
- MDI → portal.atp.azure.com
- MDO → security.microsoft.com/threatmanagement

Hoje, tudo converge no **Microsoft Defender portal** (security.microsoft.com): um único painel com uma única fila de incidentes unificada.

### 1.2 Componentes e Telemetria

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         MICROSOFT DEFENDER XDR                                       │
│                    portal: security.microsoft.com                                    │
│                                                                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │ DEFENDER FOR    │  │ DEFENDER FOR    │  │ DEFENDER FOR   │  │ DEFENDER FOR   ││
│  │ ENDPOINT (MDE)  │  │ IDENTITY (MDI)  │  │ OFFICE 365     │  │ CLOUD APPS     ││
│  │                 │  │                 │  │ (MDO)          │  │ (MDA)          ││
│  │ Telemetria:     │  │ Telemetria:     │  │ Telemetria:    │  │ Telemetria:    ││
│  │ DeviceEvents    │  │ IdentityLogon   │  │ EmailEvents    │  │ CloudAppEvents ││
│  │ DeviceProcess   │  │ IdentityDir.    │  │ EmailAttach.   │  │ AppGovernance  ││
│  │ DeviceNetwork   │  │ IdentityQuery   │  │ UrlClickEvents │  │ ShadowIT       ││
│  │ DeviceFile      │  │ AlertInfo       │  │ AlertInfo      │  │ AlertInfo      ││
│  │ DeviceRegistry  │  │                 │  │                │  │                ││
│  └────────┬────────┘  └────────┬────────┘  └───────┬────────┘  └───────┬────────┘│
│           │                   │                    │                   │           │
│           └───────────────────┴────────────────────┴───────────────────┘           │
│                                           │                                          │
│                              ┌────────────▼─────────────┐                          │
│                              │   CORRELATION ENGINE      │                          │
│                              │   (ML + fusion rules)     │                          │
│                              │   → Unified Incidents     │                          │
│                              └────────────┬─────────────┘                          │
│                                           │                                          │
│              ┌────────────────────────────┼────────────────────────────┐            │
│              ▼                            ▼                             ▼            │
│   ┌──────────────────┐        ┌───────────────────┐        ┌──────────────────────┐│
│   │ ADVANCED HUNTING  │        │ INCIDENT QUEUE    │        │ AUTO ATTACK          ││
│   │ (cross-domain KQL)│        │ (unified view)    │        │ DISRUPTION           ││
│   └──────────────────┘        └───────────────────┘        └──────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Microsoft Defender for Endpoint (MDE)

### 2.1 Onboarding de Endpoints

O onboarding de endpoints é o processo de instalar o sensor MDE (Microsoft Defender for Endpoint) nos dispositivos. Esse sensor coleta telemetria de processo, arquivo, rede e registro em tempo real, enviando para o backend Microsoft 365 Defender onde é processado por machine learning e inteligência de ameaças do MSTIC.

**Por que o onboarding é o primeiro passo prático (não o portal):** Muitos profissionais cometem o erro de passar horas configurando políticas e regras no portal MDE sem ter onboardado nenhum endpoint. Resultado: um portal vazio, sem telemetria, sem alertas reais. O onboarding é o ato de "conectar o sensor" — sem ele, o MDE não vê nada. No Banco Meridian, a estratégia de onboarding define quantos dos 2.800 dispositivos estarão protegidos e monitorados.

**Métodos de onboarding**:

| Método                    | Melhor para                                          |
|:--------------------------|:-----------------------------------------------------|
| Intune (MDM)              | Dispositivos gerenciados pelo Intune (modernos)      |
| SCCM/Endpoint Config. Mgr | Ambientes corporativos com SCCM implantado           |
| Group Policy (GPO)        | Domínios AD tradicionais (Windows 10/11/Server)      |
| Script local              | Testes, dispositivos avulsos, ambientes de lab       |
| VDI (non-persistent)      | Infraestrutura de desktop virtual                    |

**Onboarding via script local (lab)**:
```powershell
# 1. Baixar o pacote de onboarding no portal MDE
# security.microsoft.com → Settings → Endpoints → Onboarding → Windows 10/11

# 2. Extrair e executar (como administrador)
.\WindowsDefenderATPOnboardingScript.cmd

# 3. Verificar status do sensor
sc query sense
# Deve mostrar: STATUS: RUNNING

# 4. Executar teste de detecção (EICAR simulado)
powershell -command "[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object net.webclient).DownloadFile('https://aka.ms/ioavtest','test-av-test.exe')"
# O MDE deve gerar alerta de teste em ~5 minutos
```

### 2.2 Telemetria e Capacidades

**Threat & Vulnerability Management (TVM)**:
- Inventário de software instalado em todos os endpoints
- CVEs identificadas com score de exploitability
- Remediação via ticket para equipes de TI
- Weaknesses: configurações inseguras (ex.: SMBv1 habilitado, RDP exposto)

**Live Response**:
```powershell
# Comandos disponíveis no Live Response do MDE
# (executado via portal, sem acesso direto ao endpoint)

# Listar processos
processes

# Listar conexões de rede ativas
connections

# Coletar arquivo para análise forense
getfile c:\users\rafael.torres\downloads\suspicious.exe

# Executar script PowerShell
run MyScript.ps1

# Colocar arquivo em quarentena
remediate file c:\windows\temp\malware.dll

# Isolar máquina da rede
isolate
```

### 2.3 Detecções Importantes do MDE para Banco Meridian

| Técnica MITRE           | O que o MDE detecta                                           |
|:------------------------|:--------------------------------------------------------------|
| T1059 (Script Execution)| Execução de PowerShell com base64, scripts ofuscados          |
| T1003.001 (LSASS Dump)  | mimikatz, ProcDump contra lsass.exe                          |
| T1055 (Process Injection)| Injeção de código em processos legítimos                    |
| T1047 (WMI Execution)   | Execução de processos via WMI (LOLBin)                       |
| T1021 (Remote Services) | PsExec, WinRM, RDP lateral movement                          |
| T1105 (File Transfer)   | Download de ferramentas de C2 (certutil, bitsadmin)          |
| T1071 (C2 over HTTP/S)  | Comunicação com IPs/domínios de C2                           |

---

## 3. Microsoft Defender for Identity (MDI)

### 3.1 O que o MDI Protege

O MDI monitora o tráfego do Active Directory diretamente nos Domain Controllers, analisando protocolos Kerberos, NTLM, LDAP e DNS. Não depende de logs — captura o tráfego em tempo real.

**Por que o MDI é especialmente crítico para bancos com AD on-premises:** O Active Directory é o alvo preferencial de grupos APT porque comprometer o AD significa comprometer tudo. Um attacker que obtém credenciais de administrador de domínio tem acesso irrestrito a todos os servidores, dados e sistemas do banco. O MDI é a única ferramenta que monitora o tráfego de autenticação Kerberos e NTLM diretamente no Domain Controller — ataques como Kerberoasting, Golden Ticket e DCSync deixam rastros apenas no tráfego de rede do DC, não em logs tradicionais de evento do Windows.

**O que diferencia o MDI do monitoramento tradicional de logs:** As ferramentas SIEM tradicionais dependem de logs de evento do Windows (Event IDs 4768, 4769, 4771 etc.) para detectar ataques Kerberos. O problema é que esses logs são configurados no próprio DC, e um attacker com acesso de administrador pode desabilitar o logging. O MDI captura o tráfego de rede no nível do kernel — um administrador comprometido não consegue desabilitar isso sem fisicamente desconectar o sensor.

> **Por que isso importa para o Banco Meridian:** O banco tem um Domain Controller central e dois DCs regionais. Sem o MDI, um analista precisaria revisar manualmente os Event IDs de autenticação de 2.800 usuários para detectar Kerberoasting. Com o MDI, o alerta chega em segundos quando uma conta de serviço recebe mais solicitações TGS do que o normal para suas SPNs.

Para o Banco Meridian, que tem um AD on-premises sincronizado com Entra ID (Entra ID Connect), o MDI cobre:
- Domain Controllers on-premises (sensor direto no DC)
- Entra ID (via integração com Entra ID Protection)
- Active Directory Federation Services (AD FS) com sensor dedicado

### 3.2 Principais Detecções do MDI

| Ataque                    | Técnica MITRE  | Como o MDI Detecta                                               |
|:--------------------------|:--------------:|:-----------------------------------------------------------------|
| Kerberoasting             | T1558.003      | Solicitações TGS excessivas para contas de serviço (SPNs)        |
| AS-REP Roasting           | T1558.004      | Solicitações AS-REQ para contas sem pré-autenticação Kerberos    |
| Golden Ticket             | T1558.001      | Uso de TGT com vida útil anômala ou para contas inexistentes     |
| Silver Ticket             | T1558.002      | Uso de TGS forjado sem TGT correspondente                        |
| DCSync                    | T1003.006      | Usuário não-DC solicitando replicação de credenciais AD          |
| Pass-the-Hash             | T1550.002      | NTLM challenge/response com hash conhecido                       |
| Pass-the-Ticket           | T1550.003      | Uso de ticket Kerberos de outro dispositivo                      |
| Lateral Movement          | T1021          | Padrão de conexão SMB/RPC anômalo entre hosts                    |
| Reconnaissance LDAP       | T1018          | Enumeração massiva de objetos AD via LDAP                        |
| Password Spray (AD)       | T1110.003      | Múltiplas tentativas NTLM/Kerberos de baixa frequência           |

### 3.3 Configuração de Alertas de MDI no Banco Meridian

O MDI tem um sensor agent instalado diretamente em cada Domain Controller. Para instalar:

```powershell
# 1. Baixar o instalador do MDI no portal defender.microsoft.com
# Settings → Identities → Sensors → Add sensor

# 2. Executar no DC (requer privilégios de Domain Admin)
.\Azure ATP Sensor Setup.exe /quiet NetFrameworkCommandLineArguments="/q" 
    AccessKey="[chave do workspace MDI]"

# 3. Verificar status do sensor
Get-AzureATPSensor | Select-Object DisplayName, Status, Version

# 4. Configurar account sensitivity para contas VIP
# portal.atp.azure.com → Settings → Sensitive accounts
# Adicionar: CEO, CFO, CISO, CTO, Domain Admins
```

---

## 4. Microsoft Defender for Office 365 (MDO)

### 4.1 Safe Links e Safe Attachments

**Safe Links**: Reescreve URLs em e-mails e documentos Office para passar por verificação em tempo real antes do clique. Se o destino for malicioso, bloqueia e exibe aviso.

```
Fluxo Safe Links:
Usuário clica em link → Link reescrito para safelinks.protection.outlook.com
→ Verificação em tempo real (reputação, sandbox) → Permitir OU Bloquear
```

**Safe Attachments**: Abre anexos em uma sandbox isolada antes de entregar ao usuário. Detecta malware zero-day que antivírus tradicionais não identificam.

```
Fluxo Safe Attachments:
E-mail com anexo chegou → Entregar sem anexo → Rodar anexo em sandbox (1-5min)
→ Limpo: entregar com anexo → Malicioso: quarentena + alerta
```

### 4.2 Zero-Hour Auto Purge (ZAP)

O ZAP purga e-mails maliciosos que já foram entregues, retroativamente, quando novos indicadores de ameaça são identificados. Funciona para:
- Spam: remove e-mails classificados como spam após a entrega
- Phishing: purga e-mails de phishing descobertos post-delivery
- Malware: purga e-mails com malware identificado após entrega

**Para investigação**: Verificar ZAP activity via Advanced Hunting:
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where DeliveryAction == "Replaced"    // ZAP ou Safe Links reescrita
   or DeliveryAction == "Quarantined"
   or LatestDeliveryAction == "Quarantined"
| project TimeGenerated, NetworkMessageId, SenderFromAddress, 
          RecipientEmailAddress, Subject, DeliveryAction, 
          LatestDeliveryLocation
```

### 4.3 Políticas Anti-Phishing

Configurações recomendadas para o Banco Meridian:

```
Defender for Office 365 → Threat Policies → Anti-phishing → 
Banco Meridian Policy:

Impersonation settings:
  ✓ Enable user impersonation protection
    Protected users: CEO, CFO, CISO, Head of IT (20 usuários críticos)
  ✓ Enable domain impersonation protection
    Protected domains: bancomeridian.com.br, bancomeridian.com (e variações)
  ✓ Enable mailbox intelligence

Actions:
  User impersonation: Quarantine message
  Domain impersonation: Move to Junk
  Mailbox intelligence: Move to Junk

Spoof intelligence:
  ✓ Enable spoof intelligence
  Action: Quarantine
```

---

## 5. Microsoft Defender for Cloud Apps (MDA)

### 5.1 Funções CASB

O MDA atua como **Cloud Access Security Broker (CASB)**, posicionado entre usuários e aplicações cloud. Funções principais:

**Shadow IT Discovery**: Identifica aplicações cloud usadas na organização sem aprovação de TI. Baseado em logs de firewall/proxy. Para o Banco Meridian: identificar funcionários usando Dropbox, Google Drive, ou apps de comunicação não aprovados.

**Session Policies**: Controle de sessão em tempo real para aplicações conectadas. Pode:
- Bloquear download de arquivos sensíveis de aplicações não gerenciadas
- Bloquear upload para aplicações não aprovadas
- Marcar arquivos como sensíveis e aplicar label de proteção

**App Governance**: Monitoramento de aplicações OAuth registradas no tenant. Detecta apps com permissões excessivas, apps de terceiros suspeitas, e abuso de permissões delegadas.

### 5.2 Políticas Importantes para o Banco Meridian

```
POLÍTICA 1: Download de dados sensíveis de dispositivo não gerenciado
──────────────────────────────────────────────────────────────────────
Tipo: Session policy
Aplicação: Microsoft 365 (SharePoint, OneDrive)
Filtro: Device não está marcado como Compliant (não gerenciado pelo Intune)
Filtro: Arquivo tem label "Confidencial" ou "Altamente Confidencial"
Ação: Block download + Alert

POLÍTICA 2: Upload para storage cloud não aprovado
──────────────────────────────────────────────────
Tipo: Access policy
Aplicação: Dropbox, Google Drive, Box (marcados como "Unsanctioned")
Filtro: Qualquer upload de arquivo
Ação: Block + Alert + Log

POLÍTICA 3: OAuth App com permissão Mail.ReadWrite
──────────────────────────────────────────────────
Tipo: App governance policy
Condition: App solicitou permissão Mail.ReadWrite ou Mail.Send
Condition: App não está na allowlist corporativa
Ação: Alert + (opcional) Disable app
```

---

## 6. Unified Incident Queue e Automatic Attack Disruption

### 6.1 Como Funciona a Correlação

O Defender XDR usa um motor de correlação baseado em ML que:

1. **Agrupa alertas** do mesmo ataque em um único incidente (correlação por entidade, tempo e sequência de ataque)
2. **Reconstrói a kill chain** usando o modelo MITRE ATT&CK
3. **Calcula score de confiança** baseado na quantidade e qualidade dos sinais

**Exemplo de correlação para o Banco Meridian**:

```
ALERTA 1 (MDO): Phishing email com link malicioso recebido por rafael.torres — 14:02h
ALERTA 2 (Entra ID Protection): Sign-in de IP suspeito para rafael.torres — 14:23h
ALERTA 3 (MDE): Execução de powershell.exe com parâmetros suspeitos em WKST-0042 — 14:31h
ALERTA 4 (MDI): DCSync request de WKST-0042 (comportamento de DC) — 14h45

XDR Correlation:
─────────────────────────────────────────────
INCIDENT: "Multi-stage attack via phishing — BEC Campaign"
Severity: High
MITRE ATT&CK: 
  Initial Access: T1566.001 (Spearphishing Link)
  Credential Access: T1539 (Steal Web Session Cookie)
  Execution: T1059.001 (PowerShell)
  Credential Access: T1003.006 (DCSync)
Entities: rafael.torres, WKST-0042, 200.150.30.45
```

### 6.2 Automatic Attack Disruption

O **Automatic Attack Disruption** é uma capacidade do Defender XDR que contém automaticamente ataques em andamento sem intervenção humana, baseado em sinais de alta confiança.

**Quando ativa**: quando o XDR identifica um ataque de alta confiança com critérios específicos (ex.: BEC ativo, ransomware em propagação).

**Ações automáticas**:
- Desabilitar usuário comprometido (temporariamente)
- Isolar dispositivos comprometidos
- Revogar tokens OAuth maliciosos
- Bloquear endereços IP maliciosos

**Diferença do SOAR**: Attack Disruption é tomado pelo XDR diretamente, sem passar por Logic Apps. É mais rápido mas menos customizável. Os playbooks do Sentinel são disparados depois para enriquecimento e notificação.

---

## 7. Advanced Hunting Cross-Domain

### 7.1 Tabelas Disponíveis no Advanced Hunting XDR

| Domínio        | Tabelas                                                                           |
|:---------------|:----------------------------------------------------------------------------------|
| **Endpoint**   | DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents |
| **Identidade** | IdentityLogonEvents, IdentityDirectoryEvents, IdentityQueryEvents                 |
| **E-mail**     | EmailEvents, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents           |
| **Cloud Apps** | CloudAppEvents                                                                    |
| **Alertas**    | AlertInfo, AlertEvidence                                                          |

### 7.2 Query 1 — BEC (Business Email Compromise)

O **Business Email Compromise** é o ataque de maior impacto financeiro contra bancos e instituições financeiras, segundo o FBI IC3. No cenário típico de BEC contra o Banco Meridian: o atacante envia um e-mail de phishing para um funcionário com acesso ao sistema de transferências, o funcionário clica no link e entrega as credenciais em um site falso, e o atacante usa essas credenciais para autorizar transferências fraudulentas usando a conta comprometida do funcionário. Esta query cross-domain une três fontes: `EmailUrlInfo` (MDO — registra URLs clicadas nos e-mails), `EmailEvents` (MDO — metadados do e-mail, incluindo remetente e destinatário), e `IdentityLogonEvents` (MDI/Entra ID — logins do usuário). A correlação temporal `| where LoginTime > ClickTime` é o que torna esta query poderosa: não estamos procurando logins suspeitos genéricos, mas especificamente logins que ocorreram DEPOIS de um clique em URL de phishing — o padrão exato de uma conta comprometida por BEC.

O resultado desta query, se positivo, é evidência de comprometimento confirmado e deve ativar imediatamente o playbook de conta comprometida do Lab 04.

```kql
// ═══════════════════════════════════════════════════════════════════
// ADVANCED HUNTING: Business Email Compromise (BEC)
// Correlação: MDO (email suspeito) + Entra ID (login pós-phishing)
// Objetivo: Identificar usuários que clicaram em link de phishing
//           e depois logaram de IP/dispositivo suspeito
// ═══════════════════════════════════════════════════════════════════

let timeWindow = 4h;

// Passo 1: Encontrar cliques em URLs maliciosas (MDO Safe Links)
let phishingClicks = EmailUrlInfo
| where TimeGenerated > ago(timeWindow)
| where UrlChain has_any ("phish", "malware", "suspicious")   // Ajustar para IOCs reais
   or ThreatTypes has_any ("Phish", "Malware")
| project ClickTime = TimeGenerated, NetworkMessageId, 
          ClickedUrl = Url, RecipientEmailAddress;

// Passo 2: Associar cliques ao e-mail original
let phishingEmails = EmailEvents
| where TimeGenerated > ago(timeWindow)
| join kind=inner phishingClicks on NetworkMessageId
| project EmailTime = TimeGenerated, NetworkMessageId, 
          SenderFromAddress, RecipientEmailAddress, Subject,
          ClickTime, ClickedUrl;

// Passo 3: Verificar logins após o clique no phishing
phishingEmails
| join kind=inner (
    IdentityLogonEvents
    | where TimeGenerated > ago(timeWindow)
    | where ActionType == "LogonSuccess"
    | project LoginTime = TimeGenerated, AccountUpn, IPAddress, 
              DeviceName, Application, LogonType
) on $left.RecipientEmailAddress == $right.AccountUpn
// Login ocorreu DEPOIS do clique no link malicioso
| where LoginTime > ClickTime
// Login dentro de 2h após o clique
| where LoginTime < datetime_add('hour', 2, ClickTime)
| project
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    ClickTime,
    ClickedUrl,
    LoginTime,
    IPAddress,
    DeviceName,
    LogonType,
    MinutesBetweenClickAndLogin = datetime_diff('minute', LoginTime, ClickTime)
| sort by MinutesBetweenClickAndLogin asc
```

---

### 7.3 Query 2 — Lateral Movement (MDI + MDE)

O **movimento lateral** é a fase do ataque onde o adversário expande seu acesso de uma máquina ou conta comprometida para outros sistemas da rede interna — em direção aos ativos de alto valor (servidores de banco de dados, controladores de domínio, sistemas de transferência). Para o Banco Meridian, a rota típica de lateral movement é: endpoint de funcionário comprometido via phishing → servidor de arquivos do financeiro → servidor de banco de dados com contratos de crédito → controlador de domínio. Esta query une `IdentityLogonEvents` (MDI — registra logins de identidade, incluindo Kerberos e NTLM) com `DeviceNetworkEvents` (MDE — registra conexões de rede no nível de processo), correlacionando pelo hostname. O padrão de alerta é um usuário que logou recentemente em um host (`IdentityLogonEvents`) e esse mesmo host está fazendo conexões SMB (porta 445) para múltiplos hosts internos em sequência — padrão típico de worm de rede ou ferramenta de lateral movement como Impacket ou CrackMapExec.

A presença de `DeviceNetworkEvents` nesta query é o que diferencia o Advanced Hunting XDR de uma análise de logs de identidade simples: o MDI vê a identidade, o MDE vê a rede, e juntos revelam a cadeia completa.

```kql
// ═══════════════════════════════════════════════════════════════════
// ADVANCED HUNTING: Lateral Movement Detection
// Correlação: MDI (identidade) + MDE (endpoint)
// Objetivo: Detectar movimentação lateral via SMB/RPC de um host
//           comprometido para outros hosts internos
// MITRE: T1021.002 (SMB/Windows Admin Shares)
// ═══════════════════════════════════════════════════════════════════

let suspiciousAccount = "rafael.torres@bancomeridian.com.br";
let timeWindow = 24h;

// Passo 1: Obter hosts onde a conta suspeita autenticou recentemente
let authenticatedHosts = IdentityLogonEvents
| where TimeGenerated > ago(timeWindow)
| where AccountUpn == suspiciousAccount
| where ActionType == "LogonSuccess"
| project LoginTime = TimeGenerated, SourceHost = DeviceName, 
          DestinationHost = TargetDeviceName, Protocol, LogonType;

// Passo 2: Buscar conexões de rede a partir desses hosts (MDE)
let lateralConnections = DeviceNetworkEvents
| where TimeGenerated > ago(timeWindow)
| where RemotePort in (445, 139, 135, 5985, 5986)   // SMB, RPC, WinRM
| where ActionType == "ConnectionSuccess"
// Apenas conexões internas (10.x, 192.168.x, 172.16-31.x)
| where RemoteIP startswith "10." 
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and (toint(split(RemoteIP, ".")[1]) between (16 .. 31)))
| project ConnectionTime = TimeGenerated, SourceDevice = DeviceName, 
          DestinationIP = RemoteIP, DestinationPort = RemotePort,
          InitiatingProcess = InitiatingProcessFileName;

// Passo 3: Correlacionar
authenticatedHosts
| join kind=inner lateralConnections on $left.SourceHost == $right.SourceDevice
| where ConnectionTime > LoginTime    // Conexão lateral DEPOIS do login
| summarize
    LateralConnections = count(),
    TargetIPs = make_set(DestinationIP, 20),
    Protocols = make_set(InitiatingProcess, 5),
    FirstConnection = min(ConnectionTime),
    LastConnection = max(ConnectionTime)
    by SourceHost, suspiciousAccount
| where LateralConnections >= 3    // Pelo menos 3 conexões laterais (não um acesso pontual)
| sort by LateralConnections desc
```

---

### 7.4 Query 3 — AiTM Phishing (MDO + Entra ID)

O **AiTM (Adversary-in-the-Middle) phishing** é o vetor que o FS-ISAC identificou especificamente como ameaça ao Banco Meridian. No AiTM, o atacante opera um proxy reverso entre a vítima e o site legítimo da Microsoft: quando o funcionário acessa o link de phishing, ele está na verdade conectado ao servidor do atacante, que encaminha a comunicação para o Microsoft 365. O funcionário passa pelo MFA normalmente, a Microsoft aprova a sessão — e o atacante intercepta o cookie/token de sessão já autenticado. A partir daí, o MFA não protege mais: o atacante tem um token válido, completamente independente de senha ou MFA. Esta query detecta o padrão post-exploitation do AiTM: um login bem-sucedido na conta que historicamente usa MFA, mas neste login específico o `AuthenticationRequirement` é `singleFactorAuthentication` (a sessão foi autenticada sem MFA porque o token já era válido). Combina com eventos do MDO que indicam que um e-mail de phishing foi recebido e clicado, aumentando a confiança do alerta.

```kql
// ═══════════════════════════════════════════════════════════════════
// ADVANCED HUNTING: AiTM Phishing Detection
// Correlação: MDO (URL phishing) + IdentityLogonEvents (token theft)
// Objetivo: Detectar uso de token roubado via AiTM (sem MFA)
//           para acesso a aplicações Microsoft 365
// MITRE: T1557 (AiTM), T1539 (Steal Web Session Cookie)
// ═══════════════════════════════════════════════════════════════════

let timeWindow = 6h;

// Passo 1: Identificar usuários que receberam e potencialmente clicaram
//          em URL de phishing classificada como AiTM
let aitm_victims = EmailEvents
| where TimeGenerated > ago(timeWindow)
| where ThreatTypes has "Phish"
| join kind=inner (
    EmailUrlInfo
    | where TimeGenerated > ago(timeWindow)
    | where ThreatTypes has "Phish"
) on NetworkMessageId
| distinct RecipientEmailAddress, SenderFromAddress, Url;

// Passo 2: Para cada vítima potencial, buscar login sem MFA 
//          em aplicações O365 de IP não reconhecido
aitm_victims
| join kind=inner (
    IdentityLogonEvents
    | where TimeGenerated > ago(timeWindow)
    | where Application in ("Office 365", "Microsoft Teams", 
                             "SharePoint Online", "Exchange Online")
    | where LogonType == "CloudInteractive"
    // Sinais de AiTM: sem device compliance, IP externo
    | where IPAddress !startswith "10."
    | where IPAddress !startswith "192.168."
    | project LoginTime = TimeGenerated, AccountUpn, IPAddress,
              Application, DeviceInfo, AdditionalFields
) on $left.RecipientEmailAddress == $right.AccountUpn
// Extrair se havia MFA nos campos adicionais
| extend AuthMethod = tostring(parse_json(AdditionalFields).AuthenticationMethods)
| where AuthMethod !contains "MultiFactor"    // Login sem MFA mesmo sendo conta MFA-enabled
| project
    Victim = RecipientEmailAddress,
    PhishSender = SenderFromAddress,
    PhishUrl = Url,
    LoginTime,
    LoginIP = IPAddress,
    Application,
    AuthMethod
```

---

### 7.5 Query 4 — Credential Dump via LSASS (MDE)

O **dump de credenciais via LSASS** (Local Security Authority Subsystem Service) é a técnica de coleta de credenciais mais usada em ataques avançados em redes Windows. O processo LSASS mantém em memória os hashes de senhas e tickets Kerberos de todos os usuários que autenticaram na máquina — uma mina de ouro para um atacante. Ferramentas como Mimikatz, ProcDump (usada com argumento de LSASS) e ferramentas de RAT/C2 acessam a memória do LSASS para extrair essas credenciais sem precisar de nenhuma senha adicional. Para o Banco Meridian, um endpoint de TI que tem acesso a sistemas administrativos é um alvo prioritário: comprometer esse endpoint e fazer dump do LSASS pode revelar hashes de contas de administrador de domínio. Esta query monitora três tipos de eventos do MDE: processo `lsass.exe` sendo acessado por processos que não deveriam fazê-lo, criação de dump files com nome referenciando `lsass`, e execução de ferramentas conhecidas de credential dumping na linha de comando. A combinação dessas três fontes de evidência dentro do mesmo endpoint no mesmo período de tempo é um indicador de alta confiança de comprometimento.

```kql
// ═══════════════════════════════════════════════════════════════════
// ADVANCED HUNTING: LSASS Credential Dumping
// Fonte: MDE (DeviceProcessEvents + DeviceEvents)
// Objetivo: Detectar tentativas de dump de credenciais do LSASS
//           via ferramentas conhecidas (mimikatz, ProcDump, etc.)
// MITRE: T1003.001 (OS Credential Dumping: LSASS Memory)
// ═══════════════════════════════════════════════════════════════════

let timeWindow = 24h;

// Método 1: Detecção por nome de processo/ferramenta conhecida
let method1 = DeviceProcessEvents
| where TimeGenerated > ago(timeWindow)
| where FileName in~ ("mimikatz.exe", "mimikatz64.exe", 
                       "mimilsa.exe", "mimilib.dll",
                       "procdump.exe", "procdump64.exe")
   or ProcessCommandLine has_any ("sekurlsa", "lsadump", "kerberos::list",
                                   "privilege::debug", "token::elevate",
                                   "lsass.exe", "lsass.dmp")
| project Method = "Tool/Command", TimeGenerated, DeviceName, AccountDomain,
          AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName;

// Método 2: Detecção por acesso de processo a LSASS (OpenProcess com MiniDump flag)
let method2 = DeviceEvents
| where TimeGenerated > ago(timeWindow)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe", "SecurityHealthService.exe", "WerFault.exe",
    "csrss.exe", "lsass.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "svchost.exe", "System"
)
| project Method = "OpenProcess", TimeGenerated, DeviceName, AccountDomain,
          AccountName, FileName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine;

// União dos dois métodos
union method1, method2
| sort by TimeGenerated desc
```

---

### 7.6 Query 5 — OAuth App Abuse (MDA + Entra ID)

O **abuso de OAuth App** é uma técnica sofisticada de persistência que contorna completamente a autenticação baseada em usuário/senha/MFA. Após comprometer uma conta, o atacante cria ou registra um aplicativo OAuth no Entra ID e convence (ou autoriza com as credenciais roubadas) um usuário privilegiado a conceder permissões ao app. A partir desse momento, o app tem um token OAuth independente da conta do usuário — reconfigurar a senha, revogar sessões e resetar o MFA não remove o acesso do app malicioso. Permissões como `Mail.Read`, `Files.ReadWrite.All` e `User.ReadWrite.All` dão ao app acesso perpétuo às caixas de e-mail, documentos do SharePoint e gestão de usuários do banco. Esta técnica foi usada no ataque ao SolarWinds e em múltiplos ataques a instituições financeiras. Para o Banco Meridian, a query une `CloudAppEvents` (MDA — registra atividades em apps cloud) com `IdentityDirectoryEvents` (MDI/Entra — registra criação de app registrations) e filtra por permissões de alto risco, correlacionando com atividade de exfiltração posterior à autorização do app.

O campo `AdditionalFields` do `CloudAppEvents` contém o JSON completo da atividade, incluindo as permissões específicas concedidas — informação crítica para determinar o impacto do comprometimento.

```kql
// ═══════════════════════════════════════════════════════════════════
// ADVANCED HUNTING: OAuth Application Abuse
// Correlação: CloudAppEvents (MDA) + IdentityDirectoryEvents (MDI/Entra)
// Objetivo: Detectar apps OAuth criadas ou autorizadas recentemente
//           com permissões excessivas (mail.read, files.readwrite.all)
//           correlacionando com atividade suspeita pós-autorização
// MITRE: T1550.001 (OAuth Token), T1528 (Steal Application Token)
// ═══════════════════════════════════════════════════════════════════

let timeWindow = 7d;
let dangerousPermissions = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Sites.ReadWrite.All",
    "Directory.ReadWrite.All", "User.ReadWrite.All",
    "Calendars.Read", "Contacts.Read"
]);

// Passo 1: Apps OAuth criados/autorizados recentemente com permissões perigosas
let suspiciousApps = CloudAppEvents
| where TimeGenerated > ago(timeWindow)
| where ActionType in ("OAuthAppConsented", "AddDelegatedPermissionGrant",
                       "AddAppRoleAssignment", "ConsentToApplication")
| extend PermissionsGranted = tostring(RawEventData.Permissions)
| where PermissionsGranted has_any (dangerousPermissions)
| project ConsentTime = TimeGenerated, AccountDisplayName, 
          AccountUpn = AccountId, AppId = tostring(RawEventData.AppId),
          AppName = tostring(RawEventData.AppName),
          Permissions = PermissionsGranted;

// Passo 2: Verificar se o app teve atividade subsequente suspeita
suspiciousApps
| join kind=leftouter (
    CloudAppEvents
    | where TimeGenerated > ago(timeWindow)
    | where ActionType in ("FileDownloaded", "MailRead", "FileCopied")
    | summarize
        ActivityCount = count(),
        LastActivity = max(TimeGenerated),
        Operations = make_set(ActionType, 10)
        by AppId = tostring(RawEventData.ApplicationId)
) on AppId
| extend RiskScore = case(
    Permissions has "Mail.ReadWrite" and ActivityCount > 0, "Critical",
    Permissions has "Files.ReadWrite.All" and ActivityCount > 0, "High",
    isnotnull(ActivityCount) and ActivityCount > 0, "Medium",
    "Low"
)
| project ConsentTime, AccountUpn, AppName, AppId, 
          Permissions, ActivityCount, LastActivity, Operations, RiskScore
| sort by RiskScore asc, ActivityCount desc
```

---

## 8. Atividades de Fixação

### Questão 1
O MDI detectou "DCSync" realizado a partir do host WKST-0042 (uma estação de trabalho comum, não um DC). O que esse alerta indica?

a) Um Domain Controller chamado WKST-0042 está sincronizando com outros DCs normalmente  
b) Um atacante comprometeu a estação WKST-0042 e está usando técnica DCSync para extrair hashes de todas as contas do AD, incluindo o krbtgt — o que permite criar Golden Tickets  
c) O usuário logado em WKST-0042 tem permissão de Domain Replication e está fazendo backup  
d) O MDE detectou um processo de system restore no WKST-0042  

**Gabarito: B** — DCSync (T1003.006) é uma técnica que abusa das permissões de replicação do Active Directory. Normalmente, apenas DCs se comunicam entre si para sincronizar o banco de dados AD. Quando uma estação de trabalho comum solicita replicação, é extremamente suspeito — significa que o atacante compromometeu uma conta com privilégio de replicação (ex.: Domain Admin) e está usando-a para extrair todos os hashes de senha do AD, incluindo o hash da conta krbtgt (usado para assinar todos os tickets Kerberos). Com o hash krbtgt, o atacante pode forjar Golden Tickets com acesso ilimitado ao AD.

---

### Questão 2
Qual é a diferença entre Safe Links e Safe Attachments no Defender for Office 365?

a) Safe Links protege documentos Word; Safe Attachments protege PDFs  
b) Safe Links reescreve e verifica URLs em e-mails e documentos em tempo real no clique; Safe Attachments abre anexos em uma sandbox isolada antes de entregar ao usuário  
c) Safe Links é para e-mails externos; Safe Attachments é para e-mails internos  
d) Safe Links requer licença MDO P2; Safe Attachments está disponível no M365 E3  

**Gabarito: B** — Safe Links funciona no momento do clique: a URL original é reescrita para passar por um proxy de segurança da Microsoft que verifica em tempo real se o destino é malicioso (phishing, malware). Safe Attachments funciona antes da entrega: o anexo é detonado (executado) numa sandbox isolada para verificar comportamento malicioso antes de chegar à caixa de entrada do usuário. Ambos requerem MDO P1 ou superior (não incluído no M365 E3).

---

### Questão 3
Uma Advanced Hunting query correlaciona as tabelas EmailEvents e IdentityLogonEvents usando o campo RecipientEmailAddress e AccountUpn. Qual operador de join deve ser usado para manter apenas os logins que têm correspondência com um e-mail de phishing?

a) `join kind=leftouter`  
b) `join kind=inner`  
c) `join kind=anti`  
d) `join kind=fullouter`  

**Gabarito: B** — `join kind=inner` mantém apenas as linhas que têm correspondência em ambas as tabelas — exatamente o que queremos: apenas logins de usuários que também receberam o e-mail de phishing. `leftouter` manteria todos os logins (com e sem phishing correspondente), gerando resultados não relevantes. `anti` retornaria logins que NÃO têm correspondência com phishing (o oposto do desejado). `fullouter` retornaria tudo de ambas as tabelas.

---

### Questão 4
O Automatic Attack Disruption do Defender XDR isolou automaticamente o computador do CFO do Banco Meridian durante um incidente crítico. O CFO ficou sem acesso ao computador. Como o SOC deve proceder?

a) Desabilitar o Automatic Attack Disruption para evitar que isso aconteça novamente  
b) O isolamento foi a ação correta — o CFO provavelmente estava com o endpoint comprometido; o SOC deve investigar o incidente, confirmar se é True Positive, executar Live Response para análise forense, e só então desfazer o isolamento se o endpoint estiver limpo  
c) Reverter imediatamente o isolamento pois o CFO é VIP  
d) Criar uma exceção permanente para que o endpoint do CFO nunca seja isolado automaticamente  

**Gabarito: B** — O Automatic Attack Disruption age com base em sinais de alta confiança. Se o endpoint do CFO foi isolado, há evidências fortes de comprometimento. A ação correta é: (1) verificar o incidente no portal XDR para entender o gatilho; (2) usar Live Response para coletar evidências sem remover o isolamento; (3) se confirmado comprometimento, remediar o endpoint antes de desfazer o isolamento; (4) se for falso positivo, desfazer o isolamento e ajustar as detecções. Criar exceção permanente (D) para VIPs é uma má prática — endpoints de executivos são alvos de alto valor e precisam de proteção ainda maior.

---

### Questão 5
A query de Advanced Hunting para detecção de LSASS dump usa dois métodos combinados com `union`. Por que é necessário usar dois métodos distintos?

a) Porque o KQL não permite consultar DeviceProcessEvents e DeviceEvents na mesma query sem union  
b) Porque ferramentas diferentes usam técnicas diferentes: algumas são detectadas pelo nome do processo/comando (mimikatz.exe, procdump), outras pelo comportamento de OpenProcess no LSASS (ferramentas que se renomeiam ou são injected) — usar ambos aumenta a cobertura  
c) Para duplicar os alertas e garantir que pelo menos um seja gerado  
d) Porque DeviceProcessEvents é do MDE P1 e DeviceEvents é do MDE P2 — precisam ser consultados separadamente  

**Gabarito: B** — Atacantes sofisticados renomeiam ferramentas conhecidas (de mimikatz.exe para svchost.dll) ou usam técnicas sem arquivo (in-memory execution). O Método 1 (nome/comando) detecta uso direto de ferramentas conhecidas. O Método 2 (OpenProcess na LSASS de processo suspeito) detecta comportamento independente do nome da ferramenta — qualquer processo que tenta abrir o LSASS para leitura de memória é suspeito se não for um processo legítimo do sistema. Usar ambos em union maximiza a cobertura de detecção.

---

## 9. Roteiros de Gravação

### Aula 6.1 — XDR Overview + MDE + MDI (50 minutos)

---

**[0:00 — ABERTURA | 3 minutos]**

"Módulo 6 — Defender XDR. Aqui entendemos o arsenal completo de detecção Microsoft. O Sentinel que aprendemos nos módulos anteriores é o SIEM — ele recebe e correlaciona. O Defender XDR é onde os produtos de proteção vivem: endpoint, identidade, e-mail, apps cloud.

Hoje é uma aula densa. Vamos cobrir 4 produtos em detalhes. Vou focar no que importa para o dia a dia do SOC e para o SC-200."

---

**[3:00 — BLOCO 1: XDR — VISÃO GERAL | 10 minutos]**

*[Screen share: portal security.microsoft.com]*

"Abro o Microsoft Defender portal. Esta é a casa do XDR. A diferença entre isso e o portal de 3 anos atrás é dramática — antes havia portais separados para cada produto. Hoje, tudo num só lugar.

*[Mostrar a fila de incidentes unificada]*

Aqui está a fila de incidentes. Cada incidente aqui pode conter alertas de 4 produtos diferentes. Abro um incidente para mostrar.

*[Abrir incidente de exemplo]*

Vejo: alertas do MDE, do MDI e do MDO no mesmo incidente. A MITRE ATT&CK kill chain está mapeada. A timeline de ataque está reconstruída. Isso que é o poder do XDR — correlação automática."

---

**[13:00 — BLOCO 2: MDE — ENDPOINT PROTECTION | 18 minutos]**

*[Screen share: portal MDE]*

"Vou para o MDE. Clico em Devices. Aqui estão todos os endpoints do Banco Meridian onboarded.

*[Mostrar o inventário de dispositivos]*

Cada dispositivo tem um Risk Score — calculado com base em vulnerabilidades não corrigidas, configurações inseguras e alertas ativos.

Clico em um dispositivo — WKST-0042. Vejo: timeline de atividade, software instalado, vulnerabilidades (CVEs), alertas.

*[Mostrar Threat & Vulnerability Management]*

Em Vulnerability Management: 23 vulnerabilidades críticas neste host. Entre elas: CVE-2023-23397 (Outlook escalada de privilégio via calendar invite). Este CVE é especialmente relevante para bancos — atacante pode obter hash NTLM sem clique.

*[Mostrar Live Response — não executar, apenas demonstrar a interface]*

Live Response: conexão direta ao terminal do endpoint via browser. Posso coletar evidências, matar processos, buscar arquivos. Tudo auditado."

---

**[31:00 — BLOCO 3: MDI — IDENTITY PROTECTION | 17 minutos]**

*[Screen share: portal MDI via Defender portal → Identities]*

"MDI. Esta é uma das capacidades mais sub-utilizadas do Microsoft Security. E é onde os ataques mais sofisticados são detectados — movimento lateral, Kerberoasting, Golden Ticket.

*[Mostrar dashboard MDI]*

O MDI tem um sensor em cada Domain Controller do Banco Meridian. Ele vê TODO o tráfego Kerberos e NTLM da organização.

*[Mostrar alerta de Kerberoasting simulado]*

Vejo um alerta: 'Kerberoasting activity observed'. Um host solicitou tickets TGS para 15 contas de serviço diferentes em 2 minutos. Isso é Kerberoasting — o atacante está tentando quebrar os hashes de serviço offline.

*[Navegar pela timeline de ataque do alerta]*

O MDI mostra: qual host fez as requisições, quais contas de serviço foram alvos, timestamps, e qual técnica MITRE está sendo usada.

Para o SC-200: Kerberoasting = T1558.003. O MDI detecta automaticamente. A resposta: verificar se as contas de serviço têm senhas fortes (>25 caracteres aleatórios) e considerar Group Managed Service Accounts (gMSA) para rotação automática de senha."

---

**[48:00 — ENCERRAMENTO | 2 minutos]**

"Vimos o XDR overview, MDE para endpoint e MDI para identidade. Na próxima aula, fechamos com MDO para e-mail, MDA para cloud apps, e a parte mais empolgante — Advanced Hunting cross-domain."

---

### Aula 6.2 — MDO + MDA + Advanced Hunting Cross-Domain (50 minutos)

---

**[0:00 — ABERTURA | 2 minutos]**

"Última aula do Módulo 6. Cobrimos MDO, MDA e Advanced Hunting — a ferramenta de investigação mais poderosa do ecossistema Microsoft. Ao final, vocês serão capazes de rastrear um ataque do e-mail inicial até a exfiltração final, cruzando 3 produtos diferentes numa única query."

---

**[2:00 — BLOCO 1: MDO — EMAIL SECURITY | 12 minutos]**

*[Screen share: portal Defender → Email & collaboration]*

"MDO. O e-mail é o vetor #1 de ataque. 90% dos ataques começam por phishing. O MDO é a linha de defesa crítica.

*[Mostrar Threat Explorer]*

No Threat Explorer, consigo ver todos os e-mails processados com detalhes de ameaça: quais foram identificados como phishing, quais contêm malware, quais foram bloqueados vs entregues.

*[Fazer uma busca por e-mails de phishing recentes]*

Vou buscar e-mails de phishing das últimas 24h. Aqui está um: remetente fraudulento fingindo ser CFO, com link para site de coleta de credenciais.

*[Mostrar a cadeia de entrega e ações do MDO]*

O MDO detectou como phishing mas entregou para a caixa de junk. Não ideal — deveria ter ido para quarentena. Vou ajustar a política anti-phishing para quarentena em vez de junk.

*[Mostrar como ajustar a política]*

Vou mostrar também o ZAP em ação: um e-mail entregue ontem foi retroativamente classificado como malware quando a Microsoft adicionou a hash do anexo ao seu feed de TI. O ZAP automaticamente moveu da inbox para quarentena."

---

**[14:00 — BLOCO 2: MDA — CLOUD APP SECURITY | 8 minutos]**

*[Screen share: portal Defender → Cloud Apps]*

"MDA — Cloud App Security. Dois casos de uso principais que demonstrarei.

**Shadow IT Discovery**:
*[Mostrar Cloud App Catalog]*
Vejo uma lista de aplicações identificadas através de logs de proxy do Banco Meridian. WhatsApp Web tem 2.000 usuários. Dropbox tem 800. Google Drive tem 500. Nenhuma delas é uma aplicação corporativa aprovada.

Para aplicações de armazenamento cloud: posso marcar como 'Unsanctioned' e o MDA bloqueia automaticamente o acesso.

**App Governance**:
*[Mostrar App Governance]*
Aqui estão todas as apps OAuth registradas no tenant com as permissões que solicitaram. Filtro por permissões 'Mail.Read'. Aparecem 3 apps — apenas 1 está na lista corporativa aprovada. As outras 2 precisam de investigação.

Esta capacidade é crucial para detectar o cenário de OAuth App Abuse que vimos na query de Advanced Hunting."

---

**[22:00 — BLOCO 3: ADVANCED HUNTING — DEMO AO VIVO | 25 minutos]**

*[Screen share: portal Defender → Hunting → Advanced hunting]*

"Agora a cereja do bolo — Advanced Hunting. Esta é a ferramenta mais poderosa do XDR para investigação proativa.

*[Mostrar interface do Advanced Hunting]*

Aqui é basicamente um editor KQL conectado a todas as tabelas do XDR — DeviceEvents, EmailEvents, IdentityLogonEvents, CloudAppEvents e mais.

Vou executar a query de BEC ao vivo. Vou usar o período das últimas 24h com os dados do nosso ambiente de demo.

*[Colar e executar a query de BEC — Query 1 desta documentação]*

*[Esperar resultado e comentar cada linha]*

Aqui estão os resultados. Vejo 2 usuários que clicaram em link de phishing e logaram em seguida de IP externo. O mais urgente: minuto de diferença entre o clique e o login — sessão ativa provavelmente comprometida.

Para ambos, nosso playbook de conta comprometida deveria ter sido ativado. Vou verificar se o Sentinel recebeu esses dados.

*[Abrir Sentinel em outra aba e mostrar o incidente correspondente]*

Perfeito — o Sentinel tem o incidente correlacionado. O playbook já revogou as sessões. O Advanced Hunting confirmou o que o SIEM detectou.

Vou criar um 'Custom detection' a partir desta query — ela vai rodar a cada hora e gerar um alerta automaticamente no Defender XDR quando detectar esse padrão.

*[Mostrar como salvar como Custom Detection]*"

---

**[47:00 — ENCERRAMENTO | 3 minutos]**

"Concluímos o Módulo 6. O Defender XDR é o motor de detecção. O Sentinel é o cerebro de análise e resposta. Juntos, eles cobrem todo o ecossistema Microsoft — endpoint, identidade, e-mail, aplicações cloud.

No Lab 05, vocês vão investigar um caso de BEC usando Advanced Hunting cross-domain, construindo a cadeia de evidências do e-mail phishing até a exfiltração. O gabarito no repositório tem as queries comentadas linha a linha."

---

## 10. Avaliação do Módulo

**Q1.** O MDI detectou "Kerberoasting" vindo de WKST-0099. Qual é a primeira ação recomendada para o analista SOC?

a) Reiniciar o serviço Kerberos em todos os Domain Controllers  
b) Identificar a conta de usuário logada em WKST-0099, isolar o endpoint via MDE e auditar quais SPNs foram solicitados para priorizar contas de serviço com senhas fracas  
c) Desabilitar todos os SPNs de contas de serviço imediatamente  
d) Bloquear o protocolo Kerberos no firewall corporativo  

**Resposta: B** — A sequência correta: (1) identificar quem está operando o host comprometido; (2) isolar o endpoint para conter o ataque (Live Response ou MDE isolate); (3) verificar os SPNs solicitados — contas de serviço com senhas fracas precisam ter a senha rotacionada imediatamente antes que o atacante quebre os hashes offline; (4) considerar migrar contas de serviço críticas para Group Managed Service Accounts (gMSA) com rotação automática de senha a cada 30 dias.

---

**Q2.** Um analista usa Advanced Hunting para correlacionar EmailEvents e IdentityLogonEvents. A query usa `join kind=inner`. Se um usuário recebeu o e-mail mas não logou depois, o que acontece com esse registro no resultado?

a) O registro aparece com campos vazios de login  
b) O registro é descartado — o inner join mantém apenas linhas com correspondência em ambas as tabelas  
c) O registro aparece com um alerta de "Login não detectado"  
d) A query falha com erro por registros sem correspondência  

**Resposta: B** — `join kind=inner` descarta linhas que não têm correspondência em ambas as tabelas. Isso é desejado quando queremos correlacionar: "usuário que recebeu phishing E logou". Para ver usuários que receberam phishing mas NÃO logaram (para notificação preventiva), usar `join kind=leftanti`.

---

**Q3.** O que é o Zero-Hour Auto Purge (ZAP) no Defender for Office 365?

a) Uma feature que bloqueia todos os e-mails externos durante uma hora em caso de ataque detectado  
b) A capacidade de remover retroativamente e-mails da inbox dos usuários que foram inicialmente entregues mas depois classificados como phishing ou malware com base em nova inteligência de ameaças  
c) Um sistema de backup de e-mails deletados por zero horas  
d) O tempo mínimo de quarentena para e-mails suspeitos  

**Resposta: B** — ZAP age post-delivery: quando a Microsoft identifica que um e-mail já entregue é malicioso (baseado em nova TI, relatórios de usuários, ou análise adicional), o ZAP automaticamente move o e-mail da inbox para quarentena ou o deleta. Isso cobre o "gap de proteção" — e-mails que chegaram antes da ameaça ser conhecida pelo sistema de filtro. Para investigação: verificar ZAP actions em EmailPostDeliveryEvents no Advanced Hunting.

---

**Q4.** Um app OAuth chamado "Excel Budget Tool" foi autorizado pelo CFO com permissão `Mail.ReadWrite`. Qual é o risco imediato?

a) Nenhum risco — é normal que apps de Excel acessem e-mail  
b) A permissão `Mail.ReadWrite` permite que o app leia, modifique e delete todos os e-mails do CFO sem que ele precise estar logado — se o app for malicioso ou comprometido, pode exfiltrar comunicações sensíveis  
c) O app pode enviar e-mails em nome do CFO por até 1 hora  
d) O risco é apenas teórico — apps OAuth só funcionam quando o usuário está logado  

**Resposta: B** — OAuth tokens com `Mail.ReadWrite` permitem acesso delegado às caixas de e-mail independente do usuário estar logado — enquanto o token for válido. Tokens OAuth têm vida longa (refresh tokens podem durar meses). Um atacante que obteve o token pode acessar todos os e-mails do CFO continuamente. Isso é o ataque de OAuth App Abuse (T1528): o atacante convence um usuário privilegiado a autorizar um app malicioso, obtendo acesso persistente mesmo sem saber a senha.

---

**Q5.** Na query de Advanced Hunting para detecção de lateral movement, o filtro `RemotePort in (445, 139, 135, 5985, 5986)` detecta movimentação via quais protocolos?

a) HTTP/HTTPS (445=HTTPS), RDP (5985=RDP padrão)  
b) SMB (445, 139), RPC (135), WinRM (5985=HTTP, 5986=HTTPS) — todos usados em técnicas comuns de lateral movement  
c) Apenas DNS (445) e LDAP (139)  
d) Kerberos (445) e NTLM (5985)  

**Resposta: B** — As portas filtradas são: 445 (SMB — usado por PsExec, at.exe, WMI lateral movement); 139 (SMB legacy/NetBIOS); 135 (RPC Endpoint Mapper — usado para iniciar conexões DCOM/WMI remotas); 5985 (WinRM HTTP — usado por PowerShell remoting); 5986 (WinRM HTTPS — versão criptografada). Todas são portas de protocolos de administração remota Windows comumente abusadas para lateral movement.
