# Módulo 02 — Ingestão e UDM
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 2h videoaulas + 2h laboratório                                      |
| **Pré-requisito**  | Módulo 01 concluído · Tenant Google SecOps ativo                    |
| **MITRE ATT&CK**   | T1059 (Command Scripting), T1190 (Exploit Public-Facing App) — contexto de logs |
| **Ferramentas**    | Google SecOps Console, Bindplane OP Agent, gcloud CLI, parser editor |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Configurar os principais mecanismos de ingestão de logs no Google SecOps (forwarders, feeds, webhooks e Bindplane OP Agent)
2. Distinguir parsers nativos de parsers CBN (Configuration-Based Normalization) e quando usar cada um
3. Descrever a estrutura completa do Unified Data Model (UDM) com todos os namespaces
4. Mapear campos de logs proprietários para o UDM usando a sintaxe CBN
5. Validar a ingestão e normalização de logs usando UDM Search

---

## Conteúdo do Módulo

### 2.1 Arquitetura de Coleta: Visão Geral

Antes de qualquer regra de detecção funcionar, os logs precisam chegar ao Google SecOps.
A arquitetura de coleta é o alicerce de todo o SIEM — dados mal ingeridos resultam em
detecções incompletas, investigações superficiais e blindspots críticos.

No caso do Banco Meridian, o desafio é representativo do que qualquer instituição financeira
brasileira enfrenta: fontes diversas e heterogêneas. O banco tem firewalls Palo Alto nas
filiais exportando logs em CEF/Syslog; o sistema de core banking Tópus Banking gerando CSVs
proprietários; o Azure AD gerando eventos JSON via Microsoft Graph API; servidores Windows
com Event IDs clássicos; e cargas de trabalho no Google Cloud gerando Cloud Audit Logs.
Cada uma dessas fontes usa um formato diferente, um protocolo diferente e um mecanismo de
entrega diferente. A arquitetura de coleta precisa contemplar todas elas.

```
DIAGRAMA: FLUXO DE INGESTÃO DO GOOGLE SECOPS
═══════════════════════════════════════════════════════════════════════════════

  FONTES DE LOG                 MECANISMOS DE INGESTÃO            GOOGLE SECOPS
  ═════════════                 ══════════════════════            ═════════════

  ┌─────────────┐
  │  Endpoints  │──── Bindplane OP Agent ─────────────────────►┐
  │  (Windows,  │                                               │
  │   Linux,    │                                               │
  │   macOS)    │                                               │
  └─────────────┘                                               │
                                                                │
  ┌─────────────┐                                               │
  │  Firewalls  │──── Chronicle Forwarder (syslog/CEF) ────────►│
  │  IDS/IPS    │                                               │  ┌────────────────┐
  │  WAF        │                                               ├─►│   CHRONICLE    │
  └─────────────┘                                               │  │  INGESTION     │
                                                                │  │    LAYER       │
  ┌─────────────┐                                               │  │                │
  │   Cloud     │──── Google Cloud Pub/Sub ───────────────────►│  │ Parser Engine  │
  │  Services   │──── Storage Transfer Service ───────────────►│  │ (Native / CBN) │
  │  (GCP/Azure)│──── Direct API Feed ───────────────────────►│   │                │
  └─────────────┘                                               │  │ ───────────── │
                                                                │  │  UDM Schema    │
  ┌─────────────┐                                               │  │  Normalization │
  │  SaaS Apps  │──── Webhooks REST API ─────────────────────►│   └────────────────┘
  │ (M365, GSW) │──── API Polling Feed ──────────────────────►│           │
  └─────────────┘                                               │           ▼
                                                                │  ┌────────────────┐
  ┌─────────────┐                                               │  │  PETABYTE-SCALE│
  │  SIEM/SOAR  │──── Syslog / LEEF / CEF ──────────────────►│   │    STORAGE     │
  │  Legado     │                                               │  │  (BigQuery +   │
  └─────────────┘                                               │  │   Spanner)     │
                                                                │  └────────────────┘
  ┌─────────────┐                                               │
  │   Arquivos  │──── GCS Bucket Import ─────────────────────►┘
  │  CSV / JSON │
  └─────────────┘

═══════════════════════════════════════════════════════════════════════════════
```

---

### 2.2 Forwarders, Feeds, Webhooks e Bindplane OP Agent

#### 2.2.1 Chronicle Forwarder

O **Chronicle Forwarder** é um agente leve instalado em servidores on-premises ou em VMs
que coleta logs via Syslog (UDP/TCP), arquivo de log ou chamadas de API e os encaminha
criptografados para o Google SecOps.

**Casos de uso típicos:**
- Firewalls e IDS/IPS on-premises (Palo Alto, Fortinet, CheckPoint)
- Servidores de log centralizados (rsyslog, syslog-ng)
- Sistemas legados que exportam apenas Syslog

**Instalação básica (Linux):**

```bash
# 1. Baixar o binário do forwarder
curl -O https://releases.chronicle.security/forwarder/chronicle-forwarder-linux-amd64

# 2. Tornar executável
chmod +x chronicle-forwarder-linux-amd64

# 3. Criar arquivo de configuração
cat > /etc/chronicle/config.yaml << 'EOF'
output:
  url: malachiteingestion-pa.googleapis.com:443
  identity:
    secret_key: /etc/chronicle/credentials.json
collectors:
  - syslog:
      common:
        enabled: true
        data_type: PAN_FIREWALL
        data_hint: ""
        batch_n_seconds: 10
        batch_n_bytes: 1048576
      tcp_address: 0.0.0.0:10514
      connection_timeout_sec: 60
EOF

# 4. Iniciar como serviço
systemctl enable chronicle-forwarder
systemctl start chronicle-forwarder
```

#### 2.2.2 Feeds Diretos

Os **Feeds** permitem que o Google SecOps **busque ativamente** logs de fontes como buckets
GCS, APIs REST, servidores S3 ou endpoints HTTPS. São configurados diretamente na interface
web do Google SecOps, sem instalação de agente.

**Tipos de Feed disponíveis:**

| Tipo de Feed              | Protocolo        | Exemplo de Uso                              |
|:--------------------------|:----------------:|:--------------------------------------------|
| **Google Cloud Storage**  | GCS API          | Logs do Cloud Audit, VPC Flow Logs          |
| **Amazon S3**             | S3 API           | AWS CloudTrail, VPC Flow Logs               |
| **Azure Blob Storage**    | Azure Storage API| Azure Activity Logs, Defender for Cloud     |
| **HTTP(S) Pull**          | REST             | APIs de SaaS (Okta, Salesforce, Duo)        |
| **Microsoft Graph API**   | Graph REST       | Microsoft 365, Azure AD, Defender           |
| **Webhook (Push)**        | HTTPS POST       | Sistemas que enviam eventos por push        |
| **Syslog TCP/UDP**        | Syslog           | Dispositivos de rede, firewalls             |
| **Pub/Sub**               | Google Pub/Sub   | Eventos GCP (Cloud Audit, SCC)              |

**Configuração de feed via console:**

```
Navegação:
Settings → Ingestion → Feeds → + Add Feed

Campos obrigatórios:
- Feed name: "Azure AD Sign-in Logs"
- Source type: Microsoft Azure
- Log type: AZURE_AD
- Authentication: Service Principal (Client ID + Secret)
- Tenant ID: [seu tenant ID do Azure AD]
- Polling interval: 5 minutes
```

#### 2.2.3 Webhooks

Os **Webhooks** permitem que sistemas externos enviem logs diretamente ao Google SecOps
via HTTP POST. O Google SecOps gera um endpoint HTTPS único para cada webhook configurado.

```
FLUXO DO WEBHOOK:
─────────────────────────────────────────────────────────
Sistema Externo                        Google SecOps
─────────────────────────────────────────────────────────
(ex: Splunk, QRadar, SIEM legado)
         │
         │  POST /webhook/v1/{webhook_id}
         │  Headers: X-goog-api-key: {api_key}
         │  Body: {"events": [...]}
         │──────────────────────────────────────────────►
         │
         │◄─────────────────────────────────────────────
                     HTTP 200 OK
                     {"status": "ingested", "count": 1}
─────────────────────────────────────────────────────────
```

#### 2.2.4 Bindplane OP Agent

O **Bindplane OP Agent** é a solução moderna de coleta de telemetria do Google (baseada no
OpenTelemetry Collector). Ele substitui gradualmente o Chronicle Forwarder clássico e oferece
suporte nativo a dezenas de integrações, configuração centralizada via painel web e telemetria
de saúde dos agentes em tempo real.

No cenário do Banco Meridian, o Bindplane OP Agent é a escolha mais adequada para o servidor
de logs centralizado (SRV-LOG-001), pois permite ao time de SOC gerenciar todas as fontes de
coleta em um único painel web — sem precisar de SSH em servidor de produção para ajustar
configurações. Quando uma nova filial é aberta, basta adicionar um novo agente via console
e configurar as fontes remotamente.

**Vantagens do Bindplane OP sobre o Forwarder clássico:**

| Critério               | Chronicle Forwarder       | Bindplane OP Agent          |
|:-----------------------|:-------------------------:|:---------------------------:|
| **Configuração**       | Arquivo YAML local        | Painel web centralizado     |
| **Telemetria**         | Não                       | Sim (health, throughput)    |
| **Integrações**        | ~50 tipos                 | 200+ integrações            |
| **Protocolos**         | Syslog, arquivo, API      | OTel, Syslog, Prometheus +  |
| **Atualizações**       | Manual                    | Automáticas via painel      |
| **Multi-plataforma**   | Linux, Windows            | Linux, Windows, macOS, K8s  |

**Instalação do Bindplane OP Agent (Linux):**

```bash
# Instalar via script de bootstrap
curl -fsS https://storage.googleapis.com/bindplane-op-releases/bindplane-agent/latest/install.sh | bash

# Ou via pacote DEB (Ubuntu/Debian)
curl -O https://storage.googleapis.com/bindplane-op-releases/bindplane-agent/latest/bindplane-agent_linux_amd64.deb
sudo dpkg -i bindplane-agent_linux_amd64.deb

# Configurar com o token do seu tenant Google SecOps
sudo /usr/bin/bindplane-agent configure \
  --endpoint=malachiteingestion-pa.googleapis.com:443 \
  --secret-key=/etc/bindplane/credentials.json
```

---

### 2.3 Parsers Nativos vs. CBN (Configuration-Based Normalization)

Todo banco brasileiro tem sistemas legados que não constam na lista de parsers nativos do
Google SecOps. O Tópus Banking, utilizado pelo Banco Meridian como sistema de core banking,
é um exemplo clássico: seus logs são exportados em formato CSV proprietário, com campos em
português e uma estrutura que nenhum parser nativo reconhece. Sem um parser CBN, esses logs
chegam ao Google SecOps como texto bruto — visíveis, mas completamente inutilizáveis para
detecção, correlação e hunting. Se um operador do Tópus tiver suas credenciais comprometidas,
o SOC simplesmente não verá esse evento nos alertas.

Criar parsers CBN é, portanto, uma das habilidades mais estratégicas do Engenheiro de Detecção
em ambientes bancários. É o que garante que o SIEM tenha visibilidade completa do ambiente —
não apenas das fontes "fáceis" (Windows, Palo Alto, CrowdStrike), mas também das fontes
proprietárias onde muitas vezes o ataque se manifesta.

Quando um log chega ao Google SecOps, ele precisa ser **normalizado** para o UDM. Existem
dois mecanismos para isso:

#### 2.3.1 Parsers Nativos

São parsers **pré-construídos pela Google** que suportam centenas de tecnologias de mercado.
O Google mantém, atualiza e melhora esses parsers automaticamente.

**Tipos de log com parser nativo:**

| Categoria                | Exemplos de Tecnologias Suportadas                               |
|:-------------------------|:-----------------------------------------------------------------|
| **Windows Events**       | Security, System, Application, PowerShell, Sysmon               |
| **Syslog genérico**      | rsyslog, syslog-ng, qualquer appliance que exporte Syslog       |
| **CEF (ArcSight)**       | Qualquer produto que suporte o Common Event Format               |
| **LEEF (IBM)**           | QRadar, produtos IBM que suportam Log Event Extended Format      |
| **JSON genérico**        | Qualquer fonte que exporte JSON estruturado                      |
| **Firewall (NGFWs)**     | Palo Alto, Fortinet FortiGate, CheckPoint, Cisco ASA/FTD        |
| **Cloud (GCP)**          | Cloud Audit, VPC Flow, DNS, HTTP LB, Cloud Armor, SCC           |
| **Cloud (AWS)**          | CloudTrail, VPC Flow Logs, GuardDuty, Security Hub              |
| **Cloud (Azure)**        | Activity Logs, Azure AD, Defender, Sentinel                     |
| **Identity (IAM)**       | Okta, Azure AD, Google Workspace, CyberArk, Duo Security        |
| **EDR**                  | CrowdStrike, SentinelOne, Microsoft Defender for Endpoint       |
| **Email/Proxy**          | Proofpoint, Mimecast, Bluecoat, Zscaler, Cisco Umbrella         |

#### 2.3.2 Parsers CBN (Configuration-Based Normalization)

Quando nenhum parser nativo cobre sua fonte de log, você cria um **parser CBN** — um arquivo
YAML que define como mapear os campos do log bruto para o UDM.

**Quando criar um parser CBN:**
- Sistemas proprietários internos (ERP, core banking, sistemas legados)
- Logs em formatos customizados (CSV, texto fixo, XML proprietário)
- Fontes de log de fornecedores regionais/nicho não cobertos pelos parsers nativos
- Versões muito antigas de software que usam formatos de log não-padronizados

**Estrutura básica de um parser CBN:**

```yaml
# parser-topus-banking.yaml
# Parser CBN para o sistema core banking Tópus (fictício — Banco Meridian)

meta:
  name: TOPUS_BANKING
  display_name: "Tópus Banking Core System"
  description: "Parser para logs do sistema de core banking Tópus"
  version: 1.0
  author: "Time SOC - Banco Meridian"
  log_type: TOPUS_BANKING

filter:
  # Validar que o log tem o formato esperado
  - check_field:
      field: raw_log
      regex: '^[0-9]{4}-[0-9]{2}-[0-9]{2}'

extraction:
  # Extrair campos usando regex
  - regex:
      source: raw_log
      pattern: '^(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\|(?P<event_code>[A-Z0-9_]+)\|(?P<user_id>[^\|]+)\|(?P<source_ip>[0-9\.]+)\|(?P<action>[^\|]+)\|(?P<details>.+)$'

mapping:
  # Mapear campos extraídos para o UDM
  metadata.event_timestamp: timestamp
  metadata.event_type:
    condition:
      - if: "event_code == 'LOGIN_SUCCESS'"
        then: USER_LOGIN
      - if: "event_code == 'LOGIN_FAILURE'"
        then: USER_LOGIN
      - if: "event_code == 'TXN_TRANSFER'"
        then: NETWORK_CONNECTION
      - else: GENERIC_EVENT
  metadata.product_name: "Tópus Banking"
  metadata.vendor_name: "Tópus Tecnologia"
  metadata.log_type: TOPUS_BANKING
  principal.user.userid: user_id
  principal.ip: source_ip
  security_result.action:
    condition:
      - if: "action == 'ALLOW'"
        then: ALLOW
      - if: "action == 'DENY'"
        then: BLOCK
      - else: UNKNOWN_ACTION
  security_result.description: details
```

---

### 2.4 Unified Data Model (UDM): Estrutura Completa

O UDM é o schema central do Google SecOps. Todos os eventos, independentemente da fonte,
são normalizados para este modelo antes do armazenamento. Compreender o UDM é fundamental
para escrever queries e regras eficazes.

Pense no UDM como uma "língua franca" do SOC. Quando Mariana (analista L2 do Banco Meridian)
escreve uma query UDM Search, ela não precisa saber se o campo de usuário em um evento do
Windows se chama `SubjectUserName` ou `TargetUserName`, nem se no Palo Alto o IP de origem
está em `src` ou `srcip`. O UDM já traduziu tudo para `principal.user.userid` e `principal.ip`.
Isso é o que torna possível investigar um incidente que atravessa quatro fontes de log diferentes
em uma única sessão de hunting.

Os seis namespaces a seguir são os pilares do UDM. Todo evento UDM é composto por subconjuntos
desses namespaces — um evento de login usará `metadata`, `principal` e `target`; um evento de
conexão de rede usará `metadata`, `principal`, `target` e `network`. Aprender a localizar a
informação certa no namespace correto é a habilidade mais prática do analista que usa UDM Search.

```
ESTRUTURA DO UDM — VISÃO HIERÁRQUICA
═══════════════════════════════════════════════════════════════════

  UDM_EVENT
  │
  ├── metadata          (metadados do evento)
  │   ├── event_timestamp
  │   ├── event_type         (USER_LOGIN, FILE_ACCESS, NETWORK_CONNECTION, ...)
  │   ├── product_name       (Microsoft-Windows-Security-Auditing, CrowdStrike, ...)
  │   ├── vendor_name        (Microsoft, CrowdStrike, Palo Alto, ...)
  │   ├── log_type           (WINDOWS_EVENT, PAN_FIREWALL, CROWDSTRIKE_EDR, ...)
  │   ├── product_event_type (Event ID original: 4625, 4688, etc.)
  │   └── ingestion_labels   (rótulos de ingestão customizados)
  │
  ├── principal          (entidade que ORIGINOU a ação)
  │   ├── hostname           (nome do host)
  │   ├── ip                 (lista de IPs)
  │   ├── mac                (endereço MAC)
  │   ├── user
  │   │   ├── userid         (nome de usuário)
  │   │   ├── email_addresses(lista de e-mails)
  │   │   ├── user_display_name
  │   │   └── department
  │   ├── process
  │   │   ├── pid
  │   │   ├── file.full_path (caminho do executável)
  │   │   └── command_line
  │   └── asset_id           (identificador único do ativo)
  │
  ├── target             (entidade que SOFREU a ação)
  │   ├── hostname
  │   ├── ip
  │   ├── url                (URL acessada)
  │   ├── user (mesmo schema do principal.user)
  │   ├── file
  │   │   ├── full_path
  │   │   ├── sha256
  │   │   ├── md5
  │   │   └── size
  │   └── process (mesmo schema do principal.process)
  │
  ├── network            (detalhes de rede)
  │   ├── application_protocol (HTTP, DNS, KERBEROS, SMB, RDP, ...)
  │   ├── ip_protocol        (TCP, UDP, ICMP)
  │   ├── direction          (INBOUND, OUTBOUND, BROADCAST)
  │   ├── sent_bytes
  │   ├── received_bytes
  │   ├── session_id
  │   └── http
  │       ├── method         (GET, POST, PUT, DELETE, ...)
  │       ├── response_code  (200, 404, 500, ...)
  │       └── user_agent
  │
  ├── security_result    (resultado/julgamento de segurança)
  │   ├── action             (ALLOW, BLOCK, QUARANTINE, UNKNOWN_ACTION)
  │   ├── severity           (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)
  │   ├── severity_details   (string descritiva)
  │   ├── category           (SOFTWARE_MALICIOUS, POLICY_VIOLATION, ...)
  │   ├── category_details   (string descritiva)
  │   ├── description        (texto livre)
  │   └── threat_name        (nome da ameaça detectada)
  │
  └── extensions         (extensões de dados específicos)
      ├── auth               (dados de autenticação)
      │   ├── type           (KERBEROS, NTLM, OAUTH, SAML, ...)
      │   └── mechanism      (PASSWORD, CERTIFICATE, TOKEN, ...)
      ├── vulns              (vulnerabilidades)
      └── finding            (achados de segurança)

═══════════════════════════════════════════════════════════════════
```

#### 2.4.1 Namespace `metadata` — Detalhamento

| Campo                         | Tipo     | Obrigatório | Descrição                                          |
|:------------------------------|:--------:|:-----------:|:---------------------------------------------------|
| `metadata.event_timestamp`    | TIMESTAMP| Sim         | Data/hora do evento (RFC 3339)                     |
| `metadata.event_type`         | ENUM     | Sim         | Tipo de evento (ver tabela 2.4.3)                  |
| `metadata.product_name`       | STRING   | Recomendado | Nome do produto que gerou o log                    |
| `metadata.vendor_name`        | STRING   | Recomendado | Nome do fabricante do produto                      |
| `metadata.log_type`           | STRING   | Sim         | Identificador do tipo de log no Google SecOps      |
| `metadata.product_event_type` | STRING   | Opcional    | ID original do evento no produto (Event ID, etc.)  |
| `metadata.product_version`    | STRING   | Opcional    | Versão do produto que gerou o log                  |
| `metadata.ingested_timestamp` | TIMESTAMP| Automático  | Quando o log foi ingerido pelo Google SecOps       |
| `metadata.description`        | STRING   | Opcional    | Descrição livre do evento                          |

#### 2.4.2 Namespaces `principal` e `target` — Detalhamento

O `principal` é **quem faz** a ação; o `target` é **quem sofre** a ação. Ambos têm estrutura
idêntica com os sub-namespaces abaixo:

| Sub-namespace             | Campo exemplo                   | Descrição                                  |
|:--------------------------|:--------------------------------|:-------------------------------------------|
| `*.hostname`              | `SRV-DC-001`                   | Nome do host (FQDN ou hostname simples)    |
| `*.ip`                    | `["10.0.1.10", "172.16.1.5"]` | Lista de endereços IP (suporta múltiplos)  |
| `*.mac`                   | `["00:1A:2B:3C:4D:5E"]`        | Endereço MAC (lista)                       |
| `*.user.userid`           | `joao.silva`                    | Login do usuário                           |
| `*.user.email_addresses`  | `["joao@bancomeridian.com.br"]`| E-mail(s) do usuário (lista)               |
| `*.user.user_display_name`| `João Silva`                    | Nome completo do usuário                   |
| `*.process.pid`           | `1234`                          | PID do processo                            |
| `*.process.file.full_path`| `C:\Windows\System32\cmd.exe`  | Caminho completo do executável             |
| `*.process.command_line`  | `cmd.exe /c whoami`             | Linha de comando completa                  |
| `*.file.full_path`        | `/etc/passwd`                   | Caminho completo do arquivo acessado       |
| `*.file.sha256`           | `a1b2c3...`                     | Hash SHA-256 do arquivo                    |
| `*.url`                   | `https://malicious.ru/payload` | URL acessada ou destino de conexão          |
| `*.asset_id`              | `cs:device-abc123`              | ID único do ativo (ex: CrowdStrike)        |

#### 2.4.3 Os 20 Tipos de Evento UDM Mais Comuns

| #  | event_type                 | Descrição                                              | Fonte típica                              |
|:--:|:---------------------------|:-------------------------------------------------------|:------------------------------------------|
| 1  | `USER_LOGIN`               | Tentativa de autenticação (sucesso ou falha)           | AD, Azure AD, Okta, SSO                   |
| 2  | `USER_LOGOUT`              | Fim de sessão autenticada                              | AD, Azure AD, aplicações                  |
| 3  | `USER_CREATION`            | Criação de nova conta de usuário                       | AD, Azure AD, IAM cloud                   |
| 4  | `USER_DELETION`            | Exclusão de conta de usuário                           | AD, Azure AD, IAM cloud                   |
| 5  | `USER_CHANGE_PERMISSIONS`  | Mudança de permissões ou papéis de usuário             | AD, Azure AD, IAM cloud                   |
| 6  | `FILE_CREATION`            | Arquivo criado no filesystem                           | EDR (Sysmon, CrowdStrike, Defender)       |
| 7  | `FILE_DELETION`            | Arquivo excluído do filesystem                         | EDR                                       |
| 8  | `FILE_MODIFICATION`        | Arquivo modificado no filesystem                       | EDR                                       |
| 9  | `FILE_READ`                | Arquivo lido (acesso)                                  | EDR, CASB, DLP                            |
| 10 | `PROCESS_LAUNCH`           | Processo iniciado                                      | EDR (Sysmon Event ID 1, CrowdStrike)      |
| 11 | `PROCESS_TERMINATION`      | Processo encerrado                                     | EDR                                       |
| 12 | `PROCESS_INJECTION`        | Injeção de código em processo                         | EDR (detecção comportamental)             |
| 13 | `NETWORK_CONNECTION`       | Conexão de rede estabelecida                           | Firewall, EDR, VPC Flow Logs              |
| 14 | `NETWORK_HTTP`             | Requisição HTTP/HTTPS                                  | Proxy, WAF, CDN, Web ALB                  |
| 15 | `DNS_QUERY`                | Consulta DNS enviada                                   | DNS server, EDR, VPC DNS                  |
| 16 | `EMAIL_TRANSACTION`        | E-mail enviado ou recebido                             | Exchange, Gmail, Proofpoint, Mimecast     |
| 17 | `REGISTRY_CREATION`        | Chave de registro criada (Windows)                     | EDR (Sysmon Event ID 12)                  |
| 18 | `REGISTRY_MODIFICATION`    | Chave de registro modificada (Windows)                 | EDR (Sysmon Event ID 13)                  |
| 19 | `RESOURCE_CREATION`        | Recurso criado em cloud (VM, bucket, regra de firewall)| GCP Audit, CloudTrail, Azure Activity    |
| 20 | `RESOURCE_DELETION`        | Recurso excluído em cloud                              | GCP Audit, CloudTrail, Azure Activity    |

---

### 2.5 Mapeamento de Campos Proprietários para o UDM

Um dos exercícios mais frequentes no dia a dia de operações é mapear campos de logs
proprietários para o UDM. Veja exemplos práticos:

#### 2.5.1 Windows Security Event ID 4625 (Login com falha)

| Campo Windows Event          | Campo UDM                                  | Valor exemplo                      |
|:-----------------------------|:-------------------------------------------|:-----------------------------------|
| `EventID`                    | `metadata.product_event_type`              | `4625`                             |
| `TimeCreated`                | `metadata.event_timestamp`                 | `2026-04-24T14:30:00Z`             |
| (fixo)                       | `metadata.event_type`                      | `USER_LOGIN`                       |
| (fixo)                       | `metadata.product_name`                    | `Microsoft-Windows-Security-Auditing` |
| `SubjectUserName`            | `principal.user.userid`                    | `SYSTEM`                           |
| `TargetUserName`             | `target.user.userid`                       | `joao.silva`                       |
| `IpAddress`                  | `principal.ip`                             | `203.45.12.89`                     |
| `WorkstationName`            | `principal.hostname`                       | `WRK-JOAO-001`                     |
| (fixo)                       | `security_result.action`                   | `BLOCK`                            |
| `FailureReason`              | `security_result.category_details`         | `Unknown user name or bad password`|
| `LogonType`                  | `extensions.auth.mechanism`                | (mapeado por lookup table)         |

#### 2.5.2 Palo Alto PAN-OS (regra de firewall bloqueada)

| Campo PAN-OS                 | Campo UDM                                  | Valor exemplo                      |
|:-----------------------------|:-------------------------------------------|:-----------------------------------|
| `receive_time`               | `metadata.event_timestamp`                 | `2026-04-24T14:31:00Z`             |
| (fixo)                       | `metadata.event_type`                      | `NETWORK_CONNECTION`               |
| `src`                        | `principal.ip`                             | `192.168.10.45`                    |
| `dst`                        | `target.ip`                                | `185.220.101.33`                   |
| `sport`                      | `principal.port`                           | `54321`                            |
| `dport`                      | `target.port`                              | `443`                              |
| `proto`                      | `network.ip_protocol`                      | `TCP`                              |
| `action`                     | `security_result.action`                   | `BLOCK`                            |
| `rule`                       | `security_result.rule_name`                | `DENY-OUTBOUND-TOR`                |
| `bytes_sent`                 | `network.sent_bytes`                       | `1024`                             |
| `bytes_received`             | `network.received_bytes`                   | `0`                                |

---

### 2.6 Tipos de Log Suportados Nativamente

O Google SecOps possui parsers nativos para mais de 800 tipos de log. Os mais relevantes
para ambientes financeiros (como o Banco Meridian) incluem:

| Categoria            | Log Type (ID no SecOps)          | Fabricante / Produto                   |
|:---------------------|:---------------------------------|:---------------------------------------|
| **Endpoint**         | `WINDOWS_EVENT`                  | Microsoft Windows (Security, System)   |
| **Endpoint**         | `MICROSOFT_SYSMON`               | Sysinternals Sysmon                    |
| **Endpoint**         | `CROWDSTRIKE_EDR`                | CrowdStrike Falcon                     |
| **Endpoint**         | `MICROSOFT_DEFENDER_ENDPOINT`    | Microsoft Defender for Endpoint        |
| **Identity**         | `AZURE_AD`                       | Microsoft Entra ID (Azure AD)          |
| **Identity**         | `OKTA`                           | Okta Identity Platform                 |
| **Identity**         | `GOOGLE_WORKSPACE`               | Google Workspace Admin                 |
| **Firewall**         | `PAN_FIREWALL`                   | Palo Alto Networks NGFW                |
| **Firewall**         | `FORTINET_FIREWALL`              | Fortinet FortiGate                     |
| **Firewall**         | `CHECKPOINT_FIREWALL`            | Check Point NGFW                       |
| **Proxy**            | `ZSCALER_INTERNET_ACCESS`        | Zscaler ZIA                            |
| **Proxy**            | `BLUECOAT_PROXY`                 | Broadcom Symantec Proxy SG             |
| **Cloud - GCP**      | `GCP_CLOUD_AUDIT`                | Google Cloud Audit Logs                |
| **Cloud - GCP**      | `GCP_VPC_FLOW`                   | GCP VPC Flow Logs                      |
| **Cloud - AWS**      | `AWS_CLOUDTRAIL`                 | AWS CloudTrail                         |
| **Cloud - AWS**      | `GUARDDUTY`                      | AWS GuardDuty                          |
| **Cloud - Azure**    | `AZURE_ACTIVITY`                 | Azure Activity Log                     |
| **Email**            | `PROOFPOINT_MAIL`                | Proofpoint Email Security              |
| **Email**            | `MICROSOFT_EXCHANGE_ADMIN`       | Microsoft Exchange / O365              |
| **DNS**              | `INFOBLOX`                       | Infoblox DNS/DHCP                      |

---

### 2.7 Validação de Ingestão via UDM Search

Após configurar uma fonte de ingestão, é fundamental validar que os logs estão chegando
e sendo normalizados corretamente. O processo de validação segue estas etapas:

#### Passo 1: Confirmar chegada dos logs brutos

```
UDM Search:
metadata.log_type = "TOPUS_BANKING"
```

Resultado esperado: eventos listados com timestamps recentes.

#### Passo 2: Verificar mapeamento dos campos principais

```
UDM Search:
metadata.log_type = "TOPUS_BANKING" AND
principal.user.userid != ""
```

Se retornar zero resultados, o campo `userid` não está sendo mapeado. Revisar o parser CBN.

#### Passo 3: Verificar diversidade de event_types

```
UDM Search:
metadata.log_type = "TOPUS_BANKING"
| group_by metadata.event_type
| order_by count() desc
```

Deve mostrar os diferentes tipos de evento presentes no log.

#### Passo 4: Buscar por campos ausentes ou com valor padrão

```
UDM Search:
metadata.log_type = "TOPUS_BANKING" AND
security_result.action = "UNKNOWN_ACTION"
```

Eventos com `UNKNOWN_ACTION` indicam que o parser não soube mapear o valor de ação do log
bruto. Revisar a seção de mapeamento do parser CBN.

#### Passo 5: Verificar a timeline de ingestão

```
UDM Search:
metadata.log_type = "TOPUS_BANKING"
| group_by metadata.ingested_timestamp.seconds
```

Verifica se a ingestão é contínua (sem gaps) e se os timestamps fazem sentido.

---

## Atividades de Fixação

### Quiz — Módulo 02

**Questão 1:** Qual é a principal vantagem do Bindplane OP Agent sobre o Chronicle Forwarder
clássico para ambientes empresariais modernos?

- [ ] a) O Bindplane OP Agent é gratuito, enquanto o Chronicle Forwarder tem custo adicional
- [ ] b) O Bindplane OP Agent oferece configuração centralizada via painel web, telemetria de saúde e suporte a 200+ integrações baseado em OpenTelemetry
- [ ] c) O Bindplane OP Agent só funciona em ambientes Windows, o que simplifica o suporte
- [ ] d) O Bindplane OP Agent elimina a necessidade de parsers CBN, normalizando tudo automaticamente

**Resposta correta:** b) — O Bindplane OP Agent moderniza a coleta de logs com gerenciamento centralizado e maior abrangência de integrações.

---

**Questão 2:** No UDM do Google SecOps, qual namespace armazena informações sobre a entidade
que SOFREU ou foi DESTINO de uma ação (como o servidor de destino de uma conexão de rede)?

- [ ] a) `principal`
- [ ] b) `metadata`
- [ ] c) `target`
- [ ] d) `security_result`

**Resposta correta:** c) — O namespace `target` representa a entidade que foi alvo ou destino da ação.

---

**Questão 3:** O Banco Meridian usa um sistema de core banking legado chamado "Tópus Banking"
que exporta logs em formato CSV proprietário. Nenhum parser nativo do Google SecOps cobre este
sistema. Qual é a abordagem correta?

- [ ] a) Não é possível ingerir logs do Tópus Banking no Google SecOps sem um conector pago
- [ ] b) Criar um parser CBN (Configuration-Based Normalization) em YAML para mapear os campos do CSV para o UDM
- [ ] c) Converter manualmente os logs CSV para formato CEF antes de ingerir
- [ ] d) Usar apenas os logs do Azure AD e ignorar os logs do Tópus Banking

**Resposta correta:** b) — Parsers CBN são exatamente a solução para logs de sistemas legados ou proprietários não cobertos pelos parsers nativos.

---

**Questão 4:** Ao validar a ingestão de uma nova fonte de log via UDM Search, você encontra
muitos eventos com `security_result.action = "UNKNOWN_ACTION"`. O que isso indica?

- [ ] a) Os logs estão chegando com timestamps incorretos
- [ ] b) O parser CBN não conseguiu mapear o valor do campo de ação do log bruto para um valor válido do UDM
- [ ] c) Os eventos são de baixa severidade e podem ser ignorados
- [ ] d) O feed de ingestão está com erro de autenticação

**Resposta correta:** b) — `UNKNOWN_ACTION` é o valor padrão do UDM quando o parser não consegue mapear o campo de ação. Indica necessidade de ajuste no parser CBN.

---

**Questão 5:** Qual das afirmações sobre feeds diretos no Google SecOps está CORRETA?

- [ ] a) Feeds diretos requerem instalação de um agente em cada sistema de destino
- [ ] b) Feeds diretos só funcionam com serviços Google Cloud (GCS, Pub/Sub)
- [ ] c) Feeds diretos permitem que o Google SecOps busque ativamente logs de fontes como S3, Azure Blob Storage e APIs REST, sem necessidade de agente
- [ ] d) Feeds diretos têm limite de 1 GB/dia e são indicados apenas para fontes de baixo volume

**Resposta correta:** c) — Feeds diretos são configurados na interface web e o Google SecOps faz o pull dos dados ativamente, suportando múltiplos provedores de nuvem e APIs REST.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **Este roteiro é para uso exclusivo do instrutor durante a gravação das videoaulas.
> Cada bloco indica o conteúdo a ser apresentado, o tempo estimado e as orientações de produção.**

---

### AULA 2.1 — Forwarders, Feeds e Bindplane OP Agent (40 min)

---

**[ABERTURA — 3 min | Tela: Slide de capa do Módulo 02]**

"Olá! Bem-vindo ao Módulo 02 — Ingestão e UDM. Eu sou [nome do instrutor], e nesta aula a
gente vai entender como os logs chegam ao Google SecOps. Porque antes de detectar qualquer
ataque, antes de escrever qualquer regra YARA-L, a gente precisa que os dados estejam lá.

E eu costumo dizer para os meus alunos: um SIEM é tão bom quanto os dados que ele recebe. Garbage
in, garbage out. Se os logs não estão chegando, ou estão chegando malformados, a sua capacidade de
detecção vai para o buraco.

Nesta aula vamos ver os quatro mecanismos principais de ingestão do Google SecOps: o Chronicle
Forwarder clássico, os Feeds Diretos, os Webhooks e o Bindplane OP Agent — que é a solução
moderna baseada em OpenTelemetry. Vamos lá!"

---

**[BLOCO 1: Visão Geral da Arquitetura de Ingestão — 8 min | Tela: Diagrama ASCII do módulo]**

"Antes de entrar nos detalhes de cada mecanismo, quero que você tenha na cabeça o fluxo completo.
Abre o material do módulo aqui no GitHub e olha o diagrama da seção 2.1 — Arquitetura de Coleta.

Você vê que temos fontes de log dos mais variados tipos: endpoints, firewalls, serviços em nuvem,
aplicações SaaS, sistemas legados. Cada um desses tem uma forma preferida de enviar seus logs.

E o Google SecOps é exatamente o ponto de convergência de tudo isso. Tudo chega, tudo é
normalizado para o UDM, e aí fica disponível para busca e detecção.

O grande poder aqui é: independente de como o log chegou — seja via Forwarder, Feed, Webhook ou
Bindplane — depois que está no UDM, a forma de buscar e criar regras é EXATAMENTE a mesma.
Um query UDM que funciona para eventos do Windows vai funcionar igualmente para eventos do Azure
AD ou do Palo Alto. Essa é a beleza do modelo normalizado."

*[Dica de edição: mostrar o diagrama ASCII em tela cheia, destacando os diferentes caminhos com animação de setas]*

---

**[BLOCO 2: Chronicle Forwarder Clássico — 8 min | Tela: Terminal Linux]**

"Vamos ao Chronicle Forwarder. Essa é a solução mais antiga, mas ainda muito usada. Você o
instala em um servidor on-premises — geralmente um servidor Linux dedicado que fica dentro
do data center do cliente — e ele recebe Syslog dos dispositivos da rede e manda para o Google SecOps.

Deixa eu mostrar a instalação ao vivo. Aqui no meu terminal Linux...

*[Executar os comandos do Passo de instalação do Forwarder]*

O ponto mais importante aqui é o arquivo de configuração YAML. Veja esta seção:
`data_type: PAN_FIREWALL` — esse campo diz para o Google SecOps qual parser nativo usar para
interpretar os logs que chegam por esta porta. Se você colocar o tipo errado, o log vai ser
ingerido mas vai ficar sem normalização adequada.

O erro mais comum que eu vejo em campo é exatamente esse: o forwarder está funcionando, os
logs chegam, mas ninguém configurou o `data_type` correto. O analista fica sem alertas e não
entende por quê."

*[Dica de edição: destaque a linha `data_type` no arquivo YAML com um highlight amarelo]*

---

**[BLOCO 3: Feeds Diretos e Webhooks — 8 min | Tela: Google SecOps Console]**

"Agora vou mostrar como configurar um Feed Direto direto no console do Google SecOps. Feeds são
para quando a fonte de log está na nuvem e você quer que o Google SecOps vá buscar os dados,
em vez de receber.

*[Navegar para Settings → Ingestion → Feeds → Add Feed]*

Vou configurar aqui um feed para o Azure AD. Seleciono 'Microsoft Azure', escolho o log type
'AZURE_AD', insiro as credenciais do Service Principal do Azure... e aqui ó: já posso definir
o intervalo de polling. Eu recomendo 5 minutos para fontes de identidade — qualquer coisa mais
longa e você perde resolução temporal na investigação.

Agora os Webhooks. São diferentes dos feeds porque o Google SecOps não vai buscar: é o sistema
externo que empurra para o Google SecOps. O use case mais comum é integrar um SIEM legado que
o cliente quer manter, mas precisa consolidar tudo no Google SecOps para análise centralizada.

O endpoint do webhook é único por tenant e tem uma API key obrigatória no header. Isso garante
que só sistemas autorizados podem enviar dados."

*[Dica de edição: use split screen: à esquerda o console do Google SecOps, à direita um esquema do fluxo de webhook]*

---

**[BLOCO 4: Bindplane OP Agent — 10 min | Tela: Bindplane Console + Terminal]**

"E chegamos ao futuro da coleta de logs no Google SecOps: o Bindplane OP Agent. Esse é o agente
moderno, baseado no OpenTelemetry — o mesmo padrão que a CNCF adotou como universal para
observabilidade.

O que muda em relação ao Forwarder clássico? Duas coisas principais.

Primeiro: configuração centralizada. No lugar de editar um YAML em cada servidor onde o agente
está instalado, você configura tudo num painel web central. Quer adicionar uma nova fonte de log?
Clica, configura, deploy. Sem SSH em servidor de produção.

Segundo: telemetria dos próprios agentes. Você consegue ver em tempo real quais agentes estão
online, quanto throughput cada um está enviando, se algum está em erro. Isso é vital em
ambientes corporativos grandes onde você tem dezenas de agentes espalhados.

*[Mostrar o painel do Bindplane]*

Aqui no painel, vejo todos os meus agentes. Este aqui, no servidor SRV-LOG-001 do Banco Meridian,
está enviando 2.340 eventos por minuto. Este outro, no servidor de filial de Manaus, entrou em
alerta — está com zero throughput, provavelmente perdeu conectividade.

Isso é o tipo de visibilidade que o Forwarder clássico simplesmente não oferecia."

*[Dica de edição: mostrar animação de painel de monitoramento de agentes com status em tempo real]*

---

**[RECAPITULAÇÃO E CHAMADA PARA A PRÓXIMA AULA — 3 min | Tela: Slide de encerramento]**

"Ótimo! Recapitulando esta aula:

Um — temos quatro mecanismos de ingestão: Forwarder (on-premises/syslog), Feeds (pull da nuvem),
Webhooks (push externo) e Bindplane OP Agent (moderno, centralizado, baseado em OpenTelemetry).

Dois — o `data_type` na configuração do Forwarder é crítico: determina qual parser nativo será
usado para normalizar os logs.

Três — o Bindplane OP Agent é o futuro da coleta no Google SecOps e deve ser a escolha
preferencial para novas implementações.

Na próxima aula, a gente vai mergulhar fundo no coração do Google SecOps: o Unified Data Model.
Vamos entender como funciona cada namespace, como mapear campos proprietários para o UDM e
como validar se sua ingestão está correta. Te vejo lá!"

---

### AULA 2.2 — UDM Deep Dive (40 min)

---

**[ABERTURA — 2 min | Tela: Slide "UDM — A Língua Universal do Google SecOps"]**

"Bem-vindo à Aula 2.2. Aqui a gente vai falar da coisa mais importante que você precisa
dominar para trabalhar com o Google SecOps: o Unified Data Model, o UDM.

Se o Módulo 02 inteiro fosse um iceberg, o UDM seria a parte submersa — invisível na superfície,
mas sustentando tudo que você vê: as buscas, as regras, os alertas, as investigações.

Vou mostrar a estrutura completa, exemplos reais de mapeamento com eventos do Windows e do
Palo Alto, e como validar se os seus logs estão sendo normalizados corretamente. Vamos lá!"

---

**[BLOCO 1: Por que o UDM existe — 6 min | Tela: Slide comparativo]**

"Imagina o problema que o Google tinha que resolver. Um SOC corporativo típico tem logs de 50,
60 fontes diferentes. Cada uma com seu próprio formato. Windows Event ID 4625 para login com
falha. Palo Alto com seus campos em CSV. Cisco ASA com syslog no formato dele. CrowdStrike com
JSON enorme com campos com nomenclatura própria.

Antes do UDM, para escrever uma regra que detectasse 'tentativas de login com falha de qualquer
fonte', você teria que escrever condições específicas para cada tipo de log. Era impossível de
manter.

O UDM resolve isso com um conceito simples: todo evento, independente da fonte, deve ser
normalizado para o mesmo schema antes de ser armazenado. Assim, uma query `security_result.action
= 'BLOCK'` vai retornar logins bloqueados do Windows, do Azure AD, do Okta, do Palo Alto —
tudo junto, mesmo query.

Isso não é só conveniência. É a diferença entre ter detecções que cobrem toda a sua superfície
de ataque versus ter detecções cegas para boa parte do ambiente."

*[Dica de edição: mostrar side-by-side: log bruto Windows vs. log bruto PAN-OS vs. o mesmo evento normalizado no UDM]*

---

**[BLOCO 2: Estrutura dos namespaces — 15 min | Tela: Material do módulo, seção 2.4]**

"Vamos agora pela estrutura. Abra o material do módulo na seção 2.4 — vou guiar você pelo
diagrama hierárquico.

Todo evento UDM tem seis namespaces principais: metadata, principal, target, network,
security_result e extensions.

*[Apontar para cada namespace no diagrama]*

O metadata é o cartão de visita do evento. Guarda QUANDO aconteceu, QUE TIPO de evento é,
QUAL PRODUTO gerou, QUAL LOG TYPE está mapeado. Todo evento precisa de metadata.

O principal é QUEM FEZ a ação. Se um usuário fez login, o principal tem o hostname da máquina,
o IP de origem, o userid do usuário. Se um processo fez uma conexão de rede, o principal tem os
dados do processo — PID, caminho do executável, linha de comando.

O target é PARA ONDE a ação foi direcionada. O servidor destino do login, o arquivo que foi
acessado, a URL que o navegador acessou, o usuário cujas permissões foram alteradas.

Network guarda os detalhes da comunicação de rede: protocolo, bytes enviados, bytes recebidos,
método HTTP, status code. Muito usado em análise de tráfego e hunting de C2.

E security_result é o JULGAMENTO de segurança: a ação foi ALLOW ou BLOCK? Qual a severidade?
Foi detectado algum malware?

Agora deixa eu mostrar um exemplo ao vivo no console. Vou pegar um evento real de login e
dissecar campo por campo..."

*[Navegar para UDM Search, clicar em um evento e mostrar o JSON do evento expandido]*

---

**[BLOCO 3: Mapeamento de campos proprietários — 12 min | Tela: Editor de parser + UDM Search]**

"Agora o exercício mais importante desta aula: mapear um log real para o UDM.

Vou usar o exemplo das tabelas da seção 2.5 do material — o Event ID 4625 do Windows, que é
o evento de login com falha.

O campo `TargetUserName` do Windows vira `target.user.userid` no UDM. Por quê target e não
principal? Porque o Windows — na sua lógica de auditoria — considera que o PRINCIPAL é o
processo System que registrou o evento. O ALVO do login é o usuário cuja senha foi tentada.

Isso parece detalhe, mas faz uma diferença enorme nas suas queries. Se você procurar
`principal.user.userid = 'joao.silva'` para logins com falha no Windows, não vai encontrar
nada. Precisa buscar `target.user.userid = 'joao.silva'`.

Agora deixa eu mostrar como isso funciona com um log do Palo Alto...

*[Abrir o material e mostrar a tabela de mapeamento PAN-OS]*

O campo `src` do PAN-OS vira `principal.ip`. O campo `dst` vira `target.ip`. O campo `action`
do PAN-OS pode ser 'allow', 'deny', 'drop' — e o parser nativo mapeia isso para os valores
ALLOW e BLOCK do UDM. Simples assim.

Para sistemas legados sem parser nativo — como o Tópus Banking do Banco Meridian — é exatamente
esse trabalho que você vai fazer no Lab 01: criar um parser CBN que defina esses mapeamentos."

*[Dica de edição: mostrar o processo de mapeamento como uma tabela que vai se preenchendo]*

---

**[RECAPITULAÇÃO FINAL E CHAMADA PARA O LAB — 5 min | Tela: Slide de encerramento]**

"Vamos recapitular o módulo inteiro agora:

Ingestão — quatro mecanismos: Forwarder, Feeds, Webhooks e Bindplane OP Agent. Cada um para
um caso de uso específico.

Parsers — nativos para 800+ tecnologias, CBN quando o nativo não existe. CBN é YAML que
define o mapeamento campo a campo.

UDM — seis namespaces: metadata (quando/o quê), principal (quem fez), target (quem sofreu),
network (como), security_result (o julgamento), extensions (dados específicos).

E validação — sempre valide sua ingestão antes de criar regras. Use UDM Search para confirmar
que os campos certos estão sendo populados.

Agora você vai ao Lab 01, onde vai criar do zero um parser CBN para o Tópus Banking — o sistema
de core banking legado do Banco Meridian. Esse é um cenário real: todo SOC que atende banco
no Brasil vai ter sistemas legados sem parser nativo. Te vejo no lab!"

*[ORIENTAÇÕES DE PRODUÇÃO:]*
- *Duração total: 80 min (2 aulas de ~40 min cada)*
- *Aula 2.1: gravar com terminal Linux real (pode ser VM local)*
- *Aula 2.2: usar tenant Google SecOps real para mostrar eventos*
- *Adicionar callouts na tela para destacar campos importantes*
- *Quiz: 5 questões configuradas no LMS, não-bloqueante, com feedback imediato*

---

## Avaliação do Módulo 02

### Questões da Avaliação

**Questão 1:** Explique a diferença entre um Feed Direto e um Webhook no Google SecOps.
Em qual situação cada um seria mais adequado? Dê um exemplo de fonte de log para cada.

**Resposta esperada:** Feed Direto é quando o Google SecOps faz o pull dos dados (adequado para
fontes que têm API de consulta, como S3, Azure Blob, APIs REST de SaaS). Webhook é quando o
sistema externo empurra os dados para o Google SecOps (adequado para sistemas que já têm
capacidade de enviar eventos por HTTP push). Exemplos: Feed → Azure AD Sign-in Logs;
Webhook → SIEM legado integrando ao Google SecOps.

**Questão 2:** No UDM do Google SecOps, um evento de `USER_LOGIN` de um Windows Domain Controller
registra o campo `TargetUserName` com o valor `joao.silva`. Em qual campo UDM esse valor
deve ser mapeado? Por que NOT `principal.user.userid`?

**Resposta esperada:** `target.user.userid`. No modelo Windows de auditoria, o `TargetUserName`
é o usuário ALVO do login (a conta sendo autenticada), não o processo/sistema que registrou
o evento. O `principal` no Windows representa o contexto do processo System que escreveu
o evento no log — não o usuário que tentou fazer login.

**Questão 3:** O que é o namespace `security_result` no UDM e quais são os dois campos
mais críticos que ele contém? Por que esses campos são importantes para regras YARA-L?

**Resposta esperada:** `security_result` armazena o julgamento de segurança sobre o evento.
Os dois campos mais críticos são: (1) `security_result.action` — indica se a ação foi
ALLOW, BLOCK, QUARANTINE etc.; (2) `security_result.severity` — nível de severidade do evento.
São críticos para YARA-L porque permitem filtrar especificamente eventos bloqueados
(`action = "BLOCK"`) ou de alta severidade (`severity = "HIGH"`) sem depender de campos
proprietários de cada fonte de log.

### Gabarito das Questões de Múltipla Escolha

| Questão | Resposta Correta | Justificativa                                                                           |
|:-------:|:----------------:|:----------------------------------------------------------------------------------------|
|    1    |       b)         | Bindplane OP Agent: configuração centralizada, OpenTelemetry, 200+ integrações          |
|    2    |       c)         | `target` representa a entidade que sofreu/foi destino da ação                           |
|    3    |       b)         | Parsers CBN resolvem o problema de sistemas legados sem parser nativo                   |
|    4    |       b)         | `UNKNOWN_ACTION` indica falha no mapeamento do campo de ação no parser CBN              |
|    5    |       c)         | Feeds fazem pull ativo, suportam múltiplos provedores, sem necessidade de agente        |

### Critérios de Avaliação

| Pontuação | Resultado                                                                        |
|:---------:|:---------------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 03 — YARA-L                                   |
| 4/5 (80%) | Muito bom! Revise o tópico correspondente à questão errada antes de avançar     |
| 3/5 (60%) | Recomendado rever as seções 2.3 e 2.4 antes de avançar                          |
| < 3 (< 60%)| Revisite todo o módulo — compreender o UDM é pré-requisito absoluto para YARA-L|

---

*Módulo 02 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 01 — Fundamentos](../modulo-01-fundamentos/README.md)*
*Próximo: [Módulo 03 — YARA-L 2.0](../modulo-03-yara-l-detection/README.md)*
