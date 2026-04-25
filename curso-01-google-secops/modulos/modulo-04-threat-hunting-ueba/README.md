# Módulo 04 — Threat Hunting e UEBA
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 2h videoaulas + 2h laboratório + 1h live online                     |
| **Pré-requisito**  | Módulo 03 concluído · Regras YARA-L básicas funcionais              |
| **MITRE ATT&CK**   | T1071.001, T1021, T1558, T1069, T1046                               |
| **Ferramentas**    | Google SecOps UDM Search, Risk Analytics, UEBA, Timeline View       |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Aplicar as três metodologias de threat hunting (hipótese-driven, indicator-driven e situational)
2. Usar operadores avançados de UDM Search para agregação e pivoting por entidade
3. Construir a timeline de um incidente usando o Timeline View do Google SecOps
4. Interpretar o Risk Score e os sinais do UEBA para priorizar investigações
5. Executar o ciclo completo de threat hunting: hipótese → busca → validação → documentação → detecção

---

## Conteúdo do Módulo

### 4.1 Metodologia de Threat Hunting

Threat hunting não é esperar alertas dispararem. É uma atividade **proativa** de busca por
ameaças que ainda não foram detectadas pelos controles automatizados. Existem três abordagens:

```
METODOLOGIAS DE THREAT HUNTING
════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  1. HIPÓTESE-DRIVEN (Hypothesis-Driven)                      │
  │                                                              │
  │  Ponto de partida: "E se...?"                                │
  │  Exemplo: "E se um atacante comprometeu credenciais via      │
  │  phishing e está se movendo lateralmente na rede?"           │
  │                                                              │
  │  Fontes de hipóteses:                                        │
  │  • MITRE ATT&CK — técnicas relevantes para o setor          │
  │  • Threat Intelligence — relatórios de APTs que atacam bancos│
  │  • Red Team reports — técnicas observadas em exercícios      │
  │  • Purple Team exercises — gaps identificados em detecções   │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │  2. INDICATOR-DRIVEN (Indicator-Based)                       │
  │                                                              │
  │  Ponto de partida: um IOC conhecido (IP, hash, domínio)      │
  │  Exemplo: "O relatório Mandiant cita o IOC 185.220.101.33.   │
  │  Alguém no nosso ambiente se conectou a esse IP?"            │
  │                                                              │
  │  Fontes de indicadores:                                      │
  │  • Mandiant Threat Intelligence (integrado ao SecOps)        │
  │  • VirusTotal Enterprise                                     │
  │  • MISP (plataforma open-source de TI)                       │
  │  • Relatórios de CERT.br, FEBRABAN, FS-ISAC                  │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │  3. SITUATIONAL (Situation-Aware)                            │
  │                                                              │
  │  Ponto de partida: contexto externo ou interno               │
  │  Exemplo: "Identificamos um funcionário demissionário com    │
  │  acesso privilegiado. Vamos verificar atividade anômala."    │
  │                                                              │
  │  Gatilhos típicos:                                           │
  │  • Funcionário em processo de demissão                       │
  │  • Vulnerabilidade crítica publicada (0-day)                 │
  │  • Incidente em concorrente/empresa do setor                 │
  │  • Mudança de configuração crítica não planejada             │
  └─────────────────────────────────────────────────────────────┘

════════════════════════════════════════════════════════════════════
```

#### 4.1.1 O Ciclo do Threat Hunter

```
CICLO COMPLETO DO THREAT HUNTING
════════════════════════════════════════════════════════════════════

      ┌──────────────────────────────────┐
      │                                  │
      ▼                                  │
  ┌───────────┐                         │
  │ 1. CRIAR  │  Formular hipótese       │
  │ HIPÓTESE  │  baseada em TI, MITRE,   │
  │           │  contexto situacional    │
  └─────┬─────┘                         │
        │                               │
        ▼                               │
  ┌───────────┐                         │
  │ 2. BUSCAR │  Executar queries UDM,  │
  │           │  analisar UEBA, Risk     │
  │           │  Score, anomalias        │
  └─────┬─────┘                         │
        │                               │
        ▼                               │
  ┌───────────┐    ┌────────────────┐   │
  │ 3. VALIDAR│    │ Falso positivo │   │
  │           │───►│ → documentar   │───┘
  │           │    │ → descartar    │
  └─────┬─────┘    └────────────────┘
        │
        │ Ameaça confirmada
        ▼
  ┌───────────┐
  │4. DOCUMEN-│  Criar relatório de    │
  │   TAR     │  incidente, timeline,  │
  │           │  IOCs extraídos        │
  └─────┬─────┘
        │
        ▼
  ┌───────────┐
  │5. DETECTAR│  Criar regra YARA-L    │
  │           │  para detectar o       │
  │           │  padrão encontrado     │
  └───────────┘

════════════════════════════════════════════════════════════════════
```

---

### 4.2 UDM Search: Sintaxe Avançada

O UDM Search é a ferramenta principal de threat hunting no Google SecOps. Dominar sua
sintaxe avançada é essencial para investigações eficazes.

#### 4.2.1 Operadores Básicos

| Operador | Exemplo                                              | Descrição                                  |
|:---------|:-----------------------------------------------------|:-------------------------------------------|
| `=`      | `metadata.event_type = "USER_LOGIN"`                 | Igualdade exata                            |
| `!=`     | `security_result.action != "ALLOW"`                  | Diferente de                               |
| `>`      | `network.sent_bytes > 1073741824`                    | Maior que                                  |
| `<`      | `network.sent_bytes < 1024`                          | Menor que                                  |
| `=`      | `target.hostname = /.*-DC-.*/`                       | Regex (usar barra //)                      |
| `AND`    | `event_type = "USER_LOGIN" AND action = "BLOCK"`     | Ambas as condições                         |
| `OR`     | `target.port = 445 OR target.port = 3389`            | Qualquer uma das condições                 |
| `NOT`    | `NOT principal.ip = "10.0.0.0/8"`                    | Negação                                    |

#### 4.2.2 Operadores de Período

```
// Período relativo (recomendado para hunting diário)
Seletor de período: "Last 24 hours", "Last 7 days", "Last 30 days"

// Período absoluto (para investigações com timestamp conhecido)
metadata.event_timestamp >= "2026-04-20T00:00:00Z"
AND metadata.event_timestamp <= "2026-04-24T23:59:59Z"
```

#### 4.2.3 Operadores de Agregação

```
// Agrupar eventos por campo e contar
metadata.event_type = "USER_LOGIN"
| group_by principal.user.userid
| order_by count() desc
| head 20

// Calcular soma de bytes por IP destino
metadata.event_type = "NETWORK_CONNECTION"
| group_by target.ip
| aggregate sum(network.sent_bytes) as total_bytes
| order_by total_bytes desc
| head 10

// Contar eventos únicos por campo
metadata.event_type = "DNS_QUERY"
| group_by principal.hostname
| aggregate count(distinct target.hostname) as dominios_consultados
| where dominios_consultados > 100
| order_by dominios_consultados desc
```

#### 4.2.4 Pivoting por Entidade

O pivoting é uma das técnicas mais poderosas de hunting: começar de um dado (IP, usuário,
hostname) e expandir a investigação para entidades relacionadas.

```
FLUXO DE PIVOTING:
─────────────────────────────────────────────────────────────────
IP SUSPEITO → USUÁRIOS → PROCESSOS → ARTEFATOS → TIMELINE
─────────────────────────────────────────────────────────────────

Passo 1: IP suspeito → Quais usuários se conectaram deste IP?
──────────────────────────────────────────────────────────────
principal.ip = "185.220.101.33"
| group_by target.user.userid
| order_by count() desc

Passo 2: Usuário comprometido → Em quais hosts ele acessou?
──────────────────────────────────────────────────────────────
principal.user.userid = "diana.ferreira"
AND metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
| group_by target.hostname
| order_by count() desc

Passo 3: Host comprometido → Quais processos foram lançados?
──────────────────────────────────────────────────────────────
principal.hostname = "WRK-DIANA-007"
AND metadata.event_type = "PROCESS_LAUNCH"
AND NOT principal.process.file.full_path = /.*\\Windows\\.*/
| group_by principal.process.file.full_path
| order_by count() desc

Passo 4: Processo suspeito → Quais conexões de rede ele fez?
──────────────────────────────────────────────────────────────
principal.hostname = "WRK-DIANA-007"
AND metadata.event_type = "NETWORK_CONNECTION"
AND principal.process.file.full_path = /.*rundll32\.exe$/
| group_by target.ip, target.port
| order_by count() desc

Passo 5: IP de destino → Outros hosts do ambiente também se conectaram?
──────────────────────────────────────────────────────────────────────────
target.ip = "91.234.55.172"
AND metadata.event_type = "NETWORK_CONNECTION"
| group_by principal.hostname
| order_by count() desc
─────────────────────────────────────────────────────────────────
```

---

### 4.3 Timeline View: Construção de Linha do Tempo de Incidente

O Timeline View do Google SecOps permite visualizar todos os eventos relacionados a uma
entidade (usuário, host, processo, IP) em ordem cronológica. É fundamental para reconstruir
a sequência de ações durante um incidente.

#### 4.3.1 Como Acessar o Timeline View

```
Opção 1: Via Entity Search
  Settings → Entities → buscar por hostname, IP ou userid
  Clicar no resultado → aba "Timeline"

Opção 2: Via UDM Search (pivot)
  Executar uma query → clicar em um valor de campo na tabela de resultados
  Menu de contexto → "View entity timeline"

Opção 3: Via Cases (alertas)
  Cases → abrir um case → aba "Timeline" no contexto do case
```

#### 4.3.2 Exemplo de Timeline de Incidente (Banco Meridian)

A tabela a seguir ilustra a timeline do ataque de password spray que resultou no
comprometimento da conta de `diana.ferreira`:

| Timestamp (BRT)     | Evento                                         | Técnica MITRE     | Fonte de Log       |
|:--------------------|:-----------------------------------------------|:-----------------:|:-------------------|
| 09:02:14 24-Apr     | 1ª tentativa de login falhada (diana.ferreira)  | T1110.003         | WINDOWS_EVENT      |
| 09:02:14 → 09:25:07 | 46 tentativas de login falhadas (31 usuários)  | T1110.003         | WINDOWS_EVENT      |
| 09:03:05 24-Apr     | Login BEM-SUCEDIDO (diana.ferreira)            | T1078             | AZURE_AD           |
| 09:05:22 24-Apr     | Enumeração de grupos do AD (diana.ferreira)    | T1069.002         | WINDOWS_EVENT      |
| 09:07:41 24-Apr     | Acesso ao SharePoint RH (arquivos de folha)    | T1039             | AZURE_AD / M365    |
| 09:12:03 24-Apr     | Download de 47 arquivos .xlsx do SharePoint    | T1567.002         | M365 AUDIT         |
| 09:15:30 24-Apr     | Conexão RDP para SRV-FILESERVER-01             | T1021.001         | WINDOWS_EVENT      |
| 09:18:55 24-Apr     | Criação de script PowerShell em WRK-DIANA-007  | T1059.001         | SYSMON             |
| 09:23:14 24-Apr     | Conexão de saída para 91.234.55.172 (Moldova)  | T1071.001         | PAN_FIREWALL       |

---

### 4.4 Risk Analytics: Cálculo de Score e Thresholds

O **Risk Analytics** do Google SecOps atribui um **Risk Score** (0–100) a cada entidade
(usuário, host) com base nos alertas e anomalias detectados. Quanto maior o score, maior
a suspeita de comprometimento.

#### 4.4.1 Como o Risk Score é Calculado

```
FATORES QUE INFLUENCIAM O RISK SCORE:
════════════════════════════════════════════════════════════════════

  Base Score (acumulativa):
  ├── +50 pts: Alerta CRITICAL ativo associado à entidade
  ├── +30 pts: Alerta HIGH ativo
  ├── +15 pts: Alerta MEDIUM ativo
  ├── +5 pts:  Alerta LOW ativo
  │
  Multiplicadores de contexto:
  ├── x1.5: Entidade é usuário privilegiado (admin, domain admin)
  ├── x1.3: Entidade acessou dados sensíveis recentemente
  ├── x1.2: Anomalia de geolocalização (IP de país diferente do habitual)
  │
  Decaimento temporal:
  └── Score decai 20% por dia sem novos alertas (evitar scores "fossilizados")

  Score final = min(100, base_score × multiplicadores)

════════════════════════════════════════════════════════════════════
```

#### 4.4.2 Thresholds de Priorização

| Risk Score | Categoria    | Ação recomendada                                           |
|:----------:|:------------:|:-----------------------------------------------------------|
| 90 – 100   | CRITICAL     | Resposta imediata: escalar para IR team, containment       |
| 70 – 89    | HIGH         | Investigar em até 30 minutos, triagem prioritária          |
| 40 – 69    | MEDIUM       | Investigar durante o turno, análise de contexto            |
| 10 – 39    | LOW          | Monitorar, verificar se há correlação com outros sinais    |
| 0 – 9      | INFORMATIONAL| Manter no radar, revisar periodicamente                    |

#### 4.4.3 Onde Ver o Risk Score no Console

```
Navegação:
Detection → Risk Analytics → Risky Users/Hosts

Filtros disponíveis:
- Ordenar por Risk Score (maior primeiro)
- Filtrar por score mínimo (ex: > 60)
- Filtrar por período de tempo
- Filtrar por entidade tipo (user vs. host)
```

---

### 4.5 UEBA: Behavioral Analytics e Anomaly Detection

O **UEBA** (User and Entity Behavior Analytics) do Google SecOps cria um **baseline de
comportamento** para cada usuário e dispositivo, usando modelos de machine learning.
Desvios significativos da baseline geram sinais de anomalia.

#### 4.5.1 Como o UEBA Aprende o Baseline

```
PROCESSO DE APRENDIZADO DO UEBA:
═══════════════════════════════════════════════════════════════════

  Semanas 1–4: Período de aprendizado
  ─────────────────────────────────────────
  O UEBA observa e aprende os padrões de cada entidade:

  Usuário diana.ferreira:
  ├── Horários habituais: 08:30 → 18:00 (dias úteis)
  ├── Localização habitual: São Paulo (IP 177.70.x.x)
  ├── Dispositivos habituais: WRK-DIANA-007, NOTEBOOK-DIANA-002
  ├── Volume diário de dados: ~500 MB
  ├── Aplicações usadas: Outlook, SharePoint, Teams, SAP
  └── Pares de usuários (com quem colabora): carlos.souza, ana.rodrigues

  Após aprendizado: baseline estabelecido

  Semana 5+: Detecção de anomalias
  ─────────────────────────────────────────
  Evento: diana.ferreira acessa de IP 185.220.101.33 (Alemanha)
  Comparação com baseline: MUITO diferente (IP habitual = Brasil)
  Resultado: anomalia de geolocalização → +30 pts ao Risk Score

═══════════════════════════════════════════════════════════════════
```

#### 4.5.2 Modelos de ML Usados no UEBA

| Modelo                        | O que detecta                                                    |
|:------------------------------|:-----------------------------------------------------------------|
| **Peer Group Analysis**       | Comportamento anômalo em relação ao grupo (departamento/função)  |
| **Temporal Anomaly Detection**| Ações em horários incomuns para aquele usuário                   |
| **Volume Anomaly Detection**  | Acesso a volume incomum de dados (exfiltração)                   |
| **Geographic Anomaly**        | Login de localização geograficamente impossível                  |
| **Lateral Movement Detection**| Acesso a sistemas que o usuário nunca acessou antes              |
| **Privileged Account Usage**  | Uso de conta privilegiada em contextos incomuns                  |

#### 4.5.3 Context-Aware Analytics: Correlação de Sinais Fracos

Individualmente, muitos eventos do UEBA são ambíguos. O Context-Aware Analytics correlaciona
múltiplos sinais fracos para construir um caso mais sólido:

```
EXEMPLO: Context-Aware Analytics em ação
═══════════════════════════════════════════════════════════════════

Sinal 1 (sozinho: LOW):  João se conectou às 22h — pode ser trabalho urgente
Sinal 2 (sozinho: LOW):  João baixou 2 GB de arquivos — talvez trabalho legítimo
Sinal 3 (sozinho: LOW):  João acessou servidores que nunca acessou antes

JUNTOS (HIGH):
  João se conectou às 22h +
  João baixou 2 GB +
  João acessou servidores novos +
  João está em processo de demissão (contexto HR)
  ────────────────────────────────────────────────
  Risk Score: 85 → Alerta HIGH gerado automaticamente

═══════════════════════════════════════════════════════════════════
```

---

### 4.6 Hunting de C2 Beaconing

O hunting de C2 beaconing é um dos casos de uso mais comuns e mais relevantes para bancos.
O framework completo é desenvolvido no Lab 03, mas aqui apresentamos o conceito analítico.

#### 4.6.1 Análise Estatística de Beaconing

C2 beaconing tem características estatísticas distintivas:

| Métrica                    | C2 Beaconing (típico)   | Tráfego legítimo (típico)       |
|:---------------------------|:-----------------------:|:--------------------------------|
| **Número de conexões/hora**| 20–120                  | 1–5 para o mesmo destino        |
| **Variação de intervalo**  | Baixa (< 10% do média)  | Alta (comportamento humano)     |
| **Tamanho do pacote**      | Consistente (fixo)      | Variável                        |
| **Horário**                | 24x7 (inclusive madrugada)| Alinhado ao horário de trabalho|
| **Processo originador**    | Incomum (svchost, notepad)| Browser, Office, Teams         |
| **TLD do destino**         | .ru, .cn, .top, .xyz    | .com, .net, .com.br             |

#### 4.6.2 Queries UDM para Hunting de Beaconing

```
Query 1: Identificar hosts com alto volume de conexões ao mesmo destino externo
─────────────────────────────────────────────────────────────────────────────────
metadata.event_type = "NETWORK_CONNECTION"
AND network.direction = "OUTBOUND"
AND NOT target.ip = "10.0.0.0/8"
AND NOT target.ip = "172.16.0.0/12"
AND NOT target.ip = "192.168.0.0/16"
| group_by principal.hostname, target.ip
| aggregate count() as total_conexoes
| where total_conexoes > 50
| order_by total_conexoes desc


Query 2: Identificar processo originador das conexões suspeitas
─────────────────────────────────────────────────────────────────
principal.hostname = "WRK-RODRIGO-011"
AND metadata.event_type = "NETWORK_CONNECTION"
AND target.ip = "91.234.55.172"
| group_by principal.process.file.full_path
| order_by count() desc


Query 3: Verificar consistência dos intervalos (proxy de periodicidade)
─────────────────────────────────────────────────────────────────────────
principal.hostname = "WRK-RODRIGO-011"
AND target.ip = "91.234.55.172"
AND metadata.event_type = "NETWORK_CONNECTION"
| group_by metadata.event_timestamp.seconds
| order_by metadata.event_timestamp.seconds asc
```

---

### 4.7 Hunting de Lateral Movement via Kerberos

O Kerberos é o protocolo de autenticação padrão em ambientes Windows Active Directory.
Atacantes o exploram para movimento lateral via técnicas como Pass-the-Ticket e Kerberoasting.

#### 4.7.1 Indicadores de Lateral Movement via Kerberos

| Indicador                                       | Event ID Windows | Técnica MITRE   |
|:------------------------------------------------|:----------------:|:---------------:|
| Solicitação anômala de ticket de serviço (TGS)  | 4769             | T1558.003       |
| Uso de ticket em host diferente do originador   | 4768 + 4769      | T1550.003       |
| Alto volume de TGS requests em sequência        | 4769 (bulk)      | T1046 + T1558.003|
| Solicitação de ticket para serviços administrativos | 4769 CIFS/HOST | T1021.002      |
| Uso de conta com SPN para TGS (Kerberoasting)   | 4769 AES128/256  | T1558.003       |

#### 4.7.2 Query UDM para Kerberoasting

```
// Hunting de Kerberoasting: solicitações de TGS para contas com SPN
// que geralmente usam criptografia fraca (RC4) — sinal de Kerberoasting
metadata.event_type = "USER_LOGIN"
AND network.application_protocol = "KERBEROS"
AND metadata.product_event_type = "4769"
AND extensions.auth.type = "KERBEROS"
AND security_result.description = /.*Ticket Encryption Type: 0x17.*/
AND NOT principal.user.userid = /.*\$$/
| group_by principal.user.userid, target.user.userid
| aggregate count() as total_tgs
| where total_tgs > 5
| order_by total_tgs desc
```

---

### 4.8 Cinco Hipóteses de Hunting com Queries UDM

#### Hipótese 1: Comprometimento de credencial via phishing

**Hipótese:** "Um funcionário foi vítima de phishing e suas credenciais estão sendo usadas
de fora do Brasil."

```
Query: Logins bem-sucedidos de IPs fora do range normal brasileiro
───────────────────────────────────────────────────────────────────
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND target.user.email_addresses = /.*@bancomeridian\.com\.br$/
AND NOT principal.ip = "177.0.0.0/8"
AND NOT principal.ip = "189.0.0.0/8"
AND NOT principal.ip = "200.0.0.0/8"
AND NOT principal.ip = "201.0.0.0/8"
AND NOT principal.ip = "10.0.0.0/8"
| group_by principal.ip, target.user.userid
| order_by count() desc
```

#### Hipótese 2: Exfiltração de dados via armazenamento em nuvem

**Hipótese:** "Dados sensíveis estão sendo exfiltrados via upload para serviços de cloud
storage pessoal (Dropbox, Mega, Google Drive pessoal)."

```
Query: Conexões HTTPS para domínios de cloud storage pessoal
──────────────────────────────────────────────────────────────
metadata.event_type = "NETWORK_HTTP"
AND network.http.method = "PUT"
AND (
  target.hostname = /.*dropbox\.com$/ OR
  target.hostname = /.*mega\.nz$/ OR
  target.hostname = /.*onedrive\.live\.com$/ OR
  target.hostname = /.*wetransfer\.com$/ OR
  target.hostname = /.*sendspace\.com$/
)
AND network.sent_bytes > 10485760
| group_by principal.hostname, principal.user.userid, target.hostname
| aggregate sum(network.sent_bytes) as total_bytes
| order_by total_bytes desc
```

#### Hipótese 3: Reconhecimento de rede por host comprometido

**Hipótese:** "Um host comprometido está fazendo reconhecimento interno da rede antes do
movimento lateral."

```
Query: Host com conexões a muitas portas/IPs internos distintos em curto período
─────────────────────────────────────────────────────────────────────────────────
metadata.event_type = "NETWORK_CONNECTION"
AND principal.ip = "192.168.0.0/16"
AND target.ip = "192.168.0.0/16"
| group_by principal.hostname
| aggregate count(distinct target.ip) as ips_destino_unicos,
            count(distinct target.port) as portas_destino_unicas
| where ips_destino_unicos > 20 OR portas_destino_unicas > 30
| order_by ips_destino_unicos desc
```

#### Hipótese 4: Criação de persistência via scheduled task ou serviço

**Hipótese:** "Um atacante com acesso ao sistema está criando mecanismos de persistência via
Windows Scheduled Tasks ou serviços maliciosos."

```
Query: Criação de scheduled task ou service por processo incomum
─────────────────────────────────────────────────────────────────
metadata.event_type = "PROCESS_LAUNCH"
AND (
  target.process.command_line = /.*schtasks.*\/create.*/i OR
  target.process.command_line = /.*sc.*create.*/i OR
  target.process.command_line = /.*New-Service.*/i OR
  target.process.command_line = /.*Register-ScheduledTask.*/i
)
AND NOT principal.process.file.full_path = /.*\\Windows\\System32\\svchost\.exe$/
AND NOT principal.user.userid = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$/
| group_by principal.hostname, principal.user.userid, target.process.command_line
| order_by count() desc
```

#### Hipótese 5: Uso de ferramentas de administração remota por usuários comuns

**Hipótese:** "Um usuário sem perfil técnico está usando ferramentas de administração remota
(PsExec, WinRM, RDP) — indicativo de comprometimento ou insider threat."

```
Query: Usuários comuns usando ferramentas de admin remoto
──────────────────────────────────────────────────────────
metadata.event_type = "PROCESS_LAUNCH"
AND (
  target.process.file.full_path = /.*psexec\.exe$/i OR
  target.process.file.full_path = /.*psexesvc\.exe$/i OR
  target.process.command_line = /.*winrm.*/i OR
  target.process.command_line = /.*Invoke-Command.*/i
)
AND NOT principal.user.userid in %watchlist_admins_ti
AND NOT principal.hostname = /.*SRV-.*/
| group_by principal.user.userid, principal.hostname, target.process.command_line
| order_by count() desc
```

---

## Atividades de Fixação

### Quiz — Módulo 04

**Questão 1:** Um threat hunter do Banco Meridian recebeu um relatório Mandiant informando
que o grupo APT34 (associado a operações contra bancos do Oriente Médio) usa o IP
`45.77.123.89` como servidor de C2. Qual metodologia de hunting é mais adequada para
verificar se esse IOC afeta o ambiente do banco?

- [ ] a) Hipótese-driven, porque o hunter precisa criar uma hipótese sobre o comportamento do APT34
- [ ] b) Situational, porque o contexto é a publicação do relatório de TI
- [ ] c) Indicator-driven, porque o ponto de partida é um IOC conhecido (IP do servidor C2)
- [ ] d) Análise de UEBA, porque o Risk Score dos usuários indicará comprometimento

**Resposta correta:** c) — A existência de um IOC concreto (IP de C2) caracteriza hunting indicator-driven: buscar diretamente por evidências daquele indicador no ambiente.

---

**Questão 2:** Em uma investigação de lateral movement, você descobriu que o host `WRK-ANA-003`
iniciou conexões suspeitas. Qual é a PRÓXIMA etapa correta de pivoting para entender o
escopo completo do incidente?

- [ ] a) Isolar imediatamente o host WRK-ANA-003 da rede sem investigação adicional
- [ ] b) Pivotar pelo hostname para ver quais outros hosts receberam conexões a partir de WRK-ANA-003 e quais usuários estavam logados nele
- [ ] c) Abrir um ticket para o time de TI verificar fisicamente o hardware do host
- [ ] d) Aguardar o UEBA gerar um Risk Score para WRK-ANA-003 antes de continuar

**Resposta correta:** b) — O pivoting por hostname é o próximo passo natural: mapear todos os hosts destino das conexões e identificar o usuário responsável para expandir o grafo de ataque.

---

**Questão 3:** Um host do Banco Meridian tem Risk Score igual a 78 no Google SecOps UEBA.
O que isso indica e qual é a ação recomendada segundo o módulo?

- [ ] a) O host está definitivamente comprometido e deve ser isolado imediatamente
- [ ] b) O host está na faixa HIGH (70–89) e deve ser investigado em até 30 minutos com triagem prioritária
- [ ] c) O host está na faixa MEDIUM e pode aguardar revisão ao final do turno
- [ ] d) O Risk Score 78 é causado exclusivamente por alertas YARA-L ativos e não indica anomalias comportamentais

**Resposta correta:** b) — Score 78 = categoria HIGH = investigação prioritária em até 30 minutos.

---

**Questão 4:** Qual das seguintes características é um indicador estatístico de C2 beaconing
em contraste com tráfego HTTP legítimo?

- [ ] a) Alto volume de bytes enviados (C2 malware exfiltra dados continuamente)
- [ ] b) Baixa variação no intervalo entre conexões e consistência no tamanho dos pacotes (periodicidade mecânica do malware)
- [ ] c) Destino sempre em domínios com HTTPS válido (malware prefere certificados legítimos)
- [ ] d) Conexões apenas durante o horário comercial (malware tenta se misturar ao tráfego normal)

**Resposta correta:** b) — A periodicidade mecânica (intervalo consistente) e os pacotes de tamanho fixo são assinaturas características de C2 beaconing, diferente do comportamento variável e imprevisível do tráfego humano legítimo.

---

**Questão 5:** No ciclo de threat hunting descrito no módulo, qual é o resultado esperado
quando uma hipótese de hunting é CONFIRMADA (ameaça encontrada)?

- [ ] a) Apenas documentar no relatório de incidente e aguardar nova hipótese
- [ ] b) Documentar o incidente, extrair IOCs e criar uma regra YARA-L para detectar o padrão encontrado automaticamente em detecções futuras
- [ ] c) Reportar ao CISO e aguardar autorização para criar regras de detecção
- [ ] d) Encerrar o hunting, pois a ameaça já foi encontrada e documentada

**Resposta correta:** b) — O ciclo completo de hunting culmina com a criação de uma detecção automatizada (YARA-L Live Rule) para que o padrão encontrado seja detectado automaticamente no futuro, sem necessidade de hunting manual repetido.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **Este roteiro é para uso exclusivo do instrutor. Cada bloco indica o conteúdo a ser apresentado,
> o tempo estimado e as orientações de produção.**

---

### AULA 4.1 — Metodologia de Threat Hunting e UDM Search Avançado (45 min)

---

**[ABERTURA — 3 min | Tela: Slide "Threat Hunting — Caçando o que os alertas não viram"]**

"Olá! Bem-vindo ao Módulo 04. Aqui a gente vai falar de uma das habilidades mais valorizadas
no mercado de segurança hoje: o threat hunting.

Eu gosto de definir assim: o SIEM detecta o que você já sabe que é ruim. O threat hunting
encontra o que ainda não sabe que está ruim. É uma atividade proativa, investigativa, quase
como trabalho de detetive — mas com petabytes de dados à disposição.

No Google SecOps, as ferramentas de hunting são o UDM Search avançado, o Timeline View,
o Risk Analytics e o UEBA. Vamos dominar todas elas. Vamos lá!"

---

**[BLOCO 1: As três metodologias — 10 min | Tela: Slide com diagrama]**

"Três formas de fazer hunting. Todas válidas, cada uma para um contexto diferente.

A primeira — e a mais intelectualmente estimulante — é o hunting hipótese-driven. Você
começa de uma pergunta: 'E se um atacante já está dentro do ambiente e fazendo reconhecimento?
Como eu veria isso nos dados?'

A fonte dessas hipóteses é variada. Pode vir do MITRE ATT&CK — você lê uma técnica e pensa:
'o Banco Meridian tem as condições para essa técnica funcionar?'. Pode vir de um relatório de
Threat Intelligence sobre APTs que atacam bancos no Brasil. Pode vir do seu próprio instinto
depois de anos de experiência.

A segunda metodologia é indicator-driven. Mais objetiva: você tem um IOC concreto e vai buscar
por ele. O CERT.br emitiu um alerta sobre um domínio malicioso? Você busca aquele domínio no
UDM Search. Simples, mas eficaz.

E a terceira é situational: hunting motivado por contexto. Um funcionário vai ser demitido.
Um 0-day crítico foi publicado no produto que você usa. Um incidente ocorreu em um banco
concorrente. Esses contextos disparam hunting específico.

*[Pausar e olhar para a câmera]*

Na prática, um bom hunting session mistura as três. Você começa com uma hipótese, identifica
indicadores relevantes, e usa o contexto do ambiente para calibrar o que é anômalo."

---

**[BLOCO 2: UDM Search avançado ao vivo — 20 min | Tela: Google SecOps Console]**

"Agora a parte prática. Vou abrir o UDM Search e fazer uma sessão de hunting ao vivo
baseada na hipótese 1 do material: 'credenciais comprometidas de um usuário sendo usadas
de fora do Brasil'.

*[Navegar para UDM Search]*

Primeiro, a query base: logins bem-sucedidos de IPs fora dos ranges típicos do Brasil.
Vou digitar a query da seção 4.8...

*[Digitar a query da Hipótese 1]*

Olha o resultado. Temos aqui 3 logins de IPs fora do Brasil nas últimas 24 horas. Dois são
da VPN corporativa — posso verificar na lista de IPs de VPN. O terceiro... IP alemão. Vamos
investigar isso.

*[Clicar no resultado suspeito]*

Clico no IP e faço o pivot. O sistema me mostra que este IP está associado a... let me see...
ao usuário diana.ferreira. Mas olha o timestamp: 9h03 da manhã de hoje, um dia depois do
ataque de password spray que a gente identificou no Lab 02.

Isso não é coincidência. Isso é a confirmação que a conta de diana.ferreira foi comprometida
no ataque de password spray. Agora eu preciso pivotar pelo usuário para ver o que ela fez
depois de entrar.

*[Executar a query de pivoting por usuário]*

E aqui está a timeline completa: login de IP alemão, enumeração de grupos, acesso ao SharePoint,
download de arquivos... Essa é a kill chain do ataque. E foi o hunting que me trouxe até aqui —
não um alerta."

*[Dica de edição: usar picture-in-picture mostrando o hunter digitando queries enquanto os resultados aparecem na tela]*

---

**[BLOCO 3: Timeline View — 12 min]**

"Agora que identifiquei o usuário comprometido, quero ver a timeline completa. Vou para
Entity Search, busco 'diana.ferreira', seleciono a entidade de usuário...

*[Navegar para Entity Search → diana.ferreira → Timeline]*

Aqui está. Tudo o que diana.ferreira fez nas últimas 24 horas, em ordem cronológica,
com o tipo de evento e a fonte de log para cada ação.

Repare que consigo ver claramente a sequência: login estranho, depois enumeração de AD,
depois acesso a dados sensíveis, depois download em massa. Essa é a kill chain que eu
documentaria num relatório de incidente.

E o mais poderoso: consigo exportar essa timeline ou copiar para o case aberto no SOAR.
Tudo conectado."

*[ORIENTAÇÕES DE PRODUÇÃO:]*
- *Gravar com dados sintéticos do Banco Meridian no tenant de lab*
- *Usar timer na tela para mostrar a velocidade das queries no Google SecOps*
- *Live online: revisar as hipóteses de hunting criadas pelos alunos antes da sessão*

---

### AULA 4.2 — UEBA e Risk Analytics em Profundidade (45 min)

---

**[ABERTURA — 3 min | Tela: Slide "UEBA — Quando o Comportamento Conta Mais que o Evento"]**

"Na segunda aula deste módulo, vamos falar do UEBA — User and Entity Behavior Analytics.
Essa é a camada de inteligência que vai além das regras YARA-L. Em vez de detectar eventos
específicos, o UEBA detecta DESVIOS do comportamento normal.

E por que isso importa? Porque as ameaças mais sofisticadas — insider threats, APTs avançados
— muitas vezes não disparam nenhuma regra YARA-L porque não fazem nada 'tecnicamente errado'.
Eles usam credenciais válidas, acessam sistemas permitidos, mas em contextos anômalos. O UEBA
captura isso."

---

**[BLOCO 1: Como o UEBA aprende o baseline — 12 min]**

"O UEBA precisa de tempo para aprender o que é 'normal'. Nas primeiras 4 semanas depois de
ativar o Google SecOps, os modelos de ML ficam em modo de aprendizado — observando padrões
sem gerar alertas.

O que ele aprende? Para cada usuário: em quais horários costuma fazer login, de quais IPs
e localizações, em quais dispositivos, quais sistemas acessa, qual é o volume típico de dados
que transfere, com quais outros usuários colabora.

Depois de estabelecer o baseline, qualquer desvio significativo é um sinal de anomalia.

*[Mostrar no console a tela de UEBA de um usuário]*

Aqui, olhando o perfil do usuário carlos.souza, vejo o baseline dele. Horário habitual:
08:30 às 18:30. Localização habitual: São Paulo. Volume diário médio: 1,2 GB.

E aqui, o evento de anomalia de ontem: carlos.souza acessou às 23:15, de Recife, e
transferiu 8,4 GB. Esse desvio gerou um alerta e aumentou o Risk Score dele de 12 para 67."

*[Mostrar a tela do Risk Analytics com o score]*

---

**[BLOCO 2: Context-Aware Analytics — 15 min]**

"O conceito mais poderoso do UEBA é o Context-Aware Analytics. Individualmente, cada anomalia
pode ter uma explicação inocente. Juntas, contam uma história bem diferente.

Vou usar o exemplo do material: João acessou às 22h — pode ser trabalho urgente. João baixou
2 GB — pode ser trabalho legítimo. João acessou servidores novos — pode ser um projeto novo.

Mas João está em processo de demissão, acessou de madrugada, baixou 2 GB de dados financeiros,
em servidores que nunca tinha acessado nos últimos 6 meses, e vai sair da empresa amanhã?

O Context-Aware Analytics combina todos esses sinais e gera um alerta de insider threat.
Cada sinal isolado seria ignorado. A combinação é inequívoca.

Isso é o que torna o UEBA complementar e não substitutivo do YARA-L. O YARA-L detecta
padrões técnicos conhecidos. O UEBA detecta comportamentos anômalos que não têm assinatura."

---

**[RECAPITULAÇÃO E CHAMADA PARA O LAB — 15 min]**

"Recapitulando o Módulo 04:

Threat hunting tem três metodologias: hipótese-driven, indicator-driven e situational.
A melhor prática é combinar as três.

O ciclo do hunting: hipótese → busca → validação → documentação → detecção (regra YARA-L).
O hunting que não termina em detecção automatizada é um hunting incompleto.

O UDM Search avançado com pivoting é a ferramenta operacional do hunter. Dominar os
operadores de agregação e a técnica de pivoting IP → usuário → processo → artefato é
fundamental.

O UEBA e o Risk Analytics são a camada de inteligência comportamental. Use o Risk Analytics
como lista de priorização — todo dia, os top 5 entidades com maior Risk Score merecem
pelo menos uma olhada.

No Lab 03, você vai investigar um caso suspeito de C2 beaconing no host WRK-RODRIGO-011,
usando todos esses conceitos. Te vejo no lab!"

---

## Avaliação do Módulo 04

### Gabarito das Questões de Múltipla Escolha

| Questão | Resposta Correta | Justificativa                                                                                   |
|:-------:|:----------------:|:------------------------------------------------------------------------------------------------|
|    1    |       c)         | IOC concreto (IP) caracteriza hunting indicator-driven                                          |
|    2    |       b)         | Pivoting por hostname expande o grafo de ataque para hosts destino e usuários envolvidos        |
|    3    |       b)         | Risk Score 78 = categoria HIGH = investigação em até 30 minutos                                 |
|    4    |       b)         | Baixa variação de intervalo e pacotes de tamanho consistente = assinatura de beaconing          |
|    5    |       b)         | Hunting completo termina com detecção automatizada via YARA-L Live Rule                         |

### Critérios de Avaliação

| Pontuação | Resultado                                                                              |
|:---------:|:---------------------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 05 — Threat Intelligence                            |
| 4/5 (80%) | Muito bom! Revise o tópico da questão errada antes de avançar                         |
| 3/5 (60%) | Recomendado executar a sessão de hunting ao vivo descrita na Aula 4.1 antes de avançar|
| < 3 (< 60%)| Revisite todo o módulo — threat hunting é a base do Módulo 07 (Capstone)             |

---

*Módulo 04 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 03 — YARA-L 2.0](../modulo-03-yara-l-detection/README.md)*
*Próximo: [Módulo 05 — Threat Intelligence](../modulo-05-threat-intelligence/README.md)*
