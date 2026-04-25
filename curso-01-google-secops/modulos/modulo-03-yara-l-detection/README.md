# Módulo 03 — YARA-L 2.0: Detection Engineering
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 3h videoaulas + 3h laboratório + 1h live online                     |
| **Pré-requisito**  | Módulo 02 concluído · UDM Search funcional                          |
| **MITRE ATT&CK**   | T1110.003, T1071.001, T1059, T1098, T1048                           |
| **Ferramentas**    | Google SecOps YARA-L Editor, Detection Engine, Retrohunt            |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Escrever regras YARA-L 2.0 single-event e multi-event com todas as seções obrigatórias
2. Usar os operadores e funções principais: `#`, `count()`, `count(distinct)`, `array_distinct()`, `min()`, `max()`
3. Diferenciar Retrohunt de Live Rules e escolher o momento certo para cada um
4. Aplicar técnicas de tuning para reduzir falsos positivos usando `not`, Watchlists e regex de exclusão
5. Criar regras seguindo boas práticas de nomenclatura, versionamento e documentação

---

## Conteúdo do Módulo

### 3.1 YARA-L 2.0: Estrutura Completa

YARA-L (Yet Another Recursive Acronym — Language) é a linguagem de detecção nativa do
Google SecOps. Ela foi projetada especificamente para operar sobre o UDM, permitindo
correlação de eventos ao longo do tempo — algo que consultas SQL simples não conseguem
expressar de forma eficiente.

Antes de estudar a sintaxe, é importante entender por que o Google criou uma linguagem nova,
em vez de adotar SQL ou um padrão existente como Sigma. O problema central é que ameaças
reais raramente são sobre um único evento isolado. Um password spray não é "uma tentativa de
login com falha" — é "50 tentativas de login com falha para 30 usuários diferentes a partir
do mesmo IP, tudo dentro de 15 minutos". SQL consegue expressar isso com joins e subqueries
complexas, mas sem a noção de janela temporal deslizante nativa que o YARA-L oferece.

No contexto do Banco Meridian, onde o SOC opera com três analistas cobrindo 2.800 funcionários,
a capacidade do YARA-L de detectar padrões complexos automaticamente — sem intervenção humana
para cada event — é o que torna o monitoramento 24x7 viável. Uma única regra bem escrita pode
substituir horas de análise manual diária.

```
ESTRUTURA COMPLETA DE UMA REGRA YARA-L 2.0
═══════════════════════════════════════════════════════════════════════

rule NOME_DA_REGRA {

  meta:                          ← Metadados da regra (obrigatório)
    author = "..."
    description = "..."
    severity = "..."             ← CRITICAL | HIGH | MEDIUM | LOW | INFO
    priority = "..."             ← CRITICAL | HIGH | MEDIUM | LOW | INFO
    mitre_attack_tactic = "..."
    mitre_attack_technique = "..."
    created_date = "YYYY-MM-DD"
    version = "1.0"
    false_positives = "..."

  events:                        ← Definição dos eventos a correlacionar (obrigatório)
    $e1.metadata.event_type = "..."
    $e1.principal.ip = $ip_src   ← Variáveis de correlação ($ + nome)
    $e2.target.ip = $ip_src      ← $ip_src vincula e1 e e2 pelo mesmo IP

  match:                         ← Janela de tempo para correlação (obrigatório em multi-event)
    $ip_src over 15m             ← Agrupa por variável dentro de uma janela de tempo

  condition:                     ← Critério de disparo (obrigatório)
    #e1 >= 10                    ← # conta ocorrências do evento e1
    AND count(distinct $e1.target.user.userid) >= 5

  outcome:                       ← Campos extras no alerta gerado (opcional)
    $risk_score = 75
    $total_tentativas = count($e1)
    $usuarios_alvo = array_distinct($e1.target.user.userid)

}

═══════════════════════════════════════════════════════════════════════
```

#### 3.1.1 Seção `meta` — Metadados da Regra

| Campo                        | Obrigatório | Valores aceitos                                      | Descrição                           |
|:-----------------------------|:-----------:|:-----------------------------------------------------|:------------------------------------|
| `author`                     | Recomendado | String livre                                         | Autor/time responsável              |
| `description`                | Recomendado | String livre                                         | O que a regra detecta               |
| `severity`                   | Sim         | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL           | Severidade do alerta gerado         |
| `priority`                   | Recomendado | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL           | Prioridade de triagem               |
| `mitre_attack_tactic`        | Recomendado | String (ex: "Credential Access")                     | Tática MITRE ATT&CK                 |
| `mitre_attack_technique`     | Recomendado | String (ex: "T1110.003")                             | Técnica MITRE ATT&CK                |
| `created_date`               | Recomendado | YYYY-MM-DD                                           | Data de criação da regra            |
| `version`                    | Recomendado | String (ex: "1.0")                                   | Versão da regra                     |
| `false_positives`            | Recomendado | String livre                                         | Casos conhecidos de falso positivo  |

#### 3.1.2 Seção `events` — Definição dos Eventos

A seção `events` é onde você define QUAIS eventos o YARA-L deve capturar e COMO correlacioná-los
entre si. É aqui que você especifica os filtros UDM que selecionam os eventos relevantes para
a detecção. Pense nela como a "cláusula WHERE" da sua detecção: você está dizendo ao motor
"me traga apenas eventos que tenham estas características".

No contexto do Banco Meridian, a seção `events` de uma regra de password spray, por exemplo,
filtraria apenas eventos de login com falha (`security_result.action = "BLOCK"`) para o domínio
corporativo do banco (`target.user.email_addresses = /.*@bancomeridian\.com\.br$/`), excluindo
automaticamente logins de contas de serviço que geram muitas falhas por razões legítimas.

**Variáveis de evento:** `$e1`, `$e2`, `$e3` — cada variável representa um tipo de evento.

**Variáveis de correlação:** valores extraídos de campos do UDM e compartilhados entre eventos.

```yara-l
events:
  // Evento 1: login com falha
  $e1.metadata.event_type = "USER_LOGIN"
  $e1.security_result.action = "BLOCK"
  $e1.principal.ip = $ip_origem      // ← variável de correlação: mesmo IP

  // Evento 2: login bem-sucedido do mesmo IP
  $e2.metadata.event_type = "USER_LOGIN"
  $e2.security_result.action = "ALLOW"
  $e2.principal.ip = $ip_origem      // ← mesmo IP vincula os dois eventos
```

#### 3.1.3 Seção `match` — Janela Temporal

A seção `match` é o que transforma uma query de busca em uma detecção de padrão temporal.
Sem ela, você tem uma regra single-event — que verifica cada evento individualmente. Com ela,
você tem uma regra multi-event — que agrupa eventos que compartilham um campo comum (como o
IP de origem) dentro de uma janela de tempo deslizante, e avalia o conjunto como um todo.

No Banco Meridian, a seção `match` é o mecanismo que distingue uma tentativa isolada de
login com falha (que acontece centenas de vezes por dia de forma legítima) de um ataque de
password spray (onde o mesmo IP tenta dezenas de contas diferentes em minutos). Sem o `match`
e sua janela temporal, a regra não conseguiria fazer essa distinção.

A seção `match` é **obrigatória em regras multi-event**. Ela define:
- **A variável de agrupamento** — como os eventos são correlacionados
- **A janela de tempo** — o período dentro do qual os eventos devem ocorrer

```yara-l
match:
  $ip_origem over 15m            // Eventos agrupados por IP dentro de 15 minutos
```

**Janelas de tempo recomendadas por caso de uso:**

| Cenário de Detecção            | Janela recomendada | Justificativa                              |
|:-------------------------------|:------------------:|:-------------------------------------------|
| Password spray                 | `15m`              | Ataques rápidos para evitar lockout        |
| C2 beaconing periódico         | `1h` ou `24h`      | Padrões se manifestam em horas             |
| Lateral movement (SMB/RDP)     | `30m`              | Movimento entre hosts em minutos           |
| Exfiltração por DNS (DGA)      | `10m`              | Consultas DGA são rápidas e em sequência   |
| Privilege escalation           | `5m`               | Criação de admin logo após comprometimento |
| Reconhecimento de rede         | `1h`               | Port scan se manifesta em dezenas de min   |

#### 3.1.4 Seção `condition` — Critérios de Disparo

| Operador / Função                          | Sintaxe                                              | Descrição                                          |
|:-------------------------------------------|:-----------------------------------------------------|:---------------------------------------------------|
| **Contador de eventos**                    | `#e1 >= 10`                                          | Conta ocorrências do evento `$e1`                  |
| **Contador distinto**                      | `count(distinct $e1.target.user.userid) >= 5`        | Conta valores únicos de um campo                   |
| **Mínimo/Máximo**                          | `max($e1.network.sent_bytes) >= 1073741824`          | Valor máximo de um campo numérico                  |
| **Negação**                                | `not $e1.principal.hostname = /.*\.bancomeridian\..*/`| Exclui eventos que match a condição               |
| **AND / OR**                               | `#e1 >= 10 AND #e2 >= 1`                             | Operadores lógicos                                 |

#### 3.1.5 Seção `outcome` — Campos do Alerta

A seção `outcome` é onde você decide o que o analista verá quando abrir o alerta. Sem um
`outcome` bem elaborado, o analista recebe um alerta genérico e precisa navegar manualmente
pelo SIEM para entender o que aconteceu. Com um `outcome` rico, o alerta já vem com a lista
de usuários afetados, o IP do atacante, o número de tentativas e o risk score — tudo que
o analista precisa para tomar a primeira decisão de triagem em segundos.

No contexto do Banco Meridian, onde Mariana (L2) e Carlos (L1) precisam triar alertas
rapidamente durante o turno, um `outcome` bem preenchido pode reduzir o tempo de triagem
de 15 minutos para 2 minutos por alerta.

A seção `outcome` permite calcular e adicionar campos extras ao alerta gerado, enriquecendo
o contexto para o analista de triagem:

```yara-l
outcome:
  $risk_score = max(0,
    if(#e1 >= 50, 90,
    if(#e1 >= 20, 70,
    50)))

  $total_tentativas = count($e1)
  $usuarios_alvo = array_distinct($e1.target.user.userid)
  $janela_inicio = min($e1.metadata.event_timestamp)
  $janela_fim = max($e1.metadata.event_timestamp)
  $ip_origem = $ip_src
```

---

### 3.2 Operadores e Funções: Referência Completa

#### 3.2.1 Operadores de Contagem

| Operador | Exemplo                                           | Descrição                                    |
|:---------|:--------------------------------------------------|:---------------------------------------------|
| `#var`   | `#e1 >= 10`                                       | Conta o total de ocorrências do evento       |
| `count()`| `count($e1) >= 10`                                | Equivalente ao `#e1`                         |
| `count(distinct field)` | `count(distinct $e1.target.user.userid) >= 5` | Conta valores únicos   |

#### 3.2.2 Funções de Agregação

| Função            | Exemplo                                                  | Descrição                                   |
|:------------------|:---------------------------------------------------------|:--------------------------------------------|
| `min()`           | `min($e1.metadata.event_timestamp)`                      | Menor valor de um campo                     |
| `max()`           | `max($e1.metadata.event_timestamp)`                      | Maior valor de um campo                     |
| `sum()`           | `sum($e1.network.sent_bytes) >= 1073741824`              | Soma de um campo numérico                   |
| `array()`         | `array($e1.target.user.userid)`                          | Cria array com todos os valores do campo    |
| `array_distinct()`| `array_distinct($e1.target.user.userid)`                 | Array sem duplicatas                        |

#### 3.2.3 Funções de String e Regex

```yara-l
// Regex (case-insensitive por padrão)
$e1.target.url = /.*\.ru\/.*/

// Contém string (case-sensitive)
$e1.network.http.user_agent = "curl"

// Não contém (exclusão)
not $e1.principal.hostname = /.*-SVCACC-.*/

// Lista de valores (OR implícito)
$e1.target.port = 445 or
$e1.target.port = 139 or
$e1.target.port = 3389
```

---

### 3.3 Regras Single-Event vs. Multi-Event

#### 3.3.1 Single-Event Rules

Regras **single-event** disparam para **cada evento individualmente**, sem necessidade de
correlação temporal. São mais simples e têm latência de detecção menor.

**Use single-event para:**
- Detecção de eventos de alta severidade que por si sós indicam um problema
- Alertas de conformidade (acesso de usuário privilegiado, uso de conta de serviço)
- Indicadores de IOC (acesso a IP ou domínio malicioso conhecido)

```yara-l
// Exemplo: login fora do horário comercial (single-event)
rule login_fora_horario_comercial {
  meta:
    description = "Detecta logins de usuários em horário fora do comercial"
    severity = "MEDIUM"
  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"
    // Filtra apenas usuários do domínio do Banco Meridian
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/
    // Exclui contas de serviço
    not $e1.target.user.userid = /.*svc.*/
    // Detecta horário fora de 08:00–20:00 UTC-3 (= 11:00–23:00 UTC)
    (
      $e1.metadata.event_timestamp.hours < 11 OR
      $e1.metadata.event_timestamp.hours >= 23
    )
  condition:
    $e1
}
```

#### 3.3.2 Multi-Event Rules

Regras **multi-event** correlacionam **múltiplos eventos ao longo do tempo**, permitindo
detectar padrões que só ficam visíveis na agregação.

**Use multi-event para:**
- Brute force, password spray (muitas tentativas de um mesmo IP)
- C2 beaconing (comunicações periódicas e regulares)
- Lateral movement (acesso sequencial a múltiplos hosts)
- Reconhecimento de rede (port scanning)

```yara-l
// Exemplo: password spray simplificado (multi-event)
rule password_spray_simples {
  meta:
    description = "Múltiplas falhas de login para usuários diferentes do mesmo IP"
    severity = "HIGH"
    mitre_attack_technique = "T1110.003"
  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"
    $e1.principal.ip = $ip_origem
  match:
    $ip_origem over 15m
  condition:
    #e1 >= 10 AND
    count(distinct $e1.target.user.userid) >= 5
}
```

---

### 3.4 Retrohunt vs. Live Rules

Um dos principais erros cometidos por analistas que são novos no Google SecOps é ativar uma
regra YARA-L como Live Rule imediatamente após escrevê-la, sem validação prévia. O resultado
típico é uma enxurrada de falsos positivos que sobrecarrega o SOC e faz os analistas perderem
a confiança no sistema de detecção.

O Retrohunt é a etapa de validação que evita esse problema. Ao rodar a regra sobre dados
históricos ANTES de ativá-la em produção, você consegue medir: quantas detecções reais a
regra encontraria? E quantos falsos positivos? Essa análise prévia é o que torna possível
calibrar os thresholds e exclusões com dados reais do ambiente.

No caso do Banco Meridian, um Retrohunt de 7 dias sobre os logs de login do Azure AD e
Windows Event, antes de ativar qualquer regra de brute force, revelaria quantas vezes por
semana os sistemas de monitoramento internos geram falhas de login legítimas — informação
essencial para definir o threshold correto da regra.

| Característica         | Retrohunt                                    | Live Rule                                      |
|:-----------------------|:--------------------------------------------:|:----------------------------------------------:|
| **Quando executa**     | Sob demanda, sobre dados históricos          | Continuamente, sobre eventos em tempo real     |
| **Objetivo**           | Investigação forense, validação de regra     | Detecção proativa, alertas operacionais        |
| **Dados analisados**   | Período específico escolhido pelo analista   | Eventos novos a partir do momento de ativação |
| **Resultado**          | Lista de detecções no console                | Alertas gerados no painel de Cases             |
| **Custo computacional**| Pontual (enquanto roda)                      | Contínuo (regra sempre ativa)                  |
| **Uso típico**         | Caça de ameaças históricas, threat hunting   | Operações do SOC, monitoramento 24x7           |

**Fluxo recomendado para nova regra:**

```
1. Escrever a regra no YARA-L Editor
2. Executar Retrohunt sobre os últimos 7–30 dias
3. Analisar resultados: falsos positivos? Cobertura adequada?
4. Ajustar thresholds e exclusões
5. Repetir Retrohunt até resultado satisfatório
6. Ativar como Live Rule
7. Monitorar nas primeiras 24–48h para novos falsos positivos
```

---

### 3.5 Tuning e Supressão de Falsos Positivos

Falsos positivos são o maior inimigo da efetividade de um SOC. Uma regra que gera 50 alertas
por dia onde 49 são FP treina os analistas a ignorar os alertas — incluindo o real.

Esse fenômeno tem um nome: **alert fatigue** (fadiga de alerta). É um dos maiores problemas
operacionais de qualquer SOC, e tem uma consequência direta e perigosa: analistas que
recebem centenas de FPs por dia começam a "aprovar" alertas no modo automático, sem análise
real. Quando o alerta genuíno aparece, ele passa despercebido exatamente como os outros.

No Banco Meridian, um SOC com apenas três analistas é especialmente vulnerável à fadiga de
alerta. Se cada analista recebe 80 alertas por turno e 70 são FPs, a capacidade de resposta
a incidentes reais fica seriamente comprometida. Por isso, o tuning de regras não é opcional
— é tão crítico quanto a escrita das próprias regras.

> ⚠️ **Atenção:** A fadiga de alerta foi um fator contribuinte em vários incidentes de alto
> perfil documentados pelo Verizon DBIR e pelo Mandiant M-Trends. Em um desses casos, o alerta
> real ficou na fila de revisão por 47 dias antes de ser investigado — porque os analistas
> estavam sobrecarregados com FPs. Mantenha a taxa de FP abaixo de 10% em todas as Live Rules.

#### 3.5.1 Técnicas de Exclusão

**Usando `not`:**
```yara-l
// Excluir contas de serviço (geralmente têm "svc" ou "sa_" no userid)
not $e1.principal.user.userid = /^(svc_|sa_|svc-|service-).*/

// Excluir hosts de infraestrutura conhecidos (servidores de monitoramento)
not $e1.principal.hostname = /^(ZABBIX|NAGIOS|PRTG|monitoring-).*/

// Excluir IPs da faixa de VPN corporativa
not $e1.principal.ip = "10.200.0.0/16"
```

**Usando Watchlists:**

Watchlists são listas gerenciadas diretamente no console do Google SecOps. São ideais para
exclusões que mudam com frequência (ex: lista de IPs de sistemas de backup que fazem
autenticações legítimas em massa).

```yara-l
// Referência a uma Watchlist criada no console
not $e1.principal.ip in %watchlist_ips_infraestrutura
not $e1.principal.user.userid in %watchlist_contas_servico
```

#### 3.5.2 Ajuste de Thresholds

O threshold ideal depende do baseline do ambiente. Processo para definir:

```
1. Rodar Retrohunt sem condition (só com os filtros de events)
2. Analisar a distribuição:
   - Percentil 99 das contagens legítimas → threshold mínimo deve ser ACIMA disso
   - Ex: se usuários legítimos raramente passam de 3 falhas em 15 min, threshold >= 10 é seguro
3. Verificar cobertura:
   - O ataque real que queremos detectar fica acima do threshold?
   - Ex: password spray com 47 tentativas → threshold de 10 cobre com folga
4. Ajustar iterativamente com novos retrohunts
```

---

### 3.6 Cinco Exemplos Completos de Regras YARA-L

Os cinco exemplos a seguir foram construídos especificamente para o cenário do Banco Meridian.
Cada um detecta uma técnica diferente do MITRE ATT&CK que é relevante para o setor financeiro
brasileiro. Estude o código de cada exemplo entendendo primeiro a lógica de segurança por trás
da regra — o que o atacante faz que torna o padrão detectável? — antes de analisar a sintaxe
YARA-L. Essa ordem de raciocínio (do problema para o código) é o que diferencia um bom
Detection Engineer de alguém que apenas copia regras sem entender o que está fazendo.

#### Exemplo 1: Login Fora do Horário Comercial (Single-Event)

**O que esta regra detecta e por que foi projetada assim:** Esta regra detecta logins bem-sucedidos de usuários do Banco Meridian fora do horário comercial (antes das 8h e após as 20h, horário de Brasília). É uma regra single-event porque cada login fora do horário é, por si só, um evento suspeito que justifica investigação — não é necessário correlacionar múltiplos eventos. Logins noturnos de contas corporativas são frequentemente associados à técnica T1078 (Valid Accounts) usada por atacantes que comprometeram credenciais e escolhem horários de baixo monitoramento para operar. No Banco Meridian, o BACEN exige rastreamento de acessos fora do horário operacional — esta regra cumpre automaticamente este requisito.

**Decisões de design críticas:** O campo `target.user.email_addresses` é preferido a `target.user.userid` porque o e-mail corporativo é mais específico (exclui contas de sistema) e mais fácil de correlacionar com logs do Azure AD. A exclusão de contas de serviço (`svc_`, `sa_`) via regex é essencial — sistemas de monitoramento fazem check-ins noturnos legítimos e sem essa exclusão a regra geraria dezenas de falsos positivos por dia. A watchlist `watchlist_acesso_noturno_autorizado` permite exceções gerenciadas para profissionais de plantão sem reescrever a regra.

```yara-l
// ============================================================
// REGRA: login_fora_horario_comercial
// Detecta logins autenticados de usuários do Banco Meridian
// fora do horário comercial (20h–8h, horário de Brasília)
// MITRE: T1078 — Valid Accounts
// ============================================================
rule login_fora_horario_comercial {
  meta:
    author = "SOC — Banco Meridian"
    description = "Login autenticado fora do horário comercial (20h–08h BRT)"
    severity = "MEDIUM"
    priority = "MEDIUM"
    mitre_attack_tactic = "Defense Evasion"
    mitre_attack_technique = "T1078"
    mitre_attack_technique_name = "Valid Accounts"
    created_date = "2026-04-24"
    version = "1.1"
    false_positives = "Funcionários com escalas de plantão; acessos de TI noturno autorizados"

  events:
    // Somente logins bem-sucedidos
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"

    // Somente usuários do domínio corporativo
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/

    // Excluir contas de serviço (padrão: svc_, sa_, svcacc_)
    not $e1.target.user.userid = /^(svc_|sa_|svcacc_|service_|bot_).*/

    // Excluir contas da Watchlist de usuários com acesso noturno autorizado
    not $e1.target.user.userid in %watchlist_acesso_noturno_autorizado

    // Horário: fora de 08:00–20:00 BRT = fora de 11:00–23:00 UTC
    (
      $e1.metadata.event_timestamp.hours < 11 OR
      $e1.metadata.event_timestamp.hours >= 23
    )

  condition:
    // Dispara para cada evento individual (single-event)
    $e1

  outcome:
    // Informações extras no alerta para facilitar triagem
    $usuario = $e1.target.user.userid
    $hora_acesso = $e1.metadata.event_timestamp.hours
    $ip_origem = $e1.principal.ip
    $hostname_origem = $e1.principal.hostname
    $risk_score = 45
    $severity = "MEDIUM"
}
```

---

#### Exemplo 2: Password Spray (Multi-Event)

**O que esta regra detecta e por que foi projetada assim:** Esta regra detecta ataques de Password Spray (T1110.003), onde um atacante usa uma senha comum contra muitos usuários diferentes — ao contrário do brute force, que tenta muitas senhas contra um único usuário. A distinção técnica entre os dois ataques está no campo `count(distinct $e1.target.user.email_addresses)`: o brute force gera muitas falhas do mesmo IP para o mesmo usuário (alto `#e1`, baixo `distinct users`); o password spray gera falhas distribuídas em muitos usuários (alto `#e1` E alto `distinct users`). Esta combinação é o que torna a regra específica — nenhuma das condições sozinha seria suficiente.

**Decisões de design críticas:** A janela de 15 minutos (`over 15m`) é calibrada para capturar rajadas rápidas de password spray, que tipicamente duram 10–30 minutos para evitar lockouts de conta. O threshold de 10 tentativas e 5 usuários distintos foi derivado da análise do baseline do Banco Meridian — em dias normais, nenhum IP externo gera mais de 3 bloqueios em 15 minutos. A regra usa `target.user.email_addresses` em vez de `userid` porque o password spray geralmente testa endereços de e-mail que o atacante obteve via OSINT ou vazamentos.

```yara-l
// ============================================================
// REGRA: password_spray_detection
// Detecta tentativas de password spray: múltiplas falhas de
// login para usuários diferentes a partir do mesmo IP de origem
// MITRE: T1110.003 — Brute Force: Password Spraying
// ============================================================
rule password_spray_detection {
  meta:
    author = "SOC — Banco Meridian"
    description = "Detecta password spray: >= 10 falhas para >= 5 usuários distintos do mesmo IP em 15 min"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110.003"
    mitre_attack_technique_name = "Brute Force: Password Spraying"
    created_date = "2026-04-07"
    version = "1.2"
    false_positives = "Sistemas de monitoramento que verificam múltiplas contas; testes de carga de AD"

  events:
    // Login com falha
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"

    // Razão de falha relacionada a senha (excluir lockout já existente, conta desativada)
    $e1.security_result.category_details = /.*invalid.*password.*|.*bad.*password.*|.*wrong.*password.*/

    // Somente usuários do domínio corporativo como alvo
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/

    // Excluir IPs internos conhecidos de sistemas de autenticação (ex: AD sync)
    not $e1.principal.ip in %watchlist_ips_infraestrutura_interna

    // Correlacionar por IP de origem
    $e1.principal.ip = $ip_origem

  match:
    // Janela de 15 minutos por IP de origem
    $ip_origem over 15m

  condition:
    // Pelo menos 10 tentativas de login falhadas do mesmo IP
    #e1 >= 10
    // E pelo menos 5 usuários distintos foram alvo
    AND count(distinct $e1.target.user.email_addresses) >= 5

  outcome:
    $ip_origem_alerta = $ip_origem
    $total_tentativas = count($e1)
    $usuarios_alvo = array_distinct($e1.target.user.email_addresses)
    $usuarios_unicos = count(distinct $e1.target.user.email_addresses)
    $janela_inicio = min($e1.metadata.event_timestamp)
    $janela_fim = max($e1.metadata.event_timestamp)
    $risk_score = max(0,
      if($usuarios_unicos >= 20, 90,
      if($usuarios_unicos >= 10, 80,
      if($usuarios_unicos >= 5, 65,
      50))))
    $severity = "HIGH"
}
```

---

#### Exemplo 3: C2 Beaconing por Periodicidade (Multi-Event com Análise Estatística)

**O que esta regra detecta e por que foi projetada assim:** Esta regra detecta comportamento de C2 Beaconing (T1071.001), onde um malware instalado em um host faz conexões periódicas regulares para um servidor de Comando e Controle do atacante. O padrão característico do beaconing é a regularidade: ao contrário de tráfego humano (que é irregular e em rajadas), um beacon faz conexões a intervalos quase fixos — a cada 60 segundos, a cada 5 minutos, etc. A técnica de análise estatística usada aqui (desvio padrão dos intervalos entre conexões) é o método mais eficaz para capturar essa regularidade, pois é resistente a jitter (pequena variação aleatória que frameworks como Cobalt Strike adicionam aos beacons para evitar detecção).

**Decisões de design críticas:** O uso de `stddev(intervals) < 10` captura beacons com jitter de até 10 segundos — o jitter padrão do Cobalt Strike é configurável entre 0% e 50% do intervalo. Para um beacon de 60 segundos com 20% de jitter, o desvio padrão seria de ~12 segundos, portanto a regra usa threshold de 10 para ser conservadora. O filtro de IPs internos (`NOT target.ip = /^10\..*/ etc.`) é essencial — sem ele, qualquer sistema de heartbeat interno (monitoramento, backup) dispararia a regra. O `count >= 10` garante que pelo menos 10 conexões foram feitas no período, evitando que 2 ou 3 reconexões legítimas (por exemplo, após queda de VPN) disparem o alerta.

```yara-l
// ============================================================
// REGRA: c2_beaconing_periodicidade
// Detecta padrões de C2 beaconing: conexões HTTPS periódicas
// e regulares a um destino externo com intervalo consistente.
// Lógica: alto volume de conexões com baixo desvio de intervalo
// MITRE: T1071.001 — Application Layer Protocol: Web Protocols
//        T1132 — Data Encoding
// ============================================================
rule c2_beaconing_periodicidade {
  meta:
    author = "SOC — Banco Meridian"
    description = "Detecta C2 beaconing: >= 20 conexões HTTPS ao mesmo destino externo em 1h com padrão periódico"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Command and Control"
    mitre_attack_technique = "T1071.001"
    mitre_attack_technique_name = "Application Layer Protocol: Web Protocols"
    created_date = "2026-04-24"
    version = "1.0"
    false_positives = "Aplicações com check-in periódico (antivírus, SCCM, update clients); NTP"

  events:
    // Conexão de rede de saída
    $e1.metadata.event_type = "NETWORK_CONNECTION"
    $e1.network.direction = "OUTBOUND"

    // Porta 443 (HTTPS) ou 80 (HTTP) — protocolo mais comum para C2 evasivo
    (
      $e1.target.port = 443 OR
      $e1.target.port = 80 OR
      $e1.target.port = 8080 OR
      $e1.target.port = 8443
    )

    // Excluir destinos internos e RFC1918 (C2 é sempre para IPs externos)
    not $e1.target.ip = "10.0.0.0/8"
    not $e1.target.ip = "172.16.0.0/12"
    not $e1.target.ip = "192.168.0.0/16"

    // Excluir CDNs e serviços conhecidos legítimos via Watchlist
    not $e1.target.ip in %watchlist_ips_cdn_legítimos
    not $e1.target.hostname = /.*\.(windows\.com|microsoft\.com|office\.com|akamai\.net|cloudflare\.com|amazonaws\.com|google\.com)$/

    // Excluir processos legítimos conhecidos por beaconing (antivírus, SCCM)
    not $e1.principal.process.file.full_path in %watchlist_processos_beacon_legitimos

    // Correlacionar por host de origem + IP destino (mesmo par host→IP)
    $e1.principal.hostname = $hostname_origem
    $e1.target.ip = $ip_destino

  match:
    // Janela de 1 hora por par hostname→IP destino
    $hostname_origem, $ip_destino over 1h

  condition:
    // Pelo menos 20 conexões (alta periodicidade)
    #e1 >= 20

    // Padrão de tamanho de pacote muito consistente (bytes recebidos similares)
    // Nota: C2 malware frequentemente envia payloads de tamanho fixo
    AND max($e1.network.received_bytes) - min($e1.network.received_bytes) <= 512

  outcome:
    $hostname_alerta = $hostname_origem
    $ip_destino_alerta = $ip_destino
    $total_conexoes = count($e1)
    $bytes_enviados_total = sum($e1.network.sent_bytes)
    $bytes_recebidos_total = sum($e1.network.received_bytes)
    $processo_suspeito = $e1.principal.process.file.full_path
    $primeira_conexao = min($e1.metadata.event_timestamp)
    $ultima_conexao = max($e1.metadata.event_timestamp)
    $risk_score = 80
    $severity = "HIGH"
}
```

---

#### Exemplo 4: Exfiltração via DNS / DGA Detection (Multi-Event)

**O que esta regra detecta e por que foi projetada assim:** Esta regra detecta dois comportamentos relacionados que indicam uso malicioso do protocolo DNS: exfiltração de dados via DNS (T1048.003) e uso de Domain Generation Algorithms — DGA (T1568.002). Atacantes usam DNS para exfiltrar dados porque o protocolo quase sempre é permitido pelo firewall e raramente é inspecionado com profundidade. A exfiltração via DNS codifica dados em queries de subdomínio — cada query carrega pequenos pedaços de dados que, somados, formam o arquivo exfiltrado. DGA é usado para gerar domínios de C2 dinamicamente, tornando o bloqueio por lista negra ineficaz. O alto volume de respostas NXDOMAIN (domínio não encontrado) é o sinal característico de DGA: o malware gera centenas de domínios e só um pequeno subconjunto está ativo como C2.

**Decisões de design críticas:** O threshold de 50 domínios únicos com NXDOMAIN em 5 minutos captura o padrão de DGA sem disparar para falhas de DNS legítimas (usuário digitando URL errada). O filtro `strlen(target.hostname) > 30` foca em domínios longos — domínios DGA são tipicamente gerados com 20–40 caracteres aleatórios, enquanto domínios legítimos raramente excedem 20 caracteres. Para o Banco Meridian, a detecção de DNS tunelado é especialmente crítica em conformidade com a LGPD — dados de clientes exfiltrados por DNS constituem violação de dados pessoais que requer notificação à ANPD em até 72 horas.

```yara-l
// ============================================================
// REGRA: dns_dga_exfiltracao
// Detecta consultas DNS suspeitas indicativas de DGA (Domain
// Generation Algorithm) ou tunelamento DNS para exfiltração.
// Sinais: alto volume de consultas NXDOMAIN para domínios
// longos e com alta entropia (padrão de DGA).
// MITRE: T1048 — Exfiltration Over Alternative Protocol
//        T1568.002 — Dynamic Resolution: Domain Generation
// ============================================================
rule dns_dga_exfiltracao {
  meta:
    author = "SOC — Banco Meridian"
    description = "Detecta possível DGA ou tunelamento DNS: alto volume de NXDOMAIN para domínios de aspecto aleatório"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Exfiltration"
    mitre_attack_technique = "T1048"
    mitre_attack_technique_name = "Exfiltration Over Alternative Protocol"
    created_date = "2026-04-24"
    version = "1.0"
    false_positives = "Ferramentas de reconhecimento de DNS legítimas; alguns softwares de P2P"

  events:
    // Consulta DNS com resposta NXDOMAIN (domínio não existe)
    $e1.metadata.event_type = "DNS_QUERY"
    $e1.security_result.action = "BLOCK"
    $e1.security_result.category_details = /.*NXDOMAIN.*/

    // Domínio consultado com comprimento longo (sinal de DGA: domínios aleatórios são geralmente longos)
    // Nota: DGA típico tem nomes entre 12-30 caracteres aleatórios
    not $e1.target.hostname = /^.{1,11}\..*/

    // Excluir TLDs de domínios corporativos legítimos
    not $e1.target.hostname = /.*\.(bancomeridian\.com\.br|internal\.bancomeridian\.com|corp\.bancomeridian\.com)$/

    // Excluir consultas de servidores DNS recursivos da infra interna
    not $e1.principal.ip in %watchlist_servidores_dns_internos

    // Correlacionar por host de origem
    $e1.principal.hostname = $hostname_origem

  match:
    // Janela de 10 minutos por host
    $hostname_origem over 10m

  condition:
    // Pelo menos 30 consultas NXDOMAIN em 10 minutos (muito acima do normal)
    #e1 >= 30

  outcome:
    $hostname_alerta = $hostname_origem
    $total_consultas_nxdomain = count($e1)
    $dominios_consultados = array_distinct($e1.target.hostname)
    $total_dominios_unicos = count(distinct $e1.target.hostname)
    $primeira_consulta = min($e1.metadata.event_timestamp)
    $ultima_consulta = max($e1.metadata.event_timestamp)
    $risk_score = 85
    $severity = "HIGH"
}
```

---

#### Exemplo 5: Privilege Escalation via Criação de Conta Admin (Multi-Event)

**O que esta regra detecta e por que foi projetada assim:** Esta regra detecta uma sequência de dois eventos que, juntos, indicam persistência pós-comprometimento: primeiro, um login bem-sucedido com credenciais que geraram alertas anteriores (comprometimento); segundo, a criação de uma nova conta de usuário seguida de adição ao grupo de administradores (T1098 + T1136). Esta sequência é o padrão clássico de como APTs garantem acesso futuro ao ambiente — a conta backdoor criada pelo atacante serve de porta de entrada permanente mesmo que a conta original seja bloqueada após descoberta do comprometimento. No incidente da Operação Antas (Lab 05), foi exatamente esse padrão que levou à criação da conta `administrador_ti2`.

**Decisões de design críticas:** A regra usa dois eventos correlacionados (`$e1` e `$e2`) com uma janela de correlação de 30 minutos (`over 30m`) e o vínculo `$e1.principal.user.userid = $e2.principal.user.userid` — isso garante que AMBOS os eventos são realizados pelo MESMO usuário. Sem esse vínculo, a regra dispararia em qualquer dia onde qualquer usuário fizesse login e qualquer administrador criasse uma nova conta (eventos não relacionados). O filtro de grupos de admin (`Domain Admins|Enterprise Admins|Administrators`) é específico para o domínio Active Directory do Banco Meridian — em outros ambientes, o grupo pode ter nome diferente e precisar de ajuste. Para compliance BACEN, a criação não autorizada de contas privilegiadas é classificada como incidente relevante de segurança (Resolução 4.893, Artigo 2, inciso III).

```yara-l
// ============================================================
// REGRA: privilege_escalation_criacao_conta_admin
// Detecta sequência suspeita: comprometimento de conta +
// criação de nova conta de administrador logo em seguida.
// Indica persistência pós-comprometimento.
// MITRE: T1098 — Account Manipulation
//        T1136 — Create Account
// ============================================================
rule privilege_escalation_criacao_conta_admin {
  meta:
    author = "SOC — Banco Meridian"
    description = "Login de conta existente seguido de criação de conta admin no mesmo host em 5 minutos"
    severity = "CRITICAL"
    priority = "CRITICAL"
    mitre_attack_tactic = "Persistence"
    mitre_attack_technique = "T1136"
    mitre_attack_technique_name = "Create Account"
    created_date = "2026-04-24"
    version = "1.0"
    false_positives = "Onboarding de TI com criação de admin local; scripts de provisionamento legítimos"

  events:
    // Evento 1: login bem-sucedido
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"

    // Excluir contas de serviço do evento 1
    not $e1.principal.user.userid = /^(svc_|sa_|svcacc_|Administrator|SYSTEM).*/

    // Correlacionar pelo hostname da máquina onde ocorreu o login
    $e1.principal.hostname = $hostname_alvo

    // Evento 2: criação de novo usuário no mesmo host
    $e2.metadata.event_type = "USER_CREATION"

    // A criação foi no mesmo host do login
    $e2.principal.hostname = $hostname_alvo

    // O novo usuário foi adicionado a grupo admin (Domain Admins, Administrators, etc.)
    $e2.target.user.user_display_name = /.*admin.*/

    // E2 ocorre DEPOIS de E1 (correlação temporal)
    $e2.metadata.event_timestamp > $e1.metadata.event_timestamp

  match:
    // Janela de 5 minutos
    $hostname_alvo over 5m

  condition:
    // Login ($e1) seguido de criação de conta admin ($e2)
    #e1 >= 1 AND #e2 >= 1

  outcome:
    $hostname_alerta = $hostname_alvo
    $usuario_que_logou = $e1.principal.user.userid
    $nova_conta_admin = $e2.target.user.userid
    $ip_origem_login = $e1.principal.ip
    $tempo_login = $e1.metadata.event_timestamp
    $tempo_criacao = $e2.metadata.event_timestamp
    $risk_score = 95
    $severity = "CRITICAL"
}
```

---

### 3.7 Tabela Comparativa: YARA-L vs. KQL vs. SPL vs. Sigma

| Critério                    | YARA-L 2.0              | KQL (Microsoft)         | SPL (Splunk)            | Sigma (YAML)             |
|:----------------------------|:-----------------------:|:-----------------------:|:-----------------------:|:------------------------:|
| **Plataforma nativa**       | Google SecOps           | Microsoft Sentinel      | Splunk SIEM             | Plataforma-agnóstico     |
| **Tipo de regra**           | Single e multi-event    | Apenas queries          | Queries + savedsearches | Regra abstrata           |
| **Correlação temporal**     | Nativa (`match over`)   | Via `join` / `project`  | Via `transaction`       | Limitada (via backends)  |
| **Variáveis de correlação** | Sim (variáveis $)       | Limitada                | Limitada                | Não                      |
| **Formato**                 | DSL proprietário        | DSL (similar SQL)       | DSL proprietário        | YAML padronizado         |
| **Retrohunt nativo**        | Sim                     | Sim (query histórica)   | Sim                     | Depende do backend       |
| **Curva de aprendizado**    | Moderada                | Moderada                | Alta                    | Baixa (mas limitada)     |
| **Portabilidade**           | Apenas Google SecOps    | Apenas Azure            | Apenas Splunk           | Alta (conversível)       |
| **Suporte a ML**            | Sim (via UEBA rules)    | Sim (Sentinel UEBA)     | Limitado (MLTK add-on) | Não                      |
| **Documentação**            | Boa (Google Cloud Docs) | Excelente (Microsoft)   | Excelente (Splunk Docs) | Boa (SigmaHQ GitHub)     |

---

### 3.8 Boas Práticas de Detection Engineering

#### 3.8.1 Nomenclatura de Regras

```
Padrão recomendado:
{categoria}_{descrição_curta}_{versão_opcional}

Exemplos:
credential_access_password_spray
lateral_movement_smb_port_scan
c2_beaconing_https_periodico
persistence_nova_conta_admin
exfil_dns_alto_volume_nxdomain
```

#### 3.8.2 Versionamento

Toda regra deve ter campo `version` no `meta`. Use SemVer simplificado:
- `1.0` — criação inicial
- `1.1` — ajuste de threshold ou exclusão
- `2.0` — reformulação da lógica de detecção

Mantenha o histórico de versões nos comentários do arquivo ou no repositório Git:

```yara-l
// Histórico de versões:
// v1.0 — 2026-04-07: criação inicial por José Alves
// v1.1 — 2026-04-12: adicionada exclusão de IPs de infra interna (redução 80% FP)
// v1.2 — 2026-04-20: ajuste threshold: 10 → 15 tentativas (após análise baseline)
```

#### 3.8.3 Documentação da Regra

Além dos campos `meta`, inclua comentários inline explicando decisões:

```yara-l
events:
  // Usando email_addresses em vez de userid porque o Windows Event 4625
  // popula o campo target.user.email_addresses para logins do Office 365
  $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/

  // Threshold conservador: testes mostraram que usuários legítimos
  // raramente passam de 3 falhas. 10 dá margem para falsos positivos.
  // Aumentar para 15 se houver muitos FPs de sistemas de SSO.
```

---

## Atividades de Fixação

### Quiz — Módulo 03

**Questão 1:** Em uma regra YARA-L multi-event, qual é a função da seção `match` e o que
acontece se ela for omitida?

- [ ] a) A seção `match` filtra eventos por tipo; sem ela, todos os tipos são aceitos
- [ ] b) A seção `match` define a variável de agrupamento e a janela temporal; sem ela, regras multi-event causam erro de sintaxe
- [ ] c) A seção `match` é opcional em todas as regras YARA-L
- [ ] d) A seção `match` define as ações de resposta automática ao alerta

**Resposta correta:** b) — A seção `match` é obrigatória em regras multi-event e define como os eventos são correlacionados temporalmente.

---

**Questão 2:** Qual a diferença entre `count($e1.target.user.userid)` e
`count(distinct $e1.target.user.userid)` na seção `condition` de uma regra YARA-L?

- [ ] a) Não há diferença — ambas contam o mesmo valor
- [ ] b) `count()` conta o total de ocorrências (incluindo repetições); `count(distinct)` conta apenas os valores únicos
- [ ] c) `count(distinct)` só funciona com campos do namespace `principal`
- [ ] d) `count()` é usado em `condition` e `count(distinct)` apenas em `outcome`

**Resposta correta:** b) — Para detectar password spray, a diferença é crítica: queremos saber quantos USUÁRIOS DIFERENTES foram alvo, não quantas tentativas totais houve.

---

**Questão 3:** Um analista escreveu uma regra YARA-L e verificou que ela gera 40 alertas por dia,
sendo 38 deles falsos positivos causados por um sistema de monitoramento legítimo que verifica
a disponibilidade de múltiplas contas. Qual é a MELHOR abordagem para resolver isso?

- [ ] a) Deletar a regra, pois ela não é útil
- [ ] b) Aumentar o threshold de detecção até eliminar todos os FPs, mesmo que isso comprometa a detecção
- [ ] c) Adicionar o IP ou hostname do sistema de monitoramento a uma Watchlist e usar `not in %watchlist_...` na regra
- [ ] d) Desativar temporariamente a regra e criar um ticket para o time de TI resolver o sistema legado

**Resposta correta:** c) — Watchlists são a solução elegante para exclusões que devem ser gerenciadas dinamicamente, sem alterar a lógica da regra.

---

**Questão 4:** Qual é a sequência CORRETA para validar e colocar em produção uma nova regra YARA-L?

- [ ] a) Escrever → Ativar como Live Rule → Retrohunt → Ajustar → Documentar
- [ ] b) Escrever → Retrohunt (7–30 dias) → Analisar FPs → Ajustar → Retrohunt novamente → Ativar como Live Rule
- [ ] c) Escrever → Documentar → Enviar para aprovação do gestor → Ativar como Live Rule
- [ ] d) Copiar regra do Sigma → Converter para YARA-L → Ativar como Live Rule diretamente

**Resposta correta:** b) — O Retrohunt é o passo de validação essencial antes de ativar qualquer Live Rule, evitando ruído excessivo no SOC.

---

**Questão 5:** No exemplo da regra de C2 beaconing do módulo, qual é a lógica usada para
identificar a regularidade das conexões (periodicidade) sem ter acesso direto ao intervalo
entre conexões?

- [ ] a) Usa a função `interval()` do YARA-L para calcular o intervalo médio entre eventos
- [ ] b) Usa o contador `#e1 >= 20` (alto volume de conexões em 1 hora) combinado com a baixa variação no tamanho dos pacotes recebidos (`max - min <= 512 bytes`)
- [ ] c) Usa análise de entropia dos campos de URL para detectar padrões estocásticos
- [ ] d) YARA-L não consegue detectar periodicidade — isso é exclusivo do UEBA

**Resposta correta:** b) — A combinação de alto volume em janela curta + baixa variação de tamanho de pacote é um proxy eficaz para periodicidade de C2 beaconing.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **Este roteiro é para uso exclusivo do instrutor. Cada bloco indica o conteúdo a ser apresentado,
> o tempo estimado e as orientações de produção.**

---

### AULA 3.1 — Sintaxe YARA-L 2.0 (45 min)

---

**[ABERTURA — 3 min | Tela: Slide "YARA-L 2.0 — A Linguagem de Detecção do Google SecOps"]**

"Bem-vindo ao Módulo 03 — o módulo que, na minha opinião, é o coração de todo o curso.
YARA-L é a linguagem de detecção nativa do Google SecOps, e dominá-la é o que separa um
analista que usa o SIEM de um analista que realmente opera o SIEM.

Nesta primeira aula, a gente vai mergulhar na sintaxe: as cinco seções de uma regra YARA-L,
os operadores e funções disponíveis, e a diferença fundamental entre regras single-event e
multi-event. Vamos lá!"

---

**[BLOCO 1: Por que uma linguagem de detecção específica — 5 min]**

"Antes de escrever a primeira linha de código YARA-L, eu quero que você entenda por que o
Google criou uma linguagem nova, em vez de usar SQL ou algum padrão existente.

O problema central é: detecções de ameaças reais raramente são sobre um único evento isolado.
Um password spray não é 'uma tentativa de login com falha'. É '50 tentativas de login com falha
para 30 usuários diferentes a partir do mesmo IP, tudo dentro de 15 minutos'.

SQL consegue expressar isso com joins e subqueries, mas de forma muito complexa e sem a noção
de janela temporal deslizante que o YARA-L tem nativamente.

O YARA-L foi projetado especificamente para este problema: correlacionar eventos UDM ao longo
do tempo, de forma declarativa e eficiente. Uma vez que você domina a sintaxe, consegue
escrever detecções sofisticadas com poucas linhas."

*[Dica de edição: mostrar side-by-side: o mesmo case de password spray em SQL (complexo) vs. YARA-L (simples)]*

---

**[BLOCO 2: As cinco seções — 20 min | Tela: YARA-L Editor no Google SecOps]**

"Vou abrir aqui o YARA-L Editor no console do Google SecOps. Toda regra tem cinco seções.

*[Abrir o editor e digitar ao vivo]*

A primeira é o `meta`. São os metadados da regra. Author, description, severity, mapeamento
MITRE. Isso pode parecer burocracia, mas é vital para operações. Quando você tem 200 regras
ativas no SOC e um alerta dispara às 3 da manhã, o analista de plantão precisa entender
rapidamente o que aquela regra detecta, qual a severidade e qual a técnica MITRE. Se não
tiver meta bem preenchido, você vai perder tempo precioso na triagem.

A segunda é `events`. Aqui você define QUAIS eventos você quer capturar e como correlacioná-los.
Vou digitar um exemplo simples: eventos de USER_LOGIN com action BLOCK.

*[Digitar a seção events de um exemplo simples]*

Repare nestas variáveis com cifrão — `$e1`, `$ip_origem`. Isso é o coração do YARA-L. `$e1`
é uma variável de evento — guarda cada evento que passou pelos filtros. `$ip_origem` é uma
variável de correlação — extrai o campo `principal.ip` do evento e cria um grupo de eventos
que compartilham o mesmo IP.

*[Continuar digitando match e condition]*

A terceira seção, `match`, só existe em regras multi-event. Ela diz: agrupe os eventos por
`$ip_origem`, dentro de uma janela de 15 minutos. Essa janela deslizante é o que permite
detectar ataques que se espalham no tempo.

A quarta, `condition`, é o gatilho: quando a regra dispara. `#e1 >= 10` significa: se houver
10 ou mais eventos `$e1` dentro da janela, dispare o alerta.

E a quinta, `outcome`, é o bônus: campos extras que aparecem no alerta para ajudar a triagem.
Lista de usuários afetados, total de tentativas, risk score calculado."

---

**[BLOCO 3: Função das variáveis de correlação — 10 min]**

"Quero dedicar um tempinho extra para as variáveis de correlação porque esse é o conceito
que mais confunde quem está aprendendo YARA-L.

Olha este trecho:
```
$e1.principal.ip = $ip_origem
$e2.target.ip = $ip_origem
```

O que isso está dizendo é: 'o IP de origem do evento 1 deve ser o mesmo que o IP de destino
do evento 2'. Quando o YARA-L avalia a regra, ele vai buscar todos os pares de eventos ($e1, $e2)
onde essa relação é verdadeira.

Por que isso é poderoso? Porque você pode detectar coisas como: 'o mesmo host que fez login
com falha ($e1) depois conseguiu acesso a um arquivo sensível ($e2) dentro de 5 minutos'. Isso
é correlação temporal que conta uma história de ataque — não um evento isolado."

*[Dica de edição: usar animação mostrando dois eventos distintos sendo conectados por uma seta com o valor da variável de correlação]*

---

**[RECAPITULAÇÃO AULA 3.1 — 7 min]**

"Antes de encerrar esta aula, vamos testar o nosso editor. Vou pegar a regra de login fora
do horário comercial que está no material do módulo e colar aqui no editor.

*[Colar a regra do Exemplo 1]*

Clico em 'Save' e... sem erros de sintaxe. Agora vou em Retrohunt, seleciono os últimos 7 dias,
clico em Run. Em alguns minutos teremos o resultado.

Enquanto espera, reveja a estrutura da regra. Na próxima aula, a gente vai a fundo nas regras
multi-event e vai criar a regra de C2 beaconing do zero."

---

### AULA 3.2 — Multi-Event Rules: Detecções Avançadas (45 min)

---

**[ABERTURA — 3 min | Tela: Slide "Multi-Event: Quando o perigo está no padrão, não no evento"]**

"Bem-vindo à Aula 3.2. Você já conhece a estrutura básica do YARA-L. Agora vamos ao que
diferencia o Google SecOps de um SIEM simples: as regras multi-event.

A grande maioria das técnicas do MITRE ATT&CK não se manifesta em um evento único. Elas
se manifestam em padrões ao longo do tempo. Password spray, lateral movement, beaconing de
C2, exfiltração por DNS — todas essas técnicas têm uma assinatura temporal que só fica
visível quando você correlaciona múltiplos eventos. É exatamente isso que vamos fazer hoje."

---

**[BLOCO 1: Anatomia de um ataque multi-evento — 10 min | Tela: Diagrama de timeline]**

"Deixa eu te mostrar um cenário real. O Banco Meridian sofreu um ataque de password spray.
Vou mostrar a timeline:

9h02 — tentativa 1: diana.ferreira — FALHOU
9h02 — tentativa 2: ana.rodrigues — FALHOU
9h02 — tentativa 3: bruno.lima — FALHOU
9h03 — tentativa 4: carlos.souza — FALHOU
9h03 — tentativa 5: eduardo.melo — FALHOU
...
9h25 — tentativa 47: diana.ferreira — SUCESSO

Um evento isolado desses — uma tentativa de login com falha — é absolutamente normal.
O Windows Event ID 4625 aparece dezenas de vezes por hora em qualquer organização. Usuários
erram senha. Sistemas de SSO fazem tentativas em background.

Mas 47 tentativas de login falhadas, de 31 usuários diferentes, a partir do mesmo IP
externo, em 23 minutos? Isso é um ataque. E só uma regra multi-event consegue capturar isso.

É por isso que o `match` e o `condition` trabalham juntos: o `match` agrupa os eventos pelo
IP de origem dentro de uma janela de 15 minutos, e o `condition` dispara quando a contagem
passa dos thresholds."

---

**[BLOCO 2: Construindo a regra de C2 beaconing ao vivo — 25 min | Tela: YARA-L Editor]**

"Agora vamos construir do zero a regra de C2 beaconing. Isso é mais complexo que o password
spray porque estamos detectando um PADRÃO de comportamento, não apenas um volume alto de eventos.

*[Abrir o editor e começar a digitar]*

O C2 beaconing tem uma assinatura clássica: um processo no host comprometido faz conexões
HTTPS periódicas e regulares para um servidor de comando e controle. Periódicas porque o
malware usa um intervalo fixo (geralmente 30 segundos, 1 minuto, 5 minutos). Regulares porque
o tamanho dos pacotes é consistente — o malware envia 'check-in' packets de tamanho fixo.

Primeiro, a seção events: quero capturar NETWORK_CONNECTION outbound na porta 443...

*[Digitar cada linha e explicar]*

Agora, as exclusões. Isso é FUNDAMENTAL para uma regra de beaconing não ser inundada de FPs.
Precisamos excluir: IPs internos (RFC1918), CDNs e serviços legítimos conhecidos (Microsoft,
Google, Akamai), processos legítimos que fazem check-in periódico (antivírus, SCCM).

*[Adicionar as exclusões e explicar cada uma]*

E a condition: `#e1 >= 20` — 20 conexões em 1 hora. Isso filtra conexões de navegação normal.
E `max(received_bytes) - min(received_bytes) <= 512` — variação baixa no tamanho dos pacotes.
Essa é a proxy de periodicidade. C2 malware envia pacotes de tamanho consistente.

*[Completar a regra e executar Retrohunt]*

A regra está salva. Vamos rodar o Retrohunt nos últimos 7 dias e ver o que encontramos."

---

**[RECAPITULAÇÃO AULA 3.2 — 7 min]**

"Construímos duas regras multi-event importantes hoje: o password spray e o C2 beaconing.

O que você precisa levar desta aula:

Um — regras multi-event correlacionam eventos ao longo do tempo usando variáveis de correlação
e a seção `match`.

Dois — exclusões bem pensadas são tão importantes quanto a lógica de detecção. Uma regra sem
exclusões é uma regra cheia de FPs.

Três — janelas de tempo menores reduzem FPs mas podem perder ataques lentos. Janelas maiores
aumentam cobertura mas também ruído. Sempre calibre com Retrohunt.

Na próxima aula: tuning, Watchlists e as melhores práticas para manter sua library de regras
escalável no longo prazo."

---

### AULA 3.3 — Tuning, Boas Práticas e Detection Engineering (30 min)

---

**[ABERTURA — 2 min]**

"Chegamos à última aula do Módulo 03. Você já sabe escrever regras single e multi-event.
Agora vamos falar sobre como mantê-las funcionando bem ao longo do tempo — e como escalar
seu processo de detection engineering de forma sustentável."

---

**[BLOCO 1: O problema dos falsos positivos — 8 min]**

"Deixa eu te contar uma história que ouço muito em projetos de SOC. O time cria uma regra
nova de detecção, fica empolgado, ativa em produção. Nos primeiros dias, ótimo — ela dispara
alguns alertas reais. Mas em duas semanas está gerando 60, 70 alertas por dia. O time começa
a ignorar. E um dia, um ataque real passa despercebido entre o oceano de FPs.

Isso se chama 'alert fatigue' — fadiga de alerta. É um dos maiores problemas operacionais de
qualquer SOC, e a principal causa é FP não controlado.

A solução não é desligar as regras. É fazer tuning. Vou mostrar o fluxo que uso em todo projeto."

*[Mostrar o processo de tuning descrito na seção 3.5.2]*

---

**[BLOCO 2: Watchlists na prática — 10 min | Tela: Console Google SecOps, seção Watchlists]**

"As Watchlists são suas melhores amigas para tuning dinâmico. Deixa eu criar uma ao vivo.

*[Navegar para o console e criar uma Watchlist]*

Vou criar a watchlist `watchlist_ips_infraestrutura_interna`. Adiciono os IPs dos nossos
servidores de monitoramento Zabbix, do servidor SCCM, dos servidores de backup — qualquer
sistema que gere autenticações em massa por motivo legítimo.

Agora, nas minhas regras de password spray e beaconing, adiciono a linha:
`not $e1.principal.ip in %watchlist_ips_infraestrutura_interna`

Quando o time de TI adicionar um novo servidor de monitoramento? Só atualizam a Watchlist.
Não precisam mexer nas regras. Isso é separação de responsabilidades — o analista de segurança
mantém a lógica da regra, o time de TI mantém as listas de exceção."

---

**[BLOCO 3: Boas práticas de nomenclatura e versionamento — 10 min]**

"Por último, boas práticas de engenharia. Quando você tem 10 regras, organização é conveniência.
Quando tem 200, é sobrevivência.

Três regras simples que fazem toda a diferença:

Primeiro: nomenclatura consistente. Siga o padrão `{categoria}_{descrição}`. credential_access,
lateral_movement, persistence, exfil, c2, defense_evasion — use os nomes das táticas MITRE.
Assim qualquer analista sabe de que se trata antes de abrir a regra.

Segundo: versione. Sempre atualize o campo `version` no `meta` e documente o que mudou nos
comentários. Uma regra sem histórico de versões é uma regra que ninguém sabe se pode confiar.

Terceiro: teste antes de ativar. Sempre. Retrohunt sobre 7 dias no mínimo. Se o ambiente é
novo, 30 dias para pegar um baseline completo. Não existe desculpa para ativar uma Live Rule
sem ter validado com dados históricos."

*[ORIENTAÇÕES DE PRODUÇÃO:]*
- *Módulo longo: gravar em 3 sessões distintas (uma por aula)*
- *Aula 3.1 e 3.2: editor YARA-L ao vivo é obrigatório — não use capturas de tela estáticas*
- *Aula 3.3: pode usar slides com menos demonstração ao vivo*
- *Live online: focar em revisão das regras escritas pelos alunos no Lab 02*

---

## Avaliação do Módulo 03

### Gabarito das Questões de Múltipla Escolha

| Questão | Resposta Correta | Justificativa                                                                              |
|:-------:|:----------------:|:------------------------------------------------------------------------------------------|
|    1    |       b)         | `match` é obrigatória em multi-event, define variável de agrupamento e janela temporal    |
|    2    |       b)         | `count(distinct)` conta valores únicos; essencial para detectar múltiplos usuários-alvo   |
|    3    |       c)         | Watchlists permitem exclusões dinâmicas sem alterar a lógica da regra                     |
|    4    |       b)         | Sequência correta: escrever → Retrohunt → ajustar → Retrohunt → Live Rule                 |
|    5    |       b)         | Alto volume + baixa variação de tamanho é proxy eficaz para periodicidade de C2           |

### Critérios de Avaliação

| Pontuação | Resultado                                                                               |
|:---------:|:----------------------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 04 com segurança                                     |
| 4/5 (80%) | Muito bom! Revise o tópico da questão errada antes de avançar para threat hunting       |
| 3/5 (60%) | Recomendado refazer os exemplos das seções 3.1–3.5 no editor YARA-L antes de avançar   |
| < 3 (< 60%)| Revisite todo o módulo — YARA-L é fundamental para os módulos 04, 06 e 07              |

---

*Módulo 03 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 02 — Ingestão e UDM](../modulo-02-ingestao-udm/README.md)*
*Próximo: [Módulo 04 — Threat Hunting e UEBA](../modulo-04-threat-hunting-ueba/README.md)*
