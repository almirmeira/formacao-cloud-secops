# Módulo 06 — SOAR e Playbooks de Resposta
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 2h videoaulas + 2h laboratório + 1h live online                     |
| **Pré-requisito**  | Módulo 05 concluído · Conceitos de YARA-L e TI ativos               |
| **MITRE ATT&CK**   | T1566.001, T1078, T1486 — Resposta às técnicas                      |
| **Ferramentas**    | Google SecOps SOAR, Playbook Designer, Actions, Cases               |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Descrever a arquitetura do SOAR no Google SecOps e os componentes principais (cases, alerts, entities, actions, playbooks)
2. Usar o Playbook Designer visual para criar playbooks com blocos de condição, loop, ação e notificação
3. Configurar Actions para integrar o SOAR com Google Workspace, VirusTotal, EDR e ticketing
4. Criar três playbooks completos para cenários reais: phishing, conta comprometida e malware em endpoint
5. Calcular e interpretar métricas SOAR (MTTD, MTTR, automation rate)

---

## Conteúdo do Módulo

### 6.1 Arquitetura SOAR no Google SecOps

O SOAR (Security Orchestration, Automation and Response) do Google SecOps conecta o SIEM
(detecção) com as ferramentas de resposta para criar um ciclo de operações fechado.

Para entender por que o SOAR é crítico para o Banco Meridian, considere o seguinte cálculo:
sem automação, quando um alerta de phishing dispara, Carlos (analista L1) precisa abrir o
caso, consultar o VirusTotal manualmente para verificar o hash do anexo, abrir o Azure AD para
ver se o usuário clicou no link, acionar o CrowdStrike para isolar o host se necessário,
criar um ticket no Jira, notificar o CISO por e-mail e atualizar o status no sistema de
gestão de incidentes. Esse processo manual leva em média 47 minutos — durante os quais o
atacante já pode ter exfiltrado dados ou movido lateralmente.

Com o SOAR configurado corretamente, todo esse fluxo acontece em 38 segundos, de forma
automática, enquanto Carlos continua focado em outros alertas. Essa redução de MTTR de 47
minutos para 38 segundos é o argumento de ROI mais poderoso para justificar o investimento
em um SOC com SOAR — e é exatamente o que você vai construir no Lab 04.

O SOAR (Security Orchestration, Automation and Response) do Google SecOps conecta o SIEM
(detecção) com as ferramentas de resposta para criar um ciclo de operações fechado.

```
ARQUITETURA SOAR — GOOGLE SECOPS
══════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │                   DETECÇÃO (SIEM/YARA-L)                     │
  │   Alerta gerado → metadata, principal, target, evidence     │
  └───────────────────────────┬─────────────────────────────────┘
                              │ Alerta ingestado no SOAR
                              ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                          CASES                               │
  │   Agrupa alertas relacionados em um caso de incidente        │
  │   Prioridade: CRITICAL/HIGH/MEDIUM/LOW                       │
  │   Status: NEW → IN PROGRESS → CLOSED                        │
  └───────────────────────────┬─────────────────────────────────┘
                              │
          ┌───────────────────┼────────────────────────┐
          │                   │                        │
          ▼                   ▼                        ▼
  ┌───────────────┐  ┌────────────────┐  ┌────────────────────┐
  │    ALERTS     │  │    ENTITIES    │  │      PLAYBOOKS     │
  │               │  │                │  │                    │
  │ Alertas indiv.│  │ Usuários, hosts│  │ Fluxos de resposta │
  │ com evidências│  │ IPs, processos │  │ automatizados      │
  │ do SIEM       │  │ enriquecidos   │  │ com Actions        │
  └───────────────┘  └────────────────┘  └────────────────────┘
                                                  │
                              ┌───────────────────┼───────────────────────┐
                              │                   │                       │
                              ▼                   ▼                       ▼
                    ┌──────────────┐    ┌──────────────┐      ┌──────────────────┐
                    │  Contenção   │    │ Notificação  │      │   Ticketing      │
                    │  EDR isolate │    │ Email, Slack │      │ Jira/ServiceNow  │
                    │  AD block    │    │ Teams, PagerD│      │ Criação auto     │
                    └──────────────┘    └──────────────┘      └──────────────────┘

══════════════════════════════════════════════════════════════════
```

#### 6.1.1 Componentes do SOAR

| Componente     | Descrição                                                                         |
|:---------------|:----------------------------------------------------------------------------------|
| **Cases**      | Contêiner principal de um incidente; agrega alertas, entidades e ações            |
| **Alerts**     | Instâncias individuais de alerta ingestadas de fontes externas ou do SIEM         |
| **Entities**   | Objetos extraídos dos alertas: usuários, hosts, IPs, hashes, URLs                |
| **Actions**    | Integrações com ferramentas externas executadas pelo SOAR                         |
| **Playbooks**  | Fluxos de trabalho automatizados que orquestram múltiplas Actions                 |
| **Connectors** | Plugins que conectam o SOAR a ferramentas externas (EDR, ticketing, cloud, etc.)  |

---

### 6.2 Playbook Designer Visual

O Playbook Designer é uma interface visual baseada em blocos (similar ao draw.io) onde você
arrasta e conecta blocos de lógica para criar fluxos de resposta.

Antes de começar a criar playbooks, é importante adotar a mentalidade correta: um playbook
SOAR não substitui o analista — ele elimina as **tarefas mecânicas e repetíveis** que
consomem o tempo do analista. Para cada ação de um playbook, você deve perguntar: "Esta
decisão requer julgamento humano, ou é sempre a mesma dado o mesmo contexto?" Se a resposta
for "sempre a mesma", automatize. Se requer julgamento contextual, use um bloco de aprovação
humana (`Wait`).

No contexto do Banco Meridian, a regra geral é:
- **Enriquecimento** (consultar VirusTotal, Mandiant, GeoIP) → SEMPRE automatize
- **Contenção de nível P2** (bloquear IP, notificar usuário, criar ticket) → automatize
- **Contenção de nível P1** (isolar host, revogar credenciais, desabilitar conta) → aprovação
  humana antes de executar (risco de impacto operacional)
- **Escalação para CISO/Diretoria** → NUNCA automatize sem validação humana

#### 6.2.1 Tipos de Bloco Disponíveis

| Tipo de Bloco    | Ícone | Função                                                                |
|:-----------------|:-----:|:----------------------------------------------------------------------|
| **Trigger**      | ⚡    | Ponto de entrada do playbook (alerta recebido, case criado, manual)   |
| **Action**       | ⚙️   | Executar uma ação em ferramenta externa                               |
| **Condition**    | 🔀   | Desvio de fluxo baseado em resultado de ação anterior                 |
| **Loop**         | 🔄   | Iterar sobre lista de entidades (ex: lista de IOCs)                   |
| **Notification** | 🔔   | Enviar e-mail, Slack, Teams, PagerDuty                                |
| **Wait**         | ⏱️   | Pausar o playbook até aprovação humana ou timeout                     |
| **Sub-Playbook** | 📋   | Chamar outro playbook (modularidade)                                  |
| **Set Variable** | 📝   | Definir variável para uso em blocos subsequentes                      |
| **Comment**      | 💬   | Comentário inline para documentação do fluxo                          |

---

### 6.3 Actions Disponíveis: Referência

As **Actions** são as integrações do SOAR com ferramentas externas. Cada Action é um conector
que executa uma operação específica em um produto terceiro.

| Categoria         | Action                              | O que faz                                              |
|:------------------|:------------------------------------|:-------------------------------------------------------|
| **Google Workspace** | `Block User`                    | Suspende conta Google Workspace                        |
| **Google Workspace** | `Reset Password`                | Força redefinição de senha                             |
| **Google Workspace** | `Revoke OAuth Tokens`           | Invalida todos os tokens OAuth ativos                  |
| **VirusTotal**    | `Get File Report`                   | Enriquece hash com dados VT                            |
| **VirusTotal**    | `Get IP Report`                     | Enriquece IP com dados VT                              |
| **VirusTotal**    | `Get Domain Report`                 | Enriquece domínio com dados VT                         |
| **CrowdStrike**   | `Contain Host`                      | Isola host da rede via EDR                             |
| **CrowdStrike**   | `Run RTR Script`                    | Executa script no host via RTR (Real-Time Response)    |
| **Microsoft Defender** | `Isolate Device`             | Isola endpoint via MDE                                 |
| **Azure AD**      | `Disable User Account`              | Desabilita conta no Azure AD / Entra ID                |
| **Azure AD**      | `Revoke Sessions`                   | Invalida todas as sessões ativas do usuário            |
| **Jira**          | `Create Issue`                      | Abre ticket no Jira                                    |
| **Jira**          | `Update Issue`                      | Atualiza ticket existente com informações do case      |
| **ServiceNow**    | `Create Incident`                   | Abre incidente no ServiceNow                           |
| **Palo Alto**     | `Block IP`                          | Adiciona IP a grupo de bloqueio no NGFW                |
| **Email**         | `Send Email`                        | Envia e-mail de notificação ou usuário                 |
| **Slack/Teams**   | `Send Message`                      | Notifica canal do SOC via Slack ou Teams               |
| **PagerDuty**     | `Create Incident`                   | Dispara alerta no PagerDuty para on-call               |

---

### 6.4 Playbook 1: Resposta a Phishing (Completo)

**O que este playbook faz e por que está estruturado assim:** Este playbook automatiza a resposta ao phishing (T1566.001) desde a detecção até a contenção, seguindo uma lógica de escalonamento progressivo baseada na gravidade real do impacto. O playbook começa com enriquecimento (verificar se os IOCs são realmente maliciosos via VirusTotal antes de tomar qualquer ação) — isso evita que um falso positivo cause contenção desnecessária de um usuário legítimo, o que seria um incidente de disponibilidade. Só após confirmar a maliciosidade dos IOCs é que o playbook toma ações de contenção, e mesmo então, escalona: se o usuário NÃO interagiu com o link malicioso, a ação é notificação preventiva (menor impacto operacional); se interagiu, a ação é contenção imediata (maior impacto, mas necessária).

**Por que o enriquecimento via VirusTotal é o primeiro passo:** A maioria dos alertas de phishing gerados por sistemas de e-mail são falsos positivos — newsletters de marketing, promoções legítimas com redirecionadores de URL, etc. Sem enriquecimento, o playbook bloquearia e-mails legítimos e isolaria funcionários sem motivo, gerando reclamações de negócio e erosão da confiança no SOC. O threshold de `positives >= 5` no VirusTotal é conservador — 5 ou mais engines detectando como malicioso é praticamente um positivo verdadeiro.

**Impacto no MTTR do Banco Meridian:** Sem o playbook, um alerta de phishing com comprometimento confirmado levava 47 minutos para ser respondido (investigação manual + aprovações). Com o playbook, as ações de contenção (disable user, revoke sessions, contain host) são executadas em menos de 60 segundos após o alerta — a notificação ao PagerDuty garante que o analista de plantão é acionado imediatamente para as decisões que ainda requerem julgamento humano.

#### Diagrama de Fluxo

```
PLAYBOOK: PHISHING RESPONSE
══════════════════════════════════════════════════════════════════

  [TRIGGER: Alerta "Email Phishing Report" recebido]
         │
         ▼
  [ACTION: Extrair IOCs do e-mail]
  (subject, sender, attachment hashes, URLs)
         │
         ├──► $attachment_hashes (lista)
         ├──► $urls (lista)
         └──► $sender_email
         │
         ▼
  [LOOP: Para cada hash em $attachment_hashes]
  │
  │    [ACTION: VT Get File Report ($hash)]
  │           │
  │    [CONDITION: VT positives >= 5?]
  │    │      │
  │    │  SIM ├──► [VARIABLE: $malicious_hash = $hash]
  │    │  NÃO └──► [continuar loop]
  │
  [FIM LOOP]
         │
         ▼
  [LOOP: Para cada URL em $urls]
  │
  │    [ACTION: VT Get URL Report ($url)]
  │           │
  │    [CONDITION: VT malicious = true?]
  │    │      │
  │    │  SIM ├──► [VARIABLE: adicionar $url a $malicious_urls]
  │    │  NÃO └──► [continuar loop]
  │
  [FIM LOOP]
         │
         ▼
  [CONDITION: Algum IOC malicioso encontrado?]
  │
  ├── SIM ──► [ACTION: PAN Firewall Block URLs ($malicious_urls)]
  │           [ACTION: Criar IOCs customizados no SecOps]
  │           │
  │           ▼
  │    [CONDITION: Usuário receptor clicou no link/abriu anexo?]
  │    │
  │    ├── SIM ──► [ACTION: EDR Contain Host ($receptor_host)]
  │    │           [ACTION: Azure AD Disable User ($receptor)]
  │    │           [ACTION: Azure AD Revoke Sessions ($receptor)]
  │    │           [NOTIFICATION: PagerDuty Create Incident P1]
  │    │           [ACTION: Jira Create Issue "P1-PHISHING-$case_id"]
  │    │
  │    └── NÃO ──► [NOTIFICATION: Email ao usuário receptor]
  │                [EMAIL: "Phishing identificado — não abrir"]
  │                [ACTION: Jira Create Issue "P2-PHISHING-$case_id"]
  │
  └── NÃO ──► [CONDITION: Sender em domínio suspeito?]
              │
              ├── SIM ──► [ACTION: Block sender domain no gateway de e-mail]
              │           [NOTIFICATION: Email ao receptor — alerta preventivo]
              │
              └── NÃO ──► [NOTIFICATION: Email ao analista — revisão manual]

══════════════════════════════════════════════════════════════════
```

#### Pseudocódigo do Playbook

```python
# Playbook: phishing_response
# Trigger: alerta com tipo "Email Phishing Report"

def playbook_phishing_response(alert):
    # Passo 1: Extrair IOCs
    email_data = alert.get("email_metadata")
    attachment_hashes = email_data.get("attachment_sha256", [])
    urls = email_data.get("urls", [])
    sender = email_data.get("sender")
    receptor = email_data.get("recipient")
    receptor_host = alert.get("principal.hostname")

    malicious_hashes = []
    malicious_urls = []

    # Passo 2: Enriquecer hashes no VirusTotal
    for hash_value in attachment_hashes:
        vt_result = action_vt_get_file_report(hash=hash_value)
        if vt_result.get("positives", 0) >= 5:
            malicious_hashes.append(hash_value)

    # Passo 3: Enriquecer URLs no VirusTotal
    for url in urls:
        vt_result = action_vt_get_url_report(url=url)
        if vt_result.get("malicious", False):
            malicious_urls.append(url)

    # Passo 4: Contenção se IOC malicioso encontrado
    if malicious_hashes or malicious_urls:
        # Bloquear URLs maliciosas no firewall
        if malicious_urls:
            action_paloalto_block_urls(urls=malicious_urls)
            action_secops_create_iocs(indicators=malicious_urls, type="URL", confidence="HIGH")

        # Verificar se usuário interagiu
        if alert.get("user_opened_attachment") or alert.get("user_clicked_link"):
            # Contenção imediata
            action_edr_contain_host(hostname=receptor_host)
            action_azure_ad_disable_user(user=receptor)
            action_azure_ad_revoke_sessions(user=receptor)
            action_pagerduty_create_incident(priority="P1", title=f"Phishing confirmado: {receptor}")
            action_jira_create_issue(
                project="SEC",
                priority="P1",
                summary=f"PHISHING RESPONSE — {receptor}",
                description=f"Conta {receptor} comprometida via phishing. Host {receptor_host} isolado.",
                labels=["phishing", "incident-response", "t1566.001"]
            )
        else:
            # Notificação preventiva
            action_send_email(
                to=receptor,
                subject="[SEGURANÇA] E-mail de phishing identificado em sua caixa",
                body="Identificamos um e-mail de phishing enviado para você. Não abra o anexo..."
            )
            action_jira_create_issue(priority="P2", summary=f"PHISHING DETECTADO — {receptor}")
    else:
        if is_suspicious_domain(sender):
            action_email_gateway_block_domain(domain=extract_domain(sender))
        else:
            action_notify_analyst(message="Phishing report requer revisão manual", case_id=alert.case_id)
```

---

### 6.5 Playbook 2: Conta Comprometida (Completo)

**O que este playbook faz e por que está estruturado assim:** Este playbook responde a incidentes de Valid Account Abuse (T1078) — uso de credenciais legítimas por um atacante que as obteve via phishing, credential stuffing ou compra em fórum criminal. É um dos cenários mais difíceis de responder manualmente porque o comportamento do atacante é inicialmente indistinguível de um login legítimo do usuário. O playbook usa a combinação de Risk Score do UEBA (> 80) e anomalias de geolocalização para determinar a confiança no comprometimento antes de tomar ações — isso evita desabilitar a conta de um executivo que simplesmente viajou ao exterior.

**Por que a lógica de escalonamento é mais complexa neste playbook:** Diferentemente do phishing (onde o vetor é claro), o comprometimento de conta apresenta incerteza — pode ser o próprio usuário em circunstâncias incomuns. Por isso o playbook primeiro notifica o usuário por canal alternativo (SMS/WhatsApp corporativo) perguntando se o login é legítimo. Se o usuário confirmar (resposta "Sim"), o playbook encerra sem ação; se negar ou não responder em 10 minutos, prossegue com a contenção. Essa abordagem respeita a experiência do usuário legítimo enquanto ainda garante contenção rápida quando não há resposta.

**Impacto em conformidade BACEN:** Contas comprometidas que acessam o sistema de core banking (Tópus Banking) representam risco regulatório imediato — transações não autorizadas geradas por uma conta comprometida são responsabilidade do banco perante o BACEN e o BCB. A velocidade de contenção deste playbook (< 2 minutos para revogar sessões após confirmação de comprometimento) é diretamente correlacionada à redução do valor em risco de transações fraudulentas no período de comprometimento.

#### Diagrama de Fluxo

```
PLAYBOOK: CONTA COMPROMETIDA
══════════════════════════════════════════════════════════════════

  [TRIGGER: Alerta "Valid Account Abuse" ou Risk Score > 80]
         │
         ▼
  [ACTION: Enriquecer IP de login via Mandiant + VT]
         │
         ▼
  [CONDITION: IP é IOC conhecido (C2 / APT)?]
  │
  ├── SIM ──► [PRIORITY = P1]
  │
  └── NÃO ──►
         │
  [CONDITION: IP em país de alto risco?]
  │
  ├── SIM ──► [PRIORITY = P1]
  │
  └── NÃO ──► [PRIORITY = P2]
         │
         ▼
  [ACTION: Azure AD Revoke ALL Sessions do usuário]
  [ACTION: Azure AD Disable MFA temporarily — forçar re-registro]
         │
         ▼
  [CONDITION: Prioridade P1?]
  │
  ├── SIM ──► [ACTION: Azure AD Disable Account]
  │           [ACTION: EDR Contain Host (último host logado)]
  │           [NOTIFICATION: PagerDuty P1]
  │           [NOTIFICATION: Email CISO + Gerente do usuário]
  │           [ACTION: Jira Create P1 Issue]
  │
  └── NÃO ──► [ACTION: Azure AD Force Password Reset]
              [ACTION: Azure AD Enable MFA enforcement]
              [NOTIFICATION: Email ao usuário com instruções]
              [WAIT: Aprovação do analista para reativar conta]
              [ACTION: Jira Create P2 Issue]
         │
         ▼
  [ACTION: Executar Timeline View do usuário no SecOps]
  [ACTION: Documentar evidências no Case do SOAR]
  [NOTIFICATION: Slack canal #soc-incidents]

══════════════════════════════════════════════════════════════════
```

#### Pseudocódigo do Playbook

```python
# Playbook: compromised_account_response
# Trigger: alerta HIGH/CRITICAL de conta suspeita

def playbook_compromised_account(alert):
    usuario = alert.get("target.user.userid")
    ip_suspeito = alert.get("principal.ip")
    ultimo_host = alert.get("principal.hostname")

    # Passo 1: Enriquecer IP
    mandiant_result = action_mandiant_get_ip(ip=ip_suspeito)
    vt_result = action_vt_get_ip_report(ip=ip_suspeito)

    ip_malicioso = mandiant_result.get("confidence") in ["HIGH", "MEDIUM"]
    pais_risco = is_high_risk_country(mandiant_result.get("country"))

    prioridade = "P1" if (ip_malicioso or pais_risco) else "P2"

    # Passo 2: Contenção imediata (para todos os casos)
    action_azure_ad_revoke_sessions(user=usuario)
    action_azure_ad_force_mfa_re_register(user=usuario)

    # Passo 3: Contenção adicional para P1
    if prioridade == "P1":
        action_azure_ad_disable_account(user=usuario)
        action_edr_contain_host(hostname=ultimo_host)
        action_pagerduty_create_incident(priority="P1",
            title=f"Conta comprometida — {usuario} — IP APT: {ip_suspeito}")
        action_send_email(to=["ciso@bancomeridian.com.br",
                               f"{get_manager(usuario)}@bancomeridian.com.br"],
            subject=f"[P1] Conta comprometida: {usuario}",
            body=f"Conta {usuario} apresenta evidências de comprometimento...")
        action_jira_create_issue(priority="P1",
            summary=f"COMPROMISED ACCOUNT P1 — {usuario}")
    else:
        action_azure_ad_force_password_reset(user=usuario)
        action_azure_ad_enforce_mfa(user=usuario)
        action_send_email(to=f"{usuario}@bancomeridian.com.br",
            subject="[SEGURANÇA] Ação necessária na sua conta corporativa",
            body="Detectamos atividade suspeita na sua conta...")
        wait_for_analyst_approval(timeout_hours=4)
        action_jira_create_issue(priority="P2",
            summary=f"COMPROMISED ACCOUNT P2 — {usuario}")

    # Passo 4: Documentação
    action_secops_get_user_timeline(user=usuario, hours=24)
    action_slack_send_message(channel="#soc-incidents",
        message=f"Case {alert.case_id}: Conta {usuario} — {prioridade}")
```

---

### 6.6 Playbook 3: Malware em Endpoint (Completo)

**O que este playbook faz e por que está estruturado assim:** Este playbook responde a detecções de malware em endpoints (T1059, T1055, T1071) — seja via alerta do EDR (CrowdStrike Falcon) ou via regra YARA-L do Google SecOps que detectou comportamento suspeito de processo. O foco é contenção imediata do host afetado para evitar movimento lateral e exfiltração, antes da análise detalhada do malware. Esta prioridade (conter primeiro, analisar depois) é a abordagem padrão de NIST SP 800-61 para incidentes de malware com potencial de propagação — o custo de conter um host legítimo é muito menor que o custo de permitir que um worm ou ransomware se propague pela rede do Banco Meridian.

**Por que o isolamento via EDR é preferido ao isolamento de rede:** O isolamento via CrowdStrike Contain mantém o agente EDR ativo e comunicando com o servidor CrowdStrike, permitindo investigação forense do host isolado (acesso a logs, processos, artefatos) sem risco de propagação. O isolamento de rede completo (bloqueio no switch) corta também a comunicação do EDR, cegando o analista. Por isso o playbook usa contain do EDR como primeiro passo — é a opção que maximiza tanto a contenção quanto a visibilidade investigativa.

**Conexão com o Lab 03 e o Lab 05:** O cenário do Lab 03 (Cobalt Strike Beacon no WRK-RODRIGO-011) e o Lab 05 (Operação Antas com WRK-MARCOS-015) são exatamente os tipos de incidente que este playbook responderia em produção. Ao concluir o Lab 03, o aluno criou a regra YARA-L que dispara este playbook; ao concluir o Lab 05, o aluno criou um playbook equivalente para o cenário de APT. Este módulo fecha o ciclo: detecção (YARA-L) → alerta → playbook → contenção → investigação → documentação.

#### Diagrama de Fluxo

```
PLAYBOOK: MALWARE EM ENDPOINT
══════════════════════════════════════════════════════════════════

  [TRIGGER: Alerta EDR / Alerta YARA-L "processo suspeito"]
         │
         ▼
  [ACTION: VT Get File Report (hash do processo)]
         │
         ▼
  [CONDITION: VT positives >= 10?]
  │
  ├── SIM ──► [CLASSIFICAR: malware confirmado]
  │
  └── NÃO ──►
         │
  [ACTION: Mandiant Get Indicator (hash)]
         │
  [CONDITION: Hash conhecido na base Mandiant?]
  │
  ├── SIM ──► [CLASSIFICAR: malware confirmado]
  │
  └── NÃO ──► [CLASSIFICAR: suspeito — revisão humana]
         │
         ▼
  [CONDITION: Malware confirmado?]
  │
  ├── SIM ──►
  │    │
  │    ▼
  │  [ACTION: EDR Contain Host (isolamento imediato)]
  │  [ACTION: EDR Run Script — coletar artefatos (mem dump, process tree)]
  │  [ACTION: Jira Create P1 Issue]
  │  [NOTIFICATION: PagerDuty P1]
  │         │
  │         ▼
  │  [ACTION: EDR Get Process Tree (processo pai e filhos)]
  │  [ACTION: EDR Get Network Connections do processo]
  │  [ACTION: EDR Get Registry Keys modificadas]
  │         │
  │         ▼
  │  [CONDITION: Conexão de rede para IP externo?]
  │  │
  │  ├── SIM ──► [ACTION: PAN Firewall Block IP (IPs externos do processo)]
  │  │           [ACTION: SecOps Create IOC (IPs detectados)]
  │  │
  │  └── NÃO ──► [documentar ausência de conexão externa]
  │         │
  │         ▼
  │  [CONDITION: Outros hosts com mesmo hash?]
  │  │
  │  ├── SIM ──► [LOOP: Contain cada host infectado]
  │  │
  │  └── NÃO ──► [prosseguir]
  │         │
  │         ▼
  │  [NOTIFICATION: Email CISO + IR Team]
  │  [ACTION: Documentar evidências no Case]
  │
  └── NÃO (suspeito) ──►
       [NOTIFICATION: Analista L2 para revisão]
       [ACTION: Jira Create P3 Issue]
       [WAIT: 2h para revisão humana]

══════════════════════════════════════════════════════════════════
```

---

### 6.7 Métricas SOAR

| Métrica                | Definição                                                          | Meta típica        |
|:-----------------------|:-------------------------------------------------------------------|:------------------:|
| **MTTD**               | Mean Time to Detect — tempo médio entre início do ataque e alerta | < 15 min           |
| **MTTR**               | Mean Time to Respond — tempo médio entre alerta e contenção        | < 1h (P1)          |
| **Automation Rate**    | % de alertas tratados sem intervenção humana                       | > 60%              |
| **False Positive Rate**| % de alertas que são FPs após triagem                              | < 10%              |
| **Case Closure Rate**  | % de cases fechados por turno                                      | > 85%              |
| **Alert Backlog**      | Volume de alertas não triados                                      | < 50 (ideal: 0)    |
| **Playbook Coverage**  | % de tipos de alerta com playbook automatizado                     | > 80%              |

---

### 6.8 Boas Práticas de Design de Playbooks

#### 6.8.1 Princípio da Modularidade

Playbooks monolíticos são difíceis de manter. Prefira sub-playbooks reutilizáveis:

```
Playbook principal: phishing_response
  ├── Sub-playbook: enrich_iocs (reutilizado em outros playbooks)
  ├── Sub-playbook: contain_user (reutilizado em conta_comprometida)
  └── Sub-playbook: create_ticket (reutilizado em todos)
```

#### 6.8.2 Tratamento de Erro

Toda Action pode falhar. Sempre trate o caso de erro:

```python
# Sempre verifique o resultado de cada Action
result = action_edr_contain_host(hostname=host)
if not result.get("success"):
    # Fallback: notificar analista manualmente
    action_pagerduty_create_incident(priority="P1",
        title=f"FALHA na contenção automática de {host}")
    action_jira_add_comment(issue_id=case.ticket_id,
        comment=f"ERRO: contenção automática falhou. Requer contenção manual.")
```

#### 6.8.3 Logging e Auditoria

Todo playbook deve registrar cada passo para fins de auditoria:

```python
# No início de cada ação significativa:
action_case_add_comment(
    case_id=case.id,
    comment=f"[{timestamp()}] Playbook: phishing_response — Etapa: contenção de {host}"
)
```

#### 6.8.4 Decisões Humanas (Human-in-the-Loop)

Para ações destrutivas ou irreversíveis, sempre inclua um bloco de aprovação:

```
Contenção de servidor crítico (ex: servidor de banco de dados)?
→ Requer aprovação do Gerente de SOC
→ Timeout de 30 minutos (se não aprovado, escalate para CISO)
→ Logging da decisão (quem aprovou, quando, por quê)
```

---

### 6.9 Integração com Ticketing: Jira e ServiceNow

O SOAR cria tickets automaticamente no sistema de ITSM do cliente, garantindo rastreabilidade:

```
TEMPLATE DE TICKET JIRA — Gerado automaticamente pelo SOAR
═══════════════════════════════════════════════════════════
Project: SEC
Issue Type: Incident
Priority: P1
Summary: PHISHING CONFIRMED — luciana.alves@bancomeridian.com.br
Labels: phishing, t1566.001, auto-created-soar
Assignee: (automaticamente para a fila do SOC)

Description:
  Case ID: CASE-2026-04-1847
  Alert Source: Email Gateway + YARA-L
  Severity: HIGH
  Detection Time: 2026-04-24 14:22:07 BRT

  Evidence:
    - Sender: proposta@parceria-bc.com (domínio criado há 2 dias)
    - Attachment: Proposta_Banco_Central.pdf (SHA256: a1b2c3...)
    - VT Score: 52/72 engines — malware: Ursnif loader
    - Recipient: luciana.alves@bancomeridian.com.br

  Actions taken:
    - [14:22:15] Hash bloqueado no EDR
    - [14:22:16] URL do C2 bloqueada no firewall
    - [14:22:17] Sessões do usuário revogadas
    - [14:22:18] Ticket criado nesta issue

  Next steps:
    - Verificar se usuário clicou no link (Timeline View)
    - Coletar artefatos do host se interação confirmada
    - Notificar usuário e gestor
═══════════════════════════════════════════════════════════
```

---

## Atividades de Fixação

### Quiz — Módulo 06

**Questão 1:** No Google SecOps SOAR, qual é a diferença entre um **Alert** e um **Case**?

- [ ] a) Alert e Case são termos intercambiáveis que designam o mesmo objeto
- [ ] b) Alert é uma instância individual de detecção; Case é o contêiner que agrega múltiplos alertas relacionados em um incidente
- [ ] c) Case é gerado automaticamente pelo SIEM; Alert é criado manualmente pelo analista
- [ ] d) Alert tem prioridade automática; Case requer que o analista defina a prioridade manualmente

**Resposta correta:** b) — Alerts são detecções individuais; Cases agrupam alertas relacionados, entidades e ações em um contexto de incidente unificado.

---

**Questão 2:** Em um playbook de resposta a phishing, qual é o principal motivo para incluir
um bloco **Wait** (aprovação humana) antes de executar o isolamento do host do usuário receptor?

- [ ] a) O SOAR não tem permissão para executar isolamento de host sem aprovação do fornecedor de EDR
- [ ] b) Isolamento de host é uma ação potencialmente disruptiva para o negócio e deve ter aprovação humana, especialmente se o host for crítico (ex: servidor de produção)
- [ ] c) O bloco Wait é obrigatório em todos os playbooks do Google SecOps
- [ ] d) O EDR precisa de tempo para completar a preparação do agente antes do isolamento

**Resposta correta:** b) — O princípio de Human-in-the-Loop protege contra automações destrutivas em sistemas críticos. Isolamento deve ser aprovado quando o impacto no negócio não está claro.

---

**Questão 3:** Qual das seguintes métricas SOAR mede especificamente a eficácia da automação
em reduzir a carga manual dos analistas?

- [ ] a) MTTD — Mean Time to Detect
- [ ] b) MTTR — Mean Time to Respond
- [ ] c) Automation Rate — percentual de alertas tratados sem intervenção humana
- [ ] d) False Positive Rate — percentual de alertas que são FPs

**Resposta correta:** c) — A Automation Rate (> 60% é a meta típica) mede diretamente quanto do trabalho de resposta foi automatizado pelo SOAR.

---

**Questão 4:** No playbook de resposta a conta comprometida do módulo, qual é a primeira
ação executada quando um alerta com prioridade P1 é classificado (IP é IOC APT conhecido)?

- [ ] a) Criar ticket no Jira com prioridade P1
- [ ] b) Notificar o CISO por e-mail
- [ ] c) Desabilitar a conta do usuário no Azure AD
- [ ] d) Revogar todas as sessões ativas do usuário (Azure AD Revoke Sessions)

**Resposta correta:** d) — Independente de P1 ou P2, a primeira ação de contenção é revogar todas as sessões ativas. Esta ação é executada para todos os casos antes da ramificação P1/P2.

---

**Questão 5:** Qual boa prática de design de playbooks permite que o mesmo código de
"enriquecimento de IOC" seja reutilizado em múltiplos playbooks diferentes (phishing,
malware, conta comprometida)?

- [ ] a) Duplicar o código em cada playbook para garantir independência entre eles
- [ ] b) Criar sub-playbooks modulares que encapsulam lógicas reutilizáveis e podem ser chamados por múltiplos playbooks pai
- [ ] c) Usar variáveis globais do SOAR compartilhadas entre todos os playbooks
- [ ] d) Não é possível reutilizar código entre playbooks no Google SecOps SOAR

**Resposta correta:** b) — Sub-playbooks são o mecanismo de modularidade do SOAR. Um sub-playbook de enriquecimento de IOC pode ser chamado por qualquer playbook que precise enriquecer indicadores.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **Este roteiro é para uso exclusivo do instrutor. As duas aulas deste módulo são altamente
> práticas — o máximo possível deve ser demonstrado ao vivo no Playbook Designer.**

---

### AULA 6.1 — Arquitetura SOAR e Actions (45 min)

---

**[ABERTURA — 3 min | Tela: Slide "SOAR — O Músculo da Resposta Automatizada"]**

"Bem-vindo ao Módulo 06. Chegamos no componente que para mim é o diferenciador real de um
SOC maduro: o SOAR.

Qualquer SIEM detecta. A questão é: depois de detectar, o que acontece? Em SOCs sem SOAR,
acontece o seguinte: o alerta aparece na fila, o analista triagem, abre 10 ferramentas
diferentes, faz cada passo manualmente, leva 45 minutos para responder a um phishing.

Com SOAR, em 45 segundos o phishing está contido, o ticket aberto, o usuário notificado,
e o analista recebeu um resumo completo. O analista ganhou 44 minutos para trabalhar em
análises complexas que a automação não consegue fazer.

Isso não é ciência ficção — é o que os clientes alcançam quando implementam SOAR corretamente."

---

**[BLOCO 1: Cases, Alerts, Entities — 10 min | Tela: Console → Cases]**

"Vamos começar pela estrutura. Vou abrir o módulo de Cases no console.

*[Navegar para Cases]*

Aqui estão os cases abertos. Um case é como um dossiê de incidente: agrega todos os alertas
relacionados, todas as entidades envolvidas (usuários, hosts, IPs), todo o histórico de ações
executadas, e o ticket no Jira associado.

Vou abrir este case aqui, do incidente de phishing...

*[Abrir um case de exemplo]*

Vejo três abas principais: Summary (visão geral), Timeline (histórico de eventos), e
Entities (objetos relevantes do incidente).

Na aba Entities, o SOAR já extraiu automaticamente das entidades: o usuário luciana.alves,
o host WRK-LUCIANA-003, o IP do servidor de phishing, o hash do PDF malicioso, o domínio
do remetente. Cada entidade já está enriquecida com dados do VirusTotal e Mandiant.

Isso é o contexto que o analista precisa para tomar decisões. Tudo num lugar só."

---

**[BLOCO 2: Actions e Connectors — 15 min | Tela: Console → Settings → Connectors]**

"Agora vamos ver de onde vem o poder do SOAR: as Actions. Vou em Settings → Connectors.

*[Navegar para Connectors]*

Aqui estão todos os conectores instalados no nosso ambiente de lab. Vejo CrowdStrike, Azure AD,
VirusTotal, Jira, PagerDuty, Slack.

Vou abrir o conector do CrowdStrike para mostrar como funciona...

*[Abrir o conector CrowdStrike]*

Cada conector tem uma lista de Actions disponíveis. Para o CrowdStrike: Contain Host, Lift Host
Containment, Run RTR Script, Get Process Tree, Get Network Connections, Search IOC...

A configuração de cada conector é simples: você insere as credenciais de API, o endpoint da
instância, e está pronto. A autenticação é armazenada com criptografia no SOAR, então o
analista nunca precisa digitar credenciais nos playbooks.

E para testar se está funcionando: botão 'Test Connection'. Verde = pronto para uso."

---

**[BLOCO 3: Criando uma Action simples ao vivo — 15 min | Tela: Playbook Designer]**

"Vamos criar um playbook simples ao vivo — só para você ver o Designer em ação.

*[Navegar para Playbooks → + New Playbook]*

Vou criar um mini-playbook que enriquece automaticamente qualquer alerta que tenha um hash
de arquivo suspeito.

*[Arrastar bloco Trigger → Action VT Get File Report → Condition → Notification]*

Um — arrasto o bloco Trigger. Configuro: 'Alert created with field file.sha256 present'.

Dois — arrasto o bloco Action. Seleciono a action 'VirusTotal — Get File Report'. No campo
'Hash', coloco a variável do alerta: `alert.fields.file.sha256`.

Três — arrasto o bloco Condition. Condição: `vt_positives >= 10`. Branch SIM e NÃO.

No branch SIM, adiciono uma Notification: 'Slack — Send Message' para o canal #soc-incidents:
'Hash malicioso detectado: {hash} — {vt_positives}/72 engines — Case: {case_id}'.

No branch NÃO, não faço nada por enquanto — o analista vai revisar.

Salvo... clico em Activate... Playbook ativo! Qualquer alerta com hash agora passa por este fluxo."

*[ORIENTAÇÕES DE PRODUÇÃO:]*
- *Mostrar o Designer ao vivo — não usar screenshots do designer*
- *Enfatizar a facilidade de uso: sem código para criar o playbook básico*
- *Gravar em ambiente de lab com dados sintéticos do Banco Meridian*

---

### AULA 6.2 — Construindo Playbooks Completos (45 min)

---

**[ABERTURA — 2 min]**

"Na Aula 6.1 você viu a estrutura do SOAR e como funcionam as Actions. Agora vamos ao que
você veio: construir playbooks completos e reais. Vou caminhar pelo playbook de resposta a
phishing do material — o mesmo que está no Lab 04 — e explicar cada decisão de design."

---

**[BLOCO 1: Walkthrough do Playbook de Phishing — 20 min | Tela: Playbook Designer]**

"Vou abrir o playbook de phishing que preparei e caminhar por cada bloco.

*[Abrir o playbook de phishing pré-construído no Designer]*

Olha a estrutura. Começa com o Trigger, depois vai para o Loop de enriquecimento de hashes,
depois Loop de enriquecimento de URLs, depois a condition central, e se bifurca em dois caminhos.

O que eu quero que você perceba aqui são as decisões de design:

Primeiro: por que usei dois loops separados — um para hashes, um para URLs — em vez de um loop
único? Porque são dois tipos de IOC diferentes que chamam Actions diferentes. Manter separado
facilita debug e manutenção.

Segundo: por que a condition 'usuário clicou no link?' antes do isolamento? Porque isolar o
host de uma usuária que só RECEBEU um phishing mas não clicou é disruptivo e desnecessário.
Só isolo se há evidência de interação.

Terceiro: por que dois paths de notificação (PagerDuty vs. só e-mail)? Porque a gravidade é
diferente. Se o usuário clicou, é P1 — precisa de resposta imediata de um analista humano.
Se não clicou, é P2 — a notificação ao usuário é suficiente e o analista revisa na fila normal.

*[Mostrar cada bloco e explicar]*

Essas são as decisões que distinguem um playbook bom de um playbook excelente. Não é só
automatizar tudo — é automatizar na medida certa, com os guardrails certos."

---

**[BLOCO 2: Métricas e Como Medir o Sucesso — 10 min]**

"Antes de fechar o módulo, vamos falar de métricas. Porque um SOAR sem métricas é um SOAR
sem evidências de valor.

As duas métricas mais importantes que você vai apresentar ao seu CISO são MTTD e MTTR.

MTTD — Mean Time to Detect. Quanto tempo passa entre o início do ataque e o primeiro alerta?
No cenário do Banco Meridian, o password spray começou às 9:02 e o alerta disparou às 9:02:14.
MTTD de 14 segundos. Excelente.

MTTR — Mean Time to Respond. Quanto tempo entre o alerta e a contenção? Com o playbook de
conta comprometida, o SOAR revogou as sessões e desabilitou a conta em menos de 30 segundos.
Antes do SOAR, esse processo manual levava em média 47 minutos.

Esse é o argumento de negócio para o SOAR: 47 minutos vs. 30 segundos. Em 47 minutos, o
atacante fez download de 47 arquivos do SharePoint. Em 30 segundos, não faz nada.

Como medir isso no Google SecOps? Dashboard → Cases → Métricas SOAR. Exportável para CSV
para relatórios executivos mensais."

---

**[RECAPITULAÇÃO FINAL — 13 min | Tela: Slide de encerramento]**

"Recapitulando o Módulo 06:

SOAR: casos → alertas → entidades → ações → playbooks. A cadeia que conecta detecção a resposta.

Três playbooks completos que você vai implementar no Lab 04: phishing, conta comprometida e
malware em endpoint.

Boas práticas: modularidade (sub-playbooks), tratamento de erro (fallback manual), Human-in-the-Loop
para ações destrutivas, logging completo para auditoria.

E métricas: MTTD, MTTR, Automation Rate são seus KPIs para demonstrar o valor operacional do SOAR.

No Lab 04, você vai criar o playbook de phishing do zero, testando com os dados reais do caso
da Luciana Alves. Depois, no Módulo 07 — o Capstone — tudo que você aprendeu nos últimos 6
módulos vai se juntar em um cenário completo de resposta a incidente. Te vejo no lab!"

---

## Avaliação do Módulo 06

### Gabarito das Questões de Múltipla Escolha

| Questão | Resposta Correta | Justificativa                                                                                  |
|:-------:|:----------------:|:-----------------------------------------------------------------------------------------------|
|    1    |       b)         | Alert = detecção individual; Case = contêiner de incidente com múltiplos alertas              |
|    2    |       b)         | Human-in-the-Loop protege contra automações destrutivas em sistemas críticos de negócio       |
|    3    |       c)         | Automation Rate mede diretamente o percentual de alertas tratados sem intervenção humana       |
|    4    |       d)         | Revogar sessões é a primeira ação de contenção, executada para todos os casos (P1 e P2)        |
|    5    |       b)         | Sub-playbooks modulares permitem reutilização de lógica comum entre múltiplos playbooks        |

### Critérios de Avaliação

| Pontuação | Resultado                                                                             |
|:---------:|:--------------------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 07 — Capstone                                      |
| 4/5 (80%) | Muito bom! Revise o tópico da questão errada antes de avançar para o capstone        |
| 3/5 (60%) | Recomendado executar o Lab 04 antes de avançar para consolidar os conceitos práticos  |
| < 3 (< 60%)| Revisite as seções 6.1–6.4 — design de playbooks é central para o Capstone (Módulo 07)|

---

*Módulo 06 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 05 — Threat Intelligence](../modulo-05-threat-intelligence/README.md)*
*Próximo: [Módulo 07 — Capstone](../modulo-07-capstone/README.md)*
