# Lab 04 — Playbook SOAR: Resposta Automatizada a Phishing
## Curso 1: Google SecOps Essentials · CECyber

| Campo                | Detalhe                                                                |
|:---------------------|:-----------------------------------------------------------------------|
| **Duração**          | 2 horas                                                                |
| **Módulo relacionado**| Módulo 06 — SOAR e Playbooks                                          |
| **Tipo**             | Hands-on · Individual                                                  |
| **MITRE ATT&CK**     | T1566.001 (Phishing: Spearphishing Attachment)                         |
| **Pré-requisito**    | Módulo 06 concluído · Lab 02 e Lab 03 concluídos                       |
| **Ferramentas**      | Google SecOps SOAR, Playbook Designer, VirusTotal, Azure AD, Jira      |

---

## 1. Contexto Situacional

Era uma manhã de terça-feira no Banco Meridian. O helpdesk tinha acabado de abrir o turno
quando uma ligação entrou: **Luciana Alves**, gerente de contas da agência Paulista, estava
preocupada. Ela havia recebido às 08:47 um e-mail com o assunto "Proposta de Parceria —
Banco Central" de um remetente desconhecido. O e-mail tinha um PDF em anexo — "Proposta_BC_Abr2026.pdf".
Luciana havia aberto o PDF, que exibiu um documento aparentemente legítimo do Banco Central.
Mas logo depois, seu notebook começou a ficar lento, e aplicativos demorando para abrir.

O helpdesk abriu o ticket #HD-2026-04-9871 e notificou o SOC às 09:15. O analista L1 Carlos
verificou o ticket, identificou que havia abertura de PDF suspeito e escalou para o time L2.

**Você é o analista L2.** Sua missão não é apenas investigar e conter este incidente —
é criar um **playbook SOAR automatizado** que garanta que o próximo caso de phishing
seja respondido em segundos, não em minutos.

Ao terminar este lab, o playbook que você criou estará ativo e responderá automaticamente
a todos os próximos casos de phishing no Banco Meridian.

---

## 2. Situação Inicial

O ambiente de lab está configurado da seguinte forma:

```
ESTADO DO AMBIENTE BANCO MERIDIAN — LAB 04
════════════════════════════════════════════════════════════════════

  Google SecOps SOAR:
  ─────────────────────────────────────────────
  Connectors disponíveis:
    ✅ VirusTotal Enterprise     → CONNECTED
    ✅ Azure AD / Entra ID       → CONNECTED
    ✅ CrowdStrike Falcon EDR    → CONNECTED
    ✅ Palo Alto NGFW            → CONNECTED
    ✅ Jira Software             → CONNECTED
    ✅ PagerDuty                 → CONNECTED
    ✅ Email (SMTP Gmail)        → CONNECTED

  Cases existentes:
  ─────────────────────────────────────────────
  CASE-2026-04-001  HIGH  NEW  "Phishing report — Luciana Alves"
    Alert source: Email Gateway Report (helpdesk ticket)
    Principal: luciana.alves@bancomeridian.com.br
    Host: WRK-LUCIANA-003
    Attachment: Proposta_BC_Abr2026.pdf
    SHA256: 3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d

════════════════════════════════════════════════════════════════════
```

---

## 3. Problema Identificado

O Gerente de SOC, Rodrigo Saraiva, apresentou o problema estratégico:

*"Pessoal, em 2025 o Banco Meridian respondeu a 47 incidentes de phishing. O tempo médio de
resposta foi de 47 minutos, com o pior caso chegando a 3 horas e 20 minutos. Nesse tempo, os
atacantes tiveram toda a oportunidade de se mover lateralmente. Nosso objetivo com o SOAR é
chegar a um MTTR de 2 minutos para phishing. Isso só é possível se o playbook fizer
automaticamente: enriquecimento de IOCs, verificação se o usuário clicou no link, contenção
do host se necessário, notificação e ticket. Hoje você vai criar esse playbook."*

---

## 4. Roteiro de Atividades

| Etapa | Atividade                                             | Tempo estimado |
|:-----:|:------------------------------------------------------|:--------------:|
| A     | Investigar o caso manualmente antes de automatizar    | 20 min         |
| B     | Criar o playbook no Playbook Designer                 | 60 min         |
| C     | Testar o playbook com o caso da Luciana Alves         | 20 min         |
| D     | Medir o MTTR e documentar                             | 10 min         |
| E     | Ativar o playbook e criar documentação                | 10 min         |

---

## 5. Proposição do Lab

**Objetivo:** Criar um playbook SOAR completo para resposta automatizada a phishing que
reduza o MTTR de 47 minutos para menos de 2 minutos.

**Critério de sucesso:**
- Playbook criado e ativo no Google SecOps SOAR
- Playbook testado com o caso da Luciana Alves e todos os steps executados com sucesso
- MTTR medido e documentado
- Playbook cobre os 6 cenários de decisão do fluxo (seção 6.2 do Módulo 06)

---

## 6. Script Passo a Passo

### PARTE A — Investigar o Caso Manualmente (20 min)

---

#### Passo 1: Abrir o case de phishing e examinar as evidências

**Ação:** Navegar para o painel de Cases do SOAR e abrir o caso da Luciana Alves.

```
Navegação: SOAR → Cases → buscar CASE-2026-04-001

Campos a verificar na aba Summary:
- Alert source: Email Gateway Report
- Severity: HIGH
- Status: NEW
- Entities detectadas: luciana.alves, WRK-LUCIANA-003, hash do PDF, e-mail do remetente
```

**Resultado esperado:** Tela do case mostrando alertas, entidades e a aba Timeline vazia
(nenhuma ação executada ainda).

**O que verificar:** Confirme que o conector do VirusTotal está ativo — você vai usá-lo
no próximo passo.

---

#### Passo 2: Verificar o hash do PDF no VirusTotal manualmente

**Ação:** Antes de criar o playbook, faça a verificação manual para entender o que o
playbook vai automatizar.

```
Navegação: Threat Intelligence → VirusTotal → buscar hash
3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d
```

**Resultado esperado:**

```
File: Proposta_BC_Abr2026.pdf
SHA256: 3c4d5e6f...
Detection: 38/72 engines
Threat category: trojan-downloader
Threat name: PDF/Phishing.CertificadoBC.2026
First seen: 2026-04-20 (4 dias atrás)
Behavior (sandbox):
  - Cria arquivo: %TEMP%\bc_cert_helper.exe
  - Faz conexão: 45.77.123.89:443
  - Adiciona chave de registro: HKCU\Software\Microsoft\Windows\Run
```

**O que registrar:** O PDF é definitivamente malicioso (38/72). Instala um downloader e
configura persistência. Isso confirma que se Luciana abriu o PDF, o host WRK-LUCIANA-003
está comprometido.

---

#### Passo 3: Verificar se Luciana clicou/abriu o PDF via logs do EDR

**Ação:** Buscar no UDM Search por eventos de abertura do arquivo no host de Luciana.

```
Navegação: Search → UDM Search

Query:
principal.hostname = "WRK-LUCIANA-003" AND
(
  metadata.event_type = "FILE_READ" OR
  metadata.event_type = "PROCESS_LAUNCH"
) AND
(
  target.file.full_path = /.*Proposta_BC_Abr2026\.pdf/ OR
  principal.process.file.full_path = /.*AcroRd32\.exe/
)
```

**Resultado esperado:**

```
Timestamp: 2026-04-24T08:47:33Z
event_type: PROCESS_LAUNCH
principal.process.file.full_path: C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroRd32.exe
target.process.command_line: "AcroRd32.exe" "C:\Users\luciana.alves\Downloads\Proposta_BC_Abr2026.pdf"

Timestamp: 2026-04-24T08:47:51Z
event_type: PROCESS_LAUNCH
principal.process.file.full_path: C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroRd32.exe
target.process.file.full_path: C:\Windows\Temp\bc_cert_helper.exe   ← DROPPER!
```

**O que registrar:** Confirmado. Luciana abriu o PDF, o Adobe Reader executou o dropper
`bc_cert_helper.exe`. O host está comprometido. A resposta deve incluir isolamento.

---

#### Passo 4: Verificar o e-mail do remetente

**Ação:** Examinar os metadados do e-mail para identificar o remetente real.

```
Query:
principal.user.email_addresses = "luciana.alves@bancomeridian.com.br" AND
metadata.event_type = "EMAIL_TRANSACTION" AND
metadata.event_timestamp >= "2026-04-24T08:40:00Z"
```

**Resultado esperado:**

```
metadata.event_type: EMAIL_TRANSACTION
target.user.email_addresses: luciana.alves@bancomeridian.com.br
principal.user.email_addresses: "proposta@banco-central-br.com"    ← Domínio falso!
network.email.subject: "Proposta de Parceria — Banco Central"
network.email.attachment_sha256: 3c4d5e6f...
```

**O que registrar:** O remetente real é `proposta@banco-central-br.com` — domínio falso que
imita o Banco Central (`bcb.gov.br`). Este domínio deve ser bloqueado no gateway de e-mail.

---

### PARTE B — Criar o Playbook no Playbook Designer (60 min)

---

#### Passo 5: Criar um novo playbook

**Ação:** Navegar para o Playbook Designer e criar o playbook de phishing.

```
Navegação: SOAR → Playbooks → + New Playbook

Configurações:
  - Nome: phishing_response_automatizado
  - Descrição: Resposta automatizada a e-mails de phishing com PDF ou link malicioso
  - Trigger: Case created with type = "Email Phishing Report"
  - Priority: HIGH
  - Active: No (vamos ativar após os testes)
```

**Resultado esperado:** Editor de playbook em branco com o bloco Trigger já inserido.

---

#### Passo 6: Adicionar o bloco de extração de variáveis do alert

**Ação:** Adicionar o primeiro bloco Action para extrair os dados do alert.

```
No Designer, arrastar o bloco: Action → Set Variable

Configuração do bloco:
  Nome: "Extrair dados do alerta"
  Variáveis a definir:
    $attachment_hash = alert.fields["attachment_sha256"]
    $sender_email = alert.fields["sender_email"]
    $recipient = alert.fields["recipient_email"]
    $recipient_host = alert.fields["principal_hostname"]
    $case_id = case.id
```

**Resultado esperado:** Bloco de variáveis conectado ao Trigger. As variáveis estarão
disponíveis para todos os blocos subsequentes.

---

#### Passo 7: Adicionar o bloco de enriquecimento via VirusTotal

**Ação:** Adicionar a Action de consulta ao VirusTotal.

```
Arrastar: Action → VirusTotal — Get File Report

Configuração:
  Nome: "Verificar hash no VirusTotal"
  Input: hash = $attachment_hash
  Output variables:
    $vt_positives = result.positives
    $vt_total = result.total
    $vt_threat_name = result.threat_name
    $vt_malicious = result.malicious     ← true se positives >= 5
```

**Resultado esperado:** Bloco de VirusTotal conectado ao bloco de variáveis. O fluxo
executa: Trigger → Extrair variáveis → Consultar VirusTotal.

---

#### Passo 8: Adicionar o bloco de decisão baseado no resultado do VT

**Ação:** Adicionar o bloco Condition para bifurcar o fluxo baseado no resultado VT.

```
Arrastar: Condition

Configuração:
  Nome: "Hash é malicioso?"
  Condição: $vt_positives >= 10
  Branch SIM: (continua para contenção)
  Branch NÃO: (consulta Mandiant TI como segundo recurso)
```

**Nota:** No branch NÃO, adicionar um segundo bloco Action de consulta à Mandiant:

```
Action → Mandiant — Get Indicator

Configuração:
  Nome: "Verificar hash na Mandiant TI"
  Input: indicator = $attachment_hash
  Output: $mandiant_confidence = result.confidence
          $mandiant_known = (result.confidence != "NONE")
```

Após a consulta Mandiant, adicionar outro Condition:

```
Condition:
  Nome: "Mandiant conhece o hash?"
  Condição: $mandiant_known == true
  Branch SIM → mesma ação de contenção
  Branch NÃO → escalar para analista (bloco Notification)
```

**Resultado esperado:** Fluxo ramificado com dois caminhos de detecção antes de decidir
sobre contenção.

---

#### Passo 9: Adicionar os blocos de contenção (Branch: malicioso confirmado)

**Ação:** No branch de malicioso confirmado, adicionar os blocos de contenção em sequência.

```
Bloco 1 — Bloquear URL de C2 no firewall:
  Action → Palo Alto NGFW — Block URL
  Input: url_list = [$c2_url]  ← extraída do sandbox VT
  Nome: "Bloquear URL de C2 no firewall"

Bloco 2 — Criar IOC customizado no SecOps:
  Action → Google SecOps — Create Custom IOC
  Input: indicator = $attachment_hash
         type = "file_hash"
         confidence = "HIGH"
         description = "Hash phishing — " + $case_id
  Nome: "Registrar hash como IOC interno"

Bloco 3 — Verificar se usuário abriu o PDF:
  Action → Google SecOps UDM Search
  Query: principal.hostname = $recipient_host
         AND metadata.event_type = "PROCESS_LAUNCH"
         AND principal.process.file.full_path = /.*AcroRd32.exe.*/
         AND target.process.command_line = /.*\.pdf/
  Output: $user_opened_pdf = (result.count > 0)
  Nome: "Verificar interação do usuário com o PDF"
```

**Resultado esperado:** Três blocos de ação conectados no branch de malicioso confirmado.

---

#### Passo 10: Adicionar a decisão de isolamento (interação confirmada)

**Ação:** Adicionar Condition para verificar se o usuário abriu o PDF.

```
Condition:
  Nome: "Usuário abriu o PDF?"
  Condição: $user_opened_pdf == true

Branch SIM (comprometimento confirmado):
  Bloco: CrowdStrike — Contain Host
    Input: hostname = $recipient_host
    Nome: "Isolar host no EDR"

  Bloco: Azure AD — Revoke Sessions
    Input: user = $recipient
    Nome: "Revogar sessões Azure AD"

  Bloco: PagerDuty — Create Incident
    Input: priority = "P1"
           title = "PHISHING CONFIRMADO: " + $recipient + " — host comprometido"
           body = "Hash: " + $attachment_hash + " | Host: " + $recipient_host
    Nome: "Disparar alerta P1 no PagerDuty"

  Bloco: Jira — Create Issue
    Input: project = "SEC"
           priority = "P1"
           summary = "PHISHING P1 — " + $recipient
           labels = ["phishing", "t1566.001", "host-comprometido"]
    Nome: "Abrir ticket P1 no Jira"

Branch NÃO (PDF não aberto — notificação preventiva):
  Bloco: Email — Send Email
    Input: to = $recipient
           subject = "[SEGURANÇA] E-mail de phishing identificado"
           body = "Identificamos um e-mail de phishing enviado para você..."
    Nome: "Notificar usuário — phishing não clicado"

  Bloco: Email — Block Sender Domain
    Input: domain = (extract domain from $sender_email)
    Nome: "Bloquear domínio do remetente no gateway"

  Bloco: Jira — Create Issue
    Input: priority = "P2"
           summary = "PHISHING P2 — " + $recipient + " (sem interação)"
    Nome: "Abrir ticket P2 no Jira"
```

**Resultado esperado:** Fluxo completo de contenção ou notificação dependendo da interação
do usuário com o PDF.

---

#### Passo 11: Adicionar o bloco de notificação do SOC (para todos os caminhos)

**Ação:** No final de todos os branches, adicionar notificação ao canal do SOC.

```
Bloco: Slack — Send Message (ou Email para o canal de SOC)
  Input: channel = "#soc-incidents"
         message = "Case " + $case_id + ": Phishing respondido automaticamente.
                    Recipient: " + $recipient + "
                    Hash: " + $attachment_hash + "
                    VT positives: " + $vt_positives + "/" + $vt_total + "
                    Ação tomada: " + (if $user_opened_pdf then "CONTENÇÃO P1" else "NOTIFICAÇÃO P2")
  Nome: "Notificar time SOC via Slack"
```

---

#### Passo 12: Verificar o playbook completo e salvar

**Ação:** Revisar o fluxo completo no Designer antes de salvar.

**Checklist de verificação:**

- [ ] Trigger configurado para alertas de phishing
- [ ] Bloco de extração de variáveis com os 5 campos necessários
- [ ] Bloco VirusTotal com output de `$vt_positives` e `$vt_malicious`
- [ ] Condition "Hash malicioso?" com branches SIM e NÃO
- [ ] Branch NÃO inclui consulta à Mandiant com seu próprio Condition
- [ ] Branch malicioso: bloquear URL, criar IOC, verificar interação
- [ ] Condition "Usuário abriu o PDF?" com branches SIM e NÃO
- [ ] Branch SIM: EDR contain + revogar sessões + PagerDuty P1 + Jira P1
- [ ] Branch NÃO: notificar usuário + bloquear domínio + Jira P2
- [ ] Notificação final para canal #soc-incidents em todos os caminhos

**Ação:** Clicar em "Save" no topo do Designer.

**Resultado esperado:** Mensagem "Playbook saved successfully". Status: "Inactive" (intencional).

---

### PARTE C — Testar o Playbook com o Caso da Luciana Alves (20 min)

---

#### Passo 13: Executar o playbook manualmente no case de teste

**Ação:** Executar o playbook manualmente no case CASE-2026-04-001 para testar.

```
Navegação: Cases → CASE-2026-04-001 → Actions → Run Playbook
Selecionar: phishing_response_automatizado
Modo: Manual (single run)
```

**Resultado esperado:** O playbook começa a executar. No painel de execução, você vê cada
bloco sendo executado em tempo real com o status (verde = sucesso, vermelho = erro).

**Tempo esperado de execução:** 15–45 segundos (dependendo da latência das APIs externas).

---

#### Passo 14: Verificar o resultado de cada step do playbook

**Ação:** Após a execução, verificar o log de cada step na aba "Timeline" do case.

```
Navegação: Cases → CASE-2026-04-001 → aba Timeline

Verificar:
1. "Extrair dados do alerta" → SUCCESS
2. "Verificar hash no VirusTotal" → SUCCESS | $vt_positives = 38
3. "Hash é malicioso?" → SIM (38 >= 10)
4. "Bloquear URL de C2 no firewall" → SUCCESS
5. "Registrar hash como IOC interno" → SUCCESS
6. "Verificar interação do usuário com o PDF" → SUCCESS | $user_opened_pdf = true
7. "Usuário abriu o PDF?" → SIM
8. "Isolar host no EDR" → SUCCESS | WRK-LUCIANA-003 CONTAINED
9. "Revogar sessões Azure AD" → SUCCESS | luciana.alves REVOKED
10. "Disparar alerta P1 no PagerDuty" → SUCCESS | Incident #PD-1847 criado
11. "Abrir ticket P1 no Jira" → SUCCESS | SEC-4891 criado
12. "Notificar time SOC via Slack" → SUCCESS
```

**O que verificar:**
- Todos os 12 steps devem ser SUCCESS
- O host WRK-LUCIANA-003 deve aparecer como "Contained" no painel do CrowdStrike
- O ticket P1 deve aparecer criado no Jira
- O canal #soc-incidents do Slack deve ter recebido a notificação

**O que fazer se algum step falhar:**
- Step VT falha: verificar credenciais do conector VT em Settings → Connectors
- Step EDR falha: verificar se o hostname está correto (case-sensitive em alguns EDRs)
- Step Jira falha: verificar se o projeto "SEC" existe no Jira e as permissões da API key

---

### PARTE D — Medir o MTTR e Documentar (10 min)

---

#### Passo 15: Calcular o MTTR do caso manual vs. automatizado

**Ação:** Comparar o tempo de resposta manual (histórico) com o tempo do playbook.

```
MTTR calculado:

Incidente reportado:    08:47 (Luciana abre o PDF)
Helpdesk abre ticket:   09:15 (28 min depois)
SOC recebe e triagem:   09:22 (7 min depois)
Análise manual completa: 10:04 (42 min de análise)
Contenção manual:       10:09 (5 min para executar as ações)
─────────────────────────────────────────────────────────────
MTTR manual total:      82 minutos (do incidente à contenção)

Com o playbook SOAR:
Helpdesk abre ticket e       09:15
playbook é ativado:
Playbook executa:            09:15:38
                             (38 segundos de execução)
─────────────────────────────────────────────────────────────
MTTR com SOAR:               28 minutos (limitado pelo tempo do helpdesk)
MTTR do SOAR em si:          38 segundos (da criação do case à contenção)

Melhoria:  82 min → 38 seg (redução de 99.2% no tempo de resposta do SOAR)
```

**O que verificar:** O timestamp de cada step está no log de execução do playbook.
Calcule o delta entre o primeiro step e o último step de contenção.

---

### PARTE E — Ativar o Playbook e Criar Documentação (10 min)

---

#### Passo 16: Ativar o playbook para operação em produção

**Ação:** Após os testes bem-sucedidos, ativar o playbook.

```
Navegação: SOAR → Playbooks → phishing_response_automatizado
Botão: "Activate"

Configuração de trigger automático:
  Alert Type: "Email Phishing Report"
  Trigger automatically: YES
  Priority threshold: MEDIUM and above
```

**Resultado esperado:** Status do playbook muda para "Active". O playbook agora será
executado automaticamente para cada novo alerta de phishing.

---

#### Passo 17: Criar documentação do playbook

**Ação:** Criar o arquivo de documentação do playbook.

```bash
cat > ~/lab-04-playbook-doc.md << 'EOF'
# Documentação do Playbook: phishing_response_automatizado
# Criado em: 2026-04-24
# Criado por: [seu nome]
# Versão: 1.0

## Objetivo
Automatizar a resposta a incidentes de phishing com PDF ou link malicioso,
reduzindo o MTTR de 82 minutos para menos de 2 minutos.

## Trigger
Alert type: "Email Phishing Report" — gerado pelo Email Gateway (Proofpoint)
quando um usuário reporta um e-mail suspeito ou quando o gateway bloqueia
um e-mail com attachment malicioso.

## Fluxo de decisão
1. Extrai IOCs do alerta (hash, sender, recipient, host)
2. Verifica hash no VirusTotal (threshold: >= 10 detecções)
3. Se VT não identifica → consulta Mandiant TI
4. Se malicioso confirmado:
   a. Bloqueia URLs de C2 no NGFW
   b. Cria IOC customizado no SecOps
   c. Verifica se usuário abriu o PDF (UDM Search)
   d. Se abriu: isola host + revoga sessões + P1
   e. Se não abriu: notifica usuário + bloqueia domínio + P2
5. Notifica canal #soc-incidents com resumo

## Métricas (baseline 2026-04-24)
- MTTR do playbook: 38 segundos
- Taxa de automação: 100% (sem intervenção humana para P2; escalate humano para P1)
- Cobertura: phishing com attachment PDF/Office

## Limitações conhecidas
- Não cobre phishing somente com link (sem attachment)
- Não cobre e-mails de BEC (Business Email Compromise) sem malware
- O isolamento de host requer que o agente CrowdStrike esteja ativo e conectado

## Versões
v1.0 — 2026-04-24: criação inicial (Lab 04)
EOF
```

**Resultado esperado:** Documentação criada e salva.

---

## 7. Objetivos por Etapa

| Etapa | Parte do Lab         | Objetivo                                                              | Critério de Conclusão                                                    |
|:-----:|:---------------------|:----------------------------------------------------------------------|:-------------------------------------------------------------------------|
| A     | Investigação manual  | Entender o caso de phishing antes de automatizar                      | Hash confirmado malicioso no VT; interação do usuário confirmada         |
| B     | Criação do playbook  | Construir o playbook completo com todos os blocos e ramificações      | Playbook salvo sem erros; todos os 12 steps presentes                    |
| C     | Teste do playbook    | Verificar que o playbook executa corretamente com dados reais         | Todos os 12 steps com status SUCCESS no log de execução                  |
| D     | Métricas MTTR        | Medir e documentar a redução do MTTR com a automação                  | MTTR calculado e comparado (manual vs. SOAR)                             |
| E     | Ativação             | Colocar o playbook em produção para futuros alertas de phishing       | Status "Active"; trigger automático configurado; documentação criada     |

---

## 8. Gabarito Completo

### Gabarito — Resultado da Investigação Manual

| Campo                    | Valor                                                          |
|:-------------------------|:---------------------------------------------------------------|
| Hash do PDF              | `3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d...`                |
| VT Detections            | 38/72 engines — PDF/Phishing.CertificadoBC.2026               |
| Remetente real           | `proposta@banco-central-br.com` (domínio falso)               |
| Usuário interagiu?       | SIM — AcroRd32.exe abriu o PDF e executou bc_cert_helper.exe   |
| Dropper instalado        | `C:\Windows\Temp\bc_cert_helper.exe`                          |
| IP de C2 (sandbox VT)    | `45.77.123.89:443`                                             |
| Ação necessária          | Isolamento do host WRK-LUCIANA-003 + revogação de sessões      |

**Por que esse resultado confirma que deu certo:**
- 38/72 detecções no VT é uma confirmação inequívoca de arquivo malicioso. O threshold do
  playbook (>= 10 detecções) garante que não haverá falsos positivos por arquivos com 1 ou
  2 detecções duvidosas — que frequentemente são FPs de engines pouco confiáveis.
- O dropper em `%TEMP%` é o comportamento mais característico de phishing com exploit:
  o payload é sempre depositado em diretório temporário para evitar necessidade de
  privilégios administrativos. Essa localização é um IoC por si só.
- O AcroRd32.exe lançando um executável em %TEMP% é a assinatura do exploit Adobe Reader
  — processo legítimo gerando processo filho em localização anômala.

**Variações aceitáveis:**
- O número de detecções VT pode variar (30–45) dependendo de quando o hash foi submetido ao VT
- O dropper pode ter nome diferente em variantes da campanha (`cert_helper.exe`, `bcb_attach.exe`)
- O IP de C2 pode ter mudado — o hash do dropper é o IOC mais estável para IOC customizado

### Gabarito — Playbook Completo (Pseudocódigo)

O playbook completo está descrito nos passos 5–12 deste lab. A estrutura final deve ter:

- 12 blocos de ação/condição
- 3 blocos de Condition (hash malicioso? / Mandiant conhece? / usuário abriu?)
- 2 branches paralelos (P1 comprometido / P2 preventivo)
- 1 bloco de notificação final ao SOC

### Gabarito — MTTR Esperado

| Métrica                  | Antes do SOAR  | Com o SOAR     | Melhoria |
|:-------------------------|:--------------:|:--------------:|:--------:|
| MTTR total do incidente  | 82 minutos     | 28 minutos*    | -66%     |
| Tempo de execução SOAR   | N/A            | 38 segundos    | —        |
| Ações manuais necessárias| 12 ações       | 0 (P2) / 2 (P1†) | -80%  |

*28 min = tempo de helpdesk abrir ticket (não eliminável sem integração direta)
†P1 requer apenas aprovação do analista — não execução manual

### Gabarito — Erros Comuns e Soluções

| Erro                                              | Causa                                     | Solução                                                |
|:--------------------------------------------------|:------------------------------------------|:-------------------------------------------------------|
| Step VT retorna `$vt_positives = null`            | Hash não encontrado no VT (arquivo novo)  | Adicionar tratamento de null: `if $vt_positives == null → $vt_malicious = false` |
| Step EDR contain falha com "Host not found"       | Hostname com capitalização diferente       | Normalizar hostname com `.lower()` antes do contain    |
| Step Jira falha com "Permission denied"           | API key sem permissão para criar Issues    | Verificar permissões do projeto SEC no Jira            |
| Playbook não dispara automaticamente              | Trigger type incorreto                    | Verificar se o alert type é exatamente "Email Phishing Report" |
| Host isolado mas sessões ainda ativas             | Azure AD revoke tem delay de até 5 min    | Normal — adicionar wait de 5 min antes de verificar    |

---

*Lab 04 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 06 — SOAR e Playbooks](../../modulos/modulo-06-soar-playbooks/README.md)*
*Anterior: [Lab 03 — Hunting C2 Beaconing](../lab-03-hunting-c2-beaconing/README.md)*
*Próximo: [Lab 05 — Capstone](../lab-05-capstone/README.md)*
