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
════════════════════════════════════════════════════════════════════════════════

  Google SecOps SOAR:
  ─────────────────────────────────────────────────────────────────────────
  Connectors disponíveis:
    ✅ VirusTotal Enterprise     → CONNECTED
    ✅ Azure AD / Entra ID       → CONNECTED
    ✅ CrowdStrike Falcon EDR    → CONNECTED
    ✅ Palo Alto NGFW            → CONNECTED
    ✅ Jira Software             → CONNECTED
    ✅ PagerDuty                 → CONNECTED
    ✅ Email (SMTP Gmail)        → CONNECTED

  Cases existentes:
  ─────────────────────────────────────────────────────────────────────────
  CASE-2026-04-001  HIGH  NEW  "Phishing report — Luciana Alves"
    Alert source: Email Gateway Report (helpdesk ticket)
    Principal: luciana.alves@bancomeridian.com.br
    Host: WRK-LUCIANA-003
    Attachment: Proposta_BC_Abr2026.pdf
    SHA256: 3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d

════════════════════════════════════════════════════════════════════════════════
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

**O que este passo faz:** Abre o case CASE-2026-04-001 no painel SOAR e examina as entidades automaticamente extraídas: usuário, host, hash do arquivo malicioso e e-mail do remetente. Esta investigação manual é a base do playbook — você precisa entender o fluxo de investigação humano antes de automatizá-lo. O que você faz manualmente nesta parte A, o playbook fará em segundos na parte B.

**Por que agora:** Criar o playbook sem investigar o caso manualmente primeiro é o erro mais comum neste lab. Sem entender as decisões que o analista precisa tomar (o hash é malicioso? o usuário abriu o arquivo? o host está comprometido?), o playbook será incompleto e perderá cenários críticos. A investigação manual define os requisitos funcionais do playbook.

```
Navegação: SOAR → Cases → buscar CASE-2026-04-001

Campos a verificar na aba Summary:
- Alert source: Email Gateway Report
- Severity: HIGH
- Status: NEW
- Entities detectadas: luciana.alves, WRK-LUCIANA-003, hash do PDF, e-mail do remetente
```

**O que você deve ver:** Tela do case mostrando alertas, entidades e a aba Timeline vazia (nenhuma ação executada ainda). Confirme que o conector do VirusTotal está ativo — você vai usá-lo no próximo passo.

---

#### Passo 2: Verificar o hash do PDF no VirusTotal manualmente

**O que este passo faz:** Envia o SHA256 do arquivo `Proposta_BC_Abr2026.pdf` ao VirusTotal e interpreta o resultado de detecção. Esta verificação manual demonstra o fluxo que o playbook vai automatizar — uma verificação que leva o analista 2-3 minutos para fazer manualmente será feita em 3 segundos pelo SOAR.

**Por que agora:** A verificação do hash no VirusTotal é o ponto de bifurcação principal do playbook — o resultado determina se o incidente é uma ameaça real ou um falso positivo. Entender os campos retornados pelo VT (positives, total, threat_name, sandbox behavior) é essencial para configurar o bloco de VirusTotal no playbook corretamente.

```
Navegação: Threat Intelligence → VirusTotal → buscar hash
3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d
```

**O que você deve ver:**

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

O PDF é definitivamente malicioso (38/72). Instala um downloader e configura persistência. O URL de C2 identificado no sandbox (`45.77.123.89`) deve ser bloqueado imediatamente no NGFW — este será o primeiro bloco de contenção do playbook.

---

#### Passo 3: Verificar se Luciana clicou/abriu o PDF via logs do EDR

**O que este passo faz:** Busca nos logs do EDR (via UDM Search) por eventos de abertura do arquivo PDF e execução de processos suspeitos no host de Luciana. Esta verificação é o segundo ponto de bifurcação do playbook — a resposta determina se a ação necessária é contenção completa (host comprometido) ou apenas notificação preventiva (PDF recebido mas não aberto).

**Por que agora:** A decisão de isolar o host WRK-LUCIANA-003 da rede depende desta confirmação. Isolar um host sem confirmação de comprometimento causa impacto desnecessário ao negócio — Luciana é gerente de contas e o banco perde acesso aos sistemas core banking. Com confirmação técnica, a decisão de isolamento é justificada e documentada.

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

**O que você deve ver:**

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

Confirmado. Luciana abriu o PDF, o Adobe Reader executou o dropper `bc_cert_helper.exe`. O host está comprometido. A resposta deve incluir isolamento imediato do host.

---

#### Passo 4: Verificar o e-mail do remetente

**O que este passo faz:** Examina os metadados completos do e-mail no UDM Search para identificar o remetente real e confirmar que o domínio é falso. Esta informação alimenta o bloco de bloqueio de domínio no gateway de e-mail — uma das ações preventivas mais importantes do playbook para proteger outros funcionários do Banco Meridian.

**Por que agora:** O domínio falso identificado aqui deve ser bloqueado IMEDIATAMENTE no gateway para que nenhum outro funcionário receba e-mail do mesmo domínio fraudulento. Quanto mais cedo o domínio for identificado, menos vítimas adicionais haverá.

```
Query:
principal.user.email_addresses = "luciana.alves@bancomeridian.com.br" AND
metadata.event_type = "EMAIL_TRANSACTION" AND
metadata.event_timestamp >= "2026-04-24T08:40:00Z"
```

**O que você deve ver:**

```
metadata.event_type: EMAIL_TRANSACTION
target.user.email_addresses: luciana.alves@bancomeridian.com.br
principal.user.email_addresses: "proposta@banco-central-br.com"    ← Domínio falso!
network.email.subject: "Proposta de Parceria — Banco Central"
network.email.attachment_sha256: 3c4d5e6f...
```

O remetente real é `proposta@banco-central-br.com` — domínio falso que imita o Banco Central (`bcb.gov.br`). Anote o domínio — ele será a variável `$sender_domain` no playbook para a ação de bloqueio no gateway.

---

### PARTE B — Criar o Playbook no Playbook Designer (60 min)

---

#### Passo 5: Criar um novo playbook

**O que este passo faz:** Abre o Playbook Designer do Google SecOps SOAR e cria o esqueleto do playbook com o trigger correto. O trigger determina quando o playbook será executado automaticamente — alertas do tipo "Email Phishing Report" com qualquer severidade acima de MEDIUM ativarão o playbook imediatamente após a criação do case.

**Por que agora:** A configuração correta do trigger é o que garante que o playbook seja executado no momento certo. Um trigger mal configurado (ex: severity threshold muito alto) fará o playbook ignorar alertas de phishing de severidade MEDIUM — que são a maioria dos casos que deveriam ser automatizados.

```
Navegação: SOAR → Playbooks → + New Playbook

Configurações:
  - Nome: phishing_response_automatizado
  - Descrição: Resposta automatizada a e-mails de phishing com PDF ou link malicioso
  - Trigger: Case created with type = "Email Phishing Report"
  - Priority: HIGH
  - Active: No (vamos ativar após os testes)
```

**O que você deve ver:** Editor de playbook em branco com o bloco Trigger já inserido. Status "Inactive" é intencional.

---

#### Passo 6: Adicionar o bloco de extração de variáveis do alert

**O que este passo faz:** Adiciona o primeiro bloco Action que extrai os dados essenciais do alert e os armazena em variáveis reutilizáveis por todos os blocos subsequentes. Sem esta extração, cada bloco precisaria referenciar os campos do alert diretamente com caminhos longos e propensos a erros — as variáveis tornam o playbook mais legível e manutenível.

**Por que agora:** A extração de variáveis deve ser o primeiro bloco após o Trigger porque todos os outros blocos dependem dessas variáveis. Um hash de attachment não extraído neste passo tornará impossível a consulta ao VirusTotal no Passo 7.

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

**O que você deve ver:** Bloco de variáveis conectado ao Trigger. As variáveis estarão disponíveis para todos os blocos subsequentes.

---

#### Passo 7: Adicionar o bloco de enriquecimento via VirusTotal

**O que este passo faz:** Adiciona o bloco de consulta automática ao VirusTotal que verifica o hash do attachment e retorna as métricas de detecção. Este bloco automatiza o Passo 2 da investigação manual — o que levava 2-3 minutos agora acontece em 3 segundos e o resultado é disponibilizado como variáveis para o bloco de decisão seguinte.

**Por que agora:** O bloco VirusTotal deve ser colocado imediatamente após a extração de variáveis, pois o resultado ($vt_positives) é o input do bloco de decisão do Passo 8.

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

**O que você deve ver:** Bloco de VirusTotal conectado ao bloco de variáveis. Fluxo executa: Trigger → Extrair variáveis → Consultar VirusTotal.

---

#### Passo 8: Adicionar o bloco de decisão baseado no resultado do VT

**O que este passo faz:** Adiciona o primeiro bloco Condition que bifurca o fluxo com base no número de detecções no VirusTotal. O threshold de 10 detecções é conservador — um arquivo com menos de 10 detecções pode ser novo malware não indexado (day-zero) e deve ser verificado por uma segunda fonte de inteligência (Mandiant) antes de descartar.

**Por que agora:** O bloco Condition é o ponto de decisão mais importante do playbook. Sem ele, o playbook executaria contenção desnecessária para todos os alertas, gerando falsos positivos operacionais.

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

**O que você deve ver:** Fluxo ramificado com dois caminhos de detecção antes de decidir sobre contenção.

---

#### Passo 9: Adicionar os blocos de contenção (Branch: malicioso confirmado)

**O que este passo faz:** Adiciona a sequência de 3 blocos de contenção que executam as ações preventivas imediatas quando o malware é confirmado: bloquear o URL do C2 no firewall, registrar o hash como IOC interno, e verificar se o usuário interagiu com o arquivo. Estas três ações acontecem em rápida sequência, sem intervenção humana.

**Por que agora:** A contenção imediata reduz a janela de exposição. Cada segundo que o URL do C2 permanece acessível é uma oportunidade para que outros hosts comprometidos se comuniquem com o atacante.

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

**O que você deve ver:** Três blocos de ação conectados em sequência no branch de malicioso confirmado.

---

#### Passo 10: Adicionar a decisão de isolamento (interação confirmada)

**O que este passo faz:** Adiciona o segundo bloco Condition que determina se o usuário abriu o PDF e, portanto, se o host está comprometido. O branch SIM executa contenção completa. O branch NÃO executa resposta preventiva — notificar o usuário e bloquear o domínio do remetente.

**Por que agora:** Esta é a decisão mais crítica do playbook em termos de impacto ao negócio. O playbook só deve isolar quando há evidência técnica de comprometimento (o PDF foi aberto e executou o dropper).

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

**O que você deve ver:** Fluxo completo de contenção ou notificação dependendo da interação do usuário com o PDF.

---

#### Passo 11: Adicionar o bloco de notificação do SOC (para todos os caminhos)

**O que este passo faz:** Adiciona o bloco final de notificação ao canal #soc-incidents que é executado independentemente do caminho tomado pelo playbook. Este bloco garante visibilidade para o time de SOC — mesmo que o incidente seja resolvido automaticamente (P2), o analista é notificado com um resumo para verificação.

**Por que agora:** A notificação ao SOC fecha o loop de automação — o analista sabe que o playbook foi executado e pode verificar se todas as ações foram bem-sucedidas.

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

**O que este passo faz:** Revisa o fluxo completo do playbook usando o checklist de verificação antes de salvar. Esta revisão garante que nenhum bloco foi esquecido e que todos os branches estão conectados corretamente.

**Por que agora:** A revisão final antes do save é crítica porque o designer não valida automaticamente todos os requisitos funcionais. Um bloco de contenção desconectado é tecnicamente válido mas funcionalmente inútil.

**Checklist de verificação:**

- [ ] Trigger configurado para alertas de phishing
- [ ] Bloco de extração de variáveis com os 5 campos necessários
- [ ] Bloco VirusTotal com output de `$vt_positives` e `$vt_malicious`
- [ ] Condition "Hash é malicioso?" com branches SIM e NÃO
- [ ] Branch NÃO inclui consulta à Mandiant com seu próprio Condition
- [ ] Branch malicioso: bloquear URL, criar IOC, verificar interação
- [ ] Condition "Usuário abriu o PDF?" com branches SIM e NÃO
- [ ] Branch SIM: EDR contain + revogar sessões + PagerDuty P1 + Jira P1
- [ ] Branch NÃO: notificar usuário + bloquear domínio + Jira P2
- [ ] Notificação final para canal #soc-incidents em todos os caminhos

**Ação:** Clicar em "Save" no topo do Designer.

**O que você deve ver:** Mensagem "Playbook saved successfully". Status: "Inactive" (intencional).

---

### PARTE C — Testar o Playbook com o Caso da Luciana Alves (20 min)

---

#### Passo 13: Executar o playbook manualmente no case de teste

**O que este passo faz:** Executa o playbook recém-criado manualmente no case CASE-2026-04-001 para validar que todos os blocos funcionam corretamente com dados reais. A execução manual permite testar sem o risco de executar ações de contenção em produção inadvertidamente.

**Por que agora:** Testar com o case real da Luciana Alves garante que o playbook funciona com dados do ambiente do Banco Meridian especificamente. Problemas de conexão entre o SOAR e os serviços externos (CrowdStrike, Jira, PagerDuty) são descobertos aqui, com tempo para correção.

```
Navegação: Cases → CASE-2026-04-001 → Actions → Run Playbook
Selecionar: phishing_response_automatizado
Modo: Manual (single run)
```

**O que você deve ver:** O playbook começa a executar. No painel de execução, você vê cada bloco sendo executado em tempo real com o status (verde = sucesso, vermelho = erro).

**Tempo esperado de execução:** 15–45 segundos (dependendo da latência das APIs externas).

---

#### Passo 14: Verificar o resultado de cada step do playbook

**O que este passo faz:** Valida a execução de cada um dos 12 steps do playbook na aba Timeline do case. Esta verificação confirma que todas as ações de contenção foram executadas com sucesso: host isolado no EDR, sessões revogadas no Azure AD, alertas disparados no PagerDuty e tickets criados no Jira.

**Por que agora:** A verificação step-by-step é necessária porque um playbook pode retornar "Succeeded" globalmente mesmo com alguns steps falhando. Verificar cada step individualmente garante que o playbook está funcionando como esperado.

```
Navegação: Cases → CASE-2026-04-001 → aba Timeline

Verificar:
1. "Extrair dados do alerta"                      → SUCCESS
2. "Verificar hash no VirusTotal"                 → SUCCESS | $vt_positives = 38
3. "Hash é malicioso?"                            → SIM (38 >= 10)
4. "Bloquear URL de C2 no firewall"               → SUCCESS
5. "Registrar hash como IOC interno"              → SUCCESS
6. "Verificar interação do usuário com o PDF"     → SUCCESS | $user_opened_pdf = true
7. "Usuário abriu o PDF?"                         → SIM
8. "Isolar host no EDR"                           → SUCCESS | WRK-LUCIANA-003 CONTAINED
9. "Revogar sessões Azure AD"                     → SUCCESS | luciana.alves REVOKED
10. "Disparar alerta P1 no PagerDuty"             → SUCCESS | Incident #PD-1847 criado
11. "Abrir ticket P1 no Jira"                     → SUCCESS | SEC-4891 criado
12. "Notificar time SOC via Slack"                → SUCCESS
```

**O que você deve ver:** Todos os 12 steps com status SUCCESS. O host WRK-LUCIANA-003 deve aparecer como "Contained" no painel do CrowdStrike; o ticket P1 deve aparecer criado no Jira; o canal #soc-incidents do Slack deve ter recebido a notificação.

**O que fazer se algum step falhar:**
- Step VT falha: verificar credenciais do conector VT em Settings → Connectors
- Step EDR falha: verificar se o hostname está correto (case-sensitive em alguns EDRs)
- Step Jira falha: verificar se o projeto "SEC" existe no Jira e as permissões da API key

---

### PARTE D — Medir o MTTR e Documentar (10 min)

---

#### Passo 15: Calcular o MTTR do caso manual vs. automatizado

**O que este passo faz:** Calcula e documenta a redução do MTTR (Mean Time to Respond) com o SOAR. Este número é o KPI principal que o CISO apresentará ao board para justificar o investimento no SOAR — a redução de 82 para 28 minutos representa uma melhoria de 66% no MTTR total e de 99.2% no tempo de execução da resposta.

**Por que agora:** A documentação do MTTR deve ser feita imediatamente após o teste bem-sucedido, enquanto os timestamps estão frescos no log de execução do playbook.

```
MTTR calculado:

Incidente reportado:    08:47 (Luciana abre o PDF)
Helpdesk abre ticket:   09:15 (28 min depois)
SOC recebe e triagem:   09:22 (7 min depois)
Análise manual completa: 10:04 (42 min de análise)
Contenção manual:       10:09 (5 min para executar as ações)
────────────────────────────────────────────────────────────────────────
MTTR manual total:      82 minutos (do incidente à contenção)

Com o playbook SOAR:
Helpdesk abre ticket e       09:15
playbook é ativado:
Playbook executa:            09:15:38
                             (38 segundos de execução)
────────────────────────────────────────────────────────────────────────
MTTR com SOAR:               28 minutos (limitado pelo tempo do helpdesk)
MTTR do SOAR em si:          38 segundos (da criação do case à contenção)

Melhoria:  82 min → 38 seg (redução de 99.2% no tempo de resposta do SOAR)
```

**O que você deve ver:** O timestamp de cada step está no log de execução do playbook. Calcule o delta entre o primeiro step e o último step de contenção — o resultado deve ser < 60 segundos para um playbook bem configurado.

---

### PARTE E — Ativar o Playbook e Criar Documentação (10 min)

---

#### Passo 16: Ativar o playbook para operação em produção

**O que este passo faz:** Muda o status do playbook de "Inactive" para "Active" e configura o trigger automático. A partir deste momento, todo novo alerta de phishing com severidade MEDIUM ou superior criará automaticamente um case e executará o playbook — sem intervenção humana.

**Por que agora:** O playbook só deve ser ativado após os testes bem-sucedidos do Passo 14. Ativar sem testes adequados pode executar ações de contenção (isolamento de host, revogação de sessões) em incidentes que ainda precisam de investigação humana.

```
Navegação: SOAR → Playbooks → phishing_response_automatizado
Botão: "Activate"

Configuração de trigger automático:
  Alert Type: "Email Phishing Report"
  Trigger automatically: YES
  Priority threshold: MEDIUM and above
```

**O que você deve ver:** Status do playbook muda para "Active". O playbook agora será executado automaticamente para cada novo alerta de phishing.

---

#### Passo 17: Criar documentação do playbook

**O que este passo faz:** Cria o arquivo de documentação operacional do playbook que ficará disponível para todos os analistas do SOC. Esta documentação serve como referência para debugging (quando steps falham), auditoria (BACEN pode exigir documentação dos processos automatizados) e onboarding de novos analistas.

**Por que agora:** A documentação deve ser criada imediatamente após a ativação, enquanto os detalhes de configuração estão frescos.

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

**O que você deve ver:** Documentação criada e salva com todas as informações operacionais necessárias para o time do SOC.

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

**Por que esta é a resposta correta:** A cadeia de evidências — PDF malicioso (38/72 VT) → usuário abriu (AcroRd32.exe no EDR) → dropper executado (bc_cert_helper.exe em %TEMP%) — é a prova técnica necessária para justificar o isolamento do host sem necessidade de aprovação adicional. Cada evidência individualmente poderia ter explicação alternativa; as três juntas formam prova conclusiva.

**Erro mais comum neste passo:** Concluir que o host está comprometido apenas com o resultado do VirusTotal, sem verificar os logs do EDR. O VT mostra que o PDF É malicioso, mas não prova que o USUÁRIO o abriu — o arquivo pode ter sido recebido e excluído sem ser aberto. A confirmação via EDR (AcroRd32.exe + dropper) é o que justifica o isolamento com base técnica sólida.

---

### Gabarito — Playbook Completo (Pseudocódigo)

O playbook completo está descrito nos passos 5–12 deste lab. A estrutura final deve ter:

- 12 blocos de ação/condição
- 3 blocos de Condition (hash malicioso? / Mandiant conhece? / usuário abriu?)
- 2 branches paralelos (P1 comprometido / P2 preventivo)
- 1 bloco de notificação final ao SOC

**Por que esta é a resposta correta:** A estrutura com 3 Conditions é o mínimo necessário para cobrir os 6 cenários de decisão do framework de resposta a phishing do NIST. Playbooks com menos Conditions são simplistas e não lidam com casos intermediários (ex: hash não detectado pelo VT mas conhecido pela Mandiant).

**Erro mais comum neste passo:** Criar apenas 1 Condition (o do hash malicioso) e ir diretamente para contenção. Este erro ignora o caso em que o VT não conhece o hash (arquivo novo) mas a Mandiant tem informações — e ignora a verificação de interação do usuário, que é crítica para evitar isolamento desnecessário de hosts cujos funcionários não abriram o arquivo.

---

### Gabarito — MTTR Esperado

| Métrica                  | Antes do SOAR  | Com o SOAR     | Melhoria |
|:-------------------------|:--------------:|:--------------:|:--------:|
| MTTR total do incidente  | 82 minutos     | 28 minutos*    | -66%     |
| Tempo de execução SOAR   | N/A            | 38 segundos    | —        |
| Ações manuais necessárias| 12 ações       | 0 (P2) / 2 (P1†) | -80%  |

*28 min = tempo de helpdesk abrir ticket (não eliminável sem integração direta)
†P1 requer apenas aprovação do analista — não execução manual

**Por que estes são os valores corretos:** O MTTR de 28 minutos com SOAR ainda inclui o tempo do helpdesk (não eliminável neste modelo). O MTTR do SOAR em si (38 segundos) mede a eficiência da automação. Para eliminar os 28 minutos do helpdesk, seria necessário integrar o gateway de e-mail diretamente ao SOAR — o que é o próximo passo evolutivo.

**Erro mais comum neste passo:** Reportar ao CISO que o MTTR caiu para 38 segundos sem explicar que o tempo do helpdesk não está incluído. O relatório correto declara AMBOS os números: MTTR do processo = 28 min; MTTR da execução automatizada = 38 seg.

---

### Gabarito — Erros Comuns e Soluções

| Erro                                              | Causa                                     | Diagnóstico e Solução                                  |
|:--------------------------------------------------|:------------------------------------------|:-------------------------------------------------------|
| Step VT retorna `$vt_positives = null`            | Hash não encontrado no VT (arquivo novo)  | **Diagnóstico:** Arquivo criado nos últimos 24h, ainda não indexado. Adicionar tratamento de null no bloco: `if $vt_positives == null → $vt_malicious = false` e redirecionar para o branch da Mandiant |
| Step EDR contain falha com "Host not found"       | Hostname com capitalização diferente       | **Diagnóstico:** CrowdStrike é case-sensitive no hostname. Verificar o hostname exato no portal do CrowdStrike. Normalizar com `.lower()` antes do contain |
| Step Jira falha com "Permission denied"           | API key sem permissão para criar Issues    | **Diagnóstico:** Verificar em Jira → Project Settings → People → adicionar a conta do SOAR como "Member" no projeto SEC |
| Playbook não dispara automaticamente              | Trigger type incorreto                    | **Diagnóstico:** O alert type deve ser exatamente "Email Phishing Report" — verificar a ortografia exata no portal de connectors do gateway de e-mail |
| Host isolado mas sessões ainda ativas             | Azure AD revoke tem delay de até 5 min    | **Diagnóstico:** Comportamento normal da API do Azure AD. Adicionar wait de 5 min antes de verificar; documentar no relatório ao usuário que a sessão pode levar até 5 min para expirar |

---

*Lab 04 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 06 — SOAR e Playbooks](../../modulos/modulo-06-soar-playbooks/README.md)*
*Anterior: [Lab 03 — Hunting C2 Beaconing](../lab-03-hunting-c2-beaconing/README.md)*
*Próximo: [Lab 05 — Capstone](../lab-05-capstone/README.md)*
