# Lab Capstone — Operação Boto

**Curso 3: AWS Cloud Security Operations · CECyber**
**Formato:** Sessão ao vivo — 60 minutos
**Módulo Correspondente:** Módulo 10 — Capstone

---

## Seção 1 — Contexto do Cenário

A Operação Boto é o exercício final integrado do Curso 3. Ela simula um ataque real ao ambiente AWS do Banco Meridian, combinando todas as técnicas aprendidas ao longo dos 9 módulos: governança (SCPs), logging (CloudTrail), detecção (GuardDuty), investigação (Detective), resposta automatizada (EventBridge + Lambda) e proteção de aplicação (WAF).

O nome Boto faz referência ao boto-cor-de-rosa, animal símbolo do Rio Amazonas — e, no contexto da segurança, uma analogia ao atacante que se move de forma fluida e silenciosa pelos sistemas, difícil de detectar sem as ferramentas certas.

Este exercício é avaliado: os alunos devem aplicar o conhecimento de todos os módulos anteriores para identificar o ataque, conter o dano, documentar o incidente e propor melhorias sistêmicas.

---

## Seção 2 — Situação Inicial

É sexta-feira, 25 de abril de 2026, 07h30 BRT. O sistema de alertas do Banco Meridian está em estado normal. Os indicadores do Security Hub mostram postura estável:

```
SECURITY HUB — BANCO MERIDIAN (07h30 — 25/04/2026)
───────────────────────────────────────────────────────────────────
 Security Score:       84%  (meta: > 85%)
 Findings ativos:      23   (1 HIGH, 15 MEDIUM, 7 LOW)
 GuardDuty:            ✅ Operacional — 4 detectors ativos (4 contas)
 CloudTrail:           ✅ Organization Trail ativo — 3 regiões
 Config Rules:         ✅ 52 regras avaliando recursos
 WAF:                  ✅ Internet Banking protegido
 SCPs ativas:          ✅ 5 SCPs na Root

 Time de plantão:      Carlos (Analista L1)
 Mariana:              Em reunião de alinhamento com o CISO
 Você:                 Chegando ao escritório às 08h30
───────────────────────────────────────────────────────────────────
```

Carlos está monitorando o painel quando, às 08h12, o GuardDuty gera o primeiro alerta:

```
[08h12 BRT] GuardDuty MEDIUM — Recon:IAMUser/NetworkPermissions
Conta: 444444444444 (Meridian-Prod)
Usuário: analytics-service-prod
Ação: ListBuckets, DescribeVpcs, DescribeSecurityGroups
IP: 10.0.12.55 (interno — instância EC2 prod-analytics)
```

Carlos registra no ticket como "atividade de reconhecimento interna — investigar". Ele não escala porque a severidade é MEDIUM e o IP é interno.

---

## Seção 3 — O Ataque se Desdobra

**Como usar esta timeline:** A timeline abaixo é o cenário de ataque que o aluno deve investigar. Cada evento é uma evidência que pode ser encontrada em CloudTrail Lake, GuardDuty, VPC Flow Logs ou Detective — dependendo da fonte. Ao analisar cada evento, o aluno deve identificar: (1) qual serviço AWS capturou este evento; (2) qual finding GuardDuty foi gerado (se aplicável); (3) qual técnica MITRE ATT&CK corresponde; (4) qual a resposta correta para este momento específico. Alguns eventos são óbvios (o GuardDuty gera finding de alto nível imediatamente); outros são sutis (a criação do usuário `backdoor-svc` às 08h42 pode passar despercebida se o analista não executar a query do Passo 5.1 do Lab 02).

**Timeline da Operação Boto — 25/04/2026:**

```
[08h12]  Recon:IAMUser/NetworkPermissions (MEDIUM) — ignorado pelo L1
[08h23]  UnauthorizedAccess:IAMUser/MaliciousIPCaller (HIGH)
         → analytics-service-prod fazendo chamadas de IP externo
         → Carlos escala para Mariana
[08h31]  Mariana te liga: "Temos um HIGH. Preciso de você agora."
[08h35]  Você acessa o console. Encontra 3 findings simultâneos:
         → UnauthorizedAccess: credencial de EC2 usada externamente
         → Impact:S3/AnomalousBehavior.Write (30 objetos criados)
         → Backdoor:EC2/C&CActivity.B (porta 6666 para IP RU)
[08h42]  GuardDuty gera: PrivilegeEscalation:IAMUser/AnomalousBehavior
         → Novo usuário IAM criado: backdoor-svc
         → Política AdministratorAccess anexada ao backdoor-svc
[09h00]  CloudTrail confirma: SCP de proteção do CloudTrail bloqueou
         tentativa de StopLogging pelo atacante
[09h15]  Você confirma: os dados de 847 clientes foram copiados para
         bucket externo na conta do atacante
[09h30]  CISO é notificado. Janela de 72h da LGPD começa agora.
```

**Estado do ambiente quando você chega ao console às 08h35:**

```
MERIDIAN-PROD (444444444444) — Estado em 25/04/2026 08h35
─────────────────────────────────────────────────────────────────
 Instância comprometida:   i-0prod-analytics-01
 IAM User criado pelo atacante:  backdoor-svc
 Política anexada:         AdministratorAccess (!)
 Dados exfiltrados:        meridian-dados-clientes/ → 847 objetos
 Bucket de destino:        s3://exfil-bucket-7f3k2 (conta externa)
 C2 ativo:                 185.220.101.33 (Tor exit node — RU), porta 6666
 StopLogging bloqueado:    SCP funcionou — CloudTrail intacto
─────────────────────────────────────────────────────────────────
```

**Mariana ao telefone:**

> "O atacante criou um usuário IAM com AdministratorAccess. Se ele já rodou alguma coisa com esse usuário antes de você bloquear, não sabemos o que mais foi feito. Precisamos de contenção imediata, timeline completa do ataque, e eu vou precisar do relatório para o BACEN antes das 17h."

Este é o cenário que você deve resolver nas próximas 60 minutos.

---

## Referência ao Módulo 10

O cenário completo da Operação Boto, incluindo a linha do tempo do ataque, os entregáveis e o gabarito do instrutor, estão descritos integralmente no arquivo:

```
/modulos/modulo-10/README.md
```

---

## Instruções de Entrega

### O que este lab avalia

O Lab Capstone — Operação Boto é a avaliação integradora do Curso 3. Diferentemente dos labs anteriores (que guiam o aluno passo a passo), este lab simula a resposta a um incidente real em tempo real. Não há passos para seguir — há um ataque em andamento, uma linha do tempo que avança, e decisões críticas que precisam ser tomadas com as ferramentas e o conhecimento adquiridos nos Módulos 01 a 09.

**O que é avaliado:** Sua capacidade de integrar todos os serviços do curso — CloudTrail Lake (para reconstituir a timeline), GuardDuty (para interpretar os findings e sua progressão), Security Hub (para avaliar a postura no momento do ataque), Amazon Detective (para pivoting entre entidades), EventBridge + Lambda (para criar automações de resposta) e WAF (para adicionar camada de proteção após o incidente). Cada entregável avalia um aspecto diferente dessa integração.

**Por que este incidente:** A Operação Boto não é um cenário hipotético genérico. Ela foi construída a partir dos gaps reais identificados ao longo dos labs anteriores: GuardDuty habilitado apenas em sa-east-1 (Lab 03), ausência de auto-remediação para findings MEDIUM (Lab 06), IMDSv1 permitindo exfiltração de credenciais (Lab 05), ausência de SCP para proteger GuardDuty (Lab 01). O atacante explorou exatamente esses gaps — e o aluno que completou os labs anteriores com atenção reconhecerá cada gap durante a análise.

### Entregáveis Obrigatórios

Para concluir o capstone, o aluno deve entregar os seguintes documentos:

| Entregável | Formato | Prazo |
|---|---|---|
| **Timeline MITRE ATT&CK** | Tabela preenchida (PDF ou Markdown) | Durante a live (30 min) |
| **Relatório NIST SP 800-61** | Documento completo com todas as 6 fases | 48h após a live |
| **3 Automações EventBridge + Lambda** | Código Python funcional + event pattern JSON | 48h após a live |
| **Plano de Remediação** | Tabela com ações, ferramentas e responsáveis | 48h após a live |

---

## Critérios de Avaliação

### Timeline MITRE (25 pontos)

| Critério | Pontuação |
|---|---|
| Identificou todas as 8 fases do ataque | 10 pts |
| Mapeou corretamente TÁTICA e TÉCNICA MITRE para cada fase | 10 pts |
| Identificou o campo de evidência correto (CloudTrail, VPC FL, GuardDuty) | 5 pts |

### Relatório NIST SP 800-61 (35 pontos)

| Critério | Pontuação |
|---|---|
| Fase 1 (Preparação): identificou todos os 5 gaps de controle | 5 pts |
| Fase 2 (Detecção): identificou por que os primeiros findings não geraram resposta | 5 pts |
| Fase 3 (Contenção): todas as 5 ações de contenção corretas e na ordem certa | 10 pts |
| Fase 4 (Erradicação): identificou e removeu o usuário backdoor + corrigiu as configurações | 5 pts |
| Fase 5 (Recuperação): obrigações LGPD e BACEN corretamente identificadas | 5 pts |
| Fase 6 (Lições Aprendidas): pelo menos 5 ações corretivas com responsável e prazo | 5 pts |

### Automações (30 pontos)

| Critério | Pontuação |
|---|---|
| Automação A: event pattern correto para criação de usuário IAM não autorizado | 5 pts |
| Automação A: código Lambda funcional para desabilitar o usuário | 5 pts |
| Automação B: detecta criação de filter GuardDuty malicioso | 5 pts |
| Automação C: detecta AssumeRole cross-account suspeito | 5 pts |
| Código Python com error handling e logging adequados | 5 pts |
| Idempotência implementada em pelo menos 1 automação | 5 pts |

### Plano de Remediação (10 pontos)

| Critério | Pontuação |
|---|---|
| Ações imediatas (0-24h) completas e priorizadas | 4 pts |
| Ações de curto prazo (24-72h) incluindo notificações regulatórias | 3 pts |
| Ações de médio prazo (1-4 semanas) para melhoria sistêmica | 3 pts |

---

## Template de Entrega

```
CAPSTONE — OPERAÇÃO BOTO
Banco Meridian | Curso 3 AWS Cloud SecOps | CECyber

Nome do Aluno: ________________________________
Data de Entrega: ______________________________
Incident ID: INC-2026-CAPSTONE-[NOME]

┌─────────────────────────────────────────────────────────────────┐
│  DECLARAÇÃO DE AUTORIA                                         │
│  Declaro que este relatório foi elaborado por mim e representa │
│  minha análise individual do cenário apresentado.              │
│                                                                 │
│  Assinatura: _________________ Data: _______________           │
└─────────────────────────────────────────────────────────────────┘

1. TIMELINE MITRE ATT&CK
   [Preencher tabela do Módulo 10 — Entregável 1]

2. RELATÓRIO NIST SP 800-61
   [Preencher todas as 6 fases]

3. AUTOMAÇÕES EVENTBRIDGE + LAMBDA
   [Incluir código Python e event pattern JSON para as 3 automações]

4. PLANO DE REMEDIAÇÃO
   [Preencher tabelas de ações imediatas, curto e médio prazo]
```

---

## Recursos de Apoio

Para completar o capstone, revise os seguintes módulos:

| Módulo | Relevância |
|---|---|
| Módulo 01 | SCPs preventivas, IAM, External ID — Fases 3 e 4 do ataque |
| Módulo 02 | CloudTrail Lake queries para reconstrução da timeline |
| Módulo 03 | GuardDuty findings — por que alguns não geraram alerta |
| Módulo 05 | Técnicas de PR escalation e investigação forense |
| Módulo 08 | EventBridge + Lambda — as 3 automações de resposta |
| Módulo 09 | Multi-conta e separação de funções — por que a Audit Account foi acessada |

---

## Submissão

Enviar para: **secops-cursos@cecyber.com.br**

Assunto do email: `[CAPSTONE] AWS SecOps - [Nome Completo] - Operação Boto`

---

## Seção 8 — Gabarito do Instrutor

### Timeline MITRE ATT&CK — Resposta Completa

| Fase | Timestamp | Evento | Tática MITRE | Técnica | ID | Evidência |
|---|---|---|---|---|---|---|
| 1 | 08h12 | Reconhecimento interno — ListBuckets, DescribeVpcs, DescribeSecurityGroups | Discovery | Cloud Infrastructure Discovery | T1580 | CloudTrail `eventName = ListBuckets` do IP 10.0.12.55 |
| 2 | 08h19 | Acesso ao IMDS para obter credenciais da role analytics-service-prod | Credential Access | Cloud Instance Metadata API | T1552.005 | CloudTrail `GetCredentials` de 169.254.169.254 |
| 3 | 08h23 | Uso de credenciais temporárias da role a partir de IP externo (185.220.101.33) | Defense Evasion | Valid Accounts: Cloud Accounts | T1078.004 | GuardDuty `UnauthorizedAccess:IAMUser/MaliciousIPCaller` |
| 4 | 08h27 | Cópia de 847 objetos do S3 meridian-dados-clientes para bucket externo | Exfiltration | Transfer Data to Cloud Account | T1537 | CloudTrail Data Events: 847 eventos `GetObject` do IP 185.220.101.33 |
| 5 | 08h31 | Backdoor via reverse shell na porta 6666 para 185.220.101.33 | Command and Control | Application Layer Protocol | T1071 | GuardDuty `Backdoor:EC2/C&CActivity.B` + VPC Flow Logs |
| 6 | 08h35 | Criação de usuário IAM backdoor-svc via credenciais exfiltradas | Persistence | Cloud Account | T1136.003 | CloudTrail `CreateUser` + `AttachUserPolicy` com AdministratorAccess |
| 7 | 08h42 | Tentativa de desabilitar CloudTrail (bloqueada pela SCP ProtectCloudTrail) | Defense Evasion | Disable Cloud Logs | T1562.008 | CloudTrail `StopLogging` com `errorCode: Explicit deny in a service control policy` |
| 8 | 09h00 | Tentativa de mover dados para conta externa via S3 Cross-Account | Exfiltration | Transfer Data to Cloud Account | T1537 | CloudTrail S3 cross-account `GetObject` bloqueado por bucket policy |

---

### Relatório NIST SP 800-61 — Resposta por Fase

**Fase 1 — Preparação (gaps identificados):**

| Gap | Controle Ausente | Módulo de Remediação |
|---|---|---|
| Finding MEDIUM às 08h12 não escalado | EventBridge rule para MEDIUM escalado após 15 min sem resposta | Módulo 08 |
| IMDSv1 habilitado permitiu acesso a credenciais | `modify-instance-metadata-options --http-tokens required` em todas as instâncias | Módulo 05 |
| Sem bloqueio automático de IP externo usando credenciais de instância | Automação 1 (Lab 06) — teria contido em segundos | Módulo 08 |
| Usuário IAM pode criar Access Key sem MFA | SCP `RequireMFAForSensitiveActions` — adicionar `iam:CreateUser` | Módulo 01 |
| Sem detecção de novo usuário IAM fora do pipeline | EventBridge rule para CloudTrail `CreateUser` por principal não aprovado | Módulo 08 |

**Fase 3 — Contenção (sequência correta e razão):**

1. **Revogar sessões temporárias da role analytics-service-prod** via `put-role-policy` com `DateLessThan` — por que primeiro: o atacante já tem sessão ativa; desabilitar access key não revoga sessão já emitida
2. **Desabilitar usuário backdoor-svc** via `aws iam update-login-profile --no-password-reset-required` + `create-access-key-last-used` para identificar ações executadas — por que segundo: tem AdministratorAccess e pode criar outros backdoors
3. **Isolar instância i-0prod-analytics-01** via Security Group quarentena — por que terceiro: cortar C2 ativo, mas APÓS preservar evidências
4. **Criar snapshots EBS** antes do isolamento — evidências forenses para análise post-mortem
5. **Bloquear IP 185.220.101.33 no WAF** — impede acesso ao portal de internet banking pelo mesmo IP

**Fase 5 — Recuperação (obrigações regulatórias):**

| Prazo | Obrigação | Base Legal |
|---|---|---|
| 72h após ciência | Notificar ANPD sobre incidente com dados pessoais | LGPD Art. 48 |
| 72h após ciência | Comunicar BACEN sobre incidente relevante em sistema financeiro | Res. BACEN 4.893 Art. 11 |
| 5 dias úteis | Relatório detalhado ao BACEN com causa raiz e medidas corretivas | Res. BACEN 4.893 Art. 12 |
| 30 dias | Implementar medidas corretivas reportadas ao BACEN | Res. BACEN 4.893 Art. 13 |

---

### Automações de Resposta — Gabarito

**Automação A — Detectar e desabilitar usuário IAM criado fora do pipeline:**

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["CreateUser"],
    "userIdentity": {
      "arn": [{"anything-but": {"prefix": "arn:aws:iam::444444444444:role/ServiceAccountProvisioning"}}]
    }
  }
}
```

**Por que esta é a resposta correta:** Filtrar pelo eventSource `iam.amazonaws.com` e eventName `CreateUser` garante que apenas criações de usuário IAM são capturadas. A condição `anything-but` com `prefix` garante que apenas criações fora do pipeline de provisionamento aprovado disparam o alerta. Um eventPattern que capturasse todos os `CreateUser` geraria ruído para pipelines legítimos.

**Automação B — Detectar desabilitação de filtro GuardDuty malicioso:**

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["guardduty.amazonaws.com"],
    "eventName": ["CreateFilter", "UpdateFilter"],
    "requestParameters": {
      "action": ["ARCHIVE"]
    }
  }
}
```

**Por que esta é a resposta correta:** Um atacante que obtém acesso ao GuardDuty pode criar Suppression Rules (CreateFilter com action ARCHIVE) para silenciar findings futuros. Monitorar `CreateFilter` e `UpdateFilter` com `action: ARCHIVE` detecta essa técnica de evasão de defesa — MITRE T1562.006 (Disable or Modify Tools).

**Automação C — Detectar AssumeRole cross-account suspeito:**

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"],
    "userIdentity": {
      "type": ["IAMUser"]
    },
    "requestParameters": {
      "roleArn": [{"prefix": "arn:aws:iam::"}]
    },
    "errorCode": [{"exists": false}]
  }
}
```

**Por que esta é a resposta correta:** Usuários IAM assumindo roles cross-account é uma técnica de pivotamento comum após comprometimento de credenciais. O filtro `errorCode exists: false` garante que apenas AssumeRoles bem-sucedidos são capturados — tentativas bloqueadas são de interesse mas menos urgentes. Um analista L1 pode investigar cada alerta desse type para verificar se o destino da role é uma conta interna aprovada ou uma conta desconhecida.

---

### Plano de Remediação — Resposta Mínima Aceitável

| Prazo | Ação | Ferramenta | Responsável |
|---|---|---|---|
| 0-2h | Revogar todas as sessões de analytics-service-prod | `put-role-policy DateLessThan` | Security Engineer |
| 0-2h | Excluir usuário backdoor-svc + revogar todas as keys | `delete-user`, `delete-access-key` | Security Engineer |
| 0-24h | Habilitar IMDSv2 em TODAS as instâncias prod | `modify-instance-metadata-options` | Cloud Ops |
| 0-24h | Notificar ANPD e BACEN sobre exposição de dados | Portal ANPD + email BACEN | CISO + Jurídico |
| 24-72h | Habilitar EventBridge automação para findings MEDIUM + HIGH | Terraform / CDK | Security Engineer |
| 24-72h | Revisar e restringir permissões da role analytics-service-prod | IAM Access Analyzer policy generation | Security Engineer |
| 1-2 semanas | Implementar SCPs para proteção de GuardDuty filters | SCP DenyGuardDutyModification | Cloud Architect |
| 1-2 semanas | Adicionar WAF rule para bloquear todos os IPs Tor | WAF IP Set + Threat Intel feed | Security Engineer |
| 2-4 semanas | Implementar guardrails de IMDS v2 via SCP | SCP RequireIMDSv2 | Cloud Architect |
| 4 semanas | Treinamento de conscientização para time de Dev sobre credential hygiene | LMS interno | CISO |

Formato do arquivo: `capstone_operacao_boto_[nome_sobrenome].pdf` ou `.md`
