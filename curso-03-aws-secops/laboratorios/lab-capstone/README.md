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

Formato do arquivo: `capstone_operacao_boto_[nome_sobrenome].pdf` ou `.md`
