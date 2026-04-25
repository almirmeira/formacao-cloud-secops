# Lab Capstone — Operação Boto

**Curso 3: AWS Cloud Security Operations · CECyber**
**Formato:** Sessão ao vivo — 60 minutos
**Módulo Correspondente:** Módulo 10 — Capstone

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
