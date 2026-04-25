# Módulo 08 — Entra ID Protection e PIM

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 2 horas (1h videoaula + 1h laboratório)                                     |
| **Formato**              | 1 aula gravada + Lab prático no portal Azure                                |
| **Pré-requisito**        | Módulos 01–07 concluídos; Entra ID P2 habilitado                            |
| **Certificação Alvo**    | SC-200 — Domínio 1: Manage identity and access (Entra ID)                   |
| **Cenário**              | Banco Meridian — protegendo identidades privilegiadas e detectando contas comprometidas |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Configurar políticas de risco de usuário e sign-in no Entra ID Protection
2. Interpretar as detecções de risco: anonymous IP, atypical travel, leaked credentials
3. Criar Conditional Access policies baseadas em risco
4. Configurar PIM com JIT access e approval workflows para funções privilegiadas
5. Implementar Access Reviews para auditoria periódica de permissões
6. Integrar alertas do Entra ID Protection no Microsoft Sentinel

---

## 1. Entra ID Protection: Risk Policies

### 1.1 O que é o Entra ID Protection

O **Entra ID Protection** (anteriormente Azure AD Identity Protection) é um serviço que usa machine learning e inteligência de ameaças da Microsoft para:
- Detectar tentativas de comprometimento de identidades (sign-in risks)
- Identificar usuários com comportamento anômalo (user risks)
- Automaticamente bloquear ou exigir MFA quando o risco é detectado
- Alimentar o Sentinel e o Defender XDR com sinais de risco de identidade

Requer **Entra ID P2** (incluído no M365 E5 ou E5 Security).

### 1.2 User Risk vs Sign-In Risk

| Dimensão          | User Risk                                           | Sign-In Risk                                         |
|:------------------|:----------------------------------------------------|:-----------------------------------------------------|
| **O que avalia**  | Indicadores acumulados de que o usuário pode estar comprometido | Probabilidade de que uma autenticação específica seja ilegítima |
| **Persistência**  | Persiste até ser remediado (pode durar dias/semanas) | Específico para cada tentativa de login              |
| **Fontes**        | Credenciais vazadas, comportamento anômalo prolongado, threat intelligence | IP suspeito, localização anômala, padrão de ataque em andamento |
| **Ação política** | Forçar mudança de senha, bloquear acesso            | Exigir MFA, bloquear login                           |
| **Remediação**    | Usuário muda senha + admin confirma seguro          | Usuário completa MFA ou admin descarta risco         |

### 1.3 Detecções de Risco Disponíveis

| Detecção                         | Tipo          | O que detecta                                                     | Risk Level |
|:---------------------------------|:-------------:|:------------------------------------------------------------------|:----------:|
| Anonymous IP address             | Sign-in Risk  | Login de IP de anonimizador (Tor, VPN anônima)                   | Medium     |
| Atypical travel                  | Sign-in Risk  | Login de dois locais geograficamente impossíveis em curto tempo  | Medium     |
| Malware linked IP address        | Sign-in Risk  | Login de IP associado a botnet ou C2 conhecida                   | High       |
| Unfamiliar sign-in properties    | Sign-in Risk  | Login com propriedades incomuns (browser, SO, localização)       | Low/Medium |
| Password spray                   | Sign-in Risk  | Padrão de tentativas de spray na conta                           | High       |
| Suspicious inbox manipulation rules | User Risk  | Regras de encaminhamento criadas após login suspeito             | High       |
| Leaked credentials               | User Risk     | Credenciais do usuário encontradas em dark web/breach databases  | High       |
| Azure AD threat intelligence     | User Risk     | Conta associada a padrões de ataque conhecidos pelo MSTIC        | High       |
| Suspicious browser               | Sign-in Risk  | Browser com cabeçalho/comportamento suspeito                     | Low        |
| Token issuer anomaly             | Sign-in Risk  | Token emitido por forma incomum (possível AiTM)                  | Medium/High|
| Additional risk detected         | Sign-in Risk  | Microsoft identificou risco mas não divulga detalhes             | Varies     |

---

## 2. Configurando Risk Policies

### 2.1 Sign-In Risk Policy

As Sign-In Risk Policies são o mecanismo que transforma a detecção de risco em proteção automatizada. Sem uma policy configurada, o Entra ID detecta o risco (ex.: login de IP anônimo) e não faz nada — apenas registra. Com a policy configurada, o Entra ID automaticamente exige MFA ou bloqueia o login baseado no nível de risco calculado.

**Como funciona o cálculo de risco em tempo real:** O Entra ID avalia cada tentativa de autenticação em milissegundos, consultando dezenas de sinais: endereço IP (comparado com bilhões de logins históricos da Microsoft), localização geográfica (é possível ter chegado aqui dado o último login?), propriedades do dispositivo (browser, sistema operacional, linguagem), hora do dia para aquele usuário, velocidade de deslocamento. O score de risco resultante é um número entre 0 e 100, mapeado para baixo/médio/alto.

**Por que o threshold "Medium and above" é o recomendado para o Banco Meridian:** O threshold "High only" gera poucos falsos positivos mas deixa passar muitos ataques reais. O threshold "Low and above" gera muitos falsos positivos e treina os usuários a ignorar solicitações de MFA ("MFA fatigue"). "Medium and above" é o equilíbrio que captura ~85% dos logins maliciosos com uma taxa de falso positivo de 3-5% — aceitável para um banco onde o custo de uma conta comprometida é muito maior que o incômodo de um usuário legítimo tendo que passar por MFA adicional.

```
Portal Azure → Entra ID → Security → Identity Protection → Sign-in risk policy

Configurações recomendadas para Banco Meridian:
─────────────────────────────────────────────────
Users: All users
(Exclusões: contas de quebra-vidro / break glass accounts)

Sign-in risk threshold: Medium and above

Controls: Grant access
  ✓ Require multi-factor authentication

Enforce policy: ON
```

**Resultado**: Quando o Entra ID detecta um sign-in de risco médio ou alto (ex.: login de IP anônimo, atypical travel, malware-linked IP), o usuário é automaticamente solicitado a completar MFA. Se completar com sucesso → acesso concedido. Se não conseguir completar MFA → acesso negado.

### 2.2 User Risk Policy

```
Portal Azure → Entra ID → Security → Identity Protection → User risk policy

Configurações recomendadas para Banco Meridian:
─────────────────────────────────────────────────
Users: All users
(Exclusões: contas de serviço, break glass accounts)

User risk threshold: High

Controls: Grant access
  ✓ Require password change

Enforce policy: ON
```

**Resultado**: Quando um usuário tem risco high acumulado (ex.: credenciais encontradas em leak), o usuário é forçado a mudar a senha no próximo login. A senha deve ser alterada com MFA obrigatório.

### 2.3 Contas Break-Glass (Exclusão Obrigatória)

**ATENÇÃO CRÍTICA**: O Banco Meridian deve ter pelo menos 2 contas de "break glass" (acesso de emergência) excluídas de TODAS as políticas de Conditional Access e Identity Protection. Essas contas são usadas quando:
- O tenant fica inacessível por falha de MFA em massa
- Uma atualização de política de CA bloqueia todos os admins
- O provedor de MFA está fora do ar

```
Configuração das break glass accounts:
- Nomes: meridian-breakglass-01@bancomeridian.com.br / meridian-breakglass-02@...
- Senhas: longas (50+ caracteres), armazenadas em cofre físico offline
- MFA: NÃO configurar MFA nessas contas (elas são a saída de emergência se MFA falhar)
- Monitoramento: TODA autenticação dessas contas deve gerar alerta CRÍTICO no Sentinel
- Exclusão: todas as políticas de CA, Identity Protection, MFA
- Auditoria: verificar mensalmente se nunca foram usadas
```

---

## 3. Conditional Access Baseado em Risco

### 3.1 Políticas de CA com Risk Conditions

O **Conditional Access** do Entra ID é o motor de policy evaluation que decide se um login é permitido, bloqueado ou requer step-up authentication.

**Política: Bloquear logins de alto risco para sistemas críticos**

```
Nome: CA-Block-HighRisk-CoreBanking
Usuários: All users
Aplicações: Core Banking System App (app registration no Entra ID)
Condições:
  Sign-in risk: High
  User risk: High
Grant: Block access

Exceções: SOC team (para investigação)
```

**Política: MFA para risco médio**

```
Nome: CA-MFA-MediumRisk
Usuários: All users (excl. break glass)
Aplicações: All cloud apps
Condições:
  Sign-in risk: Medium or higher
  OU User risk: Medium or higher
Grant:
  ✓ Require multi-factor authentication
  ✓ Require device to be marked as compliant
```

### 3.2 Diagrama do Fluxo de Autenticação

```
USUÁRIO TENTA LOGIN
          │
          ▼
ENTRA ID RECEBE TENTATIVA
    │
    ├─ Verifica credenciais (senha/FIDO2/certificado)
    │
    ├─ Calcula SIGN-IN RISK (ML em tempo real)
    │   ├─ IP anônimo? Localização incomum? Malware IP?
    │   └─ Sign-in risk score: none/low/medium/high
    │
    ├─ Verifica USER RISK acumulado
    │   ├─ Credenciais vazadas? Comportamento anômalo recente?
    │   └─ User risk state: none/low/medium/high/dismissed
    │
    └─ AVALIA CONDITIONAL ACCESS POLICIES
        │
        ├─ Policy 1: Sign-in risk >= High AND App = CoreBanking
        │   └─ BLOCK (usuário não consegue entrar mesmo com MFA)
        │
        ├─ Policy 2: Sign-in risk >= Medium OR User risk >= Medium
        │   └─ REQUIRE MFA
        │       ├─ MFA completada com sucesso → ACESSO CONCEDIDO
        │       └─ MFA falhou → ACESSO NEGADO
        │
        └─ Policy 3: Device not compliant
            └─ BLOCK (dispositivo não gerenciado pelo Intune)
```

---

## 4. PIM — Privileged Identity Management

### 4.1 O Problema: Privilégios Permanentes

No modelo tradicional, um administrador de TI tem o papel de **Global Administrator** permanentemente. Isso significa que qualquer comprometimento da conta resulta imediatamente em acesso de altíssimo privilégio ao tenant inteiro.

O **PIM** resolve isso com Just-In-Time access: o administrador é **elegível** ao papel mas não o tem ativo. Para ativar, precisa solicitar, pode precisar de aprovação, e o acesso expira automaticamente após um tempo definido.

**Por que contas permanentemente privilegiadas são o maior risco em ambientes Microsoft:** Uma conta com Global Admin permanente, se comprometida por phishing, dá ao attacker acesso irrestrito a todo o tenant — todos os usuários, todos os dados, todas as configurações. O attacker pode criar backdoors, exportar dados de todos os usuários, desabilitar controles de segurança. Com PIM, mesmo que a conta do admin seja comprometida quando não está com a role ativa, o attacker tem uma conta comum — não Global Admin. O raio de explosão é dramaticamente reduzido.

**O impacto concreto no Banco Meridian:** Antes do PIM, o banco tinha 5 contas com Global Admin permanente. Isso significa que se qualquer uma dessas 5 contas for comprometida, o attacker tem acesso irrestrito ao tenant M365 com 2.800 usuários. Com PIM, as 5 contas são apenas "elegíveis" ao Global Admin. A role só é ativada quando necessário, por no máximo 2 horas (conforme configuração abaixo), com aprovação do CISO. A janela de risco é minimizada.

> **💡 Dica do instrutor:** Configure pelo menos 2 contas "Break Glass" que ficam permanentemente com Global Admin fora do PIM, com credenciais armazenadas em cofre físico. Essas contas são usadas apenas em emergências (PIM indisponível, bloqueio acidental de todos os admins). Configure uma Analytics Rule NRT no Sentinel que alerta imediatamente qualquer login nessas contas — elas não devem ser usadas no dia a dia, então qualquer login é automaticamente suspeito.

### 4.2 Configuração de PIM para Banco Meridian

```
Portal Azure → Entra ID → Identity Governance → Privileged Identity Management

CONFIGURAR ROLE: Global Administrator
─────────────────────────────────────
Settings:
  Activation maximum duration: 2 hours (não mais que necessário)
  On activation, require: MFA + Justification
  Require approval: YES
    Approvers: CISO (ciso@bancomeridian.com.br)
  
Alerts:
  ✓ Send notifications to admins when eligible role is activated
  ✓ Send notifications when role is assigned outside PIM

Elegíveis (não têm o papel permanentemente):
  - cto@bancomeridian.com.br (CTO — pode precisar de Global Admin em emergências)
  - head-it@bancomeridian.com.br (Head de TI)
  - soc-l3-lead@bancomeridian.com.br (SOC L3 lead — para resposta a incidentes)

CONFIGURAR ROLE: Security Administrator
─────────────────────────────────────────
Settings:
  Activation maximum duration: 4 hours
  On activation, require: MFA + Justification
  Require approval: NO (para agilidade do SOC em incidentes)

Elegíveis:
  - Todos os analistas SOC L2/L3
```

### 4.3 Fluxo de Ativação de Role via PIM

```
SOC Analista L3 precisa investigar um incidente crítico às 23h:

1. Portal Azure → PIM → My roles → Security Administrator → Activate
2. Preenche: Justification: "Investigação incidente ID-2024-0891 — possível comprometimento"
3. Duration: 2 hours
4. Confirm
5. MFA challenge → completar
6. ROLE ATIVADA — analista tem Security Admin por 2 horas
7. Após 2 horas → acesso revogado automaticamente
8. Registro de auditoria: quem ativou, quando, por quanto tempo, qual justificativa
```

**Alerta no Sentinel** (obrigatório para o Banco Meridian):
```kql
// Analytics rule: Ativação de role privilegiada fora do horário comercial
AuditLogs
| where TimeGenerated > ago(5m)
| where OperationName == "Add eligible member to role"
   or OperationName contains "Activate role"
| where InitiatedBy.app.displayName == "MS-PIM"
| extend Hour = toint(format_datetime(TimeGenerated, 'HH'))
| where Hour < 8 or Hour > 19   // Fora do horário comercial (8h-19h)
| project TimeGenerated, OperationName, 
          InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
          TargetRole = tostring(TargetResources[0].displayName)
```

---

## 5. Access Reviews

### 5.1 Por que Access Reviews São Obrigatórias no Contexto BACEN

A Resolução BACEN 4.893/2021 e a ISO 27001 exigem revisão periódica de acessos privilegiados. Sem Access Reviews:
- Funcionários que mudaram de função mantêm acessos da função anterior
- Ex-funcionários podem ter acessos não revogados
- Contas de serviço acumulam permissões ao longo do tempo
- Parceiros externos mantêm acessos após o término da parceria

### 5.2 Criando uma Access Review para Admins

```
Portal Azure → Entra ID → Identity Governance → Access reviews → New access review

Tipo: Teams + Groups OU Azure AD roles

Para revisão de Global Admins:
─────────────────────────────────
Scope: Azure AD roles
  Role: Global Administrator
Review recurrence: Quarterly (trimestral)
Start date: 01/01/2025
Duration: 14 days (revisores têm 14 dias para aprovar/negar)
Reviewers: Manager of each user (ou CISO como revisor central)

Settings:
  ✓ Auto apply results to resource (aplica automaticamente após o período)
  If reviewers don't respond: Remove access (conservador — melhor para compliance)
  At end of review: Send notification to review creators

Notification to reviewees (usuários revisados):
  ✓ Notify users being reviewed about the review
```

### 5.3 Fluxo de Access Review

```
INICIO DO CICLO TRIMESTRAL
          │
          ▼
REVISORES RECEBEM E-MAIL:
"Você tem 14 dias para revisar os acessos de X pessoas"
          │
          ▼
REVISOR FAZ LOGIN NO portal.azure.com → Identity Governance → Access reviews
    Para cada usuário sob revisão:
    ├─ "Approve" → usuário mantém acesso
    ├─ "Deny" → acesso será revogado ao fim do período
    └─ "Don't know" → sistema aplica a política padrão (remove acesso)
          │
          ▼
FIM DO PERÍODO (14 dias):
    ├─ Acessos aprovados: mantidos
    ├─ Acessos negados: revogados automaticamente
    └─ Não revisados: revogados (política "Remove access if no response")
          │
          ▼
RELATÓRIO DE AUDITORIA:
    - Quem aprovou o quê
    - Quem negou o quê
    - Quantos acessos foram removidos
    - Data e hora de cada decisão
→ Disponível para auditoria BACEN
```

---

## 6. Integração com o Microsoft Sentinel

### 6.1 Tabelas no Sentinel com Dados do Entra ID Protection

| Tabela                           | Conteúdo                                                         |
|:---------------------------------|:-----------------------------------------------------------------|
| `SigninLogs`                     | Todos os logins interativos com campos de risco                  |
| `AADNonInteractiveUserSigninLogs`| Logins silenciosos (apps, service principals)                   |
| `AADRiskyUsers`                  | Usuários com risco detectado pelo Identity Protection            |
| `AADUserRiskEvents`              | Eventos de risco individuais que compõem o user risk score       |
| `AADRiskyServicePrincipals`      | Service principals com comportamento de risco                    |
| `SecurityAlert`                  | Alertas de risco do Identity Protection enviados para o Sentinel |

### 6.2 Queries de Investigação de Identidade

```kql
// Verificar usuários com risco alto atual e suas últimas atividades
AADRiskyUsers
| where TimeGenerated > ago(7d)
| where RiskLevel == "high"
| where RiskState == "atRisk"
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | summarize LastLogin = max(TimeGenerated), 
                LoginCount = count(),
                Countries = make_set(Location, 10)
        by UserPrincipalName
) on UserPrincipalName
| project UserPrincipalName, RiskLevel, RiskState, 
          RiskDetail, LastLogin, LoginCount, Countries
| sort by LastLogin desc

// Verificar ativações de PIM suspeitas (ex.: fora do horário ou sem incidente correlacionado)
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName contains "Activate" and OperationName contains "role"
| where LoggedByService == "PIM"
| extend
    Activator = tostring(InitiatedBy.user.userPrincipalName),
    ActivatedRole = tostring(TargetResources[0].displayName),
    Justification = tostring(TargetResources[1].modifiedProperties[0].newValue)
| project TimeGenerated, Activator, ActivatedRole, Justification
```

---

## 7. Diagrama: Fluxo Completo de Sign-In com Proteção

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║         FLUXO DE AUTENTICAÇÃO — BANCO MERIDIAN                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  USUÁRIO                ENTRA ID              CA ENGINE          RECURSO         ║
║  ──────                 ────────              ─────────          ───────         ║
║                                                                                   ║
║  [Digita senha]──────►[Verifica credenciais]                                     ║
║                         │                                                         ║
║                         ▼                                                         ║
║                     [Identity Protection]                                         ║
║                     Calcula Sign-In Risk:                                         ║
║                     • IP anônimo? → +risk                                         ║
║                     • Localização incomum? → +risk                               ║
║                     • Malware IP? → +risk                                         ║
║                     • Browser suspeito? → +risk                                  ║
║                         │                                                         ║
║                         ▼                                                         ║
║                     [Verifica User Risk]                                          ║
║                     • Credencial vazada? → risk=HIGH                             ║
║                     • Comportamento anômalo? → risk=MED                          ║
║                         │                                                         ║
║                         ▼                                                         ║
║                     [Envia sinal]──────────►[Conditional Access]                 ║
║                                              Avalia políticas:                    ║
║                                              Policy 1: CoreBanking+HighRisk?      ║
║                                                └─ BLOCK                           ║
║                                              Policy 2: AnyApp+MedRisk?            ║
║                                                └─ REQUIRE MFA                    ║
║                                                    │                              ║
║  ◄──────[MFA challenge]─────────────────────────────┘                            ║
║  [Aprova MFA]────────────────────────────────────────────────────────────────►  ║
║                                                                                   ║
║                                              Policy 3: Unmanaged Device?         ║
║                                                └─ BLOCK                           ║
║                                                                                   ║
║                                              [GRANT ACCESS]───────────────────►  ║
║                                                                                   ║
║                         ┌──────────────────────────────────────────────┐        ║
║                         │              MICROSOFT SENTINEL              │        ║
║                         │  SigninLogs: RiskLevel, RiskState, CA result│        ║
║                         │  AADRiskyUsers: alert se risco persistente  │        ║
║                         │  SecurityAlert: blocked logins               │        ║
║                         └──────────────────────────────────────────────┘        ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Atividades de Fixação

### Questão 1
A sign-in risk policy do Entra ID está configurada para "Medium and above → Require MFA". Um atacante que roubou a senha de um usuário tenta logar de um servidor Tor. O sistema detecta "Anonymous IP". O que acontece?

a) O login é bloqueado automaticamente sem possibilidade de recuperação  
b) O login recebe risk sign-in = Medium, a CA policy exige MFA, o atacante não consegue completar o MFA (não tem o celular do usuário) e o acesso é negado  
c) O login é permitido porque o usuário digitou a senha correta  
d) A detecção de IP anônimo é apenas informativa e não bloqueia o acesso  

**Gabarito: B** — "Anonymous IP" gera sign-in risk de nível Medium. A CA policy configurada para "Medium and above → Require MFA" ativa o MFA challenge. O atacante que tem apenas a senha (credential theft) não consegue completar o MFA porque não tem acesso ao dispositivo de autenticação do usuário (app Microsoft Authenticator, token FIDO2, SMS). O acesso é negado. Este é exatamente o cenário para o qual o Identity Protection foi projetado — tornar credenciais roubadas inúteis sem o segundo fator.

---

### Questão 2
O PIM está configurado para o papel "Global Administrator" com aprovação requerida pelo CISO. Um analista SOC precisa ativar o papel às 2h durante um incidente crítico, mas o CISO não responde ao approval. Qual é o impacto e como mitigar?

a) O analista pode sobrescrever a aprovação após 30 minutos de espera  
b) O analista fica sem acesso Global Admin enquanto o CISO não aprovar — para mitigar: configurar múltiplos aprovadores (backup do CISO, CISO adjunto) ou usar um papel menos privilegiado para o cenário de incidente (ex.: Security Administrator não requer aprovação)  
c) O PIM tem um modo de emergência que bypassa a aprovação automaticamente  
d) O analista pode usar as credenciais do CISO para aprovar a própria solicitação  

**Gabarito: B** — Este é um problema real de operação SOC. A solução correta é: (1) configurar múltiplos aprovadores (grupo de aprovação com CISO e CISO adjunto); (2) ter um papel alternativo como Security Administrator com activação sem aprovação mas com MFA obrigatória — suficiente para investigação de incidente sem precisar de Global Admin; (3) as break-glass accounts são o último recurso para situações onde NENHUM admin privilegiado está disponível. O PIM não deve depender de um único ponto de falha (CISO único aprovador).

---

### Questão 3
Uma Access Review trimestral foi configurada com "If reviewers don't respond: Remove access". O gerente de um analista sênior está de férias e não revisou o acesso durante os 14 dias. O que acontece com o acesso do analista?

a) O acesso é mantido automaticamente até o gerente retornar  
b) O acesso é removido automaticamente quando o período da review expira, pois a política é "remove if no response"  
c) O Entra ID envia uma notificação de escalada para o gerente do gerente  
d) O analista pode se auto-aprovar na ausência do gerente  

**Gabarito: B** — A política "Remove access if no response" é a mais segura para compliance: quando um revisor não responde, assume-se que não pôde validar o acesso, portanto ele é revogado. Para mitigar o problema de revisores ausentes: (1) configurar múltiplos revisores (gerente + skip-level); (2) enviar lembretes aos revisores antes do prazo expirar (configurável nas Access Reviews); (3) revisar o relatório de acesso antes de bloquear funcionários ativos. A prioridade do banco (compliance BACEN) é que privilégios excessivos sejam removidos; a inconveniência de re-solicitar acesso é preferível a deixar acessos não auditados.

---

### Questão 4
O campo `RiskState` da tabela `AADRiskyUsers` no Sentinel tem valor `atRisk` para o usuário `maria.silva@bancomeridian.com.br`. Qual é a ação recomendada?

a) Bloquear a conta imediatamente sem investigação  
b) Investigar os eventos de risco individuais em `AADUserRiskEvents` para entender a causa, verificar se há outros incidentes correlacionados no Sentinel, e se confirmado comprometimento, forçar reset de senha e revocar sessões  
c) Ignorar — `atRisk` é um status informativo que não requer ação  
d) Desabilitar o Entra ID Protection para Maria Silva  

**Gabarito: B** — `atRisk` significa que o Entra ID Protection detectou indicadores de comprometimento para esta conta. A investigação correta: (1) verificar `AADUserRiskEvents` para entender quais detecções geraram o risco (leaked credentials? suspicious activity?); (2) verificar `SigninLogs` para localizar acessos recentes suspeitos; (3) verificar se há incidentes correlacionados no Sentinel (impossible travel, password spray); (4) se confirmado: forçar reset de senha (User Risk policy) + revogar sessões + verificar se há regras de encaminhamento criadas. Após remediação, o analista ou o próprio usuário (via reset de senha) pode diminuir o risk state de `atRisk` para `remediated`.

---

### Questão 5
Qual é a diferença entre uma Conditional Access policy e uma Identity Protection risk policy?

a) Não há diferença — são o mesmo recurso com nomes diferentes  
b) Identity Protection risk policies são regras legadas que serão descontinuadas; Conditional Access é o substituto moderno  
c) Identity Protection risk policies são configuradas diretamente no motor de risco e têm opções limitadas (MFA ou block); Conditional Access é mais flexível e permite condições complexas combinando risco, localização, dispositivo, aplicação e muito mais  
d) Conditional Access só funciona para usuários externos; Identity Protection é para usuários internos  

**Gabarito: C** — Esta é uma distinção sutil e importante. As Identity Protection "risk policies" (user risk policy e sign-in risk policy) são configuradas diretamente no portal Identity Protection com ações limitadas: "Block access" ou "Allow access + require MFA" (ou password change para user risk). As Conditional Access policies são muito mais flexíveis: permitem combinar múltiplas condições (risco + localização + tipo de dispositivo + aplicação específica + sessão de navegador) e ações granulares (require compliant device, require approved app, enable session monitoring via MCAS). A Microsoft recomenda implementar controles de risco via Conditional Access (usando as condições "Sign-in risk" e "User risk" no CA) em vez das risk policies legadas do Identity Protection.

---

## 9. Roteiro de Gravação

### Aula 8.1 — Entra ID Protection e PIM (55 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Ambiente: tenant com Entra ID P2 habilitado, pelo menos 5 usuários de teste
- Preparar: um usuário com risco simulado para demonstrar o painel
- Aberto: portal Azure, portal.azure.com/aad/protectionidentity
- Ter: PIM configurado com pelo menos 2 roles para demonstração

---

**[0:00 — ABERTURA | 3 minutos]**

"Módulo 8 — Identidade. Dizem que 'identidade é o novo perímetro'. No Banco Meridian, 2.800 funcionários têm contas que são a chave de acesso para todos os sistemas — e-mail, sistemas core, SharePoint, Azure. Se uma conta é comprometida, o atacante tem as mesmas permissões que o usuário legítimo.

Hoje vamos configurar o Entra ID Protection para detectar automaticamente contas comprometidas e o PIM para garantir que privilégios elevados sejam usados apenas quando necessário."

---

**[3:00 — BLOCO 1: IDENTITY PROTECTION — RISK POLICIES | 20 minutos]**

*[Screen share: portal Azure → Entra ID → Security → Identity Protection]*

"Abro o Identity Protection. Primeira coisa: verificar os usuários com risco detectado.

*[Clicar em Risky users]*

Aqui estão usuários com risco ativo. Tenho um usuário de teste com risco alto — 'rafaela.costa' com leaked credentials detectada. Vou clicar nele para mostrar os detalhes.

*[Mostrar o perfil de risco do usuário]*

Vejo: data de detecção, tipo de risco (leaked credentials), status (atRisk). Posso ver o histórico de sign-ins em risco para este usuário.

Agora vou configurar as risk policies.

*[Sign-in risk policy → configurar conforme documentação]*

User risk policy → configurar conforme documentação.

Atenção: vou adicionar as break-glass accounts na exclusão. Estas contas nunca devem ter políticas automáticas aplicadas.

*[Mostrar como adicionar exclusões]*"

---

**[23:00 — BLOCO 2: CONDITIONAL ACCESS COM RISCO | 12 minutos]**

*[Screen share: Entra ID → Security → Conditional Access]*

"Além das risk policies do Identity Protection, vou criar uma CA policy mais sofisticada.

*[New policy: CA-MFA-Risky-Logins]*

Condition: Sign-in risk — Medium and above
Condition: User risk — Medium and above

Grant: Require multi-factor authentication AND Require compliant device

Esta policy exige ambos: MFA e dispositivo conforme o Intune. Um atacante com a senha e até mesmo com um token de MFA roubado não consegue acessar se o dispositivo não estiver registrado e conforme.

*[Mostrar o diagrama de fluxo de autenticação enquanto explica]*"

---

**[35:00 — BLOCO 3: PIM — JUST-IN-TIME ACCESS | 15 minutos]**

*[Screen share: Entra ID → Identity Governance → PIM]*

"PIM. Vou mostrar o fluxo completo de uma ativação de role.

*[Clicar em Azure AD roles → Global Administrator → Settings]*

Configuro: duração máxima 2h, require MFA e justificativa, require aprovação pelo CISO.

*[Atribuir 'Head of IT' como elegível — não permanent]*

Agora, simulando ser o Head of IT:

*[Em nova aba/browser com conta de teste: portal Azure → PIM → My roles]*

Vejo 'Global Administrator' como eligible. Clico em Activate.

Preencho: Justification: "Investigação incidente de segurança crítico". Duration: 1 hour.

*[Mostrar o MFA challenge]*

Completo o MFA. A solicitação vai para aprovação do CISO.

*[Em outra aba, como CISO: PIM → Approve requests]*

O CISO vê a solicitação com a justificativa. Aprova.

*[Voltar à aba do Head of IT]*

Role ativada. Daqui a 1 hora, o acesso Global Admin expirará automaticamente."

---

**[50:00 — BLOCO 4: ACCESS REVIEWS | 3 minutos]**

*[Demonstração rápida — 3 minutos]*

"Brevemente, Access Reviews. Vou criar uma review trimestral para o grupo SOC.

*[Identity Governance → Access Reviews → New → configurar rapidamente]*

14 dias para revisar, gerentes como revisores, remover acesso se não responderem.

Esta automação garante que a cada 3 meses, todos os acessos privilegiados do SOC são confirmados por um ser humano — exatamente o que o BACEN exige na Resolução 4.893."

---

**[53:00 — ENCERRAMENTO | 2 minutos]**

"Concluímos o Módulo 8. O Entra ID Protection e o PIM formam uma camada de proteção de identidade que vai além da simples autenticação. Identity Protection detecta contas comprometidas automaticamente. PIM garante que privilégios existam apenas quando necessário. Juntos, implementam os princípios Zero Trust de 'verificar explicitamente' e 'menor privilégio'.

No Lab, vocês vão configurar as risk policies e simular uma ativação de PIM no ambiente de vocês. O gabarito no repositório inclui as configurações corretas verificadas."

---

## 10. Avaliação do Módulo

**Q1.** A user risk policy está configurada para "High risk → Require password change". Para que a política funcione corretamente, o usuário em alto risco DEVE:

a) Entrar em contato com o help desk para desbloquear a conta manualmente  
b) Tentar fazer login normalmente — sem MFA  
c) Fazer login (o que pode acionar um MFA challenge adicional), completar o MFA e em seguida ser forçado a criar uma nova senha  
d) Aguardar 24 horas até o risco ser automaticamente descartado  

**Resposta: C** — A user risk policy "require password change" funciona assim: o usuário em alto risco tenta logar, é solicitado a completar MFA (para verificar que é o usuário legítimo, não o atacante), e depois é obrigado a criar uma nova senha antes de ter acesso. A nova senha invalida as credenciais antigas (que o atacante pode ter). Após a mudança de senha bem-sucedida, o user risk state muda de `atRisk` para `remediated`.

---

**Q2.** No PIM, qual é a diferença entre uma atribuição "Active" e uma atribuição "Eligible" para um papel?

a) Active = o papel está permanentemente ativo; Eligible = o usuário pode ativar o papel JIT, mas ele não está ativo por padrão  
b) Active = aprovado por MFA; Eligible = sem MFA requerida  
c) Active = para usuários internos; Eligible = para usuários externos (B2B)  
d) Não há diferença prática  

**Resposta: A** — Active: o usuário tem o papel ativo permanentemente — qualquer token de acesso emitido já contém as permissões do papel. Eligible: o usuário está "elegível" para o papel, mas para ativá-lo precisa ir ao PIM, completar os requisitos de ativação (MFA, justificativa, aprovação), e só então recebe as permissões por um tempo limitado. O modelo Eligible implementa Just-in-Time access — reduz a janela de exposição de conta privilegiada comprometida de "permanente" para "duração da ativação".

---

**Q3.** O relatório de Access Review mostra que um analista SOC foi negado acesso ao grupo "Global-Readers" pelo gerente. O período de review expirou. O que acontece automaticamente?

a) O acesso é mantido até que o analista seja notificado manualmente  
b) Se a configuração da review é "Auto apply results", o acesso ao grupo é removido automaticamente; se não, é necessária ação manual de um admin  
c) O acesso é suspenso por 30 dias e depois restaurado  
d) A decisão de "deny" na Access Review não tem efeito — apenas "approve" tem efeito  

**Resposta: B** — Access Reviews com "Auto apply results to resource" habilitado aplicam as decisões automaticamente ao fim do período. Se o revisor negou o acesso, ao término da review o membro é removido do grupo automaticamente pelo Entra ID, sem necessidade de ação humana adicional. Isso é o ideal para compliance: o processo de revisão resulta em mudanças reais de acesso sem depender de ações manuais posteriores. Se "Auto apply" estiver desabilitado, o admin precisa aplicar os resultados manualmente (recomendado apenas para ambientes com processos de aprovação complexos).

---

**Q4.** Por que as break-glass accounts devem ser excluídas de TODAS as Conditional Access policies?

a) Porque essas contas têm mais permissões que Global Admin  
b) Porque são usadas em emergências quando as CA policies podem estar bloqueando o acesso de todos os admins (ex.: falha do provedor MFA, CA policy mal configurada que bloqueia tudo) — excluir garante que sempre haja um acesso de emergência ao tenant  
c) Porque o Entra ID não suporta CA policies para contas com nome "breakglass"  
d) Porque essas contas não precisam de segurança adicional  

**Resposta: B** — Break-glass accounts são o "extintor de incêndio" do tenant. Se uma CA policy mal configurada bloqueia todos os Global Admins, ou se o servidor MFA fica indisponível, ou se um incidente impede o acesso a accounts normais, as break-glass accounts são o último recurso para recuperar o acesso ao tenant. Se elas também estivessem sujeitas a CA policies, poderiam ser bloqueadas pela mesma política que bloqueou tudo. As break-glass accounts devem ser: raras (2 no máximo), com senhas extremamente longas guardadas offline, monitoradas continuamente (qualquer uso deve gerar alerta CRÍTICO no Sentinel), e nunca usadas no dia a dia.

---

**Q5.** O Entra ID Protection detectou "Token issuer anomaly" para o usuário `fernando.gomes@bancomeridian.com.br`. Combinado com ausência de device ID no token, qual é o indicador mais provável e qual ação imediata?

a) O usuário criou um novo dispositivo; nenhuma ação necessária  
b) Possível ataque AiTM (Adversary-in-the-Middle) onde o token OAuth foi roubado por um proxy intermediário; ação imediata: revogar todas as sessões ativas do usuário e forçar re-autenticação com MFA em dispositivo conhecido  
c) O token expirou normalmente; apenas renovar  
d) O usuário está acessando de VPN; adicionar o IP da VPN à allowlist  

**Resposta: B** — "Token issuer anomaly" é um sinal específico de AiTM: o token foi emitido de forma que não corresponde aos padrões normais de emissão do Entra ID (ex.: claim de MFA presente mas sem device registration correspondente, ou token emitido para um app não esperado). Combinado com ausência de device ID (típico de token roubado via proxy), o indicador é forte de que o token foi roubado via AiTM phishing. Ação imediata: revogar sessões via Graph API (ou executar o playbook de conta comprometida), forçar o usuário a re-autenticar em dispositivo registrado e conforme. Investigar também a origem do acesso e verificar se há atividade pós-comprometimento (acesso a SharePoint, criação de regras de e-mail, etc.).
