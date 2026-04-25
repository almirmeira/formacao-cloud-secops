# Lab 02 — YARA-L Multi-Event: Detecção de Password Spray
## Curso 1: Google SecOps Essentials · CECyber

| Campo                | Detalhe                                                              |
|:---------------------|:---------------------------------------------------------------------|
| **Módulo**           | Módulo 03 — YARA-L 2.0: Detection Engineering                        |
| **Duração**          | 3 horas                                                              |
| **Tipo**             | Laboratório Guiado (com seção de Desafio ao final)                   |
| **Dificuldade**      | Intermediário                                                         |
| **MITRE ATT&CK**     | T1110.003 — Brute Force: Password Spraying                           |
| **Pré-requisito**    | Módulo 02 concluído · Logs do Banco Meridian ingeridos no tenant      |
| **Ferramentas**      | Google SecOps Console · UDM Search · YARA-L Editor · CECyber Play Labs |

---

## 1. Contexto Situacional — A Crise do Banco Meridian

> *"Era uma segunda-feira comum no SOC do Banco Meridian, quando o sistema de monitoramento
> começou a piscar com algo incomum..."*

### A Empresa

O **Banco Meridian** é uma instituição financeira brasileira de médio porte (tier 2), com sede
em São Paulo e 12 filiais distribuídas pelo Brasil. Com 2.800 funcionários e uma carteira de
clientes empresariais e varejo, o banco opera sob regulação estrita do Banco Central do Brasil
— incluindo a Resolução BACEN 4.893, que exige capacidade de detecção e resposta a incidentes
cibernéticos em até 24 horas.

**Stack tecnológico:** Microsoft 365 (E3), Azure AD, sistema de core banking legado (TOTVS),
VMware vSphere 7.0, Google Cloud (cargas de trabalho analíticas).

**Time de SOC:** Mariana (Analista L2, 4 anos de experiência), Carlos (Analista L1) e você
(Engenheiro de Detecção, recém contratado para modernizar as capacidades de detecção do SIEM).

---

## 2. Situação Inicial

É segunda-feira, 7 de abril de 2026, 9h15. O ambiente do Banco Meridian está em operação
normal. O dashboard do Google SecOps exibe os indicadores de baseline habituais:

```
DASHBOARD - BANCO MERIDIAN SOC
─────────────────────────────────────────────────────
 Eventos/hora (última hora):   45.230
 Alertas ativos:               3  (todos nível LOW)
 MTTD média (30 dias):         18 min
 MTTR média (30 dias):         4h 23min
 Status dos feeds:             ✅ Todos HEALTHY
─────────────────────────────────────────────────────
```

A semana começou normalmente. O time está focado em finalizar a documentação de um simulado
de IR realizado na semana anterior. Nenhum alerta crítico nas últimas 72 horas.

---

## 3. Problema Identificado

**9h47:** Mariana, a analista L2, chama você:

*"Ei, acabei de ver algo estranho. O Carlos me mandou uma mensagem dizendo que dois usuários
do setor de Operações estão reclamando que suas senhas pararam de funcionar de repente. Eu
olhei no Azure AD e realmente as contas foram bloqueadas por excesso de tentativas de login
incorretas. Mas o detalhe é que eles estavam sentados na mesa deles o tempo todo. Alguém
tentou entrar nessas contas. Consegue investigar no SIEM e criar uma regra para pegar se isso
acontecer de novo?"*

Você acessa o Google SecOps e começa a investigação. Sua missão tem dois objetivos:

1. **Investigar o incidente:** entender o que aconteceu com as contas bloqueadas
2. **Criar uma regra YARA-L:** detectar automaticamente futuros ataques de password spray

---

## 4. Roteiro de Atividades

1. Investigar os eventos de login com falha via UDM Search
2. Caracterizar o padrão do ataque (IP de origem, horário, contas-alvo)
3. Criar uma regra YARA-L multi-event para detectar password spray
4. Testar a regra com os dados históricos (retrohunt)
5. Ativar a regra como live rule
6. Configurar supressão de contas de serviço legítimas
7. Documentar a detecção com mapeamento MITRE ATT&CK

---

## 5. Proposição Detalhada do Laboratório

### Ambiente Necessário

| Recurso                    | Detalhe                                                    |
|:---------------------------|:-----------------------------------------------------------|
| **Tenant Google SecOps**   | Tenant CECyber configurado no Módulo 00                    |
| **Dados sintéticos**       | Logs Windows Event do Banco Meridian (ingeridos no Módulo 02) |
| **Permissões necessárias** | Papel: `Chronicle Editor` (para criar regras)              |
| **Arquivos auxiliares**    | `lab-02-dados-adicionais.json` (na pasta do lab no repositório) |
| **Browser**                | Chrome ou Edge (última versão)                             |

### Cenário Técnico do Ataque

O atacante realizou um **password spray** — técnica T1110.003 do MITRE ATT&CK — que consiste
em tentar **uma senha comum** contra **muitos usuários diferentes**, evitando o bloqueio de
conta por excesso de tentativas numa única conta.

```
TÉCNICA: T1110.003 — Password Spraying

PADRÃO DO ATAQUE:
─────────────────────────────────────────────────────────────
Tentativa 1:  IP 203.45.12.89  → usuário: ana.rodrigues@bancomeridian.com.br  → senha: Meridian@2026  → FALHA
Tentativa 2:  IP 203.45.12.89  → usuário: bruno.lima@bancomeridian.com.br     → senha: Meridian@2026  → FALHA
Tentativa 3:  IP 203.45.12.89  → usuário: carlos.souza@bancomeridian.com.br   → senha: Meridian@2026  → FALHA
Tentativa 4:  IP 203.45.12.89  → usuário: diana.ferreira@bancomeridian.com.br → senha: Meridian@2026  → SUCESSO ⚠️
Tentativa 5:  IP 203.45.12.89  → usuário: eduardo.melo@bancomeridian.com.br   → senha: Meridian@2026  → FALHA
... (47 tentativas no total em 23 minutos)
─────────────────────────────────────────────────────────────
RESULTADO: 2 contas bloqueadas, 1 conta comprometida (diana.ferreira)
```

### Arquitetura do Detector YARA-L que Vamos Criar

```
LÓGICA DA REGRA YARA-L (password spray):

Para cada janela de 15 minutos:
  SE existirem:
    - Pelo menos 10 tentativas de login FALHADAS
    - Originadas do MESMO IP
    - Direcionadas a USUÁRIOS DIFERENTES (>= 5 usuários únicos)
    - Para o mesmo domínio corporativo (@bancomeridian.com.br)
  ENTÃO:
    Gerar alerta: "Password Spray Detectado"
    Severidade: HIGH
    Entidade: IP de origem
    MITRE: T1110.003
```

---

## 6. Script Passo a Passo

### Parte A — Investigação Inicial (45 min)

#### Passo 1: Acessar o Google SecOps e definir o período de investigação

**Ação:** Abra o navegador e acesse seu tenant Google SecOps

**Navegação:**
```
1. Abra o Chrome
2. Acesse: https://[seu-tenant].chronicle.security
3. Faça login com suas credenciais do lab
4. Na tela inicial (Dashboard), clique em "Search" no menu lateral esquerdo
```

**O que você verá:** A interface de UDM Search com um campo de busca em branco e filtros de período no canto superior direito.

---

#### Passo 2: Buscar os eventos de login com falha nas últimas 24 horas

**Ação:** Na caixa de busca UDM Search, digite a seguinte query:

```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK"
```

**Como executar:**
1. Clique na caixa de busca (grande, centralizada na tela)
2. Copie e cole a query acima
3. No filtro de período (canto superior direito), selecione "Last 24 hours"
4. Clique no botão "Search" (ícone de lupa ou tecle Enter)

**Resultado esperado:**
```
✅ A lista de eventos deve exibir entre 50 e 80 eventos de login bloqueado
   Cada evento mostra: timestamp, usuário, IP de origem, hostname
   Os eventos devem estar distribuídos entre 08h30 e 09h15 do dia de hoje
```

**O que fazer se não aparecer nenhum resultado:**
- Verifique se o período está em "Last 24 hours" (não "Last 1 hour")
- Verifique se os feeds de Windows Events estão com status "Healthy" em:
  `Settings → Ingestion → Feeds`
- Se os feeds estiverem com erro, consulte o Módulo 00, Etapa 8

---

#### Passo 3: Identificar o IP de origem dos ataques

**Ação:** Refine a busca para agrupar os eventos de falha por IP de origem:

```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK"
| group_by principal.ip
| order_by count() desc
```

> **📝 Nota sobre sintaxe:** A parte após `|` usa a sintaxe de pipeline do UDM Search para
> agregar resultados. Isso não é YARA-L — é apenas uma feature de análise da interface de busca.

**Resultado esperado:**
```
IP de Origem          Tentativas de Login Bloqueado
────────────────────  ───────────────────────────────
203.45.12.89          47
10.0.0.156            2    (máquina interna — provavelmente legítimo)
10.0.0.201            1    (máquina interna — provavelmente legítimo)
```

**O que registrar:** O IP `203.45.12.89` é claramente o atacante — 47 tentativas bloqueadas em menos de 1 hora, originadas de um IP externo (203.x.x.x = IP público).

---

#### Passo 4: Confirmar que diferentes usuários foram alvo do mesmo IP

**Ação:** Clique no IP `203.45.12.89` nos resultados para fazer pivot (investigação por entidade)

**Navegação:**
```
1. Nos resultados da busca, clique no IP "203.45.12.89"
2. Um painel lateral deve abrir com detalhes do IP
3. Clique em "View entity details" ou "Pivot on this IP"
4. Selecione a aba "Events" no painel de entidade
```

**Busca alternativa via UDM (se o pivot não funcionar):**

```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK" AND
principal.ip = "203.45.12.89"
```

**Resultado esperado:**
```
Você deve ver uma lista com os usuários-alvo, por exemplo:
─────────────────────────────────────────────────────────
09:02:14  BLOCK  ana.rodrigues@bancomeridian.com.br     203.45.12.89
09:02:31  BLOCK  bruno.lima@bancomeridian.com.br        203.45.12.89
09:02:48  BLOCK  carlos.souza@bancomeridian.com.br      203.45.12.89
09:03:05  SUCCESS diana.ferreira@bancomeridian.com.br   203.45.12.89 ⚠️
09:03:22  BLOCK  eduardo.melo@bancomeridian.com.br      203.45.12.89
... (continua)
─────────────────────────────────────────────────────────
```

**Descoberta crítica:** Um dos logins **TEVE SUCESSO** para o usuário `diana.ferreira`! Isso significa que a conta foi comprometida. Anote: você terá que reportar isso ao Mariana após o lab.

---

#### Passo 5: Verificar a timeline da conta comprometida

**Ação:** Investigue o que aconteceu com a conta `diana.ferreira` após o login bem-sucedido:

```
principal.user.email_addresses = "diana.ferreira@bancomeridian.com.br" AND
metadata.event_timestamp.seconds > 1743927783
```

> **Como encontrar o timestamp correto:** Clique no evento de login bem-sucedido da diana.ferreira
> e copie o timestamp no formato UNIX seconds exibido no detalhe do evento.

**Resultado esperado:**
```
Você deve ver eventos subsequentes da conta da diana.ferreira:
─────────────────────────────────────────────────────────────────────
09:03:05  USER_LOGIN SUCCESS       IP: 203.45.12.89
09:03:47  FILE_ACCESS             Acesso a: /sharepoint/rh/planilhas/
09:04:12  EMAIL_TRANSACTION       Envio de e-mail para: externo@gmail.com
09:06:33  USER_LOGOUT
─────────────────────────────────────────────────────────────────────
```

**Conclusão da investigação:** O atacante fez login bem-sucedido, acessou documentos do RH no SharePoint e enviou um e-mail para um endereço externo. Possível exfiltração de dados.

---

### Parte B — Criação da Regra YARA-L (1h 15min)

#### Passo 6: Navegar para o Editor de Regras YARA-L

**Navegação:**
```
1. No menu lateral esquerdo do Google SecOps, clique em "Detection"
2. Clique na aba "Rules"
3. Clique no botão "+ New rule" (canto superior direito)
4. O editor de YARA-L será aberto em branco
```

**O que você verá:** Um editor de código com syntax highlighting, um painel de documentação
à direita e botões de "Test" e "Save" na barra superior.

---

#### Passo 7: Escrever a regra YARA-L — Esqueleto básico

**Ação:** No editor de regras, apague o conteúdo padrão e comece a digitar nossa regra.
Começamos com o esqueleto básico:

```yara-l
rule password_spray_detection {
  meta:
    author = "CECyber - Engenheiro de Detecção"
    description = "Detecta ataques de Password Spray (T1110.003)"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110.003"
    created_date = "2026-04-07"
    false_positives = "Sistemas de teste de carga de autenticação"

  events:
    // Aqui vamos definir os eventos que queremos correlacionar

  match:
    // Aqui definimos a janela temporal e os campos de agrupamento

  condition:
    // Aqui definimos os critérios quantitativos para disparo

  outcome:
    // Aqui definimos o alerta gerado
}
```

> **📝 Explicação do esqueleto:**
> - `meta`: metadados da regra (não afeta a lógica de detecção)
> - `events`: define quais eventos queremos capturar e como referenciá-los
> - `match`: define a janela de tempo e os campos de agrupamento (o que agrupa os eventos)
> - `condition`: define o critério quantitativo para disparar o alerta
> - `outcome`: define o que o alerta vai conter quando disparar

---

#### Passo 8: Definir os eventos a capturar

**Ação:** Substitua o comentário na seção `events:` pela definição dos eventos:

```yara-l
  events:
    // Evento $e1 = tentativa de login com falha
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"
    
    // Filtrar apenas logins com senha incorreta (não lockouts por outras causas)
    $e1.security_result.category_details = /.*invalid.*password.*/
    
    // Filtrar apenas para o domínio corporativo do Banco Meridian
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/
    
    // Excluir contas de serviço (serão tratadas na supressão adiante)
    not $e1.target.user.email_addresses = /svc-.*/
    not $e1.target.user.email_addresses = /bot-.*/
    not $e1.target.user.email_addresses = /noreply-.*/
```

> **Explicação linha a linha:**
>
> `$e1` → nome da variável para este tipo de evento (podemos ter $e1, $e2, etc. em regras multi-event)
>
> `.metadata.event_type = "USER_LOGIN"` → filtra apenas eventos de tipo login
>
> `.security_result.action = "BLOCK"` → filtra apenas logins bloqueados/falhados
>
> `.security_result.category_details = /.*invalid.*password.*/` → regex para garantir que é falha
> de senha (e não bloqueio por outras razões como expiração)
>
> `not` → exclusão de padrões. Contas que começam com `svc-`, `bot-` ou `noreply-` são excluídas
> pois são contas de serviço que podem ter muitas falhas legítimas

---

#### Passo 9: Definir a janela temporal e agrupamento

**Ação:** Substitua o comentário na seção `match:`:

```yara-l
  match:
    // Agrupar eventos pelo IP de origem, dentro de uma janela de 15 minutos
    $e1.principal.ip over 15m
```

> **Explicação:**
>
> `$e1.principal.ip` → estamos agrupando PELO IP de origem. Todos os eventos do mesmo IP,
> dentro da janela de 15 minutos, serão analisados juntos.
>
> `over 15m` → janela deslizante de 15 minutos. O Google SecOps avalia continuamente: "nos
> últimos 15 minutos, o IP X gerou quantos eventos $e1?"
>
> **Por que 15 minutos?** Em um password spray real, o atacante tenta ser rápido para evitar
> detecção baseada em tempo. 15 minutos é uma janela ampla o suficiente para capturar o ataque
> completo, mas curta o suficiente para não gerar falsos positivos com tentativas isoladas ao
> longo do dia.

---

#### Passo 10: Definir os critérios de disparo

**Ação:** Substitua o comentário na seção `condition:`:

```yara-l
  condition:
    // Condição 1: pelo menos 10 tentativas de login falhadas do mesmo IP
    #e1 >= 10
    
    // Condição 2: pelo menos 5 usuários distintos foram alvo
    // (diferente de brute force, onde um só usuário é atacado)
    count(distinct $e1.target.user.email_addresses) >= 5
```

> **Explicação:**
>
> `#e1 >= 10` → o símbolo `#` (hash/cardinality) conta quantos eventos $e1 ocorreram na janela.
> Exige pelo menos 10 tentativas falhadas do mesmo IP em 15 minutos.
>
> `count(distinct ...) >= 5` → conta quantos USUÁRIOS DIFERENTES foram alvo. Isso é o coração
> da detecção de password spray: muitos usuários, mesma senha.
>
> **Combinação das duas condições:** Um IP que tentou logar 10 vezes no mesmo usuário (brute force
> clássico) NÃO dispararia esta regra, pois `count(distinct ...)` seria 1. Apenas ataques onde
> MUITOS usuários são alvo dispararão a regra.

---

#### Passo 11: Definir o outcome (conteúdo do alerta)

**Ação:** Substitua o comentário na seção `outcome:`:

```yara-l
  outcome:
    // Campos que aparecerão no alerta gerado
    $ip_origem = array_distinct($e1.principal.ip)
    $usuarios_alvo = array_distinct($e1.target.user.email_addresses)
    $total_tentativas = count($e1)
    $usuarios_unicos = count(distinct $e1.target.user.email_addresses)
    $janela_inicio = min($e1.metadata.event_timestamp)
    $janela_fim = max($e1.metadata.event_timestamp)
    $severity = "HIGH"
    $risk_score = 85
```

> **Explicação:**
>
> Os campos do `outcome` são os que aparecerão no alerta dentro do painel de Cases do Google SecOps.
> Quanto mais contexto você colocar aqui, mais fácil será para o analista de SOC triagear o alerta.
>
> - `$ip_origem` → lista de IPs de origem (agrupados)
> - `$usuarios_alvo` → lista de todos os usuários que foram alvo
> - `$total_tentativas` → número total de tentativas bloqueadas
> - `$usuarios_unicos` → quantos usuários distintos foram alvo
> - `$janela_inicio/fim` → início e fim da janela de ataque (para a timeline)
> - `$severity` e `$risk_score` → serão usados pelo SOAR para priorização

---

#### Passo 12: Regra YARA-L completa — código final

**Verifique:** Sua regra completa deve se parecer com isto:

```yara-l
rule password_spray_detection {
  meta:
    author = "CECyber - Engenheiro de Detecção"
    description = "Detecta ataques de Password Spray contra o domínio Banco Meridian"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110.003"
    mitre_attack_technique_name = "Brute Force: Password Spraying"
    created_date = "2026-04-07"
    false_positives = "Sistemas de teste de carga de autenticação; verificar com TI antes de escalar"

  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"
    $e1.security_result.category_details = /.*invalid.*password.*/
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/
    not $e1.target.user.email_addresses = /svc-.*/
    not $e1.target.user.email_addresses = /bot-.*/
    not $e1.target.user.email_addresses = /noreply-.*/

  match:
    $e1.principal.ip over 15m

  condition:
    #e1 >= 10
    count(distinct $e1.target.user.email_addresses) >= 5

  outcome:
    $ip_origem = array_distinct($e1.principal.ip)
    $usuarios_alvo = array_distinct($e1.target.user.email_addresses)
    $total_tentativas = count($e1)
    $usuarios_unicos = count(distinct $e1.target.user.email_addresses)
    $janela_inicio = min($e1.metadata.event_timestamp)
    $janela_fim = max($e1.metadata.event_timestamp)
    $severity = "HIGH"
    $risk_score = 85
}
```

---

#### Passo 13: Testar a regra com Retrohunt

**O que é Retrohunt:** É a capacidade de aplicar uma regra NOVA sobre dados HISTÓRICOS já
armazenados no Google SecOps, para verificar se a regra teria detectado ataques passados.

**Ação:**
```
1. Com a regra escrita no editor, clique no botão "Run retrohunt" (barra superior)
2. Na janela de configuração do retrohunt:
   - Start time: ontem às 00:00 (dia -1)
   - End time: agora
3. Clique em "Run"
4. Aguarde o processamento (pode levar 2–5 minutos)
```

**Resultado esperado:**
```
Retrohunt concluído:
─────────────────────────────────────────────────────────
Período analisado: 2026-04-06 00:00 → 2026-04-07 10:00
Detecções encontradas: 1
─────────────────────────────────────────────────────────
DETECÇÃO #1:
  Timestamp: 2026-04-07 09:02:14 → 09:25:07
  IP de origem: 203.45.12.89
  Tentativas: 47
  Usuários-alvo: 31
  Usuários únicos: 22
  Severidade: HIGH
  Risk Score: 85
─────────────────────────────────────────────────────────
```

**O que isso confirma:** A regra TEM RETROSPECTIVA — ela teria detectado o ataque que aconteceu
hoje de manhã. Nenhum falso positivo nos dados históricos (apenas 1 detecção, que é o ataque real).

---

#### Passo 14: Ativar a regra como Live Rule

**O que é Live Rule:** Ao ativar como live rule, o Google SecOps avalia a regra em TEMPO REAL
contra todos os novos eventos que chegam, gerando alertas imediatamente.

**Ação:**
```
1. Clique no botão "Activate" (ou "Save and activate") na barra superior
2. Na janela de confirmação:
   - Rule name: "password_spray_detection"
   - Severity: HIGH (já configurado no meta)
   - Alert mode: Per detection (um alerta por janela de 15 min que dispara)
3. Clique em "Activate"
```

**Resultado esperado:**
```
✅ Regra ativada com sucesso
Status: ACTIVE — Live Rule
Rule ID: ru_XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

**O que monitorar:** Nos próximos minutos, se houver novos ataques de password spray contra o
Banco Meridian, a regra vai gerar um alerta automaticamente no painel de Cases.

---

### Parte C — Validação e Documentação (30 min)

#### Passo 15: Verificar o alerta gerado no painel de Cases

**Navegação:**
```
1. Clique em "Cases" no menu lateral
2. Clique em "Alerts" na aba superior
3. Procure pelo alerta com o nome "password_spray_detection"
```

**Resultado esperado:**
```
ALERTA: password_spray_detection
Status: New
Severidade: HIGH
Risk Score: 85
IP de origem: 203.45.12.89
Usuários-alvo: [lista de 22 usuários]
Tentativas: 47
Janela: 09:02:14 → 09:25:07
Técnica MITRE: T1110.003
```

---

#### Passo 16: Documentar a regra com mapeamento MITRE ATT&CK completo

**Ação:** Crie o arquivo de documentação da regra no repositório local:

```bash
cat > $LAB_DIR/regras-yara-l/password_spray_detection.md << 'EOF'
# Regra: password_spray_detection
## Metadados
- **Criada em:** 2026-04-07
- **Autor:** [Seu Nome] — CECyber Lab
- **Versão:** 1.0

## MITRE ATT&CK
- **Tática:** Credential Access (TA0006)
- **Técnica:** T1110 — Brute Force
- **Sub-técnica:** T1110.003 — Password Spraying

## Descrição do Ataque
Password Spraying tenta UMA MESMA SENHA contra MUITOS usuários,
contornando políticas de lockout que monitoram tentativas por conta.

## Lógica de Detecção
- Janela: 15 minutos
- Critério: >= 10 logins falhados do mesmo IP
- Critério: >= 5 usuários distintos como alvo
- Exclusão: contas de serviço (svc-*, bot-*, noreply-*)

## Falsos Positivos Conhecidos
- Sistemas de teste de autenticação (QA/Dev) — verificar com TI
- Pen tests autorizados — verificar com time de segurança

## Ações de Resposta (Playbook)
1. Bloquear IP de origem no WAF/firewall perimetral
2. Verificar se algum login foi bem-sucedido (conta comprometida)
3. Resetar senhas dos usuários alvo
4. Notificar CISO e área de risco (requisito BACEN 4.893)
5. Abrir boletim de incidente

## Histórico de Ajustes
| Data       | Ajuste                          | Motivo                        |
|:----------:|:--------------------------------|:------------------------------|
| 2026-04-07 | Versão inicial criada           | Resposta ao incidente real     |
EOF

echo "✅ Documentação criada em $LAB_DIR/regras-yara-l/"
```

---

## 7. Objetivos por Etapa

| Etapa  | Objetivo                                                     | Critério de Aceitação                                         |
|:------:|:-------------------------------------------------------------|:--------------------------------------------------------------|
| A (1–5)| Investigar o incidente de password spray                     | Identificar o IP atacante, 47 tentativas, 1 conta comprometida |
| B (6–14)| Criar regra YARA-L multi-event funcional                    | Regra salva, retrohunt retorna 1 detecção sem falsos positivos |
| C (15–16)| Validar alerta e documentar a regra                        | Alerta HIGH visível no painel de Cases; arquivo .md criado    |

---

## 8. Gabarito Completo

### Gabarito — Parte A: Investigação

**O que o aluno deve descobrir:**

1. **IP do atacante:** `203.45.12.89` — IP externo com 47 tentativas de login bloqueadas
2. **Janela do ataque:** entre 09:02:14 e 09:25:07 (23 minutos)
3. **Número de usuários-alvo:** 31 usuários diferentes foram alvo
4. **Conta comprometida:** `diana.ferreira@bancomeridian.com.br` — login bem-sucedido às 09:03:05
5. **Ações pós-comprometimento:** acesso ao SharePoint/RH e envio de e-mail para externo (provável exfiltração)

**Query UDM correta para identificar o IP:**
```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK"
| group_by principal.ip
| order_by count() desc
```

**Query UDM correta para a timeline da conta comprometida:**
```
principal.user.email_addresses = "diana.ferreira@bancomeridian.com.br" AND
metadata.event_timestamp.seconds > [timestamp do login bem-sucedido]
```

---

### Gabarito — Parte B: Regra YARA-L

**Regra YARA-L correta e comentada:**

```yara-l
rule password_spray_detection {
  meta:
    author = "CECyber - Engenheiro de Detecção"
    description = "Detecta ataques de Password Spray contra o domínio Banco Meridian"
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110.003"
    mitre_attack_technique_name = "Brute Force: Password Spraying"
    created_date = "2026-04-07"
    false_positives = "Sistemas de teste de carga de autenticação"

  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"
    $e1.security_result.category_details = /.*invalid.*password.*/
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/
    not $e1.target.user.email_addresses = /svc-.*/
    not $e1.target.user.email_addresses = /bot-.*/
    not $e1.target.user.email_addresses = /noreply-.*/

  match:
    $e1.principal.ip over 15m

  condition:
    #e1 >= 10
    count(distinct $e1.target.user.email_addresses) >= 5

  outcome:
    $ip_origem = array_distinct($e1.principal.ip)
    $usuarios_alvo = array_distinct($e1.target.user.email_addresses)
    $total_tentativas = count($e1)
    $usuarios_unicos = count(distinct $e1.target.user.email_addresses)
    $janela_inicio = min($e1.metadata.event_timestamp)
    $janela_fim = max($e1.metadata.event_timestamp)
    $severity = "HIGH"
    $risk_score = 85
}
```

**Resultado do Retrohunt esperado:** 1 detecção, referente ao ataque de 09:02 de hoje.
Nenhum falso positivo nos dados históricos do Banco Meridian.

---

### Gabarito — Erros Comuns e Soluções

| Erro Comum                                      | Causa                                           | Solução                                          |
|:------------------------------------------------|:------------------------------------------------|:-------------------------------------------------|
| Regra não salva: "Syntax error at line X"       | Erro de sintaxe no YARA-L                       | Revisar a linha indicada; verificar aspas e parênteses |
| Retrohunt retorna 0 detecções                   | Dados de log não ingeridos ou regra muito restrita | Verificar feeds; relaxar o threshold para 5 eventos |
| Retrohunt retorna muitos falsos positivos        | Threshold muito baixo ou sem filtro de domínio  | Aumentar `#e1 >= 10` e verificar regex do domínio |
| Alerta não aparece no painel de Cases           | Regra não foi ativada como live rule             | Verificar status da regra em Detection → Rules   |
| Regex do domínio não funciona                   | Erro na expressão regular                        | Testar: `$e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/` |

---

## Desafio Extra (Opcional — 30 min)

Para alunos que concluíram o lab com antecedência:

**Desafio:** Modifique a regra para também detectar password spray via **OWA (Outlook Web Access)**,
onde os eventos de login têm `metadata.product_name = "Exchange"` e o campo de usuário está em
`target.user.userid` (não em `email_addresses`).

**Dica:** Você precisará criar uma segunda variável de evento (`$e2`) para capturar os logins OWA
e combinar as duas na seção `condition`.

**Solução do desafio:** disponível em `lab-02-desafio-gabarito.md` (acesso após o prazo de entrega).

---

*Lab 02 · Módulo 03 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
