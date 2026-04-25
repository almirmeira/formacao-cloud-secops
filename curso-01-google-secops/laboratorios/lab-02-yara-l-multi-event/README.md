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

**O que este passo faz:** Estabelece o ponto de partida da investigação, garantindo que você está conectado ao ambiente correto e que os logs do Banco Meridian estão acessíveis. Antes de executar qualquer query, é fundamental confirmar que o tenant está ativo e que o período de análise cobre a janela onde o incidente ocorreu — investigar com o período errado (por exemplo, "Last 1 hour" quando o ataque ocorreu há 3 horas) resulta em zero eventos e desperdício de tempo de diagnóstico.

**Por que agora:** Este é o primeiro passo porque não é possível investigar sem acesso ao ambiente. Confirmar o acesso antes de iniciar a investigação também verifica que as permissões necessárias estão corretas — uma regra YARA-L não pode ser salva por um usuário sem o papel `Chronicle Editor`, e descobrir isso no Passo 7 seria custoso em tempo.

**Ação:** Abra o navegador e acesse seu tenant Google SecOps

**Navegação:**
```
1. Abra o Chrome
2. Acesse: https://[seu-tenant].chronicle.security
3. Faça login com suas credenciais do lab
4. Na tela inicial (Dashboard), clique em "Search" no menu lateral esquerdo
```

**O que você verá:** A interface de UDM Search com um campo de busca em branco e filtros de período no canto superior direito.

**O que fazer se der errado:**
- Se o tenant retornar erro 403 (acesso negado), verifique se está usando as credenciais do lab fornecidas pelo instrutor — não as credenciais pessoais da Google
- Se a página não carregar, verifique se está na VPN do lab (se aplicável no seu ambiente CECyber)
- Se o dashboard carregar mas não mostrar dados, verifique o status dos feeds em `Settings → Ingestion → Feeds` — todos devem estar com status "Healthy"

---

#### Passo 2: Buscar os eventos de login com falha nas últimas 24 horas

**O que este passo faz:** Executa a primeira query de investigação, mapeando o volume geral de tentativas de login bloqueadas no ambiente do Banco Meridian nas últimas 24 horas. Esta visão panorâmica é o "mapa" da situação antes de qualquer pivoting — você ainda não sabe de onde vêm os ataques, apenas quantos eventos suspeitos existem e se o volume é anômalo em relação ao baseline. O campo `security_result.action = "BLOCK"` captura eventos de login onde o sistema negou acesso, incluindo tanto falhas de senha quanto lockouts, mas ainda não filtra por causa específica — isso será refinado nos passos seguintes.

**Por que agora:** A query mais ampla sempre vem primeiro na investigação. Começar diretamente com filtros específicos (por IP, por usuário) pode fazer você perder um padrão que só é visível na visão agregada — por exemplo, se o ataque vier de múltiplos IPs simultaneamente (distributed password spray), a query por IP único não capturaria o padrão completo. Construa o quadro geral antes de focar.

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

**O que você deve ver:**
```
✅ A lista de eventos deve exibir entre 50 e 80 eventos de login bloqueado
   Cada evento mostra: timestamp, usuário, IP de origem, hostname
   Os eventos devem estar distribuídos entre 08h30 e 09h15 do dia de hoje
```

Um volume de 50–80 bloqueios em 24 horas é altamente anômalo para o Banco Meridian — em dias normais, o baseline é de 3 a 8 bloqueios por dia (usuários esquecendo senha, troca de dispositivo). O volume anômalo é o primeiro indicador de que algo fora do padrão está acontecendo.

**O que fazer se não aparecer nenhum resultado:**
- Verifique se o período está em "Last 24 hours" (não "Last 1 hour")
- Verifique se os feeds de Windows Events estão com status "Healthy" em:
  `Settings → Ingestion → Feeds`
- Se os feeds estiverem com erro, consulte o Módulo 00, Etapa 8
- Se os feeds estiverem saudáveis mas não houver eventos, aguarde 5 minutos — os logs podem estar em processamento de ingestão

---

#### Passo 3: Identificar o IP de origem dos ataques

**O que este passo faz:** Agrupa os eventos de login bloqueado por IP de origem e ordena pelo volume de tentativas, revelando qual endereço IP está gerando o maior volume de falhas. Esta técnica de agregação é o método analítico padrão para identificar a "fonte" de um ataque de credential stuffing ou password spray — o IP com volume muito acima dos demais é o candidato principal do atacante. O operador `| group_by` do UDM Search transforma a lista de eventos individuais em uma visão analítica agregada.

**Por que agora:** Identificar o IP do atacante antes de qualquer outra análise é crítico porque todas as próximas investigações (quais usuários foram alvo, qual foi a conta comprometida, qual foi a timeline do ataque) serão filtradas por este IP. Sem identificar a fonte primeiro, você investigaria dados de todos os IPs misturados, o que torna impossível separar o ataque real de eventos legítimos no mesmo período.

**Ação:** Refine a busca para agrupar os eventos de falha por IP de origem:

```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK"
| group_by principal.ip
| order_by count() desc
```

> **Nota sobre sintaxe:** A parte após `|` usa a sintaxe de pipeline do UDM Search para
> agregar resultados. Isso não é YARA-L — é apenas uma feature de análise da interface de busca.

**O que você deve ver:**
```
IP de Origem          Tentativas de Login Bloqueado
────────────────────  ───────────────────────────────
203.45.12.89          47
10.0.0.156            2    (máquina interna — provavelmente legítimo)
10.0.0.201            1    (máquina interna — provavelmente legítimo)
```

O IP `203.45.12.89` é claramente o atacante — 47 tentativas bloqueadas em menos de 1 hora, originadas de um IP externo (203.x.x.x = IP público). Os IPs internos (10.0.0.x) com 1–2 tentativas são provavelmente usuários legítimos que erraram a senha uma vez — ruído normal que será excluído da regra YARA-L nos próximos passos.

**O que fazer se der errado:**
- Se o resultado mostrar dezenas de IPs externos com volumes similares, pode ser um ataque distribuído (distributed password spray). Registre todos os IPs externos com mais de 5 tentativas — este padrão requer uma regra YARA-L com lógica diferente da que criaremos neste lab
- Se o `| group_by` retornar erro de sintaxe, verifique se está usando a UDM Search e não o YARA-L Editor — as sintaxes são diferentes

---

#### Passo 4: Confirmar que diferentes usuários foram alvo do mesmo IP

**O que este passo faz:** Realiza o primeiro "pivoting" da investigação — partindo do IP identificado no Passo 3, expande a análise para ver quais usuários foram alvo deste IP específico. Esta técnica de pivoting é o mecanismo central de qualquer investigação de incidente: cada dado confirmado se torna o ponto de partida para a próxima descoberta. Neste passo, a confirmação de que um único IP está atacando múltiplos usuários diferentes (e não tentando uma única conta repetidamente) é a evidência que distingue um ataque de password spray de uma tentativa de brute force simples. A descoberta de um evento `ALLOW` (login bem-sucedido) no meio dos bloqueios eleva o incidente imediatamente — não é mais apenas uma tentativa de ataque, é uma conta comprometida ativa.

**Por que agora:** O pivoting por IP vem imediatamente após a identificação da fonte porque precisamos confirmar o padrão de ataque antes de criar a regra. Se um único IP estivesse atacando apenas um usuário repetidamente, a regra YARA-L teria uma lógica diferente (brute force single-user, com threshold mais baixo). O padrão de múltiplos usuários confirma que precisamos da regra multi-event com `count(distinct)` na seção `condition`.

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

**O que este passo faz:** Investiga as ações realizadas pela conta `diana.ferreira` imediatamente após o login bem-sucedido do atacante. Esta etapa é fundamental para determinar o impacto real do incidente: saber que uma conta foi comprometida é apenas metade da informação — a outra metade é o que o atacante fez com esse acesso. Acesso a dados do RH, envio de e-mails para endereços externos e download de arquivos são os indicadores mais comuns de exfiltração de dados, o que pode ativar obrigações de notificação ao BACEN (incidente relevante) e à ANPD (violação de dados pessoais conforme LGPD).

**Por que agora:** A análise de timeline pós-comprometimento é feita antes de criar qualquer regra YARA-L porque ela complementa a compreensão do ataque — sem saber o que o atacante fez após o acesso, não é possível estimar corretamente a severidade do alerta que a regra deve gerar nem definir o `risk_score` adequado para acionar o playbook de resposta correto.

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

**O que este passo faz:** Abre o editor de regras YARA-L do Google SecOps, onde a lógica de detecção será escrita. O editor oferece syntax highlighting específico para YARA-L, autocompletar de campos UDM e um painel de validação em tempo real — recursos que reduzem erros de sintaxe durante o desenvolvimento. A regra que será criada nos próximos passos transformará o padrão de ataque que você investigou manualmente (IP → múltiplos usuários → sequência rápida) em uma detecção automatizada e contínua.

**Por que agora:** A criação da regra começa somente após a investigação manual (Passos 1–5) estar completa. Criar uma regra sem entender o ataque real é um erro comum que resulta em regras com thresholds errados, filtros inadequados ou campos UDM incorretos. Com o padrão do ataque compreendido — 47 tentativas, 31 usuários, janela de 23 minutos, IP 203.45.12.89 — você agora tem todos os parâmetros necessários para configurar a regra de forma precisa.

**Navegação:**
```
1. No menu lateral esquerdo do Google SecOps, clique em "Detection"
2. Clique na aba "Rules"
3. Clique no botão "+ New rule" (canto superior direito)
4. O editor de YARA-L será aberto em branco
```

**O que você deve ver:** Um editor de código com syntax highlighting, um painel de documentação à direita e botões de "Test" e "Save" na barra superior.

**O que fazer se der errado:**
- Se o botão "+ New rule" não aparecer, seu usuário não tem o papel `Chronicle Editor` — solicite ao instrutor que verifique as permissões IAM do projeto
- Se o editor abrir com um código de exemplo pré-preenchido, selecione todo o conteúdo (Ctrl+A) e delete antes de começar

---

#### Passo 7: Escrever a regra YARA-L — Esqueleto básico

**O que este passo faz:** Cria o esqueleto estrutural da regra YARA-L com a seção `meta` preenchida e as demais seções em branco com comentários. A seção `meta` não afeta a lógica de detecção — ela documenta a regra para o time do SOC, mapeia a técnica MITRE ATT&CK para relatórios de cobertura e define a severidade do alerta que será gerado. O campo `false_positives` é especialmente importante: documenta os cenários conhecidos onde a regra pode disparar incorretamente, economizando tempo de triagem quando um analista receber um falso positivo.

**Por que agora:** O esqueleto com `meta` completo deve ser escrito antes da lógica porque ele define o "contrato" da regra — qual técnica ela detecta, qual a severidade esperada, quem é responsável. Desenvolvedores que pulam esta etapa costumam deixar a documentação para depois e nunca documentam. Com o esqueleto em branco, o editor já valida que a estrutura YAML está correta, o que confirma que podemos avançar com a lógica.

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

**O que este passo faz:** Preenche a seção `events` com os filtros que selecionam exatamente os eventos relevantes para a detecção de password spray. Cada linha da seção `events` funciona como uma cláusula WHERE — o motor YARA-L só considera eventos que satisfaçam TODOS os critérios simultaneamente. O filtro `security_result.category_details = /.*invalid.*password.*/` é especialmente crítico: sem ele, a regra também contaria bloqueios por conta expirada, lockout por excesso de tentativas anteriores ou erros de MFA — eventos que aumentariam a contagem artificialmente e gerariam falsos positivos. As exclusões de contas de serviço (`svc-`, `bot-`, `noreply-`) evitam que sistemas automáticos de monitoramento que tentam autenticar com senhas expiradas contaminem a contagem.

**Por que agora:** A seção `events` é o coração da regra — ela determina quais dados chegam até as seções `match` e `condition`. Definir os filtros com precisão agora evita ter que reescrevê-los depois, quando um retrohunt revelar falsos positivos. Cada filtro adicionado aqui foi derivado diretamente da investigação dos Passos 1–4: você sabe exatamente que tipo de evento o atacante gerou.

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

**O que este passo faz:** Define a seção `match`, que é o mecanismo que transforma esta regra de uma query simples em uma detecção temporal sofisticada. A diretiva `$e1.principal.ip over 15m` instrui o motor YARA-L a agrupar todos os eventos de login bloqueado que compartilhem o mesmo IP de origem e que ocorreram dentro de uma janela de 15 minutos. Sem a seção `match`, o motor avaliaria cada evento individualmente — e um único evento de login bloqueado nunca dispararia o alerta. Com ela, o motor avalia o CONJUNTO de eventos que chegaram do mesmo IP nos últimos 15 minutos e aplica a `condition` sobre esse conjunto.

**Por que agora:** A janela de 15 minutos é diretamente derivada da análise do Passo 4 — o ataque real ocorreu entre 09:02:14 e 09:25:07, uma janela de 23 minutos. Escolhemos 15 minutos porque ataques de password spray bem configurados costumam ocorrer em rajadas rápidas para evitar sistemas de detecção baseados em horário — 15 minutos captura a maioria dessas rajadas sem ser tão longo que aumente o tempo de detecção e sem ser tão curto que divida o mesmo ataque em múltiplas janelas.

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

**O que este passo faz:** Define a seção `condition`, que é o critério quantitativo que determina quando a regra dispara o alerta. A condição combina dois requisitos simultâneos: pelo menos 10 tentativas de login bloqueado do mesmo IP (`#e1 >= 10`) E pelo menos 5 usuários distintos como alvo (`count(distinct $e1.target.user.email_addresses) >= 5`). A combinação dos dois é o que torna a regra específica para password spray — a primeira condição sozinha capturaria também brute force de conta única; a segunda condição sozinha capturaria logins com falha de 5 usuários diferentes de uma rede corporativa com IP NAT (que pode ser 1 só atacante ou 5 usuários legítimos esquecendo a senha no mesmo dia).

**Por que agora:** O threshold de `#e1 >= 10` foi derivado da investigação: o atacante realizou 47 tentativas, mas queremos capturar ataques menores (antes que causem mais dano). 10 é um ponto seguro acima do ruído normal do ambiente (baseline de 3–8 bloqueios/dia no Banco Meridian, jamais 10 de um único IP). O threshold de 5 usuários distintos foi escolhido porque é improvável que 5 usuários diferentes esqueçam a senha no mesmo instante de um único IP — esse padrão é característica definitória do password spray.

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

**O que este passo faz:** Preenche a seção `outcome` com os campos que aparecerão no alerta quando a regra disparar. O `outcome` é a "embalagem" do alerta — ele não afeta QUANDO a regra dispara (isso é a `condition`), mas determina QUAIS informações o analista verá quando abrir o alerta no painel de Cases. Um `outcome` bem projetado reduz drasticamente o tempo de triagem: em vez de o analista precisar executar 4 queries para entender o que aconteceu, todas as informações críticas — IP do atacante, lista de usuários-alvo, duração da janela de ataque e risk score — já estão no alerta. O `$risk_score = 85` sinaliza ao SOAR que este alerta deve acionar o playbook de resposta a password spray automaticamente.

**Por que agora:** O `outcome` deve ser definido junto com a lógica da regra, não depois, porque os campos calculáveis (`count`, `array_distinct`, `min`, `max`) usam as mesmas variáveis de evento da seção `events`. Se você adicionar uma variável no `outcome` que não foi definida em `events`, o editor retorna erro de compilação. Definir agora garante que tudo é consistente antes do teste de Retrohunt.

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

**O que este passo faz:** Consolida todas as seções desenvolvidas nos passos anteriores em um bloco único para verificação final antes do teste. Esta revisão integral é uma prática essencial de Detection Engineering: antes de testar qualquer regra com dados reais, o analista percorre o código do início ao fim para verificar consistência lógica — as variáveis definidas em `events` são corretamente referenciadas em `condition` e `outcome`? O threshold da `condition` faz sentido com a janela definida em `match`? Os campos `severity` e `risk_score` refletem a gravidade real do ataque? Um erro de lógica descoberto agora custa 1 minuto para corrigir; descoberto após o retrohunt custa 20 minutos.

**Por que agora:** A consolidação e revisão final ocorrem ANTES do retrohunt porque o retrohunt é um processo computacionalmente custoso que consome créditos do tenant. Corrigir erros óbvios antes de rodar o retrohunt evita desperdício de recursos e tempo de espera desnecessário.

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

**O que este passo faz:** Executa o Retrohunt — a funcionalidade que aplica a regra YARA-L recém-criada sobre dados históricos já armazenados no Google SecOps. O Retrohunt é a etapa de validação obrigatória antes de ativar qualquer regra como Live Rule. Ele responde à pergunta fundamental: "Esta regra teria detectado o ataque real que investigamos?" Se o Retrohunt retornar 0 detecções sobre o período onde sabemos que o ataque ocorreu, há um erro na regra — seja nos filtros de `events`, no threshold da `condition` ou nos campos UDM usados. Se retornar muitas detecções em períodos onde não houve ataque, há um problema de falsos positivos que precisa de ajuste.

**Por que agora:** O Retrohunt é feito ANTES de ativar a Live Rule porque ativar uma regra com falsos positivos em produção sobrecarrega o SOC — cada FP gera um alerta que precisa ser triado por Mariana ou Carlos, consumindo tempo que deveria ser usado em incidentes reais. O custo de um Retrohunt com resultado ruim é apenas o tempo de espera e um ajuste de código; o custo de uma Live Rule com FPs é o desgaste do time inteiro.

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

**O que este passo faz:** Ativa a regra YARA-L `password_spray_detection` como uma Live Rule, tornando-a parte do mecanismo de detecção contínua do Google SecOps. A partir desta ativação, o motor YARA-L avalia todos os eventos novos que chegam em tempo real contra esta regra — sem latência, 24 horas por dia, 7 dias por semana, sem nenhuma intervenção humana. Quando o padrão de password spray for detectado novamente, um alerta será gerado automaticamente no painel de Cases, com todas as informações do `outcome` preenchidas, e o SOAR poderá iniciar automaticamente o playbook de resposta.

**Por que agora:** A ativação como Live Rule é o objetivo final deste lab — transformar uma investigação manual em uma detecção automatizada e contínua. Isso reduz o MTTD (Mean Time to Detect) de "quando o analista notar" para "segundos após o ataque ultrapassar o threshold". Para o Banco Meridian, que tem apenas três analistas cobrindo 2.800 usuários, esta automação é a diferença entre detectar um ataque de password spray na hora ou só no dia seguinte durante a revisão de logs.

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

**O que este passo faz:** Navega até o painel de Cases do Google SecOps para confirmar que a Live Rule gerou o alerta esperado com as informações corretas do `outcome`. A verificação do alerta é a validação final do ciclo completo de Detection Engineering: investigação → criação da regra → retrohunt → ativação → alerta gerado. Se o alerta aparecer com os campos corretos (IP do atacante, lista de usuários-alvo, risk score 85), o ciclo está completo e a detecção está funcionando em produção. Se algum campo estiver vazio ou incorreto, o problema está no `outcome` da regra, que pode ser corrigido sem precisar desativar a Live Rule.

**Por que agora:** A verificação do alerta é feita imediatamente após a ativação porque o ambiente de lab tem dados sintéticos que simulam ataques em tempo real — o alerta deve ser gerado em segundos. Em ambiente de produção real, a validação seria feita ao longo das próximas 24–48 horas, monitorando se novos alertas gerados estão com as informações corretas e sem falsos positivos.

**Navegação:**
```
1. Clique em "Cases" no menu lateral
2. Clique em "Alerts" na aba superior
3. Procure pelo alerta com o nome "password_spray_detection"
```

**O que você deve ver:**
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

**O que fazer se o alerta não aparecer:**
- Verifique se a regra está com status "ACTIVE" em Detection → Rules
- Em ambientes de lab, pode levar até 5 minutos para o primeiro alerta aparecer após a ativação
- Se o status da regra for "Error" em vez de "Active", há um erro de sintaxe — abra a regra e corrija o erro indicado

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

**O que este passo faz:** Cria um arquivo de documentação estruturado para a regra `password_spray_detection`, registrando as decisões de design, o mapeamento MITRE ATT&CK, os casos conhecidos de falso positivo e as notas de tuning. Esta documentação é um artefato de governança essencial em qualquer SOC maduro — ela permite que outro analista entenda, audite e ajuste a regra sem precisar consultar o criador original. Para o Banco Meridian, a documentação de regras é também um requisito de compliance: o BACEN pode solicitar evidências de que os controles de detecção estão documentados e revisados regularmente (Resolução 4.893, Artigo 10).

**Por que agora:** A documentação é feita imediatamente após a ativação da regra enquanto o contexto do incidente que motivou a criação ainda está fresco. Documentar "depois" raramente acontece — o SOC passa para o próximo incidente e a decisão de design (por que threshold 10? por que janela de 15 minutos?) se perde. Para auditorias BACEN, uma regra sem documentação é tratada como um controle não-documentado, o que pode resultar em achado de auditoria.

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
