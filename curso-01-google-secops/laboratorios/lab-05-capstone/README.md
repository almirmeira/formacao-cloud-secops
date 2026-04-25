# Lab 05 — Capstone: Investigando a Operação Antas
## Curso 1: Google SecOps Essentials · CECyber

| Campo                | Detalhe                                                                |
|:---------------------|:-----------------------------------------------------------------------|
| **Duração**          | 2h autoguiado (Parte 1) + 2h sessão live de defesa (Parte 2)           |
| **Módulo relacionado**| Módulo 07 — Capstone: Operação Antas                                  |
| **Tipo**             | Autoguiado (Parte 1) + Live com instrutor (Parte 2)                    |
| **MITRE ATT&CK**     | T1566.001, T1078, T1039, T1098, T1071.001, T1048                       |
| **Pré-requisito**    | Labs 01–04 concluídos e entregues · Módulos 01–06 completos            |
| **Ferramentas**      | Google SecOps (completo), YARA-L Editor, SOAR Designer                 |

---

## 1. Contexto Situacional — A Operação Antas

*"O alerta chegou às 3h17 de uma terça-feira. O sistema UEBA enviou uma notificação automática
ao canal #soc-alerts do Slack: Risk Score de marcos.pereira havia saltado de 15 para 94 em
menos de 6 horas. Mariana estava de plantão e abriu o caso imediatamente..."*

O Banco Meridian passa pela pior crise de segurança de sua história. Durante 9 dias consecutivos,
um grupo APT especializado em ataques ao setor financeiro brasileiro — identificado internamente
como APT-FIN-BR — conduziu uma operação multifásica contra o banco. A campanha, denominada
**Operação Antas** pelo time de IR, foi cuidadosamente planejada: os atacantes fizeram OSINT
sobre funcionários do departamento financeiro por semanas antes de lançar o spearphishing.

Marcos Pereira, analista financeiro responsável por conciliações de alto valor, recebeu um
e-mail aparentemente originado do Banco Central do Brasil — com PDF anexo sobre "Novas
Diretrizes de Compliance para Operações de Câmbio 2026". O PDF explorou uma vulnerabilidade
no Adobe Reader para instalar um Cobalt Strike Beacon, que permaneceu ativo por 9 dias antes
de ser detectado. Nesse período, 4,7 GB de dados financeiros foram exfiltrados e uma conta
de backdoor foi criada com privilégios de administrador de domínio.

**Seu papel:** Você é o Engenheiro de Detecção chamado para liderar a investigação técnica.
Mariana (L2) e Carlos (L1) irão apoiar. Sua missão é reconstruir completamente o que aconteceu,
criar as detecções que preveniriam o próximo ataque e elaborar o relatório de incidente exigido
pelo BACEN.

---

## 2. Situação Inicial

Ao começar o lab, o ambiente está no seguinte estado:

```
DASHBOARD — BANCO MERIDIAN SOC — OPERAÇÃO ANTAS
════════════════════════════════════════════════════════════════════

  Risk Analytics (momento atual, 03:45 BRT):
  ─────────────────────────────────────────────
  Entidade              Risk Score  Variação 24h  Status
  marcos.pereira            94        +79        ⚠️ CRITICAL
  WRK-MARCOS-015            87        +72        ⚠️ CRITICAL
  diana.ferreira            45         +0        HIGH (incidente anterior)
  WRK-RODRIGO-011           31        -58        RECOVERING (Lab 03 contido)

  Alertas ativos:
  ─────────────────────────────────────────────
  UEBA: Risk Score crítico — marcos.pereira      [NOVO - 03:17]
  password_spray_detection: (sem novos disparos)
  login_fora_horario: 1 alerta — marcos.pereira  [NOVO - 02:47]

  Feeds de TI:
  ─────────────────────────────────────────────
  Mandiant TI Feed     → HEALTHY
  VirusTotal Augment   → HEALTHY
  CERT.BR Feed         → HEALTHY (atualizado há 2h)

════════════════════════════════════════════════════════════════════
```

O alerta de login fora do horário (`login_fora_horario`) foi o primeiro sinal — às 02:47,
marcos.pereira fez login bem-sucedido de um IP em Moscou. O UEBA capturou isso e começou a
elevar o Risk Score. Às 03:17, o score atingiu o threshold crítico e o alerta automático foi
enviado.

---

## 3. Problema Identificado

Mariana analisa o alerta inicial e envia a seguinte mensagem no Slack às 03:52:

*"@todos — accordei com o alerta. Marcus.pereira fez login às 02:47 de Moscou. Ele está de
férias em Campos do Jordão, confirmado — falei com ele agora. Não foi ele. A conta está
comprometida. Mas quando fui ver o histórico de atividade dos últimos dias, o UEBA está
marcando WRK-MARCOS-015 com 72 pontos de aumento em 24h. Isso não é de hoje. Tem coisa
acontecendo há dias nessa máquina. Precisamos de uma investigação completa. O CISO precisa
ser acionado às 06h com um briefing preliminar."*

**O que sabemos até agora:**
- Login bem-sucedido às 02:47 de Moscou para marcus.pereira (conta comprometida)
- WRK-MARCOS-015 com Risk Score em crescimento há mais de 24h
- Nenhuma regra YARA-L disparou para o host nos últimos 9 dias
- O BACEN exige notificação de incidente em até 24 horas — o relógio está correndo

**Sua missão:**
1. Reconstruir a kill chain completa da Operação Antas
2. Identificar todos os IOCs (IP de C2, hash do dropper, conta backdoor, dados exfiltrados)
3. Criar 3 regras YARA-L que teriam detectado o ataque antes
4. Criar o playbook SOAR de resposta para esse tipo de incidente
5. Produzir o relatório de incidente no formato NIST SP 800-61 para o CISO e BACEN

---

## 4. Roteiro de Atividades

| Fase | Atividade                                              | Tempo estimado |
|:----:|:-------------------------------------------------------|:--------------:|
| A    | Detecção inicial — Risk Analytics, UEBA, alertas ativos | 20 min        |
| B    | Investigação e hunting — UDM Search avançado com pivoting | 30 min      |
| C    | Criação das 3 regras YARA-L com Retrohunt              | 30 min         |
| D    | Criação do playbook SOAR de resposta a APT             | 30 min         |
| E    | Finalizar os 4 entregáveis obrigatórios                | 10 min         |

---

## 5. Instruções Gerais

Este é o laboratório final do Curso 1 — Google SecOps Essentials. Diferente dos labs anteriores,
não há um script passo a passo para guiar você. Este é o momento de aplicar de forma integrada
tudo que você aprendeu nos módulos 01 a 06 e nos labs 01 a 04.

O laboratório está dividido em duas partes:

**Parte 1 (autoguiada, 2h):** Você investiga a Operação Antas de forma independente,
produzindo os quatro entregáveis descritos neste documento. Trabalhe no seu próprio ritmo,
mas gerencie o tempo — 2 horas é suficiente para completar se você organizou bem o trabalho.

**Parte 2 (live com instrutor, 2h):** Você apresenta os seus resultados para o instrutor
e para a turma. O instrutor fará perguntas técnicas para avaliar a profundidade do seu
entendimento. O gabarito oficial é revelado ao final.

---

## 2. O Cenário: Operação Antas

Consulte o **Módulo 07** para a narrativa completa, o perfil do atacante e a kill chain com
as seis fases do ataque.

**Resumo rápido:**
- Atacante: grupo APT-FIN-BR (nexo financeiro, infraestrutura na Europa Oriental)
- Alvo: marcos.pereira, analista financeiro do Banco Meridian
- Vetor: spearphishing com PDF (exploit Adobe Reader → Cobalt Strike Beacon)
- Impacto: credenciais comprometidas, 4,7 GB de dados financeiros exfiltrados,
  conta admin backdoor criada

---

## 3. Parte 1 — Investigação Autoguiada (2 horas)

### 3.1 Estrutura de Tempo Recomendada

```
PARTE 1 — DISTRIBUIÇÃO DE TEMPO SUGERIDA
════════════════════════════════════════════════════════════════════

  00:00 – 00:20  Fase A: Detecção inicial
                 Analisar o Risk Analytics, UEBA e alertas ativos
                 Identificar o ponto de entrada do incidente

  00:20 – 00:50  Fase B: Investigação e hunting
                 UDM Search avançado com pivoting
                 Construir a timeline do incidente

  00:50 – 01:20  Fase C: Criação das regras YARA-L
                 Criar ou refinar 3 regras cobrindo as técnicas identificadas
                 Executar Retrohunt para validar

  01:20 – 01:50  Fase D: Criação do playbook SOAR
                 Criar o playbook de response para APT/exfiltração

  01:50 – 02:00  Fase E: Finalizar entregáveis
                 Completar o relatório, revisar a timeline, organizar IOCs

════════════════════════════════════════════════════════════════════
```

### 3.2 Fase A: Detecção Inicial (20 min)

**O que esta fase faz:** Estabelece o contexto global do incidente usando as três fontes de visibilidade disponíveis: Risk Analytics (pontuação comportamental acumulada), UEBA (anomalias específicas detectadas) e Alertas YARA-L (detecções baseadas em regras). A combinação das três perspectivas forma o panorama que guiará toda a investigação subsequente. O ponto de entrada do incidente — o "paciente zero" — é identificado aqui.

**Por que começar aqui:** O Risk Analytics e UEBA fornecem o "quando" do incidente — identificam há quanto tempo o comportamento anômalo está ocorrendo. Analistas que pulam esta fase e vão diretamente para UDM Search tendem a usar janelas de tempo erradas nas queries, perdendo os eventos iniciais do comprometimento.

Comece pela visão geral. Antes de mergulhar em queries, entenda o estado do ambiente:

1. Acesse o **Risk Analytics** (`Detection → Risk Analytics`):
   - Quais entidades têm o maior Risk Score hoje?
   - Qual o histórico de 30 dias de marcos.pereira?

2. Acesse o **UEBA** para marcos.pereira:
   - Quando o Risk Score começou a subir?
   - Quais anomalias o UEBA está sinalizando?

3. Verifique os **alertas YARA-L ativos** (`Detection → Alerts`):
   - Alguma regra disparou para marcos.pereira ou WRK-MARCOS-015?
   - Qual foi o alerta mais recente? Qual o timestamp?

**Pergunta guia:** "Qual foi o primeiro sinal no Google SecOps que indicava que algo estava
errado com marcos.pereira?"

**O que você deve encontrar:** O Risk Score de marcos.pereira começou a subir em 2026-04-15 — 9 dias antes do alerta. O UEBA sinaliza "Volume anômalo de conexões de saída" e "Login de geolocalização incomum". Nenhuma regra YARA-L disparou antes do alerta de `login_fora_horario` às 02:47 do dia 24 — isso é o gap de detecção que as 3 regras da Fase C devem fechar.

Anote sua descoberta — ela vai aparecer no seu relatório na seção "Detecção".

### 3.3 Fase B: Investigação e Hunting (30 min)

**O que esta fase faz:** Aplica as técnicas de UDM Search e pivoting aprendidas nos Labs 02 e 03 para reconstruir a cadeia de ataque completa. O pivoting sequencial — rede → processo → arquivo → identidade → impacto — é a metodologia central de threat hunting. Ao final desta fase, você terá os timestamps precisos de cada fase da kill chain, os IOCs concretos e a evidência técnica para o relatório ao CISO.

**Por que esta fase é a mais crítica:** A qualidade da timeline da Fase B determina a qualidade de TODOS os outros entregáveis. Regras YARA-L escritas sem entender o comportamento real do malware terão thresholds errados; o relatório BACEN exige timestamps e IOCs específicos. Não avance para a Fase C sem uma timeline com pelo menos 8 eventos.

Com o contexto da Fase A, agora mergulhe nos dados:

**Pivoting sugerido:**

1. Busque todas as conexões de rede do host `WRK-MARCOS-015` nos últimos 7 dias
2. Identifique IPs externos suspeitos (alto volume, pequenos pacotes, 24x7)
3. Pivotar do IP de C2 para o processo originador
4. Identificar o arquivo dropper e seu processo pai (quem lançou?)
5. Verificar o vetor de chegada: buscar eventos de abertura de PDF/processo do Adobe Reader
6. Construir a timeline: qual evento ocorreu primeiro?
7. Buscar o login suspeito de marcos.pereira de IP externo após o comprometimento
8. Verificar acesso ao SharePoint e volume de download
9. Identificar a criação da conta backdoor

**Dicas de UDM Search que você já sabe usar (mas não precisa se prender a estas):**
- `principal.hostname = "WRK-MARCOS-015" AND metadata.event_type = "NETWORK_CONNECTION"`
- `target.user.userid = "marcos.pereira" AND security_result.action = "ALLOW"`
- `principal.user.userid = "marcos.pereira" AND metadata.event_type = "USER_CREATION"`

**O que você deve encontrar ao final:** O IP de C2 `45.77.123.89` com 12.847 conexões; o processo `svchost.exe` (PID 4829) como origem do beaconing; `bc_cert_helper.exe` em %TEMP% como dropper criado por `AcroRd32.exe`; 4,7 GB exfiltrados para `185.220.101.34`; e a conta `administrador_ti2` criada e adicionada ao Domain Admins.

**Resultado esperado ao final da Fase B:** Uma timeline rascunho com pelo menos 8 eventos identificados, em ordem cronológica, com timestamps precisos e técnicas MITRE mapeadas.

### 3.4 Fase C: Criação das Três Regras YARA-L (30 min)

**O que esta fase faz:** Transforma o conhecimento adquirido na investigação das Fases A e B em detecções automatizadas permanentes. Esta é a etapa de Detection Engineering do capstone — você não está apenas respondendo ao incidente atual, mas garantindo que o SOC do Banco Meridian detecte automaticamente o mesmo tipo de ataque no futuro. As três regras cobrem as três fases mais críticas do ataque da Operação Antas: o Command and Control (beaconing), a persistência (criação de conta backdoor) e o impacto (exfiltração de dados).

**Por que estas três regras e não outras:** O princípio de priorização de Detection Engineering é criar regras para os comportamentos que causaram o maior impacto e que ficaram mais tempo invisíveis. Neste incidente: (1) o beaconing ficou ativo por 9 dias sem detecção — a maior lacuna; (2) a criação de conta backdoor é um movimento irreversível que indica APT persistente; (3) a exfiltração é o impacto final que gera obrigações regulatórias (BACEN 4.893 art. 12 — notificação em 24h). Cada regra fecha uma lacuna real identificada durante a investigação.

**Por que agora:** A criação das regras ocorre com o incidente ainda fresco porque você tem acesso aos dados reais que o ataque gerou — hashes, IPs de C2, timestamps, volumes de exfiltração. Esses dados são o input para calibrar os thresholds das regras com precisão. Criar regras genéricas "em algum momento" após o incidente resulta em thresholds estimados que podem ser muito altos (deixam passar ataques menores) ou muito baixos (geram falsos positivos com backups legítimos).

Crie (ou refine) três regras YARA-L no editor do Google SecOps:

**Regra 1: Beaconing C2 específico do Cobalt Strike**

Com base no que você descobriu sobre o beaconing de WRK-MARCOS-015, refine a regra
`c2_beaconing_periodicidade` do Módulo 03 para cobrir o caso específico onde o beacon
é um processo Windows em `%TEMP%` ou `%APPDATA%` (característica do Cobalt Strike).

**Por que este refinamento importa:** A regra genérica de beaconing do Módulo 03 detecta qualquer processo fazendo conexões periódicas — incluindo atualizadores de software legítimos (Windows Update, antivírus). Adicionar o critério de processo em `%TEMP%` ou `%APPDATA%` é o diferencial: nenhum software legítimo executa e mantém beaconing a partir dessas pastas, mas o Cobalt Strike invariavelmente o faz. Esse filtro reduz os falsos positivos de dezenas por dia para próximo de zero.

**Regra 2: Criação de conta admin por usuário não-admin**

Use como base o Exemplo 5 do Módulo 03 (`privilege_escalation_criacao_conta_admin`),
mas calibre os parâmetros para o ambiente do Banco Meridian (domínio, grupos admin, etc.).

**Por que calibrar para o Banco Meridian:** O Banco Meridian tem um processo documentado de criação de contas de TI que gera eventos legítimos de USER_CREATION seguidos de GROUP_MODIFICATION. A regra do Módulo 03 dispararia para esses eventos legítimos se não for calibrada com as exclusões corretas — por exemplo, excluindo a conta do processo de onboarding de TI ou restringindo a detecção a criações que ocorrem fora do horário comercial e por usuários não membros do grupo de TI.

**Regra 3: Exfiltração em massa via HTTPS**

Crie esta regra do zero, baseada no template do Módulo 07 (seção 5.2). Defina um threshold
de bytes que seria adequado para o Banco Meridian — nem tão baixo que gere FPs de backups
legítimos, nem tão alto que deixe passar exfiltração de dados menores.

**Por que o threshold é o desafio central desta regra:** O Banco Meridian tem backups noturnos automáticos que transferem volumes significativos de dados legítimos. Uma regra com threshold muito baixo (ex: 10 MB em 1 hora) dispararia para esses backups diariamente. O threshold correto deve estar ACIMA do volume máximo de backup legítimo mas ABAIXO do volume de exfiltração observado no incidente (4,7 GB). Pesquisar os logs de backup para determinar o volume exato do baseline é parte do exercício.

**Para cada regra:**
1. Escreva no editor YARA-L
2. Salve e verifique se está sem erros de sintaxe
3. Execute Retrohunt sobre os últimos 7 dias
4. Documente o resultado do Retrohunt (quantas detecções, quais eventos)

**O que você deve ver ao final da Fase C:** As três regras salvas com status "No errors". O Retrohunt de cada regra deve retornar pelo menos 1 detecção referente ao incidente da Operação Antas. Se o Retrohunt retornar 0 detecções, revise o threshold — provavelmente está muito alto ou os campos UDM estão incorretos.

**O que fazer se der errado:**
- "Syntax error": verifique a seção indicada, especialmente se há campos UDM escritos incorretamente — use o autocompletar do editor para confirmar os nomes exatos
- Retrohunt retorna 0 detecções: relaxe o threshold 50% e rode novamente; se ainda retornar 0, o campo UDM pode estar errado — confirme o nome do campo no UDM Search com um evento real do incidente

### 3.5 Fase D: Criação do Playbook SOAR (30 min)

**O que esta fase faz:** Cria o playbook de resposta automatizada para o tipo de incidente da Operação Antas — um APT com acesso persistente, conta backdoor ativa e exfiltração de dados confirmada. Este playbook define a sequência exata de ações que o SOAR executará automaticamente quando qualquer uma das três regras YARA-L da Fase C disparar no futuro. A automação das ações de contenção (isolamento do host, revogação de credenciais) é o que transforma a capacidade de detecção em capacidade de resposta — sem o playbook, o analista recebe o alerta mas ainda precisa executar manualmente cada ação de contenção, o que pode levar 30–60 minutos. Com o playbook, as ações críticas são executadas em segundos.

**Por que a sequência de ações importa:** A ordem das ações no playbook não é arbitrária — ela reflete a priorização de contenção de danos. O isolamento do host vem primeiro porque corta o acesso do atacante ao ambiente; a revogação de credenciais vem antes da notificação porque garante que a conta comprometida não pode ser usada enquanto a notificação está sendo enviada; a criação do ticket P1 vem por último porque documenta tudo que foi feito — uma exigência do BACEN para notificações de incidentes.

**Impacto no MTTR:** O MTTD (Mean Time to Detect) já foi reduzido pelas regras da Fase C. O MTTR (Mean Time to Respond) é reduzido pelo playbook desta fase. Juntos, eles transformam a métrica atual do Banco Meridian (MTTR de 4h 23min) para um alvo abaixo de 15 minutos para os primeiros passos de contenção — o que pode ser a diferença entre exfiltração de 4,7 GB e exfiltração de 100 MB antes da contenção.

Crie um playbook SOAR para resposta ao tipo de incidente da Operação Antas.
Este playbook deve cobrir no mínimo:

1. **Isolamento imediato do host** via EDR (CrowdStrike Contain)
2. **Revogação de credenciais** comprometidas (Azure AD Revoke Sessions + Disable Account)
3. **Desabilitação da conta backdoor** criada (Azure AD Disable Account para a conta suspeita)
4. **Bloqueio de IPs de C2 e exfiltração** no firewall (PAN-OS Block IP)
5. **Notificação ao CISO e IR Team** via e-mail com resumo do incidente
6. **Criação de ticket P1 no Jira** com todos os IOCs identificados

Você pode usar como base o playbook do Lab 04 (phishing response), expandindo-o para
cobrir os cenários adicionais do APT.

**O que você deve ver ao final da Fase D:** O playbook salvo no Playbook Designer com pelo menos 6 blocos de ação conectados em sequência. O playbook deve ter pelo menos um bloco condicional (ex: "se o IP de destino for IOC conhecido → severidade P1; senão → severidade P2"). Playbooks lineares sem condicionais são aceitos, mas perdem pontos na rubrica de avaliação.

**O que fazer se der errado:**
- Se uma Action não estiver disponível (ex: CrowdStrike Contain não aparece), verifique se a integração está configurada em Settings → SOAR → Integrations — no ambiente de lab, as integrações CrowdStrike, Azure AD e PAN-OS devem estar pré-configuradas
- Se o playbook não salvar, verifique se todos os blocos de ação têm os campos obrigatórios preenchidos — campos em vermelho indicam configuração incompleta

### 3.6 Fase E: Finalizar os Entregáveis (10 min)

**O que esta fase faz:** Realiza a revisão final de qualidade dos quatro entregáveis antes da sessão live de defesa. Esta não é uma fase de criação — é uma fase de inspeção. Cada entregável deve ser verificado contra a rubrica de avaliação (seção 7) para garantir que os critérios mínimos estão atendidos. Um entregável incompleto descoberto durante a sessão live causa uma penalidade de pontuação maior do que um entregável incompleto descoberto aqui e corrigido em 5 minutos.

**Por que esta revisão é necessária:** Em um exercício de 2 horas com alta pressão cognitiva (investigação de incidente real + criação de regras + desenvolvimento de playbook + escrita de relatório), é normal que detalhes sejam omitidos por pressa. A Fase E é o "controle de qualidade" antes da entrega — uma prática padrão em ambientes de SOC real onde os relatórios de incidente BACEN têm prazo legal de 24 horas e não podem ser corrigidos após o envio.

**Impacto na avaliação final:** A sessão live de defesa (Parte 2) representa 50% da nota do capstone. A qualidade dos entregáveis da Parte 1 determina sua confiança durante a defesa — analistas que chegam com uma timeline incompleta têm dificuldade em responder as perguntas do instrutor com precisão, o que afeta a nota mesmo que a análise técnica esteja correta.

Revise e organize os quatro entregáveis obrigatórios para entrega:

1. **Timeline:** complete a tabela com todos os eventos identificados — mínimo 8 eventos com timestamp, técnica MITRE e fonte de log
2. **Relatório NIST SP 800-61:** garanta que todas as 8 seções estão preenchidas, especialmente a seção de Recomendações de Melhoria (que é avaliada separadamente na rubrica)
3. **Regras YARA-L:** confirme que as 3 regras estão salvas e com status "No errors" — regras com erro de sintaxe não contam como entregues
4. **Playbook SOAR:** confirme que o playbook está salvo (pode estar inativo para a defesa); verifique se os 6 blocos de ação mínimos estão presentes

**O que você deve confirmar antes de avançar para a Parte 2:**
- [ ] Timeline com pelo menos 8 eventos em ordem cronológica com técnicas MITRE mapeadas
- [ ] Relatório com todas as 8 seções preenchidas, incluindo IOCs e recomendações
- [ ] 3 regras YARA-L salvas sem erros, com resultado de Retrohunt documentado
- [ ] Playbook com pelo menos 6 ações e pelo menos 1 bloco condicional

---

## 4. Entregáveis Obrigatórios

Todos os quatro entregáveis devem ser submetidos antes do início da sessão live de defesa.
O instrutor vai revisar brevemente antes da defesa para garantir que estão completos.

### Entregável 1: Timeline do Incidente

Preencha a tabela abaixo com os eventos identificados durante sua investigação:

| Timestamp (UTC)  | Evento | Técnica MITRE | Fonte de Log | Severidade |
|:-----------------|:-------|:-------------:|:-------------|:----------:|
| (preencher)      | (preencher) | (preencher) | (preencher) | (preencher) |

**Mínimo obrigatório:** 8 eventos documentados com todos os campos.

**Forma de entrega:** Arquivo `timeline-capstone.md` no diretório do lab no seu ambiente.

### Entregável 2: Relatório de Incidente (NIST SP 800-61)

Use o template da seção 3.2 do Módulo 07. O relatório deve ter as 8 seções obrigatórias:

1. Identificação do Incidente (ID, data, classificação, criticidade)
2. Resumo Executivo (3–5 parágrafos)
3. Linha do Tempo (referência ao Entregável 1)
4. Indicadores de Comprometimento (IOCs identificados)
5. Análise de Impacto (dados comprometidos, sistemas afetados)
6. Ações de Contenção Executadas
7. Análise de Causa Raiz (mínimo 3 falhas de controle identificadas)
8. Lições Aprendidas e Recomendações (mínimo 5 ações concretas)

**Forma de entrega:** Arquivo `relatorio-capstone.md` no diretório do lab.

### Entregável 3: Três Regras YARA-L

As três regras devem estar salvas no YARA-L Editor do Google SecOps.

**Documentação adicional esperada:** Para cada regra, responda as seguintes perguntas:
- Qual gap de detecção esta regra fecha?
- Qual o threshold escolhido e por que?
- Quais exclusões foram necessárias e por quê?

**Forma de entrega:** Screenshot do Retrohunt de cada regra + documentação em `regras-yara-l-capstone.md`.

### Entregável 4: Playbook SOAR

O playbook deve estar salvo no SOAR (pode estar inativo).

**Documentação adicional esperada:**
- Diagrama do fluxo (pode ser uma descrição textual do fluxo, não precisa ser visual)
- Quais ações foram automatizadas vs. requerem aprovação humana?
- Como você mediria o MTTR com este playbook?

**Forma de entrega:** Screenshot do playbook no Designer + documentação em `playbook-capstone.md`.

---

## 5. Orientações para a Entrega

```
PRAZO DE ENTREGA: Até 30 minutos antes do início da sessão live de defesa

COMO ENTREGAR:
1. Salvar todos os arquivos .md no diretório do lab:
   ~/formacao-cloud-secops/capstone-submissions/[seu-nome]/

2. As regras YARA-L ficam salvas no tenant Google SecOps —
   enviar o ID das regras salvas ao instrutor via e-mail

3. O playbook SOAR fica salvo no tenant —
   enviar o nome do playbook ao instrutor via e-mail

4. O instrutor vai confirmar o recebimento via e-mail ou Slack

FORMATO DOS ARQUIVOS:
Todos os arquivos em Markdown (.md), em português do Brasil
```

---

## 6. Parte 2 — Sessão Live de Defesa (2 horas)

### 6.1 O que esperar da sessão live

A sessão live não é um exame formal — é mais parecida com uma reunião de post-mortem de
incidente que todo profissional de segurança precisa saber conduzir. Você vai apresentar
suas descobertas, explicar suas decisões e responder perguntas técnicas do instrutor.

**Estrutura da sessão (ver Módulo 07, seção 6):**

| Bloco         | Duração | Conteúdo                                           |
|:--------------|:-------:|:---------------------------------------------------|
| Abertura      | 10 min  | Instrutor apresenta o formato e confirma entregas  |
| Defesas       | 60 min  | 8–10 min por aluno (+ 3–5 min de perguntas)       |
| Revisão coletiva | 30 min | Gabarito oficial revelado, discussão dos gaps   |
| Lições aprendidas | 15 min | O que o SOC do Banco Meridian deveria mudar   |
| Encerramento  | 5 min   | Notas, próximos passos, preview Curso 2            |

### 6.2 Como preparar sua apresentação (15 min de preparação)

Você não precisa de slides. Na defesa, você vai:

1. **Compartilhar a tela** do Google SecOps Console
2. **Mostrar a timeline** que você construiu (arquivo .md ou no console do SOAR)
3. **Abrir o editor YARA-L** e mostrar uma das regras que criou, explicando a lógica
4. **Abrir o Playbook Designer** e mostrar uma decisão de design que fez

**Prepare respostas para:**
- "Quando você percebeu que o beaconing estava acontecendo? Qual query te levou até lá?"
- "Por que você escolheu esse threshold na regra de exfiltração?"
- "Se o playbook SOAR tivesse estado ativo na época, o que teria acontecido diferente?"
- "Qual foi a maior falha de controle que permitiu este incidente?"

### 6.3 Critérios de avaliação na defesa

| Critério          | Avaliação                                                             |
|:------------------|:----------------------------------------------------------------------|
| Timeline          | Clareza, completude (≥ 8 eventos), precisão das técnicas MITRE       |
| Regra YARA-L      | Consegue explicar cada condição e por que as exclusões foram escolhidas|
| Playbook SOAR     | Consegue explicar ao menos 3 decisões de design com justificativa     |
| Perguntas         | Responde com raciocínio claro, admite gaps sem esconder               |
| Postura profissional | Apresenta como um profissional de IR, não como aluno prestando prova |

---

## 7. Gabarito

O gabarito completo é revelado pelo instrutor durante a revisão coletiva da Parte 2. Para
garantir o aprendizado genuíno, o gabarito completo **não é disponibilizado antes da sessão live**.
Após a sessão live, o conteúdo abaixo fica disponível para consulta futura.

### Gabarito — Timeline Oficial (Kill Chain da Operação Antas)

| Timestamp (UTC)     | Evento                                                     | Técnica MITRE       | Fonte          |
|:--------------------|:-----------------------------------------------------------|:--------------------|:---------------|
| 2026-04-15 13:42:07 | marcos.pereira recebe e-mail com PDF malicioso             | T1566.001 Phishing  | Proofpoint     |
| 2026-04-15 14:08:33 | AcroRd32.exe abre PDF e executa exploit                    | T1203 Exploit       | SYSMON         |
| 2026-04-15 14:08:41 | Dropper `bc_cert_helper.exe` criado em %TEMP%             | T1204.002 User Exec | SYSMON         |
| 2026-04-15 14:08:44 | Cobalt Strike Beacon injetado em svchost.exe               | T1055.001 Injection | CROWDSTRIKE    |
| 2026-04-15 14:08:46 | 1ª conexão C2 para `45.77.123.89:443`                      | T1071.001 C2 Web    | PAN_FIREWALL   |
| 2026-04-15–24       | 12.847 conexões C2 em 9 dias (intervalo ~62s)              | T1071.001 C2 Web    | PAN_FIREWALL   |
| 2026-04-20 02:33:11 | User Agent de reconhecimento (acesso a SharePoint e CIFS)  | T1083 File Discovery| SYSMON         |
| 2026-04-20 03:17:45 | Exfiltração de 4,7 GB via HTTPS para `185.220.101.34`      | T1048 Exfil Alt Prot| PAN_FIREWALL   |
| 2026-04-22 09:14:29 | Criação de conta backdoor `administrador_ti2` no AD        | T1136.002 Crt Acct  | WINDOWS_EVENT  |
| 2026-04-22 09:15:02 | `administrador_ti2` adicionado ao grupo Domain Admins       | T1098 Acct Manip    | WINDOWS_EVENT  |
| 2026-04-24 02:47:33 | Login de `marcos.pereira` de IP em Moscou (conta roubada)  | T1078 Valid Accounts| AZURE_AD       |
| 2026-04-24 03:17:00 | UEBA dispara — Risk Score de marcos.pereira: 15 → 94       | N/A (Detecção)      | UEBA           |

**Pontuação da timeline:** 12 eventos = nota máxima. 8–11 eventos = aprovado. < 8 = reprovado.

**Por que essa timeline confirma o incidente:**
A sequência explicitamente mostra a kill chain completa do MITRE ATT&CK: Phishing (Entrega) →
Exploit (Execução) → C2 (Comando e Controle) → Discovery → Exfiltração → Persistência (conta
backdoor) → Credential Access (uso da conta de marcos.pereira). Esse mapeamento 1:1 com as
táticas do ATT&CK é o que estrutura o relatório BACEN e evidencia a extensão do comprometimento.

### Gabarito — IOCs da Operação Antas

| Tipo   | Indicador                                                            | Confiança |
|:-------|:---------------------------------------------------------------------|:---------:|
| IP C2  | `45.77.123.89` (Vultr VPS, EUA)                                     | HIGH      |
| IP Exfil| `185.220.101.34` (Tor Exit Node / Frantech, Moldova)               | HIGH      |
| SHA256 | `3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d...`  (PDF malicioso)    | HIGH      |
| SHA256 | `7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d...`  (bc_cert_helper.exe) | HIGH      |
| Path   | `%TEMP%\bc_cert_helper.exe`                                         | HIGH      |
| Conta  | `administrador_ti2` (backdoor, Domain Admin)                        | HIGH      |
| Domínio| `banco-central-br.com` (domínio de phishing — typosquat)            | HIGH      |

### Gabarito — Regras YARA-L Esperadas

**Regra 1 (C2 Beaconing com Processo Pai em %TEMP%):**

O código correto inclui dois eventos correlacionados: `$e1` para conexões de rede e `$e2` para o lançamento de svchost.exe por processo em %TEMP% ou %APPDATA%. O threshold mínimo aceitável é `#e1 >= 20` em janela de `1h`.

```yara-l
rule c2_beaconing_svchost_injetado {
  meta:
    author = "SOC Banco Meridian"
    severity = "CRITICAL"
    mitre_attack = "T1071.001, T1055.001"
  events:
    $e1.metadata.event_type = "NETWORK_CONNECTION"
    $e1.network.direction = "OUTBOUND"
    $e1.principal.process.file.full_path = /.*svchost.exe/
    $hostname_origem = $e1.principal.hostname

    $e2.metadata.event_type = "PROCESS_LAUNCH"
    $e2.target.process.file.full_path = /.*svchost.exe/
    $e2.principal.process.file.full_path = /(.*AppData.*|.*Temp.*)/
    $e2.principal.hostname = $hostname_origem
  match:
    $hostname_origem over 1h
  condition:
    #e1 >= 20
    AND max($e1.network.received_bytes) - min($e1.network.received_bytes) <= 512
    AND $e1 and $e2
}
```

**Por que esta é a resposta correta:** A correlação dos dois eventos (`$e1` e `$e2`) é o que diferencia beaconing por injeção de processo de beaconing direto. Sem o `$e2`, a regra excluiria o `svchost.exe` (processo legítimo) e nunca detectaria este caso. A correlação pelo `$hostname_origem` garante que ambos os eventos ocorreram no mesmo host. O threshold de 512 bytes de variação captura a uniformidade do payload do Cobalt Strike.

**Erro mais comum neste passo:** Não incluir o `$e2` (evento de lançamento de processo) e apenas verificar as conexões de rede. Isso faz com que a regra exclua `svchost.exe` (que estava na watchlist de processos legítimos) e o beaconing nunca seja detectado. A lição: exclusões de processos legítimos devem ser condicionais ao processo pai, não absolutas.

---

**Regra 2 (Privilege Escalation — Conta Backdoor):**

O código correto detecta `USER_CREATION` seguido de adição ao grupo Domain Admins dentro de 5 minutos no mesmo host.

**Por que esta é a resposta correta:** A detecção da sequência (criação + adição a grupo admin) dentro de uma janela curta identifica a criação de backdoor com certeza muito maior do que qualquer um dos eventos isoladamente. A criação de conta é legítima no dia-a-dia do AD; a adição imediata a Domain Admins não é. A janela de 5 minutos é calibrada no intervalo observado no incidente (33 segundos), com margem para variação. Severidade CRITICAL é correta — conta Domain Admin não autorizada é o indicador mais crítico de persistência em um ambiente Windows.

**Erro mais comum neste passo:** Detectar apenas `USER_CREATION` sem a correlação com adição ao grupo admin. Isso geraria dezenas de alertas diários de criação de contas normais do AD, tornando a regra inoperante na prática.

---

**Regra 3 (Exfiltração em massa HTTPS):**

O threshold correto é `sum(sent_bytes) >= 1073741824` (1 GB) em janela de `4h`. Thresholds mais baixos (100 MB em 1h) também são aceitos se justificados com dados históricos de backup legítimo do Banco Meridian.

**Por que esta é a resposta correta:** O Banco Meridian tem backups noturnos que transferem ~500 MB para o Azure Backup — um threshold abaixo de 500 MB geraria alertas de backup diariamente. 1 GB em 4h é um threshold que excede o backup máximo esperado mas ainda captura a exfiltração de 4,7 GB observada no incidente. Qualquer threshold acima de 10 GB é excessivo para um banco tier-2 e deixaria passar exfiltrações menores mas ainda críticas.

**Erro mais comum neste passo:** Definir threshold muito baixo (ex: 10 MB em 1h) sem considerar os backups legítimos. Na validação com Retrohunt, retornaria centenas de alertas de FP por dia — um volume que tornaria a regra inutilizável no SOC. A calibração do threshold com dados históricos de backups legítimos é obrigatória antes de ativar a regra.

---

**Variações aceitáveis:**
- A janela temporal das regras pode variar ±50% (ex: `2h` em vez de `1h` para beaconing)
- Exclusões diferentes para contas de serviço são aceitáveis se documentadas
- Nomes diferentes para as regras são aceitáveis desde que o padrão de nomenclatura seja
  consistente com `{categoria}_{descrição}` conforme Módulo 03 seção 3.8.1

### Gabarito — Erros Comuns e Como Identificar

| Erro                                          | Sinal de Identificação                        | Diagnóstico e Solução                                |
|:----------------------------------------------|:----------------------------------------------|:-----------------------------------------------------|
| Timeline não inclui a exfiltração             | Timeline tem < 10 eventos; missing T1048      | **Diagnóstico:** A exfiltração ocorreu às 03:17 de 20/04 para IP em Moldova. Buscar: `target.ip = "185.220.101.34" AND principal.hostname = "WRK-MARCOS-015"`. Se o IP não aparecer, buscar por `sum(network.sent_bytes) > 1000000000` agrupado por destino |
| Regra de beaconing não detectou o caso        | Retrohunt retorna 0 detecções                 | **Diagnóstico:** `svchost.exe` estava na watchlist de processos legítimos. Adicionar `$e2` de correlação de processo pai em `%TEMP%` conforme gabarito acima |
| Regra de exfil com threshold irreal (< 1 MB)  | Retrohunt retorna centenas de FPs (backups)   | **Diagnóstico:** Backups noturnos do Azure Backup geram ~500 MB/noite. Aumentar threshold para ≥ 1 GB; calibrar com dados históricos dos últimos 30 dias |
| Conta backdoor não identificada               | Timeline não tem T1136 / T1098                | **Diagnóstico:** A conta `administrador_ti2` foi criada em 2026-04-22 09:14. Buscar: `metadata.event_type = "USER_CREATION" AND target.user.userid = "administrador_ti2"` |
| Relatório sem seção de recomendações          | Rubrica: -2 pontos na seção 6 do relatório    | **Diagnóstico:** As 5 recomendações mínimas devem incluir: (1) patch do Adobe Reader CVE explorado, (2) regra de beaconing atualizada, (3) MFA para todos os Domain Admins, (4) monitoramento de criação de contas com privilégio alto, (5) segmentação de rede para limitar exfiltração |

---

## 8. Recursos de Apoio Durante o Lab

Se você travar em alguma parte da investigação, use os seguintes recursos antes de pedir
ajuda ao instrutor — a autonomia de investigação faz parte da avaliação:

| Situação                          | Recurso de apoio                                               |
|:----------------------------------|:---------------------------------------------------------------|
| Não sei como fazer uma query UDM  | Módulo 04, seção 4.2 — UDM Search Sintaxe Avançada             |
| Não lembro a sintaxe do YARA-L    | Módulo 03, seção 3.1 — Estrutura Completa do YARA-L            |
| Não sei como adicionar um bloco   | Módulo 06, seção 6.2 — Playbook Designer Visual                |
| Não sei o que cada campo UDM faz  | Módulo 02, seção 2.4 — UDM Estrutura Completa                  |
| Não lembro o ciclo de hunting     | Módulo 04, seção 4.1.1 — Ciclo do Threat Hunter                |
| Preciso do template do relatório  | Módulo 07, seção 3.2 — Relatório NIST SP 800-61                |

---

## 9. Dicas de Gestão de Tempo

```
DICAS PRÁTICAS PARA AS 2 HORAS:

✓ Comece pelo Risk Analytics e UEBA (5 min) — isso dá o contexto geral rapidamente
✓ Não se perca em detalhes: construa a timeline antes de ir a fundo em cada evento
✓ Para as regras YARA-L: use os exemplos do Módulo 03 como base — não crie do zero
✓ Para o playbook: copie o playbook do Lab 04 e adapte — não crie do zero
✓ Reserve 10 min ao final para revisar os entregáveis antes de submeter
✓ Se travar por mais de 5 min numa query: anote o problema e avance — volte no final

O que NÃO fazer:
✗ Não gaste mais de 30 min numa única fase
✗ Não tente documentar CADA evento (foque nos 8–12 mais relevantes)
✗ Não copie o gabarito de um colega — o instrutor vai notar nas perguntas da defesa
```

---

*Lab 05 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 07 — Capstone: Operação Antas](../../modulos/modulo-07-capstone/README.md)*
*Anterior: [Lab 04 — Playbook SOAR Phishing](../lab-04-playbook-soar-phishing/README.md)*
*Avaliação Final: [Avaliação Final do Curso](../../avaliacao-final/README.md)*
