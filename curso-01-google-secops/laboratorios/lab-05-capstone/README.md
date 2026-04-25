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

## 1. Instruções Gerais

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

Anote sua descoberta — ela vai aparecer no seu relatório na seção "Detecção".

### 3.3 Fase B: Investigação e Hunting (30 min)

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

**Resultado esperado ao final da Fase B:** Uma timeline rascunho com pelo menos 8 eventos
identificados, em ordem cronológica, com timestamps.

### 3.4 Fase C: Criação das Três Regras YARA-L (30 min)

Crie (ou refine) três regras YARA-L no editor do Google SecOps:

**Regra 1: Beaconing C2 específico do Cobalt Strike**

Com base no que você descobriu sobre o beaconing de WRK-MARCOS-015, refine a regra
`c2_beaconing_periodicidade` do Módulo 03 para cobrir o caso específico onde o beacon
é um processo Windows em `%TEMP%` ou `%APPDATA%` (característica do Cobalt Strike).

**Regra 2: Criação de conta admin por usuário não-admin**

Use como base o Exemplo 5 do Módulo 03 (`privilege_escalation_criacao_conta_admin`),
mas calibre os parâmetros para o ambiente do Banco Meridian (domínio, grupos admin, etc.).

**Regra 3: Exfiltração em massa via HTTPS**

Crie esta regra do zero, baseada no template do Módulo 07 (seção 5.2). Defina um threshold
de bytes que seria adequado para o Banco Meridian — nem tão baixo que gere FPs de backups
legítimos, nem tão alto que deixe passar exfiltração de dados menores.

**Para cada regra:**
1. Escreva no editor YARA-L
2. Salve e verifique se está sem erros de sintaxe
3. Execute Retrohunt sobre os últimos 7 dias
4. Documente o resultado do Retrohunt (quantas detecções, quais eventos)

### 3.5 Fase D: Criação do Playbook SOAR (30 min)

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

### 3.6 Fase E: Finalizar os Entregáveis (10 min)

Revise e organize os quatro entregáveis obrigatórios para entrega:

1. **Timeline:** complete a tabela com todos os eventos identificados
2. **Relatório NIST SP 800-61:** garanta que todas as 8 seções estão preenchidas
3. **Regras YARA-L:** confirme que as 3 regras estão salvas e funcionais
4. **Playbook SOAR:** confirme que o playbook está salvo (pode estar inativo para a defesa)

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

O gabarito completo está disponível no **Módulo 07, seção 5** e será apresentado pelo
instrutor durante a revisão coletiva da Parte 2. Para garantir o aprendizado genuíno,
o gabarito **não é disponibilizado antes da sessão live**.

Após a sessão live, o gabarito fica permanentemente disponível no Módulo 07 para
consulta futura.

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
