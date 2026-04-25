# Lab 01 — Parser CBN: Normalizando Logs do Tópus Banking
## Curso 1: Google SecOps Essentials · CECyber

| Campo                | Detalhe                                                                |
|:---------------------|:-----------------------------------------------------------------------|
| **Duração**          | 2 horas                                                                |
| **Módulo relacionado**| Módulo 02 — Ingestão e UDM                                            |
| **Tipo**             | Hands-on · Individual                                                  |
| **MITRE ATT&CK**     | T1059 (Command Scripting), T1190 (Exploit Public-Facing App)           |
| **Pré-requisito**    | Módulo 01 e 02 concluídos · Tenant Google SecOps ativo e com acesso de administrador |
| **Ferramentas**      | Google SecOps Console, Editor de Parser CBN, gcloud CLI                |

---

## 1. Contexto Situacional

O Banco Meridian opera há 22 anos no mercado financeiro brasileiro. Sua plataforma de core
banking — o sistema que processa todas as transações financeiras, controle de contas e
operações de crédito — foi construída sobre o **Tópus Banking**, um sistema proprietário
desenvolvido por uma empresa nacional de software que encerrou suas atividades em 2018.

O Tópus Banking exporta logs em um formato CSV proprietário, gerado a cada 15 minutos pelo
sistema e depositado em um servidor de logs centralizado. Esses logs contêm registros críticos
de segurança: tentativas de acesso de operadores, transações financeiras acima de R$ 10.000,
operações administrativas (criação e exclusão de clientes), e erros de autenticação.

Nenhum parser nativo do Google SecOps cobre o Tópus Banking. Os logs estão sendo ingeridos
via Bindplane OP Agent como "raw logs" sem normalização, o que significa que:

- **Nenhuma regra YARA-L** consegue correlacionar eventos do Tópus Banking com eventos de
  outras fontes (como Azure AD ou Windows Events)
- **Alertas de autenticação** do Tópus Banking não aparecem na UDM Search padrão
- **O UEBA** não consegue criar baseline de comportamento para operadores do sistema

Sua missão: criar um parser CBN completo para normalizar os logs do Tópus Banking para o
UDM, permitindo que o SOC do Banco Meridian tenha visibilidade total sobre os eventos do
sistema de core banking.

---

## 2. Situação Inicial

Ao começar o lab, o ambiente já está configurado da seguinte forma:

- Tenant Google SecOps ativo com logs sintéticos do Banco Meridian
- Bindplane OP Agent instalado no servidor de logs (SRV-LOG-001)
- Feed configurado para ler os arquivos CSV do Tópus Banking do diretório `/var/log/topus/`
- Log type configurado como `TOPUS_BANKING` (sem parser nativo — logs chegando como raw)
- Arquivo de amostra de log disponível em `/var/log/topus/sample_topus.csv`

Você deve verificar que os logs estão chegando sem normalização e então criar o parser CBN.

---

## 3. Problema Identificado

O Gerente de SOC, Rodrigo Saraiva, convocou uma reunião urgente:

*"Pessoal, tivemos um incidente no Tópus Banking ontem. Um operador externo — da empresa
parceira de crédito consignado — tentou acessar contas de clientes fora do horário permitido.
O sistema bloqueou o acesso, mas quando fui verificar no Google SecOps para cruzar com os
logs de VPN e Azure AD, não encontrei NADA do Tópus nos alertas. Os logs estão chegando como
texto puro sem campo algum normalizado. Precisamos do parser hoje."*

---

## 4. Roteiro de Atividades

| Etapa | Atividade                                    | Tempo estimado |
|:-----:|:---------------------------------------------|:--------------:|
| A     | Verificar os logs raw e analisar o formato   | 20 min         |
| B     | Criar e configurar o parser CBN              | 50 min         |
| C     | Validar a normalização via UDM Search        | 25 min         |
| D     | Teste de correlação cruzada com Azure AD     | 15 min         |

---

## 5. Proposição do Lab

**Objetivo:** Criar um parser CBN YAML funcional que normalize os logs do Tópus Banking para
o UDM do Google SecOps, permitindo busca, correlação e detecção via YARA-L.

**Critério de sucesso:**
- Eventos do Tópus Banking aparecem no UDM Search com `metadata.event_type` populado
- Campos `principal.user.userid` e `principal.ip` corretamente mapeados
- Eventos de LOGIN_FAILURE mapeados para `security_result.action = "BLOCK"`
- Retrohunt de uma regra de login fora do horário retorna eventos do Tópus Banking

---

## 6. Script Passo a Passo

### PARTE A — Verificar os Logs Raw e Analisar o Formato (20 min)

---

#### Passo 1: Acessar o arquivo de amostra de log do Tópus Banking

**O que este passo faz:** Conecta ao servidor de logs do laboratório e examina o formato CSV proprietário do Tópus Banking. Esta análise é a base para todo o parser — sem entender a estrutura exata dos dados, não é possível criar regras de extração corretas. O Tópus Banking usa um formato CSV de 8 colunas não documentado, pois a empresa fornecedora encerrou atividades em 2018.

**Por que agora:** O mapeamento de campos deve ser feito antes de abrir o editor de parser. Analistas que pulam esta etapa cometem erros de indexação (ex: mapear a coluna 3 quando o campo desejado está na coluna 4), o que gera logs normalizados incorretamente — um problema silencioso que só aparece durante incidentes reais.

```bash
# Acessar o servidor de logs via SSH
ssh operador@192.168.10.50

# Visualizar as primeiras linhas do arquivo de log do Tópus Banking
head -20 /var/log/topus/sample_topus.csv
```

**Conteúdo esperado do arquivo (formato CSV proprietário Tópus):**

```csv
TIMESTAMP,EVENTO,OPERADOR_ID,IP_ORIGEM,SISTEMA_DESTINO,ACAO,DETALHE,RESULTADO
2026-04-24T08:01:15Z,LOGIN,OPR0042,192.168.10.45,TOPUS-CORE,AUTENTICAR,Sessao_iniciada,SUCESSO
2026-04-24T08:03:22Z,TRANSACAO,OPR0042,192.168.10.45,TOPUS-CORE,CONSULTAR_CONTA,Conta_0091234_consultada,SUCESSO
2026-04-24T08:17:03Z,LOGIN,OPR0089,10.200.45.12,TOPUS-CORE,AUTENTICAR,Senha_incorreta_tentativa_1,FALHA
2026-04-24T08:17:31Z,LOGIN,OPR0089,10.200.45.12,TOPUS-CORE,AUTENTICAR,Senha_incorreta_tentativa_2,FALHA
2026-04-24T08:17:58Z,LOGIN,OPR0089,10.200.45.12,TOPUS-CORE,AUTENTICAR,Conta_bloqueada_3_tentativas,FALHA
2026-04-24T08:45:00Z,ADMIN,OPR0001,192.168.10.10,TOPUS-ADMIN,CRIAR_CLIENTE,Cliente_CPF_ending_4521_criado,SUCESSO
2026-04-24T21:33:17Z,LOGIN,OPR0099,203.45.12.89,TOPUS-CORE,AUTENTICAR,IP_externo_fora_horario,FALHA
2026-04-24T21:33:45Z,LOGIN,OPR0099,203.45.12.89,TOPUS-CORE,AUTENTICAR,Segundo_acesso_bloqueado,FALHA
```

**O que você deve ver:**
- O formato CSV tem exatamente 8 colunas separadas por vírgula
- O campo `EVENTO` pode ser: LOGIN, TRANSACAO, ADMIN, ERRO
- O campo `RESULTADO` pode ser: SUCESSO, FALHA, BLOQUEADO
- O separador de data/hora é ISO 8601 com 'Z' para UTC
- A linha de cabeçalho (TIMESTAMP,EVENTO,...) deve ser ignorada pelo parser

**O que fazer se der errado:**
- Se o arquivo não existir, use o arquivo de amostra do repositório do curso em
  `assets/lab-data/topus_sample.csv`
- Se o SSH falhar, use a interface web do servidor de logs fornecida no ambiente de lab

---

#### Passo 2: Verificar os logs chegando no Google SecOps sem normalização

**O que este passo faz:** Confirma visualmente que os logs do Tópus Banking estão chegando no Google SecOps, mas sem qualquer normalização — campos críticos como `principal.user.userid` e `metadata.event_type` estão vazios ou com valores genéricos. Esta confirmação é necessária para estabelecer o "antes" que justifica o trabalho do parser.

**Por que agora:** Antes de criar qualquer parser, é fundamental confirmar que os logs estão sendo ingeridos. Se o Bindplane Agent tiver problema, nenhum parser funcionará — e você descobrirá isso agora, com tempo para corrigir, não no final do lab.

```
Navegação: Google SecOps Console → Search → UDM Search

Query:
metadata.log_type = "TOPUS_BANKING"
```

**Resultado esperado:** Eventos listados, MAS com campos mínimos populados. A maioria dos
campos do UDM estará vazia (sem normalização).

```
Exemplo de evento raw (sem parser):
─────────────────────────────────────────────────────────────────────────────
metadata.log_type:     TOPUS_BANKING
metadata.event_type:   GENERIC_EVENT       ← não foi mapeado corretamente
principal.hostname:    (vazio)             ← campo não extraído
principal.user.userid: (vazio)             ← campo não extraído
security_result.action: UNKNOWN_ACTION     ← não foi mapeado
raw_log:               2026-04-24T08:17:03Z,LOGIN,OPR0089,...
─────────────────────────────────────────────────────────────────────────────
```

**O que você deve ver:** `principal.user.userid` vazio e `metadata.event_type` como `GENERIC_EVENT`. Isso confirma que o parser CBN é necessário — sem ele, nenhuma regra YARA-L do Banco Meridian consegue correlacionar eventos do Tópus Banking com outras fontes.

**O que fazer se der errado:**
- Se não aparecer nenhum evento com `metadata.log_type = "TOPUS_BANKING"`, verifique se
  o Bindplane OP Agent está ativo: `systemctl status bindplane-agent`
- Verifique se o feed está configurado com o log type `TOPUS_BANKING` em Settings → Ingestion

---

#### Passo 3: Documentar o mapeamento campo a campo

**O que este passo faz:** Cria a tabela de mapeamento que será o guia de construção do parser YAML. Este documento transforma o conhecimento do formato Tópus em uma especificação técnica clara para o parser CBN. Cada linha da tabela corresponde diretamente a um bloco `mapping` no YAML.

**Por que agora:** O parser CBN é escrito em YAML e requer conhecimento preciso de qual campo do CSV vai para qual campo do UDM. Sem esta tabela, o desenvolvimento do parser é tentativa e erro — o que dobra o tempo e aumenta a chance de erros de mapeamento que passam despercebidos.

| Campo Tópus CSV  | Posição | Valor exemplo          | Campo UDM                          | Transformação necessária         |
|:-----------------|:-------:|:-----------------------|:-----------------------------------|:---------------------------------|
| TIMESTAMP        | 1       | `2026-04-24T08:01:15Z` | `metadata.event_timestamp`         | Nenhuma (ISO 8601 direto)        |
| EVENTO           | 2       | `LOGIN`, `TRANSACAO`   | `metadata.event_type`              | Lookup: LOGIN→USER_LOGIN, etc.   |
| OPERADOR_ID      | 3       | `OPR0042`              | `principal.user.userid`            | Nenhuma                          |
| IP_ORIGEM        | 4       | `192.168.10.45`        | `principal.ip`                     | Nenhuma                          |
| SISTEMA_DESTINO  | 5       | `TOPUS-CORE`           | `target.hostname`                  | Nenhuma                          |
| ACAO             | 6       | `AUTENTICAR`           | `security_result.category_details` | Nenhuma                          |
| DETALHE          | 7       | `Sessao_iniciada`      | `security_result.description`      | Substituir _ por espaço          |
| RESULTADO        | 8       | `SUCESSO`, `FALHA`     | `security_result.action`           | Lookup: SUCESSO→ALLOW, FALHA→BLOCK|

**O que você deve ver:** Todos os 8 campos do CSV mapeados antes de avançar para a escrita do YAML. Se algum campo não tiver destino UDM claro, consulte a referência do UDM no Módulo 02 antes de continuar.

---

### PARTE B — Criar e Configurar o Parser CBN (50 min)

---

#### Passo 4: Acessar o Parser Editor no Google SecOps

**O que este passo faz:** Abre o editor de parsers CBN no console do Google SecOps, onde o YAML do parser será escrito e testado. Este é o ponto de entrada para o trabalho técnico central do lab — criar a lógica de normalização que transformará logs raw em eventos UDM pesquisáveis.

**Por que agora:** O acesso ao editor de parsers requer permissões específicas (`chronicle.parsers.create`). Verificar o acesso antes de escrever o YAML evita perder tempo desenvolvendo código que não pode ser salvo por falta de permissão.

```
Navegação:
Settings → Ingestion → Parser Management → + Add New Parser
```

Preencher os campos iniciais:
- **Log Type:** TOPUS_BANKING
- **Display Name:** Tópus Banking Core System
- **Description:** Parser CBN para logs do sistema de core banking Tópus do Banco Meridian

**O que você deve ver:** Editor YAML em branco aguardando o código do parser, com o log type `TOPUS_BANKING` selecionado no topo.

**O que fazer se der errado:**
- Se não encontrar "Parser Management" no menu, verifique se seu usuário tem permissão
  `chronicle.parsers.create` no IAM do Google Cloud
- Se a opção não existir, consulte o instrutor — o tenant pode requerer configuração adicional
- Se aparecer "Log type not found", crie o log type customizado primeiro em Settings → Log Types

---

#### Passo 5: Escrever a seção `meta` do parser CBN

**O que este passo faz:** Define os metadados do parser — nome, versão, autor e o log type ao qual ele se aplica. O campo `log_type` é o elo entre o parser e os logs ingeridos: o Google SecOps usa este campo para aplicar o parser correto a cada log recebido.

**Por que agora:** A seção `meta` deve ser a primeira escrita no YAML porque define o contexto do parser. Um `log_type` incorreto aqui significa que o parser nunca será aplicado aos logs do Tópus Banking — mesmo que todo o restante esteja correto.

```yaml
meta:
  name: TOPUS_BANKING
  display_name: "Tópus Banking Core System"
  description: "Parser CBN para logs do sistema de core banking Tópus — Banco Meridian"
  version: "1.0"
  author: "Time SOC — Banco Meridian"
  log_type: TOPUS_BANKING
  default_log_type: TOPUS_BANKING
```

**O que você deve ver:** Nenhum erro de validação ao salvar a seção meta. O campo `log_type` deve corresponder exatamente ao log type configurado no feed — case-sensitive: `TOPUS_BANKING` (maiúsculas, underscore).

---

#### Passo 6: Escrever a seção `filter` para validar o formato do log

**O que este passo faz:** Define os critérios de validação que o parser aplica a cada log antes de processá-lo. A regex verifica se o log começa com uma data ISO 8601 seguida de um tipo de evento válido. Logs que não passam no filtro são descartados silenciosamente — sem erro, sem consumo de recursos de parsing.

**Por que agora:** O filtro é a primeira linha de defesa do parser. Sem ele, o parser tentará processar linhas de cabeçalho CSV (TIMESTAMP,EVENTO,...) e logs de sistema do Tópus que não são eventos de segurança — gerando entradas UDM inválidas que poluem a base de dados do SOC.

```yaml
filter:
  - check_field:
      field: raw_log
      regex: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z,(LOGIN|TRANSACAO|ADMIN|ERRO),'
```

**O que você deve ver:** O parser ignorará silenciosamente logs que não seguem o formato esperado. Para confirmar, teste a regex com uma linha de log válida e depois com a linha de cabeçalho — apenas a linha válida deve passar.

**O que fazer se der errado:**
- Se a regex rejeitar logs válidos, verifique se o separador de campos é realmente vírgula
  e não ponto-e-vírgula ou pipe
- Se a regex aceitar logs de cabeçalho (TIMESTAMP,EVENTO,...), adicione um filtro `not`:
  ```yaml
  - check_field:
      field: raw_log
      not_regex: '^TIMESTAMP,'
  ```

---

#### Passo 7: Escrever a seção `extraction` com regex de captura dos campos

**O que este passo faz:** Define como os campos do CSV serão extraídos e nomeados como variáveis internas do parser. O método `csv` é a forma mais eficiente para logs com delimitador fixo — ele mapeia cada coluna para uma variável nomeada que será usada na seção `mapping`.

**Por que agora:** A extração vem antes do mapeamento porque as variáveis extraídas aqui são o input do mapeamento UDM. Sem extrair corretamente os campos do CSV, não há dados para mapear.

```yaml
extraction:
  - csv:
      source: raw_log
      delimiter: ","
      target_fields:
        - topus_timestamp
        - topus_evento
        - topus_operador_id
        - topus_ip_origem
        - topus_sistema_destino
        - topus_acao
        - topus_detalhe
        - topus_resultado
```

**Alternativa com regex (se o CSV tiver campos com vírgula interna):**

```yaml
extraction:
  - regex:
      source: raw_log
      pattern: '^(?P<topus_timestamp>[^,]+),(?P<topus_evento>[^,]+),(?P<topus_operador_id>[^,]+),(?P<topus_ip_origem>[^,]+),(?P<topus_sistema_destino>[^,]+),(?P<topus_acao>[^,]+),(?P<topus_detalhe>[^,]+),(?P<topus_resultado>[^,]+)$'
```

**O que você deve ver:** Após a extração, as variáveis `topus_timestamp`, `topus_evento` etc. estarão disponíveis para uso na seção de mapeamento. No editor de parsers, use o botão "Test" com uma linha de log real para verificar se os grupos foram extraídos corretamente — cada campo deve aparecer na lista de variáveis extraídas com o valor correto.

**O que fazer se der errado:**
- Erro "Group not found": verifique se o nome do grupo na regex corresponde ao campo
  na lista `target_fields`
- Regex não faz match: teste a regex em regex101.com com a linha de log real

---

#### Passo 8: Escrever a seção `mapping` — campos obrigatórios

**O que este passo faz:** Mapeia as variáveis extraídas do CSV para os campos do UDM (Unified Data Model) do Google SecOps. Este é o coração do parser — é aqui que os dados proprietários do Tópus Banking se tornam eventos pesquisáveis e correlacionáveis com qualquer outra fonte de log.

**Por que agora:** O mapeamento UDM só pode ser escrito depois da extração estar validada. Mapear campos não existentes gera erros silenciosos — o parser salva, mas os eventos ficam com campos vazios.

```yaml
mapping:
  # Metadados obrigatórios
  metadata.event_timestamp: topus_timestamp
  metadata.product_name: "Tópus Banking"
  metadata.vendor_name: "Tópus Tecnologia"
  metadata.log_type: TOPUS_BANKING

  # Entidade principal (quem originou a ação)
  principal.user.userid: topus_operador_id
  principal.ip: topus_ip_origem

  # Entidade alvo (sistema que recebeu a ação)
  target.hostname: topus_sistema_destino
```

**O que você deve ver:** Campos básicos mapeados. Ao testar com o botão "Test", o evento deve mostrar `principal.user.userid = "OPR0042"` e `principal.ip = "192.168.10.45"`. Se esses campos aparecerem vazios, o problema está na extração do Passo 7.

---

#### Passo 9: Mapear o event_type com lookup condicional

**O que este passo faz:** Traduz os tipos de evento proprietários do Tópus Banking (`LOGIN`, `TRANSACAO`, `ADMIN`, `ERRO`) para os tipos UDM padronizados do Google SecOps. Esta tradução é o que permite que regras YARA-L escritas para qualquer sistema detectem eventos do Tópus Banking — o YARA-L usa `metadata.event_type = "USER_LOGIN"` e funciona para Tópus, Azure AD e qualquer outra fonte normalizada.

**Por que agora:** O `event_type` é o campo mais crítico para correlação. Sem ele mapeado corretamente, o UEBA não consegue identificar padrões de comportamento do operador e as regras de detecção de credential stuffing não funcionam para o Tópus Banking.

```yaml
  # Tipo de evento — mapeamento condicional
  metadata.event_type:
    condition:
      - if: "topus_evento == 'LOGIN'"
        then: USER_LOGIN
      - if: "topus_evento == 'TRANSACAO'"
        then: NETWORK_CONNECTION
      - if: "topus_evento == 'ADMIN'"
        then: USER_CHANGE_PERMISSIONS
      - if: "topus_evento == 'ERRO'"
        then: STATUS_UPDATE
      - else: GENERIC_EVENT
```

**O que você deve ver:** Eventos de `LOGIN` aparecem com `metadata.event_type = USER_LOGIN` na UDM Search. Eventos de `TRANSACAO` aparecem com `NETWORK_CONNECTION`. Teste com uma linha de evento tipo LOGIN e verifique se `USER_LOGIN` aparece; teste também com TRANSACAO.

**O que fazer se der errado:**
- Se aparecer `GENERIC_EVENT` em vez do tipo correto, verifique a capitalização — o Tópus usa MAIÚSCULAS
- Se o condicional não funcionar, verifique se está usando `==` (dois iguais) e não apenas `=`
- Se o valor for case-sensitive, adicione `.upper()` ou use: `if: "topus_evento.lower() == 'login'"`

---

#### Passo 10: Mapear o security_result.action com lookup condicional

**O que este passo faz:** Traduz os resultados de operação do Tópus Banking (`SUCESSO`, `FALHA`, `BLOQUEADO`) para os valores padronizados do UDM (`ALLOW`, `BLOCK`). Esta tradução é fundamental para a detecção de ataques — a regra de password spray do Banco Meridian busca por `security_result.action = "BLOCK"` e precisa capturar falhas de autenticação de TODAS as fontes, incluindo o Tópus Banking.

**Por que agora:** Sem este mapeamento, tentativas de invasão ao core banking do Banco Meridian são invisíveis para o SIEM. O incidente relatado pelo Rodrigo Saraiva — operador externo fora do horário — não geraria alerta algum, pois o RESULTADO=FALHA do Tópus não se tornaria BLOCK no UDM.

```yaml
  # Resultado de segurança — ação
  security_result.action:
    condition:
      - if: "topus_resultado == 'SUCESSO'"
        then: ALLOW
      - if: "topus_resultado == 'FALHA'"
        then: BLOCK
      - if: "topus_resultado == 'BLOQUEADO'"
        then: BLOCK
      - else: UNKNOWN_ACTION

  # Detalhes da ação e descrição
  security_result.category_details: topus_acao
  security_result.description: topus_detalhe
```

**O que você deve ver:**
- Na UDM Search: `metadata.log_type = "TOPUS_BANKING" AND security_result.action = "BLOCK"`
  deve retornar os eventos de LOGIN com FALHA
- `security_result.description` deve conter o texto do campo `DETALHE` (ex: "Senha_incorreta_tentativa_1")

**O que fazer se der errado:** Se `UNKNOWN_ACTION` aparecer em eventos que deveriam ser BLOCK, verifique se o campo `RESULTADO` no CSV tem espaço extra ou capitalização diferente (ex: `falha` em vez de `FALHA`). Use `.upper()` no condicional para normalizar.

---

#### Passo 11: Adicionar o product_event_type para rastreabilidade

**O que este passo faz:** Preserva o valor original do tipo de evento do Tópus Banking no campo `metadata.product_event_type`. Enquanto o `event_type` é normalizado para o padrão UDM (USER_LOGIN), o `product_event_type` mantém o valor original (LOGIN) — essencial para forensics e auditoria BACEN, onde o auditor pode questionar a fidelidade dos dados normalizados.

**Por que agora:** Este campo deve ser adicionado junto com os demais campos de metadados. Uma vez que o parser está salvo e os logs reprocessados, adicionar campos posteriormente requer um novo ciclo de reprocessamento.

```yaml
  # Evento original — mantém o valor do sistema de origem para auditoria
  metadata.product_event_type: topus_evento
```

**O que você deve ver:** O campo `metadata.product_event_type` contém o valor original do Tópus (ex: `LOGIN`, `TRANSACAO`, `ADMIN`), permitindo que analistas vejam o código original do evento mesmo após a normalização UDM.

---

#### Passo 12: Parser CBN completo — código final

**O que este passo faz:** Consolida todas as seções desenvolvidas nos passos anteriores em um único bloco YAML coeso. Este é o parser completo que será validado e salvo. O botão "Validate" verifica a sintaxe YAML antes do save — use-o SEMPRE antes de salvar para evitar erros de sintaxe que podem corromper parsers existentes.

**Por que agora:** A consolidação e validação final garantem que não há conflitos entre as seções. YAML é sensível à indentação — um erro de espaçamento pode quebrar toda a lógica de parsing sem mensagem de erro óbvia.

```yaml
# ============================================================
# Parser CBN: TOPUS_BANKING
# Sistema: Tópus Banking Core System
# Banco: Banco Meridian
# Versão: 1.0
# Autor: Time SOC — Banco Meridian
# Data: 2026-04-24
# ============================================================

meta:
  name: TOPUS_BANKING
  display_name: "Tópus Banking Core System"
  description: "Parser CBN para logs do sistema de core banking Tópus — Banco Meridian"
  version: "1.0"
  author: "Time SOC — Banco Meridian"
  log_type: TOPUS_BANKING

filter:
  - check_field:
      field: raw_log
      regex: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z,(LOGIN|TRANSACAO|ADMIN|ERRO),'
  - check_field:
      field: raw_log
      not_regex: '^TIMESTAMP,'

extraction:
  - csv:
      source: raw_log
      delimiter: ","
      target_fields:
        - topus_timestamp
        - topus_evento
        - topus_operador_id
        - topus_ip_origem
        - topus_sistema_destino
        - topus_acao
        - topus_detalhe
        - topus_resultado

mapping:
  metadata.event_timestamp: topus_timestamp
  metadata.product_name: "Tópus Banking"
  metadata.vendor_name: "Tópus Tecnologia"
  metadata.log_type: TOPUS_BANKING
  metadata.product_event_type: topus_evento

  metadata.event_type:
    condition:
      - if: "topus_evento == 'LOGIN'"
        then: USER_LOGIN
      - if: "topus_evento == 'TRANSACAO'"
        then: NETWORK_CONNECTION
      - if: "topus_evento == 'ADMIN'"
        then: USER_CHANGE_PERMISSIONS
      - if: "topus_evento == 'ERRO'"
        then: STATUS_UPDATE
      - else: GENERIC_EVENT

  principal.user.userid: topus_operador_id
  principal.ip: topus_ip_origem
  target.hostname: topus_sistema_destino

  security_result.action:
    condition:
      - if: "topus_resultado == 'SUCESSO'"
        then: ALLOW
      - if: "topus_resultado == 'FALHA'"
        then: BLOCK
      - if: "topus_resultado == 'BLOQUEADO'"
        then: BLOCK
      - else: UNKNOWN_ACTION

  security_result.category_details: topus_acao
  security_result.description: topus_detalhe
```

**Ação:** Clicar em "Validate" para verificar a sintaxe YAML, depois em "Save".

**O que você deve ver:** Mensagem "Parser saved successfully" sem erros de validação. Se aparecer erro de validação, o editor indica a linha com o problema. Erros comuns: indentação incorreta (YAML é sensível a espaços — não use tabs), vírgulas faltando, aspas desbalanceadas.

---

### PARTE C — Validar a Normalização via UDM Search (25 min)

---

#### Passo 13: Aguardar a re-ingestão dos logs com o novo parser

**O que este passo faz:** Aguarda o Google SecOps reprocessar os logs com o parser recém-criado. O sistema não reparseia automaticamente logs históricos — apenas os novos logs ingeridos após o save do parser são processados imediatamente. Para dados históricos, é necessário aguardar a função de re-parse.

**Por que agora:** Tentar validar imediatamente após salvar o parser retornará resultados inconsistentes — alguns logs já reprocessados, outros ainda como raw. Aguardar os 5–10 minutos garante que a validação subsequente seja confiável.

```
Navegação: Settings → Ingestion → Parser Management → TOPUS_BANKING
Status: "Active" com timestamp de última atualização
```

**O que você deve ver:** Status do parser como "Active". Os próximos logs ingeridos serão automaticamente processados com o novo parser.

**Observação:** Os logs já ingeridos antes da criação do parser **não são** automaticamente re-processados. Para re-normalizar dados históricos, é necessário usar a função de "Re-parse" disponível no painel de parser management (disponível em alguns tenants).

---

#### Passo 14: Validar os campos principais via UDM Search

**O que este passo faz:** Executa 4 queries de validação que confirmam, de forma sistemática, que cada aspecto crítico do parser está funcionando: presença de dados normalizados (Q1), mapeamento de identidade (Q2), mapeamento de falhas de segurança (Q3) e distribuição de event_types (Q4). Esta validação é a entrega formal da Etapa C do lab.

**Por que agora:** A validação sequencial das 4 queries permite identificar exatamente qual componente do parser está com problema, caso algum campo esteja incorreto. Sem essa estrutura, uma falha é difícil de diagnosticar.

```
Query 1 — Verificar chegada dos logs normalizados:
───────────────────────────────────────────────────────────────────
metadata.log_type = "TOPUS_BANKING"

Resultado esperado: Eventos com campos preenchidos (não mais vazios)
```

```
Query 2 — Verificar mapeamento de userid:
──────────────────────────────────────────
metadata.log_type = "TOPUS_BANKING" AND
principal.user.userid != ""

Resultado esperado: Todos os eventos com userid preenchido (OPR0042, OPR0089, etc.)
```

```
Query 3 — Verificar eventos de falha de login (BLOCK):
────────────────────────────────────────────────────────
metadata.log_type = "TOPUS_BANKING" AND
metadata.event_type = "USER_LOGIN" AND
security_result.action = "BLOCK"

Resultado esperado: 3 eventos de falha de login do arquivo de amostra
(dois de OPR0089 + um de OPR0099 fora do horário)
```

```
Query 4 — Verificar distribuição de event_types:
─────────────────────────────────────────────────
metadata.log_type = "TOPUS_BANKING"
| group_by metadata.event_type
| order_by count() desc

Resultado esperado:
USER_LOGIN          → 5 eventos
NETWORK_CONNECTION  → 1 evento (TRANSACAO)
USER_CHANGE_PERMISSIONS → 1 evento (ADMIN)
```

**O que você deve ver:** Todos os quatro queries retornando resultados não-vazios com os contadores esperados. Se algum campo ainda aparecer vazio, revise o mapeamento correspondente no parser CBN.

**O que fazer se der errado:**
- `UNKNOWN_ACTION` ainda aparece: verifique o mapeamento `security_result.action` — provavelmente
  um dos valores de `RESULTADO` no CSV tem espaço extra ou capitalização diferente
- `GENERIC_EVENT` ainda aparece: verifique o mapeamento `metadata.event_type` e a capitalização
  dos valores de `topus_evento`

---

#### Passo 15: Correlação cruzada com Azure AD — teste de integração

**O que este passo faz:** Demonstra o valor central do UDM executando uma query que correlaciona eventos de falha de login de DUAS fontes diferentes (Tópus Banking e Azure AD) em uma única busca. Esta é a justificativa de negócio para todo o trabalho do parser — sem normalização UDM, esta correlação não seria possível.

**Por que agora:** A correlação cruzada é a validação final do lab — prova que o parser não apenas normaliza campos corretamente, mas habilita o caso de uso crítico para o CISO: ver o comportamento de um mesmo atacante em múltiplos sistemas simultaneamente.

**Contexto:** OPR0099 é o operador externo que tentou acesso fora do horário. O mesmo
usuário (`marcos.terceiro@parceiro.com.br`, cujo login corporativo é `OPR0099`) pode
ter tentado login no Azure AD do Banco Meridian também.

```
Query — Busca cruzada por usuário que falhou em múltiplas fontes:
──────────────────────────────────────────────────────────────────────────────────────
security_result.action = "BLOCK" AND
metadata.event_type = "USER_LOGIN" AND
(
  metadata.log_type = "TOPUS_BANKING" OR
  metadata.log_type = "AZURE_AD"
)
| group_by principal.ip
| order_by count() desc
```

**O que você deve ver:** Se os dados de amostra incluírem falhas no Azure AD do mesmo IP (`203.45.12.89`), a query retornará o IP com eventos de AMBAS as fontes. Este é o benefício central do UDM: a mesma query funciona para múltiplas fontes de log sem modificação. Se o resultado mostrar o IP `203.45.12.89` em eventos de ambos os log types, o parser está funcionando perfeitamente.

---

## 7. Objetivos por Etapa

| Etapa | Parte do Lab         | Objetivo                                                              | Critério de Conclusão                                          |
|:-----:|:---------------------|:----------------------------------------------------------------------|:---------------------------------------------------------------|
| A     | Análise do formato   | Compreender a estrutura do log CSV do Tópus Banking                   | Tabela de mapeamento campo a campo documentada                 |
| B     | Criação do parser    | Criar o parser CBN completo e sem erros de sintaxe                    | Parser salvo com status "Active"                               |
| C     | Validação UDM        | Confirmar que os campos críticos estão corretamente mapeados          | Quatro queries de validação retornam resultados esperados       |
| D     | Correlação cruzada   | Demonstrar que o UDM normalizado permite queries multi-fonte          | Query cruzada Tópus + Azure AD retorna resultados coerentes    |

---

## 8. Gabarito Completo

### Gabarito — Parser CBN Funcional

O parser CBN completo e funcional está documentado no **Passo 12** deste lab. Cada campo
do CSV do Tópus Banking é mapeado para o campo UDM correspondente, com as seguintes
decisões de design:

**Por que `principal.user.userid` e não `target.user.userid` para o operador?**

O código correto é mapear `OPERADOR_ID` para `principal.user.userid`. No Tópus Banking, o operador é **quem executa** a ação — ele é o `principal` (originador). O sistema alvo (`SISTEMA_DESTINO`) é o `target.hostname`. Esta semântica é diferente do Windows Event 4625, onde o usuário alvo vai para `target.user.userid`.

**Por que esta é a resposta correta:** O campo `principal` no UDM representa o agente iniciador da ação. Em logs de autenticação, quem tenta o login é o principal. Inverter essa lógica quebra todas as regras YARA-L que buscam por `principal.user.userid` — elas não encontrariam os operadores do Tópus Banking.

**Erro mais comum neste passo:** Mapear `OPERADOR_ID` para `target.user.userid` por confusão com o log do Windows (onde o target é o usuário sendo autenticado). No Tópus, o sistema não distingue target de principal dessa forma — o operador é sempre o principal.

---

**Por que `NETWORK_CONNECTION` para eventos de TRANSACAO?**

Eventos de `TRANSACAO` no Tópus Banking representam chamadas de API entre o operador e o core banking — essencialmente uma conexão de rede aplicacional. `NETWORK_CONNECTION` é o tipo UDM mais adequado para representar esse padrão.

**Por que esta é a resposta correta:** O UDM `NETWORK_CONNECTION` é usado para eventos de comunicação entre sistemas. Uma transação bancária no Tópus é uma requisição HTTP/API ao core banking — tecnicamente uma conexão de rede. Usar `GENERIC_EVENT` perderia a capacidade de correlacionar transações com eventos de rede em outras fontes.

**Erro mais comum neste passo:** Usar `USER_LOGIN` para TRANSACAO (confundir autenticação com transação) ou `GENERIC_EVENT` (usar o fallback em vez de escolher o tipo mais específico disponível).

---

**Por que mapear `security_result.description` com o campo `DETALHE`?**

O campo `DETALHE` do Tópus contém informações críticas para forensics (ex: "Conta_bloqueada_3_tentativas", "IP_externo_fora_horario"). Mapeá-lo para `security_result.description` permite que analistas vejam esse contexto diretamente no alerta, sem precisar consultar o log bruto.

**Por que esta é a resposta correta:** O campo `security_result.description` é exibido nos alertas e incidentes do Google SecOps. Colocar o contexto operacional aqui reduz o tempo de triagem — o analista não precisa abrir o raw log para entender o que aconteceu. Para auditorias BACEN, este campo é evidência direta de que o sistema registrou a razão do bloqueio.

**Erro mais comum neste passo:** Deixar `security_result.description` vazio ou mapear o campo `ACAO` (que contém o tipo de ação, não o detalhe). O campo `ACAO` deve ir para `security_result.category_details`, não para `description`.

---

### Gabarito — Queries de Validação Esperadas

| Query | Resultado esperado                                                              |
|:-----:|:--------------------------------------------------------------------------------|
| Q1    | Eventos com todos os campos UDM populados; `principal.user.userid` não vazio    |
| Q2    | Eventos com `userid` OPR0042, OPR0089, OPR0099, OPR0001                        |
| Q3    | 3 eventos: 2x OPR0089 (senha incorreta) + 1x OPR0099 (horário)                |
| Q4    | USER_LOGIN (maioria), NETWORK_CONNECTION, USER_CHANGE_PERMISSIONS              |

**Por que esses resultados confirmam que o parser está correto:**
- Q1 (campos populados): Um campo vazio indica que a coluna CSV não foi extraída corretamente.
  Se `principal.user.userid` estiver vazio, o parser está referenciando o campo errado.
- Q3 (3 bloqueios): Esta é a verificação de integridade dos dados — os 3 eventos de FALHA
  no arquivo de amostra devem aparecer todos como `BLOCK`. Se aparecerem 0 ou 1, o mapeamento
  condicional do `security_result.action` está com erro de capitalização.
- Q4 (diversidade de tipos): Confirma que o mapeamento condicional de `metadata.event_type`
  está funcionando para todos os 4 tipos de evento do Tópus.

**Variações aceitáveis:**
- Usar `NETWORK_HTTP` em vez de `NETWORK_CONNECTION` para eventos de TRANSACAO é aceitável,
  pois transações bancárias podem ser modeled como HTTP requests para o core banking.
- Mapear `security_result.category` em vez de `category_details` para o campo ACAO é
  aceitável se o aluno justificar a escolha de semântica.
- Adicionar campos extras não especificados (ex: `target.application`) é aceito desde que
  não conflite com os campos obrigatórios do gabarito.

### Gabarito — Erros Comuns e Soluções

| Erro Comum                               | Causa                                    | Diagnóstico e Solução                                              |
|:-----------------------------------------|:-----------------------------------------|:-----------------------------------------------------:|
| `UNKNOWN_ACTION` em todos os eventos     | Capitalização diferente em `RESULTADO`   | **Causa:** o CSV pode ter `Sucesso` em vez de `SUCESSO`. Verificar valores exatos: `head -5 /var/log/topus/sample_topus.csv \| cut -d, -f8`. Solução: usar `.upper()` no condicional |
| `GENERIC_EVENT` em todos os eventos      | Capitalização diferente em `EVENTO`      | **Causa:** variação de capitalização no campo EVENTO. Verificar: `cut -d, -f2`. Ajustar condicionais para maiúsculas ou adicionar `.lower()` |
| Parser status "Error" ao salvar          | Erro de indentação YAML                  | **Causa:** YAML não aceita tabs — apenas espaços. Verificar que cada nível usa 2 espaços. Copiar o YAML para um validador online (yamllint.com) antes de salvar |
| `principal.user.userid` vazio            | Nome do campo no CSV errado              | **Causa:** o campo pode ser `OPERADOR` em vez de `OPERADOR_ID` em algumas versões do Tópus. Verificar coluna 3: `cut -d, -f3` |
| Logs não aparecem após criar o parser    | Re-ingestão ainda pendente               | **Causa:** o Google SecOps processa novos logs imediatamente, mas não reparseia logs antigos automaticamente. Aguardar 10 min; verificar status do Bindplane Agent com `systemctl status bindplane-agent` |

---

*Lab 01 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 02 — Ingestão e UDM](../../modulos/modulo-02-ingestao-udm/README.md)*
*Próximo lab: [Lab 02 — YARA-L Multi-Event](../lab-02-yara-l-multi-event/README.md)*
