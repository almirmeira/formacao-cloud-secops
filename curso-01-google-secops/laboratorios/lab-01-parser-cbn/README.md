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

**Ação:** No servidor de logs do laboratório (ou usando o arquivo fornecido no repositório),
examine o conteúdo do arquivo de amostra.

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

**O que verificar:**
- O formato CSV tem 8 colunas fixas separadas por vírgula
- O campo `EVENTO` pode ser: LOGIN, TRANSACAO, ADMIN, ERRO
- O campo `RESULTADO` pode ser: SUCESSO, FALHA, BLOQUEADO
- O separador de data/hora é ISO 8601 com 'Z' para UTC

**O que fazer se der errado:**
- Se o arquivo não existir, use o arquivo de amostra do repositório do curso em
  `assets/lab-data/topus_sample.csv`
- Se o SSH falhar, use a interface web do servidor de logs fornecida no ambiente de lab

---

#### Passo 2: Verificar os logs chegando no Google SecOps sem normalização

**Ação:** Acessar o UDM Search no console do Google SecOps e verificar os eventos raw.

```
Navegação: Google SecOps Console → Search → UDM Search

Query:
metadata.log_type = "TOPUS_BANKING"
```

**Resultado esperado:** Eventos listados, MAS com campos mínimos populados. A maioria dos
campos do UDM estará vazia (sem normalização).

```
Exemplo de evento raw (sem parser):
─────────────────────────────────────────────────────────────────
metadata.log_type:     TOPUS_BANKING
metadata.event_type:   GENERIC_EVENT       ← não foi mapeado corretamente
principal.hostname:    (vazio)             ← campo não extraído
principal.user.userid: (vazio)             ← campo não extraído
security_result.action: UNKNOWN_ACTION     ← não foi mapeado
raw_log:               2026-04-24T08:17:03Z,LOGIN,OPR0089,...
─────────────────────────────────────────────────────────────────
```

**O que verificar:** Confirme que `principal.user.userid` está vazio e que `metadata.event_type`
está como `GENERIC_EVENT`. Isso confirma que o parser CBN é necessário.

**O que fazer se der errado:**
- Se não aparecer nenhum evento com `metadata.log_type = "TOPUS_BANKING"`, verifique se
  o Bindplane OP Agent está ativo: `systemctl status bindplane-agent`
- Verifique se o feed está configurado com o log type `TOPUS_BANKING` em Settings → Ingestion

---

#### Passo 3: Documentar o mapeamento campo a campo

**Ação:** Antes de escrever o YAML do parser, documente o mapeamento em uma tabela.

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

**O que verificar:** Certifique-se de que todos os 8 campos foram mapeados antes de escrever o YAML.

---

### PARTE B — Criar e Configurar o Parser CBN (50 min)

---

#### Passo 4: Acessar o Parser Editor no Google SecOps

**Ação:** Navegar para o editor de parsers no console do Google SecOps.

```
Navegação:
Settings → Ingestion → Parser Management → + Add New Parser
```

Preencher os campos iniciais:
- **Log Type:** TOPUS_BANKING
- **Display Name:** Tópus Banking Core System
- **Description:** Parser CBN para logs do sistema de core banking Tópus do Banco Meridian

**Resultado esperado:** Editor YAML em branco aguardando o código do parser.

**O que verificar:** Confirme que o log type `TOPUS_BANKING` está selecionado corretamente.
Se aparecer "Log type not found", crie o log type customizado primeiro em Settings → Log Types.

**O que fazer se der errado:**
- Se não encontrar "Parser Management" no menu, verifique se seu usuário tem permissão
  `chronicle.parsers.create` no IAM do Google Cloud
- Se a opção não existir, consulte o instrutor — o tenant pode requerer configuração adicional

---

#### Passo 5: Escrever a seção `meta` do parser CBN

**Ação:** Adicionar a seção de metadados ao editor YAML.

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

**Resultado esperado:** Nenhum erro de validação ao salvar a seção meta.

**O que verificar:** O campo `log_type` deve corresponder exatamente ao log type configurado
no feed. Case-sensitive: `TOPUS_BANKING` (maiúsculas, underscore).

---

#### Passo 6: Escrever a seção `filter` para validar o formato do log

**Ação:** Adicionar a seção de filtros que valida o formato do log antes de processar.

```yaml
filter:
  - check_field:
      field: raw_log
      regex: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z,(LOGIN|TRANSACAO|ADMIN|ERRO),'
```

**Resultado esperado:** O parser vai ignorar silenciosamente logs que não seguem o formato
esperado (ex: linhas de cabeçalho do CSV, logs de sistema do Tópus que não são eventos de segurança).

**O que verificar:** Teste a regex no seu editor favorito com uma linha de log válida e uma inválida.

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

**Ação:** Adicionar a extração dos campos CSV usando regex com grupos nomeados.

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

**Resultado esperado:** Após a extração, as variáveis `topus_timestamp`, `topus_evento` etc.
estarão disponíveis para uso na seção de mapeamento.

**O que verificar:**
- No editor de parsers, use o botão "Test" com uma linha de log real para verificar se
  os grupos foram extraídos corretamente
- Cada campo deve aparecer na lista de variáveis extraídas com o valor correto

**O que fazer se der errado:**
- Erro "Group not found": verifique se o nome do grupo na regex corresponde ao campo
  na lista `target_fields`
- Regex não faz match: teste a regex em regex101.com com a linha de log real

---

#### Passo 8: Escrever a seção `mapping` — campos obrigatórios

**Ação:** Adicionar o mapeamento dos campos básicos obrigatórios do UDM.

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

**Resultado esperado:** Campos básicos mapeados. Ao testar com o botão "Test", o evento
deve mostrar `principal.user.userid = "OPR0042"` e `principal.ip = "192.168.10.45"`.

---

#### Passo 9: Mapear o event_type com lookup condicional

**Ação:** Adicionar o mapeamento condicional do `metadata.event_type` baseado no campo `topus_evento`.

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

**Resultado esperado:** Eventos de `LOGIN` aparecem com `metadata.event_type = USER_LOGIN`
na UDM Search. Eventos de `TRANSACAO` aparecem com `NETWORK_CONNECTION`.

**O que verificar:**
- No editor de parsers, teste com uma linha de evento tipo LOGIN e verifique se `USER_LOGIN` aparece
- Teste também com TRANSACAO e verifique se `NETWORK_CONNECTION` aparece
- Se aparecer `GENERIC_EVENT` em vez do tipo correto, verifique a capitalização (TOPUS usa maiúsculas)

**O que fazer se der errado:**
- Se o condicional não funcionar, verifique se está usando `==` (dois iguais) e não apenas `=`
- Se o valor for case-sensitive, adicione `.upper()` ou use regex insensível a maiúsculas:
  `if: "topus_evento.lower() == 'login'"`

---

#### Passo 10: Mapear o security_result.action com lookup condicional

**Ação:** Mapear o resultado (SUCESSO/FALHA/BLOQUEADO) para os valores UDM de `security_result.action`.

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

**Resultado esperado:** Eventos com `RESULTADO = FALHA` agora aparecem com
`security_result.action = BLOCK` na UDM Search. Isso permitirá que regras YARA-L
como a de password spray do Lab 02 detectem também falhas de login do Tópus Banking.

**O que verificar:**
- Na UDM Search: `metadata.log_type = "TOPUS_BANKING" AND security_result.action = "BLOCK"`
  deve retornar os eventos de LOGIN com FALHA
- `security_result.description` deve conter o texto do campo `DETALHE` (substituindo _ por espaço)

---

#### Passo 11: Adicionar o product_event_type para rastreabilidade

**Ação:** Mapear o tipo de evento original do Tópus para `metadata.product_event_type`,
mantendo o valor original para fins de forensics e auditoria.

```yaml
  # Evento original — mantém o valor do sistema de origem para auditoria
  metadata.product_event_type: topus_evento
```

**Resultado esperado:** O campo `metadata.product_event_type` contém o valor original
do Tópus (ex: `LOGIN`, `TRANSACAO`, `ADMIN`), permitindo que analistas vejam o código
original do evento mesmo após a normalização UDM.

---

#### Passo 12: Parser CBN completo — código final

**Ação:** Verificar o parser completo consolidado antes de salvar.

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

**Resultado esperado:** Mensagem "Parser saved successfully" sem erros de validação.

**O que verificar:** Se aparecer erro de validação, o editor indica a linha com o problema.
Erros comuns: indentação incorreta (YAML é case-sensitive para indentação com espaços),
vírgulas faltando, aspas desbalanceadas.

---

### PARTE C — Validar a Normalização via UDM Search (25 min)

---

#### Passo 13: Aguardar a re-ingestão dos logs com o novo parser

**Ação:** Após salvar o parser, aguardar 5–10 minutos para que o Google SecOps reprocesse
os logs com o novo parser CBN.

```
Navigação: Settings → Ingestion → Parser Management → TOPUS_BANKING
Status: "Active" com timestamp de última atualização
```

**Resultado esperado:** Status do parser como "Active". Os próximos logs ingeridos serão
automaticamente processados com o novo parser.

**Observação:** Os logs já ingeridos antes da criação do parser **não são** automaticamente
re-processados. Para re-normalizar dados históricos, é necessário usar a função de
"Re-parse" disponível no painel de parser management (disponível em alguns tenants).

---

#### Passo 14: Validar os campos principais via UDM Search

**Ação:** Executar as queries de validação na UDM Search.

```
Query 1 — Verificar chegada dos logs normalizados:
───────────────────────────────────────────────────
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

**O que verificar:** Todos os quatro queries devem retornar resultados não-vazios. Se algum
campo ainda aparecer vazio, revise o mapeamento correspondente no parser CBN.

**O que fazer se der errado:**
- `UNKNOWN_ACTION` ainda aparece: verifique o mapeamento `security_result.action` — provavelmente
  um dos valores de `RESULTADO` no CSV tem espaço extra ou capitalização diferente
- `GENERIC_EVENT` ainda aparece: verifique o mapeamento `metadata.event_type` e a capitalização
  dos valores de `topus_evento`

---

#### Passo 15: Correlação cruzada com Azure AD — teste de integração

**Ação:** Executar uma query cruzada entre eventos do Tópus Banking e do Azure AD para
o mesmo operador, demonstrando o valor da normalização UDM.

**Contexto:** OPR0099 é o operador externo que tentou acesso fora do horário. O mesmo
usuário (`marcos.terceiro@parceiro.com.br`, cujo login corporativo é `OPR0099`) pode
ter tentado login no Azure AD do Banco Meridian também.

```
Query — Busca cruzada por usuário que falhou em múltiplas fontes:
──────────────────────────────────────────────────────────────────
security_result.action = "BLOCK" AND
metadata.event_type = "USER_LOGIN" AND
(
  metadata.log_type = "TOPUS_BANKING" OR
  metadata.log_type = "AZURE_AD"
)
| group_by principal.ip
| order_by count() desc
```

**Resultado esperado:** Se os dados de amostra incluírem falhas no Azure AD do mesmo IP
(`203.45.12.89`), a query retornará o IP com eventos de AMBAS as fontes.

**O que verificar:** Este é o benefício central do UDM: a mesma query funciona para
múltiplas fontes de log sem modificação. Se o resultado mostrar o IP `203.45.12.89` em
eventos de ambos os log types, o parser está funcionando perfeitamente.

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
No Tópus Banking, o operador (`OPERADOR_ID`) é **quem executa** a ação. Ele é o `principal`
(originador). O sistema alvo (`SISTEMA_DESTINO`) é o `target.hostname`. Esta semântica é
diferente do Windows Event 4625, onde o usuário alvo vai para `target.user.userid`.

**Por que `NETWORK_CONNECTION` para eventos de TRANSACAO?**
Eventos de `TRANSACAO` no Tópus Banking representam chamadas de API entre o operador e
o core banking — essencialmente uma conexão de rede aplicacional. `NETWORK_CONNECTION` é
o tipo UDM mais adequado para representar esse padrão.

**Por que mapear `security_result.description` com o campo `DETALHE`?**
O campo `DETALHE` do Tópus contém informações críticas para forensics (ex: "Conta_bloqueada_3_tentativas",
"IP_externo_fora_horario"). Mapeá-lo para `security_result.description` permite que analistas
vejam esse contexto diretamente no alerta, sem precisar consultar o log bruto.

### Gabarito — Queries de Validação Esperadas

| Query | Resultado esperado                                                              |
|:-----:|:--------------------------------------------------------------------------------|
| Q1    | Eventos com todos os campos UDM populados; `principal.user.userid` não vazio    |
| Q2    | Eventos com `userid` OPR0042, OPR0089, OPR0099, OPR0001                        |
| Q3    | 3 eventos: 2x OPR0089 (senha incorreta) + 1x OPR0099 (horário)                |
| Q4    | USER_LOGIN (maioria), NETWORK_CONNECTION, USER_CHANGE_PERMISSIONS              |

### Gabarito — Erros Comuns e Soluções

| Erro Comum                               | Causa                                    | Solução                                              |
|:-----------------------------------------|:-----------------------------------------|:-----------------------------------------------------|
| `UNKNOWN_ACTION` em todos os eventos     | Capitalização diferente em `RESULTADO`   | Verificar valores exatos no CSV; usar `.upper()`     |
| `GENERIC_EVENT` em todos os eventos      | Capitalização diferente em `EVENTO`      | Verificar CSV; ajustar condicionais para maiúsculas  |
| Parser status "Error" ao salvar          | Erro de indentação YAML                  | Verificar que cada nível usa 2 espaços; não usar tabs|
| `principal.user.userid` vazio            | Nome do campo no CSV errado              | Verificar coluna 3 do CSV = `OPERADOR_ID`            |
| Logs não aparecem após criar o parser    | Re-ingestão ainda pendente               | Aguardar 10 min; verificar status do Bindplane Agent |

---

*Lab 01 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 02 — Ingestão e UDM](../../modulos/modulo-02-ingestao-udm/README.md)*
*Próximo lab: [Lab 02 — YARA-L Multi-Event](../lab-02-yara-l-multi-event/README.md)*
