# Módulo 02 — Logging e Monitoramento em AWS

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 2 (Detection and Response)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Configurar o CloudTrail organization trail com bucket S3 centralizado e KMS
2. Criar e consultar event data stores no CloudTrail Lake com SQL
3. Implementar metric filters no CloudWatch para alertas de segurança críticos
4. Analisar VPC Flow Logs para identificar tráfego suspeito
5. Arquitetar o logging centralizado multi-conta do Banco Meridian
6. Criar regras no Amazon EventBridge para roteamento de eventos de segurança

---

## 1. AWS CloudTrail

O CloudTrail é o serviço de auditoria de API calls da AWS. Ele registra toda ação realizada por usuários, roles e serviços AWS na sua conta.

### Tipos de Eventos CloudTrail

| Tipo de Evento | O que Registra | Habilitado por Padrão | Custo Adicional | Exemplos |
|---|---|---|---|---|
| **Management Events** | Operações de controle (create, modify, delete de recursos) | Sim (90 dias free no Event History) | Primeiros 1 trail gratuito | `CreateUser`, `RunInstances`, `DeleteBucket` |
| **Data Events** | Operações de dados em objetos (S3 put/get, Lambda invoke, DynamoDB) | Não | Sim | `S3:GetObject`, `Lambda:Invoke`, `DynamoDB:PutItem` |
| **Insights Events** | Detecção de atividade API incomum (volume anômalo de calls) | Não | Sim | Spike de `TerminateInstances`, burst de `CreateUser` |

### Estrutura de um Evento CloudTrail (JSON Completo Anotado)

**O que este bloco representa:** Um evento CloudTrail é o registro completo e estruturado de uma chamada de API realizada na AWS, armazenado em formato JSON. Cada campo do JSON responde a uma das perguntas fundamentais de auditoria: quem executou a ação, o que foi executado, de onde partiu a requisição, quando ocorreu e se foi bem-sucedida. Para investigações de segurança, esses campos são os primeiros elementos examinados durante um processo de resposta a incidentes.

**Por que isso importa para o Banco Meridian:** Como instituição financeira sujeita à Resolução BACEN 4.893, o Banco Meridian é obrigado a manter trilha de auditoria completa de todas as ações sobre sistemas de informação. O evento JSON do CloudTrail é a unidade básica dessa trilha: cada `DeleteBucket`, `CreateUser` ou `StopLogging` executado em qualquer conta da organização (111 – Management, 222 – Audit, 333 – Log Archive, 444 – Production, 555 – Dev) gera exatamente esse registro, e é sobre esses registros que todas as queries SQL do CloudTrail Lake e todos os alertas do CloudWatch são construídos.

```json
{
  "eventVersion": "1.08",           // Versão do schema do evento
  "userIdentity": {
    "type": "IAMUser",              // Tipo: Root, IAMUser, AssumedRole, AWSService, FederatedUser
    "principalId": "AIDA...",       // ID único da entidade
    "arn": "arn:aws:iam::444444444444:user/joao.silva",
    "accountId": "444444444444",    // Conta onde a identidade existe
    "accessKeyId": "AKIA...",       // Access key usada (se aplicável)
    "userName": "joao.silva"        // Nome do usuário IAM
  },
  "eventTime": "2026-04-10T14:32:11Z",  // Hora UTC do evento
  "eventSource": "s3.amazonaws.com",    // Serviço que gerou o evento
  "eventName": "DeleteBucket",          // Nome da API action
  "awsRegion": "sa-east-1",            // Região onde ocorreu
  "sourceIPAddress": "189.42.100.15",  // IP de origem da requisição
  "userAgent": "aws-cli/2.15.0",       // Ferramenta usada para a chamada
  "requestParameters": {
    "bucketName": "meridian-backup-dev" // Parâmetros da chamada de API
  },
  "responseElements": null,             // Resposta do serviço (null = sem body)
  "requestID": "7A3F...",              // ID único da requisição
  "eventID": "9B2C...",               // ID único do evento CloudTrail
  "readOnly": false,                   // false = ação de escrita (crítico para alertas)
  "eventType": "AwsApiCall",           // Tipo: AwsApiCall, AwsConsoleSignIn, AwsServiceEvent
  "managementEvent": true,             // true = Management Event
  "recipientAccountId": "444444444444",// Conta que recebeu o evento
  "eventCategory": "Management",       // Categoria: Management, Data, Insights
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_256_GCM_SHA384",
    "clientProvidedHostHeader": "s3.sa-east-1.amazonaws.com"
  }
}
```

**Interpretando o resultado:** O campo `userIdentity.type = "IAMUser"` identifica que a ação partiu de um usuário IAM nominal (não de uma role ou do root). O campo `readOnly: false` sinaliza que foi uma ação de escrita — operações de escrita são sempre mais críticas do ponto de vista de segurança e devem ter alertas dedicados. O `sourceIPAddress: "189.42.100.15"` é um endereço IP público: durante uma investigação, verificar se esse IP pertence ao range corporativo do Banco Meridian ou a um endereço desconhecido é o primeiro passo de triagem. O `tlsDetails.tlsVersion: "TLSv1.3"` confirma que a comunicação usou TLS moderno — conexões com TLS 1.0 ou 1.1 seriam um sinal de alerta adicional. O `errorCode` ausente neste exemplo indica que a ação foi executada com sucesso; quando presente (ex: `AccessDenied`), indica que a tentativa foi bloqueada.

### CloudTrail Organization Trail

Um Organization Trail registra eventos de **todas as contas** da organização em um único trail, entregando logs no bucket S3 da conta Log Archive.

**Configuração recomendada:**

**O que este comando faz:** Os três comandos a seguir criam e ativam o Organization Trail centralizado do Banco Meridian. O primeiro (`create-trail`) provisiona o trail na conta Management com `--is-organization-trail`, instrução que faz a AWS replicar automaticamente o trail para todas as contas-membro da organização, e aponta a entrega dos logs para o bucket S3 na conta Log Archive (333333333333), com criptografia via KMS e validação de integridade ativada. O segundo (`put-event-selectors`) configura a captura de Data Events para objetos S3 e funções Lambda, habilitando visibilidade sobre quem leu, gravou ou invocou esses recursos — operações que os Management Events não registram. O terceiro (`start-logging`) efetivamente inicia o trail.

**Por que isso importa para o Banco Meridian:** Um trail por conta individual jamais proveria visibilidade consolidada sobre a organização multi-conta do banco. O Organization Trail é a fundação de toda a estratégia de auditoria: sem ele, um atacante que comprometesse a conta Production (444444444444) poderia destruir evidências na própria conta sem que a conta Log Archive (333333333333) registrasse qualquer coisa. A flag `--enable-log-file-validation` gera hashes SHA-256 assinados com RSA para cada arquivo de log, criando a prova de integridade forense exigida em auditorias regulatórias do BACEN.

```bash
# Criar o organization trail no Management Account
aws cloudtrail create-trail \
  --name "meridian-org-trail" \
  --s3-bucket-name "meridian-logs-333333333333" \
  --is-organization-trail \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id "arn:aws:kms:sa-east-1:333333333333:key/mrk-abc123"

# Habilitar Data Events para S3 e Lambda
aws cloudtrail put-event-selectors \
  --trail-name "meridian-org-trail" \
  --advanced-event-selectors '[
    {
      "Name": "S3DataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    },
    {
      "Name": "LambdaDataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
      ]
    }
  ]'

# Iniciar o trail
aws cloudtrail start-logging --name "meridian-org-trail"
```

**Bucket Policy do S3 Log Archive (obrigatória para Organization Trail):**

**O que este bloco representa:** Esta bucket policy define as permissões que o serviço CloudTrail precisa para entregar logs no bucket da conta Log Archive. Sem ela, o Organization Trail não consegue gravar nenhum arquivo. O documento JSON contém três declarações: a primeira (`AWSCloudTrailAclCheck`) permite que o CloudTrail verifique as permissões do bucket antes de escrever; a segunda (`AWSCloudTrailWrite`) autoriza a gravação dos arquivos de log sob a condição de que o bucket owner tenha controle total (`bucket-owner-full-control`) e que a origem seja a organização AWS correta (`aws:SourceOrgID`); a terceira (`DenyDeleteAndPublicAccess`) bloqueia explicitamente qualquer tentativa de exclusão de objetos ou do bucket e qualquer modificação do bloqueio de acesso público.

**Por que isso importa para o Banco Meridian:** A condição `aws:SourceOrgID: "o-abc123xyz"` é uma salvaguarda crítica: sem ela, qualquer conta AWS externa poderia escrever arquivos maliciosos no bucket de logs do banco, comprometendo a integridade da evidência forense. O statement `DenyDeleteAndPublicAccess` trabalha em conjunto com o S3 Object Lock: mesmo que um administrador da conta Log Archive seja comprometido, a bucket policy cria uma camada adicional de proteção contra exclusão de logs. Para o BACEN 4.893, que exige preservação de registros por 5 a 7 anos, essa combinação de Object Lock + bucket policy restritiva é o mecanismo de conformidade.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::meridian-logs-333333333333"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::meridian-logs-333333333333/AWSLogs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceOrgID": "o-abc123xyz"
        }
      }
    },
    {
      "Sid": "DenyDeleteAndPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteBucket",
        "s3:PutBucketPublicAccessBlock"
      ],
      "Resource": [
        "arn:aws:s3:::meridian-logs-333333333333",
        "arn:aws:s3:::meridian-logs-333333333333/*"
      ]
    }
  ]
}
```

**Interpretando o resultado:** O statement `AWSCloudTrailWrite` usa o operador `StringEquals` em duas condições simultâneas (AND implícito): ambas precisam ser verdadeiras para a gravação ser permitida. Isso significa que apenas o serviço CloudTrail, entregando logs da organização `o-abc123xyz`, com o parâmetro de ACL correto, tem permissão de escrita — nenhum humano, role ou serviço diferente atende a todas as três condições ao mesmo tempo. O statement `DenyDeleteAndPublicAccess` usa `Principal: "*"`, o que significa que o bloqueio se aplica a qualquer entidade, inclusive ao root da conta Log Archive — essa é a proteção mais forte disponível em bucket policies S3.

---

## 2. CloudTrail Lake

O CloudTrail Lake é um data lake gerenciado para consulta de eventos via SQL. Elimina a necessidade de mover logs para Athena manualmente.

### Event Data Stores

| Configuração | Valor Recomendado | Observação |
|---|---|---|
| **Tipo** | Organization Event Data Store | Agrega todas as contas da organização |
| **Retenção** | 2.557 dias (7 anos) | Requisito BACEN para dados financeiros |
| **Tipos de evento** | Management + Data Events S3 e Lambda | Ajustar custo vs necessidade |
| **Encryption** | KMS CMK da conta Log Archive | Obrigatório para dados regulatórios |
| **Terminação** | Não habilitar antes da retenção | Evitar exclusão acidental |

### 5 Queries SQL para Segurança

**Query 1 — Detecção de criação de usuário IAM fora do pipeline aprovado:**

**O que este comando faz:** Esta query SQL interroga o Event Data Store do CloudTrail Lake buscando todos os eventos `CreateUser` gerados pelo serviço IAM nos últimos 7 dias, excluindo apenas os criados pelas roles de provisionamento aprovadas (`ServiceAccountProvisioning` e `OrganizationAdminRole`). O resultado retorna os campos de identidade, IP de origem, região e o nome do novo usuário IAM criado, ordenados cronologicamente do mais recente para o mais antigo.

**Por que isso importa para o Banco Meridian:** A criação de usuários IAM fora do pipeline de provisionamento controlado é um dos primeiros sinais de comprometimento ou de ação maliciosa interna. Em uma organização financeira com múltiplas contas AWS, um atacante que obteve acesso privilegiado pode criar um usuário IAM "backdoor" para manter persistência mesmo após a mudança de credenciais. Qualquer resultado desta query que não seja zero deve ser tratado como incidente e iniciado o processo de resposta imediata — o Banco Meridian deve ter essa query agendada para execução diária automática.

```sql
-- Detecta criação de usuários IAM por qualquer entidade que não seja
-- o pipeline de provisionamento aprovado (role ServiceAccountProvisioning)
SELECT
    eventTime,
    userIdentity.principalId,
    userIdentity.arn,
    userIdentity.type,
    sourceIPAddress,
    awsRegion,
    requestParameters.userName AS new_iam_user
FROM
    $EDS_ID
WHERE
    eventName = 'CreateUser'
    AND eventSource = 'iam.amazonaws.com'
    AND NOT (
        userIdentity.arn LIKE '%ServiceAccountProvisioning%'
        OR userIdentity.arn LIKE '%OrganizationAdminRole%'
    )
    AND eventTime > DATE_ADD('day', -7, NOW())
ORDER BY
    eventTime DESC
```

**Interpretando o resultado:** Cada linha retornada representa um usuário IAM criado fora do processo aprovado. Os campos mais críticos são: `userIdentity.arn` (quem criou — permite identificar se é um administrador legítimo agindo fora do processo ou uma identidade comprometida), `sourceIPAddress` (verificar se o IP pertence ao range corporativo ou a localização desconhecida), e `awsRegion` (criação de usuários em regiões incomuns como `ap-southeast-1` são altamente suspeitas para um banco que opera primariamente em `sa-east-1`). O campo `new_iam_user` revela o nome escolhido — atacantes frequentemente usam nomes que imitam contas de serviço legítimas.

---

**Query 2 — Tentativas de desabilitar o CloudTrail:**

**O que este comando faz:** Esta query busca qualquer evento de modificação do CloudTrail nos últimos 30 dias, incluindo paradas de logging (`StopLogging`), exclusões de trail (`DeleteTrail`), atualizações de configuração (`UpdateTrail`), modificações de seletores de evento (`PutEventSelectors`) e remoção de tags (`RemoveTags`). Os campos `errorCode` e `errorMessage` são deliberadamente incluídos: quando presentes, indicam que a tentativa foi bloqueada por uma SCP (Service Control Policy); quando ausentes, a ação foi bem-sucedida.

**Por que isso importa para o Banco Meridian:** Desabilitar o CloudTrail é tipicamente o segundo passo de um atacante após comprometer uma conta AWS — o primeiro é estabelecer persistência, o segundo é apagar rastros. Com o Organization Trail do Banco Meridian sendo gerenciado a partir da conta Management (111111111111), as contas-membro não conseguem parar o trail organizacional por SCP, mas um comprometimento da conta Management em si poderia. Esta query deve gerar um alerta imediato via CloudWatch ou EventBridge, com notificação para o CISO e o time de segurança — não apenas para o SOC operacional.

```sql
-- Detecta qualquer tentativa de parar, excluir ou modificar trails
-- Esta é uma das primeiras ações de um atacante para cobrir rastros
SELECT
    eventTime,
    userIdentity.arn,
    userIdentity.type,
    sourceIPAddress,
    eventName,
    requestParameters,
    errorCode,         -- Se não nulo, a tentativa foi bloqueada (SCP funcionou)
    errorMessage
FROM
    $EDS_ID
WHERE
    eventName IN (
        'StopLogging',
        'DeleteTrail',
        'UpdateTrail',
        'PutEventSelectors',
        'RemoveTags'   -- Tags podem ser usadas para billing e tracking
    )
    AND eventSource = 'cloudtrail.amazonaws.com'
    AND eventTime > DATE_ADD('day', -30, NOW())
ORDER BY
    eventTime DESC
```

**Interpretando o resultado:** Linhas com `errorCode` preenchido (ex: `AccessDenied`, `ExplicitDeny`) indicam que a barreira preventiva funcionou — a SCP bloqueou a tentativa. Mesmo assim, o evento deve ser investigado: alguém tentou desabilitar o CloudTrail. Linhas com `errorCode` nulo indicam que a ação foi executada com sucesso — situação de incidente crítico que demanda resposta imediata. O campo `requestParameters` mostra qual trail foi alvo: se for o `meridian-org-trail`, a severidade é máxima. O campo `userIdentity.type` revela se o atacante usou credenciais de usuário IAM, de role assumida ou — o pior cenário — da conta root.

---

**Query 3 — Modificação de Security Group para 0.0.0.0/0:**

**O que este comando faz:** Esta query identifica todas as autorizações de regras de entrada (`AuthorizeSecurityGroupIngress`) ou saída (`AuthorizeSecurityGroupEgress`) em Security Groups que abriram acesso para qualquer endereço IPv4 (`0.0.0.0/0`) ou IPv6 (`::/0`) nos últimos 7 dias. A função `json_extract_scalar` extrai o valor do CIDR dentro do JSON aninhado dos parâmetros da requisição, permitindo filtrar apenas as modificações que efetivamente expuseram recursos à internet pública.

**Por que isso importa para o Banco Meridian:** Security Groups abertos para `0.0.0.0/0` em portas sensíveis (22/SSH, 3389/RDP, 1433/SQL Server, 3306/MySQL, 27017/MongoDB) representam exposição direta da infraestrutura bancária à internet. Sistemas financeiros operam em redes privadas com acesso controlado por bastion hosts e VPNs — qualquer abertura de Security Group para a internet pública é, no mínimo, um erro de configuração grave e, no pior caso, parte de um ataque em andamento. Esta query é especialmente relevante para a conta Production (444444444444), onde vivem os sistemas transacionais do Banco Meridian.

```sql
-- Detecta abertura de Security Groups para qualquer IP (0.0.0.0/0 ou ::/0)
-- Comum em erros de configuração e em ataques para preparar acesso
SELECT
    eventTime,
    userIdentity.arn,
    sourceIPAddress,
    awsRegion,
    requestParameters.groupId AS security_group_id,
    requestParameters.ipPermissions AS permissions_added
FROM
    $EDS_ID
WHERE
    eventName IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
    AND eventSource = 'ec2.amazonaws.com'
    AND (
        json_extract_scalar(requestParameters, '$.ipPermissions.items[0].ipRanges.items[0].cidrIp') = '0.0.0.0/0'
        OR json_extract_scalar(requestParameters, '$.ipPermissions.items[0].ipv6Ranges.items[0].cidrIpv6') = '::/0'
    )
    AND eventTime > DATE_ADD('day', -7, NOW())
ORDER BY
    eventTime DESC
```

**Interpretando o resultado:** O campo `security_group_id` identifica qual Security Group foi modificado — cruzar esse ID com o inventário de recursos da AWS (via Config ou inventário manual) revela quais instâncias EC2, bancos de dados RDS ou outros recursos estão agora expostos. O campo `permissions_added` mostra a regra completa, incluindo a porta (`fromPort`/`toPort`) e o protocolo: abertura da porta 22 para `0.0.0.0/0` é diferente de abertura da porta 80 (HTTP), embora ambas devam ser investigadas. O `sourceIPAddress` da modificação indica se foi feita do console web (endereço do console da AWS) ou via CLI (IP do operador) — e se esse IP é reconhecido.

---

**Query 4 — Acesso a dados fora do horário comercial (8h–20h BRT):**

**O que este comando faz:** Esta query identifica acessos a serviços de dados sensíveis (S3, RDS e Secrets Manager) fora do horário comercial do Banco Meridian. Como o CloudTrail registra todos os timestamps em UTC, e o Brasil opera no fuso BRT (UTC-3), o horário comercial de 8h às 20h BRT corresponde a 11h às 23h UTC — a cláusula `WHERE` filtra eventos com hora UTC menor que 11 (antes das 8h BRT) ou maior ou igual a 23 (após as 20h BRT). A query cobre os últimos 30 dias para permitir identificação de padrões recorrentes.

**Por que isso importa para o Banco Meridian:** Acessos a dados financeiros sensíveis fora do expediente são um indicador comportamental de comprometimento ou de ameaça interna. Sistemas automatizados legítimos (jobs noturnos, backups agendados) devem ter suas identidades IAM documentadas e podem ser excluídos da query com um filtro adicional. Acessos humanos a `GetSecretValue` às 3h da manhã ou downloads de objetos S3 às 2h30 da madrugada não têm justificativa operacional em um banco de varejo e devem ser investigados. Para compliance com BACEN 4.893, o registro e a análise desses padrões faz parte da gestão de riscos de acesso.

```sql
-- Detecta acessos fora do horário comercial do Banco Meridian
-- BRT = UTC-3, então horário comercial é UTC 11:00–23:00
-- Ajustar conforme fuso horário da operação
SELECT
    eventTime,
    userIdentity.arn,
    sourceIPAddress,
    eventName,
    resources[1].ARN AS resource_accessed,
    awsRegion
FROM
    $EDS_ID
WHERE
    eventSource IN ('s3.amazonaws.com', 'rds.amazonaws.com', 'secretsmanager.amazonaws.com')
    AND eventName IN ('GetObject', 'GetSecretValue', 'DescribeDBInstances')
    AND (
        HOUR(eventTime) < 11   -- Antes das 8h BRT
        OR HOUR(eventTime) >= 23  -- Após as 20h BRT
    )
    AND eventTime > DATE_ADD('day', -30, NOW())
ORDER BY
    eventTime DESC
```

**Interpretando o resultado:** O campo `resource_accessed` (extraído do array `resources[1].ARN`) identifica exatamente qual objeto S3, segredo ou instância de banco de dados foi acessada — isso é fundamental para avaliar a sensibilidade do acesso. Um acesso a `secretsmanager:GetSecretValue` às 2h da manhã para o segredo `prod/meridian/db-password` é crítico; um acesso ao segredo `dev/meridian/api-key-publica` é menos urgente. O campo `userIdentity.arn` combinado com a análise de recorrência (quantas vezes o mesmo ARN aparece fora do horário) permite distinguir entre um acidente de fuso horário de um funcionário remoto e um padrão sistemático de exfiltração.

---

**Query 5 — Uso de chave de acesso com mais de 90 dias:**

**O que este comando faz:** Esta query faz um self-join no Event Data Store: ela cruza eventos de uso de Access Key (`ct`) com os eventos de criação dessas mesmas chaves (`iam.CreateAccessKey`), calculando a idade em dias de cada chave usada. A função `DATE_DIFF` calcula o intervalo entre a data de criação da chave e o momento atual, e o filtro `> 90` seleciona apenas as chaves que excedem o limite de rotação recomendado. O `GROUP BY` garante que cada combinação única de chave, usuário e operação aparece uma única vez no resultado.

**Por que isso importa para o Banco Meridian:** Access Keys com mais de 90 dias representam um risco crescente no tempo: quanto mais antiga a chave, maior a probabilidade de que ela tenha sido exposta acidentalmente em código-fonte, logs de sistema, repositórios git ou canais de comunicação. Instituições financeiras reguladas pelo BACEN devem ter política formal de rotação de credenciais. Esta query é a ferramenta de auditoria que confirma se a política está sendo cumprida — e identifica as contas específicas que precisam de remediação imediata, que pode ser automatizada via Lambda acionado por EventBridge.

```sql
-- Detecta API calls feitas com Access Keys criadas há mais de 90 dias
-- Access Keys antigas são risco de segurança e devem ser rotacionadas
SELECT
    ct.eventTime,
    ct.userIdentity.arn,
    ct.userIdentity.accessKeyId,
    ct.sourceIPAddress,
    ct.eventName,
    ct.eventSource,
    iam.createDate AS key_creation_date,
    DATE_DIFF('day', CAST(iam.createDate AS TIMESTAMP), NOW()) AS key_age_days
FROM
    $EDS_ID ct
    JOIN $EDS_ID iam ON ct.userIdentity.accessKeyId = iam.requestParameters.accessKeyId
WHERE
    ct.userIdentity.type = 'IAMUser'
    AND iam.eventName = 'CreateAccessKey'
    AND DATE_DIFF('day', CAST(iam.createDate AS TIMESTAMP), NOW()) > 90
    AND ct.eventTime > DATE_ADD('day', -7, NOW())
GROUP BY
    ct.userIdentity.accessKeyId,
    ct.userIdentity.arn,
    ct.sourceIPAddress,
    ct.eventName,
    ct.eventSource,
    iam.createDate,
    ct.eventTime
ORDER BY
    key_age_days DESC
```

**Interpretando o resultado:** O campo `key_age_days` no topo do resultado (ordenação `DESC`) mostra as chaves mais antigas primeiro — priorize as que têm mais de 180 dias para remediação imediata. O campo `ct.eventSource` revela quais serviços AWS a chave está sendo usada para acessar: uma chave antiga sendo usada para acessar `s3.amazonaws.com` com `GetObject` em dados de produção é crítica; uma chave usada apenas para `sts.amazonaws.com` é menor risco. O `ct.sourceIPAddress` pode revelar que a chave está sendo usada de localizações geográficas incomuns, o que combinado com a idade elevada da chave pode indicar comprometimento silencioso em andamento.

---

## 3. Amazon CloudWatch para Segurança

### Metric Filters Críticos de Segurança

CloudWatch Metric Filters analisam logs do CloudTrail entregues no CloudWatch Logs e criam métricas customizadas para alarmes.

| Metric Filter | Padrão de Filtro | Limiar do Alarme | Severidade |
|---|---|---|---|
| **RootAccountUsage** | `{$.userIdentity.type = "Root"}` | >= 1 em 5 min | CRÍTICO |
| **UnauthorizedAPICalls** | `{($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied")}` | >= 10 em 5 min | ALTO |
| **ConsoleLoginWithoutMFA** | `{($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes")}` | >= 1 em 5 min | ALTO |
| **IAMPolicyChange** | `{($.eventName = DeleteGroupPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachRolePolicy)}` | >= 1 em 5 min | MÉDIO |
| **S3BucketPublicAccess** | `{($.eventName = PutBucketAcl) && ($.requestParameters.accessControlList = "*public*")}` | >= 1 em 5 min | CRÍTICO |
| **CloudTrailChange** | `{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}` | >= 1 em 5 min | CRÍTICO |
| **SecurityGroupChange** | `{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress)}` | >= 5 em 5 min | MÉDIO |
| **VPCChange** | `{($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute)}` | >= 1 em 5 min | MÉDIO |

**Exemplo de criação via CLI:**

**O que este comando faz:** Os dois comandos a seguir trabalham em par. O primeiro (`put-metric-filter`) cria um filtro que analisa cada evento JSON entregue ao log group `/meridian/cloudtrail/org-trail` e, toda vez que encontra o padrão `$.userIdentity.type = "Root"`, incrementa em 1 a métrica customizada `RootAccountUsageCount` no namespace `MeridianSecurity`. O segundo (`put-metric-alarm`) cria o alarme CloudWatch que monitora essa métrica com período de 5 minutos e limiar de 1 — ou seja, uma única ocorrência de uso de root em qualquer janela de 5 minutos dispara o alarme e envia notificação ao tópico SNS do time de segurança.

**Por que isso importa para o Banco Meridian:** O uso da conta root da AWS não tem justificativa operacional rotineira em nenhuma conta do Banco Meridian — a conta root é reservada para operações de break-glass como recuperação de acesso e configurações que a API não permite. Qualquer atividade de root deve gerar alerta imediato e ser investigada. O namespace dedicado `MeridianSecurity` organiza todas as métricas de segurança separadas das métricas operacionais, facilitando a criação de dashboards de postura de segurança e a integração com o SIEM do banco. O tópico SNS `meridian-security-alerts-critico` deve estar subscrito pelo celular e e-mail do time de segurança 24x7.

```bash
# Criar metric filter para uso da conta Root
aws logs put-metric-filter \
  --log-group-name "/meridian/cloudtrail/org-trail" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{$.userIdentity.type = "Root"}' \
  --metric-transformations \
    metricName=RootAccountUsageCount,metricNamespace=MeridianSecurity,metricValue=1,defaultValue=0

# Criar alarme CloudWatch para o metric filter
aws cloudwatch put-metric-alarm \
  --alarm-name "CRITICO-RootAccountUsage" \
  --alarm-description "Uso da conta root detectado - investigar imediatamente" \
  --metric-name RootAccountUsageCount \
  --namespace MeridianSecurity \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:sa-east-1:111111111111:meridian-security-alerts-critico" \
  --treat-missing-data notBreaching
```

**Interpretando o resultado:** O parâmetro `--treat-missing-data notBreaching` é deliberado: significa que quando não há dados (sem eventos root no período), o alarme permanece em estado `OK` — ao contrário de `breaching`, que deixaria o alarme em estado `ALARM` quando não há dados, gerando falsos positivos. O `--period 300` define uma janela deslizante de 300 segundos (5 minutos) — o alarme avalia a soma dos eventos nessa janela a cada período. O `--evaluation-periods 1` significa que basta um único período com valor >= 1 para disparar o alarme, garantindo detecção imediata sem aguardar confirmação em múltiplos períodos. O `--alarm-actions` aponta para o tópico SNS correto: usar o ARN da conta Management (111111111111) — não da conta onde o root foi usado — garante que o alerta persista mesmo que a conta comprometida tente silenciar o alarme.

---

## 4. VPC Flow Logs

VPC Flow Logs registram informações sobre o tráfego IP de e para interfaces de rede em sua VPC.

### Formato Completo dos Flow Logs

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

| Campo | Descrição | Exemplo |
|---|---|---|
| `version` | Versão do formato | `2` |
| `account-id` | ID da conta AWS | `444444444444` |
| `interface-id` | ID da ENI | `eni-0a1b2c3d` |
| `srcaddr` | Endereço IP de origem | `10.0.1.15` |
| `dstaddr` | Endereço IP de destino | `52.95.120.10` |
| `srcport` | Porta de origem | `49152` |
| `dstport` | Porta de destino | `443` |
| `protocol` | Número do protocolo (IANA) | `6` (TCP), `17` (UDP), `1` (ICMP) |
| `packets` | Pacotes transferidos | `42` |
| `bytes` | Bytes transferidos | `4312` |
| `start` | Timestamp início (Unix) | `1712750400` |
| `end` | Timestamp fim (Unix) | `1712750460` |
| `action` | Decisão do Security Group/NACL | `ACCEPT` ou `REJECT` |
| `log-status` | Status do log | `OK`, `NODATA`, `SKIPDATA` |

### Exemplos de Registros Suspeitos

**O que este bloco representa:** Os três grupos de registros a seguir são exemplos reais de padrões de tráfego malicioso capturados por VPC Flow Logs. O primeiro grupo mostra a assinatura de um port scan automatizado; o segundo, um episódio de exfiltração de dados em larga escala; o terceiro, um padrão consistente com DNS tunneling. Esses registros não mostram o conteúdo do tráfego (Flow Logs não capturam payload), mas o volume, frequência, portas e endereços são suficientes para identificar a atividade suspeita.

**Por que isso importa para o Banco Meridian:** O CloudTrail registra as ações de API mas não captura o tráfego de rede. Um atacante que obteve acesso a uma instância EC2 por meio de uma vulnerabilidade de aplicação (sem usar a API AWS) não geraria nenhum evento CloudTrail — mas geraria registros de VPC Flow Log. Para o Banco Meridian, onde sistemas de internet banking, processamento de pagamentos e APIs de Open Finance rodam em instâncias EC2, os Flow Logs são o único mecanismo de detecção de movimentação lateral entre sub-redes, exfiltração de dados via rede e reconhecimento de infraestrutura por atacantes que já estão dentro da VPC.

```
# 1. Port scan — muitas REJECT em portas diferentes do mesmo IP
2 444444444444 eni-0a1b2c3d 189.42.15.77 10.0.1.100 54321 22    6 1 44  1712750400 1712750401 REJECT OK
2 444444444444 eni-0a1b2c3d 189.42.15.77 10.0.1.100 54321 23    6 1 44  1712750401 1712750402 REJECT OK
2 444444444444 eni-0a1b2c3d 189.42.15.77 10.0.1.100 54321 3389  6 1 44  1712750402 1712750403 REJECT OK
2 444444444444 eni-0a1b2c3d 189.42.15.77 10.0.1.100 54321 8080  6 1 44  1712750403 1712750404 REJECT OK

# 2. Exfiltração — grande volume de bytes saindo para IP externo
2 444444444444 eni-0b2c3d4e 10.0.1.100 203.0.113.50 59200 443   6 8754 15430000 1712750500 1712755000 ACCEPT OK

# 3. Tráfego DNS suspeito (DNS tunneling) — muitas queries UDP 53
2 444444444444 eni-0c3d4e5f 10.0.1.200 8.8.8.8      50123 53   17 542  34680  1712750600 1712750660 ACCEPT OK
```

**Interpretando o resultado:** No exemplo 1 (port scan), o mesmo IP externo `189.42.15.77` tenta portas diferentes (22, 23, 3389, 8080) em sequência com intervalos de 1 segundo e tamanho fixo de 44 bytes — esse padrão é assinatura de scanner automatizado como nmap ou masscan. Todos os `REJECT` indicam que o Security Group está bloqueando, mas o reconhecimento ainda está ocorrendo. No exemplo 2 (exfiltração), `15.430.000 bytes` (aproximadamente 15 MB) saíram em 75 minutos (`1712755000 - 1712750500 = 4500 segundos`) de uma instância interna para o IP `203.0.113.50` — verificar esse IP em feeds de Threat Intelligence e bloquear no WAF e Security Group imediatamente. No exemplo 3 (DNS tunneling), `542 pacotes` com `34.680 bytes` para a porta 53 UDP em apenas 60 segundos é volume anormalmente alto para consultas DNS legítimas — DNS queries normais têm dezenas de bytes, não centenas.

---

## 5. Route 53 Resolver DNS Logs

Os DNS Logs registram todas as consultas DNS feitas por recursos na VPC.

### Detecção de DNS Tunneling e DGA

**O que este código faz:** Este script Python implementa o cálculo de Entropia de Shannon aplicado a nomes de domínio DNS para detecção de dois padrões maliciosos: DNS Tunneling (dados codificados em subdomínios como base32 ou hex) e DGA — Domain Generation Algorithms (malware que gera domínios aleatórios programaticamente para comunicação com servidores de C2). A entropia de Shannon mede a aleatoriedade de uma string: strings aleatórias têm alta entropia; palavras significativas em português ou inglês têm baixa entropia. O limiar de 3.5 foi calibrado empiricamente para distinguir domínios legítimos de DGA com baixa taxa de falsos positivos.

**Por que isso importa para o Banco Meridian:** Malwares como Emotet, TrickBot e variantes de RATs usados em ataques contra instituições financeiras frequentemente usam DGA para geração de domínios de C2 resistentes a blacklists — o domínio muda a cada ciclo, impossibilitando bloqueio simples por lista. DNS Tunneling é usado para exfiltrar dados em redes que bloqueiam HTTP/HTTPS mas permitem DNS (comum em ambientes corporativos com proxy). Ambos os padrões são detectáveis na camada de DNS antes de qualquer conexão TCP/IP ser estabelecida. A análise de entropia pode ser integrada como função Lambda acionada pelo CloudWatch Logs, processando os Resolver DNS Logs do Banco Meridian em tempo real.

```python
# Análise de DNS Logs via CloudWatch Insights
# Query para detectar domínios com alta entropia (possível DGA)

import math
import re

def calcular_entropia(dominio):
    """Calcula a entropia de Shannon de um domínio para detecção de DGA."""
    if not dominio:
        return 0
    frequencias = {}
    for char in dominio.lower():
        frequencias[char] = frequencias.get(char, 0) + 1
    entropia = 0
    total = len(dominio)
    for freq in frequencias.values():
        prob = freq / total
        if prob > 0:
            entropia -= prob * math.log2(prob)
    return entropia

# Domínios com entropia > 3.5 são suspeitos (DGA típico tem 3.8–4.5)
# Domínios legítimos geralmente têm entropia 2.5–3.2
dominios_teste = [
    "google.com",            # Entropia: ~2.8
    "x7z9k2m4p1.evil.com",  # Entropia: ~3.9 (possível DGA)
    "banco-meridian.com.br", # Entropia: ~3.1
    "a1b2c3d4e5f6.ddns.net" # Entropia: ~3.8 (suspeito)
]

for dominio in dominios_teste:
    e = calcular_entropia(dominio)
    status = "SUSPEITO" if e > 3.5 else "OK"
    print(f"{status:10} | Entropia: {e:.2f} | {dominio}")
```

**Interpretando o resultado:** A saída do script classifica cada domínio como `OK` ou `SUSPEITO`. O domínio `google.com` com entropia ~2.8 é legítimo: as letras são distribuídas de forma previsível e não aleatória. O domínio `x7z9k2m4p1.evil.com` com entropia ~3.9 é suspeito: a sequência de caracteres no subdomínio parece gerada por algoritmo, não escolhida por humano. O domínio `banco-meridian.com.br` com entropia ~3.1 é legítimo: o hífen e os caracteres comuns em palavras portuguesas mantêm a entropia moderada. Em produção, este código seria integrado ao pipeline de análise de DNS Logs do CloudWatch, gerando alertas automáticos para qualquer domínio que ultrapassar o limiar — e enriquecido com consulta a feeds de Threat Intelligence como AWS Partner Threat Intel ou Recorded Future.

---

## 6. Arquitetura de Logging Centralizado Multi-Conta

### Diagrama da Arquitetura

```
Banco Meridian — Arquitetura de Logging Centralizado
═══════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────────┐
  │  CONTAS FONTE (111, 222, 444, 555...)                          │
  │                                                                 │
  │  CloudTrail  →  KMS encrypt  →  cross-account delivery         │
  │  VPC Flow Logs  →  CloudWatch Logs  →  cross-account delivery  │
  │  Config Delivery  →  cross-account delivery                    │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  CONTA LOG ARCHIVE (333333333333)                              │
  │                                                                 │
  │  ┌────────────────────────────────────────────────────────┐   │
  │  │  S3: meridian-logs-333333333333                        │   │
  │  │  ├── AWSLogs/111111111111/CloudTrail/...               │   │
  │  │  ├── AWSLogs/222222222222/CloudTrail/...               │   │
  │  │  ├── AWSLogs/444444444444/CloudTrail/...               │   │
  │  │  └── AWSLogs/444444444444/VPCFlowLogs/...              │   │
  │  │                                                         │   │
  │  │  Configurações de Segurança do Bucket:                 │   │
  │  │  ✓ SSE-KMS (CMK dedicado)                              │   │
  │  │  ✓ Object Lock (WORM Compliance, 7 anos)               │   │
  │  │  ✓ MFA Delete habilitado                               │   │
  │  │  ✓ Block Public Access                                  │   │
  │  │  ✓ Versioning habilitado                               │   │
  │  │  ✓ Lifecycle: Glacier após 1 ano                       │   │
  │  └────────────────────────────────────────────────────────┘   │
  │                                                                 │
  │  CloudTrail Lake  →  Event Data Store (7 anos)                │
  │  CloudWatch Logs  →  Retenção 1 ano                           │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  CONTA AUDIT / SECURITY TOOLING (222222222222)                │
  │                                                                 │
  │  GuardDuty (Admin Delegado)  →  centraliza achados            │
  │  Security Hub (Admin Delegado)  →  painel unificado           │
  │  Config (Admin Delegado)  →  conformidade multi-conta         │
  │  Amazon Detective  →  investigações                            │
  │                                                                 │
  │  EventBridge  →  regras de detecção  →  Lambda + SNS          │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 7. Amazon EventBridge para Segurança

### Eventos de Segurança Relevantes

| Fonte | Detalhe do Evento | Exemplo de Trigger |
|---|---|---|
| `aws.guardduty` | GuardDuty Finding (severity >= 7) | Instância comprometida, cryptomining |
| `aws.securityhub` | Security Hub Finding (CRITICAL/HIGH) | Achado de controle CIS failed |
| `aws.config` | Config Rules Compliance Change | Regra s3-bucket-public-read passou a NON_COMPLIANT |
| `aws.iam` | IAM Policy Change | Política AdministratorAccess anexada a usuário |
| `aws.cloudtrail` | CloudTrail API Activity | Trail foi parado (StopLogging) |
| `aws.s3` | S3 Bucket Policy Change | Bucket policy modificada para acesso público |
| `aws.signin` | Console Login (falha ou sem MFA) | Login de root, login sem MFA |

**Exemplo de regra EventBridge para GuardDuty High:**

**O que este bloco representa:** Este JSON define um event pattern do Amazon EventBridge — a condição de filtragem que determina quais eventos do barramento default disparam a regra. O pattern seleciona apenas eventos cuja fonte é o GuardDuty (`aws.guardduty`), do tipo `GuardDuty Finding`, e cuja severidade numérica é maior ou igual a 7 (escala 1–10, onde 7–8.9 é High e 9–10 é Critical). Eventos que atendem a este pattern são roteados para os targets configurados na regra (Lambda, SNS, Step Functions, etc.).

**Por que isso importa para o Banco Meridian:** O EventBridge é o roteador de eventos de segurança da arquitetura do Banco Meridian. Em vez de polling manual ou dashboards que precisam ser monitorados, o EventBridge garante que achados críticos do GuardDuty (instância EC2 comprometida, credential exfiltration, cryptomining) disparem automação imediata — isolamento de instância via Lambda, criação de ticket no sistema de ITSM, notificação do analista de plantão. O limiar de severidade 7 é calibrado para capturar achados High e Critical sem gerar ruído excessivo com achados Low e Medium (1–6), que podem ser processados em batches periódicos. Para o Banco Meridian, achados GuardDuty severity >= 7 devem disparar o plano de resposta a incidentes (IRP) definido na política de segurança.

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [
      {"numeric": [">=", 7]}
    ]
  }
}
```

**Interpretando o resultado:** O campo `source` restringe o evento ao GuardDuty — sem isso, qualquer serviço que publicasse um evento com `detail-type: "GuardDuty Finding"` (improvável, mas possível em ambientes com eventos customizados) também acionaria a regra. O campo `detail-type` é o tipo semântico do evento, definido pela AWS por serviço. O operador `{"numeric": [">=", 7]}` usa a sintaxe de correspondência numérica do EventBridge — diferente do pattern textual, ele compara o campo `severity` como número, não como string, evitando problemas de ordenação lexicográfica (onde "9" < "10" em string, mas 9 < 10 em número). Em produção, este event pattern seria combinado com um target que invoca a função Lambda `meridian-incident-response-handler` com o payload completo do achado GuardDuty.

---

## 8. Tabela Completa de Serviços de Logging AWS

| Serviço | O que Registra | Campos-Chave | Casos de Uso de Segurança | Destino |
|---|---|---|---|---|
| **CloudTrail** | API calls (quem, o quê, quando, de onde) | eventName, userIdentity, sourceIPAddress, eventTime | Auditoria, IR, detecção de mudanças | S3, CloudWatch Logs, CloudTrail Lake |
| **VPC Flow Logs** | Tráfego IP de ENIs | srcaddr, dstaddr, srcport, dstport, action, bytes | Detecção de exfiltração, port scan, C2 | S3, CloudWatch Logs |
| **AWS WAF Logs** | Requisições HTTP avaliadas pelo WAF | clientIP, uri, country, ruleGroupList, action | Análise de ataques web, tuning de regras | S3, CloudWatch Logs, Kinesis Firehose |
| **ALB Access Logs** | Requisições ao Application Load Balancer | client_ip, request, elb_status_code, target_status_code | Análise de tráfego web, DDoS | S3 |
| **CloudFront Logs** | Requisições CDN | c-ip, x-edge-location, cs-uri-stem, sc-status | Análise de acesso global | S3 |
| **Route 53 Resolver DNS Logs** | Consultas DNS de recursos na VPC | queryName, queryType, responseCode, srcAddr | DGA, DNS tunneling, exfiltração DNS | CloudWatch Logs, S3 |
| **AWS Config** | Mudanças de configuração de recursos | resourceType, configurationItemStatus, relationships | Conformidade, drift detection | S3 |
| **S3 Access Logs** | Acessos a buckets S3 | bucketOwner, bucket, remoteIP, operation, key | Auditoria de dados, acesso não autorizado | S3 (bucket diferente) |
| **RDS Logs** | Queries, erros, conexões | timestamp, database, user, query | SQL injection, acesso anômalo a BD | CloudWatch Logs, S3 |
| **GuardDuty** | Achados de ameaças (processa CloudTrail, VPC FL, DNS) | type, severity, description, accountId | Detecção de comprometimento, threat intel | EventBridge, Security Hub |
| **Security Hub** | Achados de múltiplos serviços (GuardDuty, Inspector, etc.) | Title, Severity, ComplianceStatus | Painel unificado de postura | EventBridge, S3 |

---

## 9. Atividades de Fixação

**1.** Um atacante comprometeu uma instância EC2 na conta Production do Banco Meridian e está exfiltrando dados via HTTPS. Qual serviço de logging capturaria esse tráfego e qual campo específico indicaria o volume de dados exfiltrados?

a) CloudTrail — campo `requestParameters`
b) VPC Flow Logs — campo `bytes`
c) Route 53 Resolver DNS Logs — campo `queryName`
d) CloudWatch Logs — campo `logEvent`

**Gabarito: B** — VPC Flow Logs registra o tráfego de rede. O campo `bytes` indica o volume transferido. Campos adicionais como `dstaddr` (IP externo), `action: ACCEPT` e `dstport: 443` confirmam a exfiltração HTTPS. CloudTrail não captura o payload ou volume de transferência de dados de rede.

---

**2.** Você precisa garantir que os logs do CloudTrail do Banco Meridian sejam imutáveis por 7 anos para conformidade com o BACEN. Quais dois recursos do S3 você deve configurar no bucket de logs?

a) Versioning e MFA Delete apenas
b) S3 Object Lock (modo Compliance) e S3 Versioning
c) S3 Replication e S3 Lifecycle
d) SSE-KMS e Bucket Policy apenas

**Gabarito: B** — Object Lock em modo Compliance impede a exclusão ou modificação de objetos durante o período de retenção, mesmo por administradores ou root. Versioning é pré-requisito para Object Lock. MFA Delete é uma proteção adicional recomendada mas não substitui o Object Lock para imutabilidade.

---

**3.** O CloudTrail Lake do Banco Meridian retornou um evento com `"errorCode": "AccessDenied"` e `"errorMessage": "Explicit deny in a service control policy"`. O que isso indica?

a) O usuário não tem política IAM para a ação
b) A SCP bloqueou a ação — o CloudTrail registra TODAS as tentativas, incluindo negadas
c) O recurso foi excluído antes da ação
d) O CloudTrail teve um erro interno

**Gabarito: B** — CloudTrail registra todas as chamadas de API, incluindo as negadas. O errorCode AccessDenied com a mensagem específica de SCP indica que a barreira preventiva funcionou corretamente. Isso é valioso para IR: confirma que o atacante tentou a ação mas foi bloqueado.

---

**4.** Você quer ser notificado imediatamente quando qualquer conta da organização do Banco Meridian tentar desabilitar o CloudTrail. Qual é a arquitetura correta?

a) GuardDuty → SNS diretamente
b) CloudTrail → S3 → Lambda → SNS
c) CloudTrail → CloudWatch Logs → Metric Filter → Alarme → SNS
d) Config Rule → SNS diretamente

**Gabarito: C** — A cadeia correta é: CloudTrail envia eventos para CloudWatch Logs → Metric Filter detecta `StopLogging`/`DeleteTrail` → Alarme CloudWatch é acionado → Notificação via SNS. Alternativamente, EventBridge com regra `cloudtrail.amazonaws.com` + target SNS também é válido.

---

**5.** O que é CloudTrail Log File Validation e por que ela é crítica para investigações forenses?

a) Garante que os logs sejam criptografados com KMS
b) Verifica a integridade dos arquivos de log usando hash SHA-256 para detectar adulteração
c) Valida o formato JSON dos eventos CloudTrail
d) Confirma que o bucket S3 está configurado corretamente

**Gabarito: B** — Log File Validation gera um arquivo de digest a cada hora com hashes SHA-256 dos arquivos de log, assinado com RSA. Permite provar que os logs não foram modificados desde que foram criados pela AWS. Crítico para forense: evidências adulteradas são inadmissíveis e podem invalidar investigações.

---

## 10. Roteiro de Gravação

### Aula 2.1 — CloudTrail e CloudTrail Lake (50 min)

**Abertura (2 min):**
"Boa-noite! Sou [nome]. No módulo anterior construímos a fundação de identidade e governança do Banco Meridian. Hoje começamos a construir os olhos do nosso SOC em AWS: o sistema de logging. Sem visibilidade, não há segurança. CloudTrail é o ponto de partida."

**Bloco 1 — Por que CloudTrail é a base de tudo (5 min):**
"Uma analogia: CloudTrail é o CFTV do seu ambiente AWS. Cada chamada de API — seja via console, CLI, SDK — gera um registro. Quem criou esse bucket? Quem modificou essa Security Group? Quem assumiu essa role? Tudo está no CloudTrail.

O que o CloudTrail registra: Management Events por padrão. Data Events você precisa habilitar explicitamente — e tem custo adicional. Insights Events detectam picos anômalos de API calls.

Para o Banco Meridian, habilitamos tudo: Management, Data Events em S3 e Lambda, e Insights. O custo é justificado pelo nível de visibilidade e pela exigência regulatória."

**Bloco 2 — Anatomia de um Evento CloudTrail (8 min):**
"Vamos dissecar um evento CloudTrail real. [Mostrar JSON anotado no slide]

Os campos que mais importam para segurança:
- `userIdentity.type` — quem fez? Root? IAMUser? AssumedRole?
- `eventName` — o que foi feito? DeleteBucket? CreateUser? StopLogging?
- `sourceIPAddress` — de onde? IP interno, IP do escritório, IP suspeito?
- `errorCode` — foi bem-sucedido? `AccessDenied` significa que foi bloqueado.
- `readOnly: false` — ação de escrita, sempre mais crítica que leitura.

[Demo ao vivo] Vou navegar no Event History do CloudTrail no console e filtrar por `eventName = DeleteSecurityGroup`. Vejam como em segundos identificamos quem excluiu o grupo de segurança, de qual IP, e a que horas."

**Bloco 3 — Organization Trail (10 min):**
"Trail padrão cobre apenas uma conta. Organization Trail cobre todas as contas da organização. Para o Banco Meridian, precisamos de visibilidade unificada — Management Account, Audit, Log Archive, Production.

[Demo ao vivo] Criar o Organization Trail no console Organizations:
1. Conta Management — CloudTrail — Create trail
2. Apply to all accounts in my organization ✓
3. S3 bucket: meridian-logs-333333333333 (Log Archive account)
4. KMS key: CMK da conta Log Archive
5. Log file validation: Enable ✓
6. SNS notification: opcional mas recomendado

Bucket Policy é obrigatória para Organization Trail — a AWS precisa de permissão para gravar no bucket da outra conta. [Mostrar bucket policy]

Erro comum: esquecer o `aws:SourceOrgID` na bucket policy. Sem ele, qualquer conta AWS poderia escrever no seu bucket de logs."

**Bloco 4 — CloudTrail Lake (15 min):**
"CloudTrail Lake mudou o jogo para investigações de segurança. Antes, para fazer queries em logs históricos, você precisava: CloudTrail → S3 → Glue Crawler → Athena → resultados em minutos a horas. Com o Lake, é SQL direto em segundos.

[Criar Event Data Store ao vivo]
1. CloudTrail Lake — Event data stores — Create
2. Organization event data store ✓
3. Retenção: 2557 dias (7 anos para BACEN)
4. KMS: CMK do Log Archive

Agora vou rodar as 5 queries que preparei para vocês. [Executar Query 1 — IAM user criado fora do pipeline]

[Mostrar resultado] Vejam: em 3 segundos, tenho todos os usuários IAM criados na última semana que não foram criados pelo ServiceAccountProvisioning. Se há algum resultado aqui, é um red flag imediato.

[Executar Query 2 — Tentativas de desabilitar CloudTrail]
Esse é especialmente importante. Um atacante que acabou de comprometer uma conta, primeiro tenta apagar as evidências. Se o errorCode está presente, nossa SCP bloqueou a tentativa. Se não está, ele foi bem-sucedido — e precisamos agir agora."

**Bloco 5 — Consolidação (10 min):**
"[Recapitular os 3 pontos principais da aula]
1. Organization Trail → visibilidade unificada de todas as contas
2. Log File Validation → integridade forense
3. CloudTrail Lake → investigações SQL em segundos

Na próxima aula, CloudWatch Metric Filters, VPC Flow Logs e a arquitetura completa de logging do Banco Meridian. Até lá!"

---

### Aula 2.2 — CloudWatch, VPC Flow Logs e Arquitetura Centralizada (50 min)

**Abertura (2 min):**
"Bem-vindos à Aula 2.2! Hoje vamos construir a segunda camada de visibilidade: CloudWatch para alertas em tempo real sobre eventos de segurança, VPC Flow Logs para análise de tráfego de rede, e depois vemos a arquitetura completa que junta tudo."

**Bloco 1 — CloudWatch para Segurança (12 min):**
"CloudWatch é frequentemente subutilizado para segurança. A maioria das equipes usa para métricas de infraestrutura — CPU, memória. Mas o Metric Filter transforma o CloudWatch num sistema de alertas de segurança poderoso.

O fluxo: CloudTrail → CloudWatch Logs (habilitar no trail) → Metric Filter detecta padrão → Alarme dispara → SNS notifica → Time de segurança responde.

[Demo] Vou criar o Metric Filter para uso de root account. [Criar no console]

Filter pattern: `{$.userIdentity.type = "Root"}`

O que esse padrão faz: varre cada evento JSON no log group e, se o campo userIdentity.type for exatamente 'Root', conta como 1. Qualquer valor acima de 0 no período de 5 minutos dispara o alarme.

[Criar alarme com threshold 1 e destino SNS do time de segurança]

Vou criar agora o de Console Login sem MFA — esse é crítico. Filter pattern: `{($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes")}`

Esse filtro captura logins no console web que não usaram MFA. Para o Banco Meridian, toda autenticação humana DEVE usar MFA. Um login sem MFA é imediatamente suspeito."

**Bloco 2 — VPC Flow Logs (15 min):**
"VPC Flow Logs é nossa visibilidade de rede. O CloudTrail mostra o 'quê' da API, o Flow Log mostra o 'como' da rede.

[Habilitar VPC Flow Logs ao vivo]
1. VPC → selecionar VPC da Production → Flow Logs → Create
2. Filter: All (captura ACCEPT e REJECT)
3. Destination: CloudWatch Logs e S3 (dois destinos)
4. Format: Custom — adicionar campos ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${bytes} ${action}

[Mostrar exemplos de log suspeito]

Caso 1 — Port scan: vejam sequência de REJECT para portas 22, 23, 3389, 8080 do mesmo IP externo em segundos. Isso é um scanner automático.

Caso 2 — Exfiltração: mesma instância enviando 15 GB para um IP externo em 5 minutos via porta 443. HTTPS legítimo não tem esse volume repentino.

Caso 3 — Movimento lateral: instância do subnet público se comunicando diretamente com instâncias do subnet de banco de dados — isso não deveria acontecer pelo design da VPC.

CloudWatch Logs Insights para analisar Flow Logs:
```
fields @timestamp, srcAddr, dstAddr, bytes, action
| filter dstAddr not like /^10\./ and dstAddr not like /^172\./ and dstAddr not like /^192\.168\./
| filter action = "ACCEPT"
| stats sum(bytes) as totalBytes by dstAddr
| sort totalBytes desc
| limit 20
```
Esse query me mostra os 20 IPs externos que mais receberam dados da minha VPC. Se aparecer um IP desconhecido com GBs de dados, é red flag."

**Bloco 3 — Route 53 Resolver DNS Logs (8 min):**
"DNS é frequentemente ignorado no monitoramento de segurança. Mas DNS tunneling e DGA (Domain Generation Algorithms) são técnicas reais usadas por malware para comunicação com C2.

[Configurar Resolver Query Logging ao vivo]
1. Route 53 → Resolver → Query logging → Create
2. CloudWatch Logs Destination
3. VPCs: selecionar todas as VPCs de prod

O que procurar:
- Alto volume de queries para um único domínio (beaconing)
- Subdomínios muito longos (DNS tunneling codifica dados em subdomínios)
- Domínios com alta entropia aleatória (DGA)
- Queries para domínios de Threat Intelligence (feeds de IoC)"

**Bloco 4 — Arquitetura Centralizada (13 min):**
"Agora conectamos todos os pontos. [Mostrar diagrama ASCII da arquitetura]

Os logs de todas as contas convergem para a conta Log Archive (333). Por quê uma conta separada? Separação de funções: os administradores de produção não devem ter acesso para modificar ou excluir seus próprios logs.

O S3 do Log Archive tem Object Lock em modo Compliance — nem o root pode excluir objetos antes do prazo de retenção. Isso é a garantia de integridade forense que o BACEN exige.

A conta Audit centraliza as ferramentas de análise: GuardDuty Administrator, Security Hub Administrator, Config Aggregator. O time de segurança opera a partir da conta Audit, nunca diretamente nas contas de produção.

EventBridge é o roteador: eventos gerados em qualquer conta são roteados para targets de resposta. GuardDuty finding HIGH → Lambda de isolamento. Config rule violation → Lambda de remediação.

Esse é o design de operações de segurança que vamos construir ao longo de todo o curso."

---

## 11. Avaliação do Módulo

**Questão 1 (2 pontos):** Um analista de segurança precisa determinar qual usuário IAM criou um novo Security Group com regra `0.0.0.0/0:22` (SSH aberto para o mundo) na conta Production do Banco Meridian na última semana. Quais serviços e campos específicos ele deve consultar?

**Gabarito:** CloudTrail Event History ou CloudTrail Lake. Filtrar por `eventName = AuthorizeSecurityGroupIngress`, `eventSource = ec2.amazonaws.com`, período da última semana. Os campos relevantes são: `userIdentity.arn` (quem fez), `eventTime` (quando), `sourceIPAddress` (de onde), `requestParameters.ipPermissions` (quais regras foram adicionadas, incluindo o CIDR 0.0.0.0/0).

---

**Questão 2 (2 pontos):** Por que é insuficiente apenas habilitar CloudTrail Management Events para monitorar o acesso a dados sensíveis armazenados no S3 do Banco Meridian?

**Gabarito:** Management Events registram operações de controle (criar bucket, modificar política, deletar bucket) mas NÃO registram operações de dados como `GetObject`, `PutObject`, `DeleteObject`. Para monitorar quem leu ou modificou arquivos específicos no S3, é necessário habilitar Data Events no CloudTrail. Sem Data Events, um atacante pode exfiltrar GBs de dados do S3 sem que o CloudTrail registre nenhuma API call de acesso aos objetos.

---

**Questão 3 (2 pontos):** Descreva como você configuraria um alerta em tempo real para detectar uso da conta root em qualquer conta da organização do Banco Meridian.

**Gabarito:** 1. Organization Trail configurado para enviar logs ao CloudWatch Logs. 2. Criar Metric Filter no log group com pattern `{$.userIdentity.type = "Root"}`. 3. Criar CloudWatch Alarm com threshold ≥ 1, período 5 minutos. 4. Ação de alarme: SNS topic com subscrição do time de segurança (email + SMS). Alternativamente: EventBridge rule com pattern `{source: [aws.signin], detail: {userIdentity.type: [Root]}}` com target SNS.

---

**Questão 4 (2 pontos):** Analise o seguinte registro de VPC Flow Log e descreva o que ele indica do ponto de vista de segurança:
`2 444444444444 eni-0a1b2c3d 10.0.1.55 198.51.100.22 34567 4444 6 9854 189430000 1712750000 1712753600 ACCEPT OK`

**Gabarito:** Uma instância interna (10.0.1.55) transmitiu aproximadamente 189 MB (189.430.000 bytes) para o IP externo 198.51.100.22 na porta de destino 4444 (TCP, protocolo 6), durante 1 hora. A porta 4444 é comumente associada a ferramentas de hacking como Metasploit. O volume de dados e a porta não padrão são altamente suspeitos, indicando possível C2 (Command and Control) ou exfiltração de dados. Ação imediata: isolar a instância 10.0.1.55, investigar com Detective/CloudTrail, verificar Threat Intel para o IP 198.51.100.22.

---

**Questão 5 (2 pontos):** Qual é a diferença entre CloudTrail Event History, um CloudTrail Trail e o CloudTrail Lake? Quando usar cada um?

**Gabarito:** **Event History:** 90 dias de Management Events gratuitos, somente leitura no console, não customizável. Usar para: pesquisas rápidas e pontuais de eventos recentes. **Trail:** Configuração persistente que entrega logs em S3 e/ou CloudWatch Logs, suporta Management + Data + Insights Events, retenção configurável no S3. Usar para: logging de longo prazo, compliance, ingestão em SIEM externo. **CloudTrail Lake:** Data lake gerenciado com SQL, retenção configurável (máximo 7 anos), queries otimizadas, suporta Organization. Usar para: investigações forenses, análises complexas de segurança, correlação entre múltiplas contas e períodos longos.
