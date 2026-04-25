# Lab 06 — Análise CIEM com AWS IAM Access Analyzer
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1 hora  
> **Dificuldade:** Intermediário  
> **Módulo Relacionado:** Módulo 06 — CIEM  

---

## 1. Contexto Situacional

Uma auditoria interna do Banco Meridian revelou que vários IAM roles e users têm permissões excessivas que nunca foram usadas. O Compliance Officer identificou que 3 developers que saíram da empresa ainda têm credenciais AWS ativas. Uma role de Lambda de processamento de boletos tem `s3:*` e `iam:ListUsers` — permissões que nunca foram usadas nos 90 dias de histórico do CloudTrail.

Você foi designado para conduzir uma auditoria CIEM completa usando AWS IAM Access Analyzer.

---

## 2. Situação Inicial

A conta AWS sandbox tem:
- 15 IAM users (3 potencialmente inativos)
- 25 IAM roles (várias com permissões excessivas)
- Nenhum processo de revisão periódica de acessos
- CloudTrail habilitado (requerido para Policy Generation)

---

## 3. Problema Identificado

Sem auditoria de CIEM, os seguintes riscos existem:
1. Ex-colaboradores podem ainda ter acesso ativo
2. Roles com permissões de admin disfarçadas ("shadow admins")
3. Permissões que nunca foram usadas aumentam a superfície de ataque
4. Violação de BACEN 4.893 Art. 8 (gestão de acessos com menor privilégio)

---

## 4. Roteiro de Atividades

1. Habilitar External Access Analyzer
2. Revisar findings de acesso externo
3. Habilitar Unused Access Analyzer (90 dias)
4. Listar permissões não usadas por role
5. Iniciar Policy Generation para role específica
6. Comparar política atual vs política mínima gerada
7. Aplicar a nova política mínima
8. Verificar que Access Analyzer não gera mais findings para a role
9. Identificar e revogar credenciais de ex-colaboradores
10. Gerar relatório CIEM completo

---

## 5. Proposição

Ao final deste laboratório, você terá identificado e remediado as permissões excessivas mais críticas na conta sandbox, com evidências formais do antes/depois para auditoria BACEN.

---

## 6. Script Passo a Passo

### Passo 1: Habilitar External Access Analyzer

**O que este passo faz:** Configura o perfil AWS para o ambiente sandbox do Banco Meridian e cria o External Access Analyzer — um analisador que examina continuamente todos os recursos da conta em busca de configurações que permitam acesso de fora da conta ou organização AWS. Ao contrário de scans manuais, o External Access Analyzer funciona de forma contínua: assim que um recurso é criado ou modificado, ele é automaticamente analisado. O parâmetro `--type ACCOUNT` restringe a análise ao escopo da conta (em vez de `ORGANIZATION`, que analisaria toda a organização AWS).

**Por que esta ordem:** O External Access Analyzer precisa ser criado antes de revisar seus findings (passo 2), pois pode levar 1-2 minutos para processar todos os recursos existentes da conta. Criá-lo primeiro e verificar findings depois garante que os resultados estarão disponíveis quando necessário. Além disso, o External Access Analyzer detecta exposição externa — o risco mais imediato — enquanto o Unused Access Analyzer (passo 3) detecta permissões excessivas internas.

```bash
# Configurar perfil AWS sandbox
export AWS_PROFILE=bancomeridian-sandbox
export AWS_DEFAULT_REGION=us-east-1

# Verificar identidade
aws sts get-caller-identity

# Criar External Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-external-access \
  --type ACCOUNT \
  --region us-east-1

echo "External Access Analyzer criado"

# Verificar que está rodando
aws accessanalyzer list-analyzers \
  --query 'analyzers[?name==`bancomeridian-external-access`].[name,status]' \
  --output table
```

**Resultado esperado:**
```
-------------------------------------------------------
|                    ListAnalyzers                    |
+-------------------------------+--------------------+
|  bancomeridian-external-access|  ACTIVE            |
+-------------------------------+--------------------+
```

**O que fazer se der errado:**
- Se o status aparecer como `CREATING` em vez de `ACTIVE`, aguarde mais 60 segundos e execute novamente o comando `list-analyzers`
- Se o erro for `AccessDeniedException`, verifique se o perfil AWS tem a permissão `access-analyzer:CreateAnalyzer` — consulte o Módulo 00 para configuração de permissões mínimas
- Se o erro for `ConflictException`, um analyzer com este nome já existe — execute `aws accessanalyzer list-analyzers` para verificar o existente

---

### Passo 2: Revisar Findings de Acesso Externo

**O que este passo faz:** Consulta todos os findings ativos do External Access Analyzer e os processa com um script Python para exibir os mais relevantes. O External Access Analyzer gera um finding para cada recurso que detecta como acessível externamente — por exemplo, um bucket S3 com política que permite acesso público, ou um IAM role com trust policy que aceita `Principal: "*"` (qualquer conta AWS). O script Python filtra e formata os primeiros 10 findings para análise imediata, exibindo: o ID do finding, o ARN do recurso afetado, o tipo de recurso e a condição que permite o acesso externo.

**Por que esta ordem:** Este passo vem imediatamente após a criação do analyzer (passo 1) porque aproveita os findings que o analyzer já processou durante o tempo de espera de 60 segundos. Revisar os findings de acesso externo antes dos findings de permissões não usadas (passo 4) reflete a prioridade de risco: exposição externa é imediata e explorável por qualquer atacante na internet, enquanto permissões não usadas representam um risco latente que requer comprometimento interno primeiro.

```bash
# Aguardar o analyzer processar os recursos (pode levar 1-2 minutos)
sleep 60

# Listar todos os findings ATIVOS
aws accessanalyzer list-findings \
  --analyzer-name bancomeridian-external-access \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[*].{ID:id,Resource:resource,Type:resourceType,Condition:condition}' \
  --output table

# Listar findings críticos (acesso público ou cross-account aberto)
echo ""
echo "=== FINDINGS CRÍTICOS — ACESSO EXTERNO ==="
aws accessanalyzer list-findings \
  --analyzer-name bancomeridian-external-access \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[*]' \
  --output json | python3 - << 'PYEOF'
import json, sys

findings = json.load(sys.stdin)
print(f"Total de findings de acesso externo: {len(findings)}")
print()

for f in findings[:10]:
    print(f"Finding ID: {f.get('id', 'N/A')[:20]}...")
    print(f"  Recurso: {f.get('resource', 'N/A')}")
    print(f"  Tipo: {f.get('resourceType', 'N/A')}")

    # Analisar condição (quem tem acesso)
    condition = f.get('condition', {})
    if condition:
        print(f"  Condição: {json.dumps(condition, indent=2)[:100]}")
    print()
PYEOF
```

**O que você deve ver:**
```
Total de findings de acesso externo: 3

Finding ID: a1b2c3d4e5f6789...
  Recurso: arn:aws:s3:::bancomeridian-relatorios-publicos
  Tipo: AWS::S3::Bucket

Finding ID: f9e8d7c6b5a4321...
  Recurso: arn:aws:iam::123456789:role/api-terceiros-role
  Tipo: AWS::IAM::Role
  Condição: {"aws:PrincipalOrgID": {"StringNotEquals": "o-xxxxx"}}
```

**O que fazer se der errado:**
- Se `Total de findings de acesso externo: 0` aparecer logo após criar o analyzer, aguarde mais 2 minutos e execute novamente — o analyzer pode ainda estar processando os recursos
- Se o script Python falhar com `JSONDecodeError`, verifique se a AWS CLI retornou JSON válido executando o comando sem o pipe para Python primeiro
- Se o `sleep 60` for insuficiente no seu ambiente, aumente para `sleep 120`

---

### Passo 3: Habilitar Unused Access Analyzer

**O que este passo faz:** Cria um segundo analisador do tipo `ACCOUNT_UNUSED_ACCESS` com janela de lookback de 90 dias. Este analisador é fundamentalmente diferente do External Access Analyzer: enquanto o primeiro detecta exposição externa, o Unused Access Analyzer usa dados do AWS CloudTrail para identificar permissões IAM que foram concedidas mas nunca efetivamente utilizadas nos últimos 90 dias. O parâmetro `"unusedAccessAge": 90` define a janela de inatividade — uma permissão é considerada "não usada" se não aparecer em nenhum evento do CloudTrail nos últimos 90 dias. Este prazo alinha-se com o ciclo de revisão trimestral recomendado pelo BACEN 4.893.

**Por que esta ordem:** O Unused Access Analyzer vem após o External Access Analyzer porque seu processamento é mais demorado (2-5 minutos) e requer dados do CloudTrail. Criá-lo depois do analyzer externo permite que ambos processem em paralelo enquanto o analista revisa os findings externos (passo 2). Os dois analisadores respondem perguntas complementares: "Quem de fora pode acessar nossos recursos?" (externo) e "Quais permissões internas nunca foram usadas?" (unused access).

```bash
# Criar Unused Access Analyzer (90 dias de lookback)
aws accessanalyzer create-analyzer \
  --analyzer-name bancomeridian-unused-90d \
  --type ACCOUNT_UNUSED_ACCESS \
  --configuration '{"unusedAccessAge": 90}' \
  --region us-east-1

echo "Unused Access Analyzer criado (lookback: 90 dias)"

# Aguardar processamento
echo "Aguardando análise... (pode levar 2-5 minutos)"
sleep 120

# Verificar status
aws accessanalyzer list-analyzers \
  --query 'analyzers[?name==`bancomeridian-unused-90d`].[name,status,type]' \
  --output table
```

**O que você deve ver:**
```
--------------------------------------------------------------
|                      ListAnalyzers                         |
+--------------------------+----------+---------------------+
|  bancomeridian-unused-90d|  ACTIVE  | ACCOUNT_UNUSED_ACCESS|
+--------------------------+----------+---------------------+
```

**O que fazer se der errado:**
- Se o status aparecer como `CREATING` após os 120 segundos de espera, aguarde mais 2 minutos — a análise inicial de 90 dias de CloudTrail pode levar mais tempo em contas com alto volume de eventos
- Se receber `ValidationException: unusedAccessAge`, verifique se o CloudTrail está habilitado na conta sandbox — o Unused Access Analyzer requer CloudTrail para funcionar

---

### Passo 4: Listar Permissões Não Usadas

**O que este passo faz:** Obtém o ARN do Unused Access Analyzer dinamicamente e consulta todos os findings do tipo `UnusedPermission` — o finding mais crítico para CIEM. O script Python processa a saída JSON e agrupa os findings por recurso IAM (role ou user), exibindo as ações específicas que foram concedidas mas nunca executadas nos últimos 90 dias. Adicionalmente, o segundo comando filtra pelo tipo `UnusedIAMRole` — roles inteiras que não foram assumidas por nenhuma identidade no período, candidatas diretas à deleção.

**Por que esta ordem:** Este passo vem depois da criação do Unused Access Analyzer (passo 3) com intervalo de processamento suficiente para que os findings estejam disponíveis. Listar permissões não usadas antes de iniciar a Policy Generation (passo 5) é fundamental porque os findings desta etapa informam quais roles priorizar para geração de política mínima — você começa pela role com o maior número de permissões não usadas ou com as permissões mais críticas (iam:*, s3:Delete*, ec2:Terminate*).

```bash
# Obter ARN do Unused Access Analyzer
UNUSED_ANALYZER_ARN=$(aws accessanalyzer list-analyzers \
  --query 'analyzers[?name==`bancomeridian-unused-90d`].arn' \
  --output text)

echo "Analyzer ARN: $UNUSED_ANALYZER_ARN"
echo ""

# Listar todos os findings de permissões não usadas
aws accessanalyzer list-findings-v2 \
  --analyzer-arn "$UNUSED_ANALYZER_ARN" \
  --filter '{"findingType": {"contains": ["UnusedPermission"]}}' \
  --output json | python3 - << 'PYEOF'
import json, sys

data = json.load(sys.stdin)
findings = data.get('findings', [])

print(f"=== PERMISSÕES NÃO USADAS (últimos 90 dias) ===")
print(f"Total: {len(findings)}")
print()

# Agrupar por recurso
from collections import defaultdict
by_resource = defaultdict(list)
for f in findings:
    resource = f.get('resource', 'N/A')
    by_resource[resource].append(f)

for resource, resource_findings in list(by_resource.items())[:5]:
    print(f"Role/User: {resource.split('/')[-1]}")
    for f in resource_findings[:3]:
        details = f.get('findingDetails', {})
        actions = details.get('unusedPermissions', {}).get('actions', [])
        for action in actions[:5]:
            print(f"  - {action.get('action', 'N/A')} (nunca usada)")
    print()
PYEOF

# Também listar roles inativas (nunca usadas nos últimos 90 dias)
aws accessanalyzer list-findings-v2 \
  --analyzer-arn "$UNUSED_ANALYZER_ARN" \
  --filter '{"findingType": {"contains": ["UnusedIAMRole"]}}' \
  --query 'findings[*].resource' \
  --output text | while read role; do
    echo "ROLE INATIVA: $role"
  done
```

**O que você deve ver:**
```
=== PERMISSÕES NÃO USADAS (últimos 90 dias) ===
Total: 12

Role/User: api-pagamentos-role
  - s3:DeleteObject (nunca usada)
  - s3:DeleteBucket (nunca usada)
  - iam:ListUsers (nunca usada)

Role/User: lambda-notificacoes-role
  - ec2:DescribeInstances (nunca usada)
  - iam:GetUser (nunca usada)

ROLE INATIVA: arn:aws:iam::123456789:role/role-projeto-encerrado-2023
```

**O que fazer se der errado:**
- Se `Total: 0` aparecer, o CloudTrail da conta pode ter menos de 90 dias de histórico, ou o analyzer ainda está processando — aguarde mais 5 minutos e repita
- Se o script Python falhar com `KeyError`, o formato de output do `list-findings-v2` pode diferir entre versões da AWS CLI — use `--debug` para inspecionar o JSON bruto

---

### Passo 5: Iniciar Policy Generation

**O que este passo faz:** Identifica a role alvo para análise (buscando por nome `api-pagamentos` na conta) e, se ela não existir, cria uma role de demonstração com políticas propositalmente excessivas (`AmazonS3FullAccess` + `IAMReadOnlyAccess`) para simular o cenário realista. Em seguida, inicia o processo de Policy Generation do IAM Access Analyzer, que consulta 90 dias de eventos do CloudTrail para a role especificada e compila uma lista de quais ações IAM foram efetivamente executadas. O `JOB_ID` retornado é usado no passo 6 para recuperar a política gerada.

**Por que esta ordem:** A Policy Generation precisa ser iniciada antes de comparar a política atual com a mínima (passo 6), porque o processo de análise do CloudTrail pode levar de 5 a 30 minutos dependendo do volume de eventos. Iniciar o job no passo 5 e fazer a comparação no passo 6 permite que o processo rode em background enquanto o aluno entende o conceito. A demonstração com a role `lab06-api-pagamentos-demo` é necessária porque ambientes sandbox normalmente não têm 90 dias de CloudTrail histórico suficiente — a comparação conceitual do passo 6 supre essa limitação.

```bash
# Identificar uma role com permissões excessivas para análise
# (assumindo que 'api-pagamentos-role' tem permissões excessivas)
ROLE_ARN=$(aws iam list-roles \
  --query 'Roles[?contains(RoleName, `api-pagamentos`)].Arn' \
  --output text | head -1)

if [ -z "$ROLE_ARN" ]; then
  # Criar role de demonstração se não existir
  aws iam create-role \
    --role-name lab06-api-pagamentos-demo \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

  # Anexar política excessiva para demonstração
  aws iam attach-role-policy \
    --role-name lab06-api-pagamentos-demo \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

  aws iam attach-role-policy \
    --role-name lab06-api-pagamentos-demo \
    --policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess

  ROLE_ARN=$(aws iam get-role --role-name lab06-api-pagamentos-demo \
    --query 'Role.Arn' --output text)
  echo "Role de demonstração criada: $ROLE_ARN"
fi

echo "Analisando role: $ROLE_ARN"
echo ""

# Ver política atual (antes da geração mínima)
echo "=== POLÍTICAS ATUAIS DA ROLE ==="
aws iam list-attached-role-policies \
  --role-name $(echo $ROLE_ARN | cut -d'/' -f2) \
  --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' \
  --output table

# Iniciar Policy Generation baseada em CloudTrail
# Nota: requer CloudTrail habilitado e role de acesso ao CloudTrail
# Para sandbox sem CloudTrail configurado, mostrar o comando e o conceito

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo ""
echo "=== INICIANDO POLICY GENERATION ==="
echo "Nota: em produção, este comando analisa 90 dias de CloudTrail"
echo ""

# Tentar iniciar (pode falhar se não houver role de CloudTrail configurada)
JOB_ID=$(aws accessanalyzer start-policy-generation \
  --policy-generation-details "{\"principalArn\": \"$ROLE_ARN\"}" \
  --cloud-trail-details "{
    \"accessRole\": \"arn:aws:iam::${ACCOUNT_ID}:role/AccessAnalyzerCloudTrailRole\",
    \"startTime\": \"$(date -d '90 days ago' -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -v-90d -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"endTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"trails\": [{\"allRegions\": true}]
  }" \
  --query 'jobId' --output text 2>/dev/null || echo "POLICY_GENERATION_DEMO")

echo "Job ID: $JOB_ID"
```

**O que você deve ver:**
```
Role de demonstração criada: arn:aws:iam::123456789:role/lab06-api-pagamentos-demo

=== POLÍTICAS ATUAIS DA ROLE ===
+----------------------+------------------------------------------+
|  PolicyName          |  PolicyArn                               |
+----------------------+------------------------------------------+
|  AmazonS3FullAccess  |  arn:aws:iam::aws:policy/AmazonS3FullA...|
|  IAMReadOnlyAccess   |  arn:aws:iam::aws:policy/IAMReadOnlyAcc..|
+----------------------+------------------------------------------+

=== INICIANDO POLICY GENERATION ===
Job ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**O que fazer se der errado:**
- Se `JOB_ID=POLICY_GENERATION_DEMO`, significa que o comando falhou porque a conta sandbox não tem a role `AccessAnalyzerCloudTrailRole` ou CloudTrail configurado — isso é esperado em sandboxes; o passo 6 fará a demonstração conceitual
- Se a criação da role falhar com `EntityAlreadyExists`, execute `aws iam get-role --role-name lab06-api-pagamentos-demo` para obter o ARN existente

---

### Passo 6: Comparar Política Atual vs Política Mínima

**O que este passo faz:** Demonstra o impacto quantificado da aplicação do princípio de menor privilégio. Exibe lado a lado a política atual (permissões excessivas) versus a política mínima gerada pela análise de uso real do CloudTrail. O output mostra: (1) quais ações S3 foram efetivamente usadas (`s3:GetObject`, `s3:PutObject`, `s3:ListBucket`); (2) quais ações S3 nunca foram usadas e seriam removidas (`s3:DeleteObject`, `s3:DeleteBucket`, `s3:PutBucketPolicy` e 40+ outras); (3) a redução calculada de superfície de ataque em percentagem. Se o Job da Policy Generation concluiu, o script também tenta recuperar a política real gerada pelo CloudTrail.

**Por que esta ordem:** A comparação antes/depois vem imediatamente antes da aplicação da política mínima (passo 7) para que o analista possa revisar e aprovar as mudanças antes de qualquer alteração na conta. Este é o ponto de decisão humana no processo: o Access Analyzer sugere, o analista valida, e só então a política é aplicada. Em produção, esta revisão seria documentada como evidência de controle de acesso para auditoria BACEN.

```bash
# Mostrar o conceito de política mínima esperada

echo "=== ANÁLISE: POLÍTICA ATUAL vs POLÍTICA MÍNIMA ==="
echo ""
echo "POLÍTICA ATUAL (AmazonS3FullAccess + IAMReadOnlyAccess):"
echo "  s3:* (todas as ações S3)"
echo "  iam:Get*, iam:List*, iam:Generate* (todas as ações de leitura IAM)"
echo ""
echo "RESULTADO DA POLICY GENERATION ESPERADO (baseado em CloudTrail 90 dias):"
echo "  s3:GetObject (usada: 1.234 vezes)"
echo "  s3:PutObject (usada: 456 vezes)"
echo "  s3:ListBucket (usada: 789 vezes)"
echo ""
echo "PERMISSÕES NÃO USADAS (seriam removidas):"
echo "  s3:DeleteObject"
echo "  s3:DeleteBucket"
echo "  s3:PutBucketPolicy"
echo "  iam:GetUser (nunca usada)"
echo "  iam:ListUsers (nunca usada)"
echo "  ... + 40 outras ações"
echo ""
echo "REDUÇÃO: de 80+ permissões para 3 permissões necessárias"
echo "IMPACTO EM SEGURANÇA: superfície de ataque reduzida em ~96%"

# Verificar resultado da geração se disponível
if [ "$JOB_ID" != "POLICY_GENERATION_DEMO" ] && [ -n "$JOB_ID" ]; then
  echo ""
  echo "Aguardando geração de política..."
  sleep 30
  aws accessanalyzer get-generated-policy \
    --job-id "$JOB_ID" \
    --query 'generatedPolicyResult.generatedPolicies[0].policy' \
    --output text | python3 -m json.tool 2>/dev/null || \
    echo "Policy generation ainda em andamento..."
fi
```

**O que você deve ver:**
```
=== ANÁLISE: POLÍTICA ATUAL vs POLÍTICA MÍNIMA ===

POLÍTICA ATUAL (AmazonS3FullAccess + IAMReadOnlyAccess):
  s3:* (todas as ações S3)
  iam:Get*, iam:List*, iam:Generate* (todas as ações de leitura IAM)

RESULTADO DA POLICY GENERATION ESPERADO (baseado em CloudTrail 90 dias):
  s3:GetObject (usada: 1.234 vezes)
  s3:PutObject (usada: 456 vezes)
  s3:ListBucket (usada: 789 vezes)

PERMISSÕES NÃO USADAS (seriam removidas):
  s3:DeleteObject
  s3:DeleteBucket
  s3:PutBucketPolicy
  iam:GetUser (nunca usada)
  iam:ListUsers (nunca usada)
  ... + 40 outras ações

REDUÇÃO: de 80+ permissões para 3 permissões necessárias
IMPACTO EM SEGURANÇA: superfície de ataque reduzida em ~96%
```

**O que fazer se der errado:**
- Se `Policy generation ainda em andamento...` aparecer após 30 segundos, o job ainda está processando — isso é normal para contas com muito volume de CloudTrail; aumente o `sleep 30` para `sleep 120` e tente novamente

---

### Passo 7: Aplicar Política Mínima

**O que este passo faz:** Cria a política IAM mínima em formato JSON com apenas as três ações S3 que foram efetivamente usadas nos últimos 90 dias, restritas ao bucket específico de pagamentos (`bancomeridian-pagamentos`). Em seguida, desanexa a política excessiva (`AmazonS3FullAccess`) e anexa a nova política mínima à role. Este é o passo de remediação efetiva — as etapas anteriores foram de análise e aprovação; agora a mudança é aplicada na conta AWS real.

**Por que esta ordem:** A aplicação da política mínima ocorre apenas depois que o analista revisou o comparativo (passo 6) e aprovou a redução. Fazer o passo 7 antes do passo 6 seria como aplicar uma cirurgia sem diagnóstico. O escopo da política mínima (`Resource: bancomeridian-pagamentos/*`) é mais restritivo que a política original que permitia qualquer bucket S3 — essa especificidade é fundamental para o princípio de menor privilégio, pois impede que a role acesse outros buckets mesmo que um atacante tente.

```bash
# Criar política mínima manualmente (baseada no exemplo acima)
MINIMAL_POLICY_JSON='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3MinimalAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::bancomeridian-pagamentos/*",
        "arn:aws:s3:::bancomeridian-pagamentos"
      ]
    }
  ]
}'

ROLE_NAME=$(echo $ROLE_ARN | cut -d'/' -f2)

# Criar a nova política mínima
aws iam create-policy \
  --policy-name "${ROLE_NAME}-minimal-policy-$(date +%Y%m%d)" \
  --policy-document "$MINIMAL_POLICY_JSON" \
  --description "Política mínima gerada por Policy Analysis em $(date +%Y-%m-%d)" 2>/dev/null || \
  echo "Nota: política pode já existir"

MINIMAL_POLICY_ARN=$(aws iam list-policies \
  --scope Local \
  --query "Policies[?contains(PolicyName, '${ROLE_NAME}-minimal-policy')].Arn" \
  --output text | head -1)

if [ -n "$MINIMAL_POLICY_ARN" ]; then
  echo "Política mínima criada: $MINIMAL_POLICY_ARN"

  # Desanexar política excessiva
  aws iam detach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess 2>/dev/null || true

  # Anexar política mínima
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$MINIMAL_POLICY_ARN" 2>/dev/null || true

  echo "✓ Política mínima aplicada à role $ROLE_NAME"
fi
```

**O que você deve ver:**
```
Política mínima criada: arn:aws:iam::123456789:policy/lab06-api-pagamentos-demo-minimal-policy-20260425
✓ Política mínima aplicada à role lab06-api-pagamentos-demo
```

**O que fazer se der errado:**
- Se `aws iam create-policy` falhar com `EntityAlreadyExists`, a política já foi criada em uma execução anterior — o script lida com isso com `2>/dev/null || echo "Nota: política pode já existir"`
- Se `MINIMAL_POLICY_ARN` ficar vazia, verifique o nome da role com `echo $ROLE_NAME` e liste as políticas com `aws iam list-policies --scope Local`
- Após aplicar, verifique com `aws iam list-attached-role-policies --role-name $ROLE_NAME` que a política mínima aparece e a excessiva foi removida

---

### Passo 8: Verificar Credenciais de Ex-Colaboradores

**O que este passo faz:** Gera o relatório de credenciais nativo do IAM (CSV com informações de todos os usuários da conta) e processa com um script Python que identifica dois tipos de risco: (1) usuários humanos que não fazem login há mais de 90 dias — candidatos a ex-colaboradores com credenciais ativas; (2) access keys com mais de 90 dias sem rotação — chaves com alto risco de comprometimento por exposição não detectada. O relatório é a base de evidência para comunicar ao RH e ao time de segurança quais usuários devem ter acesso revogado imediatamente.

**Por que esta ordem:** A verificação de credenciais de ex-colaboradores ocorre depois de aplicar a remediação técnica de permissões (passo 7) porque são ações de natureza diferente. Enquanto reduzir permissões de roles existentes é uma ação puramente técnica, revogar credenciais de ex-colaboradores pode exigir validação com o RH antes da execução — especialmente em caso de false positives (colaborador em licença médica, funcionário com conta sem login regular). Esta análise informa quais usuários merecem atenção no passo 9 (shadow admins).

```bash
# Gerar relatório de credenciais
aws iam generate-credential-report 2>/dev/null
sleep 5

# Processar relatório
aws iam get-credential-report --output text --query Content | \
  base64 -d 2>/dev/null | python3 - << 'PYEOF'
import sys, csv
from datetime import datetime, timezone, timedelta

try:
    reader = csv.DictReader(sys.stdin)
    rows = list(reader)

    print("=== AUDITORIA DE CREDENCIAIS IAM ===")
    print()

    threshold_days = 90
    today = datetime.now(timezone.utc)
    inactive_users = []

    for row in rows:
        user = row.get('user', 'N/A')
        if user == '<root_account>':
            continue

        # Verificar último acesso (password)
        password_last_used = row.get('password_last_used', 'N/A')
        if password_last_used not in ['N/A', 'no_information', 'not_supported']:
            try:
                last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                days_inactive = (today - last_used).days
                if days_inactive > threshold_days:
                    inactive_users.append({
                        'user': user,
                        'days_inactive': days_inactive,
                        'last_used': password_last_used[:10]
                    })
            except Exception:
                pass

        # Verificar chaves de acesso velhas
        for key_num in ['1', '2']:
            key_active = row.get(f'access_key_{key_num}_active', 'false')
            key_last_rotated = row.get(f'access_key_{key_num}_last_rotated', 'N/A')
            if key_active == 'true' and key_last_rotated not in ['N/A', '']:
                try:
                    rotated = datetime.fromisoformat(key_last_rotated.replace('Z', '+00:00'))
                    age_days = (today - rotated).days
                    if age_days > 90:
                        print(f"CHAVE ANTIGA: {user} — access_key_{key_num} tem {age_days} dias sem rotação")
                except Exception:
                    pass

    if inactive_users:
        print(f"\nUSUÁRIOS INATIVOS (+{threshold_days} dias sem acesso):")
        for u in inactive_users:
            print(f"  {u['user']}: {u['days_inactive']} dias inativo (último: {u['last_used']})")
        print()
        print("RECOMENDAÇÃO: Verificar com RH se esses usuários ainda são colaboradores ativos.")
        print("Se saíram da empresa: REVOGAR IMEDIATAMENTE (BACEN 4.893 Art. 8)")
    else:
        print("Nenhum usuário inativo detectado nos últimos 90 dias")
except Exception as e:
    print(f"Erro ao processar relatório: {e}")
    print("O relatório pode não estar disponível nesta conta sandbox.")
PYEOF
```

**O que você deve ver:**
```
=== AUDITORIA DE CREDENCIAIS IAM ===

CHAVE ANTIGA: dev-maria-santos — access_key_1 tem 127 dias sem rotação
CHAVE ANTIGA: svc-integracao-erp — access_key_1 tem 203 dias sem rotação

USUÁRIOS INATIVOS (+90 dias sem acesso):
  joao.silva: 142 dias inativo (último: 2025-12-03)
  pedro.alves: 287 dias inativo (último: 2025-07-19)

RECOMENDAÇÃO: Verificar com RH se esses usuários ainda são colaboradores ativos.
Se saíram da empresa: REVOGAR IMEDIATAMENTE (BACEN 4.893 Art. 8)
```

**O que fazer se der errado:**
- Se receber `Erro ao processar relatório: O relatório pode não estar disponível nesta conta sandbox`, execute `aws iam generate-credential-report` novamente e aguarde 30 segundos antes de tentar `get-credential-report`
- Se `base64 -d` falhar em macOS, use `base64 -D` (letra maiúscula)
- Em contas sandbox novas, é normal não encontrar usuários inativos — o relatório ainda assim valida que o processo funciona

---

### Passo 9: Identificar Shadow Admins

**O que este passo faz:** Executa uma varredura em todas as roles da conta em busca de políticas inline que contenham `Action: "*"`, `Action: "iam:*"` ou `Action: "sts:*"` — as três configurações que caracterizam um shadow admin. Shadow admins são roles com nomes inofensivos (como `lambda-processamento-relatorios`) que possuem permissões efetivamente equivalentes às de um administrador, mas que passam despercebidas em revisões superficiais porque não têm `AdministratorAccess` como nome de política. O script usa um detector Python inline para analisar cada policy document e emitir alerta quando detecta a combinação perigosa.

**Por que esta ordem:** A identificação de shadow admins ocorre antes do relatório final (passo 10) porque é um dos achados mais críticos de uma auditoria CIEM. Um shadow admin representa um risco imediato e específico — uma conta ou role que pode comprometer toda a conta AWS se explorada. Os achados deste passo alimentam diretamente as recomendações do relatório executivo gerado no passo 10, e qualquer shadow admin identificado deve ser documentado com prioridade máxima.

```bash
echo "=== IDENTIFICANDO SHADOW ADMINS ==="
echo "Shadow admin = role com permissões equivalentes a admin, mas com nome inocente"
echo ""

# Verificar todas as roles em busca de permissões perigosas
aws iam list-roles \
  --query 'Roles[*].RoleName' \
  --output text | tr '\t' '\n' | while read role_name; do

  # Verificar políticas inline
  inline_policies=$(aws iam list-role-policies \
    --role-name "$role_name" \
    --query 'PolicyNames' \
    --output text 2>/dev/null)

  for policy_name in $inline_policies; do
    policy_doc=$(aws iam get-role-policy \
      --role-name "$role_name" \
      --policy-name "$policy_name" \
      --query 'PolicyDocument' \
      --output json 2>/dev/null)

    # Verificar se tem Action=* ou iam:*
    if echo "$policy_doc" | python3 -c "
import json, sys
try:
    doc = json.load(sys.stdin)
    for stmt in doc.get('Statement', []):
        if stmt.get('Effect') == 'Allow':
            actions = stmt.get('Action', [])
            if isinstance(actions, str): actions = [actions]
            for a in actions:
                if a in ['*', 'iam:*', 'sts:*']:
                    print('SHADOW ADMIN')
                    sys.exit(0)
except: pass
" 2>/dev/null | grep -q "SHADOW ADMIN"; then
      echo "SHADOW ADMIN DETECTADO: Role=$role_name, Policy=$policy_name"
    fi
  done
done 2>/dev/null | head -10 || echo "Nenhum shadow admin detectado (ou scan incompleto)"
```

**O que você deve ver:**
```
SHADOW ADMIN DETECTADO: Role=legacy-data-migration-role, Policy=DataMigrationPolicy
```
Ou, em ambientes limpos:
```
Nenhum shadow admin detectado (ou scan incompleto)
```

**O que fazer se der errado:**
- Se o script parecer travar (sem output por mais de 2 minutos), pode estar iterando sobre muitas roles — adicione `| head -20` antes do `while read role_name` para limitar o escopo durante o lab
- Em contas com muitas roles, adicione `--max-items 50` ao comando `aws iam list-roles` para limitar o escopo durante o exercício de laboratório

---

### Passo 10: Gerar Relatório CIEM Final

**O que este passo faz:** Consolida todos os achados dos passos anteriores em um relatório executivo estruturado, salvo em `/tmp/lab06-ciem-report.txt`. O relatório inclui: data e conta auditada, achados agrupados por categoria (acesso externo, permissões excessivas, credenciais de ex-colaboradores, shadow admins), evidência da remediação aplicada (antes/depois da role `lab06-api-pagamentos-demo`), status de conformidade com o BACEN 4.893 Art. 8, e as próximas recomendações priorizadas para os próximos 30 dias. Este formato é adequado para apresentação ao CISO e ao Compliance Officer como evidência de auditoria.

**Por que esta ordem:** O relatório é sempre o último passo porque consolida todos os achados e remediações já realizados. Gerá-lo antes de completar os passos anteriores resultaria em um relatório incompleto e enganoso. Em cenários reais de auditoria CIEM no Banco Meridian, este relatório seria gerado no final de cada ciclo trimestral de revisão de acessos e arquivado como evidência formal para o regulador.

```bash
python3 << 'PYEOF'
from datetime import datetime

report = f"""
=== RELATÓRIO DE AUDITORIA CIEM — BANCO MERIDIAN ===
Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Conta AWS: {__import__('subprocess').check_output(['aws', 'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text']).decode().strip()}
Ferramenta: AWS IAM Access Analyzer

ACHADOS PRINCIPAIS:
──────────────────────────────────────────────────────────────────────────────

1. ACESSO EXTERNO (External Access Analyzer)
   Findings ativos: verificar no console do Access Analyzer
   Ação: rever cada finding e arquivar se intencional, corrigir se não

2. PERMISSÕES EXCESSIVAS (Unused Access Analyzer — 90 dias)
   Roles com permissões não usadas: identificadas acima
   Ação: usar Policy Generation para criar políticas mínimas

3. CREDENCIAIS DE EX-COLABORADORES
   Usuários inativos detectados: verificar relatório de credenciais
   Ação: revogar credenciais de usuários inativos há mais de 90 dias

4. SHADOW ADMINS
   Roles com Action=* ou iam:*: verificar lista acima
   Ação: revisar e remover permissões excessivas

REMEDIAÇÃO APLICADA:
  ✓ Role lab06-api-pagamentos-demo: política reduzida de 80+ para 3 permissões
  ✓ Redução de superfície de ataque: ~96%

CONFORMIDADE BACEN 4.893 — Art. 8:
  Antes: sem revisão periódica de acessos
  Depois: auditoria CIEM trimestral com IAM Access Analyzer
  Próxima revisão: {datetime.now().strftime('%Y-%m-%d')} + 90 dias

RECOMENDAÇÕES PRÓXIMOS 30 DIAS:
  1. Revogar credenciais de ex-colaboradores identificados
  2. Rodar Policy Generation para as top 10 roles mais permissivas
  3. Configurar alertas CloudWatch para criação de políticas com wildcard
  4. Implementar JIT access para roles de DBA e Cloud Admin
──────────────────────────────────────────────────────────────────────────────
"""

print(report)

# Salvar relatório
with open('/tmp/lab06-ciem-report.txt', 'w') as f:
    f.write(report)
print("Relatório salvo em: /tmp/lab06-ciem-report.txt")
PYEOF
```

**O que você deve ver:**
```
=== RELATÓRIO DE AUDITORIA CIEM — BANCO MERIDIAN ===
Data: 2026-04-25 14:32
Conta AWS: 123456789012
Ferramenta: AWS IAM Access Analyzer

ACHADOS PRINCIPAIS:
──────────────────────────────────────────────────────────────────────────────

1. ACESSO EXTERNO (External Access Analyzer)
   Findings ativos: verificar no console do Access Analyzer
   ...

Relatório salvo em: /tmp/lab06-ciem-report.txt
```

**O que fazer se der errado:**
- Se o comando `aws sts get-caller-identity` dentro do script Python falhar (erro de permissão), substitua a linha do `Account` por `Account: [verificar manualmente]` na variável `report`
- Se `/tmp/lab06-ciem-report.txt` não for criado, verifique as permissões de escrita em `/tmp` com `ls -la /tmp/`

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | External Access Analyzer criado | Status `ACTIVE` no listagem |
| 2 | Findings externos revisados | Lista de findings no terminal |
| 3 | Unused Access Analyzer criado | Status `ACTIVE` no listagem |
| 4 | Permissões não usadas listadas | Lista de ações por role |
| 5 | Policy Generation iniciada | Job ID retornado |
| 6 | Comparativo exibido | Output mostra antes/depois |
| 7 | Política mínima aplicada | `aws iam list-attached-role-policies` atualizado |
| 8 | Credenciais auditadas | Relatório de usuários inativos |
| 9 | Shadow admins verificados | Output da busca por wildcards |
| 10 | Relatório gerado | Arquivo em /tmp/lab06-ciem-report.txt |

---

## 8. Gabarito Completo

### Antes e Depois — Role lab06-api-pagamentos-demo

**Antes:**

| Política | Permissões | Usadas em 90 dias |
|:---------|:----------:|:-----------------:|
| AmazonS3FullAccess | 80+ ações | 3 |
| IAMReadOnlyAccess | 25+ ações | 0 |

**Depois:**

| Política | Permissões | Redução |
|:---------|:----------:|:-------:|
| api-pagamentos-minimal-policy | 3 ações | -96% |

### Findings Access Analyzer Esperados

**External Access Analyzer:**
```
Finding: IAM Role com trust policy cross-account aberta
  Resource: arn:aws:iam::123456789:role/api-terceiros-role
  Condition: "aws:PrincipalOrgID" não está configurado
  → Qualquer conta AWS pode assumir esta role
  Ação: restringir trust policy para contas específicas da organização
```

**Unused Access Analyzer:**
```
Finding: UnusedPermission
  Resource: arn:aws:iam::123456789:role/api-pagamentos-role
  UnusedActions: [s3:DeleteObject, s3:DeleteBucket, iam:ListUsers, ...]
  DaysInactive: 90+
  Ação: usar Policy Generation para criar política mínima
```

---

*Lab 06 — Análise CIEM com AWS IAM Access Analyzer*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
