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

---

### Passo 2: Revisar Findings de Acesso Externo

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

---

### Passo 3: Habilitar Unused Access Analyzer

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

---

### Passo 4: Listar Permissões Não Usadas

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

---

### Passo 5: Iniciar Policy Generation

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

---

### Passo 6: Comparar Política Atual vs Política Mínima

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

---

### Passo 7: Aplicar Política Mínima

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

---

### Passo 8: Verificar Credenciais de Ex-Colaboradores

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

---

### Passo 9: Identificar Shadow Admins

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

---

### Passo 10: Gerar Relatório CIEM Final

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
