# Lab 07 — WAF Customizado para Internet Banking

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 07 — Segurança de Rede
**Nível:** Avançado

---

## Contexto

O Banco Meridian lançou um novo portal de internet banking em produção. Você precisa configurar o AWS WAF v2 para proteger a aplicação contra o OWASP Top 10, implementar rate limiting geográfico, configurar logging completo e realizar testes de efetividade das regras.

A aplicação está exposta via Application Load Balancer (ALB) na conta Production (444444444444), região sa-east-1.

---

## Pré-requisitos

- ALB criado e funcionando (ou simular)
- AWS CLI e Python com Boto3
- Acesso de admin à conta Production

---

## Seção 1 — Criar Web ACL Base

**Passo 1.1** — Criar a Web ACL:

```bash
# Criar Web ACL para o Internet Banking
WEB_ACL=$(aws wafv2 create-web-acl \
  --name "MeridianInternetBanking-WebACL" \
  --scope REGIONAL \
  --region sa-east-1 \
  --default-action '{"Allow": {}}' \
  --visibility-config '{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "MeridianInternetBankingWebACL"
  }' \
  --description "Web ACL para portal Internet Banking do Banco Meridian" \
  --tags '[{"Key":"Application","Value":"InternetBanking"},{"Key":"Environment","Value":"Production"},{"Key":"ManagedBy","Value":"SecurityTeam"}]' \
  --query 'Summary.{Id:Id,Name:Name,ARN:ARN}' \
  --output json)

WEB_ACL_ID=$(echo $WEB_ACL | python3 -c "import json,sys; print(json.load(sys.stdin)['Id'])")
WEB_ACL_ARN=$(echo $WEB_ACL | python3 -c "import json,sys; print(json.load(sys.stdin)['ARN'])")
WEB_ACL_LOCK=$(aws wafv2 get-web-acl \
  --name MeridianInternetBanking-WebACL \
  --scope REGIONAL \
  --id $WEB_ACL_ID \
  --region sa-east-1 \
  --query 'LockToken' \
  --output text)

echo "Web ACL criada:"
echo "  ID: $WEB_ACL_ID"
echo "  ARN: $WEB_ACL_ARN"
```

**Resultado Esperado:** Web ACL criada com default action Allow.

---

## Seção 2 — Adicionar Managed Rule Groups

**Passo 2.1** — Criar Web ACL com managed rules:

```python
import boto3
import json

waf = boto3.client('wafv2', region_name='sa-east-1')

# Obter Lock Token atual da Web ACL
WEB_ACL_ID = '<ID_DO_WEB_ACL>'
WEB_ACL_NAME = 'MeridianInternetBanking-WebACL'

web_acl = waf.get_web_acl(Name=WEB_ACL_NAME, Scope='REGIONAL', Id=WEB_ACL_ID)
lock_token = web_acl['LockToken']
current_rules = web_acl['WebACL'].get('Rules', [])

# Novas regras: Managed Rule Groups
managed_rules = [
    # Priority 1: IP Reputation (bloquear IPs de botnets e Tor)
    {
        "Name": "AWSManagedRulesAmazonIpReputationList",
        "Priority": 1,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesAmazonIpReputationList"
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "IPReputationList"
        }
    },
    # Priority 2: Known Bad Inputs
    {
        "Name": "AWSManagedRulesKnownBadInputsRuleSet",
        "Priority": 2,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesKnownBadInputsRuleSet"
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "KnownBadInputs"
        }
    },
    # Priority 3: SQL Injection
    {
        "Name": "AWSManagedRulesSQLiRuleSet",
        "Priority": 3,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesSQLiRuleSet"
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "SQLiRuleSet"
        }
    },
    # Priority 4: Common Rule Set (XSS, Path Traversal, etc.)
    {
        "Name": "AWSManagedRulesCommonRuleSet",
        "Priority": 4,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
                "ExcludedRules": []
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "CommonRuleSet"
        }
    },
    # Priority 5: Bot Control
    {
        "Name": "AWSManagedRulesBotControlRuleSet",
        "Priority": 5,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesBotControlRuleSet",
                "ManagedRuleGroupConfigs": [{
                    "AWSManagedRulesBotControlRuleSet": {
                        "InspectionLevel": "COMMON"
                    }
                }]
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "BotControl"
        }
    }
]

# Atualizar Web ACL com managed rules
response = waf.update_web_acl(
    Name=WEB_ACL_NAME,
    Scope='REGIONAL',
    Id=WEB_ACL_ID,
    DefaultAction={'Allow': {}},
    Rules=managed_rules,
    VisibilityConfig={
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "MeridianInternetBankingWebACL"
    },
    LockToken=lock_token
)

print(f"Web ACL atualizada com {len(managed_rules)} managed rule groups")
print(f"Novo Lock Token: {response['NextLockToken']}")
```

---

## Seção 3 — Adicionar Regras Customizadas

**Passo 3.1** — Rate Limiting para endpoint de login:

```python
# Obter lock token atualizado
web_acl = waf.get_web_acl(Name=WEB_ACL_NAME, Scope='REGIONAL', Id=WEB_ACL_ID)
lock_token = web_acl['LockToken']
current_rules = web_acl['WebACL'].get('Rules', [])

# Regra customizada 1: Rate Limiting para /api/auth/login
rate_limit_rule = {
    "Name": "MeridianRateLimitLogin",
    "Priority": 10,
    "Action": {"Block": {}},
    "Statement": {
        "RateBasedStatement": {
            "Limit": 50,  # 50 requests por 5 minutos por IP
            "AggregateKeyType": "IP",
            "ScopeDownStatement": {
                "ByteMatchStatement": {
                    "SearchString": "/api/auth",
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                    "PositionalConstraint": "STARTS_WITH"
                }
            }
        }
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "RateLimitLogin"
    }
}

# Regra customizada 2: Geoblocking para países de alto risco
geo_block_rule = {
    "Name": "MeridianGeoBlock",
    "Priority": 11,
    "Action": {"Block": {}},
    "Statement": {
        "GeoMatchStatement": {
            "CountryCodes": ["KP", "IR", "SY", "RU", "BY", "MM", "SD"]
        }
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "GeoBlock"
    }
}

# Regra customizada 3: Bloquear User-Agents de scanners
scanner_block_rule = {
    "Name": "MeridianBlockScanners",
    "Priority": 12,
    "Action": {"Block": {}},
    "Statement": {
        "RegexMatchStatement": {
            "RegexString": "(?i)(sqlmap|nikto|nessus|masscan|nmap|dirbuster|gobuster|hydra|medusa|w3af)",
            "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
        }
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "BlockScanners"
    }
}

all_rules = current_rules + [rate_limit_rule, geo_block_rule, scanner_block_rule]

response = waf.update_web_acl(
    Name=WEB_ACL_NAME,
    Scope='REGIONAL',
    Id=WEB_ACL_ID,
    DefaultAction={'Allow': {}},
    Rules=all_rules,
    VisibilityConfig={
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "MeridianInternetBankingWebACL"
    },
    LockToken=lock_token
)

print("Regras customizadas adicionadas")
print(f"Total de regras: {len(all_rules)}")
```

---

## Seção 4 — Associar WAF ao ALB

**Passo 4.1** — Associar Web ACL ao ALB:

```bash
# Obter ARN do ALB
ALB_ARN=$(aws elbv2 describe-load-balancers \
  --region sa-east-1 \
  --query 'LoadBalancers[?contains(LoadBalancerName, `internetbanking`)].LoadBalancerArn | [0]' \
  --output text)

echo "ALB ARN: $ALB_ARN"

# Associar Web ACL ao ALB
aws wafv2 associate-web-acl \
  --web-acl-arn $WEB_ACL_ARN \
  --resource-arn $ALB_ARN \
  --region sa-east-1

echo "Web ACL associada ao ALB: $ALB_ARN"
```

---

## Seção 5 — Configurar WAF Logging

**Passo 5.1** — Criar bucket de logs e configurar logging:

```bash
# Criar bucket para logs WAF (nome deve começar com aws-waf-logs-)
WAF_LOG_BUCKET="aws-waf-logs-meridian-internetbanking-$(date +%s)"

aws s3api create-bucket \
  --bucket $WAF_LOG_BUCKET \
  --region sa-east-1 \
  --create-bucket-configuration LocationConstraint=sa-east-1

aws s3api put-public-access-block \
  --bucket $WAF_LOG_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Habilitar logging WAF
aws wafv2 put-logging-configuration \
  --region sa-east-1 \
  --logging-configuration "{
    \"ResourceArn\": \"$WEB_ACL_ARN\",
    \"LogDestinationConfigs\": [\"arn:aws:s3:::$WAF_LOG_BUCKET\"],
    \"LoggingFilter\": {
      \"DefaultBehavior\": \"KEEP\",
      \"Filters\": [{
        \"Behavior\": \"KEEP\",
        \"Conditions\": [{
          \"ActionCondition\": {\"Action\": \"BLOCK\"}
        }],
        \"Requirement\": \"MEETS_ANY\"
      }]
    }
  }"

echo "WAF Logging habilitado para: $WAF_LOG_BUCKET"
```

---

## Seção 6 — Testes de Efetividade

**Passo 6.1** — Testes usando curl:

```bash
ALB_URL="https://internetbanking.bancomeridian.com.br"  # substituir pela URL real

echo "=== TESTE 1: SQL Injection ==="
curl -s -o /dev/null -w "%{http_code}" \
  "$ALB_URL/api/login?user=admin'%20OR%201=1--" \
  -H "User-Agent: Mozilla/5.0"
# Esperado: 403 (bloqueado pelo SQLi rule)

echo ""
echo "=== TESTE 2: XSS ==="
curl -s -o /dev/null -w "%{http_code}" \
  "$ALB_URL/api/search?q=<script>alert(1)</script>" \
  -H "User-Agent: Mozilla/5.0"
# Esperado: 403 (bloqueado pelo CommonRuleSet)

echo ""
echo "=== TESTE 3: Scanner User-Agent ==="
curl -s -o /dev/null -w "%{http_code}" \
  "$ALB_URL/" \
  -H "User-Agent: sqlmap/1.7"
# Esperado: 403 (bloqueado pelo BlockScanners rule)

echo ""
echo "=== TESTE 4: Request Legítimo ==="
curl -s -o /dev/null -w "%{http_code}" \
  "$ALB_URL/" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
# Esperado: 200 (permitido)
```

**Passo 6.2** — Teste de Rate Limiting:

```bash
echo "=== TESTE 5: Rate Limit no endpoint de login ==="
echo "Enviando 60 requisições em 5 minutos..."

SUCCESS=0; BLOCKED=0
for i in $(seq 1 60); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$ALB_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"test","pass":"test"}')
  
  if [ "$STATUS" = "403" ] || [ "$STATUS" = "429" ]; then
    BLOCKED=$((BLOCKED+1))
  else
    SUCCESS=$((SUCCESS+1))
  fi
  sleep 3  # 3 segundos entre requests
done

echo "Permitidas: $SUCCESS | Bloqueadas: $BLOCKED"
# Após ~50 requests: bloqueado
```

---

## Seção 7 — Dashboard de Métricas WAF

```python
import boto3
from datetime import datetime, timedelta, timezone

def dashboard_waf(web_acl_name, region='sa-east-1'):
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)
    
    metricas = [
        ('AllowedRequests', 'Requests permitidas'),
        ('BlockedRequests', 'Requests bloqueadas'),
        ('RateLimitLogin', 'Rate limit login ativado'),
        ('GeoBlock', 'Países bloqueados'),
        ('BlockScanners', 'Scanners bloqueados'),
        ('SQLiRuleSet', 'SQLi detectado'),
        ('CommonRuleSet', 'XSS/outros bloqueados')
    ]
    
    print(f"\n=== DASHBOARD WAF — {web_acl_name} ===")
    print(f"Período: Últimas 24 horas\n")
    
    for metrica_nome, descricao in metricas:
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/WAFV2',
            MetricName=metrica_nome,
            Dimensions=[
                {'Name': 'WebACL', 'Value': web_acl_name},
                {'Name': 'Region', 'Value': region},
                {'Name': 'Rule', 'Value': metrica_nome}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 24 horas
            Statistics=['Sum']
        )
        
        total = sum(dp['Sum'] for dp in response['Datapoints'])
        print(f"  {descricao:40s}: {int(total):>8,}")
    
    print("\n" + "=" * 60)

dashboard_waf('MeridianInternetBanking-WebACL')
```

---

## Seção 8 — Cleanup

```bash
# Desassociar Web ACL do ALB
aws wafv2 disassociate-web-acl \
  --resource-arn $ALB_ARN \
  --region sa-east-1

# Remover logging
aws wafv2 delete-logging-configuration \
  --resource-arn $WEB_ACL_ARN \
  --region sa-east-1

# Deletar Web ACL
LOCK=$(aws wafv2 get-web-acl \
  --name $WEB_ACL_NAME \
  --scope REGIONAL \
  --id $WEB_ACL_ID \
  --region sa-east-1 \
  --query 'LockToken' \
  --output text)

aws wafv2 delete-web-acl \
  --name MeridianInternetBanking-WebACL \
  --scope REGIONAL \
  --id $WEB_ACL_ID \
  --lock-token $LOCK \
  --region sa-east-1

# Remover bucket de logs WAF
aws s3 rb s3://$WAF_LOG_BUCKET --force

echo "Cleanup concluído"
```

---

## Gabarito — Validação das Regras

| Regra | Teste | Status HTTP Esperado |
|---|---|---|
| AWSManagedRulesSQLiRuleSet | `?q=1' OR 1=1--` | 403 |
| AWSManagedRulesCommonRuleSet | `<script>alert(1)</script>` | 403 |
| MeridianBlockScanners | User-Agent: `sqlmap/1.7` | 403 |
| MeridianRateLimitLogin | 60+ requests em 5 min para `/api/auth` | 403 após o 50° |
| MeridianGeoBlock | Request de IP russo (simulado) | 403 |
| Request Legítima | Browser normal, URL válida | 200 |
| WAF Logging | Verificar bucket WAF logs | Logs presentes em S3 |
