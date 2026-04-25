# Lab 07 — WAF Customizado para Internet Banking

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 07 — Segurança de Rede
**Nível:** Avançado

---

## Seção 1 — Contexto Situacional

O Banco Meridian lançou o portal de internet banking há três meses. Nas primeiras semanas após o lançamento, o time de infraestrutura recebeu relatórios de lentidão intermitente — que depois foram identificados como tentativas de ataque: bots fazendo scraping de dados de taxa de câmbio, scripts tentando enumerar contas por força bruta no endpoint de login, e uma tentativa de SQL injection que foi bloqueada apenas pelo firewall de banco de dados.

O portal está crescendo: 45.000 clientes ativos, com pico de 8.000 requisições por segundo durante o horário comercial. Não há WAF configurado — o único controle de borda é um Security Group restrito. A ausência de WAF é um finding CRITICAL no Security Hub (controle CIS 10.1 — WAF em aplicações web críticas).

O CISO determinou que o WAF precisa estar operacional antes do próximo lançamento de feature, que acontecerá em 14 dias.

---

## Seção 2 — Situação Inicial

É terça-feira, 22 de abril de 2026, 14h00. Você abre o relatório semanal de segurança da aplicação gerado pelo time de infraestrutura:

```
INTERNET BANKING — RELATÓRIO DE TRÁFEGO (14-21/04/2026)
────────────────────────────────────────────────────────────────
 Total de requisições:    12.847.500
 Requisições suspeitas identificadas manualmente: 284.300 (2.2%)
 Tentativas de login com senha incorreta:          189.400
 IPs com > 1.000 reqs/hora:                        47

 Ataques identificados (sem bloqueio automático):
 ├── SQL Injection tentativas:  1.247
 ├── XSS tentativas:              892
 ├── Path traversal tentativas:   345
 ├── Bot scraping de cotações:  31.200 requisições
 └── Credential stuffing no /login: 14.800 tentativas

 WAF ativo:      NÃO
 Rate limiting:  NÃO (apenas no nginx — sem granularidade por IP)
────────────────────────────────────────────────────────────────
```

Mariana comenta na reunião de segurança das 14h30:

> "Esses números são alarmantes. Temos mais de 14 mil tentativas de credential stuffing na semana sem nenhum bloqueio automático. Se o atacante acertar uma credencial válida, não temos nenhuma defesa de borda. Precisamos do WAF hoje."

Carlos adiciona:

> "Os bots de scraping de cotações estão gerando 31 mil requisições extras por semana — isso é custo de infraestrutura e risco de exposição de dados de mercado. Um rate limit teria bloqueado isso completamente."

---

## Seção 3 — Problema Identificado

**14h45 — Análise dos logs do ALB para quantificar o problema:**

```bash
# Analisar logs do ALB para identificar padrões de ataque
aws logs filter-log-events \
  --log-group-name /meridian/alb/access-logs \
  --filter-pattern '{ $.request_uri = "/login" && $.request_processing_time > 0.5 }' \
  --query 'events[0:10].{IP:message}' \
  --start-time $(date -d '7 days ago' +%s000)
```

O diagnóstico identifica 5 problemas distintos:

1. **Sem proteção OWASP Top 10:** SQL injection, XSS e path traversal chegam ao servidor de aplicação sem filtragem de borda
2. **Sem rate limiting por IP:** um único IP pode fazer milhares de requisições ao `/login` em minutos — credential stuffing sem fricção
3. **Sem bloqueio geográfico:** o BACEN exige que o internet banking só seja acessível a partir do Brasil (clientes estrangeiros devem usar canais específicos)
4. **Sem bot management:** scrapers automatizados consomem recursos e expõem dados de mercado sem controle
5. **Sem logging estruturado de WAF:** sem WAF, não há como rastrear ataques bloqueados nem gerar relatórios para auditoria

**Mapeamento MITRE ATT&CK:**
- **T1110.004** (Credential Stuffing) → resolvido por Rate Limiting no `/login`
- **T1190** (Exploit Public-Facing Application) → resolvido por Managed Rules OWASP
- **T1596** (Search Open Technical Databases) → resolvido por Bot Control e Rate Limiting
- **T1530** (Data from Cloud Storage Object) → rate limiting impede scraping massivo

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Implementar o AWS WAF v2 completo para o portal de internet banking, com Managed Rules para OWASP Top 10, Rate Limiting por IP para o endpoint de login, bloqueio geográfico, WAF Logging centralizado, e testes de efetividade.

**Atividades deste laboratório:**

1. Criar a Web ACL base com default action Allow
2. Adicionar AWS Managed Rule Groups (Core Rule Set, Known Bad Inputs, SQL Database)
3. Criar regra customizada de Rate Limiting no `/login` — 100 reqs/5min por IP
4. Criar regra de bloqueio geográfico (apenas BR)
5. Criar regra de bloqueio de IPs maliciosos via IP Set
6. Associar o WAF ao ALB do internet banking
7. Configurar WAF Logging com Kinesis Firehose → S3 centralizado
8. Executar testes de efetividade das regras criadas
9. Criar dashboard CloudWatch para métricas do WAF

---

## Seção 5 — Proposição do Desafio

Ao final do laboratório, Carlos vai executar uma série de testes de ataque contra o ALB:

1. Um payload SQL injection: `' OR 1=1 --` no campo de login
2. Um payload XSS: `<script>alert('xss')</script>` em campo de formulário
3. 150 requisições ao `/login` em 30 segundos do mesmo IP (credential stuffing)
4. Uma requisição com User-Agent de scanner conhecido: `sqlmap/1.6`
5. Uma requisição vindo de IP de fora do Brasil (simulado via header `x-forwarded-for`)

Para cada teste, você deve mostrar no painel do WAF o request bloqueado, a regra que bloqueou, e o log estruturado no S3.

**Critério de aprovação:** Os 5 testes devem ser bloqueados pelo WAF com ação `BLOCK` — não `ALLOW` ou `COUNT`. Requisições com ação `COUNT` significam que a regra está em modo de monitoramento, não de bloqueio.

---

## Contexto Técnico

O Banco Meridian lançou um novo portal de internet banking em produção. Você precisa configurar o AWS WAF v2 para proteger a aplicação contra o OWASP Top 10, implementar rate limiting geográfico, configurar logging completo e realizar testes de efetividade das regras.

A aplicação está exposta via Application Load Balancer (ALB) na conta Production (444444444444), região sa-east-1.

---

## Pré-requisitos

- ALB criado e funcionando (ou simular)
- AWS CLI e Python com Boto3
- Acesso de admin à conta Production

---

## Seção 1 — Criar Web ACL Base

### Passo 1.1 — Criar a Web ACL com default action Allow

**O que este passo faz:** Cria a Web ACL (Web Access Control List) — o container de regras do AWS WAFv2 que avaliará cada requisição HTTP ao internet banking do Banco Meridian. O parâmetro `--default-action Allow` define o comportamento padrão: requisições que não correspondem a nenhuma regra são permitidas. Isso é o correto para implantação inicial — se a default action fosse `Block`, qualquer requisição sem regra específica seria bloqueada, causando indisponibilidade imediata. O `--scope REGIONAL` indica que a Web ACL será associada a recursos regionais (ALB, API Gateway) — diferente do `CLOUDFRONT` que seria para CloudFront distributions. O `LockToken` retornado é o mecanismo de concorrência otimista do WAFv2 — necessário para atualizações (add-rules, update-rules).

**Por que esta ordem:** A Web ACL deve existir antes de adicionar regras. O `LockToken` é exportado agora porque expira periodicamente e deve ser re-consultado a cada operação de atualização.

**Por que isso importa para o Banco Meridian:** Esta é a estrutura que vai proteger os 45.000 clientes do internet banking do Banco Meridian das 14.587 tentativas de credential stuffing da última semana. A Web ACL é o ponto de controle único entre a internet e o ALB — todas as 8.000 requisições por segundo no horário de pico passam por ela. A decisão de usar `default-action: Allow` com regras de bloqueio específicas (em vez de `default-action: Block` com regras de permissão) é deliberada: é muito mais fácil definir o que bloquear do que enumerar todo o tráfego legítimo.

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

### Passo 2.1 — Adicionar Managed Rule Groups da AWS ao Web ACL via Python

**O que este passo faz:** Script Python que atualiza a Web ACL criada no Passo 1.1 adicionando quatro Managed Rule Groups da AWS: (1) `AWSManagedRulesCommonRuleSet` — proteção base OWASP Top 10; (2) `AWSManagedRulesKnownBadInputsRuleSet` — bloqueia inputs com padrões de exploits conhecidos (Log4Shell, Spring4Shell); (3) `AWSManagedRulesSQLiRuleSet` — proteção específica contra SQL injection com detecção de bypass; (4) `AWSManagedRulesAmazonIpReputationList` — bloqueia IPs com reputação negativa nos feeds proprietários da AWS. O script usa o `LockToken` atual da Web ACL (obtido dinamicamente via `get-web-acl`) — se o token estiver desatualizado, a operação falha com `WAFOptimisticLockException`.

**Por que esta ordem:** O `LockToken` deve ser consultado imediatamente antes de cada `update-web-acl` — tokens expiram rapidamente se outra operação modificou a Web ACL nesse intervalo. O script Python é preferível ao CLI para esta operação porque o JSON de update é complexo e difícil de formatar corretamente no shell.

**Por que isso importa para o Banco Meridian:** Estas quatro regras gerenciadas cobrem automaticamente a maioria das tentativas de exploração web registradas pela FEBRABAN em 2025-2026. A atualização automática pela AWS garante que novas assinaturas de ataques (ex: CVEs de dias zero) sejam incorporadas sem manutenção manual pelo time de segurança — reduzindo o custo operacional de manutenção da lista de regras.

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

### Passo 3.1 — Rate Limiting customizado para o endpoint de login (/api/auth/login)

**O que este passo faz:** Adiciona uma regra customizada que limita o número de requisições ao endpoint de autenticação (`/api/auth/login`) a 100 por IP em 5 minutos. A regra usa o tipo `RATE_BASED` com `AggregateKeyType: IP` — cada endereço IP tem seu próprio contador independente. A chave `ScopeDownStatement` com `ByteMatchStatement` garante que o limite se aplica APENAS ao endpoint `/api/auth/login` — não limita acesso a outras páginas do internet banking. O `LockToken` é re-consultado no início do script para garantir que está atualizado antes do update.

**Por que esta ordem:** A regra customizada deve ter prioridade após as Managed Rules (Priority 10-13) para que IPs já bloqueados por reputação não consumam processamento de Rate Limiting. A prioridade 20 garante que esta regra seja avaliada apenas para IPs que passaram pelas verificações de reputação anteriores.

**Por que isso importa para o Banco Meridian:** As 14.587 tentativas de credential stuffing da semana usaram bots com rotação de IPs. Sem Rate Limiting, cada IP tenta centenas de combinações antes da detecção. Com esta regra, o bloqueio ocorre após 100 tentativas em 5 minutos — imperceptível para clientes legítimos (que raramente erram a senha mais de 3 vezes), mas bloqueante para bots automatizados. Esta é a implementação do requisito BACEN 4.893 Art. 4: "controles de acesso que previnam tentativas repetidas de autenticação".

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

### Passo 4.1 — Associar Web ACL ao ALB do internet banking

**O que este passo faz:** Associa a Web ACL criada e configurada (Passos 1.1-3.1) ao Application Load Balancer que distribui tráfego para o internet banking do Banco Meridian. Antes da associação, o ALB aceita qualquer tráfego HTTP/HTTPS sem nenhuma inspeção de conteúdo. Após a associação, CADA requisição que chega ao ALB é avaliada pelo WAF ANTES de ser encaminhada para as instâncias de back-end. O primeiro comando identifica o ARN do ALB pelo nome — necessário porque o `associate-web-acl` requer o ARN completo, não o nome do recurso.

**Por que esta ordem:** A Web ACL deve estar completamente configurada (todas as regras adicionadas) ANTES da associação ao ALB. Associar o WAF antes de adicionar as regras de Rate Limiting significaria um período onde o WAF está ativo mas sem a proteção de Rate Limiting — uma janela de proteção incompleta.

**Por que isso importa para o Banco Meridian:** Até este passo, todas as configurações de WAF existem mas não estão protegendo nada. A associação ao ALB é o momento em que a proteção entra em vigor. Para os 45.000 clientes do internet banking, este é o passo que resolve o problema relatado na Seção 3 — as 14.587 tentativas de credential stuffing agora serão interceptadas pelo WAF antes de chegarem aos servidores de autenticação.

**Permissão IAM necessária:** `wafv2:AssociateWebACL` e `elasticloadbalancing:DescribeLoadBalancers` na conta Production (444444444444).

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

### Passo 5.1 — Criar bucket de logs e habilitar WAF Logging centralizado

**O que este passo faz:** O bucket S3 para logs do WAF tem um requisito específico: o nome DEVE começar com `aws-waf-logs-` — sem este prefixo, o WAFv2 rejeita a configuração com erro. Após criar o bucket, o `put-logging-configuration` habilita o envio de logs de todas as requisições avaliadas pelo WAF ao bucket especificado. Os logs são entregues em formato JSON comprimido (`.json.gz`) com até 5 minutos de latência. Cada registro de log contém: timestamp, IP do cliente, URI, método HTTP, ação tomada (Allow/Block), qual regra triggou, e os campos de cabeçalho inspecionados.

**Por que esta ordem:** O bucket deve existir antes do `put-logging-configuration`. O WAF não cria o bucket automaticamente — ele apenas valida que o ARN fornecido aponta para um bucket acessível com a bucket policy correta.

**Por que isso importa para o Banco Meridian:** Os logs do WAF são a evidência de proteção para auditorias do BACEN e resposta a incidentes. Um analista investigando um credential stuffing pode consultar os logs para ver todos os IPs que tentaram o endpoint `/api/auth/login` nas últimas 24 horas, filtrar os bloqueados (campo `action: BLOCK`) e os permitidos, e identificar IPs suspeitos que passaram pela proteção para investigação adicional com GuardDuty.

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

### Passo 6.1 — Testes de efetividade com curl

**O que este passo faz:** Executa testes automatizados que validam a efetividade das regras WAF configuradas. Os testes cubem os principais vetores de ataque: SQL injection (payload `' OR 1=1--`), XSS (payload `<script>alert(1)</script>`), e acesso com User-Agent de scanner malicioso. O código HTTP retornado indica o resultado: 200 significa que a requisição passou pelo WAF (ou foi bloqueada pelo back-end por outros motivos); 403 significa que o WAF bloqueou a requisição antes de chegar ao back-end.

**Por que esta ordem:** Os testes devem ser executados após a associação do WAF ao ALB (Passo 4.1) e após todas as regras estarem configuradas. Testar antes pode validar um estado incompleto.

**O que você deve ver:** SQL injection → 403; XSS → 403; Scanner UA → 403; requisição legítima → 200.

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

## Seção 9 — Gabarito Completo com Raciocínio

### Criação da Web ACL — Resposta Correta

**Por que default action = ALLOW (não BLOCK):**
Uma Web ACL com `DefaultAction: BLOCK` bloquearia TODAS as requisições que não correspondem a nenhuma regra de Allow explícita. No contexto do internet banking com 45.000 clientes, essa configuração quebraria o acesso legítimo imediatamente. A abordagem correta é:
- `DefaultAction: ALLOW` — tudo passa por padrão
- Regras de `BLOCK` específicas para padrões maliciosos conhecidos
- Regras de Rate Limit para proteção adaptativa

O resultado é: requisições legítimas passam normalmente, ataques conhecidos são bloqueados.

**Verificação correta:**
```bash
aws wafv2 get-web-acl \
  --name MeridianInternetBanking \
  --scope REGIONAL \
  --id $WEB_ACL_ID \
  --region sa-east-1 \
  --query 'WebACL.{DefaultAction:DefaultAction,NumRules:Rules|length(@)}'
# Esperado: {"DefaultAction": {"Allow": {}}, "NumRules": 5 ou mais}
```

---

### Rate Limiting no /login — Resposta Correta

**Configuração correta:**
```json
{
  "Name": "MeridianRateLimitLogin",
  "Priority": 1,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "FieldToMatch": {"UriPath": {}},
          "PositionalConstraint": "STARTS_WITH",
          "SearchString": "/login",
          "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
        }
      }
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {"SampledRequestsEnabled": true, ...}
}
```

**Por que 100 requisições em 5 minutos:** O WAF conta requisições em janelas de 5 minutos. Um usuário legítimo fazendo login com erro de senha tipicamente faz 3-5 tentativas. Um atacante de credential stuffing faz centenas por minuto. O limite de 100 em 5 minutos permite 20 tentativas por minuto — muito acima do comportamento humano, mas bem abaixo do comportamento de bot.

**Por que `ScopeDownStatement`:** Limitar o rate limit ao path `/login` evita bloquear clientes legítimos navegando outras páginas do portal. Sem o `ScopeDownStatement`, o limite se aplicaria a TODAS as requisições do IP — um usuário navegando o portal ativamente poderia ser bloqueado.

**Erros comuns:**
- Usar `AggregateKeyType: FORWARDED_IP` em vez de `IP`: `FORWARDED_IP` usa o cabeçalho `X-Forwarded-For`, que pode ser facilmente falsificado por um atacante — usar `IP` (IP real da conexão) é mais seguro
- Limite muito baixo (< 30): bloqueia usuários legítimos com conexão lenta que recarregam a página
- Esquecer o `TextTransformations: LOWERCASE`: `/Login` e `/LOGIN` não corresponderiam ao padrão `/login` sem essa transformação

---

### Bloqueio Geográfico — Resposta Correta

**Por que GeoMatchStatement (não GeoBlock via IP Set):**
O `GeoMatchStatement` usa a banco de dados de geolocalização da AWS, atualizada automaticamente. Um IP Set manual exigiria atualização constante com bilhões de IPs — inviável. A AWS mantém esse banco atualizado automaticamente.

```json
{
  "Name": "MeridianGeoBlock",
  "Priority": 2,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": ["BR"]
        }
      }
    }
  },
  "Action": {"Block": {}}
}
```

**Por que `NotStatement` com `CountryCodes: ["BR"]` em vez de listar todos os países bloqueados:** Listar todos os países não-BR exigiria 194 entradas e precisaria ser atualizado quando novos países surgem ou são extintos. `NotStatement` com `CountryCodes: ["BR"]` bloqueia automaticamente qualquer país que não seja Brasil — mais simples e à prova de futuro.

---

### Validação das Regras — Resultados Corretos

| Regra | Teste | Status HTTP Correto | Regra que bloqueia |
|---|---|---|---|
| `AWSManagedRulesSQLiRuleSet` | `?q=1' OR 1=1--` | `403 Forbidden` | `SQLi_BODY` ou `SQLi_QUERYSTRING` |
| `AWSManagedRulesCommonRuleSet` | `<script>alert(1)</script>` | `403 Forbidden` | `XSS_BODY` |
| `MeridianBlockScanners` | User-Agent: `sqlmap/1.7` | `403 Forbidden` | Regra customizada UserAgent |
| `MeridianRateLimitLogin` | 150 reqs ao `/login` em 30s | `403` após a 100ª requisição | RateBased rule |
| `MeridianGeoBlock` | IP fora do Brasil | `403 Forbidden` | GeoMatch NOT BR |
| Request legítima | GET /home com browser normal | `200 OK` | Nenhuma — DefaultAction Allow |
| WAF Logging | Verificar S3 após 5 min | Logs `.json.gz` no bucket | N/A |

**Nota sobre `COUNT` vs `BLOCK`:** Se qualquer teste retornar `200 OK` em vez de `403`, a regra está em modo `COUNT` (monitoramento) em vez de `BLOCK`. Verificar a `Action` na regra — deve ser `{"Block": {}}`, não `{"Count": {}}`.

**Interpretação do log WAF:**
```json
{
  "timestamp": 1713802800000,
  "action": "BLOCK",              // BLOCK = regra funcionando
  "httpSourceId": "alb-meridian-prod",
  "terminatingRuleId": "MeridianRateLimitLogin",
  "terminatingRuleType": "RATE_BASED",
  "httpRequest": {
    "clientIp": "189.45.132.77",  // IP do atacante
    "uri": "/login",              // Endpoint alvo
    "method": "POST",
    "requestId": "1-6603e3f0-..."
  },
  "rateBasedRuleList": [{
    "rateBasedRuleName": "MeridianRateLimitLogin",
    "limitKey": "189.45.132.77", // IP que disparou o limite
    "maxRateAllowed": 100,        // Limite configurado
    "evaluationWindowSec": 300    // Janela de 5 minutos
  }]
}
```

**Critérios de Aprovação:**
- Web ACL associada ao ALB: OBRIGATÓRIO
- Todos os 5 testes retornando 403: OBRIGATÓRIO
- WAF Logging ativo com logs visíveis no S3: OBRIGATÓRIO
- Rate limit bloqueando após o limite correto (100 requisições): OBRIGATÓRIO
- GeoBlock funcionando para IPs não-BR: OBRIGATÓRIO
