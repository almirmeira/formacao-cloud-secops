# Lab 06 — Automações de Resposta: Chave IAM, EC2, WAF

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 08 — Automação de Resposta
**Nível:** Avançado

---

## Seção 0 — Contexto Situacional e Situação Inicial

### Contexto Situacional

Após o incidente investigado no Lab 05 — onde a instância comprometida ficou ativa por 2 horas antes de qualquer contenção — o CISO emitiu uma diretriz: o Banco Meridian não pode mais depender de intervenção humana para contenção inicial de incidentes. O MTTR (Mean Time to Respond) atual é de 2h09m. A meta estabelecida é de menos de 5 minutos para contenção de findings HIGH do GuardDuty.

A solução é automação de resposta: EventBridge captura o finding, aciona uma Lambda function que executa a contenção (revogação de credenciais, isolamento de instância, bloqueio de IP), e envia notificação ao time de segurança — tudo em segundos, sem intervenção humana.

### Situação Inicial

É segunda-feira, 21 de abril de 2026, 10h00. Mariana abre a reunião de planejamento com os números do incidente de abril:

```
MÉTRICAS DE RESPOSTA A INCIDENTE — ANTES DA AUTOMAÇÃO
─────────────────────────────────────────────────────────────
 MTTR atual:             2h09m  (meta: < 5 minutos)
 Findings HIGH não atendidos em < 30min:  67%
 Tentativas de credential exfiltration:   3 (último mês)
 Instâncias isoladas manualmente:         1 (Lab 05)
 Tempo médio para isolamento manual:      38 minutos
─────────────────────────────────────────────────────────────
 Estado das automações de IR:   NENHUMA IMPLEMENTADA
 EventBridge rules ativas:      0
 Lambda functions de IR:        0
─────────────────────────────────────────────────────────────
```

> "Após o incidente do Lab 05, ficou claro que confiar apenas em intervenção humana para contenção inicial não é aceitável. Um atacante com credenciais de instância tem menos de 5 minutos para causar dano irreversível. Nossa resposta de 2 horas é completamente inadequada para ameaças modernas."

Carlos complementa:

> "O GuardDuty está gerando findings mas não há nenhuma ação automática. Cada finding HIGH fica esperando alguém ver no console. Precisamos de automação que contenha o dano enquanto a equipe faz a investigação completa."

Você recebe três tickets simultâneos:
- **SECOPS-2061:** Automação para desabilitar credencial IAM comprometida (SLA: 5 min)
- **SECOPS-2062:** Automação para isolar instância EC2 com C2 detectado (SLA: 5 min)
- **SECOPS-2063:** Automação para bloquear IP malicioso no WAF automaticamente (SLA: 2 min)

---

### Problema Identificado

As três automações resolvem três vetores diferentes de ataque identificados no histórico de incidentes do Banco Meridian:

| Automação | Vetor de Ataque | Finding Trigger | Tempo Atual de Resposta | Meta |
|---|---|---|---|---|
| 1 — Desabilitar Chave IAM | Credencial longa duração comprometida | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | 38 min | < 2 min |
| 2 — Isolar EC2 | Instância com backdoor/C2 | `Backdoor:EC2/C&CActivity.B` (HIGH) | 38 min | < 3 min |
| 3 — Bloquear IP no WAF | IP malicioso atacando aplicações web | `Recon:EC2/PortProbeUnprotectedPort` + IP em feed ameaças | Manual (indefinido) | < 1 min |

**Mapeamento MITRE ATT&CK:**
- **T1078.004** (Valid Accounts: Cloud Accounts) → Automação 1 bloqueia a credencial comprometida
- **T1071** (Application Layer Protocol: Web Shell) → Automação 2 isola a instância com backdoor
- **T1190** (Exploit Public-Facing Application) → Automação 3 bloqueia o IP atacante no WAF

Você vai implementar 3 automações de resposta a incidentes completas para o Banco Meridian:

1. **Automação 1:** Desabilitar chave IAM exposta (trigger: GuardDuty finding de credencial comprometida)
2. **Automação 2:** Isolar instância EC2 comprometida (trigger: GuardDuty finding HIGH em EC2)
3. **Automação 3:** Bloquear IP malicioso no WAF (trigger: GuardDuty finding com IP externo)

---

## Pré-requisitos

- GuardDuty habilitado na conta Audit
- EventBridge configurado
- AWS Lambda com Python 3.12
- SNS topic criado para notificações
- WAF v2 Web ACL com IP Set criado

---

## Seção 1 — Infraestrutura Base

**Passo 1.1** — Criar roles IAM para as Lambdas:

```bash
# Role para Lambda de desabilitar chave IAM
cat > /tmp/trust-lambda.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Role 1: Disable IAM Key
aws iam create-role \
  --role-name LambdaIR-DisableIAMKey \
  --assume-role-policy-document file:///tmp/trust-lambda.json

aws iam put-role-policy \
  --role-name LambdaIR-DisableIAMKey \
  --policy-name DisableKeyPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": ["iam:UpdateAccessKey","iam:ListAccessKeys","iam:PutUserPolicy","iam:TagUser"], "Resource": "*"},
      {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"},
      {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*"}
    ]
  }'

# Role 2: Isolate EC2
aws iam create-role \
  --role-name LambdaIR-IsolateEC2 \
  --assume-role-policy-document file:///tmp/trust-lambda.json

aws iam put-role-policy \
  --role-name LambdaIR-IsolateEC2 \
  --policy-name IsolateEC2Policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": ["ec2:CreateSecurityGroup","ec2:AuthorizeSecurityGroupIngress","ec2:RevokeSecurityGroupEgress","ec2:ModifyInstanceAttribute","ec2:CreateSnapshot","ec2:CreateTags","ec2:Describe*"], "Resource": "*"},
      {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"},
      {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*"}
    ]
  }'

# Role 3: Block WAF IP
aws iam create-role \
  --role-name LambdaIR-BlockWAFIP \
  --assume-role-policy-document file:///tmp/trust-lambda.json

aws iam put-role-policy \
  --role-name LambdaIR-BlockWAFIP \
  --policy-name BlockWAFIPPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": ["wafv2:GetIPSet","wafv2:UpdateIPSet"], "Resource": "*"},
      {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"},
      {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*"}
    ]
  }'

echo "Roles IAM criadas"
```

**Passo 1.2** — Criar SNS Topics:

```bash
SNS_CRITICO=$(aws sns create-topic \
  --name MeridianSecurityAlerts-CRITICO \
  --region sa-east-1 \
  --query 'TopicArn' \
  --output text)

SNS_HIGH=$(aws sns create-topic \
  --name MeridianSecurityAlerts-HIGH \
  --region sa-east-1 \
  --query 'TopicArn' \
  --output text)

# Subscrever email (substituir pelo email real)
aws sns subscribe --topic-arn $SNS_CRITICO --protocol email --notification-endpoint "secops@bancomeridian.com.br"
aws sns subscribe --topic-arn $SNS_HIGH --protocol email --notification-endpoint "secops@bancomeridian.com.br"

echo "SNS Topics: $SNS_CRITICO | $SNS_HIGH"
```

---

## Seção 2 — Automação 1: Desabilitar Chave IAM Comprometida

**Passo 2.1** — Criar o código Lambda:

```bash
cat > /tmp/lambda_disable_key.py << 'PYEOF'
import boto3
import json
import logging
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_CRITICO = "arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-CRITICO"

def handler(event, context):
    iam = boto3.client('iam')
    sns = boto3.client('sns', region_name='sa-east-1')
    
    # Extrair informações do evento GuardDuty
    finding = event.get('detail', {})
    access_key_id = (
        finding.get('resource', {}).get('accessKeyDetails', {}).get('accessKeyId')
        or event.get('access_key_id')
    )
    user_name = (
        finding.get('resource', {}).get('accessKeyDetails', {}).get('userName')
        or event.get('user_name')
    )
    
    if not access_key_id or not user_name:
        logger.error(f"Dados insuficientes: access_key_id={access_key_id}, user_name={user_name}")
        return {'statusCode': 400, 'body': 'access_key_id e user_name são obrigatórios'}
    
    logger.info(f"Processando: chave {access_key_id} do usuário {user_name}")
    
    # Verificar estado atual (idempotência)
    try:
        keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        key_info = next((k for k in keys if k['AccessKeyId'] == access_key_id), None)
        
        if not key_info:
            return {'status': 'KEY_NOT_FOUND', 'access_key_id': access_key_id}
        
        if key_info['Status'] == 'Inactive':
            logger.info(f"Chave já inativa — idempotente")
            return {'status': 'ALREADY_INACTIVE', 'access_key_id': access_key_id}
    except ClientError as e:
        logger.error(f"Erro ao verificar chave: {e}")
        raise
    
    # Desabilitar a chave
    iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Inactive')
    logger.info(f"Chave {access_key_id} desabilitada")
    
    # Revogar sessões ativas (deny inline policy)
    timestamp_agora = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": timestamp_agora}}
        }]
    }
    iam.put_user_policy(
        UserName=user_name,
        PolicyName='IR-RevokeActiveSessions',
        PolicyDocument=json.dumps(deny_policy)
    )
    
    # Notificar
    sns.publish(
        TopicArn=SNS_TOPIC_CRITICO,
        Subject=f'[IR CRÍTICO] Chave IAM Comprometida Desabilitada: {access_key_id}',
        Message=json.dumps({
            'acao': 'CHAVE_IAM_DESABILITADA',
            'usuario': user_name,
            'chave': access_key_id,
            'timestamp': timestamp_agora,
            'proximos_passos': [
                f'Investigar atividade no CloudTrail Lake: WHERE userIdentity.accessKeyId = "{access_key_id}"',
                'Verificar se novos usuários ou chaves foram criados',
                'Rotacionar todas as credenciais do usuário após investigação'
            ]
        }, indent=2, ensure_ascii=False)
    )
    
    return {'status': 'CONCLUIDO', 'chave_desabilitada': access_key_id, 'usuario': user_name}
PYEOF

# Empacotar e criar Lambda
cd /tmp && zip lambda_disable_key.zip lambda_disable_key.py
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws lambda create-function \
  --function-name MeridianIR-DisableIAMKey \
  --runtime python3.12 \
  --handler lambda_disable_key.handler \
  --zip-file fileb:///tmp/lambda_disable_key.zip \
  --role "arn:aws:iam::${ACCOUNT_ID}:role/LambdaIR-DisableIAMKey" \
  --timeout 300 \
  --memory-size 128 \
  --region sa-east-1 \
  --description "IR Automation: Desabilitar chave IAM comprometida"

echo "Lambda criada: MeridianIR-DisableIAMKey"
```

**Passo 2.2** — Criar EventBridge rule para triggerar a Lambda:

```bash
# Regra para UnauthorizedAccess findings em IAM
aws events put-rule \
  --name "IR-DisableCompromisedIAMKey" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        "UnauthorizedAccess:IAMUser/TorIPCaller",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
      ]
    }
  }' \
  --state ENABLED \
  --region sa-east-1

# Target: Lambda
LAMBDA_ARN=$(aws lambda get-function \
  --function-name MeridianIR-DisableIAMKey \
  --region sa-east-1 \
  --query 'Configuration.FunctionArn' \
  --output text)

aws events put-targets \
  --rule "IR-DisableCompromisedIAMKey" \
  --region sa-east-1 \
  --targets "[{\"Id\": \"DisableKeyLambda\", \"Arn\": \"$LAMBDA_ARN\"}]"

# Permissão para EventBridge invocar a Lambda
aws lambda add-permission \
  --function-name MeridianIR-DisableIAMKey \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --region sa-east-1

echo "EventBridge rule configurada para Automação 1"
```

---

## Seção 3 — Automação 2: Isolar EC2 Comprometida

**Passo 3.1** — Criar Lambda de isolamento (versão simplificada):

```bash
cat > /tmp/lambda_isolate_ec2.py << 'PYEOF'
import boto3
import json
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    ec2 = boto3.client('ec2', region_name='sa-east-1')
    sns = boto3.client('sns', region_name='sa-east-1')
    
    finding = event.get('detail', {})
    instance_id = (
        finding.get('resource', {}).get('instanceDetails', {}).get('instanceId')
        or event.get('instance_id')
    )
    finding_type = finding.get('type', 'Unknown')
    incident_id = f"AUTO-{int(time.time())}"
    
    if not instance_id:
        raise ValueError("instance_id não encontrado no evento")
    
    logger.info(f"Isolando instância: {instance_id}")
    
    # Obter VPC e SGs originais
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp['Reservations'][0]['Instances'][0]
    vpc_id = instance['VpcId']
    sgs_originais = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
    
    # Verificar idempotência
    tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
    if tags.get('Quarantine') == 'true':
        logger.info(f"Instância {instance_id} já está em quarentena")
        return {'status': 'ALREADY_QUARANTINED', 'instance_id': instance_id}
    
    # Criar snapshot de evidência
    volumes = [b['Ebs']['VolumeId'] for b in instance.get('BlockDeviceMappings', [])]
    snapshots = []
    for vol in volumes:
        snap = ec2.create_snapshot(
            VolumeId=vol,
            Description=f"IR-{incident_id}-{instance_id}",
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
                {'Key': 'IncidentId', 'Value': incident_id},
                {'Key': 'ForensicEvidence', 'Value': 'true'},
                {'Key': 'GuardDutyFinding', 'Value': finding_type}
            ]}]
        )
        snapshots.append(snap['SnapshotId'])
    
    # Criar SG de quarentena
    sg = ec2.create_security_group(
        GroupName=f'QUARENTENA-{incident_id}',
        Description=f'IR Quarantine {incident_id} - ZERO TRAFFIC',
        VpcId=vpc_id
    )
    sg_id = sg['GroupId']
    
    # Remover egress padrão
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )
    
    # Isolar instância
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
    
    # Tags
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'Quarantine', 'Value': 'true'},
        {'Key': 'IncidentId', 'Value': incident_id},
        {'Key': 'GuardDutyFinding', 'Value': finding_type},
        {'Key': 'IsolatedAt', 'Value': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
        {'Key': 'OriginalSGs', 'Value': ','.join(sgs_originais)}
    ])
    
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH',
        Subject=f'[IR] EC2 Isolada: {instance_id}',
        Message=json.dumps({
            'instancia': instance_id, 'finding': finding_type,
            'sg_quarentena': sg_id, 'sgs_originais': sgs_originais,
            'snapshots': snapshots, 'incident_id': incident_id
        }, indent=2)
    )
    
    return {'status': 'ISOLADO', 'instance_id': instance_id, 'sg_quarentena': sg_id}
PYEOF

zip /tmp/lambda_isolate_ec2.zip /tmp/lambda_isolate_ec2.py

aws lambda create-function \
  --function-name MeridianIR-IsolateEC2 \
  --runtime python3.12 \
  --handler lambda_isolate_ec2.handler \
  --zip-file fileb:///tmp/lambda_isolate_ec2.zip \
  --role "arn:aws:iam::${ACCOUNT_ID}:role/LambdaIR-IsolateEC2" \
  --timeout 300 \
  --region sa-east-1

echo "Lambda criada: MeridianIR-IsolateEC2"

# EventBridge rule para EC2 HIGH findings
aws events put-rule \
  --name "IR-IsolateCompromisedEC2" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}],
      "resource": {
        "resourceType": ["Instance"]
      }
    }
  }' \
  --state ENABLED \
  --region sa-east-1

LAMBDA_ARN_EC2=$(aws lambda get-function \
  --function-name MeridianIR-IsolateEC2 \
  --region sa-east-1 \
  --query 'Configuration.FunctionArn' \
  --output text)

aws events put-targets \
  --rule "IR-IsolateCompromisedEC2" \
  --region sa-east-1 \
  --targets "[{\"Id\": \"IsolateEC2Lambda\", \"Arn\": \"$LAMBDA_ARN_EC2\"}]"

aws lambda add-permission \
  --function-name MeridianIR-IsolateEC2 \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --region sa-east-1

echo "EventBridge rule configurada para Automação 2"
```

---

## Seção 4 — Automação 3: Bloquear IP no WAF

**Passo 4.1** — Criar WAF IP Set e Lambda:

```bash
# Criar IP Set no WAF para IPs bloqueados
WAF_IPSET=$(aws wafv2 create-ip-set \
  --name "MeridianBlockedIPs" \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses '[]' \
  --description "IPs bloqueados automaticamente por IR automation" \
  --region sa-east-1 \
  --query 'Summary.{Id:Id,Name:Name}' \
  --output json)

WAF_IPSET_ID=$(echo $WAF_IPSET | python3 -c "import json,sys; print(json.load(sys.stdin)['Id'])")
echo "WAF IP Set criado: $WAF_IPSET_ID"

cat > /tmp/lambda_block_waf.py << 'PYEOF'
import boto3
import json
import logging
import ipaddress

logger = logging.getLogger()
logger.setLevel(logging.INFO)

WAF_IP_SET_ID = "SUBSTITUIR_PELO_ID_REAL"
WAF_IP_SET_NAME = "MeridianBlockedIPs"

def handler(event, context):
    waf = boto3.client('wafv2', region_name='sa-east-1')
    sns = boto3.client('sns', region_name='sa-east-1')
    
    finding = event.get('detail', {})
    
    # Extrair IP de diferentes tipos de findings
    remote_ip = (
        finding.get('service', {}).get('action', {})
               .get('networkConnectionAction', {})
               .get('remoteIpDetails', {}).get('ipAddressV4')
        or finding.get('service', {}).get('action', {})
               .get('portProbeAction', {})
               .get('portProbeDetails', [{}])[0]
               .get('remoteIpDetails', {}).get('ipAddressV4')
        or event.get('remote_ip')
    )
    
    finding_type = finding.get('type', 'Unknown')
    
    if not remote_ip:
        logger.warning("Remote IP não encontrado no evento")
        return {'status': 'NO_IP_FOUND'}
    
    try:
        ip_obj = ipaddress.ip_address(remote_ip)
        cidr = f"{remote_ip}/32"
    except ValueError:
        raise ValueError(f"IP inválido: {remote_ip}")
    
    logger.info(f"Bloqueando IP: {cidr}")
    
    # Obter estado atual do IP Set
    ip_set_resp = waf.get_ip_set(
        Name=WAF_IP_SET_NAME, Scope='REGIONAL', Id=WAF_IP_SET_ID
    )
    lock_token = ip_set_resp['LockToken']
    current_addresses = ip_set_resp['IPSet']['Addresses']
    
    # Idempotência
    if cidr in current_addresses:
        logger.info(f"IP {cidr} já bloqueado")
        return {'status': 'ALREADY_BLOCKED', 'ip': cidr}
    
    # Adicionar IP
    waf.update_ip_set(
        Name=WAF_IP_SET_NAME, Scope='REGIONAL', Id=WAF_IP_SET_ID,
        Addresses=current_addresses + [cidr],
        LockToken=lock_token
    )
    logger.info(f"IP {cidr} adicionado ao WAF")
    
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH',
        Subject=f'[IR] IP Bloqueado no WAF: {remote_ip}',
        Message=json.dumps({'ip_bloqueado': cidr, 'motivo': finding_type,
                            'total_ips': len(current_addresses) + 1}, indent=2)
    )
    
    return {'status': 'BLOQUEADO', 'ip': cidr, 'finding_type': finding_type}
PYEOF

# Substituir ID real no código
sed -i "s/SUBSTITUIR_PELO_ID_REAL/$WAF_IPSET_ID/g" /tmp/lambda_block_waf.py

zip /tmp/lambda_block_waf.zip /tmp/lambda_block_waf.py

aws lambda create-function \
  --function-name MeridianIR-BlockWAFIP \
  --runtime python3.12 \
  --handler lambda_block_waf.handler \
  --zip-file fileb:///tmp/lambda_block_waf.zip \
  --role "arn:aws:iam::${ACCOUNT_ID}:role/LambdaIR-BlockWAFIP" \
  --timeout 60 \
  --region sa-east-1

echo "Lambda criada: MeridianIR-BlockWAFIP"

# EventBridge rule para findings com IP externo
aws events put-rule \
  --name "IR-BlockMaliciousIPInWAF" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "Recon:EC2/PortProbeUnprotectedPort",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
      ]
    }
  }' \
  --state ENABLED \
  --region sa-east-1

LAMBDA_ARN_WAF=$(aws lambda get-function \
  --function-name MeridianIR-BlockWAFIP \
  --region sa-east-1 \
  --query 'Configuration.FunctionArn' \
  --output text)

aws events put-targets \
  --rule "IR-BlockMaliciousIPInWAF" \
  --region sa-east-1 \
  --targets "[{\"Id\": \"BlockWAFLambda\", \"Arn\": \"$LAMBDA_ARN_WAF\"}]"

aws lambda add-permission \
  --function-name MeridianIR-BlockWAFIP \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --region sa-east-1

echo "Automação 3 configurada"
```

---

## Seção 5 — Testes das 3 Automações

**Passo 5.1** — Testar Automação 1 (desabilitar chave):

```bash
# Criar usuário e chave de teste
aws iam create-user --user-name IR-Test-User-Lab
TEST_KEY=$(aws iam create-access-key --user-name IR-Test-User-Lab)
TEST_KEY_ID=$(echo $TEST_KEY | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")
echo "Chave de teste criada: $TEST_KEY_ID"

# Invocar Lambda diretamente com evento de teste
aws lambda invoke \
  --function-name MeridianIR-DisableIAMKey \
  --region sa-east-1 \
  --payload "$(echo '{"access_key_id": "'$TEST_KEY_ID'", "user_name": "IR-Test-User-Lab"}' | base64)" \
  /tmp/lambda_result_1.json

cat /tmp/lambda_result_1.json

# Verificar que a chave foi desabilitada
aws iam list-access-keys \
  --user-name IR-Test-User-Lab \
  --query 'AccessKeyMetadata[0].Status'
# Esperado: "Inactive"
```

**Passo 5.2** — Testar Automação 3 (bloquear IP no WAF):

```bash
# Invocar Lambda com IP de teste
aws lambda invoke \
  --function-name MeridianIR-BlockWAFIP \
  --region sa-east-1 \
  --payload "$(echo '{"remote_ip": "203.0.113.100"}' | base64)" \
  /tmp/lambda_result_3.json

cat /tmp/lambda_result_3.json

# Verificar no WAF
aws wafv2 get-ip-set \
  --name MeridianBlockedIPs \
  --scope REGIONAL \
  --id $WAF_IPSET_ID \
  --region sa-east-1 \
  --query 'IPSet.Addresses'
# Esperado: ["203.0.113.100/32"]
```

---

## Seção 6 — CloudWatch Alarm para Falhas de Lambda IR

**Passo 6.1** — Criar alarme para erros nas Lambdas de IR:

```bash
for LAMBDA in MeridianIR-DisableIAMKey MeridianIR-IsolateEC2 MeridianIR-BlockWAFIP; do
  aws cloudwatch put-metric-alarm \
    --alarm-name "CRITICO-LambdaIR-Failure-$LAMBDA" \
    --alarm-description "Lambda de IR falhou — verificar imediatamente" \
    --metric-name Errors \
    --namespace AWS/Lambda \
    --dimensions Name=FunctionName,Value=$LAMBDA \
    --statistic Sum \
    --period 60 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --alarm-actions $SNS_CRITICO \
    --treat-missing-data notBreaching \
    --region sa-east-1
  
  echo "Alarme criado para $LAMBDA"
done
```

---

## Seção 7 — Dead Letter Queue para Lambda

**Passo 7.1** — Configurar DLQ para capturar falhas:

```bash
# Criar SQS DLQ
DLQ_ARN=$(aws sqs create-queue \
  --queue-name MeridianIR-Lambda-DLQ \
  --region sa-east-1 \
  --query 'QueueUrl' \
  --output text | xargs aws sqs get-queue-attributes \
    --queue-url {} \
    --attribute-names QueueArn \
    --query 'Attributes.QueueArn' \
    --output text)

echo "DLQ ARN: $DLQ_ARN"

# Configurar DLQ em cada Lambda
for LAMBDA in MeridianIR-DisableIAMKey MeridianIR-IsolateEC2 MeridianIR-BlockWAFIP; do
  aws lambda update-function-configuration \
    --function-name $LAMBDA \
    --dead-letter-config TargetArn=$DLQ_ARN \
    --region sa-east-1
  echo "DLQ configurada para $LAMBDA"
done
```

---

## Seção 8 — Cleanup

```bash
# Remover EventBridge rules
for RULE in IR-DisableCompromisedIAMKey IR-IsolateCompromisedEC2 IR-BlockMaliciousIPInWAF; do
  aws events remove-targets --rule $RULE --ids "${RULE}Lambda" --region sa-east-1
  aws events delete-rule --name $RULE --region sa-east-1
done

# Remover Lambdas
for LAMBDA in MeridianIR-DisableIAMKey MeridianIR-IsolateEC2 MeridianIR-BlockWAFIP; do
  aws lambda delete-function --function-name $LAMBDA --region sa-east-1
done

# Remover WAF IP Set
aws wafv2 delete-ip-set \
  --name MeridianBlockedIPs \
  --scope REGIONAL \
  --id $WAF_IPSET_ID \
  --lock-token $(aws wafv2 get-ip-set --name MeridianBlockedIPs --scope REGIONAL --id $WAF_IPSET_ID --region sa-east-1 --query 'LockToken' --output text) \
  --region sa-east-1

# Limpar usuário de teste
aws iam delete-access-key --user-name IR-Test-User-Lab --access-key-id $TEST_KEY_ID
aws iam delete-user --user-name IR-Test-User-Lab

echo "Cleanup concluído"
```

---

## Seção 9 — Gabarito Completo com Raciocínio

### Automação 1 — Gabarito: Desabilitar Chave IAM Comprometida

**Por que esta é a resposta correta:** A função Lambda `MeridianIR-DisableIAMKey` implementa o princípio de "contenção antes de investigação". Ao receber o finding, ela:
1. Extrai o `access_key_id` do campo `service.action.awsApiCallAction.remoteAccountDetails.affectedResources`
2. Chama `iam:UpdateAccessKey` com `Status=Inactive` — não exclui (preserva evidências)
3. Adiciona tag `Quarantine=true` no usuário — sinaliza para o time de IR
4. Envia notificação SNS com todos os detalhes para investigação humana

**Por que inativar em vez de excluir:** Excluir a chave destrói a evidência do `AccessKeyId` usado pelo atacante. Ao inativar, preservamos o `access_key_id` no CloudTrail, que pode ser usado para correlacionar todas as ações feitas com essa chave durante o comprometimento.

**Verificação correta:**
```bash
aws iam get-access-key-last-used --access-key-id <KEY_ID>
# Deve mostrar: "AccessKeyLastUsed": {"ServiceName": "Disabled"}

aws iam list-access-keys --user-name <USERNAME>
# Deve mostrar: "Status": "Inactive"
```

**Erros comuns neste passo:**
- Lambda timeout: a ação `UpdateAccessKey` pode demorar alguns segundos para propagar — configurar timeout de no mínimo 30 segundos
- Role sem permissão `iam:UpdateAccessKey`: o mais comum erro em produção — verificar a role da Lambda antes de qualquer teste
- Event pattern errado no EventBridge: usar `aws.guardduty` como source e `GuardDuty Finding` como detail-type — não `aws.iam`

---

### Automação 2 — Gabarito: Isolar EC2 Comprometida

**Por que esta é a resposta correta:** O isolamento via Security Group (em vez de stop/terminate) preserva o estado da instância para análise forense. Após o isolamento:
- A instância continua rodando — logs em memória e processos em execução são preservados
- Toda comunicação é bloqueada (sem ingress, sem egress) — o atacante perde acesso
- O estado do sistema de arquivos não muda — evidências forenses intactas

**Sequência correta na Lambda:**
```python
# 1. CRIAR Security Group de quarentena com zero regras (vazio = deny-all implícito)
sg_id = ec2.create_security_group(GroupName=f'QUARANTINE-{instance_id}-{timestamp}')

# 2. CRIAR snapshot ANTES de modificar o SG (preservar estado pre-isolamento)
ec2.create_snapshot(VolumeId=volume_id, Description=f'IR-pre-isolation-{timestamp}')

# 3. APLICAR o SG de quarentena
ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])

# 4. ADICIONAR tag de quarentena (visibilidade para outros engenheiros)
ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'Quarantine', 'Value': 'true'}])

# 5. NOTIFICAR time via SNS
```

**Por que a ordem importa:** O snapshot (passo 2) deve ser criado ANTES do isolamento (passo 3). Se criado depois, o snapshot reflete o estado pós-isolamento — não o estado durante o comprometimento, que é o mais valioso para forense.

**Verificação correta:**
```bash
aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].{SG:SecurityGroups,Tags:Tags}'
# Deve mostrar SG de quarentena e Tag Quarantine=true
```

**Erros comuns:**
- Usar `stop-instances` em vez de isolar via SG: para a instância, destruindo estado em memória e logs de processos — evidências perdidas
- Esquecer de verificar se a instância já está quarentenada (idempotência): se a Lambda for invocada duas vezes para o mesmo finding, criará dois SGs de quarentena — verificar tags antes de agir

---

### Automação 3 — Gabarito: Bloquear IP no WAF

**Por que esta é a resposta correta:** O bloqueio no WAF IP Set (em vez de NACL) é preferível porque:
1. WAF IP Sets são atualizáveis dinamicamente sem impacto nas conexões existentes
2. WAF opera na camada de aplicação (L7) — pode bloquear por IP E por outras características (User-Agent, headers)
3. WAF tem capacidade de 10.000 IPs por IP Set — escalável para feeds de Threat Intelligence
4. NACLs têm limite de 20 regras por subnet — rapidamente esgotado em bloqueios dinâmicos

**Verificação correta:**
```bash
aws wafv2 get-ip-set \
  --name MeridianBlockedIPs \
  --scope REGIONAL \
  --id $IPSET_ID \
  --region sa-east-1 \
  --query 'IPSet.Addresses'
# O IP bloqueado deve estar na lista
```

---

### Verificação Final — Checklist de Aprovação

| Automação | Teste | Resultado Correto | Evidência |
|---|---|---|---|
| 1 — Disable IAM Key | Invocar Lambda com access_key_id e user_name | Status `Inactive` + tag `Quarantine=true` + SNS enviado | `iam:GetAccessKey` mostrando Inactive |
| 2 — Isolate EC2 | GuardDuty sample finding HIGH de EC2 | SG quarentena sem regras + tag `Quarantine=true` + snapshot criado | `ec2:DescribeInstances` mostrando novo SG |
| 3 — Block WAF IP | Invocar Lambda com remote_ip | IP na lista do WAF IP Set + SNS enviado | `wafv2:GetIPSet` mostrando o IP na lista |
| Alarms | CloudWatch alarms | 3 alarms configurados para erros das Lambdas | `cloudwatch:DescribeAlarms` |
| DLQ | SQS DLQ | 1 DLQ vinculada às 3 Lambdas | `lambda:GetFunctionConfiguration` |
| EventBridge Rules | 3 rules | Rules em estado ENABLED na região sa-east-1 | `events:ListRules` |

**Meta de MTTR:** Após a implementação das 3 automações, o MTTR de contenção deve cair de 2h09m para menos de 3 minutos. Medir executando os testes com cronômetro — tempo desde a invocação do Lambda até a verificação do resultado da contenção.
