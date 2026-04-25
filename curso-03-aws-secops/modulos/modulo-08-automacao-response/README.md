# Módulo 08 — Automação de Resposta a Incidentes

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 4 (Incident Response)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Criar regras EventBridge para capturar eventos de segurança de GuardDuty, Config e Security Hub
2. Implementar Lambda functions para resposta automatizada a incidentes
3. Usar SSM Automation runbooks para remediação multi-conta
4. Orquestrar fluxos complexos de IR com AWS Step Functions
5. Implementar as 5 automações completas do Banco Meridian com código Python/Boto3
6. Aplicar o framework NIST SP 800-61 no contexto de AWS

---

## 1. Amazon EventBridge para Segurança

### Eventos de Segurança Disponíveis

| Fonte | Tipo de Evento | Trigger de Segurança |
|---|---|---|
| `aws.guardduty` | `GuardDuty Finding` | Novo finding, atualização de finding, finding arquivado |
| `aws.securityhub` | `Security Hub Findings - Imported` | Novo finding importado de qualquer fonte |
| `aws.config` | `Config Rules Compliance Change` | Recurso passou de COMPLIANT para NON_COMPLIANT |
| `aws.iam` | `AWS API Call via CloudTrail` | `CreateUser`, `AttachRolePolicy`, `CreateAccessKey` |
| `aws.s3` | `AWS API Call via CloudTrail` | `PutBucketPolicy`, `DeleteBucketPublicAccessBlock` |
| `aws.cloudtrail` | `AWS API Call via CloudTrail` | `StopLogging`, `DeleteTrail` |
| `aws.signin` | `AWS Console Sign In via CloudTrail` | Login de root, login sem MFA, login com falha |
| `aws.ec2` | `EC2 Instance State-change Notification` | Launch, stop, terminate de instância |

### Regra EventBridge Multi-Trigger de Segurança

```json
{
  "source": [
    "aws.guardduty",
    "aws.securityhub"
  ],
  "detail-type": [
    "GuardDuty Finding",
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "$or": [
      {
        "severity": [{"numeric": [">=", 7.0]}]
      },
      {
        "findings": {
          "Severity": {
            "Label": ["CRITICAL", "HIGH"]
          }
        }
      }
    ]
  }
}
```

---

## 2. Padrões de Lambda para Security Response

### Boas Práticas de Lambda para IR

| Prática | Implementação |
|---|---|
| **Least privilege** | Role com apenas as permissões necessárias para a ação específica |
| **Timeout adequado** | 5-15 min para ações de IR (default 3s é insuficiente) |
| **Error handling** | try/except em todas as chamadas de API; retry com backoff exponencial |
| **Idempotência** | Verificar se a ação já foi executada antes de executar novamente |
| **Logging** | CloudWatch Logs com structured logging (JSON) |
| **Dead Letter Queue** | SQS DLQ para capturar invocações com falha |
| **Notificação de falha** | SNS alert se a Lambda de IR falhar |

---

## 3. NIST SP 800-61 no Contexto AWS

| Fase | NIST | Implementação no Banco Meridian |
|---|---|---|
| **Preparação** | Treinar equipe, criar playbooks, preparar ferramentas | GuardDuty habilitado org-wide; Lambda de IR pré-implantadas; runbooks SSM testados; DetectiveenableEd |
| **Detecção e Análise** | Identificar indicadores de comprometimento | GuardDuty → EventBridge → Lambda de triagem; Detective para análise; CloudTrail Lake para timeline |
| **Contenção** | Limitar o impacto do incidente | Lambda de isolamento de EC2; Lambda de disable IAM key; WAF para bloquear IPs |
| **Erradicação** | Remover a causa raiz | Lambda de remediação automática Config; SSM Patch Manager; reimagem de instâncias |
| **Recuperação** | Restaurar operações normais | Snapshot restore; rotação de credenciais; deploy de nova infraestrutura via IaC |
| **Lições Aprendidas** | Documentar e melhorar | Post-mortem; atualizar playbooks; ajustar regras de detecção; Security Hub para métricas de melhoria |

---

## 4. Automação 1 — Desabilitar Chave IAM Exposta

**Cenário:** GuardDuty gera finding `UnauthorizedAccess:IAMUser/TorIPCaller` indicando que credenciais estão sendo usadas de IP Tor.

```python
import boto3
import json
import logging
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Automação 1: Desabilitar chave IAM exposta
    Trigger: GuardDuty Finding - UnauthorizedAccess ou credencial exposta no GitHub
    """
    iam = boto3.client('iam')
    sns = boto3.client('sns', region_name='sa-east-1')

    finding = event.get('detail', event)

    # Extrair informações do finding GuardDuty
    try:
        access_key_id = (
            finding.get('detail', {})
                   .get('resource', {})
                   .get('accessKeyDetails', {})
                   .get('accessKeyId')
            or event.get('access_key_id')  # invocação direta com parâmetro
        )
        user_name = (
            finding.get('detail', {})
                   .get('resource', {})
                   .get('accessKeyDetails', {})
                   .get('userName')
            or event.get('user_name')
        )
        account_id = event.get('account', context.invoked_function_arn.split(':')[4])

        if not access_key_id:
            logger.error("Access Key ID não encontrado no evento")
            return {'statusCode': 400, 'body': 'AccessKeyId não encontrado'}

        logger.info(f"Processando comprometimento de chave: {access_key_id} para usuário {user_name}")

    except (KeyError, TypeError) as e:
        logger.error(f"Erro ao parsear o finding: {e}")
        raise

    resultado = {
        'access_key_id': access_key_id,
        'user_name': user_name,
        'account_id': account_id,
        'acoes': [],
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }

    # Passo 1: Verificar estado atual da chave
    try:
        keys_response = iam.list_access_keys(UserName=user_name)
        key_info = next(
            (k for k in keys_response['AccessKeyMetadata'] if k['AccessKeyId'] == access_key_id),
            None
        )
        if not key_info:
            logger.warning(f"Chave {access_key_id} não encontrada para usuário {user_name}")
            resultado['status'] = 'KEY_NOT_FOUND'
        elif key_info['Status'] == 'Inactive':
            logger.info(f"Chave {access_key_id} já está inativa — idempotente")
            resultado['status'] = 'ALREADY_INACTIVE'
            return resultado
    except ClientError as e:
        logger.error(f"Erro ao verificar chave: {e}")
        raise

    # Passo 2: Desabilitar a chave imediatamente
    try:
        iam.update_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        resultado['acoes'].append(f"Chave {access_key_id} DESABILITADA")
        logger.info(f"Chave {access_key_id} desabilitada com sucesso")
    except ClientError as e:
        logger.error(f"FALHA ao desabilitar chave: {e}")
        # Notificar sobre a falha — situação crítica
        sns.publish(
            TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-CRITICO',
            Subject=f'FALHA IR: Não foi possível desabilitar chave comprometida {access_key_id}',
            Message=json.dumps({'erro': str(e), 'chave': access_key_id, 'usuario': user_name})
        )
        raise

    # Passo 3: Revogar todas as sessões ativas do usuário
    # (sessões STS assumidas com essa chave continuam ativas até expirar)
    try:
        # Anexar política de deny inline para bloquear sessões ativas imediatamente
        deny_all_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                    }
                }
            }]
        }
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=f'IR-DenyAllSessions-{resultado["timestamp"].replace(":", "-")}',
            PolicyDocument=json.dumps(deny_all_policy)
        )
        resultado['acoes'].append("Política de deny de sessões ativas anexada")
    except ClientError as e:
        logger.warning(f"Aviso: Não foi possível revogar sessões ativas: {e}")
        resultado['acoes'].append(f"AVISO: Revogar sessões manualmente — {str(e)}")

    # Passo 4: Criar tag de evidência no usuário IAM
    try:
        iam.tag_user(
            UserName=user_name,
            Tags=[
                {'Key': 'SecurityIncident', 'Value': 'Comprometimento de Credencial'},
                {'Key': 'IncidentTimestamp', 'Value': resultado['timestamp']},
                {'Key': 'AffectedKey', 'Value': access_key_id},
                {'Key': 'AutomatedResponse', 'Value': 'KeyDisabled'}
            ]
        )
        resultado['acoes'].append("Tags de incidente adicionadas ao usuário IAM")
    except ClientError as e:
        logger.warning(f"Aviso ao adicionar tags: {e}")

    # Passo 5: Notificar CISO e Time de Segurança
    mensagem_notificacao = {
        'titulo': 'Resposta Automática: Chave IAM Comprometida Desabilitada',
        'prioridade': 'CRÍTICA',
        'usuario_afetado': user_name,
        'chave_desabilitada': access_key_id,
        'conta': account_id,
        'timestamp': resultado['timestamp'],
        'acoes_executadas': resultado['acoes'],
        'proximos_passos': [
            '1. Investigar quais ações foram executadas com essa chave nas últimas 24h',
            '2. Usar CloudTrail Lake query: WHERE userIdentity.accessKeyId = access_key_id',
            '3. Verificar se novas chaves ou usuários foram criados',
            '4. Revisar recursos acessados (S3, RDS, EC2)',
            '5. Determinar como a chave foi comprometida (GitHub leak? phishing?)',
            '6. Após investigação: remover política de deny e deletar a chave permanentemente',
            '7. Comunicar ao usuário e ao gestor'
        ]
    }

    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-CRITICO',
        Subject=f'[IR] Chave IAM Comprometida: {access_key_id} — DESABILITADA AUTOMATICAMENTE',
        Message=json.dumps(mensagem_notificacao, indent=2, ensure_ascii=False)
    )
    resultado['acoes'].append("Notificação CISO enviada")
    resultado['status'] = 'CONCLUIDO'

    logger.info(f"Resposta automática concluída: {json.dumps(resultado)}")
    return resultado
```

---

## 5. Automação 2 — Revogar Sessões de Usuário Suspeito

```python
import boto3
import json
import time
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Automação 2: Revogar TODAS as sessões de um usuário IAM suspeito e notificar CISO.
    Trigger: GuardDuty finding de anomalia de comportamento IAM (PrivilegeEscalation ou Persistence)
    """
    iam = boto3.client('iam')
    sns = boto3.client('sns', region_name='sa-east-1')

    user_name = event.get('detail', {}).get('resource', {}).get('accessKeyDetails', {}).get('userName')
    incident_id = event.get('incident_id', f'AUTO-{int(time.time())}')

    if not user_name:
        logger.error("UserName não encontrado no evento")
        return {'statusCode': 400}

    acoes = []
    timestamp_revogacao = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    # Passo 1: Desabilitar TODAS as access keys do usuário
    keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
    for key in keys:
        if key['Status'] == 'Active':
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            acoes.append(f"Chave {key['AccessKeyId']} desabilitada")

    # Passo 2: Revogar console sessions (invalidar password temporariamente)
    # Força logout de todas as sessões de console ativas
    try:
        # Obter política de senha atual e forçar reset
        iam.update_login_profile(
            UserName=user_name,
            PasswordResetRequired=True  # Força troca de senha no próximo login
        )
        acoes.append("Login profile: PasswordResetRequired=True (força logout)")
    except iam.exceptions.NoSuchEntityException:
        acoes.append("Usuário sem login profile (sem acesso ao console)")

    # Passo 3: Anexar política de deny para invalidar sessões STS ativas
    revoke_sessions_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": f"RevokeAllSessionsBefore{timestamp_revogacao.replace(':', '')}",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": {
                    "aws:TokenIssueTime": timestamp_revogacao
                }
            }
        }]
    }

    iam.put_user_policy(
        UserName=user_name,
        PolicyName='IR-RevokeAllActiveSessions',
        PolicyDocument=json.dumps(revoke_sessions_policy)
    )
    acoes.append(f"Política de revogação de sessões ativas aplicada (antes de {timestamp_revogacao})")

    # Passo 4: Notificar CISO via SNS
    mensagem = {
        'incidente': incident_id,
        'acao': 'SESSOES_REVOGADAS',
        'usuario': user_name,
        'timestamp': timestamp_revogacao,
        'acoes_executadas': acoes,
        'nota_para_ciso': f'O usuário {user_name} teve todas as sessões revogadas preventivamente. '
                          f'Investigar imediatamente via Detective e CloudTrail Lake.',
        'query_investigacao': f"SELECT eventTime, eventName, sourceIPAddress, awsRegion FROM $EDS_ID "
                              f"WHERE userIdentity.arn LIKE '%{user_name}%' "
                              f"AND eventTime > DATE_ADD('day', -7, NOW()) ORDER BY eventTime DESC"
    }

    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-CRITICO',
        Subject=f'[IR {incident_id}] Sessões Revogadas: {user_name}',
        Message=json.dumps(mensagem, indent=2, ensure_ascii=False)
    )

    return {'status': 'CONCLUIDO', 'usuario': user_name, 'acoes': acoes}
```

---

## 6. Automação 3 — Isolar EC2 Comprometida

```python
import boto3
import json
import time
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Automação 3: Isolar instância EC2 comprometida.
    Trigger: GuardDuty finding HIGH em EC2 (CryptoCurrency, Backdoor:EC2/C&CActivity, etc.)
    """
    ec2 = boto3.client('ec2', region_name='sa-east-1')
    sns = boto3.client('sns', region_name='sa-east-1')

    # Extrair instance ID do finding GuardDuty
    finding_detail = event.get('detail', {})
    instance_id = (
        finding_detail.get('resource', {}).get('instanceDetails', {}).get('instanceId')
        or event.get('instance_id')
    )
    finding_type = finding_detail.get('type', 'Unknown')
    severity = finding_detail.get('severity', 0)
    incident_id = event.get('incident_id', f'GD-{int(time.time())}')

    if not instance_id:
        raise ValueError("Instance ID não encontrado no evento")

    logger.info(f"Iniciando isolamento de {instance_id} — Tipo: {finding_type}, Severidade: {severity}")

    # Obter VPC da instância
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    vpc_id = instance['VpcId']
    sgs_originais = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]

    # Criar snapshot de todos os volumes ANTES do isolamento
    snapshots = []
    for block_device in instance.get('BlockDeviceMappings', []):
        vol_id = block_device['Ebs']['VolumeId']
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"IR-FORENSE-{incident_id}-{instance_id}",
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
                {'Key': 'IncidentId', 'Value': incident_id},
                {'Key': 'GuardDutyFindingType', 'Value': finding_type},
                {'Key': 'ForensicEvidence', 'Value': 'true'},
                {'Key': 'DataClassification', 'Value': 'Confidential'}
            ]}]
        )
        snapshots.append(snap['SnapshotId'])
        logger.info(f"Snapshot {snap['SnapshotId']} criado para volume {vol_id}")

    # Criar Security Group de quarentena
    sg_quarentena = ec2.create_security_group(
        GroupName=f'QUARENTENA-{incident_id}',
        Description=f'IR Quarantine — {incident_id} — {finding_type}',
        VpcId=vpc_id,
        TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [
            {'Key': 'IncidentId', 'Value': incident_id},
            {'Key': 'Quarantine', 'Value': 'true'}
        ]}]
    )
    sg_id = sg_quarentena['GroupId']

    # Remover egress padrão
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )

    # Permitir apenas SSH do time de IR
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.200.0/24', 'Description': 'IR Team VPN'}]
        }]
    )

    # Mover instância para SG de quarentena
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])

    # Adicionar tags de quarentena
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'Quarantine', 'Value': 'true'},
        {'Key': 'IncidentId', 'Value': incident_id},
        {'Key': 'GuardDutyFinding', 'Value': finding_type},
        {'Key': 'IsolatedAt', 'Value': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
        {'Key': 'OriginalSGs', 'Value': ','.join(sgs_originais)}
    ])

    # Notificar
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH',
        Subject=f'[IR] EC2 Isolada: {instance_id} — {finding_type}',
        Message=json.dumps({
            'incidente': incident_id,
            'instancia': instance_id,
            'tipo_finding': finding_type,
            'severidade': severity,
            'sg_quarentena': sg_id,
            'sgs_originais': sgs_originais,
            'snapshots_criados': snapshots,
            'proximos_passos': [
                'Analisar snapshots em instância forense isolada',
                'Investigar via Detective e CloudTrail Lake',
                'Confirmar vetor de comprometimento antes de remediar'
            ]
        }, indent=2, ensure_ascii=False)
    )

    return {
        'status': 'ISOLADO',
        'instance_id': instance_id,
        'sg_quarentena': sg_id,
        'snapshots': snapshots
    }
```

---

## 7. Automação 4 — Bloquear IP Malicioso no WAF

```python
import boto3
import json
import time
import logging
import ipaddress

logger = logging.getLogger()
logger.setLevel(logging.INFO)

WAF_IP_SET_ID = 'xxxxx-yyyy-zzzz-aaaa-bbbbbbbbbbbb'
WAF_IP_SET_NAME = 'MeridianBlockedIPs'
WAF_SCOPE = 'REGIONAL'
WAF_REGION = 'sa-east-1'

def handler(event, context):
    """
    Automação 4: Bloquear IP malicioso no WAF.
    Trigger: GuardDuty finding com remote IP externo (ex: BruteForce, PortProbe, C2)
    """
    waf = boto3.client('wafv2', region_name=WAF_REGION)
    sns = boto3.client('sns', region_name=WAF_REGION)

    # Extrair IP do finding GuardDuty
    finding = event.get('detail', {})
    remote_ip = (
        finding.get('service', {}).get('action', {}).get('networkConnectionAction', {})
               .get('remoteIpDetails', {}).get('ipAddressV4')
        or finding.get('service', {}).get('action', {}).get('portProbeAction', {})
               .get('portProbeDetails', [{}])[0].get('remoteIpDetails', {}).get('ipAddressV4')
        or event.get('remote_ip')
    )

    finding_type = finding.get('type', 'Unknown')
    incident_id = event.get('incident_id', f'WAF-{int(time.time())}')

    if not remote_ip:
        raise ValueError("Remote IP não encontrado no evento")

    # Validar formato do IP
    try:
        ip_obj = ipaddress.ip_address(remote_ip)
        cidr = f"{remote_ip}/32" if ip_obj.version == 4 else f"{remote_ip}/128"
    except ValueError:
        raise ValueError(f"IP inválido: {remote_ip}")

    logger.info(f"Bloqueando IP {cidr} no WAF — Finding: {finding_type}")

    # Obter lock token atual do IP Set
    ip_set_response = waf.get_ip_set(
        Name=WAF_IP_SET_NAME,
        Scope=WAF_SCOPE,
        Id=WAF_IP_SET_ID
    )

    lock_token = ip_set_response['LockToken']
    addresses_atuais = ip_set_response['IPSet']['Addresses']

    # Verificar idempotência
    if cidr in addresses_atuais:
        logger.info(f"IP {cidr} já está bloqueado no WAF")
        return {'status': 'ALREADY_BLOCKED', 'ip': cidr}

    # Adicionar IP ao IP Set
    enderecos_atualizados = addresses_atuais + [cidr]

    waf.update_ip_set(
        Name=WAF_IP_SET_NAME,
        Scope=WAF_SCOPE,
        Id=WAF_IP_SET_ID,
        Addresses=enderecos_atualizados,
        LockToken=lock_token
    )

    logger.info(f"IP {cidr} adicionado ao WAF IP Set com sucesso")

    # Notificar
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-MEDIUM',
        Subject=f'[IR] IP Bloqueado no WAF: {remote_ip}',
        Message=json.dumps({
            'incidente': incident_id,
            'ip_bloqueado': cidr,
            'motivo': finding_type,
            'total_ips_bloqueados': len(enderecos_atualizados),
            'nota': 'Revisar em 30 dias para confirmar se o bloqueio ainda é necessário'
        }, indent=2)
    )

    return {
        'status': 'BLOQUEADO',
        'ip': cidr,
        'finding_type': finding_type,
        'incident_id': incident_id
    }
```

---

## 8. Automação 5 — Auto-Remediar Bucket S3 Público

```python
import boto3
import json
import time
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Automação 5: Remediar automaticamente bucket S3 com acesso público.
    Trigger: Config Rule s3-bucket-public-read-prohibited → NON_COMPLIANT
    """
    s3 = boto3.client('s3')
    sns = boto3.client('sns', region_name='sa-east-1')

    # Extrair bucket name do evento Config
    config_item = event.get('detail', {}).get('configurationItem', {})
    bucket_name = (
        config_item.get('resourceName')
        or event.get('bucket_name')
    )

    incident_id = event.get('incident_id', f'S3-REMEDIATION-{int(time.time())}')

    if not bucket_name:
        logger.error("Bucket name não encontrado no evento")
        return {'statusCode': 400}

    logger.info(f"Remediando bucket público: {bucket_name}")

    acoes = []

    # Passo 1: Verificar estado atual
    try:
        current_block = s3.get_public_access_block(Bucket=bucket_name)
        config_atual = current_block['PublicAccessBlockConfiguration']
        logger.info(f"Config atual de Block Public Access: {config_atual}")
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        config_atual = {}
        logger.info("Bucket sem configuração de Block Public Access")

    # Passo 2: Habilitar Block Public Access (todos os 4 blocos)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    acoes.append("Block Public Access habilitado (4/4 configurações)")

    # Passo 3: Verificar e remover ACL pública se existir
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        public_grants = [
            g for g in acl['Grants']
            if g['Grantee'].get('URI') in [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ]
        ]
        if public_grants:
            s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
            acoes.append(f"ACL pública removida ({len(public_grants)} grants públicos)")
        else:
            acoes.append("ACL já era privada — nenhuma mudança necessária")
    except Exception as e:
        logger.warning(f"Não foi possível verificar/corrigir ACL: {e}")

    # Passo 4: Adicionar tag de evidência no bucket
    try:
        existing_tags = s3.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
    except s3.exceptions.NoSuchTagSet:
        existing_tags = []

    existing_tags_dict = {t['Key']: t['Value'] for t in existing_tags}
    existing_tags_dict.update({
        'SecurityRemediation': 'PublicAccessRemoved',
        'RemediationTimestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'IncidentId': incident_id,
        'RemediatedBy': 'IR-Automation'
    })

    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={'TagSet': [{'Key': k, 'Value': v} for k, v in existing_tags_dict.items()]}
    )
    acoes.append("Tags de remediação adicionadas ao bucket")

    # Passo 5: Notificar time de segurança e dono do bucket
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-MEDIUM',
        Subject=f'[Auto-Remediação] Bucket S3 Público Corrigido: {bucket_name}',
        Message=json.dumps({
            'incidente': incident_id,
            'bucket': bucket_name,
            'acao': 'Block Public Access habilitado automaticamente',
            'config_anterior': config_atual,
            'acoes_executadas': acoes,
            'nota': f'O bucket {bucket_name} tinha acesso público e foi corrigido automaticamente. '
                    f'Verifique se algum workload legítimo foi impactado.',
            'verificar': [
                'Aplicações que dependiam de acesso público ao bucket',
                'Sites estáticos servidos diretamente pelo S3',
                'Integrações com serviços externos que usavam acesso público'
            ]
        }, indent=2, ensure_ascii=False)
    )

    return {
        'status': 'REMEDIADO',
        'bucket': bucket_name,
        'acoes': acoes,
        'incident_id': incident_id
    }
```

---

## 9. SSM Automation Runbook Multi-Conta

```yaml
# ssm-runbook-security-response.yaml
schemaVersion: "0.3"
description: |
  Runbook de Resposta a Incidentes — Banco Meridian
  Executa em múltiplas contas via delegated administration
  Ações: (1) Isolamento de EC2, (2) Disable IAM Key, (3) Notificação

assumeRole: "{{AutomationAssumeRole}}"

parameters:
  IncidentId:
    type: String
    description: "ID do incidente (ex: INC-2026-0042)"

  TargetAccountId:
    type: String
    description: "Account ID alvo (onde executar as ações)"

  InstanceId:
    type: String
    description: "Instance ID a ser isolada (ou 'NONE')"
    default: "NONE"

  AffectedAccessKeyId:
    type: String
    description: "Access Key ID a ser desabilitada (ou 'NONE')"
    default: "NONE"

  AutomationAssumeRole:
    type: String
    description: "ARN da role SSM para executar automações"

mainSteps:

  - name: LogIncidentStart
    action: aws:executeScript
    inputs:
      Runtime: python3.8
      Handler: log_start
      Script: |
        def log_start(events, context):
            import datetime
            print(f"Incidente {events['IncidentId']} iniciado em {datetime.datetime.utcnow()}")
            return {'started': datetime.datetime.utcnow().isoformat()}
      InputPayload:
        IncidentId: "{{IncidentId}}"

  - name: DisableAccessKey
    action: aws:branch
    inputs:
      Choices:
        - NextStep: ExecuteDisableKey
          Variable: "{{AffectedAccessKeyId}}"
          StringEquals: "NONE"
      Default: SkipKeyDisable

  - name: ExecuteDisableKey
    action: aws:executeAwsApi
    inputs:
      Service: iam
      Api: UpdateAccessKey
      UserName: "{{AffectedUserName}}"
      AccessKeyId: "{{AffectedAccessKeyId}}"
      Status: Inactive

  - name: IsolateEC2
    action: aws:branch
    inputs:
      Choices:
        - NextStep: SkipIsolation
          Variable: "{{InstanceId}}"
          StringEquals: "NONE"
      Default: ExecuteIsolation

  - name: ExecuteIsolation
    action: aws:executeAutomation
    inputs:
      DocumentName: MeridianIsolateEC2
      RuntimeParameters:
        InstanceId: ["{{InstanceId}}"]
        IncidentId: ["{{IncidentId}}"]

  - name: NotifyCompletion
    action: aws:executeAwsApi
    inputs:
      Service: sns
      Api: Publish
      TopicArn: "arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH"
      Subject: "[IR Concluído] Incidente {{IncidentId}}"
      Message: "SSM Automation completada para incidente {{IncidentId}} na conta {{TargetAccountId}}"
```

---

## 10. Atividades de Fixação

**1.** Uma Lambda de resposta automática falha ao tentar desabilitar a chave IAM de um usuário porque a role da Lambda não tem permissão `iam:UpdateAccessKey`. O que você deve fazer para resolver isso mantendo o princípio do menor privilégio?

a) Dar AdministratorAccess à role da Lambda
b) Adicionar apenas `iam:UpdateAccessKey` e `iam:ListAccessKeys` à policy da role da Lambda
c) Compartilhar credenciais de administrador como variáveis de ambiente da Lambda
d) Executar manualmente a ação sem automação

**Gabarito: B** — Least privilege para Lambda de IR: conceder apenas as permissões exatamente necessárias. Para desabilitar chave: `iam:UpdateAccessKey` (para atualizar o status) e `iam:ListAccessKeys` (para verificar estado atual). Adicionar também `iam:TagUser` se a função adiciona tags de evidência, e `sns:Publish` para notificação. Nada além disso.

---

**2.** Como você garantiria que a Lambda de automação de IR para isolar EC2 seja idempotente (não cause erros se executada duas vezes para o mesmo incidente)?

a) Não há como garantir idempotência em Lambda
b) Verificar antes de executar cada ação se ela já foi realizada (ex: verificar se o SG de quarentena já existe, se a instância já tem a tag Quarantine=true)
c) Usar SQS FIFO para garantir que a Lambda seja invocada apenas uma vez
d) Adicionar um lock DynamoDB antes de executar

**Gabarito: B** — Idempotência via verificação de estado prévo: (1) Antes de criar SG de quarentena: verificar se já existe um SG com nome `QUARENTENA-{incident_id}`. Se sim, reutilizar. (2) Antes de modificar SG da instância: verificar se já está no SG de quarentena. (3) Antes de criar snapshot: verificar se já existe snapshot com tag `IncidentId=xxx`. (4) Antes de enviar SNS: verificar se notificação já foi enviada (via DynamoDB ou tag no recurso). Nota: opção D (lock DynamoDB) é uma solução válida adicional para prevenir execução concorrente.

---

**3.** O EventBridge rule para GuardDuty HIGH está configurado com target Lambda. Em qual situação a Lambda pode não ser invocada mesmo com um finding HIGH no GuardDuty?

a) Sempre é invocada — EventBridge garante entrega
b) Se o finding foi arquivado antes de chegar ao EventBridge; se a Lambda está na região errada; se o rule está em uma conta diferente do finding
c) Se a Lambda tem menos de 512 MB de memória
d) Se o finding é do tipo LOW

**Gabarito: B** — Cenários onde a Lambda pode não ser invocada: (1) Finding arquivado por Suppression Rule antes do event chegar ao EventBridge (suppressão é aplicada antes do roteamento). (2) Rule configurada em sa-east-1 mas o finding foi gerado em us-east-1 (GuardDuty é regional — rules devem ser configuradas em cada região). (3) Para Organization-wide: se a rule está na conta Audit mas o finding foi na conta Production — configurar cross-account event bus forwarding.

---

**4.** Explique quando usar Step Functions em vez de Lambda diretamente para automação de IR.

a) Step Functions são sempre desnecessários — Lambda é suficiente
b) Step Functions quando o fluxo tem múltiplos passos sequenciais, condicionais, tratamento de erros, retries, e timeout superior a 15 minutos
c) Step Functions apenas para processos batch
d) Step Functions apenas quando há mais de 10 Lambdas envolvidas

**Gabarito: B** — Lambda tem timeout máximo de 15 minutos. Alguns fluxos de IR podem durar horas (ex: aguardar aprovação humana para destruir instância). Step Functions: (1) Orquestrar múltiplas Lambdas com lógica condicional (se snapshot concluído, então notificar; se falhou, então alertar CISO). (2) Parallel state para executar múltiplas ações simultaneamente (isolar EC2 E desabilitar chave em paralelo). (3) Wait state para aguardar aprovação humana via API. (4) Retry com backoff exponencial configurável. (5) Execuções que excedem 15 minutos. (6) Visibilidade completa de execução no console.

---

**5.** Qual é a fase do NIST SP 800-61 correspondente às automações EventBridge+Lambda que criamos neste módulo?

a) Preparação
b) Detecção e Análise
c) Contenção (Containment)
d) Lições Aprendidas

**Gabarito: C** — As automações (desabilitar chave, isolar EC2, bloquear IP WAF, remediar S3 público) executam ações de CONTENÇÃO — limitam o impacto e impedem que o incidente se espalhe. A Detecção é feita pelo GuardDuty/Config. A Preparação é o trabalho de criar e testar as automações antes que o incidente ocorra. A Erradicação (remover causa raiz) e Recuperação (restaurar operações) geralmente requerem análise humana após a contenção automática.

---

## 11. Roteiro de Gravação

### Aula 8.1 — EventBridge + Lambda para Response (50 min)

**Abertura (2 min):**
"Boa tarde! Módulo 8 — o módulo mais hands-on do curso. Automação de resposta. Detecção sem automação significa que um analista precisa estar olhando o painel 24h/7. Com automação, o sistema reage em segundos enquanto o analista está dormindo. Vamos construir as 5 automações principais do Banco Meridian."

**Bloco 1 — EventBridge como Roteador de Eventos (10 min):**
"[Mostrar diagrama de evento flow]

EventBridge é o barramento central de eventos AWS. Qualquer evento que acontece na AWS pode ser capturado aqui. GuardDuty finding, Config rule violation, login no console, criação de usuário IAM — tudo gera um evento.

[Criar rule ao vivo]
1. EventBridge — Rules — Create rule
2. Event source: AWS services
3. Service: GuardDuty — Event type: GuardDuty Finding
4. Event pattern: severity >= 7.0

[Mostrar o JSON do event pattern]

O event pattern é um filtro JSON. Posso ser específico: apenas findings de EC2 comprometida, apenas de certas contas, apenas de certas regiões. Quanto mais específico, menos ruído na Lambda."

**Bloco 2 — Boas Práticas de Lambda para IR (8 min):**
"[Mostrar lista de boas práticas]

Antes de escrever código, regras de ouro:
1. Least privilege: role com APENAS as permissões necessárias
2. Timeout: mínimo 5 minutos para ações de IR — APIs AWS podem ser lentas
3. Error handling: cada chamada de API pode falhar — sempre try/except
4. Idempotência: a Lambda pode ser invocada mais de uma vez para o mesmo evento
5. Structured logging: JSON no CloudWatch, não print simples

[Mostrar exemplo de role mínima para Lambda de IR]"

**Bloco 3 — Demo: Automação 1 (Desabilitar Chave Comprometida) (18 min):**
"[Criar a Lambda ao vivo]
1. Lambda — Create function — Python 3.12
2. Copiar código da Automação 1
3. Environment variables: SNS_TOPIC_ARN
4. Timeout: 5 minutos
5. Role: LambdaIRKeyDisable (com iam:UpdateAccessKey, iam:ListAccessKeys, sns:Publish)

[Testar com evento simulado]
{
  'access_key_id': 'AKIATESTKEY123',
  'user_name': 'joao.silva'
}

[Mostrar execução e logs no CloudWatch]

[Conectar ao EventBridge]
Criar rule com pattern de GuardDuty TorIPCaller, target = essa Lambda.

[Mostrar CloudWatch Alarm para erros da Lambda]
Se a Lambda de IR falha (o pior momento possível), preciso saber imediatamente. Alarme para Lambda errors > 0 notifica o CISO diretamente."

**Bloco 4 — Demo: Automação 5 (S3 Public Remediation) (12 min):**
"[Criar automação de S3 + Config ao vivo]

Essa automação fecha o ciclo de postura: Config detecta bucket público → EventBridge captura a mudança → Lambda remedia → Config reavalia → COMPLIANT.

[Criar teste: bucket S3 público → aguardar Config → automação executa → verificar]

Em produção, esse ciclo leva 2-10 minutos. Zero intervenção humana para um dos erros de configuração mais comuns em AWS."

**Fechamento (0 min):**
"Na próxima aula: SSM Automation para remediação multi-conta e Step Functions para fluxos complexos de IR."

---

### Aula 8.2 — SSM Automation + Step Functions + 5 Automações (50 min)

**Abertura (2 min):**
"Boa tarde! Vamos completar o módulo 8 com SSM Automation e Step Functions. Se Lambda é a ferramenta para ações simples, Step Functions é para fluxos complexos que precisam de orquestração, aprovação humana e tratamento robusto de erros."

**Bloco 1 — SSM Automation (12 min):**
"[Mostrar runbooks pré-existentes de segurança]

SSM já vem com runbooks de segurança prontos: `AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock`, `AWSConfigRemediation-EnableCloudTrailEncryption`, `AWSConfigRemediation-SetIAMPasswordPolicy`.

Para o Banco Meridian, o grande diferencial é execução multi-conta. O SSM Automation pode executar em múltiplas contas simultaneamente via Organizations.

[Demo ao vivo] Criar runbook customizado para IR de S3 público, idêntico ao SSM document do Módulo 4, e executar em múltiplas contas simultaneamente."

**Bloco 2 — Step Functions para IR (12 min):**
"[Mostrar diagrama de state machine]

Um incidente HIGH de GuardDuty dispara o seguinte Step Functions workflow:

Estado 1: Parallel — Execute em paralelo:
  - Branch A: Isolar EC2 (Lambda)
  - Branch B: Desabilitar chave IAM (Lambda)

Estado 2: Wait — Aguardar aprovação humana (até 8h)
  TaskToken enviado via SNS para o CISO
  CISO aprova ou rejeita via API

Estado 3: Condition — Se aprovado:
  - True: Executar erradicação (terminate instância + rotação de credenciais)
  - False: Restaurar SGs originais + investigação adicional

Estado 4: Notificar conclusão via SNS

[Criar state machine ao vivo — simplificado]"

**Bloco 3 — Automações 2, 3, 4 em Demo Rápida (18 min):**
"[Automação 2 — Revogar sessões]
Em 5 minutos: demonstrar a lógica de invalidação de sessões via inline policy. Testar com usuário de lab.

[Automação 3 — Isolar EC2]
Já vimos a lógica. Demo focada em verificar: snapshot criado? SG de quarentena criado? Instância movida? Notificação enviada?

[Automação 4 — Bloquear IP no WAF]
Demo: GuardDuty finding com IP externo → EventBridge → Lambda → WAF IP Set atualizado. Verificar no WAF console que o IP foi adicionado."

**Bloco 4 — Recap e Padronização (8 min):**
"[Mostrar tabela de mapeamento NIST]

Tudo que criamos hoje se encaixa em 3 fases do NIST:
- Preparação: configuramos as automações, testamos, documentamos
- Contenção: as 5 automações executam contenção automática
- Erradicação e Recuperação: requerem confirmação humana (Step Functions Wait)

Para a prova SCS-C02: EventBridge + Lambda é o padrão de automação de segurança mais cobrado. Conhecer o event pattern para GuardDuty, Config e Security Hub é essencial."

---

## 12. Avaliação do Módulo

**Questão 1 (2 pontos):** Você precisa criar uma automação que: (1) detecta quando uma nova instância EC2 é criada sem a tag obrigatória `CostCenter`, (2) adiciona a tag automaticamente com valor `UNKNOWN`, (3) notifica o time de FinOps. Descreva a arquitetura completa.

**Gabarito:** Arquitetura: (1) Config Rule `required-tags` configurada para `CostCenter`. (2) EventBridge Rule: source `aws.config`, detail-type `Config Rules Compliance Change`, filter `configRuleName=required-tags AND newEvaluationResult.complianceType=NON_COMPLIANT AND configurationItem.resourceType=AWS::EC2::Instance`. (3) Target: Lambda function. (4) Lambda: extrai Instance ID do evento, chama `ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'CostCenter', 'Value': 'UNKNOWN'}])`, envia SNS para time de FinOps com Instance ID e owner info do CloudTrail (quem criou a instância). IAM da Lambda: `ec2:CreateTags` e `sns:Publish` apenas.

---

**Questão 2 (2 pontos):** Qual é o risco de uma Lambda de IR com AdministratorAccess, e como você mitigaria esse risco?

**Gabarito:** Risco: se a Lambda for comprometida (via bug de code injection, SSRF, ou escalada de privilégios), o atacante terá credenciais de AdminAccess temporárias — suficiente para criar usuários, exfiltrar dados, modificar recursos em toda a conta. Mitigações: (1) Least privilege: cada Lambda de IR tem apenas as permissões mínimas para sua função específica. (2) Resource-level restrictions: ARNs específicos em vez de `*` onde possível. (3) Conditions: restringir por região, por tipo de recurso, por tag. (4) Permissions Boundary na role da Lambda: mesmo que a Lambda tente expandir suas próprias permissões, o boundary limita. (5) Revisão regular via IAM Access Analyzer para encontrar unused permissions. (6) Separar Lambdas por função: uma para EC2, outra para IAM, outra para WAF — blast radius limitado.

---

**Questão 3 (2 pontos):** Um GuardDuty finding é gerado às 03h. A Lambda de IR é invocada e executa com sucesso. Às 09h, o analista de plantão verifica o incidente e percebe que a Lambda foi invocada 5 vezes para o mesmo finding. Isso é um problema? Por que?

**Gabarito:** EventBridge pode invocar a Lambda múltiplas vezes para o mesmo evento em casos de retry (ex: Lambda retornou erro na primeira vez, EventBridge tentou novamente). Se a Lambda NÃO é idempotente: (1) O SG de quarentena pode ser criado 5 vezes com nomes diferentes, causando confusão. (2) 5 snapshots EBS são criados para o mesmo volume — custo desnecessário. (3) 5 notificações SNS chegam ao CISO. Se a Lambda É idempotente: (1) Segunda invocação verifica que SG de quarentena já existe → reutiliza. (2) Snapshot com tag IncidentId já existe → não cria novo. (3) Apenas a primeira notificação é enviada (verificando via DynamoDB ou tag no recurso). A idempotência é crítica para automações de IR — nenhuma ação destrutiva irreversível deve ser executada sem verificação de estado.

---

**Questão 4 (2 pontos):** O Banco Meridian tem 15 contas AWS. Como você garantiria que o bloqueio de IP no WAF (Automação 4) seja aplicado em todas as 15 contas quando um finding GuardDuty ocorre em qualquer delas?

**Gabarito:** Abordagem com EventBridge + Step Functions multi-conta: (1) Configurar EventBridge em cada conta para encaminhar eventos de GuardDuty HIGH para o event bus centralizado na conta Audit (cross-account event bus). (2) Na conta Audit: EventBridge rule captura o evento e dispara Step Functions. (3) Step Functions usa Parallel state com 15 ramos — cada ramo executa `LambdaInvoke` em uma conta diferente via `aws:iam::assume_role`. (4) Cada Lambda executa o bloqueio de WAF na sua conta respectiva. Alternativamente: AWS Firewall Manager com Central IP Set — atualizar o IP Set no Firewall Manager replica automaticamente para todas as contas protegidas. Esta é a abordagem mais escalável para organizações grandes.

---

**Questão 5 (2 pontos):** Qual é a fase de "Lições Aprendidas" do NIST SP 800-61 e como você a implementaria usando serviços AWS?

**Gabarito:** Lições Aprendidas: revisão pós-incidente para identificar o que funcionou, o que falhou, e como melhorar. Implementação em AWS: (1) **Métricas de IR no Security Hub:** verificar MTTR (Mean Time to Respond) e MTTD (Mean Time to Detect) via findings criados e resolvidos. (2) **CloudTrail Lake analysis:** revisar se as SCPs e Config rules teriam prevenido o incidente. (3) **GuardDuty Suppression Review:** houve findings suprimidos que deveriam ter sido tratados? (4) **Runbook Update:** atualizar documentos SSM Automation com passos adicionais identificados. (5) **Lambda IR Update:** ajustar as automações com base no que foi necessário fazer manualmente. (6) **Security Hub Custom Action:** criar um relatório de post-mortem via Lambda que documenta o incidente no formato NIST e envia ao ITSM.
