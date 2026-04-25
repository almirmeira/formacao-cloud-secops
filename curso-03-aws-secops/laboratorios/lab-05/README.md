# Lab 05 — Detective: Investigação Forense de EC2 Comprometida

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 05 — Investigação de Incidentes
**Nível:** Avançado

---

## Contexto

O GuardDuty gerou um finding HIGH `Backdoor:EC2/C&CActivity.B` para a instância `i-0a1b2c3d4e5f67890` na conta Production (444444444444) do Banco Meridian. A instância está fazendo comunicação com um IP de C2 (Command and Control) conhecido às 03h BRT.

Você é o IR Analyst de plantão. Use o Amazon Detective para reconstruir a timeline completa do comprometimento e identificar o vetor inicial. Ao final, produza um relatório técnico de IR.

---

## Pré-requisitos

- Amazon Detective habilitado (e alimentado por pelo menos 24h)
- GuardDuty habilitado e integrado com Detective
- CloudTrail Lake com Event Data Store ativo
- Acesso à Audit Account (222222222222)

---

## Seção 1 — Triagem Inicial do Finding

**Passo 1.1** — Obter detalhes completos do finding GuardDuty:

```bash
# Assumir role na Audit Account
export DETECTOR_ID="<DETECTOR_ID_AUDIT>"

# Buscar o finding específico
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Backdoor:EC2/C&CActivity.B"]},
      "severity": {"Gte": 7}
    }
  }' \
  --sort-criteria '{"AttributeName": "createdAt", "OrderBy": "DESC"}' \
  --max-results 1

# Obter detalhes
FINDING_ID="<FINDING_ID>"
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --region sa-east-1 \
  --finding-ids $FINDING_ID \
  --query 'Findings[0]' \
  --output json > /tmp/finding_details.json

# Extrair informações-chave
cat /tmp/finding_details.json | python3 -c "
import json, sys
f = json.load(sys.stdin)
print('=== TRIAGEM DO FINDING ===')
print(f'Tipo: {f[\"type\"]}')
print(f'Severidade: {f[\"severity\"]}')
print(f'Conta: {f[\"accountId\"]}')
print(f'Região: {f[\"region\"]}')
print(f'Instância: {f[\"resource\"][\"instanceDetails\"][\"instanceId\"]}')
print(f'IP do C2: {f[\"service\"][\"action\"][\"networkConnectionAction\"][\"remoteIpDetails\"][\"ipAddressV4\"]}')
print(f'País do C2: {f[\"service\"][\"action\"][\"networkConnectionAction\"][\"remoteIpDetails\"][\"country\"][\"countryName\"]}')
print(f'Porta Destino: {f[\"service\"][\"action\"][\"networkConnectionAction\"][\"remotePortDetails\"][\"port\"]}')
print(f'First Seen: {f[\"service\"][\"eventFirstSeen\"]}')
print(f'Last Seen: {f[\"service\"][\"eventLastSeen\"]}')
print(f'Contagem: {f[\"service\"][\"count\"]}')
"
```

**Resultado Esperado:**
```
=== TRIAGEM DO FINDING ===
Tipo: Backdoor:EC2/C&CActivity.B
Severidade: 7.8
Conta: 444444444444
Região: sa-east-1
Instância: i-0a1b2c3d4e5f67890
IP do C2: 185.220.101.15
País do C2: Russia
Porta Destino: 4444
First Seen: 2026-04-10T01:15:00Z
Last Seen: 2026-04-10T14:32:00Z
Contagem: 1847
```

---

## Seção 2 — Investigação com Amazon Detective

**Passo 2.1** — Pivot do Finding para o Detective:

```bash
# Obter ARN do behavior graph
aws detective list-graphs \
  --region sa-east-1 \
  --query 'GraphList[0].Arn'

GRAPH_ARN="<GRAPH_ARN>"

# Buscar a entidade instância EC2 no Detective
aws detective search-graph \
  --graph-arn $GRAPH_ARN \
  --query-text "EC2 instance i-0a1b2c3d4e5f67890" \
  --region sa-east-1

# Obter investigação para o finding
aws detective start-investigation \
  --graph-arn $GRAPH_ARN \
  --entity-arn "arn:aws:ec2:sa-east-1:444444444444:instance/i-0a1b2c3d4e5f67890" \
  --scope-start-time "2026-04-08T00:00:00Z" \
  --scope-end-time "2026-04-10T23:59:59Z" \
  --region sa-east-1
```

**Passo 2.2** — Analisar o behavior graph da instância:

No console Detective (não disponível totalmente via CLI), navegar:

1. **Findings tab:** Confirmar finding do GuardDuty
2. **Network tab:** Ver conexões de rede — tráfego para 185.220.101.15:4444
3. **Process activity tab (Runtime Monitoring):** Ver processos suspeitos
4. **API call activity:** Ver chamadas de API usando o IAM role da instância
5. **Related findings:** Outros findings para a mesma instância ou IAM role

**Passo 2.3** — Pivot para o IAM Role da instância:

```bash
# Verificar qual IAM role está associada à instância
aws ec2 describe-instances \
  --instance-ids i-0a1b2c3d4e5f67890 \
  --region sa-east-1 \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn'
```

---

## Seção 3 — Timeline com CloudTrail Lake

**Passo 3.1** — Query de timeline completo da instância (últimas 48h):

```bash
EDS_ID="<EVENT_DATA_STORE_ID>"

aws cloudtrail start-query \
  --query-statement "
    -- Timeline completo de atividade da instância comprometida
    SELECT
        eventTime,
        eventName,
        eventSource,
        userIdentity.type AS identity_type,
        userIdentity.arn AS identity_arn,
        userIdentity.accessKeyId AS access_key,
        sourceIPAddress,
        awsRegion,
        requestParameters,
        responseElements,
        errorCode
    FROM ${EDS_ID}
    WHERE
        (
            -- Eventos gerados pela instância (via IMDSv2)
            userIdentity.arn LIKE '%i-0a1b2c3d4e5f67890%'
            -- OU eventos na instância
            OR resources[0].arn LIKE '%i-0a1b2c3d4e5f67890%'
        )
        AND eventTime > timestamp '2026-04-08 00:00:00'
        AND eventTime < timestamp '2026-04-11 00:00:00'
    ORDER BY eventTime ASC
  " \
  --region sa-east-1

echo "Query de timeline disparada — aguardar resultado"
```

**Passo 3.2** — Query de atividade do IAM Role após o comprometimento:

```bash
aws cloudtrail start-query \
  --query-statement "
    -- Ações executadas pelo role da instância comprometida
    -- Foco: ações após o first seen do finding (2026-04-10 01:15 UTC)
    SELECT
        eventTime,
        eventName,
        eventSource,
        sourceIPAddress,
        awsRegion,
        json_extract_scalar(requestParameters, '$.bucketName') AS bucket_acessado,
        json_extract_scalar(requestParameters, '$.key') AS objeto_acessado,
        errorCode
    FROM ${EDS_ID}
    WHERE
        userIdentity.arn LIKE '%EC2AppRole%'
        AND eventTime > timestamp '2026-04-10 01:15:00'
        AND eventTime < timestamp '2026-04-11 00:00:00'
    ORDER BY eventTime ASC
    LIMIT 100
  " \
  --region sa-east-1
```

**Passo 3.3** — Query de detecção de criação de backdoor ou persistência:

```bash
aws cloudtrail start-query \
  --query-statement "
    -- Detectar criação de credenciais ou usuários após comprometimento
    SELECT
        eventTime,
        eventName,
        userIdentity.arn,
        sourceIPAddress,
        requestParameters.userName AS usuario_criado,
        requestParameters.policyArn AS policy_anexada
    FROM ${EDS_ID}
    WHERE
        eventName IN ('CreateUser', 'CreateAccessKey', 'AttachUserPolicy',
                      'CreateRole', 'AttachRolePolicy', 'CreatePolicy')
        AND eventSource = 'iam.amazonaws.com'
        AND eventTime > timestamp '2026-04-10 01:00:00'
        AND eventTime < timestamp '2026-04-11 00:00:00'
    ORDER BY eventTime ASC
  " \
  --region sa-east-1
```

---

## Seção 4 — Preservação de Evidências

**Passo 4.1** — Criar snapshots de preservação ANTES do isolamento:

```python
import boto3
import json
import time
import hashlib
from datetime import datetime, timezone

def preservar_evidencias_instancia(instance_id, incident_id, region='sa-east-1'):
    ec2 = boto3.client('ec2', region_name=region)
    
    # Obter informações da instância
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    
    evidencias = {
        'incident_id': incident_id,
        'instance_id': instance_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'instance_state': instance['State']['Name'],
        'vpc_id': instance.get('VpcId'),
        'subnet_id': instance.get('SubnetId'),
        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
        'iam_role': instance.get('IamInstanceProfile', {}).get('Arn', 'None'),
        'public_ip': instance.get('PublicIpAddress', 'None'),
        'private_ip': instance.get('PrivateIpAddress'),
        'tags': {t['Key']: t['Value'] for t in instance.get('Tags', [])},
        'volumes': []
    }
    
    # Snapshot de cada volume
    for mapping in instance.get('BlockDeviceMappings', []):
        vol_id = mapping['Ebs']['VolumeId']
        device = mapping['DeviceName']
        
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"FORENSE-{incident_id}-{instance_id}-{device}",
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
                {'Key': 'IncidentId', 'Value': incident_id},
                {'Key': 'SourceInstance', 'Value': instance_id},
                {'Key': 'DeviceName', 'Value': device},
                {'Key': 'ForensicEvidence', 'Value': 'true'},
                {'Key': 'PreservationTimestamp', 'Value': datetime.now(timezone.utc).isoformat()},
                {'Key': 'DataClassification', 'Value': 'Confidential-ForensicEvidence'}
            ]}]
        )
        
        evidencias['volumes'].append({
            'volume_id': vol_id,
            'device': device,
            'snapshot_id': snap['SnapshotId']
        })
        print(f"Snapshot: {snap['SnapshotId']} para {vol_id} ({device})")
    
    # Hash de documentação para chain of custody
    doc_hash = hashlib.sha256(
        json.dumps(evidencias, sort_keys=True).encode()
    ).hexdigest()
    evidencias['chain_of_custody_hash'] = doc_hash
    
    print(f"\nEvidências preservadas. Chain of custody hash: {doc_hash}")
    print(json.dumps(evidencias, indent=2, ensure_ascii=False))
    
    return evidencias

# Executar preservação
evidencias = preservar_evidencias_instancia(
    instance_id='i-0a1b2c3d4e5f67890',
    incident_id='INC-2026-LAB-005',
    region='sa-east-1'
)
```

---

## Seção 5 — Isolamento da Instância

**Passo 5.1** — Isolar a instância comprometida:

```bash
INSTANCE_ID="i-0a1b2c3d4e5f67890"
INCIDENT_ID="INC-2026-LAB-005"
VPC_ID=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --region sa-east-1 \
  --query 'Reservations[0].Instances[0].VpcId' \
  --output text)

# Criar SG de quarentena
SG_QUARANTENA=$(aws ec2 create-security-group \
  --group-name "QUARENTENA-$INCIDENT_ID" \
  --description "QUARENTENA IR - $INCIDENT_ID - SEM TRAFEGO" \
  --vpc-id $VPC_ID \
  --region sa-east-1 \
  --query 'GroupId' \
  --output text)

echo "SG Quarentena: $SG_QUARANTENA"

# Remover regra de egress padrão
aws ec2 revoke-security-group-egress \
  --group-id $SG_QUARANTENA \
  --region sa-east-1 \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# Mover instância para SG de quarentena
aws ec2 modify-instance-attribute \
  --instance-id $INSTANCE_ID \
  --region sa-east-1 \
  --groups $SG_QUARANTENA

echo "Instância isolada em SG de quarentena"

# Tags de quarentena
aws ec2 create-tags \
  --resources $INSTANCE_ID \
  --region sa-east-1 \
  --tags \
    Key=Quarantine,Value=true \
    Key=IncidentId,Value=$INCIDENT_ID \
    "Key=IsolatedAt,Value=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    Key=GuardDutyFinding,Value="Backdoor:EC2/C&CActivity.B"

echo "Tags de quarentena aplicadas"
```

---

## Seção 6 — Análise de Artefatos Forenses

**Passo 6.1** — Montar snapshot em instância de análise forense:

```bash
# Criar instância de análise forense em subnet isolada
FORENSICS_INSTANCE=$(aws ec2 run-instances \
  --region sa-east-1 \
  --image-id ami-0123456789abcdef0 \
  --instance-type t3.medium \
  --subnet-id subnet-forensics \
  --security-group-ids sg-forensics \
  --no-associate-public-ip-address \
  --iam-instance-profile Name=ForensicsInstanceProfile \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ForensicsAnalysis},{Key=IncidentId,Value=INC-2026-LAB-005}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

# Criar volume a partir do snapshot (READ-ONLY não é suportado em volumes EBS)
# Usar somente leitura na montagem via OS
FORENSICS_VOLUME=$(aws ec2 create-volume \
  --region sa-east-1 \
  --snapshot-id <SNAPSHOT_ID_FROM_STEP_4> \
  --availability-zone sa-east-1a \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=ForensicCopy,Value=true},{Key=IncidentId,Value=INC-2026-LAB-005}]' \
  --query 'VolumeId' \
  --output text)

# Anexar à instância de análise
aws ec2 attach-volume \
  --volume-id $FORENSICS_VOLUME \
  --instance-id $FORENSICS_INSTANCE \
  --device /dev/sdf \
  --region sa-east-1
```

**Passo 6.2** — Comandos de análise forense no sistema de arquivos (na instância forense):

```bash
# Na instância de análise forense via Session Manager:

# Calcular hash antes de qualquer acesso
sha256sum /dev/sdf > /forensic/hash_original_$(date +%Y%m%d_%H%M%S).txt
sha256sum /dev/sdf1 >> /forensic/hash_original_$(date +%Y%m%d_%H%M%S).txt

# Montar em READ-ONLY
mkdir -p /mnt/evidencia
mount -o ro /dev/sdf1 /mnt/evidencia

# Verificar processos que estavam rodando (cron, init services)
cat /mnt/evidencia/etc/cron.d/* 2>/dev/null
crontab -l 2>/dev/null
cat /mnt/evidencia/etc/rc.local 2>/dev/null

# Verificar arquivos modificados recentemente (últimas 48h)
find /mnt/evidencia -mtime -2 -type f | head -50

# Verificar bash history de todos os usuários
for user_dir in /mnt/evidencia/home/*; do
  echo "=== $user_dir ==="
  cat "$user_dir/.bash_history" 2>/dev/null
done
cat /mnt/evidencia/root/.bash_history 2>/dev/null

# Verificar arquivos de malware comuns
find /mnt/evidencia -name "*.sh" -perm /111 -newer /mnt/evidencia/etc/passwd | head -20
find /mnt/evidencia/tmp -type f
find /mnt/evidencia/var/tmp -type f

# Verificar conexões estabelecidas no momento do snapshot (via /proc se disponível)
cat /mnt/evidencia/proc/net/tcp 2>/dev/null | head -20
```

---

## Seção 7 — Construção da Timeline Completa

**Passo 7.1** — Executar query SQL final de reconstrução de timeline:

```python
import boto3
import json
from datetime import datetime

cloudtrail = boto3.client('cloudtrail', region_name='sa-east-1')

def construir_timeline_incidente(eds_id, instance_id, inicio, fim):
    query = f"""
    WITH eventos_instancia AS (
        -- Eventos gerados pelo role da instância (via IMDS)
        SELECT
            eventTime,
            eventName,
            eventSource,
            userIdentity.arn AS ator,
            sourceIPAddress AS ip_origem,
            awsRegion AS regiao,
            requestParameters,
            errorCode,
            'INSTANCIA_ROLE' AS tipo_evento
        FROM {eds_id}
        WHERE
            userIdentity.arn LIKE '%{instance_id}%'
            AND eventTime BETWEEN timestamp '{inicio}' AND timestamp '{fim}'

        UNION ALL

        -- Eventos que afetaram a instância
        SELECT
            eventTime,
            eventName,
            eventSource,
            userIdentity.arn AS ator,
            sourceIPAddress AS ip_origem,
            awsRegion AS regiao,
            requestParameters,
            errorCode,
            'SOBRE_INSTANCIA' AS tipo_evento
        FROM {eds_id}
        WHERE
            resources[0].arn LIKE '%{instance_id}%'
            AND eventTime BETWEEN timestamp '{inicio}' AND timestamp '{fim}'
    )
    SELECT * FROM eventos_instancia
    ORDER BY eventTime ASC
    """

    response = cloudtrail.start_query(
        QueryStatement=query
    )
    
    query_id = response['QueryId']
    print(f"Query disparada: {query_id}")
    print("Aguardar 30-60 segundos e consultar com:")
    print(f"aws cloudtrail get-query-results --event-data-store {eds_id} --query-id {query_id}")
    
    return query_id

# Executar
query_id = construir_timeline_incidente(
    eds_id='<EDS_ID>',
    instance_id='i-0a1b2c3d4e5f67890',
    inicio='2026-04-08 00:00:00',
    fim='2026-04-11 00:00:00'
)
```

---

## Seção 8 — Relatório de IR (Template)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║         RELATÓRIO DE RESPOSTA A INCIDENTE — BANCO MERIDIAN                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Incidente ID: INC-2026-LAB-005                                            ║
║  Classificação: CONFIDENCIAL                                                ║
║  Data/Hora Abertura: 2026-04-10 14:32 BRT                                 ║
║  Data/Hora Contenção: 2026-04-10 14:47 BRT (15 minutos de MTTC)          ║
║  Analista IR: [Nome]                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

1. RESUMO EXECUTIVO
   Instância EC2 i-0a1b2c3d4e5f67890 comprometida com backdoor C2.
   Comunicação com IP russo 185.220.101.15:4444 durante ~13 horas.
   Contida às 14:47 BRT via isolamento em SG de quarentena.
   Vetor inicial: [A DETERMINAR via análise forense].

2. TIMELINE DO INCIDENTE
   [Preencher com resultados das queries CloudTrail Lake]

   2026-04-10 01:15 UTC - First seen: comunicação C2 detectada pelo GuardDuty
   2026-04-10 01:15 UTC - [Determinar: primeiro acesso à instância]
   2026-04-10 14:32 UTC - GuardDuty gera finding HIGH
   2026-04-10 14:32 UTC - EventBridge → SNS → Alerta para IR Analyst
   2026-04-10 14:45 UTC - Snapshot forense criado
   2026-04-10 14:47 UTC - Instância isolada em SG de quarentena

3. VETOR INICIAL (a determinar)
   Hipótese 1: Exploração de vulnerabilidade em aplicação web exposta
   Hipótese 2: Credenciais SSM ou S3 vazadas
   Hipótese 3: Imagem Docker comprometida
   Evidência: [Preencher com achados da análise forense — Seção 6]

4. IMPACTO
   [Preencher com achados das queries — quais buckets/dados foram acessados]

5. INDICADORES DE COMPROMETIMENTO (IoCs)
   - IP C2: 185.220.101.15 (Rússia)
   - Porta: 4444 (TCP)
   - [Hashes de malware encontrados na forense]
   - [Domínios DNS suspeitos se identificados]

6. AÇÕES EXECUTADAS
   6.1 Contenção: Instância isolada em SG de quarentena
   6.2 Evidência: Snapshot EBS criado (chain of custody hash: XXXXX)
   6.3 Notificação: SNS enviado para time de segurança

7. RECOMENDAÇÕES
   7.1 Aplicar patches de segurança na nova instância
   7.2 Revisar qual porta/serviço foi explorado e corrigir
   7.3 Implementar IMDSv2 (requerer versão 2 do IMDS)
   7.4 Revisar Security Group da instância
   7.5 Atualizar Threat Intel com IoCs descobertos

8. APROVAÇÕES
   Analista IR: _________________ Data: _______
   Security Manager: ____________ Data: _______
```

---

## Gabarito — Timeline Completa do Comprometimento

| Timestamp (UTC) | Evento | Fonte | Indicador |
|---|---|---|---|
| Dia 1, 00:00 | Instância com vulnerabilidade conhecida (CVE CRITICAL no Inspector) | Inspector | Nenhum alerta configurado |
| Dia 1, 01:00 | Port probe na porta 8080 (app web) de IP externo | VPC Flow Logs | GuardDuty: PortProbe (LOW — não alertado) |
| Dia 1, 01:12 | Exploração bem-sucedida — shell reverso estabelecido | VPC Flow Logs | VPC FL: conexão estabelecida porta 4444 |
| Dia 1, 01:15 | GuardDuty detecta: `Backdoor:EC2/C&CActivity.B` | GuardDuty | Finding HIGH gerado |
| Dia 1, 01:15 | Atacante começa reconhecimento via IMDS: GetCredentials | CloudTrail | `GetCredentials` from internal IP |
| Dia 1, 01:20 | Atacante usa credenciais do role para listar buckets S3 | CloudTrail | `ListBuckets` from instance |
| Dia 1, 14:32 | IR Analyst notificado (atraso de 13h — sem EventBridge para HIGH) | SNS | Finding gerado em 01:15 mas sem rule |
| Dia 1, 14:45 | Snapshot forense criado | EC2 | Chain of custody iniciada |
| Dia 1, 14:47 | Instância isolada | EC2 | SG quarentena aplicado |

**Causa Raiz:** EventBridge rule para GuardDuty HIGH não estava configurada. Finding ficou no console sem resposta automática por 13 horas.
