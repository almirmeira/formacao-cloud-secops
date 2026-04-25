# Lab 05 — Detective: Investigação Forense de EC2 Comprometida

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 05 — Investigação de Incidentes
**Nível:** Avançado

---

## Seção 1 — Contexto Situacional

Esta é uma investigação real simulada. O GuardDuty gerou um finding crítico às 03h14 BRT: `Backdoor:EC2/C&CActivity.B` para a instância `i-0a1b2c3d4e5f67890` na conta Meridian-Prod (444444444444). O finding indica que a instância está se comunicando de forma persistente com um servidor de Command and Control (C2) em 185.220.101.15 — um IP conhecido como nó de saída da rede Tor, frequentemente associado a infraestrutura criminosa.

O campo `firstSeen` do finding indica 01h15 BRT — ou seja, a instância estava comprometida por quase 2 horas antes do alerta. Durante esse tempo, o atacante teve acesso ao IAM role da instância via Instance Metadata Service (IMDS) — e potencialmente exfiltrou credenciais temporárias para uso externo.

Este laboratório simula o processo real de resposta a incidente e forense em AWS, seguindo as fases do NIST SP 800-61: Detecção → Análise → Contenção → Erradicação → Recuperação → Lições Aprendidas.

---

## Seção 2 — Situação Inicial

É sexta-feira, 10 de abril de 2026, 03h24 BRT. O alarme do PagerDuty acorda Carlos (Analista L1 de plantão). Ele escalona para Mariana, que escalona para você.

**Finding do GuardDuty recebido via SNS (03h24 BRT):**

```
ALERTA CRÍTICO — GuardDuty Finding HIGH
════════════════════════════════════════════════════════════
 Tipo:         Backdoor:EC2/C&CActivity.B
 Severidade:   7.8 (HIGH)
 Conta:        444444444444 (Meridian-Prod)
 Região:       sa-east-1
 Instância:    i-0a1b2c3d4e5f67890
 IAM Role:     EC2AppRole
 C2 IP:        185.220.101.15 (Tor exit node — Rússia)
 Porta:        4444 (Metasploit padrão)
 First Seen:   2026-04-10T01:15:00Z   ← 2h antes do alerta!
 Last Seen:    2026-04-10T03:14:00Z
 Contagem:     1.847 conexões registradas
════════════════════════════════════════════════════════════
```

Mariana te liga às 03h27:

> "Você viu o finding? A instância está se comunicando com Tor. O IAM role dela tem acesso a buckets S3 de dados de clientes do banco. Precisamos saber: o atacante conseguiu exfiltrar dados? Quais credenciais foram comprometidas? E precisamos isolar a instância AGORA antes de fazer qualquer outra coisa."

---

## Seção 3 — Problema Identificado

**03h30 — Triagem inicial e determinação do escopo do comprometimento:**

O finding `Backdoor:EC2/C&CActivity.B` indica que a instância executa um backdoor que se comunica com um C2. As perguntas críticas são:

1. **Como o atacante entrou?** — Exploit, credencial comprometida, código malicioso implantado?
2. **O que o atacante fez durante as 2 horas?** — Exfiltração, criação de backdoors, movimentação lateral?
3. **Quais credenciais da instância foram usadas externamente?** — O IMDS foi acessado?
4. **Qual é o impacto nos dados de clientes?** — Notificação ao BACEN/LGPD necessária?

**Mapeamento MITRE ATT&CK para este incidente:**

| Fase | Técnica | ID MITRE | Indicador |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Porta 8080 aberta no SG da instância |
| Execution | Command and Scripting Interpreter | T1059 | Shell reverso para C2 185.220.101.15:4444 |
| Persistence | Server Software Component | T1505 | Webshell instalado em /tmp para acesso persistente |
| Credential Access | Cloud Instance Metadata API | T1552.005 | Acesso ao IMDS v1 para obter credenciais temporárias |
| Exfiltration | Transfer Data to Cloud Account | T1537 | Download de objetos S3 via credenciais da role EC2AppRole |
| Command and Control | Application Layer Protocol | T1071 | Comunicação C2 via Tor (porta 4444) |

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Executar investigação forense completa do comprometimento, preservar evidências com cadeia de custódia, isolar a instância, determinar o escopo de dados afetados, e documentar relatório de incidente para o CISO.

**Atividades deste laboratório:**

1. Triagem do finding GuardDuty e extração dos campos críticos (Step 1.1)
2. Pivot para o Amazon Detective e análise do behavior graph (Step 1.2)
3. Timeline com CloudTrail Lake SQL — 48h antes e depois do comprometimento (Step 1.3)
4. Análise de VPC Flow Logs para confirmar exfiltração via C2 (Step 1.4)
5. Preservação de evidências com cadeia de custódia — EBS snapshot com hash SHA-256 (Step 2.1)
6. Isolamento da instância — Security Group de quarentena (Step 2.2)
7. Revogação de credenciais temporárias da role EC2AppRole (Step 2.3)
8. Verificação do escopo de exfiltração S3 via CloudTrail Data Events (Step 3.1)
9. Relatório técnico de incidente completo (Step 4)

---

## Seção 5 — Proposição do Desafio

Ao final, você apresentará ao CISO um relatório de incidente respondendo objetivamente:

1. **Vetor inicial:** Como o atacante entrou? (evidência específica com timestamp e ARN)
2. **Janela de comprometimento:** De quando a quando o atacante teve acesso?
3. **Credenciais comprometidas:** A role EC2AppRole foi usada externamente? De qual IP?
4. **Dados afetados:** Quais buckets S3 e quais objetos específicos foram acessados?
5. **Notificação regulatória:** É necessário notificar o BACEN/ANPD? Por quê?

**Critério de aprovação:** O relatório deve conter todos os 5 pontos com evidências específicas — timestamps, ARNs, IPs, output de queries. Um relatório genérico sem evidências não é aprovado pelo CISO.

---

## Contexto Técnico

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

## Seção 8 — Gabarito Completo com Raciocínio

### Timeline Completa do Comprometimento

| Timestamp (BRT) | Evento | Fonte de Evidência | Indicador Técnico |
|---|---|---|---|
| Dia 0, 17h00 | Inspector identifica CVE-2024-1234 (CRITICAL) no servidor web da instância | Amazon Inspector | Finding CRITICAL — sem remediação agendada |
| Dia 1, 01h00 | Port scan na porta 8080 de IP externo (194.165.16.x) | VPC Flow Logs | REJECT → ACCEPT em sequência — probe bem-sucedido |
| Dia 1, 01h12 | Exploit via payload HTTP na porta 8080 — shell reverso estabelecido | VPC Flow Logs | Conexão ACCEPT de 01h12 para 185.220.101.15:4444 |
| Dia 1, 01h15 | GuardDuty gera `Backdoor:EC2/C&CActivity.B` (HIGH 7.8) | GuardDuty | firstSeen: 01h15 |
| Dia 1, 01h15 | Atacante acessa IMDS v1: `curl 169.254.169.254/latest/meta-data/iam/security-credentials/EC2AppRole` | CloudTrail | `GetCredentials` do IP interno da instância |
| Dia 1, 01h18 | Atacante lista buckets S3 com credenciais exfiltradas | CloudTrail | `ListBuckets` de IP externo 185.220.101.15 |
| Dia 1, 01h22 | Atacante faz GetObject em 47 objetos de meridian-dados-clientes/ | CloudTrail Data Events | 47 eventos `GetObject` do mesmo IP em 4 minutos |
| Dia 1, 03h14 | GuardDuty gera segundo finding — `Discovery:S3/AnomalousBehavior` | GuardDuty | Acesso anômalo ao S3 (S3 Protection detecta) |
| Dia 1, 03h24 | SNS alerta enviado ao PagerDuty (EventBridge rule ativa) | EventBridge → SNS | Latência de 2h09m por ausência de alerting para HIGH |
| Dia 1, 03h27 | IR Analyst notificado — escalação para Security Engineer | PagerDuty | Início do processo de IR |
| Dia 1, 03h30 | Snapshot forense criado com hash SHA-256 — cadeia de custódia iniciada | EC2 API | Chain of custody timestamp: 03h30 |
| Dia 1, 03h35 | Revogação de credenciais via `DateLessThan` em `aws:TokenIssueTime` | IAM API | EC2AppRole: deny all sessions emitidas antes de 03h35 |
| Dia 1, 03h38 | Instância isolada com Security Group de quarentena (zero ingress/egress) | EC2 API | SG sg-quarentena-20260410 aplicado |

---

### Passo 1.1 — Gabarito: Extração de Campos do Finding GuardDuty

**Comando correto:**
```bash
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Instancia:Resource.InstanceDetails.InstanceId,
    Role:Resource.InstanceDetails.IamInstanceProfile.Arn,
    C2_IP:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,
    C2_Porta:Service.Action.NetworkConnectionAction.RemotePortDetails.Port,
    C2_Pais:Service.Action.NetworkConnectionAction.RemoteIpDetails.Country.CountryName,
    PrimeiraVez:Service.EventFirstSeen,
    UltimaVez:Service.EventLastSeen,
    Contagem:Service.Count
  }'
```

**Por que esta é a resposta correta:** Os campos `EventFirstSeen` e `EventLastSeen` determinam a janela do comprometimento — crítico para estimar o escopo do dano. O `IamInstanceProfile.Arn` identifica qual role teve credenciais potencialmente exfiltradas. O `Country.CountryName` confirma a geolocalização do C2.

**Output esperado com anotações:**
```json
{
  "Tipo": "Backdoor:EC2/C&CActivity.B",
  "Severidade": 7.8,
  "Instancia": "i-0a1b2c3d4e5f67890",        // Isolar este recurso primeiro
  "Role": "arn:aws:iam::444444444444:instance-profile/EC2AppRole",  // Verificar permissões
  "C2_IP": "185.220.101.15",                   // Tor exit node — alto risco
  "C2_Porta": 4444,                            // Metasploit reverse shell padrão
  "C2_Pais": "Russia",                         // Geolocalização do C2
  "PrimeiraVez": "2026-04-10T01:15:00Z",      // CRÍTICO: 2h antes do alerta
  "UltimaVez": "2026-04-10T03:14:00Z",        // Comprometimento durou 2h em atividade
  "Contagem": 1847                             // 1.847 conexões registradas
}
```

**Erros comuns:**
- Usar a timestamp do alerta SNS (03h24) em vez do `EventFirstSeen` (01h15): subestima o tempo de comprometimento em 2h09m — erro crítico para determinar escopo
- Não verificar o IAM Role antes de investigar S3: sem saber as permissões da role, não é possível saber quais dados foram potencialmente acessados

---

### Passo 2.1 — Gabarito: Preservação de Evidências com Cadeia de Custódia

**Sequência correta:**
```bash
# 1. Identificar volumes da instância
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids i-0a1b2c3d4e5f67890 \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)
echo "Volumes: $VOLUMES"

# 2. Criar snapshot com metadata forense
TIMESTAMP_IR=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_ID=$(aws ec2 create-snapshot \
  --volume-id $VOLUMES \
  --description "IR-FORENSE-Meridian-${TIMESTAMP_IR}" \
  --tag-specifications \
    "ResourceType=snapshot,Tags=[
      {Key=Purpose,Value=ForenseIR},
      {Key=IncidentID,Value=INC-20260410-001},
      {Key=CreatedBy,Value=SecurityEngineer},
      {Key=ChainOfCustody,Value=Ativo}
    ]" \
  --query 'SnapshotId' --output text)
echo "Snapshot criado: $SNAPSHOT_ID"

# 3. Aguardar conclusão e calcular hash para cadeia de custódia
aws ec2 wait snapshot-completed --snapshot-ids $SNAPSHOT_ID
echo "Snapshot concluído. Calculando hash SHA-256 para cadeia de custódia..."

# Hash do ARN + Timestamp para cadeia de custódia
HASH_CADEIA=$(echo -n "arn:aws:ec2:sa-east-1:444444444444:snapshot/${SNAPSHOT_ID}:${TIMESTAMP_IR}" | sha256sum | cut -d' ' -f1)
echo "Hash cadeia de custódia: $HASH_CADEIA"
echo "Registrar este hash no ticket de incidente INC-20260410-001"
```

**Por que esta é a resposta correta:** A cadeia de custódia é um requisito forense e legal. O hash SHA-256 do identificador único do snapshot, combinado com o timestamp, cria uma impressão digital que prova que a evidência não foi alterada desde a coleta. Se o caso resultar em processo judicial ou ação regulatória, essa cadeia de custódia é a diferença entre evidência válida e inadmissível.

**Erros comuns:**
- Criar snapshot APÓS isolar a instância: o estado do sistema de arquivos pode mudar entre o comprometimento e o isolamento — idealmente, o snapshot é criado antes de qualquer modificação no estado da instância
- Não registrar o hash em local externo (ticket, log imutável): hash só no ambiente AWS não serve como cadeia de custódia independente

---

### Passo 2.3 — Gabarito: Revogação de Credenciais EC2AppRole

**Comando correto para revogar credenciais temporárias:**
```bash
# REVOGAR SESSÕES ANTERIORES — bloqueia todas as credenciais emitidas antes de agora
# Esta técnica invalida tokens temporários existentes via condição de tempo de emissão
HORA_REVOGACAO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > /tmp/policy-revoke-session.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RevokeOldSessions",
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "${HORA_REVOGACAO}"
        }
      }
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "EC2AppRole" \
  --policy-name "EmergencyRevokeAllSessions" \
  --policy-document file:///tmp/policy-revoke-session.json

echo "Credenciais da EC2AppRole emitidas antes de $HORA_REVOGACAO foram revogadas"
```

**Por que esta é a resposta correta:** Credenciais temporárias do IAM (geradas via `sts:AssumeRole` ou Instance Profile) não podem ser "excluídas" — elas existem na memória do atacante. A única forma de invalidá-las é adicionar uma política de `Deny` que inclui a condição `DateLessThan` no `aws:TokenIssueTime`. Qualquer credencial emitida antes da hora de revogação passa a receber `Deny` em toda e qualquer ação.

**Alternativa inaceitável:**
```bash
# ERRADO: Apenas excluir a role não revoga credenciais já emitidas!
aws iam delete-role --role-name EC2AppRole
# Credenciais temporárias existentes continuam válidas até o timeout natural (horas)
```

---

### Passo 3.1 — Gabarito: Determinação do Escopo de Exfiltração S3

**Query CloudTrail Lake para identificar dados acessados:**
```sql
-- Quais objetos S3 foram acessados com as credenciais da EC2AppRole
-- no IP externo 185.220.101.15 (C2 do atacante)?
SELECT
    eventTime,
    userIdentity.arn,
    userIdentity.sessionContext.sessionIssuer.arn AS role_usada,
    sourceIPAddress,
    eventName,
    resources[1].ARN AS bucket_e_objeto,
    requestParameters.key AS objeto_especifico
FROM <EDS_ID>
WHERE
    userIdentity.arn LIKE '%EC2AppRole%'
    AND sourceIPAddress = '185.220.101.15'
    AND eventSource = 's3.amazonaws.com'
    AND eventName IN ('GetObject', 'ListBucket', 'PutObject', 'DeleteObject')
    AND eventTime BETWEEN timestamp '2026-04-10 01:15:00' AND timestamp '2026-04-10 03:38:00'
ORDER BY eventTime ASC
```

**Por que esta é a resposta correta:** Filtrar por `sourceIPAddress = '185.220.101.15'` (o C2) garante que estamos vendo apenas acessos feitos pelo atacante externamente — não os acessos legítimos da instância. O campo `requestParameters.key` mostra o caminho exato do objeto acessado, essencial para determinar quais dados de clientes foram expostos e se há obrigação de notificação ao BACEN/ANPD.

**Output esperado:**
```
eventTime                    eventName  objeto_especifico
2026-04-10T01:18:00Z        ListBucket  (bucket listagem)
2026-04-10T01:19:00Z        GetObject  clientes/2026/01/cadastros.parquet
2026-04-10T01:19:01Z        GetObject  clientes/2026/01/transacoes.parquet
... (47 objetos no total)
2026-04-10T01:22:00Z        GetObject  clientes/2026/03/saldos.parquet
```

**Conclusão para o relatório:** 47 objetos do bucket `meridian-dados-clientes` foram acessados, contendo dados de cadastro e transações de clientes do Banco Meridian. Segundo a LGPD (Art. 48) e BACEN Resolução 4.893 (Art. 11), há obrigação de notificação à ANPD e ao BACEN em até 72 horas após a ciência do incidente.

---

### Causa Raiz do Incidente

**Causa Raiz Técnica:** O IMDS v1 (sem IMDSv2) permite que qualquer processo na instância — incluindo um shell reverso — faça requisições ao endpoint `169.254.169.254` sem autenticação. A migração para IMDSv2 (token obrigatório) teria impedido que o atacante obtivesse as credenciais da role.

**Ação Corretiva Imediata:**
```bash
# Exigir IMDSv2 em todas as instâncias existentes (token obrigatório)
aws ec2 modify-instance-metadata-options \
  --instance-id i-0a1b2c3d4e5f67890 \
  --http-tokens required \
  --http-endpoint enabled

# SCP para impedir criação de instâncias com IMDSv1 na organização
# (adicionar ao conjunto de SCPs implementadas no Lab 01)
```

**Causa Raiz Operacional:** Finding HIGH `Backdoor:EC2/C&CActivity.B` gerado às 01h15 permaneceu no console sem resposta por 2h09m — a EventBridge rule para GuardDuty HIGH não estava configurada. A automação de resposta (Lab 06) teria isolado a instância em segundos, reduzindo drasticamente o impacto.

**Critérios de Aprovação do Lab:**
- Timeline completa com todos os 9 eventos identificados corretamente: OBRIGATÓRIO
- Snapshot com cadeia de custódia (hash SHA-256 registrado): OBRIGATÓRIO
- Revogação de credenciais via `DateLessThan` (não exclusão de role): OBRIGATÓRIO
- Query CloudTrail Lake para escopo de exfiltração com resultado numérico: OBRIGATÓRIO
- Conclusão sobre obrigação de notificação regulatória fundamentada: OBRIGATÓRIO
