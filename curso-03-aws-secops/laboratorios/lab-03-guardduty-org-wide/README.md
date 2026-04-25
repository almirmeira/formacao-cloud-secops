# Lab 03 — GuardDuty Organization-Wide: Deploy e Análise de Findings

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 03 — Amazon GuardDuty
**Nível:** Intermediário/Avançado

---

## Seção 1 — Contexto Situacional

O Banco Meridian passou por um incidente de segurança no mês anterior: um atacante obteve credenciais de um desenvolvedor via phishing e usou essas credenciais para fazer chamadas de API em `us-east-1`. O GuardDuty estava habilitado apenas na região `sa-east-1` da conta Production — em `us-east-1`, havia zero cobertura de detecção. O finding de `InstanceCredentialExfiltration` só foi gerado depois que o atacante já havia feito download de três buckets S3.

O CISO emitiu diretriz urgente: cobertura total do GuardDuty em todas as contas e regiões, com a Audit Account como ponto centralizado de análise. Qualquer nova conta adicionada à organização deve ter GuardDuty habilitado automaticamente, sem intervenção manual.

---

## Seção 2 — Situação Inicial

É quarta-feira, 16 de abril de 2026, 08h00. Você abre o console da Audit Account e verifica o estado de cobertura do GuardDuty:

```
GUARDDUTY — BANCO MERIDIAN (Estado Atual — 16/04/2026)
────────────────────────────────────────────────────────────────────
 Conta: Meridian-Mgmt (111111111111)   → GuardDuty: DESABILITADO
 Conta: Meridian-Audit (222222222222)  → GuardDuty: DESABILITADO
 Conta: Meridian-Logs (333333333333)   → GuardDuty: DESABILITADO
 Conta: Meridian-Prod (444444444444)   → GuardDuty: HABILITADO (sa-east-1 apenas)

 Delegated Admin:       Não configurado
 Auto-enable:           DESABILITADO
 S3 Protection:         DESABILITADO (na conta Production)
 Malware Protection:    DESABILITADO
 EKS Audit Logs:        DESABILITADO
────────────────────────────────────────────────────────────────────
 Cobertura org.:   25%  (1 de 4 contas — apenas 1 região)
 Findings ativos:   3   (só na Production, sa-east-1)
 Últimas 24h:       0 alertas HIGH
────────────────────────────────────────────────────────────────────
```

Mariana chega às 08h15 com o relatório do incidente anterior em mãos:

> "Olha aqui o timeline do ataque de março. O atacante usou credenciais do Lucas — desenvolvedor — para fazer chamadas à API em `us-east-1`. O GuardDuty estava ativo apenas em `sa-east-1` na Production. Em `us-east-1`, zero detecção. Ele operou por 2 horas sem nenhum alerta, fez download de três buckets S3, e saiu. Só descobrimos quando o Lucas reportou o comportamento estranho na sua conta."

Carlos envia mensagem no Slack às 08h22:

> "Se o GuardDuty tivesse habilitado o S3 Protection na época, o finding `Discovery:S3/AnomalousBehavior` teria aparecido nos primeiros 10 minutos. Mas como estava desabilitado, o único finding que apareceu foi de `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — e só depois que os dados já haviam sido exfiltrados."

Você abre o ticket **SECOPS-2055 — Implementar GuardDuty organization-wide com cobertura total** e começa.

---

## Seção 3 — Problema Identificado

**09h00 — Mapeamento técnico do gap de cobertura:**

O problema se desdobra em cinco dimensões:

1. **Gap de conta:** 3 das 4 contas sem GuardDuty — ataques nessas contas são invisíveis ao time de segurança
2. **Gap de região:** a conta Production cobre apenas `sa-east-1` — ataques em `us-east-1` e `us-east-2` não geram findings
3. **Gap de feature:** S3 Protection e Malware Protection desabilitados — as técnicas mais usadas pelo atacante do incidente de março não são detectadas
4. **Ausência de centralização:** sem delegated admin na Audit Account, cada conta tem seu próprio painel — o time de segurança precisa fazer login em cada conta individualmente para ver os findings
5. **Sem auto-enable:** cada nova conta adicionada à organização nasce sem GuardDuty — requer ação manual que frequentemente é esquecida

**Mapeamento MITRE ATT&CK:**
- **T1078.004** (Valid Accounts: Cloud Accounts) — atacante usou credenciais comprometidas
- **T1619** (Cloud Storage Object Discovery) — mapeamento de buckets S3
- **T1537** (Transfer Data to Cloud Account) — exfiltração via download de S3

Sem GuardDuty com S3 Protection, **nenhuma dessas três técnicas geraria alerta automático**.

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Habilitar GuardDuty com cobertura organizacional completa, configurar a Audit Account (222222222222) como delegated administrator, ativar todas as features de proteção, e demonstrar análise de findings simulados.

**Atividades deste laboratório:**

1. Habilitar GuardDuty na Management Account e configurar delegated admin
2. Na Audit Account: configurar auto-enable com todas as features para novas contas
3. Adicionar as contas membro ao GuardDuty organizacional
4. Gerar sample findings para análise
5. Analisar e classificar os 5 findings com resposta correta para cada
6. Criar suppression rule para scanner de vulnerabilidades autorizado (Qualys)
7. Configurar EventBridge para notificação automática de findings HIGH

---

## Seção 5 — Proposição do Desafio

Carlos vai simular um ataque às 11h: ele executará um comando que gera um finding do tipo `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` na conta Production. Você precisa:

1. Identificar o finding em menos de 2 minutos após a geração
2. Extrair: usuário IAM afetado, IP externo de destino, país de origem, e número de eventos
3. Descrever a resposta correta em ordem: quais credenciais revogar, quais ações de contenção executar

**Critério de aprovação:** Encontrar e documentar o finding completo, e demonstrar o comando correto de revogação de credenciais com o arquivo de revogação de sessão (via `put-role-policy` com `Deny` em `sts:*` condicionado ao tempo de emissão).

---

## Contexto Técnico

O Amazon GuardDuty é o serviço de detecção de ameaças inteligente da AWS. Ele analisa automaticamente as fontes de dados da sua conta — CloudTrail, VPC Flow Logs, DNS Logs, e logs adicionais de S3, EKS, RDS e Lambda — para identificar atividade maliciosa ou não autorizada, sem exigir agentes ou infraestrutura adicional.

---

## Pré-requisitos

- AWS Organizations configurado com OUs (Lab 01 concluído)
- Acesso às contas Management (111111111111) e Audit (222222222222)
- AWS CLI e console disponíveis

---

## Seção 1 — Deploy GuardDuty Organization-Wide

### Passo 1.1 — Habilitar GuardDuty na Management Account e configurar delegated admin

**O que este passo faz:** Dois comandos em sequência: o primeiro cria o detector GuardDuty na Management Account (111111111111) — o detector é o componente que recebe e armazena as configurações do GuardDuty em uma conta/região específica; o segundo (`enable-organization-admin-account`) transfere a autoridade administrativa do GuardDuty para a conta Audit (222222222222), que a partir deste momento passa a gerenciar todos os detectors de todas as contas-membro. A conta Management não deve ser usada para operações de segurança do dia a dia — ela contém apenas o OrganizationAdminAccount e as SCPs, não ferramentas operacionais.

**Por que esta ordem:** O detector da Management Account deve existir antes da delegação de admin — sem ele, o `enable-organization-admin-account` falhará. A sequência é: criar detector → delegar admin → ir para a conta Audit → configurar auto-enable.

**Por que isso importa para o Banco Meridian:** O incidente de março aconteceu porque o GuardDuty estava habilitado apenas em `sa-east-1` da conta Production — e o atacante operou em `us-east-1`. Com a delegação de administrador para a conta Audit e auto-enable org-wide (Passo 1.2), qualquer nova conta ou região terá GuardDuty habilitado automaticamente, eliminando os pontos cegos que permitiram o ataque de março operar por 2 horas sem detecção.

**Permissão IAM necessária:** `guardduty:CreateDetector` na Management Account; `guardduty:EnableOrganizationAdminAccount` e `organizations:EnableAWSServiceAccess` na Management Account.

```bash
# Habilitar detector na Management Account
DETECTOR_MGMT=$(aws guardduty create-detector \
  --enable \
  --region sa-east-1 \
  --query 'DetectorId' \
  --output text)

echo "Detector Management Account: $DETECTOR_MGMT"

# Configurar delegated administrator
aws guardduty enable-organization-admin-account \
  --admin-account-id 222222222222 \
  --region sa-east-1

echo "Delegated Admin configurado para conta Audit (222222222222)"
```

### Passo 1.2 — Na Audit Account, configurar auto-enable e features

**O que este passo faz:** Com a delegação de admin configurada no Passo 1.1, este passo opera na conta Audit (222222222222) para configurar três comportamentos: (1) `auto-enable ALL` garante que qualquer conta nova adicionada ao Organizations receberá GuardDuty habilitado automaticamente — cobertura por design; (2) a lista de `features` com `AutoEnable: ALL` ativa todas as fontes de dados avançadas em todas as contas existentes e novas: S3 Data Events (detecta acesso anômalo a S3), EKS Audit Logs, Malware Protection para EC2 e S3, RDS Login Activity, Lambda Network Activity e Runtime Monitoring. O valor `ALL` significa "habilitar em novas contas E em contas existentes".

**Por que esta ordem:** Este passo só pode ser executado após a delegação de admin (Passo 1.1) e após assumir as credenciais da conta Audit. O detector da conta Audit (criado automaticamente quando a delegação é estabelecida) deve existir antes de configurar o `update-organization-configuration`.

**Por que isso importa para o Banco Meridian:** Cada feature ativada corresponde a uma superfície de ataque coberta: `S3_DATA_EVENTS` detectaria o download dos 47 objetos S3 com credenciais comprometidas (cenário do Lab 05); `MALWARE_PROTECTION` detectaria arquivos maliciosos em instâncias EC2 e buckets S3; `RDS_LOGIN_EVENTS` detectaria brute force em bancos de dados financeiros. Sem `AutoEnable: ALL`, uma conta Production (444444444444) requer configuração manual de cada feature — criando janelas de exposição.

```bash
# Assumir role na Audit Account
AUDIT_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/OrganizationAccountAccessRole \
  --role-session-name GuardDutyAdmin \
  --query 'Credentials' \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo $AUDIT_CREDS | python3 -c "import json,sys; print(json.load(sys.stdin)['SessionToken'])")

# Obter detector ID da Audit Account
DETECTOR_AUDIT=$(aws guardduty list-detectors \
  --region sa-east-1 \
  --query 'DetectorIds[0]' \
  --output text)

echo "Detector Audit Account: $DETECTOR_AUDIT"

# Configurar auto-enable para todas as features em novas contas
aws guardduty update-organization-configuration \
  --detector-id $DETECTOR_AUDIT \
  --auto-enable ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "MALWARE_PROTECTION", "AutoEnable": "ALL"},
    {"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "ALL"},
    {"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]' \
  --region sa-east-1

echo "Auto-enable configurado"
```

**Passo 1.3** — Verificar membros:

```bash
aws guardduty list-members \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --query 'Members[].{Conta:AccountId,Status:RelationshipStatus,Features:DetectorId}' \
  --output table
```

**Resultado Esperado:**

```
Conta         Status     Features
444444444444  Enabled    Enabled
333333333333  Enabled    Enabled
```

**Troubleshooting:**
- Conta não aparece como membro: verificar se a conta está na organização correta
- `DetectorAlreadyExists`: o detector já existe — usar `list-detectors` para obter o ID existente

---

## Seção 2 — Gerar Sample Findings

**Passo 2.1** — Gerar findings de exemplo:

```bash
# Gerar TODOS os tipos de sample findings
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-types \
    "CryptoCurrency:EC2/BitcoinTool.B" \
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" \
    "Exfiltration:S3/AnomalousBehavior" \
    "Recon:EC2/PortProbeUnprotectedPort" \
    "Malware:EC2/MaliciousFile"

echo "Sample findings gerados — aguardar 30 segundos"
sleep 30
```

### Passo 2.2 — Listar os findings gerados

**O que este passo faz:** Consulta os findings do detector da conta Audit filtrando apenas os sample findings (campo `sample: true`). Em produção, este comando sem o filtro `sample` retornaria findings reais. O filtro `--query 'FindingIds'` extrai apenas os IDs dos findings — que serão usados nos passos seguintes para obter detalhes de cada finding individualmente.

**O que você deve ver:** Uma lista de IDs de findings no formato `"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`. Se a lista estiver vazia, aguardar mais 30 segundos (os sample findings podem levar até 2 minutos para ser processados).

```bash
aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "sample": {
        "Equals": ["true"]
      }
    }
  }' \
  --query 'FindingIds' \
  --output text
```

---

## Seção 3 — Análise do Finding 1: CryptoCurrency EC2

**Passo 3.1** — Obter detalhes do finding de cryptomining:

```bash
# Filtrar o finding de cryptomining
CRYPTO_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["CryptoCurrency:EC2/BitcoinTool.B"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

# Obter detalhes completos
aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $CRYPTO_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Conta:AccountId,
    Regiao:Region,
    Instancia:Resource.InstanceDetails.InstanceId,
    IP_Destino:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,
    Descricao:Description
  }' \
  --output json
```

**Análise Esperada:**

| Campo | Valor | Interpretação |
|---|---|---|
| Tipo | `CryptoCurrency:EC2/BitcoinTool.B` | Instância comunicando com domínio/IP de pool de mineração |
| Severidade | HIGH (7.5) | Comprometimento confirmado — resposta imediata |
| Instância | `i-XXXXXXXXX` | Instância afetada |
| IP Destino | IP de pool de criptomoeda | Servidor de mineração conhecido |

**Resposta Correta para Cryptomining:**

```bash
# 1. Isolar instância imediatamente
echo "AÇÃO: Criar SG de quarentena e mover instância"

# 2. Criar snapshot de evidência
echo "AÇÃO: aws ec2 create-snapshot --volume-id <VOL_ID> --description 'Evidência Forense - Cryptomining'"

# 3. Analisar via CloudTrail Lake
echo "QUERY: SELECT * FROM EDS WHERE resources[0].arn LIKE '%<INSTANCE_ID>%' AND eventTime > timestamp '48 hours ago' ORDER BY eventTime DESC"
```

---

## Seção 4 — Análise do Finding 2: IAM Credential Exfiltration

### Passo 4.1 — Obter detalhes do finding de exfiltração de credenciais

**O que este passo faz:** Busca e exibe os detalhes do finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — o finding que indica que credenciais temporárias de um IAM role (obtidas via IMDS da instância EC2) estão sendo usadas a partir de um endereço IP externo à infraestrutura AWS. Os campos mais críticos extraídos são: `AccessKeyId` (identifica exatamente qual chave está sendo usada externamente), `IP_Externo` (endereço do atacante), e `API_Chamada` (o que o atacante está fazendo com as credenciais).

**Por que isso importa para o Banco Meridian:** Este finding é a sequência direta do `Backdoor:EC2/C&CActivity.B` analisado na Seção 3. Quando uma instância é comprometida com backdoor C2, o próximo passo típico do atacante é acessar o IMDS (http://169.254.169.254/latest/meta-data/iam/security-credentials/) para obter credenciais temporárias da role IAM — e usá-las externamente. Com IMDSv1 (sem token), qualquer código rodando na instância, incluindo malware, pode fazer essa consulta sem autenticação. O `IP_Externo` aqui é o mesmo C2 do finding anterior — confirma que é o mesmo atacante.

**Ação imediata ao ver este finding:** A role IAM deve ser revogada imediatamente usando a técnica `DateLessThan` no `aws:TokenIssueTime` — não basta excluir a role, pois as credenciais temporárias já emitidas continuam válidas até o timeout natural (até 12 horas).

```bash
CRED_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $CRED_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Usuario:Resource.AccessKeyDetails.UserName,
    AccessKeyId:Resource.AccessKeyDetails.AccessKeyId,
    IP_Externo:Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4,
    Pais:Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryName,
    API_Chamada:Service.Action.AwsApiCallAction.Api
  }' \
  --output json
```

**Checklist de Resposta:**

- [ ] Desabilitar access key comprometida: `aws iam update-access-key --status Inactive`
- [ ] Verificar quais ações foram executadas: CloudTrail Lake query por `accessKeyId`
- [ ] Verificar se novos usuários foram criados: CloudTrail query por `CreateUser`
- [ ] Verificar acesso a dados sensíveis: S3 Data Events com o mesmo `accessKeyId`
- [ ] Verificar se há novas access keys criadas pela identidade comprometida

---

## Seção 5 — Análise do Finding 3: S3 Exfiltration

### Passo 5.1 — Analisar finding de exfiltração via S3

**O que este passo faz:** Extrai os detalhes do finding de exfiltração via S3 — gerado pelo modelo de machine learning do GuardDuty quando detecta um padrão de download de objetos S3 que é estatisticamente anômalo em relação ao baseline histórico da conta. Os campos-chave extraídos incluem o bucket afetado e o número de operações de `GetObject` que excederam o padrão normal. Este finding só é gerado se S3 Data Events estiverem habilitados no GuardDuty (Passo 1.2 deste lab) e no CloudTrail (Lab 02).

**Por que isso importa para o Banco Meridian:** Este finding corresponde exatamente ao incidente de março: o atacante, com credenciais temporárias da role EC2, baixou 47 objetos do bucket `meridian-dados-clientes`. O GuardDuty detectou o download massivo porque o baseline não incluía esse volume de `GetObject` de um IP externo. Para o BACEN 4.893 Art. 11 e LGPD Art. 48, este finding é a evidência inicial que dispara o processo de notificação ao regulador em até 72 horas.

```bash
S3_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Exfiltration:S3/AnomalousBehavior"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $S3_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Bucket:Resource.S3BucketDetails[0].Name,
    Operacao:Service.Action.S3BucketAction.RequestParameters.RequestMethod,
    API:Service.Action.AwsApiCallAction.Api,
    Descricao:Description
  }' \
  --output json
```

**Questões de Investigação:**

1. Qual era o volume normal de downloads desse bucket? (comparar com baseline ML do GuardDuty)
2. Quais objetos específicos foram acessados? (S3 Data Events no CloudTrail)
3. O IP de origem é interno ou externo?
4. Há outros buckets acessados pelo mesmo IP/identidade?

---

## Seção 6 — Análise do Finding 4: Port Probe (LOW) e Suppression Rules

### Passo 6.1 — Analisar o finding de Port Probe

**O que este passo faz:** Recupera os detalhes do finding `Recon:EC2/PortProbeUnprotectedPort`, que é gerado quando o GuardDuty detecta tentativas externas de probe em portas abertas de uma instância EC2. Este finding tem severidade LOW porque port probing é comum na internet — scanners automáticos tentam portas em todos os IPs públicos continuamente. O campo `RemoteIpDetails` revela o IP de origem do probe, que determina se é um falso positivo (scanner autorizado, Shodan, etc.) ou um reconhecimento real.

**Por que isso importa para o Banco Meridian:** O Banco Meridian contrata a PentestCorp para testes de intrusão autorizados mensalmente. Durante cada ciclo de pentest, dezenas de findings `Recon:EC2/PortProbeUnprotectedPort` são gerados, inundando o painel de findings e treinando inadvertidamente a equipe a ignorar alertas LOW — o que é um risco operacional real. A Suppression Rule do Passo 6.2 resolve isso de forma documentada e auditável.

```bash
PORT_FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]},
      "sample": {"Equals": ["true"]}
    }
  }' \
  --query 'FindingIds[0]' \
  --output text)

# Verificar o IP de origem do probe
aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --finding-ids $PORT_FINDING_ID \
  --query 'Findings[0].Service.Action.PortProbeAction.PortProbeDetails[0].RemoteIpDetails'
```

### Passo 6.2 — Criar suppression rule para scanners autorizados

**O que este passo faz:** Cria um filtro do GuardDuty com ação `ARCHIVE` — findings que correspondem aos critérios são automaticamente arquivados sem aparecer no painel ativo. Os critérios combinados (AND implícito) são: finding type `Recon:EC2/PortProbeUnprotectedPort` E IP de origem exato `203.0.113.50` (scanner Qualys autorizado). O finding não é excluído — permanece consultável ao filtrar por `status: ARCHIVED`.

**Por que isso importa para o Banco Meridian:** Esta Suppression Rule é a resposta correta para o ruído operacional do scanner Qualys autorizado. A alternativa incorreta — desabilitar o GuardDuty durante scans — criaria janela de exposição real. A regra com nome descritivo (`AuthorizedVulnerabilityScanner-Qualys`) é auditável pelo BACEN: mostra que o noise reduction é intencional e documentado, não descuido.

```bash
# Criar suppression rule para o scanner de vulnerabilidades Qualys
aws guardduty create-filter \
  --detector-id $DETECTOR_AUDIT \
  --region sa-east-1 \
  --name "AuthorizedVulnerabilityScanner-Qualys" \
  --description "Suprimir port probes do scanner Qualys autorizado - IP: 203.0.113.50" \
  --action ARCHIVE \
  --rank 1 \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Equals": ["Recon:EC2/PortProbeUnprotectedPort"]
      },
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4": {
        "Equals": ["203.0.113.50"]
      }
    }
  }'

echo "Suppression rule criada para Qualys"
```

**Troubleshooting:**
- `BadRequestException`: verificar sintaxe do JSON das finding criteria
- A suppression rule aplica apenas a findings FUTUROS — findings existentes precisam ser arquivados manualmente

---

## Seção 7 — Configurar EventBridge para Resposta Automática

### Passo 7.1 — Criar regra EventBridge para findings HIGH

**O que este passo faz:** Configura o pipeline de alertas automáticos para findings GuardDuty com severidade HIGH (>= 7.0). São três recursos criados: (1) um tópico SNS `MeridianGuardDutyAlerts-HIGH` como canal de distribuição; (2) uma subscrição de e-mail para o time de segurança; (3) uma regra EventBridge com event pattern que filtra eventos do GuardDuty com `severity >= 7.0` e roteia para o SNS. O `InputTransformer` formata a mensagem com os campos mais relevantes do finding, permitindo que o time de segurança receba informação acionável diretamente no e-mail.

**Por que esta ordem:** O SNS topic deve existir antes da regra EventBridge. A subscrição de e-mail deve ser confirmada pelo destinatário para estar ativa.

**Por que isso importa para o Banco Meridian:** No incidente de março, o finding `Backdoor:EC2/C&CActivity.B` ficou no console por 2 horas e 9 minutos sem notificação. Com esta regra, o mesmo finding dispararia um alerta em segundos — conectado com o Lab 06 (Lambda de isolamento automático), o MTTC cairia de horas para minutos.

```bash
# Criar SNS topic para notificações (se não existir)
SNS_ARN=$(aws sns create-topic \
  --name MeridianSecurityAlerts-HIGH \
  --region sa-east-1 \
  --query 'TopicArn' \
  --output text)

aws sns subscribe \
  --topic-arn $SNS_ARN \
  --protocol email \
  --notification-endpoint "secops@bancomeridian.com.br"

# Criar regra EventBridge
aws events put-rule \
  --name "MeridianGuardDutyHighSeverity" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}]
    }
  }' \
  --state ENABLED \
  --description "Roteamento de findings GuardDuty HIGH para SNS" \
  --region sa-east-1

# Adicionar SNS como target
aws events put-targets \
  --rule "MeridianGuardDutyHighSeverity" \
  --region sa-east-1 \
  --targets '[{
    "Id": "SNSHighAlert",
    "Arn": "'$SNS_ARN'",
    "InputTransformer": {
      "InputPathsMap": {
        "severity": "$.detail.severity",
        "type": "$.detail.type",
        "account": "$.account",
        "region": "$.region"
      },
      "InputTemplate": "\"[ALERTA GuardDuty HIGH] Tipo: <type> | Severidade: <severity> | Conta: <account> | Região: <region>\""
    }
  }]'

echo "EventBridge rule configurada"
```

---

## Seção 8 — Relatório de Findings e Análise

```python
import boto3
import json
from datetime import datetime, timezone

def analisar_findings_guardduty(detector_id, region='sa-east-1'):
    gd = boto3.client('guardduty', region_name=region)
    
    # Listar todos os findings ativos (exceto sample)
    response = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'service.archived': {'Equals': ['false']},
                'sample': {'Equals': ['false']}
            }
        },
        SortCriteria={'AttributeName': 'severity', 'OrderBy': 'DESC'},
        MaxResults=50
    )
    
    finding_ids = response.get('FindingIds', [])
    
    if not finding_ids:
        print("Nenhum finding ativo encontrado (excluindo samples)")
        return
    
    findings = gd.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']
    
    # Agrupar por severidade
    por_severidade = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
    
    for f in findings:
        sev = f.get('Severity', 0)
        if sev >= 7.0:
            por_severidade['HIGH'].append(f)
        elif sev >= 4.0:
            por_severidade['MEDIUM'].append(f)
        else:
            por_severidade['LOW'].append(f)
    
    print(f"\n=== Relatório GuardDuty — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ===")
    print(f"Total de findings ativos: {len(findings)}")
    print(f"HIGH: {len(por_severidade['HIGH'])}")
    print(f"MEDIUM: {len(por_severidade['MEDIUM'])}")
    print(f"LOW: {len(por_severidade['LOW'])}")
    
    print("\n--- Findings HIGH (resposta imediata) ---")
    for f in por_severidade['HIGH']:
        print(f"  [HIGH] {f['Type']} | Conta: {f['AccountId']} | {f['CreatedAt']}")
    
    print("\n--- Findings MEDIUM (investigar em 24h) ---")
    for f in por_severidade['MEDIUM']:
        print(f"  [MED] {f['Type']} | Conta: {f['AccountId']}")

# Exemplo de uso (requer DETECTOR_ID real)
# analisar_findings_guardduty('DETECTOR_ID_AQUI')
print("Script de análise pronto — executar com detector_id real")
```

---

## Seção 8 — Gabarito Completo com Raciocínio

### Configuração do Delegated Admin — Resposta Correta

**Comandos corretos (em sequência):**
```bash
# 1. Na Management Account — habilitar GuardDuty e delegar admin
aws guardduty enable-organization-admin-account \
  --admin-account-id 222222222222 \
  --region sa-east-1

# 2. Na Audit Account — configurar auto-enable
DETECTOR_AUDIT=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty update-organization-configuration \
  --detector-id $DETECTOR_AUDIT \
  --auto-enable ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "MALWARE_PROTECTION", "AutoEnable": "ALL"},
    {"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "ALL"},
    {"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]'
```

**Por que esta é a resposta correta:** A ordem importa: primeiro habilitar o delegated admin (passo 1) antes de configurar o auto-enable (passo 2). Tentar configurar `update-organization-configuration` antes de `enable-organization-admin-account` resulta em erro de autorização. O valor `"AutoEnable": "ALL"` garante que TODAS as contas (existentes e futuras) recebam a feature — `NEW` habilitaria apenas para contas futuras.

**Erros comuns:**
- Usar `"AutoEnable": "NEW"` em vez de `"ALL"`: contas existentes não seriam cobertas — precisaria adicionar manualmente
- Esquecer de repetir o `enable-organization-admin-account` para cada região onde GuardDuty deve operar

---

### Finding 1 — CryptoCurrency:EC2/BitcoinTool.B — Resposta Correta

**Análise do finding:**
```bash
aws guardduty get-findings \
  --detector-id $DETECTOR_AUDIT \
  --finding-ids $CRYPTO_FINDING_ID \
  --query 'Findings[0].{
    Tipo:Type,
    Severidade:Severity,
    Instancia:Resource.InstanceDetails.InstanceId,
    IP_Pool_Mineracao:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,
    Dominio:Service.Action.DnsRequestAction.Domain,
    EventCount:Service.Count
  }'
```

**Por que esta é a resposta correta:** Para cryptomining, os campos críticos são o `InstanceId` (o que isolar), o `IpAddressV4` ou `Domain` do pool de mineração (confirma o TTP), e o `Count` (quantas conexões ocorreram — indica duração do comprometimento).

**Output esperado com anotações:**
```json
{
  "Tipo": "CryptoCurrency:EC2/BitcoinTool.B",
  "Severidade": 7.5,                           // HIGH — resposta imediata
  "Instancia": "i-0a1b2c3d4e5f67890",          // Isolar este recurso
  "IP_Pool_Mineracao": "198.51.100.45",         // IP de pool de mineração conhecido
  "Dominio": "pool.hashfort.com",               // Domínio de mining pool
  "EventCount": 342                             // 342 conexões — comprometimento antigo
}
```

**Sequência de resposta obrigatória (ordem importa):**
```bash
# 1. ISOLAR — antes de qualquer análise (impede exfiltração adicional)
aws ec2 create-security-group \
  --group-name "QUARENTENA-$(date +%Y%m%d)" \
  --description "Quarentena IR - sem ingress nem egress"
QUARENTENA_SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=QUARENTENA-$(date +%Y%m%d)" \
  --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 modify-instance-attribute \
  --instance-id i-0a1b2c3d4e5f67890 \
  --groups $QUARENTENA_SG_ID

# 2. PRESERVAR EVIDÊNCIAS — antes de terminar a instância
aws ec2 describe-instances --instance-ids i-0a1b2c3d4e5f67890 \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId'
aws ec2 create-snapshot \
  --volume-id vol-0abc123 \
  --description "FORENSE-cryptomining-$(date +%Y%m%d)"

# 3. INVESTIGAR VETOR — via CloudTrail Lake
# O que aconteceu ANTES do finding? Quem instalou o software de mining?
```

**Erros comuns:**
- Terminar a instância sem criar snapshot primeiro — perda de evidências forenses
- Só revogar SG sem verificar se há acesso via Session Manager ainda ativo

---

### Finding 2 — UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS — Resposta Correta

**Por que esta é a resposta correta:** As credenciais de instância EC2 (geradas via Instance Metadata Service - IMDS) foram usadas em um IP fora da AWS. Isso indica que alguém copiou as credenciais temporárias da instância e está usando-as externamente — provavelmente após acesso ao IMDS via SSRF ou código malicioso na instância.

**Sequência de resposta:**
```bash
# 1. REVOGAR CREDENCIAIS DA SESSION — política de Deny por tempo de emissão
# Impede imediatamente qualquer uso de credenciais temporárias emitidas antes de agora
cat > /tmp/revoke-session.json << 'EOF'
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
          "aws:TokenIssueTime": "2026-04-16T11:00:00Z"
        }
      }
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "ec2-prod-worker" \
  --policy-name "RevokeAllOldSessions" \
  --policy-document file:///tmp/revoke-session.json

# 2. ISOLAR A INSTÂNCIA (fonte das credenciais vazadas)
aws ec2 modify-instance-attribute \
  --instance-id i-0a1b2c3d4e5f67890 \
  --groups $QUARENTENA_SG_ID

# 3. INVESTIGAR VIA CLOUDTRAIL — quais ações foram executadas com a credencial
```

**Erros comuns:**
- Revogar apenas a role sem a política de Deny por `TokenIssueTime`: credenciais temporárias já emitidas continuam válidas até o timeout natural (até 12 horas)
- Investigar antes de revogar: cada minuto de delay é oportunidade para mais dano

---

### Suppression Rule — Resposta Correta

**Configuração correta:**
```bash
aws guardduty create-filter \
  --detector-id $DETECTOR_AUDIT \
  --name "AuthorizedVulnerabilityScanner-Qualys" \
  --description "Suprimir port probes do scanner Qualys autorizado (IP: 203.0.113.50)" \
  --action ARCHIVE \
  --rank 1 \
  --finding-criteria '{
    "Criterion": {
      "type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]},
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4": {
        "Equals": ["203.0.113.50"]
      }
    }
  }'
```

**Por que esta é a resposta correta:** A suppression rule deve ser ESPECÍFICA — `type` E `IP de origem`. Uma suppression pelo tipo genérico (`Recon:EC2/PortProbeUnprotectedPort`) sem filtro de IP suprimiria TODOS os port probes, incluindo ataques reais. A combinação de tipo + IP garante que apenas os scans do Qualys sejam suprimidos.

**Variações aceitáveis:** O `rank 1` define prioridade (1 = maior prioridade). Para múltiplas regras, regras mais específicas devem ter rank menor (maior prioridade). A `action ARCHIVE` é equivalente a "suppressed" — findings são arquivados automaticamente sem gerar alerta.

---

### Resumo de Respostas por Finding

| Finding | Tipo | Severidade | Sequência de Resposta | SLA |
|---|---|---|---|---|
| 1 — Cryptomining | `CryptoCurrency:EC2/BitcoinTool.B` | HIGH (7.5) | Isolar SG → Snapshot → Investigate → Terminate | < 15 min |
| 2 — Cred Exfilt. | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | HIGH (8.0) | Revoke Session (DateLessThan) → Isolar instância → CloudTrail investigation | < 5 min |
| 3 — S3 Exfilt. | `Exfiltration:S3/AnomalousBehavior` | HIGH (7.0) | Block principal → S3 Data Events investigation → Notificar DPO | < 30 min |
| 4 — Port Probe | `Recon:EC2/PortProbeUnprotectedPort` | LOW (2.0) | Verificar IP → Se autorizado: suppression rule | 24-72h |
| 5 — Malware EC2 | `Malware:EC2/MaliciousFile` | HIGH (8.0) | Isolar SG → Análise do hash (GuardDuty Malware Protection já fez snapshot) → Remediar | < 15 min |

**Critérios de Aprovação:**
- GuardDuty habilitado em todas as 4 contas com delegated admin na Audit Account: OBRIGATÓRIO
- Auto-enable configurado com `AutoEnable: ALL`: OBRIGATÓRIO
- Suppression rule com filtro por tipo E IP específico: OBRIGATÓRIO
- EventBridge rule ativa com threshold de severidade >= 7.0: OBRIGATÓRIO
- Análise correta dos 5 findings com resposta na sequência certa: 5 pontos (1 por finding)
