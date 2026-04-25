# Lab 01 — Organizations e SCPs: Governança Multi-Conta

**Curso 3: AWS Cloud Security Operations · CECyber**
**Duração:** 2 horas
**Módulo Correspondente:** Módulo 01 — Fundamentos AWS Security
**Nível:** Intermediário

---

## Seção 1 — Contexto Situacional

O Banco Meridian opera quatro contas AWS criadas organicamente ao longo de três anos: uma conta de gestão (Meridian-Mgmt), uma de auditoria (Meridian-Audit), uma de logs (Meridian-Logs) e uma de produção (Meridian-Prod). O crescimento aconteceu sem planejamento de governança, e as quatro contas coexistem sob o AWS Organizations sem OUs definidas e sem nenhuma Service Control Policy ativa.

Durante uma auditoria interna preparatória para a revisão do BACEN (Resolução 4.893), o time de compliance identificou que:

- Desenvolvedores da conta Production têm permissão para criar recursos em qualquer região do mundo, incluindo Singapura e Frankfurt — fora do perímetro aprovado pelo CISO
- Não há proteção técnica que impeça o uso da conta root nas quatro contas
- Não há restrição técnica que impeça a desabilitação do CloudTrail
- Objetos S3 podem ser criados sem criptografia em qualquer das quatro contas

O Banco Meridian precisa regularizar essa situação antes da próxima janela de auditoria, daqui a 30 dias.

---

## Seção 2 — Situação Inicial

É segunda-feira, 14 de abril de 2026, 09h00. Você chega ao escritório e abre o console AWS. O painel do AWS Organizations mostra as quatro contas, todas na raiz, sem OUs. O Security Hub está com 47 findings ativos, sendo 8 classificados como CRITICAL — todos relacionados a configurações de IAM e ausência de controles preventivos.

**Estado atual da organização:**

```
AWS Organizations — Banco Meridian
────────────────────────────────────────────
 Management Account: 111111111111 (Meridian-Mgmt)
────────────────────────────────────────────
 Root
 ├── 111111111111  Meridian-Mgmt      (sem OU)
 ├── 222222222222  Meridian-Audit     (sem OU)
 ├── 333333333333  Meridian-Logs      (sem OU)
 └── 444444444444  Meridian-Prod      (sem OU)

 SCPs ativas:       1  (apenas FullAWSAccess — sem restrições)
 OUs configuradas:  0
 Guardrails:        Nenhum
────────────────────────────────────────────
```

Mariana (Analista L2) entra na sala e comenta:

> "O relatório da auditoria interna saiu ontem à noite. Temos 30 dias para implementar controles preventivos ou o compliance não vai aprovar a certificação do BACEN. O maior risco apontado é a ausência total de SCPs — qualquer desenvolvedor com uma role permissiva pode criar recursos em Frankfurt ou desabilitar o CloudTrail."

Você abre o ticket no JIRA: **SECOPS-2041 — Implementar estrutura de governança AWS Organizations com OUs e SCPs preventivas**. O prazo é fim do dia. Vamos ao trabalho.

---

## Seção 3 — Problema Identificado

**09h15 — Carlos (Analista L1) envia mensagem no Slack:**

> "Acabei de verificar: a conta Meridian-Prod tem uma instância EC2 rodando em `eu-west-1` (Irlanda). Ninguém sabe quem criou. O CloudTrail mostra que foi criada ontem às 23h47 por `arn:aws:iam::444444444444:user/dev-pipeline-ci` via CLI. Isso está dentro do permitido pela política IAM da conta, mas Irlanda não é uma região aprovada."

O achado confirma o risco identificado na auditoria: sem SCPs, qualquer identidade com permissões IAM pode operar em qualquer região. A situação concreta é:

- **Finding crítico:** recurso provisionado em região não aprovada (`eu-west-1`)
- **Vetor:** usuário de pipeline CI com permissão `ec2:RunInstances` ampla
- **Risco:** dados de produção podem estar sendo processados fora da jurisdição aprovada pelo BACEN
- **MITRE ATT&CK:** T1562.008 (Disable or Modify Cloud Logs) — risco potencial dado que não há proteção do CloudTrail

**Diagnóstico técnico via CloudTrail Lake:**

```sql
-- Query para confirmar o escopo do problema
SELECT
    eventTime,
    userIdentity.arn,
    sourceIPAddress,
    awsRegion,
    eventName,
    requestParameters
FROM <EDS_ID>
WHERE
    awsRegion NOT IN ('sa-east-1', 'us-east-1', 'us-east-2')
    AND eventTime > DATE_ADD('day', -7, NOW())
    AND eventSource = 'ec2.amazonaws.com'
ORDER BY eventTime DESC
```

O resultado mostra 3 instâncias EC2 em regiões não aprovadas. A situação é mais abrangente do que o alerta inicial indicava.

---

## Seção 4 — Roteiro de Atividades

**Objetivo geral:** Implementar a estrutura completa de governança preventiva no AWS Organizations do Banco Meridian.

**Atividades deste laboratório:**

1. Explorar o estado atual da organização (Seção de Exploração)
2. Criar a hierarquia de OUs (Security, Production, Development, Sandbox)
3. Mover as contas para as OUs corretas
4. Criar as 4 SCPs preventivas críticas (DenyRoot, DenyRegions, DenyUnencryptedS3, ProtectCloudTrail)
5. Aplicar as SCPs nas OUs e na Root
6. Testar e validar cada SCP
7. Usar o IAM Policy Simulator para confirmar o bloqueio
8. Gerar relatório de conformidade para o ticket SECOPS-2041

**Resultado esperado ao final:** Organização com 4 OUs, 4 SCPs ativas, instâncias em regiões não aprovadas bloqueadas, CloudTrail protegido de modificação.

---

## Seção 5 — Proposição do Desafio

Você tem 2 horas para implementar os controles preventivos. Ao final, Mariana vai testar três cenários:

1. Tentar criar um EC2 em `ap-southeast-1` — deve ser bloqueado pela SCP DenyNonApprovedRegions
2. Tentar fazer upload de arquivo S3 sem criptografia — deve ser bloqueado pela SCP DenyUnencryptedS3
3. Tentar desabilitar o CloudTrail — deve ser bloqueado pela SCP ProtectCloudTrail

Se qualquer um dos três testes passar, o laboratório não estará concluído.

**Atenção:** SCPs NÃO afetam o Management Account (111111111111). Este é um comportamento esperado do AWS Organizations — jamais aplique SCPs a contas de produção sem entender esse detalhe.

---

## Seção 6 — Script Passo a Passo

### Passo 1 — Exploração do Ambiente Atual

**O que este passo faz:** Antes de qualquer mudança na organização, este passo documenta o estado atual: quais contas existem, em que posição hierárquica estão, e se o recurso de SCPs está habilitado. Esses três comandos criam o baseline que permite comparar o estado antes e depois da implementação dos controles. Sem esse baseline, seria impossível provar para a auditoria que as mudanças foram deliberadas e planejadas.

**Por que isso importa para o Banco Meridian:** A Resolução BACEN 4.893 exige que mudanças em controles de acesso sejam documentadas com evidência do estado anterior. O Banco Meridian está em fase de preparação para auditoria — qualquer alteração feita sem registro do ponto de partida pode ser questionada pelo auditor como "mudança não planejada". Este passo também confirma que as quatro contas (111111111111, 222222222222, 333333333333, 444444444444) estão todas presentes e ativas antes de reorganizá-las em OUs.

```bash
# Verificar estrutura atual da organização
aws organizations describe-organization
aws organizations list-roots
aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text)
```

**Resultado esperado:**
```json
{
  "Organization": {
    "MasterAccountId": "111111111111",
    "AvailablePolicyTypes": [
      {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
    ]
  }
}
```

**Interpretando o resultado:** `MasterAccountId: "111111111111"` confirma que você está conectado à Management Account correta (Meridian-Mgmt) — qualquer outro valor indica credenciais erradas. `AvailablePolicyTypes` com `"Status": "ENABLED"` é pré-requisito absoluto: se aparecer `"DISABLED"` ou a lista estiver vazia, nenhuma SCP criada nos próximos passos terá qualquer efeito, e todo o trabalho seguinte será inócuo. O campo `list-organizational-units-for-parent` deve retornar lista vazia — confirmando que não há OUs ainda.

```bash
# Listar todas as contas atuais
aws organizations list-accounts \
  --query 'Accounts[].{Nome:Name,ID:Id,Email:Email,Status:Status}' \
  --output table
```

**Resultado esperado:**
```
ID             Nome              Email                        Status
111111111111   Meridian-Mgmt     mgmt@bancomeridian.com.br    ACTIVE
222222222222   Meridian-Audit    audit@bancomeridian.com.br   ACTIVE
333333333333   Meridian-Logs     logs@bancomeridian.com.br    ACTIVE
444444444444   Meridian-Prod     prod@bancomeridian.com.br    ACTIVE
```

**Interpretando o resultado:** Cada linha é uma conta AWS da organização. A coluna `Status: ACTIVE` confirma que a conta está operacional e pode receber SCPs. Contas com status `SUSPENDED` ou `PENDING_CLOSURE` não devem ser movidas para OUs de produção. Note que a Management Account (111111111111) aparece na listagem, mas ela é imune a SCPs — qualquer controle aplicado à Root ou às OUs não afeta essa conta.

**Troubleshooting:**
- Se `AvailablePolicyTypes` estiver vazio: habilitar SCPs no console Organizations → Policies → Service control policies → Enable
- Se receber `AWSOrganizationsNotInUseException`: a organização não foi criada ainda

---

### Passo 2 — Criação das OUs

**O que este passo faz:** Este passo cria a hierarquia lógica de Organizational Units que segmenta as quatro contas por função de segurança e criticidade operacional. OUs são os contêineres onde SCPs serão aplicadas com granularidade — sem OUs, toda SCP precisaria ser aplicada diretamente à Root (afetando todas as contas sem distinção) ou a cada conta individualmente (ineficiente e propenso a erros). A sequência correta é: capturar o Root ID, criar as OUs usando esse ID como parent, e então mover as contas para suas OUs corretas.

**Por que isso importa para o Banco Meridian:** O BACEN exige segregação de ambientes — a conta de produção (Meridian-Prod, 444444444444) não deve ter as mesmas políticas que a conta de desenvolvimento. A estrutura de OUs permite que futuramente o Banco Meridian adicione SCPs mais restritivas na OU Production (por exemplo, bloqueando qualquer modificação de security groups sem aprovação) sem afetar as contas de Audit e Logs que têm necessidades operacionais diferentes. Essa separação é evidência concreta de "segregação de ambientes" perante o auditor do BACEN.

```bash
# Capturar o ID da Root
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Root ID: $ROOT_ID"

# OU: Security (abrigará Audit e Log Archive)
OU_SECURITY=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Security" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Security criada: $OU_SECURITY"

# OU: Production (abrigará Meridian-Prod)
OU_PRODUCTION=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Production" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Production criada: $OU_PRODUCTION"

# OU: Development
OU_DEVELOPMENT=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Development" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Development criada: $OU_DEVELOPMENT"

# OU: Sandbox
OU_SANDBOX=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Sandbox" \
  --query 'OrganizationalUnit.Id' \
  --output text)
echo "OU Sandbox criada: $OU_SANDBOX"
```

**Resultado esperado:** 4 linhas confirmando criação com IDs no formato `ou-xxxx-xxxxxxxx`.

**Interpretando o resultado:** O formato `ou-xxxx-xxxxxxxxxxxxxxxx` identifica unicamente cada OU: `ou-` é o prefixo padrão, os 4 caracteres após o hífen correspondem ao sufixo do Root ID, e o segmento final é o identificador único da OU. Salve essas variáveis em um arquivo temporário — elas serão necessárias nos passos de aplicação de SCPs e na movimentação de contas. Se qualquer variável retornar vazia (ex: `$OU_SECURITY` vazio), o comando falhou silenciosamente — verifique as permissões da role usada com `aws iam get-role --role-name <nome>`.

```bash
# Mover contas para as OUs corretas
aws organizations move-account \
  --account-id 222222222222 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_SECURITY

aws organizations move-account \
  --account-id 333333333333 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_SECURITY

aws organizations move-account \
  --account-id 444444444444 \
  --source-parent-id $ROOT_ID \
  --destination-parent-id $OU_PRODUCTION

# Verificação
aws organizations list-children \
  --parent-id $OU_SECURITY \
  --child-type ACCOUNT \
  --query 'Children[].Id'
# Esperado: ["222222222222", "333333333333"]

aws organizations list-children \
  --parent-id $OU_PRODUCTION \
  --child-type ACCOUNT \
  --query 'Children[].Id'
# Esperado: ["444444444444"]
```

**Interpretando o resultado:** O comando `move-account` não retorna output em caso de sucesso — silêncio significa êxito. A verificação com `list-children` confirma a movimentação: se `["222222222222", "333333333333"]` aparecer para a OU Security, as contas de Audit e Logs foram segregadas corretamente. A conta Meridian-Mgmt (111111111111) permanece na Root propositalmente — a Management Account não deve estar em nenhuma OU para evitar comportamentos inesperados com SCPs.

**Troubleshooting:**
- `AccountNotFoundException`: verificar se o Account ID está correto
- `SourceParentNotFoundException`: a conta pode já estar em uma OU diferente — usar `list-parents` para encontrar o parent atual

---

### Passo 3 — Criação das SCPs

**O que este passo faz:** Este passo cria os quatro documentos JSON de política e os registra no AWS Organizations como SCPs prontas para uso. Cada SCP é construída para atacar um vetor de risco específico identificado na auditoria do Banco Meridian: uso indevido de root, dispersão de dados em regiões não aprovadas, armazenamento sem criptografia e apagamento de rastros de auditoria. Os arquivos JSON são criados localmente em `/tmp/` e enviados ao Organizations via `create-policy` — neste ponto as SCPs existem na organização mas ainda não estão aplicadas a nenhum target.

**Por que isso importa para o Banco Meridian:** A criação isolada das SCPs antes da aplicação é uma boa prática de Change Management: permite revisar e validar cada JSON antes de ativar o controle. Um erro de sintaxe em uma SCP aplicada pode bloquear operações legítimas — como a SCP DenyNonApprovedRegions com `Action: "*"` (errado) em vez de `NotAction` (correto), que quebraria o IAM inteiro de todas as contas membro. A Resolução BACEN 4.893 exige que mudanças em controles de acesso sejam testadas antes da ativação em produção.

```bash
# SCP 1: DenyRootAccess
# Objetivo: Impedir o uso da conta root em todas as member accounts
# Impacto de segurança: Conta root não tem MFA obrigatório por padrão;
# seu uso contorna muitos controles. BACEN exige que acessos privilegiados
# sejam auditáveis e controlados.
cat > /tmp/scp-deny-root.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
EOF

# SCP 2: DenyNonApprovedRegions
# Objetivo: Restringir operações às regiões aprovadas (sa-east-1, us-east-1, us-east-2)
# NotAction é usado (em vez de Action) porque IAM, CloudFront e Route53 são
# serviços globais — bloqueá-los quebraria o IAM inteiro
cat > /tmp/scp-deny-regions.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*", "iam:*", "route53:*", "support:*",
        "sts:*", "globalaccelerator:*", "waf:*", "budgets:*",
        "organizations:*", "account:*", "cur:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["sa-east-1", "us-east-1", "us-east-2"]
        }
      }
    }
  ]
}
EOF

# SCP 3: DenyUnencryptedS3
# Objetivo: Garantir que todo objeto S3 use criptografia SSE-KMS ou SSE-S3
# Alinhamento BACEN 4.893: dados em repouso devem ser criptografados
cat > /tmp/scp-deny-unencrypted-s3.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3PutWithoutEncryption",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]
        }
      }
    }
  ]
}
EOF

# SCP 4: ProtectCloudTrail
# Objetivo: Proteger o CloudTrail de desabilitação por qualquer identidade
# Motivação: primeira ação de um atacante ao comprometer uma conta AWS é
# tentar apagar os rastros desabilitando o CloudTrail. Esta SCP torna
# isso tecnicamente impossível mesmo para admins da conta.
cat > /tmp/scp-protect-cloudtrail.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailModification",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors"
      ],
      "Resource": "*"
    }
  ]
}
EOF
```

```bash
# Registrar as SCPs no Organizations
SCP_ROOT_ID=$(aws organizations create-policy \
  --name "DenyRootAccess" \
  --description "Nega uso da conta root em todas as member accounts - BACEN 4.893" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-root.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyRootAccess: $SCP_ROOT_ID"

SCP_REGIONS_ID=$(aws organizations create-policy \
  --name "DenyNonApprovedRegions" \
  --description "Bloqueia uso de regioes nao aprovadas pelo Banco Meridian" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-regions.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyNonApprovedRegions: $SCP_REGIONS_ID"

SCP_S3_ID=$(aws organizations create-policy \
  --name "DenyUnencryptedS3" \
  --description "Exige criptografia em todos os objetos S3 - BACEN 4.893 Art.6" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-deny-unencrypted-s3.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP DenyUnencryptedS3: $SCP_S3_ID"

SCP_CT_ID=$(aws organizations create-policy \
  --name "ProtectCloudTrail" \
  --description "Protege CloudTrail de desabilitacao ou modificacao" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/scp-protect-cloudtrail.json \
  --query 'Policy.PolicySummary.Id' \
  --output text)
echo "SCP ProtectCloudTrail: $SCP_CT_ID"
```

**Resultado esperado:** 4 IDs no formato `p-xxxxxxxx`. Se qualquer ID estiver vazio, o comando falhou — verifique com `aws organizations list-policies --filter SERVICE_CONTROL_POLICY`.

**Interpretando o resultado:** O prefixo `p-` identifica que o objeto é uma Policy no Organizations (diferente de `r-` para Root, `ou-` para OU e `o-` para Organization). Os 8 caracteres alfanuméricos após `p-` são o identificador único da SCP. Neste momento as SCPs existem no Organizations mas estão no estado "criada, não aplicada" — elas não têm efeito sobre nenhuma conta ainda. O passo seguinte é o que ativa os controles.

---

### Passo 4 — Aplicação das SCPs às OUs

**O que este passo faz:** Este passo ativa efetivamente os controles preventivos ao anexar cada SCP ao target correto — neste caso, a Root da organização. Aplicar na Root significa que todas as member accounts herdam as políticas, independentemente de em qual OU estejam. O comando `attach-policy` é o que transforma uma SCP de "documento armazenado" para "controle ativo". A verificação final com `list-policies-for-target` confirma que os cinco itens esperados (FullAWSAccess + 4 SCPs customizadas) estão visíveis no target Root.

**Por que isso importa para o Banco Meridian:** Uma SCP criada mas não aplicada é como uma fechadura guardada em uma gaveta — o recurso existe mas não protege nada. Este passo é o momento em que os controles exigidos pelo BACEN 4.893 entram em vigor: a partir daqui, nenhuma conta membro do Banco Meridian pode criar recursos em Irlanda, Frankfurt ou Singapura, independentemente das permissões IAM que o desenvolvedor possua. A screenshot do `list-policies-for-target` com as 5 políticas é a evidência primária para o ticket SECOPS-2041.

```bash
# Aplicar todas as 4 SCPs na Root (cobertura universal para todas as contas membro)
aws organizations attach-policy \
  --policy-id $SCP_ROOT_ID \
  --target-id $ROOT_ID

aws organizations attach-policy \
  --policy-id $SCP_REGIONS_ID \
  --target-id $ROOT_ID

aws organizations attach-policy \
  --policy-id $SCP_S3_ID \
  --target-id $ROOT_ID

aws organizations attach-policy \
  --policy-id $SCP_CT_ID \
  --target-id $ROOT_ID

# Verificar políticas aplicadas na Root
aws organizations list-policies-for-target \
  --target-id $ROOT_ID \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].{Nome:Name,ID:Id}' \
  --output table
```

**Resultado esperado:**
```
Nome                    ID
FullAWSAccess           p-FullAWSAccess
DenyRootAccess          p-xxxxxxxx
DenyNonApprovedRegions  p-yyyyyyyy
DenyUnencryptedS3       p-zzzzzzzz
ProtectCloudTrail       p-aaaaaaaa
```

**Interpretando o resultado:** A tabela deve conter exatamente 5 linhas. A presença de `FullAWSAccess` com ID `p-FullAWSAccess` é esperada e obrigatória — ela é a política padrão da AWS que concede Allow a tudo, sobre a qual as quatro SCPs de Deny se sobrepõem. Este é o modelo "Deny List": concede tudo por padrão, adiciona negações específicas. Se `FullAWSAccess` for removida sem uma Allow alternativa, nenhuma ação será possível nas member accounts — situação chamada de "Allow List mode", que requer listagem explícita de todas as ações permitidas. Para o Banco Meridian, o modelo Deny List é o correto porque o time ainda não mapeou todas as ações necessárias para uma allowlist completa.

---

### Passo 5 — Testes de Validação das SCPs

**O que este passo faz:** Este passo executa testes reais nas contas membro para confirmar que cada SCP está bloqueando as ações proibidas conforme esperado. Os testes usam comandos propositalmente proibidos pelas SCPs — a resposta esperada são erros específicos de "Explicit deny in a service control policy". Além dos testes de bloqueio, o Teste 2 inclui um contra-teste positivo (upload com criptografia deve funcionar), o que confirma que a SCP não está bloqueando tudo indiscriminadamente.

**Por que isso importa para o Banco Meridian:** Controles não testados não existem do ponto de vista de auditoria. O BACEN 4.893, assim como o framework NIST CSF, exige que controles preventivos sejam validados com evidência documentada — não basta afirmar que a política foi aplicada. Os outputs de erro capturados neste passo, junto com timestamps e IDs das contas, formam o pacote de evidências para o ticket SECOPS-2041. O Teste 2 com contra-prova positiva é especialmente importante: mostra que o controle é preciso (bloqueia apenas o não permitido) e não está causando impacto operacional não intencional.

```bash
# Teste 1: DenyNonApprovedRegions
# Na conta Production (444444444444), tentar acessar recursos em região não aprovada
# Este comando deve falhar com "Explicit deny in a service control policy"
aws ec2 describe-instances --region ap-southeast-1
```

**Resultado esperado:**
```
An error occurred (UnauthorizedAccess) when calling the DescribeInstances operation:
Explicit deny in a service control policy
```

**Interpretando o resultado:** O código de erro `UnauthorizedAccess` é o identificador da rejeição por SCP em chamadas EC2. A frase literal `Explicit deny in a service control policy` no corpo do erro é a prova de que o bloqueio veio da camada de Organizations — não de uma política IAM. Se o erro retornado for `AccessDenied` sem essa frase, o bloqueio é de IAM e a SCP pode não estar aplicada corretamente. Teste este comando apenas de dentro de uma member account (222222222222, 333333333333 ou 444444444444) — na Management Account (111111111111) o comando funcionará normalmente porque SCPs não se aplicam a ela.

```bash
# Teste 2: DenyUnencryptedS3
echo "teste-meridian" > /tmp/teste-scp.txt

# Upload SEM criptografia — deve falhar
aws s3 cp /tmp/teste-scp.txt s3://meridian-test-bucket/sem-criptografia.txt

# Upload COM criptografia — deve funcionar
aws s3 cp /tmp/teste-scp.txt s3://meridian-test-bucket/com-criptografia.txt \
  --sse AES256
```

**Resultado esperado do upload sem criptografia:**
```
upload failed: An error occurred (AccessDenied) when calling the PutObject operation:
Explicit deny in a service control policy
```

**Resultado esperado do upload com criptografia:**
```
upload: /tmp/teste-scp.txt to s3://meridian-test-bucket/com-criptografia.txt
```

**Interpretando o resultado:** O primeiro upload falha porque nenhum cabeçalho de criptografia foi enviado na requisição `PutObject` — a SCP verifica o header `s3:x-amz-server-side-encryption` e, ao não encontrá-lo (ou ao encontrar valor diferente de `aws:kms` ou `AES256`), aplica o Deny. O segundo upload funciona porque `--sse AES256` instrui o CLI a adicionar o header `x-amz-server-side-encryption: AES256` na requisição, que satisfaz a condição da SCP. Este comportamento bidirecional (bloqueia sem criptografia, permite com criptografia) confirma que o controle está calibrado corretamente.

```bash
# Teste 3: ProtectCloudTrail
aws cloudtrail stop-logging --name "test-trail"
```

**Resultado esperado:**
```
An error occurred (AccessDeniedException) when calling the StopLogging operation:
Explicit deny in a service control policy
```

**Interpretando o resultado:** O erro `AccessDeniedException` com a frase de SCP confirma que a tentativa de parar o CloudTrail foi bloqueada na camada de Organizations. Este é o cenário do vetor MITRE ATT&CK T1562.008 (Disable or Modify Cloud Logs) — a SCP ProtectCloudTrail torna esse vetor tecnicamente inviável em qualquer member account do Banco Meridian. Mesmo um administrador com política IAM `AdministratorAccess` não consegue executar `StopLogging`, `DeleteTrail`, `UpdateTrail` ou `PutEventSelectors` — a SCP é a barreira máxima que o IAM não pode sobrescrever.

```bash
# Teste 4: IAM Policy Simulator para confirmar DenyRootAccess
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/admin-test \
  --action-names sts:GetSessionToken \
  --resource-arns "*" \
  --context-entries '[{"ContextKeyName":"aws:PrincipalArn","ContextKeyValues":["arn:aws:iam::444444444444:root"],"ContextKeyType":"string"}]' \
  --query 'EvaluationResults[0].{Acao:EvalActionName,Decisao:EvalDecision}'
```

**Resultado esperado:**
```json
{
  "Acao": "sts:GetSessionToken",
  "Decisao": "explicitDeny"
}
```

**Interpretando o resultado:** O simulador injeta o contexto `aws:PrincipalArn` com valor `arn:aws:iam::444444444444:root` para simular uma chamada feita pelo usuário root da conta Meridian-Prod. O campo `Decisao: "explicitDeny"` confirma que a ação seria negada. Note que este é o único teste dos quatro que usa o simulador em vez de uma chamada real — porque não é seguro usar a conta root em ambiente de produção apenas para testar o bloqueio.

---

### Passo 6 — Policy Simulator Avançado

**O que este passo faz:** Este passo usa o IAM Policy Simulator com a opção `EvalDecisionDetails` para revelar a origem exata do bloqueio — diferenciando se o Deny vem de uma SCP (nível de Organizations), de uma política IAM, de um Permissions Boundary ou de um Resource Policy. A simulação é feita sobre a ação `cloudtrail:DeleteTrail` usando o usuário `admin-test` da conta Meridian-Prod (444444444444), que representa o perfil típico de um administrador com permissões amplas. O objetivo é produzir evidência documentada de que o controle preventivo está sendo aplicado especificamente pela camada de Organizations, não por acidente de configuração IAM.

**Por que isso importa para o Banco Meridian:** Para um auditor do BACEN, há diferença fundamental entre "a ação não é permitida" e "a ação é explicitamente bloqueada por controle organizacional". O primeiro caso (`implicitDeny`) poderia ser resultado de ausência de permissão IAM — removível por qualquer administrador da conta. O segundo caso (`explicitDeny` via SCP) é um controle preventivo que não pode ser contornado por nenhum usuário da member account, incluindo o administrador local. O campo `AllowedByOrganizations: false` é a evidência técnica precisa que demonstra ao auditor que o Banco Meridian implementou controles de nível organizacional — exatamente o que o Art. 7 da Resolução 4.893 exige para ambientes com múltiplas contas.

```bash
# Verificar avaliação detalhada do DenyCloudTrail
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/admin-test \
  --action-names cloudtrail:DeleteTrail \
  --resource-arns "*" \
  --query 'EvaluationResults[0].{Acao:EvalActionName,Decisao:EvalDecision,Razao:EvalDecisionDetails}'
```

**Resultado esperado:**
```json
{
  "Acao": "cloudtrail:DeleteTrail",
  "Decisao": "explicitDeny",
  "Razao": {
    "ServiceControlPolicyDecisionDetail": {
      "AllowedByOrganizations": false
    }
  }
}
```

**Interpretando o resultado:** O campo `Decisao: "explicitDeny"` confirma que a ação foi negada por uma política explícita — não pela ausência de uma permissão Allow. A distinção entre `explicitDeny` e `implicitDeny` é crítica: `implicitDeny` significa "nenhuma política concede esta ação"; `explicitDeny` significa "uma política ativamente proíbe esta ação". O sub-campo `ServiceControlPolicyDecisionDetail.AllowedByOrganizations: false` especifica que o bloqueio origina-se especificamente de uma SCP — não de uma política IAM, Permissions Boundary ou Resource Policy. Esta combinação (`explicitDeny` + `AllowedByOrganizations: false`) é a assinatura inequívoca de um controle preventivo organizacional funcionando corretamente, e representa a evidência mais robusta que pode ser apresentada ao auditor do BACEN.

---

### Passo 7 — Documentação e Relatório

**O que este passo faz:** Gera um relatório automatizado em formato JSON de todas as SCPs ativas na organização, incluindo onde cada uma está aplicada, descrição do objetivo de segurança, contagem de targets e resumo de conformidade. O script Python usa a API do Organizations com paginação para garantir que todas as SCPs sejam capturadas, mesmo em organizações com muitas políticas. A função `gerar_relatorio_scps()` filtra a política padrão `FullAWSAccess` para focar apenas nas SCPs customizadas do Banco Meridian.

**Por que isso importa para o Banco Meridian:** Controles sem documentação não passam em auditoria — essa é uma regra invariável tanto no BACEN quanto em frameworks como ISO 27001 e NIST CSF. O relatório gerado por este script é o artefato de conformidade que fecha o ticket SECOPS-2041: ele demonstra que as 4 SCPs estão ativas, aplicadas nos targets corretos, e foram implementadas em resposta ao risco identificado. O campo `ticket: 'SECOPS-2041'` e `regulacao: 'BACEN Resolução 4.893'` no JSON vinculam o controle técnico ao requisito regulatório — exatamente o que o auditor precisa ver para validar a conformidade.

```python
import boto3
import json
from datetime import datetime

def gerar_relatorio_scps():
    organizations = boto3.client('organizations')

    relatorio = {
        'data_geracao': datetime.utcnow().isoformat(),
        'organizacao': organizations.describe_organization()['Organization']['Id'],
        'banco': 'Banco Meridian',
        'ticket': 'SECOPS-2041',
        'regulacao': 'BACEN Resolução 4.893',
        'scps': [],
        'resumo': {
            'total_scps': 0,
            'scps_na_root': 0,
            'scps_em_ou': 0
        }
    }

    paginator = organizations.get_paginator('list_policies')
    for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
        for policy in page['Policies']:
            if policy['Name'] == 'FullAWSAccess':
                continue  # Ignorar a política padrão da AWS

            policy_detail = organizations.describe_policy(PolicyId=policy['Id'])['Policy']
            targets = organizations.list_targets_for_policy(
                PolicyId=policy['Id']
            )['Targets']

            entry = {
                'nome': policy['Name'],
                'id': policy['Id'],
                'descricao': policy['Description'],
                'aplicada_em': [{'nome': t['Name'], 'tipo': t['Type']} for t in targets],
                'total_targets': len(targets)
            }
            relatorio['scps'].append(entry)
            relatorio['resumo']['total_scps'] += 1

            for t in targets:
                if t['Type'] == 'ROOT':
                    relatorio['resumo']['scps_na_root'] += 1
                elif t['Type'] == 'ORGANIZATIONAL_UNIT':
                    relatorio['resumo']['scps_em_ou'] += 1

    print(json.dumps(relatorio, indent=2, ensure_ascii=False))
    return relatorio

relatorio = gerar_relatorio_scps()
print(f"\n=== RESUMO ===")
print(f"Total de SCPs customizadas: {relatorio['resumo']['total_scps']}")
print(f"Status: {'CONFORME' if relatorio['resumo']['total_scps'] >= 4 else 'NAO CONFORME'}")
```

---

### Passo 8 — Cleanup (Ambiente de Lab)

**O que este passo faz:** Remove os recursos criados no lab para evitar custos e conflitos em contas de lab compartilhadas. Em ambientes de produção real, o cleanup NÃO deve ser executado — as SCPs devem permanecer ativas.

```bash
# ATENÇÃO: Executar apenas em ambiente de lab
# Em produção, as SCPs devem permanecer ativas

# Desanexar SCPs antes de excluir
aws organizations detach-policy --policy-id $SCP_ROOT_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_REGIONS_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_S3_ID --target-id $ROOT_ID
aws organizations detach-policy --policy-id $SCP_CT_ID --target-id $ROOT_ID

# Deletar SCPs
aws organizations delete-policy --policy-id $SCP_ROOT_ID
aws organizations delete-policy --policy-id $SCP_REGIONS_ID
aws organizations delete-policy --policy-id $SCP_S3_ID
aws organizations delete-policy --policy-id $SCP_CT_ID

# Mover contas de volta para Root antes de excluir OUs
aws organizations move-account --account-id 222222222222 \
  --source-parent-id $OU_SECURITY --destination-parent-id $ROOT_ID
aws organizations move-account --account-id 333333333333 \
  --source-parent-id $OU_SECURITY --destination-parent-id $ROOT_ID
aws organizations move-account --account-id 444444444444 \
  --source-parent-id $OU_PRODUCTION --destination-parent-id $ROOT_ID

# Deletar OUs (somente após remover todas as contas)
aws organizations delete-organizational-unit --organizational-unit-id $OU_SECURITY
aws organizations delete-organizational-unit --organizational-unit-id $OU_PRODUCTION
aws organizations delete-organizational-unit --organizational-unit-id $OU_DEVELOPMENT
aws organizations delete-organizational-unit --organizational-unit-id $OU_SANDBOX
```

---

## Seção 7 — Objetivos por Etapa

| Passo | Objetivo | Critério de Sucesso | Evidência |
|---|---|---|---|
| 1 — Exploração | Documentar estado inicial | Tabela de contas e estrutura de OUs gerada | Output do `list-accounts` |
| 2 — OUs | Criar 4 OUs e mover contas | Cada conta no parent correto | Output do `list-children` |
| 3 — SCPs | Criar 4 JSONs e registrar | 4 IDs `p-xxxxxxxx` gerados | Output do `create-policy` |
| 4 — Aplicação | Anexar SCPs na Root | 5 políticas visíveis no target Root | Output do `list-policies-for-target` |
| 5 — Testes | Validar bloqueios | 3 testes retornam `Explicit deny in a service control policy` | Screenshots dos erros |
| 6 — Simulator | Confirmar raciocínio | `AllowedByOrganizations: false` | Output do `simulate-principal-policy` |
| 7 — Relatório | Gerar artefato de conformidade | Relatório JSON com 4 SCPs documentadas | Arquivo JSON gerado |

---

## Seção 8 — Gabarito Completo

### Passo 1 — Gabarito: Exploração do Ambiente

**Comando correto:**
```bash
aws organizations describe-organization \
  --query 'Organization.{ID:Id,Master:MasterAccountId,SCPs:AvailablePolicyTypes[0].Status}'
```

**Por que esta é a resposta correta:** Este comando retorna os três campos mais críticos para confirmar que a organização está pronta para receber SCPs: o ID da organização, a conta master (Management Account) e o status das SCPs. A query `AvailablePolicyTypes[0].Status` extrai diretamente o status sem necessidade de filtro adicional — se retornar `ENABLED`, a organização está pronta; se retornar nulo ou `DISABLED`, nenhuma SCP criada nos passos seguintes terá qualquer efeito. Usar a query no CLI em vez de inspecionar o output JSON completo é mais eficiente e reduz o risco de interpretar errado um campo extenso.

**Output esperado com anotações:**
```json
{
  "ID": "o-abc123xyz",        // ID único da organização AWS — formato: o-[10 chars]
  "Master": "111111111111",   // Management Account — nunca deve ter workloads de produção
  "SCPs": "ENABLED"           // CRÍTICO: deve ser ENABLED para SCPs funcionarem
}
```

**Interpretando o resultado:** O prefixo `o-` identifica o ID como sendo de uma Organization (diferente de `r-` para Root, `ou-` para OU, `p-` para Policy). `Master: "111111111111"` confirma que você está operando a partir da Management Account correta do Banco Meridian — se aparecer outro Account ID, suas credenciais estão apontando para uma conta errada e nenhum dos comandos seguintes funcionará conforme esperado. `SCPs: "ENABLED"` é o pré-requisito absoluto — sem isso, pare aqui e habilite em Organizations → Policies → Service control policies.

**Erros comuns neste passo:**
- `AWSOrganizationsNotInUseException`: a conta não é parte de uma organização — crie uma em Organizations → Create organization ou verifique se está usando as credenciais da Management Account
- SCPs com status `DISABLED`: habilite em Organizations → Policies → Service control policies → Enable antes de continuar — pular este step e criar SCPs sem habilitar o recurso resulta em políticas que existem no Organizations mas não têm efeito algum
- Confundir a saída de `list-roots` com `describe-organization`: `list-roots` retorna o ID do Root (formato `r-xxxx`), não o da organização (formato `o-xxxxxxxxxxxx`) — são objetos distintos

---

### Passo 2 — Gabarito: Criação das OUs

**Comando correto:**
```bash
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
OU_SECURITY=$(aws organizations create-organizational-unit \
  --parent-id $ROOT_ID \
  --name "Security" \
  --query 'OrganizationalUnit.Id' \
  --output text)
```

**Por que esta é a resposta correta:** Capturar o `ROOT_ID` dinamicamente via query (em vez de hardcodar um valor como `r-abc1`) garante que o script funcione em qualquer ambiente de lab sem modificação — o ID do Root varia entre organizações. O parâmetro `--query 'OrganizationalUnit.Id' --output text` extrai apenas o ID da OU criada, permitindo atribuí-lo diretamente a uma variável shell sem precisar parsear JSON. A sequência correta é sempre: obter Root ID → criar OUs com Root como parent → mover contas para OUs.

**Output esperado:**
```
Root ID: r-xxxx
OU Security criada: ou-xxxx-xxxxxxxxxxxxxxxx   # Formato: ou-[sufixo do root]-[id único da OU]
OU Production criada: ou-xxxx-yyyyyyyyyyyyyyyy
OU Development criada: ou-xxxx-zzzzzzzzzzzzzz
OU Sandbox criada: ou-xxxx-aaaaaaaaaaaaaaaa
```

**Interpretando o resultado:** O segmento entre `ou-` e o segundo hífen (os 4 caracteres `xxxx`) é o mesmo em todas as OUs — ele deriva do ID do Root (`r-xxxx`). O segmento após o segundo hífen é único para cada OU. Se duas OUs tiverem o mesmo sufixo, algo está errado. O silêncio após os comandos `move-account` indica sucesso — este comando não retorna JSON; a verificação com `list-children` é obrigatória para confirmar.

**Erros comuns neste passo:**
- OU com o mesmo nome já existe: Organizations não permite OUs com nomes duplicados no mesmo parent — verifique com `list-organizational-units-for-parent --parent-id $ROOT_ID`
- `AccountNotFoundException` ao mover conta: confirme o Account ID com `list-accounts` — é fácil trocar dígitos em IDs de 12 caracteres
- Conta já está na OU destino: use `aws organizations list-parents --child-id 222222222222` para encontrar o parent atual antes de mover
- Tentar deletar uma OU que ainda tem contas dentro: `delete-organizational-unit` falha se houver contas ou OUs filhas — sempre mova as contas de volta para o Root antes de deletar

**Variações aceitáveis:** Os nomes das OUs podem variar (ex: "Seguranca" em vez de "Security"), desde que a estrutura lógica seja mantida e as SCPs sejam aplicadas corretamente nos targets.

---

### Passo 3 — Gabarito: Criação das SCPs

**SCP DenyRootAccess — configuração correta:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

**Por que esta é a resposta correta:** O operador `StringLike` com o padrão `arn:aws:iam::*:root` usa o wildcard `*` para corresponder a qualquer Account ID — o que significa que a SCP bloqueia o usuário root em qualquer member account, independentemente do ID numérico da conta. Usar `StringEquals` com um Account ID fixo (ex: `arn:aws:iam::444444444444:root`) bloquearia apenas aquela conta específica, deixando as demais desprotegidas. O `Action: "*"` garante que nenhuma ação seja possível para o root — não apenas as ações mais críticas. A aplicação na Root (e não em OUs) garante cobertura automática para qualquer nova conta adicionada à organização no futuro.

**Output esperado:**
```
SCP DenyRootAccess: p-abc12345   # Formato: p-[8 chars alfanuméricos]
```

**SCP DenyNonApprovedRegions — comparação correto vs. errado:**
```json
// ERRADO: bloqueia IAM, CloudFront, Route53 e outros serviços globais
{
  "Action": "*",
  "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["sa-east-1"]}}
}

// CORRETO: usa NotAction para excluir serviços globais do bloqueio de região
{
  "NotAction": ["iam:*", "cloudfront:*", "route53:*", "sts:*", "support:*",
                "organizations:*", "account:*", "cur:*"],
  "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["sa-east-1", "us-east-1", "us-east-2"]}}
}
```

**Por que esta é a resposta correta:** `NotAction` exclui os serviços listados da restrição de região — ou seja, a SCP se aplica a TODOS os serviços EXCETO os listados. IAM, CloudFront, Route53, STS, Organizations e outros são serviços globais da AWS: eles não pertencem a nenhuma região específica, e tentativas de bloqueá-los por `aws:RequestedRegion` quebram o IAM inteiro (impossibilidade de assumir roles, criar usuários, configurar policies) e qualquer serviço de borda (CloudFront, WAF, GlobalAccelerator). As três regiões aprovadas (`sa-east-1`, `us-east-1`, `us-east-2`) refletem os requisitos de soberania de dados do Banco Meridian — São Paulo para dados de clientes brasileiros, US-East para serviços globais com presença necessária nos EUA.

**Erros comuns neste passo:**
- Usar `Action: "*"` em vez de `NotAction` na SCP de regiões: quebra o IAM inteiro de todas as member accounts — ninguém consegue criar usuários, assumir roles ou fazer qualquer operação de identidade
- Esquecer `sts:*` na lista de exceções do NotAction: impede assunção de roles cross-account, quebrando pipelines de CI/CD e acessos de ferramentas de monitoramento
- Esquecer `cur:*` (Cost and Usage Reports): serviço global necessário para relatórios de custo — sua ausência impede que o time de FinOps acesse dados de billing
- JSON inválido: sempre valide com `python3 -m json.tool /tmp/scp-deny-regions.json` antes de fazer `create-policy`

---

### Passo 4 — Gabarito: Aplicação das SCPs

**Comando correto:**
```bash
aws organizations attach-policy \
  --policy-id $SCP_ROOT_ID \
  --target-id $ROOT_ID
```

**Por que esta é a resposta correta:** Aplicar na Root (em vez de em OUs específicas) garante três coisas: (1) todas as member accounts atuais recebem a SCP imediatamente; (2) qualquer nova conta adicionada à organização no futuro herda as SCPs automaticamente sem intervenção manual; (3) contas que sejam movidas entre OUs continuam protegidas porque a SCP está no nível superior da hierarquia. Para as quatro SCPs do Banco Meridian, a aplicação na Root é a escolha correta porque todas são controles de segurança baseline que devem valer para qualquer conta, sem exceção.

**Output esperado:**
```
# Sem output = sucesso (attach-policy não retorna JSON em caso de êxito)
# Verificar com:
aws organizations list-policies-for-target \
  --target-id $ROOT_ID \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].Name'
# Esperado: ["FullAWSAccess", "DenyRootAccess", "DenyNonApprovedRegions", "DenyUnencryptedS3", "ProtectCloudTrail"]
```

**Interpretando o resultado:** O silêncio após `attach-policy` é a resposta de sucesso da AWS CLI para este comando. A ausência de mensagem de erro é o sinal positivo. A verificação com `list-policies-for-target` deve retornar exatamente 5 itens — a FullAWSAccess padrão mais as 4 SCPs customizadas. Se retornar menos de 5, algum `attach-policy` falhou silenciosamente — verifique as variáveis `$SCP_ROOT_ID`, `$SCP_REGIONS_ID` etc. com `echo` para confirmar que não estão vazias.

**Erros comuns neste passo:**
- SCP aplicada em OU errada em vez da Root: o controle funcionará apenas para as contas dentro daquela OU — contas em outras OUs ficam sem proteção; confirme com `list-targets-for-policy --policy-id $SCP_ROOT_ID`
- `PolicyNotFoundException`: a variável com o ID da SCP está vazia porque `create-policy` falhou no passo anterior — verifique com `aws organizations list-policies --filter SERVICE_CONTROL_POLICY` e reaplique
- SCP aplicada mas não funcionando: a causa mais comum é que `FullAWSAccess` foi removida da Root — sem ela, o modelo Deny List colapsa e nenhuma ação é permitida (ou pior, as SCPs custom ficam em conflito indefinido)
- Tentar aplicar a mesma SCP duas vezes no mesmo target: Organizations retorna erro `DuplicatePolicyAttachmentException` — verificar com `list-policies-for-target` antes de tentar novamente

---

### Passo 5 — Gabarito: Testes de Validação

**Teste DenyNonApprovedRegions — resultado correto:**
```bash
aws ec2 describe-instances --region ap-southeast-1
# Resultado correto:
# An error occurred (UnauthorizedAccess) when calling the DescribeInstances operation:
# Explicit deny in a service control policy
```

**Por que esta é a resposta correta:** O erro `UnauthorizedAccess` com a frase `Explicit deny in a service control policy` é a assinatura inequívoca de um bloqueio por SCP em chamadas EC2. A frase exata na mensagem de erro diferencia bloqueio por SCP (controle organizacional, não contornável) de bloqueio por política IAM (contornável por admin da conta). Qualquer resposta diferente — como `AccessDenied` sem mencionar SCP, ou o comando funcionar sem erro — indica que a SCP não está ativa para aquela conta.

**Interpretando o resultado:** O teste deve ser executado com credenciais de uma member account (222222222222, 333333333333 ou 444444444444) — nunca da Management Account (111111111111), que é imune a SCPs. A região `ap-southeast-1` (Singapura) foi escolhida por ser claramente fora do perímetro aprovado e não ter ambiguidade. O mesmo teste funcionaria com qualquer região não presente na lista `["sa-east-1", "us-east-1", "us-east-2"]` da SCP.

**Erros comuns neste passo:**
- Teste executado na Management Account (111111111111): SCPs nunca afetam a Management Account — o comando funcionará normalmente, mas isso não é um bug; é um comportamento esperado do AWS Organizations
- Teste não bloqueia na member account: a conta pode não estar dentro da hierarquia onde a SCP foi aplicada — use `aws organizations list-parents --child-id 444444444444` para confirmar o parent
- Erro de IAM em vez de SCP: o usuário de teste pode não ter permissão IAM para `ec2:DescribeInstances` — o bloqueio seria por IAM, não por SCP; conceda a permissão IAM básica e repita o teste para ver o bloqueio por SCP

**Variações aceitáveis:** Qualquer comando que use um serviço regional (ec2, rds, lambda, etc.) em região não aprovada deve ser bloqueado. O serviço e a ação específicos não importam — o critério é a região.

---

### Passo 6 — Gabarito: Policy Simulator Avançado

**Comando correto:**
```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444444444444:user/admin-test \
  --action-names cloudtrail:DeleteTrail \
  --resource-arns "*" \
  --query 'EvaluationResults[0].{Acao:EvalActionName,Decisao:EvalDecision,Razao:EvalDecisionDetails}'
```

**Por que esta é a resposta correta:** O parâmetro `--policy-source-arn` indica qual identidade está sendo simulada — neste caso, o usuário `admin-test` da conta Meridian-Prod. O simulador avalia todas as políticas aplicáveis a essa identidade: políticas IAM do usuário/grupo/role, Resource Policies, Permissions Boundaries, e SCPs da organização. O campo `EvalDecisionDetails` é o que revela a origem do Deny, diferenciando `ServiceControlPolicyDecisionDetail` (SCP) de `PermissionsBoundaryDecisionDetail` (Permissions Boundary) e outros. Sem esse campo, o resultado mostraria apenas `explicitDeny` sem indicar qual tipo de política causou o bloqueio.

**Output esperado com anotações:**
```json
{
  "Acao": "cloudtrail:DeleteTrail",     // Ação simulada — exatamente o que foi pedido
  "Decisao": "explicitDeny",            // Bloqueio ativo (não implícito por ausência de Allow)
  "Razao": {
    "ServiceControlPolicyDecisionDetail": {
      "AllowedByOrganizations": false   // O bloqueio vem de uma SCP — não de IAM
    }
  }
}
```

**Interpretando o resultado:** `explicitDeny` significa que existe uma política que ativamente proíbe a ação — diferente de `implicitDeny`, que seria apenas a ausência de um Allow. A presença de `ServiceControlPolicyDecisionDetail` (e não de `IAMPolicyDecisionDetail`) prova que o bloqueio é da camada de Organizations. `AllowedByOrganizations: false` é a confirmação final: a organização negou explicitamente esta ação para esta identidade nesta conta. Este output é a evidência técnica mais robusta disponível para demonstrar que um controle preventivo organizacional está funcionando.

**Erros comuns neste passo:**
- Resultado retorna `allowed` em vez de `explicitDeny`: a SCP não está aplicada à conta ou ao target correto — verificar com `list-policies-for-target --target-id $ROOT_ID`
- `Razao` contém `IAMPolicyDecisionDetail` em vez de `ServiceControlPolicyDecisionDetail`: o bloqueio está vindo de uma política IAM, não da SCP — a SCP pode não estar ativa
- Simulador retorna `implicitDeny`: significa que nenhuma política concede a ação (e nenhuma nega explicitamente) — a SCP de Deny não está funcionando; verificar a sintaxe do JSON da SCP e se ela está aplicada no target correto

---

### Passo 7 — Gabarito: Relatório de Conformidade

**Script correto (simplificado):**
```python
import boto3
import json

organizations = boto3.client('organizations')
policies = organizations.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
scps_customizadas = [p for p in policies if p['Name'] != 'FullAWSAccess']
print(f"Total de SCPs customizadas: {len(scps_customizadas)}")
print(f"Status: {'CONFORME' if len(scps_customizadas) >= 4 else 'NAO CONFORME'}")
```

**Por que esta é a resposta correta:** O script filtra a `FullAWSAccess` (política padrão da AWS, não customizada) para contar apenas as SCPs implementadas pelo time do Banco Meridian. O critério de conformidade `>= 4` corresponde às 4 SCPs exigidas: DenyRootAccess, DenyNonApprovedRegions, DenyUnencryptedS3 e ProtectCloudTrail. O uso de paginação no script completo (`get_paginator`) garante que organizações com mais de 20 SCPs (limite padrão de página) sejam cobertas corretamente.

**Output esperado:**
```json
{
  "data_geracao": "2026-04-14T12:00:00.000000",
  "organizacao": "o-abc123xyz",
  "banco": "Banco Meridian",
  "ticket": "SECOPS-2041",
  "regulacao": "BACEN Resolução 4.893",
  "scps": [
    {"nome": "DenyRootAccess", "id": "p-xxxxxxxx", "aplicada_em": [{"nome": "Root", "tipo": "ROOT"}]},
    {"nome": "DenyNonApprovedRegions", "id": "p-yyyyyyyy", "aplicada_em": [{"nome": "Root", "tipo": "ROOT"}]},
    {"nome": "DenyUnencryptedS3", "id": "p-zzzzzzzz", "aplicada_em": [{"nome": "Root", "tipo": "ROOT"}]},
    {"nome": "ProtectCloudTrail", "id": "p-aaaaaaaa", "aplicada_em": [{"nome": "Root", "tipo": "ROOT"}]}
  ],
  "resumo": {"total_scps": 4, "scps_na_root": 4, "scps_em_ou": 0}
}

=== RESUMO ===
Total de SCPs customizadas: 4
Status: CONFORME
```

**Interpretando o resultado:** `"total_scps": 4` confirma que todas as 4 SCPs exigidas estão registradas. `"scps_na_root": 4` confirma que todas estão aplicadas na Root (cobertura universal). `"scps_em_ou": 0` é esperado neste cenário — nenhuma SCP foi aplicada em OUs individuais além da Root. O campo `"Status": "CONFORME"` é o indicador de conformidade para o ticket. Salve o JSON em arquivo com `python3 relatorio.py > relatorio_scps_$(date +%Y%m%d).json` e anexe ao ticket SECOPS-2041.

**Erros comuns neste passo:**
- `NoCredentialsError` ou `UnauthorizedError`: o script Python está usando credenciais sem permissão para `organizations:ListPolicies` — conceda a permissão ou execute com as credenciais da Management Account
- `total_scps: 0`: todas as políticas foram filtradas — verifique se os nomes das SCPs correspondem exatamente aos criados (case-sensitive); `DenyRootAccess` diferente de `denyRootAccess`
- Relatório mostra SCPs mas `aplicada_em` está vazio: as SCPs foram criadas mas não anexadas a nenhum target — execute o Passo 4 novamente

---

### Resumo das SCPs Finais Implementadas

| SCP | Aplicada em | Protege contra | Requisito BACEN |
|---|---|---|---|
| DenyRootAccess | Root | Uso de conta root sem MFA | Art. 7 — Controle de acesso privilegiado |
| DenyNonApprovedRegions | Root | Criação de recursos fora do perímetro aprovado | Art. 6 — Soberania de dados |
| DenyUnencryptedS3 | Root | Armazenamento sem criptografia | Art. 6 — Criptografia de dados em repouso |
| ProtectCloudTrail | Root | Desabilitação de trilha de auditoria | Art. 10 — Rastreabilidade de operações |
