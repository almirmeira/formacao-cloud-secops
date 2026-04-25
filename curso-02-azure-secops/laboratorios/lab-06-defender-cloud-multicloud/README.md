# Lab 06 — Defender for Cloud: Visibilidade Multi-Cloud e Compliance BACEN

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                               |
|:-------------------------|:-----------------------------------------------------------------------|
| **Duração**              | 2 horas                                                                |
| **Módulo de referência** | Módulo 07 — Microsoft Defender for Cloud                               |
| **Pré-requisito**        | Labs 01, 03, 04 e 05 concluídos                                        |
| **Nível**                | Intermediário-Avançado                                                 |

---

## Seção 1 — Contexto Situacional

O **Banco Meridian** tomou a decisão estratégica de usar a **AWS** para hospedar workloads analíticas de dados de clientes (relatórios de risco, scoring de crédito). O CISO recebeu a notícia tarde: a conta AWS já existe há 6 meses e nunca foi auditada para segurança.

Simultaneamente, o board aprovou o projeto de compliance com **BACEN 4.893** e **PCI DSS 4.0**. O banco precisa apresentar um relatório de conformidade em 30 dias.

Você foi designado para: (1) conectar a conta AWS ao Defender for Cloud para visibilidade unificada, (2) habilitar os standards de compliance BACEN e PCI DSS, e (3) remediar os 3 findings críticos mais urgentes.

---

## Seção 2 — Situação Inicial

```
┌──────────────────────────────────────────────────────────────────────────┐
│  PORTAL DEFENDER FOR CLOUD — BANCO MERIDIAN — SEGUNDA, 09:00            │
│                                                                          │
│  SECURE SCORE AZURE:    65%   ████████████░░░░░░░ (linha de base)       │
│  RECURSOS AVALIADOS:    142   (VMs, Storage, SQL, Key Vaults)           │
│  RECOMMENDATIONS:       89    (21 críticas, 35 altas, 33 médias)        │
│  DEFENDER PLANS ATIVOS: 0/8  ████████████████████ (todos desabilitados) │
│  STANDARDS COMPLIANCE:  1/3  (apenas Cloud Security Benchmark ativo)    │
│  AWS CONECTADA:         NÃO  ████████████████████ (zero visibilidade)   │
│                                                                          │
│  ALERTA DA AUDITORIA: 30 dias para apresentar relatório BACEN           │
└──────────────────────────────────────────────────────────────────────────┘

"Recebi do board a aprovação do projeto de compliance BACEN 4.893 e PCI DSS.
 Temos 30 dias para apresentar evidências. O auditor vai perguntar especificamente
 sobre a conta AWS — precisamos ter visibilidade multi-cloud. Além disso, alguém
 precisa remediar os 21 findings críticos antes que virem manchete."
 — Felipe Andrade, CISO Interino do Banco Meridian (turno de crise)
```

**Estado do ambiente**:
- Subscription Azure: Banco-Meridian-Sandbox (com Defender for Cloud habilitado)
- Conta AWS de simulação: fornecida pelo ambiente de lab (ID: `123456789012`)
- Secure Score Azure atual: ~65% (com vários findings abertos do ambiente de lab)
- Standards habilitados: apenas Microsoft Cloud Security Benchmark (padrão)
- Defender Plans: **TODOS desabilitados** — o Defender for Cloud pode ver recursos mas não os protege ativamente
- Visibilidade AWS: **ZERO** — 6 meses de operação AWS sem auditoria de segurança

---

## Seção 3 — Problema Identificado

A conta AWS do Banco Meridian tem recursos críticos (EC2, RDS, S3) sem visibilidade de segurança centralizada. O time de TI Azure não sabe o estado de segurança dos recursos AWS. O auditor do BACEN pediu:

1. Evidência de monitoramento de segurança para TODOS os ambientes cloud (Azure + AWS)
2. Relatório de compliance com BACEN 4.893
3. Plano de remediação dos findings críticos

---

## Seção 4 — Roteiro de Atividades

1. Habilitar Defender Plans críticos na subscription Azure
2. Verificar o Secure Score inicial e anotar a linha de base
3. Onboardar a conta AWS de simulação no Defender for Cloud
4. Habilitar standard BACEN 4.893 no Defender for Cloud
5. Habilitar standard PCI DSS 4.0
6. Analisar os top 5 findings críticos do relatório de compliance
7. Remediar Finding Crítico 1: VM com RDP público
8. Remediar Finding Crítico 2: Storage Account com acesso público habilitado
9. Remediar Finding Crítico 3: SQL Database sem auditoria habilitada
10. Verificar a melhoria no Secure Score e exportar relatório de compliance

---

## Seção 5 — Proposição

Ao final deste laboratório:
- Defender Plans habilitados para Servers, SQL e Storage
- Conta AWS conectada com visibilidade no Defender for Cloud
- Standards BACEN 4.893 e PCI DSS 4.0 habilitados e avaliados
- 3 findings críticos remediados e Secure Score melhorado em pelo menos 5 pontos
- Relatório de compliance exportado para entrega ao auditor

---

## Seção 6 — Script Passo a Passo

### Passo 1: Habilitar Defender Plans

**Portal Azure → Defender for Cloud → Environment settings → [Subscription] → Defender plans**

Habilitar os seguintes planos:

| Plan                     | Subplan   | Ação                |
|:-------------------------|:---------:|:--------------------|
| Defender for Servers     | P2        | Enable              |
| Defender for SQL         | Padrão    | Enable              |
| Defender for Storage     | Padrão    | Enable              |
| Defender for Key Vaults  | Padrão    | Enable              |

```
Para cada plan:
→ Clicar no toggle para "On"
→ Selecionar o subplano (P2 para Servers)
→ Clicar em Save (botão no topo da página)
```

**Verificação**:
```powershell
# Verificar planos habilitados
Get-AzSecurityPricing | Select-Object Name, PricingTier | 
    Where-Object { $_.PricingTier -eq "Standard" }
# Deve retornar: VirtualMachines, SqlServers, StorageAccounts, KeyVaults
```

**Resultado esperado**: 4 plans com PricingTier = "Standard".

**Por que confirma que funcionou:** O PowerShell retornando 4 linhas com `PricingTier = "Standard"` confirma que os plans foram habilitados com sucesso. Mas a confirmação definitiva vem 30 minutos depois, quando o Defender for Cloud começa a gerar os primeiros alertas de segurança para os recursos cobertos. Execute `Get-AzSecurityAlert | Sort-Object StartTimeUtc -Descending | Select-Object -First 5` para verificar os primeiros alertas gerados pelos Defender Plans recém-habilitados.

**Troubleshooting**:
- Se aparecer erro de "registration required": executar `Register-AzResourceProvider -ProviderNamespace Microsoft.Security`
- Se os planos não aparecerem após 5 minutos: verificar se a conta tem papel de **Security Admin** na subscription (não apenas Contributor)
- Se o custo estimado parecer alto: o custo real depende do número de recursos — para o ambiente de lab com poucos recursos, será mínimo

---

### Passo 2: Verificar Secure Score Inicial

**Defender for Cloud → Security posture**

1. Anotar o Secure Score atual: ____%
2. Anotar os controles com maior impacto potencial (top 3)
3. Anotar o número total de recursos avaliados

```kql
// Consultar Secure Score via KQL (no Sentinel/Log Analytics)
// Execute esta query para ter o baseline documentado

SecurityResources
| where type == "microsoft.security/assessments"
| extend Score = todouble(properties.status.score)
| where isnotnull(Score)
| summarize AvgScore = avg(Score), TotalAssessments = count()
```

**Anote**: Score inicial = ____%. Este será o ponto de partida para medir a melhoria.

---

### Passo 3: Onboardar Conta AWS

**Defender for Cloud → Environment settings → Add environment → Amazon Web Services**

Preencher:
```
Name: aws-meridian-analytics
Subscription: Banco-Meridian-Sandbox
Region: US East (N. Virginia)
AWS account ID: 123456789012 (fornecido pelo lab)
```

**Plans a habilitar**:
```
✓ Defender CSPM
✓ Defender for Servers (opcional no lab — pode aumentar custo)
```

**Configurar o CloudFormation** (usar a conta AWS simulada do lab):

O Defender for Cloud fornecerá um link para o CloudFormation template. Em ambiente de lab, o instrutor pode ter pré-executado o CloudFormation — verificar se já existe a role:

```powershell
# Verificar se o conector foi criado com sucesso
Get-AzSecurityConnector -ResourceGroupName "rg-meridian-secops" | 
    Select-Object Name, EnvironmentName, Hierarchy_Level
```

**Resultado esperado**: Conector AWS aparece em Environment settings com status "Connected".

**Nota para ambientes de lab**: Se o CloudFormation não puder ser executado na AWS de simulação, pular para o Passo 4 e usar apenas os recursos Azure para os passos seguintes.

---

### Passo 4: Habilitar Standard BACEN 4.893

**Defender for Cloud → Regulatory compliance → Manage compliance policies**

1. Selecionar a Subscription: Banco-Meridian-Sandbox
2. Localizar "Brazilian Financial Institutions - BACEN Resolution 4893"
   - Se não aparecer na lista: pesquisar por "BACEN" ou "Brazil"
3. Clicar no toggle para **Enable**
4. Aguardar avaliação (pode levar até 30 minutos para avaliação completa)

**Enquanto aguarda**, documentar os requisitos do BACEN que serão avaliados:

| Art. BACEN 4.893   | O que verifica                                    | Controle Azure esperado              |
|:------------------|:---------------------------------------------------|:-------------------------------------|
| Art. 5°, II        | MFA para acessos privilegiados                    | MFA habilitado em admins             |
| Art. 5°, III       | Criptografia de dados em trânsito e repouso       | Disk encryption + TLS                |
| Art. 5°, IV        | Controle de acesso com menor privilégio           | NSG + JIT VM Access                  |
| Art. 6°            | Plano de continuidade / backup                    | VM backup habilitado                 |
| Art. 19            | Retenção de logs por 5 anos                       | Log Analytics retention ≥ 1825 dias  |

---

### Passo 5: Habilitar Standard PCI DSS 4.0

**Defender for Cloud → Regulatory compliance → Manage compliance policies**

1. Localizar "PCI DSS 4.0"
2. Habilitar

**Verificação após 15 minutos**:
```
Regulatory compliance dashboard deve mostrar:
- BACEN 4.893: X% compliant
- PCI DSS 4.0: Y% compliant
- Microsoft Cloud Security Benchmark: Z% compliant
```

---

### Passo 6: Analisar Top 5 Findings Críticos

**Defender for Cloud → Recommendations → filtrar por Severity: Critical**

Anote os 5 findings críticos mais impactantes:

| # | Finding                                    | Recursos afetados | Impacto no Score |
|:-:|:-------------------------------------------|:-----------------:|:----------------:|
| 1 |                                            |                   |                  |
| 2 |                                            |                   |                  |
| 3 |                                            |                   |                  |
| 4 |                                            |                   |                  |
| 5 |                                            |                   |                  |

Para o lab, focaremos nos 3 seguintes (pré-configurados no ambiente):
1. "Management ports of virtual machines should be protected with just-in-time network access control"
2. "Storage account public access should be disallowed"
3. "SQL databases should have vulnerability findings resolved"

---

### Passo 7: Remediar Finding 1 — VM com RDP Público

**Defender for Cloud → Recommendations → "Management ports of VMs should be protected with JIT"**

1. Ver lista de VMs afetadas
2. Clicar em **Remediate** (ou "Quick Fix")
3. Selecionar as VMs: VM-Lab-Windows01
4. Configurar JIT policy:
   ```
   Port 3389 (RDP):
     Protocol: TCP
     Allowed source IPs: My IP (ou 10.0.0.0/8 para rede interna)
     Max request time: 3 hours
   
   Port 22 (SSH):
     Protocol: TCP
     Allowed source IPs: My IP
     Max request time: 3 hours
   ```
5. Clicar em **Save**

**Verificação**:
```powershell
# Verificar JIT policy habilitada
Get-AzJitNetworkAccessPolicy -ResourceGroupName "rg-meridian-secops" -VirtualMachineName "VM-Lab-Windows01"
# Deve retornar a policy JIT com as portas configuradas
```

**Resultado esperado**: NSG da VM atualizado — porta 3389 não aparece mais como "Allow Any" permanente.

**Troubleshooting**:
- Se a VM não aparecer: verificar que o Defender for Servers P2 foi habilitado no Passo 1
- Erro de permissão: verificar que tem role "Security Admin" na subscription

---

### Passo 8: Remediar Finding 2 — Storage Account Público

**Defender for Cloud → Recommendations → "Storage account public access should be disallowed"**

1. Ver lista de storage accounts afetadas
2. Clicar no finding para ver detalhes
3. Clicar em **Quick Fix** (se disponível) OU executar manualmente:

```powershell
# Desabilitar acesso público em todas as storage accounts da subscription
$storageAccounts = Get-AzStorageAccount -ResourceGroupName "rg-meridian-secops"

foreach ($sa in $storageAccounts) {
    if ($sa.AllowBlobPublicAccess -eq $true) {
        Write-Host "Desabilitando acesso público em: $($sa.StorageAccountName)"
        Set-AzStorageAccount `
            -ResourceGroupName $sa.ResourceGroupName `
            -Name $sa.StorageAccountName `
            -AllowBlobPublicAccess $false
        Write-Host "✓ Concluído: $($sa.StorageAccountName)"
    } else {
        Write-Host "✓ Já seguro: $($sa.StorageAccountName)"
    }
}
```

**Verificação**:
```powershell
# Verificar que nenhuma storage account tem acesso público
Get-AzStorageAccount -ResourceGroupName "rg-meridian-secops" | 
    Select-Object StorageAccountName, AllowBlobPublicAccess |
    Where-Object { $_.AllowBlobPublicAccess -eq $true }
# Deve retornar nenhum resultado (vazio)
```

**Resultado esperado**: Nenhuma storage account com AllowBlobPublicAccess = $true.

---

### Passo 9: Remediar Finding 3 — SQL Database sem Auditoria

**Defender for Cloud → Recommendations → "SQL databases should have auditing enabled"**

1. Ver lista de SQL databases afetados
2. Para cada banco de dados afetado, executar:

```powershell
# Habilitar auditoria no SQL Database
$resourceGroup = "rg-meridian-secops"
$serverName = "sql-meridian-lab"
$databaseName = "db-contratos"
$workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name "meridian-secops-prod").CustomerId

# Habilitar auditoria com destino Log Analytics
Set-AzSqlDatabaseAudit `
    -ResourceGroupName $resourceGroup `
    -ServerName $serverName `
    -DatabaseName $databaseName `
    -State "Enabled" `
    -LogAnalyticsTargetState "Enabled" `
    -WorkspaceResourceId (Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name "meridian-secops-prod").ResourceId

Write-Host "Auditoria habilitada para $databaseName"
```

**Verificação**:
```powershell
# Verificar configuração de auditoria
Get-AzSqlDatabaseAudit `
    -ResourceGroupName "rg-meridian-secops" `
    -ServerName "sql-meridian-lab" `
    -DatabaseName "db-contratos" | 
    Select-Object State, LogAnalyticsTargetState
# Deve mostrar: State = Enabled, LogAnalyticsTargetState = Enabled
```

---

### Passo 10: Verificar Melhoria do Secure Score e Exportar Relatório

**Verificar melhoria**:

```
Defender for Cloud → Security posture → Secure Score atual: ____%
Melhoria = Score atual - Score inicial (Passo 2)
```

**Exportar relatório de compliance para o auditor BACEN**:

```
Defender for Cloud → Regulatory compliance → BACEN 4.893
→ Download report (PDF)
→ Selecionar: "Status of controls and recommendations"
→ Download
```

**Verificação KQL — Comparar antes e depois**:

```kql
// Estado atual das recomendações após remediação
SecurityRecommendation
| where TimeGenerated > ago(2h)
| where State == "Unhealthy"
| summarize FindingsOpen = count() by RecommendationSeverity
| sort by case(RecommendationSeverity == "High", 1, 
               RecommendationSeverity == "Medium", 2, 3) asc
```

**Resultado esperado**: Número de findings "High" reduzido em pelo menos 3 em comparação com o estado inicial.

---

## Seção 7 — Objetivos por Etapa

| Etapa | Objetivo                                                | Verificação                                   |
|:-----:|:--------------------------------------------------------|:----------------------------------------------|
| 1     | Habilitar Defender Plans para workloads                | 4 plans com PricingTier = Standard            |
| 2     | Documentar linha de base do Secure Score               | Score inicial anotado (ex.: 65%)              |
| 3     | Conectar conta AWS para visibilidade multi-cloud        | Conector AWS em Environment settings          |
| 4-5   | Habilitar standards BACEN 4.893 e PCI DSS 4.0           | Ambos aparecem em Regulatory compliance       |
| 6     | Identificar top 5 findings críticos                    | Lista de 5 findings documentada               |
| 7     | Remediar JIT para VMs com portas expostas              | NSG atualizado sem regra Allow Any para RDP   |
| 8     | Remediar storage com acesso público                    | AllowBlobPublicAccess = false em todas SAs    |
| 9     | Remediar SQL sem auditoria                             | Auditoria State = Enabled no SQL Database     |
| 10    | Verificar melhoria e exportar relatório               | Score melhorou; PDF do relatório BACEN baixado |

---

## Seção 8 — Gabarito Completo

### Configurações Corretas após o Lab

**Secure Score esperado após remediação**: ≥ 70% (melhoria de pelo menos 5 pontos sobre o inicial de 65%)

**JIT Policy Final**:
```json
{
  "virtualMachines": [
    {
      "id": "/subscriptions/.../VM-Lab-Windows01",
      "ports": [
        {
          "number": 3389,
          "protocol": "TCP",
          "allowedSourceAddressPrefix": "10.0.0.0/8",
          "maxRequestAccessDuration": "PT3H",
          "status": "Enabled"
        }
      ]
    }
  ]
}
```

**Auditoria SQL**:
```powershell
# Verificação final completa
Get-AzSqlDatabaseAudit -ResourceGroupName "rg-meridian-secops" -ServerName "sql-meridian-lab" -DatabaseName "db-contratos"
# Resultado esperado:
# State              : Enabled
# AuditActionGroups  : SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, FAILED_DATABASE_AUTHENTICATION_GROUP, BATCH_COMPLETED_GROUP
# LogAnalyticsTargetState : Enabled
```

### Query de Validação Final

```kql
// Verificar estado final de compliance após remediação
SecurityRecommendation
| where TimeGenerated > ago(2h)
| summarize 
    Total = count(),
    Healthy = countif(State == "Healthy"),
    Unhealthy = countif(State == "Unhealthy"),
    NotApplicable = countif(State == "NotApplicable")
| extend ComplianceRate = round(100.0 * Healthy / (Healthy + Unhealthy), 1)
| project Total, Healthy, Unhealthy, ComplianceRate
// Esperado: ComplianceRate >= 65%
```

### Como Interpretar os Resultados de Cada Passo — Por que Confirma que Funcionou

**Passo 1 (Defender Plans):** O PowerShell retornando `PricingTier = "Standard"` para os 4 planos confirma a habilitação. A confirmação operacional vem em 30-60 minutos, quando o Defender for Cloud começa a gerar alertas para atividades suspeitas nos recursos cobertos. Um alerta de "Suspicious Activity" ou "Brute Force Attack" indica que o sensor está funcionando.

**Passo 3 (AWS Connector):** O conector está corretamente configurado quando o painel do Defender for Cloud exibe uma segunda linha em "Environment settings" com o nome "bancomeridian-aws" e status "Connected". A contagem de recursos AWS (ex.: "47 resources") confirma que o agentless scanning está funcionando. Se aparecer "0 resources", o IAM role da AWS provavelmente não tem as permissões corretas — verifique o CloudFormation stack implantado.

**Passos 4-5 (Standards BACEN e PCI):** Os standards aparecem em "Regulatory compliance" com status inicial (geralmente 40-60% — isso é normal para um ambiente novo). O importante é que aparecem na lista, não que estejam 100% compliant — compliance 100% seria suspeito, pois indica que algumas avaliações não estão rodando.

**Passo 7 (JIT):** O teste de JIT é a verificação mais importante: tente conectar via RDP diretamente no IP da VM sem solicitar acesso JIT. A conexão deve falhar (timeout). Depois, solicite acesso JIT, aguarde a aprovação automática e tente novamente — deve funcionar. Isso confirma que o controle está realmente ativo, não apenas configurado no papel.

**Passo 8 (Storage):** Execute no Cloud Shell após a remediação:
```powershell
Get-AzStorageAccount -ResourceGroupName "rg-meridian-secops" | Select-Object StorageAccountName, AllowBlobPublicAccess
```
Cada storage deve retornar `AllowBlobPublicAccess = False`. Se algum retornar `True` ou vazio, a remediação não foi aplicada a essa storage account específica.

### Erros Comuns e Como Identificar

| Problema | Sintoma | Solução |
|:---------|:--------|:--------|
| AWS Connector sem recursos | "0 resources" em Environment settings | Verificar se o IAM Role tem a permissão `SecurityAudit` managed policy; re-rodar o CloudFormation template |
| Secure Score não atualiza após remediação | Score permanece em 65% após 2h | O Secure Score tem latência de até 8h para atualizar — confirmar via PowerShell `Get-AzSecurityCompliance` em vez de confiar no portal |
| Standard BACEN não aparece | Marketplace mostra "preview" ou "not available" | Procurar por "Brazil" nos standards do portal ou usar o alias `azure-security-benchmark-bacen` |
| JIT não bloqueia acesso | VM ainda acessível sem JIT request | NSG da VM tem uma regra separada Allow para RDP/SSH que substitui o JIT — remover a regra de Allow permanente |
| Audit SQL falha | Erro 403 ao habilitar auditoria | A conta precisa de papel de `SQL Security Manager` no servidor SQL além de Contributor |

### Relatório de Compliance — Estrutura do PDF para Auditor BACEN

O relatório exportado do Defender for Cloud deve mostrar:

```
BANCO MERIDIAN — RELATÓRIO DE CONFORMIDADE
Standard: BACEN Resolução 4.893
Data: [data do lab]
Status Geral: XX% em conformidade

Controles em conformidade (verde):
  - [lista dos controles passando]

Controles com falhas (vermelho):
  - [lista dos controles falhando com recomendações]

Controles não aplicáveis:
  - [lista de controles excluídos]
```

### Desafio Extra (Opcional)

Para alunos que terminarem antes do prazo:

1. **Criar uma Azure Policy** que impeça criação de novas storage accounts com acesso público:

```json
{
  "properties": {
    "displayName": "Meridian - Bloquear Storage Account Público",
    "policyType": "Custom",
    "mode": "All",
    "parameters": {},
    "policyRule": {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
          { "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "equals": true }
        ]
      },
      "then": { "effect": "deny" }
    }
  }
}
```

2. **Verificar que a policy funciona** tentando criar uma storage account com acesso público habilitado — deve ser bloqueado.

3. **Configurar Export Contínuo** para enviar todos os findings do Defender for Cloud para o workspace Sentinel (Seção 7.2 do Módulo 07).
