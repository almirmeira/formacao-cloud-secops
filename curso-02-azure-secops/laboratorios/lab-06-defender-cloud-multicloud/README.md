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

**O que este passo faz:** O Microsoft Defender for Cloud opera em dois modos: gratuito (Free), que oferece inventário de recursos e recomendações básicas de configuração sem custo; e pago (Standard/Defender Plans), que adiciona proteção ativa, detecção de ameaças em tempo real, análise comportamental e alertas de segurança específicos por tipo de recurso. Habilitar os planos neste passo é o que transforma o Defender for Cloud de uma ferramenta de auditoria passiva em um sistema ativo de proteção. O Plano P2 para Servers, por exemplo, adiciona: avaliação de vulnerabilidades integrada (sem agente externo), Just-In-Time VM Access, análise de comportamento de processos via MDE integrado, e varredura sem agente para secrets expostos em discos. Para o Banco Meridian, que tem VMs rodando workloads financeiros e bancos SQL com dados de contratos de crédito, operá-las sem esses planos é equivalente a ter câmeras de segurança desligadas em uma agência bancária.

**Por que agora:** Os planos devem ser habilitados antes de qualquer análise de compliance ou remediação, porque sem eles o Defender for Cloud não tem visibilidade suficiente para gerar as recomendações completas. Um finding de "SQL Server sem auditoria" só aparece no painel se o Defender for SQL estiver ativo.

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

**O que este passo faz:** O Secure Score é o indicador quantitativo principal da postura de segurança de uma organização no Defender for Cloud. Funciona como um termômetro de compliance: cada controle de segurança avaliado contribui com um número de pontos, e o score final é a porcentagem de pontos obtidos sobre o total possível. Para o Banco Meridian, o score inicial provavelmente será baixo (entre 30% e 55%) porque o ambiente de lab tem configurações padrão que frequentemente violam boas práticas — VMs com RDP público, storage accounts sem criptografia, SQL sem auditoria. Documentar este valor agora é fundamental: ao final do lab, depois das remediações, o delta do score vai demonstrar o impacto real das ações executadas. Este dado — "ambiente passou de 42% para 68% de secure score" — é exatamente o tipo de evidência que o CISO usa para comunicar resultados ao board e que os auditores do BACEN usam para validar maturidade de controles.

**Por que agora:** O score inicial deve ser registrado ANTES de qualquer remediação, para que a comparação final seja válida. Um score capturado após qualquer alteração não reflete o estado real do ambiente no momento do início do lab.

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

**O que você deve ver:** O score inicial aparece como um percentual no painel circular do Security posture. O número de recursos avaliados indica quantos assets estão sob análise. Controles com seta vermelha para baixo são os que têm maior impacto potencial na melhoria do score — priorizar esses na remediação.

**Anote**: Score inicial = ____%. Este será o ponto de partida para medir a melhoria.

---

### Passo 3: Onboardar Conta AWS

**O que este passo faz:** O Banco Meridian usa Azure como cloud primária, mas — como é comum em empresas financeiras de tier 2 — tem workloads também na AWS: o sistema de backup de documentos de crédito usa S3, e uma PoC de analytics usa instâncias EC2 na região us-east-1. Sem visibilidade multicloud unificada, os analistas do SOC precisariam alternar entre o portal Azure e o console AWS para ter uma visão completa da postura de segurança — criando silos de informação e aumentando o risco de configurações inseguras passarem despercebidas. Este passo conecta a conta AWS ao Defender for Cloud usando uma role IAM criada via CloudFormation stack, permitindo que o Defender avalie configurações de segurança dos serviços AWS (S3 bucket policies, IAM permissões, Security Groups, CloudTrail) contra benchmarks como CIS AWS Foundations e AWS Foundational Security Best Practices. A conexão é feita via delegação segura de acesso (trust policy) — o Defender não armazena credenciais AWS, apenas assume a role para leitura periódica de configurações. O plano CSPM é o mais relevante para este cenário: ele avalia e pontua a postura de segurança dos recursos AWS, gerando recomendações que aparecem no mesmo painel dos recursos Azure.

**Por que agora:** A conexão multicloud deve ser feita depois dos planos estarem habilitados (Passo 1), porque é o plano CSPM que habilita o engine de avaliação de conformidade que analisará os recursos AWS conectados. Conectar antes de habilitar o CSPM resultaria em uma conta AWS visível no inventário mas sem recomendações de segurança.

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

**O que este passo faz:** O Defender for Cloud suporta múltiplos frameworks regulatórios como standards de compliance que podem ser habilitados e avaliados automaticamente. Ao habilitar o standard "Brazilian Financial Institutions - BACEN Resolution 4893", o Defender passa a verificar automaticamente se os recursos Azure do Banco Meridian atendem aos controles técnicos exigidos pela resolução do Banco Central. Cada artigo da resolução é mapeado para um ou mais controles de configuração verificáveis: MFA obrigatório para administradores (Art. 5° II), criptografia de dados em repouso (Art. 5° III), retenção de logs por 5 anos (Art. 19), e assim por diante. O resultado é um dashboard de conformidade que mostra, para cada artigo do BACEN, quantos recursos estão conformes e quantos têm gaps — precisamente o tipo de relatório que um auditor do Banco Central solicitaria durante uma inspeção. Ter este standard habilitado transforma um exercício técnico de configuração em evidência documentada de conformidade regulatória.

**Por que agora:** Os standards de compliance devem ser habilitados depois do Secure Score inicial (Passo 2), para que o score inclua os controles dos standards quando for comparado no Passo 10.

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

**O que este passo faz:** O PCI DSS (Payment Card Industry Data Security Standard) versão 4.0 é o framework de segurança obrigatório para qualquer organização que processa, armazena ou transmite dados de cartões de pagamento. O Banco Meridian emite cartões Visa e Mastercard para seus clientes de varejo — portanto está sujeito ao PCI DSS. Habilitar este standard adiciona verificações automáticas focadas em proteção de dados de cartão: segmentação de rede (requerimento 1), proteção de dados em repouso com criptografia (requerimento 3), controle de acesso mínimo (requerimento 7), e monitoramento e logging contínuos (requerimento 10-11). A combinação de BACEN 4.893 + PCI DSS 4.0 no mesmo painel do Defender for Cloud permite que o CISO e o Compliance Officer visualizem simultaneamente a conformidade com os dois frameworks mais relevantes para o banco — sem precisar de ferramentas externas de GRC. Remediações prioritárias são aquelas que melhoram ambos os scores simultaneamente: um controle como "Storage encryption at rest" atende tanto ao BACEN (proteção de dados) quanto ao PCI DSS (proteção de dados de cartão).

**Por que agora:** Habilitar o PCI DSS junto ao BACEN, na mesma sessão, permite identificar sobreposições entre os dois frameworks. Executar ambos em sequência antes de começar as remediações garante que o Secure Score do Passo 2 seja o baseline correto para a comparação no Passo 10.

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

**O que este passo faz:** O painel de Recommendations do Defender for Cloud lista todas as configurações inseguras identificadas no ambiente, priorizadas por impacto no Secure Score e severidade. Este passo é o equivalente a uma revisão de código de segurança, mas para infraestrutura: o Defender "leu" a configuração de cada recurso Azure e apontou os problemas mais graves. Filtrar por "Critical" mostra os findings que, se explorados por um atacante, poderiam resultar em comprometimento total de um recurso (RDP público exposto para a internet é um finding crítico porque é o vetor mais simples de ataque a VMs Windows). Para o Banco Meridian, os findings críticos são exatamente o que o CISO precisa saber para priorizar o esforço de hardening: quais são os "portões abertos" que um atacante como o Grupo Lazarus-BR poderia usar para entrar na infraestrutura cloud do banco?

**Por que agora:** A análise de findings vem após os standards de compliance estarem habilitados, porque com BACEN 4.893 e PCI DSS 4.0 ativos, cada finding é contextualizado não apenas por severidade técnica, mas por impacto regulatório — um finding que viola tanto o BACEN quanto o PCI tem prioridade mais alta de remediação.

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

**O que este passo faz:** O Just-In-Time (JIT) VM Access é uma funcionalidade do Defender for Cloud que transforma o acesso remoto a VMs de permanente para temporário e auditado. Sem JIT, uma VM com a porta 3389 (RDP) ou 22 (SSH) aberta no Network Security Group está permanentemente exposta à internet — qualquer atacante pode tentar brute force de credenciais 24 horas por dia. O JIT fecha essas portas por padrão no NSG e as abre somente quando um usuário autorizado solicita acesso, especificando o IP de origem e a duração máxima da sessão. Após o tempo configurado, a porta fecha automaticamente. Isso reduz a janela de ataque de 525.600 minutos por ano (porta sempre aberta) para os minutos específicos em que a porta foi deliberadamente aberta por um usuário identificado. O JIT também cria um registro de auditoria completo: quem solicitou acesso, de qual IP, quando e por quanto tempo. Para o Banco Meridian, que precisa demonstrar controle de acesso aos seus servidores cloud para o BACEN, essa evidência de auditoria é parte da documentação regulatória exigida.

**Por que agora:** A remediação de JIT deve vir antes das outras remediações porque é a que reduz a superfície de ataque ativa mais rapidamente. Uma VM com RDP público está sendo varrida por bots de internet neste momento — cada minuto que permanece assim é uma janela de risco real.

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

**O que este passo faz:** Uma storage account Azure com acesso público habilitado significa que qualquer pessoa na internet pode listar e baixar os arquivos armazenados — sem autenticação. Para um Blob Storage comum com imagens de website isso pode ser intencional, mas para o Banco Meridian, qualquer storage com documentos de clientes, contratos, relatórios financeiros ou dados de sistemas internos exposta publicamente é uma violação grave da LGPD e da BACEN 4.893. O finding "Storage account public access should be disallowed" identifica storage accounts onde a propriedade `AllowBlobPublicAccess = true` está habilitada, mesmo que nenhum container individual esteja configurado como público. Desabilitar essa propriedade no nível da storage account age como um controle preventivo: mesmo que algum container seja erroneamente configurado como público no futuro, o acesso anônimo será bloqueado pela configuração da conta. O script PowerShell aplica a correção em todas as storage accounts do resource group, garantindo cobertura completa sem necessidade de verificar cada conta individualmente.

**Por que agora:** Storage públicas são vulnerabilidades que podem ser exploradas passivamente — um scanner automático na internet pode indexar e baixar os dados sem qualquer interação com o banco. A remediação deve ser aplicada o mais rápido possível após a identificação.

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

**O que este passo faz:** A auditoria de banco de dados SQL registra todas as atividades executadas contra o banco: queries executadas, logins bem-sucedidos e falhos, alterações de schema, operações administrativas. Para o Banco Meridian, o SQL Database que armazena contratos de crédito (`db-contratos`) sem auditoria habilitada representa um gap de visibilidade crítico: se um funcionário ou atacante executar uma query que exfiltra dados de milhares de clientes, não haverá nenhum registro da operação. A habilitação da auditoria direcionada ao workspace Log Analytics do Sentinel tem dois benefícios: (1) os logs de auditoria SQL ficam disponíveis para queries KQL no Sentinel, permitindo detecção de anomalias como leituras em massa de tabelas de clientes; (2) os logs ficam sob a política de retenção de 5 anos configurada no Passo 3, atendendo ao BACEN 4.893. A configuração `AuditActionGroup` define quais operações são auditadas — o conjunto mínimo recomendado pelo BACEN inclui DATABASE_LOGOUT_GROUP (sessões), SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP e DATABASE_OBJECT_ACCESS_GROUP (acesso a objetos).

**Por que agora:** A auditoria de SQL deve ser habilitada assim que o SQL database é criado — mas no contexto do lab, é habilitada aqui como remediação de um finding do Defender. Em ambientes de produção, este controle deve fazer parte do pipeline de IaC (Infrastructure as Code) para garantir que qualquer novo banco criado já tenha auditoria habilitada por padrão.

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

**O que este passo faz:** Este é o passo de fechamento do ciclo PDCA (Plan-Do-Check-Act) do lab: após planejar as remediações (Passo 6), executá-las (Passos 7-9) e ajustar configurações, agora verificamos o resultado quantitativo e documentamos o estado para auditoria. A melhoria no Secure Score demonstra numericamente que o ambiente está mais seguro. A exportação do relatório de compliance BACEN 4.893 em PDF é o documento que o CISO do Banco Meridian entregaria a um auditor do Banco Central em uma inspeção: cada artigo da resolução aparece com status "Compliant" ou "Non-compliant", junto com a lista de recursos afetados e evidências de configuração. Ter esse relatório disponível a qualquer momento — em vez de precisar preparar manualmente planilhas de auditoria — é um dos maiores valores práticos do Defender for Cloud para bancos sob supervisão do BACEN e da CMN 4.658.

**Por que agora:** O passo de verificação vem por último porque a melhoria do score só é mensurável após as remediações estarem concluídas. A query KQL de comparação usa os últimos 2 horas para garantir que apenas as configurações pós-remediação sejam refletidas.

**Verificar melhoria:**

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
