# Módulo 07 — Microsoft Defender for Cloud: CSPM e CWPP

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                    | Detalhes                                                                    |
|:-------------------------|:----------------------------------------------------------------------------|
| **Carga Horária**        | 5 horas (2h videoaulas + 2h laboratório + 1h live online)                   |
| **Formato**              | 2 aulas gravadas + Lab 06 + sessão live de compliance review                |
| **Pré-requisito**        | Módulos 01–06 concluídos                                                    |
| **Certificação Alvo**    | SC-200 — Domínio 6: Mitigate threats using Microsoft Defender for Cloud     |
| **Cenário**              | Banco Meridian — implementando visibilidade multi-cloud e compliance BACEN  |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o participante será capaz de:

1. Diferenciar CSPM e CWPP e como se complementam no Defender for Cloud
2. Interpretar e melhorar o Secure Score com remediações priorizadas
3. Aplicar standards de compliance: MCBS, ISO 27001, PCI DSS, LGPD e BACEN 4.893
4. Configurar Defender Plans para diferentes tipos de workloads
5. Onboardar contas AWS e projetos GCP no Defender for Cloud
6. Integrar Defender for Cloud findings no Microsoft Sentinel para correlação

---

## 1. CSPM vs CWPP: Diferença e Complementaridade

### 1.1 Cloud Security Posture Management (CSPM)

O **CSPM** avalia continuamente a configuração dos recursos cloud e identifica desvios em relação às melhores práticas de segurança. Pensa-se no CSPM como um "auditor automatizado" que verifica se o ambiente está configurado corretamente.

**O que o CSPM faz**:
- Inventário contínuo de todos os recursos Azure/AWS/GCP
- Avaliação de conformidade com standards (ISO 27001, NIST, PCI DSS, BACEN)
- Geração de recomendações priorizadas por impacto no Secure Score
- Detecção de configurações inseguras (storage público, credenciais expostas, criptografia desabilitada)
- Análise de permissões excessivas (IAM overprivilege)

**O que o CSPM NÃO faz**: Não protege contra ataques em tempo real. Não detecta malware. Não responde a incidentes.

### 1.2 Cloud Workload Protection Platform (CWPP)

O **CWPP** protege workloads específicas em execução — servidores, containers, bancos de dados — com detecção de ameaças em tempo real e resposta automatizada.

**O que o CWPP faz**:
- Detecção de malware, exploits e comportamento anômalo em servidores
- Proteção de containers e Kubernetes contra ataques runtime
- Monitoramento de bancos de dados para queries maliciosas e exfiltração
- Detecção de mineradores de criptografia, backdoors, web shells
- Integração com MDE para proteção de endpoints de servidor

**O que o CWPP NÃO faz**: Não avalia configuração estática. Não verifica compliance.

### 1.3 A Complementaridade

```
CSPM (Postura)              CWPP (Proteção)
────────────────────────    ───────────────────────────
"A porta está trancada?"    "Alguém está tentando arrombar?"
Avaliação estática          Detecção dinâmica em tempo real
Recomendações preventivas   Alertas e resposta a incidentes
Standards de compliance     Threat intelligence e ML
Inventory management        Runtime protection
```

Para o Banco Meridian: CSPM garante que nenhuma VM Azure tenha RDP exposto à internet sem NSG. CWPP detecta se uma VM com RDP corretamente protegida for comprometida via outra vulnerabilidade e começar a executar comandos suspeitos.

---

## 2. Secure Score: Cálculo e Melhorias

### 2.1 Como o Secure Score é Calculado

O Secure Score é uma métrica de 0-100 que representa a postura de segurança relativa do ambiente. É calculado com base em:

```
Secure Score = (Pontos obtidos / Pontos máximos possíveis) × 100

Exemplo do Banco Meridian:
- Pontos máximos: 450 pontos (todas as recomendações implementadas)
- Pontos obtidos: 312 pontos (recomendações já implementadas)
- Secure Score: (312 / 450) × 100 = 69.3%
```

Cada **controle de segurança** (grupo de recomendações relacionadas) tem um peso em pontos. Implementar uma recomendação adiciona os pontos do controle ao score.

### 2.2 Exemplo de Controles e Impacto

| Controle de Segurança                          | Max Pontos | Implementado? | Impacto Potencial |
|:-----------------------------------------------|:----------:|:-------------:|:-----------------:|
| Enable MFA                                     | 14         | Parcial (7)   | +7 pontos         |
| Secure management ports                        | 8          | Não           | +8 pontos         |
| Apply system updates                           | 6          | Parcial (3)   | +3 pontos         |
| Enable endpoint protection                     | 2          | Sim           | —                 |
| Encrypt data at rest                           | 4          | Parcial (2)   | +2 pontos         |
| Remediate security configurations              | 3          | Não           | +3 pontos         |

### 2.3 Priorizando Recomendações

A coluna "Quick Fix" indica recomendações que podem ser remediadas com um clique ou script simples. Priorizar estas para ganho rápido de Secure Score.

**Query KQL para listar recomendações priorizadas por impacto**:
```kql
// Recomendações do Defender for Cloud ordenadas por impacto no Secure Score
SecurityRecommendation
| where TimeGenerated > ago(1d)
| where State == "Unhealthy"
| summarize 
    AffectedResources = dcount(Id),
    MaxImpact = max(RecommendationSeverity)
    by RecommendationName, RecommendationDisplayName, 
       RemediationDescription, IsBuiltIn
| sort by AffectedResources desc
```

---

## 3. Standards de Compliance

### 3.1 Standards Disponíveis no Defender for Cloud

| Standard                               | Órgão             | Relevância para Banco Meridian                      | Nº de Controles |
|:---------------------------------------|:-----------------:|:----------------------------------------------------|:---------------:|
| Microsoft Cloud Security Benchmark     | Microsoft         | Baseline de segurança Azure; sempre habilitado      | 230+            |
| Azure Security Benchmark v3            | Microsoft         | Versão anterior — substituída pelo MCSB             | 196             |
| ISO/IEC 27001:2013                     | ISO/IEC           | Certificação internacional de SGSI                  | 114             |
| NIST SP 800-53 Rev. 5                  | NIST (EUA)        | Controles de segurança federais EUA; base para outros | 1.000+        |
| NIST SP 800-171 Rev. 2                 | NIST (EUA)        | Proteção de informações controladas não-classificadas | 110           |
| PCI DSS 4.0                            | PCI SSC           | Mandatório para bancos que processam cartões        | 300+            |
| SOC 2 Type 2                           | AICPA             | Segurança, disponibilidade, confidencialidade       | 80+             |
| CIS Microsoft Azure Foundations 2.0    | CIS               | Benchmark de configuração Azure do CIS              | 180+            |
| FedRAMP Moderate                       | FedRAMP (EUA)     | Requisito para contratos com governo EUA            | 325             |
| LGPD (Lei Geral de Proteção de Dados) | ANPD (Brasil)    | Mandatório para organizações com dados de brasileiros | 65+           |
| BACEN 4.893                            | BACEN (Brasil)    | Resolução de segurança cibernética para IF          | 48+             |
| BACEN 4.658 / CMN 4.658                | BACEN (Brasil)    | Contratação de serviços cloud por IF                | 32+             |
| ISO/IEC 27002:2022                     | ISO/IEC           | Versão atualizada de controles de segurança         | 93              |
| SWIFT CSP CSCF v2023                   | SWIFT             | Mandatório para IF conectadas à rede SWIFT          | 32+             |

### 3.2 Habilitando BACEN 4.893 no Banco Meridian

```
Portal Azure → Microsoft Defender for Cloud → Regulatory compliance
→ Manage compliance policies
→ Subscription: Banco Meridian Prod
→ Enable: "Brazilian Financial Institutions - BACEN Resolution 4893"
→ Enable: "LGPD"
→ Enable: "PCI DSS 4.0" (banco processa cartões)
→ Save
```

Após habilitação (até 24h para avaliação completa), o relatório de compliance mostrará:
- Controles em conformidade (verde)
- Controles com falhas (vermelho)
- Controles não aplicáveis (cinza)

### 3.3 Controles BACEN 4.893 Mais Importantes

| Art. BACEN 4.893 | Controle                                              | Verificação no Defender for Cloud                    |
|:----------------|:------------------------------------------------------|:-----------------------------------------------------|
| Art. 5°, II      | Autenticação de dois fatores para sistemas críticos   | Recomendação: "MFA should be enabled on accounts"    |
| Art. 5°, III     | Criptografia de dados em trânsito e repouso           | "Storage should use customer-managed keys"           |
| Art. 5°, IV      | Controles de acesso baseados em mínimo privilégio     | "Management ports of VMs should be protected"        |
| Art. 5°, VII     | Testes de penetração e análise de vulnerabilidades    | Vulnerability Assessment integrado ao CWPP           |
| Art. 6°          | Plano de continuidade de negócios                     | "Backup solution should be enabled for VMs"          |
| Art. 19          | Registro e retenção de logs por 5 anos                | "Diagnostic logs in App Services should be enabled"  |
| Art. 23          | Notificação de incidentes ao BACEN em 72h             | Requer processo manual + Sentinel automation         |

---

## 4. Defender Plans: CWPP para Cada Workload

### 4.1 Tabela de Defender Plans

| Defender Plan                | O que protege                                    | Preço aproximado          | Detecções principais                                     |
|:-----------------------------|:-------------------------------------------------|:--------------------------|:---------------------------------------------------------|
| **Defender for Servers P1**  | VMs Windows e Linux (Azure, on-prem, AWS, GCP)   | ~$3.5/server/mês          | Vulnerability assessment, MDE integration                |
| **Defender for Servers P2**  | Idem P1 + recursos avançados                     | ~$7/server/mês            | +JIT access, FIM (File Integrity Monitoring), adaptive application controls |
| **Defender for Containers**  | AKS, Arc-enabled Kubernetes, container registries| ~$7/vCore/mês             | Runtime threats, image scanning, control plane attacks   |
| **Defender for SQL**         | Azure SQL, SQL Server em VMs, SQL em ARC          | ~$15/server/mês           | SQL injection, brute force, anomalous queries, data exfil |
| **Defender for Storage**     | Azure Blob, Files, Data Lake Gen2                | ~$10/storage account/mês  | Malware upload, phishing URLs, anomalous access         |
| **Defender for Key Vault**   | Azure Key Vault (secrets, keys, certificates)    | ~$0.20/10k ops/mês        | Unusual access patterns, key export, geo-anomalies       |
| **Defender for App Service** | Azure App Service (PaaS web apps)                | ~$15/app service plan/mês | Dangling DNS, web shell, suspicious file operations      |
| **Defender for ARM**         | Azure Resource Manager (control plane)           | ~$4/subscription/mês      | Suspicious admin operations, mass resource creation      |
| **Defender for DNS**         | DNS queries do Azure                             | ~$0.20/1M queries/mês     | DNS exfiltration, mining domains, C2 over DNS            |

### 4.2 Habilitando Defender Plans via PowerShell

Habilitar os Defender Plans via PowerShell é o método recomendado para ambientes que seguem Infrastructure as Code. Permite documentar exatamente quais planos estão habilitados em qual subscription, revisar mudanças via pull request e replicar a configuração em outros ambientes (ex.: criar um sandbox com a mesma postura de segurança que a produção).

**Por que não basta clicar em "Enable All" no portal:** O portal tem um botão "Enable all plans" que é tentador, mas pode gerar custos significativos não planejados. Para o Banco Meridian, habilitar todos os planos em uma subscription com 200 VMs, 50 SQL databases e 30 storage accounts pode custar $2.000-5.000/mês. A abordagem seletiva — habilitando apenas os planos para workloads que existem e que têm risco relevante — é mais responsável financeiramente sem comprometer a cobertura de segurança.

**O que cada plano no script abaixo protege no contexto do Banco Meridian:**
- `VirtualMachines`: Protege os servidores que hospedam o sistema bancário core e middleware de integração
- `SqlServers`: Protege os bancos de dados relacionais onde ficam as transações e dados de clientes
- `StorageAccounts`: Protege o armazenamento de extratos, contratos digitalizados e backups
- `KeyVaults`: Protege as chaves criptográficas usadas para assinar transações e certificados TLS

```powershell
# Habilitar Defender for Servers P2 na subscription do Banco Meridian
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"

# Habilitar Defender for SQL
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"
Set-AzSecurityPricing -Name "SqlServerVirtualMachines" -PricingTier "Standard"

# Habilitar Defender for Storage
Set-AzSecurityPricing -Name "StorageAccounts" -PricingTier "Standard"

# Habilitar Defender for Key Vault
Set-AzSecurityPricing -Name "KeyVaults" -PricingTier "Standard"

# Verificar todos os planos habilitados
Get-AzSecurityPricing | Select-Object Name, PricingTier | Format-Table

# Configurar auto-provisioning do agente MDE em novas VMs
Set-AzSecurityAutoProvisioningSetting -Name "MDE.Windows" -AutoProvision "On"
Set-AzSecurityAutoProvisioningSetting -Name "MDE.Linux" -AutoProvision "On"
```

### 4.3 JIT (Just-In-Time) VM Access

O JIT Access do Defender for Servers P2 protege portas de gerenciamento (RDP 3389, SSH 22, WinRM 5985/5986) contra exposição permanente:

```json
// Política JIT para VMs do Banco Meridian
// Aplicada via portal Defender for Cloud → Workload protections → JIT VM access

{
  "virtualMachines": [
    {
      "id": "/subscriptions/{sub}/resourceGroups/rg-meridian-legacy/providers/Microsoft.Compute/virtualMachines/VM-CoreBanking-01",
      "ports": [
        {
          "number": 3389,
          "protocol": "TCP",
          "allowedSourceAddressPrefix": "10.0.0.0/8",
          "maxRequestAccessDuration": "PT2H"
        },
        {
          "number": 22,
          "protocol": "TCP",
          "allowedSourceAddressPrefix": "10.0.0.0/8",
          "maxRequestAccessDuration": "PT1H"
        }
      ]
    }
  ]
}
```

**Funcionamento**: Por padrão, as portas estão fechadas no NSG. Quando um administrador precisa de acesso, solicita via portal/API. O acesso é aprovado (manualmente ou automaticamente baseado em critérios) e aberto por no máximo 2 horas para o IP do solicitante. Após o tempo, a porta fecha automaticamente.

---

## 5. Multi-Cloud: Onboarding AWS e GCP

### 5.1 Onboarding de Conta AWS

**Pré-requisitos na AWS**:
- Conta AWS com permissões de criação de roles IAM
- CloudTrail habilitado na conta (para logs de atividade)
- AWS Security Hub habilitado (recomendado)

**Passo a passo**:
```
Defender for Cloud → Environment settings → Add environment → Amazon Web Services
→ Subscription: Banco Meridian Prod
→ Connector name: aws-meridian-analytics
→ Região: us-east-1 (onde os workloads AWS do banco estão)

→ Select plans:
   ✓ Defender CSPM (CSPM sem agente para AWS)
   ✓ Defender for Servers (integração com MDE para EC2)
   ✓ Defender for Containers (EKS)
   ✓ Defender for SQL (RDS)

→ Configure access:
   → Criar CloudFormation Stack na AWS (usa template fornecido pelo Defender)
   → O template cria a role IAM com permissões mínimas necessárias:
      SecurityAudit (read-only para CSPM)
      + permissions para SSM (agente MDE em EC2)
   → ARN da role criada: arn:aws:iam::123456789:role/MDC-MeridiamRole
   
→ Review + Create
```

**Verificação após 24h**:
```kql
// Verificar se recursos AWS estão sendo inventariados
SecurityResources
| where Type startswith "aws/"
| summarize count() by Type, ResourceGroup
```

### 5.2 Standards Aplicados ao AWS

Após o onboarding, o Defender for Cloud aplica automaticamente:
- **AWS Foundational Security Best Practices**: 126 controles AWS
- **CIS Amazon Web Services Foundations Benchmark 2.0**: 69 controles
- **NIST SP 800-53 Rev. 5**: 1000+ controles (inclui recursos AWS)
- **PCI DSS 4.0**: controles mapeados para AWS

Para o Banco Meridian, habilitar também **BACEN 4.893** aplicado à conta AWS.

### 5.3 Onboarding de Projeto GCP

```
Defender for Cloud → Environment settings → Add environment → Google Cloud Platform
→ Connector name: gcp-meridian-backup
→ Google Cloud project ID: meridian-backup-prod

→ Configure access via Terraform ou script:
```

```bash
# Script de configuração gerado pelo Defender for Cloud
# Executar no Google Cloud Shell com permissões de Owner no projeto

# 1. Criar service account
gcloud iam service-accounts create mdc-connector \
  --display-name="Microsoft Defender for Cloud Connector"

# 2. Atribuir papel de Security Reviewer
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:mdc-connector@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

# 3. Criar key para autenticação
gcloud iam service-accounts keys create mdc-key.json \
  --iam-account=mdc-connector@PROJECT_ID.iam.gserviceaccount.com

# 4. Upload da key no portal Defender for Cloud
```

---

## 6. CWPP: Proteção de Workloads e Integração com MDE

### 6.1 Detecções de CWPP para Servidores

Com **Defender for Servers P2** habilitado, o Defender for Cloud monitora:

**Detecções Linux**:
```
- Execução de scripts suspeitos (curl | bash, wget | sh — common malware install pattern)
- Mineradores de criptografia (processo consumindo CPU anormalmente)
- Backdoors e reverse shells (conexões de saída para IPs suspeitos)
- Web shells (uploads de arquivos PHP/ASPX suspeitos)
- Exploits contra serviços de rede (Nginx, Apache, SSH brute force)
```

**Detecções Windows**:
```
- Malware injetado em processos legítimos (process hollowing)
- Execução de PowerShell ofuscado (base64 decode + exec)
- AMSI bypass attempts (AntiMalware Scan Interface)
- Fileless malware (reflective DLL injection)
- Uso de LOLBins para execução de código (certutil, regsvr32, mshta)
```

### 6.2 File Integrity Monitoring (FIM)

O FIM monitora mudanças em arquivos e registry críticos, alertando sobre alterações suspeitas:

**Arquivos monitorados (Windows)**:
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\
C:\Program Files\
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM:\SYSTEM\CurrentControlSet\Services\
```

**Arquivos monitorados (Linux)**:
```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/crontab
/etc/cron.d/
/bin/
/usr/bin/
/sbin/
```

---

## 7. Remediação Assistida e Export Contínuo

### 7.1 Quick Fix e Remediação em Escala

Algumas recomendações têm um botão "Quick Fix" que aplica a remediação automaticamente:
- Habilitar criptografia em disco para todas as VMs não criptografadas
- Habilitar MFA para contas sem MFA
- Fechar portas de gerenciamento expostas

**Remediação em lote via CLI**:
```powershell
# Remediar "Enable disk encryption for VMs" em todas as VMs do resource group
$rg = "rg-meridian-legacy"
$vms = Get-AzVM -ResourceGroupName $rg

foreach ($vm in $vms) {
    # Verificar se já tem criptografia
    $diskEncryptionStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $rg -VMName $vm.Name
    
    if ($diskEncryptionStatus.OsVolumeEncrypted -eq "NotEncrypted") {
        # Habilitar criptografia com ADE
        Set-AzVMDiskEncryptionExtension `
            -ResourceGroupName $rg `
            -VMName $vm.Name `
            -DiskEncryptionKeyVaultUrl "https://kv-meridian-security.vault.azure.net" `
            -DiskEncryptionKeyVaultId "/subscriptions/.../kv-meridian-security" `
            -SkipVmBackup `
            -Force
        
        Write-Host "Criptografia habilitada: $($vm.Name)"
    }
}
```

### 7.2 Export Contínuo para o Sentinel

Para integrar os findings do Defender for Cloud no Sentinel:

```
Defender for Cloud → Environment settings → [Subscription] → Continuous export
→ Export to Log Analytics workspace
→ Workspace: meridian-secops-prod
→ Export: 
  ✓ Security alerts (gera SecurityAlert no workspace)
  ✓ Security recommendations (gera SecurityRecommendation)
  ✓ Regulatory compliance assessments (gera SecurityRegulatoryCompliance)
→ Save
```

**Query para correlacionar alerts do Defender for Cloud com eventos do Sentinel**:
```kql
// Correlacionar alerta do Defender for Cloud com logs de atividade Azure
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProviderName == "Azure Security Center"
| where AlertSeverity in ("High", "Critical")
| extend AffectedResource = tostring(parse_json(Entities)[0].AzureID)
| join kind=leftouter (
    AzureActivity
    | where TimeGenerated > ago(24h)
    | where ActivityStatus != "Succeeded"
    | project ActivityTime = TimeGenerated, Caller, OperationName, 
              ResourceId, ActivityStatus
) on $left.AffectedResource == $right.ResourceId
| project TimeGenerated, AlertName, AlertSeverity, AffectedResource,
          ActivityTime, Caller, OperationName, ActivityStatus
```

---

## 8. Atividades de Fixação

### Questão 1
O Banco Meridian tem 50 VMs Azure. O CSPM do Defender for Cloud identificou que 30 delas têm a porta RDP (3389) aberta para o endereço 0.0.0.0/0 (internet inteira). Qual é a recomendação correta e a solução imediata?

a) Desabilitar RDP em todas as VMs e usar apenas console serial  
b) Habilitar JIT VM Access para fechar as portas RDP por padrão e abrir apenas quando necessário, pelo IP e tempo exatos solicitados  
c) Criar um NSG permitindo apenas o IP do escritório sede em 3389  
d) Mover todas as VMs para uma subnet privada sem rota para internet  

**Gabarito: B** — JIT VM Access é a solução mais segura e prática: fecha as portas de gerenciamento no NSG por padrão (zero exposure), e abre apenas quando um administrador solicita, apenas para o IP específico do solicitante, por um tempo limitado (ex.: 2 horas). A opção C (NSG com IP do escritório) é melhor que 0.0.0.0/0 mas ainda deixa a porta exposta permanentemente para o range do escritório — se o IP do escritório mudar ou for spoofado, há risco. JIT é a solução preferida pela MCRA e pelo BACEN para acesso administrativo a servidores.

---

### Questão 2
A recomendação "Defender for SQL should be enabled on SQL Servers" aparece no Secure Score com impacto de 4 pontos. O Banco Meridian tem 8 SQL Servers. Ao habilitar o Defender for SQL em todos eles, o que passa a ser monitorado?

a) Apenas o desempenho do banco de dados (queries lentas e bloqueios)  
b) Comportamento anômalo e ameaças: SQL injection, brute force, acesso de usuário de país nunca antes visto, exportação massiva de dados, logins em horários incomuns  
c) Apenas backups e recovery point objectives  
d) Conformidade com políticas de naming convention do Azure  

**Gabarito: B** — O Defender for SQL (CWPP para bancos de dados) monitora o comportamento em tempo real: tenta detectar SQL injection nas queries, brute force de autenticação, logins de localizações geográficas anômalas, exportação de volumes incomuns de dados (possível exfiltração), e acesso por contas que nunca acessaram o banco antes. Gera alertas no Defender for Cloud e sincroniza com o Sentinel. Para o Banco Meridian, o SQL Server de core banking é um ativo crítico — Defender for SQL é mandatório.

---

### Questão 3
O Banco Meridian habilitou o standard "BACEN 4.893" no Defender for Cloud e o relatório mostra 68% de compliance. O controle "Audit logs should be enabled for all databases" está falhando para 5 bancos de dados. Qual é a ação mais rápida para remediação?

a) Deletar e recriar os bancos de dados com auditoria habilitada por padrão  
b) Usar a função "Quick Fix" ou "Remediate" na recomendação para habilitar auditoria em todos os 5 bancos com um script Azure Policy ou botão de remediação  
c) Criar manualmente uma política de auditoria em cada banco de dados pelo SSMS  
d) O Defender for Cloud não suporta remediação automática de bancos de dados  

**Gabarito: B** — O Defender for Cloud oferece remediação assistida ("Quick Fix" ou "Remediate") para a maioria das recomendações. Para auditoria de SQL databases, o Quick Fix habilita a auditoria em todos os recursos falhando com um único clique, configurando automaticamente os logs para ir ao Log Analytics Workspace. Isso é muito mais eficiente do que configurar manualmente cada banco. O Defender for Cloud também pode criar Azure Policies que garantem que futuros bancos de dados sejam criados com auditoria habilitada (prevenção em vez de remediação).

---

### Questão 4
Após onboardar a conta AWS do Banco Meridian no Defender for Cloud, qual standard de compliance é aplicado automaticamente?

a) Apenas o BACEN 4.893 (por ser um banco brasileiro)  
b) O AWS Foundational Security Best Practices e o CIS Amazon Web Services Foundations Benchmark são habilitados automaticamente; outros standards como PCI DSS e BACEN devem ser habilitados manualmente  
c) Nenhum standard é aplicado automaticamente — todos devem ser configurados manualmente  
d) Apenas o ISO 27001 é aplicado automaticamente  

**Gabarito: B** — Ao onboardar uma conta AWS, o Defender for Cloud habilita automaticamente: AWS Foundational Security Best Practices (FSBP) e CIS AWS Foundations Benchmark. Isso fornece cobertura básica imediata. Standards regulatórios específicos (PCI DSS, BACEN, LGPD, NIST) devem ser habilitados manualmente conforme necessidade da organização. Para o Banco Meridian, após o onboarding, o próximo passo é habilitar PCI DSS 4.0 e BACEN 4.893 para os recursos AWS.

---

### Questão 5
O CSPM mostrou que uma conta de storage do Banco Meridian tem acesso público habilitado (anonymous blob access = true). O CWPP (Defender for Storage) também está habilitado. Qual produto detecta qual ameaça?

a) Ambos detectam a mesma coisa — são redundantes  
b) CSPM detecta a configuração incorreta (acesso público habilitado) proativamente como uma recomendação de postura; CWPP detecta se alguém está de fato acessando o storage de forma maliciosa (ex.: upload de malware, tentativa de enumerar blobs, acesso de IP suspeito)  
c) Apenas o CSPM detecta — o CWPP não monitora storage  
d) Apenas o CWPP detecta — o CSPM não avalia storage  

**Gabarito: B** — Esta é a complementaridade CSPM/CWPP em ação: CSPM identifica a vulnerabilidade de configuração (acesso público = superfície de ataque exposta) antes de ser explorada. CWPP detecta se a vulnerabilidade está sendo ativamente explorada (malware sendo uploadado para o storage, dados sendo exfiltrados, scan de blobs). Para o Banco Meridian: o CSPM gera recomendação "Disable public access to storage accounts" que deve ser remediada imediatamente; enquanto não é remediada, o CWPP monitora o storage para atividade maliciosa.

---

## 9. Roteiros de Gravação

### Aula 7.1 — CSPM, Secure Score e Compliance (50 minutos)

---

**[PRÉ-PRODUÇÃO]**
- Ambiente: subscription Azure com Defender for Cloud habilitado
- Ter: Secure Score atual calculado, pelo menos 20 recomendações falhando
- Ter habilitado: Microsoft Cloud Security Benchmark + PCI DSS

---

**[0:00 — ABERTURA | 3 minutos]**

"Módulo 7 — Defender for Cloud. Este é o módulo que fecha a visão de postura de segurança do Banco Meridian. Antes falávamos de detecção de ataques. Agora falamos de prevenção — garantir que o ambiente esteja configurado corretamente para que os ataques tenham menos superficie para explorar.

Dois conceitos centrais: CSPM (Cloud Security Posture Management) — o auditor de configuração — e CWPP (Cloud Workload Protection) — a proteção em tempo real das cargas de trabalho."

---

**[3:00 — BLOCO 1: CSPM E SECURE SCORE | 15 minutos]**

*[Screen share: portal Azure → Defender for Cloud → Overview]*

"Abro o Defender for Cloud. A primeira coisa que vejo é o Secure Score: 72%. Isso significa que o Banco Meridian implementou 72% dos controles de segurança recomendados pela Microsoft.

*[Clicar em Secure Score → ver breakdown por controle]*

Vou em 'Security posture'. Aqui estão todos os controles agrupados. Posso ver quantos pontos cada um vale e quantas recomendações ainda preciso implementar.

O maior ganho potencial: 'Enable endpoint protection' — vale 8 pontos e só preciso de uma ação. Clico para ver as VMs que não têm MDE instalado.

*[Mostrar lista de recursos com recomendação falhando]*

São 3 VMs que não têm o agente MDE. Vou usar o Quick Fix para habilitar o auto-provisioning e instalar o agente nelas automaticamente.

*[Executar Quick Fix]*

O Quick Fix criou uma Azure Policy que habilitará o agente MDE automaticamente em todas as novas VMs também. Isso é gestão de postura em escala — não apenas corrijo o presente, mas previno problemas futuros."

---

**[18:00 — BLOCO 2: REGULATORY COMPLIANCE | 20 minutos]**

*[Screen share: Defender for Cloud → Regulatory compliance]*

"Aqui está a parte mais importante para o Banco Meridian regulatório — Regulatory Compliance.

Vejo os standards habilitados: MCSB, PCI DSS 4.0, ISO 27001. Vou habilitar o BACEN 4.893.

*[Manage compliance policies → habilitar BACEN 4.893]*

Aguardar 24h para avaliação completa. Mas vou mostrar o PCI DSS que já está avaliado.

*[Clicar em PCI DSS 4.0]*

Aqui está o relatório de compliance PCI DSS. Estamos em 64%. Os controles em vermelho são onde temos falhas.

*[Expandir um controle falho — ex.: Requirement 7 (Restrict Access)]*

Este controle tem 12 recomendações. 4 delas estão falhando. Clico em uma recomendação para ver os recursos específicos que falharam e o passo a passo de remediação.

Para o relatório ao CISO: posso fazer download do relatório em PDF clicando em 'Download report'. Este relatório documenta a postura de compliance em um momento específico — útil para auditorias BACEN."

---

**[38:00 — BLOCO 3: EXEMPTIONS E GESTÃO | 10 minutos]**

*[Screen share: uma recomendação específica]*

"Nem toda recomendação precisa ser remediada. Às vezes há controles compensatórios ou contextos específicos onde a recomendação não se aplica.

Por exemplo: 'Virtual machines should encrypt temp disks, caches, and data flows'. Uma das nossas VMs é um servidor de testes que não processa dados sensíveis. Posso criar uma Exemption para ela:

*[Mostrar como criar exemption]*

Waiver vs Mitigated: Waiver = reconhecemos o risco mas assumimos; Mitigated = temos controle compensatório equivalente.

Importante: Exemptions têm validade e devem ser revisadas periodicamente. Uma exemption criada por 6 meses não deve se tornar permanente por falta de acompanhamento."

---

**[48:00 — ENCERRAMENTO | 2 minutos]**

"Na próxima aula, habilitamos os Defender Plans (CWPP) e conectamos a conta AWS do Banco Meridian para visibilidade multi-cloud. Vamos também fazer a integração com o Sentinel para que os findings do Defender for Cloud apareçam nos incidentes."

---

### Aula 7.2 — Defender Plans, Multi-Cloud e CWPP (50 minutos)

---

**[0:00 — ABERTURA | 2 minutos]**

"Continuando. Na última aula vimos CSPM e compliance. Hoje habilitamos a proteção de workloads — os Defender Plans que fazem o CWPP — e expandimos para multi-cloud, conectando a conta AWS do banco."

---

**[2:00 — BLOCO 1: HABILITANDO DEFENDER PLANS | 12 minutos]**

*[Screen share: Defender for Cloud → Environment settings → [subscription] → Defender plans]*

"Aqui estão todos os Defender Plans. Por padrão, a maioria está desabilitado — você paga por uso.

Para o Banco Meridian, vou habilitar:

Defender for Servers P2 → On. Isso instala o Agente MDE em todas as VMs da subscription e habilita JIT, FIM, Vulnerability Assessment.

*[Habilitar e mostrar os subcomponentes]*

Dentro de Servers P2: habilito 'File Integrity Monitoring'. Seleciono os diretórios a monitorar.

Defender for SQL → On. Vou para SQL servers e mostro as detecções ativas.

Defender for Storage → On. Fundamental para proteger o storage do banco.

Defender for Key Vault → On. O Key Vault guarda as chaves de criptografia — precisa de proteção especial.

*[Salvar e comentar custo estimado]*

O custo estimado está visível no lado direito. Para o Banco Meridian com 50 VMs + 8 SQL Servers + 10 storage accounts: estimativa de ~$800/mês. Para um banco tier 2, este é o custo de 1/4 de um analista SOC — com proteção 24/7 automatizada."

---

**[14:00 — BLOCO 2: ONBOARDING AWS | 18 minutos]**

*[Screen share: Defender for Cloud → Environment settings → Add environment → AWS]*

"Vou onboardar a conta AWS do Banco Meridian. Esta conta tem workloads analíticas com dados de clientes — precisamos da mesma visibilidade que temos no Azure.

*[Preencher o formulário de criação do conector AWS]*

Conector name: aws-meridian-analytics
Region: us-east-1

Plans: habilito CSPM e Defender for Servers.

*[Mostrar o template CloudFormation]*

O Defender for Cloud gera um CloudFormation template que cria a role IAM necessária na AWS. Copio o link e mostro o template.

*[Abrir o console AWS e executar o CloudFormation]*

No AWS Management Console → CloudFormation → Create Stack → com o template gerado. A Stack vai criar a role e as permissões necessárias.

*[Aguardar a stack e copiar o ARN da role]*

Copio o ARN da role criada e volto para o portal Azure. Cole o ARN.

Review + Create. Conector criado.

*[DICA DE EDIÇÃO: time-lapse da criação do conector — espera de 5min pode ser comprimida para 30s]*

Em 24h, os recursos AWS aparecerão no inventário do Defender for Cloud e no Secure Score consolidado."

---

**[32:00 — BLOCO 3: EXPORT CONTÍNUO PARA SENTINEL | 10 minutos]**

*[Screen share: Defender for Cloud → Environment settings → Continuous export]*

"Última parte: integrar o Defender for Cloud com o Sentinel.

Export to Log Analytics workspace → seleciono o workspace meridian-secops-prod.

O que exportar: Security alerts ✓, Security recommendations ✓, Regulatory compliance ✓.

Save.

Agora, vou ao Sentinel para verificar se os dados chegam.

*[Screen share: Sentinel → Logs → SecurityAlert | where ProviderName == 'Azure Security Center']*

Os alertas do Defender for Cloud aparecem na tabela SecurityAlert. Posso criar analytics rules no Sentinel que correlacionam esses alertas com outros eventos — por exemplo, se um alerta do Defender for Cloud sobre acesso anômalo a Key Vault coincide com um login suspeito no Entra ID."

---

**[42:00 — BLOCO 4: JIT VM ACCESS NA PRÁTICA | 6 minutos]**

*[Screen share: Defender for Cloud → Workload protections → Just-in-time VM access]*

"Vou demonstrar o JIT em ação. Aqui estão as VMs com JIT configurado.

Seleciono VM-CoreBanking-01. Clico em 'Request access'. Aparecem as opções de portas disponíveis: RDP 3389 e SSH 22. Seleciono RDP, defino 'My IP' como origem e tempo de acesso: 2 horas.

*[Clicar em Open ports]*

O portal mostra: 'Request approved'. Por trás, foi criada uma regra NSG temporária permitindo meu IP atual na porta 3389 por 2 horas.

Após 2 horas, a regra é removida automaticamente. O atacante que tentar RDP no mesmo endereço IP fora dessa janela receberá 'Connection timed out'."

---

**[48:00 — ENCERRAMENTO | 2 minutos]**

"Cobrimos o Defender for Cloud completo: CSPM com Secure Score e compliance BACEN, CWPP com Defender Plans para servidores e workloads, multi-cloud com AWS conectado, e integração com o Sentinel. 

No Lab 06, vocês vão fazer o onboarding AWS completo no ambiente de vocês, aplicar os standards de compliance e remediar 3 findings críticos. O gabarito mostra o estado final esperado do Secure Score."

---

## 10. Avaliação do Módulo

**Q1.** O Secure Score do Banco Meridian é de 65%. O controle "MFA should be enabled for all accounts with owner permissions on subscriptions" representa 14 pontos. Se o banco implementar MFA para essas 5 contas, qual será o novo Secure Score aproximado?

a) 65% + 14 = 79% (adição direta dos pontos)  
b) O Secure Score aumentará, mas não exatamente 14%, pois o cálculo é pontos_obtidos/pontos_totais × 100 — a contribuição real depende dos pontos totais da subscription  
c) 65% dobrado = 130% (inválido)  
d) O Secure Score só muda após 24 horas de reavaliação  

**Resposta: B** — O Secure Score não funciona por adição percentual direta. Exemplo: se pontos totais = 200 e pontos obtidos = 130 → Score = 65%. Ao implementar um controle de 14 pontos: novos pontos obtidos = 144, Score = 144/200 = 72%. A melhoria foi de 7 pontos percentuais (não 14%). O valor "14 pontos" é o peso absoluto do controle, não o ganho percentual. A resposta B é a única que reconhece essa distinção.

---

**Q2.** O File Integrity Monitoring (FIM) no Defender for Servers P2 detectou que o arquivo `/etc/sudoers` foi modificado em um servidor Linux de produção às 3h37 por um processo com PID 8472. O que isso indica?

a) Uma atualização normal do sistema operacional  
b) Uma modificação potencialmente maliciosa do arquivo de controle de acesso sudo, que pode ter concedido privilégios elevados a uma conta não autorizada — requer investigação imediata do processo 8472 e do conteúdo atual do arquivo  
c) Um bug no FIM — arquivos sudoers não são modificados por processos  
d) O cron job de backup modificou o arquivo como esperado  

**Resposta: B** — O arquivo `/etc/sudoers` define quais usuários podem executar comandos com privilégio de root via `sudo`. Sua modificação fora de janelas de manutenção planejadas, especialmente de madrugada, é altamente suspeita. Um atacante que obteve acesso a um usuário não-root pode modificar o sudoers para se conceder acesso root permanente (persistência e escalada de privilégio). A resposta correta é investigar imediatamente: identificar o processo 8472, verificar o conteúdo atual do sudoers contra o backup, e verificar se a modificação adicionou linhas não autorizadas.

---

**Q3.** Após onboardar a conta AWS, o Defender for Cloud mostra Secure Score de 58% para os recursos AWS. Isso significa que:

a) O Banco Meridian precisa migrar todos os recursos AWS para Azure  
b) 58% dos controles do CIS AWS e AWS FSBP estão em conformidade; 42% têm recomendações falhando que precisam ser avaliadas e possivelmente remediadas  
c) O ambiente AWS está completamente inseguro  
d) A Microsoft não avalia corretamente recursos AWS — o score é apenas para Azure  

**Resposta: B** — Um Secure Score de 58% para uma conta AWS recém-onboardada é normal e esperado — muitas organizações não configuram a nuvem com foco em segurança desde o início. O score de 58% significa que 42% dos controles avaliados têm pelo menos uma recomendação falhando. Isso não significa que o ambiente está completamente inseguro (alguns controles falhando são de baixo risco) — significa que há um plano de trabalho claro para melhorar a postura. O Defender for Cloud avalia nativamente recursos AWS via APIs da AWS sem necessidade de migrar para Azure.

---

**Q4.** O JIT VM Access está habilitado em 50 VMs. Um administrador precisa de acesso RDP urgente a uma VM às 23h para atender um incidente. Como ele deve proceder?

a) Desabilitar o JIT temporariamente, conectar, e reabilitar  
b) Solicitar acesso JIT via portal Defender for Cloud ou Azure Portal, especificando o IP de origem e o tempo necessário (ex.: 2 horas); o JIT abre automaticamente a porta no NSG para aquele IP pelo tempo solicitado  
c) Modificar manualmente o NSG para permitir o IP do administrador  
d) Usar o Azure Bastion em vez de JIT — o JIT não funciona fora do horário comercial  

**Resposta: B** — O JIT funciona 24/7 — não tem restrição de horário. O processo: (1) Acessar o portal Azure ou Defender for Cloud; (2) Selecionar a VM; (3) Clicar em "Request access"; (4) Especificar o IP de origem (ou "My IP" para detectar automaticamente), a porta, e o tempo; (5) O JIT abre a regra NSG em segundos. Para emergências, o processo leva menos de 1 minuto. A opção C (modificar NSG manualmente) é contrária ao objetivo do JIT e pode ser auditada como violação de política de segurança.

---

**Q5.** O Defender for SQL detectou "Unusual data export" em um banco de dados de clientes do Banco Meridian. Uma query SELECT * FROM customers WHERE country='BR' retornou 850.000 registros para um usuário que normalmente acessa menos de 100 registros/sessão. Qual é a ação imediata recomendada?

a) Ignorar — SELECT não modifica dados, portanto não é uma ameaça  
b) Investigar a sessão: identificar o usuário, o IP de origem, e verificar no Entra ID e no Sentinel se o login é legítimo; se suspeito, revogar a sessão via Logic App e aplicar bloqueio de query  
c) Deletar imediatamente o usuário que fez a query  
d) Desabilitar o Defender for SQL — está gerando falso positivo  

**Resposta: B** — "Unusual data export" é um sinal de exfiltração em andamento (T1530 — Data from Cloud Storage). A ação imediata: (1) verificar o Entra ID para confirmar se o login é legítimo (IP esperado, horário normal, MFA usado); (2) verificar no Sentinel se há outros alertas correlacionados (impossible travel, suspicious sign-in); (3) se suspeito, revogar a sessão de banco de dados e a sessão Entra ID; (4) preservar logs para investigação forense. Deletar o usuário (C) antes de investigar pode destruir evidências. Ignorar (A) é inaceitável — 850.000 registros de clientes representam LGPD e BACEN violations potenciais.
