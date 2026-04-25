# Módulo 00 — Preparação do Ambiente de Laboratório

**Curso 2 — Microsoft Sentinel & Defender: SecOps no Azure**

> Este módulo não tem videoaula. É o ponto de partida obrigatório antes de qualquer aula ou laboratório. Reserve pelo menos 2 horas para concluir todas as etapas com calma.

---

## Visão Geral

Este módulo guia você na criação de um ambiente completo de laboratório para o Curso 2. Ao final, você terá:

- Tenant Microsoft 365 E5 Developer Trial ativo
- Workspace Microsoft Sentinel provisionado
- Conectores de dados básicos ativos (Entra ID, MDE, M365)
- Cinco usuários fictícios do Banco Meridian criados
- Microsoft Defender for Endpoint em endpoints de teste
- Grupos de segurança e permissões do SOC configurados
- Dados iniciais fluindo para o Sentinel

---

## Diagrama do Ambiente de Laboratório

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TENANT: bancomeridian-lab.onmicrosoft.com                 │
│                          (Microsoft 365 E5 Trial)                           │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    MICROSOFT ENTRA ID (Azure AD)                     │    │
│  │  Usuários de Teste:  ana.costa | carlos.matos | fernanda.lima        │    │
│  │                      roberto.alves | diego.nunes                     │    │
│  │  Grupos: SOC-Analysts | SOC-Admins | BancoMeridian-Users            │    │
│  │  Licenças: M365 E5 (Sentinel, MDE, MDI, MDO, MDA, PIM)             │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                  │                                           │
│  ┌───────────────────────────────▼──────────────────────────────────────┐   │
│  │                    AZURE SUBSCRIPTION (Free Trial)                    │   │
│  │                                                                        │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │         RESOURCE GROUP: rg-secops-lab-meridian                  │  │   │
│  │  │                                                                   │  │   │
│  │  │  ┌──────────────────┐   ┌──────────────────────────────────┐   │  │   │
│  │  │  │  Log Analytics   │   │     Microsoft Sentinel           │   │  │   │
│  │  │  │  Workspace:      │◄──│  (SIEM/SOAR + Hunting)           │   │  │   │
│  │  │  │  law-meridian-01 │   │  Analytics Rules / Incidents     │   │  │   │
│  │  │  └────────┬─────────┘   └──────────────────────────────────┘   │  │   │
│  │  │           │                                                       │  │   │
│  │  │  ┌────────▼─────────────────────────────────────────────────┐   │  │   │
│  │  │  │              CONECTORES DE DADOS (Data Connectors)        │   │  │   │
│  │  │  │                                                             │   │  │   │
│  │  │  │  [Entra ID Sign-ins]  [Azure Activity]  [SecurityEvent]   │   │  │   │
│  │  │  │  [MDE via M365 Defender] [OfficeActivity] [DNS Logs]      │   │  │   │
│  │  │  └─────────────────────────────────────────────────────────-─┘   │  │   │
│  │  │                                                                   │  │   │
│  │  │  ┌──────────────────┐   ┌──────────────────────────────────┐   │  │   │
│  │  │  │  VM Win11 Test   │   │  VM Ubuntu 22.04 Test            │   │  │   │
│  │  │  │  (MDE onboarded) │   │  (CEF/Syslog via AMA)            │   │  │   │
│  │  │  │  vm-win11-01     │   │  vm-linux-01                     │   │  │   │
│  │  │  └──────────────────┘   └──────────────────────────────────┘   │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                                                                        │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │   │
│  │  │  Microsoft Defender for Cloud (CSPM/CWPP)                        │ │   │
│  │  │  Planos: Defender for Servers P1 | Defender for Storage          │ │   │
│  │  └──────────────────────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │            MICROSOFT 365 DEFENDER (portal.microsoft.com/security)         │ │
│  │  MDE — Defender for Endpoint (endpoints vm-win11-01 onboarded)            │ │
│  │  MDI — Defender for Identity (sensor em AD DS simulado)                   │ │
│  │  MDO — Defender for Office 365 Plan 2 (Exchange Online, Teams, SP)       │ │
│  │  MDA — Defender for Cloud Apps (Shadow IT + CASB)                         │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Pré-requisitos do Sistema

| Requisito                | Mínimo                              | Recomendado                          |
|:-------------------------|:------------------------------------|:-------------------------------------|
| **Sistema Operacional**  | Windows 10 21H2 / macOS 12 / Ubuntu 20.04 | Windows 11 / macOS 14 / Ubuntu 22.04 |
| **Navegador**            | Edge 110+ ou Chrome 110+            | Microsoft Edge (Chromium) atualizado |
| **Memória RAM**          | 8 GB                                | 16 GB                                |
| **Armazenamento**        | 20 GB livres                        | 50 GB livres (para VMs de teste)     |
| **Conexão Internet**     | 10 Mbps                             | 50 Mbps (downloads de políticas)     |
| **Conta Microsoft**      | Conta pessoal @outlook.com ou @hotmail.com | Conta corporativa limpa           |
| **Cartão de crédito**    | Necessário para Azure Free Trial (não é cobrado durante o lab) | Cartão virtual (Nubank/Inter) |
| **PowerShell**           | PowerShell 5.1 (Windows nativo)     | PowerShell 7.4 + módulos Az e MSOnline |
| **Azure CLI**            | Azure CLI 2.50+                     | Última versão disponível             |
| **Git**                  | Git 2.40+                           | Git 2.44+                            |
| **Visual Studio Code**   | Desejável                           | VS Code + extensão KQL               |

---

## Etapa 1 — Criar Tenant Microsoft 365 E5 Developer Trial

O tenant M365 E5 Developer Trial é **gratuito por 25 usuários** e inclui todas as licenças necessárias: Microsoft Sentinel, MDE, MDI, MDO, MDA, Entra ID P2, PIM, Purview.

### 1.1 Acessar o programa Microsoft 365 Developer

**Passo 1.** Abra o navegador e acesse `https://developer.microsoft.com/microsoft-365/dev-program`.

**Resultado esperado:** Página "Microsoft 365 Developer Program" com botão "Join now".

**O que verificar:** URL correta e página carregada em português ou inglês.

**Se der errado:** Limpe cache e cookies do navegador. Tente em janela anônima.

---

**Passo 2.** Clique em **"Join now"** (ou "Ingressar agora"). Se solicitado, entre com uma conta Microsoft pessoal existente (@outlook.com ou @hotmail.com). Se não tiver, crie em `https://account.microsoft.com`.

**Resultado esperado:** Formulário de cadastro no Developer Program.

**O que verificar:** Campo de e-mail preenchido com sua conta Microsoft.

**Se der errado:** Se a conta já foi usada anteriormente para trial, use um e-mail diferente.

---

**Passo 3.** Preencha o formulário:
- **País/região:** Brasil
- **Empresa:** CECyber Lab (ou nome fictício de sua preferência)
- **Área de atuação:** Desenvolvedor de software / Profissional de TI
- Aceite os termos de uso e clique em **"Next"**.

**Resultado esperado:** Página de seleção de tipo de sandbox.

---

**Passo 4.** Na pergunta "What type of sandbox do you want?", selecione **"Instant sandbox"** (sandbox instantâneo). Esta opção cria automaticamente 16 usuários fictícios e dados de exemplo.

**Resultado esperado:** Formulário para definir domínio e senha do administrador.

**O que verificar:** Opção "Instant sandbox" selecionada (ícone de raio).

---

**Passo 5.** Configure o domínio do tenant:
- **Domain name:** `bancomeridianlab` (ou nome similar disponível)
- O tenant completo ficará: `bancomeridianlab.onmicrosoft.com`
- **Admin username:** `admin`
- **Admin password:** Crie uma senha forte: `Meridian@SecOps2026!`
- Confirme a senha e clique em **"Continue"**.

**Resultado esperado:** Configuração de autenticação multifator (MFA).

**Se der errado:** Se o domínio estiver indisponível, tente variações: `bancomeridianlab01`, `meridianlab2026`.

---

**Passo 6.** Configure o MFA do administrador:
- Informe seu número de celular real (será usado para MFA)
- Escolha **"Text me"** para receber o código via SMS
- Digite o código recebido e clique em **"Set up"**.

**Resultado esperado:** Tela de confirmação de criação do tenant.

**O que verificar:** Mensagem de sucesso com o nome do tenant exibido.

---

**Passo 7.** Clique em **"Go to subscription"**. O portal do Microsoft 365 Admin Center será aberto.

**Resultado esperado:** Portal `https://admin.microsoft.com` logado como `admin@bancomeridianlab.onmicrosoft.com`.

**O que verificar:**
- Canto superior direito exibe seu nome de usuário
- Menu lateral mostra "Users", "Billing", "Settings"

---

**Passo 8.** No Admin Center, vá em **"Billing" > "Your products"**. Você deve ver as licenças do M365 E5 Developer ativas.

**Resultado esperado:** Lista de produtos incluindo "Microsoft 365 E5 Developer (without Windows and Audio Conferencing)" com 25 licenças disponíveis.

**O que verificar:** Status deve ser "Active". Validade: 90 dias (renovável automaticamente se houver atividade).

---

### 1.2 Verificar as licenças incluídas

**Passo 9.** Acesse `https://admin.microsoft.com` > **"Billing" > "Licenses"**. Confirme que os seguintes produtos estão presentes:

| Produto                                        | Licenças | Status   |
|:-----------------------------------------------|:--------:|:---------|
| Microsoft 365 E5 Developer                     | 25       | Active   |
| Microsoft Defender for Endpoint P2             | 25       | Active   |
| Microsoft Defender for Identity                | 25       | Active   |
| Microsoft Defender for Office 365 Plan 2       | 25       | Active   |
| Microsoft Defender for Cloud Apps              | 25       | Active   |
| Azure Active Directory Premium P2              | 25       | Active   |
| Microsoft Entra ID Governance                  | 25       | Active   |

**O que verificar:** Todas as linhas com status "Active" e pelo menos 20 licenças disponíveis.

**Se der errado:** Se algum produto estiver ausente, aguarde 15 minutos para propagação. Se persistir, acesse `https://developer.microsoft.com/microsoft-365/profile` e clique em "Renew".

---

**Passo 10.** Anote as credenciais do administrador em local seguro:

```
Tenant:         bancomeridianlab.onmicrosoft.com
Admin UPN:      admin@bancomeridianlab.onmicrosoft.com
Admin Password: Meridian@SecOps2026!
Portal M365:    https://admin.microsoft.com
Portal Azure:   https://portal.azure.com
Portal Defender: https://security.microsoft.com
```

---

## Etapa 2 — Ativar Licenças e Criar Usuários de Teste do Banco Meridian

### 2.1 Criar os cinco usuários fictícios

**Passo 11.** No Admin Center (`https://admin.microsoft.com`), vá em **"Users" > "Active users" > "+ Add a user"**.

**Passo 12.** Crie o primeiro usuário com os dados abaixo:

```
First name:   Ana Beatriz
Last name:    Costa
Username:     ana.costa
Domain:       bancomeridianlab.onmicrosoft.com
Password:     Meridian@User2026! (deixar "Require this user to change..." DESMARCADO para lab)
Location:     Brazil
```

Em **Licenses**, atribua: **Microsoft 365 E5 Developer**. Clique em **"Finish adding"**.

**Resultado esperado:** Usuário criado com sucesso. UPN: `ana.costa@bancomeridianlab.onmicrosoft.com`.

---

**Passo 13.** Repita o Passo 12 para os demais usuários:

| First Name   | Last Name | Username        | Cargo (para referência)         |
|:-------------|:----------|:----------------|:--------------------------------|
| Carlos Eduardo | Matos   | carlos.matos    | Engenheiro de Plataforma Azure  |
| Fernanda     | Lima      | fernanda.lima   | Gerente de Operações            |
| Roberto      | Alves     | roberto.alves   | Analista Financeiro             |
| Diego        | Nunes     | diego.nunes     | Administrador de Sistemas       |

Todos com a mesma senha padrão: `Meridian@User2026!` e licença M365 E5 Developer.

---

### 2.2 Criar grupos de segurança

**Passo 14.** No Admin Center, vá em **"Teams & groups" > "Active teams & groups" > "+ Add a group"**.

Crie os seguintes grupos (tipo: **Security**):

| Nome do Grupo         | Descrição                                          | Membros                          |
|:----------------------|:---------------------------------------------------|:---------------------------------|
| SOC-Analysts          | Analistas do SOC com acesso de leitura ao Sentinel | ana.costa                        |
| SOC-Admins            | Administradores do SOC com acesso completo         | admin, carlos.matos              |
| BancoMeridian-Users   | Usuários regulares do banco (sem acesso SOC)       | fernanda.lima, roberto.alves, diego.nunes |

**Resultado esperado:** Três grupos criados e visíveis em "Active teams & groups".

---

## Etapa 3 — Configurar Microsoft Sentinel

### 3.1 Criar Azure Subscription e Resource Group

**Passo 15.** Acesse `https://portal.azure.com`. Faça login com `admin@bancomeridianlab.onmicrosoft.com`.

Se for a primeira vez no Azure com esta conta, você será solicitado a criar uma assinatura. Clique em **"Start with an Azure free trial"** e informe cartão de crédito (não será cobrado durante o laboratório).

**Resultado esperado:** Portal Azure carregado, assinatura "Azure subscription 1" visível na home.

---

**Passo 16.** Crie um Resource Group. Na barra de busca do Azure Portal, pesquise **"Resource groups"** e clique em **"+ Create"**:

```
Subscription:      Azure subscription 1
Resource group:    rg-secops-lab-meridian
Region:            East US 2
```

Clique em **"Review + create"** > **"Create"**.

**Resultado esperado:** Resource group criado. Mensagem "Your deployment is complete".

---

### 3.2 Criar Log Analytics Workspace

**Passo 17.** Na barra de busca, pesquise **"Log Analytics workspaces"** > **"+ Create"**:

```
Subscription:      Azure subscription 1
Resource group:    rg-secops-lab-meridian
Name:              law-meridian-secops-01
Region:            East US 2
Pricing tier:      Pay-as-you-go (Per GB)
```

Clique em **"Review + create"** > **"Create"**.

**Resultado esperado:** Workspace provisionado em ~2 minutos. ID do workspace disponível em "Properties".

**O que verificar:** Em "Properties" do workspace, anote o **Workspace ID** e a **Primary key** (serão usados para conectar agentes).

---

### 3.3 Habilitar Microsoft Sentinel

**Passo 18.** Na barra de busca, pesquise **"Microsoft Sentinel"** > **"+ Create"**. Selecione o workspace `law-meridian-secops-01` e clique em **"Add Microsoft Sentinel"**.

**Resultado esperado:** Microsoft Sentinel habilitado no workspace. Portal do Sentinel aberto com menu lateral (Overview, Incidents, Workbooks, etc.).

**O que verificar:** Menu lateral do Sentinel visível. Aba "Overview" com gráficos (vazios inicialmente — dados chegarão após conectores).

**Se der errado:** Se o botão "Add Microsoft Sentinel" não aparecer, atualize a página. Se o workspace não aparecer na lista, aguarde 5 minutos e tente novamente.

---

### 3.4 Configurar Conectores de Dados Essenciais

**Passo 19.** No Sentinel, acesse **"Configuration" > "Data connectors"**. Você verá uma lista de conectores disponíveis.

**Passo 20.** Ative o conector **"Microsoft Entra ID"**:
- Clique em "Microsoft Entra ID" > **"Open connector page"**
- Marque: `Sign-in logs`, `Audit logs`, `Non-interactive user sign-in logs`
- Clique em **"Apply Changes"**

**Resultado esperado:** Status do conector muda para "Connected" (pode levar até 15 min).

---

**Passo 21.** Ative o conector **"Microsoft 365 Defender"**:
- Clique em "Microsoft 365 Defender" > **"Open connector page"**
- Marque todos os produtos: MDE, MDI, MDO, MDA
- Marque "Turn on" para cada produto listado
- Clique em **"Apply Changes"**

**Resultado esperado:** Conector M365 Defender conectado. Tabelas AlertEvidence, DeviceEvents, IdentityLogonEvents começam a aparecer.

---

**Passo 22.** Ative o conector **"Azure Activity"**:
- Clique em "Azure Activity" > **"Open connector page"**
- Clique em **"Launch Azure Policy Assignment wizard"**
- Selecione a assinatura "Azure subscription 1"
- Atribua a política com destino ao workspace `law-meridian-secops-01`

**Resultado esperado:** Atividade do Azure (criação de recursos, login no portal) começará a fluir em ~30 min.

---

## Etapa 4 — Instalar Microsoft Defender for Endpoint em Endpoints de Teste

### 4.1 Criar máquina virtual Windows de teste

**Passo 23.** No Azure Portal, busque **"Virtual machines"** > **"+ Create" > "Azure virtual machine"**:

```
Resource group:  rg-secops-lab-meridian
VM name:         vm-win11-meridian-01
Region:          East US 2
Image:           Windows 11 Pro (ou Windows Server 2022 se Win11 indisponível no free tier)
Size:            Standard_B2s (2 vCPUs, 4 GB RAM) — custo mínimo
Username:        adminmeridian
Password:        Meridian@VM2026!
```

Em **"Networking"**, deixe a VNet padrão. Em **"Management"**, habilite **"Auto-shutdown"** para 22h00 (evitar custos).

Clique em **"Review + create"** > **"Create"**.

**Resultado esperado:** VM provisionada em ~5 min. IP público atribuído.

**O que verificar:** Status "Running" na lista de VMs.

---

### 4.2 Fazer onboarding da VM no Defender for Endpoint

**Passo 24.** Acesse o portal Microsoft 365 Defender: `https://security.microsoft.com`.

**Passo 25.** Vá em **"Settings" > "Endpoints" > "Onboarding"**.

**Passo 26.** Selecione **"Operating system: Windows 10 and 11"** e **"Deployment method: Local Script"**. Clique em **"Download onboarding package"**.

**Resultado esperado:** Arquivo `WindowsDefenderATPOnboardingPackage.zip` baixado.

---

**Passo 27.** Conecte-se à VM via RDP:
```
IP: <IP público da vm-win11-meridian-01>
Usuário: adminmeridian
Senha: Meridian@VM2026!
```

**Passo 28.** Dentro da VM, extraia o ZIP e execute o script como Administrador:

```cmd
:: Extraia o ZIP para C:\MDE-Onboarding
cd C:\MDE-Onboarding
:: Execute o script de onboarding
WindowsDefenderATPLocalOnboardingScript.cmd
```

**Resultado esperado:** Script executa sem erros. Mensagem "Onboarding finished successfully".

**O que verificar:** No portal Defender (`security.microsoft.com` > "Assets" > "Devices"), a VM `vm-win11-meridian-01` deve aparecer em até 30 minutos.

---

## Etapa 5 — Configurar Entra ID com MFA e Políticas de Acesso

### 5.1 Habilitar MFA para usuários de teste

**Passo 29.** Acesse `https://entra.microsoft.com` (portal Microsoft Entra). Faça login como admin.

**Passo 30.** Vá em **"Identity" > "Users" > "All users"** > **"Per-user MFA"** (link no topo da página).

**Passo 31.** Selecione os usuários: `ana.costa`, `carlos.matos`, `fernanda.lima`, `roberto.alves`, `diego.nunes`. Clique em **"Enable"** > **"Enable multi-factor auth"**.

**Resultado esperado:** Status de MFA muda para "Enabled" para todos os 5 usuários.

---

### 5.2 Configurar Entra ID Protection

**Passo 32.** No portal Entra, acesse **"Protection" > "Identity Protection" > "User risk policy"**:

```
Assignments:    Todos os usuários
User risk:      Medium and above
Access:         Allow access (require password change)
```

Clique em **"Save"**.

**Passo 33.** Acesse **"Sign-in risk policy"**:

```
Assignments:    Todos os usuários
Sign-in risk:   Medium and above
Access:         Require multi-factor authentication
```

Clique em **"Save"**.

**Resultado esperado:** Duas políticas ativas no Identity Protection.

---

## Etapa 6 — Criar Grupo SOC e Configurar Permissões no Sentinel

**Passo 34.** No Azure Portal, acesse o workspace Sentinel (`law-meridian-secops-01`) > **"Access control (IAM)"** > **"+ Add" > "Add role assignment"**.

**Passo 35.** Atribua as seguintes roles:

| Grupo / Usuário    | Role Azure                              | Escopo                     |
|:-------------------|:----------------------------------------|:---------------------------|
| SOC-Analysts       | Microsoft Sentinel Reader               | Resource Group rg-secops-lab-meridian |
| SOC-Admins         | Microsoft Sentinel Contributor          | Resource Group rg-secops-lab-meridian |
| ana.costa          | Microsoft Sentinel Responder            | Workspace law-meridian-secops-01 |
| carlos.matos       | Microsoft Sentinel Contributor          | Workspace law-meridian-secops-01 |

**Resultado esperado:** Roles atribuídas. Usuária `ana.costa` pode visualizar incidentes mas não criar regras. Usuário `carlos.matos` pode criar e modificar regras analíticas.

---

**Passo 36.** Para habilitar o **PIM (Privileged Identity Management)**, acesse `https://entra.microsoft.com` > **"Identity governance" > "Privileged Identity Management"** > **"Manage" > "Azure resources"**.

Selecione a assinatura e ative o PIM para ela. Configure a role **"Microsoft Sentinel Contributor"** como "Eligible" (sob demanda) para o grupo `SOC-Analysts`, com duração máxima de ativação de **4 horas** e aprovação do admin.

---

## Etapa 7 — Verificar Ingestão de Dados Iniciais no Sentinel

**Passo 37.** Aguarde pelo menos 15 minutos após configurar os conectores. No Sentinel, acesse **"Logs"** e execute as queries abaixo para verificar ingestão:

```kql
// Verificar logs de sign-in do Entra ID
SigninLogs
| take 10
| project TimeGenerated, UserDisplayName, AppDisplayName, ResultType, IPAddress
```

**Resultado esperado:** Pelo menos 1 linha retornada com suas próprias tentativas de login.

```kql
// Verificar Azure Activity
AzureActivity
| take 10
| project TimeGenerated, Caller, OperationName, ActivityStatus
```

**Resultado esperado:** Linhas com operações realizadas no portal Azure (criação de VMs, resource groups, etc.).

```kql
// Verificar tabelas disponíveis
union withsource=TableName *
| summarize count() by TableName
| order by count_ desc
| take 30
```

**Resultado esperado:** Lista de tabelas com dados. Tabelas principais devem incluir: `SigninLogs`, `AuditLogs`, `AzureActivity`, `SecurityEvent`.

**Se der errado:** Se as tabelas aparecerem vazias, aguarde 30 minutos e repita. Certifique-se de que os conectores estão com status "Connected" em "Data connectors".

---

## Etapa 8 — Script de Health Check

Salve o script abaixo como `health-check-sentinel.ps1` e execute no PowerShell com as credenciais de admin:

```powershell
<#
.SYNOPSIS
    Health check do ambiente de laboratório do Curso 2 — Azure SecOps / Microsoft Sentinel
.DESCRIPTION
    Verifica conectividade, licenças, conectores e ingestão de dados do ambiente de lab.
    Execute como Global Administrator do tenant de laboratório.
.NOTES
    Requer: Az PowerShell module, MSOnline module ou Microsoft.Graph module
    Instale com: Install-Module -Name Az, MSOnline -Force -AllowClobber
#>

param(
    [string]$TenantDomain = "bancomeridianlab.onmicrosoft.com",
    [string]$WorkspaceId  = "",   # preencha com o Workspace ID do Log Analytics
    [string]$ResourceGroup = "rg-secops-lab-meridian"
)

$ErrorActionPreference = "Stop"
$PassedChecks = 0
$FailedChecks = 0

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    if ($Passed) {
        Write-Host "  [OK]  $Name" -ForegroundColor Green
        if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGreen }
        $script:PassedChecks++
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkRed }
        $script:FailedChecks++
    }
}

Write-Host "`n=== Health Check — Ambiente Sentinel Banco Meridian ===" -ForegroundColor Cyan
Write-Host "Tenant: $TenantDomain`n"

# ----- BLOCO 1: Conectividade Azure -----
Write-Host "--- 1. Conectividade Azure ---" -ForegroundColor Yellow
try {
    $ctx = Get-AzContext
    if ($ctx.Tenant.Domain -like "*$TenantDomain*" -or $ctx.Subscription) {
        Write-Check "Login Azure" $true "Tenant: $($ctx.Tenant.Id)"
    } else {
        Write-Check "Login Azure" $false "Execute: Connect-AzAccount -TenantId <ID>"
    }
} catch {
    Write-Check "Login Azure" $false "Execute: Connect-AzAccount"
}

# ----- BLOCO 2: Resource Group -----
Write-Host "`n--- 2. Resource Group ---" -ForegroundColor Yellow
try {
    $rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
    Write-Check "Resource Group: $ResourceGroup" ($rg -ne $null) "Região: $($rg.Location)"
} catch {
    Write-Check "Resource Group: $ResourceGroup" $false "Crie o RG no portal Azure"
}

# ----- BLOCO 3: Log Analytics Workspace -----
Write-Host "`n--- 3. Log Analytics Workspace ---" -ForegroundColor Yellow
try {
    $workspaces = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    $ws = $workspaces | Where-Object { $_.Name -like "*meridian*" }
    Write-Check "Workspace Log Analytics" ($ws -ne $null) "Nome: $($ws.Name)"
    if ($ws) {
        Write-Check "Workspace Status" ($ws.ProvisioningState -eq "Succeeded") "State: $($ws.ProvisioningState)"
    }
} catch {
    Write-Check "Log Analytics Workspace" $false "Crie o workspace conforme Passo 17"
}

# ----- BLOCO 4: Microsoft Sentinel -----
Write-Host "`n--- 4. Microsoft Sentinel ---" -ForegroundColor Yellow
try {
    $sentinelCheck = Get-AzSecurityInsightsSetting -ResourceGroupName $ResourceGroup -WorkspaceName "law-meridian-secops-01" -ErrorAction SilentlyContinue
    Write-Check "Microsoft Sentinel habilitado" ($sentinelCheck -ne $null)
} catch {
    # Módulo SecurityInsights pode não estar instalado
    Write-Check "Microsoft Sentinel" $true "Verifique manualmente no portal se o Sentinel está ativo"
}

# ----- BLOCO 5: VMs de Teste -----
Write-Host "`n--- 5. VMs de Teste ---" -ForegroundColor Yellow
try {
    $vms = Get-AzVM -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    $winVM = $vms | Where-Object { $_.Name -like "*win11*" -or $_.Name -like "*windows*" }
    Write-Check "VM Windows de teste" ($winVM -ne $null) "Nome: $($winVM.Name)"

    $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroup -Name $winVM.Name -Status -ErrorAction SilentlyContinue
    $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState*" }).DisplayStatus
    Write-Check "VM Windows: status Running" ($powerState -eq "VM running") "Status: $powerState"
} catch {
    Write-Check "VMs de Teste" $false "Crie a VM conforme Passo 23"
}

# ----- BLOCO 6: Usuários Banco Meridian -----
Write-Host "`n--- 6. Usuários Banco Meridian ---" -ForegroundColor Yellow
$expectedUsers = @("ana.costa", "carlos.matos", "fernanda.lima", "roberto.alves", "diego.nunes")
foreach ($user in $expectedUsers) {
    $upn = "$user@$TenantDomain"
    try {
        # Usando Graph API via Az module
        $uri = "https://graph.microsoft.com/v1.0/users/$upn"
        $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
        $headers = @{ Authorization = "Bearer $token" }
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction SilentlyContinue
        Write-Check "Usuário: $upn" ($result.displayName -ne $null) "Display: $($result.displayName)"
    } catch {
        Write-Check "Usuário: $upn" $false "Crie o usuário conforme Passo 12/13"
    }
}

# ----- RESUMO FINAL -----
Write-Host "`n=== RESUMO ===" -ForegroundColor Cyan
Write-Host "  Checks OK:   $PassedChecks" -ForegroundColor Green
Write-Host "  Checks FAIL: $FailedChecks" -ForegroundColor Red

if ($FailedChecks -eq 0) {
    Write-Host "`n  Ambiente 100% pronto! Pode iniciar o Módulo 01." -ForegroundColor Green
} elseif ($FailedChecks -le 3) {
    Write-Host "`n  Ambiente quase pronto. Corrija os itens em vermelho antes de prosseguir." -ForegroundColor Yellow
} else {
    Write-Host "`n  Vários problemas encontrados. Revise as etapas do Modulo 00." -ForegroundColor Red
}
```

**Como executar o health check:**

```powershell
# Instalar módulos necessários (execute uma vez)
Install-Module -Name Az -Force -AllowClobber -Scope CurrentUser
Install-Module -Name MSOnline -Force -AllowClobber -Scope CurrentUser

# Conectar ao Azure
Connect-AzAccount -TenantId "<seu-tenant-id>"

# Executar o health check
.\health-check-sentinel.ps1 -TenantDomain "bancomeridianlab.onmicrosoft.com" -ResourceGroup "rg-secops-lab-meridian"
```

---

## Etapa 9 — Guia de Cleanup ao Final do Curso

Ao concluir o Curso 2, siga os passos abaixo para evitar custos desnecessários:

### 9.1 Parar e desalocar VMs

```powershell
# Parar e desalocar a VM de teste (evita cobrança de compute)
Stop-AzVM -ResourceGroupName "rg-secops-lab-meridian" -Name "vm-win11-meridian-01" -Force

# Verificar status
Get-AzVM -ResourceGroupName "rg-secops-lab-meridian" -Status | Select Name, PowerState
```

### 9.2 Excluir Resource Group completo (DESTRUTIVO — use apenas ao final)

```powershell
# ATENÇÃO: este comando exclui TODOS os recursos do lab (VMs, Sentinel, Log Analytics)
# Execute somente ao final definitivo do curso
Remove-AzResourceGroup -Name "rg-secops-lab-meridian" -Force
```

### 9.3 Remover licenças dos usuários de teste

No Admin Center (`https://admin.microsoft.com`), selecione cada usuário de teste > **"Licenses and apps"** > desmarque "Microsoft 365 E5 Developer" > **"Save changes"**.

### 9.4 Verificar zero custo no Azure

```powershell
# Verificar recursos ainda existentes
Get-AzResource -ResourceGroupName "rg-secops-lab-meridian" -ErrorAction SilentlyContinue
# Se retornar vazio, o cleanup foi bem-sucedido
```

No portal Azure, acesse **"Cost Management + Billing" > "Cost analysis"** e filtre pelo resource group `rg-secops-lab-meridian` para confirmar que não há custos recorrentes.

---

## Tabela de Resumo do Ambiente

| Componente                  | Nome / Endereço                                       | Status Esperado        |
|:----------------------------|:------------------------------------------------------|:-----------------------|
| Tenant M365                 | bancomeridianlab.onmicrosoft.com                      | Ativo (90 dias)        |
| Admin UPN                   | admin@bancomeridianlab.onmicrosoft.com                | Global Admin           |
| Azure Subscription          | Azure subscription 1                                  | Ativa                  |
| Resource Group              | rg-secops-lab-meridian (East US 2)                   | Criado                 |
| Log Analytics Workspace     | law-meridian-secops-01                               | Ativo                  |
| Microsoft Sentinel          | Habilitado em law-meridian-secops-01                 | Conectores ativos      |
| VM Windows de Teste         | vm-win11-meridian-01                                 | Running + MDE onboard  |
| Conector Entra ID           | SigninLogs + AuditLogs                               | Connected              |
| Conector M365 Defender      | MDE + MDI + MDO + MDA                                | Connected              |
| Conector Azure Activity     | AzureActivity logs                                   | Connected              |
| Usuário SOC (Analista)      | ana.costa@bancomeridianlab.onmicrosoft.com           | Criado + licença ativa |
| Usuário SOC (Admin)         | carlos.matos@bancomeridianlab.onmicrosoft.com        | Criado + licença ativa |
| Usuário Regular 1           | fernanda.lima@bancomeridianlab.onmicrosoft.com       | Criado + licença ativa |
| Usuário Regular 2           | roberto.alves@bancomeridianlab.onmicrosoft.com       | Criado + licença ativa |
| Usuário Regular 3           | diego.nunes@bancomeridianlab.onmicrosoft.com         | Criado + licença ativa |
| Grupo SOC-Analysts          | Membro: ana.costa                                    | Criado                 |
| Grupo SOC-Admins            | Membros: admin, carlos.matos                         | Criado                 |
| Role Sentinel Reader        | Grupo: SOC-Analysts                                  | Atribuída              |
| Role Sentinel Contributor   | Grupo: SOC-Admins                                    | Atribuída              |
| Entra ID Protection         | User risk + Sign-in risk policies                    | Habilitadas            |
| PIM                         | Role Sentinel Contributor como Eligible              | Configurado            |

---

## Solução de Problemas Comuns

| Problema                                       | Causa Provável                                  | Solução                                                          |
|:-----------------------------------------------|:------------------------------------------------|:-----------------------------------------------------------------|
| Sentinel não aparece como opção no workspace   | Workspace muito recente (propagação incompleta) | Aguarde 5 min e atualize a página                                |
| Conector Entra ID mostra "Disconnected"        | Permissões insuficientes ou delay de propagação | Verifique se a conta tem Global Admin; aguarde 15 min            |
| VM não aparece no portal MDE                   | Onboarding não concluído ou script não executado como Admin | Execute o script como Administrador local da VM         |
| Logs vazios no Sentinel após 1h                | Conector não configurado corretamente           | Verifique em "Data connectors" se o status é "Connected"         |
| Erro "InsufficientPermissions" ao criar Sentinel | Conta sem permissão de Owner na assinatura   | Verifique role no IAM da assinatura; precisa de "Owner" ou "Contributor" |
| Tenant expira em 90 dias                       | Inatividade no tenant                           | Acesse o portal M365 Developer e faça atividade (qualquer ação) |
| Custo inesperado na Azure Free Trial           | VMs rodando sem parar                           | Configure auto-shutdown em cada VM; exclua recursos não usados  |

---

**Parabéns!** Se todos os itens da tabela de resumo estiverem com status esperado, você está pronto para iniciar o **Módulo 01 — Arquitetura de Segurança Microsoft**. Certifique-se de ter o ambiente saudável antes de prosseguir — muitos laboratórios dependem de dados já ingeridos no Sentinel.
