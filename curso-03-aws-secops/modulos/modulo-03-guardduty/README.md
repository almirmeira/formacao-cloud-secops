# Módulo 03 — Amazon GuardDuty

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 2 (Detection and Response)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Explicar a arquitetura do GuardDuty e suas fontes de dados
2. Interpretar finding types com exemplos reais e determinar severidade
3. Implementar GuardDuty organization-wide com delegated administrator
4. Criar regras de supressão para reduzir falsos positivos
5. Configurar Malware Protection para EC2 e S3
6. Integrar GuardDuty com Security Hub e EventBridge para automação

---

## 1. Amazon GuardDuty — Arquitetura

O GuardDuty é um serviço de detecção de ameaças gerenciado que analisa continuamente logs de múltiplas fontes usando machine learning, anomaly detection e threat intelligence.

### Fontes de Dados por Tipo de Finding

| Fonte de Dados | O que Analisa | Findings Gerados |
|---|---|---|
| **CloudTrail Management Events** | API calls de controle (IAM, EC2, S3...) | IAM, EC2, Policy findings |
| **CloudTrail S3 Data Events** | GetObject, PutObject, DeleteObject em S3 | S3 findings (exfiltração, acesso suspeito) |
| **VPC Flow Logs** | Tráfego de rede de ENIs | Network findings (port probe, C2, exfiltração) |
| **DNS Logs** | Queries DNS da VPC | DNS findings (DGA, tunneling, malicious domain) |
| **EKS Audit Logs** | Chamadas à API do Kubernetes | EKS findings (API calls suspeitas, pods maliciosos) |
| **EKS Runtime Monitoring** | Atividade em runtime de containers EKS | Runtime findings (cryptomining, escape de container) |
| **Lambda Network Activity** | Conexões de rede de funções Lambda | Lambda findings (comunicação com IPs maliciosos) |
| **RDS Login Activity** | Tentativas de login no RDS Aurora/MySQL/PostgreSQL | RDS findings (brute force, credential stuffing) |
| **Malware Protection (EC2)** | Arquivos em volumes EBS (snapshot analysis) | Malware findings (trojan, ransomware, cryptominer) |
| **Malware Protection (S3)** | Arquivos carregados no S3 | S3/MaliciousFile findings |
| **Runtime Monitoring (EC2/ECS/EKS)** | Chamadas de sistema em runtime | Runtime findings (evasão, escalada de privilégios) |

### Como o GuardDuty Funciona

**O que este diagrama representa:** O GuardDuty ingere automaticamente as fontes de log existentes na conta AWS — sem necessidade de configurar pipelines de coleta — e aplica três camadas de análise: modelos de machine learning que estabelecem o comportamento basal da conta, detecção de anomalias estatísticas e correlação com feeds proprietários de threat intelligence da AWS. Os findings resultantes são publicados em três destinos simultaneamente, habilitando tanto a visualização humana quanto a automação de resposta.

**Por que isso importa para o Banco Meridian:** Com 4 contas AWS no AWS Organizations (Management, Audit, Production, Log Archive), o Banco Meridian precisa garantir cobertura de detecção em todas elas sem multiplicar esforço operacional. O pipeline abaixo, centralizado na conta Meridian-Audit (222222222222), consolida findings de todas as contas em um único painel — eliminando pontos cegos onde atacantes poderiam operar sem detecção.

```
Fontes de Dados (CloudTrail, VPC FL, DNS, EKS...)
           │
           ▼
  ┌─────────────────────────────────────────┐
  │         GuardDuty Engine               │
  │                                         │
  │  ┌──────────────────────────────────┐  │
  │  │  Machine Learning (Baseline)     │  │
  │  │  Anomaly Detection               │  │
  │  │  Threat Intelligence Feeds       │  │
  │  │  Rule-Based Detection            │  │
  │  └──────────────────────────────────┘  │
  └──────────────────┬──────────────────────┘
                     │
                     ▼
              Findings (LOW / MEDIUM / HIGH)
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
    Security Hub  EventBridge  Console
    (ASFF format)  (Rules)   (Findings list)
```

---

## 2. Finding Types — Catálogo Completo

### Critérios de Severidade

| Severidade | Score | Critério | Ação Recomendada |
|---|---|---|---|
| **HIGH** | 7.0 – 8.9 | Comprometimento confirmado ou altamente provável; impacto imediato | Resposta imediata — escalar para CISO; isolar recurso |
| **MEDIUM** | 4.0 – 6.9 | Atividade suspeita que requer investigação; pode ser legítima | Investigar em 24h; correlacionar com outros achados |
| **LOW** | 1.0 – 3.9 | Atividade potencialmente suspeita; baixo impacto | Revisar semanalmente; ajustar supressão se necessário |

### Tabela dos 20 Finding Types Mais Importantes

| # | Finding Type | Fonte | Severidade | O que Significa | Resposta Recomendada |
|---|---|---|---|---|---|
| 1 | `UnauthorizedAccess:EC2/SSHBruteForce` | VPC Flow Logs | MEDIUM | Tentativas repetidas de SSH na instância | Verificar origem, bloquear IP no SG, revisar exposição de porta 22 |
| 2 | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | CloudTrail | HIGH | Credenciais do Instance Metadata usadas fora da AWS | Isolar instância, revogar credenciais, iniciar IR |
| 3 | `Backdoor:EC2/C&CActivity.B` | VPC Flow Logs | HIGH | Instância comunicando com IP de C2 conhecido | Isolar instância imediatamente, snapshot, análise forense |
| 4 | `CryptoCurrency:EC2/BitcoinTool.B` | VPC Flow Logs + DNS | HIGH | Instância minerando criptomoeda | Isolar, analisar como foi comprometida, terminar instância |
| 5 | `Recon:EC2/PortProbeUnprotectedPort` | VPC Flow Logs | LOW | Porta exposta sendo scanneada externamente | Revisar Security Group, fechar portas desnecessárias |
| 6 | `Policy:IAMUser/RootCredentialUsage` | CloudTrail | HIGH | Conta root foi usada para operação | Investigar por que root foi usada, revogar access keys de root |
| 7 | `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail | HIGH | CloudTrail foi desabilitado | Reabilitar trail, investigar identidade que executou, escalar |
| 8 | `Impact:S3/AnomalousBehavior.Delete` | CloudTrail S3 | HIGH | Exclusão massiva incomum de objetos S3 | Ativar S3 Versioning/Object Lock, investigar identidade |
| 9 | `Discovery:S3/MaliciousIPCaller` | CloudTrail S3 | HIGH | IP malicioso reconhecido fazendo List/Get em S3 | Bloquear IP via WAF, revisar bucket policy, inventariar dados expostos |
| 10 | `Policy:S3/BucketBlockPublicAccessDisabled` | CloudTrail | MEDIUM | Block Public Access desabilitado em bucket | Reabilitar Block Public Access, investigar por que foi desabilitado |
| 11 | `PrivilegeEscalation:IAMUser/AnomalousBehavior` | CloudTrail | HIGH | Escalada de privilégios IAM detectada por ML | Revogar políticas adicionadas, investigar identidade, auditoria IAM |
| 12 | `PersistenceIAMUser/AnomalousBehavior` | CloudTrail | HIGH | Criação anômala de credenciais (backdoor IAM) | Deletar credenciais suspeitas, auditar usuários criados recentemente |
| 13 | `Exfiltration:S3/AnomalousBehavior` | CloudTrail S3 | HIGH | Download massivo incomum de dados S3 | Revogar credenciais, bloquear IP, inventariar dados acessados |
| 14 | `Trojan:EC2/DNSDataExfiltration` | DNS Logs | HIGH | Dados sendo exfiltrados via DNS tunneling | Isolar instância, bloquear comunicação DNS externa |
| 15 | `UnauthorizedAccess:EC2/RDPBruteForce` | VPC Flow Logs | MEDIUM | Tentativas repetidas de RDP na instância | Fechar porta 3389 para 0.0.0.0/0, usar Session Manager |
| 16 | `Malware:EC2/MaliciousFile` | Malware Protection | HIGH | Arquivo malicioso detectado em volume EBS | Isolar instância, analisar arquivo, remediar |
| 17 | `Kubernetes:Malware/MaliciousFile` | EKS Runtime | HIGH | Arquivo malicioso em container EKS | Encerrar pod, investigar imagem, verificar registry |
| 18 | `Impact:EC2/PortSweep` | VPC Flow Logs | MEDIUM | Instância fazendo port sweep interno (lateral movement) | Investigar compromentimento, isolar, verificar movimento lateral |
| 19 | `Execution:Kubernetes/ExecInKubeSystemPod` | EKS Audit Logs | MEDIUM | `kubectl exec` em pod do namespace kube-system | Investigar por que exec foi executado, revisar RBAC |
| 20 | `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce` | RDS Login | HIGH | Brute force bem-sucedido em RDS | Rotacionar credenciais do banco, investigar usuário comprometido |

---

## 3. Deploy Organization-Wide

### Arquitetura Multi-Conta do GuardDuty

**O que este diagrama representa:** A arquitetura org-wide delega a administração central do GuardDuty à conta de auditoria dedicada, que passa a receber e gerenciar todos os findings das contas-membro. Isso significa que analistas do SOC do Banco Meridian trabalham em um único painel, sem precisar alternar entre contas AWS para investigar alertas. A configuração de auto-enable garante que qualquer conta nova incorporada ao Organizations já nascerá monitorada — cobertura por design, não por procedimento manual.

**Por que isso importa para o Banco Meridian:** O delegated administrator configurado na conta Meridian-Audit (222222222222) é o pilar central da estratégia de detecção do banco. Sem ele, cada analista precisaria de acesso às 4 contas separadamente, e achados críticos como `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` na conta Production poderiam passar despercebidos por falta de visibilidade consolidada.

```
AWS Organizations — GuardDuty
─────────────────────────────────────────────────────

  Management Account (111111111111)
    └── Delega administração para → Audit Account (222222222222)
                                            │
                                            ▼
                        ┌─────────────────────────────────────┐
                        │  Audit Account — Delegated Admin    │
                        │                                     │
                        │  GuardDuty Detector (centralizador) │
                        │  ├── Findings de TODAS as contas    │
                        │  ├── Supression Rules centralizadas │
                        │  └── Auto-enable para novas contas  │
                        └─────────────────────────────────────┘
                               │          │          │
                               ▼          ▼          ▼
                          Production    Log       Dev/Test
                          (444...)     Archive    (555...)
                                       (333...)
```

### Configuração do Delegated Administrator

**O que este comando/configuração faz:** A sequência de três passos abaixo implementa o modelo org-wide completo. O Passo 1 transfere a autoridade administrativa do GuardDuty da Management Account (que não deve ser usada operacionalmente) para a conta Audit dedicada. O Passo 2 configura o auto-enable de todas as features de proteção para contas novas e existentes — garantindo que nenhuma conta entre no Organizations sem cobertura. O Passo 3 incorpora explicitamente as contas já existentes como membros gerenciados, completando a visibilidade centralizada.

**Por que isso importa para o Banco Meridian:** Com a conta Meridian-Audit (222222222222) como delegated administrator, a equipe de segurança ganha visibilidade unificada de findings HIGH, MEDIUM e LOW em todas as 4 contas sem precisar de acesso cross-account individual. O auto-enable com `ALL` features ativa S3 Data Events, EKS, Malware Protection, RDS e Lambda — todas as superfícies de ataque relevantes para uma instituição financeira que roda workloads variados em múltiplas contas.

```bash
# Passo 1: Na Management Account, designar Audit Account como delegated admin
aws guardduty enable-organization-admin-account \
  --admin-account-id 222222222222 \
  --region sa-east-1

# Passo 2: Na Audit Account (como admin delegado), configurar auto-enable
aws guardduty update-organization-configuration \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --auto-enable ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "MALWARE_PROTECTION", "AutoEnable": "ALL"},
    {"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "ALL"},
    {"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]'

# Passo 3: Adicionar contas existentes como membros (se não foram adicionadas via Organizations)
aws guardduty create-members \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --account-details '[
    {"AccountId": "444444444444", "Email": "prod@bancomeridian.com.br"},
    {"AccountId": "333333333333", "Email": "logs@bancomeridian.com.br"},
    {"AccountId": "555555555555", "Email": "dev@bancomeridian.com.br"}
  ]'
```

---

## 4. Regras de Supressão de Findings

Supressão evita que findings legítimos de atividade autorizada sejam exibidos como alertas, reduzindo o ruído operacional.

### Regras de Supressão do Banco Meridian

**O que este comando/configuração faz:** As regras de supressão instruem o GuardDuty a arquivar automaticamente findings que correspondam a critérios específicos — tipo de finding combinado com origem de IP, range CIDR ou tag de instância. O finding não é excluído permanentemente; ele é arquivado e permanece consultável para fins de auditoria. Isso permite que a equipe foque em alertas genuínos sem precisar desabilitar o mecanismo de detecção global.

**Por que isso importa para o Banco Meridian:** O Banco Meridian contrata a PentestCorp para testes de intrusão autorizados a partir do range 203.0.113.0/24. Sem as regras de supressão abaixo, cada ciclo de pentest geraria dezenas de findings `Recon:EC2/PortProbeUnprotectedPort` e `UnauthorizedAccess:EC2/SSHBruteForce` — inundando o painel de findings e treinando a equipe a ignorar alertas de severidade MEDIUM, o que é exatamente o comportamento que um atacante real exploraria para passar despercebido. A regra TrustedIPList-Pentest resolve isso de forma cirúrgica, sem suprimir outros tipos de finding para aquele range.

```json
[
  {
    "nome": "TrustedIPList-Pentest",
    "descricao": "Suprimir findings de IPs da empresa de pentest autorizada",
    "criterios": {
      "finding_type": ["Recon:EC2/PortProbeUnprotectedPort", "UnauthorizedAccess:EC2/SSHBruteForce"],
      "condition": "IP de origem é o range 203.0.113.0/24 (IPs da PentestCorp)"
    },
    "filtro_json": {
      "criterion": {
        "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {
          "cidr": "203.0.113.0/24"
        },
        "type": {
          "equals": ["Recon:EC2/PortProbeUnprotectedPort", "UnauthorizedAccess:EC2/SSHBruteForce"]
        }
      }
    }
  },
  {
    "nome": "ScannerAutorizado-Qualys",
    "descricao": "Suprimir port probes do scanner de vulnerabilidades Qualys",
    "criterios": {
      "finding_type": ["Recon:EC2/PortProbeUnprotectedPort"],
      "tag_instancia": "Scanner=Qualys"
    }
  },
  {
    "nome": "NATGateway-PortSweep",
    "descricao": "Suprimir port sweep de instâncias que são o NAT Gateway",
    "criterios": {
      "finding_type": ["Impact:EC2/PortSweep"],
      "tag_instancia": "Role=NATGateway"
    }
  }
]
```

**Interpretando o resultado:** Cada objeto JSON representa uma regra de supressão distinta. O campo `criterios.finding_type` lista os tipos de finding que serão arquivados automaticamente — a supressão é sempre combinada (finding type AND condição de IP/tag), nunca global para o IP. O campo `filtro_json.criterion` é a representação exata aceita pela API do GuardDuty via `aws guardduty create-filter --action ARCHIVE`. A regra `ScannerAutorizado-Qualys` usa tag de instância ao invés de IP porque o Qualys Cloud Agent opera a partir de múltiplos IPs de origem — o critério baseado em tag é mais robusto para ferramentas SaaS. A regra `NATGateway-PortSweep` evita falsos positivos estruturais: o NAT Gateway por natureza varre portas ao rotear tráfego, gerando findings `Impact:EC2/PortSweep` que são esperados e não indicam comprometimento.

**Atenção:** Supressão arquiva o finding (não exclui) e não o exibe no console. Use com critérios específicos e bem documentados. Audite as regras de supressão mensalmente.

---

## 5. Malware Protection

### Como Funciona o Malware Protection para EC2

**O que este diagrama representa:** O fluxo de análise do Malware Protection para EC2 opera inteiramente fora da instância de produção. Quando o GuardDuty detecta comportamento suspeito em uma instância (via VPC Flow Logs ou CloudTrail), ele aciona automaticamente a criação de um snapshot EBS — uma fotografia dos dados do volume naquele momento. Esse snapshot é copiado para a infraestrutura isolada e gerenciada internamente pela AWS, analisado por engines de detecção de malware, e descartado ao final. O resultado chega como finding com hash SHA256 do arquivo malicioso e o caminho completo no sistema de arquivos.

**Por que isso importa para o Banco Meridian:** Instâncias de produção do Banco Meridian processam transações financeiras 24 horas por dia — qualquer interrupção tem custo regulatório e reputacional. A análise via snapshot garante que mesmo uma investigação ativa de malware não impacta a disponibilidade do sistema. Em um cenário real, se a instância `i-0prod123` receber um finding `Malware:EC2/MaliciousFile`, a equipe recebe o hash SHA256 e o caminho do arquivo sem precisar fazer nada — o GuardDuty já coletou a evidência forense inicial automaticamente.

```
Instância EC2 com volume EBS
         │
         │ GuardDuty detecta atividade suspeita
         ▼
GuardDuty cria snapshot do EBS
         │
         ▼
Snapshot copiado para conta GuardDuty (isolado)
         │
         ▼
Análise de malware no snapshot (sem impacto na instância)
         │
         ▼
Finding: Malware:EC2/MaliciousFile
└── threat_name, file_path, hash SHA256
         │
         ▼
Snapshot excluído após análise
```

### Como Funciona o Malware Protection para S3

**O que esta configuração faz:** O Malware Protection para S3 integra varredura antimalware diretamente no fluxo de upload de objetos. Cada arquivo enviado ao bucket configurado é interceptado e analisado antes de ser considerado "limpo" para uso pela aplicação. O resultado da varredura é gravado como tag no próprio objeto S3, permitindo que pipelines downstream (Lambda, Step Functions) tomem decisões automatizadas sem precisar consultar a API do GuardDuty — basta checar a tag `GuardDutyMalwareScanStatus` do objeto.

**Por que isso importa para o Banco Meridian:** O banco recebe documentos de clientes (comprovantes, contratos, laudos) via upload em buckets S3. Sem varredura, um cliente comprometido poderia enviar um arquivo com malware embutido que seria processado internamente — potencialmente alcançando sistemas de back-office. O tag `THREATS_FOUND` permite que uma Lambda de quarentena mova o arquivo automaticamente para um bucket isolado antes que qualquer sistema interno o acesse, transformando o GuardDuty em uma linha de defesa proativa no pipeline de dados.

1. Objeto é carregado no bucket S3 configurado
2. GuardDuty analisa o objeto automaticamente (sem agente)
3. Se malicioso: finding `S3Object/MaliciousFile` + tag `GuardDutyMalwareScanStatus: THREATS_FOUND`
4. Se limpo: tag `GuardDutyMalwareScanStatus: NO_THREATS_FOUND`
5. Lambda pode ser acionada via EventBridge para mover/quarentenar arquivos infectados

---

## 6. Integração com Security Hub e EventBridge

### Fluxo de Integração

**O que este diagrama representa:** O GuardDuty publica cada finding em dois canais simultâneos: o Security Hub (em formato ASFF — Amazon Security Finding Format), que agrega findings de múltiplos serviços AWS em um painel unificado de compliance e postura de segurança; e o EventBridge, que transforma cada finding em um evento capaz de disparar automação em tempo real. O resultado é um pipeline que vai da detecção à resposta sem intervenção humana para os cenários mais críticos.

**Por que isso importa para o Banco Meridian:** Para uma instituição financeira sujeita à Resolução BACEN 4.893, o tempo de resposta a incidentes é um critério regulatório — não apenas operacional. A integração com EventBridge permite que um finding HIGH como `Backdoor:EC2/C&CActivity.B` dispare isolamento automático da instância em segundos, enquanto notifica o CISO via SNS e abre um ticket no sistema de gestão de incidentes. O Security Hub consolida os findings das 4 contas em formato padronizado ASFF, facilitando relatórios de compliance e correlação entre alertas de diferentes origens.

```
GuardDuty Finding (HIGH)
        │
        ├──► Security Hub (ASFF format)
        │         └── Painel unificado + Compliance mapping
        │
        └──► EventBridge Rule
                  │
          ┌───────┼───────┐
          ▼       ▼       ▼
       Lambda   SNS    Step Functions
     (isolamento) (alerta)  (IR workflow)
```

### Regra EventBridge para GuardDuty High Severity

**O que este comando/configuração faz:** Esta regra EventBridge monitora continuamente o barramento de eventos da AWS na conta Meridian-Audit e filtra especificamente os eventos publicados pelo GuardDuty com severidade maior ou igual a 7.0 (limiar da classificação HIGH). Quando um finding HIGH é detectado, a regra dispara dois targets em paralelo: uma função Lambda que executa o playbook de resposta automatizada (isolamento de instância, snapshot EBS, revogação de credenciais) e um tópico SNS que notifica o time de segurança via e-mail, SMS ou integração com ferramentas de alerta como PagerDuty ou Slack.

**Por que isso importa para o Banco Meridian:** O finding type `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — um dos mais críticos para o banco — tem severidade 8.0 (HIGH) e representa credenciais temporárias de um EC2 role sendo usadas fora da infraestrutura AWS. A janela entre a detecção e o bloqueio das credenciais é o período de exposição máxima. Com esta regra, o Lambda `GuardDutyIROrchestrator` pode revogar as credenciais da session IAM comprometida em segundos, muito antes que um analista humano possa agir — reduzindo o raio de impacto de horas para segundos. O campo `222222222222` no ARN do Lambda confirma que a automação reside na conta Meridian-Audit, centralizando a resposta org-wide.

```json
{
  "Rule": {
    "Name": "MeridianGuardDutyHighSeverity",
    "EventPattern": {
      "source": ["aws.guardduty"],
      "detail-type": ["GuardDuty Finding"],
      "detail": {
        "severity": [{"numeric": [">=", 7.0]}]
      }
    },
    "State": "ENABLED",
    "Targets": [
      {
        "Id": "LambdaIROrchestrator",
        "Arn": "arn:aws:lambda:sa-east-1:222222222222:function:GuardDutyIROrchestrator"
      },
      {
        "Id": "SNSSecurityTeam",
        "Arn": "arn:aws:sns:sa-east-1:222222222222:MeridianSecurityAlerts-HIGH"
      }
    ]
  }
}
```

**Interpretando o resultado:** O campo `EventPattern.source: ["aws.guardduty"]` restringe a regra a eventos do GuardDuty — sem risco de disparos por outros serviços. O campo `detail.severity` usa o operador `>=` com valor numérico `7.0`, que corresponde exatamente ao limiar de severidade HIGH do GuardDuty (7.0–8.9). O array `Targets` tem dois destinos: `LambdaIROrchestrator` executa automação de contenção (isolamento de EC2, revogação de credenciais IAM, snapshot EBS) e `MeridianSecurityAlerts-HIGH` envia notificação imediata à equipe de segurança. A chave `"State": "ENABLED"` confirma que a regra está ativa — regras em estado `DISABLED` não disparam mesmo se o padrão casar. O ARN do Lambda e do SNS incluem `sa-east-1` e a conta `222222222222`, confirmando que a resposta é centralizada na conta Meridian-Audit independentemente de qual conta originou o finding.

---

## 7. Atividades de Fixação

**1.** O GuardDuty gerou o finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` para a instância `i-0a1b2c3d4e` na conta Production do Banco Meridian. O que esse finding indica e qual é a resposta imediata correta?

a) A instância está sendo usada para mineração de criptomoeda; reiniciar a instância
b) Credenciais do IMDS (Instance Metadata Service) da instância foram usadas de um IP fora da AWS; isolar a instância e revogar as credenciais
c) A instância está com um arquivo malicioso; executar scan de antivírus
d) A instância está fazendo port sweep interno; adicionar regra de SG restritiva

**Gabarito: B** — Este finding indica que as credenciais temporárias do IAM role attached à instância (obtidas via IMDSv1/v2) estão sendo usadas a partir de um IP externo à AWS. Indica que a instância foi comprometida e o atacante exfiltrou as credenciais. Ação imediata: (1) Colocar instância em Security Group de quarentena (sem ingress/egress), (2) Forçar revogação das credenciais da session com `aws iam update-assume-role-policy`, (3) Tirar snapshot para forense.

---

**2.** Por que o GuardDuty não gera findings para atividades em regiões onde não está habilitado?

a) GuardDuty é um serviço global que cobre todas as regiões automaticamente
b) GuardDuty é regional — precisa ser habilitado explicitamente em cada região
c) GuardDuty só funciona na região padrão da conta
d) GuardDuty depende do CloudTrail que cobre todas as regiões automaticamente

**Gabarito: B** — GuardDuty é um serviço regional. Se habilitado apenas em `sa-east-1`, atividades maliciosas em `us-east-1` ou `ap-southeast-1` não serão detectadas. Por isso é fundamental habilitar GuardDuty em TODAS as regiões, incluindo regiões não utilizadas (atacantes frequentemente usam regiões menos monitoradas). O Organization-wide deployment com auto-enable ALL garante isso.

---

**3.** Você tem um scanner de vulnerabilidades Qualys que roda semanalmente na rede do Banco Meridian e gera vários findings `Recon:EC2/PortProbeUnprotectedPort` de LOW severidade. Qual é a forma correta de lidar com isso?

a) Desabilitar o GuardDuty durante os scans semanais
b) Criar uma Trusted IP list com o IP do Qualys para isentar de todos os findings
c) Criar uma Suppression Rule específica para o finding type com o IP/tag do scanner
d) Ignorar os findings de LOW severidade permanentemente

**Gabarito: C** — Suppression Rules são o mecanismo correto para reduzir falsos positivos de fontes conhecidas. A regra deve ser específica: finding type `Recon:EC2/PortProbeUnprotectedPort` + IP do Qualys ou tag da instância `Scanner=Qualys`. Trusted IP list (opção B) suprimiria TODOS os findings para aquele IP, o que é excessivo. Nunca desabilite o GuardDuty (opção A).

---

**4.** Qual é a diferença entre Malware Protection para EC2 e Malware Protection para S3?

a) EC2 analisa arquivos em tempo real; S3 analisa apenas arquivos novos
b) EC2 usa snapshot do EBS para análise sem impacto na instância; S3 analisa objetos no momento do upload e adiciona tags ao resultado
c) São equivalentes; ambos usam o mesmo engine de análise
d) EC2 requer agente instalado; S3 é agentless

**Gabarito: B** — Malware Protection EC2: quando GuardDuty detecta atividade suspeita, cria snapshot EBS, analisa na infraestrutura isolada da GuardDuty, sem impacto na instância. Malware Protection S3: analisa objetos no momento do upload (trigger por evento S3), sem agente, e adiciona tags `GuardDutyMalwareScanStatus` ao objeto com o resultado.

---

**5.** O que significa o campo `severity` em um GuardDuty Finding e como ele difere de `criticality`?

a) São equivalentes; ambos medem o impacto do finding
b) `severity` mede a gravidade intrínseca do finding; `criticality` é um campo customizável do Security Hub para priorização do negócio
c) `severity` é um campo do CloudTrail; `criticality` é específico do GuardDuty
d) `severity` é calculado apenas por ML; `criticality` é baseado em regras fixas

**Gabarito: B** — `severity` no GuardDuty é calculado pela AWS com base na técnica de ataque, fontes de threat intel e contexto. Varia de 1.0 a 8.9 (LOW/MEDIUM/HIGH). `criticality` no Security Hub é um campo customizável (0-100) onde a organização pode ajustar a prioridade com base no contexto do negócio (ex: um finding MEDIUM num sistema de pagamento pode ter criticality 90).

---

## 8. Roteiro de Gravação

### Aula 3.1 — GuardDuty: Arquitetura e Finding Types (50 min)

**Abertura (2 min):**
"Boa-noite, pessoal! Chegamos ao módulo que muitos consideram o coração das operações de segurança AWS: o Amazon GuardDuty. Nas aulas anteriores construímos a fundação — governança com Organizations e visibilidade com CloudTrail. Hoje vemos a inteligência de ameaças em ação."

**Bloco 1 — O que é o GuardDuty e por que ele é diferente (7 min):**
"GuardDuty não é um SIEM. Não é um IDS tradicional. É um serviço de detecção de ameaças gerenciado que usa machine learning, anomaly detection e threat intelligence proprietária da AWS.

A diferença fundamental: o GuardDuty não precisa de configuração de regras. Você habilita e ele começa a funcionar. Internamente, ele consome CloudTrail, VPC Flow Logs e DNS Logs — logs que você já tem — e aplica análise inteligente.

[Mostrar diagrama da arquitetura]

O GuardDuty tem um baseline: ele aprende o comportamento normal da sua conta nos primeiros 7-14 dias. Depois começa a detectar anomalias. Essa é a base dos findings de AnomalousBehavior.

Fontes de dados: [percorrer tabela]. Notem que S3 Data Events, EKS e Lambda são features adicionais que precisam ser habilitadas explicitamente. Para o Banco Meridian, habilitamos tudo."

**Bloco 2 — Análise de Finding Types por Categoria (20 min):**
"[Abrir console GuardDuty — Findings — Sample Findings]

Vou gerar sample findings para mostrar cada categoria. Na prova SCS-C02, vocês precisam conhecer os finding types mais comuns e saber interpretar o que cada um indica.

[Finding 1: CryptoCurrency:EC2/BitcoinTool.B]
'Uma instância EC2 está se comunicando com um domínio ou IP associado a atividade de criptomoeda.' Isso indica comprometimento — alguém instalou um cryptominer na instância. Severidade HIGH. Resposta: isolar imediatamente, snapshot, análise.

[Finding 2: Stealth:IAMUser/CloudTrailLoggingDisabled]
'O CloudTrail foi desabilitado.' Isso é especialmente alarmante — um atacante só faz isso para cobrir rastros. Nossa SCP deveria ter bloqueado. Se esse finding apareceu, verificar se a SCP está aplicada ou se houve bypass via Management Account.

[Finding 3: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS]
'Credenciais temporárias do role de uma instância EC2 foram usadas a partir de um IP externo à AWS.' O IMDSv1 permitia que malware na instância obtivesse credenciais sem autenticação. Com IMDSv2 essa surface de ataque é reduzida, mas não eliminada. Resposta: isolar instância, revogar todas as sessões do role.

[Finding 4: Impact:S3/AnomalousBehavior.Delete]
'Exclusão anormal de objetos S3 detectada por ML.' O modelo de ML aprendeu o padrão de deletes normal para a conta. Um spike fora do padrão gera esse finding. Pode ser ransomware, exfiltração + delete, ou operação legítima mal comunicada.

[Percorrer mais 5-6 findings da tabela com descrição e resposta recomendada]

Dica para a prova: os findings seguem o padrão `ThreatPurpose:ResourceType/AttackTechnique`. Conhecendo os componentes, vocês conseguem inferir o meaning de findings não memorizados."

**Bloco 3 — Severidade e Priorização (8 min):**
"HIGH, MEDIUM, LOW — como o GuardDuty define isso?

[Mostrar tabela de critérios]

HIGH significa comprometimento confirmado ou altamente provável com impacto imediato. Resposta em minutos. Exemplos: credencial exfiltrada, CloudTrail desabilitado, comunicação C2.

MEDIUM significa atividade suspeita que precisa de investigação. Pode ser legítima (pentest autorizado, configuração incorreta). Resposta em horas.

LOW significa ruído ou reconhecimento precoce. Port probe externo na maioria das vezes é scanner automático da internet. Resposta na revisão semanal.

Para o SCS-C02: memorize que GuardDuty não tem severidade CRITICAL — vai de 1.0 a 8.9. Security Hub tem CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. Não confundir."

**Bloco 4 — Demo no Console (13 min):**
"[Demo ao vivo — GuardDuty console]

1. Mostrar painel principal — Summary
2. Criar sample findings (gera exemplos de todos os tipos)
3. Abrir um HIGH finding — analisar a estrutura: Summary, Resources Affected, Action
4. Mostrar o botão 'Investigate in Detective' — conexão direta para investigação
5. Mostrar como filtrar por tipo, severidade, conta
6. Mostrar o botão de Suppression — criar uma regra de supressão para um finding LOW específico"

**Fechamento (0 min):**
"Na próxima aula, vemos o deploy organization-wide com delegated administrator, Malware Protection e a integração com EventBridge para automação de resposta."

---

### Aula 3.2 — Deploy Org-Wide, Supressão e Integração (50 min)

**Abertura (2 min):**
"Bem-vindos à Aula 3.2! Saber interpretar findings é ótimo, mas o valor real do GuardDuty vem quando ele está habilitado em TODAS as suas contas e regiões, e quando os achados disparam resposta automática. Vamos construir isso agora."

**Bloco 1 — Deploy Organization-Wide (15 min):**
"Habilitar GuardDuty conta por conta é inviável para organizações com dezenas ou centenas de contas. O deploy organization-wide com delegated administrator resolve isso.

[Demo ao vivo — Management Account]
1. GuardDuty — Settings — Delegated administrator
2. Inserir Account ID: 222222222222 (Audit Account)
3. Confirm

[Trocar para Audit Account]
4. GuardDuty — Settings — Accounts
5. Auto-enable: New accounts — All Features ✓
6. Enable for all existing accounts — Apply

Resultado: qualquer nova conta adicionada ao Organizations automaticamente tem GuardDuty habilitado com todas as features. Zero esforço operacional.

[Mostrar o painel de Accounts] Vocês veem todas as contas, o status de cada feature por conta, e podem ver findings de todas as contas no painel da Audit Account."

**Bloco 2 — Supressão de Findings (8 min):**
"Falsos positivos são o maior desafio operacional de qualquer ferramenta de detecção. No GuardDuty, Suppression Rules são o mecanismo para gerenciar isso responsavelmente.

[Demo ao vivo — Criar Suppression Rule]
1. GuardDuty — Findings — Suppression rules — Create rule
2. Nome: PentestCorp-AuthorizedScanner
3. Criteria: Finding type = Recon:EC2/PortProbeUnprotectedPort
4. Add filter: Remote IP = 203.0.113.0/24

O finding não é deletado — é arquivado. Permanece visível se você procurar. Para auditorias, posso mostrar que o finding existe mas foi suprimido por razão documentada.

Auditoria de supressão: revise todas as regras mensalmente. Uma Suppression Rule antiga para um pentest de 6 meses atrás pode estar suprimindo um ataque real."

**Bloco 3 — Malware Protection (10 min):**
"Malware Protection adicionou uma dimensão completamente nova ao GuardDuty. Antes, ele detectava comportamento suspeito. Agora, detecta arquivos maliciosos reais.

[Para EC2] Quando GuardDuty detecta atividade suspeita em uma instância, ele cria automaticamente um snapshot EBS, analisa os arquivos na sua infraestrutura isolada, e gera um finding com hash SHA256 do arquivo malicioso e o caminho. Sem impacto na instância em produção.

[Para S3] Qualquer upload para buckets habilitados é escaneado automaticamente. O resultado aparece como tag no objeto:
- `GuardDutyMalwareScanStatus: NO_THREATS_FOUND` — arquivo limpo
- `GuardDutyMalwareScanStatus: THREATS_FOUND` — arquivo malicioso detectado

[Demo] Habilitar Malware Protection para um bucket S3 de upload de documentos do Banco Meridian."

**Bloco 4 — Integração EventBridge + Security Hub (15 min):**
"[Demo ao vivo] Criar a regra EventBridge para GuardDuty HIGH:

1. EventBridge — Rules — Create rule
2. Event source: AWS services — GuardDuty
3. Event type: GuardDuty Finding
4. Condition: severity >= 7
5. Target 1: Lambda function GuardDutyIROrchestrator
6. Target 2: SNS topic SecurityAlerts-HIGH

[Mostrar código Lambda de exemplo — isolamento de EC2]

O Lambda recebe o evento do GuardDuty, extrai o Instance ID, e automaticamente:
1. Adiciona tag 'Quarantine=true'
2. Cria Security Group de quarentena (sem ingress, sem egress)
3. Move a instância para o Security Group de quarentena
4. Cria snapshot EBS
5. Notifica o time de segurança via SNS

Tudo isso em segundos, sem intervenção humana. Esse é o nível de maturidade de SOC que buscamos no Banco Meridian."

---

## 9. Avaliação do Módulo

**Questão 1 (2 pontos):** O Banco Meridian recebeu um finding `CryptoCurrency:EC2/BitcoinTool.B` (HIGH) para a instância `i-0prod123` na conta Production. Descreva o passo a passo de resposta a incidente para este finding.

**Gabarito:** 1. Isolar instância imediatamente: criar SG de quarentena (sem ingress/egress exceto porta 22/443 para time de IR) e mover instância para ele. 2. Tirar snapshot EBS para preservação de evidências antes de qualquer ação destrutiva. 3. Analisar CloudTrail: quais ações foram executadas a partir da instância, quais credenciais foram usadas. 4. Analisar VPC Flow Logs: com quem a instância se comunicou, volumes de tráfego. 5. Usar Detective para reconstruir timeline do comprometimento. 6. Verificar como o criptominer foi instalado: acesso SSH, exploit de vulnerabilidade, imagem comprometida. 7. Terminate a instância após análise. 8. Criar nova instância a partir de imagem limpa. 9. Documentar e reportar conforme NIST SP 800-61.

---

**Questão 2 (2 pontos):** Por que é importante habilitar GuardDuty em regiões onde o Banco Meridian não tem workloads ativos?

**Gabarito:** Atacantes frequentemente escolhem regiões com baixo monitoramento para iniciar ataques. Técnicas comuns: (1) Criar instâncias EC2 para cryptomining em regiões não monitoradas (o custo vai para a conta da vítima). (2) Criar usuários IAM ou roles de backdoor que parecem "esquecidos". (3) Exfiltrar dados via S3 em região não monitorada. Sem GuardDuty nessas regiões, essas atividades passam completamente despercebidas. O auto-enable para todas as regiões via Organization-wide deployment resolve isso com zero esforço adicional.

---

**Questão 3 (2 pontos):** Qual é o impacto operacional do GuardDuty Malware Protection para EC2 em uma instância de produção durante a análise de malware?

**Gabarito:** Impacto ZERO na instância de produção. O Malware Protection funciona via snapshot do EBS: (1) GuardDuty cria um snapshot do volume EBS da instância, (2) copia o snapshot para a infraestrutura interna isolada do GuardDuty, (3) analisa os arquivos, (4) gera o finding com detalhes do malware, (5) exclui o snapshot. A instância continua rodando normalmente durante todo o processo. Esta é uma vantagem crítica em ambientes 24x7 onde downtime não é aceitável.

---

**Questão 4 (2 pontos):** O GuardDuty gerou 50 findings `Recon:EC2/PortProbeUnprotectedPort` (LOW) do mesmo IP 8.8.8.8 (Google DNS). Isso é um falso positivo ou um risco real? Como você deve proceder?

**Gabarito:** Provavelmente falso positivo — 8.8.8.8 é o DNS público do Google, não um scanner malicioso. Isso pode ocorrer se uma instância EC2 está exposta publicamente e scanners automáticos da internet a encontraram. Procedimento: (1) Verificar se a instância deve estar expostas publicamente — se não, fechar as portas no SG. (2) Se deve estar exposta, verificar se as portas abertas são apenas as necessárias. (3) NÃO criar Trusted IP list para 8.8.8.8 — isso suprimiria findings legítimos de comunicação maliciosa usando IP do Google. (4) Criar Suppression Rule específica para o finding type com origem no IP exato, documentando a justificativa.

---

**Questão 5 (2 pontos):** Como o GuardDuty detecta exfiltração de dados via DNS tunneling e qual finding type é gerado?

**Gabarito:** DNS Tunneling: atacante codifica dados em subdomínios DNS e faz queries para um servidor DNS malicioso que ele controla. Ex: `dXNlcm5hbWU6cGFzc3dvcmQ=.evil.com` (base64 codificado). GuardDuty analisa os DNS Logs da VPC e detecta: (1) alto volume de queries para o mesmo domínio de segundo nível, (2) subdomínios com alta entropia (aparência aleatória), (3) domínios em feeds de Threat Intelligence de DNS malicioso. Finding gerado: `Trojan:EC2/DNSDataExfiltration` (HIGH). Resposta: isolar instância, bloquear domínio no Route 53 DNS Firewall, analisar o processo que iniciou as queries DNS.
