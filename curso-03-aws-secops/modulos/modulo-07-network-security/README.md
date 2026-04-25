# Módulo 07 — Segurança de Rede em AWS

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 5 horas (2h videoaula + 2h laboratório + 1h live)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 3 (Infrastructure Security)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Projetar uma VPC segura com subnets, NAT Gateway e controles de acesso
2. Diferenciar Security Groups e NACLs e aplicar regras restritivas
3. Configurar VPC Endpoints para eliminar tráfego pela internet em serviços AWS
4. Implementar AWS WAF v2 com regras para OWASP Top 10 e proteção customizada
5. Distinguir AWS Shield Standard e Advanced e aplicar no contexto do Banco Meridian
6. Configurar AWS Network Firewall e Route 53 DNS Firewall

---

## 1. VPC Design Seguro

### Diagrama ASCII — Topologia do Banco Meridian

```
VPC Banco Meridian — sa-east-1 (10.0.0.0/16)
═══════════════════════════════════════════════════════════════════════

  Internet Gateway
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  PUBLIC SUBNETS (10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24)          │
  │                                                                     │
  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────┐ │
  │  │  ALB + WAF     │  │  NAT Gateway   │  │  Network Firewall    │ │
  │  │  (web-facing)  │  │  (egress only) │  │  (stateful inspect)  │ │
  │  └────────┬───────┘  └────────────────┘  └──────────────────────┘ │
  └───────────┼──────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  PRIVATE SUBNETS — APP (10.0.10.0/24, 10.0.11.0/24)               │
  │                                                                     │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │
  │  │  ECS/EKS Cluster │  │  EC2 Auto Scaling │  │  Lambda         │ │
  │  │  (internet-bank) │  │  (processing)     │  │  (serverless)   │ │
  │  └──────────────────┘  └──────────────────┘  └─────────────────┘ │
  └───────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  PRIVATE SUBNETS — DATA (10.0.20.0/24, 10.0.21.0/24)              │
  │                                                                     │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │
  │  │  RDS Aurora      │  │  ElastiCache     │  │  DocumentDB      │ │
  │  │  (transacoes)    │  │  (sessoes)       │  │  (documentos)    │ │
  │  └──────────────────┘  └──────────────────┘  └─────────────────┘ │
  └───────────────────────────────────────────────────────────────────────┘
              │
              ▼ (sem saída para internet — apenas VPC Endpoints)
  ┌─────────────────────────────────────────────────────────────────────┐
  │  VPC ENDPOINTS (Interface + Gateway)                               │
  │  S3 Gateway · DynamoDB Gateway · KMS Interface · Secrets Manager   │
  │  ECR · CloudWatch Logs · SSM · STS · GuardDuty · Config            │
  └─────────────────────────────────────────────────────────────────────┘
```

### Bastion Host vs Session Manager

| Critério | Bastion Host | AWS Systems Manager Session Manager |
|---|---|---|
| **Porta aberta** | SSH 22 no SG (risco) | Nenhuma — usa HTTPS outbound do agente SSM |
| **Gestão de chaves SSH** | Manual, complexa | Não necessário |
| **Auditoria** | Logs via sshd (fraco) | CloudTrail + Session recordings no S3 |
| **MFA** | Requer configuração manual | IAM MFA nativa |
| **Custo** | EC2 instance + manutenção | Gratuito (SSM é gratuito para EC2) |
| **Recomendação** | Legado — migrar para SSM | Usar em novos projetos |

---

## 2. Security Groups vs NACLs

| Critério | Security Groups | NACLs |
|---|---|---|
| **Nível** | Instância/ENI | Subnet |
| **Estado** | Stateful — respostas permitidas automaticamente | Stateless — precisa de regras explícitas de entrada E saída |
| **Regras** | Apenas Allow | Allow e Deny |
| **Avaliação** | Todas as regras avaliadas; mais permissiva vence | Avaliadas por número (menor = maior prioridade); primeira regra que combina |
| **Escopo** | Dentro da VPC e cross-VPC (Peering) | Apenas dentro da VPC |
| **Uso recomendado** | Controle de acesso principal por recurso | Bloqueio adicional de IPs/ranges em nível de subnet |

### Regras SG para Camada de Aplicação (Banco Meridian)

**O que este comando/configuração faz:** Os quatro comandos abaixo configuram o Security Group da camada de aplicação do internet banking seguindo o princípio do mínimo acesso. A aplicação aceita conexões HTTPS apenas do ALB (nunca diretamente da internet), permite acesso SSH apenas da subnet de IR em emergências, e pode iniciar conexões apenas com o banco de dados e os VPC Endpoints — nenhuma saída direta para a internet.

**Por que isso importa para o Banco Meridian:** Uma das falhas de configuração mais comuns em ambientes AWS é o Security Group com regras de ingresso `0.0.0.0/0` na porta 443 aplicado diretamente em instâncias de aplicação — expondo desnecessariamente servidores à internet quando eles deveriam ser acessíveis apenas pelo ALB. No Banco Meridian, qualquer instância comprometida no segmento de app não consegue iniciar conexões de saída para a internet (para exfiltrar dados ou comunicar com C2) porque as regras de egress só permitem tráfego para o banco de dados e endpoints AWS internos.

```bash
# Security Group: sg-app-internetbanking

# INGRESS — aceitar apenas do ALB (sem acesso direto da internet)
aws ec2 authorize-security-group-ingress \
  --group-id sg-app-internetbanking \
  --protocol tcp --port 8443 \
  --source-group sg-alb-internetbanking \
  --description "HTTPS from ALB only"

# INGRESS — aceitar SSH apenas do range de IR (quarentena/resposta)
aws ec2 authorize-security-group-ingress \
  --group-id sg-app-internetbanking \
  --protocol tcp --port 22 \
  --cidr 10.0.200.0/24 \
  --description "SSH from IR Team subnet only"

# EGRESS — permitir apenas para subnets de banco de dados e VPC Endpoints
aws ec2 authorize-security-group-egress \
  --group-id sg-app-internetbanking \
  --protocol tcp --port 5432 \
  --destination-group sg-rds-transacoes \
  --description "PostgreSQL to RDS"

aws ec2 authorize-security-group-egress \
  --group-id sg-app-internetbanking \
  --protocol tcp --port 443 \
  --destination-group sg-vpc-endpoints \
  --description "HTTPS to VPC Endpoints (KMS, Secrets Manager, S3)"
```

### NACL para Subnet de Banco de Dados

**O que este comando/configuração faz:** As quatro regras abaixo criam uma Network ACL dedicada para as subnets que hospedam o RDS Aurora de transações. Por serem stateless (ao contrário dos Security Groups), as NACLs precisam de regras explícitas tanto para ingresso quanto para egresso. A regra 100 de ingresso permite apenas PostgreSQL (porta 5432) das subnets de aplicação. A regra 32767 nega tudo mais. As regras de egresso espelham essa lógica, mas para o retorno TCP nas portas efêmeras (1024-65535), que são as portas de resposta usadas pelos clientes TCP.

**Por que isso importa para o Banco Meridian:** Security Groups são a primeira linha de defesa por instância, mas NACLs adicionam uma camada de proteção no nível de subnet que é independente dos SGs. Se um analista de segurança comete um erro ao configurar um SG do RDS e inadvertidamente abre a porta 5432 para `0.0.0.0/0`, a NACL da subnet de dados ainda bloqueia o tráfego que não vem das subnets de app. Essa defesa em profundidade é especialmente importante para dados de transações financeiras, onde uma exposição acidental pode ter consequências regulatórias severas.

```bash
# NACL para subnets de RDS — apenas permitir tráfego das subnets de app

# INGRESS: permitir PostgreSQL de subnets de app
aws ec2 create-network-acl-entry \
  --network-acl-id acl-rds-meridian \
  --ingress \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=5432,To=5432 \
  --cidr-block 10.0.10.0/23 \
  --rule-action allow

# INGRESS: negar todo o resto
aws ec2 create-network-acl-entry \
  --network-acl-id acl-rds-meridian \
  --ingress \
  --rule-number 32767 \
  --protocol -1 \
  --cidr-block 0.0.0.0/0 \
  --rule-action deny

# EGRESS: permitir resposta para subnets de app (TCP ephemeral)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-rds-meridian \
  --egress \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=1024,To=65535 \
  --cidr-block 10.0.10.0/23 \
  --rule-action allow

# EGRESS: negar todo o resto
aws ec2 create-network-acl-entry \
  --network-acl-id acl-rds-meridian \
  --egress \
  --rule-number 32767 \
  --protocol -1 \
  --cidr-block 0.0.0.0/0 \
  --rule-action deny
```

---

## 3. VPC Endpoints

### Tipos de VPC Endpoints

| Tipo | Como Funciona | Serviços Suportados | Custo |
|---|---|---|---|
| **Gateway Endpoint** | Entrada na route table da subnet apontando para o serviço | S3, DynamoDB | Gratuito |
| **Interface Endpoint (PrivateLink)** | ENI na subnet com IP privado que resolve o DNS do serviço | 100+ serviços (KMS, Secrets Manager, ECR, SSM, etc.) | $0.01/hora/AZ + $0.01/GB |
| **Gateway Load Balancer Endpoint** | Para appliances de terceiros (firewall, IDS) | Appliances de segurança | Conforme appliance |

### Forçar Uso de VPC Endpoint via Resource Policy

**O que este comando/configuração faz:** Esta bucket policy implementa uma negação condicional: qualquer acesso ao bucket `meridian-transacoes-444` que não passe pelo VPC Endpoint específico `vpce-0abc123def456789` é bloqueado, independentemente das permissões IAM do solicitante. A condição `StringNotEquals` sobre `aws:SourceVpce` é o mecanismo que garante que apenas o tráfego originado dentro da VPC (pelo endpoint) seja aceito.

**Por que isso importa para o Banco Meridian:** Credenciais AWS comprometidas (access key + secret) são um vetor de ataque frequente contra instituições financeiras. Sem esta política, um atacante que obtivesse as credenciais de uma role com acesso ao bucket poderia baixar dados de transações diretamente da internet usando o AWS CLI. Com a restrição de endpoint, as credenciais são inúteis fora da VPC — o acesso só funciona de dentro da infraestrutura do banco, eliminando a ameaça de exfiltração remota de dados via credenciais roubadas.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccessOnlyViaEndpoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::meridian-transacoes-444",
        "arn:aws:s3:::meridian-transacoes-444/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-0abc123def456789"
        }
      }
    }
  ]
}
```

**Efeito:** O bucket `meridian-transacoes-444` SÓ pode ser acessado através do VPC Endpoint específico. Qualquer acesso via internet (sem o endpoint) é negado, mesmo com credenciais válidas.

---

## 4. AWS WAF v2

### Estrutura do WAF

```
Internet → CloudFront → ALB → WAF → Aplicação
              │
         Web ACL
          │    │
    ┌─────┘    └─────────────────────────────┐
    │                                        │
Rule Groups                           Custom Rules
├── AWSManagedRulesCommonRuleSet      ├── SQLi-Detector
├── AWSManagedRulesKnownBadInputs     ├── XSS-Blocker
├── AWSManagedRulesAmazonIpReputation ├── RateLimit-PerIP
├── AWSManagedRulesSQLiRuleSet        ├── GeoBlock-External
└── AWSManagedRulesBotControlRuleSet  └── ScannerBlock
```

### 5 Regras WAF Customizadas do Banco Meridian

**Regra 1 — Bloqueio de SQL Injection Customizado:**

**O que este comando/configuração faz:** Esta regra WAF inspeciona tanto a query string quanto o body da requisição HTTP em busca de padrões de SQL Injection. As `TextTransformations` são cruciais: elas decodificam o payload antes de avaliar os padrões — URL_DECODE converte `%27` para `'`, HTML_ENTITY_DECODE converte `&#x27;` para `'`, e LOWERCASE normaliza para minúsculas. O `SensitivityLevel: HIGH` aumenta a taxa de detecção ao custo de um leve aumento de falsos positivos. A `OrStatement` garante que tanto payloads na URL quanto no body sejam verificados.

**Por que isso importa para o Banco Meridian:** SQL Injection é classificado como A03 no OWASP Top 10 e continua sendo um dos vetores de ataque mais efetivos contra sistemas financeiros. O banco de dados de transações do Banco Meridian contém informações de todas as transações dos clientes — um ataque de SQLi bem-sucedido poderia extrair dados de milhões de contas. A detecção com múltiplas transformações é necessária porque atacantes sofisticados codificam seus payloads para evitar detecções simples baseadas em strings literais.

```json
{
  "Name": "MeridianSQLiBlock",
  "Priority": 10,
  "Action": {"Block": {}},
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "SqliMatchStatement": {
            "FieldToMatch": {"QueryString": {}},
            "TextTransformations": [
              {"Priority": 1, "Type": "URL_DECODE"},
              {"Priority": 2, "Type": "HTML_ENTITY_DECODE"},
              {"Priority": 3, "Type": "LOWERCASE"}
            ],
            "SensitivityLevel": "HIGH"
          }
        },
        {
          "SqliMatchStatement": {
            "FieldToMatch": {"Body": {"OversizeHandling": "MATCH"}},
            "TextTransformations": [
              {"Priority": 1, "Type": "URL_DECODE"},
              {"Priority": 2, "Type": "LOWERCASE"}
            ],
            "SensitivityLevel": "HIGH"
          }
        }
      ]
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "MeridianSQLiBlock"
  }
}
```

**Regra 2 — Bloqueio de XSS:**

**O que este comando/configuração faz:** Esta regra detecta Cross-Site Scripting (XSS) no body das requisições com quatro camadas de decodificação sequencial. O `JS_DECODE` é especialmente importante: ele decodifica sequências de escape JavaScript como `\x3cscript\x3e` que seriam invisíveis para uma regra simples de detecção de `<script>`. A ordem das transformações importa — URL decode primeiro, depois HTML entities, depois JS escapes, e por fim normalização para minúsculas.

**Por que isso importa para o Banco Meridian:** Ataques XSS no internet banking são utilizados para roubo de sessão, sequestro de formulários de transferência e redirecionamento de transações. Um payload XSS injetado em um campo de pesquisa ou comentário pode ser executado no navegador de outros usuários ou administradores, permitindo ao atacante realizar transações não autorizadas em nome das vítimas. A detecção no WAF bloqueia esses payloads antes que cheguem à aplicação.

```json
{
  "Name": "MeridianXSSBlock",
  "Priority": 20,
  "Action": {"Block": {}},
  "Statement": {
    "XssMatchStatement": {
      "FieldToMatch": {
        "Body": {"OversizeHandling": "MATCH"}
      },
      "TextTransformations": [
        {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
        {"Priority": 2, "Type": "URL_DECODE"},
        {"Priority": 3, "Type": "JS_DECODE"},
        {"Priority": 4, "Type": "LOWERCASE"}
      ]
    }
  }
}
```

**Regra 3 — Rate Limiting por IP:**

**O que este comando/configuração faz:** Esta regra implementa rate limiting focado no endpoint de autenticação. O `RateBasedStatement` conta requisições por IP em uma janela deslizante de 5 minutos. O `ScopeDownStatement` restringe o contador apenas às requisições que começam com `/api/auth/login` — sem ele, o limite se aplicaria a todas as URLs, o que poderia bloquear usuários legítimos que navegam por muitas páginas. Um IP que excede 100 requisições nessa URL em 5 minutos é automaticamente bloqueado por 5 minutos e depois liberado.

**Por que isso importa para o Banco Meridian:** Ataques de força bruta e credential stuffing são ameaças cotidianas para o internet banking. Listas de credenciais vazadas de outros serviços são testadas automaticamente contra endpoints de login bancários. Sem rate limiting, um atacante pode testar dezenas de milhares de combinações por hora. O limite de 100 requisições/5min por IP ainda permite que um usuário legítimo faça múltiplas tentativas, mas torna ataques automatizados economicamente inviáveis — cada IP precisaria de dezenas de minutos para testar apenas algumas dezenas de credenciais.

```json
{
  "Name": "MeridianRateLimitLoginEndpoint",
  "Priority": 30,
  "Action": {"Block": {}},
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/api/auth/login",
          "FieldToMatch": {"UriPath": {}},
          "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  }
}
```

**Regra 4 — Geoblocking para Países de Alto Risco:**

**O que este comando/configuração faz:** Esta regra bloqueia requisições originadas de países listados como de alto risco regulatório ou com histórico elevado de ataques cibernéticos a instituições financeiras. O WAF usa o banco de dados de geolocalização de IP da AWS para determinar o país de origem. A lista inclui países sob sanções internacionais (KP, IR, SY, CU) e países frequentemente associados a grupos de ameaça persistente avançada (APT) que miram o setor financeiro.

**Por que isso importa para o Banco Meridian:** O Banco Meridian opera exclusivamente no mercado brasileiro. Uma transação financeira originada da Coreia do Norte ou da Síria quase certamente é maliciosa — nenhum cliente legítimo do banco estaria acessando o internet banking a partir desses países. O geoblocking reduz significativamente a superfície de ataque ao eliminar tráfego que não tem razão legítima de existir. Em caso de usuário legítimo viajando para um país bloqueado, o banco pode oferecer canais alternativos (atendimento presencial, transferência via gerente).

```json
{
  "Name": "MeridianGeoBlock",
  "Priority": 40,
  "Action": {"Block": {}},
  "Statement": {
    "GeoMatchStatement": {
      "CountryCodes": [
        "KP", "IR", "SY", "CU",
        "RU", "BY", "VE", "MM",
        "SD", "SO", "AF"
      ]
    }
  }
}
```

**Regra 5 — Bloqueio de User-Agents de Scanners:**

**O que este comando/configuração faz:** Esta regra usa uma expressão regular para detectar User-Agents de ferramentas de ataque e reconhecimento conhecidas. Ferramentas como sqlmap (injeção de SQL automatizada), nikto (scanner de vulnerabilidades web), nessus (scanner de vulnerabilidades de rede) e hydra/medusa (força bruta de credenciais) deixam rastros identificáveis no cabeçalho User-Agent. O modificador `(?i)` torna a busca case-insensitive para capturar variações de capitalização.

**Por que isso importa para o Banco Meridian:** Reconhecimento é a fase inicial de qualquer ataque estruturado (MITRE ATT&CK TA0043). Atacantes que realizam varreduras automatizadas no internet banking antes de um ataque mais sofisticado podem ser identificados e bloqueados nesta fase inicial. Bloquear user-agents de ferramentas conhecidas não elimina atacantes determinados (que podem alterar o User-Agent), mas eleva o custo do reconhecimento e elimina a grande maioria dos ataques oportunistas automatizados.

```json
{
  "Name": "MeridianBlockScanners",
  "Priority": 50,
  "Action": {"Block": {}},
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "RegexMatchStatement": {
            "RegexString": "(?i)(sqlmap|nikto|nessus|masscan|nmap|dirbuster|gobuster|wfuzz|hydra|medusa)",
            "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
          }
        }
      ]
    }
  }
}
```

---

## 5. AWS Shield

| Característica | Shield Standard | Shield Advanced |
|---|---|---|
| **Custo** | Gratuito (todos os clientes) | $3.000/mês + custos de uso |
| **Proteção DDoS** | Camadas 3 e 4 (automático) | Camadas 3, 4 e 7 (com WAF) |
| **Mitigação automática** | SYN floods, UDP floods, reflexão | + mitigação de aplicação Layer 7 |
| **Cost protection** | Não | Sim — crédito por scale-up causado por DDoS |
| **DDoS Response Team (DRT)** | Não | Sim — suporte 24x7 durante ataques |
| **Proactive Engagement** | Não | Sim — DRT contata você durante ataques |
| **Diagnósticos** | CloudWatch métricas básicas | Painel avançado + CloudFront métricas |
| **Recursos protegidos** | Automático (CloudFront, ALB, EIP) | EC2, ELB, CloudFront, Route 53, Global Accelerator |

**Recomendação para Banco Meridian:** Shield Advanced é justificável dado o perfil de risco de uma instituição financeira. O custo de $3.000/mês é insignificante comparado ao custo de um ataque DDoS bem-sucedido que derruba o internet banking.

---

## 6. AWS Network Firewall

O Network Firewall é um firewall stateful gerenciado que inspeciona tráfego de rede com regras Suricata-compatíveis.

### Arquitetura de Deploy Centralizado

```
Internet
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  VPC Inspection (Firewall VPC)                      │
│                                                      │
│  Internet Gateway → Firewall Subnet                  │
│                         │                            │
│              Network Firewall Engine                 │
│              (stateful inspection)                   │
│                         │                            │
│              Private Subnet (TGW attachment)         │
└──────────────────────────┬───────────────────────────┘
                           │ Transit Gateway
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     VPC Production   VPC Dev/Test    VPC Security
     (444...)          (555...)        (222...)
```

### Regras Suricata para Banco Meridian

**O que este comando/configuração faz:** O arquivo YAML define quatro regras Suricata para o Network Firewall do Banco Meridian. A primeira bloqueia tráfego de nós de saída da rede Tor, que é frequentemente usada para anonimizar ataques. A segunda alerta sobre DNS tunneling — técnica usada por malware para exfiltrar dados codificados em consultas DNS. A terceira detecta possíveis conexões de reverse shell para portas comumente usadas por ferramentas de ataque (4444 é a porta padrão do Metasploit). A quarta bloqueia download de executáveis de origens externas, reduzindo o risco de malware sendo baixado por instâncias comprometidas.

**Por que isso importa para o Banco Meridian:** O Network Firewall opera em um nível mais profundo que o WAF (que é específico para HTTP) ou os Security Groups (que operam em nível de porta/IP). As regras Suricata permitem inspeção de payload — o conteúdo real do tráfego de rede — o que é essencial para detectar ameaças avançadas como Command & Control (C2), DNS tunneling e exfiltração de dados codificados. Para o setor financeiro, a detecção precoce de uma instância comprometida comunicando-se com C2 pode ser a diferença entre um incidente contido e uma violação de dados em larga escala.

```yaml
# network-firewall-rules.yaml
# Regras Suricata para o Network Firewall do Banco Meridian

# Grupo 1 — Bloqueio de IPs maliciosos conhecidos
rules:
  # Bloquear comunicação com IPs de Tor exit nodes
  - action: DROP
    header: "ip any any -> any any"
    options:
      - msg: "MERIDIAN Tor Exit Node Traffic Blocked"
      - ip.src: "!${HOME_NET}"
      - dataset: "tor-exit-nodes"
      - rev: 1

  # Bloquear DNS tunneling (subdomínios muito longos)
  - action: ALERT
    header: "dns any any -> any 53"
    options:
      - msg: "MERIDIAN Potential DNS Tunneling"
      - pcre: "/[a-zA-Z0-9]{50,}\./i"
      - rev: 1

  # Alertar em conexões de reverse shell (portas comuns)
  - action: ALERT
    header: "tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,1337,31337]"
    options:
      - msg: "MERIDIAN Potential Reverse Shell Connection"
      - flow: "established"
      - rev: 1

  # Bloquear download de executáveis de IPs externos não aprovados
  - action: DROP
    header: "http $HOME_NET any -> $EXTERNAL_NET any"
    options:
      - msg: "MERIDIAN Block Executable Download"
      - content: "Content-Type: application/octet-stream"
      - http.response_header
      - rev: 1
```

---

## 7. Route 53 DNS Firewall

**O que este comando/configuração faz:** Os comandos abaixo configuram um firewall DNS para todas as VPCs de produção do Banco Meridian. O processo tem quatro etapas: criação do rule group (contêiner das regras), criação de uma domain list com domínios maliciosos conhecidos, adição dos domínios à lista, e associação do rule group às VPCs. O comando também usa a managed domain list da AWS (`AWSManagedDomainsMalwareDomainList`), que é atualizada automaticamente pelo serviço de Threat Intelligence da AWS com novos domínios de malware e C2 identificados globalmente.

**Por que isso importa para o Banco Meridian:** Malware moderno frequentemente usa DNS para comunicação com servidores de Command & Control (C2) e para exfiltração de dados. Quando uma instância comprometida tenta resolver o domínio do servidor C2, essa consulta DNS é bloqueada pelo firewall antes que qualquer conexão TCP seja estabelecida. O DNS Firewall é a defesa mais eficiente contra essa categoria de ameaça: age na camada mais baixa possível (DNS), antes que o malware consiga estabelecer comunicação, e tem custo operacional muito menor que o Network Firewall para casos de uso baseados em nomes de domínio.

```bash
# Criar rule group de DNS Firewall com domínios maliciosos
aws route53resolver create-firewall-rule-group \
  --name "MeridianDNSFirewall" \
  --tags '[{"Key":"Environment","Value":"Production"},{"Key":"ManagedBy","Value":"SecurityTeam"}]'

# Criar domain list com domínios maliciosos conhecidos
aws route53resolver create-firewall-domain-list \
  --name "MeridianMaliciousDomains"

# Adicionar domínios maliciosos conhecidos
aws route53resolver update-firewall-domains \
  --firewall-domain-list-id "rslvr-fdl-xxx" \
  --operation ADD \
  --domains '["*.evil-c2.com","*.phishing-bank.com","malware-cdn.net","tor2web.org","*.onion.to"]'

# Usar managed domain list da AWS (Threat Intelligence)
aws route53resolver create-firewall-rule \
  --firewall-rule-group-id "rslvr-frg-xxx" \
  --name "BlockAWSManagedMalware" \
  --priority 100 \
  --action BLOCK \
  --block-response NODATA \
  --firewall-domain-list-id "rslvr-fdl-yyy"  # AWS Managed: AWSManagedDomainsMalwareDomainList

# Associar rule group às VPCs de produção
aws route53resolver associate-firewall-rule-group \
  --firewall-rule-group-id "rslvr-frg-xxx" \
  --vpc-id "vpc-production" \
  --priority 100 \
  --name "MeridianDNSFirewall-Production"
```

---

## 8. Atividades de Fixação

**1.** O Banco Meridian quer garantir que as instâncias EC2 na camada de aplicação não possam acessar a internet diretamente, apenas os serviços AWS necessários via VPC Endpoints. Como você implementaria isso?

a) Adicionar regra de SG bloqueando todo egress para 0.0.0.0/0
b) Remover a rota para o Internet Gateway das route tables das subnets de app + criar VPC Endpoints para S3, KMS, Secrets Manager, SSM, ECR, CloudWatch Logs
c) Usar NAT Gateway para todas as comunicações externas
d) Instalar um firewall de aplicação em cada instância EC2

**Gabarito: B** — A abordagem correta é: (1) Remover rota IGW das subnets privadas de app. (2) Criar Interface Endpoints para serviços AWS necessários (KMS, Secrets Manager, SSM, ECR, CloudWatch Logs). (3) Criar Gateway Endpoints para S3 e DynamoDB (gratuitos, adicionados à route table). (4) Configurar Security Groups dos endpoints para aceitar apenas tráfego das subnets de app. Resultado: instâncias de app se comunicam com serviços AWS via rede privada AWS, sem tráfego pela internet.

---

**2.** Qual é a diferença fundamental entre Security Groups e NACLs em relação ao estado da conexão (stateful vs stateless)?

a) Ambos são stateful — gerenciam o estado das conexões
b) SG é stateful (retorno automático); NACL é stateless (regras separadas para ingress e egress)
c) SG é stateless; NACL é stateful
d) Ambos são stateless — requerem regras explícitas em ambas as direções

**Gabarito: B** — Security Groups são stateful: ao permitir ingress TCP na porta 443, o retorno (ephemeral ports 1024-65535) é automaticamente permitido sem regra explícita de egress. NACLs são stateless: para uma conexão HTTP, precisam de regra de INGRESS permitindo porta 80 E regra de EGRESS permitindo portas efêmeras (1024-65535) para a resposta. Esquecer as portas efêmeras no egress da NACL é o erro mais comum.

---

**3.** O time de desenvolvimento do Banco Meridian quer bloquear tentativas de brute force no endpoint `/api/auth/login` do internet banking. O WAF v2 pode fazer isso? Se sim, como?

a) Não — WAF só bloqueia ameaças de nível 3/4 (rede)
b) Sim — usando Rate-Based Rule limitando requests por IP para a URI específica
c) Sim — usando IPSet Rule com lista de IPs bloqueados
d) Não — brute force deve ser bloqueado pela aplicação

**Gabarito: B** — WAF v2 Rate-Based Rules permitem definir: threshold de requests (ex: 100 requisições em 5 minutos), chave de agregação (por IP, por session, por custom header), e scope-down (apenas para a URI `/api/auth/login`). IPs que excedem o limite são automaticamente bloqueados temporariamente. Esta é exatamente a Regra 3 (MeridianRateLimitLoginEndpoint) que criamos no módulo.

---

**4.** Em qual cenário o AWS Network Firewall é mais apropriado que o Security Group + WAF combinados?

a) Nunca — SG + WAF sempre são suficientes
b) Quando há necessidade de inspeção de tráfego East-West (entre VPCs) ou regras de nível 7 baseadas em payloads, domínios e assinaturas Suricata
c) Apenas para proteção de instâncias EC2 de alto valor
d) Apenas quando o cliente tem mais de 1.000 instâncias

**Gabarito: B** — SGs controlam tráfego de entrada/saída por instância. WAF protege especificamente aplicações web (HTTP/HTTPS). Network Firewall adiciona: (1) Inspeção East-West (tráfego entre VPCs via Transit Gateway). (2) Regras Suricata para inspeção deep de payload (não apenas cabeçalhos HTTP). (3) Bloqueio de domínios por nome (não apenas IP). (4) Detecção de C2 em protocolos não-HTTP. (5) Deploy centralizado para inspecionar tráfego de múltiplas VPCs em um único ponto.

---

**5.** O Banco Meridian está sofrendo um ataque DDoS Layer 7 que está gerando 500.000 requisições/segundo para o endpoint `/api/saldo`, causando indisponibilidade do internet banking. Quais serviços devem estar configurados para absorver e mitigar esse ataque?

a) Route 53 apenas — DNS pode rotear para endpoints alternativos
b) Shield Advanced + WAF + CloudFront + ALB — em conjunto
c) GuardDuty — detectará o ataque automaticamente
d) EC2 Auto Scaling — escalar instâncias resolve o problema

**Gabarito: B** — Defesa em profundidade para DDoS Layer 7: (1) CloudFront: absorve e distribui o tráfego globalmente. (2) WAF Rate-Based Rule: bloqueia IPs que excedem threshold. (3) Shield Advanced: detecta o padrão DDoS e aciona DRT (DDoS Response Team) automaticamente. DRT pode criar regras WAF de emergência. (4) ALB: distribui o tráfego remanescente entre múltiplas instâncias. Auto Scaling (opção D) ajuda mas não resolve o ataque — apenas escala para absorver o tráfego malicioso até o custo ser insustentável.

---

## 9. Roteiro de Gravação

### Aula 7.1 — VPC Design + SGs + NACLs + Endpoints (50 min)

**Abertura (2 min):**
"Boa tarde! Módulo 7 — segurança de rede. Toda a segurança que construímos até agora — identidade, logging, detecção, postura — vive sobre uma rede. Se a rede não for segura, todo o resto é comprometido. Hoje vamos projetar a rede do Banco Meridian seguindo as melhores práticas de segurança AWS."

**Bloco 1 — VPC Design Seguro (15 min):**
"[Mostrar diagrama da topologia do Banco Meridian]

Três camadas de subnets: pública, privada de aplicação, privada de dados. Cada camada tem seu próprio Security Group e Route Table.

Subnets públicas: apenas o ALB e o NAT Gateway ficam aqui. Nenhuma instância de aplicação. Nenhum banco de dados.

Subnets de app: instâncias ECS/EC2 que recebem tráfego do ALB. Saída apenas via NAT Gateway ou VPC Endpoints.

Subnets de dados: RDS, ElastiCache. Sem saída para internet. Apenas accept de conexões das subnets de app.

[Demo ao vivo] Criar essa estrutura no console: VPC → 6 subnets → 3 route tables → Internet Gateway → NAT Gateway.

Bastião vs Session Manager: [mostrar comparação]

Para o Banco Meridian, usamos Session Manager 100%. Zero portas SSH abertas. Sessions são gravadas no S3 e auditadas no CloudTrail. É mais seguro E mais simples."

**Bloco 2 — Security Groups na Prática (15 min):**
"[Criar Security Groups ao vivo para cada camada]

SG do ALB: ingress TCP 443 de 0.0.0.0/0 (internet). Egress TCP 8443 para SG da app.

SG da app: ingress TCP 8443 do SG do ALB (NENHUMA regra de 0.0.0.0/0). Egress TCP 5432 para SG do RDS, TCP 443 para SG dos VPC Endpoints.

SG do RDS: ingress TCP 5432 do SG da app APENAS. Sem egress (banco de dados não precisa iniciar conexões).

[Mostrar resultado] A instância de app não pode ser acessada da internet diretamente — só pelo ALB. O RDS não pode ser acessado por nenhuma instância exceto as de app. É isso que chamamos de segmentação de rede.

[Comparar com NACL] Quando usar NACL? Quando preciso de DENY explícito que SG não oferece. Exemplo: bloquear um range de IP suspeito em nível de subnet antes de chegar no SG."

**Bloco 3 — VPC Endpoints (18 min):**
"[Demo ao vivo] Criar VPC Endpoints para os serviços AWS que a aplicação usa:

1. Gateway Endpoint para S3 — gratuito, adiciona rota na route table
2. Interface Endpoint para KMS — ENI com IP privado, resolve kms.sa-east-1.amazonaws.com para IP interno
3. Interface Endpoint para Secrets Manager
4. Interface Endpoint para CloudWatch Logs

[Mostrar DNS resolution antes e depois do endpoint]

Antes do endpoint: `kms.sa-east-1.amazonaws.com` → IP público da AWS
Depois do endpoint: `kms.sa-east-1.amazonaws.com` → IP privado 10.0.30.x

A aplicação não muda nada. Mesma URL, mesma SDK call. Mas agora o tráfego vai pelo backbone privado da AWS.

[Mostrar bucket policy que força uso de endpoint]

Essa bucket policy garante que nem mesmo alguém com credenciais válidas possa acessar o bucket a não ser via endpoint. Se um atacante obtiver credenciais e tentar acessar de fora da VPC (ex: via CLI na máquina dele), a bucket policy bloqueia."

**Fechamento (0 min):**
"Na próxima aula: WAF v2 com regras customizadas, Shield para proteção DDoS, Network Firewall e DNS Firewall."

---

### Aula 7.2 — WAF + Shield + Network Firewall + DNS Firewall (50 min)

**Abertura (2 min):**
"Bem-vindos à Aula 7.2! O internet banking do Banco Meridian está na internet. Isso significa que qualquer pessoa do mundo pode tentar atacá-lo. WAF, Shield, Network Firewall e DNS Firewall são as quatro camadas de defesa que protegem o perímetro externo."

**Bloco 1 — AWS WAF v2 (20 min):**
"[Criar Web ACL ao vivo]
1. WAF — Web ACLs — Create web ACL
2. Resource type: Regional (ALB)
3. Associated resources: alb-internetbanking-meridian

[Adicionar Managed Rule Groups]
AWSManagedRulesCommonRuleSet — 700 CRS rules, cobre OWASP Top 10
AWSManagedRulesSQLiRuleSet — detecção específica de SQL injection
AWSManagedRulesKnownBadInputs — exploits conhecidos
AWSManagedRulesAmazonIpReputation — IPs de botnet, Tor, scanners

[Adicionar as 5 regras customizadas]
[Mostrar SQL injection rule com transformações]

Notem as textTransformations: URL_DECODE, HTML_ENTITY_DECODE, LOWERCASE. Sem essas transformações, um atacante pode bypass a regra codificando o payload: `1%27%20OR%201%3D1` em vez de `1' OR 1=1`. A transformação decodifica antes da avaliação.

[Configurar WAF Logging]
Logs para S3 e CloudWatch — vou habilitar full logs para todas as requests (not just blocked). Isso me permite analisar padrões de ataque sem impacto na aplicação."

**Bloco 2 — AWS Shield (8 min):**
"[Mostrar painel Shield Standard]

Shield Standard já está ativo automaticamente. Cobre: SYN floods, UDP floods, DNS reflection, ICMP floods. Tudo automático, sem configuração.

[Discutir Shield Advanced]

Para o Banco Meridian, recomendo fortemente Shield Advanced. Razão principal: o Cost Protection. Se um ataque DDoS escalar automaticamente seus Auto Scaling Groups e CloudFront, a AWS te dá crédito para os custos extras. Um ataque de 24h pode gerar dezenas de milhares de dólares em scale-up — Shield Advanced te protege desse custo.

O DRT (DDoS Response Team) é o outro benefício: durante um ataque ativo, você pode abrir um case de suporte e ter engenheiros AWS trabalhando com você em tempo real para criar regras de mitigação."

**Bloco 3 — Network Firewall (12 min):**
"[Mostrar diagrama de deploy centralizado]

Network Firewall fica em uma VPC dedicada (Inspection VPC). Todo tráfego entre VPCs passa pelo Transit Gateway, que roteia para a Inspection VPC primeiro.

[Criar policy e rule groups ao vivo — simplificado]
1. Network Firewall — Firewall policies — Create
2. Criar stateless rule group: bloquear portas 23 (Telnet) e 21 (FTP)
3. Criar stateful rule group: regras Suricata para detecção de reverse shell

[Mostrar uma regra Suricata]
`alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,31337] (msg:"Reverse Shell Suspeito"; flow:established; sid:9001001;)`

Essa regra alerta quando qualquer instância da VPC (HOME_NET) faz conexão TCP de saída para portas comuns de reverse shell em endereços externos. Não bloqueia automaticamente — alerta para o SOC investigar."

**Bloco 4 — DNS Firewall (8 min):**
"[Configurar DNS Firewall ao vivo]

1. Route 53 Resolver — DNS Firewall — Rule groups — Create
2. Add rules — Domain list:
   - AWS Managed: AWSManagedDomainsMalwareDomainList (atualizado pela AWS com feeds de Threat Intel)
   - Custom: nossa lista de domínios de C2 conhecidos

3. Associate with VPCs: todas as VPCs de produção

[Testar com um domínio da lista]
nslookup known-malware-domain.com → NXDOMAIN (bloqueado pelo DNS Firewall)

DNS Firewall é a defesa contra DGA (Domain Generation Algorithms) e DNS Tunneling. Malware que tenta se comunicar com C2 via DNS é bloqueado antes de qualquer conexão TCP ser estabelecida."

---

## 10. Avaliação do Módulo

**Questão 1 (2 pontos):** Projetando a rede do Banco Meridian, por que você colocaria o NAT Gateway na subnet pública em vez de na subnet privada, e como você garantiria que instâncias de banco de dados nunca usem o NAT Gateway?

**Gabarito:** NAT Gateway precisa de acesso ao Internet Gateway para funcionar — por isso fica na subnet pública (que tem rota para o IGW). As instâncias nas subnets privadas de app têm rota `0.0.0.0/0 → NAT Gateway ID` na route table da subnet privada, permitindo saída controlada para internet. As subnets de dados (RDS) têm route table sem rota `0.0.0.0/0` — apenas rotas locais (10.0.0.0/16 → local) e opcionalmente rotas para VPC Endpoints. Dessa forma, mesmo que alguém configure uma rota errada no SG, a route table garante que o banco de dados não pode alcançar a internet.

---

**Questão 2 (2 pontos):** Uma aplicação do Banco Meridian usa S3 para armazenar contratos. O time de segurança quer garantir que esses contratos nunca sejam acessados via internet, apenas de dentro da VPC. Descreva os dois controles necessários.

**Gabarito:** Controle 1: **Gateway VPC Endpoint para S3** — criar endpoint na VPC, adicionar rota nas route tables das subnets de app. Isso garante que o tráfego S3 vai pelo backbone privado da AWS. Controle 2: **Bucket Policy com restrição de VPC Endpoint** — `{"Effect": "Deny", "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-xxx"}}}`. Isso garante que mesmo com credenciais válidas, acesso fora do endpoint é negado. Os dois controles se complementam: o endpoint garante o roteamento privado, a bucket policy garante a restrição de acesso.

---

**Questão 3 (2 pontos):** O WAF do Banco Meridian bloqueou uma requisição legítima de um parceiro de negócios com a regra `AWSManagedRulesCommonRuleSet`. Como você permitiria o tráfego desse parceiro sem desabilitar a regra para todos?

**Gabarito:** Usar Rule Group Override com IP Exception. (1) Criar IPSet com os IPs do parceiro. (2) Na Web ACL, antes das managed rules, criar uma Custom Rule com prioridade mais alta: `"Action": {"Allow": {}}`, condição `IPSet match against parceiro-ips-set`. (3) Como WAF avalia por prioridade (menor número = avaliado primeiro), a regra de Allow do parceiro é avaliada antes do CommonRuleSet, e a requisição é permitida sem chegar às managed rules. Alternativamente: usar o Scope-Down Override nas managed rules para excluir o IPSet do parceiro da avaliação.

---

**Questão 4 (2 pontos):** Qual é a diferença entre Route 53 DNS Firewall e AWS Network Firewall para bloquear comunicação de malware com C2?

**Gabarito:** **Route 53 DNS Firewall:** age na camada DNS (UDP 53). Quando malware tenta resolver o domínio do C2, a query DNS é bloqueada antes de qualquer conexão TCP/UDP ser estabelecida. Eficaz contra malware que usa domínios dinâmicos. NÃO protege contra malware que usa IPs diretos (sem DNS). **AWS Network Firewall:** age nas camadas 3, 4 e 7. Pode bloquear por IP, porta, protocolo e payload (Suricata rules). Protege também contra conexões diretas por IP. Mais caro e mais complexo. Ideal para tráfego North-South e East-West. **Uso combinado:** DNS Firewall como primeira camada (mais barato, zero latência para malware que usa DNS) + Network Firewall como segunda camada (para IPs diretos e inspeção de payload).

---

**Questão 5 (2 pontos):** O Banco Meridian tem workloads em sa-east-1 e us-east-1. Como você garantiria proteção WAF consistente em ambas as regiões sem duplicar a configuração?

**Gabarito:** Opções: (1) **CloudFront + WAF (recomendado):** Centralizar o tráfego no CloudFront (global), associar uma única Web ACL WAF no nível global (CloudFront). O WAF é avaliado no edge da CloudFront, antes de chegar às regiões. Uma única Web ACL protege recursos em todas as regiões. (2) **AWS Firewall Manager:** gerenciar Web ACLs em múltiplas regiões e contas centralmente. Criar Security Policy no Firewall Manager que aplica a mesma Web ACL em ALBs de todas as regiões. Mudanças na policy são replicadas automaticamente. A primeira opção (CloudFront) é mais simples para o caso de uso. A segunda (Firewall Manager) é melhor quando há múltiplas contas envolvidas.
