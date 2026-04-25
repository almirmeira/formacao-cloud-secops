# Módulo 06 — Proteção de Dados em AWS

**Curso 3: AWS Cloud Security Operations · CECyber**
**Carga Horária:** 4 horas (2h videoaula + 1h laboratório)
**Certificação:** AWS Certified Security – Specialty (SCS-C02) — Domínio 5 (Data Protection)

---

## Objetivos de Aprendizagem

Ao concluir este módulo, o aluno será capaz de:

1. Implementar gerenciamento de chaves KMS com políticas adequadas
2. Diferenciar Secrets Manager e Parameter Store e usar cada um no contexto correto
3. Configurar rotação automática de segredos no Secrets Manager para RDS
4. Identificar casos de uso de CloudHSM em ambientes financeiros regulatórios
5. Usar Amazon Macie para descobrir dados sensíveis (PII/PCI/PHI) em buckets S3
6. Configurar S3 Object Lock e Block Public Access para proteção de dados

---

## 1. AWS Key Management Service (KMS)

### CMK vs AWS Managed Keys

| Característica | AWS Managed Key | Customer Managed Key (CMK) | CloudHSM Key |
|---|---|---|---|
| **Criado por** | AWS automaticamente | Cliente | Cliente (via CloudHSM) |
| **Controle de key policy** | AWS controla | Cliente controla totalmente | Cliente controla |
| **Rotação automática** | A cada 3 anos | A cada 1 ano (configurável) | Manual |
| **Auditoria no CloudTrail** | Sim | Sim | Sim |
| **Cross-account use** | Não | Sim (via key policy) | Não (diretamente) |
| **Custo** | Incluso no serviço | $1/mês/chave + $0.03/10k requests | Via CloudHSM cluster |
| **FIPS 140-2 nível** | Nível 2 | Nível 2 | Nível 3 |
| **Exclusão** | Não controlável | Agendável (7–30 dias) | Controlável |

### Anatomia de uma Key Policy KMS

**O que este comando/configuração faz:** Uma Key Policy KMS é o documento JSON que define quem pode administrar e usar uma chave de criptografia. Ela opera em cinco camadas distintas: acesso raiz da conta, administradores da chave, usuários (aplicações que encriptam/decriptam dados), acesso cross-account e regras de negação explícita. Sem a instrução de acesso raiz, nem mesmo o root consegue recuperar a chave caso as demais permissões sejam removidas acidentalmente.

**Por que isso importa para o Banco Meridian:** O BACEN 4.893 exige que o acesso às chaves criptográficas seja restrito ao mínimo necessário e que qualquer operação de exclusão de chave seja auditável. A política abaixo implementa o princípio do menor privilégio separando quem administra a chave (equipe de segurança) de quem a usa (aplicações), além de exigir MFA para qualquer operação de exclusão — impedindo que um insider ou conta comprometida destrua dados criptografados irreversivelmente.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::444444444444:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyAdministrators",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::444444444444:role/KMSAdminRole",
          "arn:aws:iam::444444444444:user/ciso-admin"
        ]
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyUsage",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::444444444444:role/ApplicationRole",
          "arn:aws:iam::444444444444:role/BackupRole"
        ]
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowCrossAccountAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::222222222222:role/AuditRole"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.sa-east-1.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DenyKeyDeletionWithoutMFA",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "kms:ScheduleKeyDeletion",
        "kms:DeleteImportedKeyMaterial"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### Envelope Encryption — Padrão DEK

**O que este comando/configuração faz:** O envelope encryption é o padrão pelo qual o KMS gera uma chave de dados temporária (DEK — Data Encryption Key) que é usada localmente para criptografar o dado, enquanto apenas o DEK é enviado ao KMS para ser protegido. O dado em si nunca trafega pelo KMS. Isso resolve dois problemas simultaneamente: o limite de 64 KB do KMS por operação e a latência/custo de chamar o serviço para cada byte de dado.

**Por que isso importa para o Banco Meridian:** O banco processa milhares de transações por segundo, cada uma com registros de vários kilobytes. Criptografar cada registro diretamente via KMS seria inviável em termos de custo (cada chamada custa $0,03 por 10 mil requisições) e latência (cada chamada de API adiciona dezenas de milissegundos). Com o padrão DEK, a criptografia local usa AES-256 na memória da aplicação, e o KMS é chamado apenas para proteger o DEK — uma chamada por "envelope", não por transação.

```
ENVELOPE ENCRYPTION (KMS + DEK)
══════════════════════════════════════════════════════

  Dado original (plaintext)
          │
          ▼
  [KMS GenerateDataKey]
  ├── Data Encryption Key (DEK) plaintext    ─── usado para criptografar o dado
  └── Data Encryption Key (DEK) ciphertext  ─── armazenado junto ao dado
          │
          ▼
  Dado criptografado (ciphertext)
  + DEK criptografado
  ─────────────────────────────────────
  Stored together in S3 / DB / EFS

  Para descriptografar:
  1. Chamar kms:Decrypt com o DEK criptografado
  2. KMS retorna DEK plaintext (verificando permissões)
  3. Usar DEK plaintext para descriptografar o dado
  4. Descartar DEK plaintext da memória

  Benefício: KMS só é chamado na abertura do envelope,
  não para cada byte de dado. Performance + custo otimizados.
```

### Multi-Region Keys

**O que este comando/configuração faz:** Multi-Region Keys (MRK) são chaves KMS sincronizadas entre regiões AWS que compartilham o mesmo material criptográfico. Isso permite que dados criptografados em sa-east-1 sejam decriptografados em us-east-1 sem operações de re-encriptação, usando a chave réplica local na região de destino — reduzindo latência e eliminando chamadas cross-region para o KMS primário.

**Por que isso importa para o Banco Meridian:** O BACEN 4.893 (Art. 16) exige que instituições financeiras mantenham planos de continuidade de negócios com capacidade de recuperação em outra localidade. O banco utiliza us-east-1 como região de DR (Disaster Recovery). Sem MRK, ao ativar o failover em us-east-1, todos os dados criptografados em sa-east-1 seriam inacessíveis até que o KMS primário fosse restaurado — exatamente o momento em que mais se precisaria dos dados. A chave réplica em us-east-1 garante que o RTO (Recovery Time Objective) não seja comprometido pela indisponibilidade criptográfica.

```python
# Criar Multi-Region Primary Key em sa-east-1
import boto3

kms_primary = boto3.client('kms', region_name='sa-east-1')

primary_key = kms_primary.create_key(
    Description='Meridian-MRK-Transacoes-Primary',
    MultiRegion=True,
    KeyUsage='ENCRYPT_DECRYPT',
    KeySpec='SYMMETRIC_DEFAULT',
    Tags=[
        {'TagKey': 'Environment', 'TagValue': 'Production'},
        {'TagKey': 'DataClassification', 'TagValue': 'Confidential'},
        {'TagKey': 'Regulation', 'TagValue': 'BACEN-4893'}
    ]
)

primary_key_id = primary_key['KeyMetadata']['KeyId']
print(f"Primary Key ARN: {primary_key['KeyMetadata']['Arn']}")

# Replicar para us-east-1 (DR region)
primary_key_replica = kms_primary.replicate_key(
    KeyId=primary_key_id,
    ReplicaRegion='us-east-1',
    Description='Meridian-MRK-Transacoes-Replica-USE1'
)

print(f"Replica Key ARN: {primary_key_replica['ReplicaKeyMetadata']['Arn']}")
```

---

## 2. Secrets Manager vs Parameter Store

| Característica | AWS Secrets Manager | SSM Parameter Store (SecureString) |
|---|---|---|
| **Custo** | $0.40/segredo/mês + $0.05/10k API calls | Gratuito (Standard) ou $0.05/parâm avançado |
| **Rotação automática** | Sim (nativa para RDS, DocumentDB, Redshift) | Não nativa (requer Lambda customizado) |
| **Replicação cross-region** | Sim | Não (apenas SSM replication por CloudFormation) |
| **Versionamento** | Sim (staging labels: AWSCURRENT, AWSPREVIOUS) | Sim (histórico de versões) |
| **Máximo de tamanho** | 65.536 bytes | 8 KB (Standard) ou 8 KB (Advanced) |
| **Integração nativa** | RDS, ECS, Kubernetes, Lambda | EC2, ECS, CodeBuild, Lambda |
| **Cross-account** | Sim (via Resource Policy) | Não nativo |
| **Casos de uso ideais** | Senhas de BD, API keys de terceiros, certificados | Strings de configuração, flags de feature, endpoints |

### Quando Usar Cada Um

| Cenário | Recomendação |
|---|---|
| Senha do banco de dados RDS de produção | Secrets Manager (rotação automática) |
| URL do endpoint da API de pagamentos | Parameter Store (sem necessidade de rotação) |
| Chave de API do Stripe (terceiro) | Secrets Manager (rotação manual mas com versionamento) |
| Flag de feature (enable_new_flow=true) | Parameter Store Standard (gratuito) |
| Certificado TLS da aplicação | Secrets Manager |
| Variáveis de ambiente não sensíveis | Parameter Store Standard |

---

## 3. AWS Secrets Manager — Rotação Automática

### Como Funciona a Rotação para RDS

```
CICLO DE ROTAÇÃO AUTOMÁTICA — RDS
════════════════════════════════════════════════════

  1. EventBridge Schedule (ex: a cada 30 dias)
           │
           ▼
  2. Secrets Manager chama Lambda de rotação
           │
      ┌────┴──────────────────────────────────────────────────────────┐
      │  LAMBDA DE ROTAÇÃO (4 etapas):                               │
      │                                                               │
      │  Step 1 — createSecret                                       │
      │    Gerar nova senha aleatória                                 │
      │    Armazenar como AWSPENDING                                  │
      │                                                               │
      │  Step 2 — setSecret                                          │
      │    Conectar ao RDS usando a senha ATUAL (AWSCURRENT)          │
      │    Executar: ALTER USER 'appuser'@'%' IDENTIFIED BY 'newpass' │
      │                                                               │
      │  Step 3 — testSecret                                         │
      │    Tentar conectar ao RDS usando a nova senha (AWSPENDING)    │
      │    Se falhar: rolar de volta e alertar                        │
      │                                                               │
      │  Step 4 — finishSecret                                       │
      │    Mover AWSPENDING para AWSCURRENT                          │
      │    Mover AWSCURRENT anterior para AWSPREVIOUS                │
      └──────────────────────────────────────────────────────────────┘
           │
           ▼
  3. Aplicação usa GetSecretValue (sempre busca AWSCURRENT)
     Zero downtime — a aplicação nunca sabe da rotação
```

### Configurar Rotação via CLI

**O que este comando/configuração faz:** Os três comandos abaixo cobrem o ciclo de vida completo de um segredo de banco de dados no Secrets Manager. O primeiro cria o segredo com metadados estruturados (usuário, senha, host, porta e nome do banco) criptografado com a CMK do banco de dados. O segundo habilita a rotação automática delegada a uma função Lambda que conhece a API do RDS PostgreSQL. O terceiro é o comando de emergência para forçar uma rotação imediata quando há suspeita de comprometimento.

**Por que isso importa para o Banco Meridian:** O BACEN 4.893 (Art. 4) determina que credenciais de acesso privilegiado devem ser gerenciadas com controles que incluem rotação periódica. Desenvolvedores do banco frequentemente codificam senhas de banco de dados diretamente em variáveis de ambiente ou arquivos de configuração — uma vulnerabilidade crítica que o Secrets Manager elimina. A integração nativa com o RDS PostgreSQL do cluster de transações permite que a senha seja trocada a cada 30 dias sem interrupção de serviço e sem que nenhum desenvolvedor precise conhecer ou manipular a credencial.

```bash
# Criar segredo para RDS do Banco Meridian
aws secretsmanager create-secret \
  --name "meridian/prod/rds/transacoes-senha" \
  --description "Senha do banco de dados de transações" \
  --secret-string '{"username":"appuser","password":"SenhaInicial@2026","host":"transacoes.cluster-xyz.sa-east-1.rds.amazonaws.com","port":5432,"dbname":"transacoes"}' \
  --kms-key-id "arn:aws:kms:sa-east-1:444444444444:key/mrk-abc123" \
  --tags '[{"Key":"DataClassification","Value":"Confidential"},{"Key":"Regulation","Value":"BACEN-4893"}]'

# Habilitar rotação automática a cada 30 dias
aws secretsmanager rotate-secret \
  --secret-id "meridian/prod/rds/transacoes-senha" \
  --rotation-lambda-arn "arn:aws:lambda:sa-east-1:444444444444:function:SecretsManagerRDSRotation" \
  --rotation-rules '{"AutomaticallyAfterDays": 30}'

# Forçar rotação imediata (emergência: senha comprometida)
aws secretsmanager rotate-secret \
  --secret-id "meridian/prod/rds/transacoes-senha" \
  --rotate-immediately
```

---

## 4. AWS CloudHSM

### Diferenças entre KMS e CloudHSM

| Critério | AWS KMS | AWS CloudHSM |
|---|---|---|
| **FIPS 140-2 Level** | Nível 2 | Nível 3 |
| **Gerenciamento** | Totalmente gerenciado pela AWS | Hardware dedicado, cliente gerencia usuários e chaves |
| **Compartilhamento** | Multi-tenant (chaves isoladas logicamente) | Single-tenant (hardware dedicado) |
| **Custo** | $1/chave/mês | ~$1.50/hora por HSM (cluster mínimo: 2 HSMs = ~$2.160/mês) |
| **API** | AWS KMS API (Boto3) | PKCS#11, JCE, Microsoft CNG |
| **Casos de uso** | Criptografia de serviços AWS, envelope encryption | CA raiz, assinatura de código, requisitos regulatórios nível 3, TLS offload |
| **Auditoria CloudTrail** | Sim | Apenas operações de gerenciamento do cluster |

### Casos de Uso Financeiros do CloudHSM

| Caso de Uso | Justificativa |
|---|---|
| **Autoridade Certificadora (CA) Raiz** | FIPS 140-2 Level 3 exigido para CA raiz em algumas certificações (WebTrust) |
| **Assinatura de código** | Chave privada de assinatura nunca sai do HSM |
| **Processamento de EMV (cartão chip)** | Derivação de chaves de sessão para transações de cartão |
| **TLS offload** | Chave privada TLS nunca exposta ao servidor de aplicação |
| **Custódia de ativos digitais** | Chave de carteira de cripto com hardware dedicado |

---

## 5. Amazon Macie

### O que o Macie Descobre

| Tipo de Dado Sensível | Exemplos | Regulação Relevante |
|---|---|---|
| **PII (Personally Identifiable Information)** | CPF, RG, data de nascimento, email | LGPD |
| **Financial Data** | Número de cartão de crédito, CVV, data de expiração | PCI DSS |
| **Credentials** | AWS Access Keys, senhas em texto claro, tokens | Segurança geral |
| **PHI (Protected Health Information)** | CID, prontuário, dados médicos | LGPD (dados sensíveis) |
| **Corporate Data** | Contratos, dados de folha de pagamento | Regulação interna |

### Configurar Discovery Job para S3

**O que este comando/configuração faz:** Este script Python cria um job de classificação no Amazon Macie que varre automaticamente quatro buckets S3 do Banco Meridian em busca de dados sensíveis — CPF, números de cartão, senhas em texto claro e outros identificadores. O parâmetro `samplingPercentage=100` indica análise exaustiva de todos os objetos, não apenas amostragem. O job é do tipo `ONE_TIME`, mas pode ser alterado para `SCHEDULED` para análise contínua com frequência configurável.

**Por que isso importa para o Banco Meridian:** O LGPD (Art. 10) e o BACEN 4.893 (Art. 3) exigem que a instituição mantenha inventário atualizado de onde estão seus dados pessoais e críticos. Sem o Macie, o banco depende de auditorias manuais periódicas — ineficientes e propensas a lacunas. Um único arquivo CSV com dados de clientes copiado inadvertidamente para um bucket de uploads pode passar meses sem ser detectado. O Macie automatiza esse inventário e gera findings que integram diretamente com o Security Hub, fechando o ciclo de visibilidade de dados.

```python
import boto3
import json

macie = boto3.client('macie2', region_name='sa-east-1')

# Criar discovery job para buckets de dados do Banco Meridian
job_response = macie.create_classification_job(
    name='MeridianPIIDiscovery-2026-Q2',
    description='Descoberta de PII/PCI em todos os buckets de dados do Banco Meridian',
    jobType='ONE_TIME',  # ou SCHEDULED para análise contínua
    s3JobDefinition={
        'bucketDefinitions': [
            {
                'accountId': '444444444444',
                'buckets': [
                    'meridian-clientes-444',
                    'meridian-transacoes-444',
                    'meridian-relatorios-444',
                    'meridian-backups-444'
                ]
            }
        ],
        'scoping': {
            'includes': {
                'and': [
                    {
                        'simpleScopeTerm': {
                            'comparator': 'GT',
                            'key': 'OBJECT_SIZE',
                            'values': ['0']
                        }
                    }
                ]
            }
        }
    },
    samplingPercentage=100,  # Analisar 100% dos objetos
    tags={'Environment': 'Production', 'Regulation': 'LGPD-PCI', 'Purpose': 'DataDiscovery'}
)

print(f"Discovery Job criado: {job_response['jobId']}")
```

### Exemplo de Finding do Macie

**O que este comando/configuração faz:** Este JSON representa um finding gerado pelo Macie após detectar dados financeiros em um objeto S3. O finding estrutura todas as informações relevantes: a severidade do achado, qual bucket e objeto foram afetados, o tipo de dado sensível encontrado, a quantidade de ocorrências e até a coluna do CSV onde os dados aparecem. A integração com Security Hub encaminha esse finding automaticamente para o painel centralizado de segurança.

**Por que isso importa para o Banco Meridian:** Este finding específico representa um cenário real de risco: 1.247 números de cartão de crédito em um arquivo de extrato no bucket de uploads de clientes. Embora o arquivo esteja criptografado com KMS e o bucket não seja público, a presença de dados PCI fora do escopo certificado PCI DSS é uma violação de conformidade. O DPO do banco e o responsável por PCI precisam ser notificados para investigar se os dados são legítimos ou resultado de um erro de processo, e avaliar se o escopo de certificação PCI precisa ser expandido.

```json
{
  "title": "S3Object contains financial data",
  "description": "O objeto S3 contém dados financeiros que se assemelham a números de cartão de crédito.",
  "severity": {
    "score": 90,
    "description": "High"
  },
  "resourcesAffected": {
    "s3Bucket": {
      "name": "meridian-uploads-clientes",
      "publicAccess": {
        "effectivePermission": "NOT_PUBLIC"
      }
    },
    "s3Object": {
      "key": "relatorios/extrato-clientes-2026-04.csv",
      "size": 2458624,
      "serverSideEncryption": {
        "encryptionType": "aws:kms",
        "kmsMasterKeyId": "arn:aws:kms:sa-east-1:444444444444:key/mrk-abc123"
      }
    }
  },
  "classificationDetails": {
    "result": {
      "sensitiveData": [
        {
          "category": "FINANCIAL_INFORMATION",
          "detections": [
            {
              "type": "CREDIT_CARD_NUMBER",
              "count": 1247,
              "occurrences": {
                "csvHeaders": ["numero_cartao"],
                "lineRanges": [{"start": 1, "end": 1247}]
              }
            }
          ],
          "totalCount": 1247
        }
      ]
    }
  }
}
```

**Interpretando o resultado:**
- `severity.score: 90` — classificado como HIGH; o Macie usa escala de 0 a 100, e dados financeiros em quantidade elevada atingem pontuação máxima
- `publicAccess.effectivePermission: NOT_PUBLIC` — o bucket não é publicamente acessível, o que mitiga o risco imediato mas não elimina a violação de escopo PCI
- `encryptionType: aws:kms` — o objeto está criptografado com KMS; a criptografia protege em repouso mas não corrige o problema de localização dos dados
- `csvHeaders: ["numero_cartao"]` — o Macie identificou exatamente a coluna no CSV que contém os dados sensíveis, facilitando a investigação
- `lineRanges: [{"start": 1, "end": 1247}]` — todas as 1.247 linhas do arquivo contêm dados de cartão, não apenas algumas

---

## 6. S3 Object Lock e Block Public Access

### S3 Object Lock — Modos

| Modo | Quem pode remover/modificar antes do prazo | Quando usar |
|---|---|---|
| **Governance** | Usuários com `s3:BypassGovernanceRetention` podem remover | Proteção padrão; permite exceções com privilégio |
| **Compliance** | Ninguém, incluindo root e AWS | Logs de auditoria, evidências forenses, requisitos BACEN |

### S3 Block Public Access — 4 Configurações

| Configuração | O que Bloqueia |
|---|---|
| `BlockPublicAcls` | Bloqueia novas ACLs públicas e PUT requests com ACL pública |
| `IgnorePublicAcls` | Ignora ACLs públicas existentes — efetivamente torna-as privadas |
| `BlockPublicPolicy` | Bloqueia bucket policies que concedem acesso público |
| `RestrictPublicBuckets` | Restringe acesso público mesmo se houver bucket policy pública |

**Configuração no nível da conta (recomendado para Banco Meridian):**

**O que este comando/configuração faz:** O comando `put-public-access-block` aplicado no nível da conta (`s3control`) cria um escudo global que prevalece sobre qualquer configuração individual de bucket. Mesmo que um desenvolvedor crie um bucket com uma política pública explicitamente ou esqueça de marcar a opção de bloqueio, a configuração da conta anula essa permissão. O segundo comando verifica e confirma que as quatro configurações foram aplicadas com sucesso.

**Por que isso importa para o Banco Meridian:** Um dos vetores de vazamento de dados mais comuns em AWS é a criação acidental de buckets S3 públicos. Dados de clientes, extratos bancários e relatórios de transações já foram expostos publicamente por erros de configuração em diversas instituições financeiras no Brasil. Habilitar Block Public Access no nível da conta elimina essa classe de erro completamente — independentemente de quem cria o bucket e de como o configura. Esta é uma das primeiras configurações que deve ser aplicada em qualquer conta AWS que processe dados do Banco Meridian.

```bash
# Habilitar Block Public Access para TODA a conta (aplica a todos os buckets)
aws s3control put-public-access-block \
  --account-id 444444444444 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verificar configuração
aws s3control get-public-access-block --account-id 444444444444
```

**Interpretando o resultado:** O comando `get-public-access-block` retorna um JSON com os quatro campos configurados. Todos devem estar `true` para garantia completa. Se qualquer um estiver `false`, existe uma janela de exposição potencial que precisa ser corrigida imediatamente.

---

## 7. Tabela de Serviços de Proteção de Dados — Contexto Regulatório

| Serviço | Caso de Uso | BACEN 4.893 | LGPD | PCI DSS |
|---|---|---|---|---|
| **KMS (CMK)** | Criptografia de dados em repouso (RDS, S3, EBS, DynamoDB) | Art. 6 (criptografia obrigatória) | Art. 46 (medidas de segurança) | Req. 3.5 (chaves criptográficas) |
| **CloudHSM** | Geração e custódia de chaves com FIPS 140-2 Level 3 | Sistemas críticos do SFN | Dados sensíveis | Req. 3.6.1 (HSM para chaves mestras) |
| **Secrets Manager** | Senhas de banco de dados, API keys, rotação automática | Art. 4 (acesso privilegiado) | Art. 46 | Req. 8.2 (gerenciamento de credenciais) |
| **S3 Object Lock (Compliance)** | Imutabilidade de logs de auditoria, evidências | Art. 7 (retenção de logs 7 anos) | Art. 37 (registros de atividades) | Req. 10.7 (retenção de logs) |
| **Amazon Macie** | Descoberta de PII/PCI/PHI em S3 | Art. 3 (inventário de dados críticos) | Art. 10 (inventário de dados pessoais) | Req. 3.1 (identificar dados de cartão) |
| **S3 Block Public Access** | Prevenir exposição pública de dados | Art. 10 (proteção de dados) | Art. 46 | Req. 1.3 (isolamento de dados) |
| **KMS (MRK)** | Replicação de dados criptografados entre regiões (DR) | Art. 16 (continuidade de negócios) | Art. 46 | Req. 12.3 (gestão de riscos) |

---

## 8. Atividades de Fixação

**1.** O Banco Meridian precisa armazenar a chave privada de sua CA raiz interna com FIPS 140-2 Level 3. Qual serviço AWS deve ser usado?

a) AWS KMS com CMK
b) AWS CloudHSM
c) AWS Secrets Manager com KMS encryption
d) SSM Parameter Store com SecureString

**Gabarito: B** — CloudHSM é o único serviço AWS que oferece FIPS 140-2 Level 3 com hardware dedicado. KMS oferece FIPS 140-2 Level 2 em hardware multi-tenant. Para chave privada de CA raiz, o hardware dedicado e Level 3 são requisitos de segurança adequados ao nível de risco.

---

**2.** Por que o envelope encryption (padrão DEK) é usado em vez de criptografar todos os dados diretamente com a chave KMS?

a) KMS não suporta criptografia de arquivos grandes
b) Performance e custo: KMS é chamado apenas para criptografar/descriptografar o DEK, não para cada byte; o DEK local criptografa os dados com AES-256 de forma mais eficiente
c) KMS tem limite de 64 KB por operação; o DEK permite arquivos maiores
d) A e C

**Gabarito: D** — KMS tem limite de 64 KB por operação de encrypt/decrypt (para uso direto). Para dados maiores, usa-se o padrão DEK: KMS gera um DEK de 256 bits, que é usado localmente (AES-GCM) para criptografar os dados. Além do limite de tamanho, há também benefício de performance e custo: milhões de operações de criptografia de dados usam apenas uma chamada KMS (para o DEK), em vez de milhões de chamadas KMS.

---

**3.** O Amazon Macie encontrou 1.247 números de cartão de crédito no bucket `meridian-uploads-clientes` em um arquivo CSV. O arquivo está criptografado com KMS e o bucket não é público. Qual é a severidade do achado e quais ações são necessárias?

a) Baixa severidade — arquivo está criptografado e não é público
b) Alta severidade — presença de dados de cartão em bucket de uploads requer remediação mesmo com criptografia
c) Média severidade — apenas notificar o time de desenvolvimento
d) Nenhuma ação necessária — KMS garante proteção completa

**Gabarito: B** — Dados PCI (números de cartão) devem existir APENAS em sistemas certificados PCI DSS, com controles específicos. Um bucket de uploads genérico não é o local correto. Ações: (1) Verificar se os dados são legítimos ou um erro de processo. (2) Se legítimos, mover para ambiente PCI-certificado ou mascarar/tokenizar. (3) Implementar controles de prevenção de DLP. (4) Verificar se outros arquivos têm dados similares. (5) Reportar ao DPO e responsável por PCI. A criptografia protege contra acesso não autorizado mas não resolve o problema de scoping PCI.

---

**4.** Qual é a diferença entre S3 Object Lock modo Governance e modo Compliance em relação ao BACEN 4.893?

a) São equivalentes para fins de conformidade BACEN
b) Modo Compliance é necessário para cumprir a exigência de imutabilidade de logs do BACEN, pois nem root pode remover objetos; Governance permite exceções
c) Modo Governance é mais restritivo que Compliance
d) BACEN 4.893 não especifica qual modo usar

**Gabarito: B** — BACEN 4.893 Art. 7 exige que logs de segurança sejam mantidos por no mínimo 5 anos (recomendamos 7 anos para alinhamento com outras regulações). Para garantir que um administrador comprometido ou mal-intencionado não possa deletar logs antes do prazo, o modo Compliance é necessário. Em modo Compliance, nem a conta root consegue deletar um objeto antes do final do retention period — a única opção é fechar a conta AWS (destruição total). Isso é exatamente a garantia de imutabilidade que a regulação exige.

---

**5.** Um desenvolvedor do Banco Meridian armazenou uma chave de API do parceiro de pagamentos diretamente no código-fonte em um repositório Git privado. Descreva o processo correto e como migrar para Secrets Manager.

a) Manter no Git privado é suficiente — nenhuma ação necessária
b) Revogar a chave exposta, criar nova, migrar para Secrets Manager e atualizar a aplicação para usar GetSecretValue
c) Mover o arquivo .env para um bucket S3 privado
d) Criptografar o arquivo com GPG e commitar o arquivo criptografado

**Gabarito: B** — Processo correto: (1) IMEDIATAMENTE: revogar a chave exposta no parceiro de pagamentos — tratar como comprometida mesmo em repo privado (ex-colaboradores, acidente de fork público, vazamento de credenciais Git). (2) Gerar nova chave no parceiro. (3) Criar segredo no Secrets Manager: `aws secretsmanager create-secret --name "meridian/prod/partner/pagamentos-apikey" --secret-string '{"api_key":"nova_chave","api_secret":"..."}'`. (4) Atualizar código para usar SDK: `secrets_client.get_secret_value(SecretId='meridian/prod/partner/pagamentos-apikey')`. (5) Remover a chave do código e do histórico Git (`git filter-repo`). (6) Configurar rotação automática ou lembrete de rotação manual.

---

## 9. Roteiro de Gravação

### Aula 6.1 — KMS e Secrets Manager (50 min)

**Abertura (2 min):**
"Boa tarde! No módulo de hoje, proteção de dados. Se os módulos anteriores foram sobre ver e detectar, hoje é sobre proteger. Criptografia é a última linha de defesa: se o atacante vaza os dados mas eles estão criptografados com chaves que ele não tem, os dados são inúteis para ele. KMS e Secrets Manager são os pilares dessa estratégia no Banco Meridian."

**Bloco 1 — KMS Deep Dive (15 min):**
"[Abrir console KMS]

Vou criar uma CMK para os dados de transações do Banco Meridian. Mas primeiro, a pergunta: por que não usar a AWS Managed Key que já existe?

Três razões: (1) Sem controle da key policy — você não pode dar acesso cross-account ou condicionar o uso por VPC Endpoint. (2) Rotação a cada 3 anos em vez de 1 ano. (3) Sem possibilidade de desabilitar ou agendar exclusão.

[Criar CMK ao vivo — tipo Symmetric, Single-Region]

Key policy — vou prestar atenção especial aqui. [Mostrar o editor de key policy]

Separo claramente dois tipos de identidades: administradores (podem gerenciar a chave) e usuários (podem apenas usar para criptografar/descriptografar). A identidade da aplicação (EC2 role, Lambda role) deve ser usuário, nunca administrador.

[Mostrar o Deny de ScheduleKeyDeletion sem MFA]

Esse statement é crítico: ninguém pode agendar exclusão da chave sem MFA. KMS deletion tem uma janela de 7-30 dias — se alguém deleta sua chave, todos os dados criptografados com ela ficam inacessíveis para sempre. Proteção por MFA é obrigatória."

**Bloco 2 — Envelope Encryption na Prática (10 min):**
"[Mostrar diagrama do padrão DEK]

Na prática, você raramente chama kms:Encrypt diretamente. Os serviços AWS fazem o envelope encryption por você: RDS usa o DEK internamente, S3 usa o DEK internamente.

Mas quando você criptografa dados no código de aplicação (ex: criptografar um campo específico antes de salvar no DynamoDB), você faz o envelope encryption manualmente:

[Mostrar código Python de envelope encryption com KMS]"

**Bloco 3 — Secrets Manager vs Parameter Store (10 min):**
"[Mostrar tabela de comparação]

A dúvida mais comum: quando usar Secrets Manager e quando usar Parameter Store?

Regra de ouro: se tem rotação automática ou se é uma senha de banco de dados de produção → Secrets Manager. Se é uma string de configuração não sensível ou flag de feature → Parameter Store Standard (gratuito).

[Demo ao vivo] Criar o segredo de RDS no Secrets Manager:
1. Secrets Manager — Store a new secret
2. Tipo: RDS database credentials
3. Selecionar o cluster RDS de transações
4. Habilitar rotação automática — 30 dias
5. Lambda de rotação: criar automaticamente

O Secrets Manager já sabe como rotacionar credenciais do RDS — ele chama um Lambda específico para cada engine (MySQL, PostgreSQL, etc.)."

**Bloco 4 — Demonstração de Rotação (13 min):**
"[Demo ao vivo — Force rotation]

Vou forçar uma rotação imediata para mostrar o processo:
`aws secretsmanager rotate-secret --secret-id meridian/prod/rds/transacoes-senha --rotate-immediately`

[Acompanhar no CloudTrail em tempo real]

1. Secrets Manager chama a Lambda de rotação
2. Lambda gera nova senha
3. Lambda conecta ao RDS e muda a senha
4. Lambda testa a nova senha
5. Secrets Manager move AWSPENDING para AWSCURRENT

A aplicação não sabe que nada aconteceu — ela sempre busca AWSCURRENT. Zero downtime. Zero mudança de código. Zero intervenção manual.

[Mostrar no console] A rotação foi completada. Vejo duas versões: AWSCURRENT (nova senha) e AWSPREVIOUS (senha anterior, mantida por 24h para rollback)."

**Fechamento (0 min):**
"Na próxima aula: CloudHSM para casos de uso financeiros avançados, Macie para descoberta de dados sensíveis, e S3 security completo."

---

### Aula 6.2 — CloudHSM, Macie e S3 Security (50 min)

**Abertura (2 min):**
"Boa tarde! Continuando com proteção de dados. Hoje vemos CloudHSM — para casos onde KMS não é suficiente — Macie para descoberta de dados sensíveis em S3, e as configurações de segurança do S3 que todo security engineer precisa conhecer."

**Bloco 1 — CloudHSM (12 min):**
"CloudHSM é para quando seus requisitos regulatórios exigem mais do que o KMS pode oferecer. FIPS 140-2 Level 3, hardware dedicado, nenhum funcionário da AWS com acesso às suas chaves.

[Mostrar diagrama de CloudHSM cluster]

O CloudHSM funciona em cluster com pelo menos 2 HSMs em AZs diferentes para HA. A chave NUNCA sai do hardware. Você interage via PKCS#11 ou JCE.

Para o Banco Meridian, os casos de uso são: CA raiz interna (emitir certificados para servidores internos), TLS offload (chave privada do certificado wildcard nunca no servidor web), e possivelmente geração de chaves de sessão EMV para o módulo de cartão.

O custo é significativo: ~$1.50/hora por HSM, mínimo 2 HSMs = ~$2.200/mês. Justificável apenas para casos críticos regulatórios."

**Bloco 2 — Amazon Macie (18 min):**
"[Habilitar Macie ao vivo — demo]

Macie — Enable Macie — Enable

Agora vou criar um discovery job para analisar os buckets de dados de clientes do Banco Meridian:
[Criar job conforme código do módulo]

[Mostrar resultado de exemplo — achado de PCI data]

Olhem esse finding: 1.247 números de cartão de crédito em um CSV. O arquivo está criptografado com KMS e o bucket não é público. Mas isso ainda é um problema: dados PCI devem estar apenas em sistemas certificados PCI. Esse bucket de uploads genérico não passou por audit PCI.

[Mostrar integração com Security Hub]

Os findings do Macie aparecem automaticamente no Security Hub como HIGH. A equipe de compliance usa o Security Hub para ver o status de conformidade PCI/LGPD em tempo real.

[Mostrar a lista de managed data identifiers do Macie]
Macie vem com 100+ identificadores gerenciados: CPF, RG, CNH, números de conta bancária, CNPJ, emails, IPs. Para dados regulados pelo BACEN e LGPD, está bem coberto out-of-the-box."

**Bloco 3 — S3 Security Completo (10 min):**
"[Mostrar as 3 camadas de segurança do S3]

Camada 1 — Block Public Access: habilitar no nível da conta. Isso cria um escudo para todos os buckets. Mesmo que alguém crie um bucket com política pública, o Block Public Access da conta bloqueia.

[Demo ao vivo] S3 → Block Public Access settings for this account → Edit → habilitar todos os 4

Camada 2 — Object Lock: para buckets de logs e compliance. Modo Compliance, retenção de 7 anos.

Camada 3 — Encryption: default encryption com KMS CMK. Qualquer objeto sem cabeçalho de criptografia é automaticamente criptografado com a chave padrão do bucket.

[Combinar com SCP] A SCP DenyUnencryptedS3 que criamos no Módulo 1 + a default encryption do bucket = dupla proteção: SCP bloqueia PUT sem criptografia, mas se alguém tentasse via console sem criptografia explícita, a default encryption do bucket ainda aplicaria automaticamente."

**Bloco 4 — Consolidação Regulatória (8 min):**
"[Mostrar tabela de compliance]

Para o Banco Meridian, mapeamos cada serviço de proteção de dados para a regulação correspondente: BACEN 4.893, LGPD, PCI DSS.

O ponto que quero reforçar: criptografia é necessária mas não suficiente. O regulator quer ver:
1. Inventário de onde estão os dados sensíveis (Macie)
2. Controles de acesso apropriados (IAM + bucket policies)
3. Criptografia com chaves gerenciadas (KMS CMK)
4. Imutabilidade de logs de auditoria (Object Lock Compliance)
5. Rotação de chaves e credenciais (KMS rotation + Secrets Manager)

Esses 5 pontos cobrem os principais requisitos de proteção de dados do BACEN e LGPD."

---

## 10. Avaliação do Módulo

**Questão 1 (2 pontos):** Explique o conceito de envelope encryption e por que o SDK AWS usa esse padrão internamente ao criptografar dados com KMS.

**Gabarito:** Envelope encryption usa duas chaves: a CMK do KMS (chave mestra) e um DEK (Data Encryption Key) gerado localmente. Processo: (1) Chamada `GenerateDataKey` ao KMS retorna o DEK em plaintext e em ciphertext (criptografado com a CMK). (2) O DEK plaintext é usado localmente para criptografar os dados (AES-256). (3) O DEK plaintext é descartado da memória. (4) O DEK ciphertext é armazenado junto aos dados criptografados. (5) Para descriptografar: enviar DEK ciphertext ao KMS (`Decrypt`) para obter DEK plaintext, usar DEK para descriptografar os dados. Razões para esse padrão: (a) KMS tem limite de 64KB por operação — não serve para dados grandes. (b) Performance: uma chamada KMS por "envelope" em vez de por byte. (c) Custo: menos API calls ao KMS.

---

**Questão 2 (2 pontos):** O Banco Meridian quer garantir que as credenciais do banco de dados de produção sejam rotacionadas automaticamente e que, em caso de comprometimento, a credencial antiga seja invalidada em menos de 1 hora. Descreva como configurar isso com Secrets Manager.

**Gabarito:** (1) Criar segredo no Secrets Manager com credenciais do RDS. (2) Habilitar rotação automática com período desejado (ex: 30 dias). (3) Para invalidação em menos de 1 hora em caso de comprometimento: criar uma automação via Lambda + CloudWatch Events que, ao receber alerta de comprometimento, chama `rotate-secret --rotate-immediately`. A rotação forçada invalida a senha atual no RDS e gera uma nova em segundos. (4) Configurar alertas de CloudTrail para acessos ao segredo de IPs suspeitos. (5) Opcionalmente: configurar rotação a cada `immediateReplacement=true` via força — o Secrets Manager pode ser configurado com dual-user rotation onde o usuário antigo é desabilitado ao finalizar a rotação (em vez de mantido como AWSPREVIOUS por 24h).

---

**Questão 3 (2 pontos):** Qual é o risco de usar `s3:BypassGovernanceRetention` de forma excessiva e como mitigar esse risco?

**Gabarito:** O risco: se muitos usuários/roles têm `s3:BypassGovernanceRetention`, o modo Governance se torna equivalente a não ter Object Lock — qualquer usuário privilegiado pode excluir objetos antes do prazo. Mitigações: (1) Conceder `BypassGovernanceRetention` APENAS para a role de emergência de IR, não para administradores regulares. (2) Exigir MFA para exercer essa permissão via condição IAM. (3) Criar alarme CloudTrail para qualquer uso de BypassGovernanceRetention. (4) Para logs de auditoria BACEN, usar modo Compliance em vez de Governance — BypassGovernanceRetention não funciona em modo Compliance. (5) Auditar trimestralmente quem tem essa permissão.

---

**Questão 4 (2 pontos):** O Amazon Macie identificou dados de CPF em um bucket de resultados de laboratório. Os dados estão mascarados (ex: `***-456-789-**`). Isso ainda é considerado dado pessoal pela LGPD?

**Gabarito:** Sim, dependendo do mascaramento. A LGPD define "dado pessoal" como informação que se refere a pessoa natural identificada ou identificável. Um CPF parcialmente mascarado (`***-456-789-**`) pode ser reidentificável quando combinado com outros dados no mesmo registro (nome, data de nascimento, email). O conceito de pseudonimização da LGPD (Art. 13) exige que o dado não possa ser associado ao titular sem uso de informação adicional mantida separadamente. Mascaramento simples não atende a pseudonimização completa. Macie pode identificar padrões de mascaramento parcial. O correto para uso analítico: tokenização (substituir CPF por token não reversível) ou anonimização completa (impossibilidade de reidentificação).

---

**Questão 5 (2 pontos):** Qual é o impacto de habilitar S3 Object Lock em modo Compliance ANTES de carregar objetos vs habilitar após?

**Gabarito:** Object Lock (ambos os modos) só pode ser habilitado em buckets NOVOS (criados com Object Lock ativo) ou em buckets existentes com versioning habilitado ANTES de qualquer objeto. Para objetos JÁ existentes no bucket: Object Lock não se aplica retroativamente — objetos existentes sem lock podem ser excluídos normalmente. Para garantir proteção de TODOS os objetos: (1) Criar novo bucket com Object Lock habilitado em modo Compliance. (2) Copiar todos os objetos existentes para o novo bucket. (3) Os objetos copiados agora têm Object Lock aplicado. (4) Deletar o bucket antigo após verificar integridade. Implicação para o Banco Meridian: se o bucket de logs já existe, o processo de migração deve ser planejado cuidadosamente para garantir continuidade e integridade.
