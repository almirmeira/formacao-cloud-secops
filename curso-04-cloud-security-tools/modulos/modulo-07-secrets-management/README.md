# Módulo 07 — Secrets Management com HashiCorp Vault
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2h videoaulas + 2h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 3 e 6 / CCSK domínio 7  
> **Cenário:** CTO do Banco Meridian quer eliminar credenciais estáticas dos microserviços

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Arquitetar uma solução de secrets management com HashiCorp Vault
2. Configurar secret engines (KV v2, database, PKI, AWS)
3. Implementar AppRole auth method para autenticação de aplicações
4. Configurar dynamic secrets com PostgreSQL (credenciais com TTL)
5. Integrar Vault com Kubernetes via External Secrets Operator
6. Escolher entre Vault e cloud-native alternatives (AWS Secrets Manager, Azure Key Vault)

---

## 1. Por Que Secrets Management É Crítico

### 1.1 O Problema do Hardcoded Secret

```
CENÁRIO REAL — BANCO MERIDIAN (ANTES DO VAULT)
──────────────────────────────────────────────────────────────────────────────
# docker-compose.yml em repositório GitHub (público por engano)
version: '3.8'
services:
  api-pagamentos:
    image: bancomeridian/api-pagamentos:latest
    environment:
      DB_PASSWORD: "P@ssw0rd_Banco_2024!"         # HARDCODED
      AWS_SECRET_KEY: "wJalrXUtnFEMI/K7MDENG/..."  # HARDCODED
      PAYMENT_API_KEY: "sk_live_abc123xyz..."        # HARDCODED
      REDIS_PASSWORD: "redis_secret_123"             # HARDCODED

Problema: esse arquivo foi commitado no git às 14h de sexta-feira.
GitHub Secret Scanning detectou em 30 segundos.
Mas bots de crawling já haviam capturado as credenciais em < 1 minuto.
Resultado: chamada do CTO às 16h com rotação emergencial de todas as credenciais.
Custo: ~8 horas de downtime + 3 dias de análise forense.
──────────────────────────────────────────────────────────────────────────────
```

**Por que esse problema é estrutural, não humano:**
- Senhas estáticas sobrevivem em backups, git history, logs de CI/CD, variáveis de ambiente exportadas acidentalmente
- Rotação manual é propensa a erros e frequentemente negligenciada
- Auditoria de uso é impossível sem logs centralizados
- Um único compromisso de credencial acessa o sistema indefinidamente

**A solução de vault resolve:**
- Credenciais dinâmicas: cada aplicação recebe credenciais únicas com TTL
- Rotação automática: credenciais expiram e são regeneradas automaticamente
- Auditoria completa: todo acesso a segredos é logado com identidade, timestamp e IP
- Least privilege: cada aplicação acessa apenas os segredos que precisa

---

## 2. HashiCorp Vault — Arquitetura Completa

### 2.1 Visão Geral

```
ARQUITETURA VAULT — BANCO MERIDIAN
──────────────────────────────────────────────────────────────────────────────
                         ┌──────────────────────────────┐
                         │      VAULT SERVER (CLUSTER)   │
                         │                               │
  APLICAÇÕES             │  ┌─────────────────────────┐  │
  ┌──────────┐           │  │    Auth Methods           │  │
  │  Lambda  │──────────▶│  │  - AppRole (aplicações)  │  │
  │  API     │           │  │  - Kubernetes (pods K8s)  │  │
  │  K8s Pod │           │  │  - AWS IAM (EC2, Lambda)  │  │
  └──────────┘           │  │  - OIDC/JWT (CI/CD)       │  │
                         │  └─────────────────────────┘  │
  OPERADORES             │                               │
  ┌──────────┐           │  ┌─────────────────────────┐  │
  │ DevOps   │──────────▶│  │    Secret Engines         │  │
  │ DBA      │           │  │  - KV v2 (estático)       │  │
  └──────────┘           │  │  - Database (dinâmico)    │  │
                         │  │  - PKI (certificados)     │  │
  CI/CD                  │  │  - SSH (OTP e CA)         │  │
  ┌──────────┐           │  │  - AWS (cred dinâmicas)   │  │
  │ GitHub   │──────────▶│  └─────────────────────────┘  │
  │ Actions  │           │                               │
  └──────────┘           │  ┌─────────────────────────┐  │
                         │  │    Policies (HCL)         │  │
                         │  │  - path-based ACLs        │  │
                         │  │  - capabilities           │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  ┌─────────────────────────┐  │
                         │  │    Storage Backend        │  │
                         │  │  - Raft (integrated)      │  │
                         │  │  - Consul                 │  │
                         │  │  - DynamoDB (AWS)         │  │
                         │  └─────────────────────────┘  │
                         └──────────────────────────────┘
──────────────────────────────────────────────────────────────────────────────
```

### 2.2 Secret Engines

**KV v2 (Key-Value versioned):**

**O que este comando faz:** Instala o Vault, inicia em modo de desenvolvimento (armazenamento em memória, sem TLS, sem autenticação real), habilita o secret engine KV v2 em um path nomeado e demonstra as operações básicas de escrita, leitura, versionamento e rollback de segredos.
**Por que isso importa:** O KV v2 é o ponto de entrada do Vault — substitui diretamente as variáveis de ambiente e arquivos `.env` hardcoded dos microserviços do Banco Meridian. Com versionamento automático, a equipe pode rastrear quem alterou qual segredo e quando, e reverter para uma versão anterior em caso de configuração incorreta — algo impossível com senhas hardcoded em repositórios.

```bash
# Instalar Vault
# macOS
brew tap hashicorp/tap && brew install hashicorp/tap/vault

# Linux
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Iniciar Vault em modo dev (apenas para laboratório — nunca em produção)
vault server -dev -dev-root-token-id="dev-root-token" &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-root-token'

# --- KV v2 Secret Engine ---

# Habilitar KV v2 em um path específico
vault secrets enable -path=bancomeridian kv-v2

# Escrever um secret
vault kv put bancomeridian/api-pagamentos/config \
  db_host=postgres.bancomeridian.internal \
  db_name=pagamentos \
  db_username=api_pagamentos \
  db_password=SenhaTemporariaAteConfigurarDynamicSecrets

# Ler um secret
vault kv get bancomeridian/api-pagamentos/config

# Ler um campo específico
vault kv get -field=db_password bancomeridian/api-pagamentos/config

# Versionar — escrever nova versão
vault kv put bancomeridian/api-pagamentos/config \
  db_host=postgres.bancomeridian.internal \
  db_name=pagamentos \
  db_username=api_pagamentos \
  db_password=NovaSenha2025!

# Listar versões
vault kv metadata get bancomeridian/api-pagamentos/config

# Restaurar versão anterior
vault kv rollback -version=1 bancomeridian/api-pagamentos/config

# Deletar permanentemente (sem possibilidade de recuperação)
vault kv destroy -versions=1 bancomeridian/api-pagamentos/config
vault kv metadata delete bancomeridian/api-pagamentos/config
```

**Database Secret Engine (Dynamic Secrets com PostgreSQL):**

**O que este comando faz:** Habilita o secret engine de banco de dados, configura a conexão do Vault com o PostgreSQL usando um usuário administrador dedicado (`vault_manager`), e cria roles que definem quais permissões SQL serão concedidas dinamicamente e por quanto tempo — 1 hora para a API de leitura e 8 horas para o serviço de transações.
**Por que isso importa:** Este é o coração da solução para o Banco Meridian. Ao invés de ter uma senha estática `BancoMeridian@2024!` sem rotação há 18 meses, cada instância da API agora recebe um usuário PostgreSQL único com expiração de 1 hora. Se um container for comprometido às 14h, o atacante tem credenciais válidas apenas até as 15h — e o Vault já terá gerado novas credenciais para o próximo container. A superfície de ataque de "permanente" passa para "máximo 1 hora".

```bash
# --- DATABASE SECRET ENGINE ---
# Este é o diferencial principal do Vault em relação a KV simples:
# credenciais são geradas dinamicamente a cada request, com TTL configurado.
# Cada aplicação (e cada request) recebe credenciais únicas e temporárias.

# 1. Habilitar o database secret engine
vault secrets enable database

# 2. Configurar a conexão com PostgreSQL
vault write database/config/bancomeridian-postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly-pagamentos,readwrite-pagamentos,admin-dba" \
  connection_url="postgresql://{{username}}:{{password}}@postgres.bancomeridian.internal:5432/pagamentos?sslmode=require" \
  username="vault_manager" \
  password="VaultManagerSecurePassword!" \
  max_open_connections=5 \
  max_idle_connections=2

# 3. Criar role de banco de dados — readonly para a API
# O Vault vai executar este SQL quando gerar credenciais para essa role
vault write database/roles/readonly-pagamentos \
  db_name=bancomeridian-postgres \
  creation_statements="
    CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
  " \
  revocation_statements="
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";
    DROP ROLE IF EXISTS \"{{name}}\";
  " \
  default_ttl="1h" \
  max_ttl="24h"

# 4. Criar role com escrita para o serviço de transações
vault write database/roles/readwrite-transacoes \
  db_name=bancomeridian-postgres \
  creation_statements="
    CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
    GRANT SELECT, INSERT, UPDATE ON transacoes TO \"{{name}}\";
    GRANT SELECT ON clientes TO \"{{name}}\";
  " \
  revocation_statements="REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="8h"

# 5. Gerar credencial dinâmica (o que a aplicação faz)
vault read database/creds/readonly-pagamentos
# Output:
# Key                Value
# ---                -----
# lease_id           database/creds/readonly-pagamentos/abc123xyz
# lease_duration     1h
# lease_renewable    true
# password           A1b2C3d4-generada-pelo-vault
# username           v-role-readonly-pagamentos-abc123-1714000000

# A aplicação usa essas credenciais por no máximo 1h
# Após 1h: credenciais expiram e o Vault as revoga no PostgreSQL

# 6. Renovar lease (se a aplicação ainda precisar)
vault lease renew database/creds/readonly-pagamentos/abc123xyz

# 7. Revogar credencial imediatamente (ex: suspeita de comprometimento)
vault lease revoke database/creds/readonly-pagamentos/abc123xyz
```

**PKI Secret Engine (CA e Certificados):**

**O que este comando faz:** Configura o Vault como uma Autoridade Certificadora (CA) interna completa — cria a CA raiz, emite e assina uma CA intermediária, define roles de emissão restritas ao domínio `bancomeridian.internal`, e emite certificados TLS com TTL de 24 horas para microsserviços específicos.
**Por que isso importa:** Para o Banco Meridian implementar mTLS entre microsserviços (exigência crescente para conformidade com BACEN e padrões Zero Trust), cada serviço precisa de um certificado. Com o PKI engine, o ciclo de vida desses certificados é totalmente automatizado — o `api-pagamentos` solicita seu próprio certificado com validade de 24 horas, e o Vault o emite e revoga sem intervenção humana. Isso elimina a gestão manual de certificados que frequentemente resulta em certificados expirados que derrubam serviços em produção.

```bash
# --- PKI SECRET ENGINE ---
# Vault como CA interna: emite certificados TLS/mTLS com TTL configurado

# 1. Habilitar PKI
vault secrets enable pki

# 2. Configurar CA raiz
vault write pki/root/generate/internal \
  common_name="BancoMeridian Internal CA" \
  ttl="87600h" \
  organization="Banco Meridian" \
  country="BR" \
  locality="São Paulo" \
  province="SP"

# 3. Criar CA intermediária
vault secrets enable -path=pki_int pki

vault write -format=json pki_int/intermediate/generate/internal \
  common_name="BancoMeridian Intermediate CA" | jq -r '.data.csr' > pki_intermediate.csr

vault write -format=json pki/root/sign-intermediate \
  csr=@pki_intermediate.csr \
  format=pem_bundle \
  ttl="43800h" | jq -r '.data.certificate' > intermediate.cert.pem

vault write pki_int/intermediate/set-signed \
  certificate=@intermediate.cert.pem

# 4. Criar role para emissão de certificados
vault write pki_int/roles/bancomeridian-services \
  allowed_domains="bancomeridian.internal,svc.cluster.local" \
  allow_subdomains=true \
  max_ttl="720h" \
  require_cn=false

# 5. Emitir certificado para um serviço
vault write pki_int/issue/bancomeridian-services \
  common_name="api-pagamentos.bancomeridian.internal" \
  ttl="24h"
```

**AWS Secret Engine (Dynamic AWS Credentials):**

**O que este comando faz:** Configura o Vault para gerar credenciais AWS temporárias dinamicamente — ao invés de criar um IAM User com chave de acesso permanente, o Vault cria um IAM User temporário com a política especificada, retorna as credenciais, e após o TTL configura o usuário temporário é deletado automaticamente.
**Por que isso importa:** No Banco Meridian, pipelines de CI/CD e scripts de automação frequentemente usam chaves AWS estáticas (`AKIA...`) que ficam em variáveis de ambiente por anos. Com o AWS Secret Engine, cada execução do pipeline recebe credenciais únicas que expiram em minutos — se uma credencial vazar em logs de CI/CD (acontece com frequência), ela já terá expirado antes que qualquer atacante possa utilizá-la.

```bash
# --- AWS SECRET ENGINE ---
# Vault gera credenciais AWS temporárias com TTL configurado
# Melhor alternativa a IAM users com chaves estáticas

# 1. Habilitar o AWS secret engine
vault secrets enable aws

# 2. Configurar credenciais do Vault para gerenciar IAM
vault write aws/config/root \
  access_key="AKIA..." \
  secret_key="..." \
  region="us-east-1"

# 3. Criar role que mapeia para uma IAM policy
vault write aws/roles/s3-readonly \
  credential_type=iam_user \
  policy_document='{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::bancomeridian-dados", "arn:aws:s3:::bancomeridian-dados/*"]
    }]
  }'

# 4. Gerar credencial AWS dinâmica
vault read aws/creds/s3-readonly
# Retorna: access_key, secret_key, security_token temporários
# O Vault cria automaticamente um IAM User temporário com a policy especificada
# Após o TTL, o Vault deleta o IAM User automaticamente
```

**SSH Secret Engine:**

**O que este comando faz:** Configura o Vault como emissor de OTPs (One-Time Passwords) para SSH — ao invés de distribuir chaves SSH estáticas para todos os servidores, cada sessão SSH usa uma senha de 16 caracteres válida por 30 minutos para um único acesso a um host específico.
**Por que isso importa:** Chaves SSH estáticas distribuídas pelos servidores do Banco Meridian são outro vetor de standing access. Se um desenvolvedor deixa a empresa, há 50 servidores onde sua chave pública precisa ser removida manualmente — e frequentemente não é. Com SSH OTP, cada acesso requer uma nova solicitação ao Vault, criando um audit trail completo: quem acessou qual servidor, quando, e com qual justificativa.

```bash
# --- SSH SECRET ENGINE (OTP mode) ---
# Vault como OTP (One-Time Password) para SSH
# Elimina chaves SSH estáticas em produção

vault secrets enable ssh

vault write ssh/roles/otp-key-role \
  key_type=otp \
  default_user=ubuntu \
  cidr_list="10.0.0.0/8"

# Gerar OTP para acesso a servidor específico
vault write ssh/creds/otp-key-role \
  username=ubuntu \
  ip=10.0.1.50
# Retorna: key (OTP de 16 chars), válida por 30 minutos para um único acesso
```

### 2.3 Auth Methods

**Token Auth (built-in, não recomendado para produção):**

**O que este comando faz:** Cria tokens Vault com política específica e TTL configurado. A variante `orphan` cria tokens que sobrevivem à expiração do token pai, útil para aplicações de longa duração.
**Por que isso importa:** Token auth é o mecanismo mais simples e o menos seguro para aplicações em produção — um token roubado concede acesso diretamente. No Banco Meridian, tokens só devem ser usados para acesso administrativo humano com MFA, nunca para autenticação de aplicações que devem usar AppRole ou Kubernetes auth.

```bash
# Criar token com política específica
vault token create -policy="api-pagamentos-policy" -ttl="1h"

# Criar token com renovação (orphan token)
vault token create -policy="api-pagamentos-policy" -ttl="24h" -period="24h" -orphan
```

**AppRole Auth (para aplicações em produção):**

**O que este comando faz:** Habilita o AppRole auth method e cria uma role para a aplicação `api-pagamentos`. O Role ID é público e identifica a aplicação; o Secret ID é efêmero (10 minutos) e é injetado pelo CI/CD no momento do deploy. A combinação dos dois gera um token Vault com as permissões necessárias.
**Por que isso importa:** O AppRole resolve o "bootstrap problem" de autenticação: como uma aplicação prova sua identidade ao Vault sem já ter uma credencial? A solução é dois fatores — o Role ID (o que a aplicação é, análogo ao username) + o Secret ID efêmero (prova de que está no ambiente correto, injetado pelo CI/CD com TTL de minutos). No Banco Meridian, isso garante que nem mesmo um desenvolvedor com acesso ao código da aplicação consegue autenticar no Vault sem o Secret ID que o CI/CD injeta em tempo de deploy.

```bash
# 1. Habilitar AppRole auth method
vault auth enable approle

# 2. Criar role para a aplicação
vault write auth/approle/role/api-pagamentos \
  role_name=api-pagamentos \
  secret_id_ttl=10m \       # secret_id expira em 10 min (short-lived para CI/CD)
  token_num_uses=10 \        # token pode ser usado no máximo 10 vezes
  token_ttl=20m \            # token expira em 20 min
  token_max_ttl=30m \        # máximo possível com renovação
  token_policies=api-pagamentos-policy

# 3. Obter Role ID (público, pode estar no repositório)
vault read auth/approle/role/api-pagamentos/role-id
# role_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# 4. Gerar Secret ID (privado, injetado pelo CI/CD ou vault-agent)
vault write -f auth/approle/role/api-pagamentos/secret-id
# secret_id: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
# secret_id_accessor: "zzzzzzzz-..."
# secret_id_ttl: 10m0s

# 5. Aplicação autentica com Role ID + Secret ID
vault write auth/approle/login \
  role_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  secret_id="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
# Retorna: client_token, lease_duration, token_policies

# 6. Aplicação usa o token para acessar secrets
VAULT_TOKEN="s.XXXXXXXXXXXXXXXXXX"
vault kv get bancomeridian/api-pagamentos/config
```

**Kubernetes Auth Method:**

**O que este comando faz:** Configura o Vault para aceitar a ServiceAccount token do Kubernetes como prova de identidade. Quando um pod com `serviceAccountName: api-pagamentos-sa` se autentica, o Vault verifica o token com a API do Kubernetes e — se o pod realmente está no namespace `production` — concede as permissões da policy `api-pagamentos-policy`.
**Por que isso importa:** No Kubernetes do Banco Meridian, cada pod já tem uma identidade nativa (ServiceAccount). O Kubernetes auth elimina a necessidade de gerenciar Role IDs e Secret IDs para pods — o Vault valida a identidade diretamente com a API do cluster. Isso significa zero configuração de credenciais nos containers: o pod "nasce" com acesso aos secrets que precisa, sem hardcoding e sem injeção manual de segredos pelo CI/CD.

```bash
# 1. Habilitar Kubernetes auth
vault auth enable kubernetes

# 2. Configurar com as informações do cluster
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# 3. Criar role que mapeia ServiceAccount K8s → Vault policy
vault write auth/kubernetes/role/api-pagamentos \
  bound_service_account_names=api-pagamentos-sa \
  bound_service_account_namespaces=production \
  policies=api-pagamentos-policy \
  ttl=1h
```

**AWS IAM Auth:**

**O que este comando faz:** Configura o Vault para aceitar a identidade AWS IAM como prova de autenticação. Uma instância EC2 ou Lambda com a role `api-pagamentos-role` pode se autenticar no Vault usando a mesma identidade IAM que já possui — sem credenciais adicionais.
**Por que isso importa:** Para workloads rodando em EC2 ou Lambda no Banco Meridian, o AWS IAM auth elimina completamente a necessidade de gerenciar AppRole credentials. A instância "nasce" com uma IAM role que o Vault reconhece e aceita como identidade válida. O resultado é um ambiente onde nenhum secret precisa existir na configuração do workload para que ele acesse outros secrets — o círculo virtuoso do secrets management.

```bash
# 1. Habilitar AWS auth
vault auth enable aws

# 2. Configurar
vault write auth/aws/config/client \
  access_key="AKIA..." \
  secret_key="..."

# 3. Criar role para instâncias EC2 com uma IAM role específica
vault write auth/aws/role/api-pagamentos-ec2 \
  auth_type=iam \
  bound_iam_principal_arn="arn:aws:iam::123456789:role/api-pagamentos-role" \
  policies=api-pagamentos-policy \
  max_ttl=500h
```

### 2.4 Policies — HCL com Path-Based ACLs

**O que este código faz:** Define políticas Vault em HCL (HashiCorp Configuration Language) que especificam quais paths de secrets cada aplicação ou papel pode acessar, com quais capabilities. A política do `api-pagamentos` limita o acesso apenas aos seus próprios secrets; a política do DBA limita ao acesso de banco de dados.
**Por que isso importa:** As policies são o mecanismo de least privilege do Vault — cada aplicação vê apenas o que precisa. No Banco Meridian, a `api-pagamentos` não consegue ler secrets da `api-compliance` mesmo que ambas estejam autenticadas no mesmo Vault. Essa segmentação garante que um compromisso de uma aplicação não vaza os secrets de outras, e cada acesso a qualquer path é registrado no audit log para evidência de conformidade BACEN.

```hcl
# policies/api-pagamentos-policy.hcl
# Política para o serviço de API de Pagamentos
# Princípio de menor privilégio: acessa APENAS o que precisa

# Acesso ao KV com configuração da aplicação
path "bancomeridian/data/api-pagamentos/*" {
  capabilities = ["read"]
}

# Acesso a credenciais dinâmicas do banco de dados
path "database/creds/readonly-pagamentos" {
  capabilities = ["read"]
}

# Acesso a credenciais AWS para leitura do S3
path "aws/creds/s3-readonly" {
  capabilities = ["read"]
}

# Renovar leases das credenciais geradas
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Revogar o próprio token (para logout da aplicação)
path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# PROIBIDO (capabilities implicitamente negadas para tudo não listado)
# - Não pode acessar secrets de outros serviços
# - Não pode gerenciar políticas
# - Não pode criar tokens para outros
# - Não pode acessar o PKI engine
```

```hcl
# policies/dba-policy.hcl
# Política para DBAs — acesso via JIT (Just-In-Time)

# Credenciais de admin de banco (escrita para operações de manutenção)
path "database/creds/admin-dba" {
  capabilities = ["read"]
}

# Leitura de secrets de configuração de banco
path "bancomeridian/data/database/*" {
  capabilities = ["read", "list"]
}

# Não tem acesso a segredos de aplicação
# Não tem acesso a credenciais AWS
# Não tem acesso a PKI

# Audit obrigatório: qualquer acesso fica registrado no audit log
```

**O que este comando faz:** Aplica as políticas HCL no Vault, tornando-as efetivas para qualquer token ou AppRole que as referencie. `vault policy list` e `vault policy read` permitem auditar quais políticas existem e o que cada uma permite.
**Por que isso importa:** Policies como código — armazenadas em arquivos HCL no repositório Git — permitem ao Banco Meridian submeter mudanças de permissões ao mesmo processo de code review que o código da aplicação. Qualquer alteração de permissão passa por aprovação, gerando um audit trail de quem aprovou cada mudança de acesso.

```bash
# Aplicar políticas
vault policy write api-pagamentos-policy policies/api-pagamentos-policy.hcl
vault policy write dba-policy policies/dba-policy.hcl

# Listar políticas
vault policy list

# Ver política específica
vault policy read api-pagamentos-policy
```

### 2.5 Lease, Renewal e Revogação

**O que este comando faz:** Gerencia o ciclo de vida dos leases — identificadores de credenciais dinâmicas geradas pelo Vault. Permite listar leases ativos, verificar detalhes, renovar antes da expiração, revogar credenciais individuais e, em casos de incidente, revogar em massa todas as credenciais de uma role com o flag `-prefix`.
**Por que isso importa:** O `-prefix revoke` é a resposta do Banco Meridian a um incidente de segurança. Se o time de SecOps detectar que a role `readonly-pagamentos` foi comprometida, um único comando revoga instantaneamente todas as credenciais de banco ativas — seja 1 instância ou 500 pods rodando em paralelo. Isso transforma o MTTR (Mean Time to Respond) de "horas de rotação manual coordenada" para "segundos".

```bash
# Conceito: toda credencial dinâmica gerada pelo Vault tem um lease_id
# O lease define: quando a credencial expira e quando o Vault vai revogá-la

# Listar leases ativos
vault list sys/leases/lookup/database/creds/readonly-pagamentos/

# Ver detalhes de um lease específico
vault lease lookup database/creds/readonly-pagamentos/abc123

# Renovar um lease (se ainda dentro do max_ttl)
vault lease renew -increment=3600 database/creds/readonly-pagamentos/abc123

# Revogar imediatamente um lease específico (comprometimento de credencial)
vault lease revoke database/creds/readonly-pagamentos/abc123

# Revogar TODOS os leases de uma role (incidente de segurança)
vault lease revoke -prefix database/creds/readonly-pagamentos/

# Forçar rotação da senha do banco no Vault (substitui a senha do root do DB engine)
vault write -f database/rotate-root/bancomeridian-postgres
```

### 2.6 High Availability com Raft Integrated Storage

**O que este comando faz:** Define a configuração do cluster Vault com 3 nós usando Raft como backend de storage integrado. Os nós se descobrem automaticamente via `retry_join` e elegem um líder — os outros dois ficam em standby ativo prontos para assumir em menos de 30 segundos.
**Por que isso importa:** O Vault é infraestrutura crítica do Banco Meridian — se ele cair, nenhuma aplicação consegue obter credenciais e os serviços ficam indisponíveis. Com 3 nós Raft, o cluster tolera a falha de 1 nó sem interrupção (quórum de 2/3). Para conformidade com BACEN 4.893 que exige resiliência de sistemas críticos, o Vault HA é mandatório para ambientes de produção.

```yaml
# vault-ha.yaml — Deploy Vault HA no Kubernetes com Raft
# 3 nós Vault = quorum Raft
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: vault
data:
  vault.hcl: |
    ui = true
    disable_mlock = true

    listener "tcp" {
      address       = "0.0.0.0:8200"
      tls_cert_file = "/vault/tls/tls.crt"
      tls_key_file  = "/vault/tls/tls.key"
    }

    storage "raft" {
      path    = "/vault/data"
      node_id = "node-1"

      retry_join {
        leader_tls_servername = "vault-0.vault-internal"
        leader_api_addr       = "https://vault-0.vault-internal:8200"
      }
      retry_join {
        leader_tls_servername = "vault-1.vault-internal"
        leader_api_addr       = "https://vault-1.vault-internal:8200"
      }
      retry_join {
        leader_tls_servername = "vault-2.vault-internal"
        leader_api_addr       = "https://vault-2.vault-internal:8200"
      }
    }

    service_registration "kubernetes" {}

    telemetry {
      prometheus_retention_time = "30s"
      disable_hostname = true
    }
```

**O que este comando faz:** Faz o deploy do cluster Vault HA no Kubernetes usando o Helm chart oficial, inicializa o cluster (gerando as unseal keys e o root token), e faz o unseal dos 3 nós usando o esquema Shamir de 5 chaves com threshold de 3.
**Por que isso importa:** O processo de inicialização gera as unseal keys — o equivalente às chaves do cofre principal do Banco Meridian. Com o esquema 5-of-3, nenhum indivíduo sozinho pode abrir o Vault (previne insider threat) e o cluster ainda funciona se 2 key holders estiverem indisponíveis. As unseal keys devem ser armazenadas em HSM ou cofre físico com acesso controlado e auditado.

```bash
# Deploy Vault HA com Helm
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault \
  --namespace vault \
  --create-namespace \
  -f vault-values.yaml

# Inicializar o cluster Vault (apenas uma vez)
kubectl exec vault-0 -n vault -- vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json > vault-init-keys.json

# ARMAZENAR OS UNSEAL KEYS E ROOT TOKEN COM SEGURANÇA MÁXIMA
# (HSM, cofre físico ou AWS Secrets Manager criptografado)

# Unseal os 3 nós (usando 3 das 5 chaves)
for i in 0 1 2; do
  kubectl exec vault-$i -n vault -- vault operator unseal $(cat vault-init-keys.json | jq -r '.unseal_keys_b64[0]')
  kubectl exec vault-$i -n vault -- vault operator unseal $(cat vault-init-keys.json | jq -r '.unseal_keys_b64[1]')
  kubectl exec vault-$i -n vault -- vault operator unseal $(cat vault-init-keys.json | jq -r '.unseal_keys_b64[2]')
done
```

---

## 3. Integração Kubernetes com Vault

### 3.1 Vault Agent Injector

O Vault Agent Injector intercepta chamadas de criação de Pods no K8s e injeta automaticamente um sidecar Vault Agent que renderiza templates com os secrets.

**O que este manifesto faz:** Configura um Deployment Kubernetes com annotations do Vault Agent Injector que instruem o mutating webhook a injetar automaticamente um container sidecar `vault-agent` no pod. O sidecar se autentica no Vault via Kubernetes auth, busca as credenciais dinâmicas do banco e as configurações do KV, e as renderiza como arquivos de texto em um volume compartilhado que a aplicação principal lê como variáveis de ambiente.
**Por que isso importa:** A grande vantagem do Vault Agent Injector é que a aplicação principal `api-pagamentos` não precisa de nenhuma biblioteca do Vault no seu código — ela simplesmente lê variáveis de ambiente normais. Para o Banco Meridian, isso significa que aplicações legadas podem se beneficiar do Vault sem refatoração: basta adicionar as annotations ao Deployment e o sidecar cuida de tudo, incluindo a renovação automática das credenciais antes da expiração do TTL.

```yaml
# deployment-com-vault-agent.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-pagamentos
  namespace: production
spec:
  template:
    metadata:
      annotations:
        # Annotations que ativam o Vault Agent Injector
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "api-pagamentos"

        # Injetar credenciais do banco como arquivo
        vault.hashicorp.com/agent-inject-secret-db-credentials: "database/creds/readonly-pagamentos"
        vault.hashicorp.com/agent-inject-template-db-credentials: |
          {{- with secret "database/creds/readonly-pagamentos" -}}
          DB_USERNAME={{ .Data.username }}
          DB_PASSWORD={{ .Data.password }}
          {{- end }}

        # Injetar config da aplicação do KV
        vault.hashicorp.com/agent-inject-secret-app-config: "bancomeridian/data/api-pagamentos/config"
        vault.hashicorp.com/agent-inject-template-app-config: |
          {{- with secret "bancomeridian/data/api-pagamentos/config" -}}
          DB_HOST={{ .Data.data.db_host }}
          DB_NAME={{ .Data.data.db_name }}
          {{- end }}

        # Renovar automaticamente quando o lease estiver para expirar
        vault.hashicorp.com/agent-pre-populate-only: "false"

    spec:
      serviceAccountName: api-pagamentos-sa
      containers:
        - name: api
          image: bancomeridian/api-pagamentos:v1.2.0
          command: ["/bin/sh", "-c"]
          args:
            - |
              # Ler secrets injetados pelo Vault Agent como variáveis de ambiente
              export $(cat /vault/secrets/db-credentials | xargs)
              export $(cat /vault/secrets/app-config | xargs)
              # Iniciar a aplicação
              exec /app/api-pagamentos
```

### 3.2 External Secrets Operator (ESO)

ESO é a abordagem mais moderna — cria recursos `ExternalSecret` no Kubernetes que o operador converte em Kubernetes `Secret` nativos, sincronizando com o Vault.

**O que este comando faz:** Instala o External Secrets Operator no cluster via Helm. O ESO é um operador Kubernetes que fica em execução contínua, observando recursos `ExternalSecret` e `SecretStore`, e sincronizando automaticamente os secrets do Vault para `Secret` nativos do Kubernetes.
**Por que isso importa:** O ESO representa a evolução do modelo de integração Vault+K8s — ao invés de um sidecar por pod, existe um único operador central para todo o cluster. Para o Banco Meridian com dezenas de microserviços no Kubernetes, isso significa menos overhead de infraestrutura (sem containers sidecar em cada pod) e uma gestão centralizada de quais aplicações acessam quais secrets.

```bash
# Instalar External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true
```

**O que este manifesto faz:** Define um `SecretStore` que descreve como o ESO se conecta ao Vault (URL, path do KV engine, versão e método de autenticação via ServiceAccount Kubernetes), e um `ExternalSecret` que mapeia secrets específicos do Vault para um `Secret` nativo do Kubernetes, com renovação automática a cada 55 minutos (antes do TTL de 1 hora).
**Por que isso importa:** Com o ESO configurado, os desenvolvedores do Banco Meridian trabalham com recursos Kubernetes nativos (`Secret`) sem precisar conhecer a API do Vault. A separação de responsabilidades é clara: a equipe de segurança gerencia o Vault e as policies; a equipe de desenvolvimento usa `ExternalSecret` CRDs como qualquer outro recurso K8s. O ESO faz a ponte entre os dois mundos, garantindo que os pods sempre tenham credenciais frescas e válidas.

```yaml
# vault-secretstore.yaml — Define a conexão com o Vault
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.vault.svc.cluster.local:8200"
      path: "bancomeridian"      # Mount path do KV engine
      version: "v2"              # KV v2

      # Autenticação via Kubernetes ServiceAccount
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "api-pagamentos"
          serviceAccountRef:
            name: api-pagamentos-sa
```

```yaml
# external-secret-db.yaml — Sincroniza credenciais dinâmicas do banco
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  refreshInterval: 55m    # Sincroniza antes do TTL de 1h

  secretStoreRef:
    name: vault-backend
    kind: SecretStore

  target:
    name: api-pagamentos-db-secret    # Nome do Secret K8s criado
    creationPolicy: Owner

  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: VaultDynamicSecret
          name: vault-db-credentials

---
# Vault Dynamic Secret Generator
apiVersion: generators.external-secrets.io/v1alpha1
kind: VaultDynamicSecret
metadata:
  name: vault-db-credentials
  namespace: production
spec:
  path: "database/creds/readonly-pagamentos"
  method: GET
  provider:
    server: "https://vault.vault.svc.cluster.local:8200"
    auth:
      kubernetes:
        mountPath: "kubernetes"
        role: "api-pagamentos"
        serviceAccountRef:
          name: api-pagamentos-sa
```

---

## 4. Cloud-Native Alternatives

### 4.1 AWS Secrets Manager

**O que este comando faz:** Cria, lê e gerencia secrets no AWS Secrets Manager. O comando de rotação configura uma Lambda function que o Secrets Manager chama automaticamente a cada 30 dias para trocar a senha — incluindo a atualização do banco de dados e todos os sistemas que usam a credencial.
**Por que isso importa:** Para o Banco Meridian operar exclusivamente na AWS, o Secrets Manager elimina a complexidade operacional do Vault com rotação automática nativa para RDS, Redshift e outros serviços AWS. A integração com CloudTrail fornece auditoria completa de cada acesso — quem leu qual secret, quando, de qual serviço — sem configuração adicional.

```bash
# Criar um secret
aws secretsmanager create-secret \
  --name "bancomeridian/api-pagamentos/db-password" \
  --description "Senha do banco de pagamentos" \
  --secret-string '{"username":"api_pagamentos","password":"SenhaSegura123!"}'

# Ler um secret (aplicação faz isso em runtime)
aws secretsmanager get-secret-value \
  --secret-id "bancomeridian/api-pagamentos/db-password" \
  --query SecretString --output text | python3 -c "
import json, sys
secret = json.load(sys.stdin)
print(f'Username: {secret[\"username\"]}')
print(f'Password: {secret[\"password\"]}')
"

# Habilitar rotação automática (Lambda rotation function)
aws secretsmanager rotate-secret \
  --secret-id "bancomeridian/api-pagamentos/db-password" \
  --rotation-lambda-arn "arn:aws:lambda:us-east-1:123456789:function:SecretsManagerRotation" \
  --rotation-rules AutomaticallyAfterDays=30

# Versões de um secret (AWSCURRENT, AWSPENDING, AWSPREVIOUS)
aws secretsmanager list-secret-version-ids \
  --secret-id "bancomeridian/api-pagamentos/db-password"

# Acesso cross-account (para ambientes multi-conta)
aws secretsmanager put-resource-policy \
  --secret-id "bancomeridian/api-pagamentos/db-password" \
  --resource-policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::STAGING_ACCOUNT:root"},
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }]
  }'

# Auditoria via CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=secretsmanager.amazonaws.com \
  --max-results 20
```

### 4.2 Azure Key Vault

**O que este comando faz:** Cria um Azure Key Vault com proteção por RBAC (em vez do modelo legado de Access Policies), atribui roles granulares a Managed Identities, e gerencia secrets, certificados e chaves criptográficas (CMEK) — incluindo chaves para Customer-Managed Encryption.
**Por que isso importa:** Para o Banco Meridian com workloads no Azure, o Key Vault com `--enable-rbac-authorization` integra diretamente com o Entra ID, permitindo que Managed Identities (sem nenhuma credencial configurada) acessem secrets de forma transparente. A flag `--enable-purge-protection` é especialmente importante para conformidade: uma vez habilitada, ninguém — nem o CISO — pode deletar permanentemente um secret sem o período de retenção de 90 dias, protegendo evidências em investigações forenses.

```bash
# Criar Key Vault
az keyvault create \
  --name bancomeridian-kv \
  --resource-group rg-security \
  --location brazilsouth \
  --enable-rbac-authorization true \  # RBAC em vez de access policies (recomendado)
  --sku standard \
  --retention-days 90 \               # Soft delete
  --enable-purge-protection           # Proteção contra delete permanente

# Atribuir role para a aplicação (RBAC)
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "MANAGED_IDENTITY_OBJECT_ID" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-security/providers/Microsoft.KeyVault/vaults/bancomeridian-kv"

# Criar secret
az keyvault secret set \
  --vault-name bancomeridian-kv \
  --name "db-password" \
  --value "SenhaSegura123!" \
  --content-type "text/plain" \
  --expires "2025-12-31T23:59:59Z"  # TTL do secret

# Ler secret
az keyvault secret show \
  --vault-name bancomeridian-kv \
  --name "db-password" \
  --query value --output tsv

# Criar certificado gerenciado
az keyvault certificate create \
  --vault-name bancomeridian-kv \
  --name api-pagamentos-cert \
  --policy "$(az keyvault certificate get-default-policy)"

# Chaves criptográficas (CMEK)
az keyvault key create \
  --vault-name bancomeridian-kv \
  --name bancomeridian-cmek \
  --kty RSA \
  --size 4096 \
  --ops sign verify wrapKey unwrapKey
```

### 4.3 GCP Secret Manager

**O que este comando faz:** Cria, versiona e gerencia secrets no GCP Secret Manager, configura notificações automáticas de rotação via Pub/Sub, e controla o acesso de service accounts via IAM granular.
**Por que isso importa:** Para workloads do Banco Meridian no GCP, o Secret Manager integra nativamente com Workload Identity Federation — eliminando chaves de conta de serviço em favor de identidades efêmeras. A integração com Cloud Audit Logs fornece rastreabilidade completa de cada acesso a cada versão de cada secret, essencial para demonstrar conformidade com LGPD e BACEN em auditorias.

```bash
# Criar secret
gcloud secrets create db-password \
  --replication-policy automatic \
  --labels "app=api-pagamentos,env=production"

# Adicionar versão (o conteúdo do secret)
echo -n "SenhaSegura123!" | \
  gcloud secrets versions add db-password --data-file=-

# Acessar secret (aplicação faz isso em runtime)
gcloud secrets versions access latest --secret db-password

# Criar notificação de rotação (Pub/Sub)
gcloud secrets create db-password-rotate \
  --rotation-period 7776000s \  # 90 dias
  --next-rotation-time 2025-07-24T00:00:00Z \
  --topics projects/bancomeridian-prod/topics/secret-rotation

# Listar versões
gcloud secrets versions list db-password

# Desabilitar versão antiga após rotação
gcloud secrets versions disable 1 --secret db-password

# IAM — conceder acesso à ServiceAccount do K8s
gcloud secrets add-iam-policy-binding db-password \
  --member "serviceAccount:api-pagamentos@bancomeridian-prod.iam.gserviceaccount.com" \
  --role "roles/secretmanager.secretAccessor"

# Auditoria via Cloud Audit Logs
gcloud logging read \
  'resource.type="secretmanager.googleapis.com/Secret" AND protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"' \
  --limit 20
```

### 4.4 Decisão de Arquitetura: Vault vs Cloud-Native

| Critério | HashiCorp Vault | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager |
|:---------|:---------------:|:-------------------:|:---------------:|:------------------:|
| **Multi-cloud** | Excelente | Apenas AWS | Principalmente Azure | Apenas GCP |
| **Dynamic secrets** | Excelente (DB, PKI, SSH, AWS) | Apenas DB com rotação | Não nativo | Não nativo |
| **PKI/CA interna** | Completo | Não | Parcial (certificados) | Não |
| **SSH OTP** | Sim | Não | Não | Não |
| **Kubernetes native** | Via ESO ou Agent | Via ESO | Via ESO | Via ESO |
| **Vendor lock-in** | Nenhum | Alto (AWS) | Alto (Azure) | Alto (GCP) |
| **Complexidade** | Alta | Baixa | Baixa | Baixa |
| **Custo (pequeno)** | Gratuito (OSS) | ~USD 0,40/secret/mês | ~USD 0,03/10k ops | ~USD 0,06/10k versões |
| **Custo (grande)** | Vault Enterprise ~USD 50k/ano | Variável por uso | Variável | Variável |
| **Auditoria** | Completa (audit log) | CloudTrail | Azure Monitor | Cloud Audit Logs |
| **Quando usar** | Multi-cloud, dynamic secrets, PKI interna, soberania de dados | AWS-only, simplicidade, rotação automática de DB | Azure-only, integração M365/Entra | GCP-only |

---

## 5. Exemplo Completo: AppRole + Database Engine + K8s Integration

**O que este script faz:** Demonstra o fluxo completo end-to-end — configura o Vault com política, AppRole e database engine; depois simula o comportamento da aplicação autenticando via AppRole, obtendo credenciais dinâmicas do PostgreSQL e conectando ao banco; e ao encerrar, revoga o lease imediatamente sem aguardar o TTL.
**Por que isso importa:** Este é o cenário real do Banco Meridian: ao invés de `DB_PASSWORD=BancoMeridian@2024!` hardcoded que está em 847 commits do git, a aplicação agora chega no ambiente sem conhecer nenhuma senha — ela aprende o Role ID no código (público), recebe o Secret ID do CI/CD (efêmero, 10 minutos), e troca esses dois tokens por credenciais de banco únicas que expiram em 1 hora. Cada acesso ao banco é auditado no Vault audit log com a identidade da aplicação, o timestamp e o IP de origem.

```bash
# ============================================================
# EXEMPLO COMPLETO: API de Pagamentos com Vault
# ============================================================

# PASSO 1: Configurar Vault para o ambiente (executar como admin)

# Política
vault policy write api-pagamentos-policy - <<EOF
path "bancomeridian/data/api-pagamentos/*" {
  capabilities = ["read"]
}
path "database/creds/readonly-pagamentos" {
  capabilities = ["read"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
}
EOF

# AppRole
vault auth enable approle
vault write auth/approle/role/api-pagamentos \
  token_policies=api-pagamentos-policy \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=1h

# Obter credenciais AppRole
ROLE_ID=$(vault read -field=role_id auth/approle/role/api-pagamentos/role-id)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/api-pagamentos/secret-id)

echo "ROLE_ID: $ROLE_ID"
echo "SECRET_ID: $SECRET_ID"
# SECRET_ID seria injetado pelo CI/CD, nunca hardcoded

# Database engine
vault secrets enable database
vault write database/config/bancomeridian-postgres \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@localhost:5432/pagamentos?sslmode=require" \
  username="vault" \
  password="vault-db-password" \
  allowed_roles="readonly-pagamentos"

vault write database/roles/readonly-pagamentos \
  db_name=bancomeridian-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="8h"

# PASSO 2: Aplicação autentica e usa os secrets (executar como aplicação)

# Login com AppRole
VAULT_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID")

export VAULT_TOKEN

# Obter credenciais dinâmicas do banco
DB_CREDS=$(vault read -format=json database/creds/readonly-pagamentos)
DB_USERNAME=$(echo $DB_CREDS | jq -r '.data.username')
DB_PASSWORD=$(echo $DB_CREDS | jq -r '.data.password')
LEASE_ID=$(echo $DB_CREDS | jq -r '.lease_id')
LEASE_DURATION=$(echo $DB_CREDS | jq -r '.lease_duration')

echo "Credenciais obtidas — expiram em: $LEASE_DURATION"
echo "Usuario: $DB_USERNAME"
# Senha não logada por segurança

# Conectar ao banco com credenciais dinâmicas
PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USERNAME" -d pagamentos -c "\dt"

# Quando a aplicação estiver encerrando, revogar o lease
vault lease revoke "$LEASE_ID"

echo "Credenciais revogadas imediatamente — banco de dados seguro."
```

---

## 6. Atividades de Fixação

### Questão 1
Qual é a principal vantagem das credenciais dinâmicas do Vault (database secret engine) em relação a armazenar senhas estáticas no Secrets Manager?

**a)** As credenciais dinâmicas são mais fáceis de configurar  
**b)** Cada request gera credenciais únicas com TTL — se comprometidas, expiram automaticamente; e a revogação é instantânea sem afetar outras instâncias da aplicação  
**c)** O Vault não cobra pelo uso de credenciais dinâmicas  
**d)** As credenciais dinâmicas funcionam sem necessidade de banco de dados  

**Gabarito: b)**  
Justificativa: Com senhas estáticas, comprometimento significa rotação de emergência que afeta todas as instâncias. Com credenciais dinâmicas, cada instância da aplicação tem sua própria credencial com TTL — se uma vaza, só essa credencial precisa ser revogada (sem impacto nas demais), e ela expiraria sozinha dentro de 1h de qualquer forma.

---

### Questão 2
O AppRole auth method usa dois componentes para autenticação. Qual é a analogia correta para entender cada componente?

**a)** Role ID = usuário, Secret ID = senha — ambos privados e devem ser protegidos  
**b)** Role ID = "quem você é" (análogo ao username, pode ser público); Secret ID = "prova de que é você" (análogo ao password, privado e de curta duração)  
**c)** Role ID e Secret ID são equivalentes — qualquer um pode ser usado sozinho  
**d)** Role ID é permanente; Secret ID é o token final de autenticação  

**Gabarito: b)**  
Justificativa: O Role ID identifica a aplicação (pode estar no código ou ambiente, não é secreto). O Secret ID é o elemento secreto efêmero — normalmente injetado pelo CI/CD no momento do deploy com um TTL de minutos. Isso segue o princípio de "dois fatores para aplicações" — a identidade (Role ID) + a prova de que está no ambiente correto (Secret ID injetado pelo CI/CD).

---

### Questão 3
Um CTO precisa decidir entre HashiCorp Vault OSS e AWS Secrets Manager. Qual critério é decisivo para escolher Vault sobre AWS Secrets Manager?

**a)** Vault é mais barato em todos os cenários  
**b)** Vault é preferível quando a organização tem multi-cloud (AWS + Azure + GCP), precisa de dynamic secrets para múltiplos backends (DB, SSH, PKI) ou tem requisito de soberania de dados (dados não podem sair da infraestrutura própria)  
**c)** Vault é preferível quando a organização é pequena e tem equipe limitada  
**d)** Vault é preferível quando a organização usa apenas AWS  

**Gabarito: b)**  
Justificativa: AWS Secrets Manager é melhor para simplicidade em ambiente AWS-only. Vault supera o Secrets Manager em: suporte multi-cloud (única plataforma para AWS + Azure + GCP), dynamic secrets para múltiplos backends (PostgreSQL, MySQL, SSH, PKI, AWS credentials simultaneamente), PKI interna completa, e soberania de dados (Vault roda on-premises ou na VPC do cliente, os dados nunca saem para um SaaS).

---

### Questão 4
O que o External Secrets Operator (ESO) faz quando configurado com um `ExternalSecret` apontando para o Vault?

**a)** Instala o Vault diretamente no cluster Kubernetes  
**b)** Cria um proxy transparente entre a aplicação e o Vault  
**c)** Sincroniza secrets do Vault para recursos nativos `Secret` do Kubernetes, renovando automaticamente antes da expiração do TTL  
**d)** Substitui o Vault Agent Injector mas requer o mesmo tipo de sidecar  

**Gabarito: c)**  
Justificativa: ESO é um operador K8s que lê `ExternalSecret` CRDs e os converte em `Secret` nativos do Kubernetes. A grande vantagem: a aplicação não precisa conhecer nada sobre Vault — apenas lê um `Secret` K8s normal. O ESO gerencia toda a complexidade: autenticação no Vault, busca do secret, criação do `Secret` K8s, e renovação automática antes da expiração.

---

### Questão 5
Por que o Azure Key Vault recomenda usar `--enable-rbac-authorization true` em vez do modelo de Access Policies?

**a)** RBAC é mais barato que Access Policies  
**b)** RBAC usa os papéis padrão do Azure (Key Vault Secrets User, Key Vault Secrets Officer) integrados ao Entra ID, permitindo gestão centralizada, audit trail completo e suporte a Managed Identities — em vez de políticas de acesso proprietárias do Key Vault que são gerenciadas separadamente  
**c)** Access Policies foram descontinuadas na versão mais recente do Key Vault  
**d)** RBAC permite acesso anônimo que as Access Policies não permitem  

**Gabarito: b)**  
Justificativa: O modelo RBAC do Key Vault usa os mesmos papéis e mecanismos do Azure RBAC (roles no Entra ID), permitindo: gestão centralizada de permissões para todo o Azure no mesmo lugar, suporte nativo a Managed Identities (sem credenciais), audit trail integrado com Azure Monitor, e Conditional Access policies do Entra ID. O modelo de Access Policies é uma implementação proprietária do Key Vault que não se integra bem ao ecossistema Azure RBAC mais amplo.

---

## 7. Roteiros de Gravação

### Aula 7.1: HashiCorp Vault — Arquitetura e Secret Engines (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | HashiCorp Vault: Arquitetura, Secret Engines e AppRole |
| **Duração** | 50 minutos |
| **Formato** | Talking head + terminal (vault CLI) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Módulo 7. Se o Módulo 6 foi sobre identidades excessivas, este módulo é sobre o problema gêmeo: credenciais estáticas que nunca expiram.

O Vault da HashiCorp é a ferramenta mais adotada no mundo para secrets management em cloud. Não porque é a mais simples — não é. Mas porque ela resolve o problema de raiz com credenciais dinâmicas, PKI interna e auditoria completa.

---

**[05:00 – 15:00 | O PROBLEMA + ARQUITETURA | Slides]**

*[Dica de edição: animação do diagrama de arquitetura entrando peça por peça]*

*[Mostra o cenário do docker-compose com senhas hardcoded]*

*[Explica a arquitetura do Vault com o diagrama]*

---

**[15:00 – 42:00 | SECRET ENGINES NA PRÁTICA | Terminal]*

*[Inicia Vault em modo dev]*

```bash
vault server -dev -dev-root-token-id="root" &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
```

*[Demonstra KV v2: criar, ler, versionar secrets]*

*[Configura database engine com PostgreSQL local]*

*[Gera credencial dinâmica, mostra o TTL, aguarda expirar, mostra que não funciona mais]*

*[Configura AppRole, demonstra o fluxo de autenticação de uma aplicação]*

---

**[42:00 – 50:00 | ENCERRAMENTO + PRÓXIMA AULA | Talking head]**

Na próxima aula: dynamic secrets com PostgreSQL em detalhes, integração com Kubernetes, e quando usar Vault vs AWS Secrets Manager vs Azure Key Vault.

---

### Aula 7.2: Dynamic Secrets + K8s Integration + Cloud-native (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Vault: Dynamic Secrets, Integração K8s e Comparativo Cloud-Native |
| **Duração** | 50 minutos |
| **Formato** | Terminal + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Na aula anterior você viu a arquitetura do Vault e os principais secret engines. Hoje vamos aprofundar em dynamic secrets — porque esse é o recurso que transforma o Vault de "gerenciador de senhas" em "plataforma de secrets" — e vamos ver como integrar com Kubernetes via External Secrets Operator.

---

**[05:00 – 25:00 | DYNAMIC SECRETS POSTGRESQL | Terminal]**

*[Configura database engine com PostgreSQL]*

*[Demonstra credenciais únicas sendo geradas a cada request]*

*[Mostra no PostgreSQL que o usuário existe — e depois de 1h que foi removido automaticamente]*

*[Demonstra revogação imediata em caso de incidente]*

---

**[25:00 – 40:00 | KUBERNETES INTEGRATION | Terminal + K8s cluster]**

*[Instala ESO no cluster kind]*

*[Configura SecretStore e ExternalSecret]*

*[Mostra que o Secret K8s é criado automaticamente]*

*[Mostra que a aplicação consegue ler o Secret K8s sem saber que veio do Vault]*

---

**[40:00 – 48:00 | CLOUD-NATIVE COMPARISON | Slides]**

*[Apresenta a tabela comparativa Vault vs Secrets Manager vs Key Vault vs Secret Manager]*

*[Explica critérios de decisão com exemplos do Banco Meridian]*

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

No Lab-05, você vai implementar o fluxo completo: Vault dev + PostgreSQL + AppRole + credencial dinâmica com TTL + integração com K8s via ESO. É um laboratório extenso mas essencial — o Vault é uma das ferramentas mais pedidas em vagas de Cloud Security Engineer.

---

## 8. Avaliação do Módulo 07

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
O que `vault lease revoke -prefix database/creds/readonly-pagamentos/` faz?

**a)** Revoga apenas o lease mais recente da role  
**b)** Revoga TODOS os leases ativos da role readonly-pagamentos (todas as credenciais dinâmicas geradas por ela) — útil em incidentes de segurança  
**c)** Remove a role do database engine permanentemente  
**d)** Suspende temporariamente a geração de novos leases  

**Gabarito: b)** O flag `-prefix` revoga todos os leases que começam com o prefixo especificado. Isso revoga todas as credenciais dinâmicas geradas por aquela role de uma vez — útil quando você suspeita que uma role foi comprometida e precisa invalidar todas as credenciais geradas por ela, independente de quantas instâncias estejam em execução.

---

**Questão 2 (10 pts)**  
Qual secret engine do Vault é usado para emitir certificados TLS internos (como para mTLS entre microsserviços)?

**a)** KV v2 (Key-Value versioned)  
**b)** PKI (Public Key Infrastructure)  
**c)** SSH  
**d)** Database  

**Gabarito: b)** O PKI secret engine transforma o Vault em uma CA (Certificate Authority) interna. Ele pode emitir certificados X.509 com TTL configurado para microsserviços, APIs internas e qualquer comunicação TLS/mTLS. É a solução para mTLS entre serviços sem precisar de uma CA externa cara.

---

**Questão 3 (10 pts)**  
Em uma arquitetura Vault HA com Raft, quantos nós são necessários para um quórum com 5 nós totais?

**a)** 2 nós  
**b)** 3 nós  
**c)** 4 nós  
**d)** 5 nós  

**Gabarito: b)** Em Raft, o quórum é (n/2 + 1), onde n é o número de nós. Com 5 nós: (5/2 + 1) = 3,5 → 3 nós. Portanto, o cluster tolera até 2 falhas de nós simultâneas e ainda funciona. Com 3 nós (mínimo recomendado para HA), o quórum é 2 nós — tolera 1 falha.

---

**Questão 4 (10 pts)**  
Qual é a diferença entre `vault.hashicorp.com/agent-inject-secret-*` (Vault Agent Injector) e External Secrets Operator?

**a)** São idênticos — apenas nomenclaturas diferentes do mesmo produto  
**b)** Agent Injector usa sidecar injetado em cada Pod; ESO é um operador K8s central que sincroniza secrets como K8s Secret nativos sem sidecar  
**c)** Agent Injector é mais seguro porque não cria K8s Secrets; ESO é menos seguro  
**d)** ESO requer o Vault Enterprise; Agent Injector funciona com OSS  

**Gabarito: b)** Agent Injector injeta um container sidecar em cada Pod que se autentica no Vault e renderiza templates de arquivos de secrets no volume compartilhado. ESO é um operador central que cria K8s `Secret` nativos — cada Pod lê o `Secret` K8s normalmente sem saber que veio do Vault. ESO é mais simples para a aplicação (sem sidecar), mas os secrets ficam temporariamente em etcd (K8s Secret).

---

**Questão 5 (10 pts)**  
No contexto do Vault database engine com PostgreSQL, o que a cláusula `revocation_statements` faz?

**a)** Define a senha de revogação de master para o banco  
**b)** É o SQL executado pelo Vault quando o lease expira ou é revogado — normalmente revoga permissões e deleta o usuário criado dinamicamente  
**c)** Define quem pode revogar credenciais manualmente  
**d)** Configura o tempo máximo antes da revogação forçada  

**Gabarito: b)** Quando um lease de credencial dinâmica expira ou é revogado manualmente, o Vault executa o `revocation_statements` — tipicamente `REVOKE ALL ON ... FROM "{{name}}"; DROP ROLE IF EXISTS "{{name}}";`. Isso garante que o usuário temporário é removido do banco de dados, eliminando completamente o acesso após o TTL.

---

**Questão 6 (10 pts)**  
Por que o AWS Secrets Manager é preferível ao HashiCorp Vault para uma startup que usa apenas AWS?

**a)** Secrets Manager tem mais recursos que o Vault  
**b)** Secrets Manager não requer operação de cluster, tem integração nativa com RDS/Redshift para rotação automática, e para organizações AWS-only a simplicidade operacional supera as vantagens do Vault  
**c)** Secrets Manager é gratuito ilimitado  
**d)** Vault não suporta integração com AWS  

**Gabarito: b)** Para ambientes AWS-only, o Secrets Manager resolve o mesmo problema com muito menos complexidade operacional: não há cluster para gerenciar, não há unseal keys para proteger, não há HA para configurar. A rotação automática para RDS, Redshift e outros serviços AWS é nativa. Para startups sem equipe de plataforma dedicada, isso é um diferencial importante.

---

*Módulo 07 — Secrets Management com HashiCorp Vault*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
