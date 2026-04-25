# Lab 05 — HashiCorp Vault: Eliminando Credenciais Estáticas
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2 horas  
> **Dificuldade:** Avançado  
> **Módulo Relacionado:** Módulo 07 — Secrets Management  

---

## 1. Contexto Situacional

O Banco Meridian tem senhas de banco de dados hardcoded em variáveis de ambiente dos seus microserviços. Uma auditoria interna descobriu que a senha do banco de pagamentos está em texto claro em 3 repositórios GitHub, no Dockerfile, e em arquivos de configuração em 12 servidores. O CTO emitiu um mandato: "Eliminar todas as credenciais estáticas em 90 dias."

Você foi designado para implementar o HashiCorp Vault como solução de secrets management e demonstrar o fluxo de dynamic credentials com PostgreSQL.

---

## 2. Situação Inicial

```
SITUAÇÃO ATUAL (problemática):
  docker-compose.yml:
    environment:
      DB_PASSWORD: "BancoMeridian@2024!"   ← hardcoded em 3 repos
      DB_HOST: "postgres.interno.local"
      DB_USER: "api_pagamentos"

  Problema: esta senha não foi rotacionada em 18 meses.
  Risco: qualquer pessoa com acesso ao repositório conhece a senha.
  Evidência forense: a senha aparece em 847 commits do git log.
```

---

## 3. Problema Identificado

Credenciais estáticas hardcoded criam múltiplos riscos:
1. Qualquer acesso ao repositório = acesso à credencial
2. Sem auditoria de uso — impossível saber se foi usada por atacante
3. Rotação requer downtime e coordenação manual
4. Violação de BACEN 4.893 Art. 8 (gestão de credenciais)

---

## 4. Roteiro de Atividades

1. Iniciar Vault em modo dev
2. Configurar PostgreSQL secret engine
3. Criar role de banco com TTL de 1 hora
4. Gerar credencial dinâmica e testar conexão
5. Verificar que a credencial expira automaticamente
6. Configurar AppRole auth method
7. Demonstrar fluxo de autenticação da aplicação
8. Integrar com Kubernetes via External Secrets Operator

---

## 5. Proposição

Ao final deste laboratório, você terá demonstrado que: (a) credenciais dinâmicas são únicas por request, (b) expiram automaticamente após 1h, (c) a aplicação se autentica via AppRole sem conhecer a senha do banco, e (d) a integração com K8s via ESO funciona de forma transparente para a aplicação.

---

## 6. Script Passo a Passo

### Passo 1: Iniciar Vault em Modo Dev

```bash
# Instalar Vault (se não instalado)
# macOS:
brew tap hashicorp/tap && brew install hashicorp/tap/vault

# Linux:
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Verificar versão
vault version

# Iniciar Vault em modo dev com token fixo para laboratório
# IMPORTANTE: modo dev NÃO É PARA PRODUÇÃO — dados em memória, sem TLS, sem HA
vault server -dev -dev-root-token-id="lab-root-token" &
VAULT_PID=$!

# Configurar variáveis de ambiente
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='lab-root-token'

# Verificar conexão
vault status
vault token lookup
```

**Resultado esperado:**
```
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             false
Total Shares       1
Threshold          1
Version            1.x.x
Cluster Name       vault-cluster-dev
Storage Type       inmem
HA Enabled         false
```

**Troubleshooting:** Se a porta 8200 estiver em uso:
```bash
vault server -dev -dev-root-token-id="lab-root-token" -dev-listen-address="127.0.0.1:8201" &
export VAULT_ADDR='http://127.0.0.1:8201'
```

---

### Passo 2: Iniciar PostgreSQL para o Laboratório

```bash
# Iniciar PostgreSQL com Docker (banco de teste)
docker run -d \
  --name vault-postgres-lab \
  -e POSTGRES_DB=bancomeridian \
  -e POSTGRES_USER=vault_admin \
  -e POSTGRES_PASSWORD=vault_lab_admin_2025 \
  -p 5432:5432 \
  postgres:15

# Aguardar PostgreSQL iniciar
sleep 5

# Verificar conexão
PGPASSWORD=vault_lab_admin_2025 psql -h localhost -U vault_admin -d bancomeridian \
  -c "SELECT version();"

# Criar tabela de teste
PGPASSWORD=vault_lab_admin_2025 psql -h localhost -U vault_admin -d bancomeridian << 'SQL'
CREATE TABLE IF NOT EXISTS transacoes (
  id SERIAL PRIMARY KEY,
  valor DECIMAL(10,2),
  descricao TEXT,
  criado_em TIMESTAMP DEFAULT NOW()
);

INSERT INTO transacoes (valor, descricao) VALUES
  (100.00, 'Depósito PIX'),
  (250.50, 'Pagamento boleto'),
  (75.00, 'TED recebida');

SELECT COUNT(*) as total_transacoes FROM transacoes;
SQL
```

**Resultado esperado:**
```
 total_transacoes
------------------
        3
```

---

### Passo 3: Configurar PostgreSQL Secret Engine

```bash
echo "=== CONFIGURANDO DATABASE SECRET ENGINE ==="

# Habilitar o database secret engine
vault secrets enable database
echo "✓ Database secret engine habilitado"

# Configurar conexão com PostgreSQL
vault write database/config/bancomeridian-db \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly-api,readwrite-transacoes" \
  connection_url="postgresql://{{username}}:{{password}}@localhost:5432/bancomeridian?sslmode=disable" \
  username="vault_admin" \
  password="vault_lab_admin_2025" \
  max_open_connections=5

echo "✓ Conexão PostgreSQL configurada no Vault"

# Verificar configuração
vault read database/config/bancomeridian-db
```

---

### Passo 4: Criar Roles com TTL

```bash
# Role readonly para a API (TTL de 1 hora)
vault write database/roles/readonly-api \
  db_name=bancomeridian-db \
  creation_statements="
    CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
    GRANT USAGE ON SCHEMA public TO \"{{name}}\";
  " \
  revocation_statements="
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";
    REVOKE USAGE ON SCHEMA public FROM \"{{name}}\";
    DROP ROLE IF EXISTS \"{{name}}\";
  " \
  default_ttl="1h" \
  max_ttl="4h"

echo "✓ Role readonly-api criada (TTL: 1h)"

# Role readwrite para o serviço de transações
vault write database/roles/readwrite-transacoes \
  db_name=bancomeridian-db \
  creation_statements="
    CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
    GRANT SELECT, INSERT, UPDATE ON transacoes TO \"{{name}}\";
    GRANT USAGE, SELECT ON SEQUENCE transacoes_id_seq TO \"{{name}}\";
  " \
  revocation_statements="
    REVOKE ALL ON transacoes FROM \"{{name}}\";
    DROP ROLE IF EXISTS \"{{name}}\";
  " \
  default_ttl="1h" \
  max_ttl="8h"

echo "✓ Role readwrite-transacoes criada (TTL: 1h)"
```

---

### Passo 5: Gerar Credencial Dinâmica e Testar

```bash
echo ""
echo "=== GERANDO CREDENCIAIS DINÂMICAS ==="
echo "Antes do Vault: senha estática 'BancoMeridian@2024!' válida para sempre"
echo "Depois do Vault: credencial única gerada agora, expira em 1h"
echo ""

# Gerar credencial dinâmica
DB_CREDS=$(vault read -format=json database/creds/readonly-api)
DB_USER=$(echo $DB_CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['username'])")
DB_PASS=$(echo $DB_CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['password'])")
LEASE_ID=$(echo $DB_CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['lease_id'])")
TTL=$(echo $DB_CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['lease_duration'])")

echo "Credencial gerada:"
echo "  Usuario: $DB_USER"
echo "  Senha: [REDACTED — não logada por segurança]"
echo "  TTL: $TTL"
echo "  Lease ID: $LEASE_ID"
echo ""

# Testar conexão com a credencial dinâmica
echo "Testando conexão com credencial dinâmica..."
PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d bancomeridian \
  -c "SELECT current_user, NOW()::text as hora_acesso;" \
  -c "SELECT COUNT(*) as transacoes_visiveis FROM transacoes;"

echo ""
echo "✓ Credencial dinâmica funciona!"

# Verificar no PostgreSQL que o usuário foi criado
PGPASSWORD=vault_lab_admin_2025 psql -h localhost -U vault_admin -d bancomeridian \
  -c "SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolname LIKE 'v-%';"
```

**Resultado esperado:**
```
Credencial gerada:
  Usuario: v-role-readonly-api-KjNm-1714000000
  Senha: [REDACTED]
  TTL: 3600
  Lease ID: database/creds/readonly-api/abc123xyz

 current_user                               | hora_acesso
--------------------------------------------+------------------------
 v-role-readonly-api-KjNm-1714000000       | 2025-04-24 15:30:01

 transacoes_visiveis
---------------------
                   3
```

---

### Passo 6: Demonstrar Expiração Automática

```bash
echo "=== DEMONSTRANDO EXPIRAÇÃO AUTOMÁTICA ==="
echo ""

# Para demonstrar sem esperar 1h, vamos revogar manualmente o lease
# (em produção, o Vault faria isso automaticamente após 1h)

echo "Revogando a credencial imediatamente (simulando expiração)..."
vault lease revoke "$LEASE_ID"
echo "Credencial revogada."
echo ""

# Tentar usar a credencial revogada
echo "Tentando usar credencial revogada..."
PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d bancomeridian \
  -c "SELECT 1;" 2>&1 | head -3 || true

echo ""
echo "Resultado esperado: FATAL: role does not exist"
echo ""

# Verificar que o usuário foi removido do PostgreSQL
PGPASSWORD=vault_lab_admin_2025 psql -h localhost -U vault_admin -d bancomeridian \
  -c "SELECT rolname FROM pg_roles WHERE rolname = '$DB_USER';"
echo "(Resultado esperado: 0 rows — usuário foi removido pelo Vault)"
```

**Resultado esperado:**
```
Revogando a credencial imediatamente...
Success! Revoked lease: database/creds/readonly-api/abc123xyz

Tentando usar credencial revogada...
psql: FATAL:  role "v-role-readonly-api-KjNm-1714000000" does not exist

 rolname
---------
(0 rows)
```

---

### Passo 7: Configurar AppRole Auth

```bash
echo "=== CONFIGURANDO APPROLE AUTH METHOD ==="

# Habilitar AppRole auth
vault auth enable approle
echo "✓ AppRole auth habilitado"

# Criar política para a API de pagamentos
vault policy write api-pagamentos-policy - << 'HCL'
# Acesso ao KV para configurações
path "secret/data/api-pagamentos/*" {
  capabilities = ["read"]
}

# Acesso a credenciais dinâmicas do banco (readonly)
path "database/creds/readonly-api" {
  capabilities = ["read"]
}

# Acesso a credenciais de escrita para o serviço de transações
path "database/creds/readwrite-transacoes" {
  capabilities = ["read"]
}

# Renovar leases
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Revogar o próprio token
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
HCL

echo "✓ Política api-pagamentos-policy criada"

# Criar role AppRole
vault write auth/approle/role/api-pagamentos \
  token_policies=api-pagamentos-policy \
  secret_id_ttl=10m \
  token_num_uses=10 \
  token_ttl=20m \
  token_max_ttl=60m

echo "✓ Role AppRole api-pagamentos criada"

# Obter Role ID (público — pode estar no código ou ambiente)
ROLE_ID=$(vault read -field=role_id auth/approle/role/api-pagamentos/role-id)
echo ""
echo "Role ID (público): $ROLE_ID"
```

---

### Passo 8: Demonstrar Fluxo de Autenticação da Aplicação

```bash
echo ""
echo "=== FLUXO DA APLICAÇÃO: AppRole → Token → Dynamic DB Credential ==="
echo ""

# PASSO 1: CI/CD injeta o Secret ID no ambiente da aplicação
# (em produção: gerado pelo CI/CD pipeline no momento do deploy)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/api-pagamentos/secret-id)
echo "Etapa 1 — CI/CD gerou Secret ID (expira em 10min): ${SECRET_ID:0:20}..."

# PASSO 2: Aplicação autentica com Role ID + Secret ID
APP_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID")
echo "Etapa 2 — Aplicação autenticou, recebeu token: ${APP_TOKEN:0:20}..."

# PASSO 3: Aplicação usa o token para obter credenciais do banco
export VAULT_TOKEN="$APP_TOKEN"

DB_CREDS_APP=$(vault read -format=json database/creds/readonly-api)
DB_USER_APP=$(echo $DB_CREDS_APP | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['username'])")
DB_PASS_APP=$(echo $DB_CREDS_APP | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['password'])")

echo "Etapa 3 — Aplicação obteve credencial dinâmica: $DB_USER_APP"

# PASSO 4: Aplicação usa as credenciais para conectar ao banco
echo "Etapa 4 — Conectando ao banco com credencial dinâmica..."
PGPASSWORD="$DB_PASS_APP" psql -h localhost -U "$DB_USER_APP" -d bancomeridian \
  -c "SELECT 'Conexão bem-sucedida! Usuário: ' || current_user AS resultado;"

echo ""
echo "=== COMPARATIVO ANTES/DEPOIS ==="
echo ""
echo "ANTES: DB_PASSWORD=BancoMeridian@2024! (hardcoded, 18 meses sem rotação)"
echo "DEPOIS: Credencial única, expira em 1h, auditada no Vault, sem hardcoding"
echo ""
echo "✓ Laboratório de Vault concluído com sucesso!"

# Restaurar token do admin
export VAULT_TOKEN='lab-root-token'
```

---

### Passo 9: Configurar KV v2 para Secrets Estáticos

```bash
echo "=== CONFIGURANDO KV v2 PARA SECRETS ESTÁTICOS ==="

# Habilitar KV v2
vault secrets enable -path=bancomeridian kv-v2
echo "✓ KV v2 habilitado no path 'bancomeridian'"

# Escrever configurações da aplicação (não-sensitivas)
vault kv put bancomeridian/api-pagamentos/config \
  db_host="postgres.bancomeridian.internal" \
  db_port="5432" \
  db_name="bancomeridian" \
  redis_host="redis.bancomeridian.internal" \
  api_timeout="30" \
  log_level="INFO"

echo "✓ Configurações da API escritas no Vault"

# Ler configurações
vault kv get bancomeridian/api-pagamentos/config

# Escrever API key de terceiro (rotacionável)
vault kv put bancomeridian/api-pagamentos/external-apis \
  payment_gateway_key="pgw_live_abc123" \
  sms_api_key="sms_live_xyz789"

echo "✓ API keys de terceiros escritas no Vault"

# Verificar versões
vault kv metadata get bancomeridian/api-pagamentos/config
```

---

### Passo 10: Integrar com Kubernetes via External Secrets Operator

```bash
echo "=== INTEGRAÇÃO VAULT + KUBERNETES ==="

# Habilitar Kubernetes auth no Vault
vault auth enable kubernetes
echo "✓ Kubernetes auth method habilitado"

# Configurar com informações do cluster kind
# (o Vault Agent dentro do cluster fornece essas informações)
KUBE_CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d | base64 -w 0)
KUBE_HOST=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')

vault write auth/kubernetes/config \
  kubernetes_host="$KUBE_HOST" \
  kubernetes_ca_cert="$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)"

# Criar role Kubernetes → Vault
vault write auth/kubernetes/role/api-pagamentos-k8s \
  bound_service_account_names=api-pagamentos-sa \
  bound_service_account_namespaces=lab05-vault \
  policies=api-pagamentos-policy \
  ttl=1h

echo "✓ Role Kubernetes auth configurada"

# Instalar External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true \
  --wait

echo "✓ External Secrets Operator instalado"

# Criar namespace e ServiceAccount
kubectl create namespace lab05-vault
kubectl create serviceaccount api-pagamentos-sa -n lab05-vault

# Criar SecretStore e ExternalSecret
kubectl apply -f - << 'YAML'
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: lab05-vault
spec:
  provider:
    vault:
      server: "http://host.docker.internal:8200"  # Vault no host
      path: "bancomeridian"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "api-pagamentos-k8s"
          serviceAccountRef:
            name: api-pagamentos-sa
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-config
  namespace: lab05-vault
spec:
  refreshInterval: 55m
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: api-pagamentos-config
    creationPolicy: Owner
  data:
    - secretKey: db_host
      remoteRef:
        key: api-pagamentos/config
        property: db_host
    - secretKey: db_name
      remoteRef:
        key: api-pagamentos/config
        property: db_name
YAML

sleep 10
kubectl get externalsecret -n lab05-vault
kubectl get secret api-pagamentos-config -n lab05-vault -o jsonpath='{.data}' | \
  python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for key, val in data.items():
    decoded = base64.b64decode(val).decode()
    print(f'{key}: {decoded}')
"

echo "✓ External Secrets sincronizando secrets do Vault para K8s Secret nativo"
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Vault iniciado | `vault status` retorna `Sealed: false` |
| 2 | PostgreSQL rodando | `psql` conecta com sucesso |
| 3 | Database engine configurado | `vault read database/config/bancomeridian-db` |
| 4 | Roles criadas | `vault list database/roles` mostra 2 roles |
| 5 | Credencial dinâmica gerada | `psql` conecta com usuário `v-role-...` |
| 6 | Expiração demonstrada | Após revogação, `psql` retorna `role does not exist` |
| 7 | AppRole configurado | `vault read auth/approle/role/api-pagamentos/role-id` retorna UUID |
| 8 | Fluxo AppRole testado | Aplicação obteve token e credencial dinâmica |
| 9 | KV v2 configurado | `vault kv get bancomeridian/api-pagamentos/config` |
| 10 | ESO instalado | `kubectl get externalsecret -n lab05-vault` |

---

## 8. Gabarito Completo

### Saída Esperada — Geração de Credencial Dinâmica

```
Key                Value
---                -----
lease_id           database/creds/readonly-api/KjNmQrStUvWxYzAb
lease_duration     1h
lease_renewable    true
password           A1B2c3d4-E5F6g7H8-i9J0kL1M
username           v-role-readonly-api-AbCd1234-1714000000
```

### Saída Esperada — Verificação de Expiração

```
Credencial revogada. Tentando conexão...
psql: error: connection to server at "localhost" (127.0.0.1), port 5432 failed:
FATAL:  role "v-role-readonly-api-AbCd1234-1714000000" does not exist

rolname
-------
(0 rows)
```

### Saída Esperada — Fluxo AppRole Completo

```
Etapa 1 — CI/CD gerou Secret ID (expira em 10min): yyyyyyyy-yyyy-yyyy...
Etapa 2 — Aplicação autenticou, recebeu token: s.XXXXXXXXXXXXXXXX...
Etapa 3 — Aplicação obteve credencial dinâmica: v-role-readonly-api-EfGh5678-...
Etapa 4 — Conectando ao banco com credencial dinâmica...

 resultado
---------------------------------------------------------
 Conexão bem-sucedida! Usuário: v-role-readonly-api-...
```

### Comparativo Audit Log — Antes/Depois

| Dimensão | Antes do Vault | Depois do Vault |
|:---------|:--------------:|:---------------:|
| Senha | Estática, hardcoded | Dinâmica, única por request |
| Validade | Permanente | 1 hora |
| Rastreabilidade | Nenhuma | Cada acesso auditado com identidade |
| Rotação | Manual, com downtime | Automática, sem downtime |
| Comprometimento | Toda a duração de vida da senha | Apenas 1 hora (TTL restante) |
| Conformidade BACEN Art. 8 | Violação | Conforme |

---

*Lab 05 — HashiCorp Vault: Eliminando Credenciais Estáticas*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
