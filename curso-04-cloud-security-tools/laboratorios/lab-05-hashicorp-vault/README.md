# Lab 05 — HashiCorp Vault: Eliminando Credenciais Estáticas
## Curso 4: Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2 horas  
> **Dificuldade:** Avançado  
> **Módulo Relacionado:** Módulo 07 — Secrets Management  

---

## 1. Contexto Situacional

O Banco Meridian tem a senha do banco de dados PostgreSQL hardcoded em todas as aplicações que acessam o banco. A senha `BancoMeridian@2024!` está visível em arquivos `docker-compose.yml`, variáveis de ambiente não criptografadas, e até em logs de CI/CD. A senha nunca foi rotacionada em 18 meses.

---

## 2. Situação Inicial

Evidência encontrada no repositório:
```yaml
# docker-compose.yml:
DB_PASSWORD: "BancoMeridian@2024!"
DB_HOST: "postgres.interno.local"
DB_PORT: "5432"
DB_USER: "api_pagamentos"
```
Esta senha existe em texto claro em múltiplos sistemas. Não há rotação automática. Não há rastreabilidade de quem usou a senha e quando. Se um desenvolvedor copiar o docker-compose.yml, terá acesso permanente ao banco de produção.

---

## 3. Problema Identificado

Credenciais estáticas violam o BACEN 4.893 Art. 8 (gestão de acessos com menor privilégio) porque:
1. A senha permanece válida indefinidamente — sem TTL
2. Não há rastreabilidade de uso — qual aplicação usou quando
3. Comprometimento de um repositório expõe todas as aplicações
4. Rotação manual requer downtime coordenado de todas as aplicações

---

## 4. Roteiro de Atividades

1. Iniciar Vault em modo dev
2. Subir PostgreSQL local de teste
3. Habilitar PostgreSQL Secret Engine
4. Criar roles de credencial dinâmica
5. Gerar credencial dinâmica e testar
6. Revogar credencial e verificar expiração
7. Configurar AppRole para autenticação da aplicação
8. Demonstrar fluxo de autenticação da aplicação
9. Criar KV store para configurações não-sensíveis
10. Integrar com Kubernetes via External Secrets Operator

---

## 5. Proposição

Ao final deste laboratório, você terá demonstrado que: (a) credenciais dinâmicas são únicas por request, (b) expiram automaticamente após 1h, (c) a aplicação se autentica via AppRole sem conhecer a senha do banco, e (d) a integração com K8s via ESO funciona de forma transparente para a aplicação.

---

## 6. Script Passo a Passo

### Passo 1: Iniciar Vault em Modo Dev

**O que este passo faz:** Inicia o HashiCorp Vault em modo desenvolvimento (`-dev`). O modo dev é inseguro para produção mas perfeito para laboratórios — ele: inicia sem necessidade de unseal manual, usa armazenamento em memória (os dados somem ao reiniciar o Vault), e gera automaticamente um root token fixo que você especifica com `--dev-root-token-id`. As variáveis de ambiente `VAULT_ADDR` e `VAULT_TOKEN` configuram o cliente CLI para se comunicar com o servidor Vault local.

**Por que agora:** O Vault precisa estar rodando antes de qualquer configuração de secret engine ou autenticação. O modo dev simplifica a inicialização para que você possa focar na lógica de secrets management, não na operação do Vault.

```bash
# Instalar Vault (se não instalado)
# macOS:
# brew tap hashicorp/tap && brew install hashicorp/tap/vault

# Linux:
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Verificar versão
vault version

# Iniciar Vault em modo dev com token fixo
vault server -dev -dev-root-token-id="lab-root-token" &
VAULT_PID=$!

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='lab-root-token'

# Verificar status
vault status
vault token lookup
```

**O que você deve ver:**
```
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.15.x
...
```
O `Sealed: false` confirma que o Vault está pronto para uso. Em produção, o Vault inicia `Sealed` e precisa de uma cerimônia de unseal com múltiplas chaves antes de aceitar requisições.

---

### Passo 2: Subir PostgreSQL Local de Teste

**O que este passo faz:** Inicia um container PostgreSQL de teste representando o banco de dados do Banco Meridian. O usuário `vault_admin` é o usuário que o Vault usará para criar e revogar credenciais dinâmicas — ele precisa ter permissão `CREATEROLE` no PostgreSQL. O script SQL cria a tabela `transacoes` e insere dados de teste para que as credenciais dinâmicas possam ser testadas com uma query real.

**Por que agora:** O Vault precisa de um banco de dados real para configurar o secret engine. Sem o PostgreSQL rodando, os passos de configuração do database engine e geração de credenciais falharão.

```bash
# Iniciar PostgreSQL via Docker
docker run -d \
  --name bancomeridian-postgres \
  -e POSTGRES_USER=vault_admin \
  -e POSTGRES_PASSWORD=vault_lab_admin_2025 \
  -e POSTGRES_DB=bancomeridian \
  -p 5432:5432 \
  postgres:15

# Aguardar PostgreSQL ficar pronto
sleep 5

# Criar estrutura de teste
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

**O que você deve ver:**
```
 total_transacoes
------------------
        3
```

---

### Passo 3: Habilitar PostgreSQL Secret Engine

**O que este passo faz:** Habilita o secret engine `database` do Vault e configura a conexão com o PostgreSQL do Banco Meridian. O `vault secrets enable database` ativa o engine no caminho `/database/`. O `vault write database/config/bancomeridian-db` configura a conexão: o Vault armazena as credenciais do `vault_admin` (necessárias para criar roles dinâmicas) de forma criptografada — a aplicação nunca vê essas credenciais. O `{{username}}` e `{{password}}` na connection_url são substituídos pelo Vault em tempo de execução.

**Por que agora:** O database secret engine é o coração deste laboratório. Sem ele, o Vault não sabe como se conectar ao PostgreSQL para criar as credenciais dinâmicas. Esta configuração precisa vir antes da criação das roles e da geração de credenciais.

```bash
# Habilitar database secret engine
vault secrets enable database
echo "Database secret engine habilitado"

# Configurar conexão com PostgreSQL do Banco Meridian
vault write database/config/bancomeridian-db \
    plugin_name=postgresql-database-plugin \
    allowed_roles="readonly-api,readwrite-transacoes" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/bancomeridian?sslmode=disable" \
    username="vault_admin" \
    password="vault_lab_admin_2025" \
    max_open_connections=5

# Verificar configuração
vault read database/config/bancomeridian-db
```

**O que você deve ver:** A configuração exibe os parâmetros sem a senha — o Vault nunca expõe a senha do `vault_admin` após a configuração. Apenas o campo `username` é visível.

---

### Passo 4: Criar Roles de Credencial Dinâmica

**O que este passo faz:** Cria duas roles no Vault que definem como as credenciais dinâmicas serão geradas:

- **readonly-api**: role para a API de consultas — acesso de leitura apenas (SELECT). O `creation_statements` é o SQL que o Vault executa no PostgreSQL quando uma credencial é solicitada. O `{{name}}` é substituído pelo Vault por um nome único gerado automaticamente (ex: `v-role-readonly-api-KjNm-1714000000`). O TTL de 1h significa que o role PostgreSQL e suas permissões são automaticamente revogados após 1 hora.

- **readwrite-transacoes**: role para a API de processamento de transações — acesso de leitura e escrita na tabela de transações.

**Por que agora:** As roles definem os "moldes" das credenciais. Você precisa criá-las antes de poder solicitar credenciais dinâmicas. Cada role pode ter TTL e permissões diferentes — princípio de menor privilégio aplicado a credenciais.

```bash
# Criar role readonly para a API de consultas
vault write database/roles/readonly-api \
    db_name=bancomeridian-db \
    creation_statements="
        CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
        GRANT CONNECT ON DATABASE bancomeridian TO \"{{name}}\";
        GRANT USAGE ON SCHEMA public TO \"{{name}}\";
        GRANT SELECT ON transacoes TO \"{{name}}\";
    " \
    revocation_statements="
        REVOKE ALL ON transacoes FROM \"{{name}}\";
        DROP ROLE IF EXISTS \"{{name}}\";
    " \
    default_ttl="1h" \
    max_ttl="8h"

echo "Role readonly-api criada (TTL: 1h)"

# Criar role readwrite para processamento de transações
vault write database/roles/readwrite-transacoes \
    db_name=bancomeridian-db \
    creation_statements="
        CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
        GRANT CONNECT ON DATABASE bancomeridian TO \"{{name}}\";
        GRANT USAGE ON SCHEMA public TO \"{{name}}\";
        GRANT SELECT, INSERT, UPDATE ON transacoes TO \"{{name}}\";
    " \
    revocation_statements="
        REVOKE ALL ON transacoes FROM \"{{name}}\";
        DROP ROLE IF EXISTS \"{{name}}\";
    " \
    default_ttl="1h" \
    max_ttl="8h"

echo "Role readwrite-transacoes criada (TTL: 1h)"
```

---

### Passo 5: Gerar Credencial Dinâmica e Testar

**O que este passo faz:** Solicita uma credencial dinâmica ao Vault para a role `readonly-api` e usa imediatamente para conectar ao PostgreSQL. O `vault read database/creds/readonly-api` instrui o Vault a: (1) se conectar ao PostgreSQL como `vault_admin`, (2) executar o `creation_statements` da role com um nome único, (3) retornar o username e password gerados. O `Lease ID` é o identificador desta credencial específica — você pode usá-lo para revogar antecipadamente. O TTL de 1h é o tempo até que o Vault automaticamente execute o `revocation_statements` e remova o role do PostgreSQL.

**Por que agora:** Esta é a demonstração central do laboratório — substituindo `BancoMeridian@2024!` estático por uma credencial única, rastreável, com TTL automático. O contraste com a situação inicial é imediato.

```bash
echo ""
echo "=== GERANDO CREDENCIAIS DINÂMICAS ==="
echo "Antes do Vault: senha estática 'BancoMeridian@2024!' válida para sempre"
echo "Depois do Vault: credencial única gerada agora, expira em 1h"
echo ""

# Gerar credencial dinâmica
CREDS=$(vault read -format=json database/creds/readonly-api)
DB_USER=$(echo $CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['username'])")
DB_PASS=$(echo $CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['password'])")
LEASE_ID=$(echo $CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['lease_id'])")
TTL=$(echo $CREDS | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['lease_duration'])")

echo "Credencial gerada:"
echo "  Usuário: $DB_USER"
echo "  Senha: [REDACTED — não logada por segurança]"
echo "  TTL: ${TTL}s ($(($TTL/3600))h)"
echo "  Lease ID: $LEASE_ID"

# Testar conexão com a credencial dinâmica
echo ""
echo "Testando conexão com credencial dinâmica..."
PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d bancomeridian \
  -c "SELECT current_user, COUNT(*) as transacoes FROM transacoes;" 2>&1
```

**O que você deve ver:**
```
Credencial gerada:
  Usuário: v-role-readonly-api-KjNm-1714000000
  TTL: 3600s (1h)
  Lease ID: database/creds/readonly-api/abc123xyz

 current_user                           | transacoes
----------------------------------------+-----------
 v-role-readonly-api-KjNm-1714000000   |          3
```
O nome do usuário como `v-role-readonly-api-KjNm-1714000000` é o padrão do Vault — cada credencial tem um nome único com timestamp, tornando-a rastreável nos logs do PostgreSQL.

---

### Passo 6: Revogar Credencial e Verificar Expiração

**O que este passo faz:** Revoga antecipadamente a credencial dinâmica usando o Lease ID e verifica que o role PostgreSQL foi removido. Esta é a demonstração do poder da revogação instantânea — em vez de rotacionar manualmente todas as aplicações, você revoga o lease e o Vault executa o `revocation_statements` automaticamente. Após a revogação, qualquer tentativa de usar aquela credencial resulta em "role does not exist" — exatamente o que você quer após um vazamento de credencial.

**Por que agora:** A revogação instantânea é um dos principais benefícios do Vault. No cenário do Banco Meridian: se um desenvolvedor vazar uma credencial estática, você precisa rotacionar a senha em todos os sistemas (downtime). Com Vault: você revoga o lease e a credencial expira em segundos, sem downtime.

```bash
echo "Revogando credencial imediatamente (antes da expiração)..."
vault lease revoke "$LEASE_ID"
echo "Credencial revogada!"

echo ""
echo "Tentando usar a credencial revogada (deve falhar)..."
PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d bancomeridian \
  -c "SELECT 1;" 2>&1 || true

echo ""
echo "Verificando que o role foi removido do PostgreSQL..."
PGPASSWORD=vault_lab_admin_2025 psql -h localhost -U vault_admin -d bancomeridian \
  -c "SELECT rolname FROM pg_roles WHERE rolname LIKE 'v-role-readonly-api-%';"
```

**O que você deve ver:**
```
Revogando...
Success! Revoked lease: database/creds/readonly-api/abc123xyz

psql: error: connection to server at "localhost" (127.0.0.1), port 5432 failed:
FATAL: role "v-role-readonly-api-KjNm-1714000000" does not exist

 rolname
---------
(0 rows)
```
O `(0 rows)` confirma que o role PostgreSQL foi removido pelo Vault após a revogação. Em um cenário de vazamento de credencial, essa seria a resposta em segundos — sem necessidade de reiniciar aplicações.

---

### Passo 7: Configurar AppRole para Autenticação da Aplicação

**O que este passo faz:** Configura o método de autenticação AppRole, que permite que a aplicação (API de pagamentos) se autentique no Vault sem usar o root token. O AppRole funciona com dois componentes: `Role ID` (identificador público da aplicação, pode ser commitado no código) e `Secret ID` (credencial temporária que o CI/CD injeta na aplicação em runtime). A política `api-pagamentos-policy` define o que a aplicação pode fazer após autenticar — apenas ler credenciais da role `readonly-api` e nada mais.

**Por que agora:** Sem AppRole, a aplicação precisaria usar o root token para se autenticar no Vault — isso seria tão ruim quanto hardcodar a senha do banco. O AppRole implementa o princípio de menor privilégio para a autenticação da aplicação no Vault.

```bash
# Criar política para a API de pagamentos
vault policy write api-pagamentos-policy - << 'HCL'
# Política: API de pagamentos pode APENAS gerar credenciais readonly
path "database/creds/readonly-api" {
  capabilities = ["read"]
}

# Pode renovar seus leases
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Pode revogar seus próprios leases
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Pode ler configurações não-sensíveis
path "bancomeridian/data/api-pagamentos/*" {
  capabilities = ["read"]
}
HCL

# Habilitar AppRole
vault auth enable approle
echo "AppRole habilitado"

# Criar role AppRole para a API de pagamentos
vault write auth/approle/role/api-pagamentos \
    policies="api-pagamentos-policy" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    secret_id_ttl="10m" \
    secret_id_num_uses=1

# Obter Role ID (este é público, pode ser commitado)
ROLE_ID=$(vault read -field=role_id auth/approle/role/api-pagamentos/role-id)
echo "Role ID (público): $ROLE_ID"
```

---

### Passo 8: Demonstrar Fluxo de Autenticação da Aplicação

**O que este passo faz:** Demonstra o fluxo completo de autenticação que a API de pagamentos executa em cada inicialização:

1. **CI/CD gera Secret ID** (expira em 10min, uso único) — o Secret ID é tão efêmero que mesmo que seja interceptado, expira antes de ser utilizável
2. **Aplicação faz login no Vault** com Role ID + Secret ID → recebe um token temporário (TTL: 1h)
3. **Aplicação usa o token** para gerar credencial dinâmica do PostgreSQL
4. **Aplicação conecta ao banco** com a credencial dinâmica

Este fluxo garante que nem a senha do banco nem o root token do Vault existem em nenhum momento na memória da aplicação por mais de 1 hora.

**Por que agora:** Este é o passo que fecha o ciclo — demonstrando que a aplicação funciona sem nunca ter conhecimento de `BancoMeridian@2024!`. O fluxo AppRole é a arquitetura de referência para autenticação de aplicações no Vault.

```bash
echo "=== FLUXO: CI/CD → AppRole → Credential → DB ==="

# PASSO 1: CI/CD injeta o Secret ID no ambiente da aplicação
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/api-pagamentos/secret-id)
echo "Etapa 1 — CI/CD gerou Secret ID (expira em 10min): ${SECRET_ID:0:20}..."

# PASSO 2: Role ID + Secret ID → Token temporário
APP_TOKEN=$(vault write -field=token auth/approle/login \
    role_id="$ROLE_ID" \
    secret_id="$SECRET_ID")
echo "Etapa 2 — Aplicação autenticou, recebeu token: ${APP_TOKEN:0:20}..."

# PASSO 3: Token → Credencial dinâmica do banco
VAULT_TOKEN="$APP_TOKEN"
DB_CREDS_APP=$(vault read -format=json database/creds/readonly-api)
DB_USER_APP=$(echo $DB_CREDS_APP | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['username'])")
DB_PASS_APP=$(echo $DB_CREDS_APP | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['password'])")
echo "Etapa 3 — Aplicação obteve credencial dinâmica: $DB_USER_APP"

# PASSO 4: Credencial dinâmica → Conexão ao banco
echo "Etapa 4 — Conectando ao banco com credencial dinâmica..."
PGPASSWORD="$DB_PASS_APP" psql -h localhost -U "$DB_USER_APP" -d bancomeridian \
  -c "SELECT current_user, SUM(valor) as total FROM transacoes;" 2>&1

echo ""
echo "Fluxo completo: a aplicação nunca conheceu BancoMeridian@2024!"
```

**O que você deve ver:**
```
Etapa 1 — CI/CD gerou Secret ID (expira em 10min): c9d4e8f2-...
Etapa 2 — Aplicação autenticou, recebeu token: s.XXXXXXXXXXXXXXXX...
Etapa 3 — Aplicação obteve credencial dinâmica: v-role-readonly-api-EfGh5678-...
Etapa 4 — Conectando ao banco com credencial dinâmica...

 current_user                         | total
--------------------------------------+--------
 v-role-readonly-api-EfGh5678-...    | 425.50

Fluxo completo: a aplicação nunca conheceu BancoMeridian@2024!
```

---

### Passo 9: Criar KV Store para Configurações

**O que este passo faz:** Configura o secret engine KV (Key-Value) versão 2 para armazenar configurações não-sensíveis mas controladas da aplicação, como `db_host`, `redis_host`, `api_timeout`. O KV v2 tem versionamento automático — toda alteração cria uma nova versão, e você pode recuperar versões antigas. Também armazena chaves de APIs de terceiros (gateway de pagamento, SMS) que precisam estar centralizadas mas não hardcodadas.

**Por que agora:** Nem todo secret precisa ser dinâmico. Configurações como host do banco de dados e API keys de terceiros se beneficiam do vault como centralizador seguro, mas não precisam ser geradas dinamicamente. O KV é a solução para esses casos.

```bash
# Habilitar KV v2 no caminho bancomeridian/
vault secrets enable -path=bancomeridian kv-v2

# Armazenar configurações da API de pagamentos
vault kv put bancomeridian/api-pagamentos/config \
    db_host="postgres.bancomeridian.internal" \
    db_port="5432" \
    db_name="bancomeridian" \
    redis_host="redis.bancomeridian.internal" \
    api_timeout="30" \
    log_level="INFO"

# Armazenar API keys de terceiros
vault kv put bancomeridian/api-pagamentos/external-apis \
    payment_gateway_key="pgw_live_abc123" \
    sms_api_key="sms_live_xyz789"

echo "Configurações armazenadas no KV store"
vault kv metadata get bancomeridian/api-pagamentos/config
```

---

### Passo 10: Integrar com Kubernetes via External Secrets Operator

**O que este passo faz:** Configura a integração entre o Vault e o Kubernetes via External Secrets Operator (ESO). O ESO é um controller Kubernetes que sincroniza secrets do Vault para Kubernetes Secrets — a aplicação usa o Secret Kubernetes normalmente, sem saber que veio do Vault. O `SecretStore` define a conexão com o Vault (usando autenticação Kubernetes). O `ExternalSecret` define quais secrets buscar do Vault e como mapeá-los para o Kubernetes Secret.

**Por que agora:** A integração com Kubernetes é o passo final que torna a solução transparente para a aplicação. Os desenvolvedores continuam usando `env.valueFrom.secretKeyRef` normalmente — a mágica do Vault acontece no controller do ESO, invisível para a aplicação.

```bash
echo "=== INTEGRAÇÃO VAULT + KUBERNETES ==="

# Habilitar Kubernetes auth no Vault
vault auth enable kubernetes
echo "Kubernetes auth habilitado"

# Configurar Kubernetes auth
KUBE_CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d | base64 -w 0)
KUBE_HOST=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')

vault write auth/kubernetes/config \
    kubernetes_host="$KUBE_HOST" \
    kubernetes_ca_cert="$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)"

# Instalar External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
    -n external-secrets-system \
    --create-namespace

# Criar namespace para a aplicação
kubectl create namespace lab05-vault

# Criar SecretStore (conexão com Vault)
kubectl apply -f - << 'YAML'
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: lab05-vault
spec:
  provider:
    vault:
      server: "http://host.docker.internal:8200"
      path: "bancomeridian"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "lab05-vault-role"
          serviceAccountRef:
            name: "default"
YAML

# Criar ExternalSecret (quais secrets buscar)
kubectl apply -f - << 'YAML'
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
kubectl get secret api-pagamentos-config -n lab05-vault -o jsonpath='{.data}' | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for key, val in data.items():
    print(f'{key}: {base64.b64decode(val).decode()}')
"
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Vault iniciado | `vault status` retorna `Sealed: false` |
| 2 | PostgreSQL rodando | `psql` conecta com sucesso |
| 3 | Database engine configurado | `vault read database/config/bancomeridian-db` |
| 4 | Roles criadas | `vault list database/roles` |
| 5 | Credencial dinâmica gerada | Username com prefixo `v-role-readonly-api-` |
| 6 | Revogação funciona | `psql` com credencial revogada retorna "role does not exist" |
| 7 | AppRole configurado | Role ID gerado |
| 8 | Fluxo AppRole completo | Aplicação conecta ao banco sem senha estática |
| 9 | KV store configurado | `vault kv get bancomeridian/api-pagamentos/config` |
| 10 | ESO integrado | ExternalSecret sincronizado com Kubernetes Secret |

---

## 8. Gabarito Completo

### Saída Esperada — Revogação de Credencial (Passo 6)

```
Revogando...
Success! Revoked lease: database/creds/readonly-api/abc123xyz

psql: error: connection to server at "localhost" (127.0.0.1), port 5432 failed:
FATAL: role "v-role-readonly-api-AbCd1234-1714000000" does not exist

 rolname
---------
(0 rows)
```

**Por que esta é a resposta correta:** O `Success! Revoked lease` confirma que o Vault executou o `revocation_statements` da role — que contém `DROP ROLE IF EXISTS "{{name}}"`. O erro `FATAL: role does not exist` ao tentar conectar com a credencial revogada confirma que a revogação foi efetiva no PostgreSQL. O `(0 rows)` na consulta de roles confirma que não há nenhum role dinâmico pendente. Este é o comportamento que transforma um vazamento de credencial de um incidente de horas (rotação manual) para segundos (vault lease revoke).

**Erro mais comum:** Não exportar as variáveis `VAULT_ADDR` e `VAULT_TOKEN` antes de executar os comandos vault. Sem essas variáveis, o cliente vault tenta se conectar em `https://127.0.0.1:8200` com HTTPS, o que falha no modo dev (HTTP). O sintoma é `Error making API request: dial tcp 127.0.0.1:8200: connect: connection refused`.

---

### Saída Esperada — Fluxo AppRole Completo (Passo 8)

```
Etapa 1 — CI/CD gerou Secret ID (expira em 10min): c9d4e8f2-...
Etapa 2 — Aplicação token: s.XXXXXXXXXXXXXXXX...
Etapa 3 — Aplicação obteve credencial dinâmica: v-role-readonly-api-EfGh5678-...
Etapa 4 — Conectando banco com credencial dinâmica...

Conexão bem-sucedida! Usuario: v-role-readonly-api-...
```

**Por que esta é a resposta correta:** O fluxo de 4 etapas implementa o princípio de Zero Trust para acesso a banco de dados: (1) identidade efêmera (Secret ID expira em 10min, uso único), (2) token de curto prazo (TTL 1h), (3) credencial dinâmica única (rastreável no PostgreSQL), (4) acesso com menor privilégio (apenas SELECT na tabela de transações). Nenhuma credencial de longa duração existe em memória ou em disco na aplicação.

**Erro mais comum:** Tentar usar o mesmo Secret ID duas vezes. O `secret_id_num_uses=1` foi configurado deliberadamente — o Secret ID é destruído após o primeiro uso. Um segundo login com o mesmo Secret ID retorna `invalid secret id`. Isso é uma medida de segurança: mesmo que o Secret ID seja interceptado em trânsito, ele já foi consumido.

---

### Comparativo Antes/Depois

| Dimensão | Antes do Vault | Depois do Vault |
|:---------|:--------------:|:---------------:|
| Senha | Estática, hardcoded | Dinâmica, única por request |
| Validade | Permanente | 1 hora |
| Rastreabilidade | Nenhuma | Cada acesso auditado com identidade |
| Rotação | Manual, com downtime | Automática, sem downtime |
| Comprometimento | Toda a duração de vida da senha | Apenas 1 hora (TTL restante) |
| Conformidade BACEN Art. 8 | Violação | Conforme |

**Por que esta é a resposta correta:** O comparativo demonstra que a solução Vault resolve especificamente cada item do Art. 8 do BACEN 4.893 (gestão de acessos com menor privilégio). A linha "Comprometimento" é a mais impactante: com a senha estática, um vazamento expõe a credencial permanentemente até rotação manual; com o Vault, o pior caso é 1 hora de exposição (o TTL da credencial dinâmica).

**Erro mais comum:** Confundir o TTL do token do AppRole (1h) com o TTL da credencial do banco (também 1h neste laboratório, mas configurável). São TTLs independentes — o token do AppRole controla quanto tempo a aplicação está autenticada no Vault, enquanto o TTL da credencial do banco controla quanto tempo o role PostgreSQL dinâmico existe. Em produção, você pode configurar TTLs diferentes para cada um.

---

*Lab 05 — HashiCorp Vault: Eliminando Credenciais Estáticas*  
*Curso 4: Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
