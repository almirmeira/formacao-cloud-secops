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

**O que esta seção faz (visão geral):** Os 10 passos deste laboratório seguem a progressão natural de uma implementação real de secrets management: primeiro o servidor (Passo 1), depois o recurso protegido (Passo 2), depois o mecanismo de proteção (Passos 3-4), depois a validação do mecanismo (Passos 5-6), depois a autenticação das aplicações (Passos 7-8), e finalmente a extensão para secrets estáticos e para orquestração Kubernetes (Passos 9-10). Esta ordem não é arbitrária — cada passo cria pré-requisitos concretos para o próximo.

**Por que a ordem importa para a segurança:** No contexto do BACEN 4.893 Art. 8, o requisito é que "credenciais sejam gerenciadas com controles adequados". Isso significa que não basta ter um Vault funcionando — é preciso demonstrar o ciclo completo: geração, uso, expiração e auditoria. Cada passo deste lab documenta um elo desse ciclo.

---

### Passo 1: Iniciar Vault em Modo Dev

**O que este passo faz:** Instala e inicia o HashiCorp Vault em modo desenvolvimento (`-dev`). O modo dev inicializa o Vault automaticamente com um seal key único, armazena dados em memória (não em disco) e usa HTTP sem TLS — tudo configurado para facilitar o aprendizado sem necessidade de uma infraestrutura complexa. O token fixo `lab-root-token` permite autenticação previsível durante o lab, substituindo o fluxo de unseal com múltiplos key shares que seria necessário em produção.

**Por que este passo vem primeiro:** Sem o Vault iniciado e acessível, nenhum dos passos subsequentes é possível. O Vault é o ponto central de controle de todos os secrets — ele precisa estar operacional antes de configurar qualquer integração. Verificar `vault status` com `Sealed: false` é a garantia de que o servidor está pronto para receber configurações.

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

**O que confirma que funcionou:** O campo `Sealed: false` é o indicador crítico. Um Vault "sealed" (selado) não serve nenhuma requisição — todos os dados estão criptografados e inacessíveis até que o unseal key correto seja fornecido. `Sealed: false` significa que o Vault foi devidamente inicializado e está pronto para operar. O campo `Storage Type: inmem` confirma que estamos em modo dev (dados em memória, não persistidos em disco).

**Troubleshooting:** Se a porta 8200 estiver em uso:
```bash
vault server -dev -dev-root-token-id="lab-root-token" -dev-listen-address="127.0.0.1:8201" &
export VAULT_ADDR='http://127.0.0.1:8201'
```

---

### Passo 2: Iniciar PostgreSQL para o Laboratório

**O que este passo faz:** Sobe um container PostgreSQL com credenciais administrativas temporárias (`vault_admin`/`vault_lab_admin_2025`) e cria a tabela `transacoes` com dados fictícios do Banco Meridian. O usuário `vault_admin` é o "super usuário" de bootstrap — ele tem permissão de CREATE ROLE e GRANT, que o Vault usará nos Passos 3-5 para criar e revogar usuários dinamicamente. A tabela `transacoes` simula o recurso crítico que as credenciais dinâmicas protegerão.

**Por que este passo vem antes da configuração do Vault:** O Vault precisa testar a conectividade com o PostgreSQL no momento da configuração (Passo 3, `vault write database/config`). Se o PostgreSQL não estiver rodando, o `vault write` falhará com erro de conexão e o Passo 3 não poderá ser concluído. A ordem correta é: infraestrutura primeiro, Vault depois.

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

**O que confirma que funcionou:** A query `SELECT COUNT(*)` retorna 3 — confirmando que a tabela foi criada e os dados inseridos com sucesso. Se retornar 0 ou erro, o Vault não terá dados para demonstrar a diferença de acesso entre as roles `readonly-api` e `readwrite-transacoes`. O `SELECT version()` que precede a criação da tabela confirma que a conexão TCP com o PostgreSQL está funcionando — se este passo falhar, a causa mais comum é o container ainda estar inicializando (aumente o `sleep 5` para `sleep 10`).

---

### Passo 3: Configurar PostgreSQL Secret Engine

**O que este passo faz:** Habilita o "database secret engine" do Vault — o módulo responsável por gerar credenciais dinâmicas para bancos de dados. Em seguida, configura a conexão entre o Vault e o PostgreSQL usando as credenciais do `vault_admin`. A partir deste momento, o Vault tem capacidade de executar statements DDL (`CREATE ROLE`, `GRANT`, `REVOKE`, `DROP ROLE`) no PostgreSQL como `vault_admin`, mas nenhuma aplicação cliente terá acesso direto a essas credenciais administrativas. O objetivo de segurança é que `vault_admin`/`vault_lab_admin_2025` nunca mais precise ser distribuída — o Vault age como proxy privilegiado.

**Por que este passo vem após o PostgreSQL estar funcionando:** O comando `vault write database/config` inclui um teste de conectividade implícito — o Vault tenta conectar ao PostgreSQL com as credenciais fornecidas para validar a configuração. Se o PostgreSQL estiver inacessível ou as credenciais estiverem erradas, o comando falhará com mensagem de erro de conexão. Este comportamento "fail fast" é intencional: melhor descobrir agora do que quando uma aplicação tentar obter uma credencial dinâmica.

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

**O que confirma que funcionou:** O `vault write database/config/bancomeridian-db` não retorna erro. Em seguida, o `vault read database/config/bancomeridian-db` exibe a configuração com `allowed_roles: [readonly-api readwrite-transacoes]` — mas sem exibir a senha do `vault_admin` (o Vault armazena credenciais de forma criptografada e nunca as retorna em leitura, apenas as usa internamente). A ausência da senha na saída do `vault read` é evidência de que o mecanismo de proteção está funcionando.

---

### Passo 4: Criar Roles com TTL

**O que este passo faz:** Define duas "roles" no Vault — templates que descrevem quais permissões SQL uma credencial dinâmica receberá ao ser gerada. A role `readonly-api` cria usuários PostgreSQL com apenas `SELECT` (para a API de consulta de transações) e a role `readwrite-transacoes` cria usuários com `SELECT, INSERT, UPDATE` (para o serviço de processamento). Os templates `{{name}}`, `{{password}}` e `{{expiration}}` são substituídos pelo Vault no momento da geração — o banco recebe o DDL completo e cria o usuário com expiração já configurada no próprio PostgreSQL (`VALID UNTIL`). O TTL de 1h significa que mesmo que o Vault falhe, o PostgreSQL removerá o acesso quando o horário de expiração chegar.

**Por que este passo vem antes da geração de credenciais:** Sem uma role definida, o comando `vault read database/creds/readonly-api` do Passo 5 retornará erro "role not found". As roles são o blueprint que o Vault usa para saber quais statements SQL executar — elas precisam existir antes de qualquer pedido de credencial.

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

**O que confirma que funcionou:** Os dois comandos `vault write database/roles/...` retornam sem erro. Para verificar:
```bash
vault list database/roles
```
O resultado deve listar `readonly-api` e `readwrite-transacoes`. Se um nome aparecer diferente (ex.: `readonly_api` com underscore), o Passo 5 falhará porque o nome da role é case-sensitive e exact-match.

---

### Passo 5: Gerar Credencial Dinâmica e Testar

**O que este passo faz:** Este é o momento central do laboratório — a primeira geração de uma credencial dinâmica. O comando `vault read database/creds/readonly-api` instrui o Vault a: (1) gerar um nome de usuário único com timestamp (ex.: `v-role-readonly-api-KjNm-1714000000`), (2) gerar uma senha aleatória de alta entropia, (3) executar os `creation_statements` da role no PostgreSQL como `vault_admin`, e (4) retornar o nome e a senha para quem requisitou — junto com um `lease_id` para rastrear e eventualmente revogar esta credencial específica. Todo esse processo ocorre em milissegundos e sem qualquer intervenção humana.

**Por que este passo vem após definir as roles:** A geração de credenciais referencia uma role existente (`readonly-api`). O Vault usa a role para saber quais statements executar, qual TTL aplicar e qual banco de dados usar. Sem a role, o Vault não tem como saber quais permissões conceder ao novo usuário.

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

**O que confirma que funcionou:** Três confirmações simultâneas: (1) `current_user` mostra o nome `v-role-readonly-api-...` — confirmando que a conexão PostgreSQL usou o usuário dinâmico, não o `vault_admin`; (2) `transacoes_visiveis = 3` — confirmando que o `GRANT SELECT` foi aplicado corretamente; (3) a query `pg_roles` mostra o usuário com `rolvaliduntil` definido para 1h no futuro — confirmando que o TTL foi aplicado também no nível do PostgreSQL como dupla garantia.

---

### Passo 6: Demonstrar Expiração Automática

**O que este passo faz:** Simula a expiração automática revogando manualmente o lease da credencial gerada no Passo 5. Em produção, o Vault executaria este processo automaticamente após 1h — aqui fazemos manualmente para demonstrar o comportamento sem esperar. Quando `vault lease revoke` é chamado, o Vault executa os `revocation_statements` da role no PostgreSQL (`REVOKE ALL` e `DROP ROLE`) usando o `vault_admin`. O resultado é que o usuário dinâmico deixa de existir no PostgreSQL imediatamente — qualquer conexão ativa com aquele usuário seria terminada.

**Por que este passo vem imediatamente após a geração:** A demonstração de expiração só faz sentido logo após a geração, enquanto o `LEASE_ID` ainda está na variável de ambiente. Este é o fechamento do ciclo de vida de uma credencial dinâmica: geração (Passo 5) → uso → expiração (Passo 6). Demonstrar os três momentos em sequência é o que faz o aluno internalizar que credenciais dinâmicas têm um ciclo de vida gerenciado, diferente de senhas estáticas que simplesmente "existem" até alguém decidir rotacioná-las.

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

**O que confirma que funcionou:** O erro `FATAL: role does not exist` e o resultado `(0 rows)` da query `pg_roles` confirmam dois níveis de proteção: (1) o Vault executou os `revocation_statements` com sucesso (o PostgreSQL eliminou o role); (2) o banco de dados não tem vestígio do usuário — um atacante que obtivesse o `LEASE_ID` após a revogação não conseguiria reutilizá-lo. Este comportamento contrasta diretamente com o cenário de credencial estática: se a senha `BancoMeridian@2024!` fosse comprometida, ela continuaria funcional indefinidamente até rotação manual.

---

### Passo 7: Configurar AppRole Auth

**O que este passo faz:** Habilita o método de autenticação AppRole e cria uma política (`api-pagamentos-policy`) que define exatamente o que a aplicação pode acessar no Vault. A política usa o princípio de least privilege: a aplicação `api-pagamentos` pode apenas ler credenciais da role `readonly-api`, renovar seus próprios leases e revogar seu próprio token — nada mais. O Role ID gerado ao final é o "endereço público" da aplicação no Vault — pode estar no código-fonte sem comprometer a segurança, pois sozinho não concede nenhum acesso.

**Por que este passo vem após validar as credenciais dinâmicas:** A ordem correta é: primeiro provar que o mecanismo de credenciais dinâmicas funciona (Passos 3-6), depois configurar o mecanismo de autenticação que as aplicações usarão para acessá-lo (Passo 7). Se o database engine não estivesse funcionando, configurar o AppRole seria inútil — a aplicação autenticaria no Vault mas não conseguiria obter credenciais do banco.

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

**O que confirma que funcionou:** O Role ID é exibido como UUID (formato `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Para verificar a política:
```bash
vault policy read api-pagamentos-policy
```
A saída deve mostrar exatamente as 5 paths configuradas. Se qualquer path estiver faltando ou com capability errada, a aplicação receberá erros de permissão no Passo 8.

---

### Passo 8: Demonstrar Fluxo de Autenticação da Aplicação

**O que este passo faz:** Simula o fluxo completo de uma aplicação real usando AppRole: o CI/CD gera um Secret ID efêmero (expira em 10 minutos), a aplicação usa Role ID + Secret ID para obter um token Vault (válido por 20 minutos), e com esse token a aplicação obtém a credencial dinâmica do banco. Nenhum momento neste fluxo a aplicação conhece a senha do `vault_admin` ou a senha do usuário dinâmico que será usado — ela recebe apenas credenciais com escopo mínimo e tempo de vida limitado.

**Por que este passo demonstra o conceito de "zero trust para aplicações":** O Secret ID tem `ttl=10m` — se o pipeline CI/CD for comprometido, o atacante tem no máximo 10 minutos para usar o Secret ID antes que expire. O token tem `token_num_uses=10` — mesmo que interceptado, só pode ser usado 10 vezes. A credencial do banco tem `ttl=1h` — mesmo que o banco de dados seja atacado e os processos listados, as credenciais expiram automaticamente. Três camadas de limitação temporal: Secret ID, Token, Credencial. Cada camada independente.

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

**O que confirma que funcionou:** A query final retorna `Conexão bem-sucedida! Usuário: v-role-readonly-api-EfGh...` — confirmando que a aplicação (representada pelo `APP_TOKEN`) conseguiu se autenticar no Vault com as permissões restritas da política `api-pagamentos-policy` e obter uma credencial dinâmica funcional para o banco. Se ocorrer erro de permissão (`permission denied`) no Passo 3 (obtenção da credencial), verifique se a política foi aplicada corretamente à role AppRole.

---

### Passo 9: Configurar KV v2 para Secrets Estáticos

**O que este passo faz:** Habilita o Key-Value versão 2 (KV v2) no path `bancomeridian` — um mecanismo de armazenamento de secrets estáticos com versionamento. Enquanto o database engine (Passos 3-6) gerencia credenciais que mudam a cada request, o KV v2 gerencia secrets que mudam com menos frequência: configurações de host/porta, API keys de terceiros, valores de configuração. O versionamento do KV v2 permite auditoria histórica — é possível ver não apenas o valor atual de um secret, mas também todos os valores anteriores com timestamps de quem e quando alterou.

**Por que este passo complementa (e não substitui) os passos anteriores:** KV v2 é para o que NÃO pode ser dinâmico — o endereço do servidor de banco (`db_host`), que não muda a cada request, deve estar no KV v2. A senha do banco (`db_password`), que PODE ser dinâmica, deve usar o database engine. Esta separação é a arquitetura correta de secrets management: use dynamic credentials onde possível, use KV v2 com rotação regular onde não for possível.

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

**O que confirma que funcionou:** O `vault kv get bancomeridian/api-pagamentos/config` exibe os pares chave-valor escritos, com o cabeçalho mostrando `version = 1` e `created_time`. O `vault kv metadata get` exibe o histórico de versões — mesmo que só exista a versão 1, a estrutura está pronta para registrar versões futuras. Em um audit de conformidade BACEN, este histórico de versões demonstra que a gestão de secrets tem rastreabilidade completa de alterações.

---

### Passo 10: Integrar com Kubernetes via External Secrets Operator

**O que este passo faz:** Configura o External Secrets Operator (ESO) — um operador Kubernetes que sincroniza automaticamente secrets do Vault para objetos `Secret` nativos do Kubernetes. O ESO usa a autenticação Kubernetes (Service Account + JWT Token) para se autenticar no Vault, lê os secrets do KV v2, e os projeta como Kubernetes Secrets no namespace da aplicação. A aplicação Kubernetes acessa seus secrets como variáveis de ambiente ou volumes — sem nunca interagir diretamente com a API do Vault. O `refreshInterval: 55m` garante que se um secret for rotacionado no Vault, o Kubernetes Secret será atualizado automaticamente em até 55 minutos.

**Por que este passo fecha o ciclo do laboratório:** Os Passos 1-8 demonstraram o Vault como solução de secrets management standalone. O Passo 10 demonstra como integrar essa solução ao ambiente de produção real do Banco Meridian — que roda workloads containerizadas em Kubernetes. Sem esta integração, o Vault seria uma ferramenta auxiliar que os desenvolvedores precisariam chamar explicitamente; com o ESO, o Vault se torna transparente para as aplicações e automático para as operações.

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

**O que confirma que funcionou:** O `kubectl get externalsecret -n lab05-vault` deve mostrar o ExternalSecret `api-config` com `READY = True` e `STATUS = SecretSynced`. Se mostrar `SecretSyncedError`, os logs do ESO (`kubectl logs -n external-secrets deploy/external-secrets`) indicarão se o problema é de autenticação (Vault rejeitou o Service Account) ou de path (key incorreta no KV v2). O script Python que lê o Kubernetes Secret (`api-pagamentos-config`) deve exibir `db_host: postgres.bancomeridian.internal` — confirmando que o valor do Vault chegou ao Kubernetes sem que nenhuma credencial intermediária precisasse ser gerenciada manualmente.

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
