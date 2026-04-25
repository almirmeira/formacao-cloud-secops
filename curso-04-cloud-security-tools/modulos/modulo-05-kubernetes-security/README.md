# Módulo 05 — Kubernetes Security
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1h videoaula + 1h laboratório  
> **Certificação Alvo:** CCSP domínio 3 / CCSK domínio 7  
> **Cenário:** Time de plataforma do Banco Meridian implementando security controls no cluster K8s

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Mapear a superfície de ataque específica de um cluster Kubernetes
2. Aplicar Pod Security Standards (PSS) por namespace com o nível correto
3. Escrever NetworkPolicies com default-deny e acesso mínimo necessário
4. Configurar RBAC com menor privilégio (sem cluster-admin para aplicações)
5. Criar políticas Kyverno para enforçar security controls preventivamente
6. Executar kube-bench e interpretar os resultados do CIS Kubernetes Benchmark

---

## 1. Kubernetes Attack Surface

A superfície de ataque de um cluster Kubernetes é significativamente maior do que um servidor tradicional:

```
SUPERFÍCIE DE ATAQUE DO KUBERNETES
──────────────────────────────────────────────────────────────────────────────
ACESSO EXTERNO
  ├── API Server (porta 6443) — exposto externamente?
  ├── etcd (porta 2379) — exposto sem TLS?
  ├── Kubelet API (porta 10250) — acesso anônimo?
  └── Dashboard — sem autenticação?

WORKLOADS
  ├── Containers privilegiados (--privileged)
  ├── hostPath mounts (acesso ao filesystem do nó)
  ├── hostNetwork: true (compartilha rede do nó)
  ├── hostPID: true (acesso a processos do nó)
  ├── runAsRoot (UID 0 dentro do container)
  └── Capabilities perigosas (CAP_SYS_ADMIN, CAP_NET_ADMIN)

IDENTIDADE E ACESSO
  ├── ServiceAccounts com cluster-admin
  ├── Tokens de ServiceAccount auto-montados desnecessariamente
  ├── RBAC excessivo (wildcards em verbs ou resources)
  └── Secrets em variáveis de ambiente (não em volumes)

REDE
  ├── Sem NetworkPolicy (todos os pods se comunicam com todos)
  ├── Serviços LoadBalancer expostos publicamente sem necessidade
  └── Ingress sem TLS

SUPPLY CHAIN
  ├── Imagens sem verificação de assinatura (módulo 4)
  ├── Imagens do Docker Hub sem fixação de digest
  └── Helm charts de fontes não confiáveis
──────────────────────────────────────────────────────────────────────────────
```

### 1.1 Os 5 Ataques Mais Comuns em K8s

| Ataque | Vetor | Impacto | Controle |
|:-------|:------|:--------|:---------|
| **Container escape** | Pod privilegiado ou hostPath | Comprometimento do nó | PSS Restricted + Kyverno |
| **Privilege escalation** | RBAC excessivo + ServiceAccount | Acesso cluster-admin | RBAC mínimo + CIEM |
| **Lateral movement** | Ausência de NetworkPolicy | Comprometimento de outros pods | NetworkPolicy default-deny |
| **Secret theft** | Secrets em env vars + RBAC no etcd | Exposição de credenciais | HashiCorp Vault + ESO |
| **Supply chain** | Imagem maliciosa no registry | Backdoor em produção | Cosign verify + Kyverno |

---

## 2. Pod Security Standards (PSS)

Pod Security Standards substituiu o deprecado PodSecurityPolicy (PSP) no Kubernetes 1.25. São 3 perfis com níveis crescentes de restrição.

### 2.1 Os Três Perfis

**Privileged:** Sem restrições. Acesso total ao nó. Apenas para componentes de sistema que realmente precisam (Falco, CNI plugins, CSI drivers).

**Baseline:** Restrições mínimas que evitam escaladas de privilégio mais óbvias. Bloqueia: hostProcess, hostNetwork, hostPID, hostPorts, AppArmor/SELinux sobrescrito, /proc mount, seccomp Unconfined, capabilities perigosas (NET_ADMIN, SYS_ADMIN). Adequado para a maioria das cargas de trabalho.

**Restricted:** Segurança máxima. Exige explicitamente: runAsNonRoot, drop ALL capabilities, seccompProfile RuntimeDefault ou Localhost. Adequado para cargas de trabalho de alto risco (processamento de dados sensíveis).

### 2.2 Como Aplicar PSS por Namespace

**O que estes manifestos fazem:** Os três namespaces a seguir implementam o padrão de segmentação de privilégios do Banco Meridian no cluster Kubernetes. O namespace `production` usa o perfil **Restricted** — o mais seguro — e aplica os três modos simultaneamente: `enforce` bloqueia qualquer pod que viole o perfil antes de ser criado (prevenção), `audit` registra violações no audit log do API server (rastreabilidade), e `warn` emite um aviso no terminal do desenvolvedor durante o `kubectl apply` (feedback imediato). O `enforce-version: v1.28` garante que as regras do PSS sejam as do Kubernetes 1.28 — isso evita surpresas quando o cluster é atualizado para uma versão que pode ter regras mais restritivas.

**Por que três namespaces com perfis diferentes:** Não é possível aplicar o perfil Restricted universalmente porque alguns componentes legítimos de sistema precisam de permissões elevadas. O Falco precisa de acesso ao kernel (perfil Privileged). Ferramentas de observabilidade como o Prometheus node-exporter precisam montar volumes do host (perfil Baseline). A API de pagamentos do Banco Meridian não precisa de nenhuma permissão elevada, portanto usa Restricted. Misturar tudo em um único namespace com perfil mais permissivo seria o caminho errado — o atacante que comprometesse um pod de pagamentos num namespace Privileged teria acesso ao kernel do nó.

```yaml
# PSS é aplicado via label no namespace
# Três modos de enforcement:
#   enforce: bloqueia pods que violam
#   audit:   permite mas registra no audit log
#   warn:    permite mas emite warning para o cliente

# Namespace de produção — perfil Restricted
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforça: bloqueia pods que violam Restricted
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    # Audit: registra violações do Restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    # Warn: avisa sobre violações do Restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
```

```yaml
# Namespace de infraestrutura — perfil Baseline (para apps que precisam de capabilities)
apiVersion: v1
kind: Namespace
metadata:
  name: infra-tools
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
```

```yaml
# Namespace de sistema — perfil Privileged (apenas componentes de sistema)
apiVersion: v1
kind: Namespace
metadata:
  name: falco-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
```

**O que o Pod a seguir demonstra:** O Pod `api-pagamentos` exemplifica uma configuração que satisfaz completamente o perfil Restricted. Cada campo do `securityContext` tem uma finalidade específica de segurança: `runAsNonRoot: true` impede que o container rode como root (UID 0), que é o usuário default em muitas imagens Docker e o vetor de múltiplos ataques de container escape; `allowPrivilegeEscalation: false` bloqueia chamadas de sistema como `setuid` ou `sudo` que elevam privilégios dentro do container; `readOnlyRootFilesystem: true` impede que malware persista no filesystem do container modificando binários; `capabilities: drop: [ALL]` remove todas as capabilities Linux (mesmo as concedidas por padrão ao root), como `NET_ADMIN` e `SYS_PTRACE`, que poderiam ser abusadas para atacar outros containers ou o nó. O uso de digest SHA256 na imagem (`@sha256:abc123`) garante imutabilidade — não é possível substituir a imagem silenciosamente via um novo push com a mesma tag.

```yaml
# Pod que satisfaz o perfil Restricted
apiVersion: v1
kind: Pod
metadata:
  name: api-pagamentos
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true          # Não pode rodar como root
    runAsUser: 1000             # UID específico (não root)
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault      # Seccomp profile padrão do runtime

  containers:
    - name: api
      image: bancomeridian/api-pagamentos:v1.2.0@sha256:abc123
      securityContext:
        allowPrivilegeEscalation: false    # Bloqueia sudo/setuid
        readOnlyRootFilesystem: true       # Filesystem imutável
        capabilities:
          drop:
            - ALL                          # Remove todas as capabilities
        runAsNonRoot: true
      resources:
        requests:
          memory: "64Mi"
          cpu: "250m"
        limits:
          memory: "128Mi"
          cpu: "500m"
      volumeMounts:
        - name: tmp
          mountPath: /tmp                  # tmp writable (necessário para alguns apps)

  volumes:
    - name: tmp
      emptyDir: {}                         # Volume temporário, não hostPath
```

---

## 3. NetworkPolicy

### 3.1 Como Funciona

NetworkPolicies são recursos Kubernetes que controlam o tráfego de rede entre pods. São aplicadas pelo CNI (Container Network Interface) — requerem um CNI compatível (Calico, Cilium, Weave, Amazon VPC CNI com Network Policy addon).

**Ponto crítico:** Por padrão, sem NetworkPolicy, TODOS os pods se comunicam com TODOS. Um pod comprometido pode alcançar qualquer banco de dados, API interna ou serviço em qualquer namespace.

### 3.2 Default-Deny Pattern

**O que esta sequência de NetworkPolicies faz:** Implementa o padrão de segurança de rede mais fundamental em Kubernetes — o "default-deny". Funciona em duas etapas complementares: (1) a política `default-deny-all` bloqueia literalmente todo o tráfego de rede de entrada e saída em todos os pods do namespace, usando `podSelector: {}` (aplica a todos os pods) e sem definir regras de `ingress` ou `egress` (bloqueio implícito total); (2) as políticas subsequentes re-autorizam apenas o tráfego estritamente necessário — DNS (sem isso nenhum pod consegue resolver nomes), comunicação do Ingress Controller para a API gateway, da API gateway para o serviço de pagamentos, e deste para o banco de dados.

**Por que o default-deny é essencial para o Banco Meridian:** Sem NetworkPolicies, qualquer pod comprometido no cluster Kubernetes do Banco Meridian pode alcançar diretamente o banco de dados de produção com os dados de clientes, APIs de outros microserviços, e até o API server do Kubernetes. Com o padrão default-deny, um atacante que comprometesse o pod de um serviço de notificações, por exemplo, não conseguiria fazer nenhuma conexão — nem para o banco de dados de pagamentos, nem para exfiltrar dados pela internet. A superfície de movimento lateral é reduzida ao mínimo necessário.

**Por que incluir allow-dns:** A NetworkPolicy `allow-dns` é necessária para que os pods consigam resolver nomes DNS dentro do cluster (como `postgres.production.svc.cluster.local`). Sem ela, o `default-deny-all` bloquearia as consultas DNS na porta 53, fazendo com que todas as conexões por nome falhassem — quebrando os microserviços mesmo que as conexões de rede em si estivessem autorizadas.

```yaml
# Passo 1: Aplicar default-deny em cada namespace de produção
# Bloqueia TODO o tráfego de entrada e saída por padrão

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}      # Aplica a TODOS os pods no namespace
  policyTypes:
    - Ingress
    - Egress
  # Sem 'ingress' ou 'egress' definidos = bloqueia tudo
```

```yaml
# Passo 2: Permitir apenas o tráfego necessário

# Permitir acesso ao DNS (necessário para resolução de nomes)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

```yaml
# Permitir API gateway receber tráfego do Ingress Controller
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-api-gateway
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-gateway              # Aplica ao pod com label app=api-gateway
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx   # Do namespace do Ingress Controller
          podSelector:
            matchLabels:
              app.kubernetes.io/name: ingress-nginx        # Do pod do Ingress Controller
      ports:
        - port: 8080
          protocol: TCP
```

```yaml
# Permitir API gateway chamar serviço de pagamentos
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-pagamentos
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: servico-pagamentos
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway    # Apenas do api-gateway
      ports:
        - port: 8081
```

```yaml
# Permitir serviço de pagamentos acessar banco de dados
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-pagamentos-to-database
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres                # Aplica ao pod do banco de dados
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: servico-pagamentos   # Apenas do serviço de pagamentos
      ports:
        - port: 5432
```

---

## 4. RBAC — Role-Based Access Control

### 4.1 Boas Práticas de RBAC no Kubernetes

**O que estes manifestos de RBAC fazem e por que a estrutura importa:** O RBAC no Kubernetes controla quais ações cada processo (identificado por uma ServiceAccount) pode realizar sobre os recursos da API do Kubernetes — não sobre o sistema operacional nem sobre o banco de dados, mas sobre os próprios objetos Kubernetes (Pods, Deployments, Secrets, ConfigMaps). A sequência a seguir cria: (1) uma `ServiceAccount` específica para o microserviço de pagamentos com `automountServiceAccountToken: false` — impedindo que o token seja montado automaticamente no filesystem do container, pois muitos microserviços nunca precisam interagir com a API Kubernetes e manter o token montado cria um vetor de ataque desnecessário; (2) uma `Role` mínima que só permite ler (`get`, `watch`) um único ConfigMap específico pelo nome (`resourceNames: ["api-pagamentos-config"]`); (3) um `RoleBinding` que vincula a ServiceAccount à Role.

**Por que a separação Role (namespace) vs ClusterRole (cluster) importa:** Uma `Role` tem escopo de namespace — ela só existe e só funciona dentro do namespace `production`. Uma `ClusterRole` tem escopo de cluster inteiro. Para aplicações como a API de pagamentos do Banco Meridian que precisam apenas dos seus próprios ConfigMaps e Secrets, uma Role é sempre a escolha correta. Usar ClusterRole permitiria ao microserviço acessar ConfigMaps de qualquer namespace — incluindo o namespace `falco-system` e `kube-system` onde ficam os componentes críticos de segurança do cluster.

```
HIERARQUIA DE RBAC KUBERNETES
──────────────────────────────────────────────────────────────────────────────
ServiceAccount (identidade)
   └── RoleBinding / ClusterRoleBinding
          └── Role / ClusterRole (permissões)
                 └── Rules (verbos sobre recursos)

REGRAS DE MENOR PRIVILÉGIO:
1. Nunca use cluster-admin para aplicações (apenas administradores humanos)
2. Prefira Role (namespace-scoped) a ClusterRole (cluster-scoped)
3. Nunca use wildcards (* nos verbs ou resources)
4. Desabilite auto-mounting de token quando não necessário
5. Use ServiceAccounts específicos por aplicação (não o default)
──────────────────────────────────────────────────────────────────────────────
```

```yaml
# ServiceAccount específica por aplicação (não usar 'default')
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-pagamentos-sa
  namespace: production
automountServiceAccountToken: false    # Não montar token automaticamente
                                       # Montar explicitamente apenas se necessário
```

```yaml
# Role mínima para a aplicação de pagamentos
# Lê apenas ConfigMaps e Secrets do próprio namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-pagamentos-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["api-pagamentos-config"]    # Apenas o ConfigMap específico
    verbs: ["get", "watch"]                     # Apenas leitura

  # Secrets via External Secrets Operator (não acessa diretamente)
  # Se necessário acesso direto:
  # - apiGroups: [""]
  #   resources: ["secrets"]
  #   resourceNames: ["api-pagamentos-secrets"]
  #   verbs: ["get"]
```

```yaml
# RoleBinding vinculando a ServiceAccount à Role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-pagamentos-rolebinding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: api-pagamentos-sa
    namespace: production
roleRef:
  kind: Role
  apiGroup: rbac.authorization.k8s.io
  name: api-pagamentos-role
```

---

## 5. Admission Controllers

### 5.1 Por Que São Importantes

Admission Controllers são plugins do API Server que interceptam requisições de criação/modificação de recursos ANTES de serem persistidas no etcd. São a última linha de defesa preventiva.

```
FLUXO DE UMA REQUISIÇÃO NO K8S
────────────────────────────────────────────────────────────────
kubectl apply → API Server → Authentication → Authorization
                                                    │
                                                    ▼
                              Mutating Admission Controllers
                              (modificam o objeto)
                                                    │
                                                    ▼
                              Validating Admission Controllers
                              (aprovam ou rejeitam)
                                                    │
                                              ┌─────▼─────┐
                                              │   etcd    │
                                              └───────────┘
────────────────────────────────────────────────────────────────
OPA Gatekeeper = ValidatingWebhookConfiguration
Kyverno = ValidatingWebhookConfiguration + MutatingWebhookConfiguration
```

---

## 6. OPA Gatekeeper

### 6.1 Arquitetura

OPA Gatekeeper estende o Kubernetes com CRDs (Custom Resource Definitions) que permitem definir políticas via OPA Rego:

- **ConstraintTemplate**: define o template da política (lógica Rego)
- **Constraint**: instância específica de uma política (com parâmetros e target)

```bash
# Instalar OPA Gatekeeper
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system \
  --create-namespace

# Verificar instalação
kubectl get pods -n gatekeeper-system
```

### 6.2 Exemplos de Políticas OPA Gatekeeper

**O que o ConstraintTemplate e a Constraint fazem:** O OPA Gatekeeper funciona com dois tipos de objetos Kubernetes. O **ConstraintTemplate** define a lógica da política em OPA Rego — é o equivalente a uma "classe" ou "template". Ele especifica: o CRD que será criado (`K8sRequiredLabels`), quais campos são aceitos como parâmetros (`labels` no spec), e a lógica Rego que valida os recursos (`violation[{"msg": msg}]`). A **Constraint** é a instância da política — especifica em quais recursos e namespaces ela se aplica, e fornece os valores dos parâmetros (quais labels são obrigatórios).

**Por que esta separação é poderosa:** Você define a lógica do ConstraintTemplate uma vez e cria múltiplas Constraints com parâmetros diferentes. Por exemplo, um único template `K8sRequiredLabels` pode ser instanciado para exigir labels diferentes em namespaces diferentes: o namespace `production` exige `app`, `team`, `version` e `cost-center`, enquanto o namespace `development` exige apenas `app` e `team`. Sem precisar duplicar a lógica Rego.

**Por que o Gatekeeper em vez de apenas PSS:** O Pod Security Standards (seção 2) cobre configurações de segurança dos Pods. O OPA Gatekeeper cobre políticas de governança corporativa — como labels obrigatórios, registry de imagens permitida, limites de recursos obrigatórios, ou qualquer política que o Banco Meridian precise além do que o PSS nativo oferece. Juntos, PSS + Gatekeeper cobrem tanto a segurança técnica quanto a governança organizacional.

**Exigir labels obrigatórios:**
```yaml
# 1. ConstraintTemplate — define a política
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items: {type: string}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Labels obrigatórias ausentes: %v", [missing])
        }
---
# 2. Constraint — instância específica aplicada a Pods
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: pods-must-have-required-labels
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]
  parameters:
    labels: ["app", "owner", "environment"]
```

---

## 7. Kyverno

### 7.1 Por Que Kyverno é Preferido por Muitas Equipes

Kyverno (do grego: "governar") usa YAML nativo Kubernetes para políticas — sem necessidade de aprender Rego. Mais acessível para equipes de plataforma que já conhecem K8s.

```bash
# Instalar Kyverno com Helm
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace

# Verificar instalação
kubectl get pods -n kyverno
kubectl get clusterpolicies
```

### 7.2 Cinco Políticas Kyverno Completas

**Política 1: Bloquear containers rodando como root**
```yaml
# kyverno-policies/block-root-containers.yaml
#
# Política: Bloquear containers que rodam como usuário root (UID 0)
# Tipo: Validate (bloqueia no admission)
# Scope: Todos os Pods nos namespaces production e staging
# Contexto BACEN: controle de acesso ao sistema — containers não devem
# ter privilégios desnecessários que permitam container escape

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-root-containers
  annotations:
    policies.kyverno.io/title: Bloquear Containers como Root
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >
      Containers não devem rodar como root (UID 0). Use runAsNonRoot=true
      e um UID específico acima de 999.
spec:
  validationFailureAction: Enforce    # Enforce=bloqueia, Audit=apenas registra
  background: true                    # Verifica pods existentes também (não apenas novos)
  rules:
    - name: check-runAsNonRoot
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      validate:
        message: >
          Container '{{request.object.spec.containers[0].name}}' deve rodar como não-root.
          Defina securityContext.runAsNonRoot=true e securityContext.runAsUser > 999.
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: "true"
            initContainers:
              - =(securityContext):
                  =(runAsNonRoot): "true"
```

**Política 2: Exigir resource limits**
```yaml
# kyverno-policies/require-resource-limits.yaml
#
# Política: Todos os containers devem ter resource requests e limits definidos
# Tipo: Validate
# Contexto: Sem resource limits, um container pode consumir todos os recursos
# do nó — denial of service acidental ou intencional

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Exigir Resource Limits
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: medium
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-resource-limits
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      validate:
        message: >
          Container '{{request.object.spec.containers[0].name}}' deve ter
          resource requests e limits definidos (CPU e memória).
        pattern:
          spec:
            containers:
              - resources:
                  requests:
                    memory: "?*"
                    cpu: "?*"
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

**Política 3: Bloquear hostPath mounts**
```yaml
# kyverno-policies/block-hostpath.yaml
#
# Política: Bloquear uso de hostPath volumes
# Tipo: Validate
# Risco: hostPath dá acesso ao filesystem do nó host, permitindo
# leitura de arquivos sensíveis (chaves, certificados, kubeconfig)
# e potencial container escape

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-hostpath
  annotations:
    policies.kyverno.io/title: Bloquear hostPath Volumes
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: critical
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-hostpath-volumes
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      validate:
        message: >
          Volumes do tipo hostPath não são permitidos em produção.
          Use emptyDir, PersistentVolumeClaim ou ConfigMap/Secret volumes.
          hostPath dá acesso ao filesystem do nó — risco de container escape.
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
                operator: GreaterThan
                value: 0
```

**Política 4: Bloquear image tag 'latest'**
```yaml
# kyverno-policies/require-image-digest.yaml
#
# Política: Imagens devem usar digest SHA256 ou tag específica (não 'latest')
# Tipo: Validate
# Risco: Tag 'latest' muda silenciosamente. Um pull de 'latest' hoje pode
# trazer uma imagem completamente diferente de 'latest' amanhã.
# Exigir digest ou tag específica garante imutabilidade e rastreabilidade.

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-latest-image-tag
  annotations:
    policies.kyverno.io/title: Bloquear Tag 'latest' em Imagens
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-image-tag-not-latest
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      validate:
        message: >
          Imagem '{{request.object.spec.containers[0].image}}' usa tag 'latest'
          ou não tem tag. Use uma tag específica (ex: v1.2.3) ou digest SHA256
          (ex: app@sha256:abc123) para garantir imutabilidade.
        foreach:
          - list: "request.object.spec.containers"
            deny:
              conditions:
                any:
                  - key: "{{element.image}}"
                    operator: Equals
                    value: "*/latest"
                  - key: "{{element.image}}"
                    operator: Equals
                    value: "latest"
                  - key: "{{element.image | contains(@, ':') | !@}}"
                    operator: Equals
                    value: true
```

**Política 5: Verificar assinatura de imagem com Cosign**
```yaml
# kyverno-policies/verify-image-signature.yaml
#
# Política: Verificar assinatura Cosign antes de permitir execução
# Tipo: VerifyImages (Kyverno feature nativa para verificação de imagem)
# Contexto: Integra com o pipeline do Módulo 4 — apenas imagens assinadas
# pelo CI/CD do Banco Meridian podem rodar em produção

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
  annotations:
    policies.kyverno.io/title: Verificar Assinatura de Imagem (Cosign)
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: critical
spec:
  validationFailureAction: Enforce
  background: false     # Não verificar pods existentes (não temos seus digests)
  rules:
    - name: verify-bancomeridian-images
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
              selector:
                matchLabels:
                  bancomeridian.com.br/verify-signature: "true"   # Opt-in por label
      verifyImages:
        - imageReferences:
            - "ghcr.io/bancomeridian/*"      # Apenas imagens do registry do BM
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/bancomeridian/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
          mutateDigest: true       # Substitui tag por digest (imutabilidade)
          verifyDigest: true       # Verifica o digest após substituição
          required: true           # Falha se não encontrar assinatura válida
```

---

## 8. CIS Kubernetes Benchmark com kube-bench

### 8.1 Como Executar

**O que estes comandos fazem:** Implantam o kube-bench como um Job Kubernetes no master node e depois no worker node, e coletam os resultados. O kube-bench é a ferramenta de referência para auditar um cluster Kubernetes contra o CIS Kubernetes Benchmark — o guia de configuração segura mantido pelo Center for Internet Security. O kube-bench precisa rodar dentro do cluster (como Job) porque precisa inspecionar arquivos de configuração do API Server, etcd e kubelet que estão no sistema de arquivos do próprio nó (montados via `hostPath`). Ele verifica mais de 60 controles de segurança organizados por componente: Control Plane (seção 1), etcd (seção 2), Control Plane Configuration (seção 3), Worker Nodes (seção 4) e Policies (seção 5).

**Por que o kube-bench é importante para o Banco Meridian:** O CIS Kubernetes Benchmark é o padrão de baseline de segurança reconhecido pelo BACEN e pelo setor financeiro. Executar o kube-bench periodicamente fornece evidência objetiva de conformidade com controles como: `--anonymous-auth=false` no API Server (bloqueia acessos não autenticados), `--authorization-mode=Node,RBAC` (garante que RBAC está habilitado), `--etcd-certfile` (comunição criptografada com etcd) e `protectKernelDefaults=true` no kubelet (proteção contra ataques ao kernel). Sem o kube-bench, vulnerabilidades de configuração do cluster permanecem invisíveis até que um atacante as explore.

```bash
# Executar kube-bench no master node
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml

# Aguardar conclusão
kubectl wait --for=condition=complete job/kube-bench-master --timeout=300s

# Ver resultados
kubectl logs job/kube-bench-master

# Executar em worker node
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml
kubectl logs job/kube-bench-node

# Executar com output JSON para análise programática
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench-json
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:latest
          command: ["kube-bench", "--json"]
          volumeMounts:
            - name: var-lib-etcd
              mountPath: /var/lib/etcd
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
      restartPolicy: Never
      volumes:
        - name: var-lib-etcd
          hostPath: {path: /var/lib/etcd}
        - name: etc-kubernetes
          hostPath: {path: /etc/kubernetes}
EOF

kubectl logs job/kube-bench-json | jq '.Controls[].tests[].results[] | select(.status == "FAIL")'
```

### 8.2 Interpretar e Remediar Findings Críticos

```
RESULTADO TÍPICO KUBE-BENCH
────────────────────────────────────────────────────────────────────────────
== Running controls for cluster ==
== CIS Kubernetes Benchmark v1.8 ==

[INFO] 1 Control Plane Security Configuration
[INFO] 1.1 Control Plane Node Configuration Files
[PASS] 1.1.1 Ensure that the API server pod specification file permissions
             are set to 600 or more restrictive
[FAIL] 1.1.2 Ensure that the API server pod specification file ownership
             is set to root:root

[INFO] 1.2 API Server
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.2 Ensure that the --token-auth-file parameter is not set
[PASS] 1.2.6 Ensure that the --authorization-mode argument is not set to
             AlwaysAllow
[FAIL] 1.2.18 Ensure that the --profiling argument is set to false

== Summary master ==
47 checks PASS
13 checks FAIL
11 checks WARN
1 checks INFO
────────────────────────────────────────────────────────────────────────────
```

**Remediações dos findings mais críticos:**

| Check | Finding | Remediação |
|:------|:--------|:----------|
| 1.2.1 | anonymous-auth não desabilitado | `--anonymous-auth=false` no kube-apiserver |
| 1.2.6 | AlwaysAllow no authorization-mode | `--authorization-mode=Node,RBAC` |
| 1.2.18 | Profiling habilitado | `--profiling=false` no kube-apiserver |
| 4.2.1 | kubelet anonymous-auth | `authentication.anonymous.enabled: false` no kubelet-config |
| 4.2.6 | kubelet sem proteção de kernelDefaults | `protectKernelDefaults: true` no kubelet |
| 5.1.1 | cluster-admin em ServiceAccounts | Auditar e remover bindings desnecessários |
| 5.7.3 | Sem NetworkPolicy | Aplicar default-deny + políticas específicas |

---

## 9. Tabela Comparativa: OPA Gatekeeper vs Kyverno

| Dimensão | OPA Gatekeeper | Kyverno |
|:---------|:--------------:|:-------:|
| **Linguagem de política** | Rego (funcional, curva de aprendizado alta) | YAML nativo K8s (familiar para quem já conhece K8s) |
| **Curva de aprendizado** | Alta (requer aprender Rego) | Baixa (YAML que você já conhece) |
| **Expressividade** | Muito alta (Rego é Turing completo) | Alta (JMESPath + CEL) |
| **Mutação de recursos** | Limitada (via rego, mais complexo) | Excelente (políticas de mutation nativas) |
| **Geração de recursos** | Não suportada nativamente | Nativa (gerar ConfigMap quando Namespace é criado) |
| **Verificação de imagem** | Não nativo (requer Ratify externo) | Nativa (verifyImages com Cosign) |
| **Performance** | Alta (Rego compilado) | Alta |
| **Maturidade** | Alta (CNCF graduated) | Alta (CNCF incubating) |
| **Ecossistema de políticas** | Gatekeeper Library (OPA Hub) | Kyverno Policies (kyverno.io/policies) |
| **Quando usar** | Times com expertise em Rego, políticas muito complexas, casos de uso além de K8s (Terraform, CI/CD) | Times de plataforma K8s, necessidade de mutation, verificação de imagem, geração de recursos |
| **Integração com Terraform** | Sim (conftest + Rego) | Não (K8s apenas) |

---

## 10. Atividades de Fixação

### Questão 1
Qual é a diferença entre os modos `enforce`, `audit` e `warn` do Pod Security Standards?

**a)** enforce bloqueia, audit grava no audit log sem bloquear, warn envia aviso ao cliente sem bloquear  
**b)** enforce e audit bloqueiam; warn apenas registra  
**c)** São apenas diferentes níveis de severidade da mesma ação  
**d)** enforce é para produção, audit para staging, warn para desenvolvimento  

**Gabarito: a)**  
Justificativa: Os três modos têm comportamentos distintos: `enforce` rejeita pods que violam o perfil; `audit` permite o pod mas registra a violação no audit log do API server; `warn` permite o pod mas retorna um warning no response da API para o cliente (visível no `kubectl apply`). É comum usar `enforce: baseline` + `audit: restricted` + `warn: restricted` para facilitar a migração gradual para o perfil mais restritivo.

---

### Questão 2
Por que o default-deny pattern de NetworkPolicy é considerado uma melhor prática?

**a)** Porque é mais fácil de configurar do que regras individuais  
**b)** Porque o Kubernetes cria automaticamente regras de allow necessárias  
**c)** Porque inverte o modelo de segurança para "negar por padrão, permitir explicitamente o necessário" — reduzindo a superfície de ataque de lateral movement  
**d)** Porque sem default-deny, o Kubernetes expõe automaticamente todos os pods na internet  

**Gabarito: c)**  
Justificativa: Sem NetworkPolicy, todos os pods se comunicam livremente dentro do cluster — um atacante que compromete um pod pode alcançar qualquer banco de dados ou serviço interno. O default-deny inverte esse modelo: após aplicá-lo, nenhum pod consegue se comunicar com nenhum outro. Você então adiciona explicitamente as rotas necessárias (API gateway → pagamentos → banco de dados). Um pod comprometido fica "preso" sem acesso a outros serviços.

---

### Questão 3
Um desenvolvedor tentou criar um Pod no namespace `production` com `securityContext.runAsUser: 0`. Qual política Kyverno do Banco Meridian bloqueou isso e qual será a mensagem de erro?

**a)** `require-resource-limits` — "Container não tem resource limits definidos"  
**b)** `block-root-containers` — "Container deve rodar como não-root. Defina securityContext.runAsNonRoot=true e runAsUser > 999"  
**c)** `block-hostpath` — "Volumes hostPath não são permitidos"  
**d)** `verify-image-signatures` — "Imagem não tem assinatura Cosign válida"  

**Gabarito: b)**  
Justificativa: `runAsUser: 0` é UID 0 (root). A política `block-root-containers` tem `validationFailureAction: Enforce` e verifica se `runAsNonRoot: true` está configurado. UID 0 é o usuário root em qualquer sistema Unix/Linux, e a política bloqueia especificamente isso para evitar container escape.

---

### Questão 4
Qual comando kube-bench lista apenas os checks que FALHARAM no formato JSON?

**a)** `kube-bench --output json --failed-only`  
**b)** `kubectl logs job/kube-bench-json | jq '.Controls[].tests[].results[] | select(.status == "FAIL")'`  
**c)** `kube-bench run --json --filter FAIL`  
**d)** `kubectl get kubebenchreport -o json | grep FAIL`  

**Gabarito: b)**  
Justificativa: kube-bench não tem um flag `--failed-only` nativo. O fluxo correto é: executar kube-bench com `--json` (saída JSON para stdout), capturar os logs do Job Kubernetes, e filtrar com `jq` para mostrar apenas os objetos com `"status": "FAIL"`.

---

### Questão 5
Quando é preferível usar Kyverno em vez de OPA Gatekeeper para admission control no Kubernetes?

**a)** Quando a organização já usa Terraform e precisa das mesmas políticas em CI/CD  
**b)** Quando a equipe prefere YAML nativo K8s, precisa de mutação de recursos, verificação de assinatura de imagem ou geração automática de recursos  
**c)** Quando as políticas precisam ser muito complexas e expressivas (condições aninhadas)  
**d)** Quando a organização não usa Helm para deploy  

**Gabarito: b)**  
Justificativa: As vantagens do Kyverno sobre o OPA Gatekeeper são: YAML nativo (sem Rego), políticas de mutação (ex: injetar sidecar automaticamente), verificação de assinatura de imagem via `verifyImages` (integração nativa com Cosign), e geração de recursos (ex: criar NetworkPolicy default-deny automaticamente quando um Namespace é criado). OPA Gatekeeper é preferível quando o time já conhece Rego, quando as políticas são muito complexas, ou quando as mesmas políticas precisam ser usadas em Terraform/CI/CD com Conftest.

---

## 11. Roteiro de Gravação — Aula 5.1: K8s Security (55 min)

### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Kubernetes Security: PSS, RBAC, Admission Controllers e Kyverno |
| **Duração** | 55 minutos |
| **Formato** | Talking head + terminal (kubectl) + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Bem-vindo ao Módulo 5. Kubernetes se tornou o sistema operacional do cloud — se você trabalha com cloud security, inevitavelmente vai trabalhar com K8s. E K8s tem uma superfície de ataque muito específica, diferente de tudo que vimos nos módulos anteriores.

Hoje vamos cobrir as quatro camadas de defesa do Kubernetes: Pod Security Standards para controlar o que containers podem fazer, NetworkPolicy para isolamento de rede, RBAC para controle de acesso com menor privilégio, e Admission Controllers — especificamente Kyverno — para enforçar todas essas políticas preventivamente.

---

**[05:00 – 15:00 | SUPERFÍCIE DE ATAQUE K8S | Slides]**

*[Dica de edição: diagrama do cluster com as camadas de ataque]*

O Kubernetes tem uma superfície de ataque multidimensional. Vamos percorrer cada camada.

*[Explica cada área de risco com o diagrama ASCII da superfície de ataque]*

O attack vector mais perigoso em K8s é o container privilegiado. Um container com `--privileged` tem acesso praticamente total ao kernel do nó host — pode montar o filesystem do host, pode ver os processos de outros containers, pode criar interfaces de rede. É equivalente a ser root no servidor físico. Nunca, em nenhuma circunstância, um container de aplicação em produção deve ser privilegiado.

O segundo mais perigoso é a ausência de NetworkPolicy. Por padrão, em Kubernetes, todos os pods de todos os namespaces se comunicam livremente entre si. Um pod comprometido em qualquer lugar do cluster pode alcançar diretamente seu banco de dados de produção. Isso não é aceitável.

---

**[15:00 – 25:00 | POD SECURITY STANDARDS | Terminal + slides]**

*[Aplica PSS nos namespaces do cluster kind local]*

```bash
# Aplicar PSS Restricted no namespace de produção
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.28

# Tentar criar pod como root (deve falhar)
kubectl run test-root --image=nginx --namespace=production \
  --overrides='{"spec":{"containers":[{"name":"test","image":"nginx","securityContext":{"runAsUser":0}}]}}'
```

*[Mostra o erro de PSS bloqueando o pod]*

---

**[25:00 – 35:00 | NETWORKPOLICY E RBAC | Terminal]**

*[Aplica default-deny e NetworkPolicies específicas]*

*[Demonstra que sem NetworkPolicy, um pod A pode fazer curl no pod B]*

*[Aplica default-deny, mostra que curl falha]*

*[Aplica NetworkPolicy específica, mostra que curl funciona novamente para o par autorizado]*

---

**[35:00 – 50:00 | KYVERNO | Terminal]**

*[Instala Kyverno no cluster kind]*

*[Aplica as 5 políticas do módulo]*

*[Testa cada política tentando criar recursos que violam]*

```bash
# Testa policy block-root-containers
kubectl run root-pod --image=nginx \
  --overrides='{"spec":{"containers":[{"name":"c","image":"nginx","securityContext":{"runAsUser":0}}]}}'
# Esperado: ERRO — "Container deve rodar como não-root"

# Testa policy require-non-latest-image-tag
kubectl run latest-pod --image=nginx:latest
# Esperado: ERRO — "Imagem usa tag latest"

# Testa verify-image-signature (com imagem não assinada)
kubectl run unsigned-pod --image=alpine:3.18
# Esperado: ERRO — "Imagem não tem assinatura Cosign válida"
```

*[Mostra os erros claros e explicativos do Kyverno]*

---

**[50:00 – 53:00 | KUBE-BENCH | Terminal]**

*[Executa kube-bench rapidamente]*

*[Mostra os resultados e explica os top 3 findings críticos]*

---

**[53:00 – 55:00 | ENCERRAMENTO | Talking head]**

No laboratório Lab-04, você vai implementar as 4 políticas Kyverno no cluster kind e testar cada uma tentando criar pods que violam as políticas. É uma simulação realista do que você faria em um cluster de produção do Banco Meridian.

---

## 12. Avaliação do Módulo 05

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
Um Pod com `hostPID: true` representa qual tipo de risco de segurança?

**a)** Permite ao container acessar o filesystem do nó host  
**b)** Permite ao container ver e interagir com todos os processos do nó host, possibilitando process injection e acesso a segredos de outros processos  
**c)** Permite ao container ter acesso root dentro de si mesmo  
**d)** Permite ao container usar a rede do nó host diretamente  

**Gabarito: b)** `hostPID: true` faz o container compartilhar o namespace de PID do nó host. O container pode ver todos os processos do nó e de outros containers. Um atacante pode usar `nsenter` para entrar no namespace de outro processo e ler sua memória, incluindo segredos carregados em memória.

---

**Questão 2 (10 pts)**  
Qual é o impacto de `automountServiceAccountToken: false` em uma ServiceAccount?

**a)** Impede a ServiceAccount de ser usada em RoleBindings  
**b)** Impede que o token da ServiceAccount seja automaticamente montado em `/var/run/secrets/kubernetes.io/serviceaccount/token` nos pods — o pod não pode fazer chamadas à API K8s sem configuração explícita  
**c)** Desabilita a ServiceAccount permanentemente  
**d)** Impede que o RBAC seja aplicado para a ServiceAccount  

**Gabarito: b)** Por padrão, K8s monta automaticamente o token da ServiceAccount em todos os pods. Esse token permite ao pod fazer chamadas à API K8s com as permissões da ServiceAccount. Para aplicações que não precisam fazer chamadas à API K8s (a maioria), desabilitar o auto-mount é uma boa prática de menor privilégio — se o container for comprometido, o atacante não terá automaticamente acesso à API do cluster.

---

**Questão 3 (10 pts)**  
Qual política Kyverno verificaria se um Pod está usando uma imagem com digest SHA256 em vez de tag mutável?

**a)** `block-root-containers`  
**b)** `require-resource-limits`  
**c)** `require-non-latest-image-tag`  
**d)** `verify-image-signatures`  

**Gabarito: c)** A política `require-non-latest-image-tag` verifica que a imagem tem uma tag específica (não `latest`) ou digest SHA256. Isso garante imutabilidade — a mesma tag sempre referencia exatamente a mesma imagem. `verify-image-signatures` vai um passo além e verifica que a imagem foi assinada pelo pipeline de CI/CD.

---

**Questão 4 (10 pts)**  
No resultado do kube-bench, o check `1.2.6 Ensure that the --authorization-mode argument is not set to AlwaysAllow` falha. O que isso significa e como remediar?

**a)** Significa que o API server está usando apenas autenticação de certificado — remediar habilitando RBAC  
**b)** Significa que o API server está configurado para autorizar QUALQUER requisição autenticada sem verificar RBAC — remediar configurando `--authorization-mode=Node,RBAC` no kube-apiserver  
**c)** Significa que não há usuários cadastrados no cluster — remediar criando um admin user  
**d)** Significa que o RBAC está em modo audit — remediar mudando para enforce  

**Gabarito: b)** `AlwaysAllow` no authorization-mode faz o API server autorizar toda requisição sem verificar RBAC — qualquer usuário autenticado pode fazer qualquer coisa. A remediação é definir `--authorization-mode=Node,RBAC` no manifesto do kube-apiserver, que habilita o RBAC normal do K8s.

---

**Questão 5 (10 pts)**  
Por que um NetworkPolicy do tipo default-deny não bloqueia resolução DNS, e como isso é tratado?

**a)** NetworkPolicy não se aplica ao DNS por design do Kubernetes  
**b)** DNS usa UDP na porta 53, e NetworkPolicies não suportam UDP  
**c)** O default-deny bloqueia TUDO incluindo DNS. É necessário criar uma NetworkPolicy explícita que permite egress na porta 53 (UDP e TCP) para não quebrar a resolução de nomes  
**d)** kube-dns tem uma exceção automática em todos os NetworkPolicies  

**Gabarito: c)** O default-deny bloqueia literalmente todo o tráfego de entrada e saída, incluindo DNS. Sem DNS, os pods não conseguem resolver nomes de serviços internos ou externos. É necessário criar uma NetworkPolicy específica que permita egress para a porta 53 (UDP/TCP) para o DNS funcionar. Geralmente isso é uma política global aplicada a todos os namespaces.

---

**Questão 6 (10 pts)**  
Qual é a vantagem da feature `verifyImages` do Kyverno sobre implementar a verificação de assinatura no pipeline de CI/CD apenas?

**a)** verifyImages é mais rápido que o Cosign CLI  
**b)** verifyImages verifica a assinatura NO MOMENTO do deploy no cluster (admission time), garantindo que mesmo que alguém consiga fazer push de uma imagem não assinada diretamente no registry, ela não será executada  
**c)** verifyImages substitui completamente o Cosign no pipeline de CI/CD  
**d)** verifyImages só funciona com imagens públicas  

**Gabarito: b)** O pipeline de CI/CD assina imagens durante o build. Mas e se alguém tiver permissão para fazer push diretamente no registry (sem passar pelo pipeline)? A política `verifyImages` do Kyverno é um segundo ponto de controle: no momento em que o Pod é criado no cluster, o Kyverno verifica a assinatura Cosign. Se a imagem não tem assinatura válida do pipeline autorizado, o Pod é bloqueado — independente de como a imagem chegou ao registry.

---

*Módulo 05 — Kubernetes Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
