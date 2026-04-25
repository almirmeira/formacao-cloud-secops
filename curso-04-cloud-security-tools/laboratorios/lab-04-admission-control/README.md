# Lab 04 — Admission Control com Kyverno
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1 hora  
> **Dificuldade:** Intermediário  
> **Módulo Relacionado:** Módulo 05 — Kubernetes Security  

---

## 1. Contexto Situacional

O time de plataforma do Banco Meridian precisa garantir que nenhum container rode como root no cluster Kubernetes de produção. Após um incidente onde um container root realizou container escape, o CISO emitiu uma política: "Todo container em produção deve rodar como usuário não-root, ter resource limits definidos, não usar hostPath, e usar tags de imagem específicas (não latest)."

Você foi designado para implementar essas políticas usando Kyverno como admission controller.

---

## 2. Situação Inicial

O cluster kind está em execução. Kyverno não está instalado. Desenvolvedores criaram pods com `runAsUser: 0` (root), sem resource limits, e usando `nginx:latest` — tudo violando as políticas de segurança definidas pelo CISO.

---

## 3. Problema Identificado

Sem admission control, qualquer desenvolvedor com permissão de `create pods` pode criar containers privilegiados. O Kubernetes não bloqueia isso por padrão (Pod Security Standards ajuda, mas Kyverno oferece mais granularidade e flexibilidade).

---

## 4. Roteiro de Atividades

1. Instalar Kyverno no cluster kind
2. Criar política: bloquear containers root
3. Criar política: exigir resource limits
4. Criar política: bloquear hostPath mounts
5. Criar política: exigir image tag (não latest)
6. Tentar criar Pod violando política de root
7. Tentar criar Pod violando política de resource limits
8. Tentar criar Pod violando política de hostPath
9. Tentar criar Pod violando política de latest tag
10. Criar Pod que satisfaz todas as políticas (deve funcionar)

---

## 5. Proposição

Ao final deste laboratório, você terá 4 políticas Kyverno ativas que bloqueiam automaticamente qualquer tentativa de criar Pods que violem as políticas de segurança do Banco Meridian, com mensagens de erro claras e acionáveis para os desenvolvedores.

---

## 6. Script Passo a Passo

### Passo 1: Instalar Kyverno

```bash
# Verificar se cluster kind está rodando
kubectl cluster-info

# Adicionar repositório Helm do Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

# Instalar Kyverno
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set replicaCount=1 \
  --set admissionController.replicas=1

# Aguardar pods ficarem prontos (pode levar 2-3 minutos)
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/instance=kyverno \
  -n kyverno \
  --timeout=300s

echo "Kyverno instalado com sucesso"
kubectl get pods -n kyverno
```

**Resultado esperado:**
```
NAME                                             READY   STATUS    RESTARTS
kyverno-admission-controller-7d8f4b9c5-xxxxx   1/1     Running   0
kyverno-background-controller-...              1/1     Running   0
kyverno-cleanup-controller-...                 1/1     Running   0
kyverno-reports-controller-...                 1/1     Running   0
```

**Troubleshooting:** Se algum pod não iniciar:
```bash
kubectl describe pod -l app.kubernetes.io/instance=kyverno -n kyverno
kubectl logs -l app.kubernetes.io/instance=kyverno -n kyverno
```

---

### Passo 2: Criar Policy — Bloquear Containers Root

```bash
# Criar namespace de teste
kubectl create namespace lab04-bancomeridian

# Aplicar política de bloqueio de containers root
kubectl apply -f - << 'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-root-containers
  annotations:
    policies.kyverno.io/title: Bloquear Containers como Root
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >
      Containers não devem rodar como root (UID 0) em conformidade com
      a política de segurança do Banco Meridian e BACEN 4.893 Art. 5.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-runAsNonRoot
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [lab04-bancomeridian, production, staging]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: Container '{{ request.object.spec.containers[0].name }}'
          deve rodar como não-root. Defina securityContext.runAsNonRoot=true
          e securityContext.runAsUser maior que 999. (BACEN 4.893 Art. 5)
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(runAsUser): ">999"
                  runAsNonRoot: "true"
YAML

echo "Política block-root-containers criada"
kubectl get clusterpolicy block-root-containers
```

**Resultado esperado:**
```
NAME                    ADMISSION   BACKGROUND   VALIDATE ACTION   READY   AGE
block-root-containers   true        true         Enforce           true    10s
```

---

### Passo 3: Criar Policy — Exigir Resource Limits

```bash
kubectl apply -f - << 'YAML'
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
              namespaces: [lab04-bancomeridian, production, staging]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: Container '{{ request.object.spec.containers[0].name }}'
          deve ter resource requests e limits definidos.
          Containers sem limits podem causar DoS acidental no nó.
          Defina resources.requests.memory, resources.requests.cpu,
          resources.limits.memory e resources.limits.cpu.
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
YAML

echo "Política require-resource-limits criada"
```

---

### Passo 4: Criar Policy — Bloquear hostPath

```bash
kubectl apply -f - << 'YAML'
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
              namespaces: [lab04-bancomeridian, production, staging]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: Volumes do tipo hostPath não são permitidos.
          hostPath dá acesso ao filesystem do nó host, permitindo container escape.
          Use emptyDir, PersistentVolumeClaim, ConfigMap ou Secret volumes.
          (BACEN 4.893 Art. 5 - controles de acesso)
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
                operator: GreaterThan
                value: 0
YAML

echo "Política block-hostpath criada"
```

---

### Passo 5: Criar Policy — Bloquear Tag Latest

```bash
kubectl apply -f - << 'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-latest-image-tag
  annotations:
    policies.kyverno.io/title: Bloquear Tag latest em Imagens
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-image-tag
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [lab04-bancomeridian, production, staging]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: A imagem '{{ request.object.spec.containers[0].image }}'
          usa tag 'latest' ou não tem tag definida.
          Use uma tag específica (ex: nginx:1.25.3) ou digest SHA256
          (ex: nginx@sha256:abc123...) para garantir imutabilidade.
        foreach:
          - list: "request.object.spec.containers"
            deny:
              conditions:
                any:
                  - key: "{{ element.image }}"
                    operator: Equals
                    value: "*:latest"
                  - key: "{{ element.image | contains(@, ':') | !@}}"
                    operator: Equals
                    value: "true"
YAML

echo "Política require-non-latest-image-tag criada"
```

---

### Passo 6: Listar Todas as Políticas

```bash
kubectl get clusterpolicies
```

**Resultado esperado:**
```
NAME                       ADMISSION   BACKGROUND   VALIDATE ACTION   READY
block-hostpath             true        true         Enforce           true
block-root-containers      true        true         Enforce           true
require-non-latest-image-tag true      true         Enforce           true
require-resource-limits    true        true         Enforce           true
```

---

### Passo 7: Testar — Pod que Viola Política de Root

```bash
echo "=== TESTE 1: Pod com root user (deve ser BLOQUEADO) ==="

kubectl apply -f - << 'YAML' 2>&1 | head -10
apiVersion: v1
kind: Pod
metadata:
  name: test-root-user
  namespace: lab04-bancomeridian
spec:
  containers:
    - name: app
      image: nginx:1.25.3
      securityContext:
        runAsUser: 0
        runAsNonRoot: false
      resources:
        requests:
          memory: "64Mi"
          cpu: "100m"
        limits:
          memory: "128Mi"
          cpu: "200m"
YAML

echo ""
echo "Esperado: Erro de admission — POLÍTICA BANCO MERIDIAN: Container deve rodar como não-root"
```

**Resultado esperado:**
```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
policy block-root-containers/check-runAsNonRoot applied to default/Pod/test-root-user 
FAILED: POLÍTICA BANCO MERIDIAN: Container 'app' deve rodar como não-root.
Defina securityContext.runAsNonRoot=true e securityContext.runAsUser maior que 999.
```

---

### Passo 8: Testar — Pod sem Resource Limits

```bash
echo "=== TESTE 2: Pod sem resource limits (deve ser BLOQUEADO) ==="

kubectl apply -f - << 'YAML' 2>&1 | head -10
apiVersion: v1
kind: Pod
metadata:
  name: test-no-limits
  namespace: lab04-bancomeridian
spec:
  containers:
    - name: app
      image: nginx:1.25.3
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      # SEM resources definidos — deve falhar na política require-resource-limits
YAML

echo ""
echo "Esperado: Erro de admission — Container deve ter resource requests e limits"
```

**Resultado esperado:**
```
Error from server: admission webhook denied the request:
policy require-resource-limits/check-resource-limits applied:
POLÍTICA BANCO MERIDIAN: Container 'app' deve ter resource requests e limits definidos.
```

---

### Passo 9: Testar — Pod com hostPath

```bash
echo "=== TESTE 3: Pod com hostPath (deve ser BLOQUEADO) ==="

kubectl apply -f - << 'YAML' 2>&1 | head -10
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpath
  namespace: lab04-bancomeridian
spec:
  containers:
    - name: app
      image: nginx:1.25.3
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      resources:
        requests: {memory: "64Mi", cpu: "100m"}
        limits: {memory: "128Mi", cpu: "200m"}
      volumeMounts:
        - name: host-vol
          mountPath: /host-data
  volumes:
    - name: host-vol
      hostPath:
        path: /etc  # Acesso ao /etc do nó host — PERIGOSO
YAML

echo ""
echo "Esperado: Erro de admission — hostPath não é permitido"
```

**Resultado esperado:**
```
Error from server: admission webhook denied the request:
policy block-hostpath/block-hostpath-volumes applied:
POLÍTICA BANCO MERIDIAN: Volumes do tipo hostPath não são permitidos.
```

---

### Passo 10: Testar — Pod com Tag Latest

```bash
echo "=== TESTE 4: Pod com imagem:latest (deve ser BLOQUEADO) ==="

kubectl apply -f - << 'YAML' 2>&1 | head -10
apiVersion: v1
kind: Pod
metadata:
  name: test-latest-tag
  namespace: lab04-bancomeridian
spec:
  containers:
    - name: app
      image: nginx:latest  # TAG LATEST — viola a política
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      resources:
        requests: {memory: "64Mi", cpu: "100m"}
        limits: {memory: "128Mi", cpu: "200m"}
YAML

echo ""
echo "Esperado: Erro de admission — Tag latest não permitida"
```

---

### Passo 11: Criar Pod Que Satisfaz Todas as Políticas

```bash
echo "=== TESTE 5: Pod que satisfaz TODAS as políticas (deve ser CRIADO) ==="

kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: pod-compliant-bancomeridian
  namespace: lab04-bancomeridian
  labels:
    app: api-pagamentos
    owner: equipe-api
    environment: test
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: api
      image: nginx:1.25.3        # Sem latest — tag específica
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
        runAsNonRoot: true
        runAsUser: 1000
      resources:
        requests:
          memory: "64Mi"
          cpu: "100m"
        limits:
          memory: "128Mi"
          cpu: "200m"
      ports:
        - containerPort: 8080
      volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
  volumes:
    - name: tmp-dir
      emptyDir: {}              # emptyDir em vez de hostPath
YAML

echo ""
kubectl get pod pod-compliant-bancomeridian -n lab04-bancomeridian

echo ""
echo "Esperado: Pod em estado 'Running' — satisfaz todas as políticas Kyverno"
```

**Resultado esperado:**
```
NAME                           READY   STATUS    RESTARTS   AGE
pod-compliant-bancomeridian   1/1     Running   0          10s
```

---

### Passo 12: Verificar Reports Kyverno

```bash
# Kyverno gera relatórios de compliance nos recursos existentes
kubectl get policyreport -n lab04-bancomeridian
kubectl describe policyreport -n lab04-bancomeridian

# Ver relatório detalhado
kubectl get policyreport -n lab04-bancomeridian -o json | python3 -c "
import json, sys
reports = json.load(sys.stdin)
for item in reports.get('items', []):
    summary = item.get('summary', {})
    print(f'=== Policy Report: {item[\"metadata\"][\"name\"]} ===')
    print(f'Pass: {summary.get(\"pass\", 0)}')
    print(f'Fail: {summary.get(\"fail\", 0)}')
    print()
    for result in item.get('results', [])[:5]:
        print(f'  [{result.get(\"result\", \"?\")}] {result.get(\"policy\", \"?\")} — {result.get(\"message\", \"\")}')
"
```

---

### Passo 13: Gerar Relatório para o CISO

```bash
cat > /tmp/lab04-admission-control-report.md << 'REPORT'
# Relatório de Admission Control — Kubernetes
## Banco Meridian — Cluster kind (laboratório)
Data: $(date +%Y-%m-%d)

## Políticas Implementadas

| Política | Tipo | Ação | Namespaces |
|:---------|:----:|:----:|:-----------|
| block-root-containers | Validate | Enforce (bloqueia) | production, staging, lab04 |
| require-resource-limits | Validate | Enforce (bloqueia) | production, staging, lab04 |
| block-hostpath | Validate + Deny | Enforce (bloqueia) | production, staging, lab04 |
| require-non-latest-image-tag | Validate | Enforce (bloqueia) | production, staging, lab04 |

## Resultados dos Testes

| Teste | Comportamento | Status |
|:------|:-------------|:------:|
| Pod root (runAsUser: 0) | Bloqueado com mensagem clara | PASS |
| Pod sem resource limits | Bloqueado com mensagem clara | PASS |
| Pod com hostPath /etc | Bloqueado com mensagem clara | PASS |
| Pod com nginx:latest | Bloqueado com mensagem clara | PASS |
| Pod compliant (tag, non-root, limits) | Criado com sucesso | PASS |

## Conformidade BACEN 4.893

Essas políticas contribuem para:
- Art. 5 — Testes de controles: políticas preventivas automatizadas
- Art. 8 — Controle de acesso: containers não podem rodar como root

## Próximos Passos

1. Aplicar policies no cluster EKS de produção
2. Adicionar política de verificação de assinatura Cosign (verifyImages)
3. Adicionar política de network policy obrigatória
4. Integrar relatórios Kyverno com SIEM para auditoria contínua
REPORT

sed -i "s/\$(date +%Y-%m-%d)/$(date +%Y-%m-%d)/" /tmp/lab04-admission-control-report.md
echo "Relatório gerado: /tmp/lab04-admission-control-report.md"
cat /tmp/lab04-admission-control-report.md
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Kyverno instalado | Pods `Running` em `kyverno` namespace |
| 2 | Policy root criada | `kubectl get clusterpolicy block-root-containers` |
| 3 | Policy limits criada | `kubectl get clusterpolicy require-resource-limits` |
| 4 | Policy hostPath criada | `kubectl get clusterpolicy block-hostpath` |
| 5 | Policy latest criada | `kubectl get clusterpolicy require-non-latest-image-tag` |
| 6 | 4 policies listadas | `kubectl get clusterpolicies` mostra 4 em Enforce |
| 7 | Pod root bloqueado | Erro admission webhook com mensagem sobre root |
| 8 | Pod sem limits bloqueado | Erro admission webhook com mensagem sobre limits |
| 9 | Pod hostPath bloqueado | Erro admission webhook com mensagem sobre hostPath |
| 10 | Pod latest bloqueado | Erro admission webhook com mensagem sobre tag |
| 11 | Pod compliant criado | Pod em `Running` sem erros |
| 12 | PolicyReport gerado | Relatório visível com pass/fail |
| 13 | Relatório para CISO | Arquivo markdown com tabela de resultados |

---

## 8. Gabarito Completo

### As 4 Policies Kyverno em YAML — Arquivo Único

```yaml
# kyverno-policies-bancomeridian.yaml
# Instalar com: kubectl apply -f kyverno-policies-bancomeridian.yaml
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-root-containers
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-runAsNonRoot
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging, lab04-bancomeridian]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: Container deve rodar como não-root.
          Defina securityContext.runAsNonRoot=true e runAsUser>999.
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(runAsUser): ">999"
                  runAsNonRoot: "true"
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-resource-limits
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging, lab04-bancomeridian]
      validate:
        message: >
          POLÍTICA BANCO MERIDIAN: Container deve ter resource requests e limits definidos.
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
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-hostpath
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-hostpath-volumes
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging, lab04-bancomeridian]
      validate:
        message: "POLÍTICA BANCO MERIDIAN: hostPath volumes não são permitidos."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
                operator: GreaterThan
                value: 0
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-latest-image-tag
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-image-tag
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging, lab04-bancomeridian]
      validate:
        message: "POLÍTICA BANCO MERIDIAN: Use tag específica, não ':latest'."
        foreach:
          - list: "request.object.spec.containers"
            deny:
              conditions:
                any:
                  - key: "{{ element.image }}"
                    operator: Equals
                    value: "*:latest"
                  - key: "{{ element.image | contains(@, ':') | !@}}"
                    operator: Equals
                    value: "true"
```

### Mensagens de Erro Esperadas

| Política | Mensagem de Erro ao Tentar Criar Pod Violador |
|:---------|:---------------------------------------------|
| block-root-containers | `POLÍTICA BANCO MERIDIAN: Container 'app' deve rodar como não-root. Defina securityContext.runAsNonRoot=true e securityContext.runAsUser maior que 999.` |
| require-resource-limits | `POLÍTICA BANCO MERIDIAN: Container 'app' deve ter resource requests e limits definidos. Containers sem limits podem causar DoS acidental no nó.` |
| block-hostpath | `POLÍTICA BANCO MERIDIAN: Volumes do tipo hostPath não são permitidos. hostPath dá acesso ao filesystem do nó host, permitindo container escape.` |
| require-non-latest-image-tag | `POLÍTICA BANCO MERIDIAN: A imagem 'nginx:latest' usa tag 'latest'. Use uma tag específica como nginx:1.25.3.` |

---

*Lab 04 — Admission Control com Kyverno*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
