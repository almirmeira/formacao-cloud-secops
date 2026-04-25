# Lab 04 — Admission Control com Kyverno
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 1 hora  
> **Dificuldade:** Intermediário  
> **Módulo Relacionado:** Módulo 05 — Kubernetes Security  

---

## 1. Contexto Situacional

O CISO do Banco Meridian emitiu uma diretriz: "Todo container em produção deve rodar como não-root, ter resource limits definidos, não montar hostPath, e usar imagens com tag específica — nunca `latest`." O Kyverno vai garantir isso automaticamente no Kubernetes, sem depender de revisão manual de cada deploy.

---

## 2. Situação Inicial

O cluster Kubernetes do Banco Meridian está em produção sem nenhum admission controller de políticas. Qualquer desenvolvedor com acesso ao `kubectl create pod` pode criar containers privilegiados, sem resource limits, com hostPath montado, e com imagens `latest` — todos configurações que criam riscos de segurança sérios.

---

## 3. Problema Identificado

Sem admission control:
- Containers rodando como root podem comprometer o nó host se houver exploração de kernel
- Containers sem resource limits podem causar DoS acidental ou intencional no nó (CPU/memória)
- hostPath dá acesso ao filesystem do nó host, permitindo container escape e leitura de segredos do Kubernetes
- Imagens `latest` são imprevisíveis — a mesma tag pode apontar para imagens diferentes em deploys distintos, quebrando reprodutibilidade e auditabilidade

---

## 4. Roteiro de Atividades

1. Instalar Kyverno no cluster kind
2. Criar política: bloquear containers root
3. Criar política: exigir resource limits
4. Criar política: bloquear hostPath
5. Criar política: bloquear tag latest
6. Listar e verificar todas as políticas
7. Testar: pod root (deve falhar)
8. Testar: pod sem resource limits (deve falhar)
9. Testar: pod com hostPath (deve falhar)
10. Testar: pod com tag latest (deve falhar)
11. Criar pod que satisfaz todas as políticas (deve passar)
12. Verificar PolicyReports do Kyverno
13. Gerar relatório para o CISO

---

## 5. Proposição

Ao final deste laboratório, você terá 4 políticas Kyverno em modo `Enforce` que bloqueiam automaticamente qualquer pod não conforme nos namespaces de produção, staging e lab do Banco Meridian.

---

## 6. Script Passo a Passo

### Passo 1: Instalar Kyverno

**O que este passo faz:** Instala o Kyverno no cluster kind via Helm. O Kyverno é um policy engine nativo do Kubernetes — ele se integra ao API server como um Admission Webhook, o que significa que todo `kubectl apply` passa pelo Kyverno antes de ser aceito pelo cluster. O flag `--set replicaCount=1` reduz para 1 réplica (suficiente para laboratório) pois em produção o Kyverno roda com 3 réplicas para alta disponibilidade.

**Por que agora:** O Kyverno precisa estar instalado e com os pods `Running` antes de criar qualquer política. O admission webhook só é registrado após a instalação completa — criar políticas antes dos pods estarem prontos pode resultar em comportamento indefinido.

```bash
# Adicionar repositório Helm do Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

# Instalar Kyverno
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set replicaCount=1 \
  --set admissionController.replicas=1

# Aguardar pods ficarem Ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/component=admission-controller \
  -n kyverno --timeout=120s

kubectl get pods -n kyverno
```

**O que você deve ver:**
```
NAME                                            READY   STATUS    RESTARTS   AGE
kyverno-admission-controller-xxxxx              1/1     Running   0          90s
kyverno-background-controller-xxxxx             1/1     Running   0          90s
kyverno-cleanup-controller-xxxxx                1/1     Running   0          90s
kyverno-reports-controller-xxxxx                1/1     Running   0          90s
```
O `kyverno-admission-controller` é o componente que intercepta as requisições ao API server. Os outros controladores gerenciam políticas em background, limpeza e relatórios.

---

### Passo 2: Criar Namespace de Teste

**O que este passo faz:** Cria o namespace `lab04-bancomeridian` onde as políticas serão aplicadas. Este namespace simula o ambiente de produção do Banco Meridian — as políticas Kyverno serão configuradas para aplicar especificamente a este namespace (além de `production` e `staging`). Usar um namespace dedicado para o laboratório evita interferir com outros namespaces do cluster kind.

**Por que agora:** O namespace precisa existir antes de criar os pods de teste. As políticas Kyverno filtram por namespace — sem o namespace correto, os testes de bloqueio não funcionarão.

```bash
kubectl create namespace lab04-bancomeridian
echo "Namespace lab04-bancomeridian criado"
```

---

### Passo 3: Criar Policy — Bloquear Containers Root

**O que este passo faz:** Cria a política Kyverno `block-root-containers` em modo `Enforce`. A política usa o operador `=(securityContext): =(runAsUser): ">999"` para verificar se o `runAsUser` é maior que 999 (UIDs de sistema geralmente ficam abaixo de 1000) e `runAsNonRoot: "true"` para confirmar que o container não rodará como root. O prefixo `=` em Kyverno significa "se o campo existir, validar" — isso permite que containers sem securityContext explícito passem na validação com um aviso, enquanto containers que explicitamente configuram root sejam bloqueados.

**Por que agora:** Esta é a política mais crítica em termos de segurança — containers root comprometidos têm muito mais capacidade de causar dano ao nó host. Criar esta política primeiro estabelece a barreira mais importante.

```bash
kubectl apply -f - << 'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-root-containers
  annotations:
    policies.kyverno.io/title: Bloquear Containers Root
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: critical
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
          deve rodar como não-root.
          Defina securityContext.runAsNonRoot=true e securityContext.runAsUser maior que 999.
          Containers root comprometidos podem dar acesso ao filesystem do nó host.
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

**O que você deve ver:**
```
NAME ADMISSION BACKGROUND VALIDATE ACTION READY AGE
block-root-containers true true Enforce true 10s
```
O `READY: true` confirma que a política foi carregada e está ativa. O `VALIDATE ACTION: Enforce` confirma que a política bloqueará (não apenas alertará) pods não conformes.

---

### Passo 4: Criar Policy — Exigir Resource Limits

**O que este passo faz:** Cria a política `require-resource-limits` que exige que todo container nos namespaces especificados defina `resources.requests` (CPU e memória mínimos garantidos) e `resources.limits` (CPU e memória máximos permitidos). O padrão `"?*"` em Kyverno significa "qualquer valor não-vazio" — a política não especifica quais limites usar, apenas que eles existam. A mensagem de erro é descritiva e educativa — explica o motivo do bloqueio ao desenvolvedor.

**Por que agora:** Resource limits são críticos para estabilidade do cluster. Um container sem limite de memória pode consumir toda a RAM do nó e causar OOMKill em outros containers — isso é tanto um vetor de DoS acidental quanto um potencial vetor de ataque.

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

### Passo 5: Criar Policy — Bloquear hostPath

**O que este passo faz:** Cria a política `block-hostpath` que usa a condição `deny` para bloquear pods que definem volumes do tipo `hostPath`. A condição `request.object.spec.volumes[].hostPath` verifica se a lista de volumes contém algum item com a chave `hostPath`. O operador `GreaterThan: 0` conta quantos volumes hostPath existem — se for maior que zero, o pod é bloqueado. `hostPath` monta um diretório do sistema de arquivos do nó host dentro do container — isso permite que um container comprometido leia segredos do kubelet, certificados TLS, e outros dados sensíveis do nó.

**Por que agora:** hostPath é o tipo de volume mais perigoso em Kubernetes. Ele efetivamente quebra o isolamento do container — um atacante com acesso a um container com hostPath pode comprometer o nó inteiro.

```bash
kubectl apply -f - << 'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-hostpath
  annotations:
    policies.kyverno.io/title: Bloquear hostPath
    policies.kyverno.io/category: Security - Banco Meridian
    policies.kyverno.io/severity: high
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
          hostPath dá acesso ao filesystem do nó host, permitindo container escape
          e leitura de segredos do Kubernetes (certificados, tokens, etc.).
          Use PersistentVolumeClaims em vez de hostPath.
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

### Passo 6: Criar Policy — Bloquear Tag Latest

**O que este passo faz:** Cria a política `require-non-latest-image-tag` que itera sobre todos os containers do pod e verifica se algum usa a tag `latest`. A iteração usa o operador `foreach` do Kyverno — diferente das outras políticas que verificam o primeiro container `containers[0]`, esta verifica todos os containers. A condição verifica se a imagem termina com `:latest` ou não tem tag (o Docker usa `latest` por padrão quando não há tag). Uma imagem sem tag específica é tão problemática quanto `latest` — não é possível rastrear exatamente qual versão está deployada.

**Por que agora:** Imagens `latest` são um problema de segurança e reprodutibilidade. Do ponto de vista de segurança, você não pode auditar qual versão de uma imagem está rodando — se uma imagem `latest` for comprometida na registry, todos os clusters que usam essa tag serão afetados no próximo restart.

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
          Use uma tag específica como nginx:1.25.3 ou sha256:abc123...
          Imagens sem tag específica não são auditáveis — você não sabe exatamente
          qual versão está rodando em produção.
        foreach:
          - list: "request.object.spec.containers"
            deny:
              conditions:
                any:
                  - key: "{{ element.image }}"
                    operator: Equals
                    value: "true"
YAML

echo "Política require-non-latest-image-tag criada"
```

---

### Passo 7: Listar Todas as Políticas

**O que este passo faz:** Lista todas as ClusterPolicies criadas e verifica que estão em modo `Enforce` e status `READY: true`. O `BACKGROUND: true` significa que o Kyverno também verifica recursos já existentes no cluster (não apenas novos) — isso gera PolicyReports para pods existentes que violam as políticas, mesmo que não sejam bloqueados retroativamente (o Enforce só bloqueia novos recursos).

**Por que agora:** Antes de testar os bloqueios, confirmar que todas as 4 políticas estão ativas e prontas evita confusão se um teste não funcionar como esperado.

```bash
kubectl get clusterpolicies
```

**O que você deve ver:**
```
NAME                          ADMISSION   BACKGROUND   VALIDATE ACTION   READY   AGE
block-hostpath                true        true         Enforce           true    2m
block-root-containers         true        true         Enforce           true    5m
require-non-latest-image-tag  true        true         Enforce           true    1m
require-resource-limits       true        true         Enforce           true    4m
```

---

### Passo 8: Testar — Pod Rodando como Root (Deve Ser Bloqueado)

**O que este passo faz:** Tenta criar um pod com `runAsUser: 0` (que é o usuário root) nos namespaces onde a política `block-root-containers` está ativa. O Kyverno intercepta a requisição no API server e rejeita antes que o pod seja criado no cluster. A mensagem de erro retornada pelo Kyverno inclui exatamente o texto que você definiu no campo `message` da política — isso é o feedback que o desenvolvedor recebe.

**Por que agora:** Testar cada política individualmente, de forma isolada, facilita o diagnóstico se algo não funcionar como esperado. Começar pelo bloqueio mais crítico (root) valida o componente mais importante do admission controller.

```bash
kubectl apply -f - << 'YAML'
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
        runAsUser: 0       # root — deve ser bloqueado
        runAsNonRoot: false
      resources:
        requests: {memory: "64Mi", cpu: "100m"}
        limits: {memory: "128Mi", cpu: "200m"}
YAML

echo "Esperado: Erro de admission — container tentando rodar como root"
```

**O que você deve ver:**
```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
policy block-root-containers/check-runAsNonRoot applied to default/Pod/test-root-user:
FAILED: POLÍTICA BANCO MERIDIAN: Container 'app' deve rodar como não-root.
Defina securityContext.runAsNonRoot=true e securityContext.runAsUser maior que 999.
```

---

### Passo 9: Testar — Pod sem Resource Limits (Deve Ser Bloqueado)

**O que este passo faz:** Tenta criar um pod que passa na validação de não-root (usa `runAsUser: 1000`) mas não define resource limits. O Kyverno verifica ambas as políticas independentemente — um pod precisa satisfazer TODAS as políticas ativas para ser admitido. A mensagem de erro identifica claramente qual política falhou e por quê.

**Por que agora:** Testar as políticas em sequência, isolando cada tipo de falha, demonstra que cada política funciona independentemente. Em produção, um pod pode falhar em múltiplas políticas simultaneamente — o Kyverno lista todas as falhas.

```bash
kubectl apply -f - << 'YAML'
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
      # SEM resource limits — deve ser bloqueado
YAML

echo "Esperado: Erro de admission — Container sem resource limits"
```

**O que você deve ver:**
```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
policy require-resource-limits/check-resource-limits applied to lab04-bancomeridian/Pod/test-no-limits:
FAILED: POLÍTICA BANCO MERIDIAN: Container 'app' deve ter resource requests e limits definidos.
```

---

### Passo 10: Testar — Pod com hostPath (Deve Ser Bloqueado)

**O que este passo faz:** Tenta criar um pod que satisfaz as políticas de não-root e resource limits, mas define um volume `hostPath` montando `/etc` do nó host. O Kyverno detecta a presença do `hostPath` na lista de volumes e bloqueia o pod. O `/etc` do nó host contém arquivos críticos do sistema como `/etc/kubernetes/pki/`, `/etc/ssl/` — um container com acesso a esse diretório pode comprometer certificados TLS do cluster.

**Por que agora:** hostPath é frequentemente usado em desenvolvimento para facilitar o compartilhamento de arquivos com o nó, mas é uma das configurações mais perigosas em produção. Testar este bloqueio especificamente demonstra que a política funciona mesmo quando as outras condições de segurança são satisfeitas.

```bash
kubectl apply -f - << 'YAML'
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
        - name: host-etc
          mountPath: /host-etc
  volumes:
    - name: host-etc
      hostPath:
        path: /etc        # acesso ao filesystem do nó — deve ser bloqueado
YAML

echo "Esperado: Erro de admission — volumes do tipo hostPath não são permitidos"
```

**O que você deve ver:**
```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
policy block-hostpath/block-hostpath-volumes applied to lab04-bancomeridian/Pod/test-hostpath:
FAILED: POLÍTICA BANCO MERIDIAN: Volumes do tipo hostPath não são permitidos.
hostPath dá acesso ao filesystem do nó host, permitindo container escape.
```

---

### Passo 11: Testar — Pod com Tag Latest (Deve Ser Bloqueado)

**O que este passo faz:** Tenta criar um pod que satisfaz todas as outras políticas mas usa a imagem `nginx:latest`. A política `require-non-latest-image-tag` detecta a tag `latest` e bloqueia o pod. Este teste confirma que as políticas são cumulativas — você precisa satisfazer TODAS as 4 para criar um pod nos namespaces protegidos.

**Por que agora:** A tag `latest` é a violação mais comum em ambientes que estão migrando para práticas mais maduras. Muitos times de desenvolvimento usam `latest` por conveniência — esta política força a adoção de tags específicas.

```bash
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: test-latest-tag
  namespace: lab04-bancomeridian
spec:
  containers:
    - name: app
      image: nginx:latest    # tag latest — deve ser bloqueada
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      resources:
        requests: {memory: "64Mi", cpu: "100m"}
        limits: {memory: "128Mi", cpu: "200m"}
YAML

echo "Esperado: Erro de admission — Tag latest não permitida"
```

---

### Passo 12: Criar Pod Que Satisfaz Todas as Políticas

**O que este passo faz:** Cria um pod que satisfaz todas as 4 políticas Kyverno simultaneamente. O pod `pod-compliant-bancomeridian` usa: `runAsUser: 1000` (não-root), `runAsNonRoot: true`, resource requests e limits definidos, imagem com tag específica `nginx:1.25.3`, sem volumes hostPath. Adicionalmente, usa `readOnlyRootFilesystem: true` (best practice — o container não pode escrever no filesystem) e `seccompProfile: RuntimeDefault` (restringe syscalls permitidas ao perfil padrão seguro do container runtime).

**Por que agora:** Após verificar que cada violação é bloqueada, você precisa confirmar que um pod válido consegue ser criado. Se este pod for bloqueado, há um problema nas políticas que precisa ser investigado.

```bash
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
      image: nginx:1.25.3
      securityContext:
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
      resources:
        requests:
          memory: "64Mi"
          cpu: "100m"
        limits:
          memory: "128Mi"
          cpu: "200m"
YAML

echo "Pod compliant criado — deve aparecer como Running"
kubectl get pod pod-compliant-bancomeridian -n lab04-bancomeridian
```

**O que você deve ver:**
```
NAME                          READY   STATUS    RESTARTS   AGE
pod-compliant-bancomeridian   1/1     Running   0          10s
```
O pod foi admitido pelo Kyverno e está rodando. Isso confirma que as políticas bloqueiam exatamente o que devem bloquear, sem bloquear pods legítimos.

---

### Passo 13: Verificar PolicyReports do Kyverno

**O que este passo faz:** Consulta os PolicyReports gerados automaticamente pelo Kyverno para o namespace `lab04-bancomeridian`. O Kyverno gera esses relatórios em background para todos os recursos existentes no namespace, mesmo que não tenham tentado fazer um deploy novo. Os relatórios mostram: quantos recursos passaram (`pass`), quantos violam as políticas (`fail`), e os detalhes de cada violação. Isso é útil para auditar o estado atual do cluster contra as políticas.

**Por que agora:** Os PolicyReports são a evidência formal de compliance — eles mostram não apenas que as políticas existem, mas que os recursos do cluster foram avaliados contra elas. Isso é o que o auditor do BACEN quer ver.

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
    print(f'Pass: {summary.get(\"pass\", 0)}')
    print(f'Fail: {summary.get(\"fail\", 0)}')
    print(f'Error: {summary.get(\"error\", 0)}')
    results = item.get('results', [])
    for r in results[:5]:
        print(f'  [{r.get(\"result\",\"?\")}] {r.get(\"policy\",\"?\")} — {r.get(\"resources\",[{}])[0].get(\"name\",\"?\")}')
"
```

---

### Passo 14: Gerar Relatório para o CISO

**O que este passo faz:** Cria um relatório Markdown documentando as 4 políticas implementadas, os testes realizados, e os próximos passos recomendados. O relatório inclui a tabela de políticas (qual violação cada uma bloqueia), a evidência dos testes (pods bloqueados com as mensagens de erro), e recomendações de políticas adicionais. A data é inserida automaticamente via `sed`.

**Por que agora:** O relatório é o entregável para o CISO. Ele documenta que a diretriz de segurança foi implementada e testada — transformando o trabalho técnico do laboratório em evidência de governança.

```bash
cat > /tmp/lab04-admission-control-report.md << 'REPORT'
# Relatório de Admission Control — Kubernetes
## Banco Meridian — Cluster
Data: $(date +%Y-%m-%d)

## Políticas Implementadas

| Política | Tipo | Ação | Namespaces |
|:---------|:----:|:----:|:-----------|
| block-root-containers | Validate | Enforce (bloqueia) | production, staging, lab04 |
| require-resource-limits | Validate | Enforce (bloqueia) | production, staging, lab04 |
| block-hostpath | Validate + Deny | Enforce (bloqueia) | production, staging, lab04 |
| require-non-latest-image-tag | Validate | Enforce (bloqueia) | production, staging, lab04 |

## Testes Realizados

| Teste | Pod | Resultado | Política |
|:------|:----|:---------:|:---------|
| Container root | test-root-user | BLOQUEADO | block-root-containers |
| Sem resource limits | test-no-limits | BLOQUEADO | require-resource-limits |
| Com hostPath | test-hostpath | BLOQUEADO | block-hostpath |
| Tag latest | test-latest-tag | BLOQUEADO | require-non-latest-image-tag |
| Pod compliant | pod-compliant-bancomeridian | ADMITIDO | Todas |

## Próximos Passos Recomendados

1. Adicionar política de network policy (isolamento de pods)
2. Adicionar política de verificação de assinatura Cosign (integrar com Lab 02)
3. Adicionar política de seccomp profile obrigatório
4. Expandir para namespace default e kube-system (com exceções)
REPORT

sed -i "s/\$(date +%Y-%m-%d)/$(date +%Y-%m-%d)/" /tmp/lab04-admission-control-report.md
echo "Relatório criado em: /tmp/lab04-admission-control-report.md"
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
| 7 | Namespace criado | `kubectl get namespace lab04-bancomeridian` |
| 8 | Pod root bloqueado | Erro admission webhook com mensagem sobre root |
| 9 | Pod sem limits bloqueado | Erro admission webhook com mensagem sobre limits |
| 10 | Pod hostPath bloqueado | Erro admission webhook com mensagem sobre hostPath |
| 11 | Pod latest bloqueado | Erro admission webhook com mensagem sobre tag |
| 12 | Pod compliant criado | Pod em `Running` sem erros |
| 13 | PolicyReport verificado | Relatório mostra `pass/fail` por recurso |
| 14 | Relatório gerado | Arquivo .md criado |

---

## 8. Gabarito Completo

### As 4 Políticas — Configuração Canônica

```yaml
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
```

**Por que esta é a resposta correta:** As 4 políticas formam um conjunto mínimo de segurança para containers em produção. Cada política cobre um vetor de ataque diferente: root (escalação de privilégio), sem limits (DoS), hostPath (container escape), latest (imprevisibilidade). O modo `Enforce` garante que nenhum pod não-conforme passe — diferente do modo `Audit` que apenas gera alertas sem bloquear. O `background: true` garante que o Kyverno também avalie recursos existentes.

**Erro mais comum:** Configurar `validationFailureAction: Audit` em vez de `Enforce`. No modo Audit, o Kyverno registra as violações mas não bloqueia os pods — o pod é criado normalmente. O Audit é útil para "shadow mode" antes de habilitar o Enforce, mas não oferece proteção real.

---

### Mensagens de Erro Esperadas por Política

| Política | Mensagem de Erro Esperada |
|:---------|:--------------------------|
| block-root-containers | `POLÍTICA BANCO MERIDIAN: Container 'app' deve rodar como não-root. Defina securityContext.runAsNonRoot=true e securityContext.runAsUser maior que 999.` |
| require-resource-limits | `POLÍTICA BANCO MERIDIAN: Container 'app' deve ter resource requests e limits definidos. Containers sem limits podem causar DoS acidental no nó.` |
| block-hostpath | `POLÍTICA BANCO MERIDIAN: Volumes do tipo hostPath não são permitidos. hostPath dá acesso ao filesystem do nó host, permitindo container escape.` |
| require-non-latest-image-tag | `POLÍTICA BANCO MERIDIAN: A imagem 'nginx:latest' usa tag 'latest'. Use uma tag específica como nginx:1.25.3.` |

**Por que esta é a resposta correta:** Mensagens de erro descritivas e educativas são uma parte essencial do admission control efetivo. Uma mensagem como "policy violation" não ajuda o desenvolvedor a corrigir o problema — a mensagem precisa explicar o que está errado, por que é um problema de segurança, e como corrigir. As mensagens acima seguem esse padrão: identificam o recurso violador, explicam o risco, e sugerem a correção.

**Erro mais comum:** Ao criar a política `require-non-latest-image-tag`, usar `validate.pattern` em vez de `validate.foreach` com `deny`. O `pattern` verifica o primeiro container — se o primeiro container tiver uma tag específica mas o segundo for `latest`, a violação passa. O `foreach` itera todos os containers, garantindo cobertura completa.

---

*Lab 04 — Admission Control com Kyverno*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
