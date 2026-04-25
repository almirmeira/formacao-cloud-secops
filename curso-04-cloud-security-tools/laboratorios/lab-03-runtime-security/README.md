# Lab 03 — Runtime Security com Falco
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2 horas  
> **Dificuldade:** Avançado  
> **Módulo Relacionado:** Módulo 04 — CWPP e Container Security  

---

## 1. Contexto Situacional

Após um incidente de segurança em produção onde um atacante executou comandos dentro de um container de API do Banco Meridian (obtendo credenciais AWS via IMDS), o CISO determinou que todos os clusters Kubernetes devem ter runtime security habilitado. Você foi designado para implementar e validar o Falco no cluster kind local antes do rollout em produção.

---

## 2. Situação Inicial

O cluster Kubernetes do Banco Meridian (simulado com kind localmente) está em execução mas sem nenhuma proteção de runtime. Um atacante que conseguir RCE em qualquer container não será detectado. O time de SecOps não tem visibilidade do comportamento interno dos containers.

---

## 3. Problema Identificado

O relatório forense do incidente revelou que o atacante executou os seguintes comandos dentro do container da API:
1. `bash` — abrindo shell interativo
2. `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` — roubando credenciais IAM
3. `cat /etc/passwd` — enumerando usuários do container
4. Escrita em `/tmp/backdoor.sh` — tentando persistência

Nenhum desses comportamentos foi detectado. O Falco teria detectado tudo isso.

---

## 4. Roteiro de Atividades

1. Verificar Falco instalado e rodando no cluster kind
2. Explorar regras padrão do Falco
3. Simular ataque: shell interativo em container
4. Verificar alertas gerados pelo Falco
5. Simular acesso ao IMDS AWS dentro do container
6. Simular escrita em /etc dentro do container
7. Criar regra Falco customizada (kubectl em container)
8. Configurar output para arquivo de log
9. Configurar webhook output simulado
10. Testar a regra customizada
11. Verificar alertas no formato JSON
12. Criar regra para detectar o padrão do incidente real
13. Exportar eventos para análise forense
14. Configurar Falcosidekick para Slack (configuração)
15. Gerar relatório de runtime security para o CISO

---

## 5. Proposição

Ao final deste laboratório, você terá:
- Falco funcionando no cluster kind com regras customizadas do Banco Meridian
- Evidência de detecção de todos os comportamentos do incidente real
- Relatório de runtime security com os alertas gerados

---

## 6. Script Passo a Passo

### Passo 1: Verificar Falco no Cluster kind

```bash
# Verificar que o cluster kind está rodando
kubectl cluster-info

# Verificar pods do Falco
kubectl get pods -n falco-system

# Se Falco não estiver instalado (módulo 00 pendente):
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set driver.kind=ebpf \
  --set tty=true

# Aguardar pods ficarem Ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=falco \
  -n falco-system --timeout=300s
```

**Resultado esperado:**
```
NAME                     READY   STATUS    RESTARTS   AGE
falco-7d8f4b9c5-xxxxx   1/1     Running   0          2m
```

**Troubleshooting:** Se o driver eBPF falhar em ambientes virtualizados:
```bash
helm upgrade falco falcosecurity/falco \
  -n falco-system \
  --set driver.kind=modern-ebpf
# ou fallback para kernel module:
--set driver.kind=kmod
```

---

### Passo 2: Explorar Regras Padrão do Falco

```bash
# Ver todas as regras carregadas
kubectl exec -n falco-system \
  $(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1) \
  -- falco --list 2>/dev/null | head -80

# Ver conteúdo das regras padrão
kubectl exec -n falco-system \
  $(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1) \
  -- cat /etc/falco/falco_rules.yaml 2>/dev/null | head -100

# Contar total de regras
kubectl exec -n falco-system \
  $(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1) \
  -- falco --list 2>/dev/null | grep -c "^rule:"
```

**Resultado esperado:** Lista de ~80+ regras built-in incluindo:
- `Terminal shell in container`
- `Read sensitive file untrusted`
- `Write below binary dir`
- `Outbound connection (BLACKLIST)`

---

### Passo 3: Preparar Container de Teste

```bash
# Criar namespace de teste
kubectl create namespace lab03-test

# Deploy de container de teste (representando API do Banco Meridian)
kubectl run api-bancomeridian \
  --image=nginx:latest \
  --namespace=lab03-test \
  --labels="app=api-bancomeridian,env=test"

kubectl wait --for=condition=ready pod/api-bancomeridian \
  -n lab03-test --timeout=60s

echo "Container de teste pronto"
kubectl get pod api-bancomeridian -n lab03-test
```

---

### Passo 4: Monitorar Alertas do Falco em Tempo Real

```bash
# Terminal 1 — manter este terminal aberto o laboratório todo
# Monitora alertas do Falco em tempo real
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)

kubectl logs -n falco-system $FALCO_POD -f | grep -E "Warning|Error|Critical" &
TAIL_PID=$!

echo "Monitoramento do Falco iniciado (PID: $TAIL_PID)"
echo "Deixe este terminal rodando e abra outro para os próximos passos"
```

---

### Passo 5: Simular Ataque #1 — Shell Interativo em Container

```bash
# SIMULAR ATAQUE: abrir shell interativo no container
# (O Falco deve detectar e alertar imediatamente)

echo "=== SIMULAÇÃO DE ATAQUE #1: Shell em Container ==="
echo "Executando: kubectl exec com shell interativo"
echo ""

# Abrir shell (apenas por alguns segundos para demonstração)
timeout 5 kubectl exec -it api-bancomeridian -n lab03-test -- /bin/bash \
  -c "echo 'Shell aberto — Falco deve ter detectado!'; whoami; id" || true

echo ""
echo "Verificar alerta no Terminal 1..."
sleep 3
```

**Alerta esperado do Falco:**
```
Warning evtsource=kernel rule="Terminal shell in container" 
output="A shell was spawned in a container with an attached terminal 
(user=root user_loginuid=-1 pod_name=api-bancomeridian ns=lab03-test 
container_id=abc123 image=nginx:latest shell=/bin/bash parent=kubectl 
cmdline=/bin/bash -c echo...)"
```

---

### Passo 6: Simular Ataque #2 — Acesso ao IMDS AWS

```bash
echo "=== SIMULAÇÃO DE ATAQUE #2: Acesso ao AWS IMDS ==="
echo "Tentando acessar 169.254.169.254 de dentro do container"
echo ""

# Tentar acessar o endpoint IMDS (não vai funcionar em kind, mas Falco detecta a tentativa de conexão)
kubectl exec api-bancomeridian -n lab03-test -- \
  sh -c "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ || echo 'Timeout (esperado em kind, mas Falco detectou a tentativa)'"

echo ""
echo "Verificar alerta de IMDS access no Terminal 1..."
sleep 3
```

---

### Passo 7: Simular Ataque #3 — Escrita em Diretório Sensível

```bash
echo "=== SIMULAÇÃO DE ATAQUE #3: Escrita em /etc ==="

kubectl exec api-bancomeridian -n lab03-test -- \
  sh -c "echo 'malicious backdoor' > /etc/cron-backdoor 2>/dev/null && echo 'Escrita realizada' || echo 'Escrita bloqueada (container imutável)'"

# Também tentar em /bin
kubectl exec api-bancomeridian -n lab03-test -- \
  sh -c "echo '#!/bin/bash' > /bin/backdoor.sh 2>/dev/null || true"

echo ""
echo "Verificar alertas de escrita sensível no Terminal 1..."
sleep 3
```

---

### Passo 8: Criar Regra Falco Customizada

```bash
# Criar arquivo de regras customizadas do Banco Meridian
cat > /tmp/bancomeridian-rules.yaml << 'FALCO_RULES'
# Regras Falco Customizadas — Banco Meridian
# Detectam os padrões específicos do incidente de segurança

# Macro auxiliar: containers do Banco Meridian
- macro: bancomeridian_container
  condition: >
    container and
    (container.image.repository startswith "bancomeridian/" or
     k8s.ns.name in (production, staging, lab03-test))

# ============================================================
# REGRA 1: Uso de kubectl DENTRO de um container
# ============================================================
# Mapeamento MITRE: T1059.006 — Python / T1610 — Deploy Container
# Contexto: kubectl dentro de um container é sinal de container escape attempt
# ou de um atacante tentando comprometer outros pods do cluster

- rule: BancoMeridian - kubectl em Container
  desc: >
    Uso do binário kubectl detectado dentro de um container.
    Isso pode indicar tentativa de container escape ou movimentação lateral
    no cluster Kubernetes.
  condition: >
    container and
    proc.name = kubectl
  output: >
    ALERTA: kubectl executado dentro de container!
    container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name
    user=%user.name args=%proc.args image=%container.image.repository
  priority: CRITICAL
  tags: [container, kubectl, lateral-movement, T1610, bancomeridian]

# ============================================================
# REGRA 2: Processo de reconhecimento após shell
# ============================================================
- list: recon_commands
  items: [id, whoami, hostname, uname, ifconfig, ip, netstat, ss, ps, top, env, printenv]

- rule: BancoMeridian - Reconhecimento em Container
  desc: >
    Execução de múltiplos comandos de reconhecimento em container.
    Sequência típica: whoami → id → uname → ifconfig → indica atividade de atacante.
  condition: >
    container and
    proc.name in (recon_commands) and
    proc.pname in (bash, sh, zsh, ksh, ash)
  output: >
    ALERTA: Comando de reconhecimento executado em container!
    comando=%proc.name container=%container.name pod=%k8s.pod.name
    ns=%k8s.ns.name user=%user.name image=%container.image.repository
  priority: WARNING
  tags: [container, recon, T1082, bancomeridian]

# ============================================================
# REGRA 3: Download de arquivo suspeito em container
# ============================================================
- rule: BancoMeridian - Download Suspeito em Container
  desc: >
    Uso de curl/wget para download de arquivo em container de produção.
    Containers imutáveis não devem fazer downloads externos em runtime.
  condition: >
    container and
    k8s.ns.name in (production, staging) and
    proc.name in (curl, wget) and
    not proc.args contains "169.254.169.254"  # IMDS é detectado por outra regra
  output: >
    ALERTA: Download externo em container de produção!
    proc=%proc.name args=%proc.args container=%container.name
    pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
  priority: ERROR
  tags: [container, download, T1105, bancomeridian]
FALCO_RULES

echo "Regras customizadas criadas em /tmp/bancomeridian-rules.yaml"
cat /tmp/bancomeridian-rules.yaml | head -5
```

---

### Passo 9: Instalar Regras Customizadas no Falco

```bash
# Criar ConfigMap com as regras customizadas
kubectl create configmap falco-bancomeridian-rules \
  --from-file=bancomeridian-rules.yaml=/tmp/bancomeridian-rules.yaml \
  -n falco-system

# Atualizar deployment do Falco para usar as regras customizadas
# (via Helm values)
cat > /tmp/falco-custom-values.yaml << 'YAML'
customRules:
  bancomeridian-rules.yaml: |
    $(cat /tmp/bancomeridian-rules.yaml)

falco:
  json_output: true
  json_include_output_property: true
  json_include_tags_property: true
YAML

# Aplicar via Helm upgrade
helm upgrade falco falcosecurity/falco \
  -n falco-system \
  --set-file customRules.bancomeridian-rules\\.yaml=/tmp/bancomeridian-rules.yaml

# Aguardar rollout
kubectl rollout status daemonset/falco -n falco-system --timeout=120s

echo "Regras customizadas instaladas"
```

---

### Passo 10: Configurar Output para Arquivo de Log

```bash
# Configurar Falco para escrever em arquivo de log JSON
cat > /tmp/falco-values-output.yaml << 'YAML'
falco:
  json_output: true
  json_include_output_property: true
  json_include_tags_property: true

  file_output:
    enabled: true
    keep_alive: false
    filename: /var/log/falco/falco-events.json

  stdout_output:
    enabled: true

falcoctl:
  config:
    artifact:
      follow:
        enabled: true
YAML

helm upgrade falco falcosecurity/falco \
  -n falco-system \
  -f /tmp/falco-values-output.yaml \
  --set-file customRules.bancomeridian-rules\\.yaml=/tmp/bancomeridian-rules.yaml

echo "Output para arquivo configurado"
```

---

### Passo 11: Simular Ataque Completo e Verificar Todos os Alertas

```bash
echo "=== SIMULAÇÃO DO INCIDENTE REAL DO BANCO MERIDIAN ==="
echo "Reproduzindo a sequência de ações do atacante..."
echo ""

# Sequência do incidente real:
# 1. Shell aberto via exploit RCE
# 2. Reconhecimento (whoami, id, uname)
# 3. Acesso ao IMDS para roubar credenciais IAM
# 4. Tentativa de persistência

# Simular toda a sequência
kubectl exec api-bancomeridian -n lab03-test -- \
  sh -c "
    echo '=== Atacante obteve RCE - abrindo sessão ==='
    whoami
    id
    uname -a
    hostname

    echo '=== Tentando roubar credenciais AWS ==='
    curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ || true

    echo '=== Tentando persistência ==='
    echo '#!/bin/bash' > /tmp/backdoor.sh
    chmod +x /tmp/backdoor.sh
    ls /tmp/

    echo '=== Fim da simulação ==='
  " 2>&1 || true

echo ""
echo "Aguardando alertas do Falco..."
sleep 5

# Coletar todos os alertas
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)
echo "=== ALERTAS GERADOS PELO FALCO ==="
kubectl logs -n falco-system $FALCO_POD --since=2m | \
  grep -E "Warning|Error|Critical|ALERTA" | head -20
```

---

### Passo 12: Verificar Alertas em Formato JSON

```bash
# Coletar alertas em JSON para análise
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)

kubectl logs -n falco-system $FALCO_POD --since=10m | \
  grep -E '^\{' | \
  python3 -c "
import json, sys

events = []
for line in sys.stdin:
    try:
        event = json.loads(line.strip())
        events.append(event)
    except json.JSONDecodeError:
        pass

print(f'Total de eventos: {len(events)}')
print()

for event in events[-10:]:
    print(f'[{event.get(\"priority\", \"?\")}] {event.get(\"rule\", \"?\")}')
    print(f'  Tempo: {event.get(\"time\", \"?\")}')
    print(f'  Output: {event.get(\"output\", \"?\")}')
    print(f'  Tags: {event.get(\"tags\", [])}')
    print()
" 2>/dev/null || echo "(JSON parsing: alguns alertas podem não estar em formato JSON)"
```

---

### Passo 13: Configurar Webhook Output (Simulado)

```bash
# Simular um webhook endpoint simples para receber alertas
# Em produção, este seria o endpoint do SIEM ou Slack

# Criar um deployment de "mock webhook receiver"
kubectl apply -f - << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-receiver
  namespace: falco-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook-receiver
  template:
    metadata:
      labels:
        app: webhook-receiver
    spec:
      containers:
        - name: receiver
          image: python:3.11-slim
          command: [python3, -c]
          args:
            - |
              from http.server import BaseHTTPRequestHandler, HTTPServer
              import json

              class Handler(BaseHTTPRequestHandler):
                  def do_POST(self):
                      length = int(self.headers['Content-Length'])
                      body = json.loads(self.rfile.read(length))
                      print(f"ALERTA RECEBIDO: {body.get('rule', 'unknown')} - {body.get('output', '')[:100]}")
                      self.send_response(200)
                      self.end_headers()
                  def log_message(self, *args): pass

              print("Webhook receiver rodando na porta 2802")
              HTTPServer(('0.0.0.0', 2802), Handler).serve_forever()
          ports:
            - containerPort: 2802
---
apiVersion: v1
kind: Service
metadata:
  name: webhook-receiver
  namespace: falco-system
spec:
  selector:
    app: webhook-receiver
  ports:
    - port: 2802
      targetPort: 2802
YAML

kubectl wait --for=condition=ready pod -l app=webhook-receiver \
  -n falco-system --timeout=60s

echo "Webhook receiver rodando em: http://webhook-receiver.falco-system.svc.cluster.local:2802"
```

---

### Passo 14: Testar Regra Customizada kubectl em Container

```bash
# Criar pod de teste que tem kubectl instalado (simulando um container comprometido)
kubectl run kubectl-test \
  --image=bitnami/kubectl:latest \
  --namespace=lab03-test \
  --command -- sleep 3600

kubectl wait --for=condition=ready pod/kubectl-test \
  -n lab03-test --timeout=60s

# Executar kubectl dentro do container (deve disparar a regra customizada)
kubectl exec kubectl-test -n lab03-test -- \
  kubectl get pods -n lab03-test 2>&1 || \
  echo "(kubectl pode não ter permissão, mas Falco já detectou a execução)"

echo ""
echo "Verificar alerta 'BancoMeridian - kubectl em Container' nos logs do Falco..."
sleep 3

FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)
kubectl logs -n falco-system $FALCO_POD --since=30s | grep -i "kubectl\|BancoMeridian"
```

---

### Passo 15: Gerar Relatório de Runtime Security

```bash
# Coletar todos os alertas das últimas horas
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)

kubectl logs -n falco-system $FALCO_POD --since=2h > /tmp/falco-lab03-events.log

# Gerar relatório
python3 << 'PYEOF'
import re
from collections import Counter
from datetime import datetime

log_file = '/tmp/falco-lab03-events.log'

with open(log_file) as f:
    content = f.read()

# Extrair regras disparadas
rules = re.findall(r'rule="([^"]+)"', content)
rule_counts = Counter(rules)

# Extrair prioridades
priorities = re.findall(r'(?:Warning|Error|Critical|Notice)', content)
priority_counts = Counter(priorities)

print(f"""
=== RELATÓRIO DE RUNTIME SECURITY — BANCO MERIDIAN ===
Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Cluster: kind-bancomeridian (laboratório)
Período: últimas 2 horas

RESUMO DE ALERTAS:
""")

for priority, count in sorted(priority_counts.items(), key=lambda x: ['Critical','Error','Warning','Notice'].index(x[0]) if x[0] in ['Critical','Error','Warning','Notice'] else 99):
    print(f"  {priority}: {count} alertas")

print(f"\nTOP REGRAS DISPARADAS:")
for rule, count in rule_counts.most_common(10):
    print(f"  ({count}x) {rule}")

print(f"""
INCIDENTE SIMULADO DETECTADO:
  ✓ Shell interativo em container detectado
  ✓ Tentativa de acesso ao AWS IMDS detectada
  ✓ Escrita em diretório sensível detectada
  ✓ Comandos de reconhecimento detectados

RECOMENDAÇÃO:
  Implementar Falco em todos os clusters EKS de produção do Banco Meridian.
  Alertas devem ser integrados com o SIEM (Microsoft Sentinel) para
  correlação com eventos de outras fontes.

  Evidência para BACEN 4.893 Art. 9 — registro de incidentes:
  Arquivo de log: /tmp/falco-lab03-events.log
  Retenção recomendada: 1 ano
""")
PYEOF

echo "Relatório gerado"
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Falco rodando | Pod `Running` em `falco-system` |
| 2 | Regras exploradas | Contagem de regras retornada |
| 3 | Container de teste criado | Pod `api-bancomeridian` Running |
| 4 | Monitoramento ativo | Logs do Falco em streaming |
| 5 | Ataque 1 simulado | Alerta "Terminal shell in container" visível |
| 6 | Ataque 2 simulado | Alerta de IMDS ou tentativa de conexão visível |
| 7 | Ataque 3 simulado | Alerta de escrita em diretório sensível visível |
| 8 | Regras customizadas criadas | Arquivo YAML com 3 regras |
| 9 | Regras instaladas | `helm upgrade` sem erros |
| 10 | Output configurado | Falco em JSON mode |
| 11 | Sequência completa simulada | Alertas gerados para cada passo |
| 12 | JSON verificado | Alertas parseados como JSON |
| 13 | Webhook configurado | Pod `webhook-receiver` Running |
| 14 | Regra customizada testada | Alerta `kubectl em Container` visível |
| 15 | Relatório gerado | Arquivo com summary de alertas |

---

## 8. Gabarito Completo

### Regras Falco do Banco Meridian — Arquivo Completo

O arquivo `/tmp/bancomeridian-rules.yaml` deve conter as 3 regras definidas no Passo 8, mais as 5 regras do Módulo 04 (total: 8 regras customizadas).

### Alertas Esperados Durante a Simulação do Incidente

```
=== SEQUÊNCIA DE ALERTAS ESPERADOS ===

1. [WARNING] Terminal shell in container
   proc.name=bash, container.name=api-bancomeridian
   → Shell interativo aberto por kubectl exec

2. [WARNING] BancoMeridian - Reconhecimento em Container
   proc.name=whoami, proc.pname=bash
   → Comandos de reconhecimento pós-shell

3. [CRITICAL] BancoMeridian - Acesso à AWS Metadata API (do módulo 04)
   fd.sip=169.254.169.254, proc.name=curl
   → Tentativa de roubo de credenciais IAM

4. [ERROR] BancoMeridian - Escrita em Diretório Sensível (do módulo 04)
   fd.name=/etc/cron-backdoor, proc.name=sh
   → Tentativa de persistência em /etc

5. [CRITICAL] BancoMeridian - kubectl em Container
   proc.name=kubectl, container.name=kubectl-test
   → kubectl executado dentro de container (rule customizada do lab)
```

### Output JSON de um Alerta Falco

```json
{
  "hostname": "kind-worker",
  "output": "Warning A shell was spawned in a container with an attached terminal 
    (user=root user_loginuid=-1 container_id=abc123 
    container_name=api-bancomeridian image=nginx:latest 
    shell=/bin/bash parent=kubectl cmdline=/bin/bash -c whoami)",
  "output_fields": {
    "container.id": "abc123",
    "container.image.repository": "nginx",
    "container.name": "api-bancomeridian",
    "evt.time": 1714000000000000000,
    "k8s.ns.name": "lab03-test",
    "k8s.pod.name": "api-bancomeridian",
    "proc.cmdline": "/bin/bash -c whoami",
    "proc.name": "bash",
    "proc.pname": "kubectl",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["container", "shell", "mitre_execution", "T1059"],
  "time": "2025-04-24T15:30:01.234567890Z"
}
```

### Integração SIEM (Próximo Passo após o Lab)

Para integrar os alertas do Falco com o Microsoft Sentinel (SIEM do Banco Meridian):

```yaml
# Adicionar ao values do Helm:
falcosidekick:
  enabled: true
  config:
    azure:
      eventhub:
        name: falco-events
        namespace: bancomeridian-events
        sharesasname: falco-policy
        sharedsaskey: "..."
    slack:
      webhookurl: "https://hooks.slack.com/services/..."
      minimumpriority: warning
    webhook:
      address: http://sentinel-webhook:8080
```

---

*Lab 03 — Runtime Security com Falco*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
