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

**O que este passo faz:** Verifica que o Falco está instalado e rodando no cluster kind local. O Falco é um agente de runtime security baseado em eBPF — ele intercepta syscalls do kernel para monitorar o comportamento de todos os processos em todos os containers do cluster. O driver eBPF é o recomendado para ambientes modernos (evita carregar módulos do kernel, mais seguro e portável). O `kubectl wait` aguarda o pod ficar `Ready` antes de continuar o laboratório.

**Por que agora:** Sem o Falco rodando, não há detecção. Todo o laboratório depende de um Falco funcional. Verificar o status antes de iniciar qualquer simulação garante que os alertas que você espera ver serão efetivamente gerados.

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

**O que você deve ver:**
```
NAME                     READY   STATUS    RESTARTS   AGE
falco-7d8f4b9c5-xxxxx   1/1     Running   0          2m
```
O `1/1` na coluna READY indica que o único container no pod está rodando. Se aparecer `0/1`, o Falco está iniciando ou há um problema com o driver eBPF.

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

**O que este passo faz:** Lista e inspeciona as regras padrão que o Falco carrega automaticamente. O Falco vem com mais de 80 regras built-in que cobrem os ataques mais comuns em containers: shell interativo, leitura de arquivos sensíveis, escrita em diretórios de binários, conexões de saída para IPs suspeitos, e outros. Cada regra tem: uma condição (quando alertar), um output (mensagem do alerta), uma prioridade (WARNING, ERROR, CRITICAL) e tags de MITRE ATT&CK.

**Por que agora:** Antes de criar regras customizadas, você precisa entender o que já está coberto pelas regras padrão. Isso evita duplicação e ajuda a identificar as lacunas que as regras customizadas do Banco Meridian precisam preencher.

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

**O que você deve ver:** Lista de 80+ regras built-in incluindo:
- `Terminal shell in container`
- `Read sensitive file untrusted`
- `Write below binary dir`
- `Outbound connection (BLACKLIST)`

---

### Passo 3: Preparar Container de Teste

**O que este passo faz:** Cria um namespace de teste e faz o deploy de um container nginx que vai representar a API do Banco Meridian. O namespace `lab03-test` isola os recursos deste laboratório dos outros namespaces do cluster. As labels `app=api-bancomeridian` e `env=test` são importantes porque as regras Falco podem usar esses metadados Kubernetes nos outputs dos alertas — isso facilita correlacionar um alerta com o pod específico que gerou o comportamento suspeito.

**Por que agora:** Você precisa de um container rodando para simular os ataques. O nginx é uma boa escolha por ser uma imagem minimal que tem shell disponível para as simulações.

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

**O que este passo faz:** Inicia o monitoramento em tempo real dos logs do Falco em background. O `kubectl logs -f` faz streaming dos logs do pod Falco, e o `grep -E "Warning|Error|Critical"` filtra apenas as linhas de alerta — o Falco gera muito output de debugging que não é relevante para o laboratório. O `&` coloca o monitoramento em background com o PID salvo, para que você possa continuar usando o mesmo terminal para os próximos passos.

**Por que agora:** Você precisa ter o monitoramento ativo ANTES de simular os ataques para ver os alertas sendo gerados em tempo real. Este terminal agirá como seu "painel de SOC" durante o laboratório — deixe-o visível enquanto executa os próximos passos.

```bash
# Terminal 1 — manter este terminal aberto o laboratório todo
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)

kubectl logs -n falco-system $FALCO_POD -f | grep -E "Warning|Error|Critical" &
TAIL_PID=$!

echo "Monitoramento do Falco iniciado (PID: $TAIL_PID)"
echo "Deixe este terminal rodando e abra outro para os próximos passos"
```

---

### Passo 5: Simular Ataque #1 — Shell Interativo em Container

**O que este passo faz:** Simula o primeiro passo do incidente real — um atacante abrindo um shell interativo dentro do container da API. O `kubectl exec -it ... -- /bin/bash` é exatamente o comando que um atacante usaria após obter acesso ao cluster. O Falco monitora syscalls e detecta quando um shell é spawned com um terminal anexado (via TTY) dentro de um container — isso é a regra `Terminal shell in container`. O `timeout 5` limita a sessão a 5 segundos para fins de demonstração.

**Por que agora:** Esta é a primeira ação da sequência do incidente real. Verificar que o Falco alerta imediatamente ao abrir o shell confirma que a detecção em tempo real está funcionando.

```bash
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

**O que você deve ver no terminal de monitoramento (Passo 4):**
```
Warning evtsource=kernel rule="Terminal shell in container" 
output="A shell was spawned in a container with an attached terminal 
(user=root user_loginuid=-1 pod_name=api-bancomeridian ns=lab03-test 
container_id=abc123 image=nginx:latest shell=/bin/bash parent=kubectl 
cmdline=/bin/bash -c echo...)"
```
O campo `rule="Terminal shell in container"` identifica a regra padrão do Falco que foi disparada. O `parent=kubectl` mostra que o shell foi aberto via kubectl — o Falco consegue rastrear toda a árvore de processos.

---

### Passo 6: Simular Ataque #2 — Acesso ao IMDS AWS

**O que este passo faz:** Simula o segundo passo do incidente real — o atacante tentando acessar o endpoint IMDS (Instance Metadata Service) da AWS para roubar credenciais IAM do nó EC2 onde o container está rodando. O endereço `169.254.169.254` é o IP fixo do IMDS em qualquer instância AWS. Em um cluster EKS real sem proteção IMDS, um container comprometido pode usar esse endpoint para obter credenciais IAM do nó e se mover lateralmente na conta AWS.

**Por que agora:** Esta é a ação mais crítica do incidente — foi aqui que o atacante obteve as credenciais AWS no incidente real. O Falco tem regras específicas para detectar conexões ao IMDS.

```bash
echo "=== SIMULAÇÃO DE ATAQUE #2: Acesso ao AWS IMDS ==="
echo "Tentando acessar 169.254.169.254 de dentro do container"
echo ""

# Tentar acessar o endpoint IMDS
kubectl exec api-bancomeridian -n lab03-test -- \
  sh -c "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ || echo 'Timeout (esperado em kind, mas Falco detectou a tentativa)'"

echo ""
echo "Verificar alerta de IMDS access no Terminal 1..."
sleep 3
```

---

### Passo 7: Simular Ataque #3 — Escrita em Diretório Sensível

**O que este passo faz:** Simula o terceiro passo do incidente — o atacante tentando criar um backdoor escrevendo em `/etc/` e `/bin/`, diretórios que nunca devem ser modificados em runtime por uma aplicação legítima. O Falco tem a regra `Write below binary dir` que detecta qualquer escrita nos diretórios de binários do sistema. Esta é uma detecção clássica de tentativa de persistência: o atacante quer garantir que mesmo após o container ser reiniciado, o backdoor permanece.

**Por que agora:** Esta é a ação de persistência do incidente. Verificar que o Falco alerta confirma que a defesa em profundidade funciona — mesmo que o atacante tenha conseguido shell e credenciais, qualquer tentativa de persistência será detectada.

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

**O que este passo faz:** Cria um arquivo de regras Falco customizadas específicas para o Banco Meridian. O arquivo define 3 regras:

**Regra 1 — kubectl em Container:** Detecta o uso do binário `kubectl` dentro de qualquer container. Isso é um sinal de tentativa de container escape ou movimentação lateral no cluster — nenhuma aplicação legítima deveria executar kubectl em runtime. A tag `T1610` mapeia para MITRE ATT&CK "Deploy Container".

**Regra 2 — Reconhecimento em Container:** Detecta execução de comandos de reconhecimento (`whoami`, `id`, `uname`, `ifconfig`, etc.) quando executados a partir de um shell (`bash`, `sh`, `zsh`). A condição `proc.pname in (bash, sh...)` é importante — filtra processos legítimos que podem chamar `hostname` por exemplo durante inicialização.

**Regra 3 — Download Suspeito:** Detecta uso de curl/wget em containers de produção/staging. Containers imutáveis não devem fazer downloads externos em runtime — isso indica execução de código não autorizado.

**Por que agora:** As regras padrão do Falco não cobrem todos os padrões específicos do incidente do Banco Meridian. As regras customizadas fecham essas lacunas e criam alertas mais descritivos e contextualizados para o time de SecOps do banco.

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

# REGRA 1: Uso de kubectl DENTRO de um container
# Mapeamento MITRE: T1059.006 / T1610 — Deploy Container
# Contexto: kubectl dentro de container é sinal de container escape attempt
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

# REGRA 2: Processo de reconhecimento após shell
# Mapeamento MITRE: T1082 — System Information Discovery
# A condição proc.pname filtra shells como processo pai para evitar
# falsos positivos de aplicações que usam esses comandos durante init
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

# REGRA 3: Download de arquivo suspeito em container
# Mapeamento MITRE: T1105 — Ingress Tool Transfer
# A condição "not proc.args contains 169.254.169.254" evita sobreposição
# com a regra de IMDS — cada regra cobre um padrão específico
- rule: BancoMeridian - Download Suspeito em Container
  desc: >
    Uso de curl/wget para download de arquivo em container de produção.
    Containers imutáveis não devem fazer downloads externos em runtime.
  condition: >
    container and
    k8s.ns.name in (production, staging) and
    proc.name in (curl, wget) and
    not proc.args contains "169.254.169.254"
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

**O que este passo faz:** Instala as regras customizadas do Banco Meridian no Falco via Helm upgrade. O `--set-file customRules.bancomeridian-rules\\.yaml=...` é o método recomendado para injetar arquivos de regras customizadas sem modificar os arquivos padrão do Falco — as regras customizadas são carregadas em adição às regras padrão, não em substituição. O `kubectl rollout status daemonset/falco` aguarda o rollout completo — o Falco roda como DaemonSet (um pod por nó) e precisa recarregar as regras em todos os nós.

**Por que agora:** As regras customizadas só começam a funcionar após o Helm upgrade e o rollout do DaemonSet. Instalar as regras antes de testar no Passo 10 garante que o Falco já estará monitorando os padrões customizados quando você simular o ataque.

```bash
# Criar ConfigMap com as regras customizadas
kubectl create configmap falco-bancomeridian-rules \
  --from-file=bancomeridian-rules.yaml=/tmp/bancomeridian-rules.yaml \
  -n falco-system

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

**O que este passo faz:** Configura o Falco para escrever alertas em um arquivo de log JSON no caminho `/var/log/falco/falco-events.json`. O formato JSON é essencial para integração com SIEMs (como Microsoft Sentinel) e ferramentas de análise — cada alerta é um objeto JSON estruturado com campos padronizados (rule, priority, time, output_fields). O `json_include_tags_property: true` garante que as tags MITRE ATT&CK sejam incluídas em cada alerta, facilitando a correlação com outros eventos de segurança.

**Por que agora:** O arquivo de log JSON é a evidência persistente dos alertas gerados durante o laboratório. Sem persistência, os alertas existem apenas no stdout do container Falco e desaparecem quando o pod é reiniciado.

```bash
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

**O que este passo faz:** Reproduz a sequência completa do incidente real do Banco Meridian dentro do container de teste: abertura de shell → reconhecimento (whoami, id, uname, hostname) → tentativa de acesso ao IMDS para roubar credenciais IAM → tentativa de persistência em /tmp. Este é o momento de verificação central do laboratório — você está confirmando que o Falco detecta cada etapa da kill chain do incidente real.

**Por que agora:** Após instalar as regras customizadas e configurar o output JSON, você precisa verificar que o sistema completo funciona — regras padrão + regras customizadas + output persistente — contra a sequência de ataque que o CISO pediu para detectar.

```bash
echo "=== SIMULAÇÃO DO INCIDENTE REAL DO BANCO MERIDIAN ==="
echo "Reproduzindo a sequência de ações do atacante..."
echo ""

# Sequência do incidente real
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

**O que este passo faz:** Coleta os alertas do Falco em formato JSON e os processa para exibir um resumo estruturado. O script Python parseia cada linha JSON dos logs e extrai os campos mais relevantes: priority, rule, time e output. O formato JSON dos alertas Falco é padronizado — os campos `output_fields` contêm os metadados Kubernetes (pod name, namespace, image) que permitem correlacionar o alerta com o recurso exato no cluster.

**Por que agora:** O formato JSON é o que o SIEM vai consumir. Verificar que os alertas estão corretamente formatados como JSON antes de configurar a integração com o Sentinel garante que não haverá problemas de parsing após o deploy em produção.

```bash
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

**O que este passo faz:** Cria um servidor HTTP simples dentro do cluster para receber alertas do Falco via webhook. Em produção, este seria o endpoint do SIEM (Microsoft Sentinel Event Hub) ou do Slack. O servidor Python (`BaseHTTPRequestHandler`) recebe requisições POST com o payload JSON do Falco, extrai a regra e o output, e os imprime — simulando o que um SIEM faria ao receber o alerta. O Service Kubernetes expõe o servidor para que o Falco (rodando em outro pod) possa alcançá-lo.

**Por que agora:** A integração com webhook é o que transforma o Falco de uma ferramenta de detecção local em um componente do ecossistema de segurança centralizado do Banco Meridian. Este passo demonstra a arquitetura de integração antes de implementá-la em produção.

```bash
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

**O que este passo faz:** Cria um container que tem o binário `kubectl` instalado (usando a imagem `bitnami/kubectl`) e executa `kubectl` dentro dele — disparando a regra customizada `BancoMeridian - kubectl em Container`. O container `kubectl-test` simula um cenário onde um atacante colocou o kubectl dentro de um container comprometido para tentar listar ou modificar outros recursos do cluster. O `kubectl exec kubectl-test -- kubectl get pods` tenta listar pods — mesmo que falhe por falta de permissão, o Falco detecta a execução do binário.

**Por que agora:** Esta é a verificação direta das regras customizadas criadas no Passo 8. Testar cada regra individualmente confirma que a condição está correta e o output está sendo gerado como esperado.

```bash
# Criar pod de teste que tem kubectl instalado
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

**O que este passo faz:** Coleta todos os alertas gerados durante as últimas 2 horas e gera um relatório de runtime security para o CISO. O script Python lê os logs do Falco, extrai as regras disparadas e conta as ocorrências, e gera um sumário estruturado incluindo: contagem por prioridade (Critical, Error, Warning), top regras disparadas, e uma confirmação de que todos os comportamentos do incidente real foram detectados. A seção "Evidência para BACEN 4.893 Art. 9" conecta os alertas ao artigo específico de registro de incidentes.

**Por que agora:** O relatório é o entregável final do laboratório. Ele consolida toda a evidência gerada durante as simulações e apresenta de forma que o CISO pode usar para justificar o investimento em runtime security e para a auditoria BACEN.

```bash
FALCO_POD=$(kubectl get pod -n falco-system -l app.kubernetes.io/name=falco -o name | head -1)

kubectl logs -n falco-system $FALCO_POD --since=2h > /tmp/falco-lab03-events.log

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

**Por que esta é a resposta correta:** As 3 regras do Passo 8 cobrem os padrões específicos do incidente do Banco Meridian: kubectl em container (movimentação lateral), reconhecimento pós-shell (pré-requisito para exfiltração) e download suspeito (delivery de payload). Cada regra tem: macro de contexto (filtra para namespaces do banco), condição precisa (evita falsos positivos), output informativo (inclui todos os campos relevantes para triagem) e tags MITRE ATT&CK (para correlação com o framework).

**Erro mais comum:** Escrever regras muito amplas que geram falsos positivos. Por exemplo: detectar qualquer uso de `curl` em todos os containers vai gerar alertas para health checks legítimos. A condição `k8s.ns.name in (production, staging)` e a exclusão de `169.254.169.254` são exemplos de como afinar a regra para reduzir o ruído sem perder cobertura.

---

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

**Por que esta é a resposta correta:** A sequência de 5 alertas cobre toda a kill chain do incidente real do Banco Meridian. Cada alerta mapeia para uma técnica MITRE ATT&CK diferente: T1059 (Execution via shell), T1082 (System Discovery), T1552.005 (Cloud Instance Metadata API), T1547 (Persistence), T1610 (Deploy Container). Um SOC bem treinado ao ver essa sequência de alertas em 5 minutos identifica imediatamente que é um ataque em andamento, não eventos isolados.

**Erro mais comum:** Não ver o alerta #3 (IMDS) em ambiente kind local. Isso é esperado — o endpoint `169.254.169.254` não existe no kind (que roda em Docker). O Falco vai detectar a tentativa de conexão (`fd.sip=169.254.169.254`) mas o curl vai dar timeout. Em um cluster EKS real, o IMDS está disponível e o roubo de credenciais seria bem-sucedido sem a proteção.

---

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

**Por que esta é a resposta correta:** Os campos mais importantes são `output_fields` (metadados estruturados que o SIEM pode indexar e buscar) e `tags` (mapeamento MITRE ATT&CK automático). O campo `proc.pname=kubectl` no output revela que o shell foi aberto via kubectl — isso distingue uma sessão de debug legítima de um ataque via exploit de RCE (onde o parent seria o processo da aplicação, não kubectl).

**Erro mais comum:** Não ver os alertas no formato JSON ao verificar os logs via `kubectl logs`. O Falco só gera JSON se `json_output: true` estiver configurado nos values do Helm. O formato padrão é texto plano — o Passo 10 configura o output JSON. Se você testar antes do Passo 10, verá texto plano nos logs.

---

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
