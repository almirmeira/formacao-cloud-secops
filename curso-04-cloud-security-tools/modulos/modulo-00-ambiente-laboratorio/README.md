# Módulo 00 — Preparação do Ambiente de Laboratório
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **⚠️ IMPORTANTE:** Conclua este módulo antes de qualquer laboratório do curso.
> O ambiente inclui Kubernetes local, Terraform, HashiCorp Vault e diversas ferramentas CLI.

---

## Visão Geral

Este módulo configura um ambiente de laboratório completo para explorar o ecossistema de
ferramentas de Cloud Security. Diferente dos cursos 1–3 que usam ambientes cloud reais, este
curso utiliza um ambiente **híbrido**: ferramentas open-source rodando localmente (K8s, Vault,
OPA) + APIs de nuvem reais (AWS, Azure) para os labs de CSPM e CIEM.

Ao final você terá:
- Cluster Kubernetes local (kind) com Falco e Kyverno
- HashiCorp Vault em modo dev para laboratórios
- AWS CLI + Azure CLI configuradas para os labs de CSPM
- GitHub Actions configurado para o pipeline DevSecOps
- Todas as ferramentas open-source instaladas

**Duração estimada:** 2–3 horas  

---

## Topologia do Ambiente

```
AMBIENTE DE LABORATÓRIO — CURSO 4
────────────────────────────────────────────────────────────────────────────
SUA MÁQUINA LOCAL
│
├── Docker Engine
│   └── kind (Kubernetes local)
│       ├── Namespace: falco-system
│       │   └── Falco DaemonSet (runtime security)
│       ├── Namespace: security-tools
│       │   ├── HashiCorp Vault (dev mode)
│       │   └── External Secrets Operator
│       └── Namespace: apps (workloads de teste)
│           ├── app-vulnerable (imagem com CVEs para scan)
│           └── app-secure (imagem hardened de referência)
│
├── Ferramentas CLI (instaladas localmente)
│   ├── Prowler v4         (CSPM: AWS + Azure + GCP)
│   ├── Checkov            (IaC scanning)
│   ├── Trivy              (containers + IaC + SBOM)
│   ├── Syft               (SBOM generation)
│   ├── Cosign             (image signing)
│   ├── kube-bench         (CIS K8s benchmark)
│   └── kubescape          (K8s security posture)
│
├── GitHub Actions (repositório de laboratório)
│   └── Pipeline: scan → build → sign → verify → deploy
│
└── Conectores para Nuvem
    ├── AWS CLI (conta sandbox CECyber)
    └── Azure CLI (tenant de demonstração CECyber)
```

---

## Etapa 1 — Instalar o Docker Engine

### Linux (Ubuntu/Debian)

**Passo 1:** Adicione o repositório oficial Docker:

```bash
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

**Passo 2:** Instale o Docker:

```bash
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**Passo 3:** Adicione seu usuário ao grupo docker (para executar sem sudo):

```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Passo 4:** Verifique a instalação:

```bash
docker run hello-world
```

**Resultado esperado:** Mensagem "Hello from Docker!" impressa no terminal

### macOS

```bash
# Instale o Docker Desktop para Mac via site oficial: docker.com/products/docker-desktop
# Ou via Homebrew:
brew install --cask docker
# Abra o Docker Desktop e aguarde inicialização
docker run hello-world
```

---

## Etapa 2 — Instalar kind (Kubernetes Local)

```bash
# Linux/macOS
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Verificar
kind --version
```

**Resultado esperado:** `kind v0.20.0 go1.x linux/amd64`

---

## Etapa 3 — Instalar kubectl

```bash
# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# macOS
brew install kubectl

# Verificar
kubectl version --client
```

---

## Etapa 4 — Criar o Cluster Kubernetes para os Labs

**Passo 1:** Crie o arquivo de configuração do cluster:

```bash
cat > $HOME/cecyber-labs/cloud-tools/kind-cluster.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: cecyber-security-lab
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
  - containerPort: 8200
    hostPort: 8200
    protocol: TCP
- role: worker
- role: worker
EOF
```

**Passo 2:** Crie o cluster:

```bash
kind create cluster --config $HOME/cecyber-labs/cloud-tools/kind-cluster.yaml
```

**Resultado esperado:**
```
Creating cluster "cecyber-security-lab" ...
 ✓ Ensuring node image (kindest/node:v1.28.0) 🖼
 ✓ Preparing nodes 📦 📦 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
 ✓ Joining worker nodes 🚜
Set kubectl context to "kind-cecyber-security-lab"
```

**Passo 3:** Verifique o cluster:

```bash
kubectl get nodes
```

**Resultado esperado:**
```
NAME                                   STATUS   ROLES           AGE
cecyber-security-lab-control-plane     Ready    control-plane   2m
cecyber-security-lab-worker            Ready    <none>          1m
cecyber-security-lab-worker2           Ready    <none>          1m
```

---

## Etapa 5 — Instalar as Ferramentas de Security

**Passo 1:** Instale todas as ferramentas em um único script:

```bash
cat > $HOME/cecyber-labs/cloud-tools/install-tools.sh << 'SCRIPT'
#!/bin/bash
# CECyber Cloud Security Tools — Instalação de Ferramentas
echo "📦 Instalando ferramentas de Cloud Security..."

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
echo "✅ Trivy: $(trivy --version | head -1)"

# Checkov
pip3 install checkov
echo "✅ Checkov: $(checkov --version)"

# Prowler v4
pip3 install prowler
echo "✅ Prowler: $(prowler --version)"

# Syft (SBOM)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
echo "✅ Syft: $(syft --version)"

# Cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign
echo "✅ Cosign: $(cosign version)"

# kube-bench
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_amd64.tar.gz -o kube-bench.tar.gz
tar -xzf kube-bench.tar.gz
sudo mv kube-bench /usr/local/bin/
rm kube-bench.tar.gz
echo "✅ kube-bench: $(kube-bench --version)"

# kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
echo "✅ kubescape: $(kubescape version)"

echo ""
echo "🎉 Instalação concluída!"
SCRIPT

chmod +x $HOME/cecyber-labs/cloud-tools/install-tools.sh
bash $HOME/cecyber-labs/cloud-tools/install-tools.sh
```

---

## Etapa 6 — Instalar Falco no Cluster Kubernetes

```bash
# Adicionar repositório Helm do Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Criar namespace
kubectl create namespace falco-system

# Instalar Falco com eBPF (recomendado)
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true

# Verificar pods
kubectl get pods -n falco-system
```

**Resultado esperado após 2–3 minutos:**
```
NAME                             READY   STATUS    RESTARTS
falco-xxxxx-yyyyy                1/1     Running   0
falco-falcosidekick-xxxxx        1/1     Running   0
falco-falcosidekick-ui-xxxxx     1/1     Running   0
```

---

## Etapa 7 — Instalar Kyverno

```bash
# Instalar Kyverno via Helm
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace

# Verificar
kubectl get pods -n kyverno
```

---

## Etapa 8 — Instalar HashiCorp Vault (modo dev para labs)

```bash
# Instalar Vault CLI
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Verificar
vault --version

# Iniciar Vault em modo dev (para laboratórios — não usar em produção!)
# Execute em um terminal separado:
vault server -dev -dev-root-token-id="cecyber-root-token" &

# Configurar variáveis
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="cecyber-root-token"

# Verificar
vault status
```

**Resultado esperado:**
```
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Vault Version   1.x.x
```

---

## Etapa 9 — Health Check Final

```bash
cat > $HOME/cecyber-labs/cloud-tools/health-check.sh << 'SCRIPT'
#!/bin/bash
PASS=0; FAIL=0

check() {
    eval "$2" &>/dev/null && echo "✅ $1" && ((PASS++)) || echo "❌ $1" && ((FAIL++))
}

echo "======================================"
echo " CECyber Cloud Security Tools Health  "
echo "======================================"

check "Docker"              "docker info"
check "kind"                "kind --version"
check "kubectl"             "kubectl version --client"
check "Cluster K8s"         "kubectl get nodes | grep Ready"
check "Trivy"               "trivy --version"
check "Checkov"             "checkov --version"
check "Prowler"             "prowler --version"
check "Syft"                "syft --version"
check "Cosign"              "cosign version"
check "kube-bench"          "kube-bench --version"
check "kubescape"           "kubescape version"
check "Falco running"       "kubectl get pods -n falco-system | grep Running"
check "Kyverno running"     "kubectl get pods -n kyverno | grep Running"
check "Vault CLI"           "vault --version"
check "Vault acessível"     "vault status"
check "AWS CLI"             "aws --version"

echo "======================================"
echo " $PASS OK · $FAIL falhas              "
echo "======================================"
[ $FAIL -eq 0 ] && echo "🎉 Pronto para os laboratórios!" || exit 1
SCRIPT

chmod +x $HOME/cecyber-labs/cloud-tools/health-check.sh
bash $HOME/cecyber-labs/cloud-tools/health-check.sh
```

---

## Resumo

| Componente             | Status Esperado |
|:-----------------------|:---------------:|
| Docker Engine          | ✅ Running       |
| kind + kubectl         | ✅ Instalados    |
| Cluster K8s (3 nós)    | ✅ Ready         |
| Falco (eBPF)           | ✅ Running       |
| Kyverno                | ✅ Running       |
| HashiCorp Vault (dev)  | ✅ Unsealed      |
| Trivy + Checkov + Syft | ✅ Instalados    |
| Prowler + kube-bench   | ✅ Instalados    |
| Cosign + kubescape     | ✅ Instalados    |

---

**Parabéns!** Ambiente configurado.

*Próximo: [Módulo 01 — Panorama de Cloud Security Tools](../modulo-01-panorama-cloud-security/README.md)*

---

*Módulo 00 · Curso 4 — Ferramentas de Cloud Security · CECyber · v2.0 · 2026*
