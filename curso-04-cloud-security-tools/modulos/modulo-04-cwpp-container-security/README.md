# Módulo 04 — CWPP e Container Security
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2h videoaulas + 2h laboratório + 1h live online  
> **Certificação Alvo:** CCSP domínio 3 / CCSK domínio 7  
> **Cenário:** Time de plataforma do Banco Meridian protegendo containers em produção

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Descrever o ciclo de vida seguro de um container e as ameaças em cada fase
2. Executar Trivy, Grype e Syft para scan de imagens e geração de SBOM
3. Assinar e verificar imagens com Cosign (Sigstore) em modo keyless
4. Escrever regras Falco para detectar comportamentos maliciosos em runtime
5. Montar um pipeline seguro de container: build → scan → sign → push → verify → runtime

---

## 1. CWPP — Por Que Containers Mudaram o Cenário de Segurança

### 1.1 O Impacto dos Containers na Superfície de Ataque

Antes dos containers, a superfície de ataque de um servidor era relativamente simples: sistema operacional, aplicação, dependências. Havia poucos artefatos para gerenciar e escanear.

Com containers e microsserviços:
- Uma aplicação que antes era 1 binário agora é 20–50 microserviços
- Cada microserviço tem sua própria imagem base com pacotes e dependências
- Imagens são pulled de registries públicos (Docker Hub) sem verificação de integridade
- Containers são imutáveis: uma vez que a imagem tem CVEs, todos os containers rodando dela são vulneráveis
- A densidade aumenta: um nó Kubernetes pode ter 100+ containers rodando simultaneamente

**Resultado:** a superfície de ataque se multiplicou por 50x, e a gestão manual é impossível.

### 1.2 O Ciclo de Vida Seguro de um Container

```
CICLO DE VIDA SEGURO DE CONTAINER
──────────────────────────────────────────────────────────────────────────────
    ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
    │  BUILD  │────▶│  SCAN   │────▶│  SIGN   │────▶│  PUSH   │────▶│  VERIFY │
    │         │     │  SBOM   │     │ Cosign  │     │  ECR/   │     │  antes  │
    │Dockerfile│    │  Trivy  │     │Sigstore │     │  GHCR   │     │ deploy  │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘     └────┬────┘
                        │                                                  │
                   Vulnerabilidades                                        │
                   encontradas?                                      ┌────▼────┐
                        │                                            │ RUNTIME │
                      FAIL                                           │  Falco  │
                  (bloqueia push)                                    │  eBPF   │
                                                                     └─────────┘
──────────────────────────────────────────────────────────────────────────────
Ferramentas por fase:
  BUILD:   Docker, Buildkit, hadolint (lint Dockerfile)
  SCAN:    Trivy, Grype, Snyk Container, Clair
  SBOM:    Syft (gera SPDX/CycloneDX), Trivy (--format cyclonedx)
  SIGN:    Cosign (keyless Sigstore ou chave), Notary v2
  PUSH:    docker push + cosign push attestation
  VERIFY:  cosign verify (policy admission controller)
  RUNTIME: Falco, Sysdig Secure, Aqua Security
──────────────────────────────────────────────────────────────────────────────
```

---

## 2. Image Scanning

### 2.1 Trivy — A Ferramenta Unificada

Trivy é atualmente a ferramenta mais usada no mundo para scan de containers. É open-source, mantida pela Aqua Security, e cobre múltiplos tipos de vulnerabilidades em um único binário.

**O que o Trivy detecta em imagens:**
- **OS packages:** vulnerabilidades em pacotes do sistema (apt, yum, apk) — mapeadas para CVE database
- **Language libraries:** vulnerabilidades em dependências de aplicação (npm, pip, gem, gradle, Maven, Go modules)
- **Secrets:** chaves API, tokens, senhas hardcoded na imagem
- **Misconfigurations:** problemas de configuração em Dockerfile (usuário root, latest tag, EXPOSE desnecessário)
- **License compliance:** licenças de dependências (GPLv3 em produto proprietário, por exemplo)

**Instalação:**
```bash
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Docker
docker pull aquasec/trivy:latest

# Verificar
trivy --version
```

**Execução completa — todos os tipos:**
```bash
# Scan básico de imagem
trivy image nginx:latest

# Scan com severity filtering (apenas HIGH e CRITICAL)
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan com falha automática em CRITICAL
trivy image --exit-code 1 --severity CRITICAL nginx:latest

# Saída JSON
trivy image --format json --output trivy-results.json nginx:latest

# Saída table (padrão, mais legível)
trivy image --format table nginx:latest

# Scan de imagem local (não no registry)
trivy image --input ./minha-imagem.tar

# Incluir checagem de secrets
trivy image --scanners vuln,secret nginx:latest

# Incluir IaC e misconfig
trivy image --scanners vuln,secret,config nginx:latest

# SBOM em formato CycloneDX
trivy image --format cyclonedx --output sbom.json nginx:latest

# SBOM em formato SPDX
trivy image --format spdx-json --output sbom.spdx.json nginx:latest

# Scan com política de ignorar CVEs sem fix disponível
trivy image --ignore-unfixed nginx:latest

# Scan de imagem no ECR
trivy image --aws-region us-east-1 123456789.dkr.ecr.us-east-1.amazonaws.com/app:latest

# Scan de arquivo tar (imagem exportada)
docker save nginx:latest -o nginx.tar
trivy image --input nginx.tar

# Scan de filesystem (não imagem container)
trivy fs ./app/

# Scan de repositório Git
trivy repo https://github.com/bancomeridian/api-pagamentos

# Scan de binário específico
trivy rootfs /path/to/app
```

**Exemplo de output JSON:**
```json
{
  "SchemaVersion": 2,
  "ArtifactName": "nginx:1.25",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {"Family": "debian", "Name": "12.0"},
    "ImageID": "sha256:abc123...",
    "RepoTags": ["nginx:1.25"],
    "RepoDigests": ["nginx@sha256:def456..."]
  },
  "Results": [
    {
      "Target": "nginx:1.25 (debian 12.0)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-44487",
          "PkgName": "libnghttp2-14",
          "InstalledVersion": "1.52.0-1",
          "FixedVersion": "1.52.0-1+deb12u1",
          "Severity": "HIGH",
          "Title": "HTTP/2 Rapid Reset Attack",
          "Description": "...",
          "CVSS": {
            "nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
          },
          "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"]
        }
      ]
    }
  ]
}
```

### 2.2 Grype — Alternativa com Integração Syft

Grype é desenvolvida pela Anchore, funciona de forma complementar ao Syft (gerador de SBOM).

```bash
# Instalar Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Scan básico
grype nginx:latest

# Scan com saída JSON
grype nginx:latest -o json > grype-results.json

# Scan de SBOM gerado pelo Syft (fluxo recomendado)
syft nginx:latest -o syft-json=sbom.json
grype sbom:sbom.json

# Scan apenas CVEs com fix disponível
grype nginx:latest --only-fixed

# Scan com threshold de severidade
grype nginx:latest --fail-on high

# Verificar apenas packages de uma linguagem específica
grype dir:./app --scope squashed
```

### 2.3 Snyk Container

```bash
# Instalar Snyk CLI
npm install -g snyk
snyk auth  # Autenticar (conta gratuita disponível)

# Scan de imagem
snyk container test nginx:latest

# Scan com output detalhado
snyk container test nginx:latest --json > snyk-results.json

# Monitorar imagem (tracking contínuo no Snyk dashboard)
snyk container monitor nginx:latest

# Scan de Dockerfile junto com a imagem
snyk container test nginx:latest --file=Dockerfile
```

### 2.4 Clair

Clair é um scanner de imagens com arquitetura API server, adequado para organizações que querem controlar todos os dados de vulnerabilidades internamente.

```bash
# Deploy Clair via Docker Compose
cat > docker-compose-clair.yml <<EOF
version: '3.8'
services:
  clair-db:
    image: postgres:15
    environment:
      POSTGRES_DB: clair
      POSTGRES_USER: clair
      POSTGRES_PASSWORD: clair123

  clair:
    image: quay.io/projectquay/clair:v4.7.0
    depends_on: [clair-db]
    ports:
      - "6060:6060"
      - "6061:6061"
    volumes:
      - ./clair-config.yaml:/etc/clair/config.yaml

  clairctl:
    image: quay.io/projectquay/clair:v4.7.0
    command: clairctl
    environment:
      CLAIR_API: http://clair:6060
EOF

# Scan via clairctl
docker exec clair clairctl report nginx:latest
```

---

## 3. SBOM — Software Bill of Materials

### 3.1 Por Que SBOMs São Importantes — A Lição do Log4Shell

Em dezembro de 2021, o Log4Shell (CVE-2021-44228) foi divulgado. Era uma vulnerabilidade crítica (CVSS 10.0) na biblioteca Log4j, usada em milhares de aplicações Java.

O problema: quais das minhas aplicações usam Log4j? A maioria das organizações levou dias ou semanas para responder essa pergunta, porque não tinham inventário das dependências dos seus softwares.

Com SBOM, a resposta seria instantânea: `grep -r "log4j" sbom.json`. Em segundos, lista completa de todas as imagens e versões afetadas.

### 3.2 Formatos de SBOM

| Formato | Organização | Casos de Uso | Suporte em Ferramentas |
|:--------|:-----------:|:------------|:---------------------:|
| SPDX | Linux Foundation | Compliance de licença, supply chain | Syft, Trivy, REUSE |
| CycloneDX | OWASP | Security, SBOM para vulnerabilidades | Syft, Trivy, Dependency-Track |
| Syft native JSON | Anchore | Análise interna, análise pelo Grype | Syft |

### 3.3 Syft — Geração de SBOM

```bash
# Instalar Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Gerar SBOM de imagem (formato Syft nativo)
syft nginx:latest

# SBOM em formato CycloneDX JSON (recomendado para análise de vulnerabilidades)
syft nginx:latest -o cyclonedx-json=sbom-cyclonedx.json

# SBOM em formato SPDX JSON
syft nginx:latest -o spdx-json=sbom-spdx.json

# SBOM de diretório (aplicação local)
syft dir:./app -o cyclonedx-json=app-sbom.json

# SBOM com todas as camadas da imagem
syft nginx:latest --scope all-layers -o cyclonedx-json=sbom.json

# Salvar como attestation (para assinar com Cosign)
syft nginx:latest -o cyclonedx-json - | cosign attest --type cyclonedx --predicate - minha-imagem:latest

# Grype usando o SBOM gerado
syft nginx:latest -o syft-json=sbom.json
grype sbom:sbom.json --output json > vulnerabilities.json
```

### 3.4 SLSA — Supply-chain Levels for Software Artifacts

SLSA é um framework do Google para avaliar e melhorar a segurança da cadeia de fornecimento de software:

| Nível | Requisitos | O que Garante |
|:------|:-----------|:-------------|
| SLSA 1 | Build documentado | Rastreabilidade básica do build |
| SLSA 2 | Build por serviço (CI) com provenance | Fonte verificável, build não alterado por humano |
| SLSA 3 | Build hardened, resistente a ataques de insider | Build isolado, não influenciável pelo dev |
| SLSA 4 | Revisão de 2 pessoas + hermetic build | Máxima segurança da cadeia |

Para o Banco Meridian, SLSA 2 é o target razoável: todos os artefatos devem ser buildados por CI/CD com provenance gerado e assinado.

---

## 4. Image Signing e Verificação

### 4.1 Cosign (Sigstore)

Cosign é a ferramenta do projeto Sigstore para assinar artefatos OCI (imagens Docker). O modo keyless usa OIDC (identidade do GitHub Actions, Google, etc.) como raiz de confiança — sem necessidade de gerenciar chaves privadas.

**Como keyless signing funciona:**
```
FLUXO COSIGN KEYLESS
───────────────────────────────────────────────────────────────────
1. CI/CD (GitHub Actions) executa: cosign sign --keyless
2. Cosign obtém token OIDC do GitHub Actions (GITHUB_ACTIONS=true)
3. Cosign envia token para Fulcio (CA do Sigstore) que emite certificado
4. Certificado inclui: identidade do CI/CD + hash da imagem
5. Cosign assina a imagem + envia para Rekor (transparency log imutável)
6. No deploy: cosign verify --certificate-identity-regexp="github.com/bancomeridian"
7. Cosign verifica que: imagem foi assinada pelo nosso CI/CD + está no Rekor
───────────────────────────────────────────────────────────────────
```

**Instalação e uso:**
```bash
# Instalar Cosign
brew install cosign
# ou
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Verificar
cosign version

# --- SIGNING COM CHAVE PRÓPRIA ---

# Gerar par de chaves
cosign generate-key-pair
# Gera: cosign.key (privada) e cosign.pub (pública)

# Assinar imagem com chave privada
cosign sign --key cosign.key minha-registry/app:v1.0.0

# Verificar assinatura com chave pública
cosign verify --key cosign.pub minha-registry/app:v1.0.0

# --- SIGNING KEYLESS (RECOMENDADO PARA CI/CD) ---

# No GitHub Actions (usando OIDC do Actions)
export COSIGN_EXPERIMENTAL=1
cosign sign --yes minha-registry/app:v1.0.0

# Verificar keyless — verificar que foi assinado pelo nosso CI/CD
cosign verify \
  --certificate-identity-regexp="https://github.com/bancomeridian/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  minha-registry/app:v1.0.0

# --- ATTESTATIONS (SBOM, SLSA PROVENANCE) ---

# Anexar SBOM como attestation
syft minha-registry/app:v1.0.0 -o cyclonedx-json=sbom.json
cosign attest \
  --type cyclonedx \
  --predicate sbom.json \
  --yes \
  minha-registry/app:v1.0.0

# Verificar attestation
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp="https://github.com/bancomeridian/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  minha-registry/app:v1.0.0 | jq .payload | base64 -d | jq .

# --- POLICY ENFORCEMENT COM COSIGN ---

# Verificar antes do deploy com Kyverno (admission controller)
# Kyverno pode verificar assinatura de imagem antes de permitir Pod creation
# Ver módulo 05 para configuração Kyverno verifyImages
```

### 4.2 Pipeline Completo: Build → Scan → Sign → Push → Verify

```yaml
# .github/workflows/container-security.yml
# Pipeline completo de segurança de container — Banco Meridian

name: Container Security Pipeline

on:
  push:
    branches: [ main ]
    paths: [ 'app/**', 'Dockerfile' ]

permissions:
  contents: read
  packages: write
  id-token: write     # Necessário para OIDC keyless signing com Cosign

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}/app

jobs:
  build-scan-sign:
    name: Build, Scan, Sign e Push
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Configurar Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login no GHCR
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # STEP 1: Build da imagem (sem push ainda)
      - name: Build da imagem
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          load: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      # STEP 2: Scan com Trivy — falha se CRITICAL CVE
      - name: Scan Trivy — vulnerabilidades
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-vuln.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'          # FALHA se encontrar CRITICAL/HIGH
          ignore-unfixed: true    # Ignora CVEs sem fix disponível

      - name: Scan Trivy — secrets na imagem
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          scanners: 'secret'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'

      # STEP 3: Gerar SBOM com Syft
      - name: Gerar SBOM com Syft
        uses: anchore/syft-action@v0.16.0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      # Upload SBOM como artefato (evidência para auditoria)
      - name: Upload SBOM como artefato
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom.cyclonedx.json
          retention-days: 365   # 1 ano de retenção para auditoria BACEN

      # STEP 4: Push da imagem (apenas se scan passou)
      - name: Push da imagem para GHCR
        uses: docker/build-push-action@v5
        id: push
        with:
          context: .
          push: true
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          labels: |
            org.opencontainers.image.revision=${{ github.sha }}
            security.scan.status=passed
            security.scan.date=${{ github.run_started_at }}

      # STEP 5: Instalar Cosign
      - name: Instalar Cosign
        uses: sigstore/cosign-installer@v3

      # STEP 6: Assinar imagem com Cosign (keyless via OIDC do GitHub Actions)
      - name: Assinar imagem com Cosign (keyless)
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}
          echo "Imagem assinada: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}"

      # STEP 7: Anexar SBOM como attestation assinada
      - name: Assinar e anexar SBOM como attestation
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign attest --yes \
            --type cyclonedx \
            --predicate sbom.cyclonedx.json \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}

      # STEP 8: Verificar assinatura (prove que funciona)
      - name: Verificar assinatura Cosign
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}.*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${DIGEST}

      # Upload SARIF para GitHub Security (Code Scanning)
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-vuln.sarif
          category: trivy-container

  deploy-verify:
    name: Deploy com Verificação de Assinatura
    runs-on: ubuntu-latest
    needs: build-scan-sign
    environment: production   # Aprovação manual para produção
    if: github.ref == 'refs/heads/main'

    steps:
      - name: Instalar Cosign
        uses: sigstore/cosign-installer@v3

      # STEP 9: Verificar assinatura ANTES de fazer deploy
      - name: Verificar assinatura antes do deploy
        run: |
          cosign verify \
            --certificate-identity-regexp="https://github.com/${{ github.repository }}.*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          echo "Assinatura verificada — imagem autorizada para deploy em produção"

      - name: Deploy para Kubernetes
        run: |
          # Atualiza a imagem no deployment K8s
          kubectl set image deployment/app \
            app=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
            --record
```

---

## 5. Runtime Protection com Falco

### 5.1 Arquitetura do Falco

Falco é a ferramenta open-source de runtime security para containers mais usada no mundo, mantida pela CNCF. Usa eBPF (ou kernel module) para interceptar syscalls do kernel e detectar comportamentos anômalos.

```
ARQUITETURA FALCO
──────────────────────────────────────────────────────────────────────────────
KERNEL SPACE
  Sistema de Arquivos │ Network │ Processos │ Capabilities
        │
  eBPF probe / kernel module (lê syscalls em tempo real)
        │
──────────────────────────────────────────────────────────────────────────────
USER SPACE
  ┌─────────────────────────────────────────────────┐
  │                FALCO ENGINE                      │
  │                                                  │
  │  ┌─────────────────────────────────────────┐    │
  │  │         Rules Engine                     │    │
  │  │  - Carrega rules YAML                    │    │
  │  │  - Compila para filtros de evento        │    │
  │  │  - Avalia cada syscall contra as rules   │    │
  │  └─────────────────────────────────────────┘    │
  │                                                  │
  │  ┌─────────────────────────────────────────┐    │
  │  │         Output Manager                   │    │
  │  │  - stdout / syslog                       │    │
  │  │  - JSON webhook                          │    │
  │  │  - gRPC (Falcosidekick)                  │    │
  │  └─────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────┘
        │                            │
   SIEM (Splunk,               Falcosidekick
   Microsoft Sentinel)         → Slack/PagerDuty
                                → S3/SIEM/webhook
──────────────────────────────────────────────────────────────────────────────
```

**Instalação no Kubernetes com Helm:**
```bash
# Adicionar repositório Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Instalar Falco com eBPF driver
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/..." \
  --set falcosidekick.config.slack.minimumpriority="warning" \
  --set tty=true

# Verificar instalação
kubectl get pods -n falco-system

# Verificar logs do Falco
kubectl logs -n falco-system -l app.kubernetes.io/name=falco

# Verificar regras carregadas
kubectl exec -n falco-system deploy/falco -- falco --list
```

### 5.2 Linguagem de Regras Falco

```yaml
# Estrutura básica de uma regra Falco

# MACRO: reutilizável em múltiplas regras
- macro: container
  condition: container.id != host

- macro: interactive
  condition: proc.aname[2] = "sshd" or proc.aname[3] = "sshd" or proc.aname[4] = "sshd"

# LIST: lista de valores reutilizável
- list: shell_binaries
  items: [bash, zsh, sh, ksh, fish, tcsh]

# RULE: detecta um comportamento específico
- rule: Terminal shell in container
  desc: Um processo de shell interativo foi iniciado dentro de um container
  condition: >
    container and                          # Dentro de um container
    proc.name in (shell_binaries) and      # É um processo de shell
    terminal.isatty and                    # Tem terminal (interativo)
    not proc.pname in (shell_binaries)    # O pai não é outro shell
  output: >
    Shell iniciado em container
    (user=%user.name user_loginuid=%user.loginuid container_id=%container.id
    container_name=%container.name image=%container.image.repository:%container.image.tag
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution, T1059]
```

**Campos mais usados nas regras:**

| Campo | Descrição | Exemplo |
|:------|:----------|:--------|
| `container.id` | ID do container | `abc123def456` |
| `container.name` | Nome do container | `nginx-prod-7f8d` |
| `container.image.repository` | Repositório da imagem | `nginx` |
| `proc.name` | Nome do processo | `bash` |
| `proc.pname` | Nome do processo pai | `kubelet` |
| `proc.cmdline` | Linha de comando completa | `curl -s http://169.254.169.254/...` |
| `fd.name` | Nome do file descriptor | `/etc/passwd` |
| `evt.type` | Tipo de evento de syscall | `open`, `execve`, `connect` |
| `user.name` | Usuário que executou | `root` |
| `k8s.ns.name` | Namespace Kubernetes | `production` |
| `k8s.pod.name` | Nome do Pod | `api-gateway-7d8f-xxx` |

### 5.3 Cinco Regras Falco Customizadas

**Regra 1: Detecção de Shell em Container (T1059)**
```yaml
# falco-rules-bancomeridian.yaml
# Regra 1: Shell interativo iniciado em container de produção
# Mapeamento MITRE: T1059 — Command and Scripting Interpreter
# Contexto: Operadores não devem precisar de shell em containers de produção.
# Se um shell é aberto, pode indicar: debugging não autorizado, comprometimento
# por um atacante que já tem RCE (Remote Code Execution) ou acesso indevido.

- rule: BancoMeridian - Shell em Container de Produção
  desc: >
    Detecta shell interativo iniciado em container de namespace production.
    Todos os containers do Banco Meridian são imutáveis — shells em produção
    indicam atividade suspeita.
  condition: >
    container and
    k8s.ns.name = "production" and
    proc.name in (shell_binaries) and
    terminal.isatty
  output: >
    ALERTA: Shell em container de produção detectado!
    ns=%k8s.ns.name pod=%k8s.pod.name container=%container.name
    user=%user.name shell=%proc.name cmd=%proc.cmdline
    image=%container.image.repository:%container.image.tag
  priority: CRITICAL
  tags: [container, shell, production, T1059, bancomeridian]
```

**Regra 2: Escrita em Diretório Sensível**
```yaml
# Regra 2: Escrita em /etc, /bin, /usr/bin, /sbin dentro de containers
# Mapeamento MITRE: T1565 — Data Manipulation / T1546 — Persistence
# Contexto: Containers são imutáveis — nenhum processo deveria modificar
# o sistema de arquivos do SO. Escrita em /etc pode indicar backdoor,
# /bin e /sbin podem indicar substituição de binário do sistema.

- list: sensitive_directories
  items:
    - /etc
    - /bin
    - /sbin
    - /usr/bin
    - /usr/sbin
    - /usr/local/bin
    - /lib
    - /lib64

- macro: write_to_sensitive_dir
  condition: >
    (evt.type = write or evt.type = openat) and
    fd.name pmatch (sensitive_directories)

- rule: BancoMeridian - Escrita em Diretório Sensível
  desc: >
    Detecta escrita em diretórios sensíveis do sistema dentro de um container.
    Containers imutáveis não devem modificar esses diretórios.
  condition: >
    container and
    write_to_sensitive_dir and
    not proc.name in (package_mgmt_binaries) and
    not container.image.repository in (bancomeridian/init-containers)
  output: >
    ALERTA: Escrita em diretório sensível no container!
    dir=%fd.name proc=%proc.name user=%user.name
    pod=%k8s.pod.name ns=%k8s.ns.name
    image=%container.image.repository:%container.image.tag
  priority: ERROR
  tags: [container, filesystem, persistence, T1565, bancomeridian]
```

**Regra 3: Processo Inesperado em Container de Banco de Dados**
```yaml
# Regra 3: Processo inesperado em containers de banco de dados
# Mapeamento MITRE: T1059 / T1036 — Masquerading
# Contexto: Containers de banco de dados do Banco Meridian devem executar
# APENAS o processo do banco (postgres, mysqld). Qualquer outro processo
# executável pode indicar comprometimento ou configuração incorreta.

- list: expected_db_processes
  items:
    - postgres
    - postmaster
    - pg_dump
    - pg_restore
    - mysqld
    - mysqld_safe
    - mongod
    - redis-server

- rule: BancoMeridian - Processo Inesperado em Container DB
  desc: >
    Detecta processo inesperado em container de banco de dados.
    Containers DB do Banco Meridian executam apenas o processo do banco.
  condition: >
    container and
    container.image.repository in (
      bancomeridian/postgres,
      bancomeridian/mysql,
      bancomeridian/mongodb
    ) and
    proc.name not in (expected_db_processes) and
    proc.name not in (ps, top, ls, cat)
  output: >
    ALERTA: Processo inesperado '%proc.name' em container de banco de dados!
    pod=%k8s.pod.name ns=%k8s.ns.name
    cmdline=%proc.cmdline user=%user.name
    image=%container.image.repository:%container.image.tag
  priority: WARNING
  tags: [container, database, anomaly, T1059, bancomeridian]
```

**Regra 4: Acesso à AWS Metadata API (T1552.005)**
```yaml
# Regra 4: Tentativa de acesso à API de metadados da AWS (IMDS)
# Mapeamento MITRE: T1552.005 — Cloud Instance Metadata API
# Contexto: A API de metadados EC2 (169.254.169.254) pode retornar credenciais
# temporárias da role IAM da instância. Se um container faz chamadas para esse
# endpoint, pode indicar tentativa de roubo de credenciais IAM.
# Nota: containers legítimos que precisam de credenciais AWS devem usar
# IRSA (IAM Roles for Service Accounts) em vez de IMDS direto.

- rule: BancoMeridian - Acesso à AWS Metadata API
  desc: >
    Detecta conexão de rede para o endpoint de metadados da AWS (169.254.169.254).
    Pode indicar tentativa de exfiltração de credenciais IAM temporárias.
    Use IRSA (IAM Roles for Service Accounts) ao invés de IMDS.
  condition: >
    container and
    evt.type in (connect, sendmsg) and
    fd.type = ipv4 and
    fd.sip = "169.254.169.254" and
    not container.image.repository in (bancomeridian/aws-sdk-init)
  output: >
    ALERTA CRÍTICO: Container tentando acessar AWS Instance Metadata Service!
    Possível tentativa de roubo de credenciais IAM.
    container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name
    proc=%proc.name cmdline=%proc.cmdline
    dest_ip=%fd.sip image=%container.image.repository:%container.image.tag
  priority: CRITICAL
  tags: [container, aws, imds, credential-theft, T1552.005, bancomeridian]
```

**Regra 5: Container Privilegiado Iniciado**
```yaml
# Regra 5: Container iniciado com --privileged ou capabilities perigosas
# Mapeamento MITRE: T1611 — Escape to Host
# Contexto: Containers privilegiados têm acesso quase total ao kernel do host.
# Se um container privilegiado é iniciado em produção, pode permitir
# container escape e comprometimento do nó Kubernetes inteiro.

- rule: BancoMeridian - Container Privilegiado Iniciado
  desc: >
    Detecta criação de container com flag --privileged ou capabilities perigosas.
    Containers privilegiados podem realizar container escape e comprometer o host.
    Política do Banco Meridian proíbe containers privilegiados em produção.
  condition: >
    container.privileged = true and
    k8s.ns.name != "kube-system" and
    k8s.ns.name != "falco-system"
  output: >
    ALERTA CRÍTICO: Container privilegiado iniciado!
    Risco de container escape e comprometimento do nó.
    container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name
    image=%container.image.repository:%container.image.tag
    user=%user.name
  priority: CRITICAL
  tags: [container, privilege-escalation, container-escape, T1611, bancomeridian]
```

**Instalar regras customizadas no Falco:**
```bash
# Método 1: ConfigMap no Kubernetes
kubectl create configmap falco-custom-rules \
  --from-file=falco-rules-bancomeridian.yaml \
  -n falco-system

# Adicionar ao values.yaml do Helm
# customRules:
#   falco-rules-bancomeridian.yaml: |
#     <conteúdo das regras>

# Método 2: Atualizar Helm com as regras
helm upgrade falco falcosecurity/falco \
  -n falco-system \
  --set-file customRules.falco-rules-bancomeridian\\.yaml=./falco-rules-bancomeridian.yaml

# Método 3: ConfigMap com volume mount (mais flexível)
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco-system
data:
  bancomeridian_rules.yaml: |
    $(cat falco-rules-bancomeridian.yaml)
EOF
```

**Configurar outputs do Falco:**
```yaml
# /etc/falco/falco.yaml
# Configuração de outputs do Falco

# Stdout (para kubectl logs)
stdout_output:
  enabled: true

# Arquivo de log
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/falco-events.json

# Syslog (para SIEM que coleta via syslog)
syslog_output:
  enabled: true

# HTTP webhook (para Falcosidekick)
http_output:
  enabled: true
  url: http://falcosidekick:2801/
  user_agent: falcosecurity/falco

# Configuração de JSON output
json_output: true
json_include_output_property: true
json_include_tags_property: true

# Grpc output (para integrações avançadas)
grpc:
  enabled: false

# Prioridade mínima para output
priority: debug
```

---

## 6. Diagrama ASCII — Pipeline Seguro de Container

```
PIPELINE SEGURO DE CONTAINER — BANCO MERIDIAN
══════════════════════════════════════════════════════════════════════════════

 DEVELOPER                  CI/CD PIPELINE                    PRODUÇÃO
 ──────────                 ──────────────                    ────────
 ┌──────────┐               ┌────────────────────────────────────────┐
 │  Código  │  ──git push──▶│                                        │
 │   app/   │               │  1. Checkov — IaC scan                 │
 │Dockerfile│               │     ✓ Dockerfile sem root              │
 └──────────┘               │     ✓ K8s sem privileged               │
                            │     ✗ FAIL → bloqueia pipeline         │
                            │                                        │
                            │  2. Build — docker buildx              │
                            │     (imagem não publicada ainda)        │
                            │                                        │
                            │  3. Trivy scan                         │
                            │     ✓ CVEs: 0 CRITICAL                 │
                            │     ✗ CRITICAL → FAIL                  │
                            │                                        │
                            │  4. Trivy secrets scan                 │
                            │     ✗ Secret encontrado → FAIL         │
                            │                                        │
                            │  5. Syft — gerar SBOM                  │
                            │     sbom.cyclonedx.json                │
                            │     (armazenado 365 dias)              │
                            │                                        │
                            │  6. docker push → Registry (ECR/GHCR) │
                            │     APENAS SE todos os scans passaram  │
                            │                                        │
                            │  7. Cosign sign (keyless OIDC)         │
                            │     + attest SBOM                      │
                            │     Registrado no Rekor (imutável)     │
                            │                                        │
                            │  8. Cosign verify (prova que funciona) │
                            └────────────────────────────────────────┘
                                          │
                                    APROVAÇÃO
                                    MANUAL (prod)
                                          │
                            ┌─────────────▼──────────────────────────┐
                            │  9. cosign verify (antes do deploy)     │
                            │     Verifica assinatura + certificado   │
                            │     ✗ Sem assinatura → Deploy NEGADO    │
                            └─────────────┬──────────────────────────┘
                                          │
                            ┌─────────────▼──────────────────────────┐
                            │ 10. kubectl apply / helm upgrade        │
                            │     Kyverno verifyImages policy         │
                            │     (segundo nível de verificação)      │
                            └─────────────┬──────────────────────────┘
                                          │
                            ┌─────────────▼──────────────────────────┐
 ALERTAS ◀───── Falco ──────│ 11. Falco runtime protection           │
 (Slack/SIEM)               │     - eBPF monitora syscalls           │
                            │     - Regras customizadas BM            │
                            │     - Alerts para SIEM                  │
                            └────────────────────────────────────────┘

══════════════════════════════════════════════════════════════════════════════
LEGENDA:
  ✓ = verificação que o artefato deve passar
  ✗ = condição de falha que bloqueia o pipeline
  SBOM = armazenado por 365 dias para auditoria BACEN
  Rekor = log de transparência imutável (prova de quando foi assinado)
══════════════════════════════════════════════════════════════════════════════
```

---

## 7. Atividades de Fixação

### Questão 1
O que diferencia o SBOM (Software Bill of Materials) de um simples relatório de vulnerabilidades como o output do Trivy?

**a)** SBOM lista apenas as CVEs encontradas; relatório de vulnerabilidades lista as dependências  
**b)** SBOM é um inventário de todos os componentes de software (pacotes, versões, licenças) independente de vulnerabilidades; relatório de vulnerabilidades é o resultado de aplicar um banco CVE contra esse inventário  
**c)** SBOM é apenas para containers; relatório de vulnerabilidades é para qualquer tipo de software  
**d)** SBOM e relatório de vulnerabilidades são sinônimos com formatos diferentes  

**Gabarito: b)**  
Justificativa: SBOM é o inventário — "quais componentes existem neste software, em quais versões, com quais licenças". É estático e não depende de banco CVE. O relatório de vulnerabilidades (Trivy, Grype) usa o SBOM e aplica um banco CVE para encontrar quais componentes têm vulnerabilidades conhecidas. Com Log4Shell, ter o SBOM permitia responder "quais imagens usam Log4j?" instantaneamente.

---

### Questão 2
O que o modo keyless do Cosign (Sigstore) usa como raiz de confiança ao invés de uma chave privada gerenciada?

**a)** Um certificado X.509 auto-assinado gerado localmente  
**b)** Uma identidade OIDC (como a identidade do GitHub Actions) emitida por Fulcio (CA do Sigstore) que é registrada no Rekor (log de transparência imutável)  
**c)** A chave privada da conta AWS IAM  
**d)** Um HSM (Hardware Security Module) gerenciado pelo usuário  

**Gabarito: b)**  
Justificativa: O Cosign keyless usa uma identidade OIDC efêmera (do GitHub Actions, Google, etc.) para obter um certificado de curta duração da Fulcio (CA do Sigstore). A assinatura é registrada no Rekor, um log de transparência imutável e verificável. Isso elimina a necessidade de gerenciar chaves privadas, que são o ponto mais comum de falha em sistemas de assinatura de código.

---

### Questão 3
Um container de API de pagamentos do Banco Meridian está executando e o Falco emitiu o alerta: "Shell em container de produção detectado — proc=bash pod=api-pagamentos-7d8f ns=production". Qual é a resposta imediata mais adequada?

**a)** Ignorar o alerta — é normal ter shells em containers  
**b)** Fazer ssh no container para verificar o que está acontecendo  
**c)** Isolar o pod imediatamente via NetworkPolicy, coletar logs e memória do container (forensics), remover o pod e iniciar investigação de incidente  
**d)** Atualizar a imagem do container para uma versão mais nova  

**Gabarito: c)**  
Justificativa: Um shell interativo em um container de produção de pagamentos é um evento de alta criticidade — pode indicar comprometimento via RCE, insider threat ou debugging não autorizado. A resposta deve ser: isolar o pod via NetworkPolicy (impede exfiltração de dados), coletar evidências forenses (logs, memória, processos), remover o pod (interrompe o acesso do atacante) e iniciar investigação de incidente. Fazer ssh "para verificar" pode destruir evidências forenses.

---

### Questão 4
No pipeline seguro de container, em qual ordem devem ocorrer as seguintes etapas?

1. cosign sign (assinar a imagem)
2. docker push (publicar no registry)
3. trivy image scan (verificar CVEs)
4. syft (gerar SBOM)
5. cosign verify (verificar assinatura antes do deploy)

**a)** 3 → 4 → 2 → 1 → 5  
**b)** 2 → 3 → 4 → 1 → 5  
**c)** 1 → 2 → 3 → 4 → 5  
**d)** 3 → 2 → 1 → 4 → 5  

**Gabarito: a)**  
Justificativa: A ordem correta é: (3) scan antes do push — não queremos publicar imagens vulneráveis; (4) gerar SBOM antes do push — o SBOM documenta o que está sendo publicado; (2) push para o registry somente após o scan passar; (1) assinar a imagem após o push (assinamos o digest que só existe após o push); (5) verificar a assinatura antes do deploy — garante que o que vai para produção é exatamente o que foi buildado e aprovado pelo pipeline.

---

### Questão 5
Qual é a principal diferença entre detectar comportamentos maliciosos com Falco em runtime vs. com Trivy em image scanning?

**a)** Trivy é mais preciso que Falco para detecção de ataques  
**b)** Falco detecta comportamentos maliciosos ENQUANTO acontecem (runtime); Trivy detecta vulnerabilidades ANTES do deploy (static analysis) — são complementares, não substitutos  
**c)** Falco é open-source; Trivy é apenas comercial  
**d)** Trivy detecta mais ameaças que Falco porque analisa mais tipos de arquivo  

**Gabarito: b)**  
Justificativa: Trivy (static) e Falco (runtime) são camadas complementares de defesa. Trivy encontra CVEs conhecidas antes do deploy — prevenção. Falco detecta comportamentos anômalos enquanto o container está rodando — detecção. Uma imagem pode passar no Trivy (sem CVEs conhecidas) mas ainda ser comprometida por um zero-day ou por um atacante que tem credenciais legítimas. Falco capturaria o comportamento suspeito mesmo sem CVE conhecida.

---

## 8. Roteiros de Gravação

### Aula 4.1: Image Scanning + SBOM + Cosign (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Container Security: Image Scanning, SBOM e Assinatura com Cosign |
| **Duração** | 50 minutos |
| **Formato** | Talking head + terminal + slides |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Bem-vindo ao Módulo 4. Neste módulo vamos focar em CWPP — Cloud Workload Protection Platform — com foco específico em containers. Containers são hoje o principal veículo de entrega de aplicações em cloud, e também uma das principais superfícies de ataque.

Vamos ver: como escanear imagens de container para CVEs com Trivy, como gerar SBOMs para saber exatamente o que está em cada imagem, e como assinar imagens com Cosign para garantir que só imagens aprovadas pelo nosso pipeline de segurança chegam à produção.

---

**[05:00 – 15:00 | CICLO DE VIDA DO CONTAINER | Slides]**

*[Dica de edição: animação do pipeline de container, passo a passo]*

Antes de entrar nas ferramentas, vamos entender o ciclo de vida seguro de um container. Há 5 fases: Build, Scan, Sign, Push e Runtime.

*[Explica cada fase com o diagrama ASCII]*

O ponto crítico que a maioria dos times ignora: a fase de scan precisa acontecer ANTES do push para o registry. Você não quer descobrir que a imagem de produção tem Log4Shell depois de estar rodando com tráfego real de clientes.

---

**[15:00 – 35:00 | TRIVY E SYFT NA PRÁTICA | Terminal]**

*[Dica de edição: tela cheia no terminal]*

Vamos para o terminal. Vou escanear uma imagem real.

```bash
trivy image nginx:1.25
```

*[Mostra e explica o output]*

*[Gera SBOM com Syft]*

```bash
syft nginx:1.25 -o cyclonedx-json=sbom.json
cat sbom.json | jq '.components | length'
```

*[Mostra quantos componentes foram encontrados]*

*[Demonstra usar o SBOM para busca de Log4j]*

```bash
cat sbom.json | jq '.components[] | select(.name | contains("log4j"))'
```

*[Mostra que a busca não encontra nada — nginx não usa Log4j]*

*[Muda para imagem Java que usa Log4j]*

---

**[35:00 – 48:00 | COSIGN KEYLESS SIGNING | Terminal]*

*[Mostra o fluxo de assinatura keyless]*

*[Demonstra cosign sign no GitHub Actions (explica o fluxo OIDC)]*

*[Demonstra cosign verify]*

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

Na próxima aula veremos o Falco para runtime protection e vamos montar o pipeline completo. Nos vemos lá!

---

### Aula 4.2: Runtime com Falco + eBPF + Pipeline Completo (50 min)

#### Informações da Aula

| Campo | Valor |
|:------|:------|
| **Título** | Runtime Security com Falco e eBPF + Pipeline Completo de Container |
| **Duração** | 50 minutos |
| **Formato** | Terminal (cluster K8s) + slides + GitHub Actions |

---

**[00:00 – 05:00 | ABERTURA | Talking head]**

Na aula anterior protegemos o container antes de ir para produção — scan, SBOM, assinatura. Nesta aula protegemos o container ENQUANTO está em produção, com o Falco.

E ao final, montamos o pipeline completo de ponta a ponta — do código ao deploy — integrando tudo que vimos neste e nos módulos anteriores.

---

**[05:00 – 20:00 | FALCO — CONCEITO E ARQUITETURA | Slides]**

*[Explica arquitetura eBPF com o diagrama]*

O Falco usa eBPF — Extended Berkeley Packet Filter — para observar syscalls do kernel em tempo real, sem modificar o kernel. É como ter um detector de movimento no nível mais baixo do sistema operacional.

*[Mostra exemplo de regra Falco e explica cada campo]*

---

**[20:00 – 40:00 | FALCO NA PRÁTICA | Terminal — cluster kind]**

*[Verifica Falco rodando no cluster kind]*

```bash
kubectl get pods -n falco-system
kubectl logs -n falco-system -l app=falco --tail=20
```

*[Simula ataque: exec em container de produção]*

```bash
# Terminal 1: Monitorar logs do Falco
kubectl logs -n falco-system -l app=falco -f

# Terminal 2: Simular exec (como um atacante faria)
kubectl exec -it deploy/app-test -- /bin/bash
```

*[Mostra alerta gerado no Terminal 1]*

*[Demonstra regra customizada sendo carregada]*

*[Testa regra de acesso ao IMDS AWS]*

```bash
kubectl exec -it deploy/app-test -- curl http://169.254.169.254/latest/meta-data/
```

---

**[40:00 – 48:00 | PIPELINE COMPLETO | GitHub Actions]*

*[Abre o workflow container-security.yml e explica cada step]*

*[Mostra execução real no GitHub Actions]*

*[Mostra como um push com imagem vulnerável falha no step de Trivy scan]*

---

**[48:00 – 50:00 | ENCERRAMENTO | Talking head]**

Você agora tem o kit completo de CWPP: Trivy para scanning, Syft para SBOM, Cosign para assinatura, e Falco para runtime. No laboratório Lab-03, você vai simular ataques reais em um cluster kind e ver o Falco detectando em tempo real.

---

## 9. Avaliação do Módulo 04

### Parte A — Múltipla Escolha (60 pontos)

**Questão 1 (10 pts)**  
Qual comando Trivy escaneia uma imagem para vulnerabilidades E secrets, falhando o pipeline se encontrar qualquer finding CRITICAL?

**a)** `trivy image --severity CRITICAL --exit-code 1 nginx:latest`  
**b)** `trivy image --scanners vuln,secret --severity CRITICAL --exit-code 1 nginx:latest`  
**c)** `trivy scan --type container --severity CRITICAL --fail nginx:latest`  
**d)** `trivy image --check vuln secret --level CRITICAL nginx:latest`  

**Gabarito: b)** `--scanners vuln,secret` ativa os scanners de vulnerabilidades e secrets simultaneamente. `--severity CRITICAL` filtra apenas severidade crítica. `--exit-code 1` faz o processo retornar código de saída 1 (falha) ao encontrar findings — necessário para que o CI/CD interprete como falha.

---

**Questão 2 (10 pts)**  
Por que o formato CycloneDX é preferido para SBOMs em contextos de segurança (análise de vulnerabilidades)?

**a)** CycloneDX é mais legível para humanos que SPDX  
**b)** CycloneDX foi criado pela OWASP com foco específico em análise de segurança e vulnerabilidades, com campos nativos para CVEs e CVSS scores  
**c)** CycloneDX é suportado apenas pelo Trivy  
**d)** CycloneDX é o único formato aceito pelo BACEN 4.893  

**Gabarito: b)** CycloneDX foi desenvolvido pela OWASP com casos de uso de segurança em mente, incluindo campos específicos para vulnerabilidades. SPDX foi desenvolvido pela Linux Foundation com foco em compliance de licença. Para análise de vulnerabilidades (como integração com Grype ou Dependency-Track), CycloneDX é mais adequado.

---

**Questão 3 (10 pts)**  
O que o campo `priority: CRITICAL` em uma regra Falco determina?

**a)** O recurso computacional que o Falco dedicará à avaliação dessa regra  
**b)** A severidade do alerta gerado quando a condição da regra é satisfeita — usado para filtrar quais alertas são enviados para SIEM ou paginam o time de segurança  
**c)** A ordem de avaliação das regras (regras CRITICAL são avaliadas primeiro)  
**d)** O impacto no desempenho do sistema quando a regra dispara  

**Gabarito: b)** `priority` em regras Falco define a severidade do evento gerado. Isso é usado para filtrar outputs: por exemplo, `minimum-priority: warning` no falcosidekick envia para Slack apenas WARNING e acima. Um alerta CRITICAL normalmente aciona pager (PagerDuty) enquanto INFO apenas loga.

---

**Questão 4 (10 pts)**  
No pipeline seguro de container, em que momento o `cosign sign` deve ser executado?

**a)** Antes do build, para garantir que o código fonte está seguro  
**b)** Após o scan e antes do push, para assinar a imagem local  
**c)** Após o push, pois a assinatura referencia o digest SHA256 que só existe no registry após o push  
**d)** No momento do deploy, para assinar a imagem no cluster Kubernetes  

**Gabarito: c)** O `cosign sign` referencia o digest SHA256 da imagem no registry (ex: `ghcr.io/app@sha256:abc123...`). Esse digest só existe após o push. Assinar antes do push é tecnicamente impossível com o fluxo padrão Cosign. O fluxo correto é: build → scan → push → sign (usando o digest retornado pelo push).

---

**Questão 5 (10 pts)**  
A regra Falco "BancoMeridian - Acesso à AWS Metadata API" detecta qual técnica MITRE ATT&CK?

**a)** T1059 — Command and Scripting Interpreter  
**b)** T1611 — Escape to Host  
**c)** T1552.005 — Cloud Instance Metadata API (Unsecured Credentials)  
**d)** T1565 — Data Manipulation  

**Gabarito: c)** T1552.005 é a técnica MITRE ATT&CK que descreve o uso da API de metadados de instâncias cloud (169.254.169.254 na AWS) para obter credenciais IAM temporárias. A regra Falco detecta conexões TCP para esse endereço, que é o indicador técnico dessa técnica.

---

**Questão 6 (10 pts)**  
Qual é o benefício do SLSA Level 2 em relação ao SLSA Level 1?

**a)** SLSA 2 exige revisão de 2 pessoas antes do build  
**b)** SLSA 2 exige que o build seja executado por um serviço de CI (não por humano) com provenance assinado e verificável, garantindo que o artefato é rastreável ao commit específico  
**c)** SLSA 2 exige criptografia de todos os artefatos de build  
**d)** SLSA 2 exige testes de penetração antes do release  

**Gabarito: b)** SLSA 2 adiciona ao SLSA 1: build deve ser executado por serviço de CI (não pode ser um humano rodando manualmente), com geração de provenance assinado (que pode ser verificado por qualquer um com a chave pública). Isso garante que o artefato veio exatamente de um determinado commit, por um determinado pipeline, em um determinado momento.

---

### Parte B — Análise de Cenário (40 pontos)

**Cenário:** O SOC do Banco Meridian recebeu um alerta do Falco às 3h da manhã: "BancoMeridian - Acesso à AWS Metadata API: container=api-transferencias pod=api-transferencias-7d8f-xxxx ns=production proc=curl cmdline=curl http://169.254.169.254/latest/meta-data/iam/security-credentials/api-role"

**Tarefas (4 perguntas, 10 pts cada):**

1. Explique o que esse alerta significa do ponto de vista técnico e qual é o risco de negócio específico para o Banco Meridian
2. Descreva a resposta imediata a esse incidente (primeiros 30 minutos)
3. Escreva uma regra Falco adicional que detectaria a exfiltração dos dados das credenciais IAM via rede para um servidor externo
4. Proponha controles preventivos para eliminar essa ameaça permanentemente

**Gabarito:**

1. **O que o alerta significa:** Um processo `curl` dentro do container `api-transferencias` está fazendo uma requisição HTTP para `169.254.169.254/latest/meta-data/iam/security-credentials/api-role` — o endpoint IMDS da AWS que retorna as credenciais IAM temporárias (AccessKeyId, SecretAccessKey, SessionToken) associadas à role `api-role` da instância EC2. Se essa requisição foi bem-sucedida, o atacante ou processo malicioso obteve credenciais AWS temporárias da role de produção do serviço de transferências, podendo usá-las para acessar serviços AWS (S3, DynamoDB, etc.) de qualquer lugar na internet até o TTL expirar.

2. **Resposta imediata (30 min):**
   - Minuto 0–5: Isolar o pod via NetworkPolicy (`deny-all-egress` para o pod específico)
   - Minuto 5–10: Coletar evidências — `kubectl logs`, `kubectl exec` para snapshot de processos e arquivos (antes de matar)
   - Minuto 10–15: Revogar as credenciais IAM temporárias via `aws iam revoke-temporary-security-credentials` ou revogar a role inteira
   - Minuto 15–20: Verificar CloudTrail para uso das credenciais comprometidas nos últimos 30 minutos
   - Minuto 20–30: Matar o pod comprometido, notificar equipe de segurança e iniciar investigação de causa raiz

3. **Regra Falco para exfiltração:**
```yaml
- rule: BancoMeridian - Exfiltração de Credenciais IMDS
  desc: Detecta envio de dados do IMDS para servidor externo
  condition: >
    container and
    evt.type in (connect, sendmsg) and
    fd.type = ipv4 and
    not fd.sip in (bancomeridian_internal_cidrs) and
    proc.name in (curl, wget, python, python3) and
    proc.cmdline contains "169.254.169.254"
  output: >
    CRÍTICO: Possível exfiltração de credenciais IMDS!
    container=%container.name pod=%k8s.pod.name
    dest=%fd.sip cmd=%proc.cmdline
  priority: CRITICAL
  tags: [exfiltration, imds, T1552.005, T1041]
```

4. **Controles preventivos:**
   - IMDSv2 obrigatório (hop limit = 1 bloqueia acesso de containers)
   - IRSA (IAM Roles for Service Accounts) em vez de instance profile
   - NetworkPolicy bloqueando saída para 169.254.169.254 de todos os pods
   - Kyverno policy bloqueando containers que não usam serviceAccount específico
   - Remover acesso de API keys hardcoded nos containers — usar AWS Secrets Manager + External Secrets Operator (módulo 7)

---

*Módulo 04 — CWPP e Container Security*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
