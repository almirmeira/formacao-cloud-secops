# Lab Capstone — Avaliação de Postura Multi-Cloud do Banco Meridian
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 3–4 horas (integra todos os laboratórios anteriores)  
> **Dificuldade:** Avançado  
> **Módulo Relacionado:** Módulo 09 — Capstone  

---

## 1. Contexto Situacional

O Banco Meridian passa por uma auditoria externa de segurança conduzida pelo BACEN. O Compliance Officer identificou que a instituição não possui evidências formais de controles de segurança em nuvem — não há relatórios de postura CSPM, não há histórico de pipelines DevSecOps, não há evidência de proteção de runtime em containers, e os segredos de aplicação são gerenciados de forma ad hoc via variáveis de ambiente. A auditoria determinará se o banco está em conformidade com a Resolução BACEN 4.893 e a LGPD.

Você foi designado como Cloud Security Engineer responsável por produzir todas as evidências de controle exigidas pela auditoria, consolidadas em um relatório executivo que será entregue ao CISO e ao auditor externo.

---

## 2. Situação Inicial

Ao iniciar este laboratório, você já concluiu os labs 01 a 06 do Curso 4 e possui:
- Ambiente AWS sandbox configurado (Lab 01)
- Repositório GitHub com pipeline DevSecOps parcial (Lab 02)
- Cluster Kubernetes com Falco instalado (Lab 03)
- HashiCorp Vault com secrets básicos configurados (Lab 05)
- Análise CIEM realizada (Lab 06)

Agora você deve integrar todos esses controles, gerar evidências formais de cada um, e consolidá-las em um relatório executivo que demonstre conformidade.

---

## 3. Objetivo do Capstone

Produzir cinco entregáveis que, juntos, compõem a evidência formal de um programa de Cloud Security maduro para o Banco Meridian:

1. **Relatório CSPM com mapeamento regulatório** — evidência de postura de segurança na nuvem
2. **Pipeline DevSecOps operacional** — evidência de controles preventivos no ciclo de desenvolvimento
3. **Regras Falco ativas em runtime** — evidência de detecção de ameaças em tempo real
4. **Vault com secrets gerenciados centralmente** — evidência de gestão segura de credenciais
5. **Relatório executivo consolidado** — síntese para o CISO e auditor externo

---

## 4. Referência ao Módulo 09

Este laboratório capstone é a implementação prática do **Módulo 09**. Consulte `/modulos/modulo-09-capstone/README.md` para:
- Contexto completo do cenário
- Os 5 entregáveis detalhados (Prowler, Pipeline, Falco, Vault, Relatório Executivo)
- Gabarito completo do instrutor com outputs esperados
- Critérios de avaliação por entregável

---

## 5. Instruções de Execução — Entregáveis

### Entregável 1: Relatório CSPM com Prowler

**O que este entregável demonstra:** Executa o Prowler em modo de auditoria completa na conta AWS sandbox, gerando um relatório HTML com todos os findings de postura de segurança mapeados aos controles regulatórios do BACEN 4.893. O Prowler é a ferramenta CSPM open-source mais utilizada para auditorias AWS, com mais de 500 checks específicos para serviços como IAM, S3, RDS, EC2, CloudTrail e GuardDuty. O mapeamento para BACEN é essencial para o contexto de um banco regulado: não basta encontrar problemas técnicos, é necessário demonstrar ao regulador quais artigos da resolução estão em conformidade e quais precisam de remediação.

**Por que começa por aqui:** O CSPM é a visão mais ampla de postura de segurança — mostra o estado de toda a conta AWS em uma única execução. Começar pelo Prowler permite identificar rapidamente os controles mais críticos que precisam ser demonstrados nos entregáveis seguintes. Os findings do Prowler também alimentam o relatório executivo (Entregável 5) com dados objetivos.

**Estimativa:** 40 minutos

```bash
# Referência: Lab 01 completo + mapeamento BACEN do Módulo 09

# Instalar Prowler (se não instalado)
pip install prowler

# Executar auditoria completa em HTML com mapeamento de compliance
prowler aws \
  --output-formats html,json \
  --output-directory ./capstone-evidencias/cspm/ \
  --compliance bacen_brazil

# Aguardar conclusão (pode levar 15-30 minutos dependendo da conta)
echo "Prowler concluído. Relatório em: ./capstone-evidencias/cspm/"

# Verificar findings críticos para o relatório executivo
prowler aws \
  --severity critical,high \
  --output-formats json \
  --output-directory ./capstone-evidencias/cspm/critical/ | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
total = len(data)
failed = sum(1 for f in data if f.get('status') == 'FAIL')
print(f'Total checks: {total}')
print(f'Falhos: {failed}')
print(f'Percentual de conformidade: {((total-failed)/total*100):.1f}%')
"
```

**Evidência esperada:** Arquivo `./capstone-evidencias/cspm/prowler-output-YYYY-MM-DD-HH-MM-SS.html` com relatório completo de postura de segurança.

---

### Entregável 2: Pipeline DevSecOps Operacional

**O que este entregável demonstra:** Prova que o pipeline de CI/CD do Banco Meridian está ativo, funcional e com todos os controles de segurança operando — Checkov escaneia IaC, Trivy escaneia containers, Cosign assina imagens aprovadas, e o Security Gate bloqueia merges que não passam nos controles. A URL do repositório GitHub com histórico de execuções do pipeline é a evidência formal de que o controle existe e funciona continuamente.

**Por que é o segundo entregável:** O pipeline é o controle preventivo mais importante — ele impede que vulnerabilidades cheguem à produção. Demonstrar que está operacional antes de mostrar o runtime security (Entregável 3) reforça a estratégia de "defense in depth": primeiro prevenir (pipeline), depois detectar (Falco).

**Estimativa:** 60 minutos

```bash
# Referência: Lab 02 completo
# O repositório já deve existir do Lab 02

# Criar commit de evidência (aciona o pipeline)
cd ~/bancomeridian-api-lab02

# Adicionar arquivo de evidência de capstone
cat > CAPSTONE-EVIDENCE.md << 'DOC'
# Capstone Evidence — Banco Meridian Pipeline DevSecOps

Data de execução do capstone: $(date +%Y-%m-%d)
Pipeline ID: $GITHUB_RUN_ID

## Controles Ativos

| Controle | Ferramenta | Status |
|:---------|:-----------|:------:|
| IaC Security Scan | Checkov (CRITICAL/HIGH bloqueante) | ATIVO |
| IaC Security Scan | tfsec (complementar, warn) | ATIVO |
| Container Vulnerability Scan | Trivy (CRITICAL bloqueante) | ATIVO |
| Container Secrets Scan | Trivy (HIGH bloqueante) | ATIVO |
| Image Signing | Cosign keyless (OIDC) | ATIVO |
| Image Verification | Cosign verify (pré-deploy) | ATIVO |
| SBOM Generation | Syft (CycloneDX) | ATIVO |
| Security Gate | GitHub Required Status Check | ATIVO |
DOC

git add CAPSTONE-EVIDENCE.md
git commit -m "capstone: adicionar evidência de pipeline para auditoria BACEN"
git push origin main

echo "Pipeline acionado — verificar em: https://github.com/$(git config user.name)/bancomeridian-api-lab02/actions"
```

**Evidência esperada:** URL do repositório GitHub com histórico de runs do workflow `DevSecOps Security Pipeline`, mostrando execuções com status `Success` e os logs de cada job (Checkov, tfsec, container-security, security-gate).

---

### Entregável 3: Falco Runtime Security

**O que este entregável demonstra:** Prova que o cluster Kubernetes do Banco Meridian tem monitoramento de runtime ativo, capaz de detectar comportamentos maliciosos em containers em tempo real. O Falco monitora chamadas de sistema (syscalls) a nível de kernel via eBPF ou módulo do kernel, detectando padrões como: execução de shell em container, leitura de arquivos sensíveis (`/etc/shadow`, `/etc/passwd`), escalada de privilégios, abertura de conexões de rede suspeitas e modificação de binários do sistema. Cada evento Falco é um alerta que pode ser enviado ao SIEM para correlação.

**Por que é o terceiro entregável:** O Falco cobre a fase de runtime — o que acontece depois do deploy. Enquanto o pipeline (Entregável 2) previne vulnerabilidades antes do deploy, o Falco detecta comportamentos maliciosos durante a execução. Juntos, eles cobrem o ciclo completo: prevenção + detecção. Sem runtime security, um container com vulnerabilidade que passou pelo pipeline (ou foi deployado por bypass) pode ser explorado sem que ninguém perceba.

**Estimativa:** 30 minutos

```bash
# Referência: Lab 03 completo
# O Falco deve estar instalado do Lab 03

# Verificar que o Falco está rodando
kubectl get pods -n falco

# Gerar evento de teste (exec em container em produção — deve acionar alerta Falco)
kubectl run test-pod --image=alpine --restart=Never -- sleep 3600
sleep 5
kubectl exec test-pod -- sh -c "cat /etc/passwd"
# Este comando deve gerar o alerta:
# "Rule: Read sensitive file untrusted"

# Coletar os alertas gerados
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | \
  grep -E "(Warning|Error|Critical)" | \
  head -20

# Salvar evidência
kubectl logs -n falco -l app.kubernetes.io/name=falco > \
  ./capstone-evidencias/falco/falco-alerts-$(date +%Y%m%d).log

echo "Falco alerts salvos em: ./capstone-evidencias/falco/"

# Limpeza
kubectl delete pod test-pod
```

**Evidência esperada:** Arquivo de log `./capstone-evidencias/falco/falco-alerts-YYYYMMDD.log` com alertas reais gerados pelo Falco, incluindo pelo menos um alerta de `Read sensitive file untrusted` acionado pelo teste acima.

---

### Entregável 4: HashiCorp Vault — Secrets Gerenciados

**O que este entregável demonstra:** Prova que o Banco Meridian centraliza o gerenciamento de segredos (senhas de banco de dados, tokens de API, certificados) no HashiCorp Vault, eliminando o risco de segredos hardcoded em código, variáveis de ambiente ou arquivos de configuração. O Vault fornece: armazenamento seguro de segredos com criptografia em repouso, controle de acesso baseado em políticas (quem pode ler qual segredo), rotação automática de credenciais, e trilha de auditoria completa de cada acesso a segredo.

**Por que é o quarto entregável:** O gerenciamento de segredos é a base de confiança de qualquer controle de segurança. Sem segredos gerenciados centralmente, mesmo que o pipeline e o Falco estejam funcionando, as credenciais de acesso a bancos de dados e APIs podem estar expostas em variáveis de ambiente ou em repositórios de código. O Vault vem depois dos controles de detect/prevent porque é a camada de infraestrutura que sustenta todos os outros controles.

**Estimativa:** 45 minutos

```bash
# Referência: Lab 05 completo
# O Vault deve estar configurado do Lab 05

# Verificar que o Vault está operacional
export VAULT_ADDR='http://127.0.0.1:8200'
vault status

# Listar os segredos configurados (evidência de gerenciamento centralizado)
vault kv list bancomeridian/

# Testar acesso com política de menor privilégio
# (autenticar como app-pagamentos e verificar o que pode acessar)
vault login -method=approle \
  role_id=$(vault read -field=role_id auth/approle/role/api-pagamentos/role-id) \
  secret_id=$(vault write -f -field=secret_id auth/approle/role/api-pagamentos/secret-id)

vault kv get bancomeridian/api-pagamentos/database

# Gerar relatório de segredos gerenciados (sem expor os valores)
echo "=== INVENTÁRIO DE SEGREDOS GERENCIADOS — BANCO MERIDIAN ===" > \
  ./capstone-evidencias/vault/vault-inventory-$(date +%Y%m%d).txt
vault kv list -format=json bancomeridian/ | \
  python3 -c "
import json, sys
secrets = json.load(sys.stdin)
print(f'Total de segredos gerenciados: {len(secrets)}')
for s in secrets:
    print(f'  - bancomeridian/{s}')
" >> ./capstone-evidencias/vault/vault-inventory-$(date +%Y%m%d).txt

echo "Inventário de segredos salvo em: ./capstone-evidencias/vault/"
```

**Evidência esperada:** Arquivo `./capstone-evidencias/vault/vault-inventory-YYYYMMDD.txt` com lista de segredos gerenciados centralmente e confirmação de acesso controlado por políticas.

---

### Entregável 5: Relatório Executivo Consolidado

**O que este entregável demonstra:** Consolida todos os achados e evidências dos entregáveis anteriores em um documento executivo estruturado para o CISO e para o auditor externo do BACEN. O relatório deve responder quatro perguntas fundamentais da auditoria: (1) Qual é a postura atual de segurança na nuvem? (2) Quais controles preventivos estão em operação? (3) Como a organização detecta e responde a ameaças em runtime? (4) Como os segredos e acessos privilegiados são gerenciados? O relatório também mapeia cada controle implementado para os artigos específicos da Resolução BACEN 4.893.

**Por que é o último entregável:** O relatório executivo só pode ser produzido depois que todos os controles foram implementados e as evidências coletadas. Ele é a síntese — não pode ser criado antes das partes que o compõem. Em uma auditoria real, este relatório seria o documento entregue ao regulador, então a qualidade e completude de cada seção impacta diretamente o resultado da auditoria.

**Estimativa:** 45 minutos

```bash
# Template: Módulo 09, seção "Entregável 5"

mkdir -p ./capstone-evidencias/relatorio

python3 << 'PYEOF'
from datetime import datetime

relatorio = f"""
# RELATÓRIO EXECUTIVO DE SEGURANÇA EM NUVEM
## Banco Meridian — Avaliação de Postura CNAPP

**Data:** {datetime.now().strftime('%d de %B de %Y')}
**Classificação:** Confidencial
**Destinatários:** CISO, Compliance Officer, Auditor Externo BACEN

---

## 1. SUMÁRIO EXECUTIVO

O Banco Meridian implementou um programa de Cloud Security abrangente cobrindo os
domínios de CSPM (Cloud Security Posture Management), Pipeline DevSecOps, Runtime
Security e Gerenciamento de Segredos. Este relatório documenta os controles
implementados, as evidências coletadas e o mapeamento de conformidade com a
Resolução BACEN 4.893.

---

## 2. POSTURA DE SEGURANÇA (CSPM — Prowler)

Ferramenta: Prowler v3.x
Data da auditoria: {datetime.now().strftime('%Y-%m-%d')}
Conta AWS auditada: [verificar no relatório HTML do Prowler]

Principais achados:
  - Verificar no relatório HTML gerado pelo Prowler
  - Destacar os 5 findings mais críticos e o plano de remediação de cada um
  - Incluir percentual de conformidade por categoria (IAM, S3, Networking, Logging)

Mapeamento BACEN 4.893:
  - Art. 5 — Gestão de riscos: [score do Prowler em controles relacionados]
  - Art. 6 — Monitoramento: [CloudTrail habilitado? GuardDuty ativo?]
  - Art. 8 — Controle de acesso: [IAM findings do Prowler]

---

## 3. CONTROLES PREVENTIVOS (Pipeline DevSecOps)

Repositório GitHub: [URL do repositório bancomeridian-api-lab02]
Pipeline: DevSecOps Security Pipeline (GitHub Actions)

Controles ativos:
  ✓ IaC Scanning — Checkov: misconfigurations CRITICAL/HIGH bloqueiam merge
  ✓ IaC Scanning — tfsec: análise complementar de Terraform
  ✓ Container Vulnerability Scanning — Trivy: CVEs CRITICAL bloqueiam push
  ✓ Container Secrets Scanning — Trivy: secrets hardcoded bloqueiam push
  ✓ Software Bill of Materials — Syft: inventário de componentes (CycloneDX)
  ✓ Image Signing — Cosign keyless: assinatura criptográfica via OIDC
  ✓ Image Verification — Cosign verify: verificação pré-deploy
  ✓ Security Gate — Required Status Check: merge fisicamente bloqueado

Conformidade BACEN 4.893:
  Art. 5 — "Identificar e classificar os dados": SBOM gerado por build
  Art. 6 — "Monitorar": pipeline cria trilha de auditoria de cada versão
  Art. 8 — "Controlar acessos": Cosign garante proveniência das imagens

---

## 4. DETECÇÃO EM RUNTIME (Falco)

Ferramenta: Falco (CNCF)
Namespace monitorado: production
Método de instrumentação: eBPF (modo kernel)

Regras ativas:
  - Terminal shell em container (T1059 MITRE ATT&CK)
  - Leitura de arquivo sensível (/etc/shadow, /etc/passwd)
  - Escalada de privilégios detectada
  - Execução de processo não esperado em container

Evidência: arquivo falco-alerts-{datetime.now().strftime('%Y%m%d')}.log
Alertas gerados no teste: [verificar no arquivo de evidência]

Conformidade BACEN 4.893:
  Art. 6 — Monitoramento de incidentes em tempo real: IMPLEMENTADO

---

## 5. GERENCIAMENTO DE SEGREDOS (HashiCorp Vault)

Ferramenta: HashiCorp Vault (open-source)
Segredos gerenciados: [verificar inventário do Entregável 4]

Controles implementados:
  ✓ Criptografia em repouso: AES-256-GCM (Vault auto-unseal)
  ✓ Controle de acesso por política: AppRole por microserviço
  ✓ Princípio de menor privilégio: cada app lê apenas seus próprios segredos
  ✓ Trilha de auditoria: every secret access logged

Eliminação de risco:
  Antes: segredos em variáveis de ambiente e arquivos .env em repositório
  Depois: segredos centralizados no Vault, injetados em runtime via sidecar

Conformidade BACEN 4.893:
  Art. 8 — "Gerenciar privilégios de acesso": IMPLEMENTADO com TTL e renovação

---

## 6. ANÁLISE CIEM (IAM Access Analyzer)

Ferramenta: AWS IAM Access Analyzer
Escopo: Conta AWS sandbox

Achados e remediações:
  - [listar findings do passo 2 do Lab 06]
  - Role lab06-api-pagamentos-demo: reduzida de 80+ para 3 permissões (-96%)
  - Credenciais de ex-colaboradores: [listar do passo 8 do Lab 06]
  - Shadow admins detectados: [listar do passo 9 do Lab 06]

Conformidade BACEN 4.893:
  Art. 8 — "Gerenciar privilégios de acesso": IMPLEMENTADO com revisão trimestral

---

## 7. PRÓXIMAS RECOMENDAÇÕES (30 DIAS)

Prioridade 1 — CRÍTICA:
  [ ] Revogar credenciais de ex-colaboradores identificados no Lab 06
  [ ] Remediar os 3 findings CRITICAL identificados pelo Prowler

Prioridade 2 — ALTA:
  [ ] Implementar Falco alertas para SIEM (Microsoft Sentinel / Splunk)
  [ ] Configurar Vault em modo HA (Alta Disponibilidade) para produção
  [ ] Habilitar GuardDuty e AWS Security Hub na conta de produção

Prioridade 3 — MÉDIA:
  [ ] Expandir pipeline DevSecOps para todos os repositórios do banco
  [ ] Implementar OPA Gatekeeper no cluster de produção (Lab 04)
  [ ] Configurar SBOM store centralizado para compliance da supply chain

---

## 8. CONCLUSÃO

O Banco Meridian demonstra controles de segurança em nuvem implementados e operacionais
nos domínios de CSPM, DevSecOps, Runtime Security e Gerenciamento de Segredos.
A conformidade com os artigos relevantes da Resolução BACEN 4.893 foi evidenciada
através dos controles documentados neste relatório.

Próxima revisão trimestral agendada: {datetime.now().strftime('%Y-%m-%d')} + 90 dias

───────────────────────────────────────────────────────────
Cloud Security Engineer: [seu nome]
Revisado por: CISO Banco Meridian
Data: {datetime.now().strftime('%d/%m/%Y')}
"""

with open('./capstone-evidencias/relatorio/relatorio-executivo-capstone.md', 'w') as f:
    f.write(relatorio)

print("Relatório executivo salvo em: ./capstone-evidencias/relatorio/relatorio-executivo-capstone.md")
print()
print("Preencha as seções marcadas com [verificar...] com os dados reais coletados nos entregáveis anteriores.")
PYEOF
```

---

## 6. Estrutura de Evidências

Ao final do capstone, a pasta de evidências deve ter a seguinte estrutura:

```
capstone-evidencias/
├── cspm/
│   ├── prowler-output-YYYY-MM-DD-HH-MM-SS.html   # Relatório Prowler HTML
│   └── critical/                                   # Findings críticos JSON
├── falco/
│   └── falco-alerts-YYYYMMDD.log                  # Alertas Falco coletados
├── vault/
│   └── vault-inventory-YYYYMMDD.txt               # Inventário de segredos
└── relatorio/
    └── relatorio-executivo-capstone.md             # Relatório executivo final
```

O repositório GitHub do Entregável 2 serve como evidência adicional autônoma.

---

## 7. Entrega e Avaliação

Submeter até o prazo definido pelo instrutor:
- **Pasta:** `capstone-bancomeridian-[seu-nome]/`
- **Conteúdo:** evidências de cada entregável (HTML, JSON, logs, YAML)
- **Relatório executivo:** arquivo Markdown ou PDF
- **Repositório GitHub:** URL do pipeline DevSecOps (Entregável 2)

**Critérios de aprovação:** ver tabela de avaliação no Módulo 09.

---

## 8. Dicas para o Relatório Executivo

- **Seja específico:** em vez de "implementamos segurança de container", escreva "Trivy detectou e bloqueou 0 imagens com CVEs CRITICAL no período de X dias de operação do pipeline"
- **Use dados reais:** os números do Prowler (percentual de conformidade), do Falco (número de alertas gerados), do Vault (quantidade de segredos centralizados) tornam o relatório auditável
- **Mapeie para o regulador:** cada controle deve ter uma referência explícita ao artigo do BACEN 4.893 que mitiga
- **Inclua o antes/depois:** para cada área onde houve remediação, mostre o estado antes e depois (ex: "antes: 0 segredos no Vault; depois: 15 segredos centralizados, eliminando 8 arquivos .env do repositório")

---

*Lab Capstone — Avaliação de Postura Multi-Cloud do Banco Meridian*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
