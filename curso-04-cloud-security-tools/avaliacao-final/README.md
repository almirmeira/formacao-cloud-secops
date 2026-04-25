# Avaliação Final — Curso 4: Ferramentas de Cloud Security
## CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 3 horas  
> **Composição:** 80% Questões objetivas (40 questões) + 20% Estudo de caso (5 questões discursivas)  
> **Aprovação:** Mínimo de 70%  
> **Certificação Alvo:** CCSP (ISC²) / CCSK (CSA)

---

## PARTE A — Questões de Múltipla Escolha (80 pontos — 2 pts cada)

### Módulo 01 — Panorama e Taxonomia

**Questão 1**  
Qual categoria de ferramenta de cloud security é responsável por descobrir e classificar dados sensíveis (PII, PCI) espalhados em repositórios cloud como S3 buckets e bancos de dados?

a) CSPM — Cloud Security Posture Management  
b) CIEM — Cloud Infrastructure Entitlement Management  
c) DSPM — Data Security Posture Management  
d) CWPP — Cloud Workload Protection Platform  

**Questão 2**  
O conceito de "toxic combination" em plataformas CNAPP descreve:

a) A combinação de múltiplas ferramentas open-source que juntas atingem paridade com CNAPP comercial  
b) Uma vulnerabilidade com score CVSS acima de 9.5 em sistema de produção  
c) A correlação de findings de múltiplas categorias (misconfiguration + CVE + permissão excessiva) que individualmente têm risco médio mas combinados formam um caminho de ataque crítico  
d) O uso de mais de 3 provedores cloud simultaneamente sem ferramenta unificada  

**Questão 3**  
De acordo com a Resolução CMN 4.658/2018, qual é o requisito mais relevante para IFs brasileiras ao escolher uma ferramenta CNAPP SaaS?

a) A ferramenta deve ter suporte em português brasileiro  
b) A ferramenta deve ter data center no Brasil ou aprovação prévia do BACEN para processamento de dados de clientes fora do território nacional  
c) A ferramenta deve ser auditada por órgão certificador do BACEN  
d) A ferramenta deve ser open-source para garantir transparência regulatória  

**Questão 4**  
Qual é a diferença fundamental entre CSPM e CWPP?

a) CSPM monitora usuários; CWPP monitora serviços  
b) CSPM avalia configurações de recursos cloud (plano de controle); CWPP protege cargas de trabalho em execução (plano de dados)  
c) CSPM funciona apenas em AWS; CWPP funciona em multi-cloud  
d) CSPM usa agente; CWPP é agentless  

---

### Módulo 02 — CSPM

**Questão 5**  
Qual comando Prowler v4 executa um scan AWS filtrado por severidade CRITICAL e HIGH, gerando saída em HTML e JSON, integrado ao Security Hub?

a) `prowler aws --level critical high --format html json --hub`  
b) `prowler aws --severity critical high --output-formats html json --security-hub`  
c) `prowler scan --provider aws --critical --html --json --security-hub`  
d) `prowler aws --findings critical high --export html,json --aws-hub`  

**Questão 6**  
O ScoutSuite é melhor descrito como:

a) Uma ferramenta de runtime security baseada em eBPF  
b) Uma ferramenta de CSPM open-source que gera relatório HTML interativo rico para análise multi-cloud  
c) Uma plataforma CNAPP comercial com Security Graph  
d) Um scanner de vulnerabilidades de containers  

**Questão 7**  
Qual framework de compliance built-in no Prowler v4 cobre regulações financeiras brasileiras incluindo BACEN 4.893?

a) `cis_aws_foundations_benchmark_v3.0`  
b) `nist_sp_800_53_revision_5_aws`  
c) `brazil_lgpd`  
d) `soc2_type_ii`  

**Questão 8**  
Na apresentação de um relatório CSPM ao CISO, qual é o principal problema de apresentar 10.000 findings sem priorização?

a) O CISO pode achar que a equipe de segurança não está trabalhando  
b) Findings de LOW podem conter vulnerabilidades críticas escondidas  
c) Transfere a carga cognitiva de priorização para o CISO sem contexto de impacto de negócio, impossibilitando decisões de investimento e remediação  
d) O relatório será muito grande para enviar por email  

---

### Módulo 03 — IaC Security

**Questão 9**  
De acordo com a regra do custo de correção, uma vulnerabilidade encontrada após um incidente de segurança em produção custa quanto em relação à mesma encontrada na fase de desenvolvimento?

a) 10 vezes mais  
b) 100 vezes mais  
c) 1.000 vezes mais  
d) 10.000 vezes ou mais  

**Questão 10**  
Qual é a diferença entre usar `--severity CRITICAL HIGH` e `--soft-fail-on MEDIUM LOW` no Checkov?

a) São equivalentes  
b) `--severity` filtra checks executados; `--soft-fail-on` executa todos os checks mas retorna exit code 0 para os severity listados  
c) `--severity` é para Terraform; `--soft-fail-on` é para Kubernetes  
d) `--soft-fail-on` suprime os findings do relatório  

**Questão 11**  
Em Rego (OPA), o que acontece quando o conjunto `deny` de uma política retorna vazio?

a) A política retorna erro de execução  
b) A política é considerada aprovada — o recurso passou em todos os checks  
c) OPA retorna "undecided" requerendo aprovação manual  
d) Conftest falha com exit code 2  

**Questão 12**  
Qual ferramenta é preferível quando se precisa cobrir IaC scan + image scan + SBOM em um único step de CI/CD?

a) Checkov  
b) tfsec  
c) Trivy  
d) KICS  

---

### Módulo 04 — CWPP e Container Security

**Questão 13**  
No pipeline seguro de container, qual é a ordem correta das etapas?

a) Push → Scan → Build → Sign → Verify  
b) Build → Scan → SBOM → Push → Sign → Verify  
c) Sign → Build → Scan → Push → Verify  
d) Build → Push → Scan → Sign → Verify  

**Questão 14**  
O que o Cosign keyless (Sigstore) usa como raiz de confiança?

a) Uma chave privada gerenciada no HSM do usuário  
b) Uma identidade OIDC efêmera (ex: GitHub Actions) certificada pela Fulcio (CA Sigstore) e registrada no Rekor  
c) O certificado X.509 da conta AWS  
d) Uma chave gerada automaticamente pelo Kubernetes  

**Questão 15**  
Qual é a principal limitação do Falco para proteção de containers comparado a scanners de imagem como Trivy?

a) Falco é mais lento que Trivy  
b) Falco detecta comportamentos em runtime (eventos reais), enquanto Trivy detecta vulnerabilidades conhecidas em estado estático — são complementares, não equivalentes  
c) Falco não suporta Kubernetes  
d) Falco só funciona em ambientes on-premises  

**Questão 16**  
A regra Falco que detecta acesso à API de metadados AWS (169.254.169.254) mapeia para qual técnica MITRE ATT&CK?

a) T1059 — Command and Scripting Interpreter  
b) T1611 — Escape to Host  
c) T1552.005 — Cloud Instance Metadata API  
d) T1565 — Data Manipulation  

---

### Módulo 05 — Kubernetes Security

**Questão 17**  
Qual é a diferença entre os modos `enforce`, `audit` e `warn` do Pod Security Standards?

a) enforce bloqueia; audit e warn permitem mas registram de formas diferentes  
b) enforce bloqueia; audit permite mas registra no audit log; warn permite mas retorna warning no response da API  
c) São sinônimos com diferentes níveis de verbosidade  
d) enforce e audit bloqueiam; warn apenas notifica  

**Questão 18**  
Por que `automountServiceAccountToken: false` é uma boa prática para a maioria das aplicações K8s?

a) Melhora a performance do Pod  
b) Impede que o token da ServiceAccount seja automaticamente montado — se o container for comprometido, o atacante não terá automaticamente acesso à API K8s  
c) Reduz o uso de memória do kubelet  
d) Permite que o Pod use múltiplas ServiceAccounts  

**Questão 19**  
Qual política Kyverno verifica se a imagem do container foi assinada com Cosign antes de permitir execução?

a) `block-root-containers`  
b) `require-non-latest-image-tag`  
c) `verify-image-signatures` (usando `verifyImages`)  
d) `block-hostpath`  

**Questão 20**  
O kube-bench executa checks do qual framework de segurança para clusters Kubernetes?

a) NIST SP 800-53  
b) CIS Kubernetes Benchmark  
c) OWASP Kubernetes Top 10  
d) ISO 27001 Kubernetes Annex  

---

### Módulo 06 — CIEM

**Questão 21**  
O Unused Access Analyzer do AWS IAM Access Analyzer detecta especificamente:

a) Recursos AWS com acesso público na internet  
b) Permissões IAM, credenciais e roles não utilizadas nos últimos 90 dias  
c) Usuários que tentaram acessar recursos sem permissão  
d) Instâncias EC2 sem tráfego de rede  

**Questão 22**  
"Permissions Creep" descreve qual problema específico em ambientes cloud?

a) Quando um usuário tenta escalar privilégios indevidamente  
b) O acúmulo gradual de permissões ao longo do tempo que nunca são removidas, criando um gap crescente entre permissões concedidas e necessárias  
c) Quando uma ferramenta CIEM gera falsos positivos excessivos  
d) A diferença de permissões entre ambientes de desenvolvimento e produção  

**Questão 23**  
O comando `aws accessanalyzer start-policy-generation` usa dados de qual serviço AWS?

a) AWS Config  
b) Amazon CloudTrail  
c) Amazon GuardDuty  
d) AWS Security Hub  

**Questão 24**  
Just-in-time access (JIT) resolve qual problema do modelo de "standing access"?

a) Standing access não suporta MFA  
b) Standing access é permanente — JIT concede acesso por demanda com TTL curto, reduzindo a janela de exposição  
c) Standing access é mais caro  
d) Standing access não funciona com RBAC  

---

### Módulo 07 — Secrets Management

**Questão 25**  
O HashiCorp Vault database secret engine gera credenciais que:

a) São armazenadas permanentemente no Vault para consulta futura  
b) São únicas por request, têm TTL configurado, e são automaticamente revogadas no banco quando o lease expira  
c) Substituem as credenciais existentes do banco de dados  
d) Funcionam apenas com PostgreSQL  

**Questão 26**  
O AppRole auth method do Vault usa dois componentes: Role ID e Secret ID. A diferença entre eles é:

a) Role ID é temporário; Secret ID é permanente  
b) Role ID é público (identifica a aplicação); Secret ID é privado e efêmero (injetado pelo CI/CD com TTL curto)  
c) São equivalentes — qualquer um pode ser usado sozinho  
d) Role ID é para humanos; Secret ID é para aplicações  

**Questão 27**  
O External Secrets Operator (ESO) no Kubernetes:

a) Instala o Vault diretamente no cluster  
b) Sincroniza secrets do Vault (ou outros backends) para recursos nativos `Secret` do K8s, sem sidecar na aplicação  
c) Substitui o kubelet na gestão de secrets  
d) Requer o Vault Enterprise para funcionar  

**Questão 28**  
Quando uma organização deve escolher AWS Secrets Manager em vez de HashiCorp Vault?

a) Quando opera em multi-cloud (AWS + Azure + GCP)  
b) Quando tem requisito de soberania de dados e não pode usar SaaS externo  
c) Quando opera apenas na AWS, valoriza simplicidade operacional, e não precisa de dynamic secrets para múltiplos backends não-AWS  
d) Quando tem equipe grande de engenharia de plataforma  

---

### Módulo 08 — CASB, SSE, DSPM e CNAPP

**Questão 29**  
O modo "inline proxy" de um CASB:

a) Conecta via API ao tenant SaaS para análise pós-fato  
b) Intercepta o tráfego em tempo real e pode bloquear uploads de dados sensíveis antes de chegarem ao SaaS destino  
c) Analisa logs de acesso ao SaaS semanalmente  
d) Funciona apenas em dispositivos corporativos gerenciados por MDM  

**Questão 30**  
ZTNA (Zero Trust Network Access), como parte do SSE, resolve qual problema fundamental da VPN tradicional?

a) VPN é mais lenta que ZTNA  
b) VPN concede acesso à rede inteira após autenticação — ZTNA concede acesso à aplicação específica com verificação contínua de identidade, dispositivo e contexto  
c) VPN requer hardware on-premises  
d) VPN não suporta autenticação por certificado  

**Questão 31**  
Por que DSPM é considerado cada vez mais necessário para conformidade com LGPD?

a) A LGPD exige certificação de ferramentas DSPM  
b) LGPD exige que organizações saibam onde estão seus dados pessoais e implementem controles — impossível sem descoberta automática em ambientes cloud com múltiplos data stores  
c) DSPM é obrigatório para empresas com mais de 100 funcionários  
d) DSPM monitora conformidade da LGPD em tempo real  

**Questão 32**  
O SideScanning™ da Orca Security lê snapshots efêmeros de disco. Qual é a principal limitação deste approach?

a) Gera alto overhead de CPU nos workloads  
b) É uma análise estática (snapshot) sem visibilidade de comportamentos em runtime — não detecta ataques acontecendo em tempo real  
c) Requer agente instalado em cada instância  
d) Funciona apenas em AWS  

**Questão 33**  
Qual plataforma CNAPP tem a menor fricção para conformidade com CMN 4.658/2018 para bancos brasileiros?

a) Wiz — por ser líder no Gartner Magic Quadrant  
b) Microsoft Defender for Cloud — por processar dados nativamente na Azure Brazil South  
c) Prisma Cloud — por ter mais frameworks de compliance  
d) Lacework — por ter o melhor suporte ao mercado brasileiro  

**Questão 34**  
O Permissions Creep Index (PCI) do Entra Permissions Management, com valor de 100, indica:

a) A identidade tem exatamente 100 permissões excessivas  
b) A identidade tem permissões massivamente maiores do que as utilizadas — máximo de permissions creep  
c) A identidade foi comprometida  
d) A identidade é um shadow admin  

---

### Conceitos Integrados (Questões 35–40)

**Questão 35**  
Um analista configura um pipeline GitHub Actions com Checkov para IaC security. Para que o pipeline BLOQUEIE merges com findings CRITICAL mas apenas AVISE para MEDIUM, a configuração correta é:

a) Dois jobs: um com `--severity CRITICAL` (falha) e outro com `--severity MEDIUM` (passa)  
b) Um job com `checkov --severity CRITICAL HIGH --soft-fail-on MEDIUM LOW`  
c) Usar tfsec para CRITICAL e Checkov para MEDIUM  
d) Configurar GitHub branch protection para bloquear apenas quando ALL jobs falham  

**Questão 36**  
No contexto de Shift-Left security, qual é a sequência correta de onde as verificações de segurança devem ocorrer?

a) Produção → Staging → Desenvolvimento  
b) IDE/Pre-commit → PR/CI → Staging → Produção (em ordem crescente de custo de correção)  
c) Produção → Desenvolvimento (shift-right)  
d) Todas as verificações devem ocorrer apenas em staging  

**Questão 37**  
Uma empresa implementou: Prowler (CSPM semanal), Trivy (container scan no CI/CD), Falco (runtime), Checkov (IaC no PR), Vault (secrets), e IAM Access Analyzer (CIEM trimestral). Qual das categorias da taxonomia Gartner NÃO está coberta?

a) CSPM  
b) CWPP  
c) KSPM detalhado e DSPM  
d) IaC Security  

**Questão 38**  
O Banco Meridian precisa apresentar evidências para o artigo 6º da BACEN 4.893 ("monitoramento contínuo"). Qual combinação de ferramentas melhor atende este requisito?

a) Checkov + tfsec (análise de IaC)  
b) Prowler (semanal) + Falco (runtime) + CloudTrail + CloudWatch Alarms  
c) Vault + IAM Access Analyzer  
d) Cosign + Syft (SBOM)  

**Questão 39**  
Um time de DevOps quer implementar o modelo "imagem assinada = autorizada para produção". Qual sequência de ferramentas implementa isso?

a) Trivy scan → Checkov → kubectl apply  
b) Trivy scan → Cosign sign → Push → Cosign verify (no admission) ou Kyverno verifyImages  
c) Falco → Cosign → kubectl apply  
d) Checkov → Trivy → Vault → kubectl apply  

**Questão 40**  
Para uma startup brasileira de fintech com 2 engenheiros de segurança, orçamento limitado e auditoria BACEN em 3 meses, qual stack mínimo open-source cobre CSPM + CWPP + IaC security suficientemente para a auditoria?

a) Vault + Consul + Nomad  
b) Prowler (CSPM) + Trivy (CWPP + IaC) + Checkov (IaC no CI/CD)  
c) OPA + Falco + kube-bench  
d) Netskope + Zscaler + Lacework  

---

## PARTE B — Estudo de Caso (20 pontos — 4 pts cada)

### Cenário

O Banco Digital Meridian está crescendo rapidamente e precisa escolher uma plataforma CNAPP para substituir sua stack atual de ferramentas pontuais (Prowler + Trivy + Falco separados, sem correlação). O CTO apresentou 4 opções ao CISO:

**Opção A:** Wiz (USD 120.000/ano)  
**Opção B:** Microsoft Defender for Cloud (USD 35.000/ano)  
**Opção C:** Orca Security (USD 70.000/ano)  
**Opção D:** Manter e aprimorar stack open-source (custo estimado: USD 90.000/ano com 1 FTE dedicado)

**Contexto específico:**
- 200 workloads: 70% AWS, 30% Azure
- Microsoft 365 E3 (Exchange, Teams, SharePoint)
- Equipe de segurança: 3 analistas
- Auditoria BACEN em 90 dias
- Regulatório: CMN 4.658 (Art. 16)
- Requisito de SIEM: Microsoft Sentinel já implementado

---

**Questão 1 (4 pts)**  
Analise a opção B (Microsoft Defender for Cloud) considerando:
- Conformidade com CMN 4.658
- Integração com o ecossistema Microsoft existente
- Prazo da auditoria

Quais são os 3 principais argumentos a favor e os 2 principais contra desta opção para o Banco Meridian?

---

**Questão 2 (4 pts)**  
Compare a Opção A (Wiz) e a Opção D (stack open-source) em termos de TCO de 3 anos para o Banco Meridian. Considere:
- Custo de licença ou custo de FTE
- Tempo até primeira evidência para o BACEN
- Capacidade de correlação de findings

Qual opção você recomenda e por quê?

---

**Questão 3 (4 pts)**  
Proposição: "A ferramenta CNAPP escolhida deve ser capaz de demonstrar conformidade com BACEN 4.893 Arts. 5, 6, 8 e 9 em um único relatório." Explique como cada um dos 4 artigos seria evidenciado por uma plataforma CNAPP, citando funcionalidades específicas da ferramenta escolhida.

---

**Questão 4 (4 pts)**  
O Banco Meridian decidiu comprar o Wiz (Opção A). Descreva um plano de PoC de 30 dias com 4 semanas definidas, métricas de sucesso para cada semana, e os critérios de aprovação final para migrar da stack open-source para o Wiz.

---

**Questão 5 (4 pts)**  
Independente da plataforma CNAPP escolhida, quais são as 5 práticas de segurança cloud que o Banco Meridian deve implementar que NÃO são cobertas por CNAPP (ou seja, são complementares e necessárias independentemente)? Cite ferramenta open-source específica para cada prática.

---

## Gabarito — Parte A

| Q | Resp | Justificativa Resumida |
|:-:|:----:|:-----------------------|
| 1 | c | DSPM foca em dados em repouso — discovery e classificação |
| 2 | c | Toxic combination = correlação de findings isolados que juntos formam ataque crítico |
| 3 | b | CMN 4.658 Art. 16 restringe dados de clientes fora do Brasil sem aprovação BACEN |
| 4 | b | CSPM = configuração (plano de controle); CWPP = workload em execução (plano de dados) |
| 5 | b | Sintaxe correta: `--severity critical high --output-formats html json --security-hub` |
| 6 | b | ScoutSuite = CSPM open-source com relatório HTML visual |
| 7 | c | `brazil_lgpd` cobre LGPD + BACEN 4.893 + CMN 4.658 |
| 8 | c | Apresentar sem priorização transfere a decisão sem contexto de negócio |
| 9 | d | Custo 1 (dev) → 10 (PR) → 100 (staging) → 1.000 (prod) → 10.000+ (pós-incidente) |
| 10 | b | `--severity` filtra execução; `--soft-fail-on` permite exit code 0 para severity listados |
| 11 | b | `deny` vazio = recurso passou na política |
| 12 | c | Trivy cobre IaC + imagem + SBOM + secrets em um binário |
| 13 | b | Build → Scan → SBOM → Push → Sign → Verify |
| 14 | b | Cosign keyless usa OIDC + Fulcio + Rekor |
| 15 | b | Falco = runtime (comportamento); Trivy = static (estado da imagem) — complementares |
| 16 | c | T1552.005 = Cloud Instance Metadata API |
| 17 | b | enforce bloqueia; audit registra; warn avisa via API response |
| 18 | b | Sem auto-mount, container comprometido não tem token K8s automaticamente |
| 19 | c | `verifyImages` do Kyverno verifica assinatura Cosign no admission |
| 20 | b | kube-bench implementa CIS Kubernetes Benchmark |
| 21 | b | Unused Access = permissões não utilizadas nos últimos 90 dias |
| 22 | b | Permissions Creep = acúmulo gradual de permissões não removidas |
| 23 | b | Policy Generation usa CloudTrail para ver ações executadas |
| 24 | b | JIT = acesso com TTL; standing = permanente |
| 25 | b | Dynamic secrets: únicos por request, TTL, revogação automática |
| 26 | b | Role ID público (identidade); Secret ID privado + efêmero (prova de ambiente) |
| 27 | b | ESO sincroniza Vault → K8s Secret nativo, sem sidecar |
| 28 | c | Secrets Manager = AWS-only, simplicidade, sem necessidade de multi-backend |
| 29 | b | Inline proxy = intercepta em tempo real, bloqueia upload |
| 30 | b | VPN = acesso à rede; ZTNA = acesso à aplicação específica com contexto |
| 31 | b | LGPD exige saber onde estão dados pessoais — sem DSPM, impossível garantir |
| 32 | b | SideScanning = foto, não filme — sem detecção de comportamento em runtime |
| 33 | b | Defender for Cloud = dados em Azure Brazil South, integração Microsoft nativa |
| 34 | b | PCI 100 = permissões máximamente excessivas em relação ao uso |
| 35 | b | `--severity CRITICAL HIGH --soft-fail-on MEDIUM LOW` |
| 36 | b | IDE → PR/CI → Staging → Produção (custo cresce da esquerda para a direita) |
| 37 | c | KSPM detalhado e DSPM não estão na stack descrita |
| 38 | b | Prowler + Falco + CloudTrail + Alarms cobrem monitoramento contínuo Art. 6 |
| 39 | b | Trivy scan → Cosign sign → Push → Cosign verify (Kyverno verifyImages) |
| 40 | b | Prowler (CSPM) + Trivy (CWPP + IaC) + Checkov (CI/CD) — stack mínimo viável |

---

## Gabarito — Parte B (Critérios de Pontuação)

### Questão 1 — Microsoft Defender for Cloud

**3 argumentos a favor (2 pts):**
1. CMN 4.658 Art. 16 atendido nativamente — Azure Brazil South sem aprovação especial do BACEN
2. Integração nativa com Microsoft Sentinel (SIEM já implementado), eliminando conectores
3. Para 30% Azure + M365 E3: cobertura nativa de SharePoint, Teams, Exchange — sem custo adicional (Foundational CSPM gratuito)

**2 contra (2 pts):**
1. Cobertura AWS (70% do ambiente) mais superficial que Wiz ou Orca para a plataforma principal
2. DSPM e correlação de attack paths menos maturos que Wiz — limitação para identificação de toxic combinations multi-cloud

---

### Questão 2 — TCO: Wiz vs Stack Open-Source

**TCO 3 anos estimado (2 pts):**
- Wiz: USD 120.000/ano × 3 = USD 360.000 + onboarding USD 20.000 = USD 380.000
- Open-source: 1 FTE × USD 90.000/ano = USD 270.000 + infra USD 10.000/ano × 3 = USD 300.000 + implementação USD 40.000 = USD 340.000

**Recomendação com justificativa (2 pts):**
Com equipe de apenas 3 analistas e auditoria em 90 dias, recomendar Wiz porque:
- Time-to-first-evidence: Wiz = 2 semanas; Open-source = 2+ meses (implementação e integração)
- Correlação de attack paths: open-source não tem — limitação crítica para detectar toxic combinations
- Diferença de TCO (USD 40.000 em 3 anos) é justificada pelo valor da correlação e pelo prazo da auditoria

---

### Questão 3 — CNAPP e BACEN 4.893

**Exemplo com Microsoft Defender for Cloud (1 pt por artigo):**
- Art. 5 (testes de vulnerabilidade): Secure Score + recomendações de CIS AWS/Azure + Defender for Containers (CVE scan)
- Art. 6 (monitoramento contínuo): Alertas em tempo real → Microsoft Sentinel, correlação com UEBA
- Art. 8 (gestão de acessos): Defender CSPM > Identity recommendations + Entra Permissions Management (CIEM)
- Art. 9 (registro de incidentes): Defender Alerts com timestamp, severity, affected resource → Sentinel SIEM com auditoria

---

### Questão 4 — Plano de PoC 30 dias

**Estrutura com 4 semanas (1 pt por semana com métricas):**
- Semana 1: Onboarding (conectar AWS + Azure) | Métrica: 100% workloads descobertos em < 48h
- Semana 2: CSPM + CIEM | Métrica: >80% dos findings Prowler identificados pelo Wiz
- Semana 3: Attack path + Correlação | Métrica: toxic combinations identificadas em cenário controlado
- Semana 4: Relatório BACEN + Integração Sentinel | Métrica: relatório BACEN apresentável ao CISO sem edição

**Critério de aprovação:** Wiz detecta ≥80% dos findings de referência (Prowler), attack path claro para pelo menos 1 toxic combination, relatório BACEN gerado automaticamente, dados confirmados em Brazil South.

---

### Questão 5 — Práticas Complementares ao CNAPP

**5 práticas com ferramenta open-source (0,8 pt cada):**
1. IaC security preventivo no CI/CD: Checkov — bloqueia misconfigurations antes do deploy (shift-left)
2. Secrets management com dynamic credentials: HashiCorp Vault — elimina credenciais estáticas
3. Container signing e verification: Cosign (Sigstore) — garante supply chain integrity
4. Admission control preventivo: Kyverno — bloqueia Pods que violam políticas de segurança
5. CIS Benchmark em K8s: kube-bench — avaliação periódica de configuração dos clusters

---

*Avaliação Final — Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
