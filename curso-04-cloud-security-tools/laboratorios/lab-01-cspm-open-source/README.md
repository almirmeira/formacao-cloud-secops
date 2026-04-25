# Lab 01 — CSPM Open-Source com Prowler v4
## Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps · CECyber

> **Duração:** 2 horas  
> **Dificuldade:** Intermediário  
> **Módulo Relacionado:** Módulo 02 — CSPM  

---

## 1. Contexto Situacional

O CISO do Banco Meridian agendou uma reunião com o Conselho de Administração para apresentar a postura de segurança do ambiente AWS antes de uma auditoria do BACEN prevista para 45 dias. Você foi contratado como Cloud Security Engineer para executar um assessment de postura cloud e produzir um relatório executivo que o CISO possa apresentar ao Conselho.

O ambiente AWS do Banco Meridian inclui:
- 120+ recursos (EC2, S3, RDS, Lambda, EKS, IAM)
- 3 contas: produção, staging e sandbox
- Localização: região us-east-1 e sa-east-1

---

## 2. Situação Inicial

O ambiente AWS foi crescendo organicamente ao longo de 3 anos. Não há um processo formal de revisão de segurança. Vários recursos foram criados por desenvolvedores sem treinamento em cloud security. Não há relatório formal de postura de segurança — apenas notas manuais esporádicas.

O CISO só sabe que "tem alguns problemas de configuração" mas não tem dados precisos para apresentar ao Conselho nem para o BACEN.

---

## 3. Problema Identificado

A auditoria do BACEN verificará conformidade com a Resolução 4.893, especificamente:
- Art. 5º: testes periódicos de vulnerabilidade e avaliação de controles
- Art. 6º: monitoramento contínuo de sistemas
- Art. 8º: gestão de acessos e autenticação

O Banco Meridian não tem evidências formais de nenhum desses controles. Você precisa gerar essas evidências nos próximos 2 horas.

---

## 4. Roteiro de Atividades

1. Instalar e configurar o Prowler v4
2. Configurar credenciais AWS de auditoria (read-only)
3. Executar scan completo com compliance BACEN
4. Filtrar e analisar os findings mais críticos
5. Mapear top 10 findings para artigos do BACEN 4.893
6. Identificar os 3 recursos mais expostos
7. Calcular o Security Score atual
8. Gerar relatório HTML para o CISO
9. Criar tabela de remediação priorizada
10. Comparar com ScoutSuite para validação
11. Configurar scan agendado semanal
12. Documentar evidências para auditoria
13. Simular apresentação ao CISO
14. Rever falsos positivos
15. Salvar relatório final

---

## 5. Proposição

Ao final deste laboratório, você terá:
- Um relatório Prowler HTML completo da conta AWS sandbox
- Um mapeamento dos findings críticos para BACEN 4.893
- Um relatório executivo pronto para apresentação ao CISO
- Evidências formais de avaliação de segurança para a auditoria BACEN

---

## 6. Script Passo a Passo

### Pré-requisitos

```bash
# Verificar Python 3.8+
python3 --version

# Verificar pip
pip3 --version

# Verificar AWS CLI configurada
aws sts get-caller-identity
```

### Passo 1: Instalar Prowler v4

```bash
# Instalar Prowler v4 via pip
pip3 install prowler

# Verificar instalação
prowler --version
# Resultado esperado: prowler 4.x.x

# Se versão antiga já instalada, atualizar
pip3 install --upgrade prowler
```

**Resultado esperado:**
```
prowler 4.3.0
```

**Troubleshooting:** Se `prowler` não for encontrado após instalação, adicionar `~/.local/bin` ao PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

---

### Passo 2: Configurar Credenciais AWS

```bash
# Método 1: AWS CLI profile (recomendado)
aws configure --profile bancomeridian-sandbox
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region name: us-east-1
# Default output format: json

# Verificar permissões (mínimo necessário: SecurityAudit + ViewOnlyAccess)
aws iam list-attached-user-policies \
  --user-name $(aws iam get-user --query 'User.UserName' --output text) \
  --profile bancomeridian-sandbox

# Método 2: Variáveis de ambiente (CI/CD)
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

# Verificar identidade
aws sts get-caller-identity --profile bancomeridian-sandbox
```

**Resultado esperado:**
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/prowler-audit"
}
```

**Troubleshooting:** Se receber `AccessDenied`, verifique se as policies `SecurityAudit` e `ViewOnlyAccess` estão anexadas ao usuário/role.

---

### Passo 3: Executar Scan Completo com Compliance BACEN

```bash
# Criar diretório para resultados
mkdir -p ~/lab01-cspm-results

# Executar Prowler com frameworks de compliance
# (estimativa: 15-25 minutos dependendo do número de recursos)
prowler aws \
  --profile bancomeridian-sandbox \
  --compliance brazil_lgpd cis_aws_foundations_benchmark_v3.0 \
  --output-formats html json csv \
  --output-path ~/lab01-cspm-results/ \
  --severity critical high medium \
  2>&1 | tee ~/lab01-cspm-results/prowler-execution.log

# Monitorar progresso
# Prowler mostra progresso por serviço: IAM, S3, EC2, RDS, etc.
```

**Resultado esperado:**
```
Prowler for AWS
Running at 2025-04-24T14:30:00Z
...
IAM: checking 85 controls... ████████████████████ done
S3: checking 45 controls... ████████████████████ done
EC2: checking 60 controls... ████████████████████ done
...
Assessment Summary:
  Total checks: 412
  Passed: 267 (64.8%)
  Failed: 145 (35.2%)
  CRITICAL: 4
  HIGH: 23
  MEDIUM: 87
  LOW: 31
```

**Troubleshooting:** Se o scan travar ou receber ThrottlingException:
```bash
prowler aws --profile bancomeridian-sandbox --service s3 iam ec2 rds
# Escanear apenas os serviços mais críticos primeiro
```

---

### Passo 4: Filtrar Findings Críticos

```bash
# Script para extrair e organizar os findings CRITICAL
python3 << 'PYEOF'
import json
import csv
from datetime import datetime

# Carregar output JSON do Prowler
with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.json') as f:
    data = json.load(f)

# Filtrar CRITICAL e HIGH
critical = [f for f in data if f.get('severity') == 'critical' and f.get('status') == 'FAIL']
high = [f for f in data if f.get('severity') == 'high' and f.get('status') == 'FAIL']

print(f"=== RELATÓRIO DE POSTURA — BANCO MERIDIAN ===")
print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
print(f"Findings CRITICAL: {len(critical)}")
print(f"Findings HIGH: {len(high)}")
print()

print("=== TOP CRITICAL FINDINGS ===")
for i, f in enumerate(critical, 1):
    print(f"{i}. [{f.get('check_id', 'N/A')}] {f.get('check_title', 'N/A')}")
    print(f"   Recurso: {f.get('resource_name', f.get('resource_uid', 'N/A'))}")
    print(f"   Região: {f.get('region', 'N/A')}")
    compliance = f.get('compliance', {})
    bacen = compliance.get('BACEN-4893', compliance.get('brazil_lgpd', 'N/A'))
    print(f"   BACEN: {bacen}")
    print()
PYEOF
```

**Resultado esperado:**
```
=== RELATÓRIO DE POSTURA — BANCO MERIDIAN ===
Data: 2025-04-24 14:55

Findings CRITICAL: 4
Findings HIGH: 23

=== TOP CRITICAL FINDINGS ===
1. [s3_bucket_public_access] S3 Bucket has public access enabled
   Recurso: bancomeridian-dados-clientes
   Região: us-east-1
   BACEN: Art.5, Art.6

2. [iam_root_account_mfa_enabled] Root account MFA not enabled
   Recurso: root
   Região: us-east-1
   BACEN: Art.8
[...]
```

---

### Passo 5: Mapear Findings para BACEN 4.893

```bash
# Criar tabela de mapeamento BACEN
python3 << 'PYEOF'
import json

# Mapeamento manual dos checks mais comuns para artigos BACEN
bacen_map = {
    's3_bucket_public_access': 'Art. 5 — Testes de controles',
    'iam_root_account_mfa_enabled': 'Art. 8 — Gestão de acessos',
    'cloudtrail_enabled': 'Art. 6 — Monitoramento',
    'rds_instance_publicly_accessible': 'Art. 5 — Testes de controles',
    'ec2_securitygroup_unrestricted_access_port_22': 'Art. 5 — Controles de acesso',
    'ebs_volume_encryption_enabled': 'Art. 5 — Proteção de dados',
    'iam_user_mfa_enabled_console_access': 'Art. 8 — Autenticação',
    'cloudwatch_log_group_retention_policy': 'Art. 6 — Logs e auditoria',
    'config_recorder_enabled': 'Art. 6 — Monitoramento',
    'guardduty_is_enabled': 'Art. 6 — Detecção de ameaças',
}

# Carregar findings
with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.json') as f:
    data = json.load(f)

failed = [f for f in data if f.get('status') == 'FAIL']

print("| Check ID | Severidade | Artigo BACEN 4.893 | Recurso |")
print("|:---------|:----------:|:-------------------|:--------|")
for f in failed[:20]:
    check_id = f.get('check_id', 'N/A')
    severity = f.get('severity', 'N/A').upper()
    bacen = bacen_map.get(check_id, 'Verificar manualmente')
    resource = f.get('resource_name', f.get('resource_uid', 'N/A'))[:40]
    print(f"| {check_id[:40]} | {severity} | {bacen} | {resource} |")
PYEOF
```

---

### Passo 6: Calcular Security Score

```bash
python3 << 'PYEOF'
import json

with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.json') as f:
    data = json.load(f)

total = len(data)
passed = len([f for f in data if f.get('status') == 'PASS'])
failed = len([f for f in data if f.get('status') == 'FAIL'])

# Cálculo ponderado por severidade
score_weights = {'critical': 0, 'high': 25, 'medium': 60, 'low': 85}
total_weighted = 0
passed_weighted = 0

for f in data:
    severity = f.get('severity', 'low')
    weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[severity]
    total_weighted += weight
    if f.get('status') == 'PASS':
        passed_weighted += weight

if total_weighted > 0:
    security_score = int((passed_weighted / total_weighted) * 100)
else:
    security_score = 0

print(f"=== SECURITY SCORE BANCO MERIDIAN ===")
print(f"Total de checks: {total}")
print(f"Checks passando: {passed} ({passed/total*100:.1f}%)")
print(f"Checks falhando: {failed} ({failed/total*100:.1f}%)")
print()
print(f"Security Score (ponderado por severidade): {security_score}/100")
print()
print("Interpretação:")
if security_score >= 85:
    print("✓ BOM — Pronto para auditoria BACEN")
elif security_score >= 70:
    print("⚠ ACEITÁVEL — Necessita melhorias antes da auditoria")
elif security_score >= 50:
    print("✗ PREOCUPANTE — Remediação urgente necessária")
else:
    print("✗ CRÍTICO — Intervenção imediata necessária")
PYEOF
```

**Resultado esperado:**
```
=== SECURITY SCORE BANCO MERIDIAN ===
Total de checks: 412
Checks passando: 267 (64.8%)
Checks falhando: 145 (35.2%)

Security Score (ponderado por severidade): 58/100

Interpretação:
✗ PREOCUPANTE — Remediação urgente necessária
```

---

### Passo 7: Visualizar Relatório HTML

```bash
# Abrir relatório HTML gerado pelo Prowler
# Localizar o arquivo HTML
ls ~/lab01-cspm-results/*.html

# Abrir no browser (Linux/WSL)
xdg-open ~/lab01-cspm-results/prowler*.html 2>/dev/null || \
  echo "Arquivo disponível em: ~/lab01-cspm-results/prowler*.html"

# No Windows WSL: copiar para diretório acessível
cp ~/lab01-cspm-results/prowler*.html /mnt/c/Users/$USER/Downloads/
echo "Relatório copiado para Downloads do Windows"
```

**O relatório HTML deve mostrar:**
- Dashboard com gráficos de severidade
- Filtros por serviço, severidade, compliance
- Cada finding com: descrição, recurso, recomendação, link para documentação
- Mapeamento de compliance (CIS, BACEN, LGPD)

---

### Passo 8: Comparar com ScoutSuite (Validação Cruzada)

```bash
# Instalar ScoutSuite
pip3 install scoutsuite

# Executar ScoutSuite (mais lento que Prowler, mas relatório diferente)
scout aws --profile bancomeridian-sandbox \
  --report-dir ~/lab01-cspm-results/scoutsuite/

# Comparar: quantos findings criticos cada ferramenta encontrou?
echo "=== COMPARATIVO PROWLER vs ScoutSuite ==="
echo "Prowler CRITICAL: $(cat ~/lab01-cspm-results/prowler-output.json | python3 -c "import json,sys; data=json.load(sys.stdin); print(len([f for f in data if f.get('severity')=='critical' and f.get('status')=='FAIL']))")"
echo "ScoutSuite: ver relatório HTML em ~/lab01-cspm-results/scoutsuite/"
```

---

### Passo 9: Identificar Top 3 Recursos Mais Expostos

```bash
python3 << 'PYEOF'
import json
from collections import defaultdict

with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.json') as f:
    data = json.load(f)

# Agrupar findings por recurso
resource_findings = defaultdict(list)
for f in data:
    if f.get('status') == 'FAIL':
        resource = f.get('resource_name', f.get('resource_uid', 'N/A'))
        severity_score = {'critical': 100, 'high': 70, 'medium': 30, 'low': 10}
        score = severity_score.get(f.get('severity', 'low'), 0)
        resource_findings[resource].append((f.get('check_id'), score))

# Ordenar por score total
ranked = sorted(resource_findings.items(),
                key=lambda x: sum(s for _, s in x[1]), reverse=True)

print("=== TOP 3 RECURSOS MAIS EXPOSTOS ===")
for i, (resource, findings) in enumerate(ranked[:3], 1):
    total_score = sum(s for _, s in findings)
    print(f"\n{i}. Recurso: {resource}")
    print(f"   Score de risco: {total_score}")
    print(f"   Findings:")
    for check_id, score in sorted(findings, key=lambda x: x[1], reverse=True)[:5]:
        print(f"   - {check_id} (score: {score})")
PYEOF
```

---

### Passo 10: Configurar Scan Agendado Semanal

```bash
# Criar script de scan agendado
cat > ~/lab01-cspm-results/prowler-weekly-scan.sh << 'SCRIPT'
#!/bin/bash
# Scan Prowler semanal — Banco Meridian
# Agendado para executar toda sexta-feira às 22h

DATE=$(date +%Y%m%d)
OUTPUT_DIR="/opt/prowler-results/$DATE"
mkdir -p $OUTPUT_DIR

# Executar scan
prowler aws \
  --profile bancomeridian-sandbox \
  --compliance brazil_lgpd cis_aws_foundations_benchmark_v3.0 \
  --output-formats html json csv \
  --output-path $OUTPUT_DIR/ \
  --severity critical high \
  --security-hub

# Enviar relatório por email (requer mailutils)
# mail -s "Prowler Security Report - $DATE" security@bancomeridian.com.br \
#   -A $OUTPUT_DIR/prowler-*.html < /dev/null

echo "Scan concluído: $OUTPUT_DIR"
SCRIPT

chmod +x ~/lab01-cspm-results/prowler-weekly-scan.sh

# Adicionar ao crontab (toda sexta às 22h)
(crontab -l 2>/dev/null; echo "0 22 * * 5 ~/lab01-cspm-results/prowler-weekly-scan.sh") | crontab -
echo "Scan semanal agendado: toda sexta-feira às 22h"
crontab -l
```

---

### Passo 11: Gerar Relatório Executivo Final

```bash
cat > ~/lab01-cspm-results/relatorio-executivo.md << 'REPORT'
# Relatório Executivo de Postura de Segurança Cloud
## Banco Meridian S.A. — Avaliação AWS
**Data:** $(date +%Y-%m-%d)  
**Executado por:** [Nome do analista]  
**Ferramenta:** Prowler v4 (open-source)  
**Classificação:** Confidencial

---

## Sumário Executivo

A avaliação de postura de segurança da conta AWS do Banco Meridian identificou
**4 findings CRÍTICOS** que requerem ação imediata para conformidade com a
Resolução BACEN 4.893.

**Security Score atual: 58/100** (meta para auditoria BACEN: 85+)

---

## Top 5 Riscos (Impacto de Negócio)

1. **Bucket S3 com dados de clientes acessível publicamente** [CRITICAL]
   Impacto: Violação LGPD + BACEN — potencial multa de até 2% do faturamento
   Remediação: 30 minutos de trabalho técnico

2. **Conta root AWS sem MFA** [CRITICAL]
   Impacto: Comprometimento total da conta AWS
   Remediação: 15 minutos

3. **CloudTrail desabilitado em 3 regiões** [CRITICAL]
   Impacto: Sem trilha de auditoria — falha direta na auditoria BACEN Art. 6
   Remediação: 2 horas

4. **Banco de dados RDS publicamente acessível** [CRITICAL]
   Impacto: Banco de dados de produção exposto à internet
   Remediação: 4 horas

5. **SSH aberto para 0.0.0.0/0 em 12 instâncias** [HIGH]
   Impacto: Risco de acesso remoto não autorizado
   Remediação: 8 horas

---

## Roadmap de Remediação

| Prazo | Ações | Horas | Responsável |
|:------|:------|:-----:|:-----------:|
| 24h | Fechar bucket S3 público + habilitar root MFA | 1h | Cloud Ops |
| 48h | Habilitar CloudTrail + mover RDS para subnet privada | 6h | Cloud Ops |
| 7 dias | Restringir SSH + habilitar MFA para usuários | 8h | Cloud Ops + Security |
| 30 dias | Resolver todos os MEDIUM | 40h | Cloud Ops |

---

## Evidência para Auditoria BACEN

- Relatório HTML: prowler-output-[date].html
- JSON estruturado: prowler-output.json
- Enviado para Security Hub: ✓
- Próxima execução agendada: sexta-feira 22h

REPORT

# Substituir data real no relatório
sed -i "s/\$(date +%Y-%m-%d)/$(date +%Y-%m-%d)/" ~/lab01-cspm-results/relatorio-executivo.md
echo "Relatório executivo criado: ~/lab01-cspm-results/relatorio-executivo.md"
```

---

### Passo 12: Verificar Falsos Positivos

```bash
# Verificar checks que podem ser falsos positivos no contexto do Banco Meridian
# Exemplo: S3 bucket público de website pode ser intencional

python3 << 'PYEOF'
import json

with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.json') as f:
    data = json.load(f)

# Candidates para false positive (lista de whitelisted resources)
known_public_resources = ['bancomeridian-website-publico', 'bancomeridian-cdn-assets']

false_positive_candidates = []
for f in data:
    if f.get('status') == 'FAIL':
        resource = f.get('resource_name', '')
        if any(fp in resource for fp in known_public_resources):
            false_positive_candidates.append(f)
            print(f"POSSÍVEL FALSO POSITIVO: {f.get('check_id')} em {resource}")
            print(f"  → Verifique se é intencional e adicione #prowler:ignore se necessário")
            print()

print(f"Total de candidatos a falso positivo: {len(false_positive_candidates)}")
PYEOF
```

---

### Passo 13: Integrar com AWS Security Hub

```bash
# Verificar se Security Hub está habilitado
aws securityhub describe-hub \
  --profile bancomeridian-sandbox \
  2>/dev/null && echo "Security Hub habilitado" || echo "Security Hub não habilitado"

# Se não habilitado, habilitar (custo adicional na conta)
# aws securityhub enable-security-hub --profile bancomeridian-sandbox

# Executar Prowler com integração Security Hub
prowler aws \
  --profile bancomeridian-sandbox \
  --security-hub \
  --severity critical high \
  --output-formats json

# Verificar findings no Security Hub
aws securityhub get-findings \
  --filters '{"ProductArn": [{"Value": "arn:aws:securityhub:*:*:product/prowler/prowler", "Comparison": "CONTAINS"}]}' \
  --profile bancomeridian-sandbox \
  --query 'Findings[0:5].[Title,Severity.Label,Resources[0].Id]' \
  --output table
```

---

### Passo 14: Exportar CSV para Análise no Excel

```bash
# O Prowler já gerou o CSV — visualizar
head -5 ~/lab01-cspm-results/prowler-output.csv

# Filtrar apenas CRITICAL e HIGH no CSV
python3 << 'PYEOF'
import csv

with open(f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/prowler-output.csv') as f:
    reader = csv.DictReader(f)
    rows = [r for r in reader if r.get('Severity', '').lower() in ['critical', 'high']]

output_file = f'{__import__("os").path.expanduser("~")}/lab01-cspm-results/critical-high-findings.csv'
with open(output_file, 'w', newline='') as f:
    if rows:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

print(f"CSV com {len(rows)} findings CRITICAL/HIGH salvo em: {output_file}")
PYEOF
```

---

### Passo 15: Consolidar Evidências para Auditoria

```bash
# Criar pacote de evidências para o BACEN
AUDIT_DIR=~/lab01-cspm-results/evidencias-bacen-$(date +%Y%m%d)
mkdir -p $AUDIT_DIR

# Copiar todos os artefatos relevantes
cp ~/lab01-cspm-results/prowler-output.json $AUDIT_DIR/
cp ~/lab01-cspm-results/*.html $AUDIT_DIR/ 2>/dev/null || true
cp ~/lab01-cspm-results/critical-high-findings.csv $AUDIT_DIR/
cp ~/lab01-cspm-results/relatorio-executivo.md $AUDIT_DIR/

# Gerar checksums para garantir integridade
sha256sum $AUDIT_DIR/* > $AUDIT_DIR/SHA256SUMS.txt

# Listar evidências
echo "=== PACOTE DE EVIDÊNCIAS PARA AUDITORIA BACEN ==="
ls -la $AUDIT_DIR/
echo ""
echo "Total de arquivos: $(ls $AUDIT_DIR | wc -l)"
echo "Tamanho total: $(du -sh $AUDIT_DIR | cut -f1)"
```

---

## 7. Objetivos por Etapa

| Passo | Objetivo | Verificação |
|:------|:---------|:-----------|
| 1 | Prowler instalado | `prowler --version` retorna `4.x.x` |
| 2 | Credenciais configuradas | `aws sts get-caller-identity` retorna Account ID |
| 3 | Scan executado | Arquivo `prowler-output.json` criado |
| 4 | Findings filtrados | Script Python retorna contagem de CRITICAL/HIGH |
| 5 | Mapeamento BACEN | Tabela de mapeamento gerada |
| 6 | Security Score calculado | Score numérico de 0–100 calculado |
| 7 | Relatório HTML aberto | Dashboard visual visível no browser |
| 8 | ScoutSuite comparado | Relatório ScoutSuite gerado |
| 9 | Top 3 recursos | Lista com score de risco por recurso |
| 10 | Scan agendado | Crontab configurado |
| 11 | Relatório executivo | Arquivo .md criado com toda a estrutura |
| 12 | Falsos positivos | Lista de candidatos identificada |
| 13 | Security Hub | Findings enviados para Security Hub |
| 14 | CSV exportado | Arquivo CSV com CRITICAL/HIGH apenas |
| 15 | Evidências consolidadas | Diretório com checksum SHA256 |

---

## 8. Gabarito Completo

### Output Esperado — Passo 3 (Resumo do Scan)

```
Assessment Summary:
  Provider: aws
  Account ID: 123456789012
  Region: us-east-1 (+ todas as outras regiões ativas)
  Date/Time: 2025-04-24T14:30:00Z
  Prowler Version: 4.3.0

  Total checks executed: 412
  Passed: 267 (64.8%)
  Failed: 145 (35.2%)
  CRITICAL: 4 (requerem ação imediata — 24h)
  HIGH: 23 (requerem ação em 7 dias)
  MEDIUM: 87 (planejar para 30 dias)
  LOW: 31 (monitorar, sem urgência)
```

### Top 5 Findings CRITICAL/HIGH — Resultado Esperado

| # | Check ID | Severidade | Recurso | Artigo BACEN |
|:-:|:---------|:----------:|:--------|:------------|
| 1 | s3_bucket_public_access | CRITICAL | bancomeridian-dados-clientes | Art. 5, LGPD 46 |
| 2 | iam_root_account_mfa_enabled | CRITICAL | root | Art. 8 |
| 3 | cloudtrail_enabled | CRITICAL | us-west-1, eu-west-1, ap-southeast-1 | Art. 6 |
| 4 | rds_instance_publicly_accessible | CRITICAL | bancomeridian-db-prod | Art. 5 |
| 5 | ec2_securitygroup_unrestricted_access_port_22 | HIGH | sg-0abc123def | Art. 5 |

### Script de Remediação — Comando Exato para Finding #1

```bash
# Remediar bucket S3 público
BUCKET_NAME="bancomeridian-dados-clientes"

# Bloquear acesso público
aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verificar que foi bloqueado
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Rerodar check específico no Prowler para confirmar remediação
prowler aws --check s3_bucket_public_access --resource-arn arn:aws:s3:::$BUCKET_NAME
# Esperado: PASS após remediação
```

### Relatório Executivo — Estrutura Completa Esperada

O arquivo `~/lab01-cspm-results/relatorio-executivo.md` deve conter:
1. Cabeçalho com data, analista e ferramenta
2. Sumário executivo com Security Score e contagem de findings
3. Top 5 riscos com impacto de negócio em linguagem não técnica
4. Tabela de remediação com prazo, esforço e responsável
5. Referência à evidência formal gerada (arquivo HTML + JSON)
6. Próximos passos (scan semanal configurado)

**Este relatório é a evidência principal para o artigo 5º da BACEN 4.893 — testes periódicos de vulnerabilidade.**

---

*Lab 01 — CSPM Open-Source com Prowler v4*  
*Curso 4: Ferramentas de Cloud Security — CNAPP, IaC e DevSecOps*  
*CECyber — Educação Corporativa em Cibersegurança*
