# Módulo 07 — Capstone: Operação Antas
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 2h laboratório autoguiado + 2h sessão live de defesa                |
| **Pré-requisito**  | Módulos 01–06 concluídos · Todos os labs entregues                  |
| **MITRE ATT&CK**   | T1566.001, T1078, T1039, T1098, T1071.001, T1048                   |
| **Ferramentas**    | Google SecOps (SIEM + SOAR + UEBA + TI), YARA-L Editor             |

---

## 1. Cenário Capstone: "Operação Antas"

### 1.1 Contexto Narrativo

Era uma terça-feira comum no SOC do Banco Meridian quando tudo mudou. O time tinha concluído
o treinamento de Google SecOps Essentials duas semanas antes e, pela primeira vez, o Risk
Analytics estava calibrado, as regras YARA-L estavam em produção e o SOAR estava operando
com três playbooks ativos. A confiança do time era alta.

Às 07:47 da manhã, uma anomalia discreta apareceu no painel de Risk Analytics: o usuário
marcos.pereira — analista financeiro sênior, acesso ao sistema de gestão de ativos do banco —
subiu de um Risk Score habitual de 8 para 34. Um delta pequeno, dentro do esperado para
"anomalia de horário", e nenhum alerta YARA-L havia disparado. O analista de plantão marcou
o evento como "observar" e seguiu para os alertas mais urgentes da fila.

O que o time não sabia era que, três dias antes, um e-mail cuidadosamente elaborado havia
chegado na caixa de marcos.pereira. O assunto: "Proposta de Integração Técnica — Parceria
Estratégica com Banco Central". O remetente: um domínio criado há 11 dias imitando o BACEN.
O anexo: um PDF que explorava uma vulnerabilidade no Adobe Reader e instalava um stager do
Cobalt Strike em segundo plano, enquanto exibia a proposta legítima na tela. Marcos havia
aberto o e-mail em seu notebook corporativo, em casa, conectado via VPN. O EDR havia detectado
uma "atividade suspeita de processo filho" mas o alerta, de severidade MEDIUM, estava na fila
de triagem havia 71 horas sem toque.

Nas próximas horas, você, como threat hunter e analista sênior do SOC, vai reconstruir,
detectar e responder à "Operação Antas" — o nome que o time de IR do Banco Meridian dará a
este incidente. A investigação vai exigir tudo que você aprendeu: UDM Search avançado,
YARA-L, UEBA, Threat Intelligence e SOAR.

### 1.2 Caracterização do Atacante

```
PERFIL DO AMEAÇA — OPERAÇÃO ANTAS
════════════════════════════════════════════════════════════════════

  Atribuição:     Grupo APT-FIN-BR (designação interna do Banco Meridian)
                  Provável nexo: crime financeiro organizado
                  Região suspeita: Europa Oriental (infraestrutura em Moldova e Romênia)

  Histórico:      Ataques a 3 bancos brasileiros tier 2 em 2025–2026
                  Foco: exfiltração de relatórios financeiros e dados de clientes

  TTPs principais:
  ├── T1566.001  Spearphishing com PDF armado (Adobe Reader exploit)
  ├── T1078      Uso de credenciais válidas comprometidas
  ├── T1039      Acesso a dados compartilhados (Cloud Storage / SharePoint)
  ├── T1098      Criação de conta admin para persistência
  ├── T1071.001  C2 via HTTPS (Cobalt Strike Beacon sobre HTTPS)
  └── T1048      Exfiltração via HTTPS para servidor em Moldova

════════════════════════════════════════════════════════════════════
```

---

## 2. Kill Chain Completa da Operação Antas

O aluno deve detectar e documentar cada fase da kill chain:

### Fase 1: Comprometimento Inicial (T1566.001)

```
DATA/HORA:  2026-04-21 T19:43:22Z (terça, 16:43 BRT)

EVENTO:
  marcos.pereira abriu o arquivo "Proposta_Parceria_BACEN_v2.pdf" em
  seu notebook corporativo (WRK-MARCOS-015), conectado via VPN corporativa.

  O PDF explorou CVE-2026-0891 (vulnerabilidade hipotética do Adobe Reader).
  Processo filho criado: rundll32.exe lançado por AcroRd32.exe.
  Processo de stager do Cobalt Strike carregado em memória via RunDLL32.

LOGS DISPONÍVEIS:
  - EDR: PROCESS_LAUNCH — AcroRd32.exe → rundll32.exe (Sysmon EID 1)
  - EDR: NETWORK_CONNECTION — rundll32.exe → 91.234.55.172:443 (primeira conexão C2)
  - EDR alerta: "Suspicious child process" — severidade MEDIUM (71h na fila sem triagem)

IOCs:
  - Hash do PDF: b3a7f2c1d8e4509a6b2f1e9d3c8a0f7e (SHA256)
  - Processo suspeito: rundll32.exe (PID 4421, pai: AcroRd32.exe)
  - IP C2: 91.234.55.172 (Moldova)
```

### Fase 2: Login Suspeito via IP Externo (T1078)

```
DATA/HORA:  2026-04-22 T00:12:04Z (quarta, 21:12 BRT)

EVENTO:
  A sessão VPN de marcos.pereira foi encerrada às 20:15.
  Às 21:12, novo login ao portal Azure AD do Banco Meridian a partir do IP
  185.220.101.33 — servidor de VPS em Frankfurt, Alemanha.
  Login bem-sucedido com as credenciais de marcos.pereira.
  MFA foi contornado — token MFA roubado via Cobalt Strike (browser session hijacking).

LOGS DISPONÍVEIS:
  - Azure AD: USER_LOGIN — ALLOW — marcos.pereira — 185.220.101.33 (Alemanha)
  - Azure AD: MFA challenge — SUCCESS (token roubado)
  - UEBA: anomalia de geolocalização — Risk Score: 8 → 34

IOCs:
  - IP de login: 185.220.101.33 (presente na base Mandiant: APT-FIN-BR)
  - Timestamp: fora do horário habitual de marcos.pereira (21:12 BRT)
```

### Fase 3: Acesso a Dados Sensíveis no Cloud Storage (T1039)

```
DATA/HORA:  2026-04-22 T00:18:41Z → T00:47:33Z

EVENTO:
  Após login no portal Azure, o atacante navegou diretamente para o SharePoint
  do Banco Meridian, pasta "Relatórios Financeiros / Q4 2025 / Consolidado".
  Acessou e fez download de 23 arquivos XLSX e 4 PDFs de relatórios financeiros
  consolidados do Q4 2025, totalizando 847 MB.

LOGS DISPONÍVEIS:
  - Microsoft 365 Audit: FILE_READ — marcos.pereira — 27 arquivos financeiros
  - Microsoft 365 Audit: FILE_DOWNLOAD (BULK) — 847 MB em 28 minutos
  - UEBA: anomalia de volume — acesso 170x acima do baseline diário de marcos.pereira

IOCs:
  - Volume anômalo: 847 MB (baseline: ~5 MB/dia para este usuário)
  - Horário anômalo: 21:18–21:47 BRT (baseline: nunca acessa após 20h)
  - Arquivos acessados: pasta /Financeiro/Q4-2025/ (nunca acessada antes)
```

### Fase 4: Criação de Conta Admin Backdoor (T1098)

```
DATA/HORA:  2026-04-22 T01:05:17Z (22:05 BRT)

EVENTO:
  Usando o acesso comprometido de marcos.pereira (que tem permissão de
  co-administrador de uma aplicação de gestão de ativos), o atacante criou
  uma nova conta de serviço no Azure AD:
  Nome: svc-integration-api01@bancomeridian.com.br
  Grupo: Domain Admins (adicionado manualmente)

LOGS DISPONÍVEIS:
  - Azure AD: USER_CREATION — marcos.pereira criou svc-integration-api01
  - Azure AD: USER_CHANGE_PERMISSIONS — svc-integration-api01 adicionado a Domain Admins
  - YARA-L: regra "privilege_escalation_criacao_conta_admin" DISPAROU (1h de delay de triagem)

IOCs:
  - Nova conta: svc-integration-api01@bancomeridian.com.br
  - Criada por: marcos.pereira (conta comprometida)
  - Adicionada a: Domain Admins
```

### Fase 5: C2 Beaconing para Moldova (T1071.001)

```
DATA/HORA:  2026-04-21 T20:43:22Z → 2026-04-24 T08:00:00Z (contínuo)

EVENTO:
  O Cobalt Strike Beacon em WRK-MARCOS-015 manteve comunicação C2 com o servidor
  91.234.55.172 (Moldova) continuamente por 3 dias e 11 horas.
  Intervalo médio de check-in: 60 segundos (± 8 segundos de jitter).
  Total de conexões C2: 4.728 conexões HTTPS na porta 443.
  Dados enviados por conexão: 256–312 bytes (comandos do operador).
  Dados recebidos por conexão: 128–192 bytes (heartbeat).

LOGS DISPONÍVEIS:
  - Firewall PAN-OS: 4.728 conexões HTTPS para 91.234.55.172
  - UEBA: host WRK-MARCOS-015 — Risk Score: 12 → 91 (alto volume de conexões externas)
  - YARA-L: regra "c2_beaconing_periodicidade" disparou na manhã de 2026-04-24 (72h late)

IOCs:
  - IP C2: 91.234.55.172 (Moldova — AutAS31975 — Frantech Solutions)
  - Porta: 443/TCP
  - Processo: rundll32.exe (parent: AcroRd32.exe)
  - Certificado TLS: auto-assinado, CN="Microsoft Update Service"
```

### Fase 6: Exfiltração de 4,7 GB via HTTPS (T1048)

```
DATA/HORA:  2026-04-22 T01:47:00Z → T02:31:15Z

EVENTO:
  Após coletar os dados, o atacante iniciou a exfiltração direta via HTTPS
  para um segundo servidor em Romania: 185.196.8.143 (Hostkey Romania).
  Os 847 MB do SharePoint + dados adicionais de e-mails e calendário foram
  comprimidos e exfiltrados em 10 sessões de 470 MB cada.
  Total exfiltrado: 4,7 GB em 44 minutos.

LOGS DISPONÍVEIS:
  - Firewall PAN-OS: 10 conexões HTTPS para 185.196.8.143, totalizando 4,7 GB enviados
  - DLP (se disponível): alerta de transferência em massa acima do threshold
  - UEBA: anomalia de volume de rede — host WRK-MARCOS-015, Risk Score → 96

IOCs:
  - IP de exfiltração: 185.196.8.143 (Romania — Hostkey)
  - Volume: 4,7 GB em 44 minutos
  - Horário: 22:47–23:31 BRT (fora do horário comercial)
```

---

## 3. Entregáveis do Capstone

### Entregável 1: Timeline Completa do Incidente

O aluno deve produzir uma tabela com todos os eventos identificados, no formato:

| Timestamp (UTC)       | Evento                                              | Técnica MITRE | Fonte de Log            | Severidade    |
|:----------------------|:----------------------------------------------------|:-------------:|:------------------------|:-------------:|
| 2026-04-21 19:43:22   | Abertura do PDF malicioso em WRK-MARCOS-015         | T1566.001     | SYSMON/CROWDSTRIKE      | HIGH          |
| 2026-04-21 19:43:35   | Processo filho: AcroRd32.exe → rundll32.exe         | T1059         | SYSMON EID 1            | HIGH          |
| 2026-04-21 20:43:22   | 1ª conexão C2 para 91.234.55.172:443                | T1071.001     | PAN_FIREWALL            | HIGH          |
| 2026-04-22 00:12:04   | Login de marcos.pereira a partir de 185.220.101.33  | T1078         | AZURE_AD                | CRITICAL      |
| 2026-04-22 00:18:41   | Acesso ao SharePoint — pasta Financeiro/Q4-2025     | T1039         | M365_AUDIT              | HIGH          |
| 2026-04-22 00:47:33   | Download de 847 MB de relatórios financeiros Q4     | T1039/T1530   | M365_AUDIT              | CRITICAL      |
| 2026-04-22 01:05:17   | Criação da conta svc-integration-api01              | T1098/T1136   | AZURE_AD                | CRITICAL      |
| 2026-04-22 01:12:44   | svc-integration-api01 adicionado a Domain Admins    | T1098         | AZURE_AD                | CRITICAL      |
| 2026-04-22 01:47:00   | Início da exfiltração para 185.196.8.143            | T1048         | PAN_FIREWALL            | CRITICAL      |
| 2026-04-22 02:31:15   | Fim da exfiltração — 4,7 GB transferidos            | T1048         | PAN_FIREWALL            | CRITICAL      |
| 2026-04-21→24 (cont.) | Beaconing C2 contínuo — 4.728 conexões              | T1071.001     | PAN_FIREWALL            | HIGH          |
| 2026-04-24 08:17:33   | Alerta YARA-L c2_beaconing disparado (72h late)     | —             | YARA-L DETECTION        | HIGH          |

### Entregável 2: Relatório de Incidente (Formato NIST SP 800-61)

O relatório deve ter as seções obrigatórias do NIST SP 800-61 Rev. 3:

```
RELATÓRIO DE INCIDENTE — OPERAÇÃO ANTAS
════════════════════════════════════════════════════════════════════

1. IDENTIFICAÇÃO DO INCIDENTE
   ID: INC-2026-04-0047
   Data de detecção: 2026-04-24 08:17 BRT
   Data de início estimada: 2026-04-21 16:43 BRT
   Classificação: APT — Exfiltração de Dados Financeiros
   Criticidade: P1 — CRÍTICO

2. RESUMO EXECUTIVO
   [3–5 parágrafos descrevendo o incidente, impacto e resposta]

3. LINHA DO TEMPO (ver Entregável 1)

4. INDICADORES DE COMPROMETIMENTO
   4.1 Indicadores de Host
     - Hash PDF malicioso: b3a7f2c1...
     - Processo suspeito: rundll32.exe (parent AcroRd32.exe)
     - Conta backdoor: svc-integration-api01@bancomeridian.com.br
   4.2 Indicadores de Rede
     - IP C2: 91.234.55.172 (Moldova)
     - IP Exfiltração: 185.196.8.143 (Romania)
     - Domínio phishing: [identificado pelo aluno]

5. ANÁLISE DE IMPACTO
   - Dados comprometidos: relatórios financeiros Q4 2025 (4,7 GB)
   - Usuários afetados: marcos.pereira (credencial comprometida)
   - Infraestrutura afetada: WRK-MARCOS-015, conta admin backdoor

6. AÇÕES DE CONTENÇÃO EXECUTADAS
   [cronograma das ações tomadas durante a resposta]

7. ANÁLISE DE CAUSA RAIZ
   [por que o incidente aconteceu, falhas de controle identificadas]

8. LIÇÕES APRENDIDAS E RECOMENDAÇÕES
   [pelo menos 5 ações de melhoria concretas]

════════════════════════════════════════════════════════════════════
```

### Entregável 3: Três Regras YARA-L Criadas Durante o Exercício

O aluno deve criar (ou melhorar a partir das regras dos módulos anteriores) as seguintes regras:

**Regra 1:** Detecção de beaconing C2 específico para o perfil do Cobalt Strike Beacon
(baseada na regra do Módulo 03, mas com refinamentos baseados nos IOCs descobertos)

**Regra 2:** Detecção de criação de conta admin por usuário não-administrador
(baseada no Exemplo 5 do Módulo 03, mas calibrada para o ambiente do Banco Meridian)

**Regra 3:** Detecção de exfiltração em massa via HTTPS (nova regra, baseada no hunting do Capstone):

```yara-l
// Template base — o aluno deve completar e calibrar
rule exfiltracao_massa_https {
  meta:
    author = "[ALUNO]"
    description = "Exfiltração de grandes volumes via HTTPS para IPs externos"
    severity = "CRITICAL"
    mitre_attack_technique = "T1048"
    // [completar campos restantes]

  events:
    $e1.metadata.event_type = "NETWORK_CONNECTION"
    $e1.network.direction = "OUTBOUND"
    $e1.target.port = 443
    // [completar: excluir IPs internos]
    // [completar: excluir CDNs legítimos]
    $e1.principal.hostname = $host_origem

  match:
    $host_origem over 1h

  condition:
    // [completar: threshold de bytes que indica exfiltração]
    // Dica: 4,7 GB = 5.046.586.982 bytes — qual threshold faz sentido?

  outcome:
    // [completar: campos relevantes para o alerta]
}
```

### Entregável 4: Playbook SOAR de Response

O aluno deve criar um playbook de response para o incidente completo da Operação Antas,
integrando os três playbooks do Módulo 06 em um único fluxo orquestrado para APT.

O playbook deve cobrir:
1. Isolamento do host WRK-MARCOS-015
2. Revogação das credenciais de marcos.pereira
3. Desabilitação da conta backdoor svc-integration-api01
4. Bloqueio dos IPs de C2 e exfiltração no firewall
5. Notificação ao CISO e ao time de IR
6. Criação de ticket P1 no Jira com todos os IOCs

---

## 4. Rubrica de Avaliação

| Entregável                  | Critério                                                                         | Pontuação   |
|:----------------------------|:---------------------------------------------------------------------------------|:-----------:|
| **Timeline do Incidente**   | Todos os 12 eventos documentados com timestamp, técnica MITRE e fonte correta   | 0–25 pts    |
| **Timeline do Incidente**   | Eventos em ordem cronológica, sem gaps na narrativa                              | 0–5 pts     |
| **Relatório NIST SP 800-61**| Todas as 8 seções obrigatórias presentes e preenchidas                          | 0–20 pts    |
| **Relatório NIST SP 800-61**| Análise de causa raiz com pelo menos 3 falhas de controle identificadas          | 0–10 pts    |
| **Relatório NIST SP 800-61**| Lições aprendidas com pelo menos 5 recomendações concretas e implementáveis      | 0–10 pts    |
| **Regras YARA-L (3)**       | Cada regra salva e sem erros de sintaxe (5 pts cada)                            | 0–15 pts    |
| **Regras YARA-L (3)**       | Retrohunt de cada regra retorna as detecções esperadas do capstone              | 0–10 pts    |
| **Playbook SOAR**           | Playbook criado e ativado sem erros                                              | 0–10 pts    |
| **Playbook SOAR**           | Cobre os 6 passos obrigatórios descritos na seção 3 (Entregável 4)             | 0–15 pts    |
| **Defesa (Live)**           | Apresentação clara e estruturada da timeline e das regras criadas               | 0–20 pts    |
| **Defesa (Live)**           | Resposta a perguntas técnicas do instrutor sobre decisões de design             | 0–10 pts    |
| **TOTAL**                   |                                                                                  | **0–150 pts**|

| Pontuação Total | Resultado                                              |
|:--------------:|:-------------------------------------------------------|
| 135–150 (90%+) | Distinção — Aprovado com excelência                   |
| 112–134 (75%+) | Aprovado — Apto para certificação                      |
| 90–111 (60%+)  | Aprovado com ressalvas — revisitar pontos específicos  |
| < 90 (< 60%)   | Não aprovado — re-submissão necessária                 |

---

## 5. Gabarito Completo do Capstone

### 5.1 Gabarito da Timeline

A timeline completa está documentada na seção 2 deste módulo (fases 1–6).
O aluno deve identificar todos os 12 eventos principais. Eventos intermediários
(como as 4.728 conexões de C2) são agrupados como uma entrada única na timeline.

**Checklist de descoberta para o aluno:**

- [ ] Alerta EDR de processo filho (AcroRd32.exe → rundll32.exe)
- [ ] 1ª conexão C2 para 91.234.55.172
- [ ] Login anômalo de 185.220.101.33 (Alemanha)
- [ ] Acesso ao SharePoint /Financeiro/Q4-2025/
- [ ] Download de 847 MB (27 arquivos)
- [ ] Criação de svc-integration-api01
- [ ] Adição ao grupo Domain Admins
- [ ] Exfiltração de 4,7 GB para 185.196.8.143
- [ ] Beaconing C2 contínuo (3d 11h)
- [ ] Correlação: alerta YARA-L criado durante o capstone

### 5.2 Gabarito das Regras YARA-L de Referência

#### Regra de Referência: Exfiltração em Massa via HTTPS

```yara-l
rule exfiltracao_massa_https {
  meta:
    author = "SOC — Banco Meridian"
    description = "Detecta exfiltração de dados em massa via HTTPS: >= 1 GB enviado para IP externo em 1 hora"
    severity = "CRITICAL"
    priority = "CRITICAL"
    mitre_attack_tactic = "Exfiltration"
    mitre_attack_technique = "T1048"
    mitre_attack_technique_name = "Exfiltration Over Alternative Protocol"
    created_date = "2026-04-24"
    version = "1.0"
    false_positives = "Backups em nuvem legítimos; uploads a CDN corporativa; grandes transferências de VPN"

  events:
    $e1.metadata.event_type = "NETWORK_CONNECTION"
    $e1.network.direction = "OUTBOUND"
    $e1.target.port = 443

    // Excluir tráfego RFC1918 (interno)
    not $e1.target.ip = "10.0.0.0/8"
    not $e1.target.ip = "172.16.0.0/12"
    not $e1.target.ip = "192.168.0.0/16"

    // Excluir CDNs e serviços legítimos conhecidos
    not $e1.target.ip in %watchlist_ips_cdn_backup_corporativo

    // Correlacionar por host de origem
    $e1.principal.hostname = $host_origem

  match:
    $host_origem over 1h

  condition:
    // Mais de 1 GB enviado em 1 hora para IPs externos (excluindo CDNs)
    sum($e1.network.sent_bytes) >= 1073741824

  outcome:
    $host_alerta = $host_origem
    $bytes_exfiltrados = sum($e1.network.sent_bytes)
    $gb_exfiltrados = sum($e1.network.sent_bytes) / 1073741824
    $ips_destino = array_distinct($e1.target.ip)
    $total_conexoes = count($e1)
    $inicio = min($e1.metadata.event_timestamp)
    $fim = max($e1.metadata.event_timestamp)
    $processo_originador = $e1.principal.process.file.full_path
    $risk_score = 95
    $severity = "CRITICAL"
}
```

### 5.3 Gabarito do Relatório de Incidente (Modelo)

**Seção 7 — Análise de Causa Raiz (modelo):**

A Operação Antas foi possível por três falhas de controle principais:

1. **Alerta de EDR não triado por 71 horas:** o alerta "Suspicious child process" de severidade
MEDIUM ficou na fila sem triagem. Causa: SLA de triagem não definido para severidade MEDIUM;
falta de automação de escalada por tempo.

2. **Regra de C2 beaconing não ativa no momento do incidente:** a regra foi criada durante o
treinamento do Módulo 03 mas não foi ativada como Live Rule antes do capstone. O beaconing
ocorreu por 72 horas sem detecção. Causa: processo de go-live de regras não documentado.

3. **MFA contornado sem alerta:** o roubo de token de MFA via Cobalt Strike não gerou alerta.
Causa: ausência de detecção de login com token em localização diferente do último token válido.

**Seção 8 — Lições Aprendidas (modelo):**

1. Definir SLA de triagem para alertas MEDIUM: máximo 4 horas (automação de escalada após timeout)
2. Criar processo formal de go-live de regras: Retrohunt → aprovação → Live Rule (checklist)
3. Implementar alerta de "impossible travel" no UEBA/Azure AD (mesmo MFA, IP diferente = alerta)
4. Revisar permissões de criação de usuário: marcos.pereira não deveria poder criar contas admin
5. Implementar DLP com alerta automático para download > 100 MB de pastas classificadas

---

## 6. Roteiro para o Instrutor: Sessão Live de Defesa do Capstone

### 6.1 Estrutura da Sessão (120 min)

```
SESSÃO LIVE — DEFESA DO CAPSTONE
════════════════════════════════════════════════════════════════════

  00:00 – 10:00  Abertura e instruções
    - Apresentar o formato da defesa
    - Confirmar que todos os alunos enviaram os entregáveis
    - Dividir a turma em duplas para peer-review enquanto aguardam

  10:00 – 70:00  Defesas individuais (ou em dupla, conforme turma)
    - Cada aluno tem 8–10 minutos para apresentar:
      • Timeline: "O que aconteceu, quando e como você descobriu"
      • 1 regra YARA-L: mostrar no editor, explicar a lógica
      • Playbook: mostrar no Designer, explicar uma decisão de design
    - 3–5 minutos de perguntas do instrutor

  70:00 – 100:00 Revisão coletiva com gabarito
    - Instrutor apresenta a timeline oficial no telão
    - Comparar com o que os alunos encontraram
    - Discutir os gaps de detecção (por que o beaconing ficou 72h sem alerta)

  100:00 – 115:00 Discussão: "O que mudaria no SOC do Banco Meridian?"
    - Lição 1: SLA de triagem por severidade
    - Lição 2: processo de go-live de regras
    - Lição 3: controles compensatórios (DLP, Impossible Travel)

  115:00 – 120:00 Encerramento e próximos passos
    - Anúncio das notas
    - Preview do Curso 2 (Azure SecOps Essentials)
    - Entrega dos certificados de conclusão

════════════════════════════════════════════════════════════════════
```

### 6.2 Perguntas de Sondagem para a Defesa

O instrutor deve usar estas perguntas para avaliar a profundidade do entendimento:

**Sobre a Timeline:**
- "Por que o alerta do EDR ficou 71 horas sem triagem? O que você mudaria no processo de SOC?"
- "Qual foi o gap entre o comprometimento inicial e o primeiro alerta YARA-L? O que isso indica?"

**Sobre as Regras YARA-L:**
- "Por que você escolhou esse threshold de bytes para a regra de exfiltração?"
- "O que aconteceria se eu adicionasse um servidor de backup legítimo que faz upload de 2 GB/hora?"
- "Mostre-me como adicionar uma exclusão para esse servidor de backup sem alterar a lógica da regra"

**Sobre o Playbook SOAR:**
- "Por que você incluiu um bloco de aprovação humana antes de desabilitar a conta de marcos.pereira?"
- "O que acontece se a action de isolamento do EDR falhar? Seu playbook trata esse cenário?"
- "Como você mediria o MTTR deste incidente com e sem o playbook automatizado?"

**Sobre Threat Intelligence:**
- "Você consultou a Mandiant para o IP 91.234.55.172 durante o hunting. O que ela retornou?"
- "O atacante poderia mudar o IP de C2 e contornar suas regras baseadas em IP. Como você tornaria a detecção mais durável?"

### 6.3 Critérios de Aprovação na Defesa

| Aspecto               | Aprovado                                              | Não aprovado                                        |
|:----------------------|:------------------------------------------------------|:----------------------------------------------------|
| **Timeline**          | Identifica > 8 dos 12 eventos com técnica MITRE correta | < 6 eventos ou técnicas sistematicamente erradas  |
| **Regra YARA-L**      | Explica a lógica da condição e os motivos das exclusões | Não consegue explicar por que o threshold foi escolhido |
| **Playbook**          | Explica ao menos 3 decisões de design do playbook      | Playbook copiado sem compreensão das decisões      |
| **Perguntas**         | Responde 3 de 5 perguntas com raciocínio claro         | Responde < 2 perguntas ou respostas superficiais    |

---

*Módulo 07 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 06 — SOAR e Playbooks](../modulo-06-soar-playbooks/README.md)*
*Laboratório: [Lab 05 — Capstone](../../laboratorios/lab-05-capstone/README.md)*
