# Lab 03 — Threat Hunting: C2 Beaconing em WRK-RODRIGO-011
## Curso 1: Google SecOps Essentials · CECyber

| Campo                | Detalhe                                                                |
|:---------------------|:-----------------------------------------------------------------------|
| **Duração**          | 2 horas                                                                |
| **Módulo relacionado**| Módulo 04 — Threat Hunting e UEBA                                     |
| **Tipo**             | Hands-on · Individual                                                  |
| **MITRE ATT&CK**     | T1071.001 (Application Layer Protocol: Web Protocols), T1132 (Data Encoding) |
| **Pré-requisito**    | Lab 02 concluído · Módulo 04 concluído                                 |
| **Ferramentas**      | Google SecOps UDM Search, UEBA, Risk Analytics, Timeline View          |

---

## 1. Contexto Situacional

Três semanas se passaram desde o incidente de password spray contra o Banco Meridian. O time
de SOC estava calibrando as regras YARA-L criadas durante o Lab 02 e monitorando os novos
alertas quando Carolina, a analista de UEBA do time, chamou a atenção para algo peculiar.

**E-mail recebido às 14:23 de uma segunda-feira:**

*De: Sistema UEBA — Google SecOps*
*Para: soc-alerts@bancomeridian.com.br*
*Assunto: [ALERT] Risk Score crítico — WRK-RODRIGO-011 — Score: 89*

*O host WRK-RODRIGO-011 teve seu Risk Score elevado de 12 para 89 nos últimos 5 dias.
Principais contribuintes: volume anômalo de conexões de rede de saída (1.847 conexões
para o mesmo IP externo nos últimos 3 dias), variação mínima no tamanho dos pacotes,
conexões fora do horário comercial. Recomenda-se investigação imediata.*

O host `WRK-RODRIGO-011` pertence a **Rodrigo Andrade**, analista de back-office responsável
pelo setor de conformidade regulatória. Rodrigo trabalha de segunda a sexta, das 9h às 18h,
e raramente acessa sistemas fora do horário. Seu perfil de rede habitual é navegação web
no SharePoint, Teams e sistema de gestão de conformidade (GRC).

Nenhuma regra YARA-L disparou para este host nos últimos 5 dias — as comunicações
individualmente são HTTPS legítimas para a porta 443. Mas o UEBA identificou o padrão
comportamental anômalo que as regras point-in-time não conseguiram capturar.

Sua missão: investigar o host WRK-RODRIGO-011, determinar se o comportamento é C2
beaconing real ou um falso positivo do UEBA, e documentar os IOCs extraídos.

---

## 2. Situação Inicial

Ao começar o lab, o ambiente está configurado da seguinte forma:

```
ESTADO DO AMBIENTE BANCO MERIDIAN — LAB 03
════════════════════════════════════════════════════════════════════

  Risk Analytics Dashboard (hoje, 14:30 BRT):
  ─────────────────────────────────────────────
  Entidade           Risk Score  Variação 5d  Status
  WRK-RODRIGO-011        89        +77        ⚠️ CRITICAL
  diana.ferreira         45        +45        ⚠️ HIGH
  WRK-ANA-003            22        +12        LOW
  marco.fernandes        18         +5        LOW

  Live Rules ativas:
  ─────────────────────────────────────────────
  password_spray_detection    → ativo
  login_fora_horario          → ativo
  c2_beaconing_periodicidade  → ativo (desde ontem — SEM DISPAROS para WRK-RODRIGO-011)

  Feeds de TI:
  ─────────────────────────────────────────────
  Mandiant TI Feed     → HEALTHY
  VirusTotal Augment   → HEALTHY
  MISP Community Feed  → HEALTHY

════════════════════════════════════════════════════════════════════
```

---

## 3. Problema Identificado

Carolina, analista L2, compartilhou as seguintes observações preliminares:

*"Olhei rapidamente os dados do WRK-RODRIGO-011. O UEBA está apontando 1.847 conexões
para o IP 91.234.55.172 nos últimos 3 dias. Esse IP é de um range em Moldova. Tentei ver
no VirusTotal mas o IP não aparece como malicioso ainda. Pode ser falso positivo — Rodrigo
tem um software de backup que eu não conheço? Ou pode ser algo real. Preciso que você
investigue com mais profundidade usando as técnicas de hunting que aprendemos."*

A regra `c2_beaconing_periodicidade` ativa desde ontem NÃO disparou para este host, apesar
das 1.847 conexões. Isso é um sinal: ou o threshold da regra está alto demais, ou há alguma
diferença no padrão que a regra não está capturando.

---

## 4. Roteiro de Atividades

| Etapa | Atividade                                              | Tempo estimado |
|:-----:|:-------------------------------------------------------|:--------------:|
| A     | Investigação inicial via UDM Search e UEBA             | 35 min         |
| B     | Análise estatística de periodicidade                   | 30 min         |
| C     | Pivoting: IP → Processo → Usuário → Timeline           | 25 min         |
| D     | Enriquecimento com TI e conclusão                      | 15 min         |
| E     | Documentação e IOCs                                    | 15 min         |

---

## 5. Proposição do Lab

**Objetivo:** Investigar o comportamento de rede anômalo do host WRK-RODRIGO-011 e determinar
se é C2 beaconing (Cobalt Strike) ou falso positivo, extraindo IOCs e documentando a conclusão.

**Critério de sucesso:**
- Identificação conclusiva: beaconing confirmado ou descartado com evidências
- Processo responsável pelo beaconing identificado (nome do executável + PID)
- Análise estatística de periodicidade documentada (intervalo médio + desvio padrão)
- IOCs extraídos (IP, processo, hash se disponível)
- Ajuste na regra YARA-L para cobrir este caso

---

## 6. Script Passo a Passo

### PARTE A — Investigação Inicial via UDM Search e UEBA (35 min)

---

#### Passo 1: Acessar o Risk Analytics e verificar o contexto do host

**Ação:** Navegar para o painel de Risk Analytics e examinar o perfil do host WRK-RODRIGO-011.

```
Navegação: Detection → Risk Analytics → Risky Hosts → WRK-RODRIGO-011

Campos a observar:
- Risk Score: 89
- Score history (gráfico de 30 dias): quando começou a subir?
- Top contributing alerts: quais eventos mais contribuíram para o score?
- Associated users: quais usuários estão logados neste host?
```

**Resultado esperado:** Você verá que:
- O Risk Score começou a subir há exatamente 5 dias (um sábado às 23:17 — fora do horário comercial)
- A maior contribuição é "Volume anômalo de conexões para IP externo único"
- O usuário associado é `rodrigo.andrade`

**O que verificar:** Anotar o timestamp exato em que o score começou a subir — isso é
a provável data/hora de comprometimento inicial.

**O que fazer se der errado:**
- Se WRK-RODRIGO-011 não aparecer no Risk Analytics, verifique se o período selecionado
  inclui os últimos 7 dias
- Se o Risk Score aparecer baixo (< 50), verifique se está vendo o host correto —
  pode haver outro com nome similar

---

#### Passo 2: Analisar as conexões de rede do host via UDM Search

**Ação:** Executar query UDM para ver todas as conexões de saída do host nos últimos 7 dias.

```
Navegação: Search → UDM Search

Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "NETWORK_CONNECTION" AND
network.direction = "OUTBOUND"
```

Selecionar período: "Last 7 days"

**Resultado esperado:** Lista de conexões de saída. Você verá um volume alto de conexões
para o IP `91.234.55.172`, com timestamps distribuídos ao longo de todos os dias, incluindo
finais de semana e madrugadas.

**O que verificar:**
- O IP `91.234.55.172` aparece com quantas conexões?
- Esse IP aparece também em madrugadas e finais de semana?
- Quais outras conexões existem? São para domínios reconhecíveis (Microsoft, Google)?

---

#### Passo 3: Agrupar conexões por IP de destino para identificar o padrão

**Ação:** Usar agregação para encontrar os IPs com maior volume de conexões.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "NETWORK_CONNECTION" AND
network.direction = "OUTBOUND" AND
NOT target.ip = "10.0.0.0/8" AND
NOT target.ip = "172.16.0.0/12" AND
NOT target.ip = "192.168.0.0/16"
| group_by target.ip
| aggregate count() as total_conexoes, sum(network.sent_bytes) as bytes_enviados
| order_by total_conexoes desc
| head 20
```

**Resultado esperado:**

```
IP destino          | total_conexoes | bytes_enviados
─────────────────────────────────────────────────────
91.234.55.172       |      1847      |    472.576
52.96.123.45        |        47      |  1.047.552    ← Microsoft (Office 365)
104.16.45.88        |        32      |    819.200    ← Cloudflare (legítimo)
20.190.160.10       |        28      |    655.360    ← Microsoft (Azure AD)
13.107.21.200       |        15      |    307.200    ← Microsoft (Teams)
```

**O que verificar:**
- O IP `91.234.55.172` deve ter um volume de conexões MUITO acima dos demais
- Os bytes enviados por conexão para `91.234.55.172` devem ser muito pequenos (pacotes de heartbeat)
- Os IPs da Microsoft/Cloudflare são legítimos e têm bytes variados (comportamento humano)

**O que fazer se der errado:**
- Se `91.234.55.172` não aparecer, ajuste o período para "Last 30 days"
- Se o IP aparecer com poucos bytes por conexão (< 1KB), isso é um sinal FORTE de beaconing
  — pacotes de heartbeat são pequenos e regulares

---

#### Passo 4: Calcular as conexões por hora para identificar o padrão 24x7

**Ação:** Agrupar as conexões para `91.234.55.172` por hora do dia para verificar
se ocorrem 24x7 (sinal de C2) ou apenas durante o horário comercial (legítimo).

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| group_by metadata.event_timestamp.hours
| order_by metadata.event_timestamp.hours asc
```

**Resultado esperado:**

```
Hora (UTC-3)  | count
──────────────────────
00            |   77    ← conexões à meia-noite!
01            |   79
02            |   76
03            |   78
...
09            |   77    ← horário comercial início
10            |   78
...
18            |   76
19            |   78
...
23            |   77    ← conexões à meia-noite!
```

**O que verificar:** O volume de conexões por hora deve ser MUITO UNIFORME ao longo das
24 horas — isso é a periodicidade mecânica do malware. Se fosse um software legítimo de
backup ou atualização, as conexões estariam concentradas em janelas específicas.

---

### PARTE B — Análise Estatística de Periodicidade (30 min)

---

#### Passo 5: Extrair os timestamps das conexões para análise de intervalo

**Ação:** Obter a lista de timestamps das conexões em ordem cronológica.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| order_by metadata.event_timestamp asc
```

**Resultado esperado:** Lista de 1.847 conexões em ordem cronológica. Exportar para CSV
clicando no botão "Export" no canto superior direito da tabela de resultados.

---

#### Passo 6: Calcular o intervalo médio entre conexões

**Ação:** Usando os timestamps exportados, calcular a análise estatística dos intervalos.

Se você tem acesso a Python no ambiente de lab, use o seguinte script:

```python
#!/usr/bin/env python3
# Análise de beaconing — Lab 03 — Google SecOps Essentials

import csv
import statistics
from datetime import datetime

# Carregar timestamps do arquivo exportado
timestamps = []
with open('beaconing_timestamps.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        ts = datetime.fromisoformat(row['metadata.event_timestamp'].replace('Z', '+00:00'))
        timestamps.append(ts)

# Ordenar por timestamp
timestamps.sort()

# Calcular intervalos entre conexões consecutivas (em segundos)
intervalos = []
for i in range(1, len(timestamps)):
    delta = (timestamps[i] - timestamps[i-1]).total_seconds()
    intervalos.append(delta)

# Estatísticas
media = statistics.mean(intervalos)
mediana = statistics.median(intervalos)
desvio_padrao = statistics.stdev(intervalos)
coef_variacao = (desvio_padrao / media) * 100

print(f"Total de conexões analisadas: {len(timestamps)}")
print(f"Período: {timestamps[0]} → {timestamps[-1]}")
print(f"\n=== ANÁLISE ESTATÍSTICA DOS INTERVALOS ===")
print(f"Intervalo médio:       {media:.1f} segundos ({media/60:.1f} minutos)")
print(f"Intervalo mediano:     {mediana:.1f} segundos")
print(f"Desvio padrão:         {desvio_padrao:.1f} segundos")
print(f"Coeficiente de variação: {coef_variacao:.1f}%")
print(f"\n=== DIAGNÓSTICO ===")
if coef_variacao < 15:
    print("⚠️  ALTA PERIODICIDADE DETECTADA — Muito provável C2 beaconing")
    print(f"   Intervalo mecânico de {media:.0f}s ± {desvio_padrao:.0f}s")
elif coef_variacao < 30:
    print("⚠️  PERIODICIDADE MODERADA — Possível C2 beaconing com jitter")
else:
    print("✓  Baixa periodicidade — Padrão consistente com tráfego legítimo")
```

**Resultado esperado da análise:**

```
Total de conexões analisadas: 1847
Período: 2026-04-19 23:17:03 → 2026-04-24 14:21:47

=== ANÁLISE ESTATÍSTICA DOS INTERVALOS ===
Intervalo médio:       61.3 segundos (1.0 minutos)
Intervalo mediano:     61.0 segundos
Desvio padrão:         4.7 segundos
Coeficiente de variação: 7.7%

=== DIAGNÓSTICO ===
⚠️  ALTA PERIODICIDADE DETECTADA — Muito provável C2 beaconing
   Intervalo mecânico de 61s ± 5s
```

**O que verificar:** Coeficiente de Variação (CV) < 15% é um indicador FORTE de C2
beaconing. Tráfego humano legítimo geralmente tem CV > 50%. Um intervalo de ~60 segundos
é consistente com o check-in padrão do Cobalt Strike Beacon.

**O que fazer se der errado:**
- Se não tiver Python disponível, calcule manualmente com os primeiros 20 intervalos:
  pegue os timestamps de 20 conexões consecutivas e calcule a diferença entre cada uma.
  Se todos forem entre 55–67 segundos, o diagnóstico é o mesmo.

---

#### Passo 7: Verificar a variação do tamanho dos pacotes

**Ação:** Analisar se o tamanho dos pacotes (bytes) é consistente entre as conexões.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| aggregate
    max(network.sent_bytes) as max_sent,
    min(network.sent_bytes) as min_sent,
    max(network.received_bytes) as max_recv,
    min(network.received_bytes) as min_recv
```

**Resultado esperado:**

```
max_sent:  312 bytes
min_sent:  256 bytes    ← variação de apenas 56 bytes
max_recv:  192 bytes
min_recv:  128 bytes    ← variação de apenas 64 bytes
```

**O que verificar:** Variação < 100 bytes nos tamanhos de pacote é um indicador de
C2 beaconing. O malware envia pacotes de check-in de tamanho fixo. Compare com os
pacotes para os IPs da Microsoft: eles têm variação de KB a MB.

---

### PARTE C — Pivoting: IP → Processo → Usuário → Timeline (25 min)

---

#### Passo 8: Identificar o processo responsável pelas conexões

**Ação:** Pivotar do IP de destino para o processo que está iniciando as conexões.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| group_by principal.process.file.full_path
| order_by count() desc
```

**Resultado esperado:**

```
Processo                                           | count
──────────────────────────────────────────────────────────
C:\Windows\System32\svchost.exe                   |  1847
```

**Análise:** `svchost.exe` é um processo legítimo do Windows, mas é frequentemente usado
por malware como "host" para injeção de código. Todas as 1.847 conexões de beaconing
partem do mesmo processo `svchost.exe`.

---

#### Passo 9: Verificar o processo pai do svchost suspeito

**Ação:** Investigar quem lançou este processo `svchost.exe` específico (processo pai).

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "PROCESS_LAUNCH" AND
target.process.file.full_path = "C:\\Windows\\System32\\svchost.exe"
```

**Resultado esperado:**

```
Evento:
  metadata.event_type:           PROCESS_LAUNCH
  metadata.event_timestamp:      2026-04-19T23:17:01Z   ← 2 segundos antes do 1º beacon!
  principal.process.file.full_path: C:\Users\rodrigo.andrade\AppData\Local\Temp\update_cfg.exe
  principal.process.pid:         8834
  target.process.file.full_path: C:\Windows\System32\svchost.exe
  target.process.pid:            9921
  target.process.command_line:   svchost.exe -k netsvcs -p
```

**O que verificar:** O processo pai do `svchost.exe` suspeito é `update_cfg.exe`, localizado
em `%TEMP%` — não é uma localização padrão para lançar processos do sistema. Isso é um
indicador claro de injeção/hollowing de processo pelo malware.

**O que fazer se der errado:**
- Se a query não retornar resultados, tente buscar por PID:
  `principal.process.pid = 9921 AND metadata.event_type = "PROCESS_LAUNCH"`

---

#### Passo 10: Investigar o arquivo suspeito update_cfg.exe

**Ação:** Verificar se o `update_cfg.exe` foi visto anteriormente e obter o hash para enriquecimento.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "FILE_CREATION" AND
target.file.full_path = /.*update_cfg\.exe.*/
```

**Resultado esperado:**

```
Evento FILE_CREATION:
  metadata.event_timestamp:    2026-04-19T23:16:54Z   ← criado 7s antes da 1ª conexão!
  principal.process.file.full_path: C:\Users\rodrigo.andrade\AppData\Roaming\...\AcroRd32.exe
  target.file.full_path:       C:\Users\rodrigo.andrade\AppData\Local\Temp\update_cfg.exe
  target.file.sha256:          4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1
  target.file.size:            892416  (872 KB)
```

**O que verificar:** O arquivo foi criado por `AcroRd32.exe` (Adobe Reader)! Isso confirma
o vetor de comprometimento: exploit no Adobe Reader → dropper → Cobalt Strike Beacon.

---

#### Passo 11: Pivotar do usuário para o Timeline View completo

**Ação:** Usar o Timeline View do Google SecOps para ver toda a atividade do usuário
`rodrigo.andrade` a partir da data de comprometimento.

```
Navegação: Search → Entities → buscar "rodrigo.andrade"
           Selecionar a entidade de usuário
           Aba "Timeline" → período: últimos 7 dias
```

**Resultado esperado:** Timeline completa mostrando:

| Timestamp (UTC)     | Evento                                            | Fonte         |
|:--------------------|:--------------------------------------------------|:--------------|
| 2026-04-19 23:16:47 | Abertura de PDF em WRK-RODRIGO-011               | CROWDSTRIKE   |
| 2026-04-19 23:16:54 | Criação de update_cfg.exe (dropper) em %TEMP%    | SYSMON        |
| 2026-04-19 23:17:01 | Lançamento de update_cfg.exe                     | SYSMON        |
| 2026-04-19 23:17:03 | 1ª conexão C2 para 91.234.55.172:443             | PAN_FIREWALL  |
| 2026-04-20 → 24     | 1.847 conexões C2 ao longo de 5 dias             | PAN_FIREWALL  |
| 2026-04-24 14:23    | Alerta UEBA disparado (Risk Score 89)            | UEBA          |

---

### PARTE D — Enriquecimento com TI e Conclusão (15 min)

---

#### Passo 12: Consultar o Mandiant sobre o IP de C2

**Ação:** Verificar o IP `91.234.55.172` na Threat Intelligence da Mandiant.

```
Navegação: Threat Intelligence → Indicators → buscar 91.234.55.172
```

**Resultado esperado:**

```
IP: 91.234.55.172
Confidence: HIGH
Threat Category: Command and Control
Infrastructure Type: VPS comercial (Frantech Solutions, Moldova)
Associated Malware: Cobalt Strike Beacon (HTTPS Malleable Profile)
Last Observed: 2026-04-23 (ontem)
Associated TTPs:
  - T1071.001 (Application Layer Protocol)
  - T1573.001 (Encrypted Channel: Symmetric Cryptography)
```

**O que verificar:** Confirmação da Mandiant de que o IP é infraestrutura C2 do Cobalt Strike.
Isso eleva a confiança do diagnóstico de CONFIRMADO para CERTO.

---

#### Passo 13: Consultar o VirusTotal para o hash do dropper

**Ação:** Verificar o hash do `update_cfg.exe` no VirusTotal.

```
Navegação: Threat Intelligence → VirusTotal → buscar hash
  4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1
```

**Resultado esperado:**

```
File: update_cfg.exe
SHA256: 4a7bc3d9...
Detection: 51/72 engines
Threat category: trojan
Threat name: CobaltStrike.Beacon.HTTPS
First seen: 2026-04-15
Last seen:  2026-04-23
Family: CobaltStrike
```

**O que verificar:** 51/72 engines confirmam que é o Cobalt Strike Beacon. O dropper foi
visto pela primeira vez há 9 dias — a campanha é recente.

---

#### Passo 14: Ajustar a regra YARA-L para cobrir este caso

**Ação:** A regra `c2_beaconing_periodicidade` existente NÃO detectou este beaconing.
Analise por que e proponha o ajuste.

**Análise do gap:**
A regra do Módulo 03 tinha condição:
```yara-l
condition:
  #e1 >= 20
  AND max($e1.network.received_bytes) - min($e1.network.received_bytes) <= 512
```

O problema: a condição `max - min <= 512` estava funcionando, mas o `#e1 >= 20` na janela
de 1 hora estava sendo cumprido. Então por que não disparou?

**Verificar no editor de regras:** A janela `match` estava configurada para `1h`, mas o
beaconing era muito regular (1 conexão/minuto). Com 60 conexões em 1h, deveria ter disparado.

**Causa raiz:** O processo era `svchost.exe` — que estava na watchlist de processos legítimos!
A exclusão `not $e1.principal.process.file.full_path in %watchlist_processos_beacon_legitimos`
estava bloqueando a detecção.

**Ajuste proposto:**

```yara-l
// REMOVER esta exclusão (svchost.exe pode ser usado por beaconing por injeção):
// not $e1.principal.process.file.full_path in %watchlist_processos_beacon_legitimos

// SUBSTITUIR por exclusão mais específica (apenas processos do sistema sem PID pai suspeito):
// Nota: esta verificação de processo pai não é diretamente suportada na condition do YARA-L
// — usar a combinação de regra YARA-L + UEBA risk score para cobertura completa

// ADICIONAR: verificação de processo pai suspeito como evento separado ($e2)
$e2.metadata.event_type = "PROCESS_LAUNCH"
$e2.principal.process.file.full_path = /.*\\AppData\\Local\\Temp\\.*/
$e2.target.process.file.full_path = $e1.principal.process.file.full_path
$e2.principal.hostname = $hostname_origem
```

---

### PARTE E — Documentação e IOCs (15 min)

---

#### Passo 15: Documentar os IOCs extraídos na investigação

**Ação:** Criar a lista de IOCs para incluir nas listas customizadas do Google SecOps
e compartilhar com o time de IR.

```bash
# Criar documento de IOCs no diretório do lab
cat > ~/lab-03-iocs.md << 'EOF'
# IOCs Extraídos — Lab 03 — C2 Beaconing WRK-RODRIGO-011
# Data: 2026-04-24
# Analista: [seu nome]
# Case ID: CASE-LAB03-001

## Indicadores de Rede
| Tipo | Indicador              | Confiança | Contexto                               |
|:-----|:-----------------------|:---------:|:---------------------------------------|
| IP   | 91.234.55.172          | HIGH      | Servidor C2 Cobalt Strike (Moldova)    |

## Indicadores de Host
| Tipo  | Indicador                                            | Confiança | Contexto                  |
|:------|:-----------------------------------------------------|:---------:|:--------------------------|
| SHA256| 4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9... | HIGH      | Cobalt Strike Beacon HTTPS|
| Path  | %TEMP%\update_cfg.exe                                | HIGH      | Dropper / Loader           |
| PID   | 9921 (svchost.exe, WRK-RODRIGO-011)                  | HIGH      | Processo beaconing         |

## Análise Estatística do Beaconing
- Intervalo médio: 61.3 segundos
- Desvio padrão: 4.7 segundos
- Coeficiente de variação: 7.7%
- Total de conexões: 1.847 (5 dias)
- Diagnóstico: C2 BEACONING CONFIRMADO — Cobalt Strike Beacon, jitter ~8%

## Conclusão
Comprometimento confirmado via exploit Adobe Reader (CVE hipotético).
Dropper instalou Cobalt Strike Beacon que manteve comunicação C2 por 5 dias.
Host WRK-RODRIGO-011 deve ser isolado e forenses coletados.
EOF
```

**Resultado esperado:** Arquivo de IOCs criado e pronto para compartilhamento com o CISO.

---

## 7. Objetivos por Etapa

| Etapa | Parte do Lab           | Objetivo                                                              | Critério de Conclusão                                                   |
|:-----:|:-----------------------|:----------------------------------------------------------------------|:------------------------------------------------------------------------|
| A     | Investigação inicial   | Confirmar que o comportamento é anômalo e identificar o IP de C2      | IP 91.234.55.172 identificado com 1.847 conexões                        |
| B     | Análise estatística    | Provar periodicidade mecânica via cálculo de intervalo                | Coeficiente de variação < 15% documentado                               |
| C     | Pivoting               | Identificar o processo responsável e o vetor de comprometimento       | update_cfg.exe criado por AcroRd32.exe identificado                     |
| D     | Enriquecimento TI      | Confirmar o malware via Mandiant + VirusTotal                         | Cobalt Strike confirmado por Mandiant + 51/72 VT engines                |
| E     | Documentação           | Extrair IOCs e propor ajuste na regra YARA-L                          | Arquivo de IOCs criado; gap na regra YARA-L identificado e documentado  |

---

## 8. Gabarito Completo

### Gabarito — Diagnóstico Final

**C2 Beaconing CONFIRMADO — Cobalt Strike Beacon (HTTPS Malleable Profile)**

**Evidências:**
1. 1.847 conexões ao mesmo IP externo em 5 dias (padrão anômalo)
2. Intervalo médio de 61.3 segundos com CV de 7.7% (alta periodicidade mecânica)
3. Variação de bytes por conexão de apenas 56 bytes (pacotes de tamanho fixo)
4. Conexões 24x7, inclusive madrugadas e fins de semana (sem comportamento humano)
5. Processo originador: `svchost.exe` lançado por `update_cfg.exe` em `%TEMP%`
6. `update_cfg.exe` criado por `AcroRd32.exe` (vetor: exploit Adobe Reader)
7. Hash do dropper: 51/72 engines VT = Cobalt Strike Beacon
8. IP confirmado pela Mandiant: C2 ativo do APT-FIN-BR

### Gabarito — IOCs

| Tipo   | Indicador                                                                     |
|:-------|:------------------------------------------------------------------------------|
| IP C2  | `91.234.55.172` (Moldova, Frantech Solutions)                                 |
| SHA256 | `4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1`          |
| Path   | `C:\Users\%USER%\AppData\Local\Temp\update_cfg.exe`                          |
| Process| `svchost.exe` (lançado por processo em %TEMP%, não pelo SCM legítimo)        |

### Gabarito — Gap na Regra YARA-L

A regra `c2_beaconing_periodicidade` tinha `svchost.exe` na Watchlist de processos legítimos,
o que preveniu a detecção. A solução é adicionar uma segunda variável de evento `$e2` que
verifica se o `svchost.exe` foi lançado por um processo em `%TEMP%` ou `%APPDATA%` — padrão
de injeção de processo típico do Cobalt Strike.

### Gabarito — Erros Comuns e Soluções

| Erro                                         | Causa                           | Solução                                              |
|:---------------------------------------------|:--------------------------------|:-----------------------------------------------------|
| IP não encontrado na Mandiant                | IP recente, ainda não indexado  | Verificar VirusTotal + pesquisa manual em Shodan    |
| Python script retorna erro de CSV            | Formato do export diferente     | Verificar se o campo de timestamp foi exportado     |
| svchost.exe não aparece na query             | Normalização diferente do campo | Tentar `principal.process.file.full_path = /.*svchost.*/` |
| Timeline não mostra events pré-comprometimento | Período muito curto            | Ampliar para "Last 14 days"                         |

---

*Lab 03 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 04 — Threat Hunting e UEBA](../../modulos/modulo-04-threat-hunting-ueba/README.md)*
*Anterior: [Lab 02 — YARA-L Multi-Event](../lab-02-yara-l-multi-event/README.md)*
*Próximo: [Lab 04 — Playbook SOAR Phishing](../lab-04-playbook-soar-phishing/README.md)*
