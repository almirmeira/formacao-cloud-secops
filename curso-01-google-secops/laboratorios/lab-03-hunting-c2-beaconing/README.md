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

**O que este passo faz:** Examina o painel de Risk Analytics do Google SecOps para entender o histórico comportamental do host WRK-RODRIGO-011. O Risk Score de 89 (CRITICAL) não é um alerta isolado — ele acumula evidências comportamentais ao longo do tempo que as regras de detecção point-in-time não capturam. O timestamp de início da anomalia identifica a provável data de comprometimento.

**Por que agora:** O Risk Analytics fornece o contexto temporal do incidente — quando o comportamento anômalo começou — o que direciona toda a investigação seguinte. Sem saber quando o score começou a subir, a análise de UDM Search pode usar um período de tempo errado e perder os primeiros eventos do comprometimento.

```
Navegação: Detection → Risk Analytics → Risky Hosts → WRK-RODRIGO-011

Campos a observar:
- Risk Score: 89
- Score history (gráfico de 30 dias): quando começou a subir?
- Top contributing alerts: quais eventos mais contribuíram para o score?
- Associated users: quais usuários estão logados neste host?
```

**O que você deve ver:**
- O Risk Score começou a subir há exatamente 5 dias (um sábado às 23:17 — fora do horário comercial)
- A maior contribuição é "Volume anômalo de conexões para IP externo único"
- O usuário associado é `rodrigo.andrade`

Anote o timestamp exato em que o score começou a subir — isso é a provável data/hora de comprometimento inicial. Este timestamp será o ponto de partida para a Timeline no Passo 11.

**O que fazer se der errado:**
- Se WRK-RODRIGO-011 não aparecer no Risk Analytics, verifique se o período selecionado
  inclui os últimos 7 dias
- Se o Risk Score aparecer baixo (< 50), verifique se está vendo o host correto —
  pode haver outro com nome similar

---

#### Passo 2: Analisar as conexões de rede do host via UDM Search

**O que este passo faz:** Executa a primeira query de UDM Search para mapear todas as conexões de saída do host nos últimos 7 dias. Esta visão inicial revela o volume total de comunicações e identifica o IP suspeito que o UEBA flagou — 91.234.55.172.

**Por que agora:** A análise de conexões de rede é o primeiro passo de threat hunting após identificar um host anômalo pelo UEBA. O volume e os destinos das conexões fornecem a evidência bruta necessária para confirmar ou descartar o beaconing.

```
Navegação: Search → UDM Search

Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "NETWORK_CONNECTION" AND
network.direction = "OUTBOUND"
```

Selecionar período: "Last 7 days"

**O que você deve ver:** Lista de conexões de saída com o IP `91.234.55.172` aparecendo com volume muito acima dos demais, com timestamps distribuídos ao longo de todos os dias, incluindo finais de semana e madrugadas. Verifique se o IP aparece também em madrugadas e finais de semana — tráfego legítimo de backup geralmente ocorre em janelas específicas, não 24x7.

---

#### Passo 3: Agrupar conexões por IP de destino para identificar o padrão

**O que este passo faz:** Agrega as conexões por IP de destino e calcula o total de conexões e bytes enviados. Esta visão comparativa é essencial: o IP de C2 deve ter um volume de conexões desproporcional em relação aos outros destinos externos, mas com bytes por conexão muito menores (pacotes de heartbeat, não transferências de dados).

**Por que agora:** A comparação quantitativa entre IPs é o que distingue C2 beaconing de uso legítimo intenso de rede. Um software de backup legítimo teria bytes altos; C2 beaconing tem conexões frequentes com bytes mínimos.

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

**O que você deve ver:**

```
IP destino          | total_conexoes | bytes_enviados
─────────────────────────────────────────────────────
91.234.55.172       |      1847      |    472.576
52.96.123.45        |        47      |  1.047.552    ← Microsoft (Office 365)
104.16.45.88        |        32      |    819.200    ← Cloudflare (legítimo)
20.190.160.10       |        28      |    655.360    ← Microsoft (Azure AD)
13.107.21.200       |        15      |    307.200    ← Microsoft (Teams)
```

Calcule o ratio bytes/conexão para o IP suspeito: 472.576 / 1847 = ~255 bytes por conexão. Compare com os IPs da Microsoft: ~22.000 bytes/conexão. Este ratio extremamente baixo é um indicador forte de pacotes de heartbeat de C2.

**O que fazer se der errado:**
- Se `91.234.55.172` não aparecer, ajuste o período para "Last 30 days"
- Se o IP aparecer com poucos bytes por conexão (< 1KB), isso é um sinal FORTE de beaconing
  — pacotes de heartbeat são pequenos e regulares

---

#### Passo 4: Calcular as conexões por hora para identificar o padrão 24x7

**O que este passo faz:** Distribui as conexões ao IP suspeito pelas 24 horas do dia. C2 beaconing automatizado ocorre de forma uniforme 24x7 — o malware não dorme. Comportamento humano legítimo (backup, atualização) tem picos em horários específicos e zero atividade em outros.

**Por que agora:** A uniformidade horária é um dos indicadores mais confiáveis de automação maliciosa. Este passo transforma a suspeita de beaconing em evidência estatística — ~77 conexões por hora, uniformemente distribuídas, não é comportamento humano.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| group_by metadata.event_timestamp.hours
| order_by metadata.event_timestamp.hours asc
```

**O que você deve ver:**

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

O volume de conexões por hora deve ser MUITO UNIFORME ao longo das 24 horas — a periodicidade mecânica do malware. Se fosse um software legítimo de backup ou atualização, as conexões estariam concentradas em janelas específicas (ex: 02h-04h) e zeradas durante o horário comercial.

---

### PARTE B — Análise Estatística de Periodicidade (30 min)

---

#### Passo 5: Extrair os timestamps das conexões para análise de intervalo

**O que este passo faz:** Obtém a lista ordenada cronologicamente de todos os timestamps das 1.847 conexões. Este export é o dado bruto necessário para o cálculo estatístico do Passo 6 — o coeficiente de variação dos intervalos é a prova matemática de beaconing.

**Por que agora:** O cálculo estatístico de periodicidade é o padrão de ouro para confirmar C2 beaconing — ele prova que as conexões seguem um padrão mecânico com variação mínima, impossível de ser gerado por comportamento humano ou por maioria dos softwares legítimos.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| order_by metadata.event_timestamp asc
```

**O que você deve ver:** Lista de 1.847 conexões em ordem cronológica. Exportar para CSV clicando no botão "Export" no canto superior direito da tabela de resultados. O arquivo será usado no Passo 6.

---

#### Passo 6: Calcular o intervalo médio entre conexões

**O que este passo faz:** Calcula as estatísticas dos intervalos entre conexões consecutivas — média, mediana, desvio padrão e coeficiente de variação (CV). O CV é o indicador decisivo: valores abaixo de 15% indicam automação mecânica (C2 beaconing com jitter mínimo); acima de 50% indica comportamento humano ou software com scheduling variável.

**Por que agora:** A análise estatística transforma a observação visual de "muitas conexões" em evidência técnica documentável — exatamente o que o CISO precisará apresentar ao board e o que o time jurídico precisará em caso de investigação formal. Um CV de 7.7% é matematicamente incompatível com comportamento humano ou software de backup legítimo.

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
    print("ALTA PERIODICIDADE DETECTADA — Muito provável C2 beaconing")
    print(f"   Intervalo mecânico de {media:.0f}s ± {desvio_padrao:.0f}s")
elif coef_variacao < 30:
    print("PERIODICIDADE MODERADA — Possível C2 beaconing com jitter")
else:
    print("Baixa periodicidade — Padrão consistente com tráfego legítimo")
```

**O que você deve ver:**

```
Total de conexões analisadas: 1847
Período: 2026-04-19 23:17:03 → 2026-04-24 14:21:47

=== ANÁLISE ESTATÍSTICA DOS INTERVALOS ===
Intervalo médio:       61.3 segundos (1.0 minutos)
Intervalo mediano:     61.0 segundos
Desvio padrão:         4.7 segundos
Coeficiente de variação: 7.7%

=== DIAGNÓSTICO ===
ALTA PERIODICIDADE DETECTADA — Muito provável C2 beaconing
   Intervalo mecânico de 61s ± 5s
```

Coeficiente de Variação (CV) < 15% é um indicador FORTE de C2 beaconing. Tráfego humano legítimo geralmente tem CV > 50%. Um intervalo de ~60 segundos é consistente com o check-in padrão do Cobalt Strike Beacon (configuração padrão: `sleep 60`).

**O que fazer se der errado:**
- Se não tiver Python disponível, calcule manualmente com os primeiros 20 intervalos:
  pegue os timestamps de 20 conexões consecutivas e calcule a diferença entre cada uma.
  Se todos forem entre 55–67 segundos, o diagnóstico é o mesmo.

---

#### Passo 7: Verificar a variação do tamanho dos pacotes

**O que este passo faz:** Analisa se os bytes enviados e recebidos por conexão são consistentes (sinal de automação) ou variáveis (sinal de comportamento humano). C2 beaconing usa pacotes de check-in de tamanho fixo — o malware envia o mesmo "heartbeat" repetidamente. Softwares legítimos têm variação de KB a MB dependendo da atividade do usuário.

**Por que agora:** A combinação de intervalos uniformes (Passo 6) com tamanho de pacotes uniforme (este passo) é a prova definitiva de beaconing automatizado. Cada indicador individualmente pode ter explicação alternativa; juntos, formam uma evidência robusta para o relatório ao CISO.

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

**O que você deve ver:**

```
max_sent:  312 bytes
min_sent:  256 bytes    ← variação de apenas 56 bytes
max_recv:  192 bytes
min_recv:  128 bytes    ← variação de apenas 64 bytes
```

Variação < 100 bytes nos tamanhos de pacote é um indicador de C2 beaconing. Compare com os pacotes para os IPs da Microsoft: eles têm variação de KB a MB. O ratio de variação do Cobalt Strike Beacon é determinístico — o jitter configurado afeta apenas o intervalo, não o tamanho do payload.

---

### PARTE C — Pivoting: IP → Processo → Usuário → Timeline (25 min)

---

#### Passo 8: Identificar o processo responsável pelas conexões

**O que este passo faz:** Pivota da perspectiva de rede (IP de destino) para a perspectiva de endpoint (processo iniciador). Esta é a técnica central de threat hunting — correlacionar eventos de rede com eventos de processo para identificar qual executável está gerando o tráfego suspeito.

**Por que agora:** Saber o IP do C2 não é suficiente para contenção — o analista precisa saber qual processo matar e qual executável remover. O processo é também a evidência que liga o tráfego de rede ao comprometimento do endpoint.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
target.ip = "91.234.55.172" AND
metadata.event_type = "NETWORK_CONNECTION"
| group_by principal.process.file.full_path
| order_by count() desc
```

**O que você deve ver:**

```
Processo                                           | count
──────────────────────────────────────────────────────────
C:\Windows\System32\svchost.exe                   |  1847
```

`svchost.exe` é um processo legítimo do Windows, mas é frequentemente usado por malware como "host" para injeção de código. Todas as 1.847 conexões de beaconing partem do mesmo processo `svchost.exe`. Um svchost legítimo raramente mantém conexões com um único IP externo por dias seguidos — isso exige investigação do processo pai no próximo passo.

---

#### Passo 9: Verificar o processo pai do svchost suspeito

**O que este passo faz:** Investiga qual processo lançou o `svchost.exe` que está gerando o beaconing. O `svchost.exe` legítimo é sempre lançado pelo `services.exe` (Service Control Manager). Um svchost lançado por qualquer outro processo é um indicador forte de process hollowing ou injeção de código — técnicas comuns do Cobalt Strike.

**Por que agora:** Identificar o processo pai é o pivô que conecta o tráfego C2 ao vetor de comprometimento inicial. O processo pai do svchost suspeito será o dropper — o arquivo malicioso que foi executado na máquina de Rodrigo.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "PROCESS_LAUNCH" AND
target.process.file.full_path = "C:\\Windows\\System32\\svchost.exe"
```

**O que você deve ver:**

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

O processo pai do `svchost.exe` suspeito é `update_cfg.exe`, localizado em `%TEMP%` — não é uma localização padrão para lançar processos do sistema. Isso é um indicador claro de injeção/hollowing de processo pelo malware. Anote o PID 9921 — ele será usado para confirmar que este é o mesmo svchost que gera o beaconing.

**O que fazer se der errado:**
- Se a query não retornar resultados, tente buscar por PID:
  `principal.process.pid = 9921 AND metadata.event_type = "PROCESS_LAUNCH"`

---

#### Passo 10: Investigar o arquivo suspeito update_cfg.exe

**O que este passo faz:** Rastreia a criação do arquivo `update_cfg.exe` para identificar qual processo o criou — revelando o vetor de comprometimento inicial. Este pivô completa a cadeia de ataque: vetor inicial → dropper → processo C2.

**Por que agora:** Conhecer o processo que criou o dropper identifica o vetor de comprometimento (ex: Adobe Reader → exploit → dropper). Essa informação é crítica para: (1) determinar o escopo do incidente — quantos outros hosts abriram o mesmo arquivo, e (2) identificar a técnica MITRE ATT&CK correta para o relatório.

```
Query:
principal.hostname = "WRK-RODRIGO-011" AND
metadata.event_type = "FILE_CREATION" AND
target.file.full_path = /.*update_cfg\.exe.*/
```

**O que você deve ver:**

```
Evento FILE_CREATION:
  metadata.event_timestamp:    2026-04-19T23:16:54Z   ← criado 7s antes da 1ª conexão!
  principal.process.file.full_path: C:\Users\rodrigo.andrade\AppData\Roaming\...\AcroRd32.exe
  target.file.full_path:       C:\Users\rodrigo.andrade\AppData\Local\Temp\update_cfg.exe
  target.file.sha256:          4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1
  target.file.size:            892416  (872 KB)
```

O arquivo foi criado por `AcroRd32.exe` (Adobe Reader)! Isso confirma o vetor de comprometimento: exploit no Adobe Reader → dropper → Cobalt Strike Beacon. Anote o hash SHA256 — ele será verificado no VirusTotal no Passo 13.

---

#### Passo 11: Pivotar do usuário para o Timeline View completo

**O que este passo faz:** Usa o Timeline View do Google SecOps para consolidar toda a atividade do usuário `rodrigo.andrade` em uma visão cronológica única — desde o comprometimento inicial até o alerta do UEBA. Este é o entregável de investigação central: a timeline do incidente.

**Por que agora:** A timeline não pode ser construída antes de todos os passos anteriores, pois depende dos timestamps e entidades identificados nas investigações de rede (Passos 2-4), processo (Passos 8-9) e arquivo (Passo 10). Esta é a síntese de toda a investigação.

```
Navegação: Search → Entities → buscar "rodrigo.andrade"
           Selecionar a entidade de usuário
           Aba "Timeline" → período: últimos 7 dias
```

**O que você deve ver:** Timeline completa mostrando:

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

**O que este passo faz:** Verifica o IP `91.234.55.172` na base de inteligência de ameaças da Mandiant integrada ao Google SecOps. A confirmação da Mandiant eleva a confiança do diagnóstico de "suspeito" para "confirmado" — transformando evidências circunstanciais em atribuição técnica formal.

**Por que agora:** O enriquecimento com TI é feito após a investigação local porque confirma ou nega as hipóteses formadas durante o hunting. Verificar o IP antes de investigar o contexto local pode levar a conclusões precipitadas — um IP que a Mandiant não conhece pode ainda ser C2, como este caso demonstra (o IP era novo e não estava na base do VirusTotal no início).

```
Navegação: Threat Intelligence → Indicators → buscar 91.234.55.172
```

**O que você deve ver:**

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

A confirmação da Mandiant de que o IP é infraestrutura C2 do Cobalt Strike eleva a confiança do diagnóstico de CONFIRMADO para CERTO. Documente o número de referência da Mandiant — ele deve constar no relatório ao CISO.

---

#### Passo 13: Consultar o VirusTotal para o hash do dropper

**O que este passo faz:** Verifica o hash SHA256 do `update_cfg.exe` no VirusTotal para confirmar que é o Cobalt Strike Beacon e obter informações sobre a campanha — família de malware, primeira observação, comportamento em sandbox. Estas informações completam o perfil técnico do ataque para o relatório de incidente.

**Por que agora:** O hash do dropper foi obtido no Passo 10. Verificar no VirusTotal é o passo final de enriquecimento — confirma a família de malware e fornece dados sobre a campanaha em andamento, que podem indicar se outros bancos estão sendo atacados.

```
Navegação: Threat Intelligence → VirusTotal → buscar hash
  4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1
```

**O que você deve ver:**

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

51/72 engines confirmam que é o Cobalt Strike Beacon. O dropper foi visto pela primeira vez há 9 dias — a campanha é recente, o que explica por que o IP ainda não estava indexado no VirusTotal no início da investigação.

---

#### Passo 14: Ajustar a regra YARA-L para cobrir este caso

**O que este passo faz:** Analisa por que a regra `c2_beaconing_periodicidade` não detectou este beaconing e propõe o ajuste necessário. Este passo fecha o ciclo de threat hunting → detecção: a investigação manual identificou o incidente; agora a regra é melhorada para detectar automaticamente casos similares no futuro.

**Por que agora:** O ajuste da regra deve ser feito antes da documentação final, pois o gap identificado é parte dos entregáveis do lab e deve estar documentado no relatório ao CISO.

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

**O que este passo faz:** Consolida todos os indicadores de comprometimento (IOCs) identificados durante a investigação em um documento formal para compartilhamento com o time de IR, outros SOCs e feeds de inteligência. Este documento é o entregável formal da investigação e a base para as ações de contenção.

**Por que agora:** A documentação de IOCs deve ser feita imediatamente após a conclusão da investigação, enquanto todos os dados estão presentes no contexto. IOCs documentados tardiamente perdem precisão — o analista pode esquecer detalhes como o PID exato ou o timestamp preciso do comprometimento.

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

**O que você deve ver:** Arquivo de IOCs criado e pronto para compartilhamento com o CISO, time de IR e para inclusão no feed de TI interno do Banco Meridian.

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

**Por que esta é a resposta correta:** A convergência de 8 indicadores independentes — cada um com explicação alternativa possível, mas impossíveis de coexistir acidentalmente — constitui evidência conclusiva. O CV de 7.7% é matematicamente incompatível com qualquer software de backup ou atualização legítimo conhecido; a combinação com processo pai em %TEMP% e hash confirmado por 51/72 engines elimina qualquer hipótese de falso positivo.

**Erro mais comum neste passo:** Concluir "provavelmente beaconing" sem documentar a evidência estatística. O CISO do Banco Meridian precisa de evidências formais — a análise estatística de CV é o que diferencia um relatório de segurança de uma suspeita informal.

---

### Gabarito — IOCs

| Tipo   | Indicador                                                                     |
|:-------|:------------------------------------------------------------------------------|
| IP C2  | `91.234.55.172` (Moldova, Frantech Solutions)                                 |
| SHA256 | `4a7bc3d9e2f1508b6c3a2d8e9f0b1e4c7a8d2f5e3b4c6a9d1e2f3b5c7d9e0f1`          |
| Path   | `C:\Users\%USER%\AppData\Local\Temp\update_cfg.exe`                          |
| Process| `svchost.exe` (lançado por processo em %TEMP%, não pelo SCM legítimo)        |

**Por que esta é a resposta correta:** IOCs sem contexto são dados brutos — IOCs com contexto são inteligência acionável. O campo "Contexto" em cada IOC informa ao analista de outro SOC exatamente o que esse indicador significa, sem precisar reler o relatório inteiro. O formato estruturado permite importação direta em feeds de TI (MISP, Mandiant Threat Feed).

**Erro mais comum neste passo:** Documentar apenas o IP do C2 e ignorar os IOCs de host (hash, path, PID). Os IOCs de host são os mais acionáveis para contenção — o analista de IR precisa do path para encontrar e remover o dropper, e do hash para criar regra de quarentena no EDR.

---

### Gabarito — Gap na Regra YARA-L

A regra `c2_beaconing_periodicidade` tinha `svchost.exe` na Watchlist de processos legítimos,
o que preveniu a detecção. A solução é adicionar uma segunda variável de evento `$e2` que
verifica se o `svchost.exe` foi lançado por um processo em `%TEMP%` ou `%APPDATA%` — padrão
de injeção de processo típico do Cobalt Strike.

**Por que esta é a resposta correta:** O erro original da regra foi uma exclusão excessivamente ampla — toda instância de `svchost.exe` foi excluída da detecção porque o processo é legítimo. A solução correta não é remover a exclusão completamente (o que geraria falsos positivos), mas torná-la condicional ao processo pai. Um `svchost.exe` lançado pelo `services.exe` é legítimo; lançado por um processo em `%TEMP%` é comprometido.

**Erro mais comum neste passo:** Propor simplesmente remover `svchost.exe` da watchlist. Isso causaria alertas de C2 beaconing para TODOS os processos svchost.exe legítimos do Windows — dezenas de alertas por hora por host, tornando o SOC inoperante em minutos. A exclusão condicional por processo pai é a abordagem correta.

---

### Gabarito — Erros Comuns e Soluções

| Erro                                         | Causa                           | Diagnóstico e Solução                                              |
|:---------------------------------------------|:--------------------------------|:-----------------------------------------------------|
| IP não encontrado na Mandiant                | IP recente, ainda não indexado  | **Diagnóstico:** IP novo em campanha ativa. Verificar VirusTotal + pesquisa manual em Shodan (buscar por banner Cobalt Strike no IP). A ausência na Mandiant não descarta o C2 — o CV < 15% ainda é evidência suficiente |
| Python script retorna erro de CSV            | Formato do export diferente     | **Diagnóstico:** O Google SecOps pode exportar com aspas ou com header diferente. Verificar se o campo de timestamp foi exportado com o nome exato `metadata.event_timestamp`. Alternativa: usar planilha Excel para calcular diferenças entre timestamps |
| svchost.exe não aparece na query             | Normalização diferente do campo | **Diagnóstico:** Alguns parsers normalizam o nome do processo sem o path completo. Tentar `principal.process.file.full_path = /.*svchost.*/` (regex) em vez de match exato |
| Timeline não mostra events pré-comprometimento | Período muito curto            | **Diagnóstico:** O lab usa timestamps de 5 dias atrás. Se o período selecionado for "Last 3 days", o evento de comprometimento (2026-04-19) fica fora. Ampliar para "Last 14 days" |

---

*Lab 03 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Módulo relacionado: [Módulo 04 — Threat Hunting e UEBA](../../modulos/modulo-04-threat-hunting-ueba/README.md)*
*Anterior: [Lab 02 — YARA-L Multi-Event](../lab-02-yara-l-multi-event/README.md)*
*Próximo: [Lab 04 — Playbook SOAR Phishing](../lab-04-playbook-soar-phishing/README.md)*
