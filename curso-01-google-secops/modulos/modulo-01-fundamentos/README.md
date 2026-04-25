# Módulo 01 — Fundamentos do Google SecOps
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                      |
|:-------------------|:-------------------------------------------------------------|
| **Carga Horária**  | 2h videoaulas + 1h live online                               |
| **Pré-requisito**  | Módulo 00 concluído com health check 14/14                   |
| **MITRE ATT&CK**   | Framework geral (sem técnica específica neste módulo)        |
| **Ferramentas**    | Google SecOps Console, gcloud CLI, MITRE ATT&CK Navigator    |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Descrever a arquitetura do Google SecOps e seus componentes principais (SIEM, SOAR, UEBA, TI)
2. Comparar o Google SecOps com outros SIEMs líderes de mercado (Splunk, Microsoft Sentinel, IBM QRadar)
3. Explicar o modelo de retenção e o pricing baseado em ingestão do Google SecOps
4. Navegar na interface do Google SecOps e identificar os painéis principais
5. Compreender como o Google SecOps se posiciona em um SOC moderno

---

## Conteúdo do Módulo

### 1.1 O que é o Google SecOps?

O Google SecOps é a evolução da plataforma Chronicle, adquirida pelo Google em 2019 e integrada
ao Google Cloud. Trata-se de uma plataforma de **Security Operations** nativamente em nuvem que
combina em um único produto:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GOOGLE SECOPS — VISÃO GERAL                      │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────┐  │
│  │     SIEM      │  │     SOAR     │  │     UEBA     │  │   TI   │  │
│  │               │  │              │  │              │  │        │  │
│  │  Ingestão     │  │  Playbooks   │  │  Analytics   │  │Mandiant│  │
│  │  UDM          │  │  Cases       │  │  Risk Score  │  │VTotal  │  │
│  │  YARA-L       │  │  Actions     │  │  Anomaly Det.│  │STIX    │  │
│  │  Retrohunt    │  │  Automation  │  │  Behavioral  │  │TAXII   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────┘  │
│                                                                      │
│  Powered by: Google Infrastructure · Petabyte-scale Storage         │
│  Backend: BigQuery · Spanner · Borg                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Diferenciais competitivos:**

| Diferencial            | Google SecOps                                | Concorrentes Típicos                     |
|:-----------------------|:---------------------------------------------|:-----------------------------------------|
| **Escala de ingestão** | Petabytes por dia sem degradação             | Limitado por hardware/licença            |
| **Retenção**           | 1 ano nativo (UD Mode) + archival ilimitado  | 90 dias típico (com custo adicional)     |
| **Modelo de pricing**  | Baseado em ingestão (não por usuário/EPS)    | Por EPS, por usuário ou por dispositivo  |
| **Threat Intel**       | Mandiant integrado nativamente               | Integração via API (paga separado)       |
| **Detecção**           | YARA-L 2.0 (linguagem proprietária)          | SPL, KQL, Sigma (não nativos)            |
| **Performance**        | Busca sobre anos de dados em segundos        | Buscas longas, timeouts comuns           |

---

### 1.2 Arquitetura do Google SecOps

#### Camada de Ingestão

```
FONTES DE LOG                 MECANISMOS DE INGESTÃO        GOOGLE SECOPS
─────────────                 ──────────────────────         ────────────
Endpoints (EDR)    ──────►   Bindplane OP Agent     ──►│
Firewall / IDS     ──────►   Forwarders             ──►│ Chronicle
Cloud Services     ──────►   Google Cloud Pub/Sub   ──►│ Ingestion
SaaS Applications  ──────►   Webhooks REST API      ──►│ Layer
SIEM Legado        ──────►   Syslog / CEF / LEEF    ──►│
```

#### Camada de Processamento

1. **Parsing:** normalização dos logs brutos para o schema UDM
2. **Enrichment:** enriquecimento com contexto de Threat Intelligence
3. **Storage:** armazenamento no motor escalável baseado em BigQuery/Spanner
4. **Indexação:** indexação para busca rápida sobre grandes volumes

#### Camada de Análise

1. **UDM Search:** busca sobre o Unified Data Model
2. **YARA-L Engine:** avaliação de regras de detecção em tempo real
3. **UEBA Engine:** análise de comportamento de entidades (usuários, dispositivos, processos)
4. **Risk Analytics:** pontuação de risco baseada em evidências acumuladas

---

### 1.3 Unified Data Model (UDM) — Introdução

O UDM é o schema normalizado do Google SecOps. Todos os logs ingeridos, independentemente do
formato original, são normalizados para o UDM antes de serem armazenados.

**Por que o UDM é importante?**
- Permite escrever regras e queries que funcionam com **qualquer fonte de log**
- Elimina a necessidade de conhecer o formato proprietário de cada fabricante
- Facilita a correlação de eventos de diferentes fontes em uma mesma investigação

**Estrutura básica de um evento UDM:**

```json
{
  "metadata": {
    "event_timestamp": "2026-04-24T14:30:00Z",
    "event_type": "USER_LOGIN",
    "product_name": "Microsoft-Windows-Security-Auditing",
    "vendor_name": "Microsoft",
    "log_type": "WINDOWS_EVENT"
  },
  "principal": {
    "hostname": "WRK-JOAO-001",
    "ip": "192.168.10.45",
    "user": {
      "userid": "joao.silva",
      "email_addresses": ["joao.silva@bancomeridian.com.br"]
    }
  },
  "target": {
    "hostname": "SRV-DC-001",
    "ip": "10.0.1.10"
  },
  "network": {
    "application_protocol": "KERBEROS"
  },
  "security_result": {
    "action": "ALLOW",
    "severity": "INFORMATIONAL"
  }
}
```

---

### 1.4 Comparativo: Google SecOps vs. Outros SIEMs

| Critério               | Google SecOps    | Microsoft Sentinel  | Splunk Enterprise  | IBM QRadar        |
|:-----------------------|:----------------:|:-------------------:|:------------------:|:-----------------:|
| **Modelo de Deploy**   | SaaS (cloud only)| SaaS (Azure only)   | On-prem / Cloud    | On-prem / Cloud   |
| **Linguagem de Query** | UDM + YARA-L     | KQL                 | SPL                | AQL               |
| **TI Integrada**       | Mandiant (nativa)| MDTI (paga)         | Splunk TI (add-on) | X-Force (add-on)  |
| **SOAR**               | Integrado nativo | Logic Apps          | SOAR (add-on $$$)  | QRadar SOAR (add) |
| **Escalabilidade**     | Petabytes/dia    | Dependente do LAW   | Limitada por HW    | Limitada por HW   |
| **Retenção padrão**    | 1 ano (UD Mode)  | 90 dias (Log Analytics) | 90 dias        | 30 dias           |
| **UEBA**               | Nativo           | Sentinel UEBA (add) | Splunk UBA ($$$)   | QRadar UBA ($$$)  |
| **Foco**               | Cloud-native     | Microsoft Ecosystem | Universal          | Enterprise        |

> **Insight de mercado (Gartner SIEM Magic Quadrant 2025):** Google SecOps é posicionado como
> "Líder" com forte capacidade de análise em grande escala, especialmente para organizações com
> volumes massivos de telemetria. Microsoft Sentinel lidera em integração com ecosistema M365.

---

### 1.5 Modelo de Retenção e Pricing

#### Modelos de Retenção

| Modo              | Retenção | Busca UDM | Use Case                              |
|:------------------|:--------:|:---------:|:--------------------------------------|
| **UD Mode**       | 1 ano    | ✅ Rápida  | Operações diárias, investigação ativa  |
| **UDM Archive**   | 2–5 anos | ⚡ Mais lenta | Compliance, forensics histórico      |
| **Raw Log Scan**  | Ilimitado| 🐢 Lenta  | Forensics profundo, replay completo   |

#### Modelo de Pricing (Ingestão-Based)

O Google SecOps cobra por **volume de dados ingeridos** (GB/dia), não por usuário, dispositivo
ou EPS (Events Per Second). Isso torna o modelo previsível e vantajoso para organizações com
muitos usuários mas volume moderado de logs.

```
Estimativa de custo para uma organização de 5.000 funcionários:
─────────────────────────────────────────────────────────────────
Fonte                    Volume estimado/dia    Custo aproximado
─────────────────────────────────────────────────────────────────
Windows Events           50 GB/dia
Linux Syslog             20 GB/dia
Firewall / IDS           30 GB/dia
Cloud Services (GCP)     10 GB/dia
─────────────────────────────────────────────────────────────────
TOTAL                   110 GB/dia             ~US$ 220/dia*
─────────────────────────────────────────────────────────────────
* Valores de referência 2026 — consulte o Google Cloud Calculator
  para precificação atual e negociação de contrato enterprise.
```

---

### 1.6 Google SecOps no Contexto do SOC Moderno

O Google SecOps é projetado para suportar todas as funções de um SOC moderno:

```
FUNÇÕES DO SOC          CAPACIDADE NO GOOGLE SECOPS
──────────────          ───────────────────────────────────────────
Detecção               YARA-L rules + Fusion (ML) + Anomaly Detection
Triagem                Alert triage com contexto UDM enriquecido
Investigação           UDM Search + Timeline + Entity pivot
Threat Hunting         UDM Search + Risk Analytics + UEBA
Resposta               SOAR Playbooks + Actions automatizadas
Threat Intelligence    Mandiant TI + VirusTotal + STIX/TAXII feeds
Métricas               MTTD, MTTR, closure rates por categoria
Compliance             Log retention + Audit logs + Chain of custody
```

---

## Atividades de Fixação

### Quiz — Módulo 01

**Questão 1:** Qual é a principal diferença entre o modelo de pricing do Google SecOps e o modelo
tradicional de SIEMs on-premises como o QRadar?

- [ ] a) O Google SecOps cobra por número de regras de detecção ativas
- [ ] b) O Google SecOps cobra por volume de dados ingeridos (GB/dia), enquanto o QRadar cobra por EPS
- [ ] c) O Google SecOps cobra por usuário simultâneo conectado ao console
- [ ] d) O Google SecOps cobra por número de alertas gerados por dia

**Resposta correta:** b) — O Google SecOps adota modelo de ingestão (GB/dia), o que favorece
organizações com muitos usuários mas volume de log controlado.

---

**Questão 2:** O Unified Data Model (UDM) do Google SecOps serve principalmente para:

- [ ] a) Criptografar os logs antes de armazená-los no Chronicle
- [ ] b) Normalizar logs de diferentes fontes para um schema comum, facilitando correlação e busca
- [ ] c) Comprimir os logs para reduzir o custo de armazenamento
- [ ] d) Exportar logs para outros sistemas SIEM

**Resposta correta:** b) — O UDM é o esquema de normalização central do Google SecOps.

---

**Questão 3:** Em um cenário de SOC multi-cloud (Azure + AWS + GCP), qual das afirmativas sobre
o Google SecOps é correta?

- [ ] a) O Google SecOps só suporta logs nativos do Google Cloud Platform
- [ ] b) O Google SecOps requer um agente proprietário para cada provedor de nuvem
- [ ] c) O Google SecOps suporta ingestão de logs de múltiplos provedores via feeds, forwarders e Bindplane
- [ ] d) O Google SecOps não suporta logs de ambientes on-premises

**Resposta correta:** c) — O Google SecOps é projetado para ambientes multi-cloud e híbridos.

---

**Questão 4:** Qual componente do Google SecOps é responsável pela detecção de comportamentos
anômalos de usuários e dispositivos, usando análise estatística e modelos de ML?

- [ ] a) YARA-L Engine
- [ ] b) Chronicle SOAR
- [ ] c) Bindplane OP Agent
- [ ] d) UEBA (User and Entity Behavior Analytics)

**Resposta correta:** d) — O UEBA analisa padrões comportamentais e detecta desvios da baseline.

---

**Questão 5:** Segundo o Gartner SIEM Magic Quadrant 2025, qual é o principal diferencial
competitivo do Google SecOps em relação a outros SIEMs líderes de mercado?

- [ ] a) Integração nativa com ecosistema Microsoft 365
- [ ] b) Capacidade de análise em grande escala (petabytes) com performance consistente
- [ ] c) Menor custo absoluto para organizações com menos de 500 usuários
- [ ] d) Suporte nativo a análise de malware com sandbox integrada

**Resposta correta:** b) — A escala de processamento baseada na infraestrutura Google é o principal diferencial.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **📹 Este roteiro é para uso exclusivo do instrutor durante a gravação das videoaulas ou na
> condução da sessão live online. Cada bloco indica o conteúdo a ser apresentado, o tempo
> estimado e as orientações de produção.**

---

### AULA 1.1 — Introdução ao Google SecOps (40 min)

---

**[ABERTURA — 3 min | Tela: Slide de capa com logo CECyber e Google SecOps]**

*[Falar com energia e entusiasmo, olhando diretamente para a câmera]*

"Olá! Seja bem-vindo ao Módulo 01 do curso Google SecOps Essentials da CECyber. Eu sou [nome do instrutor], e nas próximas semanas vou ser o seu instrutor nessa jornada pelo mundo das operações de segurança em nuvem com o Google.

Neste primeiro módulo, a gente vai entender juntos o que é o Google SecOps, de onde ele veio, como ele se posiciona no mercado de SIEMs e o que você pode esperar ao operar essa plataforma no dia a dia de um SOC. Não se preocupe se você nunca mexeu com o Chronicle ou com o Google SecOps antes — vamos começar do zero.

Ao final deste módulo, você vai conseguir explicar o que é o Google SecOps para um colega de trabalho, entender por que ele é diferente dos SIEMs tradicionais e começar a navegar na interface com confiança.

Vamos lá!"

---

**[BLOCO 1: Contexto e Posicionamento — 10 min | Tela: Compartilhar slides]**

*[Voz mais pausada, didática, como se estivesse explicando para alguém que nunca ouviu falar]*

"Antes de mergulharmos no Google SecOps em si, deixa eu contextualizar por que a gente está falando disso hoje.

Até 2015, 2016, a grande maioria dos SOCs no Brasil operava SIEMs on-premises — IBM QRadar, Splunk, ArcSight. Eram sistemas instalados na infraestrutura da própria empresa, com servidores físicos, licenças caras por EPS — Events Per Second — e times de manutenção dedicados.

O problema? Volume de dados crescendo exponencialmente. Cada novo serviço em nuvem, cada novo endpoint, cada nova aplicação SaaS gerava mais logs. E o SIEM on-premises simplesmente não conseguia escalar sem investimento enorme em hardware e licenças.

*[Pausa de 2 segundos, olhar para a câmera]*

O Google respondeu a esse desafio em 2019, quando adquiriu a startup Chronicle — que tinha nascido justamente dentro do X, o laboratório de inovação da Alphabet. A premissa do Chronicle era radical: e se a gente pudesse guardar TODOS os logs de uma organização, por ANOS, e conseguir buscar em segundos? Usando a mesma infraestrutura que move o Google Search e o YouTube?

E foi isso que o Google SecOps trouxe para o mercado. Uma plataforma onde a escala é ilimitada e o custo é previsível — você paga pelo volume que ingere, não pelo tamanho do time ou pelo número de alertas."

*[Dica de edição: corte aqui e passe para o slide do comparativo de SIEMs]*

---

**[BLOCO 2: Arquitetura da Plataforma — 12 min | Tela: Diagrama de arquitetura]**

*[Tom técnico mas acessível, apontando para os elementos do diagrama]*

"Agora vamos olhar para a arquitetura do Google SecOps. Eu vou compartilhar o diagrama que está no material do módulo, e vou te guiar pelos quatro grandes componentes.

*[Apontar para o SIEM no diagrama]*

Primeiro, o SIEM — Security Information and Event Management. É aqui que os logs chegam, são normalizados para o UDM — Unified Data Model, que a gente vai estudar mais detalhadamente no Módulo 02 — e ficam disponíveis para busca e correlação.

*[Apontar para o SOAR]*

Segundo componente: o SOAR — Security Orchestration, Automation and Response. É onde a mágica da automação acontece. Quando um alerta é gerado, o SOAR entra em ação, executando playbooks que podem tomar ações automáticas: isolar um endpoint, revogar uma credencial comprometida, notificar o time via Slack ou Teams.

*[Apontar para o UEBA]*

Terceiro: UEBA — User and Entity Behavior Analytics. O UEBA cria uma baseline de comportamento para cada usuário e dispositivo. Se o usuário João sempre acessa o sistema das 8h às 18h e de repente às 3 da manhã tem um login com um IP da Rússia... o UEBA vai detectar isso e elevar o risk score do João. A gente trabalha isso no Módulo 04.

*[Apontar para a Threat Intelligence]*

E quarto: Threat Intelligence — com a integração nativa da Mandiant, que faz parte do Google Cloud desde 2022. Feeds de IOCs, relatórios de APTs, contexto sobre malwares — tudo disponível para enriquecer automaticamente os alertas que chegam no seu SOC.

*[Pausa, olhar para a câmera]*

Esses quatro componentes trabalhando juntos é o que torna o Google SecOps uma plataforma de SecOps completa. Não é só um SIEM. É um SOC inteiro numa só plataforma."

*[Dica de edição: mostre uma animação do fluxo de dados: log → ingestão → UDM → YARA-L → alerta → SOAR]*

---

**[BLOCO 3: Demo ao Vivo — Navegação na Interface — 12 min | Tela: Tenant Google SecOps]**

*[Tom mais informal, como se estivesse mostrando algo para um amigo]*

"Agora a gente vai ao vivo. Eu vou compartilhar a tela do meu tenant do Google SecOps — o mesmo que você já deve ter configurado no Módulo 00 — e a gente vai dar uma volta pela interface.

*[Abrir o navegador e acessar o tenant]*

Aqui está a tela de login. Eu vou entrar com minhas credenciais... e pronto, estamos no dashboard principal.

*[Apontar para os elementos da tela]*

No canto superior esquerdo, vocês vêem o menu de navegação. As principais seções que a gente vai usar ao longo do curso são estas quatro: Search — para fazer nossas buscas UDM; Detection — onde ficam nossas regras YARA-L; Cases — que é o módulo de gestão de incidentes do SOAR; e Threat Intelligence.

*[Navegar para a aba Search]*

Aqui em Search, vocês já podem ver os eventos dos logs sintéticos do Banco Meridian que configuramos no Módulo 00. Vou fazer uma busca simples para mostrar como funciona:

*[Digitar na caixa de busca: metadata.event_type = 'USER_LOGIN']*

E olha — em menos de um segundo, temos todos os eventos de login dos últimos 7 dias. Isso é o poder do UDM: uma busca simples, formato padronizado, resultado instantâneo.

*[Navegar rapidamente por mais duas ou três seções]*

No Módulo 03, a gente vai entrar fundo aqui em Detection para escrever nossas próprias regras YARA-L. Por enquanto, só quero que você se familiarize com a navegação básica."

*[Dica de edição: use zoom digital nos elementos da tela para destacar menus e botões. Adicione callouts indicando o nome de cada seção.]*

---

**[RECAPITULAÇÃO E CHAMADA PARA O PRÓXIMO MÓDULO — 3 min | Tela: Slide de encerramento]**

*[Tom entusiasmado, motivador]*

"Ótimo! Vamos recapitular o que a gente viu neste módulo:

Um — o Google SecOps é uma plataforma cloud-native que combina SIEM, SOAR, UEBA e Threat Intelligence numa só solução, construída sobre a infraestrutura massiva do Google.

Dois — o modelo de pricing por ingestão é diferente do modelo tradicional por EPS ou por usuário, e isso muda completamente o TCO para organizações com grandes volumes de log.

Três — o UDM é o coração do Google SecOps: todos os logs, de qualquer fonte, são normalizados para o mesmo schema antes de serem armazenados.

E quatro — a plataforma foi projetada para resolver o principal problema dos SIEMs tradicionais: escala.

*[Pausa de 1 segundo]*

No próximo módulo — Módulo 02 — a gente vai colocar a mão na massa e começar a configurar a ingestão de logs no nosso tenant. Vamos entender como os forwarders funcionam, como escrever um parser CBN customizado e como validar que seus logs estão sendo normalizados corretamente no UDM.

Antes de avançar, faça o quiz deste módulo — são 5 questões, 10 minutinhos, e o feedback vai aparecer imediatamente após cada resposta.

Te vejo no Módulo 02. Até lá!"

---

*[ORIENTAÇÕES DE PRODUÇÃO PARA A EQUIPE:]*
- *Duração total desta aula: ~40 min (pode ser dividida em 2 pílulas: 1.1a e 1.1b)*
- *Inserir lower-thirds com nome do instrutor nos primeiros 30 segundos*
- *Adicionar legenda em português em todas as falas*
- *Música de fundo suave durante as transições entre blocos*
- *Quiz: programar no LMS com as 5 questões deste módulo, não-bloqueante*
- *Incluir link para o repositório GitHub na descrição do vídeo*

---

## Avaliação do Módulo 01

### Gabarito das Questões

| Questão | Resposta Correta | Justificativa                                                                       |
|:-------:|:----------------:|:------------------------------------------------------------------------------------|
|    1    |       b)         | Google SecOps usa modelo de ingestão (GB/dia), diferente do modelo EPS do QRadar    |
|    2    |       b)         | UDM normaliza logs de diferentes fontes para um schema comum                         |
|    3    |       c)         | Google SecOps suporta múltiplos provedores via feeds, forwarders e Bindplane         |
|    4    |       d)         | UEBA analisa comportamento de usuários e entidades com modelos de ML                 |
|    5    |       b)         | Escala de processamento em petabytes é o principal diferencial do Google SecOps      |

### Critérios de Avaliação

| Pontuação | Resultado                                                                  |
|:---------:|:---------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 02 com confiança                        |
| 4/5 (80%) | Muito bom! Revise o tópico correspondente à questão errada                |
| 3/5 (60%) | Recomendado rever as seções 1.3 e 1.4 antes de avançar                   |
| < 3 (< 60%)| Revisite todo o módulo — o conteúdo é fundamental para os próximos passos |

---

## Referências e Leitura Complementar

| Recurso                                       | Tipo       | Relevância                              |
|:----------------------------------------------|:----------:|:----------------------------------------|
| Google SecOps Documentation (cloud.google.com)| Oficial    | Referência técnica completa             |
| Gartner Magic Quadrant for SIEM 2025          | Relatório  | Posicionamento competitivo              |
| "Chronicle: Detecting Threats at Google Scale" (Google Blog) | Blog | Contexto histórico e técnico   |
| Anton Chuvakin — "Security Operations Center" (O'Reilly) | Livro | Fundamentos de SOC             |
| MITRE ATT&CK Framework — attack.mitre.org     | Framework  | Base de mapeamento de ameaças           |

---

*Módulo 01 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*  
*Próximo: [Módulo 02 — Ingestão e UDM](../modulo-02-ingestao-udm/README.md)*
