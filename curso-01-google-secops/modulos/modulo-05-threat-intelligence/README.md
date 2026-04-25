# Módulo 05 — Threat Intelligence Integrada
## Curso 1: Google SecOps Essentials · CECyber

| Campo              | Detalhe                                                             |
|:-------------------|:--------------------------------------------------------------------|
| **Carga Horária**  | 1h videoaula + 1h laboratório                                       |
| **Pré-requisito**  | Módulo 04 concluído · Conceitos de threat hunting ativos            |
| **MITRE ATT&CK**   | T1588, T1589, T1596 (Gather Victim Information)                     |
| **Ferramentas**    | Google SecOps TI Console, Mandiant Advantage, VirusTotal Enterprise |

---

## Objetivos de Aprendizagem

Ao concluir este módulo, você será capaz de:

1. Distinguir os quatro tipos de Threat Intelligence (estratégica, operacional, tática e técnica)
2. Usar o Mandiant Threat Intelligence integrado ao Google SecOps para enriquecer investigações
3. Configurar feeds STIX/TAXII e IOCs customizados no Google SecOps
4. Compreender como a TI enriquece automaticamente eventos UDM e alertas do SOAR
5. Aplicar a Pirâmide da Dor ao processo de seleção e descarte de IOCs

---

## Conteúdo do Módulo

### 5.1 Tipos de Threat Intelligence

A Threat Intelligence (TI) pode ser classificada em quatro tipos, cada um com um público-alvo
e horizonte temporal diferente.

Para contextualizar: sem Threat Intelligence, o Google SecOps é um sistema de detecção que
analisa APENAS o que acontece dentro do ambiente do Banco Meridian. Com TI integrada, o sistema
passa a ter conhecimento sobre o que está acontecendo FORA do banco — quais grupos APT estão
ativos, quais campanhas estão em andamento, quais IPs são usados para C2 por grupos que atacam
o setor financeiro brasileiro. Essa inteligência externa é o que permite ao SOC ser proativo
em vez de apenas reativo.

Um exemplo concreto do valor da TI para o Banco Meridian: se o FS-ISAC (Financial Services
ISAC) publicar um alerta sobre uma campanha ativa de phishing contra bancos brasileiros usando
um domínio específico como C2, o Google SecOps pode automaticamente verificar se algum host
do banco já tentou se conectar a esse domínio — antes de qualquer analista humano saber da
campanha. Essa é a diferença entre TI como "relatório para ler" e TI como "dado operacional
integrado ao SIEM".

```
PIRÂMIDE DOS TIPOS DE THREAT INTELLIGENCE
══════════════════════════════════════════════════════════════════

                        ┌──────────────────┐
                        │   ESTRATÉGICA    │  ← CISO, Diretoria
                        │  (trends, APTs,  │
                        │  geopolítica)    │
                        └────────┬─────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │      OPERACIONAL         │  ← Gestor de SOC
                    │  (TTPs, campanhas ativas,│
                    │  atores, timing)         │
                    └────────────┬─────────────┘
                                 │
               ┌─────────────────┴──────────────────┐
               │           TÁTICA                    │  ← Analista L2/L3
               │  (padrões de ataque, ferramentas,  │
               │  técnicas específicas — TTPs)       │
               └─────────────────┬──────────────────┘
                                 │
       ┌─────────────────────────┴──────────────────────────┐
       │                    TÉCNICA                          │  ← Analista L1 / SIEM
       │  (IOCs: IPs, domínios, hashes, URLs, e-mails)      │
       │  Mais acionável, mais volátil, menor vida útil      │
       └──────────────────────────────────────────────────────┘

══════════════════════════════════════════════════════════════════
```

| Tipo            | Audiência          | Horizonte | Exemplos                                                  |
|:----------------|:------------------:|:---------:|:----------------------------------------------------------|
| **Estratégica** | CISO, Board        | 6–24 meses| Relatórios de tendências, perfis de APTs por setor       |
| **Operacional** | Gestor de SOC, IR  | 1–6 meses | Campanhas ativas de phishing, infraestrutura de ataque   |
| **Tática**      | Analistas L2/L3    | 1–90 dias | TTPs do MITRE ATT&CK, playbooks de ataque                |
| **Técnica**     | Analistas L1, SIEM | Horas–dias| IPs maliciosos, domínios, hashes de malware, URLs        |

---

### 5.2 Mandiant Threat Intelligence no Google SecOps

O **Mandiant Threat Intelligence** está integrado nativamente ao Google SecOps desde a
aquisição da Mandiant pelo Google em 2022. Isso significa que os dados de TI da Mandiant
estão disponíveis sem configuração adicional para tenants com a licença adequada.

Essa integração nativa é um diferencial significativo em relação a outros SIEMs, onde você
precisaria assinar um feed de TI separado, configurar uma API key, criar regras de correlação
com os IOCs e manter essa integração funcionando. No Google SecOps, tudo isso é automático:
quando um IOC da Mandiant corresponde a um evento ingerido, o alerta é gerado sem nenhuma
configuração adicional do SOC.

> **Por que isso importa para o Banco Meridian:** O setor financeiro brasileiro é alvo frequente
> de grupos APT como o FIN7, APT34 e grupos regionais como o Prilex (especializado em fraudes
> com maquininhas de cartão). A Mandiant rastreia ativamente esses grupos e mantém feeds de
> IOCs atualizados com a infraestrutura usada em campanhas recentes. Com a integração nativa,
> o SOC do Banco Meridian recebe automaticamente alertas quando qualquer host interno tenta
> se comunicar com essa infraestrutura — mesmo que a campanha tenha começado horas antes.

#### 5.2.1 Applied Threat Intelligence (ATI)

O **Applied TI** é a camada que transforma dados brutos de inteligência em alertas acionáveis.
Ele automaticamente:

- Correlaciona IOCs da Mandiant com eventos ingeridos no UDM
- Gera alertas quando um IOC da Mandiant é observado no ambiente
- Enriquece eventos UDM com contexto de ameaça (nome do ator, campanha, malware relacionado)

```
FLUXO DO APPLIED TI:
═══════════════════════════════════════════════════════════════
  Mandiant IOC Feed                   Google SecOps UDM
  ─────────────────                   ──────────────────────
  IP: 185.220.101.33   ──────────►   NETWORK_CONNECTION
  Ator: APT34                         target.ip = 185.220.101.33
  Campanha: OilRig                    │
  Confiança: HIGH                     ▼
                                    Alerta gerado automaticamente:
                                    "Conexão a C2 do APT34 detectada"
                                    + contexto: OilRig, Iran-nexus,
                                      setor financeiro, confiança HIGH
═══════════════════════════════════════════════════════════════
```

#### 5.2.2 Threat Actors, Campaigns e Indicators no Console

```
Navegação: Threat Intelligence → (Actors | Campaigns | Indicators)

Threat Actors:
  - Perfis completos de grupos APT (APT1, APT34, FIN7, Lazarus, etc.)
  - TTPs mapeadas ao MITRE ATT&CK
  - Histórico de campanhas e alvos
  - Indicadores associados ao ator

Campaigns:
  - Campanhas ativas ou recentes de grupos APT
  - Relação de alvos por setor e região
  - IOCs específicos da campanha
  - Timeline de atividade

Indicators:
  - Busca por IP, domínio, hash, URL, e-mail
  - Confiança (LOW, MEDIUM, HIGH)
  - Data de observação mais recente
  - Contexto de ameaça associado
```

#### 5.2.3 Verificar um IP Suspeito no Mandiant

```
Exemplo de investigação: IP 185.220.101.33 identificado em logs do Banco Meridian

1. Acessar: Threat Intelligence → Indicators → buscar 185.220.101.33

Resultado Mandiant:
───────────────────────────────────────────────────────
IP Address: 185.220.101.33
Confidence: HIGH
Threat Category: Command and Control (C2)
Associated Actor: APT34 (alias: OilRig, Helix Kitten)
Associated Malware: POWRUNER, BONDUPDATER
Campaigns: OilRig 2025-Q1 — Financial Sector
Last Observed: 2026-04-22 (2 dias atrás)
Context: Servidor C2 ativo; infraestrutura baseada em VPS
         comercial em Frankfurt, Alemanha
Recommended Action: BLOCK e investigar hosts que se conectaram
───────────────────────────────────────────────────────
```

---

### 5.3 VirusTotal Enterprise Augment

O **VirusTotal Enterprise** está integrado nativamente ao Google SecOps para enriquecimento
automático de indicadores. Funciona em duas modalidades:

#### 5.3.1 Enriquecimento Automático de IOCs

Quando um evento UDM contém um campo `file.sha256`, `target.url` ou `target.ip`, o Google
SecOps automaticamente consulta o VirusTotal e adiciona os resultados ao contexto do evento:

```
Evento UDM (antes do enriquecimento):
───────────────────────────────────────────────────
principal.process.file.sha256 = "a1b2c3d4..."
principal.hostname = "WRK-DIANA-007"
metadata.event_type = "PROCESS_LAUNCH"
───────────────────────────────────────────────────

Evento UDM (após enriquecimento automático via VirusTotal):
───────────────────────────────────────────────────
... (campos anteriores mantidos)
enrichment.vt_detections = 45
enrichment.vt_total_engines = 72
enrichment.vt_threat_category = "trojan"
enrichment.vt_threat_name = "Cobalt Strike Beacon"
enrichment.vt_first_seen = "2026-01-15"
enrichment.vt_last_seen = "2026-04-23"
enrichment.vt_reputation = -85
───────────────────────────────────────────────────
```

#### 5.3.2 Investigação Manual via VirusTotal no Console

```
Navegação: Threat Intelligence → VirusTotal → buscar hash, IP ou domínio

Campos retornados:
- Positives: X/Y motores de antivírus detectaram como malicioso
- Threat category: trojan, ransomware, c2, adware, etc.
- First submission / Last analysis date
- Community score e comentários
- Network indicators: IPs, domínios, URLs relacionados
- Behavior: sandbox analysis (processos criados, conexões, registry keys)
```

---

### 5.4 Feeds STIX/TAXII: Configuração e Consumo

Para o Banco Meridian, os feeds externos mais relevantes são os especializados no setor
financeiro brasileiro: o FS-ISAC (Financial Services Information Sharing and Analysis Center),
o CERT.BR (que mantém feeds de IOCs de ataques contra infraestrutura crítica brasileira) e
grupos de compartilhamento coordenados pela FEBRABAN. Esses feeds regionais e setoriais
frequentemente contêm IOCs que não estão nos feeds globais, pois são específicos de campanhas
contra o setor bancário brasileiro — phishing focado no M365, fraudes com PIX e ransomware
direcionado a instituições financeiras.

> **💡 Dica do instrutor:** Feeds de TI são mais úteis quando são ESPECÍFICOS para o seu
> setor e região. Um feed genérico com 500.000 IOCs vai gerar muitos falsos positivos e
> sobrecarregar o SIEM com correlações inúteis. Priorize feeds do FS-ISAC e CERT.BR antes
> de adicionar feeds comerciais genéricos.

**STIX** (Structured Threat Information eXpression) é o formato padrão para compartilhar
informações de ameaças. **TAXII** (Trusted Automated eXchange of Intelligence Information)
é o protocolo de transporte para compartilhar dados STIX.

#### 5.4.1 Configurar um Feed TAXII no Google SecOps

```
Navegação: Settings → Ingestion → Threat Intelligence → + Add Feed → TAXII

Campos de configuração:
  - Feed Name: "MISP - Banco Central CERT"
  - TAXII Server URL: https://taxii.bcb.gov.br/taxii21/
  - Collection ID: fs-isac-iocs
  - API Key: [chave fornecida pelo provedor]
  - Polling Interval: 15 minutes
  - Start Date: [data de início da coleta]
```

#### 5.4.2 Manutenção de Feeds TAXII

| Ação de manutenção              | Frequência   | Por que é importante                                     |
|:--------------------------------|:------------:|:---------------------------------------------------------|
| Verificar status do feed        | Diária       | Feeds offline = blindspot de TI                         |
| Revisar volume de IOCs novos    | Semanal      | Feeds com poucos IOCs podem estar desatualizados         |
| Validar qualidade dos IOCs      | Mensal       | Feeds de baixa qualidade geram FPs nas detecções        |
| Renegociar access key           | Conforme TTL | Chaves expiradas causam interrupção silenciosa           |

---

### 5.5 IOCs Customizados: Listas de Indicadores Proprietários

Além dos feeds externos, o Banco Meridian pode criar suas próprias listas de IOCs baseadas
em incidentes internos, acordos com parceiros do setor financeiro (FS-ISAC) e pesquisa interna.

#### 5.5.1 Criar uma Lista de IOCs Customizada

```
Navegação: Threat Intelligence → Custom IOCs → + Create List

Exemplo: Lista de IPs observados no ataque de password spray de abril/2026

Nome da lista: bank-meridian-incident-apr2026
Tipo: IP Address
Confiança: HIGH
Descrição: "IPs usados no ataque de password spray identificado em 2026-04-07"
Tags: password-spray, incident-response, t1110-003

IPs a adicionar:
  203.45.12.89    # IP principal do atacante
  185.220.101.33  # IP do C2 identificado no hunting
  91.234.55.172   # IP de exfiltração identificado no capstone
```

#### 5.5.2 Usar IOCs Customizados em Regras YARA-L

```yara-l
rule conexao_a_iocs_internos {
  meta:
    description = "Conexão a IP na lista de IOCs internos do Banco Meridian"
    severity = "HIGH"
  events:
    $e1.metadata.event_type = "NETWORK_CONNECTION"
    // Referência à lista customizada de IOCs
    $e1.target.ip in %bank-meridian-incident-apr2026
  condition:
    $e1
}
```

---

### 5.6 Integração TI → SIEM: Enriquecimento de Eventos UDM

**O que esta integração faz e por que muda o trabalho do analista:** O enriquecimento TI → UDM adiciona contexto de inteligência de ameaças diretamente em cada evento normalizado, antes que o analista sequer abra o alerta. Sem enriquecimento, um evento de conexão de rede mostra apenas `principal.ip = "203.45.12.89"` — o analista precisaria copiar o IP, abrir o VirusTotal em outra aba, esperar a resposta e interpretar o resultado. Com enriquecimento, o mesmo evento mostra automaticamente `principal.ip_geo_artifact.attribute.labels: ["APT28", "Fancy Bear", "Russia"]` e `security_result.threat_name: "Cobalt Strike C2"` — o analista vê em 2 segundos que o IP é infraestrutura de APT russo. Essa redução no tempo de contextualização é o principal driver de redução de MTTD em SOCs com grande volume de alertas.

O diagrama a seguir mostra como a Threat Intelligence enriquece os eventos UDM:

```
FLUXO DE ENRIQUECIMENTO TI → UDM:
══════════════════════════════════════════════════════════════════

  Log bruto chega                    Evento UDM normalizado
  (ex: conexão de rede)              (ex: NETWORK_CONNECTION)
         │                                    │
         ▼                                    ▼
   Parser CBN / Nativo          ┌─────────────────────────────┐
         │                      │  Enriquecimento automático  │
         │                      │                             │
         ▼                      │  Mandiant: IP é C2 do APT34 │
  Campos UDM populados          │  VirusTotal: hash malicioso │
  (ip, hostname, userid, etc.)  │  MISP: domínio em campanha  │
         │                      │  Lista interna: IP banido   │
         └──────────────────────┤                             │
                                └─────────────────────────────┘
                                         │
                                         ▼
                              Evento UDM enriquecido:
                              security_result.threat_name = "Cobalt Strike"
                              security_result.category = "SOFTWARE_MALICIOUS"
                              enrichment.ti_confidence = "HIGH"
                              enrichment.ti_actor = "APT34"
                              enrichment.ti_campaign = "OilRig 2025-Q1"

══════════════════════════════════════════════════════════════════
```

---

### 5.7 Integração TI → SOAR: TI nos Playbooks para Tomada de Decisão

**O que este padrão de integração faz e por que é importante:** A integração TI → SOAR transforma dados de inteligência de ameaças em critérios objetivos para decisões automatizadas de resposta a incidentes. Sem TI no playbook, o analista precisaria consultar manualmente o Mandiant ou VirusTotal para cada hash ou IP detectado antes de decidir se isola o host — um processo que leva de 5 a 15 minutos por alerta. Com a integração, o SOAR consulta automaticamente as fontes de TI e toma a decisão de isolamento em segundos, com base em thresholds pré-definidos (ex: `positives >= 10` ou `confidence = HIGH`). Esta automação é especialmente crítica para incidentes de ransomware, onde cada minuto de atraso na contenção pode significar a propagação para novos hosts.

O SOAR usa dados de Threat Intelligence como entrada para decisões nos playbooks:

```
EXEMPLO: Playbook de resposta a malware usando TI para decisão automática
═════════════════════════════════════════════════════════════════════════

  Alerta disparado: processo suspeito com hash desconhecido
         │
         ▼
  [Ação SOAR] Consultar VirusTotal com o hash
         │
         ├── VT positives >= 10?  → SIM → Isolar host automaticamente
         │                                 Abrir P1 no Jira
         │                                 Notificar CISO
         │
         └── VT positives < 10?   → NÃO → Consultar Mandiant
                   │
                   ├── IOC na base Mandiant? → SIM → Mesmo fluxo de isolamento
                   │
                   └── Sem informação       → Abrir P2 no Jira
                                              Assignar para analista L2
                                              Coletar artefatos adicionais

═════════════════════════════════════════════════════════════════════════
```

---

### 5.8 Pirâmide da Dor Aplicada ao Google SecOps

A **Pirâmide da Dor** (Pain Pyramid), criada por David Bianco, classifica os tipos de
indicadores por sua capacidade de causar "dor" ao atacante se forem detectados e bloqueados.

```
PIRÂMIDE DA DOR — APLICAÇÃO NO GOOGLE SECOPS
══════════════════════════════════════════════════════════════════

                         ┌──────────────────────┐
                         │  Objetivos (Goals)   │  ← DIFÍCIL de mudar
                         │  "roubar dados do    │    para o atacante
                         │   Banco Meridian"    │
                         └──────────┬───────────┘
                                    │
                       ┌────────────┴───────────────┐
                       │  TTPs (Técnicas, Táticas,  │  ← DOLOROSO de mudar
                       │  Procedimentos)            │    → Usar YARA-L multi-event
                       │  T1110.003, T1071.001      │    → Detectar no UEBA
                       └────────────┬───────────────┘
                                    │
                      ┌─────────────┴────────────────┐
                      │     Ferramentas              │  ← INCÔMODO de mudar
                      │  Cobalt Strike, Mimikatz     │    → Detecção por hash
                      │  Empire, Metasploit          │    → Detecção por assinatura
                      └─────────────┬────────────────┘
                                    │
                    ┌───────────────┴──────────────────┐
                    │     Infraestrutura de Rede       │  ← MODERADO de mudar
                    │  Domínios C2, IPs de C2          │    → Feeds TAXII/STIX
                    └───────────────┬──────────────────┘
                                    │
                  ┌─────────────────┴────────────────────┐
                  │         Artefatos de Rede            │  ← FÁCIL de mudar
                  │  User-Agents, URIs de C2 específicos │    para o atacante
                  └─────────────────┬────────────────────┘
                                    │
                 ┌──────────────────┴─────────────────────┐
                 │            Hash de Arquivo             │  ← TRIVIAL de mudar
                 │  MD5, SHA-1, SHA-256 de malware        │    → menos útil no long run
                 └──────────────────────────────────────────┘

Princípio: quanto mais alto na pirâmide, mais difícil é para o atacante se adaptar,
e mais durável e valiosa é a detecção.

Recomendação para Google SecOps:
 - Regras YARA-L baseadas em TTPs (topo) → mais durável
 - Feeds de IP/domínio (meio) → útil mas volátil
 - Detecção por hash (base) → útil mas atacante troca em segundos

══════════════════════════════════════════════════════════════════
```

---

### 5.9 Ciclo de Vida de um IOC

| Fase          | Descrição                                                                   | Ação no Google SecOps                               |
|:-------------|:-----------------------------------------------------------------------------|:----------------------------------------------------|
| **Criação**   | IOC identificado via hunting, IR ou feed externo                            | Adicionar à lista customizada ou configurar feed    |
| **Validação** | Verificar se o IOC é legítimo (não é IP de CDN ou serviço legítimo)         | Consultar Mandiant + VirusTotal + pesquisa manual   |
| **Uso**       | IOC ativo sendo usado para detecção e enriquecimento                        | Associar a regras YARA-L; monitorar alertas         |
| **Revisão**   | IOC pode ter expirado (IP reutilizado, domínio expirado, hash não-relevante) | Revisar mensalmente; checar last_seen da Mandiant   |
| **Descarte**  | IOC desatualizado, reutilizado por entidade legítima ou com muitos FPs      | Remover da lista ou reduzir confiança para LOW      |

---

### 5.10 Fontes de TI Open-Source (para Ambientes sem Mandiant Enterprise)

| Fonte                    | URL                          | Tipo de IOC         | Foco                              |
|:-------------------------|:-----------------------------|:-------------------:|:----------------------------------|
| **MISP Community**       | misp-project.org             | Todos              | Compartilhamento colaborativo      |
| **AlienVault OTX**       | otx.alienvault.com           | IP, domínio, hash   | Comunidade ampla, volume alto     |
| **abuse.ch URLhaus**     | urlhaus.abuse.ch             | URL, domínio        | Distribuição de malware           |
| **abuse.ch MalwareBazaar**| bazaar.abuse.ch             | Hash de malware     | Amostras de malware               |
| **Emerging Threats**     | rules.emergingthreats.net    | IP, domínio, Suricata| Firewall/IDS rules                |
| **FeodoTracker**         | feodotracker.abuse.ch        | IP                  | Servidores C2 de botnet           |
| **Phishtank**            | phishtank.com                | URL                 | Páginas de phishing               |
| **CERT.br**              | cert.br/indicadores          | IP, URL, hash       | Específico para Brasil            |
| **FS-ISAC**              | fsisac.com                   | Todos               | Setor financeiro (acesso restrito)|

---

## Atividades de Fixação

### Quiz — Módulo 05

**Questão 1:** O analista do SOC do Banco Meridian recebeu um hash SHA-256 de um malware
identificado em um ataque ao setor financeiro. Segundo a Pirâmide da Dor, qual é o valor
estratégico de bloquear apenas este hash?

- [ ] a) Alto — bloqueio de hash é a defesa mais eficaz e durável contra malware
- [ ] b) Baixo — hash é o tipo de indicador mais fácil de contornar para o atacante (basta recompilar o malware)
- [ ] c) Médio — hash identifica a ferramenta, que é mais difícil de mudar que o IP
- [ ] d) Nulo — hashes de malware não são aceitos como IOC no Google SecOps

**Resposta correta:** b) — Na Pirâmide da Dor, hash está na base — é trivial para o atacante alterar. Bloquear o hash é útil no curto prazo, mas não é uma defesa durável.

---

**Questão 2:** O time de segurança do Banco Meridian quer configurar uma integração de TI
com o FS-ISAC (Financial Services ISAC) para receber IOCs específicos do setor financeiro.
Qual protocolo de transporte padronizado deve ser usado?

- [ ] a) RSS/Atom — protocolo universal de feed web
- [ ] b) TAXII (Trusted Automated eXchange of Intelligence Information) — protocolo padrão para compartilhamento de dados STIX
- [ ] c) SNMP — protocolo de monitoramento de rede
- [ ] d) SMTP — protocolo de e-mail para recebimento de boletins de TI

**Resposta correta:** b) — TAXII é o protocolo padrão do setor para compartilhamento automático de inteligência em formato STIX.

---

**Questão 3:** Um analista do Banco Meridian usa o Google SecOps e percebe que alguns eventos
UDM de conexões de rede têm um campo `enrichment.ti_confidence = "HIGH"` e `enrichment.ti_actor
= "APT34"`. O que isso indica?

- [ ] a) O analista manualmente adicionou essa informação ao evento via edição do UDM
- [ ] b) O enriquecimento automático da Mandiant Threat Intelligence correlacionou o IP de destino com IOCs do grupo APT34
- [ ] c) O UEBA calculou que a conexão tem 90% de probabilidade de ser maliciosa
- [ ] d) A regra YARA-L que gerou o alerta tem `meta.author = "APT34"` configurado

**Resposta correta:** b) — O Applied Threat Intelligence da Mandiant, integrado nativamente, enriquece automaticamente eventos com contexto de ameaça quando os indicadores (IPs, domínios, hashes) constam na base de dados Mandiant.

---

**Questão 4:** No ciclo de vida de um IOC, qual fase vem imediatamente após a criação
de um novo indicador identificado durante um exercício de threat hunting?

- [ ] a) Uso — o IOC deve ser adicionado às regras YARA-L imediatamente
- [ ] b) Descarte — IOCs de hunting têm vida curta e devem ser descartados após o uso
- [ ] c) Validação — verificar se o IOC é legítimo (não é CDN ou serviço legítimo) antes de usá-lo
- [ ] d) Revisão — revisar o IOC mensalmente antes de qualquer uso

**Resposta correta:** c) — Validação é obrigatória antes do uso. IOCs não validados geram FPs e esgotam a credibilidade do sistema de detecção.

---

**Questão 5:** Segundo a Pirâmide da Dor, qual tipo de indicador causa MAIS dor ao atacante
quando detectado e bloqueado, sendo portanto a categoria mais valiosa para investimento em
capacidades de detecção?

- [ ] a) Hashes de arquivo (SHA-256, MD5) — identificam o malware específico
- [ ] b) IPs e domínios de C2 — bloqueiam a infraestrutura do atacante
- [ ] c) TTPs (Táticas, Técnicas e Procedimentos) mapeadas ao MITRE ATT&CK
- [ ] d) Artefatos de rede como User-Agents específicos

**Resposta correta:** c) — TTPs estão no topo da Pirâmide da Dor. Para o atacante, mudar a técnica é custoso (requer retreinamento, novas ferramentas, novas operações). Detectar TTPs via YARA-L multi-event é a estratégia mais durável.

---

## Roteiro de Gravação — Instrutor (em Primeira Pessoa)

> **Este roteiro é para uso exclusivo do instrutor. A aula é de 50 minutos e mais intensa
> conceitualmente — calibre o ritmo para garantir que os conceitos da Pirâmide da Dor e
> da integração TI→SOAR fiquem claros.**

---

### AULA 5.1 — Threat Intelligence Integrada no Google SecOps (50 min)

---

**[ABERTURA — 3 min | Tela: Slide com a Pirâmide da Dor]**

"Bem-vindo ao Módulo 05. Hoje vamos falar de Threat Intelligence — a camada de contexto que
transforma dados brutos em inteligência acionável.

Uma coisa que eu sempre digo para os meus alunos: um SIEM sem Threat Intelligence é como um
detetive sem prontuário criminal. Você vê que algo aconteceu, mas não sabe quem fez, por quê,
ou se já aconteceu antes em outro lugar.

O Google SecOps tem uma vantagem enorme aqui: a Mandiant está integrada nativamente. Isso
significa que enquanto você duerme, a plataforma está correlacionando seus logs com a maior
base de dados de inteligência de ameaças do mundo. Vamos entender como aproveitar isso ao máximo."

---

**[BLOCO 1: Os quatro tipos de TI — 8 min | Tela: Pirâmide dos tipos de TI]**

"Comecemos com os fundamentos. Threat Intelligence não é só uma lista de IPs maliciosos.
É um espectro que vai do estratégico ao técnico.

*[Apontar para cada nível da pirâmide]*

Na base, a TI técnica: IOCs concretos — IPs, domínios, hashes, URLs. É a mais acionável
no dia a dia do SOC e a que mais rapidamente fica obsoleta. O atacante muda de IP em questão
de horas.

Subindo um nível, artefatos de rede e ferramentas: User-Agents customizados, URIs de C2,
binários específicos. Mais estável que IPs, mas o atacante ainda pode mudar.

E lá em cima, as TTPs — Táticas, Técnicas e Procedimentos. Aqui é onde está o valor real
de longo prazo. Um grupo APT como o APT34 não muda seu modus operandi a cada campanha.
Eles continuam usando spear phishing, Kerberoasting, exfiltração via DNS. Se você detecta
as TTPs, você detecta o grupo independentemente de qual IP ou ferramenta eles estão usando
neste mês.

Esse é o conceito da Pirâmide da Dor, criada pelo David Bianco. E é o guia para priorizarmos
nosso investimento em capacidades de detecção."

*[Dica de edição: usar animação mostrando a pirâmide de baixo para cima, com exemplos concretos em cada nível]*

---

**[BLOCO 2: Mandiant TI ao vivo — 15 min | Tela: Google SecOps Console → Threat Intelligence]**

"Agora vamos ao console. Vou mostrar o módulo de Threat Intelligence do Google SecOps.

*[Navegar para Threat Intelligence no console]*

Aqui temos três seções principais: Threat Actors, Campaigns e Indicators.

Vou em Indicators e buscar o IP que identificamos na investigação de hunting: 185.220.101.33.

*[Digitar na busca e mostrar os resultados]*

Olha o que a Mandiant sabe sobre esse IP. Confidence HIGH. Associado ao APT34 — também
conhecido como OilRig ou Helix Kitten. Usado em campanhas contra o setor financeiro no
Oriente Médio e América Latina. Last observed há 2 dias.

Isso muda completamente a gravidade do nosso incidente. Não é um atacante aleatório. É um
grupo sofisticado com histórico de ataques a bancos. Essa informação vai para o relatório
de incidente, para a decisão de resposta, para o CISO.

Agora vou em Threat Actors e abro o perfil completo do APT34...

*[Navegar para o perfil do ator]*

Aqui estão todas as TTPs que eles usam — mapeadas ao MITRE ATT&CK. E olha isso: eles têm
histórico de usar password spray (T1110.003) como vetor inicial. Que foi exatamente o que
aconteceu com o Banco Meridian. Isso não é coincidência — é um indicativo forte de que
estamos lidando com o mesmo grupo."

---

**[BLOCO 3: VirusTotal + IOCs customizados — 10 min]**

"O VirusTotal Enterprise trabalha ao lado da Mandiant no Google SecOps. Enquanto a Mandiant
foca em inteligência sobre grupos APT e campanhas, o VirusTotal foca na análise de artefatos
técnicos: hashes de malware, URLs maliciosas, domínios.

*[Demonstrar busca de hash no VirusTotal via SecOps]*

E aqui está a mágica do enriquecimento automático: sem que eu faça nada, quando o Google
SecOps ingere um evento com um hash de processo desconhecido, ele automaticamente consulta
o VirusTotal e adiciona os resultados ao evento UDM. Então quando eu abro esse alerta, já vejo:
45/72 engines detectaram como malicioso, categoria trojan, nome: Cobalt Strike Beacon.

Isso transforma a triagem. Em vez de o analista L1 precisar copiar o hash, ir ao VirusTotal,
copiar o resultado de volta, tudo já está no alerta. O tempo de triagem cai de 15 para 2 minutos.

E para IOCs que nenhuma fonte externa conhece — como os IPs identificados em incidentes internos
do Banco Meridian — usamos as listas customizadas de IOCs. Mostro como criar uma ao vivo..."

*[Demonstrar criação de lista customizada no console]*

---

**[RECAPITULAÇÃO E CHAMADA PARA O PRÓXIMO MÓDULO — 14 min | Tela: Slide de encerramento]**

"Recapitulando o Módulo 05:

TI tem quatro tipos: estratégica, operacional, tática e técnica. A técnica é a mais acionável,
a tática é a mais durável. Invista nos dois.

Mandiant é sua fonte primária no Google SecOps: enriquecimento automático, perfis de atores,
campanhas ativas, IOCs com confiança qualificada.

VirusTotal enriquece automaticamente artefatos técnicos — sem ação manual do analista.

Feeds STIX/TAXII conectam o Google SecOps a fontes externas como FS-ISAC, MISP, abuse.ch.

E a Pirâmide da Dor guia suas prioridades: detectar TTPs via YARA-L multi-event causa
mais dor ao atacante do que bloquear IPs.

No próximo módulo — Módulo 06 — vamos entrar no SOAR: playbooks, automação e resposta a
incidentes. É onde tudo que aprendemos até aqui começa a se unir em um sistema integrado
de operações de segurança. Te vejo lá!"

*[ORIENTAÇÕES DE PRODUÇÃO:]*
- *Duração total: 50 min (módulo mais curto — aula única)*
- *Demonstrações ao vivo no console são obrigatórias nas seções 5.2 e 5.3*
- *Pirâmide da Dor: usar animação gráfica — conceito central deste módulo*
- *Se tenant não tiver Mandiant completo: usar screenshots do material como alternativa*

---

## Avaliação do Módulo 05

### Gabarito das Questões de Múltipla Escolha

| Questão | Resposta Correta | Justificativa                                                                                    |
|:-------:|:----------------:|:--------------------------------------------------------------------------------------------------|
|    1    |       b)         | Hash está na base da Pirâmide da Dor — trivial de mudar; baixo valor estratégico de longo prazo |
|    2    |       b)         | TAXII é o protocolo padrão de transporte para dados STIX em compartilhamento de TI              |
|    3    |       b)         | Applied TI da Mandiant enriquece automaticamente eventos com contexto de ameaça correlacionado   |
|    4    |       c)         | Validação é obrigatória antes do uso para evitar FPs e danos à credibilidade do sistema          |
|    5    |       c)         | TTPs no topo da pirâmide causam mais dor — atacante precisa mudar todo o modus operandi          |

### Critérios de Avaliação

| Pontuação | Resultado                                                                              |
|:---------:|:---------------------------------------------------------------------------------------|
| 5/5 (100%)| Excelente! Prossiga para o Módulo 06 — SOAR                                           |
| 4/5 (80%) | Muito bom! Revise o tópico da questão errada antes de avançar                         |
| 3/5 (60%) | Recomendado rever as seções 5.4 e 5.8 (TAXII e Pirâmide da Dor) antes de avançar     |
| < 3 (< 60%)| Revisite todo o módulo — TI fundamenta a tomada de decisão nos playbooks do Módulo 06|

---

*Módulo 05 · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
*Anterior: [Módulo 04 — Threat Hunting e UEBA](../modulo-04-threat-hunting-ueba/README.md)*
*Próximo: [Módulo 06 — SOAR e Playbooks](../modulo-06-soar-playbooks/README.md)*
