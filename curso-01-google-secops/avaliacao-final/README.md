# Avaliação Final — Curso 1: Google SecOps Essentials
## CECyber — Programa de Formação Security Operations em Nuvem

| Campo                    | Detalhe                                                             |
|:-------------------------|:--------------------------------------------------------------------|
| **Formato**              | 80% Múltipla Escolha + 20% Estudo de Caso Prático                  |
| **Duração Total**        | 2 horas 30 minutos                                                  |
| **Parte 1 (Múltipla Escolha)** | 40 questões · 1h 30min                                      |
| **Parte 2 (Estudo de Caso)**   | 1 cenário · 5 perguntas discursivas · 60 min                |
| **Peso**                 | Parte 1: 80% da nota · Parte 2: 20% da nota                        |
| **Nota Mínima**          | 70% para aprovação                                                  |
| **Material Permitido**   | Consulta ao repositório GitHub (sem internet externa)               |
| **Cobertura**            | Todos os 7 módulos do curso                                         |

---

## Instruções Gerais

1. Leia todas as questões com atenção antes de responder
2. Para a Parte 1, marque apenas uma alternativa por questão
3. Para a Parte 2, responda de forma objetiva e técnica — seja específico
4. Use terminologia técnica correta (nomes de produtos, técnicas MITRE, comandos)
5. Nos campos de query/código, escreva a sintaxe exata (YARA-L ou UDM Search)
6. O gabarito completo está na seção final deste documento

---

## Parte 1 — Questões de Múltipla Escolha (80%)

### Nível Básico — Questões 01 a 12 (2,5 pontos cada)

**Q01.** O Google SecOps (Chronicle) é uma plataforma de Security Operations que combina múltiplos componentes em um único produto. Qual das seguintes combinações representa corretamente os quatro componentes principais?

- [ ] A) SIEM, EDR, WAF e CASB
- [ ] B) SIEM, SOAR, UEBA e Threat Intelligence
- [ ] C) SIEM, XDR, CSPM e CNAPP
- [ ] D) IDS, SOAR, IAM e Log Management

---

**Q02.** O modelo de precificação do Google SecOps é baseado em:

- [ ] A) Número de usuários com acesso ao console
- [ ] B) Número de regras YARA-L ativas
- [ ] C) Volume de dados ingeridos (GB/dia)
- [ ] D) Número de alertas gerados por mês

---

**Q03.** O Unified Data Model (UDM) do Google SecOps foi projetado para:

- [ ] A) Comprimir logs para reduzir custos de armazenamento
- [ ] B) Normalizar eventos de diferentes fontes para um schema comum, facilitando busca e correlação
- [ ] C) Criptografar logs em repouso usando AES-256
- [ ] D) Formatar logs para exportação ao formato SIEM legado

---

**Q04.** Qual componente do Google SecOps é responsável por criar uma "baseline" de comportamento de usuários e detectar desvios estatisticamente anômalos?

- [ ] A) YARA-L Engine
- [ ] B) Bindplane OP Agent
- [ ] C) Chronicle SOAR
- [ ] D) UEBA (User and Entity Behavior Analytics)

---

**Q05.** O campo `metadata.event_type` no UDM do Google SecOps é utilizado para:

- [ ] A) Identificar a versão do agente de coleta
- [ ] B) Classificar o tipo de evento (USER_LOGIN, FILE_ACCESS, NETWORK_CONNECTION, etc.)
- [ ] C) Armazenar o nível de severidade do evento
- [ ] D) Registrar o horário de ingestão do evento no Chronicle

---

**Q06.** No contexto de ingestão de logs no Google SecOps, o Bindplane OP Agent é utilizado para:

- [ ] A) Criar regras de detecção YARA-L
- [ ] B) Coletar e encaminhar logs de endpoints e servidores para o Google SecOps
- [ ] C) Executar playbooks SOAR automaticamente
- [ ] D) Gerenciar as permissões IAM do tenant Chronicle

---

**Q07.** A técnica MITRE ATT&CK T1110.003 refere-se a:

- [ ] A) Exfiltração de dados via protocolo DNS
- [ ] B) Injeção de SQL em aplicações web
- [ ] C) Password Spraying — tentativa de uma senha comum contra muitos usuários
- [ ] D) Lateral movement via Pass-the-Hash

---

**Q08.** Em uma regra YARA-L, a seção `match:` é utilizada para:

- [ ] A) Definir os campos que aparecerão no alerta gerado
- [ ] B) Definir a janela temporal e os campos de agrupamento dos eventos
- [ ] C) Filtrar quais eventos serão avaliados pela regra
- [ ] D) Configurar a severidade do alerta

---

**Q09.** A Configuration-Based Normalization (CBN) no Google SecOps é utilizada para:

- [ ] A) Configurar políticas de retenção de dados
- [ ] B) Criar parsers customizados para fontes de log proprietárias que não têm parser nativo
- [ ] C) Normalizar a configuração dos data connectors
- [ ] D) Configurar alertas de disponibilidade do tenant

---

**Q10.** Em uma busca UDM Search no Google SecOps, qual operador é utilizado para buscar eventos que corresponderam a um padrão de texto usando expressão regular?

- [ ] A) `equals`
- [ ] B) `contains`
- [ ] C) `/regex_pattern/`
- [ ] D) `LIKE "pattern%"`

---

**Q11.** O modelo de retenção "UD Mode" no Google SecOps oferece retenção padrão de:

- [ ] A) 30 dias
- [ ] B) 90 dias
- [ ] C) 6 meses
- [ ] D) 1 ano

---

**Q12.** Qual é a principal diferença entre uma Live Rule e uma Retrohunt Rule no Google SecOps?

- [ ] A) Live Rules detectam em tempo real; Retrohunt Rules analisam dados históricos já armazenados
- [ ] B) Live Rules são mais caras; Retrohunt Rules são gratuitas
- [ ] C) Live Rules usam YARA-L 1.0; Retrohunt Rules usam YARA-L 2.0
- [ ] D) Live Rules só funcionam com logs Windows; Retrohunt Rules com qualquer tipo de log

---

### Nível Intermediário — Questões 13 a 32 (2,5 pontos cada)

**Q13.** Na sintaxe YARA-L 2.0, o símbolo `#` (hash) antes de uma variável de evento, como `#e1`, representa:

- [ ] A) Um comentário de linha
- [ ] B) A cardinalidade (contagem) dos eventos que correspondem à variável
- [ ] C) Um campo obrigatório na seção `meta`
- [ ] D) Uma referência a um campo personalizado (custom field)

---

**Q14.** Você está investigando um possível password spray no Google SecOps. Qual das seguintes queries UDM Search melhor identifica tentativas de login falhadas de um mesmo IP externo para múltiplos usuários?

- [ ] A) `metadata.event_type = "NETWORK_FLOW" AND principal.ip = "203.45.12.89"`
- [ ] B) `metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK" AND principal.ip = "203.45.12.89"`
- [ ] C) `metadata.event_type = "USER_LOGIN" AND security_result.action = "ALLOW" AND principal.ip = "203.45.12.89"`
- [ ] D) `metadata.event_type = "FILE_ACCESS" AND security_result.action = "BLOCK"`

---

**Q15.** Uma regra YARA-L que utiliza a função `count(distinct $e1.target.user.email_addresses)` está medindo:

- [ ] A) O número total de eventos de login na janela
- [ ] B) O número de usuários-alvo únicos que foram alvo dos eventos capturados
- [ ] C) O número de IPs de origem distintos
- [ ] D) O tamanho médio dos payloads dos eventos

---

**Q16.** No contexto de Threat Intelligence no Google SecOps, qual é a função da integração com o VirusTotal Augment?

- [ ] A) Executar análise dinâmica de malware em sandbox
- [ ] B) Enriquecer automaticamente eventos com reputação de IPs, domínios e hashes usando a base de dados do VirusTotal
- [ ] C) Criar regras de detecção baseadas em padrões de malware do VirusTotal
- [ ] D) Substituir o Mandiant Threat Intelligence em ambientes que não têm licença Google

---

**Q17.** Um analista de SOC recebe um alerta do Google SecOps indicando que uma conta de usuário fez login às 03:27 de São Paulo, de um IP localizado na Lituânia, quando o comportamento histórico do usuário é sempre de logins das 08h às 19h do Brasil. Qual componente do Google SecOps gerou esse tipo de alerta?

- [ ] A) YARA-L Engine (regra multi-event)
- [ ] B) UEBA com Risk Analytics e detecção de comportamento anômalo
- [ ] C) Bindplane OP Agent com análise de horário
- [ ] D) Chronicle SOAR com playbook de verificação geográfica

---

**Q18.** Na seção `events:` de uma regra YARA-L, a diretiva `not` é utilizada para:

- [ ] A) Negar toda a regra se a condição for verdadeira
- [ ] B) Excluir eventos que correspondam ao padrão indicado (supressão de falsos positivos)
- [ ] C) Definir um evento opcional que não precisa estar presente
- [ ] D) Inverter a severidade do alerta gerado

---

**Q19.** O Google SecOps suporta ingestão de logs de ambientes multi-cloud. Qual dos seguintes mecanismos é recomendado para ingerir logs de AWS CloudTrail no Google SecOps?

- [ ] A) Bindplane OP Agent instalado em cada instância EC2
- [ ] B) Feed configurado via Google Cloud Pub/Sub ou diretamente da bucket S3 (S3 feed)
- [ ] C) Exportação manual de CSV pelo console AWS mensalmente
- [ ] D) API REST direta entre AWS e o Google SecOps sem necessidade de configuração

---

**Q20.** Em um playbook SOAR do Google SecOps, o objeto `case` representa:

- [ ] A) Uma regra de detecção YARA-L ativa
- [ ] B) O container que agrupa um ou mais alertas relacionados a um incidente para gerenciamento e resposta
- [ ] C) Um feed de Threat Intelligence configurado
- [ ] D) Um relatório de investigação exportado em PDF

---

**Q21.** Um engenheiro de detecção criou uma regra YARA-L com o seguinte critério na seção `condition:`: `#e1 >= 10 AND count(distinct $e1.target.user.email_addresses) >= 5`. Essa combinação de condições serve para:

- [ ] A) Detectar brute force (muitas tentativas contra um único usuário)
- [ ] B) Detectar password spray (muitas tentativas contra muitos usuários do mesmo IP)
- [ ] C) Detectar credential stuffing de múltiplos IPs
- [ ] D) Detectar account takeover após login bem-sucedido

---

**Q22.** A janela temporal `over 15m` na seção `match:` de uma regra YARA-L significa:

- [ ] A) A regra é avaliada apenas a cada 15 minutos (batch processing)
- [ ] B) A regra usa uma janela deslizante de 15 minutos para correlacionar eventos
- [ ] C) Eventos com mais de 15 minutos são descartados da regra
- [ ] D) O alerta gerado tem um timeout de 15 minutos antes de ser encerrado

---

**Q23.** Qual campo UDM seria mais adequado para representar o processo que iniciou uma conexão de rede em um evento do tipo NETWORK_CONNECTION?

- [ ] A) `metadata.product_name`
- [ ] B) `principal.process.file.full_path`
- [ ] C) `network.application_protocol`
- [ ] D) `security_result.category`

---

**Q24.** No contexto do Google SecOps, Applied Threat Intelligence (ATI) da Mandiant é usado para:

- [ ] A) Gerar relatórios de compliance BACEN automaticamente
- [ ] B) Priorizar automaticamente alertas com base em inteligência de ameaças ativas e relevantes para o setor
- [ ] C) Substituir a funcionalidade de SOAR para resposta automática
- [ ] D) Criptografar os feeds de IOCs antes de armazená-los no Chronicle

---

**Q25.** Um parser CBN (Configuration-Based Normalization) customizado no Google SecOps é composto principalmente por:

- [ ] A) Código Python com lógica de parsing e transformação de campos
- [ ] B) Arquivo YAML ou JSON que define mapeamentos entre campos do log bruto e campos UDM
- [ ] C) Regras YARA-L que filtram e transformam os eventos durante a ingestão
- [ ] D) Scripts Bash que pré-processam os logs antes de enviá-los ao Chronicle

---

**Q26.** Em uma investigação de incidente no Google SecOps, o recurso "Timeline" é usado para:

- [ ] A) Visualizar o cronograma de produção das videoaulas do curso
- [ ] B) Mostrar a sequência cronológica de eventos relacionados a uma entidade (usuário, IP ou host) em uma investigação
- [ ] C) Exibir o histórico de versões das regras YARA-L criadas
- [ ] D) Monitorar o uptime do tenant Google SecOps

---

**Q27.** Qual métrica operacional mede o tempo decorrido desde que um ataque se inicia até que o SOC detecta e gera um alerta?

- [ ] A) MTTR (Mean Time to Respond)
- [ ] B) MTTD (Mean Time to Detect)
- [ ] C) RTO (Recovery Time Objective)
- [ ] D) SLA (Service Level Agreement)

---

**Q28.** No contexto de Threat Hunting no Google SecOps, "pivoting" refere-se a:

- [ ] A) Alterar a regra YARA-L para detectar um novo tipo de ameaça
- [ ] B) A técnica de usar um IOC encontrado (IP, hash, domínio) para buscar entidades relacionadas e expandir o escopo da investigação
- [ ] C) Migrar logs de um tenant para outro
- [ ] D) Rotar credenciais de API do tenant Chronicle

---

**Q29.** Segundo a Resolução BACEN 4.893, uma instituição financeira que detecta um incidente de segurança cibernética significativo deve:

- [ ] A) Reportar ao Banco Central em até 72 horas (similar ao GDPR europeu)
- [ ] B) Seguir um plano de resposta a incidentes documentado, com prazo de até 4 horas para contenção
- [ ] C) Notificar o Banco Central do Brasil conforme os procedimentos e prazos definidos na própria resolução, além de manter registro de todos os incidentes
- [ ] D) Apenas registrar internamente o incidente sem obrigação de notificação externa

---

**Q30.** Uma regra YARA-L multi-event utiliza variáveis `$e1` e `$e2`. Isso indica que:

- [ ] A) A regra detecta apenas dois eventos isolados, sem correlação entre eles
- [ ] B) A regra correlaciona dois tipos diferentes de eventos que devem ocorrer em sequência ou juntos na mesma janela temporal
- [ ] C) A regra tem dois thresholds alternativos — se o primeiro não disparar, o segundo é testado
- [ ] D) As variáveis $e1 e $e2 representam o mesmo tipo de evento em instâncias diferentes

---

**Q31.** No framework MITRE ATT&CK, a tática "Credential Access" (TA0006) inclui técnicas como:

- [ ] A) Apenas phishing e spearphishing de credenciais
- [ ] B) Password Spraying (T1110.003), Credential Dumping (T1003), Kerberoasting (T1558.003) e outras técnicas de obtenção de credenciais
- [ ] C) Apenas técnicas de lateral movement usando credenciais roubadas
- [ ] D) Persistência via criação de novas contas de usuário

---

**Q32.** Qual dos seguintes campos UDM representaria melhor o endereço de e-mail do usuário que iniciou um evento (principal)?

- [ ] A) `metadata.vendor_name`
- [ ] B) `principal.user.userid`
- [ ] C) `principal.user.email_addresses`
- [ ] D) `target.user.email_addresses`

---

### Nível Avançado — Questões 33 a 40 (2,5 pontos cada)

**Q33.** Um engenheiro de detecção precisa criar uma regra YARA-L que detecte C2 beaconing — comunicação periódica de um endpoint comprometido para um servidor de comando e controle, caracterizada por intervalos regulares de conexão. Qual abordagem de detecção é mais eficaz?

- [ ] A) Detectar qualquer evento NETWORK_CONNECTION com destino a IP externo
- [ ] B) Usar uma regra multi-event que analisa a variância dos intervalos de tempo entre conexões consecutivas do mesmo host para o mesmo destino, dentro de uma janela longa (ex: 2h), identificando padrões de periodicidade estatisticamente significativos
- [ ] C) Criar uma lista de IPs de servidores C2 conhecidos e bloquear via regra de firewall
- [ ] D) Alertar sempre que um endpoint fizer mais de 10 conexões externas em 5 minutos

---

**Q34.** Durante um threat hunting no Google SecOps, você percebe que um usuário legítimo está gerando muitos alertas de UEBA por trabalhar em horários incomuns (plantão noturno). Qual é a abordagem mais adequada para reduzir falsos positivos sem comprometer a detecção?

- [ ] A) Desativar o UEBA para esse usuário permanentemente
- [ ] B) Aumentar o threshold de todas as regras UEBA para cobrir horários noturnos
- [ ] C) Adicionar o usuário a uma Watchlist de "usuários de plantão" e criar uma supressão condicional nas regras YARA-L relevantes, usando `not $e.principal.user.email_addresses in %watchlist_plantao`
- [ ] D) Criar uma nova regra que ignore todos os eventos fora do horário comercial

---

**Q35.** Você está integrando feeds STIX/TAXII de um provedor de Threat Intelligence externo ao Google SecOps. Qual é o fluxo correto de integração?

- [ ] A) Importar o arquivo STIX manualmente via console e criar regras YARA-L manualmente para cada IOC
- [ ] B) Configurar o feed TAXII no Google SecOps (Settings → Threat Intelligence → Feeds → TAXII), que consumirá automaticamente os IOCs do servidor TAXII e os tornará disponíveis para enriquecimento de alertas e lookup em regras
- [ ] C) Exportar os IOCs do STIX para CSV e fazer upload diário via API REST
- [ ] D) Usar o Bindplane OP Agent como proxy para converter STIX em formato UDM

---

**Q36.** Em um cenário de incident response usando o SOAR do Google SecOps, um playbook automatizado precisa revogar todas as sessões ativas de um usuário comprometido no Google Workspace. Qual mecanismo de action o playbook deve utilizar?

- [ ] A) Executar um script Python via Cloud Function que chama a Admin SDK do Google Workspace
- [ ] B) Enviar um e-mail ao administrador do Google Workspace solicitando a revogação manual
- [ ] C) Usar a action nativa do Google SecOps SOAR "Google Workspace — Revoke User Sessions" via integração com a Admin SDK, passando como parâmetro o email do usuário comprometido obtido do campo `$case.principal.user.email_addresses`
- [ ] D) Deletar o usuário do Google Workspace via API REST e recriá-lo com nova senha

---

**Q37.** Ao avaliar o TCO (Total Cost of Ownership) de SIEMs para um banco regulado brasileiro, qual fator torna o modelo de ingestão (GB/dia) do Google SecOps potencialmente mais vantajoso que o modelo por EPS de um SIEM on-premises?

- [ ] A) O Google SecOps não tem custo de mão de obra para manutenção de infraestrutura, já que é SaaS
- [ ] B) O custo por GB de ingestão no Google SecOps é invariavelmente menor que o custo por EPS de qualquer SIEM on-premises
- [ ] C) O modelo por ingestão permite que a organização ingira TODOS os logs sem se preocupar com custo de EPS pico (ex.: durante um incidente, onde o volume de eventos explode), mantendo custo proporcional ao volume médio de dados — e não ao pico de eventos
- [ ] D) O Google SecOps oferece créditos automáticos para instituições financeiras reguladas pelo BACEN

---

**Q38.** Um analista detecta no Google SecOps que um host interno começou a fazer consultas DNS para domínios gerados algoritmicamente (Domain Generation Algorithm — DGA), característico de malware que usa DGA para se comunicar com C2 em domínios dinâmicos. Qual técnica MITRE ATT&CK melhor descreve essa atividade e como você estruturaria a detecção?

- [ ] A) T1071.004 — Application Layer Protocol: DNS. Detectar via YARA-L analisando o número de NXDomain responses de um mesmo host (muitos domínios inexistentes = possível DGA), usando `count(distinct $e.network.dns.questions.name) >= 50 over 10m` com `$e.network.dns.response_code = "NXDOMAIN"`
- [ ] B) T1566.001 — Spearphishing Attachment. Detectar via análise de anexos de e-mail com extensão .exe
- [ ] C) T1190 — Exploit Public-Facing Application. Detectar via logs de WAF com status 500
- [ ] D) T1059.001 — PowerShell. Detectar via eventos de execução de script no Windows Event Log

---

**Q39.** Você precisa criar uma regra YARA-L que detecte a técnica "AS-REP Roasting" (T1558.004) — onde um atacante solicita tickets Kerberos de contas com pré-autenticação desabilitada para realizar ataque offline. Quais eventos UDM e campos você deveria analisar?

- [ ] A) Eventos `USER_LOGIN` com falha e campo `security_result.category = "AUTHZ_FAILURE"`
- [ ] B) Eventos de tipo `NETWORK_CONNECTION` com protocolo `KERBEROS` e porta de destino 88, buscando `network.kerberos.ticket_encryption_type = 23` (RC4-HMAC, indicativo de AS-REP Roasting) e ausência de pré-autenticação no campo de flags do ticket
- [ ] C) Eventos de `FILE_ACCESS` em arquivos `.keytab` no servidor Kerberos
- [ ] D) Eventos de `USER_UNCATEGORIZED` com `metadata.product_name = "Active Directory"`

---

**Q40.** Um CISO de banco brasileiro pergunta por que o time de SOC deve usar o framework MITRE ATT&CK como referência para mapear regras de detecção, em vez de apenas criar regras baseadas em IPs e hashes de ameaças conhecidas. Qual é a resposta mais tecnicamente correta?

- [ ] A) O MITRE ATT&CK é exigido explicitamente pela Resolução BACEN 4.893, tornando seu uso obrigatório para IFs
- [ ] B) IPs e hashes são IOCs de baixa durabilidade (atacantes os rotacionam facilmente), enquanto as TTPs do MITRE ATT&CK descrevem comportamentos que mudam muito mais lentamente — detectar comportamentos é mais eficaz e resiliente que detectar artefatos específicos. A Pirâmide da Dor (Pyramid of Pain) ilustra bem esse conceito: quanto mais alta a abstração no MITRE ATT&CK, mais custoso é para o atacante mudar o comportamento
- [ ] C) O MITRE ATT&CK é gratuito e elimina a necessidade de contratar feeds de Threat Intelligence pagos
- [ ] D) O MITRE ATT&CK suporte apenas detecção de ameaças em ambientes Windows on-premises

---

## Parte 2 — Estudo de Caso (20%)

### Cenário: "Operação Kauã — Incidente no Banco Meridian"

**Duração:** 60 minutos  
**Valor:** 20% da nota final

---

#### Narrativa do Caso

**Contexto:** É sexta-feira, 12 de maio de 2026, 22h43. Você é o Engenheiro de Detecção de plantão
no SOC do Banco Meridian. A maioria do time está de folga. O sistema de alertas do Google SecOps
dispara com severidade CRITICAL.

**O incidente:**

O Google SecOps gerou 3 alertas em sequência nos últimos 8 minutos:

```
22:35:14  [HIGH]     password_spray_detection — IP: 189.31.77.204 — 34 usuários-alvo
22:39:07  [CRITICAL] account_takeover_post_spray — usuario: rafael.torres@bancomeridian.com.br
22:43:22  [CRITICAL] data_exfiltration_suspected — usuario: rafael.torres — 2.3 GB para ext. IP
```

Investigando no Google SecOps, você encontra a seguinte sequência de eventos:

```
22:30:01  USER_LOGIN BLOCK    pedro.alves@bancomeridian.com.br   IP: 189.31.77.204
22:30:18  USER_LOGIN BLOCK    marcia.santos@bancomeridian.com.br IP: 189.31.77.204
22:30:35  USER_LOGIN BLOCK    joao.ferreira@bancomeridian.com.br IP: 189.31.77.204
[... 31 tentativas adicionais BLOCK ...]
22:38:55  USER_LOGIN SUCCESS  rafael.torres@bancomeridian.com.br IP: 189.31.77.204
22:39:12  FILE_ACCESS         /sharepoint/financeiro/balancetes-abril-2026.xlsx
22:39:28  FILE_ACCESS         /sharepoint/financeiro/projecoes-credito-q3-2026.xlsx
22:39:44  FILE_ACCESS         /sharepoint/juridico/contratos-clientes-prime.zip (890 MB)
22:40:11  EMAIL_TRANSACTION   To: financeiro-externo@mailtemp.io — Attachment: 45 MB
22:41:03  NETWORK_CONNECTION  Destino: 82.194.67.3:443 (AS: 201814 MivoCloud, Moldova) — 2.3 GB transfer
22:41:55  USER_LOGOUT         rafael.torres@bancomeridian.com.br
```

A conta de Rafael Torres normalmente opera das 09h às 18h, de IPs dentro da rede corporativa
(10.0.x.x) ou VPN (172.16.x.x). Rafael estava de licença médica nesta data.

---

#### Perguntas do Estudo de Caso

**Pergunta 1 (20 pontos):**
Com base nos eventos apresentados, identifique e descreva:
- a) A técnica de Initial Access utilizada pelo atacante (nome da técnica, ID MITRE ATT&CK)
- b) A técnica de Credential Access (nome, ID MITRE ATT&CK)
- c) A provável técnica de Exfiltration (nome, ID MITRE ATT&CK)
- d) A tática geral do ataque e seu enquadramento na kill chain

---

**Pergunta 2 (20 pontos):**
Escreva as 3 queries UDM Search que você executaria imediatamente no Google SecOps para:
- a) Verificar se outras contas foram comprometidas pelo mesmo IP após o login bem-sucedido de Rafael
- b) Identificar todos os arquivos acessados pela conta comprometida no período do incidente
- c) Verificar se o IP `82.194.67.3` aparece em outros eventos históricos nos últimos 30 dias

---

**Pergunta 3 (20 pontos):**
Descreva o plano de contenção imediata que você executaria nos próximos 30 minutos, considerando:
- a) Ações urgentes na conta do rafael.torres
- b) Ações no nível de rede (IP de origem)
- c) Comunicação interna (quem contatar? Com que urgência?)
- d) Obrigações regulatórias (o que a Resolução BACEN 4.893 exige neste cenário?)

---

**Pergunta 4 (20 pontos):**
Você precisa criar uma nova regra YARA-L para detectar a situação de "login bem-sucedido após password spray do mesmo IP", evitando que esse padrão passe despercebido no futuro. Escreva a estrutura completa da regra YARA-L (meta, events, match, condition, outcome), explicando a lógica de cada seção.

---

**Pergunta 5 (20 pontos):**
Ao final do incidente, você deve elaborar um resumo executivo em formato de relatório para o CISO e para o time jurídico. Descreva os elementos que um relatório de incidente cibernético deve conter, com base nas melhores práticas do NIST SP 800-61 e nas exigências da Resolução BACEN 4.893, e escreva um parágrafo resumindo este incidente específico como se fosse para o CISO.

---

## Gabarito — Parte 1: Múltipla Escolha

| Q    | Resposta | Módulo | Justificativa Resumida                                                    |
|:----:|:--------:|:------:|:--------------------------------------------------------------------------|
|  01  |    B     |   01   | Os 4 componentes principais são SIEM, SOAR, UEBA e Threat Intelligence    |
|  02  |    C     |   01   | Google SecOps cobra por volume de dados ingeridos (GB/dia)                |
|  03  |    B     |   01/02| UDM normaliza eventos de diferentes fontes para schema comum               |
|  04  |    D     |   04   | UEBA cria baseline e detecta desvios comportamentais                       |
|  05  |    B     |   02   | metadata.event_type classifica o tipo de evento (USER_LOGIN, etc.)         |
|  06  |    B     |   02   | Bindplane OP Agent coleta e encaminha logs para o Google SecOps            |
|  07  |    C     |   03   | T1110.003 = Password Spraying — uma senha, muitos usuários                 |
|  08  |    B     |   03   | match: define janela temporal e campos de agrupamento                      |
|  09  |    B     |   02   | CBN cria parsers customizados para fontes sem parser nativo                |
|  10  |    C     |   02   | Regex em UDM Search usa /pattern/                                          |
|  11  |    D     |   01   | UD Mode oferece retenção de 1 ano como padrão                              |
|  12  |    A     |   03   | Live: tempo real; Retrohunt: análise de dados históricos                   |
|  13  |    B     |   03   | #e1 representa a cardinalidade (contagem) de eventos da variável           |
|  14  |    B     |   03/04| Busca correta: USER_LOGIN + BLOCK + IP específico                          |
|  15  |    B     |   03   | count(distinct ...) conta usuários-alvo únicos                             |
|  16  |    B     |   05   | VirusTotal Augment enriquece eventos com reputação de IOCs                 |
|  17  |    B     |   04   | UEBA + Risk Analytics detecta desvio de baseline comportamental            |
|  18  |    B     |   03   | not em events: exclui eventos que correspondem ao padrão                   |
|  19  |    B     |   02   | AWS CloudTrail: feed via Pub/Sub ou S3 feed direto                         |
|  20  |    B     |   06   | case: container de alertas relacionados a um incidente no SOAR             |
|  21  |    B     |   03   | Combinação: muitas tentativas + muitos usuários = password spray           |
|  22  |    B     |   03   | over 15m: janela deslizante de correlação de 15 minutos                    |
|  23  |    B     |   02   | principal.process.file.full_path = processo que iniciou a conexão          |
|  24  |    B     |   05   | ATI prioriza alertas com base em inteligência de ameaças ativas            |
|  25  |    B     |   02   | Parser CBN = arquivo YAML/JSON com mapeamento de campos                    |
|  26  |    B     |   04   | Timeline: sequência cronológica de eventos de uma entidade                 |
|  27  |    B     |   06   | MTTD = Mean Time to Detect (tempo de detecção)                             |
|  28  |    B     |   04   | Pivoting: usar IOC para expandir escopo da investigação                    |
|  29  |    C     |   01   | BACEN 4.893: plano de resposta documentado + registro de incidentes        |
|  30  |    B     |   03   | $e1 e $e2: dois tipos diferentes de eventos correlacionados                |
|  31  |    B     |   03   | TA0006 inclui T1110.003, T1003, T1558.003 e outras técnicas de credential  |
|  32  |    C     |   02   | principal.user.email_addresses = e-mail do usuário que originou o evento   |
|  33  |    B     |   04   | C2 beaconing: análise de variância de intervalos em janela longa           |
|  34  |    C     |   03   | Watchlist + supressão condicional para usuários de plantão legítimos       |
|  35  |    B     |   05   | Feed TAXII: configurar em Settings → TI → Feeds → TAXII                   |
|  36  |    C     |   06   | Action nativa Google Workspace no SOAR para revogação de sessões           |
|  37  |    C     |   01   | Ingestão por GB: custo proporcional ao volume médio, não ao pico de EPS    |
|  38  |    A     |   04/05| DGA = T1071.004, detectar NXDomain responses em volume alto (count >= 50)  |
|  39  |    B     |   04   | AS-REP Roasting: eventos Kerberos port 88, encryption type RC4 (type 23)   |
|  40  |    B     |   01   | Pyramid of Pain: TTPs têm durabilidade >> IPs/hashes; comportamentos são resistentes |

---

## Gabarito — Parte 2: Estudo de Caso

### Gabarito — Pergunta 1

**a) Técnica de Initial Access:**
- **Nome:** Valid Accounts (com credenciais obtidas via Password Spraying)
- **ID MITRE:** T1078 — Valid Accounts (usada após T1110.003 — Password Spraying)
- **Explicação:** O atacante obteve acesso usando credenciais válidas da conta de Rafael Torres, que foram comprometidas via password spray. O acesso inicial foi via autenticação legítima com credenciais roubadas.

**b) Técnica de Credential Access:**
- **Nome:** Brute Force: Password Spraying
- **ID MITRE:** T1110.003
- **Evidência:** 34 tentativas de login bloqueadas para usuários diferentes do mesmo IP em 8 minutos, com uma tentativa bem-sucedida para rafael.torres.

**c) Técnica de Exfiltration:**
- **Nome:** Exfiltration Over C2 Channel / Exfiltration to Cloud Storage
- **ID MITRE:** T1041 — Exfiltration Over C2 Channel (2,3 GB para IP de Moldova via porta 443)
- **Evidência adicional:** EMAIL_TRANSACTION com arquivo de 45MB para endereço @mailtemp.io (T1048 — Exfiltration Over Alternative Protocol)

**d) Kill chain completa:**
```
Reconhecimento → Password Spray (T1110.003) → Login bem-sucedido (T1078) →
→ Collection (T1213 — Data from Information Repositories: SharePoint) →
→ Exfiltration Over C2 Channel (T1041) + Email (T1048)
Táticas: Credential Access → Initial Access → Collection → Exfiltration
```

---

### Gabarito — Pergunta 2

**a) Verificar outras contas comprometidas após login do Rafael:**
```
metadata.event_type = "USER_LOGIN" AND
security_result.action = "ALLOW" AND
principal.ip = "189.31.77.204" AND
metadata.event_timestamp > "2026-05-12T22:38:00Z"
```

**b) Todos os arquivos acessados pela conta comprometida:**
```
metadata.event_type = "FILE_ACCESS" AND
principal.user.email_addresses = "rafael.torres@bancomeridian.com.br" AND
metadata.event_timestamp > "2026-05-12T22:38:00Z"
metadata.event_timestamp < "2026-05-12T22:42:00Z"
```

**c) Histórico do IP 82.194.67.3 nos últimos 30 dias:**
```
target.ip = "82.194.67.3" OR principal.ip = "82.194.67.3"
| group_by metadata.event_type
| order_by count() desc
```
*(Selecionar período: Last 30 days)*

---

### Gabarito — Pergunta 3

**a) Ações urgentes na conta rafael.torres (próximos 10 min):**
1. Revogar todas as sessões ativas do rafael.torres no Azure AD / Google Workspace (Admin Console → Usuários → Revoke sessions)
2. Resetar a senha da conta imediatamente (senha forte, comunicar ao usuário pelo celular corporativo)
3. Habilitar MFA forçado para a conta (se não estiver ativo)
4. Colocar a conta em estado "disabled" temporariamente até confirmação da situação com Rafael
5. Verificar se rafael.torres tem acesso privilegiado (admin, acesso a sistemas críticos) — se sim, acionar CISO imediatamente

**b) Ações no nível de rede (próximos 10 min):**
1. Bloquear IP `189.31.77.204` no firewall perimetral / WAF (regra de bloqueio de entrada)
2. Bloquear IP `82.194.67.3` no firewall perimetral (destino de exfiltração)
3. Verificar se há outras conexões ativas para `82.194.67.3` ou AS 201814 MivoCloud
4. Bloquear domínio `mailtemp.io` no gateway de e-mail
5. Solicitar ao ISP rastreamento forense do tráfego (via operadora)

**c) Comunicação interna:**
- **Imediato (próximos 15 min):** CISO de plantão (ligação telefônica — não apenas WhatsApp)
- **Urgente (próxima 1h):** DPO (Data Protection Officer) — dados pessoais podem ter sido expostos (LGPD)
- **Urgente (próxima 1h):** Jurídico corporativo — para avaliar obrigações regulatórias
- **Urgente (próxima 2h):** CEO / COO de plantão (dado o volume de dados e sensibilidade)
- **Documentar:** Abrir ticket de incidente com timestamp de cada ação tomada

**d) Obrigações regulatórias (BACEN 4.893):**
- O Banco Meridian deve registrar o incidente em seu sistema de gestão de incidentes (requisito da norma)
- Avaliar se o incidente se enquadra como "incidente relevante" segundo os critérios da BACEN 4.893 (impacto em serviços, clientes, dados financeiros)
- Se classificado como relevante: notificar o Banco Central do Brasil no prazo definido pela resolução
- Comunicar os clientes afetados pela possível exposição de dados (LGPD, Art. 48)
- Manter toda a cadeia de evidências para a investigação forense

---

### Gabarito — Pergunta 4

**Regra YARA-L — Login bem-sucedido após password spray:**

```yara-l
rule account_compromise_post_spray {
  meta:
    author = "CECyber - Engenheiro de Detecção"
    description = "Detecta login bem-sucedido do mesmo IP após password spray"
    severity = "CRITICAL"
    priority = "CRITICAL"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110.003"
    playbook = "account_takeover_response"
    created_date = "2026-05-12"

  events:
    // $e1: tentativas de login com falha (spray)
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "BLOCK"
    $e1.target.user.email_addresses = /.*@bancomeridian\.com\.br$/
    
    // $e2: login bem-sucedido — MESMO IP que realizou o spray
    $e2.metadata.event_type = "USER_LOGIN"
    $e2.security_result.action = "ALLOW"
    
    // Correlação: ambos os eventos devem ter o MESMO IP de origem
    $e1.principal.ip = $e2.principal.ip

  match:
    // Janela de 30 minutos — o login bem-sucedido deve ocorrer após o spray
    $e2.principal.ip over 30m

  condition:
    // Spray: pelo menos 8 falhas de contas diferentes
    #e1 >= 8
    count(distinct $e1.target.user.email_addresses) >= 4
    // Login bem-sucedido ocorreu
    #e2 >= 1

  outcome:
    $ip_atacante = $e2.principal.ip
    $conta_comprometida = $e2.target.user.email_addresses
    $total_falhas = count($e1)
    $usuarios_sprayed = count(distinct $e1.target.user.email_addresses)
    $timestamp_comprometimento = $e2.metadata.event_timestamp
    $severity = "CRITICAL"
    $risk_score = 100
}
```

**Explicação da lógica:**
- `$e1`: captura as tentativas bloqueadas (o spray)
- `$e2`: captura o login bem-sucedido do mesmo IP
- `$e1.principal.ip = $e2.principal.ip`: essa correlação é o coração da regra — o mesmo IP que realizou o spray também fez login bem-sucedido, caracterizando account takeover pós-spray
- A janela de 30 minutos cobre a maioria dos sprays que ocorrem de forma acelerada

---

### Gabarito — Pergunta 5

**Elementos do relatório de incidente (NIST SP 800-61 + BACEN 4.893):**

1. **Identificação do incidente:** data/hora de detecção e ocorrência, ID do incidente, classificação de severidade
2. **Resumo executivo:** descrição em linguagem não técnica do que aconteceu e o impacto
3. **Linha do tempo (Timeline):** sequência cronológica detalhada de todos os eventos
4. **Análise técnica:** TTPs utilizadas, sistemas afetados, dados potencialmente comprometidos, indicadores de comprometimento (IOCs)
5. **Impacto:** dados expostos (tipo, quantidade, classificação LGPD), sistemas afetados, impacto financeiro estimado
6. **Ações de contenção tomadas:** o quê, quando, por quem
7. **Análise de causa raiz:** como o atacante obteve acesso inicial, qual vulnerabilidade explorou
8. **Recomendações de remediação:** ações de curto, médio e longo prazo
9. **Conformidade regulatória:** obrigações BACEN 4.893 e LGPD atendidas
10. **Lições aprendidas:** o que pode melhorar nas detecções, processos e controles

**Parágrafo de resumo executivo para o CISO:**

*"Na noite de sexta-feira, 12 de maio de 2026, o SOC do Banco Meridian detectou e respondeu a um incidente de comprometimento de conta de alto impacto. Um atacante originário de IP brasileiro (189.31.77.204) conduziu um ataque de password spraying contra 34 contas corporativas entre 22h30 e 22h39, obtendo acesso bem-sucedido à conta do colaborador Rafael Torres, que se encontrava de licença médica. Em aproximadamente 3 minutos de acesso, o atacante acessou documentos confidenciais nas áreas Financeiro e Jurídico no SharePoint e exfiltrou aproximadamente 2,3 GB de dados para um servidor em Moldova (AS MivoCloud). O SOC iniciou a contenção às 22h43, com revogação das sessões, bloqueio de IPs e notificação da cadeia de gestão. Dados pessoais e informações financeiras sensíveis podem ter sido comprometidos, demandando avaliação jurídica urgente para fins de obrigações LGPD e eventual notificação ao Banco Central do Brasil nos termos da Resolução BACEN 4.893."*

---

## Tabela de Aproveitamento

| Pontuação Total | Equivalente (%) | Resultado                                                      |
|:---------------:|:---------------:|:---------------------------------------------------------------|
| 90–100 pontos   | 90–100%         | Excelente — Aprovado com distinção                             |
| 80–89 pontos    | 80–89%          | Muito Bom — Aprovado                                           |
| 70–79 pontos    | 70–79%          | Bom — Aprovado (nota mínima atingida)                          |
| 60–69 pontos    | 60–69%          | Regular — Reprovado — Revisar módulos indicados                |
| Abaixo de 60    | < 60%           | Insuficiente — Reprovado — Recomendar revisão completa do curso |

---

*Avaliação Final · Curso 1 — Google SecOps Essentials · CECyber · v2.0 · 2026*
