# Avaliação Final — Curso 2: Microsoft Sentinel & Defender: SecOps no Azure

**Curso 2 · Microsoft Sentinel & Defender: SecOps no Azure · CECyber**

| Campo                     | Detalhes                                                              |
|:--------------------------|:----------------------------------------------------------------------|
| **Total de questões**     | 40 múltipla escolha (80%) + 5 discursivas em estudo de caso (20%)    |
| **Duração**               | 3 horas                                                               |
| **Nota mínima aprovação** | 70% (score total ponderado)                                           |
| **Certificação alvo**     | Microsoft SC-200                                                      |
| **Cenário do caso**       | Banco Meridian — incidente AiTM                                       |

---

## Parte 1 — Múltipla Escolha (80 pontos / 40 questões × 2 pontos cada)

### Módulo 01 — Arquitetura Microsoft Security (4 questões)

**Q01.** No modelo de responsabilidade compartilhada Azure, qual é a responsabilidade do cliente ao usar o Azure SQL Database (PaaS)?

a) Gerenciar o hardware e a rede física do datacenter  
b) Aplicar patches no motor do banco de dados  
c) Gerenciar os dados, identidades de acesso, conformidade e criptografia dos dados  
d) Administrar o sistema operacional do servidor que hospeda o banco de dados  

**Q02.** O princípio Zero Trust "Assume Breach" implica qual das seguintes abordagens?

a) Desativar todos os acessos remotos e exigir presença física no escritório  
b) Projetar controles assumindo que o atacante já está dentro, com micro-segmentação, encriptação de tráfego interno e analytics comportamental  
c) Instalar antivírus em todos os endpoints e considerar isso suficiente  
d) Desconfiar de todos os fornecedores externos e usar apenas software desenvolvido internamente  

**Q03.** Qual produto Microsoft é responsável por detectar ataques como Kerberoasting e Golden Ticket no Active Directory?

a) Microsoft Defender for Endpoint (MDE)  
b) Microsoft Defender for Office 365 (MDO)  
c) Microsoft Defender for Identity (MDI)  
d) Microsoft Defender for Cloud Apps (MDA)  

**Q04.** O Banco Meridian usa Microsoft 365 E3. O CISO quer adicionar Entra ID Protection (risco de identidade) e PIM. Qual licença é necessária?

a) Microsoft 365 E3 já inclui Entra ID Protection e PIM  
b) Entra ID Premium P1 é suficiente para ambos  
c) Entra ID Premium P2 (incluído no M365 E5 ou E5 Security) para Entra ID Protection e PIM  
d) Uma licença separada "Defender for Identity" é necessária  

---

### Módulo 02 — Sentinel Deployment (4 questões)

**Q05.** O Banco Meridian precisa manter logs de autenticação por 5 anos para o BACEN. Qual configuração é mais eficiente em termos de custo?

a) Configurar 1825 dias no tier Interactive (Hot) para todas as tabelas  
b) Configurar 90 dias no tier Interactive e 1735 dias no tier Archive, totalizando 1825 dias  
c) Criar um Storage Account separado com exportação manual via Azure Data Factory  
d) Log Analytics não suporta mais de 2 anos de retenção — usar Azure Blob Storage  

**Q06.** Ao configurar o conector Microsoft Defender XDR no Sentinel, qual opção é obrigatória para evitar duplicação de incidentes?

a) "Enable automatic incident synchronization"  
b) "Turn off all Microsoft incident creation rules for these products"  
c) "Merge all alerts into existing incidents"  
d) "Disable XDR incident creation and use Sentinel only"  

**Q07.** Uma Data Collection Rule (DCR) com a seguinte transformação KQL: `source | where EventID != 4634` tem qual efeito na ingestão de dados?

a) Eventos com EventID 4634 são armazenados numa tabela separada  
b) Eventos com EventID 4634 são descartados antes de chegarem ao workspace, reduzindo o volume ingerido e o custo  
c) Eventos com EventID 4634 recebem uma flag de baixa prioridade no workspace  
d) A transformação não afeta a ingestão — apenas filtra os resultados nas queries  

**Q08.** O Content Hub instalou a solução "Microsoft Entra ID" com 30 analytics rules. Após a instalação, quantas rules estão detectando ameaças ativamente?

a) Todas as 30 rules estão ativas automaticamente após a instalação  
b) Nenhuma — as rules são instaladas como templates e precisam ser ativadas manualmente  
c) Apenas as 5 rules mais críticas são ativadas automaticamente  
d) Depende do plano de licença do Sentinel  

---

### Módulo 03 — KQL (4 questões)

**Q09.** Qual query KQL retorna os 10 usuários com mais logins bem-sucedidos nas últimas 24 horas?

a) `SigninLogs | where ResultType == 0 | top 10 by UserPrincipalName`  
b) `SigninLogs | where TimeGenerated > ago(24h) | where ResultType == 0 | summarize count() by UserPrincipalName | top 10 by count_`  
c) `SigninLogs | limit 10 | where ResultType == 0 | order by UserPrincipalName`  
d) `SigninLogs | count | where ResultType == 0 | take 10`  

**Q10.** O operador KQL `join kind=leftouter` preserva:

a) Apenas linhas com correspondência em ambas as tabelas  
b) Todas as linhas da tabela esquerda, com campos vazios onde não há correspondência na tabela direita  
c) Todas as linhas de ambas as tabelas, incluindo onde não há correspondência  
d) Apenas linhas da tabela direita sem correspondência na tabela esquerda  

**Q11.** A função KQL `ago(7d)` retorna:

a) A data de 7 dias no futuro  
b) A data e hora exata de 7 dias atrás relativa ao momento de execução da query  
c) O número 7 em formato datetime  
d) Um intervalo de 7 dias sem data de referência  

**Q12.** Qual é a diferença entre `summarize count() by X` e `summarize dcount(X)`?

a) Não há diferença — ambos contam registros  
b) `count() by X` conta o número de registros por valor de X; `dcount(X)` conta o número de valores distintos de X  
c) `count() by X` é para campos numéricos; `dcount(X)` é para campos de texto  
d) `dcount` não existe no KQL — o correto é `distinct count`  

---

### Módulo 04 — Detection Engineering (5 questões)

**Q13.** Uma analytics rule NRT tem qual limitação que a torna inadequada para detectar impossible travel?

a) NRT não suporta a tabela SigninLogs  
b) NRT não suporta operações de `join` e tem lookback máximo de 10 minutos  
c) NRT não pode ser integrada ao MITRE ATT&CK  
d) NRT não gera alertas — apenas atualiza dashboards  

**Q14.** O alert grouping "Group all events into a single alert" para uma analytics rule de password spray significa que:

a) Apenas o primeiro evento de spray gera um alerta  
b) Todos os resultados da query numa execução são consolidados em um único alerta  
c) Múltiplos alertas são gerados, um por conta tentada  
d) O Sentinel agrupa alertas de várias rules diferentes  

**Q15.** Uma analytics rule usa `_GetWatchlist('vip-users') | project UserPrincipalName` para elevar a severidade de alertas envolvendo VIPs. Um atacante criou um usuário chamado `admin@bancomeridian.com.br` e o adicionou à watchlist via API. O impacto é:

a) Nenhum — a watchlist é imutável após a criação  
b) Alertas envolvendo `admin@bancomeridian.com.br` terão severidade elevada, potencialmente priorizando um caminho de ataque que passa por essa conta comprometida  
c) A watchlist é automaticamente verificada contra o Entra ID para validar que os usuários existem  
d) Apenas usuários com role Global Admin podem modificar watchlists  

**Q16.** O Fusion detectou "Multi-stage attack: Phishing → Credential Access → Lateral Movement". O analista não configurou nenhuma rule para detectar este padrão. Isso é porque:

a) O Fusion requer configuração manual de cada padrão de ataque  
b) O Fusion é um motor de ML da Microsoft que correlaciona automaticamente alertas sem configuração do usuário, usando modelos pré-treinados que são atualizados continuamente  
c) O Fusion detectou o ataque por acidente — não foi projetado para isso  
d) Alguém do Content Hub configurou o Fusion como parte de uma solução  

**Q17.** A analytics rule de SharePoint Exfiltration usa `AvgDailyDownloads` calculado dos últimos 30 dias e um multiplicador de 5x. Um novo funcionário no primeiro mês terá `AvgDailyDownloads = 0`. O que acontece com a detecção para ele?

a) A rule gerará muitos falso-positivos para novos funcionários pois qualquer download tem Multiplier = infinito  
b) A query inclui `| where AvgDailyDownloads > 0` que exclui usuários sem histórico, evitando falso-positivos para novos funcionários  
c) O Sentinel detecta automaticamente usuários novos e ajusta o threshold  
d) O funcionário não será detectado pela rule mesmo que faça downloads massivos  

---

### Módulo 05 — SOAR e Logic Apps (4 questões)

**Q18.** Um playbook Logic App usa o "Incident trigger" do Sentinel. Para extrair o UserPrincipalName completo de uma entidade Account do incidente, qual expressão está correta?

a) `@{triggerBody()?['user']?['email']}`  
b) `@{concat(items('For_each')?['properties']?['accountName'],'@',items('For_each')?['properties']?['upnSuffix'])}`  
c) `@{triggerBody()?['incidentInfo']?['affectedUser']}`  
d) `@{body('Get_Account_Entity')?['userPrincipalName']}`  

**Q19.** Por que um playbook de resposta a incidentes deve adicionar um comentário ao incidente do Sentinel ao final da execução?

a) É obrigatório pela documentação da Microsoft para que o incidente seja fechado  
b) Para documentar quais ações automáticas foram executadas (audit trail) e informar analistas humanos sobre o estado atual, evitando duplicação de ações  
c) Para aumentar o número de eventos no workspace e melhorar as métricas de SOC  
d) Para que o Sentinel possa sincronizar o incidente com o Defender XDR  

**Q20.** A fórmula `datetime_diff('minute', ClosedTime, CreatedTime)` calcula qual métrica de SOC?

a) MTTD — Mean Time to Detect (tempo de detecção)  
b) MTTR — Mean Time to Respond/Resolve (tempo de resolução de cada incidente)  
c) MTTF — Mean Time to Failure  
d) SLA compliance rate  

**Q21.** Uma automation rule tem prioridade 1 e outra tem prioridade 10. Quando um novo incidente é criado e ambas as condições são atendidas, qual executa primeiro?

a) A que foi criada primeiro (prioridade baseada em data)  
b) A com prioridade 1 — números menores = maior prioridade no Sentinel  
c) A com prioridade 10 — é executada antes porque foi configurada por último  
d) Ambas executam simultaneamente em paralelo  

---

### Módulo 06 — Defender XDR (5 questões)

**Q22.** O MDI detectou um "DCSync" sendo executado a partir da estação de trabalho WKST-0099. O que esta detecção indica?

a) Um Domain Controller está sincronizando normalmente com outros DCs  
b) Um atacante comprometeu uma conta com privilégio de replicação AD e está extraindo hashes de todos os usuários, incluindo krbtgt  
c) O usuário de WKST-0099 tem permissão legítima de replicação  
d) O MDI detector de DCSync está gerando falso-positivo — é uma operação normal  

**Q23.** O ZAP (Zero-Hour Auto Purge) no Defender for Office 365 age:

a) Bloqueando e-mails antes da entrega quando detectados como suspeitos  
b) Removendo retroativamente e-mails já entregues quando nova inteligência de ameaças os classifica como phishing ou malware  
c) Purging e-mails deletados pelo usuário após 0 horas  
d) Zerando as listas negras de spam a cada hora  

**Q24.** A query de Advanced Hunting para BEC usa `join kind=inner` entre EmailUrlInfo e IdentityLogonEvents. Se um usuário recebeu o e-mail de phishing mas NÃO fez login depois, seu registro:

a) Aparece com campos de login vazios (null)  
b) É descartado — o inner join mantém apenas linhas com correspondência em ambas as tabelas  
c) Gera um alerta separado de "e-mail recebido sem login suspeito"  
d) É armazenado numa tabela temporária para análise posterior  

**Q25.** O Automatic Attack Disruption do Defender XDR isolou automaticamente o laptop do CFO durante um incidente crítico. O SOC deve:

a) Reverter imediatamente o isolamento pois CFO é VIP  
b) Criar uma exceção permanente para o laptop do CFO não ser isolado  
c) Investigar o incidente via Live Response, confirmar comprometimento ou falso-positivo, e só então desfazer o isolamento se o endpoint estiver limpo  
d) Desabilitar o Automatic Attack Disruption para evitar impacto em executivos  

**Q26.** Uma Advanced Hunting query usa `DeviceNetworkEvents | where RemotePort in (445, 135, 5985)`. Quais atividades esta query detecta?

a) Tráfego HTTP/HTTPS e FTP  
b) Conexões de gerenciamento remoto via SMB (445), RPC (135) e WinRM (5985) — comuns em lateral movement  
c) Conexões de banco de dados (SQL, MongoDB, Redis)  
d) Tráfego DNS e DHCP  

---

### Módulo 07 — Defender for Cloud (4 questões)

**Q27.** Qual é a diferença fundamental entre CSPM e CWPP no Microsoft Defender for Cloud?

a) CSPM protege servidores; CWPP protege bancos de dados  
b) CSPM avalia configurações estáticas de postura de segurança (preventivo); CWPP detecta ameaças em workloads em execução (detectivo/responsivo)  
c) CSPM é para Azure; CWPP é para AWS e GCP  
d) CSPM é gratuito; CWPP requer licença paga  

**Q28.** O Secure Score aumentou de 68% para 74% após habilitar MFA para os 5 administradores globais. O controle tinha peso de 14 pontos. Como calcular a melhoria real em % do score?

a) 74% - 68% = 6% (diferença direta dos scores)  
b) O ganho é exatamente os 14 pontos do controle convertidos para %  
c) A melhoria de 6 pontos percentuais é correta — ela reflete os pontos obtidos divididos pelo total máximo da subscription  
d) O score não pode aumentar apenas com MFA — requer remediação de findings de rede também  

**Q29.** O JIT VM Access está configurado para o servidor de core banking. Um administrador precisa de acesso RDP às 2h durante um incidente. Qual é o processo correto?

a) Desabilitar o JIT temporariamente, conectar, e reativar  
b) Modificar manualmente a regra NSG para permitir o IP do admin  
c) Solicitar acesso JIT via portal Azure especificando IP, porta e duração (máx. configurado); o JIT abre a regra NSG automaticamente pelo tempo solicitado  
d) O JIT só funciona durante o horário comercial — usar break glass para acesso noturno  

**Q30.** Após onboardar a conta AWS no Defender for Cloud, qual standard é habilitado automaticamente?

a) BACEN 4.893 (por ser um banco brasileiro)  
b) AWS Foundational Security Best Practices e CIS AWS Foundations Benchmark  
c) ISO 27001 e SOC 2  
d) Nenhum standard — todos devem ser habilitados manualmente  

---

### Módulo 08 — Entra ID Protection e PIM (4 questões)

**Q31.** A sign-in risk policy está configurada para "Medium and above → Require MFA". Um atacante com a senha de um usuário tenta logar de um IP de Tor. O sistema detecta "Anonymous IP" (risco: Medium). O resultado é:

a) O login é bloqueado automaticamente sem opção de MFA  
b) O login recebe risk = Medium; a CA policy exige MFA; o atacante não consegue completar o MFA (não tem o dispositivo); acesso negado  
c) O login é permitido porque a senha está correta  
d) O IP de Tor gera risco Low, que está abaixo do threshold Medium  

**Q32.** No PIM, qual é a diferença entre atribuição "Active" e "Eligible" para Global Administrator?

a) Active = aprovado; Eligible = pendente de aprovação  
b) Active = papel permanentemente ativo em todos os tokens; Eligible = papel não está ativo, requer ativação JIT com requisitos (MFA, justificativa, aprovação opcional)  
c) Active = para usuários internos; Eligible = para usuários externos  
d) Não há diferença prática  

**Q33.** Uma Access Review trimestral para admins foi configurada com "Remove access if reviewer doesn't respond". O gerente de um admin ficou doente e não revisou. O que acontece?

a) O acesso é mantido até o gerente retornar  
b) O Entra ID envia escalada automática para o RH  
c) O acesso é removido automaticamente quando o período de 14 dias expira  
d) O próprio admin pode auto-aprovar o acesso na ausência do revisor  

**Q34.** O campo `AuthenticationRequirement == "singleFactorAuthentication"` num login bem-sucedido de uma conta que normalmente usa MFA é indicativo de:

a) O usuário desabilitou temporariamente o MFA  
b) O token OAuth foi emitido sem exigir MFA — possível AiTM onde o token foi roubado após o proxy completar o MFA e repassar um token sem claim de MFA adequado  
c) O usuário acessou de um dispositivo trusted que bypassa MFA  
d) O Conditional Access está mal configurado no tenant  

---

### Módulo 09 — Threat Hunting (3 questões)

**Q35.** Qual é a principal vantagem do threat hunting proativo em relação à detecção reativa?

a) O hunting proativo gera mais alertas que analytics rules  
b) O hunting proativo pode descobrir atacantes que usam técnicas não cobertas pelas detecções existentes, usando hipóteses baseadas em threat intelligence para reduzir o dwell time  
c) O hunting proativo é mais barato porque não usa processamento do workspace  
d) O hunting proativo substitui completamente as analytics rules  

**Q36.** A hipótese de hunting para Pass-the-Hash usa a combinação EventID 4624 + LogonType 3 + NTLM. Por que LogonType 3 é necessário?

a) Porque EventID 4624 sozinho representa todos os tipos de login  
b) LogonType 3 = autenticação de rede remota; Pass-the-Hash é sempre remoto; incluir LogonType 2 (interativo local) adicionaria muitos falso-positivos  
c) LogonType 3 é o código de NTLM no protocolo Kerberos  
d) Porque EventID 4624 com LogonType 3 significa falha de autenticação  

**Q37.** Um Bookmark no Sentinel é diferente de um Incidente porque:

a) Bookmarks são mais seguros que incidentes  
b) Um Bookmark preserva evidências sem gerar trabalho formal no fluxo SOC; criar um Incidente a partir do Bookmark formaliza a investigação na fila de trabalho com SLA e responsável  
c) Bookmarks são para evidências de baixa severidade; incidentes para alta severidade  
d) Não há diferença — bookmark e incidente são sinônimos  

---

### Módulo 10 — Capstone / Integração (3 questões)

**Q38.** No cenário da Operação Guaraná, o atacante usou "singleFactorAuthentication" para login. Qual analytics rule (módulo 04) teria detectado isso mais rapidamente?

a) Rule de Password Spray (NRT)  
b) Rule de Impossible Travel (Scheduled)  
c) Rule de AiTM Token Theft — detecta logins SFA de contas com histórico de MFA, sem device ID registrado  
d) Rule de SharePoint Exfiltration  

**Q39.** A Fase 6 do ataque (refresh token OAuth de 90 dias) persiste mesmo após o reset de senha do usuário comprometido. Qual ação de remediação é ESPECÍFICA para esta fase?

a) Forçar reset de senha do usuário  
b) Revogar sessões via Graph API  
c) Revogar e deletar o OAuth app registration criado pelo atacante no Entra ID, invalidando todos os refresh tokens emitidos para aquele app  
d) Isolar o endpoint via MDE  

**Q40.** O Banco Meridian tem um incidente de comprometimento de conta com exfiltração de dados de clientes. Qual é o prazo de notificação ao BACEN conforme a Resolução 4.893?

a) 24 horas  
b) 48 horas  
c) 72 horas  
d) 7 dias úteis  

---

## Parte 2 — Estudo de Caso: Incidente AiTM no Banco Meridian (20 pontos)

### Cenário

Na segunda-feira, às 09h15, o Microsoft Sentinel gerou o seguinte incidente no Banco Meridian:

```
Incident ID: BancM-2025-0156
Title: [Fusion] Multi-stage attack: AiTM Phishing → Token Theft → Data Collection
Severity: High
Status: New
Entities: ana.lima@bancomeridian.com.br, IP 45.89.100.23
MITRE ATT&CK: T1566.002 (Spearphishing), T1557 (AiTM), T1530 (Cloud Data)

Alertas correlacionados:
1. [MDO] Phishing email delivered: From microsoftsuporte-br.com, subject "Ação necessária"
2. [Entra ID Protection] Sign-in from anonymous IP: 45.89.100.23 (Romênia)
3. [Sentinel Rule] AiTM Token Theft - Login SFA sem Device
4. [Sentinel Rule] Anomalous SharePoint Download — 800% de baseline

Timeline:
09:15 — E-mail de phishing entregue e clicado (MDO)
09:33 — Login de 45.89.100.23 (RO) sem device ID (Entra ID Protection)
09:33–12:47 — 847 arquivos baixados do SharePoint de Contratos (OfficeActivity)
```

### Pergunta Discursiva 1 (4 pontos)

**Pergunta**: Descreva as ações imediatas (nos primeiros 10 minutos após descoberta do incidente) que o analista SOC L3 deve tomar, e explique como o playbook Logic App do Lab 04 auxilia na execução dessas ações.

**Gabarito esperado (rubrica)**:

Resposta deve cobrir:
1. **Revogar sessões imediatamente** via playbook (ou manualmente se playbook não disparou): execução da chamada Graph API `/users/{id}/revokeSignInSessions` — invalida todos os tokens ativos (2 pts)
2. **Preservar evidências**: antes de qualquer outra ação, verificar e documentar os logs no Sentinel — screenshots/bookmarks dos 4 alertas correlacionados; a ordem importa para chain of custody (1 pt)
3. **Notificar partes interessadas**: o playbook envia mensagem automática ao Teams com link do incidente; para incidente de alta severidade, notificar também o gestor de ana.lima e o CISO (1 pt)

---

### Pergunta Discursiva 2 (4 pontos)

**Pergunta**: O e-mail de phishing foi entregue pelo MDO sem ser classificado como phishing na hora da entrega. Explique 3 razões técnicas pelas quais isso pode ocorrer e como mitigar cada uma.

**Gabarito esperado**:

1. **Domínio recente** (`microsoftsuporte-br.com` criado há menos de 24h): feeds de reputação de URL não têm histórico negativo para domínios novos. Mitigação: habilitar "First contact safety tips" no MDO; configurar políticas que tratam domínios com menos de X dias como suspeitos (2 pts)
2. **URL limpa no momento da varredura, maliciosa depois** (Time-of-click detonation): o link pode apontar para um site legítimo inicialmente e depois redirecionar para o proxy AiTM. Mitigação: Safe Links com "on-click verification" em vez de "scan at delivery only" (1 pt)
3. **Nenhuma TI disponível na hora da entrega**: o grupo APT usa domínios que ainda não constam em nenhuma lista negra. Mitigação: integrar feeds de TI especializados em typosquatting (ferramentas como dnstwist) via TAXII connector no Sentinel; enriquecer alertas MDO com essa TI (1 pt)

---

### Pergunta Discursiva 3 (4 pontos)

**Pergunta**: 847 arquivos foram exfiltrados do SharePoint de Contratos. O banco tem obrigações regulatórias com o BACEN e LGPD. Descreva as ações de notificação e as implicações regulatórias.

**Gabarito esperado**:

1. **BACEN 4.893, Art. 23**: incidentes relevantes de segurança devem ser notificados ao BACEN em até **72 horas** da detecção. A notificação deve incluir: natureza do incidente, sistemas afetados, dados comprometidos, ações tomadas. O banco deve documentar formalmente a notificação. (2 pts)
2. **LGPD, Art. 48**: quando o incidente envolver dados pessoais de clientes (contratos = dados de clientes), o banco deve notificar a ANPD e os titulares dos dados afetados em prazo razoável. A notificação deve indicar quais dados foram expostos e medidas de mitigação adotadas. (1 pt)
3. **Documentação interna**: manter registro do incidente por pelo menos 5 anos (BACEN 4.893, Art. 19) com toda a evidência técnica, timeline e ações tomadas. O Sentinel (workspace com 5 anos de retenção) serve como repositório. (1 pt)

---

### Pergunta Discursiva 4 (4 pontos)

**Pergunta**: A analytics rule de AiTM Token Theft criada no Lab 03 (Módulo 04) usou `join kind=inner` com lookback de 7 dias para verificar histórico de MFA do usuário. Por que este design é necessário, e quais são as limitações desta abordagem?

**Gabarito esperado**:

1. **Por que o join com histórico MFA**: a condição `AuthenticationRequirement == "singleFactorAuthentication"` por si só não é suficiente — há cenários legítimos onde MFA não é exigido (ex.: trusted locations, compliant devices). O join verifica que o usuário TEM histórico de MFA, tornando o login SFA realmente anômalo para aquele usuário específico. (2 pts)

2. **Limitações**:
   - **Novos usuários** sem 7 dias de histórico MFA não serão detectados — o join não retornará resultados. Mitigação: adicionar uma branch alternativa que detecta contas novas sem qualquer histórico de device ID. (1 pt)
   - **Usuários que nunca usaram MFA** (se a CA policy não era obrigatória antes) também passarão despercebidos. O banco deve garantir que MFA é obrigatório para todos (como pré-condição para que esta rule seja eficaz). (1 pt)

---

### Pergunta Discursiva 5 (4 pontos)

**Pergunta**: Após o incidente, o CISO quer implementar "Automatic Attack Disruption" para que futuros ataques AiTM sejam contidos automaticamente antes que exfiltração ocorra. Descreva como esta funcionalidade funciona, quais são os pré-requisitos no ecossistema Microsoft, e quais são os riscos operacionais de ativar respostas automáticas agressivas.

**Gabarito esperado**:

1. **Como funciona o Automatic Attack Disruption** (XDR): o motor de correlação ML do Defender XDR identifica ataques de alta confiança em andamento (BEC, ransomware, AiTM) e executa ações de contenção automaticamente sem aprovação humana — desabilitar contas comprometidas, isolar endpoints, revogar tokens OAuth maliciosos. As ações são baseadas em modelos de ML treinados em trilhões de sinais do ecossistema Microsoft. (2 pts)

2. **Pré-requisitos**: MDE habilitado (para isolamento de endpoint), Entra ID com permissões de revogação de sessão, MDO (para detecção inicial via phishing), conectores XDR completos configurados no Sentinel. Todos precisam estar no mesmo tenant. (1 pt)

3. **Riscos operacionais**: falso positivo com Account Disruption pode desabilitar a conta de um executivo durante um período crítico de negócios (ex.: durante uma transferência importante); isolamento automático de endpoint pode interromper operações críticas; sem processo de revisão rápida de FPs, a automação pode causar danos maiores que o ataque. Mitigação: configurar exceções para contas críticas, ter processo de revisão de "disruption events" em <5min, testar o sistema em ambiente de staging antes da produção. (1 pt)

---

## Gabarito — Parte 1 (Múltipla Escolha)

| Q   | Resp | Q   | Resp | Q   | Resp | Q   | Resp |
|:----|:----:|:----|:----:|:----|:----:|:----|:----:|
| Q01 | C    | Q11 | B    | Q21 | B    | Q31 | B    |
| Q02 | B    | Q12 | B    | Q22 | B    | Q32 | B    |
| Q03 | C    | Q13 | B    | Q23 | B    | Q33 | C    |
| Q04 | C    | Q14 | B    | Q24 | B    | Q34 | B    |
| Q05 | B    | Q15 | B    | Q25 | C    | Q35 | B    |
| Q06 | B    | Q16 | B    | Q26 | B    | Q36 | B    |
| Q07 | B    | Q17 | B    | Q27 | B    | Q37 | B    |
| Q08 | B    | Q18 | B    | Q28 | C    | Q38 | C    |
| Q09 | B    | Q19 | B    | Q29 | C    | Q39 | C    |
| Q10 | B    | Q20 | B    | Q30 | B    | Q40 | C    |

---

## Tabela de Aproveitamento

| Faixa de Score   | Classificação         | Recomendação                                              |
|:-----------------|:----------------------|:----------------------------------------------------------|
| 90–100 pontos    | Excelente             | Pronto para SC-200; candidato a Monitor/Tutor             |
| 80–89 pontos     | Aprovado com distinção| Revisar pontos perdidos antes do SC-200                   |
| 70–79 pontos     | Aprovado              | Revisar módulos com erros; repetir labs correspondentes   |
| 60–69 pontos     | Recuperação           | Refazer os módulos 04–07; reavaliação em 2 semanas        |
| < 60 pontos      | Reprovado             | Rever o curso completo; agendar tutoria individual        |

### Distribuição por Módulo

| Módulo                          | Questões | Pontos |
|:--------------------------------|:--------:|:------:|
| 01 — Arquitetura Microsoft      | 4        | 8      |
| 02 — Sentinel Deployment        | 4        | 8      |
| 03 — KQL                        | 4        | 8      |
| 04 — Detection Engineering      | 5        | 10     |
| 05 — SOAR e Logic Apps          | 4        | 8      |
| 06 — Defender XDR               | 5        | 10     |
| 07 — Defender for Cloud         | 4        | 8      |
| 08 — Entra ID Protection + PIM  | 4        | 8      |
| 09 — Threat Hunting             | 3        | 6      |
| 10 — Capstone / Integração      | 3        | 6      |
| **Subtotal Múltipla Escolha**   | **40**   | **80** |
| Estudo de Caso (5 discursivas)  | 5        | 20     |
| **TOTAL**                       | **45**   | **100**|
