# Avaliação Final — AWS Cloud Security Operations

**Curso 3: AWS Cloud Security Operations · CECyber**
**Certificação Alvo:** AWS Certified Security – Specialty (SCS-C02)
**Peso na Nota Final:** 80% (questões) + 20% (estudo de caso)
**Duração:** 3 horas

---

## Parte 1 — Questões de Múltipla Escolha (80 pontos / 40 questões / 2 pts cada)

### Bloco 1: Fundamentos e Governança (Módulos 1 e 9)

**Q01.** Um desenvolvedor do Banco Meridian acidentalmente criou um bucket S3 público com dados de clientes na conta Production. A SCP `DenyUnencryptedS3` estava aplicada na OU Production. Qual afirmação é correta?

a) A SCP impede a criação de buckets públicos além de exigir criptografia
b) A SCP bloqueia apenas `PutObject` sem criptografia — a criação do bucket público não é coberta por essa SCP específica
c) SCPs não se aplicam a operações do S3
d) A SCP teria impedido a criação do bucket

**Q02.** O Banco Meridian usa `iam:PassRole` com a seguinte política: `"Action": "iam:PassRole", "Resource": "arn:aws:iam::444444444444:role/*"`. Qual é o risco de segurança dessa configuração?

a) Nenhum — PassRole é uma permissão de leitura
b) Permite que o usuário passe QUALQUER role da conta para serviços AWS, incluindo roles com AdministratorAccess
c) Só funciona para EC2, então o risco é limitado
d) PassRole requer MFA, então é seguro

**Q03.** Qual é a diferença entre uma SCP com `"NotAction"` e uma SCP com `"Action"`?

a) `NotAction` bloqueia TUDO exceto as ações listadas; `Action` bloqueia apenas as ações listadas
b) `Action` bloqueia TUDO exceto as ações listadas; `NotAction` bloqueia apenas as ações listadas
c) São equivalentes — apenas sintaxe diferente
d) `NotAction` é usado para Allow List; `Action` para Deny List

**Q04.** A Management Account do Banco Meridian foi comprometida. Qual é o impacto máximo potencial?

a) Apenas os recursos da Management Account são afetados
b) O atacante pode remover SCPs, modificar OUs, acessar qualquer conta da organização e desabilitar GuardDuty em todas as contas
c) Apenas as contas na mesma OU são afetadas
d) O GuardDuty detecta automaticamente e isola a conta

**Q05.** O IAM Access Analyzer do Banco Meridian encontrou que o bucket `meridian-relatorios` é acessível pela principal `arn:aws:iam::999999999999:root`. Esse Account ID não é reconhecido. O que isso indica?

a) Configuração normal de bucket público
b) O bucket tem uma resource-based policy concedendo acesso a uma conta AWS desconhecida — potencial exposição não intencional
c) O Access Analyzer está com falha — reiniciar o serviço
d) Acesso de auditoria automático pela AWS

---

### Bloco 2: Logging e Monitoramento (Módulo 2)

**Q06.** Um analista precisa determinar se houve exfiltração de dados de um bucket S3 durante um período de 6 meses. O CloudTrail Event History mostra apenas 90 dias. Como obter os dados mais antigos?

a) Não é possível — CloudTrail não retém dados além de 90 dias
b) Os logs completos estão no S3 bucket do CloudTrail organization trail — usar Athena ou CloudTrail Lake para consultar
c) Solicitar os dados à AWS via case de suporte
d) Os dados estão no CloudWatch Logs com retenção de 1 ano

**Q07.** Qual é o `filter pattern` correto do CloudWatch Logs para detectar logins no console AWS sem MFA?

a) `{$.eventName = "ConsoleLogin"}`
b) `{($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed = "No")}`
c) `{($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes")}`
d) `{$.userIdentity.type = "IAMUser"}`

**Q08.** O VPC Flow Log abaixo indica qual tipo de atividade suspeita?
`2 444444444444 eni-0abc 10.0.1.50 185.220.101.15 52341 4444 6 9871 142350000 1712750000 1712753600 ACCEPT OK`

a) Tráfego HTTP normal
b) Exfiltração de dados (~142 MB) via TCP para IP externo na porta 4444 (associada a C2/reverse shell) durante 1 hora
c) Conexão SSH legítima
d) Resposta de consulta DNS

**Q09.** Para qual finalidade o CloudTrail Lake é MELHOR que a combinação CloudTrail + S3 + Athena?

a) Custo — CloudTrail Lake é mais barato para consultas frequentes
b) Velocidade de queries, suporte nativo a organização, retenção de 7 anos, e eliminação de infraestrutura Athena/Glue
c) Integração com SIEM de terceiros
d) São equivalentes — apenas preferência do arquiteto

**Q10.** Qual campo do evento CloudTrail indica que uma ação foi bloqueada por uma SCP?

a) `"blocked": true`
b) `"errorCode": "AccessDenied"` + `"errorMessage": "Explicit deny in a service control policy"`
c) `"scp_block": "true"`
d) `"denied": "SCP"`

---

### Bloco 3: Amazon GuardDuty (Módulo 3)

**Q11.** O finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` foi gerado para a instância `i-0abc123`. O que isso indica com mais precisão?

a) A instância tem um malware que está consumindo CPU para mineração
b) As credenciais temporárias do IAM role attached à instância (via IMDS) estão sendo usadas de um IP fora dos data centers da AWS
c) A instância está fazendo port scanning na rede interna
d) O Instance Metadata Service está desabilitado

**Q12.** O Banco Meridian tem um pentest agendado com a empresa PentestCorp usando IPs no range `203.0.113.0/24`. Os findings `Recon:EC2/PortProbeUnprotectedPort` estão poluindo o console do GuardDuty. Qual é a abordagem CORRETA?

a) Desabilitar o GuardDuty durante o pentest
b) Adicionar `203.0.113.0/24` à Trusted IP List do GuardDuty para que nenhum finding seja gerado para esse range
c) Criar uma Suppression Rule específica para o finding type + range de IP do pentest
d) Ignorar os findings LOW durante o período do pentest

**Q13.** Qual feature do GuardDuty analisa arquivos em volumes EBS sem impacto na instância de produção?

a) Runtime Monitoring
b) Malware Protection para EC2 (análise via snapshot)
c) EC2 Scanning do Inspector
d) EKS Audit Logs

**Q14.** Em uma organização com 50 contas AWS, um finding GuardDuty na conta 30 com severidade MEDIUM não gerou alerta automático. Qual é a causa mais provável?

a) O GuardDuty estava desabilitado nessa conta
b) A EventBridge rule na conta Audit está configurada apenas para findings HIGH (severity >= 7.0)
c) MEDIUM findings nunca geram alertas no GuardDuty
d) O finding foi suprimido automaticamente

**Q15.** Qual é a diferença entre `Recon:EC2/PortProbeUnprotectedPort` e `Recon:EC2/Portscan`?

a) São equivalentes — apenas nomenclatura diferente
b) PortProbeUnprotectedPort: porta específica sendo probeada externamente. Portscan: a PRÓPRIA instância está fazendo scan de portas em outros hosts (indica comprometimento)
c) PortProbeUnprotectedPort é HIGH; Portscan é LOW
d) Portscan usa VPC Flow Logs; PortProbeUnprotectedPort usa DNS Logs

---

### Bloco 4: Postura de Segurança (Módulo 4)

**Q16.** O Banco Meridian quer demonstrar conformidade PCI DSS 3.2.1 para uma auditoria. Qual serviço AWS fornece o painel de controles específicos para PCI DSS e o percentual de conformidade?

a) AWS Config Aggregator
b) AWS Security Hub com standard PCI DSS 3.2.1 habilitado
c) Amazon Inspector
d) AWS Audit Manager

**Q17.** Uma Config Rule do tipo `CHANGE_TRIGGERED` para `restricted-ssh` avalia Security Groups. Quando exatamente a avaliação é disparada?

a) A cada 24 horas automaticamente
b) Quando um Security Group é criado, modificado ou deletado
c) Apenas quando o admin executa manualmente
d) A cada 1 hora

**Q18.** O Amazon Inspector encontrou CVE-2024-12345 (CVSS 8.5) em 5 instâncias EC2 expostas publicamente. Qual é o SLA de remediação e a ação mais urgente?

a) 30 dias; patch no próximo ciclo
b) 7 dias; verificar exploitability e patch; para instâncias publicamente acessíveis, considerar isolamento imediato
c) 90 dias; aguardar fornecedor
d) 24h; restart das instâncias resolve

**Q19.** Qual é a vantagem de um Conformance Pack sobre Config Rules individuais para o mapeamento BACEN 4.893?

a) Conformance Packs são mais baratos por avaliar menos recursos
b) Permitem deployar um conjunto de regras como uma unidade versionável, com painel consolidado de conformidade por framework
c) São mais rápidos para avaliar recursos
d) Conformance Packs não usam Config Rules

**Q20.** O Security Hub reporta `ComplianceStatus: FAILED` para o controle `CIS.1.14 - Ensure hardware MFA is enabled for the root account`. O que isso significa e como remediar?

a) A conta root não tem MFA configurado — criar chave de acesso MFA no console IAM para root
b) O controle CIS 1.14 verifica especificamente MFA de hardware (chave física) para root; remediar habilitando um dispositivo MFA de hardware (ex: YubiKey) na conta root
c) MFA de software (TOTP) não é aceito pela AWS
d) Remediação automática via SSM resolve esse controle

---

### Bloco 5: Investigação de Incidentes (Módulo 5)

**Q21.** O Amazon Detective requer que qual serviço esteja habilitado para funcionar?

a) AWS Config
b) Amazon GuardDuty
c) AWS CloudTrail
d) Amazon Macie

**Q22.** Você está investigando um incidente de privilege escalation. No CloudTrail Lake, encontrou a sequência: `ListRoles` → `AssumeRole(SecurityAuditRole)` → `SimulatePrincipalPolicy` → `CreatePolicy(AdministratorAccess)` → `AttachUserPolicy`. Qual técnica MITRE isso representa?

a) T1078 - Valid Accounts
b) T1548 - Abuse Elevation Control Mechanism (escalada de privilégios via IAM)
c) T1537 - Transfer Data to Cloud Account
d) T1496 - Resource Hijacking

**Q23.** Por que um snapshot EBS criado para análise forense NUNCA deve ser montado em modo de escrita em uma instância de análise?

a) Snapshots não podem ser montados em modo de escrita
b) Montar em modo de escrita modifica metadados do filesystem (atime, mtime) contaminando as evidências e invalidando o hash de integridade
c) É muito lento para análise forense
d) A AWS não permite acesso de escrita a snapshots

**Q24.** O External ID em uma trust policy de role cross-account protege contra qual ataque?

a) SQL Injection
b) "Confused Deputy Problem" — impede que um intermediário mal-intencionado use uma role criada para você para assumir seus recursos
c) Brute force de credenciais
d) DNS hijacking

**Q25.** Qual é a forma mais eficiente de revogar IMEDIATAMENTE todas as sessões STS ativas de um usuário IAM comprometido?

a) Excluir o usuário IAM
b) Desabilitar as access keys e adicionar uma política inline com `"Effect": "Deny", "Action": "*", "Condition": {"DateLessThan": {"aws:TokenIssueTime": "<timestamp_agora>"}}`
c) Aguardar as sessões expirarem naturalmente
d) Contatar o suporte AWS para invalidar as sessões

---

### Bloco 6: Proteção de Dados (Módulo 6)

**Q26.** Qual é o padrão de envelope encryption e por que o SDK da AWS o usa?

a) Criptografia de dados diretamente com a chave KMS para máxima segurança
b) Criptografia de um DEK com a CMK (KMS), e uso do DEK para criptografar os dados em memória. Resolve o limite de 64KB do KMS e otimiza performance e custo
c) Uso de dois layers de criptografia AES-256 para dados sensíveis
d) Criptografia assimétrica para dados em trânsito

**Q27.** O Banco Meridian precisa armazenar a chave privada de sua CA raiz com FIPS 140-2 Level 3 e hardware dedicado. Qual serviço usar?

a) AWS KMS com CMK
b) AWS CloudHSM
c) AWS Secrets Manager com KMS encryption
d) ACM (AWS Certificate Manager)

**Q28.** Qual é a diferença entre Secrets Manager com rotação automática e Parameter Store para senhas de banco de dados RDS?

a) Parameter Store tem rotação automática nativa para RDS; Secrets Manager não
b) Secrets Manager tem rotação automática nativa para RDS (via Lambda); Parameter Store não tem rotação nativa e é mais adequado para strings de configuração não sensíveis
c) São equivalentes para RDS
d) Parameter Store é mais seguro por não ter acesso externo

**Q29.** O Amazon Macie encontrou 50.000 CPFs em um bucket de relatórios. O bucket tem criptografia KMS e não é público. Qual é a ação correta sob a LGPD?

a) Nenhuma ação necessária — bucket criptografado e privado é suficiente
b) Notificar o DPO, verificar se o processamento dos dados tem base legal, revisar minimização de dados, e implementar controles de acesso adicionais ao bucket
c) Habilitar Object Lock imediatamente
d) Mover os dados para um bucket separado

**Q30.** Qual modo do S3 Object Lock é necessário para cumprir com requisito de imutabilidade de logs por 7 anos do BACEN, onde NINGUÉM (nem root) pode deletar os objetos antes do prazo?

a) Governance mode
b) Compliance mode
c) Retention mode
d) Legal Hold

---

### Bloco 7: Segurança de Rede (Módulo 7)

**Q31.** Por que uma instância EC2 na subnet privada de app do Banco Meridian consegue acessar o S3 mesmo sem acesso à internet?

a) O S3 tem IP privado por padrão
b) Um Gateway VPC Endpoint para S3 cria uma rota direta via backbone privado da AWS na route table da subnet
c) A instância usa o NAT Gateway para acessar o S3
d) S3 é acessível via IPv6 privado

**Q32.** A diferença fundamental entre Security Group e NACL em relação ao estado da conexão é:

a) SG é stateless (exige regras de ingress e egress separadas); NACL é stateful
b) SG é stateful (retorno automático permitido); NACL é stateless (exige regras separadas para ingress e egress, incluindo portas efêmeras)
c) Ambos são stateful
d) Ambos são stateless

**Q33.** O internet banking do Banco Meridian sofreu um ataque de brute force com 500.000 requests/min no endpoint `/api/auth/login`. Qual regra WAF mitiga isso?

a) SQLi Rule Group
b) Rate-Based Rule com limit de 100 requests por IP por 5 minutos, com scope-down para a URI `/api/auth/login`
c) GeoBlock Rule
d) IP Reputation List

**Q34.** Qual é a diferença entre AWS Shield Standard e AWS Shield Advanced em relação a ataques DDoS Layer 7?

a) Ambos protegem Layer 7
b) Shield Standard protege Layer 3/4 automaticamente; Shield Advanced adiciona proteção Layer 7 em conjunto com WAF, plus DRT, Cost Protection e diagnósticos avançados
c) Shield Advanced apenas aumenta os limites de Scale do Shield Standard
d) Shield Standard inclui suporte do DRT (DDoS Response Team)

**Q35.** O AWS Network Firewall é mais adequado que WAF + Security Groups quando:

a) Você tem menos de 100 instâncias
b) Precisa de inspeção deep de payload east-west (entre VPCs via TGW), regras Suricata, ou bloqueio de domínios em protocolos não-HTTP
c) Apenas para ambientes multi-conta
d) Quando o custo de WAF é proibitivo

---

### Bloco 8: Automação de Resposta (Módulo 8)

**Q36.** Uma Lambda de IR executa corretamente na primeira invocação mas falha na segunda invocação para o mesmo incidente porque tenta criar um Security Group com nome já existente. Qual princípio de design foi violado?

a) Least Privilege
b) Idempotência — a Lambda deve verificar se o SG já existe antes de criar
c) Separation of Duties
d) Defense in Depth

**Q37.** Qual é o evento EventBridge correto para capturar quando um Config Rule muda de COMPLIANT para NON_COMPLIANT?

a) `{"source": ["aws.config"], "detail-type": ["Config Rules Compliance Change"]}`
b) `{"source": ["aws.cloudtrail"], "detail-type": ["Config Rule Violation"]}`
c) `{"source": ["aws.securityhub"], "detail-type": ["Config Finding"]}`
d) `{"source": ["aws.config"], "detail-type": ["AWS API Call via CloudTrail"]}`

**Q38.** Em um Step Functions workflow de IR, para que serve o `Wait State` com `taskToken`?

a) Para aguardar a conclusão de uma consulta ao banco de dados
b) Para parar a execução até receber aprovação humana explícita (via API callback) antes de executar ações irreversíveis como terminar uma instância
c) Para limitar o rate de chamadas a APIs AWS
d) Para aguardar que um snapshot EBS seja concluído

**Q39.** Qual é a fase NIST SP 800-61 que corresponde às automações de isolamento de EC2 e desabilitar IAM key implementadas no Módulo 8?

a) Preparação
b) Detecção e Análise
c) Contenção
d) Erradicação

**Q40.** A Lambda de IR `DisableIAMKey` tem um Dead Letter Queue (DLQ) configurado para SQS. Qual é a finalidade do DLQ nesse contexto?

a) Armazenar os resultados bem-sucedidos das invocações
b) Capturar invocações que falharam após todas as tentativas (retry), permitindo investigação posterior e reprocessamento manual de incidentes críticos que não foram atendidos
c) Aumentar a capacidade de processamento da Lambda
d) Armazenar os eventos GuardDuty para análise histórica

---

## Parte 2 — Estudo de Caso (20 pontos / 5 questões discursivas / 4 pts cada)

### Cenário: Incidente Multi-Vetor no Banco Meridian

**Situação:** Em uma segunda-feira às 09h15 BRT, o Security Hub do Banco Meridian exibiu os seguintes findings simultâneos:

1. **GuardDuty HIGH:** `PrivilegeEscalation:IAMUser/AnomalousBehavior` — usuário `paulo.santos` (Developer)
2. **GuardDuty HIGH:** `Exfiltration:S3/AnomalousBehavior` — bucket `meridian-contratos-financeiros`
3. **Config NON_COMPLIANT:** `s3-bucket-public-read-prohibited` — bucket `meridian-uploads-web`
4. **GuardDuty MEDIUM:** `UnauthorizedAccess:EC2/SSHBruteForce` — instância `i-0prod-web-01`
5. **Inspector CRITICAL:** `CVE-2024-99999` (CVSS 9.3) — instância `i-0prod-web-01`

**Análise adicional do CloudTrail Lake:**
- `paulo.santos` executou `SimulatePrincipalPolicy` às 08:47
- `paulo.santos` executou `CreatePolicy` com `Action: *` às 08:52
- `paulo.santos` executou `AttachUserPolicy` (self) às 08:53
- O usuário `backup-system-user` fez `GetObject` em 12.000 objetos do bucket `meridian-contratos-financeiros` entre 07h00-09h00
- `backup-system-user` é um usuário legítimo de backup, mas com acesso cross-region incomum (Oregon)

---

**EC1 (4 pontos):** Analise os findings 1 e 2 em conjunto. Qual é a relação entre eles e qual é a hipótese mais provável sobre como o comprometimento ocorreu?

**GABARITO EC1:** Os findings 1 e 2 provavelmente estão correlacionados. Finding 1: `paulo.santos` executou privilege escalation (CreatePolicy + AttachUserPolicy self) — agora tem AdministratorAccess. Finding 2: exfiltração S3 ocorre de `backup-system-user` entre 07h-09h — ANTES da escalada de `paulo.santos` às 08h52. Portanto são eventos independentes. Hipóteses: (A) Dois vetores simultâneos: `paulo.santos` comprometido por phishing ou credential leak; `backup-system-user` comprometido separadamente ou acesso legítimo de backup mal configurado com acesso cross-region. (B) `paulo.santos` usou seus próprios acessos legítimos para reconhecimento (08:47 SimulatePrincipalPolicy), identificou que podia escalar, e a exfiltração de S3 foi feita pela conta comprometida separadamente. Prioridade: finding 1 é escalada ativa — conter imediatamente. Finding 2 pode ser exfiltração já concluída — investigar escopo dos dados.

---

**EC2 (4 pontos):** O finding 3 (S3 público) e o finding 5 (CVE CRITICAL) estão na mesma instância `i-0prod-web-01`. Descreva como esses dois findings combinados aumentam o risco do finding 4 (SSH brute force).

**GABARITO EC2:** Combinação de fatores amplifica o risco: (1) CVE CRITICAL (CVSS 9.3) na instância que está sendo atacada por SSH = se o brute force tiver sucesso, o atacante pode imediatamente usar a CVE para escalar privilégios no SO. (2) Inspector + Network Reachability mostra que a instância é publicamente acessível — o brute force SSH pode ser de qualquer IP do mundo. (3) S3 bucket público `meridian-uploads-web` — se a instância for comprometida, o atacante provavelmente tem acesso ao bucket e pode exfiltrar ou envenenar os uploads. Risk composto: acesso inicial via SSH brute force + escalada local via CVE + exfiltração via S3 = comprometimento completo da instância e dos dados de upload. Ação imediata: (1) Fechar porta 22 para 0.0.0.0/0 (manter apenas range do IR), (2) Aplicar workaround da CVE, (3) Bloquear acesso público ao bucket S3.

---

**EC3 (4 pontos):** Descreva as ações de contenção para os 5 findings, na ordem de prioridade. Justifique a priorização.

**GABARITO EC3:** Ordem de prioridade e justificativa:

1. **Finding 1 — paulo.santos escalada (IMEDIATO, 0-5 min):** Revogar todas as permissões adicionadas, desabilitar access keys, revogar sessões ativas com deny policy. Razão: escalada ativa, atacante pode estar executando mais ações agora.

2. **Finding 5 — CVE CRITICAL em i-0prod-web-01 (IMEDIATO, 0-15 min):** Aplicar workaround (`-Djava.security.egd` ou similar), considerar isolamento do tráfego de internet. Razão: combinado com brute force ativo, a janela de exploração é mínima.

3. **Finding 4 — SSH Brute Force em i-0prod-web-01 (IMEDIATO, 0-10 min):** Remover regra SSH `0.0.0.0/0` do Security Group. Razão: ataque ativo, fecha a porta de acesso.

4. **Finding 3 — S3 Público (15-30 min):** Habilitar Block Public Access no bucket `meridian-uploads-web`. Razão: auto-remediação já deveria ter tratado, mas dado o contexto de incidente, tratar manualmente também.

5. **Finding 2 — Exfiltração S3 (análise paralela):** Investigar o escopo (quais objetos foram acessados), revogar credenciais de `backup-system-user` se acesso anômalo confirmado, notificar DPO se dados pessoais foram expostos.

---

**EC4 (4 pontos):** A sequência de ações do `paulo.santos` — `SimulatePrincipalPolicy` → `CreatePolicy` → `AttachUserPolicy` — mapeia para qual técnica MITRE ATT&CK? Escreva a query SQL para o CloudTrail Lake que detecta essa sequência.

**GABARITO EC4:** Técnica MITRE: T1548.005 - Abuse Elevation Control Mechanism: Cloud Accounts, combinado com T1136.003 - Create Account (se criar usuário backdoor) e Discovery T1087.004 (SimulatePrincipalPolicy para enumeração). 

Query SQL:
```sql
WITH timeline AS (
    SELECT
        eventTime,
        eventName,
        userIdentity.arn AS ator,
        userIdentity.userName AS usuario,
        sourceIPAddress
    FROM $EDS_ID
    WHERE
        userIdentity.userName = 'paulo.santos'
        AND eventName IN ('SimulatePrincipalPolicy', 'CreatePolicy', 'AttachUserPolicy', 'AttachRolePolicy')
        AND eventSource = 'iam.amazonaws.com'
        AND eventTime > DATE_ADD('day', -1, NOW())
    ORDER BY eventTime ASC
)
SELECT * FROM timeline
```
Contexto: o SimulatePrincipalPolicy sem executar ação é o reconhecimento. CreatePolicy + AttachUserPolicy é a escalada. Detectar a SEQUÊNCIA dentro de um intervalo curto (< 30 min) é o sinal de alerta.

---

**EC5 (4 pontos):** O bucket `meridian-contratos-financeiros` contém contratos assinados de 250.000 clientes. O finding de exfiltração confirma que 12.000 objetos foram baixados por `backup-system-user` em uma região não habitual. Quais são as obrigações regulatórias do Banco Meridian e os prazos?

**GABARITO EC5:** Obrigações regulatórias múltiplas:

**LGPD (Lei 13.709/2018):**
- Art. 48: Comunicar à ANPD (Autoridade Nacional de Proteção de Dados) em prazo razoável (interpretado como 72 horas pela prática regulatória)
- Art. 48: Comunicar ao titular dos dados afetados (250.000 clientes)
- Incluir na comunicação: natureza dos dados, categorias de titulares afetados, medidas de mitigação tomadas

**BACEN (Resolução BCB 4.893/2021):**
- Art. 13: Comunicar ao Banco Central incidentes de segurança que possam impactar o Sistema Financeiro Nacional
- Prazo: imediatamente após identificação, ou no mínimo no mesmo dia útil
- Incluir: natureza do incidente, impacto estimado, medidas adotadas

**Ações imediatas para conformidade:**
1. Documentar o incidente com timeline e escopo (dados afetados)
2. Convocar DPO (Data Protection Officer) e Jurídico imediatamente
3. Preparar comunicação formal para ANPD (dentro de 72h)
4. Preparar comunicação para BACEN (no mesmo dia útil)
5. Redigir comunicação aos 250.000 clientes afetados
6. Contratar empresa especializada em resposta a incidentes se necessário

---

## Gabarito — Questões de Múltipla Escolha

| Questão | Gabarito | Módulo |
|---|---|---|
| Q01 | B | 01 |
| Q02 | B | 01 |
| Q03 | A | 01 |
| Q04 | B | 01/09 |
| Q05 | B | 01 |
| Q06 | B | 02 |
| Q07 | C | 02 |
| Q08 | B | 02 |
| Q09 | B | 02 |
| Q10 | B | 02 |
| Q11 | B | 03 |
| Q12 | C | 03 |
| Q13 | B | 03 |
| Q14 | B | 03 |
| Q15 | B | 03 |
| Q16 | B | 04 |
| Q17 | B | 04 |
| Q18 | B | 04 |
| Q19 | B | 04 |
| Q20 | B | 04 |
| Q21 | B | 05 |
| Q22 | B | 05 |
| Q23 | B | 05 |
| Q24 | B | 05 |
| Q25 | B | 05 |
| Q26 | B | 06 |
| Q27 | B | 06 |
| Q28 | B | 06 |
| Q29 | B | 06 |
| Q30 | B | 06 |
| Q31 | B | 07 |
| Q32 | B | 07 |
| Q33 | B | 07 |
| Q34 | B | 07 |
| Q35 | B | 07 |
| Q36 | B | 08 |
| Q37 | A | 08 |
| Q38 | B | 08 |
| Q39 | C | 08 |
| Q40 | B | 08 |

---

## Nota de Aprovação

| Score | Resultado |
|---|---|
| >= 70% | APROVADO — Certificado de conclusão emitido |
| >= 85% | APROVADO COM DISTINÇÃO |
| < 70% | RECUPERAÇÃO — Módulos indicados para revisão |

**Resultado Final:** Parte 1 (max 80 pts) + Parte 2 (max 20 pts) = 100 pts total

**Alinhamento com SCS-C02:** Esta avaliação cobre os 5 domínios do exame AWS Certified Security – Specialty. Alunos com score >= 80% têm forte preparo para o exame de certificação.
