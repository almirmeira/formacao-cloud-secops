# Referências de Classe Mundial — Cloud Security & Cybersecurity

**CECyber · Programa de Formação Security Operations em Nuvem**

---

## Como Usar Este Documento

Este documento é o seu guia de imersão intelectual no campo de segurança cibernética de classe mundial. Organize seu consumo de conteúdo em três eixos:

1. **Especialistas (Seção 1):** siga pelo menos 5 desses profissionais nas plataformas onde são mais ativos. Eles fornecem contexto e inteligência que nenhum curso consegue substituir
2. **Relatórios (Seção 2):** reserve 1-2h por mês para ler os relatórios listados. São a inteligência estratégica do setor
3. **Frameworks e Normas (Seção 3):** use como referência ao projetar controles ou escrever políticas
4. **Regulatórios brasileiros (Seção 4):** obrigatório para quem trabalha com instituições financeiras, de saúde ou qualquer empresa que processa dados de cidadãos brasileiros

---

## Seção 1 — 25 Especialistas de Classe Mundial

### 1. Bruce Schneier

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Criptografia, política de segurança, privacidade, filosofia de risco tecnológico       |
| **Cargo/Afiliação**  | Fellow e Lecturer, Harvard Kennedy School; Author in Residence, IBM                    |
| **Contribuições**    | Criador do algoritmo Blowfish/Twofish; cunhou o conceito de "security theater"; articulou o trade-off liberdade-segurança. Autor de textos fundadores sobre por que a segurança falha sistemicamente |
| **Obras Recomendadas** | "Secrets and Lies" (2000); "Beyond Fear" (2003); "Data and Goliath" (2015); "Click Here to Kill Everybody" (2018); "A Hacker's Mind" (2023) |
| **Onde Seguir**      | Blog: schneier.com; Newsletter gratuita "Crypto-Gram" (mensal); LinkedIn; X @schneierblog |
| **Relevância Cloud SecOps** | Seus ensaios sobre modelos de confiança e falhas sistêmicas são essenciais para entender por que Zero Trust ganhou tração. "A Hacker's Mind" explica como atacantes pensam em termos de incentivos |

---

### 2. Brian Krebs

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Jornalismo investigativo de segurança, cibercrime, fraude financeira, dark web         |
| **Cargo/Afiliação**  | Fundador e editor do KrebsOnSecurity.com (independente)                                |
| **Contribuições**    | Investigações premiadas sobre grandes brechas (Target 2013, Adobe 2013, Equifax 2017). Revelou operações criminosas de ransomware, botnet, fraude de cartão de crédito. Ex-repórter do Washington Post |
| **Obras Recomendadas** | "Spam Nation" (2014) — história do negócio de spam russo; KrebsOnSecurity.com (leitura obrigatória semanal) |
| **Onde Seguir**      | Blog: krebsonsecurity.com; X @briankrebs; Mastodon infosec.exchange/@briankrebs        |
| **Relevância Cloud SecOps** | Suas investigações mostram como os ataques funcionam do ponto de vista dos atacantes — essencial para construir threat models realistas. Coverage de violações de nuvem e credential stuffing |

---

### 3. Mikko Hyppönen

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Malware research, threat intelligence, APT (Advanced Persistent Threats), história do cybercrime |
| **Cargo/Afiliação**  | Chief Research Officer, WithSecure (ex-F-Secure); Membro do Europol EC3 Advisory Board |
| **Contribuições**    | Análise pioneira de malware (I Love You, Anna Kournikova, Stuxnet, WannaCry). Cunhou a "Hyppönen Law": "Whenever an appliance is described as being 'smart', it's vulnerable". Palestrante TED com 3M+ views |
| **Obras Recomendadas** | "If It's Smart, It's Vulnerable" (2022) — livro sobre IoT security; TED Talk "Fighting Viruses, Defending the Net"; podcast "The Cyber" |
| **Onde Seguir**      | X @mikko; LinkedIn; mikkohypponen.com; talks no YouTube                                |
| **Relevância Cloud SecOps** | Contextualiza ameaças APT e como malware evolui — fundamental para construir hipóteses de threat hunting. Sua perspectiva histórica sobre como o cybercrime se profissionalizou é única |

---

### 4. Troy Hunt

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Data breaches, credential compromise, developer security awareness                     |
| **Cargo/Afiliação**  | Fundador e operador do Have I Been Pwned (HIBP); Microsoft Regional Director          |
| **Contribuições**    | Criou o Have I Been Pwned (haveibeenpwned.com) — maior base pública de credenciais comprometidas, usada por empresas e governos do mundo todo. Exposição e documentação de centenas de brechas |
| **Obras Recomendadas** | Blog: troyhunt.com (arquivos sobre cada grande breach); cursos Pluralsight sobre OWASP e web security |
| **Onde Seguir**      | Blog: troyhunt.com; X @troyhunt; LinkedIn; YouTube (palestras conferências)            |
| **Relevância Cloud SecOps** | Essencial para entender o problema de credential stuffing (alimentado por breach data). HIBP é uma ferramenta real usada em playbooks de SOC para verificar comprometimento de contas |

---

### 5. Eugene Kaspersky

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Malware research, AV/EDR, ciberguerra, política de cibersegurança global               |
| **Cargo/Afiliação**  | CEO e Co-fundador da Kaspersky Lab                                                     |
| **Contribuições**    | Construiu um dos maiores laboratórios de pesquisa de ameaças do mundo. Análises de Stuxnet, Flame, Duqu (malware de Estado). Visão crítica sobre a crescente militarização do ciberespaço |
| **Obras Recomendadas** | Blog: eugene.kaspersky.com; Securelist.com (blog técnico da Kaspersky Research)       |
| **Onde Seguir**      | LinkedIn; X @e_kaspersky; Securelist.com para pesquisa técnica de malware              |
| **Relevância Cloud SecOps** | Kaspersky GReAT (Global Research and Analysis Team) produz relatórios técnicos profundos sobre APTs — leitura obrigatória para threat hunters. Nota: use pesquisa técnica mas avalie políticas de dados com cautela |

---

### 6. Dmitri Alperovitch

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Threat intelligence, APT attribution, geopolítica cibernética, defesa nacional         |
| **Cargo/Afiliação**  | Co-fundador da CrowdStrike (até 2020); fundador e Chairman do Silverado Policy Accelerator |
| **Contribuições**    | Co-criou o conceito de "Fancy Bear" (APT28) e "Cozy Bear" (APT29) para atribuição de ataques russos. Investigação do DNC hack (2016). Liderou desenvolvimento da Falcon Platform da CrowdStrike |
| **Obras Recomendadas** | "World on the Brink" (2024) — sobre a nova guerra fria tecnológica; podcast "Geopolitics Decanted" |
| **Onde Seguir**      | X @DAlperovitch; LinkedIn; Silverado Policy Accelerator; podcast Geopolitics Decanted   |
| **Relevância Cloud SecOps** | Sua estrutura de atribuição de ameaças e entendimento de motivações de atores estatais é crucial para contextualizarmos ataques a infraestrutura cloud de setores críticos (financeiro, energia) |

---

### 7. Kevin Beaumont

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Threat research, vulnerability disclosure, Microsoft security ecosystem, honeypots     |
| **Cargo/Afiliação**  | Director of Threat Intelligence at Arcanum Cyber; ex-Microsoft e ex-NHS                |
| **Contribuições**    | Criador da rede de honeypots "GoodMorningCyberWar"; disclosure responsável de vulnerabilidades críticas (Exchange, WinRM); análise pioneira de CVEs de alto impacto (PrintNightmare, Follina, ProxyLogon). Voz crítica sobre a postura de segurança da Microsoft |
| **Obras Recomendadas** | Blog: doublepulsar.com; Medium @GossiTheDog; threads no X sobre exploração de CVEs |
| **Onde Seguir**      | Blog: doublepulsar.com; X @GossiTheDog; LinkedIn                                       |
| **Relevância Cloud SecOps** | Indispensável para quem opera no ecossistema Microsoft (Sentinel, MDE, Exchange). Seus análises rápidas de novas CVEs e exploits são frequentemente a melhor fonte de informação técnica antes dos CVSSs oficiais |

---

### 8. Jen Easterly

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Política de segurança nacional, infraestrutura crítica, liderança em cibersegurança    |
| **Cargo/Afiliação**  | Ex-Diretora da CISA (Cybersecurity and Infrastructure Security Agency, 2021–2025); ex-NSA |
| **Contribuições**    | Liderou a CISA durante as maiores crises de cibersegurança dos EUA: Log4Shell, SolarWinds recovery, Volt Typhoon. Criou a doutrina "Secure by Design" e "Secure by Default". Autora de novas exigências de divulgação de incidentes |
| **Obras Recomendadas** | Discursos e testemunhos no Congresso (disponíveis no YouTube); CISA Guidance Documents (cisa.gov); podcast "Resilient America" |
| **Onde Seguir**      | LinkedIn; X @CISAJen; cisa.gov para guidance documents                                 |
| **Relevância Cloud SecOps** | A doutrina "Secure by Design" é diretamente aplicável a como configuramos serviços cloud. As KEV (Known Exploited Vulnerabilities) da CISA são referência obrigatória para priorização de patches |

---

### 9. Katie Moussouris

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Vulnerability disclosure, bug bounty policy, direito de segurança, ética em infosec   |
| **Cargo/Afiliação**  | Fundadora e CEO da Luta Security; criadora do primeiro programa de bug bounty da Microsoft |
| **Contribuições**    | Criou o Coordinated Vulnerability Disclosure (CVD) framework que se tornou padrão internacional. Arquitetou os primeiros programas de bug bounty de organizações militares dos EUA (HackerOne × DoD). Ativista por remuneração justa em infosec |
| **Obras Recomendadas** | Artigos acadêmicos sobre CVD policy; palestra DEFCON "Don't Fail at Scaling Your Bug Bounty"; lutasecurity.com |
| **Onde Seguir**      | X @k8em0; LinkedIn; lutasecurity.com                                                   |
| **Relevância Cloud SecOps** | Entender políticas de disclosure e como o mercado de vulnerabilidades funciona é essencial para quem precisa priorizar patches e comunicar riscos ao management. Seus frameworks ajudam a criar programas de responsible disclosure |

---

### 10. Nicole Perlroth

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Jornalismo investigativo, ciberguerra, mercado de exploits zero-day, diplomacia cyber  |
| **Cargo/Afiliação**  | Ex-repórter de cibersegurança do New York Times (13 anos); atualmente consultora e autora |
| **Contribuições**    | Cobertura exclusiva de Stuxnet, ataques iranianos a bancos americanos, operações de vigilância da NSA (via Snowden documents), mercado de exploits da empresa italiana Hacking Team |
| **Obras Recomendadas** | "This Is How They Tell Me the World Ends" (2021) — o melhor livro sobre o mercado de zero-days; Nicole Perlroth Book (altamente recomendado para qualquer profissional de segurança) |
| **Onde Seguir**      | X @nicoleperlroth; LinkedIn; substack (Nicole Perlroth)                                |
| **Relevância Cloud SecOps** | O livro "This Is How They Tell Me the World Ends" é leitura obrigatória para entender o ecossistema de exploits que alimenta APTs. Contextualiza por que zero-days em cloud platforms são tão valiosos |

---

### 11. Andy Greenberg

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Jornalismo investigativo, ciberguerra, hackers, privacidade, cryptocurrencies           |
| **Cargo/Afiliação**  | Senior Writer, WIRED Magazine                                                          |
| **Contribuições**    | Cobertura histórica de Julian Assange e WikiLeaks, pesquisa de privacidade digital, investigação das operações cibernéticas russas (NotPetya, Sandworm). Cobertura de Silk Road e desmontagem de dark markets |
| **Obras Recomendadas** | "Sandworm" (2019) — história do grupo hacker russo mais destrutivo da história (NotPetya); "This Machine Kills Secrets" (2012) |
| **Onde Seguir**      | WIRED.com (perfil Andy Greenberg); X @a_greenberg; LinkedIn                            |
| **Relevância Cloud SecOps** | "Sandworm" é a melhor narrativa de um APT afetando infraestrutura crítica global (NotPetya custou ~$10B). Essencial para threat hunters entenderem o padrão de operações de wiper e destructive malware |

---

### 12. Graham Cluley

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Malware research, antivirus, divulgação pública de ameaças, podcasting de segurança    |
| **Cargo/Afiliação**  | Freelance security analyst; ex-Sophos, McAfee                                          |
| **Contribuições**    | 30 anos de research em malware (Sophos, McAfee). Blog prolífico com análises acessíveis de incidentes para audiências técnicas e não-técnicas. Vencedor de múltiplos prêmios "Most Influential Security Blogger" |
| **Obras Recomendadas** | Blog: grahamcluley.com; podcast "Smashing Security" (co-hosted com Carole Theriault) — um dos melhores podcasts de segurança do mundo |
| **Onde Seguir**      | Blog: grahamcluley.com; Podcast Smashing Security; X @gcluley; LinkedIn                |
| **Relevância Cloud SecOps** | Smashing Security é excelente para manter equipes de SOC atualizadas sobre novos ataques em linguagem acessível. Bom para onboarding de novos analistas ou para apresentações executivas |

---

### 13. Daniel Miessler

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Segurança ofensiva, AppSec, AI security, filosofia de segurança, educação               |
| **Cargo/Afiliação**  | Fundador da Unsupervised Learning (newsletter e podcast); ex-HP, ex-consultor independente |
| **Contribuições**    | Criador do projeto fabric (LLM pipelines para security workflows); metodologia de aprendizado de segurança; blog com ensaios profundos sobre carreira e mentalidade em segurança. Pioneiro em aplicações de LLMs em segurança |
| **Obras Recomendadas** | Newsletter Unsupervised Learning (danielmiessler.com); projeto fabric no GitHub (danielmiessler/fabric) |
| **Onde Seguir**      | danielmiessler.com; X @DanielMiessler; LinkedIn; GitHub danielmiessler                 |
| **Relevância Cloud SecOps** | Seu projeto fabric tem pipelines de LLM prontos para análise de logs de segurança, summarização de relatórios e geração de detecções. Útil para modernizar workflows de SOC com AI. Newsletter obrigatória para tendências |

---

### 14. Anton Chuvakin

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | SIEM, SOC design, log management, Gartner research, cloud security operations          |
| **Cargo/Afiliação**  | VP and Distinguished Analyst, Google Cloud Security; ex-Gartner (SIEM Magic Quadrant lead analyst) |
| **Contribuições**    | Definiu o conceito moderno de SIEM como analista do Gartner. Criou o framework de "Detection as Code". Co-autor de múltiplos livros de logging e SIEM. Agora pesquisa Cloud Security Operations no Google |
| **Obras Recomendadas** | "Security Information and Event Management (SIEM) Implementation" (2010, ainda relevante); Blog: detect-respond.blogspot.com |
| **Onde Seguir**      | Blog: detect-respond.blogspot.com; LinkedIn; X @anton_chuvakin                         |
| **Relevância Cloud SecOps** | Essencial para quem projeta ou opera um SOC. Seu framework de "Detection Engineering" é a base conceitual de módulos de detecção dos Cursos 1 e 2. Seu trabalho no Google em Chronicle/SecOps é diretamente relevante |

---

### 15. Theresa Payton

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Liderança em cibersegurança corporativa, cyber fraud, privacidade digital, diversidade em tech |
| **Cargo/Afiliação**  | CEO da Fortalice Solutions; primeira mulher a servir como CIO da Casa Branca (Bush Administration) |
| **Contribuições**    | CIO da Casa Branca de 2006 a 2008 durante período de transformação digital crítico. Especialista em proteção de cidadãos contra fraude digital. Autora de três livros sobre cyber risk. Comentarista frequente em grandes mídias |
| **Obras Recomendadas** | "Protecting the Brand" (2017); "Manipulated" (2020) — sobre operações de influência digital; "Privacy in the Age of Big Data" (2014) |
| **Onde Seguir**      | X @TheresaPayton; LinkedIn; fortalicesolutions.com                                     |
| **Relevância Cloud SecOps** | Sua perspectiva como ex-CIO do governo e CEO de consultoria oferece a visão executiva de como CISOs e CIOs tomam decisões de investimento em segurança — útil para apresentações de ROI e business cases |

---

### 16. Chuck Brooks

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Tecnologias emergentes de segurança, AI security, regulação, homeland security          |
| **Cargo/Afiliação**  | Professor Adjunto, Georgetown University; Chair do AI Security Working Group (CISA)    |
| **Contribuições**    | Curador dos artigos de segurança mais lidos no LinkedIn. Conecta academia, governo e indústria em AI security, quantum computing e regulação de tecnologias emergentes |
| **Obras Recomendadas** | LinkedIn Articles (follow no LinkedIn é praticamente obrigatório); chuckbrooks.net    |
| **Onde Seguir**      | LinkedIn (250k+ seguidores); X @ChuckDBrooks; chuckbrooks.net                          |
| **Relevância Cloud SecOps** | Melhor fonte para curadoria de artigos de segurança — segui-lo no LinkedIn garante um feed de conteúdo de alta qualidade. Relevante para quem acompanha AI security e computação quântica aplicada à criptografia |

---

### 17. Keren Elezari

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Perspectiva do hacker como aliado, threat intelligence, mulheres em cybersecurity      |
| **Cargo/Afiliação**  | Pesquisadora e analista de segurança, Tel Aviv University; TED Speaker                 |
| **Contribuições**    | TED Talk "Hackers: the Internet's immune system" (3M+ views) — reframou hackers como defensores necessários. Ponte entre comunidade hacker e corporações. Organizadora da conferência LioneSSes |
| **Obras Recomendadas** | TED Talk: "Hackers: the Internet's immune system"; keren.guru                         |
| **Onde Seguir**      | X @k3r3n3; LinkedIn; keren.guru                                                        |
| **Relevância Cloud SecOps** | Sua perspectiva sobre a mentalidade hacker como necessária para defesa é fundamental para threat hunters. Ensina a pensar como atacante — essencial para hipóteses de hunting |

---

### 18. Jake Williams

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Incident response, digital forensics, reverse engineering, malware analysis, NSA tools |
| **Cargo/Afiliação**  | Faculty, IANS Research; co-fundador da Rendition Infosec; ex-NSA TAO (Tailored Access Operations) |
| **Contribuições**    | Ex-operador da TAO da NSA (unidade de hacking mais avançada do mundo). Disclosure pública de ferramentas da NSA vazadas pelo Shadow Brokers. Referência técnica em análise de malware avançado e resposta a incidentes em APTs |
| **Obras Recomendadas** | SANS courses (autor de vários); Twitter threads sobre análise de malware e IR; IANS Research Papers |
| **Onde Seguir**      | X @MalwareJake; LinkedIn; renditioninfosec.com                                         |
| **Relevância Cloud SecOps** | Perspectiva única de quem atacou sistemas como operador de estado e agora os defende. Seus comentários técnicos sobre malware avançado e IR são referência para L3 SOC e threat hunters sênior |

---

### 19. David Kennedy

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Penetration testing, red team, social engineering, security awareness                  |
| **Cargo/Afiliação**  | CEO da TrustedSec e Binary Defense; criador da SET (Social Engineering Toolkit)        |
| **Contribuições**    | Criou o Social-Engineer Toolkit (SET) — ferramenta de pentesting mais usada do mundo. Ex-CISO, ex-analista de inteligência USMC. Testemunhou no Congresso sobre ataques ao governo |
| **Obras Recomendadas** | "Metasploit: The Penetration Tester's Guide" (co-autor); SET documentation (GitHub trustedsec/social-engineer-toolkit) |
| **Onde Seguir**      | X @HackingDave; LinkedIn; trustedsec.com blog                                          |
| **Relevância Cloud SecOps** | Perspectiva ofensiva sobre como ataques são executados na prática — essencial para calibrar detecções. Seus write-ups de red team exercícios mostram quais TTPs realmente funcionam contra defesas corporativas |

---

### 20. Eric Cole

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Defesa de redes, zero trust, segurança de carreira, treinamento executivo de CISO       |
| **Cargo/Afiliação**  | Fundador da Secure Anchor Consulting; ex-CIA; ex-CTO da Lockheed Martin CIRT           |
| **Contribuições**    | Articulou o conceito de "defesa profunda" adaptado para ambientes modernos. Autor de livros fundamentais de segurança. Coach de CISOs. Professor SANS por mais de 20 anos |
| **Obras Recomendadas** | "Hackers Beware" (2002); "Network Security Bible" (2005); "Online Danger" (2018); podcast "Live and Let Die" |
| **Onde Seguir**      | LinkedIn; X @drericcole; drericcole.com                                                |
| **Relevância Cloud SecOps** | Excelente para profissionais que querem transitar para papéis de liderança (CISO, Security Director). Seu framework de "defesa em profundidade" é direto ao tema dos nossos cursos de multi-cloud |

---

### 21. Shira Rubinoff

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | AI security, board-level cyber governance, women in cybersecurity                      |
| **Cargo/Afiliação**  | President, Tech Cybersecurity Business; Strategic Advisor (NASDAQ boards); Forbes Contributor |
| **Contribuições**    | Advoga pela integração de cibersegurança no board executivo. Mentora para mulheres em carreiras de tech e segurança. Análise de como IA muda o landscape de ameaças e defesa |
| **Obras Recomendadas** | Forbes Articles (Forbes.com/sites/Shira); LinkedIn Articles                           |
| **Onde Seguir**      | LinkedIn; X @ShiraRubinoff; Forbes.com                                                 |
| **Relevância Cloud SecOps** | Para profissionais de segurança que precisam comunicar riscos para boards e executives. Perspectiva de governança de AI security é cada vez mais relevante com adoção de ML em detecção de ameaças |

---

### 22. Magda Chelly

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | CISO role, cyber risk management, cyber insurance, board cyber governance              |
| **Cargo/Afiliação**  | Founder & CEO, Responsible Cyber; ex-CISO em várias organizações                      |
| **Contribuições**    | Uma das primeiras CISOs mulheres no mercado asiático. Framework de "responsible cyber" que integra sustentabilidade e ESG ao gerenciamento de risco cibernético. Cyber risk quantification |
| **Obras Recomendadas** | "CISO Compass" (contribuição); LinkedIn Articles; responsible.cyber                    |
| **Onde Seguir**      | LinkedIn; X @Magda_Chelly; responsible.cyber                                           |
| **Relevância Cloud SecOps** | Perspectiva de CISO prática sobre como cloud security é gerenciada no nível executivo. Seu framework de "responsible cyber" é relevante para mapeamento de risco em ambientes multi-cloud |

---

### 23. Lesley Carhart

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | ICS/OT security, incident response, digital forensics, comunicação técnica             |
| **Cargo/Afiliação**  | Principal Threat Analyst, Dragos Inc. (líder em OT/ICS security)                       |
| **Contribuições**    | Referência técnica em incident response para infraestrutura crítica (ICS/OT). Comunicação excepcional de conceitos complexos de segurança. Mentora ativa da comunidade infosec, especialmente para grupos sub-representados |
| **Obras Recomendadas** | Blog: tisiphone.net; Twitter threads técnicos sobre IR em ICS; DFIR webinars           |
| **Onde Seguir**      | Blog: tisiphone.net; X @hacks4pancakes; LinkedIn                                       |
| **Relevância Cloud SecOps** | Embora focada em OT/ICS, seus frameworks de IR são diretamente aplicáveis a cloud. Relevante especialmente para setores críticos (energia, utilities, manufatura) que conectam OT ao cloud |

---

### 24. Richard Stiennon

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | História e taxonomia de segurança, análise de mercado, strategic cybersecurity         |
| **Cargo/Afiliação**  | Chief Research Analyst, IT-Harvest; ex-Gartner VP                                      |
| **Contribuições**    | Criou o mapa de cibersegurança mais completo do setor (Security Yearbook — mais de 3.000 vendors catalogados). Analista independente que cobre o mercado de security com profundidade histórica |
| **Obras Recomendadas** | "Security Yearbook" (anual); "There Will Be Cyberwar" (2015); it-harvest.com           |
| **Onde Seguir**      | X @stiennon; LinkedIn; it-harvest.com; Security Yearbook (anual)                       |
| **Relevância Cloud SecOps** | Para entender o mercado de vendors de Cloud Security (CSPM, CWPP, CNAPP, CASB) nada melhor que o Security Yearbook. Essencial para quem precisa avaliar e selecionar ferramentas |

---

### 25. Joseph Steinberg

| Campo                | Detalhes                                                                               |
|:---------------------|:---------------------------------------------------------------------------------------|
| **Área de Atuação**  | Cybersecurity strategy, board advisory, consumer security, column writing              |
| **Cargo/Afiliação**  | CEO da SecureMySocial; Inc.com columnist; Forbes contributor                            |
| **Contribuições**    | Pontes entre cybersecurity técnica e audiências de negócios e consumidores. Author de livros educacionais. Expert witness em casos legais de cybersecurity |
| **Obras Recomendadas** | "Cybersecurity for Dummies" (2019 — 4th edition atualizada); columnismo no Inc.com; josephsteinberg.com |
| **Onde Seguir**      | X @JosephSteinberg; LinkedIn; josephsteinberg.com; Inc.com                             |
| **Relevância Cloud SecOps** | Excelente para criar material educativo para usuários não-técnicos e management. Seu livro "Cybersecurity for Dummies" é uma leitura útil para preparar apresentações executivas |

---

## Seção 2 — Relatórios de Referência Obrigatória

| Título | Organização | Frequência | Link | O Que Monitorar |
|:-------|:------------|:----------:|:-----|:----------------|
| **Microsoft Digital Defense Report (MDDR)** | Microsoft | Anual (outubro) | microsoft.com/security/business/mddr | Tendências de ataques no ecossistema Microsoft; dados de identidade comprometida; ransomware por setor |
| **CrowdStrike Global Threat Report** | CrowdStrike | Anual (fevereiro) | crowdstrike.com/global-threat-report | TTPs dos principais adversários (Fancy Bear, Lazarus, etc.); tempo médio de breach (breakout time) |
| **Unit 42 Cloud Threat Report** | Palo Alto Networks | Semestral | unit42.paloaltonetworks.com | Misconfigurações cloud mais exploradas; ataques a containers e Kubernetes; supply chain attacks |
| **Mandiant M-Trends Report** | Mandiant / Google | Anual (março) | mandiant.com/m-trends | Dwell time médio; setores mais atacados; técnicas APT predominantes no ano |
| **IBM X-Force Threat Intelligence Index** | IBM Security | Anual | ibm.com/security/threat-intelligence | Ranking de técnicas MITRE; ataques por indústria; vulnerabilidades mais exploradas |
| **AWS re:Inforce Security Talks** | Amazon | Anual (conferência) | re-inforce.awsevents.com | Novidades em GuardDuty, Security Hub, IAM; melhores práticas de clientes enterprise |
| **Google Cloud Threat Horizons Report** | Google Cloud | Semestral | cloud.google.com/blog/security | Ataques a Google Cloud; crypto mining incidents; credential theft patterns |
| **World Economic Forum Global Risks Report** | WEF | Anual (janeiro) | reports.weforum.org | Cyber como risco sistêmico global; percepção de risco por CxOs |
| **CERT.BR Relatório Anual** | CERT.BR / NIC.br | Anual | cert.br/stats | Incidentes de segurança no Brasil; phishing, scans, botnets; contexto local para analistas brasileiros |
| **Fortinet Global Threat Landscape Report** | Fortinet | Semestral | fortinet.com/threat-landscape-report | Exploits mais ativos; ransomware por região; botnet activity |
| **Verizon Data Breach Investigations Report (DBIR)** | Verizon | Anual (abril) | verizon.com/dbir | A referência estatística de breaches: por vetor, motivo, indústria, tamanho de empresa. Dados empíricos vs percepção |
| **ENISA Threat Landscape Report** | ENISA (EU) | Anual (outubro) | enisa.europa.eu | Perspectiva europeia de ameaças; análise de ataques a infraestrutura crítica |
| **MITRE ATT&CK Techniques Update** | MITRE | Semestral (v16, v17...) | attack.mitre.org | Novas técnicas e sub-técnicas adicionadas; mudanças em técnicas cloud |
| **Sophos State of Ransomware** | Sophos | Anual | sophos.com/state-of-ransomware | Dados de vitimização por ransomware; pagamento de resgate; recuperação; por setor e tamanho |

---

## Seção 3 — Frameworks e Normas Técnicas

### 3.1 Frameworks de Ameaças e Defesa

| Framework | Descrição | URL | Versão Atual | Uso no Curso |
|:----------|:----------|:----|:------------:|:-------------|
| **MITRE ATT&CK Enterprise** | Matriz de táticas, técnicas e procedimentos (TTPs) de adversários. Base universal para mapear detecções e hunting | attack.mitre.org | v16 (2026) | Todos os cursos — tagging de regras, hunting hipóteses |
| **MITRE ATT&CK Cloud (IaaS)** | Sub-conjunto do ATT&CK para AWS, Azure, GCP, Office 365 | attack.mitre.org/matrices/enterprise/cloud | v16 (2026) | C2, C3, C4 |
| **MITRE D3FEND** | Contrapartida defensiva do ATT&CK: mapeamento de técnicas de defesa para técnicas de ataque | d3fend.mitre.org | v1.0 | C1, C2, C3 — para selecionar controles |
| **MITRE Engage** | Framework de Active Defense e engajamento de adversários | engage.mitre.org | v1.0 | C1 Mod 04 (threat hunting), C3 Mod 05 |
| **Pyramid of Pain** | Modelo de David Bianco: hierarquia de IOCs por durabilidade. TI feeds no nível mais baixo; TTPs no mais alto | sans.org/tools/pyramid-of-pain | — | C1 Mod 01, C2 Mod 04 |
| **Diamond Model of Intrusion Analysis** | Modelo de correlação de incidentes (adversary, capability, infrastructure, victim) | activeresponse.org/diamond-model | — | C1 Mod 07, C3 Mod 05 |
| **Cyber Kill Chain** | Lockheed Martin: 7 fases de um ataque avançado (Reconnaissance → Actions on Objectives) | lockheedmartin.com/cyber | — | C1 Mod 01 (intro) |

### 3.2 Normas de Segurança da Informação

| Norma | Descrição | URL | Edição | Uso no Curso |
|:------|:----------|:----|:------:|:-------------|
| **NIST SP 800-53 Rev. 5** | Controles de segurança e privacidade para sistemas federais dos EUA. Base para frameworks corporativos e regulatórios | csrc.nist.gov/pubs/sp/800/53/r5 | Rev. 5 (2020) | C3 Mod 04 (Security Hub NIST standard), C4 Mod 01 |
| **NIST SP 800-61 Rev. 2** | Guia de resposta a incidentes de computadores. Define fases PICERL (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned) | csrc.nist.gov/pubs/sp/800/61/r2 | Rev. 2 (2012) | C1 Mod 07, C2 Mod 10, C3 Mod 05 |
| **NIST Cybersecurity Framework (CSF) 2.0** | Framework de gerenciamento de risco cibernético: Govern, Identify, Protect, Detect, Respond, Recover | nist.gov/cyberframework | v2.0 (2024) | C4 Mod 01 |
| **CIS Benchmarks** | Configurações de hardening recomendadas para AWS, Azure, GCP, Kubernetes, Docker, Windows, Linux | cisecurity.org/cis-benchmarks | Atualizados continuamente | C3 Mod 04 (CIS AWS standard no Security Hub) |
| **CIS Controls v8** | 18 controles prioritários de segurança com implementações por nível (IG1, IG2, IG3) | cisecurity.org/controls | v8 (2021) | Mapeamento em todos os cursos |
| **ISO/IEC 27001:2022** | Norma de Sistema de Gestão de Segurança da Informação (SGSI). Annex A com controles | iso.org/standard/82875.html | 2022 | C4 Mod 01 (CCSP preparo) |
| **ISO/IEC 27017:2015** | Controles de segurança para serviços de cloud (extensão do 27001 para cloud) | iso.org/standard/43757.html | 2015 | C4 Mod 01, 08 |
| **ISO/IEC 27018:2019** | Proteção de PII em cloud pública | iso.org/standard/76559.html | 2019 | C4 Mod 08 (CASB/DSPM) |
| **OWASP Top 10 (2021)** | 10 vulnerabilidades de aplicação web mais críticas | owasp.org/Top10 | 2021 | C4 Mod 03, 04 |
| **OWASP Cloud Top 10** | Riscos de segurança específicos de cloud (Accountability gap, Insecure Interfaces, etc.) | owasp.org/www-project-cloud-top-10 | 2023 | C4 Mod 01, 02 |
| **CSA Cloud Controls Matrix (CCM)** | Framework de controles específico para cloud do Cloud Security Alliance. Mapeado para ISO, NIST, PCI DSS | cloudsecurityalliance.org/artifacts/cloud-controls-matrix | v4.0 | C4 Mod 01, C3 Mod 04 |
| **MCRA — Microsoft Cybersecurity Reference Architectures** | Diagramas e frameworks de referência da Microsoft para Zero Trust, Sentinel, MCRA | aka.ms/mcra | Atualizado continuamente | C2 Mod 01 |
| **AWS Security Reference Architecture (SRA)** | Arquitetura de referência da AWS para contas e serviços de segurança | docs.aws.amazon.com/prescriptive-guidance | 2024 | C3 Mod 01, 09 |
| **AWS Well-Architected Framework — Security Pillar** | 7 áreas de design seguro para workloads AWS | docs.aws.amazon.com/wellarchitected | 2024 | C3 todos os módulos |

---

## Seção 4 — Contexto Regulatório Brasileiro

### 4.1 Resolução BACEN 4.893/2021 — Política de Segurança Cibernética para IFs

**Publicação:** Banco Central do Brasil, 26 de fevereiro de 2021
**Vigência:** 1º de março de 2021

| Artigo | Exigência Principal | Relevância Cloud |
|:------:|:--------------------|:----------------|
| Art. 3 | Política de Segurança Cibernética documentada, aprovada pela Diretoria | SOC precisa ser parte formal da política |
| Art. 7 | Gerenciamento de incidentes: plano documentado, testado e atualizado anualmente | Playbooks SOAR e runbooks de IR devem ser atualizados |
| Art. 9 | Gestão de vulnerabilidades: identificação, classificação, tratamento e monitoramento | CSPM (Prowler, Security Hub, Defender for Cloud) é resposta direta |
| Art. 10 | Controles de acesso: privilégio mínimo, segregação de funções, autenticação multifator | IAM least privilege, MFA, PIM, IAM Identity Center |
| Art. 11 | Criptografia: dados em repouso e em trânsito | KMS, TLS, at-rest encryption obrigatórios |
| Art. 12 | Monitoramento contínuo: logs de segurança, alertas, detecção de anomalias | SIEM (Sentinel, GuardDuty, Chronicle) é resposta direta |
| Art. 13 | Continuidade de negócios: redundância, backup, testes de continuidade | Multi-region, cross-account backup, DRPs |
| Art. 16 | Registro de ocorrências: incidentes relevantes devem ser registrados e reportados ao Banco Central | Incident tracking, relatórios de incidente |
| Art. 17 | Serviços críticos prestados por terceiros em nuvem: avaliação de conformidade dos provedores | AWS/Azure/GCP Shared Responsibility; questões regulatórias de resiliência |

**Exigências específicas para serviços em nuvem:**
A resolução 4.893 (substituída parcialmente pela CMN 4.658 para aspectos de cloud) exige que as IFs:
- Definam quais serviços críticos podem ser executados em nuvem pública
- Avaliem a conformidade regulatória do provedor cloud (data residency, auditabilidade)
- Garantam continuidade com SLAs contratuais
- Mantenham capacidade de auditoria independente dos serviços em nuvem

---

### 4.2 CMN 4.658/2018 — Contratação de Nuvem por Instituições Financeiras

**Publicação:** Conselho Monetário Nacional, 26 de abril de 2018

| Aspecto | Exigência | Solução Cloud |
|:--------|:----------|:--------------|
| **Jurisdição dos Dados** | Dados de clientes brasileiros devem estar sujeitos à lei brasileira, independente da localização física | AWS sa-east-1 (São Paulo), Azure Brazil South, Google Cloud São Paulo como primárias |
| **Auditabilidade** | IF deve ter direito de auditoria nos sistemas do provedor cloud | AWS Artifact (relatórios de conformidade), Azure Trust Center, Google Cloud Compliance |
| **Portabilidade** | Dados devem poder ser migrados para outro provedor sem dependência exclusiva | Arquiteturas multi-cloud evitam vendor lock-in; padrões abertos |
| **Segurança** | Controles de segurança equivalentes ao ambiente on-premises | Frameworks de segurança: AWS SRA, Azure SAS, Google Cloud Architecture Framework |
| **Notificação** | IF deve informar ao Banco Central sobre contratação de serviços relevantes em nuvem | Processo de notificação ao BACEN antes de migrar workloads críticos |
| **Plano de Saída** | Existência de plano documentado para migração ou descontinuação do serviço | Exit plans, backups cross-cloud, documentação de dependências |

---

### 4.3 LGPD — Lei Geral de Proteção de Dados (Lei 13.709/2018)

**Vigência:** Lei em vigor desde setembro de 2020; penalidades aplicáveis desde agosto de 2021
**Autoridade:** ANPD (Autoridade Nacional de Proteção de Dados)

| Artigo/Capítulo | Exigência | Relevância Cloud SecOps |
|:----------------|:----------|:------------------------|
| Art. 46 | Medidas técnicas e administrativas para proteger dados pessoais contra acessos não autorizados | CSPM, CWPP, CIEM, criptografia (KMS), controles de acesso (IAM, Entra ID) |
| Art. 46 §2 | Regulamentação pela ANPD de padrões técnicos mínimos | CIS Benchmarks, ISO 27001, BACEN 4.893 como referências aceitas |
| Art. 47 | Operadores de dados pessoais têm as mesmas obrigações dos controladores | Provedores cloud são operadores; contratos devem refletir isso |
| Art. 48 | Notificação de incidentes ao titular e à ANPD em prazo razoável | Incident response plans devem incluir notificação LGPD; playbooks de IR ativam esse fluxo |
| Art. 49 | Sistemas de processamento de dados devem ser desenvolvidos observando segurança by design | Shift-left security, IaC security (Curso 4), Secure SDLC |
| Art. 50 | Boas práticas e governança de dados pessoais (Privacy by Design) | DLP, CASB, DSPM são ferramentas que suportam art. 50 |

**Penalidades (LGPD, Art. 52):**
- Advertência com prazo para medidas corretivas
- Multa simples de até 2% do faturamento do grupo econômico no Brasil (máximo R$ 50 milhões por infração)
- Multa diária
- Publicização da infração (reputacional)
- Bloqueio ou eliminação dos dados pessoais
- Suspensão parcial do banco de dados (por até 6 meses)
- Suspensão total da atividade de tratamento

---

### 4.4 Marco Civil da Internet (Lei 12.965/2014)

Estabelece princípios, garantias, direitos e deveres para o uso da Internet no Brasil.

| Artigo | Relevância para Segurança |
|:------:|:--------------------------|
| Art. 13 | Obrigação de guarda de logs de conexão por 1 ano por provedores de conexão |
| Art. 15 | Obrigação de guarda de logs de aplicação por 6 meses por provedores de aplicação |
| Art. 23 | Requisitos para compartilhamento de dados com órgãos de segurança pública |

**Implicação para Cloud SecOps:** Os logs de CloudTrail, VPC Flow Logs, Sentinel, e Google SecOps devem ter políticas de retenção que atendam ao mínimo legal do Marco Civil (1 ano para conexão, 6 meses para aplicação) — frequentemente excedidos por razões operacionais e regulatórias do BACEN (2+ anos).

---

### 4.5 SUSEP — Circular 677/2022 — Setor de Seguros

Aplicável para seguradoras e resseguradoras reguladas pela SUSEP.

Exigências principais relevantes para Cloud SecOps:
- Política de segurança cibernética com escopo equivalente à BACEN 4.893
- Testes de penetração anuais em ambientes críticos
- Relatório anual de segurança cibernética à SUSEP
- Notificação de incidentes significativos

---

### 4.6 ANPD — Regulamentação de Segurança da Informação (2024)

A ANPD publicou em 2024 regulamentação sobre incidentes de segurança com dados pessoais, estabelecendo:

| Aspecto | Exigência |
|:--------|:----------|
| **Prazo de notificação** | Comunicação à ANPD em até 72 horas após ciência do incidente (aproximando-se do GDPR) |
| **Critério de relevância** | Incidente deve ser comunicado quando puder causar danos relevantes aos titulares |
| **Conteúdo da notificação** | Data/hora, natureza dos dados, número estimado de titulares, medidas tomadas, responsável técnico |
| **Comunicação aos titulares** | Titulares afetados devem ser comunicados em prazo razoável com linguagem clara |
| **Relatório completo** | Relatório detalhado à ANPD em até 30 dias com análise de causa raiz |

**Implicação para Cloud SecOps:** Playbooks de IR devem incluir um "LGPD track" paralelo que verifica se dados pessoais foram acessados e ativa o fluxo de notificação ANPD/titulares quando aplicável.

---

*Última atualização: 2026-04-24 · CECyber · Programa de Formação Security Operations em Nuvem*
