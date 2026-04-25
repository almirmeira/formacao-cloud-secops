# CLAUDE.md — Memória do Projeto
## Programa de Formação: Security Operations em Nuvem (CECyber)

> Este arquivo é a **memória viva** do projeto. Deve ser consultado e atualizado a cada sessão
> de trabalho, registrando decisões, progresso, padrões e contexto relevante.

---

## 1. Identidade do Projeto

| Campo                    | Valor                                                              |
|:-------------------------|:-------------------------------------------------------------------|
| **Nome do Programa**     | Formação Security Operations em Nuvem                             |
| **Organização**          | CECyber — Educação Corporativa em Cibersegurança                  |
| **Versão do Documento**  | 2.0 (2026)                                                        |
| **Repositório GitHub**   | github.com/almirmeira/formacao-cloud-secops                       |
| **Repositório Referência**| github.com/almirmeira/pos-cloud-security                         |
| **Documento Base**       | CECyber_Programa_SecOps_40-40-20.pdf (versão 2.0)                |
| **Idioma**               | Português do Brasil (pt-BR) — com acentuação e caracteres especiais |

---

## 2. Visão Geral do Programa

O programa reúne **4 cursos livres corporativos** voltados a profissionais de TI, Cloud Computing
e Segurança Cibernética que atuam ou buscam atuar em operações de segurança em ambientes de nuvem.

### Panorama dos Cursos

| Nº  | Nome do Curso                                   | CH   | Vídeo | Lab  | Live | Certificação Alvo                        |
|:---:|:------------------------------------------------|:----:|:-----:|:----:|:----:|:-----------------------------------------|
|  1  | Google SecOps Essentials                        | 30h  | 12h   | 12h  | 6h   | Google Cloud Professional Security Eng.  |
|  2  | Microsoft Sentinel & Defender: SecOps no Azure  | 40h  | 16h   | 16h  | 8h   | Microsoft SC-200                          |
|  3  | AWS Cloud Security Operations                   | 40h  | 16h   | 16h  | 8h   | AWS Certified Security – Specialty        |
|  4  | Ferramentas de Cloud Security: CNAPP, IaC e DevSecOps | 30h | 12h | 12h | 6h | CCSP (ISC²) / CCSK (CSA)               |

**Carga horária total:** 140 horas  
**Modelo pedagógico:** 40% Videoaulas · 40% Laboratórios · 20% Live Online

---

## 3. Modelo Pedagógico 40/40/20

### 40% — Videoaulas (Assíncrono)
- Pílulas de 8 a 15 minutos (microlearning)
- Produção em estúdio: talking head + screen share + animações
- Quizzes integrados (H5P ou LMS nativo): 3–5 questões por módulo
- Legendas e transcrição obrigatórias (acessibilidade)
- Revisão semestral obrigatória

### 40% — Laboratórios (Prática)
- Laboratórios guiados (step-by-step) e laboratórios desafio (sem guia)
- Ambientes: tenants reais (Azure, AWS, GCP sandbox, K8s) + CECyber Play Labs
- Avaliação automatizada onde possível (scripts de validação)
- Sandbox isolado com guardrails, budgets e cleanup automático

### 20% — Live Online (Síncrono)
- 60–70% do tempo live: execução guiada de laboratórios com o instrutor
- Mentorias de checkpoint (~15–20%)
- Discussão de casos reais do mercado brasileiro (~10%)
- Abertura e defesa do capstone (~10%)
- Turmas reduzidas: 15–20 alunos por sessão ao vivo
- Cadência: 1–2 sessões por semana (19h–21h ou sábados pela manhã)

---

## 4. Público-Alvo

- **Profissionais de TI:** admins, engenheiros de infra, suporte N2/N3, service desk, transição para Cloud Security
- **Profissionais de Cloud:** cloud engineers, arquitetos, DevOps, SRE, Platform Engineers
- **Profissionais de Segurança Cibernética:** analistas de SOC (L1, L2, L3), threat hunters, incident responders, analistas de vuln, GRC
- **Líderes técnicos:** coordenadores, tech leads, arquitetos, gestores

### Pré-requisitos Gerais
- Formação técnica em TI, Cloud ou Segurança (CompTIA Security+, Network+, Cloud+ ou equivalente)
- Experiência prática com ao menos um provedor de nuvem OU certificações foundational (AWS CCP, AZ-900, Google Cloud Digital Leader)
- Familiaridade com logs, redes TCP/IP e linha de comando (bash/PowerShell)
- Noções de MITRE ATT&CK (apresentadas nos módulos introdutórios quando necessário)

---

## 5. Estrutura do Repositório

```
formacao-cloud-secops/
├── CLAUDE.md                          # Este arquivo — memória do projeto
├── README.md                          # Landing page principal
├── assets/
│   ├── diagramas/                     # SVGs de arquitetura, topologia, fluxos
│   ├── infograficos/                  # Infográficos e visualizações
│   └── imagens/                       # Imagens auxiliares
├── docs/
│   ├── modelo-pedagogico.md           # Detalhamento do modelo 40/40/20
│   ├── trilhas-formacao.md            # Trilhas Single-Cloud, Multi-Cloud, Architect
│   ├── mapa-certificacoes.md          # Mapeamento módulo × capítulo de certificações
│   ├── referencias-especialistas.md   # Especialistas e referências bibliográficas
│   └── contexto-regulatorio-brasil.md # BACEN, LGPD, Marco Civil, SUSEP, ANPD
├── curso-01-google-secops/
│   ├── README.md                      # Ementa e informações gerais
│   ├── modulos/                       # Conteúdo de cada módulo
│   └── laboratorios/                  # Labs com storytelling e gabaritos
├── curso-02-azure-secops/
│   ├── README.md
│   ├── modulos/
│   └── laboratorios/
├── curso-03-aws-secops/
│   ├── README.md
│   ├── modulos/
│   └── laboratorios/
└── curso-04-cloud-security-tools/
    ├── README.md
    ├── modulos/
    └── laboratorios/
```

---

## 6. Estrutura Obrigatória de Cada Módulo

Cada módulo dos 4 cursos deve conter os seguintes elementos:

### 6.1 Aulas (Videoaulas e Live)
Cada aula deve ter:
- **Conteúdo conceitual** completo (teoria, exemplos, diagramas)
- **Roteiro de gravação em primeira pessoa** — texto narrativo que o instrutor lê/segue durante a gravação ou live online, com:
  - Abertura (apresentação do tema, objetivos da aula)
  - Desenvolvimento (conteúdo em blocos sequenciais)
  - Demonstrações práticas (passo a passo narrado)
  - Recapitulação e chamada para o laboratório
  - Dicas de edição de vídeo (cortes, transições, tela cheia)
  - Indicação de tempo estimado por bloco

### 6.2 Atividades de Fixação
- Quizzes com 3–5 questões por módulo
- Exercícios de revisão conceitual
- Desafios rápidos (5–10 min) de reconhecimento de cenário

### 6.3 Laboratórios (estrutura obrigatória de 8 seções)
1. **Contexto Situacional** — storytelling com cenário realista
2. **Situação Inicial** — estado do ambiente antes do incidente
3. **Problema Identificado** — alerta/detecção que desencadeou o laboratório
4. **Roteiro de Atividades** — lista numerada de etapas
5. **Proposição Detalhada** — recursos necessários, pré-condições, arquitetura
6. **Script Passo a Passo** — comandos, configs, capturas esperadas por etapa
7. **Objetivos por Etapa** — critério de aceitação de cada passo
8. **Gabarito Completo** — resposta detalhada com resultados esperados em cada etapa

**Nível de detalhe obrigatório nos laboratórios:**
- Cada passo deve ser **numerado e atômico** (uma ação por passo)
- Incluir o **comando exato** a ser executado (com variáveis nomeadas)
- Mostrar o **resultado esperado** após cada passo (saída do terminal, screenshot, estado do portal)
- Indicar **o que verificar** para confirmar que o passo foi bem-sucedido
- Incluir **seção "Se der errado"** com os erros mais comuns e como resolvê-los
- Usar blocos de código com syntax highlighting para todos os comandos
- Para ações em portal/console web: descrever o caminho de navegação exato (menu > submenu > botão)

### 6.4 Avaliação Final do Módulo
- Questões de múltipla escolha (mínimo 5)
- Questão dissertativa ou cenário de análise
- Rubrica de avaliação com pontuação por critério

### 6.5 Avaliação Final do Curso
Ao final de cada curso (após o Capstone), deve haver uma **Avaliação Final de Curso** mais ampla e abrangente:
- **80% Múltipla Escolha** — mínimo de 40 questões cobrindo todos os módulos do curso
  - Questões de nível básico (recordação/compreensão): 30%
  - Questões de nível intermediário (aplicação/análise): 50%
  - Questões de nível avançado (avaliação/criação): 20%
  - Todas as questões com justificativa da resposta correta no gabarito
- **20% Estudo de Caso ou Laboratório Prático**
  - Cenário inédito (não coberto nos módulos)
  - Problema situacional com contexto realista do mercado brasileiro
  - Rubrica detalhada com critérios de pontuação por entregável
  - Gabarito completo com resposta esperada e variações aceitas
- **Critério de aprovação:** 70% de aproveitamento global
- Arquivo: `avaliacao-final/README.md` dentro de cada pasta de curso

### 6.5 Módulo 00 — Preparação do Ambiente de Laboratório
**Cada curso deve ter um Módulo 00** dedicado exclusivamente à criação e configuração do ambiente
que será utilizado em todos os laboratórios do curso. Este módulo inclui:
- Diagrama da topologia completa do ambiente de laboratório
- Provisionamento de contas/tenants (Azure Free Trial, AWS Sandbox, GCP Free Tier)
- Instalação de ferramentas e CLIs necessárias
- Configuração de permissões e roles mínimas necessárias
- Scripts de setup automatizado (bash/PowerShell/Terraform)
- Verificação de saúde do ambiente (health check script)
- Guia de troubleshooting dos problemas mais comuns no setup
- Cleanup guide (como destruir/resetar o ambiente)

---

## 7. Padrões de Qualidade do Repositório

### Idioma e Ortografia
- **Todo o conteúdo em português do Brasil** (pt-BR)
- Acentuação completa: á, é, í, ó, ú, â, ê, ô, ã, õ, ç, ü
- Nunca usar anglicismos quando existir equivalente consagrado em pt-BR

### Tabelas Markdown
- Sempre usar delimitadores completos de linha e coluna, incluindo borda direita
- Usar `:---:` (centralizado), `:---` (alinhado à esquerda) ou `---:` (alinhado à direita) conforme contexto
- Exemplo de formato correto:
  ```
  | Coluna A   | Coluna B   | Coluna C   |
  |:-----------|:----------:|-----------:|
  | Dado 1     | Dado 2     | Dado 3     |
  ```

### Elementos Visuais
- Diagramas SVG posicionados ao longo de todo o repositório
- Topologias físicas e lógicas obrigatórias nos módulos de infraestrutura
- Infográficos de processo para cada laboratório

### Laboratórios
Estrutura obrigatória para cada laboratório:
1. **Contexto Situacional** (storytelling)
2. **Situação Inicial** — estado do ambiente antes do incidente
3. **Problema Identificado** — o que foi detectado/alertado
4. **Roteiro de Atividades** — lista de etapas a cumprir
5. **Proposição Detalhada do Laboratório** — recursos necessários, pré-condições
6. **Script Passo a Passo** — comandos, configs, capturas de tela esperadas
7. **Objetivos por Etapa** — critério de aceitação de cada passo
8. **Gabarito Completo** — resposta detalhada com resultados esperados

---

## 7. Trilhas de Formação

| Trilha                          | Composição                                  | CH Total  | Perfil                              |
|:--------------------------------|:--------------------------------------------|:---------:|:------------------------------------|
| **SecOps Single-Cloud**         | 1 curso (Google, Azure ou AWS)              | 30–40h    | Empresas com único provedor de nuvem |
| **SecOps Multi-Cloud**          | Azure + AWS (+ opcional Google)             | 80–110h   | Bancos e seguradoras multi-cloud     |
| **Cloud Security Architect**    | Ferramentas + 1 curso SecOps                | 60–70h    | Arquitetos e líderes técnicos        |
| **Formação Completa**           | 4 cursos                                    | 140h      | Head of Cloud Security / pipeline CISO |

---

## 8. Mapa de Certificações Alvo

| Certificação                                 | Emissor    | Curso(s) Preparatório(s) |
|:---------------------------------------------|:----------:|:-------------------------|
| Google Cloud Professional Cloud Security Eng.| Google     | Curso 1                  |
| Microsoft SC-200                             | Microsoft  | Curso 2                  |
| AWS Certified Security – Specialty (SCS-C02) | AWS        | Curso 3                  |
| CCSP                                         | ISC²       | Curso 4 + Curso 2/3      |
| CCSK                                         | CSA        | Curso 4                  |
| CISSP (domínio Cloud Security)               | ISC²       | Curso 4                  |
| CompTIA CySA+                                | CompTIA    | Cursos 1, 2 e 3          |
| CompTIA CASP+                                | CompTIA    | Curso 4                  |

---

## 9. Referências de Classe Mundial Utilizadas

### Organizações e Fabricantes
Gartner, Unit 42 (Palo Alto Networks), Fortinet, Cisco, WEF (World Economic Forum),
IBM Security, CERT.BR, Trellix, Linux Foundation, Microsoft, Amazon AWS, Google GCP,
CrowdStrike, Anthropic, OpenAI, Juniper, Zscaler, Check Point, Cloudflare, SentinelOne,
Okta, Mandiant (Google Cloud), Splunk (Cisco), Trend Micro, Kaspersky, Sophos, Proofpoint,
CyberArk, Tenable, Rapid7, Qualys, Darktrace, Akamai, Broadcom (Symantec).

### Especialistas de Referência
Bruce Schneier, Brian Krebs, Mikko Hyppönen, Troy Hunt, Eugene Kaspersky,
Dmitri Alperovitch, Kevin Beaumont, Jen Easterly, Katie Moussouris, Nicole Perlroth,
Andy Greenberg, Graham Cluley, Daniel Miessler, Anton Chuvakin, Theresa Payton,
Chuck Brooks, Keren Elezari, Jake Williams, David Kennedy, Eric Cole,
Shira Rubinoff, Magda Chelly, Lesley Carhart, Richard Stiennon, Joseph Steinberg.

### Frameworks e Normas
- MITRE ATT&CK (mapeamento obrigatório em todas as detecções)
- NIST SP 800-53, NIST SP 800-61, NIST CSF
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes)
- ISO/IEC 27001:2022
- AWS Well-Architected Framework (Security Pillar)
- Microsoft MCRA (Cybersecurity Reference Architecture)
- OWASP Top 10

### Regulatório Brasileiro
- Resolução BACEN 4.893
- CMN 4.658
- LGPD (Lei Geral de Proteção de Dados)
- Marco Civil da Internet
- SUSEP e ANPD

---

## 10. Decisões de Design e Histórico

| Data       | Decisão                                                                     | Justificativa                                           |
|:----------:|:----------------------------------------------------------------------------|:--------------------------------------------------------|
| 2026-04-24 | Repositório criado: `almirmeira/formacao-cloud-secops`                      | Projeto novo para grande cliente, baseado no PDF v2.0   |
| 2026-04-24 | Idioma: português do Brasil (pt-BR) integral                                | Requisito explícito do cliente                          |
| 2026-04-24 | Elementos visuais SVG em todos os cursos                                    | Melhor rendeirização em GitHub e ferramentas Markdown   |
| 2026-04-24 | Labs com storytelling situacional obrigatório                               | Abordagem pedagógica definida no escopo do cliente      |
| 2026-04-24 | Gabaritos completos incluídos em todos os laboratórios                      | Requisito explícito do cliente                          |
| 2026-04-24 | Tabelas com delimitadores completos (incluindo borda direita)                | Melhor formatação visual no GitHub                      |

---

## 11. Progresso do Desenvolvimento

### Fase 1 — Estrutura Base (em andamento)
- [x] Repositório local inicializado
- [x] Estrutura de diretórios criada
- [x] CLAUDE.md criado
- [ ] README.md principal
- [ ] SVGs de arquitetura
- [ ] Docs gerais (modelo pedagógico, trilhas, certificações)

### Fase 2 — Conteúdo dos Cursos
- [ ] Curso 1: Google SecOps Essentials (README + 7 módulos + 5 labs)
- [ ] Curso 2: Azure SecOps (README + 10 módulos + 7 labs)
- [ ] Curso 3: AWS SecOps (README + 10 módulos + 8 labs)
- [ ] Curso 4: Cloud Security Tools (README + 9 módulos + 7 labs)

### Fase 3 — Material de Suporte
- [ ] Mapa de certificações detalhado
- [ ] Referências e especialistas
- [ ] Contexto regulatório brasileiro
- [ ] Gabaritos completos de todos os laboratórios

---

## 12. Como Contribuir (Instruções para Sessões Futuras)

1. Sempre consultar este CLAUDE.md antes de iniciar o trabalho
2. Manter o idioma pt-BR rigoroso em todo o conteúdo
3. Seguir o padrão de laboratório (8 seções obrigatórias)
4. Criar SVGs para cada nova topologia ou processo
5. Mapear todo conteúdo técnico ao MITRE ATT&CK quando aplicável
6. Atualizar a seção "Progresso do Desenvolvimento" ao concluir cada entregável
7. Registrar novas decisões de design na seção 10

---

*Última atualização: 2026-04-24*
