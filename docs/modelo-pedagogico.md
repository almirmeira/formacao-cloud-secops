# Modelo Pedagógico 40/40/20
## Programa de Formação Security Operations em Nuvem · CECyber

---

## Visão Geral

O programa adota um modelo pedagógico híbrido fundamentado em **três pilares complementares e
interdependentes**, projetado para maximizar a retenção de conhecimento e a transferência de
habilidades para o ambiente real de trabalho.

A distribuição **40/40/20** não é arbitrária — ela decorre de pesquisas pedagógicas sobre
aprendizagem de adultos (Adult Learning Theory de Malcolm Knowles) e da prática observada nos
melhores programas de formação técnica do mercado de segurança (SANS Institute, GIAC, EC-Council).

```
┌──────────────────────────────────────────────────────────────────────────┐
│  FUNDAMENTAÇÃO PEDAGÓGICA DO MODELO 40/40/20                              │
│                                                                            │
│  • Pirâmide de Aprendizagem (Edgar Dale): estudantes retêm               │
│    10% do que leem · 20% do que ouvem · 75% do que praticam              │
│    → Justifica a alta proporção de prática (53% do tempo total)           │
│                                                                            │
│  • Adult Learning (Knowles): adultos aprendem melhor quando:              │
│    - Veem relevância imediata para seu trabalho                           │
│    - Têm autonomia sobre o ritmo de aprendizagem                         │
│    - Aprendem resolvendo problemas reais                                  │
│    → Justifica labs hands-on e cenários situacionais                      │
│                                                                            │
│  • Spaced Repetition: revisão do conteúdo em intervalos crescentes        │
│    → Justifica a estrutura: vídeo → lab → live (ciclo de reforço)         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Pilar 1 — Videoaulas (40%)

### Características

As videoaulas são o **primeiro contato** do aluno com o conteúdo conceitual de cada módulo.
Funcionam como a "aula expositiva" do modelo tradicional, mas com vantagens do digital:
revisão ilimitada, pausa, velocidade variável e acesso assíncrono.

### Especificações Técnicas

| Parâmetro                | Especificação                                                      |
|:-------------------------|:-------------------------------------------------------------------|
| **Duração por pílula**   | 8 a 15 minutos (microlearning)                                     |
| **Formato de vídeo**     | MP4 / H.264 · Resolução mínima 1920×1080 (Full HD)                |
| **Qualidade de áudio**   | 44.1 kHz estéreo · sem eco nem ruído de fundo                      |
| **Produção**             | Talking head + screen share + animações + lower-thirds institucionais |
| **Legendas**             | Obrigatórias em português (para acessibilidade e revisão)          |
| **Transcrição**          | Disponibilizada em PDF para cada aula                              |
| **Revisão obrigatória**  | Semestral (dado o ritmo de evolução das plataformas cloud)         |
| **Armazenamento**        | LMS da CECyber + CDN com acesso global                            |

### Estrutura Padrão de Cada Pílula

```
[00:00–00:30] ABERTURA
  • Nome do instrutor e do módulo
  • Objetivo da aula (1 frase objetiva)
  • "Ao final desta aula você vai conseguir..."

[00:30–10:00] DESENVOLVIMENTO
  • Conteúdo conceitual dividido em blocos de 2–3 minutos
  • Intercalar: slides → demo em tela → animação → slides
  • Usar exemplos do contexto brasileiro (banco, varejo, governo)

[10:00–12:00] DEMONSTRAÇÃO PRÁTICA
  • Mostrar o conceito sendo aplicado na ferramenta real
  • Narrar cada ação: "Agora vou clicar em... note que..."

[12:00–13:30] RECAPITULAÇÃO
  • Resumir os 3 pontos principais da aula
  • Conectar com o conteúdo do próximo módulo

[13:30–15:00] CHAMADA PARA A PRÁTICA
  • "Agora é sua vez: no laboratório você vai..."
  • Indicar o número do lab correspondente
```

### Quizzes Integrados

- Inseridos após cada pílula (não bloqueiam o progresso)
- 3 a 5 questões por módulo
- Formato: múltipla escolha, verdadeiro/falso, correspondência
- Feedback imediato com justificativa da resposta correta
- Implementação: H5P (Moodle) ou questões nativas do LMS com xAPI

---

## Pilar 2 — Laboratórios Hands-On (40%)

Os laboratórios são o **coração pedagógico** do programa. É onde a aprendizagem real acontece
— transformando conceito em competência operacional.

### Tipologia dos Laboratórios

```
┌─────────────────────────────────────────────────────────────────────┐
│  TIPOLOGIA DE LABORATÓRIOS                                           │
│                                                                      │
│  1. LABORATÓRIO GUIADO (step-by-step)                                │
│     • Passo a passo detalhado com resultado esperado em cada etapa  │
│     • Objetivo: fixação e compreensão procedimental                 │
│     • Avaliação: checklist de completude                            │
│     • Proporção: ~60% dos labs do curso                             │
│                                                                      │
│  2. LABORATÓRIO DESAFIO (hands-on sem guia)                         │
│     • Problema situacional com critérios de aceitação               │
│     • Aluno decide a abordagem e os comandos                        │
│     • Avaliação: resultado final comparado ao gabarito             │
│     • Proporção: ~25% dos labs do curso                             │
│                                                                      │
│  3. CAPSTONE (projeto integrador)                                    │
│     • Cenário complexo multi-módulo sem guia                        │
│     • Produto: relatório de incidente + artefatos técnicos         │
│     • Avaliação: rubrica qualitativa por instrutor                  │
│     • Proporção: 1 por curso (~15% do tempo de lab)                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Estrutura Obrigatória de 8 Seções

Todo laboratório do programa segue rigorosamente esta estrutura:

| Seção | Conteúdo                                                           | Objetivo Pedagógico              |
|:-----:|:-------------------------------------------------------------------|:---------------------------------|
|   1   | **Contexto Situacional** — storytelling com cenário realista       | Criar engajamento e relevância   |
|   2   | **Situação Inicial** — estado do ambiente antes do incidente       | Estabelecer baseline             |
|   3   | **Problema Identificado** — alerta/detecção que desencadeou o lab  | Criar senso de urgência          |
|   4   | **Roteiro de Atividades** — lista numerada de etapas               | Dar orientação estruturada       |
|   5   | **Proposição Detalhada** — recursos, pré-condições, arquitetura    | Garantir pré-condições corretas  |
|   6   | **Script Passo a Passo** — comandos exatos, resultados esperados   | Garantir execução sem falhas     |
|   7   | **Objetivos por Etapa** — critério de aceitação de cada passo      | Validar aprendizagem incremental |
|   8   | **Gabarito Completo** — resposta detalhada com variações aceitas   | Resolver dúvidas pós-lab         |

### Ambientes de Execução

| Ambiente                  | Uso                                                               |
|:--------------------------|:------------------------------------------------------------------|
| **CECyber Play Labs**     | Plataforma proprietária para simulações operacionais complexas    |
| **Google SecOps Tenant**  | Tenant de demonstração pré-configurado (Curso 1)                  |
| **Azure M365 E5 Trial**   | Tenant trial gratuito (Curso 2)                                   |
| **AWS Sandbox**           | Conta sandbox CECyber com guardrails (Curso 3)                    |
| **Kubernetes Local (kind)** | Cluster local para labs de container security (Curso 4)         |

### Critérios de Qualidade dos Labs

- **Atomicidade:** cada passo é uma única ação com resultado verificável
- **Idempotência:** re-executar o passo produz o mesmo resultado
- **Observabilidade:** toda ação tem uma forma de confirmar que funcionou
- **Segurança:** labs em ambientes isolados; nunca usar dados reais de clientes
- **Cleanup:** todo lab tem instruções de limpeza do ambiente

---

## Pilar 3 — Live Online (20%)

As sessões ao vivo são o elemento de **maior densidade pedagógica** do programa. Não são aulas
tradicionais — são sessões de execução guiada de laboratórios complexos, mentorias e debate
de casos reais.

### Composição do Tempo Live

```
DISTRIBUIÇÃO TÍPICA DE UMA SESSÃO LIVE DE 2h (base: curso 40h)
────────────────────────────────────────────────────────────────
65–70% (1h18–1h24): Laboratório ao vivo com o instrutor
  • Instrutor executa o lab em conjunto com a turma
  • Passo a passo, pausas para perguntas, variações
  • Foco nos labs mais complexos (capstone, multi-estágio)

15–20% (18–24 min): Mentoria e checkpoint
  • Revisão de entregáveis pendentes
  • Dúvidas técnicas individuais
  • Orientação sobre o capstone

10% (~12 min): Discussão de caso real
  • Incidente real do mercado (anonimizado)
  • Debate sobre decisões técnicas e regulatórias
  • Conexão com contexto BACEN/LGPD brasileiro

~5% (6 min): Abertura ou encerramento
  • Alinhamento de expectativas
  • Preview do próximo módulo
  • Defesa do capstone (sessão final)
────────────────────────────────────────────────────────────────
```

### Operação das Sessões

| Parâmetro                    | Especificação                                          |
|:-----------------------------|:-------------------------------------------------------|
| **Cadência**                 | 1–2 sessões por semana                                 |
| **Horário**                  | 19h–21h (dias úteis) ou sábados 09h–11h                |
| **Plataforma**               | Zoom ou Microsoft Teams (videoconferência interativa)  |
| **Câmera**                   | Obrigatória para o instrutor; fortemente recomendada para alunos |
| **Gravação**                 | Automática · disponível no LMS em até 24h              |
| **Tamanho de turma (live)**  | Máximo 15–20 alunos para garantir interação individual |
| **Suporte**                  | Instrutor monitor via chat/breakout rooms durante os labs |
| **Faltas**                   | Compensáveis pela gravação + entrega do lab correspondente |
| **Instrutor**                | Mesmo profissional em todas as sessões (vínculo pedagógico) |

---

## Tempo Total de Prática Efetiva

```
DISTRIBUIÇÃO DE TEMPO — CURSOS DE 40H (EXEMPLO: SENTINEL & DEFENDER)
─────────────────────────────────────────────────────────────────────
16h  →  Videoaulas (40%)          — Teoria + demos guiadas
16h  →  Labs autoguiados (40%)    — Prática independente
 8h  →  Live online (20%)         — Sendo composta por:
   5.2h  →  Labs ao vivo (65%)    — Prática guiada ao vivo
   1.2h  →  Mentoria (15%)        — Revisão técnica
   0.8h  →  Casos reais (10%)     — Discussão situacional
   0.8h  →  Abertura/capstone     — Orientação e avaliação

TOTAL DE PRÁTICA EFETIVA:
  Labs autoguiados: 16h
+ Labs ao vivo:      5.2h
                    ─────
TOTAL PRÁTICO:      21.2h = 53% do tempo total do curso
─────────────────────────────────────────────────────────────────────
```

---

## Avaliação e Aprovação

### Critérios por Curso

| Componente                              | Cursos 30h | Cursos 40h |
|:----------------------------------------|:----------:|:----------:|
| Quizzes integrados às videoaulas        |    20%     |    15%     |
| Laboratórios guiados e desafios         |    40%     |    35%     |
| Participação em lives e mentorias       |    10%     |    —       |
| Projeto individual / simulado           |    —       |    35%     |
| Capstone no CECyber Play Labs           |    30%     |    15%     |

### Avaliação Final de Curso

Após o Capstone, cada curso inclui uma **Avaliação Final** mais abrangente:
- **80%** — Questões de múltipla escolha (mínimo 40 questões, cobrindo todos os módulos)
  - Nível básico (30%): recordação e compreensão
  - Nível intermediário (50%): aplicação e análise
  - Nível avançado (20%): avaliação e criação
- **20%** — Estudo de caso prático ou laboratório inédito
  - Cenário não coberto nos módulos
  - Rubrica detalhada com critérios por entregável
  - Gabarito completo fornecido após a entrega

### Critério de Aprovação

**70% de aproveitamento global** em cada componente avaliativo.

### Certificação

O **certificado digital** CECyber inclui:
- Nome completo do participante
- Nome do curso e carga horária discriminada por modalidade
- Competências técnicas declaradas (lista de skills cobertas)
- Indicação de preparação para a certificação internacional alinhada
- QR Code de validação autêntica (base de dados CECyber)

---

## Atualização e Manutenção do Conteúdo

Dado o ritmo acelerado de evolução das plataformas de nuvem e ferramentas de segurança,
o programa segue uma política de **revisão semestral obrigatória**:

| Frequência              | Tipo de Revisão                                                          |
|:------------------------|:-------------------------------------------------------------------------|
| **Mensal**              | Verificação de links, versões de ferramentas e mudanças de interface     |
| **Semestral**           | Revisão completa de conteúdo, atualização de labs, novos casos reais     |
| **Anual**               | Revisão estrutural: novos módulos, substituição de tecnologias obsoletas  |
| **Ad hoc**              | Atualizações urgentes (novo exame, nova regulamentação, incidente relevante) |

---

*Modelo Pedagógico 40/40/20 · Programa de Formação Security Operations em Nuvem · CECyber · v2.0 · 2026*
