# 🛡️ Zimbra Threat Hunt

> Triagem forense **read-only** para servidores Zimbra Collaboration, focada na
> detecção de IOCs de malwares conhecidos: mineradores (XMRig, Minerd),
> webshells JSP, persistência via cron/systemd, túneis reversos e
> indicadores de comprometimento correlacionados.

[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![Zimbra](https://img.shields.io/badge/Zimbra-8.x-orange.svg)](https://www.zimbra.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-RHEL%207%20%7C%208%20%7C%209-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-est%C3%A1vel-brightgreen.svg)]()

**Stack:** Python 3.6+ · Bash 4 · HTML/CSS/JS · JSON

---

## 📖 Sumário

- [Sobre](#-sobre)
- [Princípios](#-princípios)
- [Principais recursos](#-principais-recursos)
- [Pipeline](#-pipeline)
- [Estrutura de saída](#-estrutura-de-saída)
- [Instalação](#-instalação)
- [IOCs configuráveis](#-iocs-configuráveis)
- [Dashboard HTML](#-dashboard-html)
- [Limitações](#-limitações)
- [Estrutura do repositório](#-estrutura-do-repositório)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)
- [Autor](#-autor)

---

## 🎯 Sobre

O **Zimbra Threat Hunt** é uma ferramenta de triagem forense **passiva e
read-only** para servidores Zimbra Collaboration que precisam avaliar se
*"este servidor está comprometido"* sem derrubar serviços, sem alterar arquivos.

Foi desenhado para o cenário real de ataques a servidores Zimbra observados
nos últimos meses:

- **Mineração de criptomoedas** em `/tmp`, `/dev/shm`, `/var/tmp`
- **Webshells JSP/JSPX** plantadas em `jetty/webapps/zimbra/public/`
- **Persistência via cron** (`/etc/cron.d/`, crontab de usuário)
- **Chamadas a C2** a partir de IPs já mapeados
- **Coleta de evidências correlacionadas** sem custo de interpretação manual

O output é um **relatório forense com score, classificação, achados
priorizados, correlações e manifesto de integridade** — pronto para ser
anexado a um ticket de incidente.

---

## 🔒 Princípios

A ferramenta segue **cinco regras invioláveis**:

1. **Não mata processos** — só lê `/proc`
2. **Não apaga, não edita, não altera permissões** de nada existente
3. **Não executa amostras** encontradas no disco
4. **Não abre conexões externas** para C2, não baixa payload
5. **Não acessa conteúdo de e-mails, senhas ou chaves privadas**

A quarentena (opcional) apenas **copia** arquivos suspeitos para um diretório
protegido, com hash SHA-256 e manifesto — nunca move nem apaga o original.

---

## ✨ Principais recursos

### Coleta

- **Identificação** de versão do Zimbra, sistema operacional, interfaces
- **Processos**: varredura de `/proc`, whitelist de kernel threads e processos
  legítimos do Zimbra, detecção de executáveis em tmp, deletados mas em execução,
  mismatch entre `comm` e `exe`
- **Rede**: conexões `established`, matching contra IPs/portas de IOC
- **Arquivos temporários**: varredura com `find -mtime`, whitelist de subdiretórios
  internos do Zimbra (`cstrm`, `convertd`, `zmstat`, `nginx`, `.swatchdog_script.*`,
  `jffi*.tmp`), detecção por nome, hash, magic bytes e shebang
- **Persistência**: cron de sistema, cron de usuário, systemd units, `rc.local`,
  com whitelist explícita do Zimbra (`/opt/zimbra/libexec/*`) e deduplicação
- **SSH**: `authorized_keys` de root, `zimbra` e usuários de `/home`, com
  fingerprint SHA-256
- **Webshell**: JSP/JSPX recentes em `jetty/webapps`, com detecção de
  `Runtime.exec`, `ProcessBuilder`, `defineClass`, `Class.forName` e IOC textual
- **Logs**: `/var/log/secure`, `/var/log/cron`, `/var/log/maillog`,
  `/opt/zimbra/log/*.log`, com filtros específicos para não gerar falso positivo
  do `sudo` legítimo do Zimbra e do cron interno
- **Pacotes**: inventário RPM/DPKG

### Dashboard

- **Relatório TXT** com resumo executivo, achados, correlações e limitações
- **Dashboard HTML** dark theme, autocontido (sem dependência externa):
  - Cards de severidade (CRITICO/ALTO/MEDIO/BAIXO/INFO)
  - Correlação visual de incidentes
  - Seções colapsáveis (`<details>`) para achados e IOCs
  - Botões "Expandir tudo / Recolher tudo"
- **`resumo.json`** estruturado para automação
- **`manifesto_evidencias.txt`** com hash SHA-256 de cada arquivo gerado

### Correlação e priorização

- Agrupamento automático por **PID, path normalizado e IOC** → "incidentes"
- Score de risco **0-100** com pesos por severidade e diversidade de tipos
- Classificação final: `Comprometimento confirmado`, `Fortes indícios`,
  `Suspeita`, `Inconclusiva`, `Nenhum indício`

---

## 🔄 Pipeline
flowchart TD
    A["scripts/zimbra_hunt.sh<br/>Wrapper interativo<br/><br/>• Menu: Quick / Full / Módulo específico<br/>• Configuração: output, --days, --timeout, --no-quarantine<br/>• Executa o motor Python"] 

    B["scripts/zimbra_forensics.py<br/>Motor de análise forense"]

    A --> B

    subgraph MODULES["Módulos de análise"]
        direction TB
        M1["identify"] --> M2["processes"] --> M3["network"]
        M4["tmpfiles"] --> M5["persistence"] --> M6["ssh"]
        M7["webshell"] --> M8["logs"] --> M9["packages"]
    end

    B --> MODULES

    MODULES --> C["Correlacionar evidências<br/>correlate()"]
    C --> D["Calcular score de risco<br/>calculate_score()"]
    D --> E["Gerar relatórios<br/>report()"]

    E --> F["Saída: evidence_YYYYMMDD_HHMMSS/"]

    subgraph OUTPUT["Evidências e artefatos gerados"]
        direction TB
        O1["00_resumo/<br/>resumo.json"]
        O2["01_identificacao/<br/>sistema.txt + zimbra.txt"]
        O3["02_processos/<br/>processos.json + suspeitos.json"]
        O4["03_rede/<br/>conexoes.json"]
        O5["04_arquivos_tmp/<br/>suspeitos.json"]
        O6["05_persistencia/<br/>cron.json + systemd.json + ssh_*.json"]
        O7["06_webshell/<br/>suspeitos.json"]
        O8["08_logs/<br/>resumo.json"]
        O9["09_quarentena/<br/>Arquivos isolados, quando aplicável"]
        O10["10_analise/<br/>pacotes.txt"]
        O11["relatorio_forense.html<br/>Dashboard com tema escuro"]
        O12["relatorio_forense.txt<br/>Relatório para tickets"]
        O13["manifesto_evidencias.txt<br/>Hashes SHA-256 das evidências"]
    end

    F --> OUTPUT

    classDef wrapper fill:#1e3a5f,stroke:#60a5fa,color:#ffffff
    classDef engine fill:#312e81,stroke:#a78bfa,color:#ffffff
    classDef module fill:#164e63,stroke:#22d3ee,color:#ffffff
    classDef analysis fill:#713f12,stroke:#fbbf24,color:#ffffff
    classDef output fill:#14532d,stroke:#4ade80,color:#ffffff

    class A wrapper
    class B engine
    class M1,M2,M3,M4,M5,M6,M7,M8,M9 module
    class C,D,E analysis
    class F,O1,O2,O3,O4,O5,O6,O7,O8,O9,O10,O11,O12,O13 output
 
---

📂 Estrutura dos resultados

Cada execução gera um diretório evidence_YYYYMMDD_HHMMSS/, contendo as evidências coletadas, os resultados das análises e os relatórios forenses.

evidence_20261012_103332/
├── 00_resumo/
│ └── resumo.json # score, classificação, métricas
├── 01_identificacao/
│ ├── sistema.txt
│ └── zimbra.txt
├── 02_processos/
│ ├── processos.json # todos os processos enriquecidos
│ └── suspeitos.json # apenas os que bateram IOC/padrão
├── 03_rede/
│ ├── ss_established.txt
│ └── conexoes.json
├── 04_arquivos_tmp/
│ └── suspeitos.json
├── 05_persistencia/
│ ├── cron.json
│ ├── systemd.json
│ └── ssh_authorized_keys.json
├── 06_webshell/
│ └── suspeitos.json
├── 08_logs/
│ ├── journald.txt
│ └── resumo.json
├── 09_quarentena/ # cópias read-only de arquivos suspeitos
├── 10_analise/
│ └── pacotes.txt
├── relatorio_forense.html # dashboard HTML (dark theme)
├── relatorio_forense.txt # relatório em texto
└── manifesto_evidencias.txt # inventário com SHA-256

---

## 🚀 Instalação e uso

Todos os requisitos, passo a passo de instalação, flags de linha de comando,
exemplos de execução, automação via cron e troubleshooting estão em:

📄 **[docs/IMPLANTACAO.md](docs/IMPLANTACAO.md)**

---

🎯 IOCs configuráveis
Toda a inteligência de detecção vem de scripts/iocs.json.
Estrutura esperada:

Chave	Descrição
ips	Lista de IPs de C2 / pool de mineração
domains	Domínios de C2 / pool
ports	Portas suspeitas (ex.: 3333, 4444, 14444)
paths	Caminhos de arquivo conhecidos como IOC
file_names	Nomes de arquivo (case-insensitive)
process_patterns	Regex para linha de comando de processo
log_patterns	Regex aplicadas em linhas de log
sha256	Hashes SHA-256 de amostras conhecidas
ssh_indicators	Comentários e fingerprints de chaves SSH
Manutenção: adicione novos IOCs ao arquivo sem alterar o código. A
validação de regex roda no carregamento — padrões inválidos são reportados
em LIMITAÇÕES do relatório.

Manutenção: adicione novos IOCs ao arquivo sem alterar o código. A
validação de regex roda no carregamento — padrões inválidos são reportados
em LIMITAÇÕES do relatório.

📊 Dashboard HTML
O relatório HTML é autocontido — não requer internet, não carrega fontes
externas, funciona offline. Recursos:

Tema dark baseado em GitHub Dark

Cards de severidade com contagem por nível

Achados colapsáveis: CRITICO expandido, demais recolhidos

Seção de IOCs com <details> por categoria (IPs, domínios, caminhos…)

Correlação visual de incidentes multi-evidência

Botões "Expandir tudo / Recolher tudo"

🔗 [Ver exemplo do relatório](https://htmlpreview.github.io/?https://github.com/MatheusCDB/zimbra-threat-hunt/blob/main/docs/relatorio_forense.html)

⚠️ Limitações
- Não substitui EDR/AV/SIEM — é triagem de IOC, não detecção comportamental
- Não cobre análise de memória volátil, rootkits em kernel ou comprometimento
de firmware
- Falsos negativos possíveis se o atacante usou IOCs ainda não catalogados
em iocs.json
- Timeout padrão de 120s por comando — em servidores muito grandes, ajuste --timeout
- Logs rotacionados: só o arquivo atual é analisado; .gz, .1, .2 não

🤝 Contribuindo
- Faça um fork
- Crie uma branch (git checkout -b feature/minha-melhoria)
- Commit suas mudanças (git commit -am 'Add ...')
-Push (git push origin feature/minha-melhoria)
- Abra um Pull Request

📄 Licença
Este projeto está sob a licença MIT. Veja [LICENSE](https://license/)  para detalhes.

Autor
Matheus C. D. B. — @MatheusCDB
