# 🚀 Guia de Implantação

Guia operacional para instalar, configurar e automatizar o Zimbra Threat Hunt
em produção. Para visão geral, arquitetura e estrutura de saída, consulte o
[README](../README.md).

---

## 📖 Índice

- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Primeira execução](#-primeira-execução)
- [Flags de linha de comando](#-flags-de-linha-de-comando)
- [Interpretando a saída](#-interpretando-a-saída)
- [Automação via cron](#-automação-via-cron)
- [Manutenção de IOCs](#-manutenção-de-iocs)
- [Visualização do dashboard](#-visualização-do-dashboard)
- [Troubleshooting](#-troubleshooting)

---

## 🔧 Pré-requisitos

- **Python 3.6+** (`python3 --version`)
- **Bash 4.x** (`bash --version`)
- **Acesso root** ao servidor Zimbra (para ler `/proc/*/exe` e logs)
- **~50 MB livres** em `/root` para as evidências
- **Zimbra 8.x ou 9.x** instalado em `/opt/zimbra`

---

## 📦 Instalação

### 1. Clone o repositório

```bash
cd /root
git clone https://github.com/MatheusCDB/zimbra-threat-hunt.git
cd zimbra-threat-hunt
```

### 2. Ajuste os IOCs

```bash
vi scripts/iocs.json
```

Adicione os IOCs do seu ambiente (IPs, domínios, caminhos, hashes). Se
preferir começar do zero, apague o conteúdo e preencha só as chaves que
você tem:

```json
{
  "ips": ["203.0.113.10"],
  "file_names": ["w3.sh", "softwaretech"],
  "sha256": []
}
```

### 3. Torne os scripts executáveis

```bash
chmod +x scripts/zimbra_forensics.py
chmod +x scripts/zimbra_hunt.sh
```

### 4. (Opcional) Instale globalmente

```bash
sudo cp scripts/zimbra_forensics.py /usr/local/bin/
sudo cp scripts/zimbra_hunt.sh    /usr/local/bin/
sudo cp scripts/iocs.json         /usr/local/bin/
sudo chmod +x /usr/local/bin/zimbra_forensics.py
sudo chmod +x /usr/local/bin/zimbra_hunt.sh
```

Depois disso, `zimbra_hunt.sh` fica disponível de qualquer diretório.

---

## ▶️ Primeira execução

### Modo interativo (recomendado)

```bash
cd /root/zimbra-threat-hunt/scripts
sudo ./zimbra_hunt.sh
```

Menu:

- **1) Quick** — módulos essenciais (~5-10s)
- **2) Full** — todos os 9 módulos (~10-30s)
- **3) Padrão** — Quick + webshell + logs
- **4) Módulo específico** — escolher quais rodar
- **9) Configurações** — output, `--days`, `--timeout`, quarentena

### Linha de comando direta

```bash
# Auditoria rápida
sudo python3 scripts/zimbra_forensics.py --quick --output /root/forense

# Auditoria completa, últimos 7 dias
sudo python3 scripts/zimbra_forensics.py --full --output /root/forense --days 7

# Módulos específicos
sudo python3 scripts/zimbra_forensics.py \
    --module processes --module network \
    --output /root/forense
```

Ao final, o script imprime:

```
============================================================
Score: 0/100 - Nenhum indicio relevante identificado
Relatorios: /root/forense/evidence_20261012_103332/relatorio_forense.txt
            /root/forense/evidence_20261012_103332/relatorio_forense.html
============================================================
```

---

## ⚙️ Flags de linha de comando

| Flag | Padrão | Descrição |
|---|---|---|
| `--output DIR` | `/root/zimbra_forensics` | Diretório base de saída |
| `--ioc-file PATH` | `scripts/iocs.json` | Arquivo de IOCs |
| `--days N` | `5` | Janela de análise (dias para trás) |
| `--timeout N` | `120` | Timeout por comando (segundos) |
| `--quick` | — | Só módulos essenciais |
| `--full` | — | Todos os 9 módulos |
| `--module NAME` | — | Roda apenas o(s) módulo(s) informado(s) |
| `--no-quarantine` | — | Não copia arquivos para `09_quarentena/` |

Módulos disponíveis: `identify`, `processes`, `network`, `tmpfiles`,
`persistence`, `ssh`, `webshell`, `logs`, `packages`.

---

## 📊 Interpretando a saída

A estrutura completa do diretório `evidence_*/` está no
[README](../README.md#-estrutura-dos-resultados). Os arquivos mais úteis no
dia a dia:

| Arquivo | Uso |
|---|---|
| `relatorio_forense.txt` | Anexar em ticket de incidente |
| `relatorio_forense.html` | Apresentar para gestão / cliente |
| `manifesto_evidencias.txt` | Prova de integridade (path \| size \| sha256) |
| `00_resumo/resumo.json` | Automação / ingestão em SIEM |
| `02_processos/suspeitos.json` | Investigação técnica de processos |
| `04_arquivos_tmp/suspeitos.json` | Arquivos suspeitos com hash e razão |
| `09_quarentena/` | Cópias read-only para análise posterior |

---

## ⏰ Automação via cron

### Execução diária às 03:00

```bash
sudo crontab -e
```

Adicione:

```cron
0 3 * * * /usr/bin/python3 /root/zimbra-threat-hunt/scripts/zimbra_forensics.py \
    --full --output /var/log/zimbra-hunt --days 1 --timeout 300 \
    >> /var/log/zimbra-hunt.log 2>&1
```

### Execução horária (só módulos críticos)

```cron
0 * * * * /usr/bin/python3 /root/zimbra-threat-hunt/scripts/zimbra_forensics.py \
    --module processes --module network --module tmpfiles \
    --output /var/log/zimbra-hunt --days 1 --timeout 120 \
    >> /var/log/zimbra-hunt.log 2>&1
```

### Rotação de logs

Crie `/etc/logrotate.d/zimbra-hunt`:

```
/var/log/zimbra-hunt.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

### Limpeza de evidências antigas

```bash
find /var/log/zimbra-hunt/evidence_* -maxdepth 0 -mtime +30 -exec rm -rf {} \;
```

---

## 🎯 Manutenção de IOCs

Toda a inteligência de detecção vem de `scripts/iocs.json`. Para adicionar
novos IOCs, edite o arquivo e reinicie a auditoria — **não é necessário
alterar código**.

### Onde buscar IOCs novos

- Histórico de incidentes da sua organização
- Feeds públicos (AlienVault OTX, abuse.ch, etc.)
- Análises de amostras em VirusTotal / Hybrid Analysis
- Comunidades de resposta a incidentes

### Como adicionar

```json
{
  "ips": ["203.0.113.10"],
  "file_names": ["novo_nome.sh"],
  "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
}
```

### Validação

```bash
python3 -c "import json; json.load(open('scripts/iocs.json'))" && echo "OK"
```

Padrões de regex inválidos são reportados na seção **LIMITAÇÕES** do
relatório gerado, sem interromper a execução.

---

## 🔗 Visualização do dashboard

### Local

```bash
firefox /root/forense/evidence_*/relatorio_forense.html
```

### Remota (via SSH)

```bash
# No servidor
cd /root/forense/evidence_20261012_103332/
python3 -m http.server 8080

# No seu navegador
# http://<ip-do-servidor>:8080/relatorio_forense.html
```

### Exemplo público

🔗 **[Ver exemplo do relatório](https://htmlpreview.github.io/?https://github.com/MatheusCDB/zimbra-threat-hunt/blob/main/docs/relatorio_forense.html)**

---

## 🐛 Troubleshooting

### "Permission denied" ao ler `/proc/*/exe`

Rode como `root`. Em containers com restrição de `/proc`, os findings de
processo virão acompanhados de aviso em `LIMITAÇÕES`.

### `find timeout em /opt/zimbra/data/tmp`

Ajuste `--timeout 600` ou reduza a janela com `--days 1`.

### "Nenhum diretório webapps do Zimbra encontrado"

Verifique se o Zimbra está instalado em `/opt/zimbra`. Se estiver em outro
path, abra uma issue.

### Score 0 mas você suspeita que há algo

- Aumente `--days 30` para cobrir mais histórico
- Adicione IOCs específicos em `scripts/iocs.json`
- Rode `--full` para incluir `webshell` e `logs`
- Revise `manifesto_evidencias.txt` para ver o que foi coletado

### Script aborta com `IndentationError`

Verifique a versão do Python:

```bash
python3 --version   # precisa ser 3.6+
python3 -m py_compile scripts/zimbra_forensics.py
```

---

## 📄 Licença

MIT — veja [LICENSE](../LICENSE).
