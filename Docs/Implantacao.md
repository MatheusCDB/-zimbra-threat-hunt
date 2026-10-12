```markdown
## 🚀 Instalação

Guia passo a passo para instalar e usar o Zimbra Threat Hunt em produção.

### Requisitos

- **Python 3.6+** (testado até 3.12)
- **Zimbra 8.x ou 9.x** (funciona em 7.x também)
- **Sistema**: RHEL/CentOS 7, 8, 9 ou equivalente
- **Privilégios**: `root` (necessário para ler `/proc/*/exe` e logs)
- **Bash 4.x** (para o wrapper interativo)

## 📦 Instalação

### 1. Clone o repositório

```bash
cd /root
git clone https://github.com/<seu-usuario>/zimbra-threat-hunt.git
cd zimbra-threat-hunt

# 2. Copie os IOCs de exemplo
cp iocs.example.json iocs.json
vi iocs.json <  Ajuste os IOCs para o seu ambiente (opcional)


# 4. Torne executável
chmod +x zimbra_forensics.py zimbra_hunt.sh

# 5. (Opcional) Instale como comando
sudo cp zimbra_forensics.py /usr/local/bin/
sudo cp zimbra_hunt.sh /usr/local/bin/

▶️ Uso
Modo interativo

sudo ./zimbra_hunt.sh
Menu com opções:

- Quick — módulos essenciais (5-10s)
- Full — todos os 9 módulos (10-30s)
- Módulo específico — escolher quais rodar
- Configurações — output --days, --timeout, quarentena

Flags disponíveis
Flag	Padrão	Descrição
--output DIR	/root/zimbra_forensics	Diretório de saída
--ioc-file PATH	./iocs.json	Arquivo de IOCs
--days N	5	Janela de análise (dias)
--timeout N	120	Timeout por comando (segundos)
--quick	—	Só módulos essenciais
--full	—	Todos os módulos
--module NAME	—	Rodar só esse(s) módulo(s)
--no-quarantine	—	Não copia arquivos para 09_quarentena/

Ao final, o script imprime:

============================================================
Score: 0/100 - Nenhum indicio relevante identificado
Relatorios: /root/forense/evidence_20261012_103332/relatorio_forense.txt
            /root/forense/evidence_20261012_103332/relatorio_forense.html
============================================================

📂 Saída gerada
Cada execução cria um diretório timestamped:

text
/root/forense/evidence_20261012_103332/
├── 00_resumo/
│   └── resumo.json
├── 01_identificacao/
│   ├── sistema.txt
│   └── zimbra.txt
├── 02_processos/
│   ├── processos.json
│   └── suspeitos.json
├── 03_rede/
│   ├── ss_established.txt
│   └── conexoes.json
├── 04_arquivos_tmp/
│   └── suspeitos.json
├── 05_persistencia/
│   ├── cron.json
│   ├── systemd.json
│   └── ssh_authorized_keys.json
├── 06_webshell/
│   └── suspeitos.json
├── 08_logs/
│   ├── journald.txt
│   └── resumo.json
├── 09_quarentena/                  # cópias dos arquivos suspeitos
├── 10_analise/
│   └── pacotes.txt
├── relatorio_forense.html          # dashboard HTML (dark theme)
├── relatorio_forense.txt           # relatório em texto
└── manifesto_evidencias.txt        # SHA-256 de tudo gerado
Interpretando cada arquivo
Arquivo	O que contém	Uso
relatorio_forense.txt	Resumo, achados, correlações	Anexar em ticket
relatorio_forense.html	Mesmo conteúdo, dashboard	Apresentar para gestão
manifesto_evidencias.txt	path | size | sha256	Prova de integridade
00_resumo/resumo.json	Score, classificação, métricas	Automação / SIEM
02_processos/suspeitos.json	Processos que bateram IOC	Investigação técnica
09_quarentena/	Cópias read-only	Análise posterior

Como adicionar IOCs:

{
  "ips": ["novo.ip.aqui"],
  "file_names": ["novo_nome.sh"],
  "sha256": ["hash_novo"]
}

Depois de editar, valide:
python3 -c "import json; json.load(open('iocs.json'))" && echo "OK"
