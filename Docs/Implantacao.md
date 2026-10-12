## 🚀 Instalação

### Requisitos

- **Python 3.6+** (testado até 3.12)
- **Zimbra 8.x ou 9.x** (funciona em 7.x também)
- **Sistema**: RHEL/CentOS 7, 8, 9 ou equivalente
- **Privilégios**: `root` (necessário para ler `/proc/*/exe` e logs)
- **Bash 4.x** (para o wrapper interativo)

### Instalação rápida

```bash
# 1. Clone
git clone https://github.com/MatheusCDB/zimbra-threat-hunt.git
cd zimbra-threat-hunt

# 2. Copie os IOCs de exemplo
cp iocs.example.json iocs.json

# 3. Ajuste os IOCs para o seu ambiente (opcional)
vi iocs.json

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
