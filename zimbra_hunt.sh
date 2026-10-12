#!/usr/bin/env bash
# ============================================================
#  [*]  Zimbra Forensics - Threat Hunt (wrapper)
#  Triagem forense READ-ONLY de possiveis infeccoes.
# ============================================================
set -u

# ---------- Configuracao ----------
SCRIPT_PY="${SCRIPT_PY:-/root/zimbra_forensics.py}"
DEFAULT_OUT="/root/zimbra_forensics"
DEFAULT_TIMEOUT=120
DEFAULT_DAYS=5
DEFAULT_IOC=""
PY="${PYTHON:-python3}"

# Cores (desabilita se nao for TTY)
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""
    C_RED=""; C_GREEN=""; C_YELLOW=""
    C_BLUE=""; C_CYAN=""
fi

# ---------- Utilidades ----------
die() { echo "${C_RED}[!] $*${C_RESET}" >&2; exit 1; }

banner() {
    clear 2>/dev/null || true
    echo "${C_BOLD}${C_CYAN}"
    echo "# ============================================================"
    echo "#  [*] ZIMBRA SECURITY AUDIT"
    echo "# ============================================================"
    echo "${C_RESET}"
    echo "${C_DIM}  Host      : $(hostname 2>/dev/null)"
    echo "  Data/Hora : $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "  Script Py : ${SCRIPT_PY}"
    echo "  Usuario   : $(id -un) ($(id -u))"
    echo "${C_RESET}"
}

check_env() {
    [ -f "$SCRIPT_PY" ] || die "Script Python nao encontrado: $SCRIPT_PY"
    command -v "$PY" >/dev/null 2>&1 || die "Python nao encontrado: $PY"
    if [ "$(id -u)" -ne 0 ]; then
        echo "${C_YELLOW}[!] Aviso: nao esta rodando como root. Algumas leituras podem falhar.${C_RESET}"
        echo
    fi
}

# ---------- UI ----------
menu_principal() {
    while true; do
        banner
        echo "${C_BOLD}  Selecione o modo de execucao:${C_RESET}"
        echo
        echo "    ${C_GREEN}1)${C_RESET} Quick     ${C_DIM}(identify, processes, network, tmpfiles, persistence, ssh)${C_RESET}"
        echo "    ${C_GREEN}2)${C_RESET} Full      ${C_DIM}(todos os modulos)${C_RESET}"
        echo "    ${C_GREEN}3)${C_RESET} Padrao    ${C_DIM}(quick + webshell + logs)${C_RESET}"
        echo "    ${C_GREEN}4)${C_RESET} Modulo especifico"
        echo
        echo "    ${C_YELLOW}9)${C_RESET} Configuracoes atuais"
        echo "    ${C_YELLOW}0)${C_RESET} Sair"
        echo
        printf "  Opcao: "
        read -r op

        case "$op" in
            1) modo="quick";     break ;;
            2) modo="full";      break ;;
            3) modo="default";   break ;;
            4) selecionar_modulos; continue ;;
            9) configurar; continue ;;
            0|q|Q) echo; echo "${C_DIM}Saindo.${C_RESET}"; exit 0 ;;
            *) echo "${C_RED}  Opcao invalida.${C_RESET}"; sleep 1 ;;
        esac
    done
}

selecionar_modulos() {
    local mods="identify processes network tmpfiles persistence ssh webshell logs packages"
    local sel=()
    while true; do
        banner
        echo "${C_BOLD}  Selecione um ou mais modulos (separados por espaco):${C_RESET}"
        echo
        local i=1
        for m in $mods; do
            local mark="[ ]"
            for s in "${sel[@]:-}"; do [ "$s" = "$m" ] && mark="[x]"; done
            printf "    %s %d) %s\n" "$mark" "$i" "$m"
            i=$((i+1))
        done
        echo
        echo "    ${C_DIM}Digite numeros separados por espaco (ex: 1 2 5)"
        echo "    Enter vazio = confirmar | 'v' = voltar | 'a' = todos${C_RESET}"
        printf "  Selecao: "
        read -r line
        case "$line" in
            v|V) return ;;
            a|A) sel=($mods); continue ;;
            "") [ ${#sel[@]} -gt 0 ] && break || echo "${C_RED}  Nenhum modulo selecionado.${C_RESET}"; sleep 1 ;;
            *)
                sel=()
                for n in $line; do
                    case "$n" in
                        1) sel+=(identify) ;;
                        2) sel+=(processes) ;;
                        3) sel+=(network) ;;
                        4) sel+=(tmpfiles) ;;
                        5) sel+=(persistence) ;;
                        6) sel+=(ssh) ;;
                        7) sel+=(webshell) ;;
                        8) sel+=(logs) ;;
                        9) sel+=(packages) ;;
                        *) echo "${C_YELLOW}  Ignorado: $n${C_RESET}" ;;
                    esac
                done
                ;;
        esac
    done
    modo="module"
    MODULES_SEL="${sel[*]}"
}

configurar() {
    while true; do
        banner
        echo "${C_BOLD}  Configuracoes:${C_RESET}"
        echo
        echo "    1) Diretorio de saida    : ${C_CYAN}${OUT_DIR:-$DEFAULT_OUT}${C_RESET}"
        echo "    2) Dias (janela analise) : ${C_CYAN}${DAYS:-$DEFAULT_DAYS}${C_RESET}"
        echo "    3) Timeout por comando   : ${C_CYAN}${TIMEOUT:-$DEFAULT_TIMEOUT}${C_RESET}"
        echo "    4) Arquivo de IOCs       : ${C_CYAN}${IOC_FILE:-<vazio, usa default>}${C_RESET}"
        echo "    5) Quarentena            : ${C_CYAN}${QUARANTINE:-sim}${C_RESET}"
        echo
        echo "    ${C_YELLOW}0)${C_RESET} Voltar"
        echo
        printf "  Opcao: "
        read -r op
        case "$op" in
            1) printf "  Novo diretorio [%s]: " "${OUT_DIR:-$DEFAULT_OUT}"; read -r v; [ -n "$v" ] && OUT_DIR="$v" ;;
            2) printf "  Novo valor de dias [%s]: " "${DAYS:-$DEFAULT_DAYS}"; read -r v; [ -n "$v" ] && DAYS="$v" ;;
            3) printf "  Novo timeout (s) [%s]: " "${TIMEOUT:-$DEFAULT_TIMEOUT}"; read -r v; [ -n "$v" ] && TIMEOUT="$v" ;;
            4) printf "  Caminho do iocs.json (vazio p/ limpar) [%s]: " "${IOC_FILE:-}"; read -r v; IOC_FILE="$v" ;;
            5) if [ "${QUARANTINE:-sim}" = "sim" ]; then QUARANTINE="nao"; else QUARANTINE="sim"; fi ;;
            0) return ;;
            *) echo "${C_RED}  Opcao invalida.${C_RESET}"; sleep 1 ;;
        esac
    done
}

confirmar() {
    banner
    echo "${C_BOLD}  Resumo da execucao:${C_RESET}"
    echo
    echo "    Modo          : ${C_CYAN}${modo}${C_RESET}"
    [ "$modo" = "module" ] && echo "    Modulos       : ${C_CYAN}${MODULES_SEL}${C_RESET}"
    echo "    Saida         : ${C_CYAN}${OUT_DIR:-$DEFAULT_OUT}${C_RESET}"
    echo "    Dias          : ${C_CYAN}${DAYS:-$DEFAULT_DAYS}${C_RESET}"
    echo "    Timeout (s)   : ${C_CYAN}${TIMEOUT:-$DEFAULT_TIMEOUT}${C_RESET}"
    echo "    IOCs          : ${C_CYAN}${IOC_FILE:-<default>}${C_RESET}"
    echo "    Quarentena    : ${C_CYAN}${QUARANTINE:-sim}${C_RESET}"
    echo
    printf "  Executar agora? [S/n]: "
    read -r r
    case "${r:-S}" in
        s|S|y|Y|"") return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- Execucao ----------
montar_cmd() {
    CMD=("$PY" "$SCRIPT_PY")
    case "$modo" in
        quick)   CMD+=(--quick) ;;
        full)    CMD+=(--full) ;;
        default) : ;;
        module)
            for m in $MODULES_SEL; do CMD+=(--module "$m"); done
            ;;
    esac
    CMD+=(--output "${OUT_DIR:-$DEFAULT_OUT}")
    CMD+=(--days "${DAYS:-$DEFAULT_DAYS}")
    CMD+=(--timeout "${TIMEOUT:-$DEFAULT_TIMEOUT}")
    [ -n "${IOC_FILE:-}" ] && CMD+=(--ioc-file "$IOC_FILE")
    [ "${QUARANTINE:-sim}" = "nao" ] && CMD+=(--no-quarantine)
    return 0
}

executar() {
    banner
    CMD=()   # garante que nao herdou lixo
    montar_cmd
    echo "${C_BOLD}  Executando:${C_RESET}"
    echo "    ${C_DIM}${CMD[*]}${C_RESET}"
    echo
    echo "${C_BOLD}${C_BLUE}# ============================================================${C_RESET}"
    echo "${C_BOLD}${C_BLUE}#  [>] INICIANDO COLETA - $(date '+%Y-%m-%d %H:%M:%S')${C_RESET}"
    echo "${C_BOLD}${C_BLUE}# ============================================================${C_RESET}"
    echo
    if "${CMD[@]}"; then
        rc=0
    else
        rc=$?
    fi
    echo
    echo "${C_BOLD}${C_BLUE}# ============================================================${C_RESET}"
    echo "${C_BOLD}${C_BLUE}#  [<] COLETA FINALIZADA - exit ${rc}${C_RESET}"
    echo "${C_BOLD}${C_BLUE}# ============================================================${C_RESET}"
    echo
    if [ "$rc" -eq 0 ]; then
        local latest
        latest=$(ls -1dt "${OUT_DIR:-$DEFAULT_OUT}"/evidence_* 2>/dev/null | head -n1)
        if [ -n "$latest" ]; then
            echo "${C_GREEN}[+] Evidencia gerada:${C_RESET} ${latest}"
            echo "${C_GREEN}[+] Relatorio TXT   :${C_RESET} ${latest}/relatorio_forense.txt"
            echo "${C_GREEN}[+] Relatorio HTML  :${C_RESET} ${latest}/relatorio_forense.html"
            echo
            printf "  Visualizar relatorio TXT agora? [s/N]: "
            read -r r
            case "${r:-N}" in
                s|S|y|Y) ${PAGER:-less} "${latest}/relatorio_forense.txt" ;;
            esac
        fi
    else
        echo "${C_RED}[!] Execucao terminou com codigo ${rc}.${C_RESET}"
    fi
    echo
    printf "  Pressione Enter para voltar ao menu..."
    read -r _
}

# ---------- Loop principal ----------
main() {
    check_env
    while true; do
        menu_principal
        confirmar || continue
        executar
        # reset modulos
        unset MODULES_SEL 2>/dev/null || true
    done
}

main "$@"
