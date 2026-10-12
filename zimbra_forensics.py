#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zimbra Forensics v3.0.1  (compativel com Python 3.6+)
Triagem forense READ-ONLY para servidores Zimbra Collaboration.

Principios:
  * Nao mata processos, nao apaga/edita arquivos, nao altera permissoes.
  * Nao executa amostras, nao abre conexoes externas, nao baixa malware.
  * Nao acessa conteudo de e-mails, senhas ou chaves privadas.
  * Limita tempo, tamanho e profundidade de cada verificacao.
  * Erros e limitacoes sao registrados explicitamente.
"""

import argparse
import hashlib
import html
import json
import os
import platform
import re
import shutil
import socket
import stat as statmod
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if sys.version_info < (3, 6):
    sys.stderr.write("Este script requer Python 3.6 ou superior.\n")
    sys.exit(2)

VERSION = "3.0.1"
SEV_ORDER = ["CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"]
SEV_WEIGHT = {"CRITICO": 40, "ALTO": 20, "MEDIO": 8, "BAIXO": 3, "INFO": 0}
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_LOG_LINES = 20000
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024
QUARANTINE_MAX_BYTES = 32 * 1024 * 1024

# ---------------------------------------------------------------------------
# Whitelists de ruído conhecido do Zimbra e do sistema
# ---------------------------------------------------------------------------

# Cron legítimo do Zimbra (definição e execução em log)
ZIMBRA_CRON_WHITELIST = re.compile(
    r"/opt/zimbra/libexec/(zmlogprocess|zmloggerctl|zmmtastatus|"
    r"zmmailboxdmgr|zmstatuslog|zmqueuelog|zmconfigd|zmmtaconfig|"
    r"zmmtaconfigctl|zmlocalconfig|zmcertmgr|zmupdateauthkeys|"
    r"zmdiaglog|zmclamdctl|zmamavisdctl|zmmtaconfig)"
)

# Caminhos legítimos do Zimbra que NÃO devem ser tratados como /tmp suspeito
ZIMBRA_LEGIT_TMP_PATHS = re.compile(
    r"^/opt/zimbra/(data/tmp|log|jetty|common|libexec|bin|conf|index|store)/"
)

# Ferramentas/perl do Zimbra legítimos
ZIMBRA_LEGIT_BIN = re.compile(
    r"^/opt/zimbra/(common/bin|common/sbin|bin|libexec|java/bin|"
    r"common/libexec|common/lib/perl|common/lib64)/"
)

# Kernel threads (aparecem entre colchetes em /proc/PID/comm e no ps)
KERNEL_THREAD = re.compile(r"^\[[^\]]+\]$")

# Padrões de processo que são benignos em qualquer contexto
BENIGN_PROC_NAMES = {
    "kworker", "ksmd", "ksoftirqd", "migration", "rcu_sched", "rcu_bh",
    "watchdog", "cpuhp", "idle", "systemd", "init", "kthreadd",
    "scsi_eh", "kdmflush", "kdmremove", "bioset", "xfs", "ext4",
    "jbd2", "kauditd", "irqbalance", "rpciod", "nfsiod", "kblockd",
    "md", "raid", "zvol", "kintegrityd", "crypto", "tpm_devs",
}

# Padrões de IOC que NÃO devem ser aplicados a logs genéricos
GENERIC_SUDO_PATTERN = re.compile(r"sudo:.*COMMAND")
SUDO_SUSPICIOUS_TARGET = re.compile(
    r"COMMAND=.*?(/tmp/|/dev/shm/|/var/tmp/|/opt/zimbra/data/tmp/|"
    r"softwaretech|xmrig|minerd|w3\.sh|dns-filter|\.swatchd|\.dl_|\.rguard)"
)

# --- Whitelists de log (evitam FP em /var/log/secure, /var/log/cron, nginx) ---

# Alvo legitimo de sudo do Zimbra (postconf, zmprov, zmlocalconfig etc.)
SUDO_ZIMBRA_TARGET = re.compile(
    r"COMMAND=/opt/zimbra/(common/sbin|common/bin|bin|libexec|"
    r"common/libexec|java/bin)/"
)

# Sudo que NAO e do Zimbra e cai em diretorio temporario -> so isso e suspeito
SUDO_TMP_TARGET = re.compile(
    r"COMMAND=\S*(/tmp/|/var/tmp/|/dev/shm/)"
)

# Caminhos internos do Zimbra que aparecem em logs e NAO sao IOC
ZIMBRA_LOG_WHITELIST = re.compile(
    r"/opt/zimbra/data/tmp/"
    r"|/opt/zimbra/libexec/"
    r"|/opt/zimbra/common/"
    r"|/opt/zimbra/log/"
    r"|/opt/zimbra/jetty"
    r"|/opt/zimbra/conf/"
)

# Nginx warn "buffered to a temporary file" e ruido operacional puro
NGINX_TMP_WARN = re.compile(
    r"a client request body is buffered to a temporary file"
    r"|an upstream response is buffered to a temporary file"
)

# Alvo "logico" do /var/log/cron para o Zimbra (cron log repete comando)
CRON_ZIMBRA_CMD = re.compile(
    r"CMD \(/opt/zimbra/(libexec|bin|common)/"
)

# ---------------------------------------------------------------------------
# Utilitarios
# ---------------------------------------------------------------------------

LOG = []          # type: List[str]
INCONCLUSIVE = [] # type: List[str]


def now_local():
    # type: () -> datetime
    return datetime.now().astimezone()


def ts_str():
    # type: () -> str
    return now_local().strftime("%Y-%m-%d %H:%M:%S %z")


def ensure_dir(p):
    # type: (Any) -> Path
    path = Path(p)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        pass
    return path


def safe_write(path, content, mode=0o600):
    # type: (Any, str, int) -> None
    p = Path(path)
    ensure_dir(p.parent)
    try:
        with open(str(p), "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        os.chmod(str(p), mode)
    except OSError as e:
        LOG.append("[!] Falha ao gravar %s: %s" % (p, e))


def which(cmd):
    # type: (str) -> Optional[str]
    return shutil.which(cmd)


def run(cmd, timeout=30):
    # type: (List[str], int) -> Tuple[int, str, str, bool]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"),
                False)
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout", True)
    except FileNotFoundError:
        return (-2, "", "not found", False)
    except Exception as e:
        return (-3, "", str(e), False)


def sha256_file(path, max_bytes=MAX_HASH_BYTES):
    # type: (str, int) -> Optional[str]
    try:
        st = os.lstat(path)
        if not statmod.S_ISREG(st.st_mode):
            return None
        if st.st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def human_size(n):
    # type: (int) -> str
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return "%d%s" % (n, unit)
        n //= 1024
    return "%dP" % n


def read_text_limited(path, max_bytes=MAX_READ_BYTES):
    # type: (str, int) -> str
    try:
        st = os.lstat(path)
        if not statmod.S_ISREG(st.st_mode):
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except (OSError, PermissionError):
        return ""


def file_meta(path):
    # type: (str) -> Dict[str, Any]
    d = {"path": path}  # type: Dict[str, Any]
    try:
        st = os.lstat(path)
        d["size"] = st.st_size
        d["size_h"] = human_size(st.st_size)
        d["mode"] = oct(st.st_mode & 0o7777)
        d["uid"] = st.st_uid
        d["gid"] = st.st_gid
        d["mtime"] = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        d["atime"] = datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S")
        d["ctime"] = datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        d["is_symlink"] = statmod.S_ISLNK(st.st_mode)
        d["is_regular"] = statmod.S_ISREG(st.st_mode)
        try:
            import pwd as _pwd, grp as _grp
            d["user"] = _pwd.getpwuid(st.st_uid).pw_name
            d["group"] = _grp.getgrgid(st.st_gid).gr_name
        except Exception:
            pass
    except (OSError, PermissionError) as e:
        d["error"] = str(e)
    return d


def log(msg):
    # type: (str) -> None
    line = "[%s] %s" % (ts_str(), msg)
    LOG.append(line)
    print(line, flush=True)


def inconclusive(msg):
    # type: (str) -> None
    INCONCLUSIVE.append(msg)
    LOG.append("[?] INCONCLUSIVO: %s" % msg)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Findings(object):
    def __init__(self):
        # type: () -> None
        self.items = []  # type: List[Dict[str, Any]]
        self._n = 0

    def add(self, severity, ftype, target, evidence, reason,
            status="Suspeita fundamentada", user=None, pid=None,
            path=None, ioc=None, confidence="media",
            recommendation=None, related=None, ts=None):
        # type: (str, str, str, str, str, str, Optional[str], Optional[int], Optional[str], Optional[str], str, Optional[str], Optional[List[str]], Optional[str]) -> Dict[str, Any]
        if severity not in SEV_WEIGHT:
            severity = "MEDIO"
        self._n += 1
        item = {
            "id": "F-%04d" % self._n,
            "severity": severity,
            "type": ftype,
            "status": status,
            "target": target,
            "user": user,
            "pid": pid,
            "path": path,
            "ioc": ioc,
            "evidence": evidence,
            "reason": reason,
            "confidence": confidence,
            "recommendation": recommendation or "",
            "related": related or [],
            "timestamp": ts or ts_str(),
        }
        self.items.append(item)
        return item

    def by_severity(self, sev):
        # type: (str) -> List[Dict[str, Any]]
        return [i for i in self.items if i["severity"] == sev]


# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------

class Ctx(object):
    def __init__(self, args):
        # type: (argparse.Namespace) -> None
        self.args = args
        self.root_out = ensure_dir(args.output)
        stamp = now_local().strftime("%Y%m%d_%H%M%S")
        self.evidence = ensure_dir(self.root_out / ("evidence_" + stamp))
        self.start = time.time()
        self.findings = Findings()
        self.system = {}  # type: Dict[str, Any]
        self.zimbra = {}  # type: Dict[str, Any]
        self.iocs = {}    # type: Dict[str, Any]
        self.results = {} # type: Dict[str, Any]
        self.module_times = {} # type: Dict[str, float]
        self.checked = [] # type: List[str]
        for d in ["00_resumo", "01_identificacao", "02_processos", "03_rede",
                  "04_arquivos_tmp", "05_persistencia", "06_webshell",
                  "07_iocs", "08_logs", "09_quarentena", "10_analise"]:
            ensure_dir(self.evidence / d)

    def sub(self, name):
        # type: (str) -> Path
        return self.evidence / name

    def mark(self, name):
        # type: (str) -> None
        self.checked.append(name)

    def timeit(self, name):
        # type: (str) -> Any
        ctx_self = self
        class _T(object):
            def __enter__(s):
                s.t0 = time.time()
                return s
            def __exit__(s, *a):
                ctx_self.module_times[name] = time.time() - s.t0
        return _T()


# ---------------------------------------------------------------------------
# Modulo: identificacao
# ---------------------------------------------------------------------------

def module_identify(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("identify"):
        log("== Modulo: identificacao ==")
        info = {}  # type: Dict[str, Any]
        info["hostname"] = socket.gethostname()
        try:
            info["fqdn"] = socket.getfqdn()
        except Exception:
            info["fqdn"] = ""
        info["os"] = platform.platform()
        try:
            info["kernel"] = platform.release()
            info["arch"] = platform.machine()
        except Exception:
            info["kernel"] = ""
            info["arch"] = ""
        info["collected_at"] = ts_str()
        info["tz"] = list(time.tzname)
        try:
            with open("/proc/uptime") as f:
                info["uptime_sec"] = float(f.read().split()[0])
            info["uptime_h"] = round(info["uptime_sec"] / 3600.0, 2)
        except Exception:
            info["uptime_sec"] = None

        distro = {}
        for p in ("/etc/os-release", "/etc/redhat-release", "/etc/debian_version"):
            if os.path.exists(p):
                distro[p] = read_text_limited(p, 8192).strip()
        info["distro_files"] = distro

        ips = []  # type: List[str]
        hname = which("hostname") or "hostname"
        rc, out, _, _ = run([hname, "-I"], timeout=5)
        if rc == 0 and out.strip():
            ips = out.split()
        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("10.255.255.255", 1))
                ips = [s.getsockname()[0]]
                s.close()
            except Exception:
                pass
        info["ips"] = ips

        ipbin = which("ip") or "ip"
        _, ipout, _, _ = run([ipbin, "-brief", "addr"], timeout=5)
        info["interfaces"] = ipout.strip()

        _, routeout, _, _ = run([ipbin, "route"], timeout=5)
        info["routes"] = routeout.strip()

        dfbin = which("df") or "df"
        _, dfout, _, _ = run([dfbin, "-h"], timeout=10)
        info["disk"] = dfout.strip()

        tdbin = which("timedatectl") or "timedatectl"
        _, timedout, _, _ = run([tdbin], timeout=5)
        info["timedatectl"] = timedout.strip()

        zinfo = {"version": None, "install_dir": None,
                 "webapps_dirs": []}  # type: Dict[str, Any]
        zmcontrol = "/opt/zimbra/bin/zmcontrol"
        if os.path.exists(zmcontrol):
            rc, out, err, _ = run([zmcontrol, "status"], timeout=30)
            zinfo["status_rc"] = rc
            zinfo["status"] = out.strip() or err.strip()

        rel = "/opt/zimbra/.install_history"
        if os.path.exists(rel):
            zinfo["install_history_tail"] = read_text_limited(rel, 8192)[-4096:]

        if which("rpm"):
            rc, out, _, _ = run([which("rpm"), "-q", "zimbra-core"], timeout=10)
            if rc == 0:
                zinfo["version"] = out.strip()
        if not zinfo["version"] and which("dpkg"):
            rc, out, _, _ = run([which("dpkg"), "-l", "zimbra-core"], timeout=10)
            if rc == 0 and "zimbra-core" in out:
                zinfo["version"] = out.strip().splitlines()[-1]

        for cand in ("/opt/zimbra/jetty/webapps",
                     "/opt/zimbra/jetty_base/webapps"):
            if os.path.isdir(cand):
                zinfo["webapps_dirs"].append(cand)
        if os.path.isdir("/opt/zimbra"):
            zinfo["install_dir"] = "/opt/zimbra"

        try:
            import pwd as _pwd
            zinfo["user"] = _pwd.getpwnam("zimbra").pw_uid
        except Exception:
            zinfo["user"] = None

        ctx.system = info
        ctx.zimbra = zinfo
        ctx.results["identify"] = info
        safe_write(ctx.sub("01_identificacao") / "sistema.txt",
                   json.dumps(info, indent=2, ensure_ascii=False))
        safe_write(ctx.sub("01_identificacao") / "zimbra.txt",
                   json.dumps(zinfo, indent=2, ensure_ascii=False))
        ctx.mark("identify")


# ---------------------------------------------------------------------------
# Modulo: processos
# ---------------------------------------------------------------------------

DEFAULT_PROC_PATTERNS = [
    r"xmrig", r"minerd", r"miner", r"softwaretech", r"ksmd", r"w3\.sh",
    r"runloop", r"elock", r"dns-filter", r"socat", r"/dev/tcp",
    r"bash -i", r"nc -e", r"ncat", r"aakore", r"coldtechreview",
    r"check3\.sh", r"p\.sh",
]


def _proc_expected_zimbra():
    # type: () -> List[str]
    return [
        "java", "mysqld", "mariadbd", "slapd", "amavisd", "clamd", "freshclam",
        "postfix", "master", "smtpd", "qmgr", "pickup", "smtp", "lmtp",
        "nginx", "httpd", "apache2", "memcached", "zmconfigd", "zmstat",
        "zmmailboxd", "zmlogger", "zmmtaconfig", "zmcbpolicyd", "zmlocalconfig",
        "zmmemcached", "zmopendkim", "zmproxy", "zmrr", "zmstore",
        "logmailboxd", "/opt/zimbra/", "perl",
    ]


def module_processes(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("processes"):
        log("== Modulo: processos ==")
        iocs = ctx.iocs
        patterns = iocs.get("process_patterns") or DEFAULT_PROC_PATTERNS
        ioc_hashes = set(h.lower() for h in iocs.get("sha256", []))
        ioc_paths = iocs.get("paths", [])
        ioc_names = set(n.lower() for n in iocs.get("file_names", []))

        psbin = which("ps") or "ps"
        rc, psout, _, _ = run([psbin, "-eo",
                               "pid,ppid,user,etimes,pcpu,pmem,stat,args"],
                              timeout=20)
        if rc != 0:
            inconclusive("ps indisponivel")
            return
        procs = []  # type: List[Dict[str, Any]]
        lines = psout.splitlines()
        for line in lines[1:]:
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            pid, ppid, user, etimes, pcpu, pmem, st, args = parts
            try:
                pid_i = int(pid)
            except ValueError:
                continue
            procs.append({"pid": pid_i, "ppid": ppid, "user": user,
                          "etimes": etimes, "pcpu": pcpu, "pmem": pmem,
                          "stat": st, "args": args})

        safe_write(ctx.sub("02_processos") / "ps.txt", psout)

        enriched = []   # type: List[Dict[str, Any]]
        interesting = [] # type: List[Dict[str, Any]]
        skipped_kernel = 0

        for p in procs:
            pid = p["pid"]
            base = "/proc/%d" % pid

            # Ler comm primeiro e pular kernel threads / processos benignos
            comm = ""
            try:
                with open(base + "/comm") as f:
                    comm = f.read().strip()
            except Exception:
                pass

            if KERNEL_THREAD.match(comm) or comm in BENIGN_PROC_NAMES:
                skipped_kernel += 1
                continue

            exe = ""
            cwd = ""
            cmd = ""
            try:
                if os.path.exists(base + "/exe"):
                    exe = os.readlink(base + "/exe")
            except OSError:
                exe = ""
            try:
                if os.path.exists(base + "/cwd"):
                    cwd = os.readlink(base + "/cwd")
            except OSError:
                cwd = ""
            try:
                with open(base + "/cmdline", "rb") as f:
                    cmd = f.read(4096).replace(b"\x00", b" ").decode("utf-8", "replace")
            except Exception:
                cmd = ""

            p["exe"] = exe
            p["cwd"] = cwd
            p["cmdline"] = cmd
            p["comm"] = comm
            enriched.append(p)

            args_l = p["args"].lower()
            cmd_l = cmd.lower()
            exe_l = exe.lower()
            user_l = p["user"].lower()

            suspicious = False
            reasons = []  # type: List[str]

            # Se e um binario legitimo do Zimbra, nao aplicar padroes em args
            is_zimbra_bin = bool(exe and ZIMBRA_LEGIT_BIN.match(exe))

            if not is_zimbra_bin:
                for pat in patterns:
                    try:
                        if re.search(pat, args_l) or re.search(pat, cmd_l):
                            context = (exe_l or "") + " " + (cwd or "").lower()
                            if re.search(pat, context):
                                suspicious = True
                                reasons.append("padrao '%s' no executavel/cwd" % pat)
                            else:
                                if exe and (exe.startswith("/usr/bin/")
                                            or exe.startswith("/bin/")
                                            or exe.startswith("/opt/zimbra/")):
                                    # nao marcar so por citacao em args
                                    pass
                                else:
                                    suspicious = True
                                    reasons.append("padrao '%s' na linha de comando" % pat)
                            break
                    except re.error:
                        inconclusive("regex invalida em process_patterns: %s" % pat)

            # Executavel em tmp (exceto subdirs legitimos do Zimbra)
            if exe and (exe.startswith("/tmp/") or exe.startswith("/var/tmp/")
                        or exe.startswith("/dev/shm/")
                        or (exe.startswith("/opt/zimbra/data/tmp/")
                            and not ZIMBRA_LEGIT_TMP_PATHS.match(exe))):
                suspicious = True
                reasons.append("executavel em diretorio temporario: %s" % exe)

            if exe.endswith(" (deleted)"):
                suspicious = True
                reasons.append("executavel apagado mas em execucao")

            if comm and exe:
                exe_base = os.path.basename(exe)
                if comm not in exe_base and not exe_base.startswith(comm):
                    if any(pat in comm.lower() for pat in patterns):
                        suspicious = True
                        reasons.append("nome '%s' difere do executavel '%s'"
                                       % (comm, exe_base))

            h = sha256_file(exe) if (exe and os.path.exists(exe)) else None
            if h and h.lower() in ioc_hashes:
                suspicious = True
                reasons.append("SHA-256 corresponde a IOC conhecido: %s" % h)

            if user_l == "zimbra" and exe:
                in_zimbra = exe.startswith("/opt/zimbra/")
                in_system = (exe.startswith("/usr/") or exe.startswith("/bin/")
                             or exe.startswith("/sbin/"))
                if not in_zimbra and not in_system:
                    suspicious = True
                    reasons.append("processo do usuario zimbra fora de /opt/zimbra: %s" % exe)

            for ip in ioc_paths:
                if not ip:
                    continue
                context = (exe or "") + " " + (cwd or "")
                if ip in context:
                    suspicious = True
                    reasons.append("caminho IOC '%s'" % ip)
                    break

            if exe and os.path.basename(exe).lower() in ioc_names:
                suspicious = True
                reasons.append("nome de arquivo IOC: %s" % os.path.basename(exe))

            if suspicious:
                p["reasons"] = reasons
                interesting.append(p)

        log("  processos analisados: %d, kernel threads pulados: %d, "
            "suspeitos: %d" % (len(procs), skipped_kernel, len(interesting)))

        for p in interesting:
            sev = "MEDIO"
            conf = "media"
            status = "Suspeita fundamentada"
            joined = " | ".join(p.get("reasons", []))
            if ("SHA-256 corresponde" in joined
                    or "executavel apagado" in joined
                    or "executavel em diretorio temporario" in joined):
                sev = "ALTO"
                status = "Evidencia forte"
                conf = "alta"
            if "SHA-256 corresponde" in joined:
                sev = "CRITICO"
                status = "Evidencia forte"
            if re.search(r"xmrig|minerd|softwaretech", p["args"].lower()):
                sev = "CRITICO"
            ctx.findings.add(
                severity=sev, ftype="Processo suspeito",
                target="PID %s (%s)" % (p["pid"], p.get("exe") or p["args"][:60]),
                evidence=joined,
                reason="Correspondencia a padrao/IOC de processo",
                status=status, user=p["user"], pid=p["pid"],
                path=p.get("exe") or p.get("cwd"),
                confidence=conf,
                recommendation="Correlacionar com rede, cron e arquivos em disco antes de qualquer acao.",
            )

        safe_write(ctx.sub("02_processos") / "processos.json",
                   json.dumps(enriched, indent=2, ensure_ascii=False))
        safe_write(ctx.sub("02_processos") / "suspeitos.json",
                   json.dumps(interesting, indent=2, ensure_ascii=False))
        ctx.results["processes"] = {"total": len(procs),
                                    "kernel_skipped": skipped_kernel,
                                    "suspeitos": len(interesting)}
        ctx.mark("processes")


# ---------------------------------------------------------------------------
# Modulo: rede
# ---------------------------------------------------------------------------

def _parse_ss_line(line):
    # type: (str) -> Optional[Dict[str, Any]]
    parts = line.split()
    if len(parts) < 5:
        return None
    local = parts[3]
    peer = parts[4]
    users = ""
    m = re.search(r'users:\((.*)\)\s*$', line)
    if m:
        users = m.group(1)
    procs = []
    for mm in re.finditer(r'\("([^"]+)",pid=(\d+)', users):
        procs.append({"name": mm.group(1), "pid": int(mm.group(2))})
    return {"local": local, "peer": peer, "procs": procs}


def module_network(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("network"):
        log("== Modulo: rede ==")
        if not which("ss"):
            inconclusive("ss indisponivel; tentando netstat")
            if which("netstat"):
                rc, out, _, _ = run([which("netstat"), "-tnp"], timeout=20)
                if rc != 0:
                    inconclusive("falha ao executar netstat")
                    return
            else:
                inconclusive("nem ss nem netstat disponiveis")
                return
        else:
            rc, out, _, _ = run([which("ss"), "-tnp", "state", "established"],
                                timeout=20)
            if rc != 0:
                inconclusive("falha ao executar ss")
                return
        safe_write(ctx.sub("03_rede") / "ss_established.txt", out)

        ioc_ips = set(ctx.iocs.get("ips", []))
        ioc_domains = set(d.lower() for d in ctx.iocs.get("domains", []))
        ioc_ports = set(str(p) for p in ctx.iocs.get("ports", []))

        conns = []  # type: List[Dict[str, Any]]
        for line in out.splitlines()[1:]:
            d = _parse_ss_line(line)
            if not d:
                continue
            peer_host, _, peer_port = d["peer"].rpartition(":")
            local_host, _, local_port = d["local"].rpartition(":")
            d["peer_host"] = peer_host
            d["peer_port"] = peer_port
            d["local_host"] = local_host
            d["local_port"] = local_port
            conns.append(d)

            if peer_host in ioc_ips:
                ctx.findings.add(
                    severity="ALTO",
                    ftype="Conexao externa com IOC",
                    target="%s:%s" % (peer_host, peer_port),
                    evidence="conexao estabelecida para IP de IOC; processos: %s" % d["procs"],
                    reason="IP presente no banco de IOCs",
                    status="Evidencia forte", ioc=peer_host, confidence="alta",
                    recommendation="Correlacionar processo remoto; avaliar bloqueio conforme politica.",
                )
            if peer_port in ioc_ports and peer_host in ioc_ips:
                ctx.findings.add(
                    severity="CRITICO",
                    ftype="Conexao a pool/C2 conhecido",
                    target="%s:%s" % (peer_host, peer_port),
                    evidence="destino %s:%s corresponde a IOC" % (peer_host, peer_port),
                    reason="IP+porta constam no IOC",
                    status="Evidencia forte",
                    ioc="%s:%s" % (peer_host, peer_port),
                    confidence="alta",
                )
            if peer_host in ioc_domains:
                ctx.findings.add(
                    severity="ALTO",
                    ftype="Dominio C2 observado",
                    target=peer_host,
                    evidence="conexao a dominio de IOC",
                    reason="Dominio presente no IOC",
                    status="Evidencia forte", ioc=peer_host, confidence="media",
                )

        safe_write(ctx.sub("03_rede") / "conexoes.json",
                   json.dumps(conns, indent=2, ensure_ascii=False))
        ctx.results["network"] = {"conexoes": len(conns)}
        ctx.mark("network")


# ---------------------------------------------------------------------------
# Modulo: arquivos temporarios
# ---------------------------------------------------------------------------

TMP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/opt/zimbra/data/tmp"]

# Subdiretorios internos do Zimbra que NAO devem ser tratados como suspeitos
ZIMBRA_TMP_WHITELIST = re.compile(
    r"^/opt/zimbra/data/tmp/(cstrm|convertd|zmstat|logprocess|"
    r"zmmailboxd|javac|hsperfdata|zmmtaconfig|clamav|amavis)"
)


def module_tmpfiles(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("tmpfiles"):
        log("== Modulo: arquivos temporarios ==")
        days = ctx.args.days
        ioc_paths = ctx.iocs.get("paths", [])
        ioc_names = set(n.lower() for n in ctx.iocs.get("file_names", []))
        ioc_hashes = set(h.lower() for h in ctx.iocs.get("sha256", []))
        findings_files = []  # type: List[Dict[str, Any]]

        if not which("find"):
            inconclusive("find indisponivel")
            return

        for d in TMP_DIRS:
            if not os.path.isdir(d):
                continue
            cmd = [which("find"), d, "-xdev", "-type", "f",
                   "-mtime", "-%d" % days, "-printf",
                   "%p|%s|%u|%g|%m|%TY-%Tm-%Td %TH:%TM:%TS|%AY-%Am-%Ad %AH:%AM:%AS|%CY-%Cm-%Cd %CH:%CM:%CS\n"]
            rc, out, err, timed = run(cmd, timeout=max(30, ctx.args.timeout))
            if timed:
                inconclusive("find timeout em %s" % d)
            if rc != 0 and not out:
                inconclusive("find rc=%d em %s: %s" % (rc, d, err.strip()[:120]))
                continue
            for line in out.splitlines():
                parts = line.split("|")
                if len(parts) < 9:
                    continue
                path = parts[0]

                # Ignorar subdiretorios internos conhecidos do Zimbra
                if ZIMBRA_TMP_WHITELIST.match(path):
                    ctx.results.setdefault("tmpfiles_whitelisted", []).append(path)
                    continue

                try:
                    size_i = int(parts[1])
                except ValueError:
                    size_i = 0
                suspicious = False
                reasons = []  # type: List[str]
                base = os.path.basename(path).lower()

                if base.startswith("."):
                    suspicious = True
                    reasons.append("arquivo oculto")
                if base in ioc_names:
                    suspicious = True
                    reasons.append("nome corresponde a IOC")
                for ip in ioc_paths:
                    if ip and ip in path:
                        suspicious = True
                        reasons.append("caminho IOC")
                        break
                if base.endswith(".sh") or base.endswith(".pl") or base.endswith(".py"):
                    suspicious = True
                    reasons.append("script executavel")

                content_head = b""
                try:
                    with open(path, "rb") as f:
                        content_head = f.read(64)
                except Exception:
                    pass
                if content_head.startswith(b"\x7fELF"):
                    suspicious = True
                    reasons.append("binario ELF")
                if content_head.startswith(b"#!"):
                    reasons.append("possui shebang")

                if size_i <= MAX_HASH_BYTES:
                    h = sha256_file(path)
                    if h and h.lower() in ioc_hashes:
                        suspicious = True
                        reasons.append("SHA-256 IOC: %s" % h)

                if not suspicious:
                    continue
                meta = file_meta(path)
                meta["reasons"] = reasons
                meta["sha256"] = sha256_file(path)
                findings_files.append(meta)

                sev = "MEDIO"
                status = "Suspeita fundamentada"
                conf = "media"
                joined_r = " ".join(reasons)
                if ("nome corresponde a IOC" in joined_r
                        or "SHA-256 IOC" in joined_r
                        or "caminho IOC" in joined_r):
                    sev = "ALTO"
                    status = "Evidencia forte"
                    conf = "alta"

                ctx.findings.add(
                    severity=sev, ftype="Arquivo suspeito em tmp",
                    target=path,
                    evidence="; ".join(reasons),
                    reason="arquivo modificado nos ultimos %d dias em diretorio temporario" % days,
                    status=status, path=path, confidence=conf,
                    recommendation="Preservar copia antes de qualquer acao; correlacionar com processo/rede.",
                )

                if ctx.args.quarantine and size_i <= QUARANTINE_MAX_BYTES \
                        and not meta.get("is_symlink"):
                    try:
                        dest = ctx.sub("09_quarentena") / os.path.basename(path)
                        i = 1
                        while dest.exists():
                            dest = ctx.sub("09_quarentena") / ("%s.%d" % (os.path.basename(path), i))
                            i += 1
                        shutil.copy2(path, str(dest), follow_symlinks=False)
                        os.chmod(str(dest), 0o400)
                        ctx.results.setdefault("quarantine", []).append({
                            "origem": path, "copia": str(dest),
                            "sha256": sha256_file(path),
                        })
                    except Exception as e:
                        inconclusive("falha ao preservar %s: %s" % (path, e))

        safe_write(ctx.sub("04_arquivos_tmp") / "suspeitos.json",
                   json.dumps(findings_files, indent=2, ensure_ascii=False))
        ctx.results["tmpfiles"] = {"suspeitos": len(findings_files)}
        ctx.mark("tmpfiles")


# ---------------------------------------------------------------------------
# Modulo: persistencia
# ---------------------------------------------------------------------------

PERSIST_PATTERNS = [
    r"softwaretech", r"xmrig", r"minerd", r"w3\.sh", r"check3\.sh",
    r"p\.sh", r"dns-filter", r"coldtechreview", r"pool\.supportxmr",
    r"80\.96\.113\.59", r"64\.89\.163\.212", r"curl", r"wget", r"base64",
    r"/tmp/", r"/dev/shm",
]


def _scan_cron_files(ctx):
    # type: (Ctx) -> None
    cron_files = ["/etc/crontab", "/etc/anacrontab"]
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly",
              "/var/spool/cron", "/var/spool/cron/crontabs"):
        if os.path.isdir(d):
            try:
                for f in sorted(os.listdir(d)):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp):
                        cron_files.append(fp)
            except OSError:
                pass

    collected = []  # type: List[Dict[str, Any]]
    seen_evidence = set()
    for cf in cron_files:
        if not os.path.exists(cf):
            continue
        content = read_text_limited(cf, 200000)
        if not content:
            continue
        meta = file_meta(cf)
        collected.append({"file": cf, "meta": meta, "content": content})
        for line in content.splitlines():
            line_strip = line.strip()
            if not line_strip or line_strip.startswith("#"):
                continue

            # Whitelist explicita do Zimbra
            if ZIMBRA_CRON_WHITELIST.search(line_strip):
                continue
            # cron legitimo do sistema (updatedb, logrotate, certwatch, etc.)
            if re.match(r"^[^/]*(/usr/bin/|/usr/sbin/|/bin/|/sbin/)", line_strip):
                if not re.search(r"/tmp/|/dev/shm/|/var/tmp/", line_strip):
                    continue

            for pat in PERSIST_PATTERNS:
                if re.search(pat, line_strip):
                    sev = "MEDIO"
                    status = "Suspeita fundamentada"
                    conf = "media"
                    if re.search(r"/tmp/|/dev/shm|softwaretech|xmrig|minerd|w3\.sh",
                                 line_strip):
                        sev = "ALTO"
                        status = "Evidencia forte"
                        conf = "alta"
                    if re.search(r"softwaretech|w3\.sh|runloop|/tmp/\.dl_12339",
                                 line_strip):
                        sev = "CRITICO"
                        status = "Evidencia forte"

                    # Deduplicar por evidencia normalizada
                    norm = re.sub(r"\s+", " ", line_strip).strip().lower()
                    if norm in seen_evidence:
                        break
                    seen_evidence.add(norm)

                    ctx.findings.add(
                        severity=sev, ftype="Cron suspeito",
                        target=cf, path=cf,
                        evidence=line_strip,
                        reason="padrao '%s' em arquivo de cron" % pat,
                        status=status, confidence=conf,
                        recommendation="Nao remover sem preservar copia. Correlacionar com arquivo referenciado.",
                    )
                    break

    for user in ("root", "zimbra"):
        if which("crontab"):
            rc, out, err, _ = run([which("crontab"), "-u", user, "-l"], timeout=10)
            if rc == 0 and out.strip():
                collected.append({"user_crontab": user, "content": out})
                for line in out.splitlines():
                    if not line.strip() or line.strip().startswith("#"):
                        continue
                    if ZIMBRA_CRON_WHITELIST.search(line):
                        continue
                    for pat in PERSIST_PATTERNS:
                        if re.search(pat, line):
                            norm = re.sub(r"\s+", " ", line).strip().lower()
                            if norm in seen_evidence:
                                break
                            seen_evidence.add(norm)
                            ctx.findings.add(
                                severity="ALTO" if re.search(
                                    r"/tmp/|/dev/shm|softwaretech|xmrig",
                                    line) else "MEDIO",
                                ftype="Cron de usuario",
                                target="crontab %s" % user,
                                evidence=line,
                                reason="padrao '%s' no crontab de %s" % (pat, user),
                                user=user, confidence="media",
                            )
                            break
            elif rc != 0:
                inconclusive("crontab -u %s rc=%d: %s" % (user, rc, err.strip()[:100]))

    safe_write(ctx.sub("05_persistencia") / "cron.json",
               json.dumps(collected, indent=2, ensure_ascii=False))


def _scan_systemd(ctx):
    # type: (Ctx) -> None
    dirs = ["/etc/systemd/system", "/usr/lib/systemd/system",
            "/lib/systemd/system", "/run/systemd/system"]
    units = []  # type: List[Dict[str, Any]]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                if not (f.endswith(".service") or f.endswith(".timer")):
                    continue
                fp = os.path.join(d, f)
                if not os.path.isfile(fp):
                    continue
                content = read_text_limited(fp, 64000)
                meta = file_meta(fp)
                units.append({"file": fp, "meta": meta, "content": content})

                suspicious = False
                reasons = []  # type: List[str]
                for m in re.finditer(r"^\s*ExecStart\s*=\s*(.+)$", content, re.M):
                    execline = m.group(1).strip()
                    if re.search(r"/tmp/|/var/tmp|/dev/shm|softwaretech|aakore|"
                                 r"\.dl_|\.swatchd|\.rguard|\.khp",
                                 execline, re.I):
                        suspicious = True
                        reasons.append("ExecStart suspeito: %s" % execline[:160])
                if re.search(r"softwaretech|aakore|idle|ksmd", f, re.I):
                    suspicious = True
                    reasons.append("nome de unidade suspeito: %s" % f)
                if os.path.getmtime(fp) > time.time() - 86400 * ctx.args.days:
                    reasons.append("unidade modificada recentemente")

                if suspicious:
                    ctx.findings.add(
                        severity="ALTO", ftype="systemd unit anomala",
                        target=fp, path=fp,
                        evidence=" | ".join(reasons),
                        reason="unidade com caminho/nome compativel com IOC",
                        status="Evidencia forte", confidence="alta",
                        recommendation="Nao parar/desabilitar. Preservar e correlacionar com processos.",
                    )
        except PermissionError:
            inconclusive("sem permissao em %s" % d)

    safe_write(ctx.sub("05_persistencia") / "systemd.json",
               json.dumps(units, indent=2, ensure_ascii=False))


def _scan_rc_local(ctx):
    # type: (Ctx) -> None
    for f in ("/etc/rc.local", "/etc/rc.d/rc.local"):
        if os.path.exists(f):
            content = read_text_limited(f, 64000)
            meta = file_meta(f)
            if content.strip():
                for pat in PERSIST_PATTERNS:
                    if re.search(pat, content):
                        ctx.findings.add(
                            severity="MEDIO", ftype="rc.local suspeito",
                            target=f, path=f,
                            evidence="padrao '%s' em rc.local" % pat,
                            reason="script de inicializacao contem padrao suspeito",
                            confidence="media",
                        )
                        break
            safe_write(ctx.sub("05_persistencia") / os.path.basename(f),
                       json.dumps({"meta": meta, "content": content},
                                  indent=2, ensure_ascii=False))


def module_persistence(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("persistence"):
        log("== Modulo: persistencia ==")
        _scan_cron_files(ctx)
        _scan_systemd(ctx)
        _scan_rc_local(ctx)
        ctx.mark("persistence")


# ---------------------------------------------------------------------------
# Modulo: SSH
# ---------------------------------------------------------------------------

SSH_KEY_DIRS = [
    "/root/.ssh/authorized_keys",
    "/opt/zimbra/.ssh/authorized_keys",
]


def _discover_homes():
    # type: () -> List[str]
    homes = []
    try:
        for entry in os.listdir("/home"):
            h = "/home/%s/.ssh/authorized_keys" % entry
            if os.path.exists(h):
                homes.append(h)
    except OSError:
        pass
    return homes


def module_ssh(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("ssh"):
        log("== Modulo: SSH authorized_keys ==")
        files = list(SSH_KEY_DIRS) + _discover_homes()
        results = []  # type: List[Dict[str, Any]]
        ioc_comment = None
        ioc_fp = None
        for ioc in ctx.iocs.get("ssh_indicators", []):
            if ioc.get("type") == "comment":
                ioc_comment = ioc.get("value")
            if ioc.get("type") == "fingerprint_sha256":
                ioc_fp = ioc.get("value")

        for f in files:
            if not os.path.exists(f):
                continue
            content = read_text_limited(f, 200000)
            meta = file_meta(f)
            lines = [l for l in content.splitlines() if l.strip()]
            entry = {"file": f, "meta": meta, "keys": []}
            for idx, line in enumerate(lines, 1):
                key_info = {"line": line[:400], "index": idx}
                if which("ssh-keygen"):
                    try:
                        tmp = subprocess.run(
                            [which("ssh-keygen"), "-lf", "-"],
                            input=line.encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10)
                        key_info["fingerprint"] = tmp.stdout.decode(
                            "utf-8", "replace").strip()
                    except Exception:
                        key_info["fingerprint"] = ""
                entry["keys"].append(key_info)
                if ioc_comment and ioc_comment in line:
                    ctx.findings.add(
                        severity="ALTO", ftype="Chave SSH nao reconhecida",
                        target=f, path=f,
                        evidence="comentario '%s' presente na chave" % ioc_comment,
                        reason="comentario consta em IOC historico",
                        status="Evidencia forte", confidence="alta",
                        recommendation="Preservar arquivo; investigar origem e rotacionar chaves conforme politica.",
                    )
                if ioc_fp and key_info.get("fingerprint") and ioc_fp in key_info["fingerprint"]:
                    ctx.findings.add(
                        severity="ALTO", ftype="Chave SSH IOC",
                        target=f, path=f,
                        evidence="fingerprint corresponde a IOC: %s" % key_info["fingerprint"],
                        reason="fingerprint em IOC historico",
                        status="Evidencia forte", confidence="alta",
                    )
            results.append(entry)
            safe_write(ctx.sub("05_persistencia") /
                       ("ssh_" + os.path.basename(f) + ".json"),
                       json.dumps(entry, indent=2, ensure_ascii=False))
        ctx.results["ssh"] = results
        ctx.mark("ssh")


# ---------------------------------------------------------------------------
# Modulo: webshell JSP/JSPX
# ---------------------------------------------------------------------------

JSP_SUSPICIOUS = [
    r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec",
    r"ProcessBuilder",
    r"Base64\.getDecoder",
    r"getInputStream\s*\(\s*\)",
    r"new\s+File\s*\(\s*request\.getParameter",
    r"Class\.forName\s*\(\s*request\.getParameter",
    r"defineClass\s*\(",
]

JSP_IOC = [
    r"softwaretech", r"dns-filter", r"xmrig", r"stratum",
    r"coldtechreview", r"pool\.supportxmr",
    r"80\.96\.113\.59", r"64\.89\.163\.212", r"w3\.sh",
]

# Marcadores que, isoladamente, ja caracterizam webshell (execucao dinamica
# ou acesso a parametro de request). Os demais JSP_SUSPICIOUS sao "fracos"
# e so contam em conjunto com ausencia de contexto legitimo.
JSP_STRONG_MARKERS = [
    r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec",
    r"ProcessBuilder",
    r"defineClass\s*\(",
    r"Class\.forName\s*\(\s*request\.getParameter",
    r"new\s+File\s*\(\s*request\.getParameter",
]

# Caminhos publicos do Zimbra que sao legitimos (evita FP de admin/public)
LEGIT_WEBAPP = re.compile(
    r"/opt/zimbra/jetty(_base)?/webapps/(zimbra|service|zimbraAdmin|"
    r"zimbraMail|zimlet|zmail|public)/"
)


def module_webshell(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("webshell"):
        log("== Modulo: webshell JSP/JSPX ==")
        bases = ctx.zimbra.get("webapps_dirs") or []
        if not bases:
            inconclusive("nenhum diretorio webapps do Zimbra encontrado")
            ctx.mark("webshell")
            return

        days = ctx.args.days
        ioc_paths = ctx.iocs.get("paths", [])
        findings_list = []  # type: List[Dict[str, Any]]

        for base in bases:
            cmd = [which("find"), base, "-xdev", "-type", "f",
                   "(", "-name", "*.jsp", "-o", "-name", "*.jspx",
                   "-o", "-name", "*.jspf", ")",
                   "-mtime", "-%d" % days, "-printf",
                   "%p|%s|%TY-%Tm-%Td %TH:%TM:%TS\n"]
            rc, out, err, timed = run(cmd, timeout=max(60, ctx.args.timeout))
            if timed:
                inconclusive("find timeout em %s" % base)
            candidates = []
            for line in out.splitlines():
                candidates.append(line.split("|")[0])
            for ip in ioc_paths:
                if ip.endswith(".jsp") or ip.endswith(".jspx"):
                    full = ip if ip.startswith("/") else base + "/" + ip
                    if os.path.exists(full) and full not in candidates:
                        candidates.append(full)

            for cand in candidates:
                content = read_text_limited(cand, 500000)
                strong = []  # execucao dinamica / IOC / nome historico
                weak = []    # oculto, padroes ambiguos

                for pat in JSP_SUSPICIOUS:
                    try:
                        if re.search(pat, content, re.I):
                            if any(re.search(sp, pat) for sp in JSP_STRONG_MARKERS):
                                strong.append("padrao suspeito: %s" % pat)
                            else:
                                weak.append("padrao suspeito: %s" % pat)
                    except re.error:
                        pass

                for pat in JSP_IOC:
                    if re.search(pat, content, re.I):
                        strong.append("IOC no conteudo: %s" % pat)

                base_name = os.path.basename(cand).lower()
                if base_name in ("snmpc_rce.jsp", "launchimgdata.jsp"):
                    strong.append("nome de arquivo observado em incidente anterior")
                if base_name.startswith("."):
                    weak.append("arquivo oculto em webapps")

                reasons = strong + weak

                # Se esta em area publica legitima E nao ha razao forte, pular.
                if LEGIT_WEBAPP.search(cand) and not strong:
                    continue

                if not reasons:
                    continue

                meta = file_meta(cand)
                meta["reasons"] = reasons
                meta["sha256"] = sha256_file(cand)
                findings_list.append(meta)

                sev = "ALTO"
                status = "Evidencia forte"
                if strong:
                    sev = "CRITICO"

                ctx.findings.add(
                    severity=sev, ftype="Webshell JSP/JSPX suspeita",
                    target=cand, path=cand,
                    evidence="; ".join(reasons[:5]),
                    reason="conteudo/nome compativel com webshell",
                    status=status, confidence="alta",
                    recommendation="Preservar copia, comparar com pacote original do Zimbra e revisar logs HTTP/Jetty.",
                )

        safe_write(ctx.sub("06_webshell") / "suspeitos.json",
                   json.dumps(findings_list, indent=2, ensure_ascii=False))
        ctx.results["webshell"] = {"suspeitos": len(findings_list)}
        ctx.mark("webshell")


# ---------------------------------------------------------------------------
# Modulo: logs
# ---------------------------------------------------------------------------

LOG_FILES = [
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/secure",
    "/var/log/auth.log",
    "/var/log/cron",
    "/var/log/maillog",
    "/var/log/zimbra.log",
    "/opt/zimbra/log/mailbox.log",
    "/opt/zimbra/log/audit.log",
    "/opt/zimbra/log/zmmailboxd.out",
    "/opt/zimbra/log/nginx.log",
    "/opt/zimbra/log/nginx.access.log",
]

LOG_PATTERNS = [
    # Execucao em tmp FORA de /opt/zimbra/data/tmp
    (r"/(tmp|var/tmp|dev/shm)/", "execucao em tmp"),
    # Downloader
    (r"curl\s+http", "curl http"),
    (r"wget\s+http", "wget http"),
    # Payload obfuscado
    (r"base64\s+-d", "base64 -d"),
    (r"chmod\s+\+x", "chmod +x"),
    # Acesso
    (r"Accepted publickey", "SSH aceito"),
    (r"Accepted password", "senha aceita"),
    (r"Failed password", "senha falhou"),
    # IOC de malware
    (r"xmrig", "xmrig"),
    (r"minerd", "minerd"),
    (r"softwaretech", "softwaretech"),
    (r"w3\.sh", "w3.sh"),
    (r"dns-filter", "dns-filter"),
    (r"reverse shell", "reverse shell"),
]

def module_logs(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("logs"):
        log("== Modulo: logs ==")
        days = ctx.args.days
        ioc_ips = set(ctx.iocs.get("ips", []))
        summary = []  # type: List[Dict[str, Any]]

        for lf in LOG_FILES:
            if not os.path.exists(lf):
                continue
            try:
                size = os.path.getsize(lf)
            except OSError:
                continue
            partial = size > MAX_LOG_BYTES
            try:
                with open(lf, "r", encoding="utf-8", errors="replace") as f:
                    if partial:
                        f.seek(-MAX_LOG_BYTES, os.SEEK_END)
                    lines = []
                    for i, line in enumerate(f):
                        if i >= MAX_LOG_LINES:
                            partial = True
                            break
                        lines.append(line)
            except (OSError, PermissionError) as e:
                inconclusive("nao foi possivel ler %s: %s" % (lf, e))
                continue

            # Agrupa por (pattern, ioc_ip, severidade) para evitar 200 findings
            # identicos do mesmo arquivo.
            grouped = {}  # type: Dict[Tuple[str, Optional[str], str], Dict[str, Any]]
            total_hits = 0

            for line in lines:
                stripped = line.rstrip("\n")

                # --- Filtros de ruido conhecido ---

                # Nginx warn de buffering em /opt/zimbra/data/tmp -> ignora
                if NGINX_TMP_WARN.search(stripped) and ZIMBRA_LOG_WHITELIST.search(stripped):
                    continue

                # Linha de /var/log/cron executando comando do Zimbra -> ignora
                if lf == "/var/log/cron" and CRON_ZIMBRA_CMD.search(stripped):
                    continue

                # Sudo do Zimbra ou sudo sem alvo em tmp -> ignora
                if "sudo:" in stripped and "COMMAND=" in stripped:
                    if SUDO_ZIMBRA_TARGET.search(stripped):
                        continue
                    if not SUDO_TMP_TARGET.search(stripped):
                        continue  # sudo sem alvo suspeito, ignora

                # Demais linhas passam pelos patterns
                for pat, label in LOG_PATTERNS:
                    if not re.search(pat, stripped):
                        continue

                    # Se for execucao em /tmp que na verdade e /opt/zimbra/data/tmp -> ignora
                    if pat.startswith(r"/(tmp|var/tmp|dev/shm)/") \
                            and ZIMBRA_LOG_WHITELIST.search(stripped):
                        break

                    match_ioc = None
                    for ip in ioc_ips:
                        if ip in stripped:
                            match_ioc = ip
                            break

                    sev = "ALTO" if match_ioc else "MEDIO"
                    if "Accepted publickey" in stripped or "Accepted password" in stripped:
                        sev = "INFO"

                    key = (label, match_ioc, sev)
                    entry = grouped.get(key)
                    if entry is None:
                        grouped[key] = {
                            "pattern": label,
                            "severity": sev,
                            "ioc_ip": match_ioc,
                            "example": stripped[:400],
                            "count": 1,
                        }
                    else:
                        entry["count"] += 1
                    total_hits += 1
                    break  # um pattern por linha e suficiente

            # Gera um finding por grupo (nao por linha)
            for entry in grouped.values():
                ctx.findings.add(
                    severity=entry["severity"],
                    ftype="Evento em log",
                    target=lf,
                    path=lf,
                    evidence="%s (x%d)" % (entry["example"], entry["count"]),
                    reason="correspondeu a '%s'" % entry["pattern"],
                    ioc=entry["ioc_ip"],
                    confidence="media" if entry["severity"] != "ALTO" else "alta",
                )
            summary.append({"file": lf, "linhas": len(lines),
                            "partial": partial, "grupos": len(grouped),
                            "hits_totais": total_hits})

        if which("journalctl"):
            rc, out, _, timed = run(
                [which("journalctl"), "--since", "-%dd" % days,
                 "--no-pager", "-n", "5000"], timeout=60)
            if not timed and rc == 0:
                safe_write(ctx.sub("08_logs") / "journald.txt", out[:2000000])

        safe_write(ctx.sub("08_logs") / "resumo.json",
                   json.dumps(summary, indent=2, ensure_ascii=False))
        ctx.results["logs"] = summary
        ctx.mark("logs")

# ---------------------------------------------------------------------------
# Modulo: pacotes
# ---------------------------------------------------------------------------

def module_packages(ctx):
    # type: (Ctx) -> None
    with ctx.timeit("packages"):
        log("== Modulo: inventario de pacotes ==")
        out_lines = []  # type: List[str]
        if which("rpm"):
            rc, out, _, _ = run([which("rpm"), "-qa"], timeout=60)
            if rc == 0:
                out_lines.append("== RPM ==")
                out_lines.append(out)
        if which("dpkg"):
            rc, out, _, _ = run([which("dpkg"), "-l"], timeout=60)
            if rc == 0:
                out_lines.append("== DPKG ==")
                out_lines.append(out)
        safe_write(ctx.sub("10_analise") / "pacotes.txt", "\n".join(out_lines))
        ctx.mark("packages")


# ---------------------------------------------------------------------------
# Correlacao
# ---------------------------------------------------------------------------

MAX_RELATED = 8

def correlate(ctx):
    # type: (Ctx) -> List[List[Dict[str, Any]]]
    items = ctx.findings.items
    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Agrupa por (path, evid_norm) e por (ioc) e por (pid)
    # NAO agrupa so por path, senao 200 findings do mesmo arquivo
    # viram um "incidente" gigante sem significado.
    keys = {}  # type: Dict[Any, int]
    for idx, it in enumerate(items):
        evid_norm = re.sub(r"\s+", " ", (it.get("evidence") or "").strip())[:80].lower()
        for k in (
            ("pid", it.get("pid")),
            ("path_evid", (it.get("path"), evid_norm) if it.get("path") else None),
            ("ioc", tuple(it.get("ioc")) if isinstance(it.get("ioc"), list)
                    else it.get("ioc")),
        ):
            if k[1] in (None, "", ()):
                continue
            if k in keys:
                union(idx, keys[k])
            else:
                keys[k] = idx

    clusters = {}  # type: Dict[int, List[Dict[str, Any]]]
    for idx, it in enumerate(items):
        clusters.setdefault(find(idx), []).append(it)

    grouped = []
    for c in clusters.values():
        if len(c) >= 2:
            grouped.append(c)
    for c in grouped:
        for it in c:
            others = [x["id"] for x in c if x is not it]
            it["related"] = others[:MAX_RELATED]
            if len(others) > MAX_RELATED:
                it["related"].append("+%d" % (len(others) - MAX_RELATED))
    return grouped

def calculate_score(findings):
    # type: (Findings) -> Tuple[int, str]
    # Agrupar por (severidade, tipo, evidencia normalizada).
    # Cada grupo conta UMA vez, mas o tamanho do grupo adiciona bonus logaritmico.
    groups = {}  # type: Dict[Tuple[str, str, str], List[Dict[str, Any]]]
    for f in findings.items:
        evid_norm = re.sub(r"\s+", " ", (f.get("evidence") or "").strip())[:120].lower()
        key = (f["severity"], f["type"], evid_norm)
        groups.setdefault(key, []).append(f)

    total = 0
    for (sev, _ftype, _ev), lst in groups.items():
        base = SEV_WEIGHT[sev]
        extra = 0
        if len(lst) > 1:
            import math
            extra = int(base * min(0.5, math.log10(len(lst)) / 4.0))
        total += base + extra

    if total > 100:
        total = 100

    crit = [f for f in findings.items if f["severity"] == "CRITICO"]
    alto = [f for f in findings.items if f["severity"] == "ALTO"]
    crit_conf = [f for f in crit if f["status"] in ("Evidencia forte", "Confirmado")]
    alto_conf = [f for f in alto if f["status"] in ("Evidencia forte",)]

    # Tipos distintos, para nao classificar como comprometimento
    # so porque 200 linhas do mesmo log batem o mesmo pattern.
    tipos_alto = set(f["type"] for f in alto_conf)
    tipos_crit = set(f["type"] for f in crit_conf)

    if crit_conf and len(tipos_crit) >= 2:
        cls = "Comprometimento confirmado"
    elif crit_conf:
        cls = "Fortes indicios de comprometimento"
    elif len(alto_conf) >= 3 and len(tipos_alto) >= 3:
        cls = "Fortes indicios de comprometimento"
    elif alto_conf and len(tipos_alto) >= 2:
        cls = "Suspeita de comprometimento"
    elif alto_conf:
        cls = "Suspeita de comprometimento"
    elif findings.items:
        cls = "Suspeita de comprometimento"
    elif INCONCLUSIVE:
        cls = "Analise inconclusiva"
    else:
        cls = "Nenhum indicio relevante identificado"
    return total, cls


# ---------------------------------------------------------------------------
# Relatorios
# ---------------------------------------------------------------------------

def report_txt(ctx, score, classification, grouped):
    # type: (Ctx, int, str, List[List[Dict[str, Any]]]) -> str
    lines = []  # type: List[str]
    add = lines.append
    add("=" * 78)
    add("Zimbra Forensics v%s - Relatorio Forense" % VERSION)
    add("=" * 78)
    add("Data da analise : %s" % ts_str())
    add("Duracao         : %ss" % round(time.time() - ctx.start, 1))
    add("Host            : %s (%s)" % (ctx.system.get("hostname"), ctx.system.get("fqdn")))
    add("S.O.            : %s" % ctx.system.get("os"))
    add("Kernel          : %s / %s" % (ctx.system.get("kernel"), ctx.system.get("arch")))
    add("Zimbra          : %s" % (ctx.zimbra.get("version") or "nao detectado"))
    add("Score de risco  : %d/100" % score)
    add("Classificacao   : %s" % classification)
    add("")
    add("-" * 78)
    add("RESUMO EXECUTIVO")
    add("-" * 78)
    for sev in SEV_ORDER:
        n = len(ctx.findings.by_severity(sev))
        add("  %-9s: %d" % (sev, n))
    add("  Modulos executados : %s" % (", ".join(ctx.checked) or "nenhum"))
    add("  Verificacoes inconclusivas: %d" % len(INCONCLUSIVE))
    add("")
    add("-" * 78)
    add("ACHADOS")
    add("-" * 78)
    for f in ctx.findings.items:
        add("[%s] %s - %s" % (f["id"], f["severity"], f["type"]))
        add("  Alvo        : %s" % f["target"])
        if f.get("user"):
            add("  Usuario     : %s" % f["user"])
        if f.get("pid"):
            add("  PID         : %s" % f["pid"])
        if f.get("path"):
            add("  Caminho     : %s" % f["path"])
        if f.get("ioc"):
            add("  IOC         : %s" % f["ioc"])
        add("  Status      : %s (confianca %s)" % (f["status"], f["confidence"]))
        add("  Evidencia   : %s" % f["evidence"])
        add("  Motivo      : %s" % f["reason"])
        if f.get("related"):
            add("  Relacionado : %s" % ", ".join(f["related"]))
        if f.get("recommendation"):
            add("  Recomendacao: %s" % f["recommendation"])
        add("")

    if grouped:
        add("-" * 78)
        add("CORRELACOES")
        add("-" * 78)
        for i, c in enumerate(grouped, 1):
            add("Incidente %d: %d evidencias" % (i, len(c)))
            for it in c:
                add("  - %s [%s] %s (%s)" % (it["id"], it["severity"], it["type"], it["target"]))
            add("")

    add("-" * 78)
    add("LIMITACOES")
    add("-" * 78)
    for l in (INCONCLUSIVE or ["Nenhuma limitacao registrada."]):
        add("  - %s" % l)
    add("")

    add("-" * 78)
    add("RECOMENDACOES GERAIS")
    add("-" * 78)
    add("  - Preservar evidencias antes de qualquer alteracao.")
    add("  - Nao desabilitar servicos sem analise previa.")
    add("  - Revisar chaves SSH e contas privilegiadas.")
    add("  - Comparar arquivos do Zimbra com pacote oficial da mesma versao.")
    add("  - Avaliar bloqueio dos IOCs confirmados conforme politica.")
    add("  - Rotacionar credenciais potencialmente expostas.")
    add("")

    add("-" * 78)
    add("EVIDENCIAS")
    add("-" * 78)
    add("  Diretorio: %s" % ctx.evidence)
    add("")
    return "\n".join(lines)


def report_html(ctx, score, classification, grouped):
    # type: (Ctx, int, str, List[List[Dict[str, Any]]]) -> str
    e = html.escape

    def sev_class(s):
        # type: (str) -> str
        return {"CRITICO": "sev-crit", "ALTO": "sev-high",
                "MEDIO": "sev-med", "BAIXO": "sev-low",
                "INFO": "sev-info"}.get(s, "sev-info")

    parts = []  # type: List[str]
    parts.append("<!DOCTYPE html>\n<html lang=\"pt-br\"><head>\n"
                 "<meta charset=\"utf-8\">"
                 "<title>Zimbra Forensics v%s - Relatorio</title>\n" % VERSION)
    parts.append("""<style>
body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;
     margin:0;background:#f4f6f8;color:#1c1f24}
header{background:#0b3d5c;color:#fff;padding:18px 24px}
header h1{margin:0;font-size:20px}
header .meta{font-size:13px;opacity:.9;margin-top:6px}
main{max-width:1100px;margin:20px auto;padding:0 16px}
section{background:#fff;border:1px solid #dde3e8;border-radius:8px;
        margin:14px 0;padding:16px 18px}
h2{font-size:16px;margin:0 0 10px;border-bottom:1px solid #e3e8ec;
   padding-bottom:6px;color:#0b3d5c}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid #eef1f3;padding:6px 8px;text-align:left;
      vertical-align:top}
th{background:#f7f9fa}
.score{font-size:28px;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;
       font-size:11px;color:#fff}
.sev-crit{background:#8b0000}.sev-high{background:#c0392b}
.sev-med{background:#d68910}.sev-low{background:#7f8c8d}
.sev-info{background:#2980b9}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}
pre{background:#f7f9fa;border:1px solid #e1e6ea;padding:8px;
    overflow:auto;font-size:12px}
.small{font-size:12px;color:#56606a}
</style></head><body>""")
    parts.append("<header><h1>Zimbra Forensics v%s - Relatorio de Investigacao de Seguranca</h1>" % VERSION)
    parts.append("<div class=\"meta\">Data: %s &middot; Host: %s &middot; S.O.: %s &middot; Zimbra: %s &middot; ID: %s</div>"
                 % (e(ts_str()), e(str(ctx.system.get("hostname"))),
                    e(str(ctx.system.get("os"))),
                    e(str(ctx.zimbra.get("version") or "n/d")),
                    e(ctx.evidence.name)))
    parts.append("</header><main>")

    parts.append("<section><h2>Resumo Executivo</h2>")
    parts.append("<p>Classificacao: <b>%s</b> &nbsp; Score: <span class=\"score\">%d</span>/100</p>"
                 % (e(classification), score))
    parts.append("<table><tr><th>Severidade</th><th>Qtde</th></tr>")
    for sev in SEV_ORDER:
        parts.append("<tr><td><span class=\"badge %s\">%s</span></td><td>%d</td></tr>"
                     % (sev_class(sev), sev, len(ctx.findings.by_severity(sev))))
    parts.append("</table>")
    parts.append("<p class=\"small\">Modulos: %s<br>Verificacoes inconclusivas: %d</p>"
                 % (e(", ".join(ctx.checked) or "-"), len(INCONCLUSIVE)))
    parts.append("</section>")

    parts.append("<section><h2>Informacoes do Sistema</h2><table>")
    for k in ("hostname", "fqdn", "ips", "os", "kernel", "arch",
              "uptime_h", "collected_at", "tz"):
        v = ctx.system.get(k)
        parts.append("<tr><th>%s</th><td>%s</td></tr>" % (e(k), e(str(v))))
    parts.append("</table></section>")

    parts.append("<section><h2>Achados de Seguranca e Evidencias</h2>")
    if not ctx.findings.items:
        parts.append("<p>Nenhum achado registrado.</p>")
    for f in ctx.findings.items:
        parts.append("<details open>")
        parts.append("<summary><span class=\"badge %s\">%s</span> [%s] %s - %s</summary>"
                     % (sev_class(f["severity"]), e(f["severity"]),
                        e(f["id"]), e(f["type"]), e(f["target"])))
        parts.append("<table>")
        for k, label in (("status", "Status"), ("confidence", "Confianca"),
                         ("user", "Usuario"), ("pid", "PID"),
                         ("path", "Caminho"), ("ioc", "IOC"),
                         ("evidence", "Evidencia"), ("reason", "Motivo"),
                         ("recommendation", "Recomendacao")):
            v = f.get(k)
            if v in (None, ""):
                continue
            parts.append("<tr><th>%s</th><td>%s</td></tr>" % (e(label), e(str(v))))
        if f.get("related"):
            parts.append("<tr><th>Relacionado</th><td>%s</td></tr>"
                         % e(", ".join(f["related"])))
        parts.append("</table></details>")
    parts.append("</section>")

    parts.append("<section><h2>Referencias e IOCs Utilizados</h2><table>")
    parts.append("<tr><th>Tipo</th><th>Valor</th><th>Origem/Contexto</th></tr>")
    for ioc in ctx.iocs.get("ips", []):
        parts.append("<tr><td>IP</td><td>%s</td><td>historico</td></tr>" % e(ioc))
    for ioc in ctx.iocs.get("domains", []):
        parts.append("<tr><td>Dominio</td><td>%s</td><td>historico</td></tr>" % e(ioc))
    for ioc in ctx.iocs.get("paths", []):
        parts.append("<tr><td>Caminho</td><td>%s</td><td>historico</td></tr>" % e(ioc))
    parts.append("</table></section>")

    if grouped:
        parts.append("<section><h2>Correlacoes</h2>")
        for i, c in enumerate(grouped, 1):
            parts.append("<h3>Incidente %d - %d evidencias</h3><ul>" % (i, len(c)))
            for it in c:
                parts.append("<li>[%s] <b>%s</b> %s - %s</li>"
                             % (e(it["id"]), e(it["severity"]),
                                e(it["type"]), e(it["target"])))
            parts.append("</ul>")
        parts.append("</section>")

    parts.append("<section><h2>Limitacoes</h2><ul>")
    for l in (INCONCLUSIVE or ["Nenhuma limitacao registrada."]):
        parts.append("<li>%s</li>" % e(l))
    parts.append("</ul></section>")

    parts.append("</main></body></html>")
    return "".join(parts)


def build_manifest(ctx):
    # type: (Ctx) -> str
    lines = ["# Manifesto de evidencias - %s" % ctx.evidence.name,
             "# Gerado em %s" % ts_str(),
             "# path | size | sha256", ""]
    for root, _, files in os.walk(str(ctx.evidence)):
        for f in sorted(files):
            fp = os.path.join(root, f)
            try:
                size = os.path.getsize(fp)
            except OSError:
                size = -1
            h = sha256_file(fp, max_bytes=512 * 1024 * 1024)
            lines.append("%s | %d | %s" % (fp, size, h or "-"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main / CLI
# ---------------------------------------------------------------------------

MODULES = ["identify", "processes", "network", "tmpfiles",
           "persistence", "ssh", "webshell", "logs", "packages"]

QUICK_MODULES = ["identify", "processes", "network", "tmpfiles",
                 "persistence", "ssh"]


def load_iocs(path):
    # type: (str) -> Dict[str, Any]
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in ("process_patterns", "log_patterns", "webshell_patterns"):
            for pat in data.get(key, []) or []:
                try:
                    re.compile(pat)
                except re.error as e:
                    inconclusive("regex invalida em iocs.%s: %s (%s)" % (key, pat, e))
        return data
    except Exception as e:
        inconclusive("falha ao carregar IOCs: %s" % e)
        return {}


def parse_args():
    # type: () -> argparse.Namespace
    ap = argparse.ArgumentParser(
        prog="zimbra_forensics.py",
        description="Zimbra Forensics v%s - triagem forense read-only" % VERSION,
    )
    ap.add_argument("--output", default="/root/zimbra_forensics",
                    help="diretorio base de saida")
    ap.add_argument("--ioc-file", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "iocs.json"))
    ap.add_argument("--days", type=int, default=5,
                    help="janela de analise (dias)")
    ap.add_argument("--timeout", type=int, default=120,
                    help="timeout base por comando/modulo (segundos)")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--module", action="append", default=[],
                    choices=MODULES)
    ap.add_argument("--quarantine", dest="quarantine", action="store_true",
                    default=True)
    ap.add_argument("--no-quarantine", dest="quarantine",
                    action="store_false")
    return ap.parse_args()


def main():
    # type: () -> int
    args = parse_args()
    ctx = Ctx(args)
    ctx.iocs = load_iocs(args.ioc_file)

    log("Zimbra Forensics v%s - inicio (Python %s)" % (VERSION, platform.python_version()))
    log("Saida: %s" % ctx.evidence)

    if args.module:
        selected = [m for m in MODULES if m in args.module]
    elif args.quick:
        selected = QUICK_MODULES
    elif args.full:
        selected = MODULES
    else:
        selected = QUICK_MODULES + ["webshell", "logs"]

    handlers = {
        "identify": module_identify,
        "processes": module_processes,
        "network": module_network,
        "tmpfiles": module_tmpfiles,
        "persistence": module_persistence,
        "ssh": module_ssh,
        "webshell": module_webshell,
        "logs": module_logs,
        "packages": module_packages,
    }

    for name in selected:
        try:
            handlers[name](ctx)
        except Exception as ex:
            inconclusive("modulo %s falhou: %s" % (name, ex))

    grouped = correlate(ctx)
    score, classification = calculate_score(ctx.findings)

    txt = report_txt(ctx, score, classification, grouped)
    safe_write(ctx.evidence / "relatorio_forense.txt", txt)

    html_doc = report_html(ctx, score, classification, grouped)
    safe_write(ctx.evidence / "relatorio_forense.html", html_doc)

    summary = {
        "version": VERSION,
        "started_at": ts_str(),
        "duration_sec": round(time.time() - ctx.start, 1),
        "score": score,
        "classification": classification,
        "checked_modules": ctx.checked,
        "inconclusive": INCONCLUSIVE,
        "module_times": ctx.module_times,
        "results": {k: v for k, v in ctx.results.items()
                    if k in ("processes", "network", "tmpfiles", "webshell")},
    }
    safe_write(ctx.sub("00_resumo") / "resumo.json",
               json.dumps(summary, indent=2, ensure_ascii=False))

    manifest = build_manifest(ctx)
    safe_write(ctx.evidence / "manifesto_evidencias.txt", manifest)

    log("=" * 60)
    log("Score: %d/100 - %s" % (score, classification))
    log("Relatorios: %s/relatorio_forense.txt" % ctx.evidence)
    log("            %s/relatorio_forense.html" % ctx.evidence)
    log("=" * 60)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] interrompido pelo usuario\n")
        sys.exit(130)