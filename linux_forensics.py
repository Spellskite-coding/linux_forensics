#!/usr/bin/env python3
import os
import sys
import re
import ipaddress

# ==========================================
# CONFIGURATION & IoC
# ==========================================

SUSPICIOUS_CMD_KEYWORDS = [
    'nc -e', 'nc -c', 'ncat ', '/dev/tcp/', '/dev/udp/', 'wget http',
    'curl -s', 'base64 -d', 'nohup', 'bash -i', 'pty.spawn', 'socat',
    'python3 -c', 'perl -e'
]

SUSPICIOUS_ENV_VARS = ['LD_PRELOAD', 'PROMPT_COMMAND', 'LD_AUDIT']

# Couleurs ANSI
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

# ==========================================
# MOTEUR I/O SÉCURISÉ & SANITIZATION
# ==========================================

def sanitize_str(text):
    if not text: return ""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', text).strip()

def safe_read_file(filepath):
    try:
        flags = os.O_RDONLY | os.O_NOATIME | os.O_NONBLOCK
        fd = os.open(filepath, flags)
    except OSError:
        try:
            fd = os.open(filepath, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            return None
    try:
        with os.fdopen(fd, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read(512000)
    except Exception:
        return None

# ==========================================
# RÉSOLUTION RÉSEAU & NAMESPACES
# ==========================================

def hex_to_ip(hex_str):
    """Convertit les IP:Port hexadécimales (IPv4 et IPv6 little-endian) du noyau."""
    try:
        ip_hex, port_hex = hex_str.split(':')
        port = int(port_hex, 16)

        if len(ip_hex) == 8: # IPv4
            ip = f"{int(ip_hex[6:8], 16)}.{int(ip_hex[4:6], 16)}.{int(ip_hex[2:4], 16)}.{int(ip_hex[0:2], 16)}"
            return f"{ip}:{port}"

        elif len(ip_hex) == 32: # IPv6 (Format noyau : 4 mots de 32 bits little-endian)
            words = [ip_hex[i:i+8] for i in range(0, 32, 8)]
            ipv6_raw = "".join([w[6:8] + w[4:6] + w[2:4] + w[0:2] for w in words])
            ipv6_formatted = ":".join([ipv6_raw[i:i+4] for i in range(0, 32, 4)])
            ip = str(ipaddress.IPv6Address(ipv6_formatted).compressed)
            return f"[{ip}]:{port}"

        return "Unknown:Port"
    except Exception:
        return "ParseError:Port"

def get_active_network_sockets():
    """Extrait les inodes des sockets TCP/UDP actifs."""
    sockets = {}
    target_states = ['01', '02', '0A'] # ESTABLISHED, SYN_SENT, LISTEN

    for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
        filepath = f'/proc/net/{proto}'
        if not os.path.exists(filepath):
            continue

        content = safe_read_file(filepath)
        if not content: continue

        lines = content.splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 10:
                local_addr, remote_addr, state, inode = parts[1], parts[2], parts[3], parts[9]

                if proto.startswith('tcp') and state not in target_states:
                    continue

                # Ignore le trafic purement local (Loopback IPv4 127.0.0.1 et IPv6 ::1)
                if (local_addr.startswith('0100007F') and remote_addr == '00000000:0000') or \
                   (local_addr == '00000000000000000000000001000000' and remote_addr == '00000000000000000000000000000000'):
                    continue

                sockets[inode] = {
                    'proto': proto,
                    'local': hex_to_ip(local_addr),
                    'remote': hex_to_ip(remote_addr)
                }
    return sockets

def get_process_sockets(pid):
    """Récupère les inodes réseau associés à un PID."""
    inodes = set()
    fd_dir = f'/proc/{pid}/fd'
    if not os.path.exists(fd_dir):
        return inodes

    try:
        with os.scandir(fd_dir) as entries:
            for entry in entries:
                try:
                    link = os.readlink(entry.path)
                    if link.startswith('socket:['):
                        inodes.add(link[8:-1])
                except OSError:
                    pass
    except OSError:
        pass
    return inodes

def get_init_namespace():
    """Récupère le namespace réseau du processus init (PID 1) comme référence."""
    try:
        return os.readlink('/proc/1/ns/net')
    except OSError:
        return None

# ==========================================
# LE MOTEUR DU SNIPER (OPTIMISÉ SCANDIR)
# ==========================================

def hunt_c2_and_anomalies(is_root):
    print(f"{CYAN}[*] Étape 1 : Cartographie des sockets réseau actifs (ESTABLISHED / LISTEN / UDP)...{RESET}")
    active_sockets = get_active_network_sockets()
    print(f"{CYAN}[*] {len(active_sockets)} sockets réseau pertinents identifiés.{RESET}")

    init_ns = get_init_namespace()
    print(f"{CYAN}[*] Étape 2 : Corrélation PID <-> Socket et recherche d'anomalies (Tir de précision)...{RESET}\n")
    found = False

    try:
        with os.scandir('/proc') as entries:
            for entry in entries:
                pid_str = entry.name
                if not pid_str.isdigit() or pid_str == '1':
                    continue

                proc_dir = entry.path
                try:
                    # 1. Vérification réseau : Le processus a-t-il un socket actif ?
                    p_sockets = get_process_sockets(pid_str)
                    network_context = []
                    for inode in p_sockets:
                        if inode in active_sockets:
                            s_info = active_sockets[inode]
                            network_context.append(f"{s_info['proto'].upper()} {s_info['local']} -> {s_info['remote']}")

                    if not network_context:
                        continue

                    # 2. Le PID est connecté. Est-il suspect ?
                    is_anomalous = False
                    anomaly_reasons = []

                    # A. Namespace Isolation (Évasion Docker/Conteneur)
                    if is_root and init_ns:
                        try:
                            pid_ns = os.readlink(os.path.join(proc_dir, 'ns/net'))
                            if pid_ns != init_ns:
                                is_anomalous = True
                                anomaly_reasons.append(f"Namespace réseau isolé (Conteneur/Sandboxing) : {pid_ns}")
                        except OSError:
                            pass

                    # B. Exécution depuis un dossier suspect (Persistance / Dropper)
                    try:
                        exe_path = os.readlink(os.path.join(proc_dir, 'exe'))
                        if any(x in exe_path for x in ['/tmp/', '/dev/shm/', '/.config/', '/.local/']):
                            is_anomalous = True
                            anomaly_reasons.append(f"Exécution depuis une zone atypique/cachée : {exe_path}")
                    except OSError:
                        pass

                    # C. Analyse des Capacités Linux (Privilege Escalation furtive)
                    status_raw = safe_read_file(os.path.join(proc_dir, 'status'))
                    if status_raw:
                        proc_uid = None
                        cap_eff = "0000000000000000"
                        for line in status_raw.splitlines():
                            if line.startswith('Uid:'):
                                proc_uid = line.split()[1]
                            elif line.startswith('CapEff:'):
                                cap_eff = line.split()[1]

                        # Si le process n'appartient pas à root mais possède des capacités effectives
                        if proc_uid and proc_uid != '0' and cap_eff != '0000000000000000':
                            is_anomalous = True
                            anomaly_reasons.append(f"Privilèges noyau anormaux (Capabilities: {cap_eff}) pour un non-root")

                    # D. Cmdline LotL (Living off the Land)
                    cmdline_raw = safe_read_file(os.path.join(proc_dir, 'cmdline'))
                    if cmdline_raw:
                        cmdline = sanitize_str(cmdline_raw)
                        for keyword in SUSPICIOUS_CMD_KEYWORDS:
                            if keyword in cmdline.replace("'", "").replace('"', "").replace("\\", ""):
                                is_anomalous = True
                                anomaly_reasons.append(f"Mot-clé cmdline suspect ({keyword}) : {cmdline[:80]}...")
                                break

                    # E. Injections (LD_PRELOAD)
                    environ_raw = safe_read_file(os.path.join(proc_dir, 'environ'))
                    if environ_raw:
                        for var in environ_raw.split('\x00'):
                            for bad_env in SUSPICIOUS_ENV_VARS:
                                if bad_env in var:
                                    is_anomalous = True
                                    anomaly_reasons.append(f"Injection environnementale : {sanitize_str(var)}")
                                    break

                    # 3. VERDICT
                    if is_anomalous:
                        proc_name = safe_read_file(os.path.join(proc_dir, 'comm'))
                        proc_name = sanitize_str(proc_name) if proc_name else "Unknown"

                        print(f"{RED}{BOLD}[!] COMPROMISSION RÉSEAU ACTIVE DÉTECTÉE (PID: {pid_str} | {proc_name}){RESET}")
                        print(f"{RED} ├─ Connexion(s) : {', '.join(network_context)}{RESET}")
                        for reason in anomaly_reasons:
                            print(f"{RED} └─ Motif        : {reason}{RESET}")
                        print("")
                        found = True

                except (IOError, OSError):
                    pass
    except OSError:
        pass

    if not found:
        print(f"{BOLD}[+] Scan terminé : Aucun comportement réseau anormal détecté.{RESET}")

# ==========================================
# MAIN ROUTINE
# ==========================================

def main():
    is_root = (os.geteuid() == 0)

    print(f"{YELLOW}=" * 70)
    print("      DFIR LINUX SNIPER - NETWORK & PROCESS CORRELATOR")
    print("=" * 70 + f"{RESET}")

    if is_root:
        print(f"{RED}[!] PRIVILÈGES : ROOT (Périmètre total & Analyse Namespaces){RESET}")
    else:
        print(f"{CYAN}[*] PRIVILÈGES : STANDARD (Certaines vérifications nécessitent Root){RESET}")
    print(f"{YELLOW}=" * 70 + f"{RESET}")

    # --- BLOC DE CONFIRMATION ---
    while True:
        choice = input("\nVoulez-vous engager le tir de précision sur ce périmètre ? (y/n) : ").strip().lower()
        if choice == 'y':
            print(f"\n{CYAN}[+] Déverrouillage et démarrage de la collecte chirurgicale...{RESET}\n")
            break
        elif choice == 'n':
            print("[-] Annulation. Sécurité maintenue, fin du script.")
            sys.exit(0)
        else:
            print("Entrée invalide, veuillez taper 'y' ou 'n'.")
    # ----------------------------------------

    hunt_c2_and_anomalies(is_root)

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    main()
