#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
linux_forensics.py - DFIR LINUX SNIPER v2.4
Corrélateur Réseau / Processus / Système de fichiers pour live forensics Linux.

Contraintes de conception (inchangées) :
  * Aucune dépendance externe (stdlib uniquement, Python >= 3.6).
  * Exécution intégralement en mémoire : aucune écriture disque, aucun appel
    réseau, aucun signal envoyé, aucun module chargé.
  * Lecture seule stricte : O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOATIME.
  * Comportement dégradé mais utile en utilisateur standard, complet en root.
  * Confirmation explicite de l'analyste après affichage d'un avertissement.

Sortie : indicateurs pondérés + SHA256 de chaque artefact retenu, pour
pivot CTI (VirusTotal / MISP / OpenCTI / MalwareBazaar).

Changelog v2.4 — campagne de tests en conteneurs (Debian, Ubuntu, RockyLinux,
AlmaLinux) avec simulation d'attaque et SAST (bandit, semgrep, pyflakes)
------------------------------------------------------------------------
Détection ajoutée :
  * Confrontation légère et non récursive de /usr/bin, /usr/sbin, /bin,
    /sbin à la base de paquets, exécutée PAR DÉFAUT (auparavant réservée à
    --verify-system, qui reste seul à parcourir récursivement /usr/lib et
    /usr/libexec). Fermait un angle mort réel : un implant déposé
    directement dans /usr/bin, sans bit SUID et sans être en cours
    d'exécution durant le scan, était invisible sans penser explicitement à
    --verify-system. Le verdict 'MODIFIÉ' (empreinte divergente, rare et
    univoque) reste pondéré comme avant ; le verdict 'hors-paquet' (fréquent
    et souvent légitime sur une image Docker officielle — policy-rc.d,
    pebble, initctl ajoutés par l'outillage de construction, jamais par un
    paquet) est pondéré plus bas par défaut pour rester silencieux au seuil
    d'affichage standard tout en restant présent dans la table de pivot
    CTI ; --verify-system, explicitement demandé, garde le poids plein.
Correctifs :
  * Le dédoublonnage par chemin réel des artefacts fichiers ne conservait
    que le motif du finding au score le plus haut et jetait silencieusement
    les autres : un binaire SUID copie d'un interpréteur (porte dérobée
    d'élévation, motif le plus décisif du rapport) pouvait disparaître du
    constat si une heuristique généraliste sans rapport (nom caché, zone
    inscriptible) affichait par ailleurs un score plus élevé sur le même
    fichier. Fusion par texte de motif (évite le double comptage d'un motif
    identique détecté deux fois via des racines de parcours qui se
    recouvrent) au lieu d'un remplacement par le seul meilleur score.
  * --no-hash n'était pas honoré par le balayage SUID/SGID : une empreinte
    SHA256 était systématiquement calculée pour chaque binaire SUID/SGID
    trouvé, contredisant la promesse documentée (« n'empreinte aucun
    fichier ») et coûtant du CPU/IO sur un hôte de production justement
    sollicité en mode triage rapide.
  * Empreinte MD5 (comparaison à la base dpkg uniquement, jamais un IoC)
    marquée usedforsecurity=False pour les scanners SAST, avec repli
    silencieux pour Python < 3.9.

Changelog v2.3 — campagne faux négatifs
---------------------------------------
Banc de 12 techniques d'attaque non anticipées par les règles : 10 passaient
au travers. Toutes détectées après correction.

Détection ajoutée :
  * Intégrité par la base de paquets : lecture directe de
    /var/lib/dpkg/info/*.md5sums (aucun appel à dpkg, aucun binaire externe).
    Un binaire de distribution modifié ou un implant déposé dans /usr/lib
    qu'aucun paquet ne revendique sont désormais visibles. Appliqué par défaut
    aux binaires en cours d'exécution et aux SUID ; --verify-system étend le
    contrôle à tous les binaires système. Les diversions dpkg-divert sont
    prises en compte (sinon /usr/bin/man remontait à tort).
  * Persistance systemd (unités système, utilisateur et générateurs),
    autostart XDG, environment.d, fichiers de démarrage shell (.bashrc,
    .profile, .zshrc...), règles udev, ld.so.conf.d, jobs at, init.d,
    apt.conf.d, sudoers.d.
  * Balayage des binaires SUID/SGID des chemins système : un SUID dont le
    contenu est un interpréteur (empreinte comparée aux shells de l'hôte) est
    une porte dérobée d'élévation, quel que soit son nom.
  * Zones de staging /var/lib, /var/cache, /usr/share.
Correctifs :
  * Un même fichier atteint par deux racines (/root et /root/.ssh) était
    restitué deux fois : déduplication par chemin réel, meilleur score retenu.
  * Contenu de persistance à trois niveaux au lieu de deux : la référence à
    une zone monde-inscriptible ne pèse que 20 dans un fichier de
    distribution, 45 ailleurs.
  * ld.so.conf.d : comparaison sur chemin normalisé (libc.conf déclare
    '/usr/local/lib' sans slash final et remontait à tort).
  * Avertissement explicite si --verify-system est lancé sans root : des
    milliers d'atimes seront modifiés faute d'O_NOATIME.

Changelog v2.2
--------------
Faux positifs corrigés (Firefox ESR / session XFCE) :
  * Les 9 processus de contenu Firefox remontaient pour
    LD_PRELOAD=libmozsandbox.so, sa propre sandbox. L'allowlist par nom de
    bibliothèque, non tenable, est remplacée par une évaluation de la
    bibliothèque RÉELLEMENT chargée : le soname relatif est résolu via
    /proc/<pid>/maps (sans exécuter ldconfig), puis jugé sur sa provenance,
    son propriétaire et ses permissions. /usr/lib appartenant à root et non
    inscriptible par d'autres = intégration légitime, silence total.
  * Un chemin absolu en zone temporaire, home ou chemin caché reste
    critique même si le fichier a disparu (implant effaçant son .so).
  * Fichiers de session X11/XFCE/PulseAudio (.X0-lock, .xfsm-ICE-*,
    .ICEauthority, .pulse-*) écartés de la collecte quand ils sont inertes :
    données pures, non exécutables, < 64 Ko. Un ELF ou un script portant
    l'un de ces noms reste signalé (mimétisme).

Changelog v2.1
--------------
Faux positifs corrigés (remontés du terrain, Kali/XFCE) :
  * `xfsettingsd`, `mdadm`, `watchdogd` qualifiés d'usurpation de thread noyau :
    la regex matchait des préfixes nus (xfs, md, watchdog). Un thread noyau est
    désormais reconnu par sa forme réelle (nom contenant '/', nom exact figé,
    ou crochet initial).
  * `sudo`, `su`, `pkexec`, `fusermount3` signalés en élévation de privilèges :
    RUID != EUID = 0 EST le mécanisme setuid. La règle ne se déclenche plus que
    si le binaire ne porte PAS le bit setuid — le cas réellement anormal.
  * Noeuds `chr`/`blk` de systemd (`/run/user/<uid>/systemd/inaccessible/`)
    qualifiés de périphérique hors /dev : allowlist de ces chemins.
  * Toute liste d'IoC ou outil de sécurité posé en zone temporaire (ce script
    y compris) matchait ses propres motifs : au-delà de 4 techniques cumulées,
    le fichier est traité comme une liste d'IoC et n'est plus scoré.
  * Bit SUID pondéré selon la zone : critique en /tmp ou chemin caché,
    signalé sans dramatiser dans /usr/local/bin ou /opt.
Correctifs :
  * `curl|wget -o` (minuscule) et redirection `>` vers /tmp ignorés par le motif
    de téléchargement, qui n'acceptait que `-O`.
  * Le hachage ne renvoie plus jamais d'empreinte tronquée en cas de lecture
    interrompue : abandon explicite plutôt qu'un SHA256 faux.
  * Auto-exclusion du scanner de sa propre chasse fichiers.

Changelog v2.0
--------------
Correctifs de bugs :
  * Filtrage loopback IPv6 inopérant (comparaison sur une chaîne contenant
    le port) et sessions loopback ESTABLISHED remontées à tort.
  * Conversion hexadécimale des adresses codée en dur pour little-endian.
  * Écrasement d'entrées de socket sur l'inode 0 (TIME_WAIT / orphelins).
  * Fuite de descripteur si os.fdopen() échouait après os.open().
  * Blocage possible sur FIFO/device faute de contrôle S_ISREG.
  * Comparaison de CapEff à une constante de 16 zéros (dépend du noyau).
  * `break` inopérant sur la boucle externe lors du parsing d'environ.
  * `f"{COULEUR}=" * 70` répétait la séquence ANSI 70 fois.
  * input() sur stdin non interactif levait EOFError non gérée.
  * PID 1 arbitrairement exclu de l'analyse.
Durcissement :
  * O_NOFOLLOW systématique (anti-symlink), lectures bornées, budget global
    de fichiers, non-franchissement des points de montage, anti-ReDoS.
  * Neutralisation des séquences ANSI présentes dans les noms de fichiers
    et les cmdline (anti-injection dans le terminal de l'analyste).
Détection ajoutée :
  * Binaire supprimé ou memfd toujours en exécution, usurpation de nom de
    thread noyau, ptrace actif, élévation RUID/EUID.
  * Processus cachés (getdents filtré), LKM masqué, kernel tainted,
    sockets sans propriétaire, /etc/ld.so.preload.
  * Chasse fichiers dans les répertoires de prédilection des implants avec
    SHA256, analyse de contenu des scripts déposés et des tâches planifiées.
"""

import argparse
import errno
import hashlib
import ipaddress
import os
import re
import stat
import sys
import time

VERSION = "2.4"

# ==========================================================================
# CONFIGURATION & IoC
# ==========================================================================

# --- Limites de sûreté (anti-DoS sur soi-même) ---
MAX_PROC_READ = 512 * 1024          # octets lus par pseudo-fichier /proc
HASH_CHUNK = 1024 * 1024            # taille de bloc pour le SHA256
DEFAULT_MAX_HASH_SIZE = 128 * 1024 * 1024
DEFAULT_MAX_DEPTH = 6
DEFAULT_MAX_FILES_PER_ROOT = 8000
GLOBAL_FILE_BUDGET = 60000
REGEX_PROBE_LIMIT = 64 * 1024        # borne les moteurs regex (anti-ReDoS sur fichier gonflé)
CONTENT_SCAN_MAX = 256 * 1024        # taille max d'un script dont on lit le contenu
IOC_LIST_THRESHOLD = 4               # au-delà : liste d'IoC, pas un payload
DEFAULT_MAX_FILE_FINDINGS = 150      # artefacts fichiers restitués en détail
DEFAULT_MAX_HASH_FILES = 2000        # plafond global de fichiers empreintés
MAX_IOC_ROWS = 500                   # lignes de la table de pivot CTI
MAX_PID_BRUTEFORCE = 131072

# --- Seuils de scoring (réduction des faux positifs) ---
SEV_CRITICAL = 70
SEV_HIGH = 50
SEV_MEDIUM = 30

# --- Patterns de ligne de commande (regex ciblées, pas de mots-clés nus) ---
CMD_PATTERNS = [
    (re.compile(r'/dev/(tcp|udp)/[0-9a-z]', re.I),
     "Reverse shell natif bash (/dev/tcp)", 70),
    (re.compile(r'\b(nc|ncat|netcat)(\.\w+)?\b[^;|&]{0,120}?\s-\w*e\w*(\s|$)'),
     "Netcat avec exécution de commande (-e/-c)", 65),
    (re.compile(r'\b(curl|wget)\b[^;|&]{0,160}\|\s*(ba|z|k|da)?sh\b'),
     "Téléchargement redirigé vers un interpréteur (dropper)", 70),
    (re.compile(r'\b(curl|wget)\b[^;|&]{0,160}(\s(-o|-O|--output(-document)?)\s*|'
                r'\s*>\s*)/(tmp|dev/shm|var/tmp|run/shm)/', re.I),
     "Téléchargement vers un répertoire monde-inscriptible", 55),
    (re.compile(r'\bpython[0-9.]*\s+-c\b.{0,300}?(socket\.socket|pty\.spawn|os\.dup2|'
                r'SOCK_STREAM|connect\()', re.S),
     "One-liner Python établissant un socket / relais de tty", 60),
    (re.compile(r'\bpython[0-9.]*\s+-c\b.{0,300}?(subprocess|os\.system|os\.popen|'
                r'exec\(|eval\()', re.S),
     "One-liner Python exécutant des commandes (LotL, à corréler)", 25),
    (re.compile(r'\bperl\s+-e\b.{0,300}?(socket|exec|system)', re.S),
     "One-liner Perl orienté shell/socket", 60),
    (re.compile(r'\bruby\s+-r?socket\b'), "One-liner Ruby socket", 55),
    (re.compile(r'\bphp\s+-r\b.{0,300}?(fsockopen|exec|system)', re.S),
     "One-liner PHP orienté shell/socket", 60),
    (re.compile(r'\bsocat\b[^;|&]{0,160}(exec|system):', re.I),
     "Socat avec exécution de commande", 65),
    (re.compile(r'\bbase64\s+(-d|--decode)\b[^;|&]{0,120}\|\s*(ba|z|k|da)?sh\b'),
     "Payload base64 décodé puis exécuté", 70),
    (re.compile(r'\b(bash|sh|zsh|ksh)\s+-[a-z]*i\b'),
     "Shell interactif lancé en ligne de commande", 20),
    (re.compile(r'\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|HISTSIZE=0'),
     "Anti-forensic : neutralisation de l'historique shell", 55),
    (re.compile(r'\bchattr\s+[+-]i\b'),
     "Anti-forensic : verrouillage d'attribut immuable", 45),
    (re.compile(r'ld\.so\.preload'),
     "Manipulation de /etc/ld.so.preload (hooking userland)", 60),
    (re.compile(r'\binsmod\b|\bmodprobe\s+\./|/proc/self/mem\b'),
     "Manipulation noyau / mémoire du processus courant", 55),
    (re.compile(r'memfd_create|/memfd:'),
     "Exécution depuis un fichier anonyme en mémoire (memfd)", 65),
    (re.compile(r'\b(xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|tsunami|dota3?|'
                r'watchdogs|sysrv|xmr-stak|nanominer|teamtnt)\b', re.I),
     "Nom associé à un malware/cryptominer Linux connu", 85),
    (re.compile(r'--donate-level|stratum\+tcp://|pool\.(minexmr|supportxmr|nanopool)', re.I),
     "Configuration de pool de minage", 85),
    (re.compile(r'\bchmod\s+([0-7]*[1357][0-7]{0,2}|[ugoa]*[+=][rw]*[xs][rws]*)'
                r'\s+/(tmp|dev/shm|var/tmp)/'),
     "Attribution du bit d'exécution dans un répertoire temporaire", 20),
]

# --- Variables d'environnement à haut risque ---
ENV_CRITICAL = ('LD_PRELOAD', 'LD_AUDIT')
ENV_WATCH = ('LD_LIBRARY_PATH', 'PROMPT_COMMAND', 'BASH_ENV', 'ENV', 'PYTHONSTARTUP')

# --- Répertoires d'exécution atypiques ---
EXEC_RED_ZONES = (
    '/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/', '/dev/mqueue/',
    '/var/spool/', '/var/lock/', '/var/run/', '/run/user/',
)
EXEC_TRUSTED_PREFIX = (
    '/usr/bin/', '/usr/sbin/', '/usr/lib/', '/usr/libexec/', '/usr/share/',
    '/bin/', '/sbin/', '/lib/', '/lib64/', '/opt/', '/snap/',
    '/usr/local/bin/', '/usr/local/sbin/', '/usr/local/lib/', '/usr/local/libexec/',
)

# --- Capacités Linux réellement dangereuses pour un processus non-root ---
DANGEROUS_CAPS = {
    1: 'CAP_DAC_OVERRIDE', 2: 'CAP_DAC_READ_SEARCH', 4: 'CAP_FOWNER',
    6: 'CAP_SETGID', 7: 'CAP_SETUID', 8: 'CAP_SETPCAP',
    16: 'CAP_SYS_MODULE', 17: 'CAP_SYS_RAWIO', 18: 'CAP_SYS_CHROOT',
    19: 'CAP_SYS_PTRACE', 21: 'CAP_SYS_ADMIN', 22: 'CAP_SYS_BOOT',
    38: 'CAP_PERFMON', 39: 'CAP_BPF',
}

# --- Noms de threads noyau usurpés par les rootkits userland ---
# Un vrai thread noyau porte soit un nom contenant '/' (kworker/0:1,
# jbd2/sda1-8, irq/24-pciehp), soit un nom figé de la liste exacte ci-dessous.
# Les préfixes nus sont proscrits : 'xfs' matchait xfsettingsd, 'md' matchait
# mdadm, 'watchdog' matchait watchdogd (démons userland parfaitement légitimes).
KTHREAD_SLASHED = re.compile(
    r'^(kworker|ksoftirqd|migration|watchdog|irq|rcu[a-z_]*|jbd2|xfs-|xfsaild|'
    r'scsi_eh|scsi_tmf|dm-|md\d*_|writeback|ext4-|btrfs-|nfsd|kdmflush|'
    r'loop\d+|card\d+-|nvme-|cpuhp|idle_inject|ksmd)/')
KTHREAD_EXACT = re.compile(
    r'^(kthreadd|kswapd\d*|khugepaged|kcompactd\d*|kdevtmpfs|oom_reaper|'
    r'khungtaskd|kauditd|kblockd|kintegrityd|kverityd|ksmd|kdamond|kthrotld|'
    r'netns|kstrp|edac-poller|devfreq_wq|inet_frag_wq|kmpath_rdacd|kmpathd|'
    r'acpi_thermal_pm|ipv6_addrconf|cryptd|zswap-shrink|charger_manager|'
    r'xfsalloc|xfs_mru_cache|kcompactd|khubd|kaluad|kmpath_handlerd|'
    r'scsi_eh_\d+|scsi_tmf_\d+|md\d+_[a-z0-9]+|nvme-[a-z-]+wq|raid\d+wq|'
    r'dm_bufio_cache|tpm_dev_wq|blkcg_punt_bio|led_workqueue|ata_sff)$')


def looks_like_kthread_name(comm):
    """Le nom imite-t-il un thread noyau ? Trois formes seulement."""
    if comm.startswith('['):
        return True
    if '/' in comm and KTHREAD_SLASHED.match(comm):
        return True
    return bool(KTHREAD_EXACT.match(comm))

# --- Fichiers de persistance systématiquement empreintés ---
PERSISTENCE_FILES = (
    '/etc/ld.so.preload', '/etc/rc.local', '/etc/crontab',
    '/etc/hosts.deny', '/etc/sudoers',
)
PERSISTENCE_DIRS = (
    # Tâches planifiées
    '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
    '/etc/cron.weekly', '/etc/cron.monthly',
    '/var/spool/cron', '/var/spool/cron/crontabs', '/var/spool/cron/atjobs',
    '/var/spool/at',
    # Démarrage et environnement shell
    '/etc/profile.d', '/etc/update-motd.d', '/etc/init.d',
    '/etc/rc.local.d',
    # Unités systemd (système et générateurs)
    '/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system',
    '/etc/systemd/user', '/usr/lib/systemd/user',
    '/etc/systemd/system-generators', '/usr/lib/systemd/system-generators',
    # Démarrage graphique
    '/etc/xdg/autostart',
    # Chargement de bibliothèques et périphériques
    '/etc/ld.so.conf.d', '/etc/udev/rules.d', '/lib/udev/rules.d',
    '/usr/lib/udev/rules.d',
    # Chaîne de paquets (APT::Update::Pre-Invoke est un vecteur connu)
    '/etc/apt/apt.conf.d', '/etc/sudoers.d',
)
# Deux niveaux : le niveau faible (curl/wget seuls) est omniprésent dans les
# scripts légitimes de distribution (update-motd, apt, certbot...).
PERSISTENCE_STRONG = re.compile(
    r'/dev/tcp/|\b(nc|ncat|netcat)\b[^\n]{0,80}\s-\w*e|'
    r'base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba)?sh|'
    r'(curl|wget)[^\n]{0,120}\|\s*(ba)?sh|'
    r'\b(chattr\s+[+-]i|history\s+-c|HISTFILE=/dev/null)\b|'
    r'memfd_create|\bsocat\b[^\n]{0,80}exec:', re.I | re.M)
# Référence à une zone monde-inscriptible : anormal dans une unité ou une
# tâche déposée par un tiers, banal dans un script de distribution.
PERSISTENCE_MEDIUM = re.compile(
    r'(/tmp/|/dev/shm/|/var/tmp/|/run/shm/)[\w.\-]+', re.I)
PERSISTENCE_WEAK = re.compile(
    r'\b(curl|wget)\b|\bbase64\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b', re.I)

# Fichiers de démarrage shell : vecteur de persistance utilisateur classique.
SHELL_RC_NAMES = frozenset([
    '.bashrc', '.bash_profile', '.bash_login', '.bash_logout', '.profile',
    '.zshrc', '.zprofile', '.zshenv', '.zlogin', '.kshrc', '.cshrc',
    '.login', '.xprofile', '.xinitrc', '.xsession', '.pam_environment',
    'bash.bashrc', 'profile', 'zshrc', 'zprofile', 'zshenv',
])

# Interpréteurs : un binaire SUID dont le contenu est un shell est une porte
# dérobée d'élévation, quel que soit son nom.
INTERPRETER_PATHS = (
    '/bin/bash', '/bin/sh', '/bin/dash', '/bin/zsh', '/bin/ksh', '/bin/busybox',
    '/usr/bin/bash', '/usr/bin/sh', '/usr/bin/dash', '/usr/bin/zsh',
    '/usr/bin/ksh', '/usr/bin/busybox', '/usr/bin/perl', '/usr/bin/env',
)
# Répertoires balayés à la recherche de binaires SUID/SGID anormaux.
SETUID_SWEEP_DIRS = ('/usr/bin', '/usr/sbin', '/bin', '/sbin',
                     '/usr/local/bin', '/usr/local/sbin', '/usr/lib',
                     '/usr/libexec', '/opt')
# Répertoires binaires système principaux, confrontés à la base de paquets à
# CHAQUE exécution (non récursif : seul le niveau 0, quelques centaines à
# quelques milliers de fichiers). Sans ce contrôle par défaut, un implant
# déposé directement dans /usr/bin — sans bit SUID et jamais exécuté durant
# le scan — resterait invisible tant que l'analyste ne pense pas à relancer
# avec --verify-system, qui seul parcourt récursivement l'arborescence
# complète (/usr/lib, /usr/libexec, 2 niveaux de profondeur).
PRIMARY_SYSTEM_BIN_DIRS = ('/usr/bin', '/usr/sbin', '/bin', '/sbin')

# --- Noeuds de périphérique légitimes hors /dev ---
# systemd crée chr/blk/fifo/sock/dir/reg en mode 0000 dans
# /run/systemd/inaccessible/ et /run/user/<uid>/systemd/inaccessible/ pour
# masquer des chemins via les unités (InaccessiblePaths=).
BENIGN_DEVICE_NODES = re.compile(
    r'(^|/)(run/)?(user/\d+/)?systemd/inaccessible/(chr|blk|fifo|sock|dir|reg)$')


def is_benign_device_node(path):
    return bool(BENIGN_DEVICE_NODES.search(path))


# --- Répertoires appartenant à la distribution (vérifiables par paquet) ---
DISTRO_DIRS = ('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/usr/libexec/',
               '/bin/', '/sbin/', '/lib/', '/lib64/', '/usr/lib64/')
DPKG_INFO_DIR = '/var/lib/dpkg/info'
MD5SUMS_READ_LIMIT = 16 * 1024 * 1024


def _package_keys(path):
    """Clés candidates dans la base dpkg, en tenant compte du usr-merge
    (/bin/sleep est listé usr/bin/sleep sur les distributions fusionnées)."""
    rel = path.lstrip('/')
    keys = {rel}
    for prefix in ('bin/', 'sbin/', 'lib/', 'lib64/'):
        if rel.startswith(prefix):
            keys.add('usr/' + rel)
    if rel.startswith('usr/'):
        keys.add(rel[4:])
    return keys


def dpkg_diversions():
    """Chemins déroutés par dpkg-divert. Ils n'apparaissent pas dans les
    md5sums du paquet d'origine et seraient sinon signalés 'hors-paquet'
    (cas classique de /usr/bin/man dans les images conteneurisées)."""
    data = read_text('/var/lib/dpkg/diversions', limit=4 * 1024 * 1024)
    if not data:
        return set()
    lines = [l.strip() for l in data.splitlines() if l.strip()]
    diverted = set()
    # Format : 3 lignes par entrée (origine, destination, paquet).
    for index in range(0, len(lines) - 2, 3):
        diverted.add(lines[index])
        diverted.add(lines[index + 1])
    return diverted


def package_baseline(paths):
    """Empreintes MD5 de référence pour un ensemble borné de chemins.
    Lecture directe de /var/lib/dpkg/info/*.md5sums : aucun appel à dpkg,
    aucun binaire externe, et seules les entrées demandées sont conservées en
    mémoire. Retourne None si l'hôte n'est pas basé sur dpkg."""
    if not os.path.isdir(DPKG_INFO_DIR):
        return None
    wanted = {}
    for path in paths:
        for key in _package_keys(path):
            wanted.setdefault(key, set()).add(path)
    if not wanted:
        return {}
    found = {}
    try:
        with os.scandir(DPKG_INFO_DIR) as entries:
            for entry in entries:
                if not entry.name.endswith('.md5sums'):
                    continue
                data = read_text(entry.path, limit=MD5SUMS_READ_LIMIT)
                if not data:
                    continue
                for line in data.splitlines():
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    digest, rel = parts[0], parts[1].strip()
                    for target in wanted.get(rel, ()):
                        found[target] = digest
    except OSError:
        return None
    return found


def _new_md5():
    """MD5 non cryptographique : seul algorithme publié par les .md5sums
    dpkg, utilisé exclusivement pour comparer un binaire à cette base — pas
    comme SHA256 IoC. usedforsecurity=False (Python >= 3.9) documente
    l'intention pour les scanners SAST ; repli silencieux avant 3.9."""
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()  # nosec B324 nosemgrep: py36-3.8 fallback, not a security use


def md5_path(path, max_size):
    """MD5 d'un fichier régulier, uniquement pour comparer à la base dpkg qui
    ne publie que des MD5. Jamais utilisé comme IoC."""
    fd = open_ro(path, nofollow=False)
    if fd is None:
        return None
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_size:
            return None
        h = _new_md5()
        while True:
            try:
                chunk = os.read(fd, HASH_CHUNK)
            except (BlockingIOError, InterruptedError, OSError):
                return None
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def verify_against_packages(paths, max_size):
    """{chemin: 'ok'|'modifie'|'hors-paquet'} pour les chemins situés dans une
    arborescence de distribution. 'hors-paquet' signale un binaire qu'aucun
    paquet ne revendique : un implant déposé dans /usr/lib en est un."""
    targets = [p for p in paths if any(p.startswith(d) for d in DISTRO_DIRS)]
    if not targets:
        return {}
    baseline = package_baseline(targets)
    if baseline is None:
        return {}
    diverted = dpkg_diversions()
    verdicts = {}
    for path in targets:
        reference = baseline.get(path)
        if reference is None:
            if path in diverted or any(path.endswith(suffix) for suffix in
                                       ('.orig', '.dpkg-old', '.dpkg-new',
                                        '.dpkg-dist', '.distrib', '.bak')):
                verdicts[path] = 'ok'
                continue
            verdicts[path] = 'hors-paquet'
            continue
        actual = md5_path(path, max_size)
        if actual is None:
            continue
        verdicts[path] = 'ok' if actual == reference else 'modifie'
    return verdicts


# --- Magies de fichiers ---
MAGIC_ELF = b'\x7fELF'
MAGIC_SCRIPT = b'#!'

# ==========================================================================
# PRÉSENTATION TERMINAL
# ==========================================================================

class Palette(object):
    """Codes ANSI, neutralisés si la sortie n'est pas un TTY (--no-color)."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def __call__(self, text, code):
        if not self.enabled:
            return text
        return '\033[%sm%s\033[0m' % (code, text)

    def red(self, t):
        return self(t, '91')

    def green(self, t):
        return self(t, '92')

    def yellow(self, t):
        return self(t, '93')

    def cyan(self, t):
        return self(t, '96')

    def grey(self, t):
        return self(t, '90')

    def bold(self, t):
        return self(t, '1')


C = Palette(False)   # remplacé dans main()


def out(msg=''):
    try:
        sys.stdout.write(msg + '\n')
    except (BrokenPipeError, ValueError):
        raise SystemExit(0)


def severity_label(score):
    if score >= SEV_CRITICAL:
        return 'CRITIQUE', C.red
    if score >= SEV_HIGH:
        return 'ELEVE', C.red
    if score >= SEV_MEDIUM:
        return 'MOYEN', C.yellow
    return 'INFO', C.cyan


# ==========================================================================
# MOTEUR I/O SÉCURISÉ (lecture seule, non bloquant, anti-symlink)
# ==========================================================================

O_NOATIME = getattr(os, 'O_NOATIME', 0o1000000)
O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)

_STATS = {
    'noatime_ok': 0,
    'noatime_fallback': 0,
    'read_denied': 0,
    'hashed': 0,
    'hash_bytes': 0,
}


def open_ro(path, nofollow=True):
    """Ouvre un fichier en lecture seule sans jamais suivre de lien symbolique
    et sans jamais bloquer (FIFO / device). Retourne un fd ou None."""
    flags = os.O_RDONLY | os.O_NONBLOCK | O_CLOEXEC
    if nofollow:
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags | O_NOATIME)
        _STATS['noatime_ok'] += 1
        return fd
    except OSError as exc:
        # O_NOATIME exige d'être propriétaire du fichier ou CAP_FOWNER.
        if exc.errno in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EROFS):
            try:
                fd = os.open(path, flags)
                _STATS['noatime_fallback'] += 1
                return fd
            except OSError:
                _STATS['read_denied'] += 1
                return None
        _STATS['read_denied'] += 1
        return None


def read_bytes(path, limit=MAX_PROC_READ, nofollow=True, require_regular=False):
    """Lecture bornée et non bloquante. Ne lève jamais."""
    fd = open_ro(path, nofollow=nofollow)
    if fd is None:
        return None
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return None
        if require_regular and not stat.S_ISREG(st.st_mode):
            return None
        buf = bytearray()
        while len(buf) < limit:
            try:
                chunk = os.read(fd, min(65536, limit - len(buf)))
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        return bytes(buf)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def read_text(path, limit=MAX_PROC_READ, nofollow=True):
    data = read_bytes(path, limit=limit, nofollow=nofollow)
    if data is None:
        return None
    return data.decode('utf-8', 'replace')


def sanitize(text, maxlen=None):
    """Neutralise les caractères de contrôle (protection du terminal contre
    l'injection de séquences ANSI par un nom de fichier ou une cmdline)."""
    if not text:
        return ''
    clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', text)
    clean = re.sub(r'\s{2,}', ' ', clean).strip()
    if maxlen and len(clean) > maxlen:
        clean = clean[:maxlen] + '...'
    return clean


def readlink(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def sha256_fd(fd, size_hint, max_size):
    """Empreinte un descripteur déjà ouvert et validé. Retourne (hash, magic)."""
    if size_hint is not None and size_hint > max_size:
        return 'NON-CALCULE (taille > limite)', b''
    h = hashlib.sha256()
    magic = b''
    total = 0
    stalls = 0
    while True:
        try:
            chunk = os.read(fd, HASH_CHUNK)
        except (BlockingIOError, InterruptedError):
            # Une empreinte partielle présentée comme valide serait pire que
            # pas d'empreinte du tout : on abandonne plutôt que de tronquer.
            stalls += 1
            if stalls > 16:
                return None, magic
            continue
        except OSError:
            return None, magic
        if not chunk:
            break
        if not magic:
            magic = chunk[:8]
        total += len(chunk)
        if total > max_size:
            return 'NON-CALCULE (taille > limite)', magic
        h.update(chunk)
    _STATS['hashed'] += 1
    _STATS['hash_bytes'] += total
    return h.hexdigest(), magic


def sha256_path(path, max_size, nofollow=True):
    """SHA256 d'un fichier régulier. Ne suit pas les symlinks, ne bloque pas
    sur un FIFO ou un device."""
    fd = open_ro(path, nofollow=nofollow)
    if fd is None:
        return None, b''
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return None, b''
        if not stat.S_ISREG(st.st_mode):
            return None, b''
        return sha256_fd(fd, st.st_size, max_size)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def file_kind(magic):
    if magic.startswith(MAGIC_ELF):
        return 'ELF'
    if magic.startswith(MAGIC_SCRIPT):
        return 'SCRIPT'
    if magic[:2] in (b'\x1f\x8b',) or magic[:4] in (b'PK\x03\x04', b'\xfd7zXZ'):
        return 'ARCHIVE'
    return 'DATA'


def fmt_time(epoch):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))
    except (ValueError, OSError):
        return '?'


def fmt_size(n):
    for unit in ('o', 'Ko', 'Mo', 'Go'):
        if n < 1024:
            return '%d%s' % (n, unit)
        n //= 1024
    return '%dTo' % n


# ==========================================================================
# COLLECTE DES RÉSULTATS
# ==========================================================================

class Report(object):
    def __init__(self):
        self.findings = []
        self.iocs = []          # (sha256, path, contexte)
        self._seen_hash = set()

    def add(self, score, category, title, details, hashes=None):
        self.findings.append({
            'score': score, 'category': category, 'title': title,
            'details': details, 'hashes': hashes or [],
        })

    def add_ioc(self, digest, path, context):
        if not digest or not re.fullmatch(r'[0-9a-f]{64}', digest):
            return
        key = (digest, path)
        if key in self._seen_hash:
            return
        self._seen_hash.add(key)
        self.iocs.append((digest, path, context))

    def sorted_findings(self, min_score):
        keep = [f for f in self.findings if f['score'] >= min_score]
        return sorted(keep, key=lambda f: -f['score'])


REPORT = Report()


# ==========================================================================
# RÉSOLUTION RÉSEAU
# ==========================================================================

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING',
}
TCP_TARGET_STATES = ('01', '02', '0A')      # ESTABLISHED, SYN_SENT, LISTEN


def _hex_to_addr(hex_addr):
    """Convertit une adresse hexadécimale du noyau (ordre hôte) en objet
    ipaddress. Gère explicitement l'endianness de la machine."""
    raw = bytes(bytearray.fromhex(hex_addr))
    if len(raw) == 4:
        if sys.byteorder == 'little':
            raw = raw[::-1]
        return ipaddress.IPv4Address(raw)
    if len(raw) == 16:
        if sys.byteorder == 'little':
            raw = b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return ipaddress.IPv6Address(raw)
    raise ValueError('longueur d adresse inattendue')


def parse_hex_endpoint(token):
    """'0100007F:1F90' -> (IPv4Address, 8080). Retourne (None, None) si KO."""
    try:
        hex_addr, hex_port = token.split(':')
        return _hex_to_addr(hex_addr), int(hex_port, 16)
    except (ValueError, ipaddress.AddressValueError):
        return None, None


def addr_repr(addr, port):
    if addr is None:
        return '?:?'
    if addr.version == 6:
        return '[%s]:%d' % (addr.compressed, port)
    return '%s:%d' % (addr.compressed, port)


def is_unspecified(addr):
    return addr is not None and int(addr) == 0


def parse_socket_table(path, proto):
    """Parse une table /proc/net/{tcp,tcp6,udp,udp6}. Retourne {inode: info}."""
    content = read_text(path)
    if not content:
        return {}
    result = {}
    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local_tok, remote_tok, state, uid, inode = (
            parts[1], parts[2], parts[3].upper(), parts[7], parts[9])
        if inode == '0':
            continue                      # sockets orphelins / TIME_WAIT
        if proto.startswith('tcp') and state not in TCP_TARGET_STATES:
            continue

        laddr, lport = parse_hex_endpoint(local_tok)
        raddr, rport = parse_hex_endpoint(remote_tok)
        if laddr is None:
            continue

        # Filtrage du trafic strictement local (corrige le bug de la v1 :
        # les sessions établies 127.0.0.1 <-> 127.0.0.1 passaient au travers).
        loop_local = laddr.is_loopback
        loop_remote = raddr is not None and (raddr.is_loopback or is_unspecified(raddr))
        if loop_local and loop_remote:
            continue

        remote_public = bool(raddr is not None and not is_unspecified(raddr)
                             and not raddr.is_private and not raddr.is_loopback
                             and not raddr.is_link_local and not raddr.is_multicast)
        listening_public = bool(state == '0A' and not laddr.is_loopback)

        result[inode] = {
            'proto': proto,
            'state': TCP_STATES.get(state, 'UDP' if proto.startswith('udp') else state),
            'local': addr_repr(laddr, lport),
            'remote': addr_repr(raddr, rport) if raddr is not None else '-',
            'remote_public': remote_public,
            'remote_ip': raddr.compressed if raddr is not None else None,
            'listening_public': listening_public,
            'uid': uid,
        }
    return result


def collect_sockets(netns_pids, is_root):
    """Agrège les tables de sockets du namespace courant et, en root, de tous
    les namespaces réseau distincts trouvés (détection de C2 conteneurisé)."""
    tables = {}
    namespaces = {'host': ''}
    if is_root:
        namespaces.update(netns_pids)

    for ns_id, pid in namespaces.items():
        base = '/proc/net' if not pid else '/proc/%s/net' % pid
        for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
            path = '%s/%s' % (base, proto)
            if not os.path.exists(path):
                continue
            for inode, info in parse_socket_table(path, proto).items():
                info['netns'] = ns_id
                tables.setdefault(inode, info)
    return tables


def process_socket_inodes(pid):
    """Inodes de socket détenus par un PID (via /proc/<pid>/fd)."""
    inodes = set()
    fd_dir = '/proc/%s/fd' % pid
    try:
        with os.scandir(fd_dir) as entries:
            for entry in entries:
                link = readlink(entry.path)
                if link and link.startswith('socket:['):
                    inodes.add(link[8:-1])
    except OSError:
        pass
    return inodes


# ==========================================================================
# INSPECTION DES PROCESSUS
# ==========================================================================

PF_KTHREAD = 0x00200000


def parse_proc_stat(pid):
    """Parse /proc/<pid>/stat en gérant les comm contenant espaces/parenthèses."""
    raw = read_text('/proc/%s/stat' % pid, limit=8192)
    if not raw:
        return None
    close = raw.rfind(')')
    open_ = raw.find('(')
    if close == -1 or open_ == -1 or close < open_:
        return None
    comm = raw[open_ + 1:close]
    fields = raw[close + 1:].split()
    if len(fields) < 20:
        return None
    try:
        return {
            'comm': comm,
            'state': fields[0],
            'ppid': fields[1],
            'flags': int(fields[6]),
            'starttime': fields[19],
        }
    except (ValueError, IndexError):
        return None


def parse_proc_status(pid):
    raw = read_text('/proc/%s/status' % pid, limit=32768)
    if not raw:
        return {}
    info = {}
    for line in raw.splitlines():
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        info[key.strip()] = value.strip()
    return info


def caps_to_names(cap_hex):
    try:
        mask = int(cap_hex, 16)
    except (ValueError, TypeError):
        return []
    return [name for bit, name in DANGEROUS_CAPS.items() if mask & (1 << bit)]


def path_is_hidden(path):
    return any(part.startswith('.') and part not in ('.', '..')
               for part in path.split('/') if part)


LIB_TRUSTED_PREFIX = ('/usr/lib/', '/usr/lib64/', '/usr/lib32/', '/usr/libx32/',
                      '/lib/', '/lib64/', '/libx32/', '/lib32/',
                      '/usr/local/lib/', '/usr/libexec/', '/opt/', '/snap/')
MAPS_READ_LIMIT = 4 * 1024 * 1024


def resolve_preloaded_lib(pid, token):
    """Chemin réellement chargé pour une entrée LD_PRELOAD. Une valeur
    relative (Firefox exporte 'libmozsandbox.so') est résolue en lisant les
    mappings du processus, sans exécuter ldconfig ni le moindre binaire."""
    token = token.strip()
    if not token:
        return None
    if os.path.isabs(token):
        return token
    base = os.path.basename(token)
    maps = read_text('/proc/%s/maps' % pid, limit=MAPS_READ_LIMIT)
    if not maps:
        return None
    for line in maps.splitlines():
        idx = line.find(' /')
        if idx == -1:
            continue
        path = line[idx + 1:].strip()
        if path and os.path.basename(path) == base:
            return path
    return None


def risky_lib_path(path):
    """Chemin de bibliothèque intrinsèquement anormal, même si le fichier
    n'existe plus : un implant efface souvent son .so après chargement."""
    if not path or not os.path.isabs(path):
        return False
    return (any(path.startswith(z) for z in EXEC_RED_ZONES)
            or path.startswith(('/home/', '/root/', '/var/www/', '/srv/'))
            or path_is_hidden(path))


def classify_preloaded_lib(pid, token):
    """'system' (intégration légitime), 'suspect' ou 'unknown'."""
    resolved = resolve_preloaded_lib(pid, token)
    if not resolved:
        return ('suspect' if risky_lib_path(token) else 'unknown'), None
    try:
        real = os.path.realpath(resolved)
        st = os.stat(real)
    except OSError:
        # Fichier disparu : le chemin déclaré reste jugeable.
        return ('suspect' if risky_lib_path(resolved) else 'unknown'), None
    if not stat.S_ISREG(st.st_mode):
        return 'suspect', real
    # Inscriptible par le monde, ou par un groupe autre que root : toute
    # personne pouvant réécrire la bibliothèque peut injecter du code.
    writable_by_others = bool(st.st_mode & stat.S_IWOTH) or (
        bool(st.st_mode & stat.S_IWGRP) and st.st_gid != 0)
    trusted = (any(real.startswith(pfx) for pfx in LIB_TRUSTED_PREFIX)
               and st.st_uid == 0
               and not writable_by_others
               and not path_is_hidden(real))
    return ('system' if trusted else 'suspect'), real


def exe_privilege_state(pid):
    """'setuid-root' / 'setgid' / 'plain' / 'unknown' pour le binaire mappé.
    Passe par /proc/<pid>/exe : donne l'inode réel même si le fichier a été
    supprimé, et évite toute course sur le chemin."""
    try:
        st = os.stat('/proc/%s/exe' % pid)
    except OSError:
        return 'unknown'
    if st.st_mode & stat.S_ISUID and st.st_uid == 0:
        return 'setuid-root'
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        return 'setgid'
    return 'plain'


def analyse_process(pid, sockets, init_netns, args, is_root, pkg_verdicts=None):
    """Analyse un PID et retourne un dict de constat si le score est retenu."""
    proc_dir = '/proc/%s' % pid
    st = parse_proc_stat(pid)
    if st is None:
        return None

    # Les threads noyau n'ont ni exe ni cmdline : on les exclut du scoring
    # métier, sauf s'ils détiennent un socket (cas rootkit LKM).
    is_kthread = bool(st['flags'] & PF_KTHREAD)

    score = 0
    reasons = []
    hashes = []

    # --- Contexte réseau ---
    net_ctx = []
    public_egress = False
    public_listen = False
    for inode in process_socket_inodes(pid):
        info = sockets.get(inode)
        if not info:
            continue
        net_ctx.append('%s %s %s -> %s' % (
            info['proto'].upper(), info['state'], info['local'], info['remote']))
        public_egress |= info['remote_public']
        public_listen |= info['listening_public']

    if is_kthread and net_ctx:
        score += 60
        reasons.append(('Thread noyau détenant un socket réseau (rootkit LKM ?)', 60))
    elif is_kthread:
        return None

    # --- Binaire exécuté ---
    exe_raw = readlink('%s/exe' % proc_dir)
    exe = exe_raw or ''
    exe_deleted = exe.endswith(' (deleted)')
    exe_clean = exe[:-10] if exe_deleted else exe

    if exe_deleted:
        score += 65
        reasons.append(('Binaire supprimé du disque mais toujours en exécution : %s'
                        % sanitize(exe_clean, 160), 65))
    if exe_clean.startswith('/memfd:') or exe_clean.startswith('memfd:'):
        score += 75
        reasons.append(('Exécution depuis un fichier anonyme en mémoire (memfd) : %s'
                        % sanitize(exe_clean, 120), 75))
    elif exe_clean:
        in_red = any(exe_clean.startswith(z) for z in EXEC_RED_ZONES)
        trusted = any(exe_clean.startswith(p) for p in EXEC_TRUSTED_PREFIX)
        if in_red:
            score += 55
            reasons.append(('Exécution depuis une zone monde-inscriptible : %s'
                            % sanitize(exe_clean, 160), 55))
        elif path_is_hidden(exe_clean) and not trusted:
            score += 45
            reasons.append(('Exécution depuis un répertoire caché : %s'
                            % sanitize(exe_clean, 160), 45))

    # --- Intégrité du binaire vis-à-vis de la base de paquets ---
    verdict = (pkg_verdicts or {}).get(exe_clean)
    if verdict == 'modifie':
        score += 80
        reasons.append(('Binaire de distribution MODIFIÉ : le contenu ne '
                        'correspond pas à l\'empreinte du paquet', 80))
    elif verdict == 'hors-paquet':
        score += 45
        reasons.append(('Binaire situé dans une arborescence de distribution '
                        'mais revendiqué par aucun paquet installé', 45))

    # --- Usurpation d'identité de thread noyau ---
    comm = sanitize(st['comm'], 64)
    if exe_clean and not is_kthread and looks_like_kthread_name(comm):
        score += 60
        reasons.append(('Nom de processus usurpant un thread noyau (%s) alors '
                        'qu\'un binaire est mappé : %s'
                        % (comm, sanitize(exe_clean, 120)), 60))

    # --- Ligne de commande ---
    cmdline_raw = read_bytes('%s/cmdline' % proc_dir, limit=16384)
    cmdline = ''
    if cmdline_raw:
        cmdline = sanitize(cmdline_raw.decode('utf-8', 'replace').replace('\x00', ' '), 400)
        probe = cmdline.replace('"', '').replace("'", '').replace('\\', '')
        for pattern, label, weight in CMD_PATTERNS:
            if pattern.search(probe):
                score += weight
                reasons.append(('%s : %s' % (label, cmdline[:180]), weight))

    # --- Répertoire courant ---
    cwd = readlink('%s/cwd' % proc_dir) or ''
    if cwd.endswith(' (deleted)'):
        score += 20
        reasons.append(('Répertoire de travail supprimé : %s' % sanitize(cwd, 120), 20))
    elif any(cwd.startswith(z) for z in ('/tmp/', '/dev/shm/', '/var/tmp/')) and net_ctx:
        score += 20
        reasons.append(('Processus réseau travaillant depuis %s' % sanitize(cwd, 120), 20))

    # --- Statut : uid, capacités, ptrace ---
    status = parse_proc_status(pid)
    uid_field = status.get('Uid', '').split()
    ruid = uid_field[0] if uid_field else '?'
    euid = uid_field[1] if len(uid_field) > 1 else ruid

    if ruid != '?' and euid != '?' and ruid != euid and euid == '0':
        # sudo, su, pkexec, fusermount3, mount, ping... produisent tous
        # RUID != EUID = 0 par construction : c'est le mécanisme setuid, pas une
        # anomalie. Seul un binaire SANS bit setuid tournant en EUID=0 l'est.
        privilege = exe_privilege_state(pid)
        if privilege == 'plain':
            score += 45
            reasons.append(('EUID=0 (RUID=%s) alors que le binaire ne porte pas '
                            'le bit setuid : élévation obtenue autrement' % ruid, 45))

    if euid not in ('0', '?'):
        dangerous = caps_to_names(status.get('CapEff', '0'))
        if dangerous:
            weight = 45 if any(c in ('CAP_SYS_MODULE', 'CAP_SYS_ADMIN',
                                     'CAP_SYS_PTRACE', 'CAP_BPF') for c in dangerous) else 25
            score += weight
            reasons.append(('Capacités noyau anormales pour un non-root : %s'
                            % ', '.join(dangerous), weight))

    tracer = status.get('TracerPid', '0')
    if tracer not in ('0', ''):
        score += 30
        reasons.append(('Processus tracé par le PID %s (injection / debug actif)'
                        % tracer, 30))

    # --- Namespace réseau (informatif : conteneurs légitimes très fréquents) ---
    pid_netns = readlink('%s/ns/net' % proc_dir)
    isolated = bool(init_netns and pid_netns and pid_netns != init_netns)
    if isolated and net_ctx:
        score += 10
        reasons.append(('Namespace réseau isolé (conteneur) : %s' % pid_netns, 10))

    # --- Environnement (LD_PRELOAD & co) ---
    environ_raw = read_bytes('%s/environ' % proc_dir, limit=65536)
    if environ_raw:
        seen_env = set()
        for var in environ_raw.decode('utf-8', 'replace').split('\x00'):
            if '=' not in var:
                continue
            name, _, value = var.partition('=')
            name = name.strip()
            if name in seen_env:
                continue
            if name in ENV_CRITICAL and value.strip():
                seen_env.add(name)
                # On ne juge pas la variable sur son libellé mais sur la
                # bibliothèque effectivement chargée : provenance, propriétaire
                # et permissions. Firefox (libmozsandbox.so), snapd, NVIDIA ou
                # jemalloc préchargent légitimement depuis /usr/lib.
                for token in re.split(r'[:\s]+', value):
                    if not token.strip():
                        continue
                    verdict, resolved = classify_preloaded_lib(pid, token)
                    if verdict == 'system':
                        continue
                    if verdict == 'suspect':
                        weight = 70
                        detail = ('Injection de bibliothèque via %s : %s '
                                  '(hors chemin système, ou propriétaire / '
                                  'permissions anormaux)'
                                  % (name, sanitize(resolved or token, 160)))
                    else:
                        weight = 25
                        detail = ('%s=%s défini mais la bibliothèque n\'est pas '
                                  'mappée dans le processus (préchargement '
                                  'échoué ou effacé)'
                                  % (name, sanitize(token, 120)))
                    score += weight
                    reasons.append((detail, weight))
                    if resolved:
                        digest, _magic = sha256_path(resolved, args.max_file_size)
                        if digest:
                            hashes.append((digest, resolved,
                                           'bibliothèque préchargée'))
            elif name in ENV_WATCH and value.strip():
                probe = value.replace('"', '').replace("'", '')
                for pattern, label, weight in CMD_PATTERNS:
                    if pattern.search(probe):
                        seen_env.add(name)
                        score += min(weight, 50)
                        reasons.append(('Contenu suspect dans %s : %s'
                                        % (name, sanitize(value, 160)), min(weight, 50)))
                        break

    # --- Pondération contextuelle réseau ---
    if score > 0 and net_ctx:
        if public_egress:
            score += 20
            reasons.append(('Communication sortante vers une IP publique '
                            '(canal C2 potentiel)', 20))
        if public_listen:
            score += 15
            reasons.append(('Socket en écoute exposé hors loopback (backdoor ?)', 15))

    if score < SEV_MEDIUM:
        return None

    # --- Empreinte du binaire pour pivot CTI ---
    # /proc/<pid>/exe reste lisible même si le binaire a été supprimé : c'est
    # souvent la seule copie récupérable de l'implant.
    if exe_raw and not exe_clean.startswith(('/memfd:', 'memfd:')):
        digest, magic = sha256_path('%s/exe' % proc_dir, args.max_file_size,
                                    nofollow=False)
        if digest:
            hashes.append((digest, exe_clean or ('/proc/%s/exe' % pid),
                           'binaire du PID %s (%s)' % (pid, file_kind(magic))))

    return {
        'pid': pid,
        'comm': comm,
        'uid': ruid,
        'ppid': st['ppid'],
        'exe': sanitize(exe or 'introuvable', 200),
        'cmdline': cmdline or '(vide)',
        'net': net_ctx,
        'score': score,
        'reasons': reasons,
        'hashes': hashes,
        'netns': pid_netns,
    }


def enumerate_pids():
    pids = []
    try:
        with os.scandir('/proc') as entries:
            for entry in entries:
                if entry.name.isdigit():
                    pids.append(entry.name)
    except OSError:
        pass
    return pids


def map_network_namespaces(pids):
    """{ns_id: pid_representatif} — nécessite root pour les autres utilisateurs."""
    mapping = {}
    for pid in pids:
        ns = readlink('/proc/%s/ns/net' % pid)
        if ns and ns not in mapping:
            mapping[ns] = pid
    return mapping


def module_processes(args, is_root):
    out(C.cyan('[*] Étape 1/4 — Cartographie des namespaces et des sockets actifs'))
    pids = enumerate_pids()
    netns_map = map_network_namespaces(pids)
    init_netns = readlink('/proc/1/ns/net')
    sockets = collect_sockets(netns_map, is_root)
    out(C.grey('    %d processus visibles, %d namespace(s) réseau, %d socket(s) pertinents'
               % (len(pids), len(netns_map) or 1, len(sockets))))

    out(C.cyan('[*] Étape 2/4 — Corrélation PID <-> socket et scoring comportemental'))

    # Vérification d'intégrité groupée : la base de paquets n'est parcourue
    # qu'une fois pour l'ensemble des binaires en cours d'exécution.
    exes = set()
    for pid in pids:
        link = readlink('/proc/%s/exe' % pid)
        if link and not link.endswith(' (deleted)'):
            exes.add(link)
    pkg_verdicts = {} if args.no_pkgcheck else verify_against_packages(
        sorted(exes), args.max_file_size)
    if pkg_verdicts:
        anomalies = sum(1 for v in pkg_verdicts.values() if v != 'ok')
        out(C.grey('    %d binaire(s) confronté(s) à la base de paquets, '
                   '%d écart(s)' % (len(pkg_verdicts), anomalies)))

    hits = []
    for pid in pids:
        try:
            result = analyse_process(pid, sockets, init_netns, args, is_root,
                                     pkg_verdicts)
        except OSError:
            continue          # le processus a disparu pendant l'analyse
        if result:
            hits.append(result)

    hits.sort(key=lambda h: -h['score'])
    for hit in hits:
        label, painter = severity_label(hit['score'])
        title = ('[%s] PID %s (%s) — score %d'
                 % (label, hit['pid'], hit['comm'], hit['score']))
        details = [
            'PPID        : %s   UID : %s' % (hit['ppid'], hit['uid']),
            'Binaire     : %s' % hit['exe'],
            'Cmdline     : %s' % hit['cmdline'],
        ]
        if hit['net']:
            for conn in hit['net'][:8]:
                details.append('Connexion   : %s' % conn)
        else:
            details.append('Connexion   : aucune socket active')
        for reason, weight in hit['reasons']:
            details.append('Motif (+%-3d): %s' % (weight, reason))
        for digest, path, ctx in hit['hashes']:
            details.append('SHA256      : %s  (%s)' % (digest, ctx))
            REPORT.add_ioc(digest, path, ctx)
        REPORT.add(hit['score'], 'PROCESSUS', title, details)

    out(C.grey('    %d processus retenus au-dessus du seuil de bruit' % len(hits)))
    return pids, sockets


# ==========================================================================
# DÉTECTION DE ROOTKITS / DISSIMULATION
# ==========================================================================

def collect_all_tids(pids):
    tids = set(pids)
    for pid in pids:
        try:
            with os.scandir('/proc/%s/task' % pid) as entries:
                for entry in entries:
                    if entry.name.isdigit():
                        tids.add(entry.name)
        except OSError:
            continue
    return tids


def detect_hidden_pids(pids):
    """Un PID accessible par stat() mais absent du listing de /proc trahit un
    rootkit qui filtre getdents(). Double passe pour éliminer les processus
    créés pendant le scan (source majeure de faux positifs)."""
    known = collect_all_tids(pids)
    raw = read_text('/proc/sys/kernel/pid_max', limit=64)
    try:
        pid_max = int((raw or '32768').strip())
    except ValueError:
        pid_max = 32768
    limit = min(pid_max, MAX_PID_BRUTEFORCE)

    candidates = []
    for pid in range(1, limit + 1):
        spid = str(pid)
        if spid in known:
            continue
        try:
            os.stat('/proc/%s' % spid)
        except OSError:
            continue
        candidates.append(spid)

    if not candidates:
        return [], limit

    # Seconde passe : le processus est-il toujours invisible ET toujours vivant ?
    known2 = collect_all_tids(enumerate_pids())
    confirmed = []
    for spid in candidates:
        if spid in known2:
            continue
        try:
            os.stat('/proc/%s' % spid)
        except OSError:
            continue
        confirmed.append(spid)
    return confirmed, limit


def detect_module_mismatch():
    """Compare /proc/modules et /sys/module : un LKM masquant son entrée dans
    /proc/modules reste souvent visible dans sysfs."""
    proc_mods = set()
    content = read_text('/proc/modules', limit=1024 * 1024)
    if content is None:
        return None
    for line in content.splitlines():
        parts = line.split()
        if parts:
            proc_mods.add(parts[0])

    sys_mods = set()
    try:
        with os.scandir('/sys/module') as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    # Un module chargé possède un répertoire 'initstate'.
                    if os.path.exists('/sys/module/%s/initstate' % entry.name):
                        sys_mods.add(entry.name)
    except OSError:
        return None
    return proc_mods, sys_mods


def detect_partial_proc_view():
    """Un /proc partiel (conteneur, namespace PID tiers) produit des sockets
    sans propriétaire apparent : il faut le savoir avant de crier au rootkit."""
    hints = []
    if os.path.exists('/.dockerenv'):
        hints.append('/.dockerenv présent')
    cgroup = read_text('/proc/1/cgroup', limit=65536) or ''
    if re.search(r'docker|kubepods|containerd|lxc|libpod|garden', cgroup, re.I):
        hints.append('cgroup de PID 1 de type conteneur')
    init_pidns = readlink('/proc/1/ns/pid')
    self_pidns = readlink('/proc/self/ns/pid')
    if init_pidns and self_pidns and init_pidns != self_pidns:
        hints.append('namespace PID distinct de celui de PID 1')
    comm = read_text('/proc/1/comm', limit=256) or ''
    if comm.strip() not in ('systemd', 'init', 'upstart', 'openrc-init', 'runit', ''):
        hints.append('PID 1 atypique (%s)' % sanitize(comm, 32))
    return hints


def module_verify_system(args):
    """Confrontation exhaustive des binaires système à la base de paquets.
    Optionnelle : coûteuse en I/O, mais c'est le seul contrôle qui détecte un
    binaire de distribution trojanisé qui n'est pas en cours d'exécution."""
    out(C.cyan('[*] Étape complémentaire — Intégrité des binaires système'))
    seen = set()
    targets = []
    for base in ('/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/libexec'):
        stack = [(base, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 2:
                continue
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            for entry in entries:
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if entry.name not in SKIP_DIR_NAMES:
                        stack.append((entry.path, depth + 1))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                try:
                    key = (st.st_dev, st.st_ino)
                except AttributeError:
                    key = entry.path
                if key in seen:
                    continue        # usr-merge : /bin/x et /usr/bin/x
                seen.add(key)
                targets.append((entry.path, st))

    verdicts = verify_against_packages([p for p, _ in targets],
                                       args.max_file_size)
    if not verdicts:
        out(C.grey('    Base de paquets indisponible (hôte non dpkg) : '
                   'contrôle ignoré'))
        return

    anomalies = 0
    for path, st in targets:
        verdict = verdicts.get(path)
        if verdict in (None, 'ok'):
            continue
        anomalies += 1
        digest, magic = sha256_path(path, args.max_file_size)
        score = 80 if verdict == 'modifie' else 40
        reasons = ['Binaire de distribution MODIFIÉ (contenu différent de '
                   'l\'empreinte du paquet)' if verdict == 'modifie' else
                   'Fichier dans un chemin système revendiqué par aucun '
                   'paquet installé']
        details = [
            'Type        : %s   Taille : %s   Mode : %s'
            % (file_kind(magic), fmt_size(st.st_size), oct(st.st_mode & 0o7777)),
            'Modifié le  : %s' % fmt_time(st.st_mtime),
        ] + ['Motif       : %s' % r for r in reasons]
        if digest:
            details.append('SHA256      : %s' % digest)
            REPORT.add_ioc(digest, path, 'binaire système %s' % verdict)
        label, _painter = severity_label(score)
        REPORT.add(score, 'INTEGRITE',
                   '[%s] %s — score %d' % (label, sanitize(path, 200), score),
                   details)
    out(C.grey('    %d binaire(s) vérifié(s), %d écart(s)'
               % (len(verdicts), anomalies)))


def module_rootkit(pids, sockets, is_root):
    out(C.cyan('[*] Étape 3/4 — Recherche d\'indicateurs de dissimulation (rootkit)'))

    # 1. Processus cachés
    hidden, scanned = detect_hidden_pids(pids)
    if hidden:
        details = ['Plage inspectée : PID 1 à %d' % scanned]
        for spid in hidden[:20]:
            st = parse_proc_stat(spid)
            comm = sanitize(st['comm'], 48) if st else '?'
            exe = sanitize(readlink('/proc/%s/exe' % spid) or 'inconnu', 160)
            details.append('PID caché %s (%s) — binaire : %s' % (spid, comm, exe))
            digest, magic = sha256_path('/proc/%s/exe' % spid, DEFAULT_MAX_HASH_SIZE,
                                        nofollow=False)
            if digest:
                details.append('SHA256      : %s  (%s)' % (digest, file_kind(magic)))
                REPORT.add_ioc(digest, exe, 'binaire de processus caché PID %s' % spid)
        REPORT.add(85, 'ROOTKIT',
                   '[CRITIQUE] %d processus invisible(s) dans le listing de /proc'
                   % len(hidden), details)

    # 2. Modules noyau masqués
    mods = detect_module_mismatch()
    if mods:
        proc_mods, sys_mods = mods
        ghosts = sorted(sys_mods - proc_mods)
        if ghosts:
            REPORT.add(80, 'ROOTKIT',
                       '[CRITIQUE] Module(s) noyau présent(s) dans sysfs mais absent(s) '
                       'de /proc/modules',
                       ['Module masqué : %s' % sanitize(m, 64) for m in ghosts[:20]])

    # 3. Taint flags
    tainted = read_text('/proc/sys/kernel/tainted', limit=64)
    if tainted:
        try:
            flags = int(tainted.strip())
        except ValueError:
            flags = 0
        marks = []
        if flags & (1 << 0):
            marks.append('module propriétaire chargé (bit 0)')
        if flags & (1 << 12):
            marks.append('module hors-arbre chargé (bit 12)')
        if flags & (1 << 13):
            marks.append('module non signé chargé (bit 13)')
        if flags & (1 << 5):
            marks.append('erreur machine détectée (bit 5)')
        if marks:
            REPORT.add(35, 'ROOTKIT',
                       '[MOYEN] Noyau marqué "tainted" (valeur %d)' % flags,
                       marks + ['Corréler avec la liste des modules chargés et '
                                'la politique de signature de l\'hôte.'])

    # 4. Sockets sans processus propriétaire (root uniquement : sinon les fd
    #    des autres utilisateurs sont illisibles et tout remonterait en FP).
    if is_root:
        owned = set()
        for pid in pids:
            owned |= process_socket_inodes(pid)
        partial_view = detect_partial_proc_view()
        orphans = []
        for inode, info in sockets.items():
            if inode in owned:
                continue
            if info['proto'].startswith('udp'):
                continue
            if info['state'] not in ('ESTABLISHED', 'LISTEN'):
                continue
            # Un socket vu dans un namespace réseau tiers appartient par
            # construction à un processus potentiellement hors de notre vue.
            if info.get('netns', 'host') != 'host':
                continue
            orphans.append('%s %s %s -> %s (inode %s, uid %s)' % (
                info['proto'].upper(), info['state'], info['local'],
                info['remote'], inode, info['uid']))
        if orphans:
            score = 40 if partial_view else 65
            label = 'MOYEN' if partial_view else 'ELEVE'
            notes = ['Un processus dissimulé ou un handler noyau peut détenir '
                     'ces sockets.']
            if partial_view:
                notes.append('ATTENUATION : vue partielle de /proc détectée (%s). '
                             'Des processus légitimes hors de ce namespace PID '
                             'expliquent probablement ces sockets — rejouer '
                             'depuis l\'hôte pour trancher.'
                             % ', '.join(partial_view))
            REPORT.add(score, 'ROOTKIT',
                       '[%s] %d socket(s) TCP actif(s) sans processus propriétaire '
                       'identifiable' % (label, len(orphans)),
                       orphans[:20] + notes)
    else:
        out(C.grey('    Corrélation des sockets orphelins ignorée (nécessite root)'))

    # 5. /etc/ld.so.preload
    preload = read_text('/etc/ld.so.preload', limit=65536)
    if preload and preload.strip():
        digest, _magic = sha256_path('/etc/ld.so.preload', DEFAULT_MAX_HASH_SIZE)
        details = ['Contenu : %s' % sanitize(preload, 300)]
        if digest:
            details.append('SHA256      : %s' % digest)
            REPORT.add_ioc(digest, '/etc/ld.so.preload', 'fichier de préchargement global')
        for lib in preload.split():
            lib = lib.strip()
            if lib and os.path.isabs(lib):
                ldigest, lmagic = sha256_path(lib, DEFAULT_MAX_HASH_SIZE)
                if ldigest:
                    details.append('SHA256      : %s  (%s, %s)'
                                   % (ldigest, sanitize(lib, 120), file_kind(lmagic)))
                    REPORT.add_ioc(ldigest, lib, 'bibliothèque préchargée globalement')
        REPORT.add(75, 'ROOTKIT',
                   '[CRITIQUE] /etc/ld.so.preload est présent et non vide '
                   '(hooking userland global)', details)

    out(C.grey('    Contrôles de dissimulation terminés'))


# ==========================================================================
# CHASSE SUR LE SYSTÈME DE FICHIERS
# ==========================================================================

def build_hunt_roots(is_root, extra_dirs):
    """Répertoires de prédilection des malwares Linux, adaptés au privilège."""
    roots = []

    def push(path, depth, cap, tag):
        if os.path.isdir(path):
            roots.append({'path': path, 'depth': depth, 'cap': cap, 'tag': tag})

    for path in ('/tmp', '/var/tmp', '/dev/shm', '/run/shm', '/dev/mqueue'):
        push(path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES_PER_ROOT, 'monde-inscriptible')

    push('/dev', 3, 4000, 'périphériques')
    for path in ('/usr/local/bin', '/usr/local/sbin', '/usr/local/lib', '/opt'):
        push(path, 3, 3000, 'installation locale')
    for path in PERSISTENCE_DIRS:
        push(path, 2, 500, 'persistance')
    push('/var/www', 4, 4000, 'exposé web')
    push('/srv', 4, 4000, 'exposé service')
    push('/var/lib', 4, 5000, 'staging système')
    push('/var/cache', 3, 3000, 'staging système')
    push('/usr/share', 3, 5000, 'staging système')

    # Répertoires utilisateurs
    homes = []
    if is_root:
        passwd = read_text('/etc/passwd', limit=1024 * 1024) or ''
        for line in passwd.splitlines():
            parts = line.split(':')
            if len(parts) >= 6:
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                home = parts[5]
                if (uid == 0 or uid >= 1000) and home.startswith('/') \
                        and home not in ('/', '/nonexistent', '/dev/null'):
                    homes.append(home)
    else:
        home = os.path.expanduser('~')
        if home.startswith('/'):
            homes.append(home)

    for home in sorted(set(homes)):
        push(home, 1, 800, 'racine du home')
        for sub in ('.local/share', '.local/bin', '.ssh', '.cache',
                    'bin', '.fonts', '.themes'):
            push(os.path.join(home, sub), 4, 3000, 'home caché')
        # Persistance graphique et systemd côté utilisateur
        for sub in ('.config/autostart', '.config/systemd/user',
                    '.config/environment.d', '.local/share/systemd/user',
                    '.config/upstart'):
            push(os.path.join(home, sub), 3, 500, 'persistance')
        push(os.path.join(home, '.config'), 4, 3000, 'home caché')

    # Sessions utilisateurs (tmpfs volatil, très prisé des implants)
    try:
        with os.scandir('/run/user') as entries:
            for entry in entries:
                if entry.name.isdigit():
                    push(entry.path, 3, 2000, 'session tmpfs')
    except OSError:
        pass

    for path in extra_dirs or []:
        push(path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES_PER_ROOT, 'fourni par l\'analyste')

    # Déduplication par chemin réel
    seen = set()
    unique = []
    for root in roots:
        key = os.path.realpath(root['path'])
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


SKIP_DIR_NAMES = {
    'docker', 'containerd', 'overlay2', 'snapd', 'flatpak', 'libvirt',
    'apt', 'dpkg', 'rpm', 'man-db', 'locales', 'fontconfig', 'doc', 'icons',
    'node_modules', '.git', '.svn', '__pycache__', 'site-packages',
    'dist-packages', '.cargo', '.rustup', '.nvm', '.npm', '.m2', '.gradle',
    'mozilla', 'chromium', 'google-chrome', 'BraveSoftware', 'thunderbird',
}
SKIP_ABS_DIRS = {'/proc', '/sys', '/dev/pts', '/dev/fd', '/run/systemd/inaccessible'}

try:
    SELF_PATH = os.path.realpath(os.path.abspath(__file__))
except (NameError, OSError):
    SELF_PATH = ''


# Artefacts de session X11/XFCE/PulseAudio, créés à chaque ouverture de
# session dans /tmp. Écartés uniquement s'ils sont inertes : données pures,
# non exécutables et de petite taille. Un fichier ELF ou un script portant
# l'un de ces noms reste signalé (technique de mimétisme connue).
BENIGN_SESSION_FILES = re.compile(
    r'^\.(X\d+-lock|ICEauthority|Xauthority|xfsm-ICE-[A-Za-z0-9]{4,10}|'
    r'esd-\d+|pulse-[A-Za-z0-9]+|wl-[A-Za-z0-9-]+|xdg-[A-Za-z0-9-]+)$')
BENIGN_SESSION_MAX = 64 * 1024


def score_file(entry_path, st, magic, root_tag, name):
    """Pondération d'un artefact fichier. Retourne (score, [(motif, poids)]) —
    chaque motif porte son poids individuel pour permettre une fusion sans
    double comptage lorsque plusieurs détections convergent sur un même
    chemin réel (cf. dédoublonnage dans module_filesystem)."""
    score = 0
    reasons = []
    hidden = name.startswith('.')
    kind = file_kind(magic)

    if (BENIGN_SESSION_FILES.match(name) and kind == 'DATA'
            and not st.st_mode & 0o111 and st.st_size < BENIGN_SESSION_MAX):
        return 0, []
    executable = bool(st.st_mode & 0o111)
    in_tmp = any(entry_path.startswith(z) for z in
                 ('/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/', '/dev/mqueue/'))

    if st.st_mode & stat.S_ISUID:
        # Un SUID en zone monde-inscriptible ou cachée est une porte dérobée ;
        # dans /usr/local/bin ou /opt, c'est le plus souvent un outil
        # d'administration légitime — à lister, pas à qualifier de critique.
        if in_tmp or hidden or path_is_hidden(entry_path):
            score += 70
            reasons.append(('Bit SUID en zone monde-inscriptible ou cachée '
                            '(propriétaire UID %d)' % st.st_uid, 70))
        else:
            score += 30
            reasons.append(('Bit SUID hors des chemins système de la distribution '
                            '(propriétaire UID %d) — à confronter à la baseline'
                            % st.st_uid, 30))
    if st.st_mode & stat.S_ISGID and executable:
        score += 35
        reasons.append(('Bit SGID positionné (groupe GID %d)' % st.st_gid, 35))

    if kind == 'ELF':
        if in_tmp:
            score += 60
            reasons.append(('Binaire ELF dans un répertoire temporaire', 60))
        elif hidden:
            score += 55
            reasons.append(('Binaire ELF portant un nom caché', 55))
        elif entry_path.startswith('/dev/'):
            score += 70
            reasons.append(('Binaire ELF stocké sous /dev', 70))
        elif root_tag in ('exposé web', 'exposé service'):
            score += 45
            reasons.append(('Binaire ELF dans une arborescence exposée', 45))
        else:
            score += 20
            reasons.append(('Binaire ELF hors chemin système standard', 20))
    elif kind == 'SCRIPT' and (in_tmp or hidden) and executable:
        score += 35
        reasons.append(('Script exécutable %s' % ('caché' if hidden else 'temporaire'), 35))
    elif executable and in_tmp:
        score += 30
        reasons.append(('Fichier exécutable dans un répertoire temporaire', 30))
    elif hidden and in_tmp:
        score += 25
        reasons.append(('Fichier caché dans un répertoire temporaire', 25))

    if entry_path.startswith('/dev/') and stat.S_ISREG(st.st_mode) \
            and not entry_path.startswith(('/dev/shm/', '/dev/mqueue/')) \
            and not is_benign_device_node(entry_path):
        score += 45
        reasons.append(('Fichier régulier sous /dev (hors tmpfs légitime)', 45))

    # Noms de dissimulation classiques
    if re.match(r'^\.{2,}$|^\s|\s$|^\.\s', name) or '\u200b' in name or '\u202e' in name:
        score += 40
        reasons.append(('Nom de fichier conçu pour la dissimulation visuelle', 40))
    if re.match(r'^\.(X11|ICE|font|Test|cache)-?(unix|lock)?$', name) and stat.S_ISREG(st.st_mode):
        score += 30
        reasons.append(('Nom mimant un socket système classique', 30))

    # Clés SSH et cron : persistance
    if name == 'authorized_keys':
        score += 30
        reasons.append(('Point de persistance SSH — vérifier chaque clé', 30))

    return score, reasons


def scan_root(root, args, budget):
    """Parcours borné, sans franchir de point de montage, sans suivre de lien."""
    findings = []
    base = root['path']
    try:
        base_st = os.lstat(base)
    except OSError:
        return findings
    base_dev = base_st.st_dev
    seen_files = 0
    stack = [(base, 0)]

    while stack:
        current, depth = stack.pop()
        if depth > root['depth'] or seen_files >= root['cap'] or budget['left'] <= 0:
            continue
        if os.path.realpath(current) in SKIP_ABS_DIRS:
            continue
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue

        for entry in entries:
            if seen_files >= root['cap'] or budget['left'] <= 0:
                break
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            if st.st_dev != base_dev:
                continue                     # ne franchit pas les montages
            name = entry.name

            if stat.S_ISDIR(st.st_mode):
                if name in SKIP_DIR_NAMES:
                    continue
                stack.append((entry.path, depth + 1))
                continue

            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                # FIFO, socket, device : jamais ouverts, mais un device inattendu
                # dans /tmp mérite d'être signalé.
                if (stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode)) \
                        and not entry.path.startswith('/dev/') \
                        and not is_benign_device_node(entry.path):
                    findings.append({
                        'path': entry.path, 'st': st, 'score': 55,
                        'reasons': ['Fichier de périphérique hors de /dev'],
                        'digest': None, 'kind': 'DEVICE',
                    })
                continue

            seen_files += 1
            budget['left'] -= 1

            # Le scanner ne se dénonce pas lui-même : sa table d'IoC déclenche
            # ses propres règles de contenu.
            if SELF_PATH and os.path.realpath(entry.path) == SELF_PATH:
                continue

            # Pré-filtre bon marché avant toute lecture : on ne lit un fichier
            # que s'il est un candidat plausible.
            hidden = name.startswith('.')
            executable = bool(st.st_mode & 0o111)
            in_tmp = any(entry.path.startswith(z) for z in
                         ('/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/',
                          '/dev/mqueue/', '/dev/'))
            special = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
            persistence = (root['tag'] == 'persistance'
                           or name in SHELL_RC_NAMES
                           or name == 'authorized_keys')
            if not (hidden or executable or in_tmp or special or persistence):
                continue
            if st.st_size == 0 and not special:
                continue

            magic = read_bytes(entry.path, limit=8, require_regular=True) or b''
            score, reasons = score_file(entry.path, st, magic, root['tag'], name)

            # Contenu des scripts déposés en zone temporaire : un dropper y est
            # souvent en clair et doit remonter en CRITIQUE, pas en MOYEN.
            if (file_kind(magic) == 'SCRIPT' or name.endswith(
                    ('.sh', '.py', '.pl', '.php', '.rb'))) \
                    and in_tmp and st.st_size < CONTENT_SCAN_MAX:
                content = read_text(entry.path, limit=CONTENT_SCAN_MAX) or ''
                probe = content[:REGEX_PROBE_LIMIT].replace('"', '').replace("'", '')
                matches = [(w, l) for pat, l, w in CMD_PATTERNS if pat.search(probe)]
                # Un dropper est court et concentre 1 ou 2 techniques. Un fichier
                # qui les cumule toutes est presque toujours une liste d'IoC, une
                # cheat-sheet ou un outil de détection (celui-ci y compris) :
                # le signaler serait un faux positif systématique.
                if len(matches) >= IOC_LIST_THRESHOLD:
                    reasons.append(('Cumule %d techniques distinctes : signature '
                                    'd\'une liste d\'IoC ou d\'un outil de sécurité, '
                                    'non scoré' % len(matches), 0))
                elif matches:
                    weight, label = max(matches)
                    score += weight
                    reasons.append(('Contenu du script — %s' % label, weight))

            if persistence and st.st_size < CONTENT_SCAN_MAX:
                content = (read_text(entry.path, limit=CONTENT_SCAN_MAX)
                           or '')[:REGEX_PROBE_LIMIT]
                # Un fichier appartenant à root et non inscriptible par un
                # tiers vient presque toujours de la distribution : les
                # signaux faibles y sont du bruit, les signaux forts non.
                distro_owned = (st.st_uid == 0
                                and not st.st_mode & stat.S_IWOTH
                                and not entry.path.startswith(('/home/', '/root/')))
                label = ('Fichier de démarrage shell'
                         if name in SHELL_RC_NAMES else 'Point de persistance')

                # /etc/ld.so.conf.d ne doit contenir que des répertoires de
                # bibliothèques système : un chemin ailleurs redirige l'éditeur
                # de liens de TOUS les binaires de l'hôte.
                if '/ld.so.conf' in entry.path:
                    for raw in content.splitlines():
                        candidate = raw.split('#', 1)[0].strip()
                        # Comparaison sur le chemin normalisé : libc.conf
                        # déclare '/usr/local/lib' sans slash final.
                        normalized = candidate.rstrip('/') + '/'
                        if (candidate.startswith('/')
                                and not normalized.startswith(LIB_TRUSTED_PREFIX)):
                            score += 65
                            reasons.append(('Chemin de bibliothèque hors '
                                            'arborescence système déclaré à '
                                            'l\'éditeur de liens : %s'
                                            % sanitize(candidate, 100), 65))
                            break
                if PERSISTENCE_STRONG.search(content):
                    score += 60
                    reasons.append(('%s — shell distant, décodage exécuté ou '
                                    'anti-forensic dans le contenu' % label, 60))
                elif PERSISTENCE_MEDIUM.search(content):
                    weight = 20 if distro_owned else 45
                    score += weight
                    reasons.append(('%s — référence à une zone monde-inscriptible'
                                    % label, weight))
                elif PERSISTENCE_WEAK.search(content) and not distro_owned:
                    score += 30
                    reasons.append(('%s non maîtrisé appelant réseau/décodage '
                                    '(propriétaire UID %d)' % (label, st.st_uid), 30))

            if score < args.min_file_score:
                continue

            digest = None
            if not args.no_hash:
                if budget['hash_left'] > 0:
                    budget['hash_left'] -= 1
                    digest, magic2 = sha256_path(entry.path, args.max_file_size)
                    if magic2 and not magic:
                        magic = magic2
                else:
                    budget['hash_skipped'] += 1
                    digest = 'NON-CALCULE (plafond de hachage atteint)'

            findings.append({
                'path': entry.path, 'st': st, 'score': score,
                'reasons': reasons, 'digest': digest, 'kind': file_kind(magic),
            })
    return findings


def interpreter_hashes(max_size):
    """Empreintes des interpréteurs présents sur l'hôte."""
    known = {}
    for path in INTERPRETER_PATHS:
        digest, _magic = sha256_path(path, max_size, nofollow=False)
        if digest and len(digest) == 64:
            known[digest] = path
    return known


def sweep_setuid_binaries(args):
    """Recherche ciblée des binaires SUID/SGID dans les chemins système, puis
    confrontation à la base de paquets et aux empreintes d'interpréteurs.
    Les SUID légitimes (sudo, mount, passwd...) sont revendiqués par un paquet
    et ne produisent aucun constat."""
    candidates = []
    for base in SETUID_SWEEP_DIRS:
        stack = [(base, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 2:
                continue
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            for entry in entries:
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if entry.name not in SKIP_DIR_NAMES:
                        stack.append((entry.path, depth + 1))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    candidates.append((entry.path, st))

    if not candidates:
        return []

    # --no-hash promet de n'empreinter aucun fichier : la détection par
    # empreinte (contenu = interpréteur connu) et la confrontation à la base
    # de paquets (qui nécessite un MD5 du candidat) sont donc désactivées,
    # au profit d'un simple pic de magie 8 octets pour garder un 'kind'
    # correct. Les signaux qui ne nécessitent aucune lecture de contenu
    # (inscriptible par tous) restent actifs.
    do_hash = not args.no_hash
    verdicts = ({} if (args.no_pkgcheck or not do_hash)
                else verify_against_packages([p for p, _ in candidates],
                                             args.max_file_size))
    shells = interpreter_hashes(args.max_file_size) if do_hash else {}
    findings = []
    for path, st in candidates:
        score = 0
        reasons = []
        if do_hash:
            digest, magic = sha256_path(path, args.max_file_size)
        else:
            digest = None
            magic = read_bytes(path, limit=8, require_regular=True) or b''

        if digest and digest in shells:
            score += 90
            reasons.append(('Binaire SUID/SGID dont le contenu est un '
                            'interpréteur (%s) : porte dérobée d\'élévation'
                            % shells[digest], 90))
        verdict = verdicts.get(path)
        if verdict == 'modifie':
            score += 80
            reasons.append(('Binaire SUID/SGID de distribution MODIFIÉ', 80))
        elif verdict == 'hors-paquet':
            score += 50
            reasons.append(('Binaire SUID/SGID dans un chemin système mais '
                            'revendiqué par aucun paquet installé', 50))
        if st.st_mode & stat.S_IWOTH:
            score += 60
            reasons.append(('Binaire SUID/SGID inscriptible par tous', 60))

        if score < args.min_file_score:
            continue
        findings.append({'path': path, 'st': st, 'score': score,
                         'reasons': reasons, 'digest': digest,
                         'kind': file_kind(magic)})
    return findings


def sweep_untracked_system_binaries(args):
    """Confrontation légère et NON récursive des répertoires binaires système
    principaux à la base de paquets, exécutée par défaut (contrairement à
    --verify-system, coûteux et optionnel). Ferme l'angle mort d'un implant
    posé directement dans /usr/bin/, /usr/sbin/, /bin/ ou /sbin/ sans bit
    SUID et sans être en cours d'exécution : jusqu'ici invisible sauf à
    penser explicitement à --verify-system. --no-hash désactive ce contrôle
    (il nécessite de lire chaque binaire candidat pour le comparer à son
    empreinte de paquet) ; --no-pkgcheck aussi."""
    if args.no_pkgcheck or args.no_hash:
        return []
    seen = set()
    targets = []
    for base in PRIMARY_SYSTEM_BIN_DIRS:
        try:
            entries = list(os.scandir(base))
        except OSError:
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                key = (st.st_dev, st.st_ino)
            except AttributeError:
                key = entry.path
            if key in seen:
                continue          # usr-merge : /bin/x et /usr/bin/x
            seen.add(key)
            targets.append((entry.path, st))

    if not targets:
        return []
    verdicts = verify_against_packages([p for p, _ in targets], args.max_file_size)
    if not verdicts:
        return []              # hôte non-dpkg : contrôle silencieusement ignoré

    findings = []
    for path, st in targets:
        verdict = verdicts.get(path)
        if verdict in (None, 'ok'):
            continue
        # 'modifie' (empreinte divergente) reste un signal fort et rare :
        # poids inchangé par rapport à --verify-system. 'hors-paquet' est en
        # revanche courant et légitime sur une image Docker officielle
        # (/usr/sbin/policy-rc.d, /usr/bin/pebble, /usr/sbin/initctl... des
        # utilitaires ajoutés par l'outillage de construction de l'image,
        # jamais par un paquet) : le signaler par défaut au même poids que
        # --verify-system (45, au-dessus du seuil d'affichage) noierait le
        # résultat dans le bruit sur des hôtes parfaitement sains. Poids
        # réduit ici pour rester silencieux par défaut (INFO, sous le seuil
        # d'AFFICHAGE — le seuil de RETENTION par défaut reste franchi, donc
        # l'empreinte demeure dans la table de pivot CTI) ; --verify-system,
        # explicitement demandé, garde le poids plein (45).
        score = 80 if verdict == 'modifie' else 25
        reason = ('Binaire de distribution MODIFIÉ (contenu différent de '
                  'l\'empreinte du paquet)' if verdict == 'modifie' else
                  'Fichier dans un chemin système revendiqué par aucun '
                  'paquet installé')
        if score < args.min_file_score:
            continue
        digest, magic = sha256_path(path, args.max_file_size)
        findings.append({'path': path, 'st': st, 'score': score,
                         'reasons': [(reason, score)], 'digest': digest,
                         'kind': file_kind(magic)})
    return findings


def hash_persistence_files():
    results = []
    for path in PERSISTENCE_FILES:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        digest, magic = sha256_path(path, DEFAULT_MAX_HASH_SIZE)
        if digest:
            results.append((digest, path, st, file_kind(magic)))
    return results


def _digest_rank(digest):
    """Ordonne les empreintes candidates lors d'une fusion : un SHA256 réel
    prime sur un marqueur 'NON-CALCULE (...)' , qui prime sur une absence."""
    if digest and re.fullmatch(r'[0-9a-f]{64}', digest):
        return 2
    if digest:
        return 1
    return 0


def module_filesystem(args, is_root):
    out(C.cyan('[*] Étape 4/4 — Chasse aux artefacts sur les répertoires à risque'))
    roots = build_hunt_roots(is_root, args.extra_dir)
    out(C.grey('    %d racine(s) inspectée(s) — profondeur max %d, budget %d fichiers'
               % (len(roots), DEFAULT_MAX_DEPTH, GLOBAL_FILE_BUDGET)))

    budget = {'left': GLOBAL_FILE_BUDGET,
              'hash_left': 0 if args.no_hash else args.max_hash_files,
              'hash_skipped': 0}
    raw_findings = []
    for root in roots:
        raw_findings.extend(scan_root(root, args, budget))
    raw_findings.extend(sweep_setuid_binaries(args))
    raw_findings.extend(sweep_untracked_system_binaries(args))

    # Deux racines peuvent couvrir le même fichier (/root et /root/.ssh), ou
    # deux détections différentes converger sur le même chemin (heuristique
    # générique de score_file + empreinte d'interpréteur de
    # sweep_setuid_binaries) : fusion par texte de motif plutôt que
    # remplacement par le seul score le plus haut, pour ne jamais faire
    # disparaître un motif décisif (ex. « ce SUID est un shell renommé »)
    # simplement parce qu'une autre détection, moins précise, marquait un
    # score plus élevé sur ce même fichier. Un motif au texte identique
    # (cas des racines qui se recouvrent) n'est compté qu'une fois.
    unique = {}
    for item in raw_findings:
        try:
            key = os.path.realpath(item['path'])
        except OSError:
            key = item['path']
        previous = unique.get(key)
        if previous is None:
            unique[key] = dict(item)
            continue
        merged_reasons = dict(previous['reasons'])
        for text, weight in item['reasons']:
            merged_reasons.setdefault(text, weight)
        previous['reasons'] = list(merged_reasons.items())
        previous['score'] = sum(merged_reasons.values())
        if _digest_rank(item['digest']) > _digest_rank(previous['digest']):
            previous['digest'] = item['digest']
            previous['kind'] = item['kind']
    all_findings = list(unique.values())

    all_findings.sort(key=lambda f: -f['score'])
    truncated = max(0, len(all_findings) - args.max_file_findings)
    if truncated:
        REPORT.add(SEV_MEDIUM, 'FICHIER',
                   '[MOYEN] Restitution tronquée : %d artefact(s) supplémentaire(s) '
                   'non détaillé(s)' % truncated,
                   ['Les %d artefacts les mieux notés sont détaillés ci-dessus.'
                    % args.max_file_findings,
                    'Un volume aussi élevé traduit en général une arborescence '
                    'bruyante (serveur de build, /tmp partagé) plutôt qu\'une '
                    'compromission massive.',
                    'Cibler avec --extra-dir, remonter --min-file-score, ou '
                    'relever --max-file-findings pour tout voir.'])
    if budget['hash_skipped']:
        REPORT.add(SEV_MEDIUM, 'FICHIER',
                   '[MOYEN] Plafond de hachage atteint : %d fichier(s) non '
                   'empreinté(s)' % budget['hash_skipped'],
                   ['Plafond courant : %d fichiers (--max-hash-files).'
                    % args.max_hash_files])
    for item in all_findings[:args.max_file_findings]:
        st = item['st']
        label, _painter = severity_label(item['score'])
        title = '[%s] %s — score %d' % (label, sanitize(item['path'], 200), item['score'])
        details = [
            'Type        : %s   Taille : %s   Mode : %s'
            % (item['kind'], fmt_size(st.st_size), oct(st.st_mode & 0o7777)),
            'Propriétaire: UID %d / GID %d' % (st.st_uid, st.st_gid),
            'Modifié le  : %s   (ctime %s)' % (fmt_time(st.st_mtime), fmt_time(st.st_ctime)),
        ]
        for reason, weight in sorted(item['reasons'], key=lambda r: -r[1]):
            details.append('Motif (+%-3d): %s' % (weight, reason))
        if item['digest'] and item['digest'].startswith('NON-CALCULE'):
            details.append('SHA256      : %s — relancer avec --max-file-size '
                           'pour empreinter cet artefact' % item['digest'])
        elif item['digest']:
            details.append('SHA256      : %s' % item['digest'])
            REPORT.add_ioc(item['digest'], item['path'], 'artefact %s' % item['kind'])
        elif not args.no_hash:
            details.append('SHA256      : non calculable (lecture refusée)')
        REPORT.add(item['score'], 'FICHIER', title, details)

    # Fichiers de persistance systématiquement empreintés (valeur CTI/baseline)
    for digest, path, st, kind in hash_persistence_files():
        REPORT.add_ioc(digest, path, 'fichier de persistance (référence)')
        REPORT.add(SEV_MEDIUM - 5, 'PERSISTANCE',
                   '[INFO] Empreinte de référence : %s' % path,
                   ['Type        : %s   Modifié le : %s' % (kind, fmt_time(st.st_mtime)),
                    'SHA256      : %s' % digest])

    out(C.grey('    %d artefact(s) retenu(s), %d fichier(s) empreinté(s)'
               % (len(all_findings), _STATS['hashed'])))


# ==========================================================================
# RESTITUTION
# ==========================================================================

def render(args, is_root, elapsed):
    out('')
    out(C.yellow('=' * 78))
    out(C.bold('  RESULTATS'))
    out(C.yellow('=' * 78))

    findings = REPORT.sorted_findings(args.min_score)
    if not findings:
        out(C.green('[+] Aucun indicateur au-dessus du seuil %d.' % args.min_score))
        out(C.grey('    Absence de détection != absence de compromission : ce script '
                   'ne couvre ni la mémoire noyau ni les journaux.'))
    else:
        by_cat = {}
        for finding in findings:
            by_cat.setdefault(finding['category'], []).append(finding)
        for category in ('ROOTKIT', 'PROCESSUS', 'INTEGRITE', 'FICHIER',
                         'PERSISTANCE'):
            items = by_cat.get(category)
            if not items:
                continue
            out('')
            out(C.bold('--- %s (%d) ---' % (category, len(items))))
            for finding in items:
                _label, painter = severity_label(finding['score'])
                out('')
                out(painter(finding['title']))
                for line in finding['details']:
                    out('    %s' % line)

    # Table IoC : le livrable directement exploitable en CTI
    if REPORT.iocs:
        out('')
        out(C.yellow('=' * 78))
        out(C.bold('  EMPREINTES SHA256 COLLECTEES (pivot CTI)'))
        out(C.yellow('=' * 78))
        out(C.grey('Inclut les artefacts retenus sous le seuil d\'affichage : '
                   'soumettre l\'ensemble aux sources CTI avant de conclure.'))
        for digest, path, ctx in REPORT.iocs[:MAX_IOC_ROWS]:
            out('%s  %s' % (digest, sanitize(path, 150)))
            out(C.grey('%s  %s' % (' ' * 64, ctx)))
        if len(REPORT.iocs) > MAX_IOC_ROWS:
            out(C.grey('... %d empreinte(s) supplémentaire(s) non affichée(s).'
                       % (len(REPORT.iocs) - MAX_IOC_ROWS)))

    out('')
    out(C.yellow('-' * 78))
    out('Durée : %.1fs | Fichiers empreintés : %d (%s) | Lectures refusées : %d'
        % (elapsed, _STATS['hashed'], fmt_size(_STATS['hash_bytes']),
           _STATS['read_denied']))
    out('Ouvertures O_NOATIME : %d | Repli sans O_NOATIME (atime modifié) : %d'
        % (_STATS['noatime_ok'], _STATS['noatime_fallback']))
    if not is_root:
        out(C.grey('Périmètre partiel : namespaces, fd des autres utilisateurs, '
                   'environ distant et homes tiers non lisibles en utilisateur standard.'))
    out(C.yellow('-' * 78))


# ==========================================================================
# BANNIÈRE, AVERTISSEMENT ET CONFIRMATION
# ==========================================================================

def banner(is_root, args):
    out(C.yellow('=' * 78))
    out(C.bold('      DFIR LINUX SNIPER v%s — NETWORK / PROCESS / FILESYSTEM CORRELATOR'
               % VERSION))
    out(C.yellow('=' * 78))
    if is_root:
        out(C.red('[!] PRIVILEGES : ROOT — périmètre complet '
                  '(namespaces, fd globaux, homes, capacités)'))
    else:
        out(C.cyan('[*] PRIVILEGES : UTILISATEUR STANDARD — périmètre restreint '
                   'aux objets lisibles par UID %d' % os.getuid()))
        out(C.grey('    Les processus tiers, leurs fd et les autres homes resteront '
                   'invisibles : une exécution root est recommandée en IR.'))
    out(C.yellow('=' * 78))
    out('')
    out(C.bold('AVERTISSEMENT — LIRE AVANT DE LANCER LA COLLECTE'))
    out('  1. Lecture seule : aucune écriture disque, aucun réseau, aucun signal '
        'envoyé, aucun module chargé.')
    out('  2. Les fichiers sont ouverts avec O_NOATIME quand c\'est permis ; sinon '
        'l\'atime des fichiers lus est mis à jour (trace mineure).')
    out('  3. Le calcul SHA256 consomme du CPU et des I/O : impact possible sur un '
        'hôte de production chargé.')
    out('  4. Sur une machine compromise, le noyau peut mentir : ces résultats sont '
        'des indicateurs, pas un verdict. Confirmer par une acquisition mémoire.')
    out('  5. Les sorties peuvent contenir des données sensibles (cmdline, chemins '
        'utilisateurs) : traiter le transcript comme une pièce à conviction.')
    out('  6. Ordre d\'acquisition : capturer la RAM et le réseau AVANT ce scan si '
        'la volatilité prime.')
    if args.verify_system and not is_root:
        out('')
        out(C.red('  ATTENTION : --verify-system en utilisateur standard lit '
                  'des milliers de binaires système'))
        out(C.red('  dont vous n\'êtes pas propriétaire : O_NOATIME est refusé '
                  'et leur atime sera modifié.'))
        out(C.red('  Préférer une exécution root, ou renoncer à ce contrôle si '
                  'les atimes sont une preuve.'))
    out('')


def confirm(args):
    if args.yes:
        out(C.cyan('[+] Consentement fourni via --yes : démarrage de la collecte.'))
        return True
    if not sys.stdin.isatty():
        out(C.red('[-] Entrée standard non interactive et --yes absent : '
                  'annulation par sécurité.'))
        return False
    while True:
        try:
            choice = input('\nEngager la collecte en lecture seule sur ce périmètre ? '
                           '(y/n) : ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            out('')
            out('[-] Annulation.')
            return False
        if choice in ('y', 'yes', 'o', 'oui'):
            out('')
            out(C.cyan('[+] Démarrage de la collecte chirurgicale...'))
            out('')
            return True
        if choice in ('n', 'no', 'non'):
            out('[-] Annulation. Aucun accès effectué, fin du script.')
            return False
        out('Entrée invalide, tapez \'y\' ou \'n\'.')


# ==========================================================================
# MAIN
# ==========================================================================

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog='linux_forensics.py',
        description='Live forensics Linux sans dépendance : corrélation '
                    'réseau/processus, détection de rootkit et collecte de '
                    'SHA256 pour pivot CTI.',
        epilog='Exécution en lecture seule. Aucune donnée n\'est écrite sur le '
               'disque : rediriger la sortie vers un collecteur distant.')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='consentement explicite (IR automatisée) ; '
                             'l\'avertissement reste affiché')
    parser.add_argument('--no-color', action='store_true',
                        help='désactive les séquences ANSI')
    parser.add_argument('--no-fs', action='store_true',
                        help='ignore la chasse sur le système de fichiers')
    parser.add_argument('--no-rootkit', action='store_true',
                        help='ignore les contrôles de dissimulation')
    parser.add_argument('--no-hash', action='store_true',
                        help='n\'empreinte aucun fichier (scan très rapide)')
    parser.add_argument('--min-score', type=int, default=SEV_MEDIUM,
                        help='seuil d\'affichage des constats (défaut : %d)' % SEV_MEDIUM)
    parser.add_argument('--min-file-score', type=int, default=25,
                        help='seuil de rétention d\'un artefact fichier (défaut : 25)')
    parser.add_argument('--max-file-size', type=int, default=DEFAULT_MAX_HASH_SIZE,
                        help='taille maximale empreintée en octets (défaut : 128 Mo)')
    parser.add_argument('--max-file-findings', type=int,
                        default=DEFAULT_MAX_FILE_FINDINGS,
                        help='artefacts fichiers détaillés dans le rapport '
                             '(défaut : %d)' % DEFAULT_MAX_FILE_FINDINGS)
    parser.add_argument('--max-hash-files', type=int,
                        default=DEFAULT_MAX_HASH_FILES,
                        help='plafond global de fichiers empreintés '
                             '(défaut : %d)' % DEFAULT_MAX_HASH_FILES)
    parser.add_argument('--verify-system', action='store_true',
                        help='confronte TOUS les binaires système à la base de '
                             'paquets (détecte un binaire trojanisé non lancé ; '
                             'quelques secondes d\'I/O supplémentaires)')
    parser.add_argument('--no-pkgcheck', action='store_true',
                        help='ignore la confrontation à la base de paquets '
                             '(dpkg)')
    parser.add_argument('--extra-dir', action='append', metavar='CHEMIN',
                        help='répertoire supplémentaire à inspecter (répétable)')
    args = parser.parse_args(argv)

    # Bornage défensif : une valeur absurde ne doit pas produire un
    # comportement silencieusement incohérent (empreintes toutes refusées,
    # rapport vide sans explication...).
    args.max_file_size = max(1, min(args.max_file_size, 64 * 1024 ** 3))
    args.max_hash_files = max(0, min(args.max_hash_files, 1000000))
    args.max_file_findings = max(1, min(args.max_file_findings, 100000))
    args.min_score = max(0, min(args.min_score, 1000))
    args.min_file_score = max(0, min(args.min_file_score, 1000))
    args.extra_dir = [d for d in (args.extra_dir or []) if os.path.isabs(d)]
    return args


def main(argv=None):
    global C
    args = parse_args(argv if argv is not None else sys.argv[1:])

    use_color = sys.stdout.isatty() and not args.no_color and \
        os.environ.get('TERM', '') not in ('', 'dumb')
    C = Palette(use_color)

    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(line_buffering=True, errors='replace')
        except (ValueError, OSError):
            pass

    try:
        is_root = (os.geteuid() == 0)
    except AttributeError:
        out('[-] Plateforme non POSIX : ce script cible Linux uniquement.')
        return 2

    if not os.path.isdir('/proc/1'):
        out('[-] /proc est indisponible : impossible de conduire l\'analyse.')
        return 2

    banner(is_root, args)
    if not confirm(args):
        return 0

    start = time.time()
    try:
        pids, sockets = module_processes(args, is_root)
        if not args.no_rootkit:
            module_rootkit(pids, sockets, is_root)
        else:
            out(C.grey('[*] Étape 3/4 ignorée (--no-rootkit)'))
        if args.verify_system and not args.no_pkgcheck:
            module_verify_system(args)
        if not args.no_fs:
            module_filesystem(args, is_root)
        else:
            out(C.grey('[*] Étape 4/4 ignorée (--no-fs)'))
    except KeyboardInterrupt:
        out('')
        out(C.yellow('[!] Interruption analyste : restitution des constats partiels.'))
    render(args, is_root, time.time() - start)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        try:
            os.close(sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
