---
title: 'Unix Administraltion'
published: 2024-12-16
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---

------------------------------------------------------------------------------------------------------------------------------------------------------------
# CHAPITRE 1
------------------------------------------------------------------------------------------------------------------------------------------------------------

## /etc/passwd 
un fichier de type texte dont chaque ligne définit un compte utilisateur.   
*Form* =  Nom d'utilisateur : Mot de Passe : UID : GID : Commentaire : Repertoire dde connexion: Commande de connexion

## /etc/group 
un fichier de type texte dont chaque ligne définit un group d'utilisateurs.   
*Form* =  Nom de groupe : Mot de Passe : GID : Liste des utilisateurs autorisés à se connecter au Groupe 

  -- L'UID est une valeur comprise entre 0 et la valeur définie par la constante UID_MAX du fichier /etc/login.defs
  
  -- La constante UID_MIN du fichier /etc/login.defs définit la valeur minimale des UID des utilisateurs. ( UID_MIN = 1000 )

## Commandes de gestion

| Fonction                                           | Commandes                            |
|----------------------------------------------------|--------------------------------------|
| Gestion des comptes utilisateurs                  | `useradd`, `usermod`, `userdel`      |
| Gestion des comptes de groupe                     | `groupadd`, `groupmod`, `groupdel`   |
| Vérification des fichiers `/etc/passwd` et `/etc/group` | `pwck`, `grpck`                |
| Informations sur un utilisateur                   | `finger`                             |
| Changement du shell ou commentaire d’un utilisateur | `chfn`, `chsh`                     |
| Modification du mot de passe d’un utilisateur     | `passwd`                             |
| Pour se connecter à un compte                     | `su`                                 |
| Pour connaître son identité                       | `id`                                 |
| Pour lister les groupes d’un utilisateur          | `groups`                             |
| Pour éditer les fichiers `/etc/passwd` et `/etc/group` | `vipw`, `vigr`                   |

---

## useradd

``` 
useradd [-c comment] [-d home_dir] [-e expire_date] [-f inactive_time] [-g initial group] [-G group] [, ...]] [-m [-k skeleton_dir]] [-s shell] [-u uid [-o]] [-n] [-r] login 
```

| Option            | Description                                                                                                     |
|-------------------|-----------------------------------------------------------------------------------------------------------------|
| `-c comment`      | Le commentaire.                                                                                                |
| `-d home_dir`     | Le répertoire de connexion.                                                                                    |
| `-e expire_date`  | La date d'expiration du compte.                                                                                |
| `-f inactive_time`| Le nombre de jours au bout duquel un compte est inutilisable après l'expiration d'un mot de passe.             |
| `-g initial group`| Le groupe initial, par défaut, ali pour l'utilisateur ali.                                                     |
| `-k skeleton_dir` | Le répertoire de peuplement du répertoire de connexion. Les fichiers qu'il contient sont copiés dans /etc/skel.|
| `-s shell`        | Le shell de l'utilisateur, par défaut bash.                                                                    |
| `-u uid`          | L'UID de l'utilisateur.                                                                                        |
| `-o`              | Permet de créer un compte d'utilisateur avec un identifiant (UID) dupliqué (non unique).                      |
| `-n`              | Ne crée pas un groupe avec le même nom que celui de l'utilisateur, mais l'ajoute au groupe spécifié par `-g`.  |
| `-r`              | Permet de créer un compte avec un UID inférieur à `UID_MIN` défini dans `/etc/login.defs`.                    |
| `-G group,..`     | Les groupes supplémentaires.                                                                                   |
| `-m`              | Crée le répertoire de connexion de l'utilisateur.                                                             |

```
useradd -D
```
*passwd* : ```passwd [option] Nom_utilisateur``` ( option : -l verouiller, -u devrouiller, -d supprimer le mot de pass )
Dans cette forme, la commande useradd permet de définir les valeurs utilisées par défaut quand on crée un compte utilisateur.


Le répertoire /etc/skel de Linux est très important: il contient des modèles de fichiers de configuration des sessions des utilisateurs.

``` 
┌──(kali㉿level)-[/etc/skel]
└─$ ls -aC .
.   .bash_logout  .bashrc.original  .face       .java     .zshrc ..  .bashrc       .config           .face.icon  .profile
```

-- .bashrc : A shell script that runs whenever a new Bash shell session is started. ( fichier de définition des alias )
-- .profile : A shell script that is executed when a user logs in.
-- .bash_profile: script exécuté à la connexion
-- .bash_logout: script exécuté à la déconnexion
-- .Xdefaults: fichiers de définitions des ressources des applications X


------------------------------------------------------------------------------------------------------------------------------------------------------------
# CHAPITRE 2
------------------------------------------------------------------------------------------------------------------------------------------------------------

------------------------------------
## Arborescence ( Systéme de fichier )
------------------------------------

| Répertoire          | Description                                                                                             |
|----------------------|---------------------------------------------------------------------------------------------------------|
| `/`                 | Répertoire racine, là où tous les autres répertoires sont montés (accrochés).                          |
| `/bin`              | Commandes UNIX, une partie des binaires du système et quelques commandes.                              |
| `/sbin`             | Programmes exécutables indispensables à la gestion du système.                                         |
| `/etc`              | Quelques fichiers de configuration et des fichiers systèmes pour le démarrage.                        |
| `/dev`              | Fichiers unité (périphériques, spéciaux).                                                             |
| `/home`             | Partie où sont stockés les fichiers propres aux utilisateurs.                                         |
| `/var`              | Fichiers temporaires de taille variable : démons, spools d'email, imprimantes, logs, locks, etc.      |
| `/opt`              | Lieu d'installation préféré des logiciels "modernes".                                                |
| `/boot`             | Image du noyau pour Linux.                                                                            |
| `/tmp`              | Fichiers temporaires, utilisés par l’éditeur de texte `vi`, les compilateurs, etc.                     |
| `/usr`              | Espace "standard".                                                                                    |
| `/usr/bin`          | Pour les binaires.                                                                                    |
| `/usr/lib`          | (Library) Fichiers d’information, pour les bibliothèques du langage C.                                |
| `/usr/include`      | Fichiers d’entête pour programmes C (`.h`).                                                           |
| `/usr/local`        | Espace "non standard", personnalisation locale du système.                                            |
| `/usr/local/bin`    | Rajout de binaires en local.                                                                          |
| `/usr/local/lib`    | Idem pour les bibliothèques.                                                                          |
| `/usr/local/include`| Idem pour les fichiers "includes".                                                                    |
| `/usr/local/src`    | Code source des différents programmes du système.                                                     |
| `/usr/man`          | Aide en ligne.                                                                                        |
| `/mnt`              | (Mount) Montage de disquettes, accès aux données depuis le répertoire `/mnt`.                         |
| `/lost+found`       | (Perdu et trouvé) Contient les fichiers retrouvés par la commande `fsck`.                             |


----------------------
## Les types de fichiers
----------------------

## Classification des fichiers:
| Type                  | Symbole | Description                                                                                          | Exemple                              |
|-----------------------|---------|------------------------------------------------------------------------------------------------------|--------------------------------------|
| Fichier régulier      | `-`     | Capables de stocker des données (zip, tar, doc, txt, etc.).                                         | `document.txt`, `archive.zip`       |
| Dossier               | `d`     | Rassemble des fichiers.                                                                             | `/home/user`, `/etc`                |
| Lien symbolique       | `l`     | Pointe sur un autre fichier.                                                                        | `/lib/libc.so.6`, `/dev/cdrom`      |
| Socket                | `s`     | Permet de communiquer par le réseau.                                                               | `.sock`                             |
| Block device          | `b`     | Permet d’effectuer une opération sur un périphérique capable de stocker des données.               | Disques SCSI/USB/SATA : `/dev/sd*`  |
| Character device      | `c`     | Permet d’effectuer une opération sur un périphérique incapable de stocker des données.             | Souris, webcam : `/dev/input/mice`  |

| Fichier                | Symbole (`ls -l`) | Création                     | Destruction  |
|------------------------|---------|------------------------------|-----------------------|
| Ordinaire             | `-`     | `vi`, ...                   | `rm`                 |
| Répertoire            | `d`     | `mkdir`                     | `rmdir`, `rm -r`     |
| Périphérique caractère| `c`     | `mknod`                     | `rm`                 |
| Périphérique bloc     | `b`     | `mknod`                     | `rm`                 |
| Socket locales        | `s`     | `socket(2)`                 | `rm`                 |
| Tube nommé            | `p`     | `mknod`                     | `rm`                 |
| Lien symbolique       | `l`     | `ln -s`                     | `rm`                 |

## Unités de disque:

| Type d'unité         | Emplacement                   | Symbole | Description                  |
|-----------------------|-------------------------------|---------|------------------------------|
| Fichiers son          | `/dev/audio`                 | `c`     | Fichiers audio              |
| Unité de CD-ROM       | `/dev/hdc`                   | `b`     | Lecteur de CD-ROM           |
| Console               | `/dev/console`               | `c`     | Console système             |
| Ports de modems       | `/dev/cua0`                  | `c`     | Ports pour modems           |
| Unités de disquette   | `/dev/fd0`                   | `b`     | Lecteur de disquettes       |
| Unités à bandes       | `/dev/rft0`, `/dev/nrtf0`    | `b`     | Lecteurs à bandes           |

## commandes hexdump et od (octal dump)

Manipulate it to learn it


----------------------
## Les droits étendues
----------------------

## read , write and execute

```
(valeurs octales : 400,200,100,40,20,10,4,2,1)

```


## sticky bit* : valeur octale : 1000, valeur symbolique : lettre t

*Exécutable*: il reste en mémoire, son chargement est rapide
*Répertoire*: la destruction d'un fichier est réservée au propriétaire

pour plus de clarification : 

"""
There are two definitions: one for files, one for directories.

For files, particularly executables, superuser could tag these as to be retained in main memory, even when their need ends, to minimize swapping that would occur when another need arises, and the file now has to be reloaded from relatively slow secondary memory.[1] This function has become obsolete due to swapping optimization.

For directories, when a directory's sticky bit is set, the filesystem treats the files in such directories in a special way so only the file's owner, the directory's owner, or root user can rename or delete the file. Without the sticky bit set, any user with write and execute permissions for the directory can rename or delete contained files, regardless of the file's owner. Typically this is set on the /tmp directory to prevent ordinary users from deleting or moving other users' files. 

"""

Les droits d'endossement (valeurs octales : SUID=4000, SGID=2000, valeur symbolique : s) :

-- SUID ( Set User ID ) : Si un fichier exécutable possède le bit SUID, il s'exécute avec les privilèges de son propriétaire, peu importe l'utilisateur qui le lance.
`Exemple` : Le programme /usr/bin/passwd utilise le bit SUID pour permettre à un utilisateur de modifier son mot de passe, car cette opération nécessite l'accès au fichier système /etc/shadow

-- SGID ( Set Group ID ) : Si un fichier exécutable possède le bit SGID, il s'exécute avec les privilèges du groupe propriétaire.

Exemple : 
```bash
ls -l /usr/bin/passwd
-r-sr-xr-x 1 root root
12345oct 2 2001/usr/bin/passwd
```

## Commandes génériques

• mkfs: Crée un FS

• mount: Monte un FS

• umount: Démonte un FS

• fsck: Vérifie un FS

• df: Espace libre

• du: Espace occupé

• lsof: Identifie les processus

## Commandes propres à ext2

• mke2fs: Crée un FS

• e2fsck: Vérifie un FS

• tune2fs: Paramètre un FS

• dumpe2fs: Informations sur le super bloc et les groupes de blocs

• debugfs: Débogue un FS


## Maintien de quotas de disques

La mise en œuvre des quotas va permettre à l'administrateur de limiter le nombre de fichiers ou le nombre de blocs d'un utilisateur ou d'un groupe, sur un disque.


Pour les fichiers aussi bien que les blocs, il existe deux limites:

La limite « hard » qui est infranchissable. Un utilisateur ou un groupe qui atteint sa limite «hard » de fichiers ne pourra pas en créer un de plus.

La limite « soft» peut être franchie pendant un certain nombre de jours consécutifs, sept par défaut.

## Gestion des quotas (Une synthèse)

### Activation des quotas:

 Pour toutes les SdF: #quotaon –a ( tout les SDF )
 Pour une partition: #quotaon /home 
 Pour un utilisateur: #quotaon -u ali
 Pour un groupe : #quotaon –g


### Désactivation des quotas: #quotaoff -a

 Visualisation de la politique de quota associé à un utilisateur:

quota
Disk quota for user ali (uid 1000): none

quota -u ali
Disk quota for user ali (uid 1000): none

### Edition des quotas:

```bash
edquota –u ali
```

Disk quotas for user ali (uid 1000):
Filesystem   blocks soft hard inodes soft hard 
/dev/sda1    0      0    0    1      5    10

0 signifie pas de limite

```bash
edquota -t
```

```bash
#setquota ali 1000 2000 100 110 /dev/sda1
```

# Processus et Planification des travaux

## Processus

La commande ‘ps -uax’
La commande ‘pstree’
La commande ‘ps -eaf’
La commande ‘kill -9 pid’
La commande ‘job %n_job’

## Planification des travaux

La commande at ne lance qu'une seule fois une commande à une
heure particulière.
Syntaxe: 
```bash
at date <commande>
```
La commande crontab permet l'exécution périodique et automatique.

```bash
crontab min heure_jour jour_mois mois_année jour_semaine action
```

Ex : $ crontab "5 3 15 6 2 /path/to/script.sh"


# BASH SCRIPTING

Les scripts Bash vous permettent d'automatiser des tâches et d'exécuter des commandes en séquence. Voici un guide rapide pour commencer à écrire des scripts Bash.


## Exemple d'un script simple :
```bash
#!/bin/bash
# Ceci est un script Bash simple

echo "Bonjour, le monde!"
```
| Variable  | Description                                             |
|-----------|---------------------------------------------------------|
| ` $# `    | **Nombre d'arguments** passés au script.                |
| ` $0 `    | **Nom du script** ou de la commande en cours d'exécution.|
| ` $1, $2, ... ` | **Arguments positionnels** du script (1er, 2ème, ...).|
| ` $@ `    | **Liste de tous les arguments**, séparés par des espaces.|
| ` $* `    | **Tous les arguments** sous forme d'une seule chaîne.   |
| ` $? `    | **Code de retour** de la dernière commande exécutée.    |
| ` $$ `    | **PID** (identifiant du processus) du script.           |
| ` $! `    | **PID** du dernier processus exécuté en arrière-plan.   |

touch monscript.sh
echo "hello"
nom="John"
$nom

## Conditions

```bash
nombre=10
if [ $nombre -gt 5 ]; then
  echo "Le nombre est supérieur à 5."
else
  echo "Le nombre est inférieur ou égal à 5."
fi
```

-lt less than ( < )
-le less than or equal to ( <= )
-eq equals ( = )
-gt greater than ( > )
-ge greater than or equal to ( >= )
-ne different ( != )
-e file : True if file exists.
-f file: True if file exists and is a regular file.
-d file: True if file exists and is a directory.
-s file: True if file exists and has a size greater than zero.
-r file: True if file exists and is readable.
-w file: True if file exists and is writable.
-x file: True if file exists and is executable.
string1 = string2: True if string1 is equal to string2.
string1 != string2: True if string1 is not equal to string2.
-z string: True if string is empty (has zero length).
-n string: True if string is not empty.

Les crochets [ ] sont utilisés pour les tests conditionnels.
In an if, it is possible to do several tests at the same time && ||

read -p ' Any Thing to tell: ' var

## Exemple de boucle for

```bash
for i in {1..5}
do
  echo "Itération $i"
done
```

## Exemple de boucle while

```bash
while [ $compteur -le 5 ]; do
    echo "Compteur : $compteur"
    compteur=$((compteur + 1)) # Incrémentation de la variable
done
```







Les commandes dial TP4 :

mount | column -t 

df -B512 ( La commande df indique l'espace libre des disques contenant des
systèmes de fichiers montés. )

La commande du affiche le nombre de blocs d'un kilo-octet utilisés par
une arborescence qui peut coïncider avec celle d'un système de fichiers.

Quelles sont les tailles de blocs possibles dans un système de fichiers de type ext2 ?
1 Ko (1024 octets)
2 Ko (2048 octets)
4 Ko (4096 octets)
8 Ko (8192 octets) (rare, nécessite un noyau personnalisé ou architectures spécifiques).

SI au moins un processus executra dans l'espace user ( kali2 ) , no one peut demonter le FS de ce user, le systeme l'empeche
'
Le système de fichiers /home est probablement monté et utilisé par des utilisateurs, donc si un processus (comme more ou d'autres programmes utilisant des fichiers dans /home) est en cours d'exécution et utilise le répertoire /home, il empêchera l'administrateur de démonter ce système de fichiers. En effet, Linux bloque le démontage d'un système de fichiers tant qu'il est utilisé.
'

Le FS /dev/hda8 est monté sur le répertoire /games . Que doit-on faire pour que ce FS ne soit accessible
qu'à l'utilisateur ali?

khassna nbadlo f /etc/fstab bach n3tiw permission ghir l ali 





