#!/bin/bash
# backup-journal.sh — Round 33
#
# Sauvegarde quotidienne des fichiers journal (data/journal-*.json) vers un
# dossier daté séparé, avec rotation (les sauvegardes de plus de 30 jours
# sont supprimées automatiquement).
#
# Pourquoi : le journal (historique des paris, ROI/CLV) vit uniquement sur
# le disque de ce droplet depuis le Round 12. Sans copie séparée, une seule
# commande malheureuse (ex. un "rm" au mauvais endroit) ou une panne disque
# suffirait à tout perdre irrécupérablement. Ce script protège contre le
# premier cas (erreur humaine, corruption du fichier vivant) — PAS contre
# la perte totale du droplet lui-même (panne matérielle, suppression du
# droplet) : pour ce risque-là, il faudrait en plus rapatrier
# régulièrement une copie hors du droplet (voir note en bas de ce fichier).
#
# Installation (à faire une seule fois) :
#   1. Copier ce fichier sur le serveur : scp backup-journal.sh root@68.183.64.243:/opt/value-board/
#   2. Le rendre exécutable : ssh root@68.183.64.243 "chmod +x /opt/value-board/backup-journal.sh"
#   3. Ajouter une tâche cron quotidienne (à 4h du matin, heure creuse) :
#      ssh root@68.183.64.243
#      crontab -e
#      # Ajouter cette ligne à la fin du fichier qui s'ouvre :
#      0 4 * * * /opt/value-board/backup-journal.sh >> /opt/value-board/backup.log 2>&1

set -euo pipefail

JOURNAL_DIR="${JOURNAL_DIR:-/opt/value-board/data}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/value-board/backups}"
RETENTION_DAYS=30

DATE_TAG="$(date +%Y-%m-%d)"
DEST="$BACKUP_ROOT/$DATE_TAG"

if [ ! -d "$JOURNAL_DIR" ]; then
  echo "$(date -Iseconds) — JOURNAL_DIR introuvable ($JOURNAL_DIR), rien à sauvegarder."
  exit 0
fi

mkdir -p "$DEST"

# Copie uniquement les fichiers journal (pas de dossier caché ni de fichier
# temporaire qui traînerait dans ce dossier) — cp échoue silencieusement en
# "no matches found" si aucun fichier journal n'existe encore, d'où le
# `|| true` pour ne pas faire échouer tout le script sur un droplet tout
# neuf sans historique.
cp "$JOURNAL_DIR"/journal-*.json "$DEST"/ 2>/dev/null || true

COUNT=$(ls -1 "$DEST"/journal-*.json 2>/dev/null | wc -l | tr -d ' ')
echo "$(date -Iseconds) — $COUNT fichier(s) journal sauvegardé(s) dans $DEST"

# Rotation : supprime les dossiers de sauvegarde de plus de RETENTION_DAYS
# jours, pour éviter que ce dossier ne grossisse indéfiniment (un fichier
# journal reste petit — quelques Ko à quelques Mo — donc 30 jours de copies
# quotidiennes restent négligeables en espace disque).
find "$BACKUP_ROOT" -maxdepth 1 -type d -mtime +"$RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true

# ---------------------------------------------------------------------
# Note — ce script protège contre une erreur humaine ou une corruption du
# fichier vivant, PAS contre la perte totale du droplet. Pour ce risque
# supplémentaire (peu probable mais total s'il survient), le plus simple
# sans infrastructure supplémentaire : rapatrier de temps en temps une
# copie sur ton Mac avec une seule commande, par exemple une fois par mois :
#
#   scp root@68.183.64.243:/opt/value-board/backups/$(date +%Y-%m-%d)/*.json ~/Desktop/value-board-backup/
#
# Automatiser complètement ce rapatriement (vers un cloud externe type S3,
# Backblaze, etc.) est possible mais demanderait de choisir et configurer
# un service de stockage externe — volontairement laissé de côté ici tant
# que ce n'est pas devenu un vrai besoin.
