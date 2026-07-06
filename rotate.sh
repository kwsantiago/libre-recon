#!/usr/bin/env bash
# rotate.sh -- example --on-ban hook for `libre_recon.py watch`.
#
# When your garbageman node's address lands on the Knots banlist, LR nodes stop
# peering with it. The counter is to rotate identity faster than they can ban:
# generate a NEW Tor onion and restart the node on it, so the ban no longer
# applies. Wire it up with:
#
#   python3 libre_recon.py watch --addr <your.onion> --on-ban ./rotate.sh
#
# ADAPT the paths/commands below to your setup (Umbrel/Start9/bare-metal differ).
# $BANNED_ADDR is exported by `watch`.
set -euo pipefail

: "${BITCOIN_CLI:=bitcoin-cli}"
: "${BITCOIND:=bitcoind}"
: "${HS_DIR:=/var/lib/tor/bitcoin-service}"     # your Tor HiddenServiceDir
: "${TOR_RESTART:=sudo systemctl restart tor}"  # how to restart Tor

log() { echo "[$(date -u +%FT%TZ)] rotate: $*"; }

log "banned as ${BANNED_ADDR:-<unknown>} -- rotating Tor onion and restarting node"

# 1. Stop the node cleanly.
"$BITCOIN_CLI" stop || true
sleep 5

# 2. Rotate the hidden-service key. Removing it makes Tor mint a fresh onion.
#    (Back up first if you want to keep a pool of pre-generated onions instead.)
sudo rm -f "$HS_DIR/hs_ed25519_secret_key" \
           "$HS_DIR/hs_ed25519_public_key" \
           "$HS_DIR/hostname"
$TOR_RESTART
sleep 10

NEW_ONION="$(sudo cat "$HS_DIR/hostname")"
log "new onion: $NEW_ONION"

# 3. Restart the node. If you pin -externalip/-onion, update it to $NEW_ONION
#    (e.g. in bitcoin.conf) before this line.
"$BITCOIND" -daemon

log "rotated. Point your watcher at the new address:"
log "  python3 libre_recon.py watch --addr $NEW_ONION --on-ban ./rotate.sh"
