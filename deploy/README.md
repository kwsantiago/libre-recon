# garbageman-in-a-box

A one-command Docker deploy of a stealth-configured garbageman node plus the
`libre-recon` ban watchdog. For Start9 users, prefer a native package; this is
for VPS / bare-metal / anyone on Docker.

## Run

```bash
cd deploy
echo "NODE_ADDR=<your-public-ip-or-onion>" > .env   # so the watchdog knows what to watch
docker compose up -d --build
```

`--build` compiles the garbageman node from the `garbageman-29.3-battle` branch
(all stealth fixes baked in) the first time; subsequent starts are instant.

## What you get

- **garbageman** — the node, stealth-configured (see `bitcoin.conf`): spoofed user
  agent, libre-relay bit-29 signalling, feefilter matched to Libre Relay, filtering
  intact. Listens on 8333 so LR nodes can dial you and you occupy their slots.
- **tor** — a SOCKS proxy so the watchdog's checks go over Tor.
- **watchdog** — polls the public Knots banlists for your `NODE_ADDR` and logs the
  moment you're banned (`docker compose logs -f watchdog`).

## Reachability

Occupying LR slots means being dial-able. Map port 8333 to a reachable address
(clearnet IP, VPS, or a Tor hidden service). Tor gives unlinkability but the
banlists already carry thousands of onion bans, so pair it with rotation.

## Auto-rotation (optional, advanced)

The watchdog runs `rotate.sh` on a new ban, but restarting the node/onion from
inside a container needs orchestration. Simplest safe option: a host cron that
reacts to the watchdog log, or run the watchdog on the host (`python3
libre_recon.py watch --addr <addr> --on-ban ./rotate.sh`) where `rotate.sh` can
`docker compose restart garbageman` and rotate your Tor key. Mounting the Docker
socket into the watchdog also works but widens its blast radius, your call.

## Build source

The node is built from `github.com/privkeyio/bitcoin` branch
`garbageman-29.3-battle` (garbageman-29.3 + the getdata-pigeon removal, peering
hardening, and feefilter fix). Override with build args `BATTLE_REPO` /
`BATTLE_REF`.
