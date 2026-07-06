# libre-recon

Reconnaissance for the transaction-relay policy war. `libre-recon` maps the
libre-relay (service bit 29) side of the Bitcoin network, tells garbageman
(filtering) nodes apart from genuine Libre Relay nodes, audits your own node's
disguise, and checks the public Knots banlists.

It is the mirror image of the tools used to *detect* garbageman nodes: it runs
the same passive classification against the network so you can see the
battlefield the way the other side does.

- **Outbound only. No listening node required.**
- **Pure Python 3 standard library. No dependencies, nothing to install.**
- Runs direct, behind a VPN, or over Tor.

## Usage

```bash
# Census the libre-relay network: discover bit-29 nodes and classify them
python3 libre_recon.py crawl --seeds 6

# Classify specific nodes
python3 libre_recon.py probe 1.2.3.4:8333 5.6.7.8

# Audit YOUR node: which detection tells expose it as garbageman?
python3 libre_recon.py check 127.0.0.1:8333

# Check the public Knots banlist (is an address banned?)
python3 libre_recon.py banlist --ip 1.2.3.4
```

Route any command over Tor with `--socks5 127.0.0.1:9050` (recommended for
`crawl`).

## Privacy

Every mode is outbound-only, so the nodes you contact see the source IP of your
connection. Behind a VPN they see the VPN exit, not you, that hides your real IP.
For crawling, prefer **Tor** (`--socks5`): a fresh circuit per connection avoids
getting one IP flagged as a scanner, and keeps the crawler unlinked from your own
relay node. Note the banlists already contain thousands of onion addresses, Tor
is not immune to being banned, only to being tied back to you.

## How classification works, and its limits

For each libre (bit-29) node:

| Tell | Meaning |
|---|---|
| `NODE_REDUCED_DATA` (bit 27) set | Knots/garbageman only; a real Libre Relay node never sets it. The reliable passive classifier. |
| user agent contains `Knots` | an un-spoofed garbageman node |
| `feefilter` | equals `minrelaytxfee` only on a synced, calm-mempool node; during IBD or congestion every node reports a high value. **Used only in `check`** (where you know your own node's state), never to classify others. |

The GM-vs-LR split relies on these tells, so it **fades as garbageman's disguise
improves** (e.g. once bit-27 is decoupled). The durable metric is the **total
bit-29 census over time**; counting the garbageman fleet itself will eventually
need a coordination channel, not passive classification.

## License

MIT. See LICENSE.
