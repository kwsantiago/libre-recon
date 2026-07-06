# Garbageman operator runbook

How to run a garbageman node for the transaction-relay policy war, and keep it in
the fight. This is the operator playbook that goes with the `libre-recon` tools.

## What you're running, and why

A garbageman node runs Bitcoin Knots filtering policy but advertises the
libre-relay service bit (29), so Libre Relay (LR) nodes preferentially peer with
it. It then drops the data-spam transactions LR wants relayed. The point is to
occupy LR's preferential-peering slots and absorb spam before it reaches miners.
**It is a numbers game: the more garbageman nodes occupying LR slots, the less
spam propagates.** Running one is the contribution.

## 1. Get the node

Build from the garbageman branch (Knots 29.3 base):

```bash
git clone https://github.com/chrisguida/bitcoin && cd bitcoin
git checkout garbageman-29.3
cmake -B build -D RDTS_CONSENT=IMPLICIT && cmake --build build -j$(nproc)
```

Run these stealth/hardening changes if not yet merged (they are what keep a GM
node from being trivially detected and de-slotted):
- remove the getdata "pigeon" patch (it fingerprints the node) — chrisguida/bitcoin PR #2
- libre-relay peering hardening (eclipse/budget/accounting) — PR #3
- match LR's feefilter fee floor — PR #4

## 2. Run it effectively (the offense)

Garbageman's weapon is occupying LR's outbound libre slots, which means LR nodes
must be able to **dial into you**. A listening, inbound-reachable node occupies
far more slots than an outbound-only one.

- **Clearnet listening** (home IP, or a VPS/tunnel) is the most effective, LR
  nodes crawl and dial bit-29 peers.
- **Tor-only** still works outbound but occupies fewer slots (you can't be dialed
  in as easily). A clearnet reachable address, even via VPS or a tunnel, is worth
  it for the offense.
- Do **not** run `-corepolicy`: it switches to Core policy and disables the
  datacarrier filtering that is the entire point.

## 3. Check your disguise

Audit what your node leaks to peers:

```bash
python3 libre_recon.py check <your-node-ip>:8333
```

Current reality (be honest with yourself):
- User agent is spoofed to `/Satoshi:.../` (no "Knots"), defeats the substring
  banlists.
- `feefilter` matches LR (100) with PR #4.
- **`NODE_REDUCED_DATA` (bit 27) is still advertised** and, paired with bit 29, is
  a zero-false-positive tell — this is how you get identified today. It is welded
  to RDTS enforcement and can't be dropped until RDTS activates. Until then, a GM
  node *is* identifiable by a determined adversary. Plan around it: numbers and
  rotation, not perfect stealth.

## 4. Stay in the fight (ban-resilience)

When you're identified you get banned (added to the Knots banlist and dropped by
LR nodes). The counter is to rotate faster than they can ban:

```bash
python3 libre_recon.py watch --addr <your.onion-or-ip> --on-ban ./rotate.sh
```

`watch` polls the public banlists and runs your rotation hook the moment your
address is banned. `rotate.sh` is an example that mints a new Tor onion and
restarts the node. Tor gives unlinkability, not ban-immunity (thousands of onions
are already banned) — rotation is what keeps you effective.

## 5. Know the battlefield

```bash
python3 libre_recon.py crawl --seeds 6 --socks5 127.0.0.1:9050
```

Track the libre-relay census over time: how many nodes, how the GM/LR split moves.
The network is small and churny, which is exactly why more operators matters.

## The honest bottom line

A filtering node is ultimately detectable by what it does not relay, so this is
not won by invisibility. It is won by **numbers** (occupy more slots than they can
route around), **rotation** (never stay banned), and the **RDTS consensus change**
that settles the big-data fight above the relay layer. Run a node. Keep it moving.
