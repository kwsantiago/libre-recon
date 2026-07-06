#!/usr/bin/env python3
# libre-recon -- map the libre-relay network, classify garbageman vs Libre Relay,
# audit your own node's disguise, and check the public Knots banlists.
#
# Outbound only. No listening node required. Pure Python standard library.
# Distributed under the MIT license.
"""
Modes:
  probe   HOST:PORT ...        classify specific nodes
  crawl   [--seeds N]          getaddr-gossip discovery + census of the libre net
  check   HOST:PORT            stealth audit: which detection tells expose YOUR node
  banlist [--ip A.B.C.D]       fetch the public Knots banlist and check an address

Networking:
  --socks5 127.0.0.1:9050      route over Tor (recommended for crawling: a fresh
                               circuit per connection avoids getting one IP flagged
                               and de-links the crawler from your own node)

Notes on the tells:
  - NODE_REDUCED_DATA (bit 27): set by Knots/garbageman, never by a real Libre
    Relay node. The reliable passive classifier today.
  - user agent containing "Knots": an un-spoofed garbageman node.
  - feefilter: equals minrelaytxfee only on a synced, calm-mempool node; during
    IBD or congestion every node reports a high value, so it is used only in the
    self `check` (where you know your node's state), never to classify others.
  The GM/LR split fades as garbageman's disguise improves; the durable metric is
  the total bit-29 census over time.
"""
import argparse
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import random
import socket
import struct
import time
import urllib.request

MAGIC = {"main": bytes.fromhex("f9beb4d9"), "testnet4": bytes.fromhex("1c163f28"),
         "regtest": bytes.fromhex("fabfb5da")}
DNS_SEEDS = ["seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
             "seed.btc.petertodd.net", "seed.bitcoin.wiz.biz", "dnsseed.emzy.de",
             "seed.bitcoin.sprovoost.nl", "seed.mainnet.achownodes.xyz"]
BANLISTS = {
    "aeonBTC/Knots-Banlist": "https://raw.githubusercontent.com/aeonBTC/Knots-Banlist/main/banlist.json",
}
NODE_WITNESS = 1 << 3
NODE_REDUCED_DATA = 1 << 27   # Knots/garbageman only
NODE_LIBRE_RELAY = 1 << 29    # == NODE_PREFERENTIAL_PEERING on the Knots side


# --- minimal Bitcoin P2P ---------------------------------------------------
def _sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _wrap(magic, command, payload):
    c = command.encode() + b"\x00" * (12 - len(command))
    return magic + c + struct.pack("<I", len(payload)) + _sha256d(payload)[:4] + payload


def _csize(f):
    n = f[0]
    if n < 0xfd:
        return n, 1
    if n == 0xfd:
        return struct.unpack("<H", f[1:3])[0], 3
    if n == 0xfe:
        return struct.unpack("<I", f[1:5])[0], 5
    return struct.unpack("<Q", f[1:9])[0], 9


def _build_version():
    p = struct.pack("<iQq", 70016, NODE_WITNESS, int(time.time()))
    p += struct.pack("<Q", 0) + b"\x00" * 16 + struct.pack(">H", 0)
    p += struct.pack("<Q", NODE_WITNESS) + b"\x00" * 16 + struct.pack(">H", 0)
    p += struct.pack("<Q", random.getrandbits(64))
    ua = b"/libre-recon:1.0/"
    p += struct.pack("<B", len(ua)) + ua + struct.pack("<i", 0) + struct.pack("<?", False)
    return p


def _socks5(sock, proxy, host, port):
    ph, pp = proxy.rsplit(":", 1)
    sock.connect((ph, int(pp)))
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise OSError("socks5 rejected")
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    r = sock.recv(10)
    if len(r) < 2 or r[1] != 0x00:
        raise OSError("socks5 connect failed")


def _open(host, port, socks5, timeout):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if socks5:
        _socks5(s, socks5, host, port)
    else:
        s.connect((host, port))
    return s


def _read(sock, magic):
    hdr = b""
    while len(hdr) < 24:
        c = sock.recv(24 - len(hdr))
        if not c:
            raise OSError("closed")
        hdr += c
    if hdr[:4] != magic:
        raise OSError("bad magic")
    command = hdr[4:16].rstrip(b"\x00").decode(errors="replace")
    length = struct.unpack("<I", hdr[16:20])[0]
    payload = b""
    while len(payload) < length:
        c = sock.recv(min(65536, length - len(payload)))
        if not c:
            raise OSError("closed mid-payload")
        payload += c
    return command, payload


def _parse_version(p):
    services = struct.unpack("<Q", p[4:12])[0]
    off = 4 + 8 + 8 + 26 + 26 + 8
    ualen = p[off]
    ua = p[off + 1: off + 1 + ualen].decode(errors="replace")
    return services, ua


def _parse_addrv2(p):
    count, o = _csize(p)
    out = []
    for _ in range(count):
        try:
            o += 4
            svc, n = _csize(p[o:]); o += n
            netid = p[o]; o += 1
            alen, n = _csize(p[o:]); o += n
            addr = p[o:o + alen]; o += alen
            port = struct.unpack(">H", p[o:o + 2])[0]; o += 2
            if netid == 1 and alen == 4:
                out.append((svc, socket.inet_ntop(socket.AF_INET, addr), port))
            elif netid == 2 and alen == 16:
                out.append((svc, socket.inet_ntop(socket.AF_INET6, addr), port))
        except Exception:
            break
    return out


def probe(host, port, network="main", socks5=None, timeout=15):
    magic = MAGIC[network]
    s = _open(host, port, socks5, timeout)
    try:
        s.sendall(_wrap(magic, "version", _build_version()))
        services = ua = feefilter = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            command, payload = _read(s, magic)
            if command == "version":
                services, ua = _parse_version(payload)
                s.sendall(_wrap(magic, "verack", b""))
            elif command == "feefilter":
                feefilter = struct.unpack("<q", payload[:8])[0]
                break
            elif command == "ping":
                s.sendall(_wrap(magic, "pong", payload[:8]))
            if services is not None and command == "verack":
                break
        return {"host": host, "port": port, "services": services, "ua": ua,
                "feefilter": feefilter, "class": classify(services, ua)}
    finally:
        s.close()


def getaddr(host, port, network="main", socks5=None, timeout=20):
    magic = MAGIC[network]
    s = _open(host, port, socks5, timeout)
    try:
        s.sendall(_wrap(magic, "version", _build_version()))
        addrs, asked = [], False
        deadline = time.time() + timeout
        while time.time() < deadline:
            command, payload = _read(s, magic)
            if command == "version":
                s.sendall(_wrap(magic, "sendaddrv2", b""))
                s.sendall(_wrap(magic, "verack", b""))
            elif command == "verack":
                s.sendall(_wrap(magic, "getaddr", b"")); asked = True
            elif command == "ping":
                s.sendall(_wrap(magic, "pong", payload[:8]))
            elif command == "addrv2" and asked:
                addrs += _parse_addrv2(payload)
                if len(addrs) > 500:
                    break
        return addrs
    finally:
        s.close()


def classify(services, ua):
    if services is None or not (services & NODE_LIBRE_RELAY):
        return "non-libre"
    if services & NODE_REDUCED_DATA:
        return "garbageman"
    if ua and "Knots" in ua:
        return "garbageman"
    return "libre-relay"


# --- banlist ---------------------------------------------------------------
def fetch_banlist(url, timeout=30):
    """Return (ip_networks, n_onion_or_other). Onion/I2P/CJDNS bans can't be IP-matched."""
    raw = urllib.request.urlopen(url, timeout=timeout).read()
    nets, other = [], 0
    for e in json.loads(raw).get("banned_nets", []):
        a = e.get("address")
        if not a:
            continue
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            other += 1
    return nets, other


def ip_banned(nets, ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nets)


# --- modes -----------------------------------------------------------------
def do_probe(cands, args):
    counts = {}
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(probe, h, p, args.network, args.socks5): (h, p) for h, p in cands}
        for f in cf.as_completed(futs):
            h, p = futs[f]
            try:
                r = f.result()
                counts[r["class"]] = counts.get(r["class"], 0) + 1
                print("%-24s services=0x%08x ff=%s ua=%s -> %s"
                      % (f"{h}:{p}", r["services"] or 0, r["feefilter"], r["ua"], r["class"]))
            except Exception:
                counts["unreachable"] = counts.get("unreachable", 0) + 1
    print("\n=== census ===")
    for k in ("garbageman", "libre-relay", "non-libre", "unreachable"):
        if k in counts:
            print("  %-12s %d" % (k, counts[k]))


def do_crawl(args):
    seedips = []
    for h in DNS_SEEDS:
        try:
            seedips += [ai[4][0] for ai in socket.getaddrinfo(h, 8333, socket.AF_INET)]
        except Exception:
            pass
    seedips = list(dict.fromkeys(seedips))
    random.shuffle(seedips)
    seen, libre, ok = set(), {}, 0
    for ip in seedips:
        if ok >= args.seeds:
            break
        try:
            addrs = getaddr(ip, 8333, args.network, args.socks5)
        except Exception:
            continue
        if not addrs:
            continue
        ok += 1
        for svc, ah, ap_ in addrs:
            if (ah, ap_) not in seen:
                seen.add((ah, ap_))
                if svc & NODE_LIBRE_RELAY:
                    libre[(ah, ap_)] = svc
    print("gossiped from %d node(s): %d addrs, %d advertise the libre bit; probing..."
          % (ok, len(seen), len(libre)))
    do_probe(list(libre.keys()), args)


def do_check(host, port, args):
    r = probe(host, port, args.network, args.socks5)
    print("probed %s:%d  ua=%s  services=0x%08x  feefilter=%s\n"
          % (host, port, r["ua"], r["services"] or 0, r["feefilter"]))
    svc, ua, ff = r["services"] or 0, r["ua"] or "", r["feefilter"]
    exposed = False
    if not (svc & NODE_LIBRE_RELAY):
        print("[note   ] NODE_LIBRE_RELAY (bit 29) not set -> not peering as libre-relay")
    if svc & NODE_REDUCED_DATA:
        print("[EXPOSED] NODE_REDUCED_DATA (bit 27) advertised -> a real Libre Relay never sets it"); exposed = True
    else:
        print("[ ok    ] NODE_REDUCED_DATA (bit 27) not advertised")
    if "Knots" in ua:
        print("[EXPOSED] user agent contains 'Knots' -> un-spoofed"); exposed = True
    else:
        print("[ ok    ] user agent shows no 'Knots' tag")
    if ff is not None and 0 <= ff < 1_000_000 and ff >= 1000:
        print("[warn   ] feefilter=%d -> Knots default; Libre Relay sends 100 (only visible on a calm mempool)" % ff)
    elif ff is not None and 0 <= ff < 1_000_000:
        print("[ ok    ] feefilter=%d matches Libre Relay's floor" % ff)
    print("\nverdict:", "DETECTABLE as garbageman" if exposed else "no passive garbageman tell observed")


def do_banlist(args):
    any_ok = False
    for name, url in BANLISTS.items():
        try:
            nets, other = fetch_banlist(url)
        except Exception as e:
            print("%s: fetch failed: %s" % (name, e)); continue
        any_ok = True
        print("%s: %d IP nets banned (+%d onion/other)" % (name, len(nets), other))
        if args.ip:
            print("  %s: %s" % (args.ip, "BANNED" if ip_banned(nets, args.ip) else "not banned"))
    if not any_ok:
        print("no banlist fetched")


def main():
    ap = argparse.ArgumentParser(prog="libre-recon", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    def common(p):
        p.add_argument("--network", default="main", choices=list(MAGIC))
        p.add_argument("--socks5", default=None, help="SOCKS5 proxy, e.g. 127.0.0.1:9050 for Tor")
        p.add_argument("--workers", type=int, default=16)

    pp = sub.add_parser("probe"); pp.add_argument("targets", nargs="+"); common(pp)
    cp = sub.add_parser("crawl"); cp.add_argument("--seeds", type=int, default=4); common(cp)
    kp = sub.add_parser("check"); kp.add_argument("target"); common(kp)
    bp = sub.add_parser("banlist"); bp.add_argument("--ip", default=None); common(bp)
    args = ap.parse_args()

    if args.mode == "probe":
        cands = [(t.rpartition(":")[0] or t, int(t.rpartition(":")[2]) if ":" in t else 8333)
                 for t in args.targets]
        do_probe(cands, args)
    elif args.mode == "crawl":
        do_crawl(args)
    elif args.mode == "check":
        h = args.target.rpartition(":")[0] or args.target
        p = int(args.target.rpartition(":")[2]) if ":" in args.target else 8333
        do_check(h, p, args)
    elif args.mode == "banlist":
        do_banlist(args)


if __name__ == "__main__":
    main()
