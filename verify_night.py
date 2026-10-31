#!/usr/bin/env python3
"""Перевірка чистоти pcap ночі без tcpdump: DNS, NTP, порт i2pd, трафік повз VPN-тунель.
Використання: python3 scripts/verify_night.py captures/night1"""
import json
import struct
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool
from pathlib import Path

I2P_PORT = 24567
WG_PORT = 51820


VM_IP = bytes([10, 0, 2, 15])


def ports(frame):
    """(вихідний?, порт джерела, порт призначення, зміщення UDP) з Ethernet-кадру;
    None — не IP, не TCP/UDP або не перший IP-фрагмент (у ньому немає портів)."""
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    if ethertype == 0x0800:                      # IPv4
        if struct.unpack_from("!H", frame, 20)[0] & 0x1FFF:
            return None                          # наступний фрагмент: на місці портів — дані
        ihl = (frame[14] & 0x0F) * 4
        proto, off, out = frame[23], 14 + ihl, frame[26:30] == VM_IP
    elif ethertype == 0x86DD:                    # IPv6 (без розбору розширених заголовків)
        proto, off, out = frame[20], 54, frame[22] != 0xFE   # fe80:: — службові NDP
    else:
        return None
    if proto not in (6, 17) or len(frame) < off + 4:
        return None
    sport, dport = struct.unpack_from("!HH", frame, off)
    return out, sport, dport, off


def qname(frame, off):
    """Ім'я з DNS-запиту (UDP-заголовок 8 байт + DNS-заголовок 12 байт)."""
    o, parts = off + 20, []
    while o < len(frame) and frame[o]:
        parts.append(frame[o + 1:o + 1 + frame[o]].decode(errors="replace"))
        o += 1 + frame[o]
    return ".".join(parts)


def scan(path):
    c, names = Counter(), Counter()
    first = last = None
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while hdr := f.read(16):
            sec, _, caplen, _ = struct.unpack(endian + "IIII", hdr)
            frame = f.read(caplen)
            first = first or sec
            last = sec
            c["pkts"] += 1
            p = ports(frame)
            if p is None:
                c["other"] += 1
                continue
            out, sp, dp, off = p
            if 53 in (sp, dp):
                c["dns"] += 1
                if dp == 53:
                    names[qname(frame, off)] += 1
            if 123 in (sp, dp):
                c["ntp"] += 1
            if I2P_PORT in (sp, dp):
                c["i2p_port"] += 1
            if out and WG_PORT not in (sp, dp):
                c["not_wg"] += 1                 # вихідний пакет повз тунель — справжній витік для VPN
    c["dur_s"] = (last - first) if first else 0
    return path.name, (c, names)


def main():
    root = Path(sys.argv[1])
    files = sorted(root.glob("vm*/*.pcap"))
    with Pool() as pool:
        res = dict(pool.map(scan, files))
    dns_names = defaultdict(Counter)
    for name, (c, names) in res.items():
        dns_names[name.split("__")[0]].update(names)
    res = {name: c for name, (c, _) in res.items()}
    journal = [json.loads(l) for j in sorted(root.glob("vm*/journal.jsonl")) for l in open(j)]
    ok = {f"{r['label']}__{r['session']}.pcap" for r in journal if r["status"] == "ok"}
    print(f"pcap: {len(files)}, сесій ok у журналах: {len(ok)}, без pcap: {len(ok - res.keys())}, "
          f"pcap без запису ok: {len(res.keys() - ok)}")

    by = defaultdict(list)
    for name, c in res.items():
        by[name.split("__")[0]].append(c)
    print(f"\n{'клас':15} {'n':>3} {'пакетів,медіана':>16} {'трив.,с мін–макс':>17} "
          f"{'DNS макс':>9} {'NTP макс':>9} {'i2pd макс':>10} {'вих. повз WG':>13}")
    for label, cs in sorted(by.items()):
        pk = sorted(c["pkts"] for c in cs)
        d = [c["dur_s"] for c in cs]
        print(f"{label:15} {len(cs):3} {pk[len(pk) // 2]:16} {min(d):8}–{max(d):<8} "
              f"{max(c['dns'] for c in cs):9} {max(c['ntp'] for c in cs):9} "
              f"{max(c['i2p_port'] for c in cs):10} {max(c['not_wg'] for c in cs):13}")

    print("\nПідозрілі сесії:")
    for name, c in sorted(res.items()):
        label = name.split("__")[0]
        why = []
        if label.startswith("tor") and c["dns"]:
            why.append(f"DNS {c['dns']} у Tor")
        if label != "i2p" and c["i2p_port"]:
            why.append(f"порт i2pd {c['i2p_port']}")
        if label == "vpn" and c["not_wg"]:
            why.append(f"{c['not_wg']} вихідних пакетів повз тунель")
        if c["dur_s"] < 240:
            why.append(f"тривалість {c['dur_s']} с")
        if why:
            print(f"  {name}: {', '.join(why)}")

    print("\nDNS-запити в Tor-класах (ім'я: кількість):")
    for label, names in sorted(dns_names.items()):
        if label.startswith("tor") and names:
            print(f"  {label}: " + ", ".join(f"{n} {k}" for n, k in
                                                ((v, k) for k, v in names.most_common())))


if __name__ == "__main__":
    main()
