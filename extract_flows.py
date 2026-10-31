#!/usr/bin/env python3
"""Етап Е: pcap сесій → потоки → ознаки (CSV для навчання моделей розділу 3).
Потік — двонапрямлений: протокол + 2 адреси + 2 порти. Напрям «fwd» — від VM (10.0.2.15), «bwd» — до VM.
Потік завершується: TCP RST або FIN з обох боків; пауза > IDLE с; тривалість > ACTIVE с
(як у CICFlowMeter — довгі тунелі Tor/VPN діляться на відрізки по 120 с).
Фільтри (журнал, п. 7):
  1) службовий трафік ОС — DNS 53, DHCP 67/68, NTP 123, mDNS 5353, не-IPv4 (ARP, IPv6 NDP);
  2) IP-фрагменти приєднуються до потоку свого першого фрагмента (не стають окремими «потоками»);
  3) потоки без пакетів в одному з напрямків — «хвости» попередньої сесії і сканування;
  4) перші SKIP с сесії — старт Firefox (службові завантаження Mozilla, ≈ 8 МБ);
  5) TCP-пакети, довші за MTU (TSO/GRO — запис іде до сегментації мережевою картою), діляться на сегменти ≤ MTU,
     як їх бачить спостерігач на лінії зв'язку (журнал, п. 9.1).
IP-адреси і порти пишуться лише як метадані (стовпці meta_*), НЕ як ознаки.
Режим (3-й аргумент, розділ 3.4) — імітація обфускації для всіх класів, крім clearnet:
  pad_mtu  — навантаження кожного пакета з даними доповнюється до PAD_TO байт (вирівнювання розмірів);
  pad_rand — до навантаження додається випадкове доповнення 0–255 байт;
  jitter   — кожен пакет затримується на випадковий час 0–JITTER с (порядок пакетів може змінитися);
  pad_mtu+jitter — обидва. Без аргументу — none (основний набір даних).
meta_no_payload = 1 — потік без жодного байта даних (напр. SYN → RST до недоступного моста obfs4).
Використання: python3 scripts/extract_flows.py lab/captures data/flows [режим]"""
import csv
import json
import struct
import sys
import zlib
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

import numpy as np

VM_IP = bytes([10, 0, 2, 15])
SERVICE_PORTS = {53, 67, 68, 123, 5353}
SKIP = 15.0          # с від початку запису
IDLE = 120.0         # с без пакетів — потік завершено
ACTIVE = 120.0       # максимальна тривалість одного запису потоку
ACT_GAP = 5.0        # пауза, що розділяє періоди активності (active/idle)
MTU = 1500           # MTU Ethernet: довші TCP-пакети в записі — це TSO/GRO, їх ділимо на сегменти
PAD_TO = 1400       # pad_mtu: розмір навантаження після доповнення
JITTER = 0.05        # jitter: максимальна затримка пакета, с
MODES = {"none", "pad_mtu", "pad_rand", "jitter", "pad_mtu+jitter"}

META = ["meta_session", "label", "meta_night", "meta_vm", "meta_flow", "meta_start_s",
        "meta_proto", "meta_remote_ip", "meta_remote_port", "meta_local_port", "meta_no_payload"]


def stats(x, prefix):
    if len(x) == 0:
        return {f"{prefix}_{k}": 0.0 for k in ("min", "max", "mean", "std")}
    return {f"{prefix}_min": float(x.min()), f"{prefix}_max": float(x.max()),
            f"{prefix}_mean": float(x.mean()), f"{prefix}_std": float(x.std())}


def features(f):
    o = np.argsort(f["t"], kind="stable")     # після jitter пакети можуть іти не по порядку
    t = np.array(f["t"])[o]
    ln = np.array(f["len"], float)[o]         # довжина IP-пакета
    pl = np.array(f["pl"], float)[o]          # корисне навантаження TCP/UDP
    hd = ln - pl                              # заголовки IP + TCP/UDP
    out = np.array(f["out"], bool)[o]
    fl = np.array(f["flags"], np.uint8)[o]
    dur = t[-1] - t[0]
    fw, bw = out, ~out
    r = {"protocol": f["proto"], "duration": dur,
         "fwd_pkts": int(fw.sum()), "bwd_pkts": int(bw.sum()),
         "fwd_bytes": ln[fw].sum(), "bwd_bytes": ln[bw].sum(),
         "fwd_payload_bytes": pl[fw].sum(), "bwd_payload_bytes": pl[bw].sum(),
         "fwd_data_pkts": int((pl[fw] > 0).sum()), "bwd_data_pkts": int((pl[bw] > 0).sum()),
         "fwd_header_bytes": hd[fw].sum(), "bwd_header_bytes": hd[bw].sum()}
    r |= stats(ln, "pkt_len") | stats(ln[fw], "fwd_pkt_len") | stats(ln[bw], "bwd_pkt_len")
    r |= stats(pl[pl > 0], "payload") | stats(pl[fw & (pl > 0)], "fwd_payload") | stats(pl[bw & (pl > 0)], "bwd_payload")
    d = max(dur, 1e-6)
    r |= {"flow_bytes_s": ln.sum() / d, "flow_pkts_s": len(t) / d,
          "fwd_pkts_s": fw.sum() / d, "bwd_pkts_s": bw.sum() / d,
          "down_up_ratio": bw.sum() / max(fw.sum(), 1),
          "bytes_ratio_fwd_bwd": ln[fw].sum() / max(ln[bw].sum(), 1)}
    r |= stats(np.diff(t), "flow_iat") | stats(np.diff(t[fw]), "fwd_iat") | stats(np.diff(t[bw]), "bwd_iat")
    for bit, name in ((1, "fin"), (2, "syn"), (4, "rst"), (8, "psh"), (16, "ack"), (32, "urg")):
        r[f"{name}_cnt"] = int(((fl & bit) > 0).sum())
    r["fwd_psh_cnt"] = int(((fl[fw] & 8) > 0).sum())
    r["init_win_fwd"] = f["win_fwd"]
    r["init_win_bwd"] = f["win_bwd"]
    # періоди активності, розділені паузами > ACT_GAP
    gaps = np.diff(t)
    cut = np.flatnonzero(gaps > ACT_GAP)
    starts = np.r_[0, cut + 1]
    ends = np.r_[cut, len(t) - 1]
    r |= stats(t[ends] - t[starts], "active") | stats(gaps[cut], "idle")
    return r


def packets(path):
    """(час, src, dst, proto, sport, dport, ip_len, payload, flags, win) для IPv4 TCP/UDP;
    фрагменти — з портами першого фрагмента. Лічильник відкинутого — у Counter."""
    drop = Counter()
    frag_ports = {}
    with open(path, "rb") as f:
        f.read(24)
        while hdr := f.read(16):
            sec, usec, caplen, _ = struct.unpack("<IIII", hdr)
            fr = f.read(caplen)
            t = sec + usec / 1e6
            if struct.unpack_from("!H", fr, 12)[0] != 0x0800:
                drop["не IPv4"] += 1
                continue
            ihl = (fr[14] & 15) * 4
            tot, ipid, frag = struct.unpack_from("!HHH", fr, 16)
            proto, src, dst = fr[23], fr[26:30], fr[30:34]
            if proto not in (6, 17):
                drop["не TCP/UDP"] += 1
                continue
            offset, more = frag & 0x1FFF, frag & 0x2000
            fkey = (src, dst, ipid, proto)
            if offset:                                    # наступний фрагмент — без заголовка TCP/UDP
                if fkey not in frag_ports:
                    drop["фрагмент без першого"] += 1
                    continue
                sp, dp = frag_ports[fkey]
                yield t, src, dst, proto, sp, dp, tot, tot - ihl, 0, -1
                continue
            o = 14 + ihl
            sp, dp = struct.unpack_from("!HH", fr, o)
            if more:
                frag_ports[fkey] = (sp, dp)
            if proto == 6:
                thl = (fr[o + 12] >> 4) * 4
                pl, fl, win = tot - ihl - thl, fr[o + 13], struct.unpack_from("!H", fr, o + 14)[0]
                if tot > MTU:                             # TSO/GRO: ядро віддало мережевій карті «суперсегмент»;
                    drop["TSO-суперсегмент"] += 1         # у мережі він іде сегментами по MTU — ділимо так само
                    mss = MTU - ihl - thl
                    while pl > mss:
                        drop["TSO-додано сегментів"] += 1
                        yield t, src, dst, proto, sp, dp, MTU, mss, fl & ~9, win   # без FIN(1) і PSH(8)
                        pl -= mss
                    tot = ihl + thl + pl
                yield t, src, dst, proto, sp, dp, tot, pl, fl, win
            else:
                yield t, src, dst, proto, sp, dp, tot, tot - ihl - 8, 0, -1
    yield None, drop


def process(job):
    path, label, session, night, vm, mode = job
    flows, done = {}, []
    drop = Counter()
    t_first = None
    obf = mode != "none" and label != "clearnet"
    rng = np.random.default_rng(zlib.crc32(session.encode()))   # відтворюваний випадковий шум для кожної сесії

    def close(key):
        done.append(flows.pop(key))

    for p in packets(path):
        if p[0] is None:
            drop.update(p[1])
            break
        t, src, dst, proto, sp, dp, ln, pl, flags, win = p
        t_first = t_first or t
        if t - t_first < SKIP:
            drop["перші 15 с"] += 1
            continue
        if sp in SERVICE_PORTS or dp in SERVICE_PORTS:
            drop["службові порти"] += 1
            continue
        if obf:                                            # імітація обфускації (лише не-clearnet, розділ 3.4)
            add = 0
            if pl > 0 and "pad_mtu" in mode:
                add = max(PAD_TO - pl, 0)
            elif pl > 0 and mode == "pad_rand":
                add = int(rng.integers(0, 256))
            drop["obf_orig_bytes"] += ln
            drop["obf_added_bytes"] += add
            ln, pl = ln + add, pl + add
            if "jitter" in mode:
                t += rng.uniform(0, JITTER)
        out = src == VM_IP
        remote, rport, lport = (dst, dp, sp) if out else (src, sp, dp)
        key = (proto, remote, rport, lport)
        f = flows.get(key)
        if f and (t - f["t"][-1] > IDLE or t - f["t"][0] > ACTIVE):
            close(key)
            f = None
        if f is None:
            f = flows[key] = {"key": key, "proto": proto, "t": [], "len": [], "pl": [], "out": [], "flags": [],
                              "win_fwd": -1, "win_bwd": -1, "fin": set()}
        f["t"].append(t)
        f["len"].append(ln)
        f["pl"].append(max(pl, 0))
        f["out"].append(out)
        f["flags"].append(flags)
        if win >= 0:
            side = "win_fwd" if out else "win_bwd"
            if f[side] < 0:
                f[side] = win
        if proto == 6 and flags & 4:                       # RST
            close(key)
        elif proto == 6 and flags & 1:                     # FIN
            f["fin"].add(out)
            if len(f["fin"]) == 2:
                close(key)
    done += flows.values()

    rows = []
    for i, f in enumerate(sorted(done, key=lambda f: f["t"][0])):
        n_out = sum(f["out"])
        if n_out == 0 or n_out == len(f["out"]):
            drop["потік в один бік"] += 1
            continue
        proto, remote, rport, lport = f["key"]
        no_payload = int(sum(f["pl"]) == 0)                # невдале з'єднання (SYN → RST), даних не було
        meta = dict(zip(META, (session, label, night, vm, i, round(f["t"][0] - t_first, 3),
                               proto, ".".join(map(str, remote)), rport, lport, no_payload)))
        rows.append(meta | {k: (round(v, 6) if isinstance(v, float) else v) for k, v in features(f).items()})
    return session, label, rows, drop


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "none"
    assert mode in MODES, f"режим: {sorted(MODES)}"
    out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for jf in sorted(src.glob("night*/vm*/journal.jsonl")):
        for line in open(jf):
            r = json.loads(line)
            pcap = jf.parent / f"{r['label']}__{r['session']}.pcap"
            if r["status"] == "ok" and pcap.exists():
                jobs.append((pcap, r["label"], r["session"], r["night"], r["vm"], mode))
    print(f"сесій: {len(jobs)}, режим: {mode}", flush=True)
    jobs.sort(key=lambda j: -j[0].stat().st_size)          # великі спершу — рівніше навантаження
    with Pool() as pool, open(out / "flows.csv", "w", newline="") as ff, \
            open(out / "sessions.csv", "w", newline="") as sf:
        fw = sw = None
        for n, (session, label, rows, drop) in enumerate(pool.imap_unordered(process, jobs), 1):
            if rows:
                if fw is None:
                    fw = csv.DictWriter(ff, fieldnames=list(rows[0]))
                    fw.writeheader()
                fw.writerows(rows)
            srow = {"session": session, "label": label, "flows": len(rows),
                    "pkts_in_flows": sum(r["fwd_pkts"] + r["bwd_pkts"] for r in rows)} | \
                   {f"drop_{k}": v for k, v in sorted(drop.items())}
            if sw is None:
                sw = csv.DictWriter(sf, fieldnames=["session", "label", "flows", "pkts_in_flows",
                                                    "drop_не IPv4", "drop_не TCP/UDP", "drop_фрагмент без першого",
                                                    "drop_перші 15 с", "drop_службові порти", "drop_потік в один бік",
                                                    "drop_TSO-суперсегмент", "drop_TSO-додано сегментів",
                                                    "drop_obf_orig_bytes", "drop_obf_added_bytes"],
                                    restval=0)
                sw.writeheader()
            sw.writerow(srow)
            if n % 50 == 0:
                print(f"  {n}/{len(jobs)}", flush=True)


if __name__ == "__main__":
    main()
