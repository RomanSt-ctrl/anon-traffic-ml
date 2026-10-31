#!/usr/bin/env python3
"""Нічний збір розміченого трафіку: одна сесія = один режим = один pcap-файл."""
import argparse
import json
import random
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

LAB = Path("/opt/lab")
OUT = LAB / "captures"
I2P_PORT = 24567          # фіксований порт i2pd: відфільтровуємо його в усіх не-I2P сесіях
MODES = ["clearnet", "vpn", "tor_plain", "tor_obfs4", "tor_snowflake", "tor_webtunnel", "i2p"]


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def curl(url, *extra, timeout=30):
    """Повертає (HTTP-код, тіло відповіді). Код "000" — з'єднання не вдалося."""
    r = run(["curl", "-s", "-m", str(timeout), "-w", "\n%{http_code}", *extra, url])
    body, _, code = r.stdout.rpartition("\n")
    return code, body


# Процеси шукаємо за командним рядком (-f), а не за назвою:
# i2pd 3.0 перейменовує свій процес на "i2pd-daemon", і "pkill -x i2pd" його не бачить
TOOLS = {"tor": "^tor -f ", "i2pd": "^i2pd --datadir", "firefox": "/usr/lib/firefox/"}


def kill(pattern):
    """Зупинити процес сигналом TERM; якщо за 30 с не завершився — KILL."""
    run(["pkill", "-f", pattern])
    for _ in range(30):
        if run(["pgrep", "-f", pattern]).returncode != 0:
            return
        time.sleep(1)
    run(["pkill", "-9", "-f", pattern])


def leftovers():
    """Які інструменти анонімізації ще працюють (має бути порожньо перед стартом режиму)."""
    alive = [name for name, pattern in TOOLS.items() if run(["pgrep", "-f", pattern]).returncode == 0]
    if run(["ip", "link", "show", "proton"]).returncode == 0:
        alive.append("wireguard")
    return alive


def stop_all():
    """Повернути систему в чистий стан між сесіями."""
    run(["sudo", "pkill", "-INT", "-x", "tcpdump"])
    kill(TOOLS["firefox"])
    run(["pkill", "-x", "geckodriver"])
    kill(TOOLS["tor"])
    kill(TOOLS["i2pd"])
    run(["sudo", "wg-quick", "down", "proton"])
    shutil.rmtree("/tmp/tor-data", ignore_errors=True)
    # віддалені сервери ще ~30 с досилають FIN/RST на закриті з'єднання — не пускаємо їх у наступну сесію
    time.sleep(30)


# ---------- запуск режимів: повертають рядок для журналу або None, якщо режим не запрацював

def start_tor(mode):
    torrc = LAB / "torrc" / mode.removeprefix("tor_")
    with open("/tmp/tor.log", "w") as log:
        subprocess.Popen(["tor", "-f", str(torrc)], stdout=log, stderr=subprocess.STDOUT)
    # вбудовані мости перевантажені: obfs4/Snowflake інколи стартують кілька хвилин
    deadline = time.time() + (300 if mode == "tor_plain" else 600)
    while "Bootstrapped 100%" not in Path("/tmp/tor.log").read_text():
        if time.time() > deadline:
            return None
        time.sleep(2)
    # через перевантажений міст перший ланцюжок інколи не встигає — даємо три спроби
    for attempt in range(3):
        code, body = curl("https://check.torproject.org/api/ip",
                          "--socks5-hostname", "127.0.0.1:9050", timeout=60)
        if code == "200" and json.loads(body).get("IsTor"):
            return json.loads(body)["IP"]
    return None


def start_i2p():
    subprocess.Popen(["i2pd", f"--datadir={LAB}/i2pd", "--certsdir=/usr/share/i2pd/certificates",
                      f"--port={I2P_PORT}", "--httpproxy.port=4444", "--http.port=7070",
                      "--log=file", f"--logfile={LAB}/i2pd/i2pd.log", "--loglevel=warn"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 600
    while time.time() < deadline:
        time.sleep(15)
        for site in ("http://stats.i2p/", "http://zzz.i2p/", "http://reg.i2p/"):
            code, _ = curl(site, "-x", "http://127.0.0.1:4444", timeout=60)
            if code in ("200", "301", "302"):
                return "i2p-ready"
    return None


def start_vpn(home_ip):
    if run(["sudo", "wg-quick", "up", "proton"]).returncode != 0:
        return None
    code, ip = curl("https://api.ipify.org", timeout=20)
    return ip if code == "200" and ip != home_ip else None


def start_mode(mode, home_ip):
    if mode.startswith("tor_"):
        return start_tor(mode)
    if mode == "i2p":
        return start_i2p()
    if mode == "vpn":
        return start_vpn(home_ip)
    code, _ = curl("https://api.ipify.org", timeout=20)
    return "direct" if code == "200" else None


# ---------- запис трафіку

def start_capture(iface, gateway, pcap, mode):
    # SSH-керування приходить лише від NAT-шлюзу; просто "not port 22" не можна —
    # один із вбудованих мостів obfs4 працює саме на порту 22
    flt = f"not (host {gateway} and tcp port 22)"
    if mode != "i2p":
        flt += f" and not port {I2P_PORT}"
    proc = subprocess.Popen(["sudo", "tcpdump", "-i", iface, "-n", "-Z", "lab", "-w", str(pcap), flt],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)                       # дати tcpdump відкрити інтерфейс
    return proc


def stop_capture(proc):
    run(["sudo", "pkill", "-INT", "-x", "tcpdump"])
    proc.wait(timeout=30)


# ---------- браузер

def make_browser(mode):
    opts = Options()
    opts.add_argument("-headless")
    opts.binary_location = "/usr/bin/firefox"
    prefs = {
        # фонові служби Firefox, не пов'язані з переглядом сторінок
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        "toolkit.telemetry.enabled": False,
        "app.normandy.enabled": False,
        "app.update.auto": False,
        "browser.safebrowsing.malware.enabled": False,
        "browser.safebrowsing.phishing.enabled": False,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        "network.trr.mode": 5,          # вимкнути DNS-over-HTTPS: DNS іде системним шляхом
        "network.proxy.type": 0,        # 0 = без проксі (clearnet, vpn)
    }
    if mode.startswith("tor_"):
        prefs |= {"network.proxy.type": 1,
                  "network.proxy.socks": "127.0.0.1", "network.proxy.socks_port": 9050,
                  "network.proxy.socks_version": 5, "network.proxy.socks_remote_dns": True}
    elif mode == "i2p":
        prefs |= {"network.proxy.type": 1,
                  "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 4444,
                  "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 4444}
    for key, value in prefs.items():
        opts.set_preference(key, value)
    driver = webdriver.Firefox(options=opts, service=Service("/usr/local/bin/geckodriver"))
    driver.set_page_load_timeout(90)
    return driver


def browse(driver, sites, minutes, rng):
    """Імітація перегляду: сайт → прокрутка → іноді перехід за посиланням → пауза."""
    end = time.time() + minutes * 60
    pages = 0
    while time.time() < end:
        url = rng.choice(sites)
        try:
            driver.get(url)
            pages += 1
            for _ in range(rng.randint(1, 4)):
                driver.execute_script("window.scrollBy(0, arguments[0]);", rng.randint(300, 900))
                time.sleep(rng.uniform(2, 6))
            host = urlsplit(driver.current_url).netloc
            links = [a.get_attribute("href") for a in driver.find_elements(By.CSS_SELECTOR, "a[href]")[:60]]
            links = [link for link in links if link and urlsplit(link).netloc == host]
            if links and rng.random() < 0.5 and time.time() < end:
                driver.get(rng.choice(links))
                pages += 1
        except WebDriverException:
            pass                        # сайт не відкрився — це теж реалістичний трафік, ідемо далі
        time.sleep(rng.uniform(5, 20))
    return pages


def read_sites(path):
    lines = path.read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def sites_for(mode, sites):
    if mode == "i2p":
        return sites["i2p"]
    if mode.startswith("tor_"):
        return sites["clearnet"] + sites["onion"]
    return sites["clearnet"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm", type=int, required=True)
    ap.add_argument("--night", type=int, required=True)
    ap.add_argument("--reps", type=int, default=9, help="скільки сесій кожного режиму")
    ap.add_argument("--minutes", type=float, default=5, help="тривалість запису однієї сесії")
    ap.add_argument("--modes", default=",".join(MODES))
    args = ap.parse_args()

    rng = random.Random(args.night * 100 + args.vm)
    schedule = args.modes.split(",") * args.reps
    rng.shuffle(schedule)

    route = run(["ip", "-o", "route", "show", "default"]).stdout.split()
    gateway, iface = route[2], route[4]
    sites = {name: read_sites(LAB / "sites" / f"{name}.txt") for name in ("clearnet", "onion", "i2p")}
    OUT.mkdir(exist_ok=True)
    journal = OUT / "journal.jsonl"

    stop_all()
    home_ip = curl("https://api.ipify.org")[1]
    print(f"vm{args.vm} night{args.night}: {len(schedule)} sessions, iface {iface}, gateway {gateway}", flush=True)

    for i, mode in enumerate(schedule, 1):
        if shutil.disk_usage(OUT).free < 1_000_000_000:
            print("Менше 1 ГБ вільного місця — зупиняюсь", flush=True)
            break
        sid = f"n{args.night}_vm{args.vm}_s{i:03d}"
        pcap = OUT / f"{mode}__{sid}.pcap"
        rec = {"session": sid, "label": mode, "vm": args.vm, "night": args.night,
               "planned_min": args.minutes, "status": "started"}
        t0 = time.time()
        try:
            alive = leftovers()
            if alive:
                rec["status"] = f"dirty: {','.join(alive)}"   # чужий процес зіпсував би мітку
                continue
            rec["exit"] = start_mode(mode, home_ip)
            rec["ready_s"] = round(time.time() - t0)
            if rec["exit"] is None:
                rec["status"] = "not_ready"
                continue
            cap = start_capture(iface, gateway, pcap, mode)
            rec["start"] = now()
            driver = make_browser(mode)
            try:
                rec["pages"] = browse(driver, sites_for(mode, sites), args.minutes, rng)
            finally:
                driver.quit()
            time.sleep(3)               # дочекатися останніх пакетів (закриття з'єднань)
            stop_capture(cap)
            rec["end"] = now()
            rec["bytes"] = pcap.stat().st_size
            rec["status"] = "ok"
        except Exception as e:
            rec["status"] = f"error: {e!r}"[:300]
        finally:
            stop_all()
            with journal.open("a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(f"[{i}/{len(schedule)}] {now()} {mode:14} {rec['status']}", flush=True)
            time.sleep(10)
    print("Готово", flush=True)


if __name__ == "__main__":
    main()
