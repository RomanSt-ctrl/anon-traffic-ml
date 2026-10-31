#!/usr/bin/env bash
# Запуск нічного збору на 5 клонах. Використання: bash scripts/start_night.sh <ніч> [reps] [хвилин]
set -euo pipefail
cd ~/claude_dir/kursova/doslid1/lab
NIGHT=$1
REPS=${2:-8}
MIN=${3:-5}
for N in 1 2 3 4 5; do
    VBoxManage startvm lab-$N --type headless
done
for N in 1 2 3 4 5; do
    until ssh -o ConnectTimeout=3 lab-$N true 2>/dev/null; do sleep 5; done
    # ім'я машини має бути в /etc/hosts, інакше кожен sudo шле DNS-запит про нього (шум у pcap)
    ssh lab-$N 'grep -q lab-golden /etc/hosts || echo "127.0.1.1 lab-golden" | sudo tee -a /etc/hosts >/dev/null'
    # не брати домен пошуку з DHCP: інакше частина DNS-запитів VPN-сесії йде повз тунель
    ssh lab-$N 'sudo grep -q use-domains /etc/netplan/50-cloud-init.yaml || { printf "network:\n  version: 2\n  ethernets:\n    lan:\n      match:\n        name: \"en*\"\n      dhcp4: true\n      dhcp6: true\n      dhcp4-overrides:\n        use-domains: false\n      dhcp6-overrides:\n        use-domains: false\n" | sudo tee /etc/netplan/50-cloud-init.yaml >/dev/null; sudo netplan apply; sleep 5; }'
    scp -q secrets/proton$N.conf lab-$N:/tmp/proton.conf
    ssh lab-$N 'sudo install -m 600 /tmp/proton.conf /etc/wireguard/proton.conf && rm /tmp/proton.conf'
    scp -q scripts/collect.py lab-$N:/opt/lab/collect.py
    scp -q vm/sites/*.txt lab-$N:/opt/lab/sites/
    ssh lab-$N "tmux new-session -d -s collect '/opt/lab/venv/bin/python /opt/lab/collect.py --vm $N --night $NIGHT --reps $REPS --minutes $MIN 2>&1 | tee -a /opt/lab/captures/console.log'"
    echo "lab-$N: запущено"
done
