#!/usr/bin/env bash
# Забрати дані ночі з 5 VM, звірити, очистити VM і вимкнути їх. Використання: bash scripts/fetch_night.sh <ніч>
set -euo pipefail
cd ~/claude_dir/kursova/doslid1/lab
NIGHT=$1
for N in 1 2 3 4 5; do
    if ssh lab-$N 'tmux has-session -t collect 2>/dev/null'; then
        echo "lab-$N: збір ще йде — зупиняюсь"; exit 1
    fi
done
for N in 1 2 3 4 5; do
    DST=captures/night$NIGHT/vm$N
    mkdir -p $DST
    rsync -a lab-$N:/opt/lab/captures/ $DST/
    # звірка: однаковий список файлів і розмірів у VM і на хості
    remote=$(ssh lab-$N 'cd /opt/lab/captures && find . -type f -printf "%P %s\n" | sort')
    here=$(cd $DST && find . -type f -printf "%P %s\n" | sort)
    if [ "$remote" != "$here" ]; then
        echo "lab-$N: розбіжність після копіювання — VM не очищаю"; exit 1
    fi
    echo "lab-$N: скопійовано $(echo "$here" | wc -l) файлів, $(du -sh $DST | cut -f1)"
    ssh lab-$N 'rm -f /opt/lab/captures/*'
    VBoxManage controlvm lab-$N acpipowerbutton
done
for i in $(seq 36); do
    VBoxManage list runningvms | grep -q 'lab-[1-5]' || break
    sleep 5
done
# якщо котрась VM не відреагувала на кнопку живлення за 3 хв — вимикаємо примусово (дані вже на хості)
for N in $(VBoxManage list runningvms | grep -o 'lab-[1-5]' | cut -d- -f2); do
    VBoxManage controlvm lab-$N poweroff
done
echo "Усі VM вимкнено"
