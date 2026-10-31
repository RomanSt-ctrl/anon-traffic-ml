#!/usr/bin/env bash
# Стан нічного збору: скільки сесій готово, статуси, вільне місце. Використання: bash scripts/check_night.sh
for N in 1 2 3 4 5; do
    ssh -o ConnectTimeout=5 lab-$N '
        J=/opt/lab/captures/journal.jsonl
        alive=$(tmux has-session -t collect 2>/dev/null && echo працює || echo завершено)
        done=$(wc -l < $J 2>/dev/null || echo 0)
        free=$(df -h --output=avail /opt/lab | tail -1)
        statuses=$(jq -r .status $J 2>/dev/null | sort | uniq -c | xargs)
        echo "lab-'$N': $alive, сесій $done/56, вільно$free, статуси: $statuses"
        jq -r "select(.status != \"ok\") | \"   ! \(.label) \(.status)\"" $J 2>/dev/null'
done
