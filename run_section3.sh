#!/bin/bash
# Повне відтворення розділів 3.2–3.4 з pcap (журнал, п. 9). Запуск з каталогу doslid1:  bash scripts/run_section3.sh
set -euo pipefail
PY=../venv/bin/python
mkdir -p results/logs
$PY scripts/extract_flows.py lab/captures data/flows                     # етап Е: основний набір (≈ 15 с)
$PY scripts/select_features.py   2>&1 | tee results/logs/3_2.log         # 3.2 (≈ 3 хв)
$PY scripts/train_models.py      2>&1 | tee results/logs/3_3.log         # 3.3
for m in pad_rand pad_mtu jitter pad_mtu+jitter; do                      # 3.4: масковані копії набору
    $PY scripts/extract_flows.py lab/captures "data/flows_obf/$m" "$m"
done
$PY scripts/obfuscation.py       2>&1 | tee results/logs/3_4.log         # 3.4
$PY scripts/robustness.py       2>&1 | tee results/logs/3_5.log         # додаткові перевірки достовірності
