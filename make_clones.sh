#!/usr/bin/env bash
# Створення 5 зв'язаних клонів від знімка "ready" еталонної VM
set -euo pipefail
VMDIR=~/VirtualMashines/Kursova
for N in 1 2 3 4 5; do
    VBoxManage clonevm lab-golden --snapshot ready --options link --name lab-$N --basefolder "$VMDIR" --register
    VBoxManage modifyvm lab-$N --natpf1 delete ssh
    VBoxManage modifyvm lab-$N --natpf1 "ssh,tcp,127.0.0.1,222$N,,22"
    VBoxManage modifyvm lab-$N --uart-mode1 file "$VMDIR/lab-$N/serial.log"
done
VBoxManage list vms | grep lab-
