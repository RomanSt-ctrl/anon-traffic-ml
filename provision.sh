#!/usr/bin/env bash
# Налаштування еталонної VM для запису трафіку. Запускати від root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== 1. Вимикаємо фонові служби, що створюють мережевий шум"
systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer \
    motd-news.timer fwupd-refresh.timer ua-timer.timer \
    update-notifier-download.timer update-notifier-motd.timer apport-autoreport.timer \
    ModemManager.service 2>/dev/null || true
apt-get purge -y unattended-upgrades snapd || true

echo "== 2. Репозиторії Tor Project і Mozilla"
apt-get update
apt-get install -y curl gpg ca-certificates
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
    | gpg --batch --yes --dearmor -o /etc/apt/keyrings/torproject.gpg
echo "deb [signed-by=/etc/apt/keyrings/torproject.gpg] https://deb.torproject.org/torproject.org noble main" \
    > /etc/apt/sources.list.d/torproject.list
curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg -o /etc/apt/keyrings/mozilla.asc
echo "deb [signed-by=/etc/apt/keyrings/mozilla.asc] https://packages.mozilla.org/apt mozilla main" \
    > /etc/apt/sources.list.d/mozilla.list
printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' > /etc/apt/preferences.d/mozilla
# i2pd 2.49 з репозиторію Ubuntu падає (general protection fault у потоці SSU2) — беремо PPA розробників
add-apt-repository -y ppa:purplei2p/i2pd

echo "== 3. Пакети"
apt-get update
apt-get install -y tor deb.torproject.org-keyring i2pd wireguard-tools tcpdump firefox \
    python3-venv jq tmux
# Системні служби tor та i2pd не потрібні: скрипт запускатиме їх сам, коли треба
systemctl disable --now tor tor@default i2pd || true
systemctl mask tor tor@default i2pd

echo "== 4. Сумісність wg-quick з systemd-resolved"
command -v resolvconf >/dev/null || ln -s /usr/bin/resolvectl /usr/local/bin/resolvconf

echo "== 5. lyrebird (obfs4, Snowflake, WebTunnel) з Tor Browser"
install -m 0755 /tmp/lyrebird /usr/local/bin/lyrebird

echo "== 6. geckodriver — «пульт керування» Firefox для Selenium"
GV=$(curl -fsSL https://api.github.com/repos/mozilla/geckodriver/releases/latest | jq -r .tag_name)
curl -fsSL "https://github.com/mozilla/geckodriver/releases/download/$GV/geckodriver-$GV-linux64.tar.gz" \
    | tar -xz -C /usr/local/bin

echo "== 7. Робочі папки і Python-середовище"
install -d -o lab -g lab /opt/lab /opt/lab/captures /opt/lab/i2pd /opt/lab/torrc /opt/lab/sites
sudo -u lab python3 -m venv /opt/lab/venv
sudo -u lab /opt/lab/venv/bin/pip install --quiet selenium

echo "== 8. AppArmor: дозволити i2pd працювати з /opt/lab/i2pd"
printf '/opt/lab/i2pd/ rw,\n/opt/lab/i2pd/** rwk,\n' > /etc/apparmor.d/local/usr.sbin.i2pd
apparmor_parser -r /etc/apparmor.d/usr.sbin.i2pd

echo "== 9. Мережа без прив'язки до MAC-адреси (інакше в клонах не підніметься)"
# use-domains: false — не брати домен пошуку з DHCP (інакше DNS-запити з цим доменом ідуть повз VPN-тунель)
printf 'network:\n  version: 2\n  ethernets:\n    lan:\n      match:\n        name: "en*"\n      dhcp4: true\n      dhcp6: true\n      dhcp4-overrides:\n        use-domains: false\n      dhcp6-overrides:\n        use-domains: false\n' \
    > /etc/netplan/50-cloud-init.yaml
chmod 600 /etc/netplan/50-cloud-init.yaml
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
netplan generate

echo "== Готово"
tor --version | head -1; i2pd --version | head -1; firefox --version; geckodriver --version | head -1
/usr/local/bin/lyrebird -version 2>&1 | head -1 || true
