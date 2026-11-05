#!/bin/sh
# xkeen-ik installer (Keenetic + Entware).
#   curl -fsSL https://raw.githubusercontent.com/icomium/xkeen-ik/main/install.sh | sh
# Variables: XIK_BRANCH (default main)
set -e
REPO="icomium/xkeen-ik"
BRANCH="${XIK_BRANCH:-main}"
DIR=/opt/etc/xkeen-ik
export PATH=/opt/bin:/opt/sbin:$PATH

[ -x /opt/bin/opkg ] || { echo "Нужен Entware (/opt/bin/opkg). Сначала установите его на USB-накопитель."; exit 1; }

echo "== 1/4 Зависимости"
opkg update
opkg install curl ca-certificates tar
if ! command -v python3 >/dev/null 2>&1; then
  opkg install python3 || opkg install python3-light python3-openssl
fi
CHECK='import ssl, zipfile, json, urllib.request, tarfile, hashlib, difflib, http.server'
python3 -c "$CHECK" 2>/dev/null || { opkg install python3-openssl python3-codecs >/dev/null 2>&1 || true; }
python3 -c "$CHECK" || { echo "В Python не хватает модулей (ssl/zipfile). Установите полный пакет: opkg install python3"; exit 1; }

echo "== 2/4 Панель xkeen-ik"
mkdir -p "$DIR"
curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/xkeen-ik.py" -o "$DIR/xkeen-ik.py.new"
python3 -c "import sys; compile(open(sys.argv[1]).read(), 'x', 'exec')" "$DIR/xkeen-ik.py.new"
mv "$DIR/xkeen-ik.py.new" "$DIR/xkeen-ik.py"
chmod 755 "$DIR/xkeen-ik.py"

echo "== 3/4 SKeen (без ядра)"
if [ ! -x /opt/bin/skeen ]; then
  echo ">>> Установщик SKeen спросит про sing-box: выберите ПРОПУСТИТЬ. Ядро sing-box-lx поставит xkeen-ik."
  curl -Ls https://github.com/jinndi/SKeen/releases/latest/download/skeen | sh
else
  echo "SKeen уже установлен, пропускаю."
fi

echo "== 4/4 Ядро sing-box-lx, настройка SKeen, автозапуск"
python3 "$DIR/xkeen-ik.py" setup | tee /tmp/xik-setup.log
/opt/etc/init.d/S98xkeen-ik restart

IP=$(ip -4 addr show br0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -n1)
TOKEN=$(sed -n 's/^TOKEN=//p' /tmp/xik-setup.log | head -n1)
rm -f /tmp/xik-setup.log
echo
echo "Готово. Панель: http://${IP:-ROUTER_IP}:8090/?token=${TOKEN}"
