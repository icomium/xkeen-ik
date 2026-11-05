#!/bin/sh
# Полное удаление xkeen-ik + sing-box-lx + SKeen с роутера Keenetic (Entware).
#
# Использование:  sh uninstall.sh [опции]
#   -n, --dry-run    ничего не удалять, только показать план и проверки
#   -y, --yes        не спрашивать подтверждение
#   --keep-data      оставить настройки (/opt/etc/skeen и /opt/etc/xkeen-ik)
#   --no-backup      не делать архив настроек перед удалением
#   -h, --help       эта справка
#
# Что НЕ удаляется: Entware, python3, curl и другие пакеты opkg, /opt/bin/sing-box
# (мог быть поставлен вами), правила и политики самого KeeneticOS.
# Коды выхода: 0 - всё чисто, 1 - были ошибки, 2 - остались следы (см. вывод),
#              64 - неверные аргументы, 65 - отмена пользователем/не те условия.

R="${XIK_ROOT:-}"          # префикс корня (нужен только для тестов)
YES=0; DRY=0; KEEP=0; BKP=1
ERR=0; WARN=0; LEFT=0
TS=$(date +%Y%m%d-%H%M%S)

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ok]   %s\n' "$*"; }
info() { printf '  [..]   %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; WARN=$((WARN+1)); }
err()  { printf '  [FAIL] %s\n' "$*"; ERR=$((ERR+1)); }
left() { printf '  [LEFT] %s\n' "$*"; LEFT=$((LEFT+1)); }
step() { printf '\n== %s\n' "$*"; }

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

for a in "$@"; do
  case "$a" in
    -y|--yes) YES=1 ;;
    -n|--dry-run) DRY=1 ;;
    --keep-data) KEEP=1 ;;
    --no-backup) BKP=0 ;;
    -h|--help) usage; exit 0 ;;
    *) say "Неизвестный параметр: $a"; usage; exit 64 ;;
  esac
done

# ---------- пути ----------
PANEL_FILES="$R/opt/etc/init.d/S98xkeen-ik $R/opt/bin/xkeen-ik $R/opt/var/run/xkeen-ik.pid $R/opt/var/log/xkeen-ik.log"
PANEL_DATA="$R/opt/etc/xkeen-ik"
CORE_FILES="$R/opt/bin/sing-box-lx $R/opt/bin/sing-box-lx.bak $R/opt/bin/.xik-tmp"
SKEEN_FILES="$R/opt/etc/init.d/S99SKeen $R/opt/bin/skeen $R/opt/bin/skeen-api $R/opt/bin/skeen-box $R/opt/etc/ndm/netfilter.d/skeen_firewall.sh $R/tmp/.skeen $R/tmp/run/skeen.pid $R/tmp/run/skeen-api.pid"
SKEEN_DATA="$R/opt/etc/skeen"
PORTS="8090 3000 9999 9090 65082"

exists() { [ -e "$1" ] || [ -L "$1" ]; }

# безопасное удаление: только внутри /opt и /tmp, никогда сами корневые каталоги
safe_rm() {
  for p in "$@"; do
    case "$p" in
      "$R"/opt/*|"$R"/tmp/*) ;;
      *) err "отказ удалять путь вне /opt и /tmp: $p"; continue ;;
    esac
    case "$p" in
      "$R/opt"|"$R/opt/"|"$R/opt/bin"|"$R/opt/bin/"|"$R/opt/etc"|"$R/opt/etc/"|"$R/opt/etc/init.d"|"$R/opt/etc/init.d/"|"$R/opt/var"|"$R/opt/var/"|"$R/tmp"|"$R/tmp/"|"$R/opt/etc/ndm"|"$R/opt/etc/ndm/"|"$R/opt/etc/ndm/netfilter.d"|"$R/opt/etc/ndm/netfilter.d/")
        err "отказ удалять системный каталог: $p"; continue ;;
    esac
    if exists "$p"; then
      if [ "$DRY" = 1 ]; then
        info "[dry-run] rm -rf $p"
      elif rm -rf "$p" 2>/dev/null; then
        ok "удалено: $p"
      else
        err "не удалось удалить: $p"
      fi
    fi
  done
}

# PID процессов по имени бинарника или подстроке командной строки
pids_by() {
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = "$$" ] && continue
    [ -r "$d/cmdline" ] || continue
    cl=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    [ -n "$cl" ] || continue
    first=${cl%% *}; base=${first##*/}
    for pat in "$@"; do
      case "$pat" in
        name:*) [ "$base" = "${pat#name:}" ] && { echo "$pid"; break; } ;;
        cmd:*)  case "$cl" in *"${pat#cmd:}"*) echo "$pid"; break ;; esac ;;
      esac
    done
  done
}
running_pids() { pids_by name:sing-box-lx name:skeen-box name:skeen-api cmd:xkeen-ik.py cmd:/opt/bin/skeen; }

# ---------- 0. предварительные проверки ----------
step "0. Проверки перед удалением"
if [ -z "$R" ] && [ "$(id -u 2>/dev/null)" != "0" ]; then
  err "нужны права root"; exit 65
fi
if [ ! -d "$R/opt" ]; then
  err "каталог /opt не найден: Entware не установлен или флешка не смонтирована"; exit 65
fi
ok "/opt доступен"
touch "$R/opt/.xik-write-test" 2>/dev/null && rm -f "$R/opt/.xik-write-test" && ok "/opt доступен для записи" || { err "/opt только для чтения"; exit 65; }

FOUND=0
for p in $PANEL_FILES $PANEL_DATA $CORE_FILES $SKEEN_FILES $SKEEN_DATA; do exists "$p" && FOUND=1; done
RP=$(running_pids)
[ -n "$RP" ] && FOUND=1
if [ "$FOUND" = 0 ]; then
  ok "следов xkeen-ik / sing-box-lx / SKeen не найдено, удалять нечего"
fi

# ---------- план ----------
step "План удаления"
say "  Панель:   $PANEL_FILES"
[ "$KEEP" = 1 ] && say "  Данные панели и SKeen: СОХРАНЯЮТСЯ (--keep-data)" || say "  Данные:   $PANEL_DATA $SKEEN_DATA"
say "  Ядро:     $CORE_FILES"
say "  SKeen:    $SKEEN_FILES"
[ -n "$RP" ] && say "  Запущены процессы (PID): $(echo $RP)"
[ "$DRY" = 1 ] && say "  РЕЖИМ ПРОБНОГО ЗАПУСКА: файлы не изменяются"
if exists "$R/opt/bin/sing-box"; then
  warn "найден /opt/bin/sing-box - он НЕ удаляется (не относится к панели). Удалите сами: opkg remove sing-box или rm"
fi

if [ "$DRY" != 1 ] && [ "$YES" != 1 ] && [ "$FOUND" = 1 ]; then
  printf '\nВведите yes для удаления: '
  if [ -r /dev/tty ]; then read ans < /dev/tty; else ans=""; fi
  [ "$ans" = "yes" ] || { say "Отменено."; exit 65; }
fi

# ---------- 1. туннели OpkgTun ----------
step "1. Интерфейсы OpkgTun, созданные SKeen"
if [ -x "$R/opt/bin/skeen" ] && [ -z "$R" ]; then
  TUNS=$("$R/opt/bin/skeen" tun list 2>/dev/null)
  if [ -n "$TUNS" ]; then
    warn "SKeen создал OpkgTun-интерфейсы. Они не удаляются автоматически:"
    printf '%s\n' "$TUNS" | sed 's/^/         /'
    say "         Удалите нужные командой:  skeen tun delete <имя>  (до удаления SKeen)"
  else
    ok "OpkgTun-интерфейсов нет"
  fi
else
  info "skeen недоступен, пропуск"
fi

# ---------- 2. резервная копия ----------
step "2. Резервная копия настроек"
BK="$R/opt/xkeen-ik-removed-$TS.tar.gz"
if [ "$KEEP" = 1 ]; then
  info "настройки остаются на месте, архив не нужен"
elif [ "$BKP" != 1 ]; then
  warn "архив отключён (--no-backup): настройки и подписки будут удалены безвозвратно"
else
  LIST=""
  exists "$SKEEN_DATA" && LIST="$LIST ${SKEEN_DATA#$R/}"
  exists "$PANEL_DATA" && LIST="$LIST ${PANEL_DATA#$R/}"
  if [ -z "$LIST" ]; then
    info "сохранять нечего"
  elif ! command -v tar >/dev/null 2>&1; then
    err "tar не найден, архив невозможен. Повторите с --no-backup или установите tar (opkg install tar)"
    [ "$DRY" = 1 ] || exit 1
  elif [ "$DRY" = 1 ]; then
    info "[dry-run] tar czf $BK $LIST"
  else
    if (cd "${R:-/}" && tar czf "$BK" $LIST 2>/dev/null) && tar tzf "$BK" >/dev/null 2>&1; then
      chmod 600 "$BK" 2>/dev/null
      ok "архив создан и проверен: $BK ($(wc -c < "$BK") байт; внутри токены и ссылки подписок, храните как секрет)"
    else
      err "не удалось создать архив $BK - удаление остановлено, ничего не тронуто"
      rm -f "$BK"; exit 1
    fi
  fi
fi

# ---------- 3. остановка ----------
step "3. Остановка служб"
if [ "$DRY" = 1 ]; then
  info "[dry-run] остановка xkeen-ik, skeen, завершение процессов"
else
  [ -x "$R/opt/etc/init.d/S98xkeen-ik" ] && [ -z "$R" ] && { "$R/opt/etc/init.d/S98xkeen-ik" stop >/dev/null 2>&1; ok "xkeen-ik остановлен"; }
  if [ -x "$R/opt/bin/skeen" ] && [ -z "$R" ]; then
    if command -v timeout >/dev/null 2>&1; then timeout 60 "$R/opt/bin/skeen" stop >/dev/null 2>&1; else "$R/opt/bin/skeen" stop >/dev/null 2>&1; fi
    ok "skeen stop выполнен (он же снимает правила iptables)"
  fi
  RP=$(running_pids)
  if [ -n "$RP" ]; then
    info "завершаю оставшиеся процессы: $(echo $RP)"
    kill $RP 2>/dev/null; sleep 3
    RP=$(running_pids)
    [ -n "$RP" ] && { kill -9 $RP 2>/dev/null; sleep 1; }
  fi
  RP=$(running_pids)
  [ -z "$RP" ] && ok "процессов нет" || err "процессы не завершились: $(echo $RP)"
fi

# ---------- 4. удаление ----------
step "4. Удаление файлов"
safe_rm $PANEL_FILES
safe_rm $SKEEN_FILES
safe_rm $CORE_FILES
if [ "$KEEP" = 1 ]; then
  info "настройки сохранены: $SKEEN_DATA $PANEL_DATA"
else
  safe_rm $PANEL_DATA
  safe_rm $SKEEN_DATA
fi
# осиротевшие ссылки на наши скрипты
for l in "$R"/opt/bin/xkeen-ik* "$R"/opt/bin/skeen*; do
  if [ -L "$l" ] && [ ! -e "$l" ]; then safe_rm "$l"; fi
done

# ---------- 5. проверка результата ----------
step "5. Проверка результата"
ALLP="$PANEL_FILES $CORE_FILES $SKEEN_FILES"
[ "$KEEP" = 1 ] || ALLP="$ALLP $PANEL_DATA $SKEEN_DATA"
if [ "$DRY" = 1 ]; then
  info "[dry-run] проверка результата пропущена"
else
  for p in $ALLP; do exists "$p" && left "файл остался: $p"; done
  [ "$LEFT" = 0 ] && ok "все файлы удалены"

  RP=$(running_pids)
  [ -z "$RP" ] && ok "процессов sing-box-lx/skeen/xkeen-ik нет" || left "процессы ещё работают: $(echo $RP)"

  hooks=$(ls "$R"/opt/etc/init.d 2>/dev/null | grep -iE 'skeen|xkeen-ik')
  [ -z "$hooks" ] && ok "скриптов автозапуска нет" || left "в init.d остались: $(echo $hooks)"
  nh=$(ls "$R"/opt/etc/ndm/*.d 2>/dev/null | grep -i skeen)
  [ -z "$nh" ] && ok "хуков NDM нет" || left "хуки NDM остались: $(echo $nh)"

  if [ -z "$R" ]; then
    for t in iptables-save ip6tables-save; do
      if command -v $t >/dev/null 2>&1; then
        n=$($t 2>/dev/null | grep -ciE 'skeen')
        [ "$n" = 0 ] && ok "$t: правил SKeen нет" || left "$t: найдено правил с 'skeen': $n (поможет перезагрузка роутера)"
      fi
    done
    if command -v ip >/dev/null 2>&1; then
      fw=$(ip rule show 2>/dev/null | grep -i fwmark)
      [ -z "$fw" ] && ok "ip rule: правил по fwmark нет" || warn "ip rule содержит fwmark-правила (могут быть от других служб):$(printf '\n%s' "$fw" | sed 's/^/\n         /')"
    fi
    if command -v netstat >/dev/null 2>&1; then
      for port in $PORTS; do
        netstat -ltn 2>/dev/null | grep -qE "[:.]$port[[:space:]]" && warn "порт $port всё ещё слушается (проверьте: netstat -ltnp)"
      done
    fi
  fi
fi

# ---------- итог ----------
step "Итог"
if [ "$DRY" = 1 ]; then
  say "Пробный запуск завершён. Для реального удаления запустите без -n."
  [ "$ERR" -gt 0 ] && exit 1
  exit 0
fi
say "ошибок: $ERR, предупреждений: $WARN, остатков: $LEFT"
[ "$KEEP" != 1 ] && [ "$BKP" = 1 ] && exists "$BK" && say "Архив настроек: $BK"
say "Entware, python3 и пакеты opkg не тронуты. Если остались [LEFT] по iptables или портам - перезагрузите роутер."
[ "$ERR" -gt 0 ] && exit 1
[ "$LEFT" -gt 0 ] && exit 2
exit 0
