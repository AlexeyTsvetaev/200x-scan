#!/usr/bin/env bash
#
# RealiTLScanner → отбор доменов (без LE) → проверка HTTPS на код 200 без редиректа.
#
# Файлы по умолчанию:
#   REALITY_SCAN_LOG=/tmp/reality-scan-last.log
#   REALITY_OK_DOMAINS=/tmp/reality-domains-200.txt
#
# IP можно не указывать: скрипт сам узнает публичный IPv4 этой машины (curl к ipify и др.).
# Отключить авто-IP: REALITY_NO_AUTO_IP=1 или явно SCAN_IP=...
#
# Примеры:
#   ./reality-scanner-pick-domains.sh                          # авто IP, 30 потоков
#   ./reality-scanner-pick-domains.sh 40                      # авто IP, 40 потоков
#   ./reality-scanner-pick-domains.sh 195.246.110.129         # свой IP
#   ./reality-scanner-pick-domains.sh 195.246.110.129 40
#
# После заливки скрипта на GitHub (замени USER/REPO/ветку):
#   curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/reality-scanner-pick-domains.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/reality-scanner-pick-domains.sh | bash -s -- --max-scan-sec 300
#
# Только проверка по логу:  ./reality-scanner-pick-domains.sh --check-only
# Ctrl+C во время скана — дальше проверка по REALITY_SCAN_LOG.
#

set -uo pipefail

readonly SCANNER_PATH="${REALITL_SCANNER:-/tmp/RealiTLScanner}"
readonly SCANNER_URL="https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-64"

# Предсказуемые пути — не нужно искать mktemp-имя
: "${REALITY_SCAN_LOG:=/tmp/reality-scan-last.log}"
: "${REALITY_OK_DOMAINS:=/tmp/reality-domains-200.txt}"

die() { echo "[!] $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Нужна команда: $1"; }

usage() {
  cat <<EOF
Файлы по умолчанию:
  Лог сканера:     ${REALITY_SCAN_LOG}
  Домены с 200:    ${REALITY_OK_DOMAINS}

Запуск (IP необязателен — берётся публичный IPv4 этой машины):
  $0                      # авто IP, 30 потоков
  $0 40                   # авто IP, 40 потоков
  $0 <IPv4> [threads]     # явный IP
  SCAN_IP=1.2.3.4 $0       # явный IP через env

Опции:
  --check-only [файл]  Только проверка curl (файл по умолчанию: ${REALITY_SCAN_LOG})
  --max-scan-sec <N>   Остановить скан через N секунд (нужен timeout)
  -h, --help           Справка

Переменные: SCAN_IP, SCAN_THREADS, REALITY_NO_AUTO_IP=1 (запретить авто-IP),
            REALITY_SCAN_LOG, REALITY_OK_DOMAINS, REALITL_SCANNER
EOF
}

# Простая проверка IPv4 (для аргументов)
is_ipv4() {
  [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# Публичный IPv4 машины, с которой запущен скрипт (для RealiTLScanner -addr)
detect_public_ipv4() {
  local ip=""
  need_cmd curl
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://icanhazip.com" \
    "https://checkip.amazonaws.com"
  do
    ip=$(curl -fsS --max-time 10 "$url" 2>/dev/null | tr -d '\r\n' | head -1)
    if is_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

resolve_scan_ip_and_threads() {
  # Уже задано из env — позиционные ниже перезапишут при необходимости
  local ip="${SCAN_IP:-}"
  local threads="${SCAN_THREADS:-30}"

  case "${1:-}" in
    "")
      ;;
    *)
      if [[ -n "${2:-}" ]]; then
        is_ipv4 "$1" || die "Первый аргумент должен быть IPv4: $1"
        [[ "$2" =~ ^[0-9]+$ ]] || die "Второй аргумент — число потоков: $2"
        ip="$1"
        threads="$2"
      else
        if is_ipv4 "$1"; then
          ip="$1"
        elif [[ "$1" =~ ^[0-9]+$ ]]; then
          threads="$1"
        else
          die "Аргумент: IPv4 или число потоков (при авто-IP): $1"
        fi
      fi
      ;;
  esac

  if [[ -z "$ip" ]]; then
    if [[ "${REALITY_NO_AUTO_IP:-}" == "1" ]]; then
      die "Задай IP: $0 <IPv4> [threads] или SCAN_IP=... (или убери REALITY_NO_AUTO_IP=1)"
    fi
    echo "[*] Публичный IPv4 не указан — определяю автоматически (эта машина)..."
    ip=$(detect_public_ipv4) || die "Не удалось получить публичный IPv4. Укажи вручную: $0 <IPv4> [threads] или SCAN_IP=1.2.3.4"
    echo "[*] Будет использован адрес: $ip"
  else
    echo "[*] Адрес для скана: $ip"
  fi

  echo "[*] Потоков сканера: $threads"
  SCAN_RESOLVED_IP="$ip"
  SCAN_RESOLVED_THREADS="$threads"
}

download_scanner() {
  if [[ -x "$SCANNER_PATH" ]]; then
    echo "[*] Сканер уже есть: $SCANNER_PATH"
    return 0
  fi
  need_cmd wget
  echo "[*] Скачивание RealiTLScanner → $SCANNER_PATH"
  wget -q -L --timeout=30 --tries=3 "$SCANNER_URL" -O "$SCANNER_PATH" || die "Не удалось скачать сканер"
  chmod +x "$SCANNER_PATH" || die "chmod не удался"
}

http_code_no_redirect() {
  local url="$1"
  curl -sS -g --connect-timeout 8 --max-time 20 -o /dev/null -w '%{http_code}' \
    "$url" 2>/dev/null || echo "000"
}

is_letsencrypt() {
  local issuer="$1"
  local il
  il=$(echo "$issuer" | tr '[:upper:]' '[:lower:]')
  [[ "$il" == *"let's encrypt"* ]] || [[ "$il" == *"lets encrypt"* ]] || [[ "$il" == *"letsencrypt"* ]]
}

# При успехе кладёт URL в GOT_URL (одна строка для записи в файл)
GOT_URL=""
check_domain_200() {
  local domain="$1"
  local code code_www=""

  GOT_URL=""
  domain="${domain#\*.}"

  code=$(http_code_no_redirect "https://${domain}/")
  if [[ "$code" == "200" ]]; then
    GOT_URL="https://${domain}/"
    echo "OK  $GOT_URL  (HTTP $code)"
    return 0
  fi

  if [[ "$domain" != www.* ]]; then
    code_www=$(http_code_no_redirect "https://www.${domain}/")
    if [[ "$code_www" == "200" ]]; then
      GOT_URL="https://www.${domain}/"
      echo "OK  $GOT_URL  (HTTP $code_www)"
      return 0
    fi
  fi

  echo "SKIP $domain  (https://$domain/ → $code, https://www.$domain/ → ${code_www:-n/a})"
  return 1
}

run_domain_checks() {
  local scan_out="$1"
  local ok_out="$2"

  [[ -f "$scan_out" ]] || die "Файл лога не найден: $scan_out"
  : >"$ok_out"
  echo "[*] Проверка доменов из лога: $scan_out"
  echo "[*] Результаты с HTTP 200 пишутся в: $ok_out"
  if [[ -s "$scan_out" ]]; then
    echo "[*] Размер лога: $(wc -c <"$scan_out") байт"
  else
    echo "[!] Лог пустой — проверять нечего."
    print_final_summary "$ok_out" 0 0
    return 0
  fi

  echo ""
  echo "=== Проверка (кроме Let's Encrypt), первый ответ без редиректа, код 200 ==="
  echo ""

  local line domain issuer n_ok n_all url_line
  n_ok=0
  n_all=0

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    domain=$(echo "$line" | sed -n 's/.*cert-domain=\([^ ]*\).*/\1/p')
    issuer=$(echo "$line" | sed -n 's/.*cert-issuer="\([^"]*\)".*/\1/p')
    [[ -z "$domain" ]] && continue
    ((n_all++)) || true

    if is_letsencrypt "$issuer"; then
      echo "LE   $domain  (issuer: $issuer)"
      continue
    fi

    echo "---- $domain  (issuer: ${issuer:-unknown})"
    if check_domain_200 "$domain"; then
      [[ -n "$GOT_URL" ]] && echo "$GOT_URL" >>"$ok_out"
      ((n_ok++)) || true
    fi
  done < <(grep 'cert-domain=' "$scan_out" 2>/dev/null | sort -u)

  print_final_summary "$ok_out" "$n_ok" "$n_all"
}

print_final_summary() {
  local ok_out="$1"
  local n_ok="$2"
  local n_all="$3"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " Итого: HTTP 200 — $n_ok из $n_all (уникальных cert-domain, не LE)"
  echo " Файл со списком URL: $ok_out"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "=== Домены / URL с ответом 200 (готово к копированию) ==="
  if [[ -s "$ok_out" ]]; then
    cat "$ok_out"
  else
    echo "(нет ни одного домена с 200 по текущим правилам)"
  fi
  echo ""
}

run_scanner_with_early_exit() {
  local ip="$1"
  local threads="$2"
  local scan_out="$3"
  local max_sec="${4:-}"

  download_scanner

  echo ""
  echo "┌─────────────────────────────────────────────────────────────────────"
  echo "│ Лог сканера (фиксированный путь): $scan_out"
  echo "│ Список с 200 будет в: ${REALITY_OK_DOMAINS}"
  echo "│ Ctrl+C — остановить скан и сразу проверить накопленные строки в логе."
  echo "└─────────────────────────────────────────────────────────────────────"
  echo ""

  echo "[*] Команда: $SCANNER_PATH -addr $ip -thread $threads"
  if [[ -n "$max_sec" ]]; then
    need_cmd timeout
    echo "[*] Лимит времени скана: ${max_sec}s"
  fi
  echo ""

  : >"$scan_out"

  if [[ -n "$max_sec" ]]; then
    ( timeout -k 10 "$max_sec" "$SCANNER_PATH" -addr "$ip" -thread "$threads" 2>&1 || true ) | tee -a "$scan_out" &
  else
    "$SCANNER_PATH" -addr "$ip" -thread "$threads" 2>&1 | tee -a "$scan_out" &
  fi
  local pipe_pid=$!

  cleanup_pipe() {
    if kill -0 "$pipe_pid" 2>/dev/null; then
      echo "" >&2
      echo "[*] Остановка сканера — дальше проверка доменов по файлу: $scan_out" >&2
      kill -TERM "$pipe_pid" 2>/dev/null || true
      wait "$pipe_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_pipe INT

  wait "$pipe_pid" 2>/dev/null || true
  trap - INT
}

main() {
  local CHECK_ONLY="" MAX_SCAN_SEC="" CHECK_FILE=""
  local IP THREADS

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check-only)
        # второй аргумент опционален — путь к логу
        if [[ -n "${2:-}" && "$2" != -* ]]; then
          CHECK_FILE="$2"
          shift 2
        else
          CHECK_ONLY=1
          shift
        fi
        ;;
      --max-scan-sec)
        [[ -n "${2:-}" ]] || die "Укажи секунды: --max-scan-sec 120"
        MAX_SCAN_SEC="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        die "Неизвестная опция: $1 (см. $0 --help)"
        ;;
      *)
        break
        ;;
    esac
  done

  need_cmd grep
  need_cmd sed
  need_cmd curl

  if [[ -n "$CHECK_ONLY" || -n "$CHECK_FILE" ]]; then
    local logf="${CHECK_FILE:-$REALITY_SCAN_LOG}"
    run_domain_checks "$logf" "$REALITY_OK_DOMAINS"
    exit 0
  fi

  resolve_scan_ip_and_threads "${1:-}" "${2:-}"
  local IP THREADS
  IP="$SCAN_RESOLVED_IP"
  THREADS="$SCAN_RESOLVED_THREADS"

  run_scanner_with_early_exit "$IP" "$THREADS" "$REALITY_SCAN_LOG" "$MAX_SCAN_SEC"

  echo ""
  run_domain_checks "$REALITY_SCAN_LOG" "$REALITY_OK_DOMAINS"
}

main "$@"
