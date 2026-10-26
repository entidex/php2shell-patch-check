#!/usr/bin/env bash
# php2shell-check: read-only PHP2Shell exposure check for Linux web servers
# Checks CVE-2026-109618 and CVE-2026-109619 (PHP2Shell, patched 21 Oct 2026).
#
# READ-ONLY. This script never installs, updates, restarts, deletes or edits
# anything (apart from its own temporary report file). It reads package data,
# process data and file metadata, and runs "php -v" style version commands,
# but only on PHP programs that root owns and no other user can change. PHP
# found anywhere else, or inside a container, is listed but never run. Run it only on servers you own or are
# authorised to manage.
#
# Nothing leaves the server unless you add --submit. With --submit, the JSON
# report (hostname, OS, PHP versions and any flagged file paths) is sent to
# entidex.com for your PHP2Shell Patch Check order and the verdict is printed.
#
# Usage: sudo bash php2shell-check.sh [--json report.json] [--since YYYY-MM-DD]
#                                      [--roots "/var/www /srv/www"] [--no-files]
#                                      [--submit CHECK-CODE]
#        bash php2shell-check.sh --status CHECK-CODE
# Exit codes: 0 = no action needed, 1 = action needed, 2 = could not confirm
#
# (c) 2026 Entidex Ltd, England and Wales, Company No. 17250646

set -u
export LC_ALL=C

TOOL_VERSION="1.2.0"
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
SINCE="2026-10-19"          # leak was 20 Oct; look a day earlier
JSON_OUT=""
SCAN_FILES=1
ROOTS=""
MAX_LIST=20
SUBMIT_CODE=""
STATUS_CODE=""
ENTIDEX_URL="${ENTIDEX_URL:-https://entidex.com}"

usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --json)     JSON_OUT="${2:-}"; shift 2 ;;
    --since)    SINCE="${2:-}"; shift 2 ;;
    --roots)    ROOTS="${2:-}"; shift 2 ;;
    --no-files) SCAN_FILES=0; shift ;;
    --submit)   SUBMIT_CODE="${2:-}"; shift 2 ;;
    --status)   STATUS_CODE="${2:-}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if ! date -d "$SINCE" >/dev/null 2>&1; then
  echo "--since must be a date like 2026-10-19" >&2; exit 2
fi

# ---------- check code + upload helpers (only used with --submit / --status) ----------
norm_code() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -d ' '; }
valid_code() { printf '%s' "$1" | grep -Eq '^EDX-[0-9]{6}-[A-Z0-9]{4}-[A-Z0-9]{10}$'; }
case "$ENTIDEX_URL" in https://*|http://localhost*|http://127.0.0.1*) ;; *) echo "ENTIDEX_URL must be https://" >&2; exit 2 ;; esac
for c in SUBMIT_CODE STATUS_CODE; do
  v="$(norm_code "${!c}")"; printf -v "$c" '%s' "$v"
  if [ -n "$v" ] && ! valid_code "$v"; then
    echo "That check code doesn't look right. Copy it exactly from your pro-forma email (e.g. EDX-261022-AB12-K7Q2M9XW4T)." >&2; exit 2
  fi
done

# HTTP via curl (or wget). Prints the response body, then the status code on the last line.
http_call() { # method url [file]
  local method="$1" url="$2" file="${3:-}" code_hdr="X-Check-Code: $CODE_FOR_HTTP"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$file" ]; then
      curl -sS -m 60 -X "$method" -H "$code_hdr" -H 'Content-Type: application/json' \
        -H "User-Agent: php2shell-check/$TOOL_VERSION" --data-binary "@$file" -w '\n%{http_code}' "$url"
    else
      curl -sS -m 60 -X "$method" -H "$code_hdr" -H "User-Agent: php2shell-check/$TOOL_VERSION" -w '\n%{http_code}' "$url"
    fi
  elif command -v wget >/dev/null 2>&1; then
    local out; out="$(mktemp)"
    if [ -n "$file" ]; then
      wget -q -T 60 -O "$out" --content-on-error --header="$code_hdr" --header='Content-Type: application/json' \
        --method="$method" --body-file="$file" "$url"
    else
      wget -q -T 60 -O "$out" --content-on-error --header="$code_hdr" "$url"
    fi
    local rc=$?; cat "$out"; rm -f "$out"; printf '\n%s' "$([ $rc -eq 0 ] && echo 200 || echo 000)"
  else
    printf '%s\n000' '{"message":"curl or wget is needed to send the report"}'
  fi
}
# First "key":"value" string in a JSON body (good enough for our own API's flat fields).
jget() { printf '%s' "$2" | grep -o "\"$1\":\"[^\"]*\"" | head -n1 | sed -e "s/^\"$1\":\"//" -e 's/"$//'; }
# Last "key":"value" string (the order-level field in --status responses).
jlast() { printf '%s' "$2" | grep -o "\"$1\":\"[^\"]*\"" | tail -n1 | sed -e "s/^\"$1\":\"//" -e 's/"$//'; }
print_findings() { printf '%s' "$1" | grep -o '"message":"[^"]*"' | sed -e 's/^"message":"/    · /' -e 's/"$//' | head -n 20; }

# ---------- output helpers ----------
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; D=""; N=""
fi
say()  { printf '%s\n' "$*"; }
head1(){ printf '\n%s%s%s\n' "$B" "$*" "$N"; }

json_esc() {
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | awk 'BEGIN{ORS="\\n"}{print}' \
    | sed 's/\\n$//'
}

IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1

if [ -n "$STATUS_CODE" ]; then
  CODE_FOR_HTTP="$STATUS_CODE"
  resp="$(http_call GET "$ENTIDEX_URL/api/patch-checks")"
  code="$(printf '%s' "$resp" | tail -n1)"; body="$(printf '%s' "$resp" | sed '$d')"
  say "${B}PHP2Shell Patch Check status${N} ${D}($ENTIDEX_URL)${N}"
  if [ "$code" != "200" ]; then say "  ${R}$(jget message "$body")${N}"; exit 2; fi
  say "  Order $(jget reference "$body") · paid: $(printf '%s' "$body" | grep -o '"paid":[a-z]*' | head -n1 | cut -d: -f2)"
  printf '%s' "$body" | grep -o '"host":"[^"]*","checkedAt":[^,]*,"verdict":"[^"]*","status":"[^"]*"' \
    | sed -e 's/"host":"\([^"]*\)","checkedAt":[^,]*,"verdict":"\([^"]*\)","status":"\([^"]*\)"/  · \1: \2 (\3)/' | head -n 20
  printf '%s' "$body" | grep -o '"verifyUrl":"[^"]*"' | sed -e 's/^"verifyUrl":"/  Signed result: /' -e 's/"$//' | sort -u
  say "  $(jlast next "$body")"
  exit 0
fi

if [ -n "$SUBMIT_CODE" ] && [ -z "$JSON_OUT" ]; then
  JSON_OUT="$(mktemp /tmp/php2shell-report.XXXXXX)" || { echo "Could not create a temp file for the report" >&2; exit 2; }
  SUBMIT_TMP=1
fi
HOST="$(hostname 2>/dev/null || echo unknown)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OS="unknown"
if [ -r /etc/os-release ]; then
  OS="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-${NAME:-unknown}}")"
fi

# ---------- version logic ----------
# Upstream releases that contain the fix
fixed_for() {
  case "$1" in
    8.5) echo 8.5.12 ;; 8.4) echo 8.4.27 ;; 8.3) echo 8.3.36 ;; 8.2) echo 8.2.35 ;;
    *) echo "" ;;
  esac
}
ver_ge() { # ver_ge A B  -> true if A >= B
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}
major_minor() { printf '%s' "$1" | awk -F. '{print $1"."$2}'; }

# ---------- package helpers ----------
PKG_TOOL=""
command -v dpkg-query >/dev/null 2>&1 && PKG_TOOL="dpkg"
[ -z "$PKG_TOOL" ] && command -v rpm >/dev/null 2>&1 && PKG_TOOL="rpm"

pkg_owner() { # file -> package name or empty
  case "$PKG_TOOL" in
    dpkg) dpkg-query -S "$1" 2>/dev/null | head -n1 | cut -d: -f1 | cut -d, -f1 ;;
    rpm)  rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n1 ;;
  esac
}
pkg_version() {
  case "$PKG_TOOL" in
    dpkg) dpkg-query -W -f='${Version}' "$1" 2>/dev/null ;;
    rpm)  rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null ;;
  esac
}
# Prints: both | one | none | nolog
pkg_cve_status() {
  local pkg="$1" log="" a=0 b=0 f
  case "$PKG_TOOL" in
    dpkg)
      for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
        [ -r "$f" ] && { log="$(zcat "$f" 2>/dev/null)"; break; }
      done
      ;;
    rpm) log="$(rpm -q --changelog "$pkg" 2>/dev/null)" ;;
  esac
  [ -z "$log" ] && { echo nolog; return; }
  printf '%s' "$log" | grep -q "$CVE_A" && a=1
  # Debian/Ubuntu sometimes name one patch for both, e.g. CVE-2026-109618_109619
  printf '%s' "$log" | grep -qE "$CVE_B|${CVE_A}_${CVE_B##*-}" && b=1
  if [ $a -eq 1 ] && [ $b -eq 1 ]; then echo both
  elif [ $a -eq 1 ] || [ $b -eq 1 ]; then echo one
  else echo none; fi
}

# ---------- 1. find PHP runtimes ----------
# Only run a PHP program if root owns it and no other user can change it or any
# folder above it. On a server that is already compromised, a program called
# "php" in /tmp or a web folder could be the attacker's, and this script runs as
# root, so running it would hand them the server.
safe_to_run() {
  local p="$1" d
  [ "$(stat -c '%u' "$p" 2>/dev/null)" = "0" ] || return 1
  [ -z "$(find "$p" -maxdepth 0 -perm /022 2>/dev/null)" ] || return 1
  d="$(dirname "$p")"
  while :; do
    [ "$(stat -c '%u' "$d" 2>/dev/null)" = "0" ] || return 1
    [ -z "$(find "$d" -maxdepth 0 -perm /022 2>/dev/null)" ] || return 1
    [ "$d" = "/" ] && break
    d="$(dirname "$d")"
  done
  return 0
}
SELF_PIDNS="$(readlink /proc/$$/ns/pid 2>/dev/null)"
CONTAINER_RT="false"
if command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1 || command -v ctr >/dev/null 2>&1 \
   || [ -S /run/containerd/containerd.sock ] || [ -S /var/run/docker.sock ]; then
  CONTAINER_RT="true"
fi
declare -A SEEN=()
CANDIDATES=()
add_cand() {
  local p="$1" rp
  [ -e "$p" ] || return 0
  rp="$(readlink -f "$p" 2>/dev/null || echo "$p")"
  [ -f "$rp" ] || return 0
  [ -n "${SEEN[$rp]:-}" ] && return 0
  SEEN[$rp]=1; CANDIDATES+=("$rp")
}

for n in php php-cgi php-fpm lsphp frankenphp; do
  p="$(command -v "$n" 2>/dev/null)" && add_cand "$p"
done
shopt -s nullglob
for p in /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* /usr/local/bin/php* \
         /usr/local/sbin/php-fpm* /usr/local/bin/frankenphp \
         /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
         /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
         /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/sbin/php-fpm \
         /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp \
         /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm; do
  case "$p" in *-config|*ize|*.dpkg-*|*-dbg) continue ;; esac
  add_cand "$p"
done

# running processes (also finds builds in unusual places)
declare -A RUNNING=()
declare -A CONT_SEEN=()
STALE=()
CONTAINER_PHP=()
for d in /proc/[0-9]*; do
  exe="$(readlink "$d/exe" 2>/dev/null)" || continue
  base="${exe##*/}"; base="${base% (deleted)}"
  case "$base" in
    php|php[0-9]*|php-fpm*|php-cgi*|lsphp*|frankenphp)
      # A different PID namespace means a container: its file paths are not
      # this server's, so record it and never run or assess the host path.
      pidns="$(readlink "$d/ns/pid" 2>/dev/null)"
      if [ -n "$SELF_PIDNS" ] && [ -n "$pidns" ] && [ "$pidns" != "$SELF_PIDNS" ]; then
        key="$pidns|${exe% (deleted)}"
        if [ -z "${CONT_SEEN[$key]:-}" ]; then CONT_SEEN[$key]=1; CONTAINER_PHP+=("${d#/proc/}|${exe% (deleted)}"); fi
        continue
      fi
      if [[ "$exe" == *" (deleted)" ]]; then
        STALE+=("${d#/proc/}|${exe% (deleted)}")
      else
        RUNNING[$exe]=1; add_cand "$exe"
      fi
      ;;
    apache2|httpd)
      if grep -q 'libphp.*(deleted)' "$d/maps" 2>/dev/null; then
        STALE+=("${d#/proc/}|$(grep -o '/[^ ]*libphp[^ ]*' "$d/maps" | head -n1) (mod_php)")
      fi
      ;;
  esac
done

# Apache mod_php modules (shared libraries, cannot be run)
MODPHP=()
for p in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
         /usr/lib/httpd/modules/libphp*.so /etc/httpd/modules/libphp*.so; do
  rp="$(readlink -f "$p")"; [ -n "${SEEN[$rp]:-}" ] && continue
  SEEN[$rp]=1; MODPHP+=("$rp")
done
shopt -u nullglob

# ---------- 2. assess each runtime ----------
# record: kind|path|version|package|pkgver|status|reason|running
RESULTS=()
assess() {
  local kind="$1" path="$2" ver="$3" pkg pkgver cve mm fix status reason run="no"
  [ -n "${RUNNING[$path]:-}" ] && run="yes"
  pkg="$(pkg_owner "$path")"; pkgver=""; cve="nolog"
  if [ -n "$pkg" ]; then pkgver="$(pkg_version "$pkg")"; cve="$(pkg_cve_status "$pkg")"; fi

  if [ -z "$ver" ]; then
    status="UNKNOWN"; reason="could not read the PHP version"
  else
    mm="$(major_minor "$ver")"; fix="$(fixed_for "$mm")"
    if [ "$cve" = "both" ]; then
      status="PATCHED"; reason="package changelog lists both CVE fixes (distro backport)"
    elif [ -n "$fix" ] && ver_ge "$ver" "$fix"; then
      status="PATCHED"; reason="version $ver includes the fix (needs $fix or later)"
    elif [ "$cve" = "one" ]; then
      status="VULNERABLE"; reason="package changelog lists only one of the two CVE fixes"
    elif [ -n "$fix" ]; then
      if [ -n "$pkg" ] && [ "$cve" = "nolog" ]; then
        status="UNKNOWN"; reason="version $ver is below $fix and the package has no changelog to confirm a backport; check with your provider"
      else
        status="VULNERABLE"; reason="version $ver is below the fixed release $fix"
      fi
    elif ! ver_ge "$ver" "8.2"; then
      if [ -n "$pkg" ] && [ "$cve" = "none" ]; then
        status="VULNERABLE"; reason="PHP $mm is end of life and its package shows no PHP2Shell fix"
      else
        status="UNKNOWN"; reason="PHP $mm is end of life; only a source patch can fix it. Ask your provider to confirm it was applied, and plan an upgrade to 8.2+"
      fi
    else
      status="UNKNOWN"; reason="PHP $mm is newer than this tool knows; check php.net"
    fi
  fi
  RESULTS+=("$kind|$path|${ver:-?}|${pkg:--}|${pkgver:--}|$status|$reason|$run")
}

UNTRUSTED=()
for bin in "${CANDIDATES[@]}"; do
  case "${bin##*/}" in
    php-fpm*) kind="php-fpm" ;; php-cgi*) kind="php-cgi" ;; lsphp*) kind="litespeed" ;;
    frankenphp) kind="frankenphp" ;; *) kind="php-cli" ;;
  esac
  if ! safe_to_run "$bin"; then
    UNTRUSTED+=("$bin")
    RESULTS+=("$kind|$bin|?|-|-|UNKNOWN|not run: this PHP program, or a folder above it, can be changed by users other than root, so it could have been planted. Check who put it there|$([ -n "${RUNNING[$bin]:-}" ] && echo yes || echo no)")
    continue
  fi
  out="$(timeout 10 "$bin" -v 2>/dev/null </dev/null | head -n3)"
  ver="$(printf '%s' "$out" | grep -oE 'PHP v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
  assess "$kind" "$bin" "$ver"
done
for c in "${CONTAINER_PHP[@]}"; do
  RESULTS+=("container|pid ${c%%|*}: ${c#*|}|?|-|-|UNKNOWN|PHP is running inside a container, which this check can't see into. Run the check inside the container, or rebuild its image on a fixed PHP|yes")
done
for so in "${MODPHP[@]}"; do
  pkg="$(pkg_owner "$so")"; ver=""
  if [ -n "$pkg" ]; then
    ver="$(pkg_version "$pkg" | sed -e 's/^[0-9]*://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
  fi
  assess "apache-mod_php" "$so" "$ver"
done

# ---------- 3. pending updates (read-only, uses cached package lists) ----------
PENDING=""
if command -v apt >/dev/null 2>&1; then
  PENDING="$(apt list --upgradable 2>/dev/null | grep -E '^(php|libapache2-mod-php|libphp)' | cut -d/ -f1 | sort -u | tr '\n' ' ')"
elif command -v dnf >/dev/null 2>&1; then
  PENDING="$(dnf -q -C check-update 'php*' 'ea-php*' 'alt-php*' 2>/dev/null | awk 'NF==3{print $1}' | sort -u | tr '\n' ' ')"
elif command -v yum >/dev/null 2>&1; then
  PENDING="$(yum -q -C check-update 'php*' 'ea-php*' 'alt-php*' 2>/dev/null | awk 'NF==3{print $1}' | sort -u | tr '\n' ' ')"
fi

# ---------- 4. signs of compromise (file metadata + pattern match only) ----------
UPLOAD_PHP=(); CORE_CHANGED=(); TMP_PHP=(); SUSPICIOUS=(); NEW_PHP_COUNT=0; ROOTS_USED=""
if [ "$SCAN_FILES" -eq 1 ]; then
  if [ -z "$ROOTS" ]; then
    shopt -s nullglob
    for r in /var/www /srv/www /srv/http /usr/share/nginx/html /home/*/public_html \
             /home/*/www /home/*/domains/*/public_html /var/www/vhosts/*/httpdocs; do
      [ -d "$r" ] && ROOTS="$ROOTS $r"
    done
    shopt -u nullglob
  fi
  ROOTS_USED="$(echo $ROOTS)"
  PHPX='.*\.\(php[0-9s]*\|phtml\|phar\)$'
  for r in $ROOTS; do
    [ -d "$r" ] || continue
    while IFS= read -r f; do UPLOAD_PHP+=("$f"); done < <(
      find "$r" -xdev -path '*/wp-content/uploads/*' -type f -iregex "$PHPX" 2>/dev/null | head -n 200)
    while IFS= read -r f; do CORE_CHANGED+=("$f"); done < <(
      find "$r" -xdev \( -path '*/wp-includes/*' -o -path '*/wp-admin/*' \) -type f -name '*.php' \
        -newerct "$SINCE" 2>/dev/null | head -n 200)
    while IFS= read -r f; do
      NEW_PHP_COUNT=$((NEW_PHP_COUNT+1))
      if [ "$NEW_PHP_COUNT" -le 5000 ] && grep -qE \
        'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(|(system|passthru|shell_exec|proc_open|popen)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)' \
        "$f" 2>/dev/null; then
        SUSPICIOUS+=("$f")
      fi
    done < <(find "$r" -xdev -type f -iregex "$PHPX" -newerct "$SINCE" 2>/dev/null)
  done
  while IFS= read -r f; do TMP_PHP+=("$f"); done < <(
    find /tmp /var/tmp /dev/shm -xdev -maxdepth 2 -type f -iregex "$PHPX" 2>/dev/null | head -n 200)
fi

# ---------- 5. verdict ----------
N_VULN=0; N_UNK=0; N_OK=0
for r in "${RESULTS[@]}"; do
  case "$(echo "$r" | cut -d'|' -f6)" in
    VULNERABLE) N_VULN=$((N_VULN+1)) ;; UNKNOWN) N_UNK=$((N_UNK+1)) ;; PATCHED) N_OK=$((N_OK+1)) ;;
  esac
done
N_IOC=${#SUSPICIOUS[@]}
N_REVIEW=$(( ${#UPLOAD_PHP[@]} + ${#CORE_CHANGED[@]} + ${#TMP_PHP[@]} ))

if [ ${#RESULTS[@]} -eq 0 ] && [ "$CONTAINER_RT" = "true" ]; then
  VERDICT="NOT_CONFIRMED"; EXIT=2
elif [ ${#RESULTS[@]} -eq 0 ]; then
  VERDICT="NO_PHP_FOUND"; EXIT=0
elif [ $N_VULN -gt 0 ] || [ ${#STALE[@]} -gt 0 ] || [ $N_IOC -gt 0 ] || [ ${#UNTRUSTED[@]} -gt 0 ]; then
  VERDICT="ACTION_NEEDED"; EXIT=1
elif [ $N_UNK -gt 0 ]; then
  VERDICT="NOT_CONFIRMED"; EXIT=2
else
  VERDICT="PATCHED"; EXIT=0
fi
[ $IS_ROOT -eq 0 ] && [ "$VERDICT" = "PATCHED" ] && { VERDICT="NOT_CONFIRMED"; EXIT=2; }

# ---------- 6. text report ----------
say "${B}PHP2Shell check${N} ${D}v$TOOL_VERSION · $CVE_A, $CVE_B${N}"
say "${D}Host $HOST · $OS · $NOW · read-only${N}"
[ $IS_ROOT -eq 0 ] && say "${Y}Not running as root: other users' processes and files may be missed. Re-run with sudo for a full result.${N}"

head1 "PHP runtimes found: ${#RESULTS[@]}"
if [ ${#RESULTS[@]} -eq 0 ]; then
  say "  No PHP found on this server."
  [ "$CONTAINER_RT" = "true" ] && say "  ${Y}Containers are installed here. PHP inside a stopped or idle container can't be seen; run the check inside each container that serves websites.${N}"
fi
for r in "${RESULTS[@]}"; do
  IFS='|' read -r kind path ver pkg pkgver status reason run <<<"$r"
  case "$status" in PATCHED) c=$G ;; VULNERABLE) c=$R ;; *) c=$Y ;; esac
  rflag=""; [ "$run" = "yes" ] && rflag=" ${D}(running)${N}"
  say "  ${c}${status}${N}  PHP $ver  $kind$rflag"
  say "     ${D}$path${N}"
  [ "$pkg" != "-" ] && say "     ${D}package $pkg $pkgver${N}"
  say "     $reason"
done

if [ ${#STALE[@]} -gt 0 ]; then
  head1 "${R}Restart needed${N}"
  say "  These processes still run PHP code that was replaced on disk, so the fix is not live yet:"
  for s in "${STALE[@]}"; do say "  pid ${s%%|*}  ${s#*|}"; done
fi

[ -n "$PENDING" ] && { head1 "PHP updates waiting to install"; say "  $PENDING"; }

if [ "$SCAN_FILES" -eq 1 ]; then
  head1 "Signs of compromise since $SINCE"
  say "  ${D}Web roots scanned: ${ROOTS_USED:-none found}${N}"
  say "  PHP files created or changed since $SINCE: $NEW_PHP_COUNT"
  list() { local t="$1"; shift; [ $# -eq 0 ] && return; say "  $t: $#"; local i=0 f
           for f in "$@"; do i=$((i+1)); [ $i -gt $MAX_LIST ] && { say "     … and $(( $# - MAX_LIST )) more"; break; }; say "     $f"; done; }
  list "${R}Files matching web-shell patterns${N}" "${SUSPICIOUS[@]}"
  list "${Y}PHP files in temp folders (review)${N}" "${TMP_PHP[@]}"
  list "${Y}PHP files inside WordPress uploads (review)${N}" "${UPLOAD_PHP[@]}"
  list "${Y}WordPress core files changed (normal after an update; review)${N}" "${CORE_CHANGED[@]}"
  [ $N_IOC -eq 0 ] && [ $N_REVIEW -gt 0 ] && [ "$VERDICT" != "ACTION_NEEDED" ] && say "  ${Y}Nothing matched web-shell patterns, but review the files listed above.${N}"
  [ $N_IOC -eq 0 ] && [ $N_REVIEW -eq 0 ] && say "  ${G}Nothing suspicious found in file checks.${N}"
  say "  ${D}Also check WordPress admin users, e.g.: wp user list --role=administrator --fields=user_login,user_registered${N}"
fi

head1 "Result"
case "$VERDICT" in
  PATCHED)       say "  ${G}${B}PATCHED${N}  Every PHP runtime found includes the PHP2Shell fix." ;;
  NO_PHP_FOUND)  say "  ${G}${B}NO PHP FOUND${N}  This server does not appear to run PHP." ;;
  NOT_CONFIRMED) say "  ${Y}${B}NOT CONFIRMED${N}  Some runtimes could not be confirmed as fixed. Ask your provider, or book a Patch Check." ;;
  ACTION_NEEDED) say "  ${R}${B}ACTION NEEDED${N}"
    [ $N_VULN -gt 0 ] && say "  · Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your distro's patched package)."
    [ ${#STALE[@]} -gt 0 ] && say "  · Restart PHP-FPM / LiteSpeed / Apache so the patched code is live."
    [ ${#UNTRUSTED[@]} -gt 0 ] && say "  · PHP programs found in places other users can change. They were not run. Treat the server as possibly compromised and get help."
    [ $N_IOC -gt 0 ] && say "  · Files matching web-shell patterns found. Treat the server as possibly compromised and get help before deleting anything."
    say "  · UK guidance (NCSC): update internet-facing PHP now, or take it offline until you can." ;;
esac

# ---------- 7. JSON report ----------
if [ -n "$JSON_OUT" ]; then
  jarr() { local first=1 x; printf '['; for x in "$@"; do [ $first -eq 0 ] && printf ','; first=0; printf '"%s"' "$(json_esc "$x")"; done; printf ']'; }
  {
    printf '{"tool":"php2shell-check","tool_version":"%s","cves":["%s","%s"],' "$TOOL_VERSION" "$CVE_A" "$CVE_B"
    printf '"host":"%s","os":"%s","checked_at":"%s","root":%s,"since":"%s",' \
      "$(json_esc "$HOST")" "$(json_esc "$OS")" "$NOW" "$([ $IS_ROOT -eq 1 ] && echo true || echo false)" "$SINCE"
    printf '"verdict":"%s","runtimes":[' "$VERDICT"
    first=1
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r kind path ver pkg pkgver status reason run <<<"$r"
      [ $first -eq 0 ] && printf ','; first=0
      printf '{"kind":"%s","path":"%s","version":"%s","package":"%s","package_version":"%s","status":"%s","reason":"%s","running":%s}' \
        "$kind" "$(json_esc "$path")" "$ver" "$(json_esc "$pkg")" "$(json_esc "$pkgver")" "$status" "$(json_esc "$reason")" \
        "$([ "$run" = yes ] && echo true || echo false)"
    done
    printf '],"restart_needed":'; jarr "${STALE[@]}"
    printf ',"untrusted_binaries":'; jarr "${UNTRUSTED[@]}"
    printf ',"container_php":'; jarr "${CONTAINER_PHP[@]}"
    printf ',"container_runtime":%s' "$CONTAINER_RT"
    printf ',"pending_updates":"%s"' "$(json_esc "$PENDING")"
    printf ',"files":{"scanned":%s,"roots":"%s","new_php_since":%d,' "$([ $SCAN_FILES -eq 1 ] && echo true || echo false)" "$(json_esc "$ROOTS_USED")" "$NEW_PHP_COUNT"
    printf '"webshell_patterns":'; jarr "${SUSPICIOUS[@]}"
    printf ',"temp_php":'; jarr "${TMP_PHP[@]}"
    printf ',"uploads_php":'; jarr "${UPLOAD_PHP[@]}"
    printf ',"wp_core_changed":'; jarr "${CORE_CHANGED[@]}"
    printf '}}\n'
  } > "$JSON_OUT"
  sum="$(sha256sum "$JSON_OUT" 2>/dev/null | cut -d' ' -f1)"
  say ""; say "${D}JSON report: $JSON_OUT${sum:+  sha256 $sum}${N}"
fi

# ---------- 8. submit (opt-in) ----------
if [ -n "$SUBMIT_CODE" ]; then
  head1 "Sending report to Entidex"
  CODE_FOR_HTTP="$SUBMIT_CODE"
  resp="$(http_call POST "$ENTIDEX_URL/api/patch-checks" "$JSON_OUT")"
  code="$(printf '%s' "$resp" | tail -n1)"; body="$(printf '%s' "$resp" | sed '$d')"
  [ "${SUBMIT_TMP:-0}" = "1" ] && rm -f "$JSON_OUT"
  if [ "$code" != "200" ]; then
    say "  ${R}Not sent ($code): $(jget message "$body")${N}"
    say "  The local result above still stands. Reply to your pro-forma email if this keeps happening."
  else
    v="$(jget verdict "$body")"
    case "$v" in
      pass)       say "  ${G}${B}VERIFIED: PASS${N}" ;;
      fix_needed) say "  ${Y}${B}NOT YET: FIX AND RE-RUN${N}" ;;
      escalate)   say "  ${R}${B}NEEDS A PERSON${N}" ;;
      *)          say "  ${Y}${B}NOT ACCEPTED${N}" ;;
    esac
    say "  $(jget summary "$body")"
    [ "$v" != "pass" ] && print_findings "$body"
    url="$(jget verifyUrl "$body")"; [ -n "$url" ] && say "  Signed result: $url"
    say "  $(jget next "$body")"
  fi
fi

exit "$EXIT"
