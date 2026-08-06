#!/bin/bash
# linux-cryptojack-hunter
#
# IOC-driven detector/responder for a recurring cryptojacking campaign: an
# XMRig-family miner plus a C2 process that masquerades under a random or
# kernel-thread-like name, kept alive by whichever persistence mechanism
# happens to be in fashion that week (disguised cron, disguised systemd
# unit, backdoor user, userland rootkit via ld.so.preload, or a systemd
# watchdog with a blockchain-hosted C2 fallback). Full writeup in README.md.
#
# Indicators live in iocs.conf, sourced at runtime, so the engine below
# never needs to change to track a different set of IOCs or a different
# campaign entirely.
#
# Usage:
#   ./check-infection.sh              report only (default, safe)
#   ./check-infection.sh --kill       act on CONFIRMED findings
#   ./check-infection.sh --deep       also run the slower package-integrity check
#   ./check-infection.sh --json       emit findings as a JSON array
#   ./check-infection.sh --log FILE   also append a plain-text report to FILE
#   ./check-infection.sh --iocs FILE  use a different indicator file
#
# Exit codes: 0 nothing found, 1 found something (report or kill mode), 2 usage error.
#
# Severity model: CONFIRMED means a specific indicator matched (an exact
# domain, IP, username, file signature) and --kill acts on it. WARNING means
# a generic behavioral pattern matched that is common enough in legitimate
# setups that automatic removal is not attempted; it is always left for a
# human to look at.

set -u
VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOC_FILE="$SCRIPT_DIR/iocs.conf"
KILL=0
DEEP=0
JSON=0
LOG_FILE=""

usage() {
  cat <<EOF
linux-cryptojack-hunter v$VERSION

Usage: $0 [options]

  --kill          kill processes and remove persistence for CONFIRMED findings
  --deep          also run the slower package-integrity check
  --json          emit findings as a JSON array on stdout
  --log FILE      append a plain-text report to FILE
  --iocs FILE     load indicators from FILE (default: $IOC_FILE)
  -h, --help      show this help
  -v, --version   show version

Exit code: 0 nothing found, 1 something found, 2 usage error.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --kill) KILL=1 ;;
    --deep) DEEP=1 ;;
    --json) JSON=1 ;;
    --log) LOG_FILE="${2:-}"; shift ;;
    --iocs) IOC_FILE="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "linux-cryptojack-hunter v$VERSION"; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ ! -f "$IOC_FILE" ]; then
  echo "IOC file not found: $IOC_FILE" >&2
  exit 2
fi
# shellcheck source=iocs.conf
source "$IOC_FILE"

FOUND=0
FINDINGS_JSON=()
LOG_LINES=()

has() { command -v "$1" >/dev/null 2>&1; }

say() {
  local line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  [ "$JSON" = 1 ] || echo "$line"
  LOG_LINES+=("$line")
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s" | tr '\n' ' '
}

# record <check> <confirmed|warning> <detail>
record() {
  local check="$1" severity="$2" detail="$3"
  FOUND=1
  if [ "$severity" = "confirmed" ]; then
    say "CONFIRMED [$check]: $detail"
  else
    say "WARNING [$check]: $detail (generic pattern, not auto-removed, review manually)"
  fi
  FINDINGS_JSON+=("{\"check\":\"$(json_escape "$check")\",\"severity\":\"$severity\",\"detail\":\"$(json_escape "$detail")\"}")
}

# Remove a file even if it carries the immutable attribute (chattr +i is a
# common way for this campaign to keep its persistence files from being
# deleted mid-cleanup).
safe_remove() {
  local path="$1"
  if has lsattr && lsattr "$path" 2>/dev/null | awk '{print $1}' | grep -q i; then
    chattr -i "$path" 2>/dev/null
  fi
  rm -f "$path"
}

say "=== linux-cryptojack-hunter v$VERSION - $(hostname) - $(date) ==="

# 1) High-CPU process running from /tmp or /var/tmp.
say "Checking for high-CPU processes running from /tmp or /var/tmp..."
if has ps && has awk; then
  while read -r pid cpu comm; do
    [ -z "$pid" ] && continue
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    case "$exe" in
      /tmp/*|/var/tmp/*)
        record "tmp-exec" "confirmed" "pid=$pid cpu=${cpu}% comm=$comm exe=$exe"
        [ "$KILL" = 1 ] && kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
        ;;
    esac
  done < <(ps -e -o pid=,%cpu=,comm= | awk -v t="$CPU_THRESHOLD" '$2+0 > t {print $1, $2, $3}')
else
  say "  skipped (ps/awk not available)"
fi

# 1b) Process using a real kernel thread's name but with a non-empty
#     cmdline. Real kernel threads always have an empty /proc/PID/cmdline
#     (they are not invoked with arguments, they are spawned by the
#     kernel itself); this is the same test `ps` uses internally to decide
#     whether to print a name in brackets. Do NOT use
#     `readlink -f /proc/PID/exe` for this: it does not fail or empty out
#     for a real kernel thread, it echoes the unresolved path back
#     unchanged, which would misclassify kthreadd/kswapd0/ksmd as fake.
say "Checking for processes masquerading as kernel threads..."
if has pgrep; then
  for name in "${FAKE_KERNEL_NAMES[@]}"; do
    for pid in $(pgrep -x "$name" 2>/dev/null); do
      [ -s "/proc/$pid/cmdline" ] || continue
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
      record "fake-kernel-thread" "confirmed" "pid=$pid name=$name has a non-empty cmdline (real kernel threads never do) exe=${exe:-?}"
      if [ "$KILL" = 1 ]; then
        kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
        [ -n "$exe" ] && [ -f "$exe" ] && safe_remove "$exe" && say "  removed binary: $exe"
      fi
    done
  done
else
  say "  skipped (pgrep not available)"
fi

# 1c) Running process whose backing binary has since been deleted, and
#     originally lived somewhere no legitimate long-running binary should
#     (a hidden dotfile, /tmp, /var/tmp, /dev/shm). Self-deleting after
#     launch is a common evasion trick (nothing left on disk to scan).
#     Flagged as a WARNING, not CONFIRMED: a normal package upgrade also
#     leaves a running process pointing at a deleted binary, this narrows
#     it to paths that were already suspicious before the deletion.
say "Checking for running processes with a deleted backing binary in a suspicious location..."
if has ps; then
  while read -r pid comm; do
    [ -z "$pid" ] && continue
    link=$(readlink "/proc/$pid/exe" 2>/dev/null)
    case "$link" in
      *" (deleted)")
        orig="${link% (deleted)}"
        case "$orig" in
          /tmp/*|/var/tmp/*|/dev/shm/*|*/.*)
            record "deleted-exe" "warning" "pid=$pid comm=$comm running from a since-deleted binary at $orig"
            ;;
        esac
        ;;
    esac
  done < <(ps -e -o pid=,comm=)
else
  say "  skipped (ps not available)"
fi

# 1d) Hidden executable file (dotfile) in a system binary directory. No
#     legitimate package installs a dotfile there.
say "Checking for hidden files in system binary directories..."
for dir in /bin /usr/bin /sbin /usr/sbin; do
  for f in "$dir"/.[!.]*; do
    [ -f "$f" ] || continue
    record "hidden-binary" "confirmed" "$f"
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  done
done

# 2) Network connections to a known C2 IP.
say "Checking network connections to known C2 IPs..."
if has ss; then
  for ip in "${C2_IPS[@]}"; do
    hits=$(ss -tnp 2>/dev/null | grep -F "$ip")
    if [ -n "$hits" ]; then
      record "c2-connection" "confirmed" "active connection to $ip: $(echo "$hits" | tr '\n' ';')"
      if [ "$KILL" = 1 ]; then
        echo "$hits" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
          kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
        done
      fi
    fi
  done
elif has netstat; then
  for ip in "${C2_IPS[@]}"; do
    hits=$(netstat -tnp 2>/dev/null | grep -F "$ip")
    [ -n "$hits" ] && record "c2-connection" "confirmed" "active connection to $ip (netstat, pid not auto-parsed, kill manually): $(echo "$hits" | tr '\n' ';')"
  done
else
  say "  skipped (neither ss nor netstat available)"
fi

# 2b) Outbound connection to a common mining-pool port. Not proof on its
#     own (a handful of legitimate services use these ports too), so this
#     is a WARNING.
say "Checking for connections to common mining-pool ports..."
if has ss; then
  for port in "${MINING_PORTS[@]}"; do
    hits=$(ss -tnp state established "( dport = :$port )" 2>/dev/null | tail -n +2)
    [ -n "$hits" ] && record "mining-port" "warning" "established connection to port $port: $(echo "$hits" | tr '\n' ';')"
  done
else
  say "  skipped (ss not available)"
fi

# 2c) /etc/ld.so.preload: the classic userland rootkit hook (hides
#     processes/files by intercepting readdir). A clean system has this
#     file absent or empty; any content at all is suspicious on its own.
say "Checking /etc/ld.so.preload for a rootkit hook..."
if [ -s /etc/ld.so.preload ]; then
  lib=$(cat /etc/ld.so.preload)
  record "ld-preload-rootkit" "confirmed" "/etc/ld.so.preload points to: $lib"
  if [ "$KILL" = 1 ]; then
    for l in $lib; do
      [ -f "$l" ] && safe_remove "$l" && say "  removed: $l"
    done
    safe_remove /etc/ld.so.preload
    say "  removed /etc/ld.so.preload"
  fi
fi

# 3) Miner config signature (v.json-style XMRig config) in a temp dir.
say "Checking for miner config files in /tmp and /var/tmp..."
for f in /tmp/*.json /var/tmp/*.json; do
  [ -f "$f" ] || continue
  if grep -qE '"randomx"|"cn-heavy"|c3pool' "$f" 2>/dev/null; then
    record "miner-config" "confirmed" "$f"
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  fi
done

# 4) Known backdoor users.
say "Checking for known backdoor users..."
for u in "${BACKDOOR_USERS[@]}"; do
  if id "$u" >/dev/null 2>&1; then
    record "backdoor-user" "confirmed" "user '$u' exists"
    if [ "$KILL" = 1 ]; then
      userdel -r "$u" 2>/dev/null
      rm -f /etc/sudoers.d/*"$u"* 2>/dev/null
      say "  removed user + sudoers entries: $u"
    fi
  fi
done

# 5) systemd units matching a known name, or newer than the host's own
#    provisioning (a weak signal on its own, reported but never removed
#    automatically).
say "Checking for known-named systemd units..."
if has systemctl; then
  for name in "${KNOWN_UNIT_NAMES[@]}"; do
    if systemctl list-units --all --no-legend 2>/dev/null | grep -q "$name"; then
      record "known-unit" "confirmed" "$name"
      if [ "$KILL" = 1 ]; then
        systemctl stop "$name.service" "$name.timer" 2>/dev/null
        systemctl disable "$name.service" "$name.timer" 2>/dev/null
        find /etc/systemd/system -iname "${name}*" -delete 2>/dev/null
        say "  stopped/disabled/removed: $name"
      fi
    fi
  done
  newer=$(find /etc/systemd/system -maxdepth 1 -newer /etc/hostname -type f 2>/dev/null)
  [ -n "$newer" ] && record "unit-newer-than-host" "warning" "unit file(s) newer than /etc/hostname: $(echo "$newer" | tr '\n' ';')"
else
  say "  skipped (systemctl not available)"
fi

# 5b) Disguised systemd watchdog: the unit's own NAME changes every time,
#     so this matches on content instead: an ExecStart referencing a
#     hidden dotfile, or a self-checking "while true" loop polling with
#     pgrep/pidof.
say "Checking systemd services for a disguised watchdog pattern..."
if has systemctl; then
  for unit_file in /etc/systemd/system/*.service; do
    [ -f "$unit_file" ] || continue
    content=$(cat "$unit_file" 2>/dev/null)
    if echo "$content" | grep -qE 'ExecStart=.*/(bin|usr/bin|sbin|usr/sbin)/\.[^[:space:]]' \
       || echo "$content" | grep -qE 'while true.*(pgrep|pidof)'; then
      record "watchdog-unit" "confirmed" "$unit_file: $(echo "$content" | tr '\n' ';')"
      if [ "$KILL" = 1 ]; then
        unit_name=$(basename "$unit_file")
        systemctl stop "$unit_name" 2>/dev/null
        systemctl disable "$unit_name" 2>/dev/null
        safe_remove "$unit_file"
        find /etc/systemd/system -maxdepth 2 -iname "${unit_name%.service}*" -delete 2>/dev/null
        systemctl daemon-reload 2>/dev/null
        say "  stopped/disabled/removed: $unit_name"
      fi
    fi
  done
fi

# 6) Every user's crontab plus /etc/cron.d. The known dropper domain is
#    often embedded as a base64 blob rather than plain text, so any
#    long base64-looking substring gets decoded before the domain
#    comparison. A domain match is CONFIRMED and safe to remove; a bare
#    "downloads and pipes into a shell" pattern is too broad to trust
#    blindly (legitimate deploy/healthcheck scripts do this too), so it
#    is only ever reported.
say "Checking crontabs and /etc/cron.d..."
check_cron_content() {
  local label="$1" content="$2"
  local domain_hit=0 heuristic_hit=0
  local decoded combined
  decoded=$(echo "$content" | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | while read -r b64; do
    echo "$b64" | base64 -d 2>/dev/null
  done)
  combined="$content
$decoded"
  for d in "${DROPPER_DOMAINS[@]}"; do
    echo "$combined" | grep -qF "$d" && domain_hit=1
  done
  echo "$combined" | grep -qE 'base64 -d \| */bin/sh|curl[^|]*\| *(/bin/)?sh\b|wget[^|]*\| *(/bin/)?sh\b' && heuristic_hit=1

  if [ "$domain_hit" = 1 ]; then
    record "cron-dropper" "confirmed" "$label: $(echo "$content" | tr '\n' ';')"
    return 0
  fi
  if [ "$heuristic_hit" = 1 ]; then
    record "cron-fetch-pipe-shell" "warning" "$label: $(echo "$content" | tr '\n' ';')"
  fi
  return 1
}
if has crontab; then
  for u in $(cut -f1 -d: /etc/passwd); do
    c=$(crontab -u "$u" -l 2>/dev/null) || continue
    [ -n "$c" ] && check_cron_content "crontab of $u" "$c"
  done
fi
for f in /etc/cron.d/*; do
  [ -f "$f" ] || continue
  c=$(cat "$f" 2>/dev/null)
  if check_cron_content "$f" "$c"; then
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  fi
done

# 7) --deep only: binaries in system directories not owned by any
#    installed package. A real, general-purpose technique (the same idea
#    behind `rpm -Va` / `debsums`), gated behind --deep because it spawns
#    one package-manager query per file and is noticeably slower.
if [ "$DEEP" = 1 ]; then
  say "Deep check: looking for unowned binaries in system directories..."
  if has dpkg; then
    for dir in /bin /usr/bin /sbin /usr/sbin; do
      for f in "$dir"/*; do
        [ -f "$f" ] && [ -x "$f" ] || continue
        dpkg -S "$f" >/dev/null 2>&1 || record "unowned-binary" "warning" "$f is not owned by any installed package (dpkg)"
      done
    done
  elif has rpm; then
    for dir in /bin /usr/bin /sbin /usr/sbin; do
      for f in "$dir"/*; do
        [ -f "$f" ] && [ -x "$f" ] || continue
        rpm -qf "$f" >/dev/null 2>&1 || record "unowned-binary" "warning" "$f is not owned by any installed package (rpm)"
      done
    done
  else
    say "  skipped (neither dpkg nor rpm available)"
  fi
fi

say "=== end of check ==="
if [ "$FOUND" = 1 ]; then
  say "RESULT: found sign(s) of infection."
  [ "$KILL" = 1 ] || say "(ran in report mode, repeat with --kill to act on CONFIRMED findings)"
else
  say "RESULT: nothing found."
fi

if [ "$JSON" = 1 ]; then
  printf '['
  for i in "${!FINDINGS_JSON[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '%s' "${FINDINGS_JSON[$i]}"
  done
  printf ']\n'
fi

if [ -n "$LOG_FILE" ]; then
  printf '%s\n' "${LOG_LINES[@]}" >> "$LOG_FILE"
fi

[ "$FOUND" = 1 ] && exit 1
exit 0
