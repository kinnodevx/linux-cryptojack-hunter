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
EXTRA_SCAN_DIRS=("${EXTRA_SCAN_DIRS[@]:-}")

FOUND=0
CONFIRMED_COUNT=0
WARNING_COUNT=0
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
    CONFIRMED_COUNT=$((CONFIRMED_COUNT + 1))
    say "CONFIRMED [$check]: $detail"
  else
    WARNING_COUNT=$((WARNING_COUNT + 1))
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

# Forensics for a CONFIRMED malicious process: full parent chain up to init,
# plus the most recent web-server access-log lines, appended to a standing
# log file. Every check in this script so far only ever answered "what is
# running and how do I kill it" — after weeks of the same campaign coming
# back on both VPS with no confirmed entry vector, this answers "what
# spawned it" instead. Called before kill (or in report-only mode too, so a
# plain cron run still captures it) for every check that identifies a
# specific malicious PID. Read-only: walks /proc and tails existing log
# files, never touches anything.
FORENSICS_LOG="/root/infection-forensics.log"
capture_forensics() {
  local pid="$1" context="$2"
  [ -d "/proc/$pid" ] || return 0
  {
    echo "=== forensics: $context, pid=$pid, $(date '+%Y-%m-%d %H:%M:%S') ==="
    echo "-- process ancestry (this pid up to init) --"
    local p="$pid" depth=0 ppid comm exe cmdline
    while [ -n "$p" ] && [ "$p" != "0" ] && [ "$depth" -lt 15 ]; do
      if [ -r "/proc/$p/stat" ]; then
        comm=$(cat "/proc/$p/comm" 2>/dev/null)
        exe=$(readlink "/proc/$p/exe" 2>/dev/null)
        # /proc/PID/stat is "pid (comm) state ppid ...", and comm can itself
        # contain spaces or parens (this campaign's own "redis-server re"
        # disguise does exactly that) — a naive `awk '{print $4}'` silently
        # picks up a field of the comm text instead of the real ppid the
        # moment that happens. The format guarantees comm is bounded by the
        # FIRST '(' and the LAST ')' on the line, so strip up through that
        # last ')' before splitting on whitespace; caught live when this
        # exact process ("redis-server re") produced ppid=S instead of a
        # number, breaking ancestry capture on the one campaign this
        # forensics feature was built to trace.
        ppid=$(sed -E 's/^[0-9]+ \(.*\) //' "/proc/$p/stat" 2>/dev/null | awk '{print $2}')
        cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
        echo "  pid=$p ppid=$ppid comm=$comm exe=${exe:-?} cmdline=${cmdline:-?}"
        p="$ppid"
      else
        echo "  pid=$p (already gone from /proc, chain stops here)"
        break
      fi
      depth=$((depth + 1))
    done
    echo "-- sockets currently held by this pid --"
    has ss && ss -tnp 2>/dev/null | grep -F "pid=$pid,"
    echo "-- last 100 lines of any nginx access log on the box (manual eyeballing, no automated correlation yet) --"
    for log in /var/log/nginx/*access*.log; do
      [ -f "$log" ] && tail -n 100 "$log" 2>/dev/null
    done
    echo "=== end forensics ==="
    echo
  } >> "$FORENSICS_LOG" 2>/dev/null
  say "  forensics for pid $pid captured to $FORENSICS_LOG"
}

say "=== linux-cryptojack-hunter v$VERSION - $(hostname) - $(date) ==="

# 0) Every user's crontab plus /etc/cron.d, checked and cleared FIRST —
#    before any process gets killed below. This used to be the last check
#    in the file (see the historical numbering "6)" still used by its
#    detail comment below); moved to run first after catching a live race
#    on oddify (2026-08-10): --kill killed the miner process, then before
#    it got down to clearing the crontab, the system's own per-minute cron
#    tick fired (the watchdog entry itself, `kill -0 <pid> || ...curl
#    init.sh | sh`), saw the process was already dead, and relaunched the
#    entire infection from scratch — new pid, new ld.so.preload, new
#    systemd unit, new crontab — seconds before the reverify scan ran,
#    which then (correctly) reported it as still CONFIRMED. Not a new
#    attacker technique, just a self-inflicted ordering bug: as long as the
#    watchdog cron entry outlives the process it watches, any --kill that
#    takes more than a few seconds risks losing this exact race. Clearing
#    the cron-based persistence before touching the process closes it.
say "Checking crontabs and /etc/cron.d..."
check_cron_content() {
  local label="$1" content="$2"
  local domain_hit=0 heuristic_hit=0 watchdog_hit=0 loader_hit=0
  local decoded combined
  decoded=$(echo "$content" | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | while read -r b64; do
    echo "$b64" | base64 -d 2>/dev/null
  done)
  combined="$content
$decoded"
  for d in "${DROPPER_DOMAINS[@]}" "${C2_IPS[@]}"; do
    echo "$combined" | grep -qF "$d" && domain_hit=1
  done
  # Self-healing watchdog disguised as a cron entry instead of a systemd
  # unit: probes its own liveness (kill -0 <pid>, pgrep, pidof, or a specific
  # /proc/net/tcp connection) and only fetches+executes a remote payload when
  # that check fails. A legitimate cron job essentially never combines a
  # liveness probe with a curl/wget-to-shell fallback in the same line, so
  # this is specific enough to treat as CONFIRMED, same as the systemd
  # watchdog-unit check.
  echo "$combined" | grep -qE '(kill -0|pgrep|pidof).*(curl|wget)[^|]*\|\s*(/bin/)?sh\b' && watchdog_hit=1
  echo "$combined" | grep -qE 'base64 -d \| */bin/sh|curl[^|]*\| *(/bin/)?sh\b|wget[^|]*\| *(/bin/)?sh\b' && heuristic_hit=1
  # @reboot persistence for a KNOWN loader binary: no domain/IP and no
  # fetch-and-pipe in the cron line itself, since the payload is already
  # sitting on disk (usually /var/tmp) and cron just launches it by exact
  # filename after every reboot. This survives a plain process-kill because
  # the process check only sees it while it is running; found live on oddify
  # 2026-08-07 as a triplicated "@reboot cd /var/tmp && nohup ./cpu-logind
  # -c config.json" entry that kept respawning the miner across reboots.
  # Matching on an exact KNOWN_LOADER_FILES name (not a generic word) keeps
  # this CONFIRMED-safe instead of a heuristic.
  #
  # \.? before the name: a bare boundary char ([/[:space:]] or start) is not
  # enough on its own once a loader uses the dotfile convention (.khp seen
  # live on oddify 2026-08-13, direct "* * * * * /bin/.khp" persistence —
  # no watchdog probe, no domain/IP in the line itself, so domain_hit and
  # watchdog_hit both stayed 0 and this loop was the only thing that could
  # have caught it). Without the optional dot, "/bin/.khp" left a literal
  # "." sitting between the "/" boundary and "khp", which the character
  # class never allowed, so loader_hit silently stayed 0 for a fully
  # correct KNOWN_LOADER_FILES entry ("khp" was already listed) and the
  # line was treated as ordinary content forever.
  for name in "${KNOWN_LOADER_FILES[@]}"; do
    echo "$combined" | grep -qE "(^|[/[:space:]])\.?${name}([[:space:]]|\$)" && loader_hit=1
  done

  if [ "$domain_hit" = 1 ] || [ "$watchdog_hit" = 1 ] || [ "$loader_hit" = 1 ]; then
    local check="cron-dropper"
    [ "$watchdog_hit" = 1 ] && [ "$domain_hit" = 0 ] && [ "$loader_hit" = 0 ] && check="cron-watchdog"
    [ "$loader_hit" = 1 ] && [ "$domain_hit" = 0 ] && [ "$watchdog_hit" = 0 ] && check="cron-loader-persistence"
    record "$check" "confirmed" "$label: $(echo "$content" | tr '\n' ';')"
    return 0
  fi
  if [ "$heuristic_hit" = 1 ]; then
    record "cron-fetch-pipe-shell" "warning" "$label: $(echo "$content" | tr '\n' ';')"
  fi
  return 1
}
# Per-line version of the same three CONFIRMED checks above (domain/IP,
# watchdog liveness-probe, known-loader @reboot persistence), used only to
# decide what to KEEP when cleaning a crontab. A user's crontab is not
# self-contained: root's crontab on a real box mixes this campaign's
# persistence with entirely unrelated legitimate jobs. Found live on oddify
# (2026-08-12): a --kill run matched one malicious watchdog line in root's
# crontab and, at the time, removed the whole crontab via `crontab -r` —
# which also silently deleted an unrelated legitimate cron entry (a
# te.la app's payment-delivery retry job) that happened to live in the same
# file. That job's absence went unnoticed until a customer-facing symptom
# (delayed Telegram invite delivery) surfaced days later. `crontab -r`
# deletes the entire file for that user with no way to recover just the
# legitimate lines afterward, so from here on cleanup is surgical: rebuild
# the crontab from only the lines that do NOT match, and only fall back to
# removing the file entirely if literally nothing legitimate is left.
cron_line_is_malicious() {
  local line="$1" decoded combined
  decoded=$(echo "$line" | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | while read -r b64; do
    echo "$b64" | base64 -d 2>/dev/null
  done)
  combined="$line
$decoded"
  for d in "${DROPPER_DOMAINS[@]}" "${C2_IPS[@]}"; do
    echo "$combined" | grep -qF "$d" && return 0
  done
  echo "$combined" | grep -qE '(kill -0|pgrep|pidof).*(curl|wget)[^|]*\|\s*(/bin/)?sh\b' && return 0
  # \.? before the name: same dotfile-boundary gap as check_cron_content
  # above (kept in sync — this is the surgical per-line cleaner, so missing
  # it here means a line like "* * * * * /bin/.khp" gets silently KEPT
  # during a --kill crontab rebuild instead of stripped).
  for name in "${KNOWN_LOADER_FILES[@]}"; do
    echo "$combined" | grep -qE "(^|[/[:space:]])\.?${name}([[:space:]]|\$)" && return 0
  done
  return 1
}
if has crontab; then
  for u in $(cut -f1 -d: /etc/passwd); do
    c=$(crontab -u "$u" -l 2>/dev/null) || continue
    if [ -n "$c" ] && check_cron_content "crontab of $u" "$c"; then
      if [ "$KILL" = 1 ]; then
        clean=$(printf '%s\n' "$c" | while IFS= read -r cronline; do
          [ -z "$cronline" ] && { printf '%s\n' "$cronline"; continue; }
          cron_line_is_malicious "$cronline" || printf '%s\n' "$cronline"
        done)
        if [ -n "$(printf '%s' "$clean" | tr -d '[:space:]')" ]; then
          printf '%s\n' "$clean" | crontab -u "$u" -
          say "  removed malicious line(s) from crontab, kept the rest: $u"
        else
          crontab -u "$u" -r 2>/dev/null
          say "  cleared crontab (nothing legitimate left): $u"
        fi
      fi
    fi
  done
fi
for f in /etc/cron.d/*; do
  [ -f "$f" ] || continue
  c=$(cat "$f" 2>/dev/null)
  if check_cron_content "$f" "$c"; then
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  fi
done

# 1) High-CPU process running from /tmp or /var/tmp. The attacker renames
#    this binary every time (cpu-logind, dashboard, and whatever comes
#    next), specifically to dodge exact-name matching like
#    KNOWN_LOADER_FILES. A high-CPU process whose own backing binary lives
#    in /tmp or /var/tmp is confirmed malicious regardless of what it is
#    named, so --kill now also removes that exact backing file, not just
#    the process. Before this, killing the process left the binary itself
#    on disk under --kill (seen live on oddify: cpu-logind survived one
#    remediation pass this way, then again hours later as /tmp/dashboard,
#    same 8350992-byte binary, new name, still not deleted by any check).
say "Checking for high-CPU processes running from /tmp or /var/tmp..."
if has ps && has awk; then
  while read -r pid cpu comm; do
    [ -z "$pid" ] && continue
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    case "$exe" in
      /tmp/*|/var/tmp/*)
        record "tmp-exec" "confirmed" "pid=$pid cpu=${cpu}% comm=$comm exe=$exe"
        capture_forensics "$pid" "tmp-exec"
        if [ "$KILL" = 1 ]; then
          kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
          [ -n "$exe" ] && [ -f "$exe" ] && safe_remove "$exe" && say "  removed: $exe"
        fi
        ;;
      /usr/share/man/*|/usr/share/doc/*|/usr/share/info/*|/usr/share/locale/*|/usr/share/mime/*)
        # 1a-ii) High-CPU process backed by a binary sitting inside a
        # pure-documentation/package-metadata directory. Nothing legitimate
        # ever puts an executable in man/doc/info/locale/mime data — package
        # managers only ever write text/data files there — so this is as
        # safe to trust as /tmp or /var/tmp, no name-based heuristic needed.
        #
        # Found live on oddify: journald-7a35f733 (mimicking systemd-journald
        # by name — not a real kernel thread, so the fake-kernel-thread check
        # below doesn't apply) running from a hidden directory under
        # /usr/share/man/man3/, a location no existing check ever looked at.
        #
        # Deliberately NOT generalized to "any hidden directory anywhere":
        # tested that first and it killed live Claude Code processes running
        # from ~/.local/share/claude/... — .local/.config/.cache/.npm/.cargo
        # etc. are completely normal per-user install locations. Scoping to
        # specific directories that can never legitimately hold an
        # executable is the safe version of the same idea.
        record "doc-dir-exec" "confirmed" "pid=$pid cpu=${cpu}% comm=$comm exe=$exe"
        capture_forensics "$pid" "doc-dir-exec"
        if [ "$KILL" = 1 ]; then
          kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
          [ -f "$exe" ] && safe_remove "$exe" && say "  removed: $exe"
        fi
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
      capture_forensics "$pid" "fake-kernel-thread"
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
#     legitimate package installs a dotfile there. Deliberately NOT
#     extended to EXTRA_SCAN_DIRS: a web app root has legitimate dotfiles
#     everywhere (.env, .gitignore, .env.example, node_modules/.package-
#     lock.json), so "any dotfile is confirmed malware" is true for a
#     system bin dir and flatly false for an app root. Learned this one
#     expensively: an earlier version of this exact check ran against
#     EXTRA_SCAN_DIRS and --kill deleted five different apps' .env files
#     in one pass. Web app roots are covered by 1d-ii below instead, which
#     only matches a specific known filename, never "any dotfile".
say "Checking for hidden files in system binary directories..."
for dir in /bin /usr/bin /sbin /usr/sbin; do
  [ -d "$dir" ] || continue
  for f in "$dir"/.[!.]*; do
    [ -f "$f" ] || continue
    record "hidden-binary" "confirmed" "$f"
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  done
done

# 1d-ii) Loader with a known filename that does NOT use the dotfile
#     convention. Seen once already: /bin/idle, deliberately named to look
#     boring rather than hidden, so 1d above never catches it. Also checks
#     EXTRA_SCAN_DIRS for the same reason as above, and /tmp + /var/tmp:
#     found live on oddify 2026-08-07 that killing the process, removing
#     config.json, and clearing the @reboot crontab all still left
#     /var/tmp/cpu-logind itself sitting on disk untouched (the process,
#     config, and cron checks never look at the loader binary's own file),
#     so nothing had to be re-downloaded for the next reinfection to relaunch
#     it — closing the loop means removing the binary too, not just what
#     launches or configures it.
say "Checking for known loader filenames in system binary directories, web app roots, and /tmp/var-tmp..."
for dir in /bin /usr/bin /sbin /usr/sbin /tmp /var/tmp ${EXTRA_SCAN_DIRS[@]:-}; do
  [ -d "$dir" ] || continue
  for name in "${KNOWN_LOADER_FILES[@]}"; do
    f="$dir/$name"
    [ -f "$f" ] || continue
    record "known-loader-file" "confirmed" "$f"
    [ "$KILL" = 1 ] && safe_remove "$f" && say "  removed: $f"
  done
done

# 1d-iii) Running process matching the self-relaunch invocation signature:
#     /bin/sh /bin/<X> <name> /bin/<name>, where a loader calls itself with
#     the target process name repeated as an argument. Generic by design
#     (does not depend on the loader's filename), to survive the next
#     rename. A legitimate script essentially never invokes itself this way.
#
#     Reads /proc/PID/cmdline directly instead of piping through `ps -e`:
#     caught live on 173.199.92.19 missing a process that /proc itself
#     could see fine (stat/cat on /proc/PID/status worked, ps -e simply
#     never printed it) — cause not confirmed (not the ld.so.preload
#     rootkit, that file was absent), but /proc is the ground truth ps is
#     built on, so read it directly rather than trust ps not to drop a row.
say "Checking for processes matching the self-relaunch loader pattern..."
for d in /proc/[0-9]*; do
  pid=$(basename "$d")
  cmd=$( { tr '\0' ' ' < "$d/cmdline"; } 2>/dev/null )
  [ -z "$cmd" ] && continue
  case "$cmd" in
    *"/bin/sh /bin/"*|*"/bin/dash /bin/"*|*"/bin/bash /bin/"*)
      echo "$cmd" | grep -qE '/bin/(sh|dash|bash) /(bin|usr/bin|sbin|usr/sbin)/[^ ]+ [^ ]+ /(bin|usr/bin|sbin|usr/sbin)/[^ ]+' || continue
      record "self-relaunch-loader" "confirmed" "pid=$pid cmd=$cmd"
      [ "$KILL" = 1 ] && kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
      ;;
  esac
done

# 1e) chattr missing while lsattr is present: e2fsprogs ships both in the
#     same package, so this asymmetry does not happen by normal wear. Seen
#     repeatedly: chattr specifically deleted, which blocks a defender (or
#     this script's own --kill) from locking files back down after cleanup,
#     and from clearing the spurious /tmp lock in 1f below. Runs before 1f
#     for exactly that reason. Reinstalling e2fsprogs only replaces a
#     binary that is either missing or byte-identical to the package's, so
#     it is safe to do automatically under --kill, unlike most package
#     operations this script would otherwise only ever recommend.
say "Checking for a selectively removed chattr binary..."
if has lsattr && ! has chattr; then
  record "chattr-removed" "confirmed" "lsattr is present but chattr is missing (e2fsprogs ships both)"
  if [ "$KILL" = 1 ] && has apt-get; then
    say "  attempting to restore it: apt-get install --reinstall e2fsprogs"
    # /tmp itself may be locked (see 1f) and break apt's own scratch space;
    # route around it with a TMPDIR apt is still allowed to write to.
    mkdir -p /root/.cryptojack-hunter-tmp 2>/dev/null
    if TMPDIR=/root/.cryptojack-hunter-tmp DEBIAN_FRONTEND=noninteractive \
       apt-get install --reinstall -y e2fsprogs >/dev/null 2>&1 && has chattr; then
      say "  chattr restored"
    else
      say "  could not restore chattr automatically, reinstall e2fsprogs by hand"
    fi
  fi
fi

# 1f) /tmp or /var/tmp carrying the immutable or append-only attribute. A
#     normal system never sets either on these directories (constant
#     create/delete traffic would break instantly); a static campaign
#     scanning /tmp for miners has been seen chattr +i'ing it instead, which
#     as a side effect breaks anything that needs a scratch dir there
#     (including apt/dpkg, which is how this was first noticed). Safe to fix
#     automatically: removing a spurious lock here only restores normal
#     behavior, it cannot make a clean system worse.
say "Checking /tmp and /var/tmp for a spurious immutable/append lock..."
if has lsattr; then
  for dir in /tmp /var/tmp; do
    [ -d "$dir" ] || continue
    flags=$(lsattr -d "$dir" 2>/dev/null | awk '{print $1}')
    case "$flags" in
      *i*|*a*)
        record "tmp-locked" "confirmed" "$dir has attributes '$flags' set (immutable/append-only), not normal for a scratch directory"
        if [ "$KILL" = 1 ]; then
          if has chattr; then
            chattr -i -a "$dir" 2>/dev/null && say "  cleared attributes on $dir" || say "  chattr present but failed to clear attributes on $dir — check manually"
          else
            say "  chattr not available, could not clear attributes on $dir — reinstall e2fsprogs (note: a locked /tmp can itself block apt's own temp files; see 1c for the TMPDIR workaround) then rerun --kill"
          fi
        fi
        ;;
    esac
  done
else
  say "  skipped (lsattr not available)"
fi

# 1f-ii) Immutable or append-only attribute on the crontab spool file itself
#     (/var/spool/cron/crontabs/<user>, not just the directory). A step
#     beyond 1f: locking the spool file blocks `crontab -e`/`crontab -`
#     from writing at all (fails with "rename: Operation not permitted"),
#     which means a malicious cron line survives even a successful-looking
#     `crontab -l | grep -v ... | crontab -` — the write silently fails and
#     the next `crontab -l` right after can still show the old in-memory/
#     cached listing, making the removal look like it worked when it did
#     not. Seen live on oddify 2026-08-13 (the .khp/javab incident): this
#     is what let a single "* * * * * /bin/.khp" line survive multiple
#     rounds of manual cleanup. Safe to clear automatically, same reasoning
#     as 1f — a legitimate crontab spool file is never immutable.
say "Checking the crontab spool file itself for a spurious immutable/append lock..."
if has lsattr; then
  for spool in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$spool" ] || continue
    flags=$(lsattr "$spool" 2>/dev/null | awk '{print $1}')
    case "$flags" in
      *i*|*a*)
        record "crontab-spool-locked" "confirmed" "$spool has attributes '$flags' set (immutable/append-only) — blocks crontab writes for this user even though \`crontab -l\` may still look normal"
        if [ "$KILL" = 1 ]; then
          if has chattr; then
            chattr -i -a "$spool" 2>/dev/null && say "  cleared attributes on $spool" || say "  chattr present but failed to clear attributes on $spool — check manually"
          else
            say "  chattr not available, could not clear attributes on $spool — reinstall e2fsprogs then rerun --kill"
          fi
        fi
        ;;
    esac
  done
else
  say "  skipped (lsattr not available)"
fi

# 1g) Immutable attribute on a logging/audit binary. Seen once already on
#     rsyslogd: locking the binary itself does not touch a single log line,
#     but it silently breaks the daemon the next time a routine package
#     update tries to replace it (dpkg cannot even take its usual backup
#     link), and a dead rsyslogd means every log source that only goes
#     through it (auth.log, syslog) goes dark while nothing on the surface
#     looks tampered with. None of these binaries has any legitimate reason
#     to be immutable. Safe to clear automatically, the same as 1f.
say "Checking logging/audit binaries for a spurious immutable lock..."
if has lsattr; then
  for bin in /usr/sbin/rsyslogd /usr/sbin/auditd /usr/bin/journalctl /usr/lib/systemd/systemd-journald; do
    [ -e "$bin" ] || continue
    flags=$(lsattr "$bin" 2>/dev/null | awk '{print $1}')
    case "$flags" in
      *i*)
        record "logging-binary-locked" "confirmed" "$bin has the immutable attribute set ('$flags'), which blocks its own future updates and can leave it dead after the next upgrade"
        if [ "$KILL" = 1 ]; then
          if has chattr; then
            chattr -i "$bin" 2>/dev/null && say "  cleared immutable attribute on $bin" || say "  chattr present but failed to clear immutable attribute on $bin — check manually"
          else
            say "  chattr not available, could not clear immutable attribute on $bin — reinstall e2fsprogs then rerun --kill"
          fi
        fi
        ;;
    esac
  done
else
  say "  skipped (lsattr not available)"
fi

# 1h) Any LIVE process whose backing binary is literally named `xmrig`,
#     regardless of how it was launched. The systemd-unit-specific check
#     further below (miner-systemd-unit) only catches the case where a
#     unit file's ExecStart runs it; found live on oddify 2026-08-13
#     launched as a bare orphaned process (ppid=1, no systemd unit at
#     all, presumably `nohup .../xmrig ... &` disowned from the RCE's
#     shell) sitting directly inside the vulnerable app's own directory
#     (/var/www/scratchcard/backoffice/xmrig-6.21.0/xmrig) rather than
#     /tmp or /root — a new drop location for this campaign, and one
#     `tmp-exec` (which only looks at /tmp/var-tmp) never covers.
#     Matching the literal binary name is durable because xmrig itself
#     is never renamed, only where/how it's run changes. Reads /proc
#     directly (not `ps`) for the same reason as the fake-kernel-thread/
#     self-relaunch checks below — don't trust a possibly-hijacked `ps`.
#
#     Placement matters: this runs BEFORE the c2-connection check just
#     below. First version had this check after c2-connection, and lost
#     the cleanup race every time on oddify — c2-connection matches the
#     same live process (via its C2 IP) and kills it first, but only
#     kills the pid, never touches the binary on disk. By the time this
#     check ran, /proc/PID/exe was already gone (process dead) and there
#     was nothing left to remove, leaving the 8.9MB binary + config.json
#     orphaned on disk indefinitely. Moving this earlier means it kills
#     AND removes the binary first; c2-connection's own kill attempt
#     right after becomes a harmless no-op against an already-dead pid.
say "Checking for any running process backed by a binary literally named xmrig..."
for d in /proc/[0-9]*; do
  pid=${d##*/}
  exe=$(readlink "$d/exe" 2>/dev/null) || continue
  case "$exe" in
    */xmrig)
      capture_forensics "$pid" "xmrig-process"
      record "xmrig-process" "confirmed" "pid=$pid running from $exe"
      if [ "$KILL" = 1 ]; then
        kill -9 "$pid" 2>/dev/null
        say "  killed pid $pid"
        parent_dir=$(dirname "$exe")
        case "$(basename "$parent_dir")" in
          xmrig*|Xmrig*|XMRig*)
            # Versioned install dir (xmrig-6.21.0/ etc) belongs to the
            # miner, not the host app — safe to remove entirely, same as
            # miner-systemd-unit's install-directory cleanup below.
            rm -rf "$parent_dir" && say "  removed: $parent_dir"
            ;;
          *)
            # Parent dir doesn't look miner-specific (could be the app's
            # own root) — only remove the binary itself, not the directory
            # it's sitting in.
            safe_remove "$exe" && say "  removed: $exe"
            ;;
        esac
      fi
      ;;
  esac
done

# 2) Network connections to a known C2 IP.
say "Checking network connections to known C2 IPs..."
if has ss; then
  for ip in "${C2_IPS[@]}"; do
    hits=$(ss -tnp 2>/dev/null | grep -F "$ip")
    if [ -n "$hits" ]; then
      record "c2-connection" "confirmed" "active connection to $ip: $(echo "$hits" | tr '\n' ';')"
      echo "$hits" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
        capture_forensics "$pid" "c2-connection ($ip)"
        [ "$KILL" = 1 ] && kill -9 "$pid" 2>/dev/null && say "  killed pid $pid"
      done
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

# 2d) Core system utility (ps, top, ...) replaced by a filtering wrapper
#     script instead of the real compiled binary. A different, older-style
#     userland rootkit hook than ld.so.preload: instead of intercepting
#     readdir, it renames the real binary to <name>.original and drops a
#     shell script in its place that calls the original and pipes the
#     output through `grep -v <hidden-name>` to hide a specific process from
#     anyone running ps/top by hand — or from this very script, since every
#     CPU-based check above depends on `ps -e`.
#
#     Found live on oddify: /usr/bin/ps and /usr/bin/top both replaced this
#     way (dpkg -V flags both, confirmed against the real procps package),
#     filtering out a process named "javab" — the same name seen before as
#     a disguised systemd unit in this campaign's history. ps.original was
#     already missing by the time this was found, so the wrapper was 100%
#     broken (ps returned nothing at all instead of hiding just one
#     process) — meaning every ps-dependent check in this script had been
#     silently blind on this host the whole time, and the only reason
#     cpu-logind/dashboard/etc. kept getting caught anyway is that
#     known-loader-file, c2-connection and miner-config never relied on ps.
#
#     No legitimate ps/top install is ever a shell script that shells out to
#     a `.original`-suffixed sibling and filters its own output — that
#     combination is unambiguous, so this is CONFIRMED and safe to fix by
#     reinstalling the owning package (same pattern already used for a
#     locked/deleted chattr or rsyslogd).
say "Checking core utilities for a hidden-process filtering wrapper..."
for bin in "${WRAPPED_BIN_CANDIDATES[@]}"; do
  path=$(command -v "$bin" 2>/dev/null)
  [ -n "$path" ] && [ -f "$path" ] || continue
  head -c 64 "$path" 2>/dev/null | grep -q '^#!' || continue
  content=$(cat "$path" 2>/dev/null)
  if echo "$content" | grep -qE '\.original\b.*\|[[:space:]]*grep[[:space:]]+-v'; then
    record "utility-hijacked" "confirmed" "$path is a wrapper hiding output from the real binary: $(echo "$content" | tr '\n' ';')"
    if [ "$KILL" = 1 ]; then
      # Prefer restoring the preserved "$path.original" sibling directly
      # over a package reinstall: it needs no network and no apt (which
      # itself needs a writable /tmp for its temp files — see 1f/1c), and
      # it's exactly what the wrapper script itself shells out to, so if
      # it's there it is by construction the same binary that was renamed
      # away. Only fall back to apt if that sibling is gone (seen live on
      # oddify: ps.original had already been removed by the time this was
      # found, leaving the wrapper 100% broken with nothing to fall back
      # on locally).
      if [ -f "${path}.original" ]; then
        mv "${path}.original" "$path" 2>/dev/null && chmod 755 "$path" 2>/dev/null && say "  restored $path from its preserved .original copy"
      else
        pkg=$(dpkg -S "$path" 2>/dev/null | cut -d: -f1 | head -1)
        if [ -n "$pkg" ]; then
          if apt-get install --reinstall -y "$pkg" >/dev/null 2>&1; then
            say "  reinstalled package '$pkg' to restore $path"
          else
            say "  apt-get install --reinstall failed for '$pkg' (a locked /tmp can cause this — see 1f) — $path not auto-fixed, restore it manually"
          fi
        else
          say "  no .original sibling and could not determine the owning package for $path — not auto-fixed, restore it manually"
        fi
      fi
    fi
  fi
done

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
        # Grab the ExecStart target before the unit file is gone — same
        # lesson as known-loader-file: stopping/deleting the unit does not
        # touch whatever binary it launched, so a payload dropped alongside
        # it survives the "clean" system untouched. Caught live on oddify
        # 2026-08-11: this block correctly removed `moneroocean_miner` (an
        # XMRig install from MoneroOcean's own public setup script) but
        # left the entire /root/moneroocean/ directory — binary, config,
        # log — sitting on disk, because that cleanup only ever lived in
        # the newer miner-systemd-unit check below, which never got a
        # chance to run since this block (earlier in the script) had
        # already deleted the unit file by the time it did.
        #
        # Scoped deliberately to a short list of drop locations rather than
        # "wherever ExecStart points": a known-unit name could in principle
        # front-run a legitimate system binary (e.g. a future addition to
        # KNOWN_UNIT_NAMES pointing at /usr/bin/something), and blindly
        # rm -rf'ing that ExecStart's parent directory would be catastrophic.
        # /root, /tmp, /var/tmp, /home, /opt are never legitimate homes for
        # a systemd ExecStart target, so removing their subtree here carries
        # the same safety guarantee as the /tmp-scoped process checks above.
        exec_target=$(grep -oE 'ExecStart=[^[:space:]]+' "/etc/systemd/system/${name}.service" 2>/dev/null | head -1 | cut -d= -f2)
        systemctl stop "$name.service" "$name.timer" 2>/dev/null
        systemctl disable "$name.service" "$name.timer" 2>/dev/null
        find /etc/systemd/system -iname "${name}*" -delete 2>/dev/null
        case "$exec_target" in
          /root/*|/tmp/*|/var/tmp/*|/home/*|/opt/*)
            payload_dir=$(dirname "$exec_target")
            [ -d "$payload_dir" ] && rm -rf "$payload_dir" && say "  removed payload directory: $payload_dir"
            ;;
        esac
        # Without this, systemd keeps the unit "Loaded" from its in-memory
        # cache even after the file is gone, so `list-units --all` (what the
        # check above greps) keeps matching it on the next run — a clean
        # remediation reported back as still-CONFIRMED. Caught live on
        # apostacertabet: redis-sentinel kept showing up after stop+disable+
        # delete until a manual `daemon-reload` made it disappear. The other
        # two systemd-unit checks below already had this line; this one just
        # never got it when it was written first.
        systemctl daemon-reload 2>/dev/null
        # daemon-reload alone isn't enough for a unit that ended up in
        # "failed" state (as opposed to just "loaded from a since-deleted
        # file") — systemd keeps failed units in its bookkeeping until an
        # explicit reset-failed, so list-units --all kept matching this one
        # after a full, verified-complete removal (unit file gone, payload
        # directory gone) on 149.28.123.247: the moneroocean_miner install
        # there had failed to launch in the first place (203/EXEC, bad
        # binary path) and sat in that failed state for days, which this
        # check's daemon-reload never cleared.
        systemctl reset-failed "$name.service" "$name.timer" 2>/dev/null
        say "  stopped/disabled/removed: $name"
      fi
    fi
  done
  newer=$(find /etc/systemd/system -maxdepth 1 -newer /etc/hostname -type f 2>/dev/null)
  [ -n "$newer" ] && record "unit-newer-than-host" "warning" "unit file(s) newer than /etc/hostname: $(echo "$newer" | tr '\n' ';')"
else
  say "  skipped (systemctl not available)"
fi

# 5a2) systemd unit whose ExecStart runs a binary literally named `xmrig`.
#      Found live on oddify 2026-08-11 as `moneroocean_miner.service`,
#      installed straight from MoneroOcean's own public setup script
#      (github.com/MoneroOcean/xmrig_setup) — a real, unmodified miner
#      binary, self-installed with a legitimate-sounding unit description
#      ("Monero miner service") and throttled (Nice=10) to stay under the
#      radar of anything watching for a loud, obviously-malicious process.
#      This traced back to the actual entry vector for the first time in
#      this campaign's history: `ppid` on the shell that ran the installer
#      was the live scratchcard-backoffice Next.js server (port 4000) —
#      confirmed RCE in a production app, not the usual /tmp dropper this
#      script has been chasing. Matching on the literal binary name (not
#      the unit name, which the attacker could rename next time, or the
#      install directory) is what makes this durable — xmrig itself is
#      never going to be renamed, that's the actual miner.
say "Checking systemd units for an ExecStart running a binary named xmrig..."
if has systemctl; then
  for unit_file in /etc/systemd/system/*.service; do
    [ -f "$unit_file" ] || continue
    if grep -qE 'ExecStart=.*/xmrig([[:space:]]|$)' "$unit_file" 2>/dev/null; then
      unit_name=$(basename "$unit_file" .service)
      target=$(grep -oE 'ExecStart=[^[:space:]]+' "$unit_file" | head -1 | cut -d= -f2)
      record "miner-systemd-unit" "confirmed" "$unit_file runs $target: $(tr '\n' ';' < "$unit_file")"
      if [ "$KILL" = 1 ]; then
        systemctl stop "$unit_name" 2>/dev/null
        systemctl disable "$unit_name" 2>/dev/null
        safe_remove "$unit_file"
        # Remove the whole install directory (config/log/binary), not just
        # the xmrig binary itself — same lesson as known-loader-file: a
        # kill that only stops the process/unit but leaves the payload on
        # disk means the next reboot (or a stray `systemctl start`) brings
        # it right back with nothing left to re-download.
        [ -n "$target" ] && [ -d "$(dirname "$target")" ] && rm -rf "$(dirname "$target")" && say "  removed: $(dirname "$target")"
        systemctl daemon-reload 2>/dev/null
        systemctl reset-failed "$unit_name.service" 2>/dev/null
        say "  stopped/disabled/removed: $unit_name"
      fi
    fi
  done
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
        systemctl reset-failed "$unit_name" 2>/dev/null
        say "  stopped/disabled/removed: $unit_name"
      fi
    fi
  done
fi

# 5c) systemd unit whose ExecStart runs a raw script sitting directly under
#     /etc/ (not the legitimate /etc/init.d/ SysV convention), where that
#     script re-execs /usr/bin/systemd on an uncommented line. Seen once
#     already disguised as "vimenv": the script was padded with several
#     paragraphs of verbatim GNU Coding Standards text as comments, so a
#     quick `cat` looks like nothing but boilerplate documentation, and the
#     one real command hides easily in the middle. A legitimate package
#     never installs its startup script as a bare file directly in /etc/.
say "Checking for a systemd unit disguised as a padded boilerplate script..."
if has systemctl; then
  for unit_file in /etc/systemd/system/*.service; do
    [ -f "$unit_file" ] || continue
    target=$(grep -oE 'ExecStart=/etc/[^/[:space:]]+' "$unit_file" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$target" ] && [ -f "$target" ] || continue
    # Strip full-line comments and blank lines before checking; the disguise
    # relies on a wall of "# ..." text hiding one real command in the middle.
    payload=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$target" 2>/dev/null)
    if echo "$payload" | grep -qE '(^|[;&|[:space:]])/(usr/bin|bin)/systemd([[:space:]]|$)'; then
      record "boilerplate-systemd-reexec" "confirmed" "$unit_file execs $target, which re-invokes systemd on an uncommented line: $(echo "$payload" | tr '\n' ';')"
      if [ "$KILL" = 1 ]; then
        unit_name=$(basename "$unit_file")
        systemctl stop "$unit_name" 2>/dev/null
        systemctl disable "$unit_name" 2>/dev/null
        safe_remove "$unit_file"
        safe_remove "$target"
        systemctl daemon-reload 2>/dev/null
        systemctl reset-failed "$unit_name" 2>/dev/null
        say "  stopped/disabled/removed: $unit_name and $target"
      fi
    fi
  done
fi

# 6) (moved to run first, right after the header — see the "0)" comment
#    near the top of the file for why. Left this number gap intentionally
#    instead of renumbering every other section.)

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
if [ "$CONFIRMED_COUNT" -gt 0 ]; then
  say "RESULT: $CONFIRMED_COUNT confirmed infection indicator(s) found."
  [ "$KILL" = 1 ] || say "(ran in report mode, repeat with --kill to act on CONFIRMED findings)"
elif [ "$WARNING_COUNT" -gt 0 ]; then
  say "RESULT: nothing confirmed, $WARNING_COUNT generic warning(s) for manual review."
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

# Exit 1 only for CONFIRMED findings, so a cron/monitoring wrapper can alert
# on real infection signal without paging on WARNING-only noise (a unit file
# newer than /etc/hostname, a fetch-and-pipe pattern in a legitimate deploy
# script, etc).
[ "$CONFIRMED_COUNT" -gt 0 ] && exit 1
exit 0
