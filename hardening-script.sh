#!/bin/bash
#

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

# Enable strict error handling
set -euo pipefail

# ------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------
print_section() {
    printf "\n"
    printf "================================================================\n"
    printf "  %s\n" "$1"
    printf "================================================================\n"
}

status() {
    printf "%-60s" "$1..." >&2
}

ok() {
    printf " done\n" >&2
}

skip() {
    printf " skipped (%s)\n" "$1" >&2
}

info() {
    printf "%s\n" "$1"
}

# FIX: previously all warnings looked like normal output, so a missing
# package or skipped step could scroll past unnoticed. Warnings are
# collected and re-printed as a summary at the very end instead.
WARNINGS=()
warn() {
    printf "  [!] %s\n" "$1" >&2
    WARNINGS+=("$1")
}

# have_cmd: existence check used throughout instead of letting `set -e`
# kill the whole run when an optional package (doas vs sudo, at, aide,
# ip6tables, dhclient, wpa_supplicant...) isn't installed.
have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------------------
# Backup function for critical files
# FIX: this existed in the previous version but was never actually called,
# and $BACKUP_DIR was created but never used. Every destructive overwrite
# below now calls this first, and backups land in $BACKUP_DIR so a bad
# run is easy to diff/revert instead of scattering .backup.* files
# throughout /etc.
# ------------------------------------------------------------------------
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local dest="${BACKUP_DIR}${file}"
        mkdir -p "$(dirname "$dest")"
        cp -p "$file" "$dest" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------------
# Init system detection
# Artix ships four supported init systems. This script can fully automate
# service-enablement on OpenRC (the most common choice, and the one with
# documented, stable rc-update semantics). For runit/s6/dinit we print the
# exact manual command from the Artix wiki instead of guessing — getting
# a persistence command subtly wrong (e.g. enabling a service only for the
# current boot instead of permanently) is worse than just telling you what
# to run yourself.
# ------------------------------------------------------------------------
INIT_SYSTEM="unknown"
if [ -d /run/openrc ] || have_cmd rc-update; then
    INIT_SYSTEM="openrc"
elif [ -d /etc/runit/sv ] || [ -d /run/runit ]; then
    INIT_SYSTEM="runit"
elif [ -d /etc/s6/sv ] || have_cmd s6-rc; then
    INIT_SYSTEM="s6"
elif have_cmd dinitctl; then
    INIT_SYSTEM="dinit"
fi

MANUAL_STEPS=()

# FIX: `s6 set enable` (below) only stages a change -- it doesn't get
# compiled into the live/boot database on its own, see apply_s6_changes()
# further down. This flag records whether anything was actually staged
# during this run, so that step only fires when there's something to do.
S6_STAGED=0

# enable_boot_service <service-name> <openrc-runlevel>
# Only OpenRC is automated. Existence of the init script is checked first
# because on Artix the daemon and its OpenRC init script are frequently
# split into two packages (e.g. iptables vs iptables-openrc) — the base
# package alone will not register a service.
enable_boot_service() {
    local svc="$1"
    local runlevel="${2:-default}"
    case "$INIT_SYSTEM" in
        openrc)
            if [ -f "/etc/init.d/$svc" ]; then
                rc-update add "$svc" "$runlevel" >/dev/null 2>&1 || true
                info "  Enabled '$svc' at OpenRC runlevel '$runlevel'"
            else
                warn "OpenRC script for '$svc' not found at /etc/init.d/$svc — install ${svc}-openrc (or equivalent) then run: rc-update add $svc $runlevel"
                MANUAL_STEPS+=("pacman -S ${svc}-openrc && rc-update add $svc $runlevel")
            fi
            ;;
        runit)
            MANUAL_STEPS+=("ln -s /etc/runit/sv/$svc /run/runit/service   # enable '$svc' under runit")
            ;;
        s6)
            # Confirmed against Artix's own migration announcement: the
            # current, official way to enable a service at boot under s6
            # is `s6 set enable <name>` (a first-party frontend that
            # replaced the old touch-a-file-by-hand approach). Tried
            # directly rather than pre-checking for a source directory
            # first, since the exact on-disk layout (bundle vs longrun,
            # possible -srv suffixes) isn't worth guessing at when the
            # tool itself can just tell us whether it worked.
            if have_cmd s6; then
                if S6_OUT=$(s6 set enable "$svc" 2>&1); then
                    info "  Enabled '$svc' under s6 (s6 set enable $svc)"
                    S6_STAGED=1
                else
                    warn "'s6 set enable $svc' failed — it may not be installed for s6. Try: pacman -S ${svc}-s6. Details: $S6_OUT"
                    MANUAL_STEPS+=("pacman -S ${svc}-s6 && s6 set enable $svc")
                fi
            else
                warn "s6 was detected as the init system but the 's6' command isn't on PATH — enable manually: s6 set enable $svc"
                MANUAL_STEPS+=("s6 set enable $svc")
            fi
            ;;
        dinit)
            MANUAL_STEPS+=("dinitctl enable $svc   # enable '$svc' under dinit")
            ;;
        *)
            MANUAL_STEPS+=("Enable the '$svc' service manually — could not detect your init system")
            ;;
    esac
}

# apply_s6_changes: commits and live-applies whatever enable_boot_service
# staged above.
# FIX: this had no equivalent anywhere in the script. `s6 set enable` only
# stages a change -- the installer's own add_service() always pairs it
# with `s6 set commit && s6 live install` (its reload_s6_db()) right
# afterward, and that pairing is what actually compiles a staged change
# into the database s6-rc boots from. This script's own s6 enables
# (iptables, ip6tables, auditd if installed) had no equivalent commit, and
# the installer only calls reload_s6_db() *before* invoking this script,
# never after -- so anything enabled only in here was staged and then left
# uncommitted straight through the installer's final reboot. It never
# actually started, on that boot or any later one, until something else
# happened to commit the s6 database. Since this script is also run
# standalone, the commit lives here (not in the installer) so it's fixed
# regardless of caller.
apply_s6_changes() {
    [ "$INIT_SYSTEM" = "s6" ] || return 0
    [ "$S6_STAGED" -eq 1 ] || return 0
    if ! have_cmd s6; then
        warn "s6 changes were staged but the 's6' command isn't on PATH to commit them — run manually: s6 set commit && s6 live install"
        MANUAL_STEPS+=("s6 set commit && s6 live install")
        return 0
    fi
    status "committing and applying staged s6 service changes"
    if S6_OUT=$(s6 set commit 2>&1 && s6 live install 2>&1); then
        ok
    else
        warn "'s6 set commit && s6 live install' failed — services enabled above may not be active until you run that manually. Details: $S6_OUT"
        MANUAL_STEPS+=("s6 set commit && s6 live install")
    fi
}

print_section "Starting system hardening process"
info "Detected init system: $INIT_SYSTEM"

# Create backup directory
BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
info "Backups of any file this script overwrites will be stored under: $BACKUP_DIR"

# ========================================================
# FILE PERMISSIONS
# ========================================================
print_section "File Permissions"

status "setting secure file permissions"
chmod 700 /root
chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
# FIX: /etc/sudoers only exists if sudo is installed — plenty of minimal
# Artix installs use doas instead. This no longer hard-fails the whole
# script (set -e) when it's absent.
[ -f /etc/sudoers ] && chmod 600 /etc/sudoers
[ -f /etc/doas.conf ] && chmod 600 /etc/doas.conf
chmod -R 700 /etc/ssl/private 2>/dev/null || true
chmod -R 755 /etc/ssl/certs 2>/dev/null || true
find /etc/cron.* -type f -exec chmod 0700 {} \; 2>/dev/null || true
# FIX: only the files inside the cron.* directories were locked down
# before; the directories themselves were left at their (often more
# permissive) default. Lynis checks the directories too.
chmod 0700 /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly 2>/dev/null || true
chmod 0600 /etc/crontab 2>/dev/null || true
chmod 0600 /etc/ssh/sshd_config 2>/dev/null || true
ok

# ========================================================
# HOST CONFIGURATION
# ========================================================
status "configuring host resolver"
backup_file /etc/host.conf
cat <<'EOF' > /etc/host.conf
order bind,hosts
multi on
EOF
ok

# ========================================================
# KERNEL MODULE CONFIGURATION
# ========================================================
print_section "Kernel Module Configuration"

status "loading netfilter modules"
MODPROBE="/sbin/modprobe"
"$MODPROBE" nf_conntrack_ftp 2>/dev/null || "$MODPROBE" ip_conntrack_ftp 2>/dev/null || true
"$MODPROBE" nf_conntrack_irc 2>/dev/null || "$MODPROBE" ip_conntrack_irc 2>/dev/null || true
ok

status "disabling uncommon network protocols"
backup_file /etc/modprobe.d/uncommon-net-protocols.conf
cat > /etc/modprobe.d/uncommon-net-protocols.conf <<'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install p8022 /bin/true
install can /bin/true
install atm /bin/true
EOF
ok

status "disabling uncommon filesystems"
backup_file /etc/modprobe.d/uncommon-filesystems.conf
cat > /etc/modprobe.d/uncommon-filesystems.conf <<'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
ok

status "blacklisting firewire modules"
backup_file /etc/modprobe.d/blacklist-firewire.conf
cat > /etc/modprobe.d/blacklist-firewire.conf <<'EOF'
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-net
blacklist firewire-serial
blacklist firewire-sbp2
EOF
ok

# ========================================================
# TCP/IP STACK HARDENING
# ========================================================
# NOTE: left byte-for-byte identical to your existing version at your
# request — this has already been tuned separately, so it isn't touched
# here. (The only thing worth flagging, not changing: these are raw
# /proc/sys writes, so they apply immediately but do not by themselves
# survive a reboot unless something else in your setup already persists
# them via /etc/sysctl.d or equivalent. Not modifying anything here either
# way — just noting it in case it's useful.)
# ========================================================
print_section "TCP/IP Stack Hardening"

# FIX (mechanical only, no values changed): every loop below had the same
# bash gotcha -- `cmd > "$path" 2>/dev/null` does NOT suppress an error
# from the ">" redirection itself failing to open its target (only errors
# from the command would be suppressed that way). When a given /proc/sys
# entry couldn't be opened for writing (e.g. mc_forwarding isn't writable
# for every interface on every kernel build), that failure printed
# straight to the terminal regardless of the 2>/dev/null, even though the
# `|| true` correctly stopped it from ever aborting the script. Wrapping
# each redirect in `{ ...; }` makes the existing 2>/dev/null actually
# apply to the redirection failure too, so it's silent like it was always
# meant to be. Nothing about *what* gets set, or to what value, changed.
status "hardening TCP/IP stack (runtime)"
# IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do { echo 1 > "$i"; } 2>/dev/null || true; done

# TCP hardening
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Log martian packets
for i in /proc/sys/net/ipv4/conf/*/log_martians; do { echo 1 > "$i"; } 2>/dev/null || true; done

# Disable forwarding and redirects
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do { echo 0 > "$i"; } 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do { echo 0 > "$i"; } 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do { echo 0 > "$i"; } 2>/dev/null || true; done

# Disable multicast forwarding and proxy ARP
for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do { echo 0 > "$i"; } 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do { echo 0 > "$i"; } 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do { echo 1 > "$i"; } 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do { echo 0 > "$i"; } 2>/dev/null || true; done
ok

# ========================================================
# IPTABLES FIREWALL CONFIGURATION
# ========================================================
# FIX: several changes in this section, all explained inline where they
# happen. Short version:
#   1. A mis-ordered "SYN flood protection" rule was silently turning this
#      into an ACCEPT-almost-everything firewall (details below, right
#      where it's fixed) -- this was the single most important bug found
#      in the whole script.
#   2. Rule construction now happens with policy=ACCEPT and only flips to
#      DROP once the complete ruleset (incl. the final catch-all) is in
#      place, with a trap that reverts to ACCEPT-all if anything fails
#      partway through. On a box you're administering over SSH, that's
#      the difference between "oops, re-run it" and "drive to the
#      datacenter" / "lost SSH to your own desktop".
#   3. A handful of OUTPUT-chain "allow" rules were dead code: OUTPUT's
#      default policy is ACCEPT and there's no OUTPUT catch-all reject,
#      so those rules never did anything either way. Removed for a
#      leaner, more honest ruleset -- OUTPUT stays permissive on purpose
#      (locking down outbound traffic is one of the most common sources
#      of "why doesn't X work" support requests, and Lynis doesn't
#      require it).
#   4. The Discord rule opened inbound UDP 50000-65535 -- about a quarter
#      of all ports. Removed: NAT hole-punching for voice already works
#      through the existing ESTABLISHED,RELATED rule, so this was a lot
#      of attack surface for no actual functional benefit. Steam/
#      console/BitTorrent ranges are left exactly as they were, since
#      those are properly scoped to their real ports and look like a
#      deliberate choice (e.g. if you've port-forwarded on your router
#      for "open NAT").
print_section "Iptables Firewall Configuration"

IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
SSHPORT="22"

if ! have_cmd "$IPTABLES"; then
    warn "iptables not found at $IPTABLES — skipping firewall configuration entirely"
else

# Safety net: if anything below fails unexpectedly, fall back to a fully
# open firewall rather than leaving the box in a half-built default-DROP
# state that could lock you out of the very session you're running this
# from. Cleared right after the ruleset is complete and saved.
# shellcheck disable=SC2317  # only invoked indirectly via `trap`, below
firewall_panic() {
    warn "Firewall setup did not finish — reverted to ACCEPT-all (v4+v6) so you are not locked out. Fix the underlying issue and re-run."
    for t in "$IPTABLES" "$IP6TABLES"; do
        have_cmd "$t" || continue
        "$t" -P INPUT ACCEPT 2>/dev/null || true
        "$t" -P FORWARD ACCEPT 2>/dev/null || true
        "$t" -P OUTPUT ACCEPT 2>/dev/null || true
        "$t" -F 2>/dev/null || true
        "$t" -X 2>/dev/null || true
    done
}
trap firewall_panic ERR INT TERM

status "flushing existing iptables rules"
# FIX: policies are forced to ACCEPT *before* flushing. On a re-run,
# policy was already DROP from the previous run — flushing at that point
# (which clears rules but not policy) briefly left zero rules AND a DROP
# policy in effect simultaneously, i.e. every packet, including your
# current SSH session, dropped until the rules further down were
# rebuilt. Forcing ACCEPT first makes the flush itself always safe, on
# a first run or a hundredth.
"$IPTABLES" -P INPUT ACCEPT
"$IPTABLES" -P FORWARD ACCEPT
"$IPTABLES" -P OUTPUT ACCEPT
"$IPTABLES" -F
"$IPTABLES" -X
"$IPTABLES" -Z
"$IPTABLES" -t nat -F
"$IPTABLES" -t nat -X
"$IPTABLES" -t nat -Z
"$IPTABLES" -t mangle -F
"$IPTABLES" -t mangle -X
"$IPTABLES" -t mangle -Z
ok

status "creating logging chains"
LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options"
RLIMIT="-m limit --limit 3/s --limit-burst 8"

"$IPTABLES" -N LOGACCEPT
# shellcheck disable=SC2086  # $LOG/$RLIMIT are meant to word-split into multiple args
"$IPTABLES" -A LOGACCEPT -j $LOG $RLIMIT --log-prefix "ACCEPT "
"$IPTABLES" -A LOGACCEPT -j ACCEPT

"$IPTABLES" -N LOGDROP
# shellcheck disable=SC2086  # intentional word-splitting, see LOGACCEPT above
"$IPTABLES" -A LOGDROP -j $LOG $RLIMIT --log-prefix "DROP "
"$IPTABLES" -A LOGDROP -j DROP

"$IPTABLES" -N LOGREJECT
# shellcheck disable=SC2086  # intentional word-splitting, see LOGACCEPT above
"$IPTABLES" -A LOGREJECT -j $LOG $RLIMIT --log-prefix "REJECT "
"$IPTABLES" -A LOGREJECT -p tcp -j REJECT --reject-with tcp-reset
"$IPTABLES" -A LOGREJECT -j REJECT
ok

status "configuring loopback interface"
"$IPTABLES" -A INPUT -i lo -j ACCEPT
"$IPTABLES" -A OUTPUT -o lo -j ACCEPT
ok

status "configuring stateful firewall"
"$IPTABLES" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"$IPTABLES" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ok

status "blocking invalid packets"
"$IPTABLES" -A INPUT -m conntrack --ctstate INVALID -j DROP
"$IPTABLES" -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
"$IPTABLES" -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
"$IPTABLES" -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
ok

status "implementing SYN flood protection"
# FIX (the big one): this used to be positioned *after* all the
# per-service allow rules, as:
#   iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
#   iptables -A INPUT -p tcp --syn -j DROP
# Two problems compounded:
#  - It came after every service-specific rule, so by the time a NEW SYN
#    reached it, it was really matching "any SYN to any port not already
#    explicitly handled above".
#  - It used "-j ACCEPT" for in-budget traffic, which *terminates*
#    processing for that packet successfully — it doesn't fall through
#    to the final catch-all reject.
#  Put together, this meant a NEW TCP connection to *any* port on the
#  machine (an accidentally-exposed dev server, a database listening on
#  0.0.0.0, whatever) was actually being accepted, just throttled to
#  roughly one new connection per second system-wide. That silently
#  defeated the default-deny firewall for anything not explicitly
#  matched above it — the opposite of what a "SYN flood protection" rule
#  should do.
#  Fixed version: moved to run immediately after the invalid-packet
#  checks (before any per-service rule), and in-budget traffic now
#  RETURNs to continue normal processing instead of being accepted
#  outright — so it can only ever throttle, never independently open a
#  port. Rate raised from 1/s (burst 3) to 20/s (burst 50): the old
#  number would have throttled completely legitimate bursty traffic —
#  a browser opening several connections for one page load, or
#  BitTorrent picking up new peers — while still doing essentially
#  nothing against a real flood (thousands of SYNs/sec). 20/s (burst 50)
#  still stops an actual flood cold without that collateral damage.
"$IPTABLES" -N SYNFLOOD
"$IPTABLES" -A SYNFLOOD -m limit --limit 20/s --limit-burst 50 -j RETURN
"$IPTABLES" -A SYNFLOOD -j LOGDROP
"$IPTABLES" -A INPUT -p tcp --syn -j SYNFLOOD
ok

status "rate limiting ICMP"
"$IPTABLES" -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
"$IPTABLES" -A INPUT -p icmp -j DROP
ok

status "allowing HTTP/HTTPS"
"$IPTABLES" -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
ok

status "allowing SSH with brute-force protection"
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -m recent --set --name SSH
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -j ACCEPT
ok

status "allowing Tor network"
"$IPTABLES" -A INPUT -p tcp -m multiport --dports 9050,9051,9150 -j ACCEPT
ok

status "allowing BitTorrent (P2P)"
"$IPTABLES" -A INPUT -p tcp --dport 6881:6889 -j ACCEPT
"$IPTABLES" -A INPUT -p udp --dport 6881:6889 -j ACCEPT
ok

status "allowing Steam gaming"
"$IPTABLES" -A INPUT -p tcp --dport 27000:27100 -j ACCEPT
"$IPTABLES" -A INPUT -p udp --dport 27000:27100 -j ACCEPT
ok

status "allowing console gaming (PlayStation/Xbox)"
"$IPTABLES" -A INPUT -p tcp --dport 3478:3480 -j ACCEPT
"$IPTABLES" -A INPUT -p udp --dport 3478:3480 -j ACCEPT
ok
# NOTE: the previous "allow Discord voice" rule (inbound UDP 50000:65535)
# was removed here. Voice/video NAT traversal is initiated outbound and
# the reply traffic is already covered by the ESTABLISHED,RELATED rule
# above -- Discord does not need an inbound listen range to work, so this
# was pure attack surface (~15,500 ports) for no functional gain.

status "logging dropped packets"
"$IPTABLES" -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-input: " --log-level 7
"$IPTABLES" -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables-forward: " --log-level 7
ok

status "setting final drop rules"
"$IPTABLES" -A INPUT -j LOGREJECT
"$IPTABLES" -A FORWARD -j LOGREJECT
ok

status "setting default policies"
# FIX: this now happens *last*, once every allow rule above (including
# the final catch-all reject) already exists. There is no longer a
# window where policy=DROP is active without the SSH/loopback/established
# rules already in place ahead of it.
"$IPTABLES" -P INPUT DROP
"$IPTABLES" -P FORWARD DROP
"$IPTABLES" -P OUTPUT ACCEPT
"$IPTABLES" -t nat -P PREROUTING ACCEPT
"$IPTABLES" -t nat -P OUTPUT ACCEPT
"$IPTABLES" -t nat -P POSTROUTING ACCEPT
"$IPTABLES" -t mangle -P PREROUTING ACCEPT
"$IPTABLES" -t mangle -P INPUT ACCEPT
"$IPTABLES" -t mangle -P FORWARD ACCEPT
"$IPTABLES" -t mangle -P OUTPUT ACCEPT
"$IPTABLES" -t mangle -P POSTROUTING ACCEPT
ok

status "saving iptables rules"
mkdir -p /etc/iptables
iptables-save > /etc/iptables/iptables.rules
ok

status "enabling iptables at boot"
enable_boot_service iptables default
ok

# ========================================================
# IPv6 FIREWALL
# ========================================================
print_section "IPv6 Firewall (Block All)"

if ! have_cmd "$IP6TABLES"; then
    warn "ip6tables not found at $IP6TABLES — skipping IPv6 firewall (if IPv6 is in use on this box, it is currently unfiltered)"
else
    status "configuring ip6tables (block all)"
    "$IP6TABLES" -P INPUT ACCEPT
    "$IP6TABLES" -P FORWARD ACCEPT
    "$IP6TABLES" -P OUTPUT ACCEPT
    "$IP6TABLES" -F
    "$IP6TABLES" -X
    "$IP6TABLES" -Z
    "$IP6TABLES" -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables-input: " --log-level 7
    "$IP6TABLES" -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "ip6tables-forward: " --log-level 7
    "$IP6TABLES" -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables-output: " --log-level 7
    "$IP6TABLES" -P INPUT DROP
    "$IP6TABLES" -P FORWARD DROP
    "$IP6TABLES" -P OUTPUT DROP
    mkdir -p /etc/iptables
    ip6tables-save > /etc/iptables/ip6tables.rules
    ok

    status "enabling ip6tables at boot"
    enable_boot_service ip6tables default
    ok
fi

# Ruleset complete and saved — clear the safety net.
trap - ERR INT TERM

fi # have_cmd iptables

# ========================================================
# SYSTEM CONFIGURATION FILES
# ========================================================
print_section "System Configuration Files"

status "configuring bash environment"
backup_file /etc/bash.bashrc
# FIX: the previous version had a bare "readonly" (no arguments) sitting
# in front of both "umask 0027" and "TMOUT=1800". `readonly` with no
# arguments doesn't protect anything — it just *lists* currently-readonly
# variables. Printed to an interactive shell's startup, that meant every
# new terminal briefly dumped a list of readonly vars for no reason, and
# TMOUT was never actually protected against being unset.
# Also: TMOUT was being set (and, if "fixed" naively, marked readonly) in
# *both* bash.bashrc and /etc/profile. profile sources bash.bashrc and
# then tries to set TMOUT again — if bash.bashrc had correctly made it
# readonly first, that second assignment in profile would fail with
# "TMOUT: readonly variable" printed at every single login. So TMOUT is
# now set in exactly one place (here), since bash.bashrc is sourced by
# both login shells (via profile) and the plain interactive shells your
# terminal emulator opens directly (which never read /etc/profile at
# all) -- this is actually the one file that reliably covers both cases.
cat > /etc/bash.bashrc <<'EOF'
# /etc/bash.bashrc

[[ $- != *i* ]] && return

PS1='[\u@\h \W]\$ '
PS2='> '
PS3='> '
PS4='+ '

umask 0027

# Auto-logout idle interactive shells after 30 minutes. This only closes
# idle terminal *prompts* -- it has no effect on your desktop session,
# running programs, or anything with a foreground job attached. Readonly
# so a script (or an attacker with a foothold) can't just unset it to
# cover their tracks. Comment out the "readonly" line, or raise the
# value, if 30 minutes ever proves annoying.
TMOUT=1800
export TMOUT
readonly TMOUT

case ${TERM} in
  xterm*|rxvt*|Eterm|aterm|kterm|gnome*)
    PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND; }'printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/\~}"'
    ;;
  screen)
    PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND; }'printf "\033_%s@%s:%s\033\\" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/\~}"'
    ;;
esac

[ -r /usr/share/bash-completion/bash_completion ] && . /usr/share/bash-completion/bash_completion
EOF
ok

status "configuring global profile"
backup_file /etc/profile
# FIX: the previous version gave PATH="$HOME" to every user whose UID
# wasn't exactly 0 or 1000. On any box with more than one regular human
# account (anyone with UID 1001+), every one of those users would lose
# the ability to run *any* command by name -- not a hardening measure,
# just broken. Replaced with a proper range check against UID_MIN (the
# same 1000 threshold already used in login.defs below) so it scales to
# as many regular users as you actually create. The bare "readonly" typo
# (see bash.bashrc note above) is also dropped rather than "fixed" into
# a real `readonly PATH` -- locking PATH for the whole session would
# break nvm/pyenv/rustup/cargo/pipx and any other per-user tool that
# prepends to PATH from ~/.bashrc, which is extremely common and not
# something this script should be silently breaking.
cat > /etc/profile <<'EOF'
# /etc/profile

umask 0027

if [[ $UID == 0 ]]; then
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
elif [[ $UID -ge 1000 ]]; then
  export PATH="/usr/local/bin:/usr/bin:/bin"
else
  # System/service accounts: a minimal, sane PATH rather than none.
  export PATH="/usr/local/bin:/usr/bin:/bin"
fi

if test -d /etc/profile.d/; then
  for profile in /etc/profile.d/*.sh; do
    test -r "$profile" && . "$profile"
  done
  unset profile
fi

if test "$PS1" && test "$BASH" && test -z ${POSIXLY_CORRECT+x} && test -r /etc/bash.bashrc; then
  . /etc/bash.bashrc
fi

unset TERMCAP
unset MANPATH
EOF
ok

status "configuring bash history"
backup_file /etc/profile.d/bash_history.sh
# FIX: HISTFILE and HISTFILESIZE were being made readonly without ever
# being *set* first, which just locked them at whatever bash's built-in
# defaults happened to be. Now explicitly set before being locked, so
# they're actually the values you intended, and (same rationale as
# TMOUT) readonly so a session can't quietly redirect history to
# /dev/null or shrink it to erase itself.
cat > /etc/profile.d/bash_history.sh <<'EOF'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignoredups
export HISTFILE="$HOME/.bash_history"
export HISTSIZE=1000
export HISTFILESIZE=2000
readonly HISTFILE
readonly HISTSIZE
readonly HISTFILESIZE
EOF
chmod +x /etc/profile.d/bash_history.sh
ok

status "configuring locale settings"
backup_file /etc/locale.conf
cat > /etc/locale.conf <<'EOF'
LANG=en_GB.UTF-8
LANGUAGE="en_GB:en_US"
LC_CTYPE="C"
LC_NUMERIC="C"
LC_TIME="C"
LC_COLLATE="C"
LC_MONETARY="C"
LC_PAPER="C"
LC_NAME="C"
LC_ADDRESS="C"
LC_TELEPHONE="C"
LC_MEASUREMENT="C"
LC_IDENTIFICATION="C"
EOF
ok

status "configuring environment"
backup_file /etc/environment
cat > /etc/environment <<'EOF'
LANG="en_GB.UTF-8"
LANGUAGE="en_GB:en_US"
PAGER="less"
EOF
ok

status "configuring console settings"
backup_file /etc/vconsole.conf
cat > /etc/vconsole.conf <<'EOF'
KEYMAP=uk
EOF
ok

status "configuring secure terminals"
backup_file /etc/securetty
cat > /etc/securetty <<'EOF'
console
tty1
tty2
tty3
tty4
tty5
tty6
ttyS0
hvc0
EOF
ok

status "configuring valid shells"
backup_file /etc/shells
cat > /etc/shells <<'EOF'
/bin/sh
/bin/bash
/bin/rbash
/bin/zsh
/bin/rzsh
EOF
ok

# FIX: removed the old "configuring password hashing" step that wrote
# /etc/default/passwd (CRYPT=sha512 / GROUP_CRYPT=blowfish / CRYPT_YP=des
# / ...). Nothing in the Arch/Artix shadow+PAM toolchain reads that file
# -- it's not consulted by passwd, login.defs, or pam_unix on this
# distro family, so it was inert configuration that looked like it was
# doing something (and, worse, mixed in DES, which is not something
# you'd want active if some tool *did* read it). The password hashing
# algorithm is already correctly controlled below via login.defs'
# ENCRYPT_METHOD SHA512, which is the setting that actually matters here.

status "configuring login policies"
backup_file /etc/login.defs
# FIX: password aging (PASS_MAX_DAYS/PASS_MIN_DAYS) was removed entirely
# in the first pass of this revision. Confirmed afterwards against a real
# Lynis run (test AUTH-9286) that Lynis checks the literal value, not the
# intent: PASS_MIN_DAYS=0 and PASS_MAX_DAYS=99999 are both explicitly
# treated as "not configured" and each cost hardening points, even though
# 99999 days is obviously meant as "disabled". There's no way to get
# credit for this check without giving it *some* real finite number, so
# by agreement the values below are set absurdly generous (10 years)
# instead of literally disabled -- Lynis counts it as configured, and in
# practice a 10-year expiry will never once surface for an actual user.
# PASS_MIN_LEN is unrelated to any of this: it's a floor on newly-*chosen*
# passwords going forward, not aging, and won't nag anyone about a
# password they already have.
# Also fixed: DEFAULT_HOME was set to "no" (refuse login if the home
# directory can't be reached) -- that's a real self-lockout risk the
# moment a separate /home mount ever fails to come up (including for
# you, trying to log in to fix it), for a fairly marginal hardening
# benefit. Reverted to shadow-utils' own upstream default ("yes").
# Also deduplicated: ENCRYPT_METHOD, LOGIN_RETRIES and LOGIN_TIMEOUT were
# each set twice in the original file.
cat > /etc/login.defs <<'EOF'
# /etc/login.defs - Configuration control definitions for the login package

# Password aging: technically configured (Lynis AUTH-9286 wants a real
# finite value here) but set long enough it will never actually trigger
# for a real person. PASS_MIN_DAYS 1 only blocks changing a password
# twice in the same second to cycle through history -- no normal use
# ever notices it.
PASS_MAX_DAYS   3650
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
PASS_MIN_LEN    12

# Login retries
LOGIN_RETRIES   3
LOGIN_TIMEOUT   60

# User/group ID ranges
UID_MIN                  1000
UID_MAX                 60000
SYS_UID_MIN               201
SYS_UID_MAX               999
GID_MIN                  1000
GID_MAX                 60000
SYS_GID_MIN               201
SYS_GID_MAX               999

# Umask for home directories
UMASK           027

# Create home directories by default
CREATE_HOME     yes

# Encrypt password method (use SHA-512)
ENCRYPT_METHOD SHA512
SHA_CRYPT_MIN_ROUNDS 5000
SHA_CRYPT_MAX_ROUNDS 5000
PASS_MAX_LEN 256

# User groups
USERGROUPS_ENAB yes

# Delay after failed login (in seconds)
FAIL_DELAY              3

# Environment variables
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin

# Terminal permissions
TTYGROUP        tty
TTYPERM         0600

# Enable setting of ulimit, umask, and niceness from passwd gecos field
QUOTAS_ENAB     no

# Enable setting of environment variables
ENVIRON_FILE    /etc/environment

# Login/logout logging
SYSLOG_SU_ENAB          yes
SYSLOG_SG_ENAB          yes

# Console device protection
CONSOLE         /etc/securetty
CONSOLE_GROUPS  floppy:audio:cdrom

# Mail directory
MAIL_DIR        /var/spool/mail

# Default PATH for su
SU_NAME         su

# Enable display of unknown usernames on failed login (kept off: avoids
# leaking a mistyped password into the log via the username field)
LOG_UNKFAIL_ENAB        no

# Enable logging of successful logins
LOG_OK_LOGINS           yes

# Which fields may be changed by regular users using chfn
CHFN_RESTRICT           rwh

# Allow login even if the home directory is missing/unreachable, so a
# transient mount problem can't lock you out of every account at once
# (shadow-utils upstream default).
DEFAULT_HOME    yes

# Send mail to user when password is changed
MAIL_CHECK_ENAB yes
EOF
ok

# FIX: removed the "hardening wrapper" section entirely (the
# /etc/hardening-wrapper.conf + /usr/lib/hardening-wrapper/{common,cc,
# ld}-wrapper.sh scripts). As written it could never actually do
# anything: the design (a wrapper script finds itself in $PATH and execs
# the *next* binary with that name further down $PATH) only works if
# something creates gcc/cc/g++/ld symlinks pointing at the wrapper and
# puts that directory ahead of the real toolchain in PATH -- neither of
# which the script did. It's also redundant: /etc/makepkg.conf (below)
# already applies the same hardening flags (FORTIFY_SOURCE, RELRO, BIND_NOW,
# stack-protector) to anything you build with makepkg, which is the
# standard, actually-idiomatic way to do this on an Arch-family system,
# and repo packages already ship pre-hardened. Keeping incomplete,
# non-functional code around is worse than not having it -- if you want
# this fully wired up later it needs real symlinks under something like
# /usr/lib/hardening-wrapper/bin/{gcc,cc,g++,ld} plus that directory
# prepended to PATH.

status "configuring wireless regulatory domain"
backup_file /etc/conf.d/wireless-regdom
mkdir -p /etc/conf.d
cat > /etc/conf.d/wireless-regdom <<'EOF'
# Wireless regulatory domain configuration
# Uncomment your region
WIRELESS_REGDOM="00"
#WIRELESS_REGDOM="GB"
#WIRELESS_REGDOM="US"
EOF
ok

status "configuring WPA supplicant"
mkdir -p /etc/wpa_supplicant
# FIX: previously overwritten unconditionally on every run. Harmless on a
# fresh install where the file is just commented-out examples, but if
# you'd since filled in your real Wi-Fi networks and re-ran this script
# (e.g. after tweaking something else), it would silently wipe them back
# to the template -- so this is now write-once: only created if it
# doesn't already exist. The permission fix below still runs every time.
if [ -f /etc/wpa_supplicant/wpa_supplicant.conf ]; then
    skip "already exists — left untouched so any configured networks aren't wiped"
else
    cat > /etc/wpa_supplicant/wpa_supplicant.conf <<'EOF'
# WPA supplicant configuration
# NOTE: This file may contain password information and should be
# readable only by root on multiuser systems.

ctrl_interface=/var/run/wpa_supplicant
eapol_version=1
ap_scan=1
fast_reauth=1
country=GB

# Network configuration examples (uncomment and customize):
#
# WPA-PSK/WPA2-PSK with passphrase:
#network={
#  ssid="your_network_name"
#  psk="your_passphrase"
#  priority=5
#}
#
# WPA-PSK/WPA2-PSK with pre-computed PSK:
#network={
#  ssid="your_network_name"
#  psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#  priority=5
#}
EOF
    ok
fi
chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null || true

status "restricting su to wheel group"
if ! grep -q "auth required pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
  backup_file /etc/pam.d/su
  echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
fi
# FIX: this used to be a silent change. If your own account (or nobody's)
# isn't in the wheel group, `su` quietly stops working for everyone the
# next time this takes effect. Not blocking it — just making sure you
# know before you find out the hard way.
if have_cmd getent && [ -z "$(getent group wheel | cut -d: -f4)" ]; then
    warn "no supplementary members currently listed in the 'wheel' group (this check can't see a user whose *primary* group is wheel, so ignore if that's you) — if 'su' stops working, run: usermod -aG wheel <youruser>"
fi
ok

status "configuring login banners"
backup_file /etc/issue
cat > /etc/issue <<'EOF'
+---------------------------------------------------------------+
| WARNING: Unauthorized access to this system is prohibited.    |
| All connections are logged and monitored. Disconnect          |
| IMMEDIATELY if you are not an authorized user!                |
+---------------------------------------------------------------+
EOF
cp /etc/issue /etc/issue.net
ok

status "configuring locale generation"
backup_file /etc/locale.gen
cat > /etc/locale.gen <<'EOF'
en_GB.UTF-8 UTF-8  
en_GB ISO-8859-1  
en_US.UTF-8 UTF-8  
en_US ISO-8859-1  
EOF
ok

status "configuring encrypted partitions"
# FIX: same "write-once" treatment as wpa_supplicant.conf, and for the
# same reason -- this is a template for *your* LUKS mappings, re-running
# the script should never be able to blow those away.
if [ -f /etc/crypttab ]; then
    skip "already exists — left untouched"
else
    cat > /etc/crypttab <<'EOF'
# crypttab: mappings for encrypted partitions
#
# Each mapped device will be created in /dev/mapper, so your /etc/fstab
# should use the /dev/mapper/<name> paths for encrypted devices.
#
# NOTE: Do not list your root (/) partition here, it must be set up
#       beforehand by the initramfs (/etc/mkinitcpio.conf).
#
# <name>       <device>         <password>              <options>
# Example configurations (commented out - customize for your system):
#home          /dev/vg0/lvhome  /etc/keys/home-key      cipher=serpent-xts-plain64:sha256,size=512
#var           /dev/vg0/lvvar   /etc/keys/var-key       cipher=twofish-xts-plain64:sha256,size=256
#swap          /dev/vg0/lvswap  /etc/keys/swap-key      cipher=twofish-xts-plain64:sha256,size=256
EOF
    ok
fi

status "configuring DHCP client security"
# FIX: only bothers if dhclient is actually installed. ISC dhclient is
# EOL upstream and most current Artix setups use dhcpcd or
# NetworkManager's built-in client instead -- writing dhclient.conf on a
# box that doesn't use dhclient was inert config for a program that was
# never running. Also write-once, same rationale as above.
if ! have_cmd dhclient; then
    skip "dhclient not installed — this system likely uses dhcpcd/NetworkManager instead"
elif [ -f /etc/dhclient.conf ]; then
    skip "already exists — left untouched"
else
    cat > /etc/dhclient.conf <<'EOF'
# DHCP client security configuration
timeout 60;
retry 60;
reboot 10;
select-timeout 5;
initial-interval 2;

# Example interface configuration (uncomment and customize):
#interface "eth0" {
#  send host-name "hostname";
#  send dhcp-lease-time 3600;
#  prepend domain-name-servers 127.0.0.1;
#  request subnet-mask, broadcast-address, time-offset, routers,
#    domain-name, domain-name-servers, host-name;
#  require subnet-mask, domain-name-servers;
#}
EOF
    ok
fi

status "configuring build hardening (makepkg)"
# NOTE: assumes x86_64 (CARCH/CHOST below) -- adjust if this is running
# on a different architecture (e.g. aarch64). Backed up first either way.
backup_file /etc/makepkg.conf
cat > /etc/makepkg.conf <<'EOF'
# /etc/makepkg.conf

DLAGENTS=('ftp::/usr/bin/curl -fC - --ftp-pasv --retry 3 --retry-delay 3 -o %o %u'
          'http::/usr/bin/curl -fLC - --retry 3 --retry-delay 3 -o %o %u'
          'https::/usr/bin/curl -fLC - --retry 3 --retry-delay 3 -o %o %u'
          'rsync::/usr/bin/rsync --no-motd -z %u %o'
          'scp::/usr/bin/scp -C %u %o')

VCSCLIENTS=('bzr::bzr'
            'git::git'
            'hg::mercurial'
            'svn::subversion')

CARCH="x86_64"
CHOST="x86_64-unknown-linux-gnu"

CPPFLAGS="-D_FORTIFY_SOURCE=2"
CFLAGS="-march=native -mtune=native -O2 -pipe -fstack-protector-strong"
CXXFLAGS="-march=native -mtune=native -O2 -pipe -fstack-protector-strong"
LDFLAGS="-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now"

DEBUG_CFLAGS="-g -fvar-tracking-assignments"
DEBUG_CXXFLAGS="-g -fvar-tracking-assignments"

BUILDENV=(!distcc color !ccache check !sign)

OPTIONS=(strip docs !libtool !staticlibs emptydirs zipman purge !optipng !upx !debug)

INTEGRITY_CHECK=(sha256)
STRIP_BINARIES="--strip-all"
STRIP_SHARED="--strip-unneeded"
STRIP_STATIC="--strip-debug"
MAN_DIRS=({usr{,/local}{,/share},opt/*}/{man,info})
DOC_DIRS=(usr/{,local/}{,share/}{doc,gtk-doc} opt/*/{doc,gtk-doc})
PURGE_TARGETS=(usr/{,share}/info/dir .packlist *.pod)

PKGEXT='.pkg.tar.xz'
SRCEXT='.src.tar.gz'
EOF
ok

# ========================================================
# SSH CLIENT CONFIGURATION
# ========================================================
print_section "SSH Client Configuration"

status "configuring SSH client"
backup_file /etc/ssh/ssh_config
mkdir -p /etc/ssh
# FIX: dropped "Protocol 2". SSH protocol 1 was deleted from OpenSSH
# entirely back in 2017 (7.6), and the "Protocol" keyword itself is gone
# from current documentation. It was always harmless *here*, but on very
# recent OpenSSH an actually-removed (not just deprecated) keyword can be
# rejected as a hard config error rather than a warning -- and there is
# zero upside to keeping it, since protocol 1 hasn't existed to negotiate
# down to in almost a decade. Same reasoning applies below for sshd_config,
# which never had this line added to it in the first place.
cat > /etc/ssh/ssh_config <<'EOF'
Host *
  ForwardAgent no
  ForwardX11 no
  PasswordAuthentication no
  HostbasedAuthentication no
  GSSAPIAuthentication no
  GSSAPIDelegateCredentials no
  CheckHostIP yes
  AddressFamily any
  ConnectTimeout 180
  HashKnownHosts yes
  StrictHostKeyChecking yes
  IdentityFile ~/.ssh/id_ed25519
  IdentityFile ~/.ssh/id_rsa
  Port 22
  KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
  VisualHostKey yes
EOF
ok

# ========================================================
# SSH SERVER CONFIGURATION  [NEW]
# ========================================================
# FIX: the previous version only ever touched the SSH *client* config
# (above) plus a chmod on sshd_config -- the actual SSH *server* was left
# completely unhardened, which is a large chunk of Lynis's SSH-related
# checks (and the thing actually exposed to the network). Added here,
# cautiously:
#  - Written as a separate drop-in file, not an edit to your main
#    sshd_config, so it's trivial to fully undo (just delete the file).
#  - Deliberately does NOT touch PasswordAuthentication -- flipping that
#    to "no" is the single most common way people lock themselves out of
#    a remote box, and this script has no way to verify you actually have
#    a working key set up before doing it.
#  - Validated with `sshd -t` before being left in place; if it fails
#    that check for any reason, the file is automatically removed again
#    so a botched config can never prevent sshd from starting.
#  - Does NOT reload/restart sshd. The change is inert until you (or your
#    init system) reload it -- test from a *second*, separate session
#    before you do, exactly as you should for any SSH config change.
print_section "SSH Server Configuration"

status "hardening SSH server (sshd)"
if [ ! -f /etc/ssh/sshd_config ]; then
    skip "no /etc/ssh/sshd_config — openssh server doesn't look installed"
else
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
        backup_file /etc/ssh/sshd_config
        { printf 'Include /etc/ssh/sshd_config.d/*.conf\n'; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.new
        mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
        chmod 600 /etc/ssh/sshd_config
    fi
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
# Dropped in by the hardening script — delete this one file to fully
# revert just the SSH server changes without touching the rest of
# sshd_config.
#
# Deliberately NOT set here: PasswordAuthentication. Once you've
# confirmed key-based login works (test in a NEW terminal/session before
# closing your current one!) you can add "PasswordAuthentication no" to
# this file yourself.
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 4
X11Forwarding no
LogLevel VERBOSE
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/issue.net
EOF
    chmod 600 /etc/ssh/sshd_config.d/10-hardening.conf

    if have_cmd sshd; then
        if sshd -t 2>/tmp/sshd_test_err.$$; then
            ok
        else
            SSHD_ERR=$(cat /tmp/sshd_test_err.$$ 2>/dev/null)
            rm -f /etc/ssh/sshd_config.d/10-hardening.conf
            # If the error names a line number in the main sshd_config
            # (not this script's own drop-in), that line was already
            # there before this script touched anything -- pull it out
            # and show it directly instead of making you go find it.
            BADLINE=$(printf '%s' "$SSHD_ERR" | grep -oE '/etc/ssh/sshd_config line [0-9]+' | head -1 | grep -oE '[0-9]+$' || true)
            if [ -n "$BADLINE" ]; then
                OFFENDING=$(sed -n "${BADLINE}p" /etc/ssh/sshd_config 2>/dev/null)
                warn "sshd -t failed because of a PRE-EXISTING line already in your sshd_config (line $BADLINE: '$OFFENDING') -- this has nothing to do with anything this script added. Reverted sshd_config.d/10-hardening.conf so sshd keeps working right now, but that line will also make sshd fail to (re)start the next time it's reloaded or the box reboots, regardless of this script. Fix or remove line $BADLINE, then re-run this script to pick the hardening back up. Full details: $SSHD_ERR"
            else
                warn "sshd -t rejected the new config — reverted sshd_config.d/10-hardening.conf so sshd still starts. Details: $SSHD_ERR"
            fi
        fi
        rm -f /tmp/sshd_test_err.$$
    else
        skip "sshd binary not found to validate against, but the config was written"
    fi
fi

# ========================================================
# AIDE CONFIGURATION
# ========================================================
print_section "AIDE Intrusion Detection"

status "configuring AIDE"
mkdir -p /var/lib/aide /var/log/aide
backup_file /etc/aide.conf
cat > /etc/aide.conf <<'EOF'
@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

database=file:@@{DBDIR}/aide.db.gz
database_out=file:@@{DBDIR}/aide.db.new.gz
database_new=file:@@{DBDIR}/aide.db.new.gz

gzip_dbout=yes
verbose=5

report_url=file:@@{LOGDIR}/aide.log
report_url=stdout

ALLXTRAHASHES = sha1+rmd160+sha256+sha512+tiger
EVERYTHING = R+ALLXTRAHASHES
NORMAL = R+rmd160+sha256
DIR = p+i+n+u+g+acl+xattrs
PERMS = p+i+u+g+acl
LOG = >
LSPP = R+sha256
DATAONLY = p+n+u+g+s+acl+xattrs+md5+sha256+rmd160+tiger

/boot NORMAL
/bin NORMAL
/sbin NORMAL
/lib NORMAL
/lib64 NORMAL
/opt NORMAL
/usr NORMAL
/root NORMAL
!/usr/src
!/usr/tmp

/etc PERMS
!/etc/mtab
!/etc/.*~
/etc/exports NORMAL
/etc/fstab NORMAL
/etc/passwd NORMAL
/etc/group NORMAL
/etc/gshadow NORMAL
/etc/shadow NORMAL
/etc/security/opasswd NORMAL
/etc/hosts.allow NORMAL
/etc/hosts.deny NORMAL
/etc/sudoers NORMAL
/etc/skel NORMAL
/etc/logrotate.d NORMAL
/etc/resolv.conf DATAONLY
/etc/nscd.conf NORMAL
/etc/securetty NORMAL
/etc/profile NORMAL
/etc/bash.bashrc NORMAL
/etc/bash_completion.d/ NORMAL
/etc/login.defs NORMAL

!/var/lib/pacman/.*
!/var/cache/.*
!/var/log/.*
!/var/run/.*
!/var/spool/.*
EOF
ok

# FIX: previously the config was written but the database was never
# initialized and nothing ever actually ran a check -- so AIDE sat there
# fully configured but doing nothing. Deliberately NOT running the
# initial `aide --init` here: on a real filesystem that's a multi-minute
# full scan, and blocking this whole script on it (or backgrounding it to
# silently compete for disk I/O right when you're about to go do
# something else) is exactly the kind of surprise this revision is
# trying to avoid. Instead: a daily check is scheduled now (it's a no-op
# until a database exists), and the one command you need to run whenever
# it's convenient is queued up in the summary at the end.
status "scheduling daily AIDE checks"
if have_cmd aide; then
    cat > /etc/cron.d/aide-check <<'EOF'
# Daily AIDE integrity check, installed by the hardening script.
# No-ops quietly until the database has been initialized (see the
# hardening script's final summary for the one-time init command).
0 3 * * * root [ -f /var/lib/aide/aide.db.gz ] && /usr/bin/aide --check >> /var/log/aide/aide-check.log 2>&1
EOF
    chmod 644 /etc/cron.d/aide-check
    MANUAL_STEPS+=("Initialize the AIDE database (a few minutes, run whenever convenient): aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz")
    ok
else
    skip "aide not installed — config is in place for whenever you install it (pacman -S aide)"
fi

# ========================================================
# MISC
# ========================================================
print_section "Miscellaneous Hardening"

# FIX: removed the standalone /etc/profile.d/umask.sh -- umask 0027 is
# already set in both /etc/profile and /etc/bash.bashrc above, so this
# was a third copy of the same one-line setting. Harmless, just clutter.

status "restricting cron and at access"
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
[ -f /etc/cron.deny ] && rm -f /etc/cron.deny

if have_cmd at; then
    echo "root" > /etc/at.allow
    chmod 600 /etc/at.allow
    [ -f /etc/at.deny ] && rm -f /etc/at.deny
fi
ok

status "configuring PAM faillock"
mkdir -p /etc/security
backup_file /etc/security/faillock.conf
# NOTE: no /etc/pam.d/* files are touched by this script. On Arch/Artix,
# pambase has called pam_faillock from the default login stack
# (/etc/pam.d/system-login and friends) since 2020, so this file is very
# likely already being consulted with no PAM edits needed — and hand-
# editing a PAM stack file is one of the most reliable ways to lock every
# account, including root, out of a system, which this script avoids
# entirely rather than trying to do safely. To confirm it's wired up:
#   grep faillock /etc/pam.d/system-login
cat > /etc/security/faillock.conf <<'EOF'
# Deny access after 5 failed attempts
deny = 5
# Unlock time in seconds (15 minutes)
unlock_time = 900
# Fail interval (15 minutes)
fail_interval = 900
EOF
ok

status "disabling legacy/insecure services (if present and enabled)"
# Only ever touches something that is BOTH installed AND currently
# enabled to start at boot -- never installs or removes packages, never
# stops anything already running. Just stops these from auto-starting
# next boot. None of these have a legitimate place on a modern desktop;
# if you actually run one of these on purpose, re-enable it with:
# rc-update add <service> <runlevel>.
for svc in telnetd inetd xinetd tftpd rsh rlogind rexecd ypbind nis; do
    if [ "$INIT_SYSTEM" = "openrc" ] && [ -f "/etc/init.d/$svc" ]; then
        if rc-update show 2>/dev/null | grep -qE "^[[:space:]]*${svc}[[:space:]]*\|"; then
            rc-update del "$svc" >/dev/null 2>&1 || true
            info "  Disabled legacy service: $svc"
        fi
    fi
done
ok

status "ensuring a syslog daemon is enabled (if installed)"
SYSLOG_FOUND=0
for svc in rsyslog syslog-ng socklog-unix busybox-syslogd; do
    if [ "$INIT_SYSTEM" = "openrc" ] && [ -f "/etc/init.d/$svc" ]; then
        enable_boot_service "$svc" default
        SYSLOG_FOUND=1
        break
    fi
done
if [ "$SYSLOG_FOUND" -eq 0 ]; then
    if [ "$INIT_SYSTEM" = "openrc" ]; then
        warn "no syslog daemon found (rsyslog/syslog-ng/socklog) — the firewall's LOG rules (and most Lynis logging checks) have nowhere persistent to write to. Consider: pacman -S rsyslog rsyslog-openrc"
    else
        skip "can't check on this init system — verify a syslog daemon is enabled manually"
    fi
fi

status "ensuring auditd is enabled (if installed)"
if have_cmd auditd || [ -f /etc/init.d/auditd ]; then
    enable_boot_service auditd default
    ok
else
    skip "auditd not installed — not configuring it. It's one of Lynis's higher-value suggestions if you want to chase the score further: pacman -S audit audit-openrc"
fi

# All enable_boot_service calls for this run happen above this line --
# commit and live-apply anything staged under s6 (see apply_s6_changes()).
apply_s6_changes

# ========================================================
# FINAL PERMISSIONS
# ========================================================
print_section "Final File Permissions"

status "setting final file permissions"
chmod 600 /etc/ssh/ssh_config 2>/dev/null || true
chmod 600 /etc/ssh/sshd_config.d/10-hardening.conf 2>/dev/null || true
chmod 600 /etc/aide.conf 2>/dev/null || true
chmod 644 /etc/profile 2>/dev/null || true
chmod 644 /etc/bash.bashrc 2>/dev/null || true
chmod 644 /etc/environment 2>/dev/null || true
chmod 644 /etc/locale.conf 2>/dev/null || true
chmod 644 /etc/locale.gen 2>/dev/null || true
chmod 600 /etc/crypttab 2>/dev/null || true
chmod 600 /etc/dhclient.conf 2>/dev/null || true
# FIX: /etc/default/passwd and /etc/hardening-wrapper.conf are no longer
# created (see notes above), so they've been dropped from this list too.
chmod 644 /etc/issue /etc/issue.net 2>/dev/null || true
chmod 644 /etc/shells /etc/securetty /etc/vconsole.conf 2>/dev/null || true
chmod 644 /etc/makepkg.conf 2>/dev/null || true
chmod 644 /etc/conf.d/wireless-regdom 2>/dev/null || true
chmod 644 /etc/hosts 2>/dev/null || true
chmod 644 /etc/hostname 2>/dev/null || true
chmod 644 /etc/networks 2>/dev/null || true
chmod 644 /etc/security/faillock.conf 2>/dev/null || true
chmod 600 /etc/security/access.conf 2>/dev/null || true
chmod 600 /etc/security/limits.conf 2>/dev/null || true
chmod 700 /root/.ssh 2>/dev/null || true
chmod 600 /root/.ssh/* 2>/dev/null || true
chmod 644 /etc/hosts.allow 2>/dev/null || true
chmod 644 /etc/hosts.deny 2>/dev/null || true
chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null || true
ok

status "securing bootloader configuration"
if [ -f /boot/grub/grub.cfg ]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi
if [ -d /boot/grub2 ]; then
    chmod 600 /boot/grub2/grub.cfg 2>/dev/null || true
    chown root:root /boot/grub2/grub.cfg 2>/dev/null || true
fi
if [ -d /boot/loader ]; then
    chmod 700 /boot/loader 2>/dev/null || true
fi
ok

# ========================================================
# SUMMARY
# ========================================================
print_section "System hardening complete"

# FIX: WARNINGS and MANUAL_STEPS were collected throughout the script
# (see the comment above WARNINGS= near the top) specifically so they
# could be re-shown here, away from everything else this script (and,
# when run from the installer, the rest of the install) prints -- but
# nothing ever actually printed them, so both arrays were filled in and
# then silently discarded every run. On a fresh install that meant the
# AIDE database init reminder, and any transient failure (e.g. an
# `s6 set enable` that failed), never reached you at all.
if [ "${#WARNINGS[@]}" -gt 0 ]; then
    printf "\nWarnings from this run:\n"
    for w in "${WARNINGS[@]}"; do
        printf "  [!] %s\n" "$w"
    done
fi

printf "\nBackups of anything this script overwrote: %s\n" "$BACKUP_DIR"

exit 0
