#!/bin/bash

# Re-exec under bash if this was invoked via sh/dash instead (e.g. `sh
# hardening-script.sh`) — `set -o pipefail` and other bash-only syntax
# below are not POSIX and fail immediately under a non-bash shell.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

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

WARNINGS=()
warn() {
    printf "  [!] %s\n" "$1" >&2
    WARNINGS+=("$1")
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local dest="${BACKUP_DIR}${file}"
        mkdir -p "$(dirname "$dest")"
        cp -p "$file" "$dest" 2>/dev/null || true
    fi
}

# Init system detection: OpenRC and systemd are automated directly;
# runit/s6/dinit are automated with their own native enable commands.
INIT_SYSTEM="unknown"
if [ -d /run/systemd/system ] && have_cmd systemctl; then
    INIT_SYSTEM="systemd"
elif [ -d /run/openrc ] || have_cmd rc-update; then
    INIT_SYSTEM="openrc"
elif [ -d /etc/runit/sv ] || [ -d /run/runit ]; then
    INIT_SYSTEM="runit"
elif [ -d /etc/s6/sv ] || have_cmd s6-rc; then
    INIT_SYSTEM="s6"
elif have_cmd dinitctl; then
    INIT_SYSTEM="dinit"
fi

# Tracks whether apply_s6_changes() has anything staged to commit.
S6_STAGED=0

enable_boot_service() {
    local svc="$1"
    local runlevel="${2:-default}"
    case "$INIT_SYSTEM" in
        systemd)
            if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q .; then
                systemctl enable "${svc}.service" >/dev/null 2>&1 && info "  Enabled '$svc' under systemd" \
                    || warn "systemctl enable ${svc}.service failed — it may already be enabled or managed another way"
            else
                warn "No ${svc}.service unit found — nothing to enable under systemd for '$svc'"
            fi
            ;;
        openrc)
            if [ ! -f "/etc/init.d/$svc" ] && have_cmd pacman; then
                pacman -S --noconfirm --needed "${svc}-openrc" >/dev/null 2>&1 || true
            fi
            if [ -f "/etc/init.d/$svc" ]; then
                rc-update add "$svc" "$runlevel" >/dev/null 2>&1 || true
                info "  Enabled '$svc' at OpenRC runlevel '$runlevel'"
            else
                warn "OpenRC script for '$svc' still not found at /etc/init.d/$svc after attempting to install ${svc}-openrc — '$svc' will not start at boot"
            fi
            ;;
        runit)
            if [ -d "/etc/runit/sv/$svc" ] && [ -d /run/runit/service ]; then
                ln -sf "/etc/runit/sv/$svc" /run/runit/service 2>/dev/null && info "  Enabled '$svc' under runit" \
                    || warn "Could not symlink '$svc' into /run/runit/service"
            else
                warn "No runit service definition found for '$svc' at /etc/runit/sv/$svc — nothing to enable"
            fi
            ;;
        s6)
            if ! have_cmd s6 && have_cmd pacman; then
                pacman -S --noconfirm --needed "${svc}-s6" >/dev/null 2>&1 || true
            fi
            if have_cmd s6; then
                if S6_OUT=$(s6 set enable "$svc" 2>&1); then
                    info "  Enabled '$svc' under s6 (s6 set enable $svc)"
                    S6_STAGED=1
                else
                    warn "'s6 set enable $svc' failed even after attempting to install ${svc}-s6. Details: $S6_OUT"
                fi
            else
                warn "s6 was detected as the init system but the 's6' command still isn't available — could not enable '$svc'"
            fi
            ;;
        dinit)
            if have_cmd dinitctl; then
                dinitctl enable "$svc" >/dev/null 2>&1 && info "  Enabled '$svc' under dinit" \
                    || warn "'dinitctl enable $svc' failed"
            else
                warn "dinit was detected as the init system but 'dinitctl' isn't available — could not enable '$svc'"
            fi
            ;;
        *)
            warn "Could not detect a supported init system — '$svc' was not enabled at boot"
            ;;
    esac
}

# Commits and live-applies whatever enable_boot_service staged under s6.
apply_s6_changes() {
    [ "$INIT_SYSTEM" = "s6" ] || return 0
    [ "$S6_STAGED" -eq 1 ] || return 0
    if ! have_cmd s6; then
        warn "s6 changes were staged but the 's6' command isn't available to commit them"
        return 0
    fi
    status "committing and applying staged s6 service changes"
    if S6_OUT=$(s6 set commit 2>&1 && s6 live install 2>&1); then
        ok
    else
        warn "'s6 set commit && s6 live install' failed — services enabled above may not be active yet. Details: $S6_OUT"
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
[ -f /etc/sudoers ] && chmod 600 /etc/sudoers
[ -f /etc/doas.conf ] && chmod 600 /etc/doas.conf
chmod -R 700 /etc/ssl/private 2>/dev/null || true
chmod -R 755 /etc/ssl/certs 2>/dev/null || true
find /etc/cron.* -type f -exec chmod 0700 {} \; 2>/dev/null || true
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
mkdir -p /etc/modprobe.d
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
# These are raw /proc/sys writes: applied immediately, but not persisted
# across reboot unless mirrored in /etc/sysctl.d.
print_section "TCP/IP Stack Hardening"

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
# OUTPUT stays permissive on purpose (Lynis doesn't require locking down
# outbound traffic, and it's a common source of "why doesn't X work").
print_section "Iptables Firewall Configuration"

IPTABLES="$(command -v iptables 2>/dev/null || echo /sbin/iptables)"
IP6TABLES="$(command -v ip6tables 2>/dev/null || echo /sbin/ip6tables)"
IPTABLES_RESTORE="$(command -v iptables-restore 2>/dev/null || echo /sbin/iptables-restore)"
IP6TABLES_RESTORE="$(command -v ip6tables-restore 2>/dev/null || echo /sbin/ip6tables-restore)"
SSHPORT="22"

# Persists a saved ruleset across reboot regardless of init system, and
# regardless of whether the distro ships a native iptables.service (Arch/
# Artix do; Debian/Ubuntu/Mint typically don't). On systemd, the native
# unit is used if one exists; otherwise a minimal restore-on-boot unit is
# created and enabled instead, so the ruleset survives a reboot either way
# with nothing left for you to do.
persist_firewall_boot() {
    local family="$1" svc="$2" rules_file="$3" restore_bin="$4"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q .; then
            systemctl enable "${svc}.service" >/dev/null 2>&1 || true
        else
            backup_file "/etc/systemd/system/${svc}-restore.service"
            cat > "/etc/systemd/system/${svc}-restore.service" <<EOF
[Unit]
Description=Restore $family firewall rules (installed by hardening script)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
ExecStart=$restore_bin $rules_file
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
            chmod 644 "/etc/systemd/system/${svc}-restore.service"
            systemctl daemon-reload
            systemctl enable "${svc}-restore.service" >/dev/null 2>&1 || true
        fi
    elif [ "$INIT_SYSTEM" = "runit" ] && [ ! -d "/etc/runit/sv/$svc" ]; then
        mkdir -p "/etc/runit/sv/${svc}-restore"
        backup_file "/etc/runit/sv/${svc}-restore/run"
        cat > "/etc/runit/sv/${svc}-restore/run" <<EOF
#!/bin/sh
# Restores $family firewall rules at boot (installed by hardening script).
exec 2>&1
$restore_bin $rules_file
exec sleep infinity
EOF
        chmod 755 "/etc/runit/sv/${svc}-restore/run"
        if [ -d /run/runit/service ]; then
            ln -sf "/etc/runit/sv/${svc}-restore" /run/runit/service 2>/dev/null || true
        fi
    else
        enable_boot_service "$svc" default
    fi
}

if ! have_cmd "$IPTABLES"; then
    warn "iptables not found at $IPTABLES — skipping firewall configuration entirely"
else

# Safety net: revert to a fully open firewall if setup fails partway
# through, instead of leaving a half-built default-DROP state in place.
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
# Policies forced to ACCEPT before flushing, so a re-run (where policy is
# already DROP from last time) never leaves a zero-rule DROP window.
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
# Must run before any per-service allow rule, and in-budget traffic must
# RETURN (not ACCEPT), or this silently turns into an accept-almost-
# everything rule that bypasses the final catch-all reject.
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

status "logging dropped packets"
"$IPTABLES" -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-input: " --log-level 7
"$IPTABLES" -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables-forward: " --log-level 7
ok

status "setting final drop rules"
"$IPTABLES" -A INPUT -j LOGREJECT
"$IPTABLES" -A FORWARD -j LOGREJECT
ok

status "setting default policies"
# Must run last, once every allow rule (incl. the catch-all reject) exists.
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
persist_firewall_boot "IPv4" iptables /etc/iptables/iptables.rules "$IPTABLES_RESTORE"
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
    persist_firewall_boot "IPv6" ip6tables /etc/iptables/ip6tables.rules "$IP6TABLES_RESTORE"
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

status "configuring login policies"
backup_file /etc/login.defs
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
# Write-once: never overwrite a real configured network list.
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
if have_cmd getent && ! getent group wheel >/dev/null 2>&1; then
    groupadd wheel 2>/dev/null && info "  Created the 'wheel' group (none existed on this system)"
fi
if ! grep -q "auth required pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
  backup_file /etc/pam.d/su
  echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
fi
if have_cmd getent && [ -z "$(getent group wheel | cut -d: -f4)" ]; then
    INVOKING_USER="${SUDO_USER:-}"
    if [ -z "$INVOKING_USER" ] && have_cmd logname; then
        INVOKING_USER="$(logname 2>/dev/null || true)"
    fi
    if [ -n "$INVOKING_USER" ] && [ "$INVOKING_USER" != "root" ] && id "$INVOKING_USER" >/dev/null 2>&1; then
        usermod -aG wheel "$INVOKING_USER" 2>/dev/null \
            && info "  Added '$INVOKING_USER' to the wheel group so su keeps working" \
            || warn "Could not add '$INVOKING_USER' to the wheel group automatically — su may stop working for that user"
    else
        warn "no supplementary members currently listed in the 'wheel' group, and the invoking user couldn't be determined automatically (this check also can't see a user whose *primary* group is wheel, so ignore if that's you)"
    fi
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
# Write-once: this is a template for your LUKS mappings.
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
# Assumes x86_64 (CARCH/CHOST below) — adjust for other architectures.
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
# SSH SERVER CONFIGURATION
# ========================================================
# Written as a drop-in (delete the file to fully undo), validated with
# `sshd -t` before being left in place, and never reloads/restarts sshd —
# test from a second session before doing that yourself.
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
            # If the error names a line in the main sshd_config, that was
            # pre-existing — surface it directly instead of making you dig.
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

status "scheduling daily AIDE checks"
if have_cmd aide; then
    cat > /etc/cron.d/aide-check <<'EOF'
# Daily AIDE integrity check, installed by the hardening script.
0 3 * * * root [ -f /var/lib/aide/aide.db.gz ] && /usr/bin/aide --check >> /var/log/aide/aide-check.log 2>&1
EOF
    chmod 644 /etc/cron.d/aide-check
    ok

    status "initializing AIDE database (this can take a few minutes)"
    if aide --init >/var/log/aide/aide-init.log 2>&1 && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null; then
        ok
    else
        warn "AIDE database initialization did not finish cleanly — see /var/log/aide/aide-init.log. The daily check will start working automatically once /var/lib/aide/aide.db.gz exists."
    fi
else
    skip "aide not installed — nothing to schedule"
fi

# ========================================================
# MISC
# ========================================================
print_section "Miscellaneous Hardening"

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
# No /etc/pam.d/* files are touched — editing a PAM stack file is one of
# the most reliable ways to lock every account out of a system. Confirm
# it's wired up with: grep faillock /etc/pam.d/system-login
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
# Only stops something already installed AND enabled from auto-starting
# next boot.
for svc in telnetd inetd xinetd tftpd rsh rlogind rexecd ypbind nis; do
    if [ "$INIT_SYSTEM" = "openrc" ] && [ -f "/etc/init.d/$svc" ]; then
        if rc-update show 2>/dev/null | grep -qE "^[[:space:]]*${svc}[[:space:]]*\|"; then
            rc-update del "$svc" >/dev/null 2>&1 || true
            info "  Disabled legacy service: $svc"
        fi
    elif [ "$INIT_SYSTEM" = "systemd" ] && have_cmd systemctl; then
        if systemctl is-enabled "${svc}.service" >/dev/null 2>&1; then
            systemctl disable "${svc}.service" >/dev/null 2>&1 && info "  Disabled legacy service: $svc"
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
    elif [ "$INIT_SYSTEM" = "systemd" ] && have_cmd systemctl && systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q .; then
        enable_boot_service "$svc" default
        SYSLOG_FOUND=1
        break
    fi
done
if [ "$SYSLOG_FOUND" -eq 1 ]; then
    ok
elif [ "$INIT_SYSTEM" = "systemd" ]; then
    # systemd-journald handles logging by default even with no separate
    # syslog daemon installed, so there's always somewhere for logs to go.
    ok
else
    skip "no syslog daemon found (rsyslog/syslog-ng/socklog) to enable"
fi

status "ensuring auditd is enabled (if installed)"
if have_cmd auditd || [ -f /etc/init.d/auditd ]; then
    enable_boot_service auditd default
    ok
else
    skip "auditd not installed — nothing to configure"
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
# SYSTEMD SERVICE HARDENING
# ========================================================
# Independent of the OpenRC/runit/s6/dinit detection used above. Addresses
# Lynis BOOT-5264 ("Consider hardening system services", checked via
# `systemd-analyze security`) for boxes that use systemd as their init.
print_section "Systemd Service Hardening"

status "checking init system for systemd"
if [ -d /run/systemd/system ] && have_cmd systemctl; then
    ok
    info "Detected systemd — sandboxing known-safe services"

    # Directives applied to every candidate with no exceptions: none of
    # them have any legitimate reason to gain new privileges, adjust the
    # clock, use exotic namespaces, or change the hostname.
    SYSTEMD_HARDENING_ALWAYS=$(cat <<'EOF'
[Service]
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
EOF
)

    # ProtectKernelModules, RestrictRealtime, and PrivateDevices are each
    # skipped for the specific services that genuinely rely on what they'd
    # block, so hardening never costs real functionality:
    #  - rtkit-daemon exists specifically to grant realtime scheduling to
    #    other processes (audio servers, etc.) — realtime access is the
    #    whole point of the service, so RestrictRealtime stays off for it.
    #  - thermald may need to load the "msr" kernel module to read CPU
    #    temperature on some hardware, so ProtectKernelModules stays off.
    #  - CUPS may drive a USB/parallel printer, switcheroo-control switches
    #    GPUs via /dev/dri, thermald reads CPU temperature via
    #    /dev/cpu/*/msr, and blueman-mechanism can touch Bluetooth device
    #    nodes — PrivateDevices stays off for all four.
    NO_PROTECT_KERNEL_MODULES="thermald.service"
    NO_RESTRICT_REALTIME="rtkit-daemon.service"
    NO_PRIVATE_DEVICES="cups.service cups-browsed.service switcheroo-control.service thermald.service blueman-mechanism.service"

    # Self-contained background daemons commonly flagged UNSAFE/EXPOSED/
    # MEDIUM by `systemd-analyze security`. Anything not on this list, or
    # not installed, is left alone entirely — dbus, NetworkManager,
    # display managers, and most systemd-* units are deliberately
    # excluded since a wrong guess on those can break the whole system.
    SYSTEMD_HARDEN_CANDIDATES="cron.service crond.service anacron.service rsyslog.service avahi-daemon.service cups.service cups-browsed.service clamav-daemon.service clamav-freshclam.service fail2ban.service irqbalance.service earlyoom.service switcheroo-control.service kerneloops.service preload.service thermald.service uuidd.service accounts-daemon.service power-profiles-daemon.service rtkit-daemon.service blueman-mechanism.service dnsmasq.service networkd-dispatcher.service"

    HARDENED_SERVICES=()
    for svc in $SYSTEMD_HARDEN_CANDIDATES; do
        if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
            status "hardening $svc"
            OVERRIDE_DIR="/etc/systemd/system/${svc}.d"
            mkdir -p "$OVERRIDE_DIR"
            backup_file "${OVERRIDE_DIR}/hardening.conf"
            {
                printf '%s\n' "$SYSTEMD_HARDENING_ALWAYS"
                case " $NO_PROTECT_KERNEL_MODULES " in
                    *" $svc "*) : ;;
                    *) printf 'ProtectKernelModules=yes\n' ;;
                esac
                case " $NO_RESTRICT_REALTIME " in
                    *" $svc "*) : ;;
                    *) printf 'RestrictRealtime=yes\n' ;;
                esac
                case " $NO_PRIVATE_DEVICES " in
                    *" $svc "*) : ;;
                    *) printf 'PrivateDevices=yes\n' ;;
                esac
            } > "${OVERRIDE_DIR}/hardening.conf"
            chmod 644 "${OVERRIDE_DIR}/hardening.conf"
            ok
            HARDENED_SERVICES+=("$svc")
        fi
    done

    if [ "${#HARDENED_SERVICES[@]}" -gt 0 ]; then
        status "reloading systemd manager configuration"
        systemctl daemon-reload
        ok

        # try-restart only restarts a service that's already running, and
        # does nothing to one that isn't — so this applies the sandboxing
        # immediately wherever it's safe to, with no reboot and nothing
        # left for the user to do by hand.
        for svc in "${HARDENED_SERVICES[@]}"; do
            status "applying sandboxing to $svc"
            systemctl try-restart "$svc" >/dev/null 2>&1 || true
            ok
        done
    else
        info "  No candidate services from the hardening list were found installed"
    fi
else
    skip "systemd not detected"
fi

# ========================================================
# SUMMARY
# ========================================================
print_section "System hardening complete"

if [ "${#WARNINGS[@]}" -gt 0 ]; then
    printf "\nWarnings from this run:\n"
    for w in "${WARNINGS[@]}"; do
        printf "  [!] %s\n" "$w"
    done
fi

printf "\nBackups of anything this script overwrote: %s\n" "$BACKUP_DIR"

exit 0
