#!/bin/bash
# Usage: hardening.sh [--revert]
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
[ "$(id -u)" -eq 0 ] || { echo "FAIL  run as root" >&2; exit 1; }
set -uo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

SSH_PORT=""                 # empty keeps the port sshd already listens on
SSH_FROM=any                # any | lan | none
SSH_PASSWORDS=auto          # auto: off once a user has authorized_keys | yes | no
IPV6=block                  # block | allow
LAN_NETS=""                 # e.g. "192.168.1.0/24 fd00:1::/64"; LAN_* ports open only to these
LAN_TCP="27036:27037"       # Steam Remote Play
LAN_UDP="27031:27036 5353"  # Steam Remote Play, mDNS
PUBLIC_TCP=""               # open to any source, e.g. "6881:6889 27015"
PUBLIC_UDP=""
DNS_LOCK=auto               # auto: on when dnscrypt-proxy runs and resolv.conf is loopback-only | yes | no
MDNS_PUBLISH=no             # no: avahi browses but stops announcing this host
YESCRYPT_COST=8             # 128 MiB per hash
TMOUT_SECONDS=1800
STATE=/var/lib/hardening

NPASS=0 NFAIL=0
pass() { printf 'PASS  %s\n' "$*"; NPASS=$((NPASS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; NFAIL=$((NFAIL + 1)); }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf '      %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

save() {
    local f
    for f; do
        [ -e "$STATE/orig$f" ] || [ -e "$STATE/new$f" ] && continue
        if [ -e "$f" ] || [ -L "$f" ]; then
            mkdir -p "$STATE/orig${f%/*}" && cp -a "$f" "$STATE/orig$f"
        else
            mkdir -p "$STATE/new${f%/*}" && : > "$STATE/new$f"
        fi
    done
}

put() {
    local mode=$1 f=$2 tmp
    tmp=$(mktemp) || return 1
    cat > "$tmp"
    if [ -f "$f" ] && cmp -s "$tmp" "$f"; then
        rm -f "$tmp"; chmod "$mode" "$f"; return 0
    fi
    save "$f"
    [ -d "${f%/*}" ] || { mkdir -p "${f%/*}" && printf '%s\n' "${f%/*}" >> "$STATE/newdirs"; }
    install -m "$mode" "$tmp" "$f"
    local rc=$?
    rm -f "$tmp"
    return $rc
}

edit() {
    local f=$1; shift
    save "$f"
    sed -i "$@" "$f"
}

set_mode() {
    local m=$1 p; shift
    for p; do
        [ -e "$p" ] || continue
        awk -F'\t' -v p="$p" '$2 == p { f = 1 } END { exit !f }' "$STATE/modes" 2>/dev/null ||
            printf '%s\t%s\n' "$(stat -c %a "$p")" "$p" >> "$STATE/modes"
        chmod "$m" "$p"
    done
}

set_def() {
    local f=$1 k=$2 v=$3
    if grep -Eq "^[[:space:]]*${k}[[:space:]]" "$f"; then
        grep -Eq "^${k}[[:space:]]+$v\$" "$f" || edit "$f" -E "s|^[[:space:]]*${k}[[:space:]].*|$k\t$v|"
    else
        save "$f"; printf '%s\t%s\n' "$k" "$v" >> "$f"
    fi
}

set_kv() {
    local f=$1 k=$2 v=$3
    if grep -Eq "^[[:space:]]*${k}[[:space:]]*=" "$f"; then
        grep -Eq "^$k = $v\$" "$f" || edit "$f" -E "s|^[[:space:]]*${k}[[:space:]]*=.*|$k = $v|"
    else
        save "$f"; printf '%s = %s\n' "$k" "$v" >> "$f"
    fi
}

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "${1%%-*}" | sort -V | head -1)" = "$2" ]; }

IN_CHROOT=0
[ "$(stat -Lc %d:%i / 2>/dev/null)" = "$(stat -Lc %d:%i /proc/1/root/ 2>/dev/null)" ] || IN_CHROOT=1

INIT=unknown
if [ "$IN_CHROOT" = 0 ]; then
    case "$(cat /proc/1/comm 2>/dev/null)" in
        systemd) INIT=systemd ;;
        openrc-init) INIT=openrc ;;
        runit|runit-init) INIT=runit ;;
        s6-svscan) INIT=s6 ;;
        dinit) INIT=dinit ;;
    esac
fi
if [ "$INIT" = unknown ]; then
    if [ -x /usr/lib/systemd/systemd ] || [ -x /lib/systemd/systemd ]; then INIT=systemd
    elif have openrc || have rc-update; then INIT=openrc
    elif have s6-svscan && { [ -d /etc/s6 ] || have s6-rc; }; then INIT=s6
    elif have runsvdir; then INIT=runit
    elif have dinit; then INIT=dinit
    fi
fi

ADMIN=${DOAS_USER:-${SUDO_USER:-}}
[ -n "$ADMIN" ] || ADMIN=$(logname 2>/dev/null) || true
if [ -z "$ADMIN" ] && [ -r /proc/self/loginuid ]; then
    lu=$(cat /proc/self/loginuid)
    [ "$lu" != 4294967295 ] && ADMIN=$(id -nu "$lu" 2>/dev/null || true)
fi
[ "$ADMIN" = root ] && ADMIN=""

SSHD=$(command -v sshd || echo /usr/sbin/sshd)

S6_STAGED=0
pac_try() { have pacman && pacman -S --needed --noconfirm "$1" >/dev/null 2>&1; }

enable_service() {
    local s=$1 p=$1 sv dst
    case $s in auditd) p=audit ;; ip6tables) p=iptables ;; esac
    case $INIT in
        systemd)
            systemctl enable "$s.service" >/dev/null 2>&1 ;;
        openrc)
            [ -f "/etc/init.d/$s" ] || pac_try "$p-openrc"
            [ -f "/etc/init.d/$s" ] || return 1
            rc-update add "$s" default >/dev/null 2>&1
            return 0 ;;
        runit)
            sv=/etc/runit/sv; [ -d "$sv" ] || sv=/etc/sv
            [ -d "$sv/$s" ] || pac_try "$p-runit"
            [ -d "$sv/$s" ] || return 1
            for dst in /run/runit/service /var/service /etc/runit/runsvdir/default; do
                [ -d "$dst" ] && { ln -sfn "$sv/$s" "$dst/$s"; return; }
            done
            return 1 ;;
        s6)
            have s6 || return 1
            s6 set enable "$s" >/dev/null 2>&1 || { pac_try "$p-s6" && s6 set enable "$s" >/dev/null 2>&1; } || return 1
            S6_STAGED=1 ;;
        dinit)
            [ -f "/etc/dinit.d/$s" ] || pac_try "$p-dinit"
            [ -f "/etc/dinit.d/$s" ] || return 1
            dinitctl enable "$s" >/dev/null 2>&1 || { mkdir -p /etc/dinit.d/boot.d && ln -sf "/etc/dinit.d/$s" /etc/dinit.d/boot.d/; } ;;
        *) return 1 ;;
    esac
}

s6_commit() {
    [ "$INIT" = s6 ] && [ "$S6_STAGED" = 1 ] || return 0
    if s6 set commit >/dev/null 2>&1; then
        pass "s6: service changes committed"
        s6 live install >/dev/null 2>&1 || info "s6: live install failed, changes apply at next boot"
    else
        fail "s6: 's6 set commit' failed, enabled services will not start at boot"
    fi
}

sshd_check() {
    local tmp="" out rc
    local -a k=()
    if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
        tmp=$(mktemp -d) && ssh-keygen -q -t ed25519 -N '' -f "$tmp/k" >/dev/null 2>&1 && k=(-h "$tmp/k")
    fi
    out=$("$SSHD" "$@" ${k[@]+"${k[@]}"} 2>&1); rc=$?
    case $out in
        *"Missing privilege separation directory: "*)
            out=${out##*directory: }
            mkdir -p "${out%%[[:space:]]*}"
            out=$("$SSHD" "$@" ${k[@]+"${k[@]}"} 2>&1); rc=$? ;;
    esac
    [ -n "$tmp" ] && rm -rf "$tmp"
    printf '%s\n' "$out"
    return $rc
}

yescrypt_ok() {
    grep -q '^[^:]*:\$y\$' /etc/shadow 2>/dev/null && return 0
    have perl && perl -e 'my $h = crypt("x", q($y$j9T$KcY5dS0bTG4I1RP2rHBaX.)); exit(defined $h && $h =~ /^\$y\$/ ? 0 : 1)'
}

pristine() {
    local f=$1 bad=$2 d pkg ver c tmp
    if [ -f "$f.pacnew" ]; then echo "$f.pacnew"; return; fi
    if have pacman && have bsdtar && pkg=$(pacman -Qqo "$f" 2>/dev/null); then
        ver=$(pacman -Q "$pkg" | awk '{print $2}')
        for c in /var/cache/pacman/pkg/"$pkg-$ver"-*.pkg.tar.*; do
            case $c in *.sig) continue ;; esac
            [ -f "$c" ] || continue
            tmp=$(mktemp)
            if bsdtar -xOf "$c" "${f#/}" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then echo "$tmp"; return; fi
            rm -f "$tmp"
        done
    fi
    for d in /root/hardening-backups-*/; do
        [ -f "$d${f#/}" ] || continue
        [ "$(sha256sum < "$d${f#/}" | cut -c1-16)" = "$bad" ] && continue
        echo "$d${f#/}"; return
    done
    return 1
}

legacy_repair() {
    local ev=0 e f h src
    ls -d /root/hardening-backups-*/ >/dev/null 2>&1 && ev=1
    grep -qs '^install squashfs /bin/true$' /etc/modprobe.d/uncommon-filesystems.conf && ev=1
    [ "$ev" = 1 ] || return 0
    for e in /etc/profile:4bcb10381b732ff2 /etc/bash.bashrc:0725202b30e1f923 /etc/shells:cebbd16e1135550a \
             /etc/login.defs:aadde12cc06385c5 /etc/ssh/ssh_config:0e89333e4bd82cb6 /etc/makepkg.conf:f92355fae445b46a \
             /etc/host.conf:18391637e7a31586 /etc/locale.gen:433c51fe92a94ce4 /etc/locale.conf:3665a41fa8e3f8fd \
             /etc/environment:3405a141d908ea12 /etc/vconsole.conf:733dd6663595cc62 /etc/conf.d/wireless-regdom:3c98edd20d55fb43 \
             /etc/aide.conf:d70b34ef5c4a7417 /etc/security/faillock.conf:e3b2224b885b35ac; do
        f=${e%%:*} h=${e#*:}
        [ -f "$f" ] && [ "$(sha256sum < "$f" | cut -c1-16)" = "$h" ] || continue
        if src=$(pristine "$f" "$h"); then
            cp "$src" "$f" && pass "legacy: restored $f from $src"
            case $src in /tmp/*) rm -f "$src" ;; *.pacnew) rm -f "$src" ;; esac
        else
            case $f in /etc/locale.*|/etc/environment|/etc/vconsole.conf|/etc/conf.d/*|/etc/host.conf)
                info "legacy: $f still holds the old script's content (no pristine copy found)" ;;
            *)  fail "legacy: $f still holds the old script's content and no pristine copy was found" ;;
            esac
        fi
    done
    for e in /etc/profile.d/bash_history.sh:6af75c770b18d579 /etc/cron.d/aide-check:f11ed3798a047dfa \
             /etc/ssh/sshd_config.d/10-hardening.conf:7726c5006c3f4c14 /etc/modprobe.d/uncommon-filesystems.conf:a18e55c7b7c9ad79 \
             /etc/modprobe.d/uncommon-net-protocols.conf:8eb7e1b76422a273 /etc/modprobe.d/blacklist-firewire.conf:9ea2fe8930583000; do
        f=${e%%:*} h=${e#*:}
        [ -f "$f" ] && [ "$(sha256sum < "$f" | cut -c1-16)" = "$h" ] && rm -f "$f" && pass "legacy: removed $f"
    done
    local -a units=()
    for f in /etc/systemd/system/*.service.d/hardening.conf; do
        [ -f "$f" ] && grep -q '^MemoryDenyWriteExecute=yes' "$f" && grep -q '^RemoveIPC=yes' "$f" || continue
        rm -f "$f"; rmdir "${f%/*}" 2>/dev/null
        f=${f#/etc/systemd/system/}; units+=("${f%.d/hardening.conf}")
    done
    if [ "${#units[@]}" -gt 0 ]; then
        pass "legacy: removed blanket sandbox overrides from ${units[*]}"
        if [ "$IN_CHROOT" = 0 ] && [ "$INIT" = systemd ]; then
            systemctl daemon-reload && systemctl try-restart "${units[@]}" >/dev/null 2>&1
        fi
    fi
}

do_modules() {
    local inuse fs out="" kept=""
    inuse=" $({ findmnt -rno FSTYPE; findmnt --fstab -rno FSTYPE; } 2>/dev/null | sort -u | tr '\n' ' ') "
    for fs in cramfs freevxfs jffs2 hfs hfsplus adfs affs befs bfs efs hpfs jfs minix nilfs2 omfs qnx4 qnx6 sysv ufs gfs2 ocfs2 reiserfs; do
        case $inuse in *" $fs "*) kept+=" $fs"; continue ;; esac
        out+="install $fs /bin/false"$'\n'
    done
    printf '%s' "$out" | put 644 /etc/modprobe.d/uncommon-filesystems.conf &&
    printf 'install %s /bin/false\n' dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm |
        put 644 /etc/modprobe.d/uncommon-net-protocols.conf &&
    printf 'blacklist %s\n' firewire-core firewire-ohci firewire-net firewire-serial firewire-sbp2 |
        put 644 /etc/modprobe.d/blacklist-firewire.conf &&
    pass "modules: rare filesystems and network protocols blocked, FireWire not autoloaded (squashfs, udf, f2fs untouched)" ||
    fail "modules: could not write /etc/modprobe.d"
    [ -n "$kept" ] && info "in use, left loadable:$kept"
}

do_coredumps() {
    printf '%s\n' '# hardening.sh' '* hard core 0' | put 644 /etc/security/limits.d/90-hardening.conf &&
        pass "core dumps: hard limit 0 for non-root users"
    if [ -x /usr/lib/systemd/systemd-coredump ] || [ -x /lib/systemd/systemd-coredump ]; then
        printf '%s\n' '[Coredump]' 'Storage=none' 'ProcessSizeMax=0' | put 644 /etc/systemd/coredump.conf.d/90-hardening.conf &&
            pass "systemd-coredump: storage disabled"
    fi
}

do_shell() {
    if grep -Eq '^[[:space:]]*umask[[:space:]]+0?0?22[[:space:]]*$' /etc/profile 2>/dev/null; then
        edit /etc/profile -E 's/^([[:space:]]*umask[[:space:]]+)0?0?22[[:space:]]*$/\1027/'
    fi
    put 644 /etc/profile.d/hardening.sh <<EOF
# hardening.sh
umask 027
export HISTCONTROL=ignoreboth
if [ "\$(id -u)" -eq 0 ] || [ -n "\${SSH_CONNECTION:-}" ] || tty 2>/dev/null | grep -q '^/dev/tty[0-9]'; then
    case \$(readonly -p) in
        *' TMOUT'[=\ ]*) ;;
        *)
            TMOUT=$TMOUT_SECONDS
            readonly TMOUT
            export TMOUT
            ;;
    esac
fi
EOF
    pass "shell: umask 027, ${TMOUT_SECONDS}s idle logout on TTY/SSH/root shells only, space-prefixed commands kept out of history"
}

do_logindefs() {
    local f=/etc/login.defs
    [ -f "$f" ] || { skip "login.defs: not present"; return; }
    set_def "$f" UMASK 027
    set_def "$f" HOME_MODE 0700
    set_def "$f" PASS_MAX_DAYS 99998
    set_def "$f" PASS_MIN_DAYS 1
    if yescrypt_ok; then
        set_def "$f" ENCRYPT_METHOD YESCRYPT
        set_def "$f" YESCRYPT_COST_FACTOR "$YESCRYPT_COST"
    fi
    grep -Eq '^[[:space:]]*CONSOLE_GROUPS[[:space:]]' "$f" && edit "$f" -E 's/^([[:space:]]*CONSOLE_GROUPS[[:space:]])/#\1/'
    pass "login.defs: UMASK 027, HOME_MODE 0700, PASS_MAX_DAYS 99998, yescrypt cost $YESCRYPT_COST, CONSOLE_GROUPS off"
}

pam_wheel_on() {
    local f=$1
    [ -f "$f" ] || return 0
    grep -Eq '^[[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+su[[:space:]]*$' "$f" && return 0
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' "$f"; then
        if grep -Eq '^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' "$f"; then
            edit "$f" -E '0,/^#[[:space:]]*(auth[[:space:]]+required[[:space:]]+pam_wheel\.so)/s//\1/'
        else
            save "$f"; printf 'auth\t\trequired\tpam_wheel.so use_uid\n' >> "$f"
        fi
    fi
    grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' "$f" ||
        edit "$f" -E '/^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/s/$/ use_uid/'
}

pam_rehash() {
    local f=$1 tmp
    tmp=$(mktemp) || return 1
    sed -E "/^[[:space:]]*password[[:space:]].*pam_unix\.so/{
s/[[:space:]](md5|bigcrypt|sha256|sha512|blowfish|gost_yescrypt|yescrypt)([[:space:]]|\$)/ yescrypt\2/
/[[:space:]]yescrypt([[:space:]]|\$)/!s/\$/ yescrypt/
s/[[:space:]]rounds=[0-9]+//
s/\$/ rounds=$YESCRYPT_COST/
}" "$f" > "$tmp"
    if cmp -s "$tmp" "$f"; then rm -f "$tmp"; return 0; fi
    save "$f"; cat "$tmp" > "$f"; rm -f "$tmp"
}

do_pam() {
    local f wgid members mod old
    if [ -d /etc/security ]; then
        [ -f /etc/security/faillock.conf ] || { save /etc/security/faillock.conf; : > /etc/security/faillock.conf; }
        set_kv /etc/security/faillock.conf deny 5
        set_kv /etc/security/faillock.conf unlock_time 900
        set_kv /etc/security/faillock.conf fail_interval 900
        if grep -Eqs '^[[:space:]]*-?auth[[:space:]].*pam_faillock\.so' /etc/pam.d/*; then pass "faillock: 5 failures in 15 min lock the account for 15 min"
        else fail "faillock: settings written, but no /etc/pam.d stack loads pam_faillock.so, so failures are not counted"; fi
    fi

    getent group wheel >/dev/null || groupadd wheel
    if [ -n "$ADMIN" ] && ! id -nG "$ADMIN" 2>/dev/null | tr ' ' '\n' | grep -qx wheel; then
        usermod -aG wheel "$ADMIN" && pass "wheel: added $ADMIN"
    fi
    wgid=$(getent group wheel | cut -d: -f3)
    members=$(getent group wheel | cut -d: -f4)
    [ -n "$members" ] || members=$(awk -F: -v g="$wgid" '$4 == g { print $1; exit }' /etc/passwd)
    if [ -n "$members" ]; then
        pam_wheel_on /etc/pam.d/su && pam_wheel_on /etc/pam.d/su-l && pass "su: limited to wheel ($members), covers both 'su' and 'su -'"
    else
        fail "su: wheel has no members and the invoking user is unknown; pam_wheel left off to avoid locking su"
    fi

    if yescrypt_ok; then
        for f in /etc/pam.d/*; do
            [ -f "$f" ] && grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$f" && pam_rehash "$f"
        done
        pass "PAM: new passwords hashed with yescrypt cost $YESCRYPT_COST"
        old=$(awk -F: '$2 ~ /^\$(1|5|6|2[aby])\$/ { printf "%s ", $1 }' /etc/shadow 2>/dev/null)
        [ -n "$old" ] && info "still on old hashes until their next password change: $old"
    else
        skip "PAM: libcrypt without yescrypt, hashing left as is"
    fi

    mod=$(find /usr/lib/security /usr/lib64/security /lib/security /usr/lib/x86_64-linux-gnu/security /lib/x86_64-linux-gnu/security \
          -maxdepth 1 -name pam_pwquality.so 2>/dev/null | head -1)
    f=/etc/pam.d/passwd
    if [ -z "$mod" ]; then
        skip "pwquality: pam_pwquality.so not installed"
    else
        [ -f /etc/security/pwquality.conf ] || { save /etc/security/pwquality.conf; : > /etc/security/pwquality.conf; }
        set_kv /etc/security/pwquality.conf minlen 12
        if grep -Eq '^[[:space:]]*password[[:space:]].*pam_(pwquality|cracklib|passwdqc)\.so' "$f" 2>/dev/null; then
            pass "pwquality: minlen 12 (module already in $f)"
        elif [ "$(grep -Ec '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$f" 2>/dev/null)" = 1 ]; then
            edit "$f" -E '/^[[:space:]]*password[[:space:]].*pam_unix\.so/{
i\password\trequisite\tpam_pwquality.so retry=3
/use_authtok/!s/$/ use_authtok/
}'
            pass "pwquality: new passwords need 12+ characters and fail on dictionary words"
        else
            skip "pwquality: $f layout not recognised, module not wired in"
        fi
    fi
}

do_shells() {
    local u uid sh n=0
    while IFS=: read -r u _ uid _ _ _ sh; do
        [ "$uid" -eq 0 ] 2>/dev/null || { [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; } || continue
        case $sh in ""|*/nologin|*/false) continue ;; esac
        [ -x "$sh" ] && ! grep -qxF "$sh" /etc/shells || continue
        save /etc/shells; printf '%s\n' "$sh" >> /etc/shells
        pass "shells: added $sh for $u (pam_shells rejects logins with unlisted shells)"; n=$((n + 1))
    done < /etc/passwd
    [ "$n" = 0 ] && pass "shells: every login shell in use is listed in /etc/shells"
}

do_homes() {
    local u uid home n=0
    while IFS=: read -r u _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ] && [ -d "$home" ] || continue
        case $home in /home/?*|/var/home/?*) ;; *) continue ;; esac
        [ $((8#$(stat -c %a "$home") & 7)) -eq 0 ] && continue
        set_mode o-rwx "$home" && n=$((n + 1))
    done < /etc/passwd
    pass "homes: other-user access removed on $n home directories, new homes created 0700"
}

allow_list() {
    local f=$1 bin grp
    bin=$(command -v "$2") || return 1
    if [ -n "$ADMIN" ]; then printf 'root\n%s\n' "$ADMIN"; else printf 'root\n'; fi | put 600 "$f"
    grp=$(stat -c %G "$bin")
    [ "$grp" != root ] && chgrp "$grp" "$f" && chmod 640 "$f"
    [ -f "${f%.allow}.deny" ] && { save "${f%.allow}.deny"; rm -f "${f%.allow}.deny"; }
    return 0
}

do_cron() {
    local f
    if allow_list /etc/cron.allow crontab; then
        set_mode 600 /etc/crontab
        set_mode 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
        while IFS= read -r -d '' f; do set_mode go-rwx "$f"; done < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f -print0 2>/dev/null)
        pass "cron: crontab limited to root${ADMIN:+ and $ADMIN}"
    fi
    allow_list /etc/at.allow at && pass "at: limited to root${ADMIN:+ and $ADMIN}"
    return 0
}

do_netprivacy() {
    local f v
    if [ -d /etc/NetworkManager ]; then
        put 644 /etc/NetworkManager/conf.d/90-hardening.conf <<'EOF'
# hardening.sh
[connection]
ipv4.dhcp-send-hostname=0
ipv6.dhcp-send-hostname=0
ipv4.dhcp-client-id=mac
ipv6.ip6-privacy=2
EOF
        v=$(NetworkManager --version 2>/dev/null)
        if [ -n "$v" ] && ! ver_ge "$v" 1.52; then
            fail "NetworkManager $v ignores a global dhcp-send-hostname default (1.52+); run: nmcli connection modify <name> ipv4.dhcp-send-hostname no"
        else
            pass "NetworkManager: DHCP stops sending the hostname, client-id follows the randomized MAC (next reconnect)"
        fi
    fi
    f=/etc/dhcpcd.conf
    if [ -f "$f" ] && ! grep -Eq '^[[:space:]]*anonymous([[:space:]]|$)' "$f"; then
        if grep -Eq '^[[:space:]]*(interface|ssid|profile|arping)[[:space:]]' "$f"; then
            edit "$f" -E '0,/^[[:space:]]*(interface|ssid|profile|arping)[[:space:]]/s//anonymous\n&/'
        else
            save "$f"; printf 'anonymous\n' >> "$f"
        fi
    fi
    [ -f "$f" ] && pass "dhcpcd: RFC 7844 anonymity profile (no hostname, DUID or vendor class)"
    for f in /etc/dhcp/dhclient.conf /etc/dhclient.conf; do
        [ -f "$f" ] && grep -Eq '^[[:space:]]*send[[:space:]]+host-name' "$f" &&
            edit "$f" -E 's/^([[:space:]]*send[[:space:]]+host-name)/#\1/' && pass "dhclient: hostname no longer sent ($f)"
    done
    f=/etc/avahi/avahi-daemon.conf
    if [ -f "$f" ] && [ "$MDNS_PUBLISH" = no ]; then
        if ! grep -Eq '^[[:space:]]*disable-publishing[[:space:]]*=[[:space:]]*yes' "$f"; then
            if grep -Eq '^[[:space:]]*#?[[:space:]]*disable-publishing[[:space:]]*=' "$f"; then
                edit "$f" -E 's/^[[:space:]]*#?[[:space:]]*disable-publishing[[:space:]]*=.*/disable-publishing=yes/'
            elif grep -q '^\[publish\]' "$f"; then
                edit "$f" '/^\[publish\]/a disable-publishing=yes'
            else
                save "$f"; printf '\n[publish]\ndisable-publishing=yes\n' >> "$f"
            fi
        fi
        pass "avahi: query-only, hostname no longer announced (next avahi restart)"
    fi
}

LOCK=0 DNS_UIDS="" SSH_PORTS="" SSH_SRC4="" SSH_SRC6=""

nets() {
    local n
    for n in $LAN_NETS; do
        case $n in *:*) [ "$1" = 6 ] && echo "$n" ;; *) [ "$1" = 4 ] && echo "$n" ;; esac
    done
}

rules_in() {
    local fam=$1 n p s
    echo "-A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP"
    echo "-A INPUT -p tcp --syn -m hashlimit --hashlimit-mode srcip --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-name syn$fam -j DROP"
    if [ "$fam" = 4 ]; then s=$SSH_SRC4; else s=$SSH_SRC6; fi
    for n in $s; do
        for p in $SSH_PORTS; do
            echo "-A INPUT -s $n -p tcp --dport $p -m conntrack --ctstate NEW -m recent --name ssh$fam --set"
            echo "-A INPUT -s $n -p tcp --dport $p -m conntrack --ctstate NEW -m recent --name ssh$fam --update --seconds 60 --hitcount 4 -j DROP"
            echo "-A INPUT -s $n -p tcp --dport $p -j ACCEPT"
        done
    done
    for n in $(nets "$fam"); do
        for p in $LAN_TCP; do echo "-A INPUT -s $n -p tcp --dport $p -j ACCEPT"; done
        for p in $LAN_UDP; do echo "-A INPUT -s $n -p udp --dport $p -j ACCEPT"; done
        if [ "$fam" = 4 ]; then
            echo "-A INPUT -s $n -p icmp --icmp-type echo-request -m limit --limit 5/sec -j ACCEPT"
        else
            echo "-A INPUT -s $n -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 5/sec -j ACCEPT"
        fi
    done
    for p in $PUBLIC_TCP; do echo "-A INPUT -p tcp --dport $p -j ACCEPT"; done
    for p in $PUBLIC_UDP; do echo "-A INPUT -p udp --dport $p -j ACCEPT"; done
    [ "$fam" = 4 ] && echo "-A INPUT -m addrtype --dst-type BROADCAST -j DROP"
    echo "-A INPUT -m addrtype --dst-type MULTICAST -j DROP"
    echo "-A INPUT -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix \"fw$fam-drop: \""
}

rules_lock() {
    local u rej=icmp-port-unreachable
    [ "$LOCK" = 1 ] || return 0
    [ "$1" = 6 ] && rej=icmp6-port-unreachable
    echo "-A OUTPUT -j dns-lock"
    echo "-A dns-lock -o lo -j RETURN"
    echo "-A dns-lock -o tun+ -j RETURN"
    echo "-A dns-lock -o wg+ -j RETURN"
    for u in $DNS_UIDS; do echo "-A dns-lock -m owner --uid-owner $u -j RETURN"; done
    echo "-A dns-lock -p udp --dport 53 -j REJECT --reject-with $rej"
    echo "-A dns-lock -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
    echo "-A dns-lock -p tcp --dport 853 -j REJECT --reject-with tcp-reset"
}

rules_v4() {
    printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]'
    [ "$LOCK" = 1 ] && echo ':dns-lock - [0:0]'
    printf '%s\n' '-A INPUT -i lo -j ACCEPT' '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' \
        '-A INPUT -m conntrack --ctstate INVALID -j DROP'
    rules_in 4
    rules_lock 4
    echo COMMIT
}

rules_v6() {
    local t
    echo '*filter'
    if [ "$IPV6" = block ]; then
        printf '%s\n' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT DROP [0:0]' \
            '-A INPUT -i lo -j ACCEPT' '-A OUTPUT -o lo -j ACCEPT' '-A OUTPUT -p ipv6-icmp -j DROP' \
            '-A OUTPUT -p tcp -j REJECT --reject-with tcp-reset' '-A OUTPUT -j REJECT --reject-with icmp6-adm-prohibited' COMMIT
        return
    fi
    printf '%s\n' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]'
    [ "$LOCK" = 1 ] && echo ':dns-lock - [0:0]'
    printf '%s\n' '-A INPUT -i lo -j ACCEPT' '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
    for t in router-advertisement neighbour-solicitation neighbour-advertisement; do
        echo "-A INPUT -p ipv6-icmp --icmpv6-type $t -m hl --hl-eq 255 -j ACCEPT"
    done
    printf '%s\n' '-A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 130 -j ACCEPT' \
        '-A INPUT -m conntrack --ctstate INVALID -j DROP' \
        '-A INPUT -s fe80::/10 -p udp --sport 547 --dport 546 -j ACCEPT'
    rules_in 6
    rules_lock 6
    echo COMMIT
}

persist_fw() {
    local svc=$1 rules=$2 bin=$3 conf sv dst
    if [ "$INIT" = openrc ]; then
        conf=$(sed -n -E 's/^[[:space:]]*IP6?TABLES_SAVE="?([^"]*)"?.*/\1/p' "/etc/conf.d/$svc" 2>/dev/null | tail -1)
        [ -n "$conf" ] && [ "$conf" != "$rules" ] && put 600 "$conf" < "$rules"
    fi
    if enable_service "$svc"; then pass "firewall: $svc restores $rules at boot ($INIT)"; return; fi
    case $INIT in
        systemd)
            put 644 "/etc/systemd/system/$svc-restore.service" <<EOF
[Unit]
Description=Restore $svc rules (hardening.sh)
DefaultDependencies=no
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=$bin $rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload >/dev/null 2>&1
            systemctl enable "$svc-restore.service" >/dev/null 2>&1 && pass "firewall: $svc-restore.service restores $rules at boot" ||
                fail "firewall: could not enable $svc-restore.service" ;;
        runit)
            sv=/etc/runit/sv; [ -d "$sv" ] || sv=/etc/sv
            printf '#!/bin/sh\nexec 2>&1\n%s %s\nexec sleep infinity\n' "$bin" "$rules" | put 755 "$sv/$svc-restore/run"
            for dst in /run/runit/service /var/service /etc/runit/runsvdir/default; do
                [ -d "$dst" ] && { ln -sfn "$sv/$svc-restore" "$dst/$svc-restore"; pass "firewall: runit $svc-restore restores $rules at boot"; return; }
            done
            fail "firewall: no runit service directory to enable $svc-restore" ;;
        *)
            fail "firewall: could not enable $svc under $INIT, rules will not survive a reboot" ;;
    esac
}

do_firewall() {
    local r4 r6 err before="" f4=/etc/iptables/iptables.rules f6=/etc/iptables/ip6tables.rules ipt ip6t
    ipt=$(command -v iptables-restore) || { fail "firewall: iptables-restore not found"; return; }
    ip6t=$(command -v ip6tables-restore || true)
    if { have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; } || { have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; }; then
        fail "firewall: firewalld or ufw is active, iptables ruleset not applied"; return
    fi

    if [ "$SSH_FROM" != none ] && [ -x "$SSHD" ]; then
        if [ -n "$SSH_PORT" ]; then SSH_PORTS=$SSH_PORT
        else SSH_PORTS=$(sshd_check -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | xargs); fi
        [ -n "$SSH_PORTS" ] || SSH_PORTS=22
        if [ "$SSH_FROM" = lan ]; then SSH_SRC4=$(nets 4); SSH_SRC6=$(nets 6)
        else SSH_SRC4=0.0.0.0/0; SSH_SRC6=::/0; fi
    fi

    if [ "$DNS_LOCK" != no ]; then
        if awk '$1 == "nameserver" { n++; if ($2 !~ /^127\./ && $2 != "::1") bad = 1 } END { exit !(n > 0 && !bad) }' /etc/resolv.conf 2>/dev/null &&
           { [ "$DNS_LOCK" = yes ] || pgrep -x dnscrypt-proxy >/dev/null; }; then
            DNS_UIDS=$(ps -o uid= -C dnscrypt-proxy,dnsmasq,unbound 2>/dev/null | tr -d ' ' | sort -u | tr '\n' ' ')
            LOCK=1
        elif [ "$DNS_LOCK" = yes ]; then
            fail "firewall: DNS lock skipped, resolv.conf points at non-loopback nameservers"
        fi
    fi

    r4=$(mktemp) && r6=$(mktemp) || return
    rules_v4 > "$r4"; rules_v6 > "$r6"
    if ! err=$("$ipt" --test < "$r4" 2>&1); then fail "firewall: IPv4 ruleset rejected: $err"; rm -f "$r4" "$r6"; return; fi
    if [ -n "$ip6t" ] && ! err=$("$ip6t" --test < "$r6" 2>&1); then
        if [ -e /proc/sys/net/ipv6 ]; then fail "firewall: IPv6 ruleset rejected: $err"; rm -f "$r4" "$r6"; return; fi
        info "firewall: IPv6 disabled in this kernel, ip6tables skipped"; ip6t=""
    fi
    put 600 "$f4" < "$r4"
    [ -n "$ip6t" ] && put 600 "$f6" < "$r6"
    rm -f "$r4" "$r6"

    if [ "$IN_CHROOT" = 0 ]; then
        before=$(iptables -S 2>/dev/null)
        if "$ipt" < "$f4" && { [ -z "$ip6t" ] || "$ip6t" < "$f6"; }; then
            pass "firewall: live, inbound default-drop, IPv6 $IPV6 (filter table only; nat/mangle untouched)"
        else
            fail "firewall: live apply failed"
        fi
        case $before in *DOCKER*|*LIBVIRT*|*incus*|*CNI-*) info "restart docker/libvirt/incus: their filter chains were replaced" ;; esac
        if have fail2ban-client && fail2ban-client ping >/dev/null 2>&1; then
            if fail2ban-client reload --restart --all >/dev/null 2>&1; then pass "fail2ban: jails restarted, chains re-created, bans restored"
            else fail "fail2ban: 'fail2ban-client reload --restart --all' failed, bans are not enforced"; fi
        fi
    fi
    info "inbound: ssh ${SSH_PORTS:-closed}${SSH_PORTS:+ from $SSH_FROM}; LAN ${LAN_NETS:-none}; public tcp ${PUBLIC_TCP:-none} udp ${PUBLIC_UDP:-none}"
    [ "$LOCK" = 1 ] && info "DNS lock on (exempt uids: ${DNS_UIDS:-none}); disable until reboot or re-run with: iptables -F dns-lock"
    if have nft && nft list tables 2>/dev/null | grep -Evq '^table (ip|ip6) (filter|nat|mangle|raw|security)$'; then
        info "other nftables tables are loaded; a packet must pass them too: $(nft list tables 2>/dev/null | tr '\n' ' ')"
    fi
    persist_fw iptables "$f4" "$ipt"
    [ -n "$ip6t" ] && persist_fw ip6tables "$f6" "$ip6t"
}

has_keys() {
    local u uid home
    while IFS=: read -r u _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ] || continue
        grep -Eqs '(^|[[:space:]])(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9-]+@openssh\.com)[[:space:]]+AAAA' "$home/.ssh/authorized_keys" && return 0
    done < /etc/passwd
    return 1
}

do_ssh() {
    local cfg=/etc/ssh/sshd_config drop=/etc/ssh/sshd_config.d/10-hardening.conf pw="" err tmp
    if [ -f "$cfg" ] && [ -x "$SSHD" ]; then
        grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$cfg" || edit "$cfg" '1i Include /etc/ssh/sshd_config.d/*.conf'
        case $SSH_PASSWORDS in
            no) pw=no ;;
            yes) pw=yes ;;
            *) has_keys && pw=no ;;
        esac
        {
            echo "# hardening.sh"
            [ -n "$SSH_PORT" ] && echo "Port $SSH_PORT"
            [ -n "$pw" ] && printf 'PasswordAuthentication %s\nKbdInteractiveAuthentication %s\n' "$pw" "$pw"
            cat <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
MaxSessions 4
LoginGraceTime 30
AllowAgentForwarding no
AllowTcpForwarding local
X11Forwarding no
TCPKeepAlive no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
KexAlgorithms -ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
MACs -umac-64-etm@openssh.com,umac-64@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1
EOF
        } | put 600 "$drop"
        if err=$(sshd_check -t); then
            pass "sshd: drop-in valid (sshd -t); active after the next sshd reload"
            case $pw in
                no) pass "sshd: password and keyboard-interactive login off" ;;
                "") info "sshd: password login left as configured, no user has ~/.ssh/authorized_keys yet" ;;
            esac
        else
            rm -f "$drop"; fail "sshd: drop-in rejected and removed: $err"
        fi
        if [ -f /etc/ssh/moduli ]; then
            tmp=$(mktemp) && awk '$5 >= 3071' /etc/ssh/moduli > "$tmp"
            if [ -s "$tmp" ] && ! cmp -s "$tmp" /etc/ssh/moduli; then
                save /etc/ssh/moduli; cat "$tmp" > /etc/ssh/moduli; pass "sshd: DH moduli below 3072 bits removed"
            fi
            rm -f "$tmp"
        fi
        set_mode 600 "$cfg"
    else
        skip "sshd: not installed"
    fi

    cfg=/etc/ssh/ssh_config drop=/etc/ssh/ssh_config.d/10-hardening.conf
    if [ -f "$cfg" ] && have ssh; then
        grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/ssh_config\.d/\*\.conf' "$cfg" || edit "$cfg" '1i Include /etc/ssh/ssh_config.d/*.conf'
        printf '%s\n' '# hardening.sh' 'Host *' '    HashKnownHosts yes' '    ForwardAgent no' '    ForwardX11 no' | put 644 "$drop"
        set_mode 644 "$cfg"
        if ssh -G localhost >/dev/null 2>&1; then
            pass "ssh client: known_hosts hashed, agent/X11 forwarding off, OpenSSH algorithm defaults kept"
        else
            rm -f "$drop"; fail "ssh client: config rejected by 'ssh -G', drop-in removed"
        fi
    fi
}

do_banners() {
    local b
    b=$(printf '%s\n' \
        '+---------------------------------------------------------------+' \
        '| WARNING: Unauthorized access to this system is prohibited.    |' \
        '| All connections are logged and monitored. Disconnect          |' \
        '| IMMEDIATELY if you are not an authorized user!                |' \
        '+---------------------------------------------------------------+')
    printf '%s\n' "$b" | put 644 /etc/issue && printf '%s\n' "$b" | put 644 /etc/issue.net && pass "banners: /etc/issue, /etc/issue.net"
}

do_services() {
    local s b found=0
    if [ "$INIT" != systemd ]; then
        for s in syslog-ng:syslog-ng rsyslog:rsyslogd socklog-unix:socklog; do
            have "${s#*:}" || continue
            found=1
            if enable_service "${s%%:*}"; then pass "logging: ${s%%:*} enabled at boot"; else fail "logging: could not enable ${s%%:*}"; fi
            break
        done
        [ "$found" = 1 ] || skip "logging: no syslog daemon installed"
    fi
    if have auditd; then
        if enable_service auditd; then pass "auditd: enabled at boot"; else fail "auditd: could not enable"; fi
    fi
    for b in telnetd in.telnetd inetd xinetd in.tftpd tftpd in.rshd rshd in.rlogind rlogind in.rexecd rexecd ypbind; do
        have "$b" && fail "legacy daemon installed: $b, remove its package"
    done
    return 0
}

do_perms() {
    set_mode o-rwx /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-
    set_mode 644 /etc/passwd /etc/group
    set_mode 700 /root /root/.ssh
    [ -d /root/.ssh ] && find /root/.ssh -type f -exec chmod go-rwx {} +
    set_mode 600 /etc/doas.conf /etc/crypttab /etc/wpa_supplicant/wpa_supplicant.conf /boot/grub/grub.cfg /boot/grub2/grub.cfg
    [ -d /etc/ssl/private ] && chmod -R o-rwx /etc/ssl/private
    pass "permissions: shadow, root home, doas.conf, crypttab, wpa_supplicant.conf, grub.cfg"
}

do_aide() {
    local attrs="p+l+u+g+s" v err d dirs=""
    have aide || { skip "aide: not installed"; return; }
    v=$(aide --version 2>&1)
    grep -q '^acl: yes' <<< "$v" && attrs+="+acl"
    grep -q '^xattrs: yes' <<< "$v" && attrs+="+xattrs"
    mkdir -p /var/lib/aide /var/log/aide && chmod 700 /var/lib/aide /var/log/aide
    for d in /boot /usr /opt /root/.ssh; do [ -d "$d" ] && dirs+="${d//./\\.} FULL"$'\n'; done
    put 600 /etc/aide.conf <<EOF
@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide
database_in=file:@@{DBDIR}/aide.db.gz
database_out=file:@@{DBDIR}/aide.db.new.gz
database_new=file:@@{DBDIR}/aide.db.new.gz
gzip_dbout=yes
log_level=warning
report_level=changed_attributes
report_url=file:@@{LOGDIR}/aide.log
report_url=stdout

FULL = $attrs+i+n+m+c+sha512
ETC = $attrs+sha512

${dirs}/etc ETC
!/usr/src
!/etc/mtab\$
!/etc/adjtime\$
!/etc/ld\.so\.cache\$
!/etc/resolv\.conf\$
!/etc/machine-id\$
!/etc/hostname\$
!/etc/pacman\.d/gnupg
!/etc/\.
!/etc/.*~\$
EOF
    if ! err=$(aide --config-check -c /etc/aide.conf 2>&1); then fail "aide: config rejected: $err"; return; fi
    pass "aide: config valid; /etc checked by content, owner and mode, not inode/ctime"
    if [ -d /etc/cron.daily ] && { have crond || have cron || have fcron; }; then
        put 700 /etc/cron.daily/aide-check <<EOF
#!/bin/sh
[ -f /var/lib/aide/aide.db.gz ] || exit 0
nice -n 19 ionice -c 3 $(command -v aide) --check -c /etc/aide.conf > /var/log/aide/aide-check.log 2>&1
rc=\$?
[ "\$rc" -eq 0 ] || logger -t aide -p authpriv.warning "aide --check exit \$rc, see /var/log/aide/aide-check.log"
exit 0
EOF
        pass "aide: daily check at idle priority via /etc/cron.daily, changes reported to syslog"
    else
        skip "aide: no cron daemon with /etc/cron.daily, daily check not scheduled"
    fi
    if [ "$IN_CHROOT" = 1 ]; then info "aide: chroot detected, run 'aide --init' after first boot"; return; fi
    info "aide: building baseline, this takes a few minutes"
    if nice -n 19 ionice -c 3 aide --init -c /etc/aide.conf > /var/log/aide/aide-init.log 2>&1 &&
       mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; then
        pass "aide: baseline stored in /var/lib/aide/aide.db.gz"
    else
        fail "aide: --init failed, see /var/log/aide/aide-init.log"
    fi
}

revert() {
    local p
    [ -d "$STATE" ] || { fail "revert: nothing recorded in $STATE"; return; }
    if [ -f "$STATE/modes" ]; then
        while IFS=$'\t' read -r m p; do chmod "$m" "$p" 2>/dev/null; done < "$STATE/modes"
        pass "revert: permissions restored"
    fi
    if [ -d "$STATE/orig" ]; then
        while IFS= read -r -d '' p; do
            p=${p#"$STATE/orig"}
            cp -a "$STATE/orig$p" "$p" && pass "revert: restored $p"
        done < <(find "$STATE/orig" \( -type f -o -type l \) -print0)
    fi
    for p in iptables-restore ip6tables-restore; do
        [ -e "$STATE/new/etc/systemd/system/$p.service" ] && systemctl disable "$p.service" >/dev/null 2>&1
        rm -f "/run/runit/service/$p" "/var/service/$p" "/etc/runit/runsvdir/default/$p"
    done
    if [ -d "$STATE/new" ]; then
        while IFS= read -r -d '' p; do
            p=${p#"$STATE/new"}
            rm -f "$p" && pass "revert: removed $p"
        done < <(find "$STATE/new" -type f -print0)
    fi
    [ -f "$STATE/newdirs" ] && tac "$STATE/newdirs" | while IFS= read -r p; do rmdir "$p" 2>/dev/null; done
    local fam bin rules
    for fam in iptables ip6tables; do
        bin=$(command -v "$fam-restore") || continue
        rules=/etc/iptables/$fam.rules
        if [ -f "$rules" ]; then
            "$bin" < "$rules" && pass "revert: $fam reloaded from $rules"
        else
            "${bin%-restore}" -P INPUT ACCEPT; "${bin%-restore}" -P FORWARD ACCEPT; "${bin%-restore}" -P OUTPUT ACCEPT
            "${bin%-restore}" -F; "${bin%-restore}" -X
            pass "revert: $fam filter table open"
        fi
    done
    have fail2ban-client && fail2ban-client ping >/dev/null 2>&1 && fail2ban-client reload --restart --all >/dev/null 2>&1
    rm -rf "$STATE"
    info "services enabled at boot stay enabled"
}

summary() {
    printf '\n%d passed, %d failed\n' "$NPASS" "$NFAIL"
    [ "$NFAIL" -eq 0 ]
}

main() {
    case ${1:-} in
        --revert) revert; summary; exit ;;
        "") ;;
        *) echo "usage: $0 [--revert]" >&2; exit 2 ;;
    esac
    mkdir -p "$STATE" && chmod 700 "$STATE"
    info "init: $INIT$([ "$IN_CHROOT" = 1 ] && echo ' (chroot, live changes skipped)'), admin user: ${ADMIN:-unknown}"
    legacy_repair
    do_modules
    do_coredumps
    do_shell
    do_logindefs
    do_pam
    do_shells
    do_homes
    do_cron
    do_netprivacy
    do_firewall
    do_ssh
    do_banners
    do_services
    do_perms
    s6_commit
    do_aide
    summary
}

[ "${BASH_SOURCE[0]}" = "$0" ] && main "$@"
