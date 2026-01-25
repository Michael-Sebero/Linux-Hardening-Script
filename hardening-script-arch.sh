#!/bin/bash

### ALGIZ VERSION

# Force unbuffered output for immediate visibility
export PYTHONUNBUFFERED=1
stty -icanon min 1 time 0 2>/dev/null || true

# Print section header
print_section() {
    printf "\n"
    printf "================================================================\n"
    printf "  %s\n" "$1"
    printf "================================================================\n"
}

# Print formatted status messages
status() {
    printf "%-60s" "$1..." >&2
}

ok() {
    printf " done\n" >&2
}

info() {
    printf "%s\n" "$1"
}

print_section "Starting system hardening process"

# ========================================================
# FILE PERMISSIONS
# ========================================================
print_section "File Permissions"

status "setting secure file permissions"
chmod 700 /root
chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 600 /etc/sudoers
chmod -R 700 /etc/ssl/private 2>/dev/null || true
chmod -R 755 /etc/ssl/certs
find /etc/cron.* -type f -exec chmod 0700 {} \; 2>/dev/null || true
chmod 0600 /etc/crontab 2>/dev/null || true
chmod 0600 /etc/ssh/sshd_config 2>/dev/null || true
ok

# ========================================================
# HOST CONFIGURATION
# ========================================================
status "configuring host resolver"
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
print_section "TCP/IP Stack Hardening"

status "hardening TCP/IP stack (runtime)"
# IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > "$i" 2>/dev/null || true; done

# TCP hardening
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Log martian packets
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > "$i" 2>/dev/null || true; done

# Disable forwarding and redirects
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > "$i" 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > "$i" 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > "$i" 2>/dev/null || true; done

# Disable multicast forwarding and proxy ARP
for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do echo 0 > "$i" 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > "$i" 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > "$i" 2>/dev/null || true; done
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > "$i" 2>/dev/null || true; done
ok

# ========================================================
# IPTABLES FIREWALL CONFIGURATION
# ========================================================
print_section "Iptables Firewall Configuration"

IPTABLES="/sbin/iptables"
SSHPORT="22"

status "flushing existing iptables rules"
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

status "setting default policies"
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

status "creating logging chains"
LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options"
RLIMIT="-m limit --limit 3/s --limit-burst 8"

"$IPTABLES" -N LOGACCEPT
"$IPTABLES" -A LOGACCEPT -j $LOG $RLIMIT --log-prefix "ACCEPT "
"$IPTABLES" -A LOGACCEPT -j ACCEPT

"$IPTABLES" -N LOGDROP
"$IPTABLES" -A LOGDROP -j $LOG $RLIMIT --log-prefix "DROP "
"$IPTABLES" -A LOGDROP -j DROP

"$IPTABLES" -N LOGREJECT
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

status "rate limiting ICMP"
"$IPTABLES" -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
"$IPTABLES" -A INPUT -p icmp -j DROP
"$IPTABLES" -A OUTPUT -p icmp -j ACCEPT
ok

status "allowing DNS queries"
"$IPTABLES" -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
ok

status "allowing HTTP/HTTPS"
"$IPTABLES" -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
ok

status "allowing SSH with brute-force protection"
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -m recent --set --name SSH
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
"$IPTABLES" -A INPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -j ACCEPT
"$IPTABLES" -A OUTPUT -p tcp --dport "$SSHPORT" -m conntrack --ctstate NEW -j ACCEPT
ok

status "allowing email protocols"
"$IPTABLES" -A OUTPUT -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT  # SMTP submission
"$IPTABLES" -A OUTPUT -p tcp --dport 995 -m conntrack --ctstate NEW -j ACCEPT  # POP3S
"$IPTABLES" -A OUTPUT -p tcp --dport 993 -m conntrack --ctstate NEW -j ACCEPT  # IMAPS
ok

status "allowing Git protocols"
"$IPTABLES" -A OUTPUT -p tcp --dport 9418 -m conntrack --ctstate NEW -j ACCEPT  # Git protocol
ok

status "allowing Tor network"
"$IPTABLES" -A INPUT -p tcp -m multiport --dports 9050,9051,9150 -j ACCEPT
"$IPTABLES" -A OUTPUT -p tcp -m multiport --dports 9050,9051,9150 -j ACCEPT
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

status "allowing Discord voice"
"$IPTABLES" -A INPUT -p udp --dport 50000:65535 -j ACCEPT
"$IPTABLES" -A OUTPUT -p udp --dport 50000:65535 -j ACCEPT
ok

status "implementing SYN flood protection"
"$IPTABLES" -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
"$IPTABLES" -A INPUT -p tcp --syn -j DROP
ok

status "logging dropped packets"
"$IPTABLES" -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-input: " --log-level 7
"$IPTABLES" -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables-forward: " --log-level 7
ok

status "setting final drop rules"
"$IPTABLES" -A INPUT -j LOGREJECT
"$IPTABLES" -A FORWARD -j LOGREJECT
ok

status "saving iptables rules"
mkdir -p /etc/iptables
iptables-save > /etc/iptables/iptables.rules
ok

# ========================================================
# IPv6 FIREWALL
# ========================================================
print_section "IPv6 Firewall (Block All)"

IP6TABLES="/sbin/ip6tables"

status "configuring ip6tables (block all)"
"$IP6TABLES" -F
"$IP6TABLES" -X
"$IP6TABLES" -Z
"$IP6TABLES" -P INPUT DROP
"$IP6TABLES" -P FORWARD DROP
"$IP6TABLES" -P OUTPUT DROP
"$IP6TABLES" -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables-input: " --log-level 7
"$IP6TABLES" -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "ip6tables-forward: " --log-level 7
"$IP6TABLES" -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables-output: " --log-level 7
ip6tables-save > /etc/iptables/ip6tables.rules
ok

# ========================================================
# SYSTEM CONFIGURATION FILES
# ========================================================
print_section "System Configuration Files"

status "configuring bash environment"
cat > /etc/bash.bashrc <<'EOF'
# /etc/bash.bashrc

[[ $- != *i* ]] && return

PS1='[\u@\h \W]\$ '
PS2='> '
PS3='> '
PS4='+ '

readonly
umask 0027

readonly
TMOUT=1800

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
cat > /etc/profile <<'EOF'
# /etc/profile

umask 0027

if [[ $UID == 0 ]]; then
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/bin"
elif [[ $UID == 1000 ]]; then
  export PATH="/usr/local/bin:/usr/bin"
else
  readonly 
  export PATH="$HOME"
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

readonly
TMOUT="1800"
export TMOUT

unset TERMCAP
unset MANPATH
EOF
ok

status "configuring bash history"
cat > /etc/profile.d/bash_history.sh <<'EOF'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignoredups
export HISTSIZE=1000
readonly HISTSIZE
readonly HISTFILE
readonly HISTFILESIZE
EOF
chmod +x /etc/profile.d/bash_history.sh
ok

status "configuring locale settings"
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
cat > /etc/environment <<'EOF'
LANG="en_GB.UTF-8"
LANGUAGE="en_GB:en_US"
PAGER="less"
EOF
ok

status "configuring console settings"
cat > /etc/vconsole.conf <<'EOF'
KEYMAP=uk
EOF
ok

status "configuring secure terminals"
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
cat > /etc/shells <<'EOF'
/bin/sh
/bin/bash
/bin/rbash
/bin/zsh
/bin/rzsh
EOF
ok

status "configuring password hashing"
cat > /etc/default/passwd <<'EOF'
CRYPT=sha512
GROUP_CRYPT=blowfish
CRYPT_FILES=blowfish
CRYPT_YP=des
blowfish: 24-31
BLOWFISH_CRYPT_FILES=10
sha256/sha512: 9999-9999999
SHA512_CRYPT_FILES=10000
EOF
ok

status "configuring hardening wrapper"
cat > /etc/hardening-wrapper.conf <<'EOF'
HARDENING_BINDNOW=1
HARDENING_PIE=1
HARDENING_FORTIFY=2
HARDENING_RELRO=1
HARDENING_STACK_CHECK=1
HARDENING_STACK_PROTECTOR=3
EOF

# Create hardening wrapper scripts
mkdir -p /usr/lib/hardening-wrapper

cat > /usr/lib/hardening-wrapper/common.sh <<'EOF'
error() {
  printf "%s\n" "$1" >&2
  exit 1
}

run_wrapped_binary() {
  # search for the wrapped binary in $PATH
  # ignore paths before our own for compatibility with other wrappers
  unwrapped=false
  self=false
  IFS=: read -ra path <<< "$PATH";
  for p in "${path[@]}"; do
    binary="$p/${0##*/}"
    if $self && [[ -x "$binary" ]]; then
      unwrapped="$binary"
      break
    elif [[ "$binary" -ef "$0" ]]; then
      self=true
    fi
  done

  exec "$unwrapped" "${arguments[@]}" "$@"
}
EOF

cat > /usr/lib/hardening-wrapper/cc-wrapper.sh <<'EOF'
#!/bin/bash

. "${0%/*}/common.sh"

declare -A default
while IFS== read key value; do
  default["$key"]="$value"
done < /etc/hardening-wrapper.conf

force_fPIE="${HARDENING_PIE:-"${default[HARDENING_PIE]:-1}"}"
force_fortify="${HARDENING_FORTIFY:-"${default[HARDENING_FORTIFY]:-2}"}"
force_pie="${HARDENING_PIE:-"${default[HARDENING_PIE]:-1}"}"
force_stack_check="${HARDENING_STACK_CHECK:-"${default[HARDENING_STACK_CHECK]:-1}"}"
force_stack_protector="${HARDENING_STACK_PROTECTOR:-"${default[HARDENING_STACK_PROTECTOR]:-3}"}"

optimizing=0

for opt; do
  case "$opt" in
    -fno-PIC|-fno-pic|-fno-PIE|-fno-pie|-nopie|-static|--static|-shared|--shared|-D__KERNEL__|-nostdlib|-nostartfiles|-mcmodel=kernel)
      force_fPIE=1
      force_pie=1
      ;;
    -fPIC|-fpic|-fPIE|-fpie)
      force_fPIE=1
      ;;
    -c|-E|-S)
      force_pie=1
      ;;
    -nostdlib|-ffreestanding)
      force_stack_protector=3
      ;;
    -D_FORTIFY_SOURCE*)
      force_fortify=2
      ;;
    -O0)
      optimizing=0
      ;;
    -O*)
      optimizing=2
      ;;
  esac
done

arguments=(-B/usr/lib/hardening-wrapper/bin)

case "$force_fPIE" in
  0) ;;
  1) arguments+=(-fPIE) ;;
  *) error 'invalid value for HARDENING_PIE' ;;
esac

case "$force_fortify" in
  0) ;;
  1|2) (( optimizing )) && arguments+=(-D_FORTIFY_SOURCE=$force_fortify) ;;
  *) error 'invalid value for HARDENING_FORTIFY' ;;
esac

case "$force_pie" in
  0) ;;
  1) arguments+=(-pie) ;;
  *) error 'invalid value for HARDENING_PIE' ;;
esac

case "$force_stack_check" in
  0) ;;
  1) arguments+=(-fstack-check) ;;
  *) error 'invalid value for HARDENING_STACK_CHECK' ;;
esac

case "$force_stack_protector" in
  0) ;;
  1) arguments+=(-fstack-protector) ;;
  2) arguments+=(-fstack-protector-strong) ;;
  3) arguments+=(-fstack-protector-all) ;;
  *) error 'invalid value for HARDENING_STACK_PROTECTOR' ;;
esac

run_wrapped_binary "$@"
EOF

cat > /usr/lib/hardening-wrapper/ld-wrapper.sh <<'EOF'
#!/bin/bash

. "${0%/*}/common.sh"

declare -A default
while IFS== read key value; do
  default["$key"]="$value"
done < /etc/hardening-wrapper.conf

force_bindnow="${HARDENING_BINDNOW:-"${default[HARDENING_BINDNOW]:-1}"}"
force_relro="${HARDENING_RELRO:-"${default[HARDENING_RELRO]:-1}"}"

case "$force_bindnow" in
  0) ;;
  1) arguments+=(-z now) ;;
  *) error 'invalid value for HARDENING_BINDNOW' ;;
esac

case "$force_relro" in
  0) ;;
  1) arguments+=(-z relro) ;;
  *) error 'invalid value for HARDENING_RELRO' ;;
esac

run_wrapped_binary "$@"
EOF

chmod +x /usr/lib/hardening-wrapper/common.sh
chmod +x /usr/lib/hardening-wrapper/cc-wrapper.sh
chmod +x /usr/lib/hardening-wrapper/ld-wrapper.sh
ok

status "configuring wireless regulatory domain"
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
chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf
ok

status "restricting su to wheel group"
if ! grep -q "auth required pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
  echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
fi
ok

status "configuring login banners"
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
cat > /etc/locale.gen <<'EOF'
en_GB.UTF-8 UTF-8  
en_GB ISO-8859-1  
en_US.UTF-8 UTF-8  
en_US ISO-8859-1  
EOF
ok

status "configuring encrypted partitions"
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

status "configuring DHCP client security"
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

status "configuring build hardening (makepkg)"
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
  Protocol 2
  KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
  VisualHostKey yes
EOF
ok

# ========================================================
# AIDE CONFIGURATION
# ========================================================
print_section "AIDE Intrusion Detection"

status "configuring AIDE"
mkdir -p /var/lib/aide /var/log/aide
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

# ========================================================
# MISC
# ========================================================

status "configuring stricter default umask"
cat > /etc/profile.d/umask.sh <<'EOF'
# Set stricter umask for security
umask 027
EOF
chmod +x /etc/profile.d/umask.sh
ok

status "restricting cron and at access"
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
[ -f /etc/cron.deny ] && rm /etc/cron.deny

if command -v at >/dev/null 2>&1; then
    echo "root" > /etc/at.allow
    chmod 600 /etc/at.allow
    [ -f /etc/at.deny ] && rm /etc/at.deny
fi
ok

status "configuring PAM faillock"
mkdir -p /etc/security
cat > /etc/security/faillock.conf <<'EOF'
# Deny access after 5 failed attempts
deny = 5
# Unlock time in seconds (15 minutes)
unlock_time = 900
# Fail interval (15 minutes)
fail_interval = 900
EOF
ok

# ========================================================
# FINAL PERMISSIONS
# ========================================================
print_section "Final File Permissions"

status "setting final file permissions"
chmod 600 /etc/ssh/ssh_config
chmod 600 /etc/aide.conf 2>/dev/null || true
chmod 644 /etc/profile
chmod 644 /etc/bash.bashrc
chmod 644 /etc/environment
chmod 644 /etc/locale.conf
chmod 644 /etc/locale.gen
chmod 600 /etc/crypttab
chmod 600 /etc/dhclient.conf
chmod 600 /etc/default/passwd
chmod 644 /etc/hardening-wrapper.conf
chmod 644 /etc/issue /etc/issue.net
chmod 644 /etc/shells /etc/securetty /etc/vconsole.conf
chmod 644 /etc/makepkg.conf
chmod 644 /etc/conf.d/wireless-regdom
chmod 644 /etc/hosts
chmod 644 /etc/hostname
chmod 644 /etc/networks
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

print_section "System hardening complete"

exit 0
