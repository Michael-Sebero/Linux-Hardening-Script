#!/bin/bash

sudo ufw limit 22/tcp  
sudo ufw allow 80/tcp  
sudo ufw allow 443/tcp  
sudo ufw default deny incoming  
sudo ufw default allow outgoing
sudo ufw enable

sudo sysctl kernel.modules_disabled=1
sudo sysctl -a
sudo sysctl -A
sudo sysctl mib
sudo sysctl net.ipv4.conf.all.rp_filter
sudo sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)0.arp'

cat <<EOF > /etc/host.conf
order bind,hosts
multi on
EOF

sudo cp jail.local /etc/fail2ban/
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

echo "listening ports"
sudo netstat -tunlp

set -e
echo "Changing umask permissions..."
umask 0027
sleep 2

echo "Applying Hardened configuration files"
cat confs/etc-aide-conf > /etc/aide.conf
cat confs/etc-bash-bashrc > /etc/bash.bashrc
cat confs/etc-conf-d-wireless-regdom > /etc/conf.d/wireless-regdom
cat confs/etc-crypttab > /etc/crypttab
cat confs/etc-dhclient-conf > /etc/dhclient.conf
cat confs/etc-environment > /etc/environment
cat confs/etc-hardening-wrapper-conf > /etc/hardening-wrapper.conf
cat confs/etc-iptables-ip6tables.rules > /etc/iptables/ip6tables.rules
cat confs/etc-iptables-iptables.rules > /etc/iptables/iptables.rules
cat confs/etc-issue > /etc/issue
cat confs/etc-issue-net > /etc/issue.net
cat confs/etc-locale-conf > /etc/locale.conf
cat confs/etc-locale-gen > /etc/locale.gen
cat confs/etc-logrotate-conf > /etc/logrotate.conf
cat confs/etc-mkinitcpio-conf > /etc/mkinitcpio.conf
cat confs/etc-modprobe-d-blacklist-firewire > /etc/modprobe.d/blacklist-firewire
cat confs/etc-modprobe-d-blacklist-usb > /etc/modprobe.d/blacklist-usb
cat confs/etc-motd > /etc/motd
cat confs/etc-profile > /etc/profile
cat confs/etc-securetty > /etc/securetty
cat confs/etc-security-access-conf > /etc/security/access.conf
cat confs/etc-security-group-conf > /etc/security/group.conf
cat confs/etc-security-limits-conf > /etc/security/limits.conf
cat confs/etc-security-namespace-conf > /etc/security/namespace.conf
cat confs/etc-security-pam-env-conf > /etc/security/pam-env.conf
cat confs/etc-security-time-conf > /etc/security/time.conf
cat confs/etc-shells > /etc/shells
cat confs/etc-ssh-ssh_config > /etc/ssh/ssh_config
cat confs/etc-ssh-sshd_config > /etc/ssh/sshd_config
cat confs/etc-sudoers > /etc/sudoers
cat confs/etc-vconsole-conf > /etc/vconsole.conf
cat confs/etc-wpa_supplicant-wpa-supplicant-conf > /etc/wpa_supplicant/wpa-supplicant.conf
cat confs/etc-zsh-zprofile > /etc/zsh/zprofile
cat confs/etc-zsh-zshrc > /etc/zsh/zshrc

echo "Configs in correct state now..."
