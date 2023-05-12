#!/bin/bash
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
cat confs/etc-fstab > /etc/fstab
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
