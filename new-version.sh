#!/bin/bash

# Modernized Linux Hardening Script

# Determine package manager
if [ -f /etc/debian_version ]; then
    PM="apt"
    echo "Detected Debian/Ubuntu based system."
elif [ -f /etc/arch-release ]; then
    PM="pacman"
    echo "Detected Arch based system."
elif [ -f /etc/fedora-release ]; then
    PM="dnf"
    echo "Detected Fedora based system."
else
    echo "Unsupported Linux distribution."
    exit 1
fi

# Update and install necessary packages
echo "Installing necessary packages..."
if [ "$PM" = "apt" ]; then
    sudo apt update && sudo apt install -y ufw fail2ban auditd acct apparmor aide unattended-upgrades
elif [ "$PM" = "pacman" ]; then
    sudo pacman -Syu --noconfirm ufw fail2ban audit apparmor aide acct
elif [ "$PM" = "dnf" ]; then
    sudo dnf install -y ufw fail2ban audit apparmor aide psacct
fi

# Enable UFW (Uncomplicated Firewall) and set basic rules
echo "Configuring UFW..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable

# Harden sysctl settings
echo "Hardening sysctl settings..."
cat << EOF | sudo tee /etc/sysctl.d/99-security.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Hide kernel pointers
kernel.kptr_restrict = 2

# Enable ExecShield protection
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Disable core dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0
EOF

sudo sysctl -p /etc/sysctl.d/99-security.conf

# Secure SSH
echo "Securing SSH..."
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Install and configure Fail2Ban
echo "Installing and configuring Fail2Ban..."
if [ -f /etc/fail2ban/jail.conf ]; then
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
fi
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Configure automatic security updates (for Debian/Ubuntu only)
if [ "$PM" = "apt" ]; then
    echo "Configuring automatic security updates..."
    sudo dpkg-reconfigure -plow unattended-upgrades
fi

# Install and configure auditd
echo "Installing and configuring auditd..."
sudo systemctl enable auditd
sudo systemctl start auditd

# Disable unnecessary services
echo "Disabling unnecessary services..."
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
sudo systemctl disable rpcbind

# Set UMASK
echo "Setting UMASK..."
sudo sed -i 's/UMASK.*/UMASK 027/' /etc/login.defs

# Secure shared memory
echo "Securing shared memory..."
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab

# Harden /proc filesystem
echo "Hardening /proc filesystem..."
echo "proc     /proc     proc     defaults,hidepid=2     0     0" | sudo tee -a /etc/fstab

# Enable process accounting
echo "Enabling process accounting..."
sudo systemctl enable acct
sudo systemctl start acct

# Secure cron
echo "Securing cron..."
sudo chmod 600 /etc/crontab
sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

# Install and configure AppArmor
echo "Installing and configuring AppArmor..."
sudo aa-enforce /etc/apparmor.d/*

# Enable and configure System Integrity Checker (AIDE)
echo "Installing and configuring AIDE..."
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

echo "System hardening complete. Please reboot the system for all changes to take effect."
