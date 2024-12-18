#!/bin/bash

# Lock root account
passwd -l root

# Updates and upgrades
apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get install unattended-upgrades -y
echo "Updates, upgrades, and installations have finished"
dpkg-reconfigure --frontend=readline --terse -plow unattended-upgrades <<< 'y'

# Configure 20auto-upgrades
printf "APT::Periodic::Update-Package-Lists "1";\n" >> /etc/apt/apt.conf.d/20auto-upgrades
printf "APT::Periodic::Download-Upgradeable-Packages "1";\n" >> /etc/apt/apt.conf.d/20auto-upgrades
printf "APT::Periodic::AutocleanInterval "7";\n" >> /etc/apt/apt.conf.d/20auto-upgrades
printf "APT::Periodic::Unattended-Upgrade "1";\n" >> /etc/apt/apt.conf.d/20auto-upgrades

# Configure 50auto-upgrades
printf "Unattended-Upgrade::Allowed-Origins {\n\t\"${distro_id} stable\";\n\t\"${distro_id} ${distro_codename}-security\";\n\t\"${distro_id} ${distro_codename}-updates\";\n};\n\nUnattended-Upgrade::Package-Blacklist {\n\t\"libproxy1v5\";\n};\n" >> /etc/apt/apt.conf.d/50auto-upgrades

# Disable the guest account
sed -i 's/allow-guest=true/allow-guest=false/' /etc/lightdm/lightdm.conf
sed -i 's/greeter-hide-users=false/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
sed -i 's/greeter-show-manual-login=false/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
sed -i 's/autologin-user=all/autologin-user=none/' /etc/lightdm/lightdm.conf

# Look out for UID 0 users and hidden users
echo "Checking for UID 0 users..."
awk -F: '$3 == 0' /etc/passwd
echo "Checking for hidden users..."
awk -F: '$1 ~ /^_/ {print $1}' /etc/passwd

# List and look for unauthorized users
cut -d: -f1 /etc/passwd

# Ask for the number of users to be deleted and delete them
cut -d: -f1 /etc/passwd
read -p "Enter the number of users to be deleted: " num_delusers

if [ $num_delusers -gt 0 ]; then
    if [ $num_delusers -gt 1 ]; then
        for ((i=1; i<=$num_delusers; i++)); do
            read -p "Enter username to be deleted ($i): " del_userlist[$i]
        done
    else
        read -p "Enter Username to be deleted (1): " del_userlist[1]
    fi

    for ((i=1; i<=$num_delusers; i++)); do
        echo "User to be deleted: ${del_userlist[$i]}"
        userdel -r "${del_userlist[$i]}"
    done
fi

# Compare /etc/passwd and /etc/group to the read me