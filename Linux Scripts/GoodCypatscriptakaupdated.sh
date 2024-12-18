#!/bin/bash

# Makes sure you read the read me
echo "Read the read me."
while true; do
  read -p "Have you read the README? (yes/no): " answer
  case $answer in
    [Yy][Ee][Ss]|[Yy])
      echo "Great! Continuing with the script..."
      break
      ;;
    [Nn][Oo]|[Nn])
      echo "Please read the README before proceeding."
      ;;
    *)
      echo "Invalid response. Please type yes or no."
      ;;
  esac
done

# Locks root acc
passwd -l root

# Disable the guest account
sed -i 's/allow-guest=true/allow-guest=false/' /etc/lightdm/lightdm.conf
sed -i 's/greeter-hide-users=false/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
sed -i 's/greeter-show-manual-login=false/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
sed -i 's/autologin-user=all/autologin-user=none/' /etc/lightdm/lightdm.conf

# Updates and Auto Updates
apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get install unattended-upgrades -y
echo "Updates, upgrades, and installations have finished"
dpkg-reconfigure --frontend=readline --terse -plow unattended-upgrades <<< 'y'
echo "Unattended upgrades have been configured"

# Define the file paths
PASSWD_FILE="/etc/passwd"
GROUP_FILE="/etc/group"

# Function to parse passwd for UID 0 users
find_uid_zero_users() {
  echo "Users with UID 0 (root users):"
  awk -F: '$3 == 0 {print $1}' "$PASSWD_FILE"
}

# Function to find hidden users (those starting with a dot)
find_hidden_users() {
  echo "Hidden users (starting with a dot):"
  awk -F: '$1 ~ /^\./ {print $1}' "$PASSWD_FILE"
}


# Main function
main() {
  find_uid_zero_users
  echo ""
  find_hidden_users
  echo ""
}

# Call the main function
main

# Checks and deletes unauthorized users
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


# File containing authorized users and their groups
AUTHORIZED_FILE="./authorized_users.txt"
GROUPS_FILE="./groups.txt"

# Function to create the authorized_users.txt file with an example if it doesn't exist
create_authorized_file() {
    echo "Creating the authorized_users.txt file..."

    cat <<EOL > "$AUTHORIZED_FILE"
# Format: username group
# List the authorized users and the groups they belong to.

# Administrative users
john adm
jane adm

# System users
mike sudo
anna developers
tom adm

# Developers group
bob developers

# Add more users below following the same format
# user group
EOL

    echo "The file '$AUTHORIZED_FILE' has been created with an example structure."
    echo "Please add your authorized users and their groups in the file."
    
    # Open the file in a text editor
    nano "$AUTHORIZED_FILE"
}

# Function to create the groups.txt file with an example if it doesn't exist
create_groups_file() {
    echo "Creating the groups.txt file..."

    cat <<EOL > "$GROUPS_FILE"
# List the groups you want to check and manage in this file
# Each line should be a group name

adm
sudo
developers

# Add more groups below as needed
EOL

    echo "The file '$GROUPS_FILE' has been created with an example structure."
    echo "Please add the groups you want to manage in the file."

    # Open the file in a text editor
    nano "$GROUPS_FILE"
}

# Check if the authorized users file exists
if [[ ! -f "$AUTHORIZED_FILE" ]]; then
  echo "Authorized users file '$AUTHORIZED_FILE' not found!"
  echo "Would you like to create it now? (yes/no)"
  read -r response
  if [[ "$response" =~ ^[Yy][Ee][Ss]|[Yy]$ ]]; then
    create_authorized_file
  else
    echo "Cannot proceed without the authorized users file. Exiting."
    exit 1
  fi
fi

# Check if the groups file exists
if [[ ! -f "$GROUPS_FILE" ]]; then
  echo "Groups file '$GROUPS_FILE' not found!"
  echo "Would you like to create it now? (yes/no)"
  read -r response
  if [[ "$response" =~ ^[Yy][Ee][Ss]|[Yy]$ ]]; then
    create_groups_file
  else
    echo "Cannot proceed without the groups file. Exiting."
    exit 1
  fi
fi

# Function to remove unauthorized users from a group
remove_unauthorized_users() {
  local group=$1

  # Get the current members of the group
  current_users=$(getent group "$group" | awk -F: '{print $4}' | tr ',' ' ')

  # Check each current user and remove them if not authorized
  for user in $current_users; do
    if ! grep -qE "^$user $group\$" "$AUTHORIZED_FILE"; then
      echo "Removing unauthorized user $user from group $group"
      gpasswd -d "$user" "$group"
    fi
  done
}

# Function to add authorized users to their groups
add_authorized_users() {
  while read -r user group; do
    # Skip comment lines and empty lines
    [[ $user =~ ^#.*$ || -z $user ]] && continue

    # Check if the user is already in the group
    if ! getent group "$group" | grep -q "$user"; then
      echo "Adding authorized user $user to group $group"
      gpasswd -a "$user" "$group"
    fi
  done < "$AUTHORIZED_FILE"
}

# Read the list of groups from the groups.txt file
GROUPS=()
while read -r group; do
  # Skip comment lines and empty lines
  [[ $group =~ ^#.*$ || -z $group ]] && continue

  # Add valid groups to the GROUPS array
  GROUPS+=("$group")
done < "$GROUPS_FILE"

# Main script logic
for group in "${GROUPS[@]}"; do
  echo "Processing group: $group"
  remove_unauthorized_users "$group"
done

echo ""
echo "Adding authorized users to their respective groups..."
add_authorized_users

echo "Added removed users from groups"

#Enable the firewall (ufw)
sudo ufw enable
#Check firewall rules for unauthorized inbound rules
sudo ufw status numbered
sudo ufw delete number
Check for unauthorized admins
cat /etc/group | grep sudo
#Delete unauthorized users
sudo userdel -r user # Only use -r if they don't say anything against deleting the user and their files.
# Check for other undeleted home directories
cd 
ls
#Check repo list
cat /etc/apt/sources.list
#Look through all sources in this directory
ls /etc/apt/sources.list.d/
cat /etc/apt/sources.list.d/filename
#Update and upgrade the system
# Make sure to listen to what's happening. Something important might require your verification.
sudo apt-get update
sudo apt-get dist-upgrade -y
sudo apt-get install -f -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get check
#Get packages to be used later in this checklist
sudo apt-get -V -y install firefox chkrootkit ufw gufw clamav
#Delete telnet
sudo apt-get purge telnet
#Enable automatic updates (credit) In the GUI set Update Manager->Settings->Updates->Check for updates:->Daily.
#Optional: If the README wants administrators to use sudo
sudo usermod -l root
#Disable login as root in sshd config
# Make sure openssh-server is installed before doing this.
sudo nano /etc/ssh/sshd_config
# Look for PermitRootLogin, replace "PermitRootLogin" with "PermitRootLogin no" without quotes
sudo service ssh restart
#Optional: If the README says it doesn't want openssh-server or ftp
sudo apt-get -y purge openssh-server* 
sudo apt-get -y purge vsftpd*
#Remove common malware (credit)
sudo apt-get -y purge hydra*
sudo apt-get -y purge john* #John the Ripper, brute forcing software
sudo apt-get -y purge nikto* #Website pentesting
sudo apt-get -y purge netcat* #Scans open ports, installed by default?
Check for prohibited files
# You MUST paste this into a bash or sh file to run.
for suffix in mp3 txt wav wma aac mp4 mov avi gif jpg png bmp img exe msi bat sh
do
  sudo find /home -name *.$suffix
done
echo "Finding Media Files"
echo "||||Video Files||||" >> /var/local/mediafiles.log
locate *.mkv *.webm *.flv *.vob *.ogv *.drc *.gifv *.mng *.avi$ *.mov *.qt *.wmv *.yuv *.rm *.rmvb *.asf *.amv *.mp4$ *.m4v *.mp *.m?v *.svi *.3gp *.flv *.f4v >> /var/local/mediafiles.log
echo "||||Audo Files||||" >> /var/local/mediafiles.log
locate *.3ga *.aac *.aiff *.amr *.ape *.arf *.asf *.asx *.cda *.dvf *.flac *.gp4 *.gp5 *.gpx *.logic *.m4a *.m4b *.m4p *.midi *.mp3 *.pcm *.rec *.snd *.sng *.uax *.wav *.wma *.wpl *.zab >> /var/local/mediafiles.log
#Optional: If your README wants it, harden VSFTPD (credit)
# Disable anonymous uploads
sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
# FTP user directories use chroot
sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
sudo service vsftpd restart
#Enforce passwords
PASS_MIN_DAYS 7
PASS_MAX_DAYS 90
PASS_WARN_AGE 14
#Password authentication (credit)
# Be VERY careful running anything that edits PAM configs. You could get locked out of everything!
sudo sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
#Force strong passwords (credit)
sudo apt-get -y install libpam-cracklib
sudo sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password
#Check the crontab for malware or unauthorized actions
# Do this as root and as every user.
# As you:
crontab -e
# As root:
sudo crontab -e
# As another user:
sudo su - user
crontab -e
#Check host and nameservers
# Make sure it looks something like "nameservers x.x.x.x". Try using 8.8.8.8
sudo nano /etc/resolv.conf
# Make sure your traffic isn't redirecting
sudo nano /etc/hosts
#Check sudoers for wrongdoings
# There should be no "NOPASSWD"
sudo visudo
# Make sure all administrators are in group sudo, look for unauthorized users
sudo ls /etc/sudoers.d/
#Install rootkit and malware scanning tools (credit)
sudo apt-get install -y chkrootkit rkhunter
# rkhunter usage:
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter -c --enable all --disable none
# chkrootkit usage:
sudo chkrootkit -q
# Visit http://www.chkrootkit.org/README for more
# clamav usage:
# Update clamav
sudo freshclam
# Scan a directory recursively and ring a bell if something is found
clamscan -r --bell -i /home/user/
# Scan the whole system (NOT recommended!)
clamscan -r --remove /
# Safest option:
sudo apt-get install clamtk
sudo clamtk
#Optional: Secure apache
#Optional: Run Lynis AV (credit)
wget https://downloads.cisofy.com/lynis/lynis-2.6.9.tar.gz -O lynis.tar.gz
sudo tar -xzf ./lynis.tar.gz --directory /usr/share/
cd /usr/share/lynis
/usr/share/lynis/lynis update info
/usr/share/lynis/lynis audit system
#Secure sysctl (credit)
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -p
#Look through running processes
ps -ax
htop
#Check config files for important services, there's almost always atleast one point (MySQL, SSH, Apache, README software)
#Look for illegitimate services
sudo service --status-all
#Check the installed packages list for hacking tools
apt list --installed
#Stop services (credit)
# DO NOT STOP ALL OF THESE WITHOUT READING THE README OR UNDERSTANDING WHAT YOU'RE ABOUT TO DO!
service sshd stop
service telnet stop # Remote Desktop Protocol
service vsftpd stop # FTP server
service snmp stop # Type of email server
service pop3 stop # Type of email server
service icmp stop # Router communication protocol
service sendmail stop # Type of email server
service dovecot stop # Type of email server
service --status-all | grep "+" # shows programs with a return code of 0 (C/C++ users will understand), which is non-native programs


#Disable Remote Desktop