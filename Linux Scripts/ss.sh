ufw deny netbios-ns
ufw deny netbios-dgm
ufw deny netbios-ssn
ufw deny microsoft-ds
apt-get -y -qq purge samba
apt-get -y -qq purge samba-common
apt-get -y -qq purge samba-common-bin
apt-get -y -qq purge samba4
ufw deny telnet 
ufw deny rtelnet 
ufw deny telnets
apt-get -y -qq purge telnet
apt-get -y -qq purge telnetd
apt-get -y -qq purge inetutils-telnetd
apt-get -y -qq purge telnetd-ssl
echo "Telnet port has been denied on the firewall and Telnet has been removed."
ufw deny smtp 
ufw deny pop2 
ufw deny pop3
ufw deny imap2 
ufw deny imaps 
ufw deny pop3s
apt-get -y -qq purge sendmail
apt-get -y -qq purge dovecot*
echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
ufw deny ms-sql-s 
ufw deny ms-sql-m 
ufw deny mysql
ufw deny mysql-proxy
ufw deny postgresql*
apt-get -y -qq purge mysql
apt-get -y -qq purge mysql-client-core-5.5
apt-get -y -qq purge mysql-client-core-5.6
apt-get -y -qq purge mysql-common-5.5
apt-get -y -qq purge mysql-common-5.6
apt-get -y -qq purge mysql-server
apt-get -y -qq purge mysql-server-5.5
apt-get -y -qq purge mysql-server-5.6
apt-get -y -qq purge mysql-client-5.5
apt-get -y -qq purge mysql-client-5.6
apt-get -y -qq purge mysql-server-core-5.6
apt-get -y -qq purge postgresql
echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL and postgresql have been removed."
ufw deny http
ufw deny https
apt-get -y -qq purge apache2
rm -r /var/www/*
echo "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
ufw deny domain
apt-get -y -qq purge bind9
echo "domain port has been denied on the firewall. DNS name binding has been removed."
	