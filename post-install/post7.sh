#!/bin/bash
###		RHEL 7.x  customization script
###		Created and edited by Okan
###		29/03/2016

DATE_NOW=$(date +"%y%m%d_%H%M%S")

BASHRC_CONF_FILE="/etc/bashrc"
IPV6_CONF_FILE="/etc/modprobe.d/ipv6.conf"
SYSCTL_CONF_FILE="/etc/sysctl.conf"
SUDOERS_CONF_FILE="/etc/sudoers"
SSH_KEY_FILE="/home/user/.ssh/authorized_keys"
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOX41YRHsOu98Wj1Uqq+XqiyBQ4aMwiYZmCmbgoCfOwgl0l2YmfIUmPZO7YbF4hM+eNMlpMYmeQBakKfrdk+T8Vr9mR9J4UxyDhyqK4nceyc+iMF7LcS3xsc+dJ60nhZTen3As4lhYJxrxTvtfT8XVXNj60s/c6qmVHJBHkmaQyfuEkYWBL67m9AxVe4pkq5sjF5DFpI/T6BjhuxZe60UVJPj9fXy2aC+Zj5Mer6kNkElGJtSi2H+WY9uxbvlbDnQbZ7os0RtKMIeKR3+HWIbu8Hyh5r6/eGPdD/MfGF7x2qVTMD5/zgMyKhEX4yWnv7Xd/jmnISG4VP8g0OTOj77t root@o -linuxpc"


RESOLVCONF_FILE="/etc/resolv.conf"
RESOLVCONF="
domain xxxx.com.tr
search xxxx.com.tr
nameserver IP.IP
nameserver IP.IP
"


NTP_CONF_FILE="/etc/chrony.conf"
NTP_CONF="
# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
#server 0.rhel.pool.ntp.org iburst
#server 1.rhel.pool.ntp.org iburst
#server 2.rhel.pool.ntp.org iburst
#server 3.rhel.pool.ntp.org iburst

# Ignore stratum in source selection.
stratumweight 0

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Enable kernel RTC synchronization.
rtcsync

# In first three updates step the system clock instead of slew
# if the adjustment is larger than 10 seconds.
makestep 10 3

# Allow NTP client access from local network.
#allow 192.168/16

# Listen for commands only on localhost.
bindcmdaddress 127.0.0.1
bindcmdaddress ::1

# Serve time even if not synchronized to any NTP server.
#local stratum 10

keyfile /etc/chrony.keys

# Specify the key used as password for chronyc.
commandkey 1

# Generate command key if missing.
generatecommandkey

# Disable logging of client accesses.
noclientlog

# Send a message to syslog if a clock adjustment is larger than 0.5 seconds.
logchange 0.5

logdir /var/log/chrony
#log measurements statistics tracking

server IP.IP iburst
server IP.IP iburst


"


SELINUX_CONF_FILE="/etc/sysconfig/selinux"
SELINUX_CONF="
SELINUX=disabled
SELINUXTYPE=targeted
"


PAMD_CONF_FILE="/etc/pam.d/system-auth"
PAMD_CONF='
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_fprintd.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

#password    requisite     pam_cracklib.so try_first_pass retry=3 type=
#password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1	lcredit=-1 reject_username
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=10

password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
'


LOGINDEFS_CONF_FILE="/etc/login.defs"
LOGINDEFS_CONF='
#
# Please note that the parameters in this configuration file control the
# behavior of the tools from the shadow-utils component. None of these
# tools uses the PAM mechanism, and the utilities that use PAM (such as the
# passwd command) should therefore be configured elsewhere. Refer to
# /etc/pam.d/system-auth for more information.
#

# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR	Maildir
MAIL_DIR	/var/spool/mail
#MAIL_FILE	.mail

# Password aging controls:
#
#	PASS_MAX_DAYS	Maximum number of days a password may be used.
#	PASS_MIN_DAYS	Minimum number of days allowed between password changes.
#	PASS_MIN_LEN	Minimum acceptable password length.
#	PASS_WARN_AGE	Number of days warning given before a password expires.
#
PASS_MAX_DAYS	45
PASS_MIN_DAYS	2
PASS_MIN_LEN	5
PASS_WARN_AGE	7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN			  500
UID_MAX			60000

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN			  500
GID_MAX			60000

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD	/usr/sbin/userdel_local

#
# If useradd should create home directories for users by default
# On RH systems, we do. This option is overridden with the -m flag on
# useradd command line.
#
CREATE_HOME	yes

# The permission mask is initialized to this value. If not specified,
# the permission mask will be initialized to 022.
UMASK           077

# This enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

# Use SHA512 to encrypt password.
ENCRYPT_METHOD SHA512

'


SSHD_CONF_FILE="/etc/ssh/sshd_config"
SSHD_CONF='

#       $OpenBSD: sshd_config,v 1.80 2008/07/02 02:24:18 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options change a
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

# Disable legacy (protocol version 1) support in the server for new
# installations. In future the default will change to require explicit
# activation of protocol 1
Protocol 2

# HostKey for protocol version 1
#HostKey /etc/ssh/ssh_host_key
# HostKeys for protocol version 2
#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_dsa_key

# Lifetime and size of ephemeral version 1 server key
#KeyRegenerationInterval 1h
#ServerKeyBits 1024

# Logging
# obsoletes QuietMode and FascistLogging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#RSAAuthentication yes
#PubkeyAuthentication yes
#AuthorizedKeysFile     .ssh/authorized_keys
#AuthorizedKeysCommand none
#AuthorizedKeysCommandRunAs nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#RhostsRSAAuthentication no
# similar for protocol version 2
#HostbasedAuthentication no
# Change to yes if you dont trust ~/.ssh/known_hosts for
# RhostsRSAAuthentication and HostbasedAuthentication
#IgnoreUserKnownHosts no
# Dont read the users ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no
PasswordAuthentication yes

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
#GSSAPIAuthentication no
GSSAPIAuthentication yes
#GSSAPICleanupCredentials yes
GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to yes to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to no.
#UsePAM no
UsePAM yes

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#UsePrivilegeSeparation yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#ShowPatchLevel no
#UseDNS yes
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    /usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       ForceCommand cvs server


ClientAliveInterval 300
ClientAliveCountMax 2
'


MOTD_CONF_FILE="/etc/motd"
MOTD_CONF='
###########################################################################################################
#                                           !!! UYARI MESAJI !!!                                          #
#                                                                                                         #
#  xxxx Bilgi Guvenligi Politikalari geregi bu sistemde  yapacaginiz her turlu islem kayit altina     #
#  alinmaktadir. Yapilacak her turlu yetkisiz islemler, islemi yapana yazili/sozlu uyari verilmesi,       #
#  xxxx daki isine son verilmesine ve/veya aleyhinde ADLI VE CEZAI yasal islemler baslatilmasina      #
#  varincaya kadar cesitli disiplin islemleriyle sonuclanabilir.                                          #
#                                                                                                         #
#                                           !!! WARNING MESSAGE !!!                                       #
#                                                                                                         #
#  According to xxxx Information Security Policies, all activities are logged and monitored.          #
#  Misuse or unauthorized activities may result in legal prosecution or penalties.                        #
#                                                                                                         #
###########################################################################################################
'


RSYSLOG_CONF_FILE="/etc/rsyslog.conf"
RSYSLOG_CONF='
$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)
$ModLoad imklog   # provides kernel logging support (previously done by rklogd)
#$ModLoad immark  # provides --MARK-- message capability
#$ModLoad imudp
#$UDPServerRun 514
#$ModLoad imtcp
#$InputTCPServerRun 514
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
#$ActionFileEnableSync on
$IncludeConfig /etc/rsyslog.d/*.conf
#kern.*                                                 /dev/console
*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
##authpriv.*                                              @@servervm-arcscon1:514
mail.*                                                  -/var/log/maillog
cron.*                                                  /var/log/cron
*.emerg                                                 *
uucp,news.crit                                          /var/log/spooler
local7.*                                                /var/log/boot.log
##*.*							@@servervm-arcscon1:514
$WorkDiretory /var/lib/rsyslog # where to place spool files
$WorkDiretory /var/lib/rsyslog # where to place spool files
$ActionQueueFileName fwdRule1 # unique name prefix for spool files
$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
$ActionQueueType LinkedList   # run asynchronously
$ActionResumeRetryCount -1    # infinite retries if host is down
#*.* @@remote-host:514
$template SpiceTmpl,"%TIMESTAMP%.%TIMESTAMP:::date-subseconds% %syslogtag% %syslogseverity-text%:%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"
:programname, startswith, "spice-vdagent"	/var/log/spice-vdagent.log;SpiceTmpl
'


function set_rsyslog {
	cp ${RSYSLOG_CONF_FILE} ${RSYSLOG_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$RSYSLOG_CONF" > $RSYSLOG_CONF_FILE
}


function set_bashrc {
	cp ${BASHRC_CONF_FILE} ${BASHRC_CONF_FILE}_BCK_$DATE_NOW
	grep -q '^export HISTTIMEFORMAT' $BASHRC_CONF_FILE || echo -e '\nexport HISTTIMEFORMAT="%d/%m/%y %T "' >> $BASHRC_CONF_FILE
	grep -q '^alias vi=vim' $BASHRC_CONF_FILE || echo -e '\nalias vi=vim' >> $BASHRC_CONF_FILE
}


function set_sshd {
	cp ${SSHD_CONF_FILE} ${SSHD_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$SSHD_CONF" > $SSHD_CONF_FILE
}


function set_resolvconf {
    cp ${RESOLVCONF_FILE} ${RESOLVCONF_FILE}_BCK_$DATE_NOW
	echo -e "$RESOLVCONF" > $RESOLVCONF_FILE
}


function set_ntp {
    cp ${NTP_CONF_FILE} ${NTP_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$NTP_CONF" > $NTP_CONF_FILE
	echo -e "\n" >> /root/crontab_BCK_$DATE_NOW ;crontab -l >> /root/crontab_BCK_$DATE_NOW
	echo "* */2 * * * systemctl stop chronyd; ntpdate server-dc1.xxxx.com.tr; ntpdate server-dc1.xxxx.com.tr; systemctl start chronyd" | crontab -
	echo "OPTIONS=-4" > /etc/sysconfig/chronyd
	systemctl enable chronyd
	systemctl restart chronyd
	ntpdate server-dc1.xxxx.com.tr
	sleep 10
	chronyc tracking
}


function set_iptables {
	systemctl stop firewalld.service
	systemctl disable firewalld.service
}


function set_ip6tables {
	cp ${IPV6_CONF_FILE} ${IPV6_CONF_FILE}_BCK_$DATE_NOW
	echo 'options ipv6 disable=1' > $IPV6_CONF_FILE
	cp ${SYSCTL_CONF_FILE} ${SYSCTL_CONF_FILE}_BCK_$DATE_NOW
	grep -q '^net.ipv6.conf.all.disable_ipv6' $SYSCTL_CONF_FILE && sed -i 's/net.ipv6.conf.all.disable_ipv6=.*/net.ipv6.conf.all.disable_ipv6=1/g' $SYSCTL_CONF_FILE || echo -e '\nnet.ipv6.conf.all.disable_ipv6=1' >> $SYSCTL_CONF_FILE
    systemctl stop ip6tables.service
    systemctl disable ip6tables.service

}


function set_selinux {
	cp ${SELINUX_CONF_FILE} ${SELINUX_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$SELINUX_CONF" > $SELINUX_CONF_FILE
}


function set_networkmanager {
	systemctl stop NetworkManager.service
	systemctl disable NetworkManager.service
}


function set_pamd {
    cp ${PAMD_CONF_FILE} ${PAMD_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$PAMD_CONF" > $PAMD_CONF_FILE
}


function set_logindefs {
    cp ${LOGINDEFS_CONF_FILE} ${LOGINDEFS_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$LOGINDEFS_CONF" > $LOGINDEFS_CONF_FILE
}


function set_motd {
	cp ${MOTD_CONF_FILE} ${MOTD_CONF_FILE}_BCK_$DATE_NOW
	echo -e "$MOTD_CONF" > $MOTD_CONF_FILE
}


function set_simpana {
	groupadd simpana
	wget --no-check-certificate -O /opt/simpana_linux64.tar.gz https://IP.IP/ks/3rd_Party/simpana_linux64.tar.gz
	tar zxvf /opt/simpana_linux64.tar.gz -C /
	sed -i 's/<OsDisplayInfo OSBuild=.*>/<OsDisplayInfo OSBuild="'$(uname -r)'" OSName="Linux" ProcessorType="x86_64">/g' /opt/UnixCustomPackage/pkg/rec/default.xml
	/opt/UnixCustomPackage/pkg/silent_install -param /opt/UnixCustomPackage/pkg/rec/default.xml
	rm /opt/simpana_linux64.tar.gz
}


function set_hpovo {
	wget --no-check-certificate -O /opt/hpovo_linux_v11.13.tar.gz https://IP.IP/ks/3rd_Party/hpovo_linux_v11.13.tar.gz
	tar zxvf /opt/hpovo_linux_v11.13.tar.gz -C /opt/
	chmod -R 755 /opt/Linux_v11.13/*
	/opt/Linux_v11.13/oainstall.sh -i -a -includeupdates -minprecheck -s servervm-hpomo1.xxxx.com.tr -cs servervm-hpomo1.xxxx.com.tr
	rm /opt/hpovo_linux_v11.13.tar.gz
}


function set_kexec {
	wget --no-check-certificate -O /usr/local/bin/kexec-reboot https://IP.IP/ks/scripts/kexec-reboot.sh
	wget --no-check-certificate -O /usr/local/bin/kexec-reboot-latest https://IP.IP/ks/scripts/kexec-reboot-latest.sh
	chmod 755 /usr/local/bin/kexec-reboot
	chmod 755 /usr/local/bin/kexec-reboot-latest
}


function set_registration {
	wget --no-check-certificate -O /opt/candlepin-cert-consumer-latest.noarch.rpm  https://IP.IP/pub/candlepin-cert-consumer-latest.noarch.rpm
	rpm -ivh /opt/candlepin-cert-consumer-latest.noarch.rpm
	subscription-manager unregister
	subscription-manager register --org xxxx --user admin --pass admin
}


function set_updates {
        grep -q '^sslverify=0' /etc/yum.conf || echo -e '\nsslverify=0' >> /etc/yum.conf
        subscription-manager attach --pool 8a6095be522565db01523156d15b4129
	yum repolist
	yum update --exclude=kernel* --exclude=redhat-release* -y
}


function set_remove_subscription_only {
	subscription-manager remove --all
	rm -f /opt/candlepin-cert-consumer-latest.noarch.rpm
}


function set_admin_users {
	cp ${SUDOERS_CONF_FILE} ${SUDOERS_CONF_FILE}_BCK_$DATE_NOW
	grep -q '^%wheel  ALL=(ALL)       NOPASSWD: ALL' ${SUDOERS_CONF_FILE} || echo "%wheel  ALL=(ALL)       NOPASSWD: ALL" >> ${SUDOERS_CONF_FILE}
	useradd -G wheel -c "xxxx System Administration Group" user
	echo 'user:$6$/CV/fVo.Bk7Pt1cG$BGsEU7rgkBoyLuJpfWeWrFGb0SpxQI8BNxdPixgV64bXxYwdM0nt.B9zulmxrxlsNEl6ggEIhZeMRXpik1b9D.' | chpasswd --encrypted
	chage -I -1 -m 0 -M 99999 -E -1 user
}


function open_rsyslog_prod {
	sed -i 's/##authpriv.*                                              @@servervm-arcscon1:514/authpriv.*                                              @@servervm-arcscon1:514/g' ${RSYSLOG_CONF_FILE}
	systemctl restart rsyslog.service
}


function remove_custom_rpms {
	yum -y erase avahi
	yum -y erase NetworkManager
	yum -y erase ntp
}


function install_custom_rpms {
	# some utilities
	yum -y install expect ftp ksh mksh rsh ruby-irb screen telnet gcc gcc-c++ dos2unix sg3_utils sysfsutils aide
	# xforwarding
	yum -y install xauth xclock xorg-x11-utils xhost
	# fuse-sshfs
	yum install -y fuse fuse-libs
	# mail client
	yum -y install sendmail sendmail-cf
}


function install_powerpath {
	if [ ! "$(virt-what)" ]; then
		wget --no-check-certificate https://servervm-rhasset1/ks/3rd_Party/emc/emc-powerpath-rhel7.repo -O /etc/yum.repos.d/emc-powerpath-rhel7.repo
		grep -q '^sslverify=0' /etc/yum.conf || echo -e '\nsslverify=0' >> /etc/yum.conf
		yum clean all
		yum repolist
		yum install -y EMCpower.LINUX.x86_64
	fi

}

function install_hpfirmware {
	if [ ! "$(virt-what)" ]; then
		# install hpfirmware
		echo ""
	fi

}


function add_custom_repo {
        grep -q '^sslverify=0' /etc/yum.conf || echo -e '\nsslverify=0' >> /etc/yum.conf
        wget --no-check-certificate https://servervm-rhasset1/ks/3rd_Party/custom/custom-repo-rhel7.repo -O /etc/yum.repos.d/custom-repo-rhel7.repo
        yum clean all
        yum repolist
}


function add_ssh_key {
	if [ ! -d $(dirname $SSH_KEY_FILE) ]; then
		mkdir $(dirname $SSH_KEY_FILE)
	fi

	if [ -f $SSH_KEY_FILE ]; then
		grep -q "$SSH_KEY" $SSH_KEY_FILE || echo "$SSH_KEY" >> $SSH_KEY_FILE
	else
		echo "$SSH_KEY" >> $SSH_KEY_FILE
	fi
}

function first_time_test {
	set_iptables
	set_ip6tables
	set_resolvconf
	set_sshd
	set_bashrc
	set_selinux
	set_networkmanager
	set_pamd
	set_logindefs
	set_motd
	set_rsyslog
	set_admin_users
	set_registration
	set_updates
	set_remove_subscription_only
	set_kexec
	remove_custom_rpms
	install_custom_rpms
	install_powerpath
	install_hpfirmware
#	add_ssh_key
	add_custom_repo
	set_ntp
}


function first_time_prod {
	first_time_test
	open_rsyslog_prod
	set_simpana
	set_hpovo
}


key="$1"

case $key in
    --firsttime-prod)
		first_time_prod
    ;;
    --firsttime-test)
        first_time_test
    ;;
    *)
        echo -e "No parameter given..."
    ;;
esac
