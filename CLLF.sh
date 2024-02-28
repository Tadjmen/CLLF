#!/bin/bash
# coded by XuanMike - XM1945
# C - version 1.1
# CLLF - Collect Linux Logs Forensic

sed -i 's/ = /=/' CLLF.config
source CLLF.config


#@> COLORS
BK="\e[7m"
NORMAL="\e[0m"
RED="\e[31m"
YELLOW="\e[93m"
GREEN="\e[32m"


#@> Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root"
  exit
fi


#@> EXIT FUNCTION
trap ctrl_c INT
ctrl_c(){
    echo -e ""
    echo -e "${YELLOW} [!] ${NORMAL} KEYBOARD INTERRUPTION, ${GREEN}EXITING CLLF${NORMAL}..."
    exit 127
}

#@> Print BANNER
BANNER(){
    clear
    echo -e ""
    echo -e "${YELLOW}

                ░█████╗░██╗░░░░░██╗░░░░░███████╗
                ██╔══██╗██║░░░░░██║░░░░░██╔════╝
                ██║░░╚═╝██║░░░░░██║░░░░░█████╗░░
                ██║░░██╗██║░░░░░██║░░░░░██╔══╝░░
                ╚█████╔╝███████╗███████╗██║░░░░░
                ░╚════╝░╚══════╝╚══════╝╚═╝░░░░░

${NORMAL}"
    echo -e "[${YELLOW}CLLF${NORMAL}] == A Collecter Collect Linux Logs Forensic by (${BK}XM${NORMAL})"
}



#> PRINT USAGE
PRINTUSAGE(){
    echo -e ""
    echo -e "[${BOLD}CLLF${NORMAL}] - Release by ${BOLD}XM${NORMAL} with ${RED}<3${NORMAL}\n"
    echo -e "Syntax Usage:"
    echo -e "./CLLF.sh [-l log.op] [Just run with root]"
    echo -e ""
    #echo -e "Flags:"
	#echo -e "   -l, --log						Logs collect options                    -l full"
	#echo -e "          \"${GREEN}full${NORMAL}\" is Full folder /var/log (Maybe so big...)"
	#echo -e "          \"${GREEN}lite${NORMAL}\" is Common Linux log files names and usage"
    #echo -e ""
    #echo -e "Optional Flags:"
	#echo -e "   -o, --OUTDIR						Write to output folder                  -o \"10.0.1.134\""
    #echo -e "   -s, --silent                            Hide output in the terminal             ${GREEN}Default: ${RED}False${NORMAL}"
	echo -e "Example Usage:"
    echo -e "${BK}./CLLF.sh -l full -o 10.0.1.134${NORMAL}"
    exit 0
}

#> ARGUMENT FLAGS
while [ -n "$1" ]; do
    case $1 in
            -h|--help)
                PRINTUSAGE
                shift ;;
            *)
                PRINTUSAGE
    esac
    shift
done



mkdir $OUTDIR
cd $OUTDIR
touch err


#@> GET SYSTEM INFO
GET_SYSTEM_INFO(){
    #
    # @desc   :: This function saves SYSTEM_INFO
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing SYSTEM_INFO... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYSTEM_INFO && cd SYSTEM_INFO
	echo "      Collecting Basic Info..."
	whoami > "whoami.txt" 2>> ../err
	uptime > "uptime.txt" 2>> ../err
	ip a > "ipconfig.txt" 2>> ../err
	hostname > "hostname.txt" 2>> ../err
	uname -a > "uname.txt" 2>> ../err
	cat /proc/cpuinfo > "cpuinfo.txt" 2>> ../err
	cat /proc/meminfo > "meminfo.txt" 2>> ../err
	cat /proc/version> "version.txt" 2>> ../err
 	ls -lah /var/log/ > "var_log_directory_listing.txt" 2>> ../err
	printenv > "printenv.txt" 2>> ../err
	set > "set.txt" 2>> ../err
	#This saves loaded modules
	lsmod > "lsmod.txt" 2>> ../err
	cat /proc/modules > "proc_modules.txt" 2>> ../err
	echo "      Collecting modules info..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do echo -e "\nModule: $i"; modinfo $i ; done > modules_info.txt 2>> ../err
	echo "      Collecting hash loaded modules..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do modinfo $i | grep "filename:" | awk '{print $2}' | xargs -I{} sha1sum {} ; done > modules_sha1.txt 2>> ../err
	#Sudo version
	sudo -V "Sudo_Ver.txt" 2>> ../err
	echo "      Collecting mount..."
	mount > mount.txt 2>> ../err
	
	if $get_metadatatime; then
		if which stat &>/dev/null; then
			echo "      Collecting ALL metadata system Time - Just wait..."
			echo -e "Permission,uOwner,gOwner,Size, File Name,Create Time, Access Time, Modify Time, Status Change Time" > metadata-ALLtimes.csv | find / -exec sh -c 'if [ $(find "$1" -maxdepth 1 -type f | wc -l) -le 1000 ]; then stat --printf="%A,%U,%G,%s,%n,%w,%x,%y,%z\n" "$1"; fi' sh {} \; >> metadata-ALLtimes.csv 2>> ../err
		else 
			echo "      Collecting metadata-accesstimes..."
			find / -printf "%CY-%Cm-%Cd %CT,%M,%s,%u,%g,%h,%f\n" > metadata-accesstimes.csv 2>> ../err
		fi
	else
		echo "      NOT Collect metadata-accesstimes..."
	fi

	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: SYSTEM_INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET DISK
GET_DISK(){
    #
    # @desc   :: This function saves disks state
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing disks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir DISKS && cd DISKS
	echo "      Collecting Disk tree, LVM, Disk Usage, Free Disks,  ..."
	fdisk -l > "fdisk.txt" 2>> ../err
	df -h > "df_h.txt" 2>> ../err
	findmnt -a -A > "findmnt.txt" 2>> ../err
	vgdisplay -v > "vgdisplay.txt" 2>> ../err
	lvdisplay -v > "lvdisplay.txt" 2>> ../err
	vgs --all > "vgs.txt" 2>> ../err
	lvs --all > "lvs.txt" 2>> ../err
	free > "free.txt" 2>> ../err
	cat /proc/partitions > "proc_partitions.txt" 2>> ../err
	du > "du.txt" 2>> ../err
	echo "      Collecting fstab  ..."
	cat /etc/fstab > "fstab.txt" 2>> ../err
	cat /etc/mtab > "mtab.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Disks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET PACKAGES
GET_PACKAGES(){
    #
    # @desc   :: This function saves all installed packages
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing packages ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PACKAGES && cd PACKAGES
	echo "      Verifying installed package info..."
	
	if which dpkg &>/dev/null; then
		if $verify_package; then
			dpkg -V > deb-package-verify.txt
		fi
		echo "      List installed package by APT..."
		apt list --installed > "apt_list_installed.txt" 2>> ../err
		echo "      List installed package ..."
		dpkg -l > "dpkg_l.txt" 2>> ../err
		dpkg-query -l > "dpkg_query.txt" 2>> ../err
	else 
		if $verify_package; then
			rpm -qVa > rpm-package-verify.txt
		fi
		echo "      List installed package by yum, dnf..."
  		if which yum &>/dev/null; then
			yum list installed > "yum_list_installed.txt" 2>> ../err
   		else
			dnf list installed > "dnf_list_installed.txt" 2>> ../err
   		fi
		rpm -qa > "rpm_qa.txt" 2>> ../err
		rpm -Va > "rpm_Va.txt" 2>> ../err
	fi
	
	echo "      Collecting snap list  ..."
	snap list > "snap_list.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Packages  are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET ACCOUNT
GET_ACCOUNT(){
    #
    # @desc   :: This function saves users and groups
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing users and groups ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir ACCOUNTS && cd ACCOUNTS
	echo "      Collecting passwd, shadow, group  ..."
	cat /etc/passwd | cut -d: -f1,3,4,5,6,7 | grep -vE '(nologin|halt|false|shutdown|sync)' | sort > "etc_passwd_login.txt" 2>> ../err
	cat /etc/passwd | cut -d: -f1,3,4,5,6,7 | grep -E '(nologin|halt|false|shutdown|sync)' | sort > "etc_passwd_nologin.txt" 2>> ../err
	cat /etc/sudoers > "etc_sudoers.txt" 2>> ../err
	cat /etc/group > "etc_group.txt" 2>> ../err
	cat /etc/shadow > "etc_shadow.txt" 2>> ../err
	cat /etc/gshadow > "etc_gshadow.txt" 2>> ../err
	echo "      Collecting information about users who are currently logged in  ..."
	who -alpu > "who_alpu.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Accounts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET PROCESS
GET_PROCESS(){
    #
    # @desc   :: This function saves running process
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing process ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PROCESS && cd PROCESS
	echo "      Collecting pstree, Information of running process  ..."
	pstree > "pstree.txt" 2>> ../err
	ps faux > "ps_faux.txt" 2>> ../err
	top -H -b -n 1 > "top.txt" 2>> ../err
	echo "      Collecting the process hashes..."
	find -L /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > Running-processhashes.txt 2>> ../err
	echo "      Collecting the process symbolic links..."
	find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > Running-process-exe-links.txt 2>> ../err
	echo "      Collecting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > Running-process-cmdline.txt 2>> ../err
	echo "      Collecting Run-time variable data..."
	ls -latr /var/run 2>/dev/null > TEMP-VAR_RUN.txt 2>> ../err
	ls -latr /run 2>/dev/null > TEMP-RUN.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Process are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET SERVICES
GET_SERVICES(){
    #
    # @desc   :: This function saves services
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing services ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SERVICES && cd SERVICES
	echo "      Collecting Information of running services..."
	systemctl list-units --all > "systemctl_list_units.txt" 2>> ../err
	(ls -la /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "ls_systemd_system.txt" 2>> ../err
	echo "      Collecting status ALL services..."
	service --status-all > "service_status_all.txt" 2>> ../err
	
	if which chkconfig &>/dev/null; then
		chkconfig --list > "chkconfig.txt" 2>> ../err
	fi
	
	echo "      Collecting list services per Status..."
	systemctl --type=service --state=failed > "systemctl_services_failed.txt" 2>> ../err
	systemctl --type=service --state=active > "systemctl_services_active.txt" 2>> ../err
	systemctl --type=service --state=running > "systemctl_services_running.txt" 2>> ../err
	ls -l /etc/init.d/* > "ls_etc_initd.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: services are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET OPENED PORTS
GET_OPENED_PORTS(){
    #
    # @desc   :: This function saves opened ports
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing ports ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PORTS && cd PORTS
	echo "      Collecting OPENED PORTS..."
	ss --all > "ss_all.txt" 2>> ../err
	ss -lntu > "ss_lntu.txt" 2>> ../err
	netstat -a > "netstat_a.txt" 2>> ../err
	netstat -lntu > "netstat_lntu.txt" 2>> ../err
	
	if which lsof &>/dev/null; then
		echo "      Collecting List open files..."
		lsof -i -n -P > "lsof.txt" 2>> ../err
	fi
	
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: ports are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET NETWORK INFO
GET_NETWORK_INFO(){
    #
    # @desc   :: This function saves network INFO statistics
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing NETWORK INFO ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir NETWORK_INFO && cd NETWORK_INFO
	# IP
	echo "      Collecting IP Address, RX, TX packets..."
	ip -s -s link > "all_rx_tx_packets.txt" 2>> ../err
	ip addr > "ip_addr.txt" 2>> ../err
	# Other
	echo "      Collecting Kernel Interface table..."
	netstat -i > "netstat_i.txt" 2>> ../err
	nmcli device status > "nmcli_device_status.txt" 2>> ../err
	#  information on the hardware configuration
	echo "      Collecting hardware configuration..."
	lshw -class network -short > "lshw.txt" 2>> ../err
	
	if which hwinfo &>/dev/null; then
		echo "      Collecting hardware Info..."
		hwinfo --short --network > "hwinfo.txt" 2>> ../err
	fi
	
	echo "      Collecting Host configuration Network..."
	cat /etc/hosts > "etc_hosts.txt" 2>> ../err
	cat /etc/hosts.allow > "etc_hosts_allow.txt" 2>> ../err
	#Get routing table
	echo "      Collecting Routing Table..."
	
	if ip route &>/dev/null; then
		ip route > Network-routetable.txt 2>> ../err
	else
		netstat -rn > Network-routetable.txt 2>> ../err
	fi
		
	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "      Collecting IPtables..."
		iptables -L -n -v --line-numbers > "iptables_Full.txt" 2>> ../err
		iptables -L > "iptables.txt" 2>> ../err
	fi

	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "      Collecting IP6tables..."
		ip6tables -L -n -v > "ip6tables_Full.txt" 2>> ../err
	fi
	
	#Get UFW status
	if which ufw &>/dev/null; then
		echo "      Collecting UFW status..."
		ufw status verbose > "UFW_status.txt" 2>> ../err
	fi
	
	#Get firewall-cmd information
	if which firewall-cmd &>/dev/null; then
		echo "      Collecting firewall-cmd status..."
		firewall-cmd --list-services > "firewall_cmd_list_services.txt" 2>> ../err
		firewall-cmd --list-all > "firewall_cmd_list_all.txt" 2>> ../err
		firewall-cmd --list-ports > "firewall_cmd_list_ports.txt" 2>> ../err
	fi


	#Get SeLinux Verbose information
	if which sestatus &>/dev/null; then
		echo "      Collecting SELinux status..."
		sestatus -v > SELinux-selinux.txt 2>> ../err
		echo "      Collecting SELinux booleans..."
		getsebool -a > SELinux-booleans.txt 2>> ../err
	fi

	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: NETWORK INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET schedule_tasks
GET_TASKS(){
    #
    # @desc   :: This function saves scheduled tasks (servicse, cron, rc, .profile ...)
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing tasks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SCHEDULE_TASKS && cd SCHEDULE_TASKS
	echo "      Collecting Task Scheduler..."
	(cat /etc/*cron**/* /etc/cron* /var/spool/**/cron*) > "ALL_cron.txt" 2>> ../err
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l | grep -v "^#"; done > "cron_per_User.txt" 2>> ../err
	(cat /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "systemd.txt" 2>> ../err
	(cat /etc/rc*.d**/* /etc/rc.local*) > "rc.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: tasks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET FULL hidden home files
GET_HIDDEN_HOME_FILE(){
    #
    # @desc   :: This function saves scheduled tasks (servicse, cron, rc, .profile ...)
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing GET FULL hidden home files ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir HIDDEN_HOME_FILES && cd HIDDEN_HOME_FILES
	echo "      Collecting hidden home files..."
	grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f6 -d ':' | xargs -I {} find {} ! -path {} -prune -name .\* -print0 2>> ../err | xargs -0 tar -czvf hidden-user-home-dir.tar.gz  > hidden-user-home-dir-list.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: GET FULL hidden home files are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET FULL Config
GET_ETC(){
    #
    # @desc   :: This function saves Full_Config (all of /etc ...)
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing Full_Config ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir FULL_CONFIG && cd FULL_CONFIG
	echo "      Collecting Full_Config..."
	tar zcf ETC.tar.gz /etc 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Full_Config are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET LOGS
GET_SYS_LOGS(){
    #
    # @desc   :: This function saves Logs
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYS_LOGS && cd SYS_LOGS
	echo "      Collecting popular services Logs..."
	last -Faixw > "last.txt" 2>> ../err
	journalctl -x > "journalctl_x.txt" 2>> ../err
	journalctl -k > "journalctl_k.txt" 2>> ../err
	cat /var/log/**audit** 2>> ../err | more > "auditd.txt" 2>> ../err
	cat /var/log/boot** 2>> ../err | more > "boot.txt" 2>> ../err
	utmpdump /var/log/btmp** 2>> ../err | more > "btmp.txt" 2>> ../err
	utmpdump /var/log/wtmp** 2>> ../err | more > "wtmp.txt" 2>> ../err
	cat /var/log/apt/** 2>> ../err | more > "apt.txt" 2>> ../err
	cat /var/log/kern** 2>> ../err | more > "kern.txt" 2>> ../err
	cat /var/log/mail** 2>> ../err | more > "mail.txt" 2>> ../err
	cat /var/log/message** 2>> ../err | more > "message.txt" 2>> ../err
	cat /var/log/secure** 2>> ../err | more > "secure.txt" 2>> ../err
	cat /var/log/**auth** 2>> ../err | more > "auditd.txt" 2>> ../err
	cat /var/log/syslog** 2>> ../err | more > "syslog.txt" 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET LOGS
GET_FULL_LOGS(){
    #
    # @desc   :: This function saves FULL Logs
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing FULL Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir LOGS_FULL && cd LOGS_FULL
	#Collect all files in in /var/log folder.
	echo "      Collecting FULL Logs folder..."
	tar -czvf Full-var-log.tar.gz --dereference --hard-dereference --sparse /var/log > Full-var-log-list.txt 2>> ../err
		echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: FULL Logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET WEBSERVERSCRIPTS
GET_WEBSERVERSCRIPTS(){
    #
    # @desc   :: This function saves web server scripts
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing web server scripts... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir WEBSERVERSCRIPTS && cd WEBSERVERSCRIPTS
	echo "      Collecting WEBSERVERSCRIPTS..."
	find /var/www/ -type f \( -iname \*.py -o -iname \*.php -o -iname \*.js -o -iname \*.rb -o -iname \*.pl -o -iname \*.cgi -o -iname \*.sh -o -iname \*.go -o -iname \*.war -o -iname \*.config -o -iname \*.conf \) -print0 2>> ../err | xargs -0 tar -czvf WEBSERVERSCRIPTS.tar.gz > WEBSERVERSCRIPTS.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: web server scripts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..  
}


#@> GET.ssh folder
GET_SSHKEY(){ #Production
	mkdir SSH-FOLDERS && cd SSH-FOLDERS
	echo "      Collecting .ssh folder..."
	find / -xdev -type d -name .ssh -print0 2>> ../err | xargs -0 tar -czvf ssh-folders.tar.gz > ssh-folders-list.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: SSH FOLDER are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> GET HISTORIES
GET_HISTORIES(){
    #
    # @desc   :: This function saves histories
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing Histories... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir HISTORIES && cd HISTORIES
	echo "      Collecting HISTORIES ..."
	find / -type f -iname ".*_history" -print0 2>> ../err | xargs -0 tar -czvf histories.tar.gz  > histories.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Histories are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..  
}


#@> GET SUSPICIOUS
GET_SUSPICIOUS(){
    #
    # @desc   :: This function saves suspicious files
    #
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " Processing suspicious files... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SUSPICIOUS && cd SUSPICIOUS
	echo "      Collecting SUSPICIOUS File ..."
	find /tmp -type f -perm /+x -print0 | xargs -0 tar -czvf File-Excute-TMP.tar.gz > "File-Excute-TMP.txt" 2>> ../err
	find /tmp -iname ".*" -print0 | xargs -0 tar -czvf File-HIDE-TMP.tar.gz > "File-HIDE-TMP.txt" 2>> ../err
 	find / -type f -perm /+x -exec sha256sum {} + > hash_results.txt 2>> ../err
	echo "      Collecting SUID-SGID File ..."
	find / -xdev -type f \( -perm -04000 -o -perm -02000 \) -print0 2>> ../err | xargs -0 tar -czvf SUID-SGID.tar.gz > SUID-SGID-list.txt 2>> ../err
	echo -e "${BK}        ${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: suspicious files are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..  
}


# Clean up
CLEAN_UP(){ #Production

	# Archive/Compress files
	cd ..
	echo " "
	echo -e " Creating $OUTDIR.tar.gz "
	tar -czf $OUTDIR.tar.gz $OUTDIR 2>/dev/null
	
	# Clean-up $OUTDIR directory if the tar exists
	if [ -f $OUTDIR.tar.gz ]; then
	 rm -r $OUTDIR
	fi
	
	# Check if clean-up successful
	if [ ! -d $OUTDIR ]; then
	 echo " Clean-up Successful!"
	fi
	if [ -d $OUTDIR ]; then
	 echo " "
	 echo " WARNING Clean-up ERROR! "
	 echo $OUTDIR*
	fi

}


#@> SENDING FINAL NOTIFICATION
SEND_NOTE(){
    echo -e ""
    echo -e "${BK} COMPLETED ${NORMAL}"
    echo -e "${GREEN}[CLLF] - Scanning completed at $(date)${NORMAL}" 
}

RUN(){
	duvarlog=$(du -sh /var/log/ 2>/dev/null)
	if $get_logs; then
		echo -e "\n${RED}Warning${NORMAL} - Size is ${GREEN}$duvarlog${NORMAL}, Do you want to continue, ${YELLOW}Y${NORMAL} to continue, ${GREEN}N${NORMAL} to Cancel.\n" ; sleep 3
		read -p "Choice to continue Y/N:" -n 1 -r varchoice
		echo
		if [[ $varchoice =~ ^[Yy]$ ]]; then
			GET_FULL_LOGS
		else
			cd ..
			rm -rf $OUTDIR
			exit 0;
		fi
	fi

	if $get_config; then
		GET_ETC; sleep 5
	fi
	
	if $get_hidden_home_file; then
		GET_HIDDEN_HOME_FILE; sleep 5
	fi
	
	if $get_hidden_home_file; then
		GET_DISK; sleep 5
	fi

 	GET_SYSTEM_INFO; sleep 5
	GET_PACKAGES; sleep 5
	GET_ACCOUNT; sleep 5
	GET_PROCESS; sleep 5
	GET_SERVICES; sleep 5
	GET_OPENED_PORTS; sleep 5
	GET_NETWORK_INFO; sleep 5
	GET_TASKS; sleep 5
	GET_WEBSERVERSCRIPTS; sleep 5
	GET_SSHKEY; sleep 5
	GET_HISTORIES; sleep 5
	GET_SUSPICIOUS; sleep 5
	GET_SYS_LOGS; sleep 5
}


while true
do
	BANNER
	RUN
	SEND_NOTE
	break 0 2>/dev/null
done

CLEAN_UP
exit 0
