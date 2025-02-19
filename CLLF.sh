#!/bin/bash
# coded by XuanMike - XM1945
# C - version 1.1
# CLLF - Collect Linux Logs Forensic

SCRIPT=$(readlink -f "$0")
BASEDIR="$(dirname "$SCRIPT")"
cd $BASEDIR

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
	#echo -e "   -l, --log						Logs collect options					-l full"
	#echo -e "		  \"${GREEN}full${NORMAL}\" is Full folder /var/log (Maybe so big...)"
	#echo -e "		  \"${GREEN}lite${NORMAL}\" is Common Linux log files names and usage"
	#echo -e ""
	#echo -e "Optional Flags:"
	#echo -e "   -o, --OUTDIR						Write to output folder				  -o \"10.0.1.134\""
	#echo -e "   -s, --silent							Hide output in the terminal			 ${GREEN}Default: ${RED}False${NORMAL}"
	echo -e "Example Usage:"
	echo -e "${BK}./CLLF.sh -l full -o 10.0.1.134${NORMAL}"
	exit 0
}

#> ARGUMENT FLAGS
while [ -n "$1" ]; do
	case $1 in
			-o|--OUTDIR)
				OUTDIR="$2"
				shift ;;
			-a|--auto)
				auto=true
				check_liveIR=false
				shift ;;
			-h|--help)
				PRINTUSAGE
				shift ;;
			*)
				PRINTUSAGE
	esac
	shift
done

if [[ $OUTDIR == /* ]]; then
	mkdir -p "$OUTDIR"
else
	OUTDIR="$BASEDIR/$OUTDIR"
	mkdir -p "$OUTDIR"
fi
cd "$OUTDIR"
touch err

#@> GET SYSTEM INFO
GET_SYSTEM_INFO(){
	#
	# @desc   :: This function saves SYSTEM_INFO
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing SYSTEM_INFO... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYSTEM_INFO && cd SYSTEM_INFO
	echo "	  Collecting Basic Info..."
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "whoami" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	whoami >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "uptime" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	uptime >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "ipconfig" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	ip a >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "hostname" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	hostname >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "uname -a" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	uname -a >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "OS release" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	cat /etc/os-release >> "systeminfo.txt" 2>> ../err
	echo -e "-------------------------------------" >> systeminfo.txt
	echo -e "Linux release" >> systeminfo.txt
	echo -e "-------------------------------------" >> systeminfo.txt
	cat /proc/version> "version.txt" 2>> ../err
	cat /proc/cpuinfo > "cpuinfo.txt" 2>> ../err
	cat /proc/meminfo > "meminfo.txt" 2>> ../err
 	ls -lah /var/log/ > "var_log_directory_listing.txt" 2>> ../err
	printenv >> "printenv.txt" 2>> ../err
	set >> "set.txt" 2>> ../err
	echo $PATH >> "path.txt" 2>> ../err
	#This saves loaded modules
	echo -e "lsmod > "all_loaded_modules.txt"" >> all_loaded_modules.txt
	echo -e "-------------------------------------" >> all_loaded_modules.txt
	lsmod > "all_loaded_modules.txt" 2>> ../err
	echo -e "-------------------------------------" >> all_loaded_modules.txt
	echo -e "cat /proc/modules" >> all_loaded_modules.txt
	echo -e "-------------------------------------" >> all_loaded_modules.txt
	cat /proc/modules >> "all_loaded_modules.txt" 2>> ../err
	echo "	  Collecting modules info..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do echo -e "\nModule: $i"; modinfo $i ; done > modules_info.txt 2>> ../err
	echo "	  Collecting hash loaded modules..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do modinfo $i | grep "filename:" | awk '{print $2}' | xargs -I{} sha1sum {} ; done > modules_sha1.txt 2>> ../err
	echo "	  Collecting mount..."
	mount > mount.txt 2>> ../err
	
	if $get_metadatatime; then
		echo "	  Collecting metadata-time..."
		if [ "$(uname -m)" = "x86_64" ]; then
			chmod +x "$BASEDIR/bin/metadatatime_x86_64" 2>> ../err
			"$BASEDIR/bin/metadatatime_x86_64" > /dev/null 2>&1
		elif [ "$(uname -m)" = "i686" ] || [ "$(uname -m)" = "i586" ] || [ "$(uname -m)" = "i386" ]; then
			chmod +x "$BASEDIR/bin/metadatatime_i386" 2>> ../err
			"$BASEDIR/bin/metadatatime_i386" > /dev/null 2>&1
		else 
			echo -e "Check architecture" >> "metadata-time.csv" 2>> ../err
		fi

		#OLD get metadata
		#if which stat &>/dev/null; then
		#	echo "	  Collecting ALL metadata system Time - Just wait..."
		#	echo -e "Permission,uOwner,gOwner,Size, File Name,Create Time, Access Time, Modify Time, Status Change Time" > metadata-ALLtimes.csv | find / -mount -exec sh -c 'if [ $(find "$1" -maxdepth 1 -type f | wc -l) -le 1000 ]; then stat --printf="%A,%U,%G,%s,%n,%w,%x,%y,%z\n" "$1"; fi' sh {} \; >> metadata-ALLtimes.csv 2>> ../err
		#else 
		#	echo "	  Collecting metadata-accesstimes..."
		#	find / -mount -printf "%CY-%Cm-%Cd %CT,%M,%s,%u,%g,%h,%f\n" > metadata-accesstimes.csv 2>> ../err
		#fi
	else
		echo "	  NOT Collect metadata-accesstimes..."
	fi

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: SYSTEM_INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET DISK
GET_DISK(){
	#
	# @desc   :: This function saves disks state
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing disks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir DISKS && cd DISKS
	echo "	  Collecting Disk tree, LVM, Disk Usage, Free Disks,  ..."
	echo -e "-------------------------------------" >> disk_info.txt
	echo -e "List partition" >> disk_info.txt
	echo -e "-------------------------------------" >> disk_info.txt
	fdisk -l >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	cat /proc/partitions >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	echo -e "Disk filesystem" >> disk_info.txt
	echo -e "-------------------------------------" >> disk_info.txt
	df -h >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	echo -e "Mount list" >> disk_info.txt
	echo -e "-------------------------------------" >> disk_info.txt
	findmnt -a -A >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	echo -e "Display information about volume groups, logical volumes" >> disk_info.txt
	echo -e "-------------------------------------" >> disk_info.txt
	vgdisplay -v >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	lvdisplay -v >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	vgs --all >> "disk_info.txt" 2>> ../err
	echo -e "-------------------------------------" >> disk_info.txt
	lvs --all >> "disk_info.txt" 2>> ../err
	free >> "free_mem.txt" 2>> ../err
	echo "	  Collecting fstab  ..."
	cat /etc/fstab >> "startup_mount_fstab.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Disks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET PACKAGES
GET_PACKAGES(){
	#
	# @desc   :: This function saves all installed packages
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing packages ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PACKAGES && cd PACKAGES
	echo "	  Verifying installed package info..."
	
	if which dpkg &>/dev/null; then
		if $verify_package; then
			dpkg -V > deb-package-verify.txt
		fi
		echo "	  List installed package by APT..."
		apt list --installed > "apt_list_installed.txt" 2>> ../err
		echo "	  List installed package ..."
		dpkg -l > "dpkg_l.txt" 2>> ../err
		dpkg-query -l > "dpkg_query.txt" 2>> ../err
	else 
		if $verify_package; then
			rpm -qVa > rpm-package-verify.txt
		fi
		echo "	  List installed package by yum, dnf..."
  		if which yum &>/dev/null; then
			yum list installed > "yum_list_installed.txt" 2>> ../err
   		else
			dnf list installed > "dnf_list_installed.txt" 2>> ../err
   		fi
		rpm -qa > "rpm_qa.txt" 2>> ../err
		rpm -Va > "rpm_Va.txt" 2>> ../err
	fi
	
	echo "	  Collecting snap list  ..."
	snap list > "snap_list.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Packages  are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET ACCOUNT
GET_ACCOUNT(){
	#
	# @desc   :: This function saves users and groups
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing users and groups ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir ACCOUNTS && cd ACCOUNTS
	echo "	  Collecting passwd, shadow, group  ..."
	cat /etc/passwd | cut -d: -f1,3,4,5,6,7 | grep -vE '(nologin|halt|false|shutdown|sync)' | sort > "etc_passwd_login.txt" 2>> ../err
	cat /etc/passwd | cut -d: -f1,3,4,5,6,7 | grep -E '(nologin|halt|false|shutdown|sync)' | sort > "etc_passwd_nologin.txt" 2>> ../err
	cat /etc/sudoers > "etc_sudoers.txt" 2>> ../err
	cat /etc/group > "etc_group.txt" 2>> ../err
	cat /etc/shadow > "etc_shadow.txt" 2>> ../err
	cat /etc/gshadow > "etc_gshadow.txt" 2>> ../err
	echo "	  Collecting list of root account  ..."
	grep ":0:" /etc/passwd > "root_user.txt" 2>> ../err
	echo "	  Collecting information about users who are currently logged in  ..."
	who -alpu > "who_alpu.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Accounts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET PROCESS
GET_PROCESS(){
	#
	# @desc   :: This function saves running process
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing process ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PROCESS && cd PROCESS
	echo "	  Collecting pstree, Information of running process  ..."
	echo -e "-------------------------------------" >> display_process.txt
	echo -e "Pstree" >> display_process.txt
	echo -e "-------------------------------------" >> display_process.txt
	pstree >> "display_process.txt" 2>> ../err
	echo -e "-------------------------------------" >> display_process.txt
	echo -e "PS FXAU" >> display_process.txt
	echo -e "-------------------------------------" >> display_process.txt
	ps faux >> "display_process.txt" 2>> ../err
	echo -e "-------------------------------------" >> display_process.txt
	echo -e "TOP" >> display_process.txt
	echo -e "-------------------------------------" >> display_process.txt
	top -H -b -n 1 >> "display_process.txt" 2>> ../err
	echo "	  Collecting the process hashes..."
	find -L /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > Running_processhashes.txt 2>> ../err
	echo "	  Collecting the process symbolic links..."
	find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > Running_process_exe_links.txt 2>> ../err
 	echo "	  Collecting the process environment..."
	find /proc/[0-9]*/environ | xargs head 2>/dev/null > Running_process_environ.txt 2>> ../err
  	echo "	  Collecting the process CWD..."
	find /proc/[0-9]*/cwd | xargs head 2>/dev/null > Running_process_cwd.txt 2>> ../err
	echo "	  Collecting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > Running_process_cmdline.txt 2>> ../err
 	echo "	  Collecting the process comm..."
	find /proc/[0-9]*/comm | xargs head 2>/dev/null > Running_process_comm.txt 2>> ../err
	echo "	  Collecting Run-time variable data..."
	ls -latr /var/run 2>/dev/null > TEMP_VAR_RUN.txt 2>> ../err
	ls -latr /run 2>/dev/null > TEMP-RUN.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Process are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET SERVICES
GET_SERVICES(){
	#
	# @desc   :: This function saves services
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing services ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SERVICES && cd SERVICES
	echo "	  Collecting Information of running services..."
	systemctl list-units --all > "systemctl_list_units.txt" 2>> ../err
	(ls -la /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "ls_systemd_system.txt" 2>> ../err
	echo "	  Collecting status ALL services..."
	service --status-all > "service_status_all.txt" 2>> ../err
	
	if which chkconfig &>/dev/null; then
		chkconfig --list > "chkconfig.txt" 2>> ../err
	fi
	
	echo "	  Collecting list services per Status..."
	systemctl --type=service --state=failed > "systemctl_services_failed.txt" 2>> ../err
	systemctl --type=service --state=active > "systemctl_services_active.txt" 2>> ../err
	systemctl --type=service --state=running > "systemctl_services_running.txt" 2>> ../err
	ls -l /etc/init.d/* > "ls_etc_initd.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: services are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET OPENED PORTS
GET_OPENED_PORTS(){
	#
	# @desc   :: This function saves opened ports
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing ports ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PORTS && cd PORTS
	echo "	  Collecting OPENED PORTS..."
	ss --all > "ss_all.txt" 2>> ../err
	ss -lntu > "ss_lntu.txt" 2>> ../err
	netstat -a > "netstat_a.txt" 2>> ../err
	netstat -plntu > "netstat_with_PID.txt" 2>> ../err
	
	if which lsof &>/dev/null; then
		echo "	  Collecting List open files..."
  		lsof > "list_open_files.txt" 2>> ../err
		lsof -i -n -P > "list_open_files_contain_ipv4.txt" 2>> ../err
	fi
	
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: ports are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET NETWORK INFO
GET_NETWORK_INFO(){
	#
	# @desc   :: This function saves network INFO statistics
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing NETWORK INFO ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir NETWORK_INFO && cd NETWORK_INFO
	# IP
	echo "	  Collecting IP Address, RX, TX packets..."
	ip -s -s link > "all_rx_tx_packets.txt" 2>> ../err
	ip addr > "ip_addr.txt" 2>> ../err
	# Other
	echo "	  Collecting Kernel Interface table..."
	netstat -i > "netstat_i.txt" 2>> ../err
	nmcli device status > "nmcli_device_status.txt" 2>> ../err
	#  information on the hardware configuration
	echo "	  Collecting hardware configuration..."
	lshw -class network -short > "lshw.txt" 2>> ../err
	
	if which hwinfo &>/dev/null; then
		echo "	  Collecting hardware Info..."
		hwinfo --short --network > "hwinfo.txt" 2>> ../err
	fi
	
	echo "	  Collecting Host configuration Network..."
	cat /etc/hosts > "etc_hosts.txt" 2>> ../err
	cat /etc/hosts.allow > "etc_hosts_allow.txt" 2>> ../err
	#Get routing table
	echo "	  Collecting Routing Table..."
	
	if ip route &>/dev/null; then
		ip route > Network-routetable.txt 2>> ../err
	else
		netstat -rn > Network-routetable.txt 2>> ../err
	fi
		
	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "	  Collecting IPtables..."
		iptables -L -n -v --line-numbers > "iptables_full.txt" 2>> ../err
		iptables -L > "iptables.txt" 2>> ../err
	fi

	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "	  Collecting IP6tables..."
		ip6tables -L -n -v > "ip6tables_full.txt" 2>> ../err
	fi
	
	#Get UFW status
	if which ufw &>/dev/null; then
		echo "	  Collecting UFW status..."
		ufw status verbose > "ufw_status.txt" 2>> ../err
	fi
	
	#Get firewall-cmd information
	if which firewall-cmd &>/dev/null; then
		echo "	  Collecting firewall-cmd status..."
		firewall-cmd --list-services > "firewall_cmd_list_services.txt" 2>> ../err
		firewall-cmd --list-all > "firewall_cmd_list_all.txt" 2>> ../err
		firewall-cmd --list-ports > "firewall_cmd_list_ports.txt" 2>> ../err
	fi


	#Get SeLinux Verbose information
	if which sestatus &>/dev/null; then
		echo "	  Collecting SELinux status..."
		sestatus -v > seLinux-selinux.txt 2>> ../err
		echo "	  Collecting SELinux booleans..."
		getsebool -a > seLinux-booleans.txt 2>> ../err
	fi

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: NETWORK INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET schedule_tasks
GET_TASKS(){
	#
	# @desc   :: This function saves scheduled tasks, can use to Persistent (servicse, cron, rc, .profile ...)
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing tasks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SCHEDULE_TASKS && cd SCHEDULE_TASKS
	echo "	  Collecting Task Scheduler..."
	(ls -la /etc/*cron**/* /etc/cron* /var/spool/**/cron*) >> "all_cron.txt" 2>> ../err
	(cat /etc/*cron**/* /etc/cron* /var/spool/**/cron*) >> "all_cron.txt" 2>> ../err
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l | grep -v "^#"; done > "cron_per_user.txt" 2>> ../err
	(cat /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "systemd.txt" 2>> ../err
	(cat /etc/rc*.d**/* /etc/rc.local*) > "rc.txt" 2>> ../err
	echo "	  Collecting Shell Configuration..."
	(cat /etc/*.bashrc) > "bashrc-config.txt" 2>> ../err
	(cat /etc/profile /etc/profile.d/* ) > "profile_config.txt" 2>> ../err
	(cat ~/.bash_profile ~/.bash_login ~/.profile ) > "found_first_to_executed.txt" 2>> ../err
	echo "	  Collecting timers list..."
   	systemctl list-timers --all > "list_timers.txt" 2>> ../err
	echo "	  Collecting XDG Autostart..."
	cat /home/*/.config/autostart/* > "xdg_autostart.txt" 2>> ../err
	echo "	  Collecting MOTD ..."
	cat /etc/update-motd.d/* > "motd.txt" 2>> ../err
	echo "	  Collecting APT config ..."
	cat /etc/apt/apt.conf.d/* > "apt.txt" 2>> ../err
	echo "	  Collecting udev Rules contain RUN..."
	cat /etc/udev/rules.d/* | grep "RUN" > "udev_rules_run.txt" 2>> ../err

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: tasks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET FULL hidden home files
GET_HIDDEN_FILE_FOLDER(){
	#
	# @desc   :: This function saves HIDDEN FILE FOLDER
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing GET hidden home files and hidden Folder ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir HIDDEN_FILE_FOLDER && cd HIDDEN_FILE_FOLDER
	echo "	  Collecting hidden File and DIR /..."
 	cut -d',' -f5 "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | grep -E '/\.[^/]*' > all_hidden_file_folder.csv 2>> ../err
	echo "	  Collecting hidden File and DIR in HOME folder ..."
	cut -d',' -f5 "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | grep -E '^/home/|^/root/' > hidden_file_folder_in_home.csv 2>> ../err
	echo "	  Get hidden File and DIR in HOME folder ..."
	cut -d',' -f5 "$OUTDIR/HIDDEN_FILE_FOLDER/hidden_file_folder_in_home.csv" | xargs -d '\n' timeout 1800s tar -czvf hidden_file_folder_in_home.tar.gz > /dev/null 2>&1
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: GET hidden home files and hidden Folder are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET FULL Config
GET_ETC(){
	#
	# @desc   :: This function saves Full_Config (all of /etc ...)
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing Full_Config ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir FULL_CONFIG && cd FULL_CONFIG
	echo "	  Collecting Full_Config..."
	tar zcf ETC.tar.gz /etc 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Full_Config are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET LOGS
GET_SYS_LOGS(){
	#
	# @desc   :: This function saves Logs
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYS_LOGS && cd SYS_LOGS
	echo "	  Collecting popular services Logs..."
	last -Faixw > "last.txt" 2>> ../err
	journalctl -x > "journalctl_x.txt" 2>> ../err
	journalctl -k > "journalctl_k.txt" 2>> ../err
	cat /var/log/**audit** 2>> ../err | more > "auditd.txt" 2>> ../err
	cat /var/log/boot** 2>> ../err | more > "boot.txt" 2>> ../err
	utmpdump /var/log/btmp** 2>> ../err | more > "invalid_login_attempts.txt" 2>> ../err
	utmpdump /var/log/wtmp** 2>> ../err | more > "login_logout_activity.txt" 2>> ../err
 	utmpdump /var/log/utmp** 2>> ../err | more > "current_session_active.txt" 2>> ../err
  	utmpdump /var/run/utmp 2>> ../err | more > "current_session_active.txt" 2>> ../err
	cat /var/log/apt/** 2>> ../err | more > "apt.txt" 2>> ../err
	cat /var/log/kern** 2>> ../err | more > "kern.txt" 2>> ../err
	cat /var/log/mail** 2>> ../err | more > "mail.txt" 2>> ../err
	cat /var/log/message** 2>> ../err | more > "message.txt" 2>> ../err
	cat /var/log/secure** 2>> ../err | more > "secure.txt" 2>> ../err
	cat /var/log/**auth** 2>> ../err | more > "auth.txt" 2>> ../err
	cat /var/log/syslog** 2>> ../err | more > "syslog.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET LOGS
GET_FULL_LOGS(){
	#
	# @desc   :: This function saves FULL Logs
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing FULL Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir LOGS_FULL && cd LOGS_FULL
	#Collect all files in in /var/log folder.
	echo "	  Collecting FULL Logs folder..."
	tar -czvf full_var_log.tar.gz --dereference --hard-dereference --sparse /var/log > full_var_log_list.txt 2>> ../err
		echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: FULL Logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET WEBSERVERSCRIPTS
GET_WEBSERVERSCRIPTS(){
	#
	# @desc   :: This function saves web server scripts
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing web server scripts... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir WEBSERVERSCRIPTS && cd WEBSERVERSCRIPTS
	echo "	  Collecting WEBSERVERSCRIPTS..."
	find /var/www/ -type f \( -iname \*.py -o -iname \*.php -o -iname \*.js -o -iname \*.rb -o -iname \*.pl -o -iname \*.cgi -o -iname \*.sh -o -iname \*.go -o -iname \*.war -o -iname \*.config -o -iname \*.conf \) -print0 2>> ../err | xargs -0 tar -czvf webserverscripts.tar.gz > webserverscripts.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: web server scripts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET HISTORIES
GET_HISTORIES(){
	#
	# @desc   :: This function saves histories
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing Histories... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir HISTORIES && cd HISTORIES
	echo "	  Collecting HISTORIES ..."
	cut -d',' -f5 "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | grep "_history" 2>> ../err | xargs -d '\n' timeout 1800s tar -czvf histories.tar.gz > histories.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Histories are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET SUSPICIOUS
GET_SUSPICIOUS(){
	#
	# @desc   :: This function saves suspicious files
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing suspicious files... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SUSPICIOUS && cd SUSPICIOUS
	echo "	  Collecting file excute in /tmp..."
	awk -F',' '$1 ~ /^-.*x/ && $5 ~ /^\/tmp\// {print $5}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" 2>> ../err | xargs -d '\n' timeout 1800s tar -czvf file_excuteable_tmp.tar.gz > "file_excuteable_tmp.txt" 2>> ../err
	echo "	  Collecting file hidden in /tmp..."
	awk -F',' '$5 ~ /^\/tmp\/\..*/ {print $5}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" 2>> ../err | xargs -d '\n' timeout 1800s tar -czvf file_hidden_tmp.tar.gz > "file_hidden_tmp.txt" 2>> ../err
	echo "	  Collecting sha256 in /tmp..."
 	awk -F',' '$5 ~ /^\/tmp/ && $1 ~ /^-.*/ {print $5}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | xargs -I {} sha256sum {} > tmp_file_hash_results.txt 2>> ../err
	echo "	  Collecting suid-sgid File ..."
	find /bin /usr/bin /home /root /var -xdev -type f \( -perm -04000 -o -perm -02000 \) -print0 2>> ../err | xargs -0 tar -czvf suid_sgid.tar.gz > suid_sgid_list.txt 2>> ../err
	echo "	  File small less than 1kb..."
	awk -F',' '$1 !~ /^d/ && $4 < 1024 {print $5}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" 2>> ../err | grep "www\|apache2\|nginx\|httpd\|http\|html" | xargs -d '\n' timeout 1800s tar -czvf smaller_files_1kb.tar.gz > smaller_files_1kb.txt 2>> ../err
	echo "	  File greater than 10 MegaBytes..."
	awk -F',' '$1 !~ /^d/ && $4 > 10000000 {print $5}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" 2>> ../err > greater_than_10_mb.txt 2>> ../err

	echo "	  Collecting .ssh folder..."
	find /home /root /back* -xdev -type d -name .ssh -print0 2>> ../err | xargs -0 tar -czvf ssh_folders.tar.gz > ssh_folders_list.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: suspicious files are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


# Clean up
CLEAN_UP(){ #Production

	# Archive/Compress files
	cd "$BASEDIR"
	echo " "
	echo -e " Creating $OUTDIR.tar.gz "
	tar -czf "$OUTDIR.tar.gz" -C "$OUTDIR" . 2>/dev/null
	
	# Clean-up $OUTDIR directory if the tar exists
	if [ -f "$OUTDIR.tar.gz" ]; then
	 rm -r "$OUTDIR"
	fi
	
	# Check if clean-up successful
	if [ ! -d "$OUTDIR" ]; then
	 echo " Clean-up Successful!"
	fi
	if [ -d "$OUTDIR" ]; then
	 echo " "
	 echo " WARNING Clean-up ERROR! "
	 echo "$OUTDIR*"
	fi

}


#@> SENDING FINAL NOTIFICATION
SEND_NOTE(){
	echo -e ""
	echo -e "${BK} COMPLETED ${NORMAL}"
	echo -e "${GREEN}[CLLF] - Scanning completed at $(date)${NORMAL}" 
	echo -e "\n\n"
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|	  2024 - ____ _____ ________ | Threat Hunting and Incident Response	|"
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "\n\n"
}

RUN(){
	duvarlog=$(du -sh /var/log/ 2>/dev/null)
	if $get_logs; then
		if [[ $auto == true ]]; then
			echo -e "\n\n"
			echo -e "+---------------------------------------------------------------------------+"
			echo -e "|	  ${RED}AUTO MODE IS ON${NORMAL} - Size is ${GREEN}${duvarlog}${NORMAL} of Log will be Collect..."
			echo -e "+---------------------------------------------------------------------------+"
			echo -e "\n\n"
		else
			echo -e "\n${RED}Warning${NORMAL} - Size is ${GREEN}$duvarlog${NORMAL}, Do you want to continue, ${YELLOW}Y${NORMAL} to continue, ${GREEN}N${NORMAL} to Cancel.\n" ; sleep 1
			read -p "Choice to continue Y/N:" -n 1 -r varchoice
			echo
			if [[ $varchoice =~ ^[Yy]$ ]]; then
				get_logs_confirm=true
			else
				cd "$BASEDIR"
				rm -rf "$OUTDIR"
				exit 0;
			fi
		fi
	fi
	if $run_liveIR; then
		/bin/bash "$BASEDIR/liveIR.sh"; sleep 5
	fi
	GET_SYSTEM_INFO; sleep 5
	if $get_logs_confirm; then
		GET_FULL_LOGS
	fi
	if $get_config; then
		GET_ETC; sleep 5
	fi
	if $get_hidden_file_folder; then
		GET_HIDDEN_FILE_FOLDER; sleep 5
	fi
	if $get_disk; then
		GET_DISK; sleep 5
	fi
	GET_PACKAGES; sleep 5
	GET_ACCOUNT; sleep 5
	GET_PROCESS; sleep 5
	GET_SERVICES; sleep 5
	GET_OPENED_PORTS; sleep 5
	GET_NETWORK_INFO; sleep 5
	GET_TASKS; sleep 5
	GET_WEBSERVERSCRIPTS; sleep 5
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
