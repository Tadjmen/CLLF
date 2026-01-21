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

# Timeout set
low_to="60s"			#1 min
med_to="300s"			#5 min
hight_to="3600s"		#60 min
force_kill="10s" 

run_timeout() {
	local dur="$1"; shift
	timeout -k "$force_kill" "$dur" "$@" 2>>../err
	local rc=$?

	case "$rc" in
		124)
			echo "[TIMEOUT] Lệnh bị timeout sau $dur: $*" >&2
			;;
		137)
			echo "[TIMEOUT-KILL] Lệnh bị kill : $*" >&2
			;;
	esac
	return $rc
}

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
				check_liveir=false
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
	# @desc	 :: This function saves SYSTEM_INFO
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing SYSTEM_INFO... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYSTEM_INFO && cd SYSTEM_INFO
	echo "		Collecting Basic Info..."
	for cmd in "whoami" "uptime" "ip a" "hostname" "uname -a" "cat /etc/os-release"; do
		echo -e "\n========== $cmd ==========" >> systeminfo.txt
		run_timeout "$med_to" $cmd >> systeminfo.txt 2>/dev/null
	done
	run_timeout "$low_to" cat /proc/version> "version.txt" 2>> ../err
	run_timeout "$low_to" cat /proc/cpuinfo > "cpuinfo.txt" 2>> ../err
	run_timeout "$low_to" cat /proc/meminfo > "meminfo.txt" 2>> ../err
	run_timeout "$low_to" printenv >> "printenv.txt" 2>> ../err
	echo $PATH >> "path.txt" 2>> ../err
	echo "		Collecting all alias..."
	run_timeout "$low_to" alias | grep '=' > all_alias.txt 2>> ../err
	run_timeout "$low_to" bash -lc 'alias' | grep '=' >> all_alias.txt 2>> ../err

	#This saves loaded modules
	for cmd in "lsmod" "cat /proc/modules"; do
		echo -e "\n========== $cmd ==========" >> all_loaded_modules.txt
		run_timeout "$med_to" $cmd >> all_loaded_modules.txt 2>> ../err
	done
	echo "		Collecting modules info..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do echo -e "\nModule: $i"; run_timeout "$med_to" modinfo $i ; done > modules_info.txt 2>> ../err
	echo "		Collecting system library type info..."
	run_timeout "$med_to" find /lib /usr/lib -type f -name '*.so*' -exec file {} \; > system_library_type.txt 2>> ../err
	echo "		Collecting hash loaded modules..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do run_timeout "$med_to" modinfo $i | grep "filename:" | awk '{print $2}' | run_timeout "$med_to" xargs -I{} sha1sum {} ; done > modules_sha1.txt 2>> ../err
	run_timeout "$med_to" find /lib/modules/$(uname -r)/kernel -name '*.ko*' | while read -r module; do
		if ! run_timeout "$med_to" modinfo "$module" | grep -q 'signature:'; then
			echo "Unsigned kernel module: $module" >> unsigned_modules.txt 2>> ../err
		fi
	done
	echo "		Collecting mount..."
	run_timeout "$low_to" mount > mount.txt 2>> ../err
	
	if $get_metadatatime; then
		echo "		Collecting metadata-time..."
		if [ "$(uname -m)" = "x86_64" ]; then
			chmod +x "$BASEDIR/bin/metadatatime_x86_64" 2>> ../err
			run_timeout "$hight_to" "$BASEDIR/bin/metadatatime_x86_64" > metadatatime_results.csv 2>/dev/null
		elif [ "$(uname -m)" = "i686" ] || [ "$(uname -m)" = "i586" ] || [ "$(uname -m)" = "i386" ]; then
			chmod +x "$BASEDIR/bin/metadatatime_i386" 2>> ../err
			run_timeout "$hight_to" "$BASEDIR/bin/metadatatime_i386" > metadatatime_results.csv 2>/dev/null
		else 
			echo -e "Check architecture" >> "metadata-time.csv" 2>> ../err
		fi

	else
		echo "		NOT Collect metadata-accesstimes..."
	fi

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: SYSTEM_INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET DISK
GET_DISK(){
	#
	# @desc	 :: This function saves disks state
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing disks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir DISKS && cd DISKS
	echo "		List disk, partition info..."
	for cmd in "fdisk -l" "cat /proc/partitions" "df -h" "findmnt -a -A" "vgdisplay -v" "lvdisplay -v" "vgs --all" "lvs --all"; do
		echo -e "\n========== $cmd ==========" >> disk_info.txt
		run_timeout "$med_to" $cmd >> disk_info.txt 2>> ../err
	done
	echo "		Collecting mem status	..."
	run_timeout "$med_to" free >> "free_mem.txt" 2>> ../err
	echo "		Collecting fstab	..."
	run_timeout "$med_to" cat /etc/fstab >> "startup_mount_fstab.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Disks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET PACKAGES
GET_PACKAGES(){
	#
	# @desc	 :: This function saves all installed packages
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing packages ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PACKAGES && cd PACKAGES
	echo "		Verifying installed package info..."
	
	if which dpkg &>/dev/null; then
		if $verify_package; then
			run_timeout "$med_to" dpkg -V > deb-package-verify.txt
		fi
		echo "		List installed package by APT..."
		run_timeout "$med_to" apt list --installed > "apt_list_installed.txt" 2>> ../err
		echo "		List installed package ..."
		run_timeout "$med_to" dpkg -l > "dpkg_l.txt" 2>> ../err
		run_timeout "$med_to" dpkg-query -l > "dpkg_query.txt" 2>> ../err
	else 
		if $verify_package; then
			run_timeout "$med_to" rpm -qVa > rpm-package-verify.txt
		fi
		echo "		List installed package by yum, dnf..."
		if which yum &>/dev/null; then
			run_timeout "$med_to" yum list installed > "yum_list_installed.txt" 2>> ../err
		else
			run_timeout "$med_to" dnf list installed > "dnf_list_installed.txt" 2>> ../err
		fi
		run_timeout "$med_to" rpm -qa > "rpm_qa.txt" 2>> ../err
		run_timeout "$med_to" rpm -Va > "rpm_Va.txt" 2>> ../err
	fi
	
	echo "		Collecting snap list	..."
	run_timeout "$med_to" snap list > "snap_list.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Packages	are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET ACCOUNT
GET_ACCOUNT(){
	#
	# @desc	 :: This function saves users and groups
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing users and groups ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir ACCOUNTS && cd ACCOUNTS
	echo "		Collecting passwd, shadow, group	..."
	run_timeout "$med_to" cat /etc/passwd > "etc_passwd.txt" 2>> ../err
	run_timeout "$med_to" cat /etc/sudoers.d/* /etc/sudoers > "etc_sudoers.txt" 2>> ../err
	run_timeout "$med_to" cat /etc/group > "etc_group.txt" 2>> ../err
	run_timeout "$med_to" cat /etc/shadow > "etc_shadow.txt" 2>> ../err
	run_timeout "$med_to" cat /etc/gshadow > "etc_gshadow.txt" 2>> ../err
	echo "		Collecting list of root account	..."
	run_timeout "$med_to" grep ":0:" /etc/passwd > "root_user.txt" 2>> ../err
	echo "		Collecting information about users who are currently logged in	..."
	run_timeout "$med_to" who -alpu > "who_alpu.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Accounts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET PROCESS
GET_PROCESS(){
	#
	# @desc	 :: This function saves running process
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing process ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PROCESS && cd PROCESS
	echo "		Collecting process running	..."
	run_timeout "$low_to" ps aux 2>/dev/null > ps_aux.txt 2>> ../err
	echo "		Collecting process running	..."
	run_timeout "$low_to" ps faux 2>/dev/null > ps_faux.txt 2>> ../err
	echo "		Collecting the process hashes..."
	run_timeout "$med_to" find -L /proc/[0-9]*/exe -print0 2>/dev/null |xargs -0 sha1sum 2>/dev/null > running_processhashes.txt 2>> ../err
	echo "		Collecting the process symbolic links..."
	run_timeout "$med_to" find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > running_process_exe_links.txt 2>> ../err
	 echo "		Collecting the process environment..."
	run_timeout "$med_to" find /proc/[0-9]*/environ | xargs head 2>/dev/null > running_process_environ.txt 2>> ../err
		echo "		Collecting the process CWD..."
	run_timeout "$med_to" find /proc/[0-9]*/cwd | xargs ls -l 2>/dev/null > running_process_cwd.txt 2>> ../err
	echo "		Collecting the process cmdline..."
	run_timeout "$med_to" find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > running_process_cmdline.txt 2>> ../err
	echo "		Collecting Run-time variable data..."
	run_timeout "$med_to" ls -latr /var/run 2>/dev/null > TEMP_VAR_RUN.txt 2>> ../err
	run_timeout "$med_to" ls -latr /run 2>/dev/null > TEMP-RUN.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Process are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET SERVICES
GET_SERVICES(){
	#
	# @desc	 :: This function saves services
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing services ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SERVICES && cd SERVICES
	echo "		Collecting name of running services..."
	run_timeout "$med_to" systemctl list-units --all > "systemctl_list_units.txt" 2>> ../err
	echo "		Collecting detail of all services..."
	for file in /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service /lib/systemd/system/*; do
		[ -f "$file" ] && echo -e "\n========== $file ==========\n" && run_timeout "$low_to" cat "$file"
	done > "systemd_service.txt" 2>> ../err
	for file in /etc/init.d/*; do
		[ -f "$file" ] && echo "========== $file ==========" && run_timeout "$low_to" cat "$file"
	done > "init_service.txt" 2>> ../err
	echo "		Collecting status ALL services..."
	service --status-all > "service_status_all.txt" 2>> ../err
	
	if which chkconfig &>/dev/null; then
		run_timeout "$med_to" chkconfig --list > "chkconfig.txt" 2>> ../err
	fi
	
	echo "		Collecting list services per Status..."
	run_timeout "$med_to" systemctl --type=service --state=failed > "systemctl_services_failed.txt" 2>> ../err
	run_timeout "$med_to" systemctl --type=service --state=active > "systemctl_services_active.txt" 2>> ../err
	run_timeout "$med_to" systemctl --type=service --state=running > "systemctl_services_running.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: services are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET OPENED PORTS
GET_OPENED_PORTS(){
	#
	# @desc	 :: This function saves opened ports
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing ports ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir PORTS && cd PORTS
	echo "		Collecting OPENED PORTS..."
	run_timeout "$med_to" ss --all > "ss_all.txt" 2>> ../err
	run_timeout "$med_to" ss -plntu > "ss_with_pid.txt" 2>> ../err
	run_timeout "$med_to" netstat -a > "netstat_a.txt" 2>> ../err
	run_timeout "$med_to" netstat -plntu > "netstat_with_pid.txt" 2>> ../err	
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: ports are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET NETWORK INFO
GET_NETWORK_INFO(){
	#
	# @desc	 :: This function saves network INFO statistics
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing NETWORK INFO ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir NETWORK_INFO && cd NETWORK_INFO
	# IP
	echo "		Collecting IP Address, RX, TX packets..."
	run_timeout "$low_to" ip -s -s link > "all_rx_tx_packets.txt" 2>> ../err
	run_timeout "$low_to" ip addr > "ip_addr.txt" 2>> ../err
	# Other
	echo "		Collecting Kernel Interface table..."
	run_timeout "$med_to" netstat -i > "netstat_i.txt" 2>> ../err
	run_timeout "$med_to" nmcli device status > "nmcli_device_status.txt" 2>> ../err
	#	information on the hardware configuration
	echo "		Collecting hardware configuration..."
	run_timeout "$med_to" lshw -class network -short > "lshw.txt" 2>> ../err
	
	if which hwinfo &>/dev/null; then
		echo "		Collecting hardware Info..."
		run_timeout "$med_to" hwinfo --short --network > "hwinfo.txt" 2>> ../err
	fi
	
	echo "		Collecting Host configuration Network..."
	run_timeout "$low_to" cat /etc/hosts > "etc_hosts.txt" 2>> ../err
	run_timeout "$low_to" cat /etc/hosts.allow > "etc_hosts_allow.txt" 2>> ../err
	#Get routing table
	echo "		Collecting Routing Table..."
	
	if ip route &>/dev/null; then
		run_timeout "$low_to" ip route > network-routetable.txt 2>> ../err
	else
		run_timeout "$low_to" netstat -rn > network-routetable.txt 2>> ../err
	fi
		
	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "		Collecting IPtables..."
		run_timeout "$low_to" iptables -L -n -v --line-numbers > "iptables_full.txt" 2>> ../err
		run_timeout "$low_to" iptables -L > "iptables.txt" 2>> ../err
	fi

	#Get iptables. iptables rules.
	if which iptables &>/dev/null; then
		echo "		Collecting IP6tables..."
		run_timeout "$low_to" ip6tables -L -n -v > "ip6tables_full.txt" 2>> ../err
	fi
	
	#Get UFW status
	if which ufw &>/dev/null; then
		echo "		Collecting UFW status..."
		run_timeout "$low_to" ufw status verbose > "ufw_status.txt" 2>> ../err
	fi
	
	#Get firewall-cmd information
	if which firewall-cmd &>/dev/null; then
		echo "		Collecting firewall-cmd status..."
		run_timeout "$med_to" firewall-cmd --list-services > "firewall_cmd_list_services.txt" 2>> ../err
		run_timeout "$med_to" firewall-cmd --list-all > "firewall_cmd_list_all.txt" 2>> ../err
		run_timeout "$med_to" firewall-cmd --list-ports > "firewall_cmd_list_ports.txt" 2>> ../err
	fi


	#Get SeLinux Verbose information
	if which sestatus &>/dev/null; then
		echo "		Collecting SELinux status..."
		run_timeout "$med_to" sestatus -v > seLinux-selinux.txt 2>> ../err
		echo "		Collecting SELinux booleans..."
		run_timeout "$med_to" getsebool -a > seLinux-booleans.txt 2>> ../err
	fi

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: NETWORK INFO are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET schedule_tasks
GET_TASKS(){
	#
	# @desc	 :: This function saves scheduled tasks, can use to Persistent (servicse, cron, rc, .profile ...)
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing tasks ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SCHEDULE_TASKS && cd SCHEDULE_TASKS
	echo "		Collecting all crontab location..."
	for file in /etc/*cron**/* /etc/cron* /var/spool/**/cron*; do
		[ -f "$file" ] && echo -e "\n========== $file ==========\n" && cat "$file"
	done >> "all_cron.txt" 2>> ../err
	echo "		Collecting crontab per user..."
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l | grep -v "^#"; done > "cron_per_user.txt" 2>> ../err
	echo "		Collecting at job..."
	for j in $(atq | cut -f 1); do run_timeout "$low_to" at -c "$j"; done > "at_job.txt" 2>> ../err
	echo "		Collecting user boot..."
	for file in /{root,home/*}/.{bashrc,bash_profile,bash_login,bash_logout,profile,zshrc,zprofile,zlogout,shrc,cshrc,tcshrc,kshrc,mkshrc}; do
		[ -f "$file" ] && echo "========== $file ==========" && run_timeout "$low_to" cat "$file"
	done > "shell_config_user_boot.txt" 2>> ../err
	echo "		Collecting system boot..."
	for file in /etc/{profile,bash.bashrc,zsh/zshrc,zsh/zprofile,zsh/zlogin,zsh/zlogout,profile.d/*,rc.local*,init.d/*,rc*.d/*}; do
		[ -f "$file" ] && echo "========== $file ==========" && run_timeout "$low_to" cat "$file"
	done > "shell_config_system_boot.txt" 2>> ../err
	echo "		Collecting timers list..."
	run_timeout "$low_to" systemctl list-timers --all > "list_timers.txt" 2>> ../err
	echo "		Collecting XDG Autostart..."
	run_timeout "$med_to" cat /home/*/.config/autostart/* > "xdg_autostart.txt" 2>> ../err
	echo "		Collecting MOTD ..."
	run_timeout "$med_to" cat /etc/update-motd.d/* > "motd.txt" 2>> ../err
	echo "		Collecting APT config ..."
	run_timeout "$med_to" cat /etc/apt/apt.conf.d/* > "apt.txt" 2>> ../err
	echo "		Collecting udev Rules contain RUN..."
	run_timeout "$med_to" cat /etc/udev/rules.d/* 2>/dev/null | grep "RUN" > "udev_rules_run.txt" 2>> ../err

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: tasks are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}



#@> GET LOGS
GET_SYS_LOGS(){
	#
	# @desc	 :: This function saves Logs
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SYS_LOGS && cd SYS_LOGS
	echo "		Collecting popular services Logs..."
	run_timeout "$med_to" last -Faixw > "last.txt" 2>> ../err
	run_timeout "$med_to" journalctl -x > "journalctl_x.txt" 2>> ../err
	run_timeout "$med_to" journalctl -k > "journalctl_k.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/audit/** 2>> ../err > "auditd.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/boot** 2>> ../err > "boot.txt" 2>> ../err
	run_timeout "$med_to" utmpdump /var/log/btmp** 2>> ../err > "invalid_login_attempts.txt" 2>> ../err
	run_timeout "$med_to" utmpdump /var/log/wtmp** 2>> ../err > "login_logout_activity.txt" 2>> ../err
	run_timeout "$med_to" utmpdump /var/log/utmp** 2>> ../err > "current_session_active.txt" 2>> ../err
	run_timeout "$med_to" utmpdump /var/run/utmp 2>> ../err > "current_session_active.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/apt/** 2>> ../err > "apt.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/kern** 2>> ../err > "kern.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/mail** 2>> ../err > "mail.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/message** 2>> ../err > "message.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/secure** 2>> ../err > "secure.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/**auth** 2>> ../err > "auth.txt" 2>> ../err
	run_timeout "$med_to" cat /var/log/syslog** 2>> ../err > "syslog.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET FULL LOGS
GET_FULL_LOGS(){
	#
	# @desc	 :: This function saves FULL Logs
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing FULL Logs ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir LOGS_FULL && cd LOGS_FULL
	#Collect all files in in /var/log folder.
	echo "		Collecting FULL Logs folder..."
	run_timeout "$hight_to" tar -czvf full_var_log.tar.gz --dereference --hard-dereference --sparse /var/log > var_log_archived.txt 2>> ../err
	run_timeout "$low_to" ls -lah /var/log/ > "var_log_directory_listing.txt" 2>> ../err
		echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: FULL Logs are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET HISTORIES
GET_HISTORIES(){
	#
	# @desc	 :: This function saves histories
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing Histories... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir HISTORIES && cd HISTORIES
	echo "		Collecting HISTORIES ..."
	run_timeout "$med_to" cut -d',' -f6 "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | tr -d '\r"' | grep -E "_history$" 2>> ../err | run_timeout "$hight_to" xargs -d '\n' tar -czvf histories.tar.gz > histories.txt 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: Histories are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd "$OUTDIR"
}


#@> GET SUSPICIOUS
GET_SUSPICIOUS(){
	#
	# @desc	 :: This function saves suspicious files
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " Processing suspicious files... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	mkdir SUSPICIOUS && cd SUSPICIOUS
	echo "		Collecting sha256 in /tmp..."
	run_timeout "$med_to" awk -F',' '$6 ~ /^"\/tmp/ && $1 ~ /^-.*/ {print $6}' "$OUTDIR/SYSTEM_INFO/metadatatime_results.csv" | xargs -I {} sha256sum {} > tmp_file_hash_results.txt 2>> ../err
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
	echo -e "|	 2025 - ____ _____ ________ | Threat Hunting and Incident Response	 |"
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "\n\n"
}

RUN(){
	duvarlog=$(du -sh /var/log/ 2>/dev/null)

	GET_SYSTEM_INFO; sleep 2
	if $get_logs; then
		GET_FULL_LOGS
	fi
	if $get_disk; then
		GET_DISK; sleep 2
	fi
	GET_PACKAGES; sleep 2
	GET_ACCOUNT; sleep 2
	GET_PROCESS; sleep 2
	GET_SERVICES; sleep 2
	GET_OPENED_PORTS; sleep 2
	GET_NETWORK_INFO; sleep 2
	GET_TASKS; sleep 2
	GET_HISTORIES; sleep 2
	GET_SUSPICIOUS; sleep 2
	GET_SYS_LOGS; sleep 2

	export OUTDIR #export OUTDIR, can use in liveir
	if $run_liveir; then
		/bin/bash "$BASEDIR/liveir.sh"; sleep 2
	fi
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
