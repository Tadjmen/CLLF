#!/bin/bash
# coded by XuanMike - XM1945


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

#@> Print BANNER
BANNER(){
	clear
	echo -e ""
	echo -e "${YELLOW}
  _   ___  _____  ______  _______     ________ __
 | | / / |/ / _ \/_  __/ /  _/ _ \___/_  __/ // /
 | |/ /    / ___/ / /   _/ // , _/___// / / _  / 
 |___/_/|_/_/    /_/   /___/_/|_|    /_/ /_//_/  

${NORMAL}"
	echo -e "[${YELLOW}rasoat.sh${NORMAL} - VNPT IR-TH] == A Modular of (${BK}CLLF${NORMAL})"
}


OUTDIR=Logs_$(hostname -I | awk '{print $1}')_$(hostname)_$(date +%F_%H-%M-%S)
mkdir $OUTDIR && cd $OUTDIR
touch err


#@> NETWORK SUSPICIUS
NETWORK_SUSPICIUS(){
	#
	# @desc   :: This function saves NETWORK_SUSPICIUS
	#
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e "| Processing NETWORK_SUSPICIUS... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	echo -e "+---------------------------------------------------------------------------+"
	mkdir NETWORK_SUSPICIUS && cd NETWORK_SUSPICIUS
	echo "	  Collecting netstat with PID ..."
	netstat -plntu > "netstat_with_PID.txt" 2>> ../err
	echo "	  Collecting LSOF with IPV4 ..."
	lsof -i -n -P > "List_open_files_contain_ipv4.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: NETWORK_SUSPICIUS are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> PROCESS SUSPICIUS
PROCESS_SUSPICIUS(){
	#
	# @desc   :: This function saves PROCESS SUSPICIUS
	#
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|${BK}		${NORMAL}" | tr -d '\n' | echo -e "| Processing PROCESS_SUSPICIUS ... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	echo -e "+---------------------------------------------------------------------------+"
	mkdir PROCESS_SUSPICIUS && cd PROCESS_SUSPICIUS
	echo "	  Collecting deleted still running ..."
	ls -alR /proc/*/exe 2> /dev/null | grep deleted > "Process_deleted_but_running.txt" 2>> ../err
	echo "	  Collecting Real Process running path ..."
	ls -al /proc/*/exe 2> /dev/null |  grep "\->" > "Real_process_running_path.txt" 2>> ../err
	echo "	  Collecting Process running with suspicious CWD ..."
	ls -al /proc/*/cwd 2> /dev/null | grep "\->" | grep "/home/\|/temp\|/dev/shm\|/var/run|/run\|/var/spool" > "Process_running_with_suspicious_CWD.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: PROCESS_SUSPICIUS are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..
}


#@> FILES SUSPICIUS
FILES_SUSPICIUS(){
	#
	# @desc   :: This function saves FILES SUSPICIUS
	#
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|${BK}		${NORMAL}" | tr -d '\n' | echo -e "| Processing FILES_SUSPICIUS... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	echo -e "+---------------------------------------------------------------------------+"
	mkdir FILES_SUSPICIUS && cd FILES_SUSPICIUS
	#echo "	  Collecting immutable files and directories..."
	#lsattr / -R 2> /dev/null | grep "\----i" > "immutable_files_and_directories.txt" 2>> ../err
	#echo "	  Collecting decentralized File and DIR..."
	#find / \( -nouser -o -nogroup \) -exec ls -lg {} \; > "decentralized_file_dir.txt" 2>> ../err
	echo "	  Collecting list File ELF in TMP..."
	find /tmp -type f -exec file -p '{}' \; | grep ELF > "ELF_file_in_TMP.txt" 2>> ../err
	echo "	  Collecting list File hide in TMP..."
	find /tmp -iname ".*" -print0 | xargs -0 tar -czvf File_hidden_TMP.tar.gz > "File_hidden_TMP.txt" 2>> ../err
	echo "	  Collecting list File hide in TMP (hash)..."
 	find /tmp -type f -perm /+x -exec sha256sum {} + > tmp_file_hash_results.txt 2>> ../err
	echo "	  Collecting SUSPICIOUS File ..."
	find /tmp -type f -perm /+x -print0 | xargs -0 tar -czvf File_Excuteable_TMP.tar.gz > "File_Excuteable_TMP.txt" 2>> ../err
	echo "	  Collecting file modify last 1 DAY..."
	find /home/ /etc/ -type d -name .cache -prune -o -type f -mtime -1 -print  > "last_1_day_file_modify.txt" 2>> ../err
	echo "	  Collecting file ELF in Log..."
	grep [[:cntrl:]] /var/log/*.log > "elf_in_log.txt" 2>> ../err

	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: web server scripts are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..  
}

#@> USER SUSPICIUS
USER_SUSPICIUS(){
	#
	# @desc   :: This function saves USER SUSPICIUS
	#
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|${BK}		${NORMAL}" | tr -d '\n' | echo -e "| Processing suspicious files... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	echo -e "+---------------------------------------------------------------------------+"
	mkdir USER_SUSPICIUS && cd USER_SUSPICIUS
	echo "	  Collecting list root user ..."
	grep ":0:" /etc/passwd > "list_root_user.txt" 2>> ../err
	echo "	  Collecting Sudoers permission ..."
	cat /etc/sudoers > "sudoers.txt" 2>> ../err
	echo "	  Collecting List user Loginable ..."
	cat /etc/passwd | cut -d: -f1,3,4,5,6,7 | grep -vE '(nologin|halt|false|shutdown|sync)' | sort > "list_user_loginable.txt" 2>> ../err
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " COLLECTED: suspicious files are successfully saved. ${BK}${NORMAL} (${YELLOW}OK${NORMAL})"
	cd ..  
}


#@> PERSISTENT SUSPICIOUS
PERSISTENT_SUSPICIOUS(){
	#
	# @desc   :: This function saves PERSISTENT_SUSPICIOUS
	#
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|${BK}		${NORMAL}" | tr -d '\n' | echo -e "| Processing suspicious PERSISTENT... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	echo -e "+---------------------------------------------------------------------------+"
	mkdir PERSISTENT_SUSPICIOUS && cd PERSISTENT_SUSPICIOUS

	echo "	  Collecting Crontab per user ..."
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l | grep -v "^#"; done > "cron_per_user.txt" 2>> ../err
	echo "	  Collecting list-timers ..."
	systemctl list-timers --all > "list-timers.txt" 2>> ../err
	cd ..  

	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|===================== ${GREEN}Done!, Collecting successfully${NORMAL} ======================|"
	echo -e "+---------------------------------------------------------------------------+"
	read -rsp $'Press ENTER to continue... \n'

}

${GREEN} ${NORMAL} 
#-----------------------------------------------------------------------------------------------------------------------------------------------------------

VIEW_NETWORK_SUSPICIUS(){
	#
	# @desc   :: This function saves NETWORK_SUSPICIUS
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " VIEWING.. NETWORK_SUSPICIUS... ${BK}${NORMAL} (${YELLOW}it may take time${NORMAL})"
	cd NETWORK_SUSPICIUS
	echo -e "	  ${YELLOW}Viewing.. LSOF with IP ...${NORMAL}"
	cat "List_open_files_contain_ipv4.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. netstat with PID ...${NORMAL}"
	cat "netstat_with_PID.txt" | more 2>&1
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${GREEN} Done!${NORMAL}"
	echo -e "+---------------------------------------------------------------------------+"
 	read -rsp $'Press ENTER to continue... \n'
	cd ..
}


#@> PROCESS SUSPICIUS
VIEW_PROCESS_SUSPICIUS(){
	#
	# @desc   :: This function saves PROCESS SUSPICIUS
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " VIEWING.. PROCESS_SUSPICIUS ... ${BK}${NORMAL} "
	cd PROCESS_SUSPICIUS
	echo -e "	  ${YELLOW}Viewing.. deleted still running ...${NORMAL}"
	cat "Process_deleted_but_running.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. Real Process running path ...${NORMAL}"
	cat "Real_process_running_path.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. Process running with suspicious CWD ...${NORMAL}"
	cat "Process_running_with_suspicious_CWD.txt" | more 2>&1
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${GREEN} Done!${NORMAL}"
	echo -e "+---------------------------------------------------------------------------+"
 	read -rsp $'Press ENTER to continue... \n'
	cd ..
}


#@> FILES SUSPICIUS
VIEW_FILES_SUSPICIUS(){
	#
	# @desc   :: This function saves FILES SUSPICIUS
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " VIEWING.. FILES_SUSPICIUS... ${BK}${NORMAL} "
	cd FILES_SUSPICIUS
	#echo -e "	  ${YELLOW}Viewing.. immutable files and directories...${NORMAL}"
	#cat "immutable_files_and_directories.txt" | more 2>&1
	#read -rsp $'Press ENTER to continue... \n'
	#echo -e "	  ${YELLOW}Viewing.. decentralized File and DIR...${NORMAL}"
	#cat "decentralized_file_dir.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. list File ELF in TMP...${NORMAL}"
	cat "ELF_file_in_TMP.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. list File hide in TMP...${NORMAL}"
	cat "File_hidden_TMP.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. list File hide in TMP (hash)...${NORMAL}"
 	cat "tmp_file_hash_results.txt" | more 2>&1
 	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. SUSPICIOUS File ...${NORMAL}"
	cat "File_Excuteable_TMP.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. file modify last 1 DAY...${NORMAL}"
	cat "last_1_day_file_modify.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. file ELF in Log...${NORMAL}"
	cat "elf_in_log.txt" | more 2>&1
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${GREEN} Done!${NORMAL}"
	echo -e "+---------------------------------------------------------------------------+"
 	read -rsp $'Press ENTER to continue... \n'
	cd ..  
}

#@> USER SUSPICIUS
VIEW_USER_SUSPICIUS(){
	#
	# @desc   :: This function saves USER SUSPICIUS
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " VIEWING.. suspicious files... ${BK}${NORMAL} "
	cd USER_SUSPICIUS
	echo -e "	  ${YELLOW}Viewing.. list root user ...${NORMAL}"
	cat "list_root_user.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. Sudoers permission ...${NORMAL}"
	cat "sudoers.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. List user Loginable ...${NORMAL}"
	cat "list_user_loginable.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${GREEN} Done!${NORMAL}"
	echo -e "+---------------------------------------------------------------------------+"
 	read -rsp $'Press ENTER to continue... \n'
	cd ..  
}


#@> PERSISTENT SUSPICIOUS
VIEW_PERSISTENT_SUSPICIOUS(){
	#
	# @desc   :: This function saves PERSISTENT_SUSPICIOUS
	#
	echo -e "${BK}		${NORMAL}" | tr -d '\n' | echo -e " VIEWING.. suspicious PERSISTENT... ${BK}${NORMAL} "
	cd PERSISTENT_SUSPICIOUS
	echo -e "	  ${YELLOW}Viewing.. Crontab per user ...${NORMAL}"
	cat "cron_per_user.txt" | more 2>&1
	read -rsp $'Press ENTER to continue... \n'
	echo -e "	  ${YELLOW}Viewing.. list-timers ...${NORMAL}"
	cat "list-timers.txt" | more 2>&1
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "${GREEN} Done!${NORMAL}"
	echo -e "+---------------------------------------------------------------------------+"
 	read -rsp $'Press ENTER to continue... \n'
	cd ..  
}

#@> SENDING FINAL NOTIFICATION
SEND_NOTE(){
	echo -e ""
	echo -e "${BK} COMPLETED ${NORMAL}"
	echo -e "${GREEN}[CLLF] - Scanning completed at $(date)${NORMAL}" 
	echo -e "\n\n"
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "|    2024 - ____ _____ ________ | Threat Hunting and Incident Response      |"
	echo -e "+---------------------------------------------------------------------------+"
	echo -e "\n\n"
}

RUN(){

 	NETWORK_SUSPICIUS
	PROCESS_SUSPICIUS
	FILES_SUSPICIUS
	USER_SUSPICIUS
	PERSISTENT_SUSPICIOUS

 	VIEW_NETWORK_SUSPICIUS
	VIEW_PROCESS_SUSPICIUS
	VIEW_FILES_SUSPICIUS
	VIEW_USER_SUSPICIUS
	VIEW_PERSISTENT_SUSPICIOUS
}


while true
do
	BANNER
	RUN
	SEND_NOTE
	break 0 2>/dev/null
done

#CLEAN_UP
exit 0
