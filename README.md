# CLLF - Collect Linux Logs Forensic
## Usage
[Just run with root]
* ./CLLF.sh [-h]  (For most cases).
* ./CLLF_Restricted_SHELL.sh -h  (In case Linux shell restricted).

**Syntax Usage CLLF**

```bash

                
                ░█████╗░██╗░░░░░██╗░░░░░███████╗
                ██╔══██╗██║░░░░░██║░░░░░██╔════╝
                ██║░░╚═╝██║░░░░░██║░░░░░█████╗░░
                ██║░░██╗██║░░░░░██║░░░░░██╔══╝░░
                ╚█████╔╝███████╗███████╗██║░░░░░
                ░╚════╝░╚══════╝╚══════╝╚═╝░░░░░
    

[CLLF] == A Collecter Collect Linux Logs Forensic by (XM)

Syntax Usage CLLF:
./CLLF.sh [-h] [Just run with root]

Example Usage:
./CLLF.sh

```


**Syntax Usage CLLF_Restricted_SHELL.sh**: 	
```bash
./CLLF_Restricted_SHELL.sh [-l full/lite] [-o output destination]
./CLLF_Restricted_SHELL.sh [-h] [Just run with root]

Flags:
  -l, --log           Logs collect options        -l full
        "full" is Full folder /var/log (Maybe so big...)
        "lite" is Common Linux log files names and usage

Optional Flags:
  -o, --OUTDIR        Write to output folde       -o "10.0.1.134"
Example Usage:

./CLLF.sh -l full -o 10.0.1.134
```
> [!WARNING]
> I will not update CLLF_Restricted_SHELL.sh anymore, pls use CLLF.sh or Edit your script manually.



## Edit Config File at CLLF.config
~~~
# Config File while using CLLF
# Just use "true" and "false" for parameter value.
# 
#
#
#run_liveIR=true                                                                      Live IR
#check_liveIR=true                                                                    Check results Live IR
#get_metadatatime=true                                                                Get all metadata off file and folder, Like MFT in Windows
#get_config=false                                                                     Just copy Full /ETC folder ;D
#get_logs=true                                                                        Just copy Full /var/log folder ;D
#get_hidden_file_folder=true                                                          Copy all File in Hidden Folder at HOME
#get_disk=false                                                                       Disk INFO
#verify_package=false                                                                 dpkg -V
#VR="v1.1"                                                                            ...
#OUTDIR=Logs_$(hostname -I | awk '{print $1}')_$(hostname)_$(date +%F_%H-%M-%S)       OUTDIR
################################################
~~~

## Fix some errors while using CLLF

```bash
XM:~ chmod +x CLLF.sh && ./CLLF.sh
Error: ./CLLF.sh : /bin/bash^M : bad interpretor: No such file or directory
                                                    
# fix
XM:~ sed -i -e 's/\r$//' CLLF.sh
```

## Extract the Files after collecting

```bash
XM:~ for file in $(find . -name "*.tar.gz"); do tar -xvf "${file}" -C "$(dirname "${file}")"; done
```

