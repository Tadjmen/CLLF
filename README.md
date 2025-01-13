# CLLF - Collect Linux Logs Forensic
## Usage
[Just run with root]
* ./CLLF.sh [-h]  (For most cases).

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
## 🌠 Star Evolution

Explore the star history of this project and see how it has evolved over time:
<picture>
  <p align="center">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="
      https://api.star-history.com/svg?repos=Tadjmen/CLLF&type=Date&theme=dark
    "
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="
      https://api.star-history.com/svg?repos=Tadjmen/CLLF&type=Date
    "
  />
  <img
    alt="Star History Chart" width="600" height="350"
    src="https://api.star-history.com/svg?repos=Tadjmen/CLLF&type=Date"
  />
  </p>
</picture>
Your support is greatly appreciated. We're grateful for every star! Your backing fuels our passion. ✨
