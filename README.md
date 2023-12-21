# Collect Linux Logs Forensic



## Usage


```bash

                
                ░█████╗░██╗░░░░░██╗░░░░░███████╗
                ██╔══██╗██║░░░░░██║░░░░░██╔════╝
                ██║░░╚═╝██║░░░░░██║░░░░░█████╗░░
                ██║░░██╗██║░░░░░██║░░░░░██╔══╝░░
                ╚█████╔╝███████╗███████╗██║░░░░░
                ░╚════╝░╚══════╝╚══════╝╚═╝░░░░░
    

[CLLF] == A Collecter Collect Linux Logs Forensic by (XM)

Syntax Usage:
./CLLF.sh [-h] [Just run with root] (For most cases)
./CLLF_Restricted_SHELL.sh -h  (In case Linux shell restricted)

Example Usage:
./CLLF.sh

```

## Edit Config File at CLLF.config
~~~
get_metadatatime=true
get_config=false
get_logs=true
get_hidden_home_file=true
get_disk=false
verify_package=false
VR="v1.1"
OUTDIR=Logs_$(hostname -I | awk '{print $1}')_$(hostname)_$(date +%F_%H-%M-%S)
~~~

## Fix errors while using CLLF

```bash
XM:~ chmod +x CLLF.sh && ./CLLF.sh
Error: ./CLLF.sh : /bin/bash^M : bad interpretor: No such file or directory
                                                    
# fix
XM:~ sed -i -e 's/\r$//' install.sh
```

## Extract the Files after collecting

```bash
XM:~ for file in $(find . -name "*.tar.gz"); do tar -xvf "${file}" -C "$(dirname "${file}")"; done
```

