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
./CLLF.sh [-l log.op] [-o output destination]

Flags:
   -l, --log                                            Logs collect options                    -l full
          "full" is Full folder /var/log (Maybe so big...)
          "lite" is Common Linux log files names and usage

Optional Flags:
   -o, --OUTDIR                                         Write to output folder                  -o "10.0.1.134"
Example Usage:
./CLLF.sh -l full -o 10.0.1.134


```

## Fix errors while using CLLF

```bash
XM:~ chmod +x CLLF.sh && ./CLLF.sh -l full -o 192.168.13.27
Error: ./CLLF.sh : /bin/bash^M : bad interpretor: No such file or directory
                                                    
# fix
XM:~ sed -i -e 's/\r$//' install.sh
```

## Extract the Files after collecting

```bash
XM:~ for file in $(find . -name "*.tar.gz"); do tar -xvf "${file}" -C "$(dirname "${file}")"; done
```

