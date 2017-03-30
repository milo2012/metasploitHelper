metasploitHelper  
================  
##Introduction

- TLDR. Metasploit contains port-based modules as well as URI-based modules (web servers). This tool bridges Nmap XML file with Metasploit and generates a resource script containing matching Metasploit modules. that you can run against the target servers.

##Longer Introduction
- The script checks for metasploit modules matching the port number listed in the nmap XML file.  
- The script also brute force  URIs listed in urlList.txt against the web services and when found, it will perform a lookup against Metasploit.
- The script then generates a metasploit resource script for the matching modules so that you can run the metasploit modules easily against the target hosts via the command "msfconsole -r msfRun.rc"  
- Denial of service (DoS) modules in Metasploit are excluded.
  
##Requirements
```
- Python 2.7
- pip install python-libnmap  
- pip install requests --upgrade  
```  
  
##Usage  
```
root@kali:/code# python msfHelper18.py  -h
usage: PROG [-h] [-P MYPASSWORD] [-p PORTSINPUT] [-i] [-m] [-a] [-n THREADS]
            [-u] [-q] [--info] [-v] [-s]
            [-e {services,web,all,ports,exploitdb}]
            [target [target ...]]

                __ _   _      _                 
 _ __ ___  ___ / _| | | | ___| |_ __   ___ _ __ 
| '_ ` _ \/ __| |_| |_| |/ _ \ | '_ \ / _ \ '__|
| | | | | \__ \  _|  _  |  __/ | |_) |  __/ |   
|_| |_| |_|___/_| |_| |_|\___|_| .__/ \___|_|   
                               |_|              

+-- https://github.com/milo2012/metasploitHelper

positional arguments:
  target                The target IP(s), range(s), CIDR(s), hostname(s),
                        FQDN(s) or file(s) containg a list of targets

optional arguments:
  -h, --help            show this help message and exit
  -P MYPASSWORD         Password to connect to msfrpc
  -p PORTSINPUT         Only scan specific TCP ports
  -i                    Intelligent mode (Match the Nmap service banner with
                        the Metasploit modules
  -m, --manual          Manually start up Msfconsole and 'load msgrpc
                        Pass=xxxx'
  -a, --scanall         Scan all 65535 TCP ports
  -n THREADS            Set how many concurrent threads to use (default: 5)
  -u, --update          Update Metasploit and metasploitHelper DB
  -q, --quick           Performs a quick scan - Do not use modules where
                        TARGETURI is set to /
  --info                Lookup information about ports online
  -v, --verbose         Verbose mode
  -s, --showonly        Show matching Metasploit modules but don't run

Whether to run Metasploit 'services', 'ports', 'web' modules or 'exploitdb':
  Options for executing commands

  -e {services,web,all,ports,exploitdb}, --exec-method {services,web,all,ports,exploitdb}

```  
     
##Sample Usage Examples
- Use the intelligent mode and scan/test the target IP
```  
python msfHelper.py 192.168.1.6 -i
```    
- Specify the ports to be tested
```  
python msfHelper.py 192.168.1.6 -i -p 21,5432  
```    
- Run metasploit modules that matches the port number   
```  
python msfHelper.py 192.168.1.6 -i -e ports
