metasploitHelper (msfHelper)
================  
##Slides for Black Hat Asia 2017
https://goo.gl/pSUgnc

##Introduction
metasploitHelper is meant to assist penetration testers in network penetration tests. 

metasploitHelper (msfHelper) communicates with Metasploit via msrpc.  It uses both port and web related exploits from Metasploit. 

You can point msfHelper at an IP address/Nmap xml file/File containing list of Ip addresses. 

it performs a nmap scan of the target host(sh and then attempt to find compatible and possible Metasploit modules based on 1) nmap service banner and 2) service name and run them against the targets.

It is also possible to use the -m option in msfHelper along with msfconsole (load msgrpc Pass=xxx) if you would like to interact with the targets that msfHelper had compromised.
  
msfHelper by default only test ports which were found in metasploit modules.  If you would like to scan all ports, please use the -a option.
    
##Requirements
```
Kali Linux 2016.2 VM

$ apt-get install git-core -y 
$ git clone https://github.com/SpiderLabs/msfrpc
$ cd msfrpc && cd python-msfrpc && python setup.py install
$ pip install tabulate termcolor python-libnmap msgpack-python tabulate beautifulsoup4 termcolor requests
$ git clone https://github.com/milo2012/metasploitHelper
$ python msfHelper.py x.x.x.x -i 

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

```    
- Scan and test all ports on target host  
```  
python msfHelper.py 192.168.1.6 -i -a
 
```    
- Enable verbose mode (see results from Metasploit modules  
```  
python msfHelper.py 192.168.1.6 -i -v
 
 
```    
- Run msfHelper and interact with the shells
```  
#on the first terminal window
$ msfconsole
$ load msgrpc Pass=xxxxx

#on the second terminal window
python msfHelper.py 192.168.1.6 -i -m -P xxxxx
 
```    
- As Nmap sometimes is unable to fingerprint the target port accurately, you might want to use the --info option to retrieve information from speedguide (google cache) as to what applications typically use the port
```  
python msfHelper.py 192.168.1.6 -i --info

```    
- Do not run metasploit modules. Only run exploit-db detection
```  
python msfHelper.py 192.168.1.6 -e exploitdb
 

```    
- Run "port" based detection
```  
python msfHelper.py 192.168.1.6 -i -e ports
 

```    
- Run "services" based detection
```  
python msfHelper.py 192.168.1.6 -i -e services


```    
- Run "web" based detection
```  
python msfHelper.py 192.168.1.6 -i -e web
 

