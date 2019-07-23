metasploitHelper (msfHelper)
================  
**Slides for Black Hat Asia 2017 :**
https://goo.gl/pSUgnc

## Introduction
metasploitHelper is meant to assist penetration testers in network penetration tests.

metasploitHelper (`msfHelper`) communicates with Metasploit via *msrpc*. It uses both port and web related exploits from Metasploit.

You can point msfHelper at an IP address/Nmap XML file/File containing list of Ip addresses.

First, it performs a Nmap scan of the target host(s) and then attempt to find compatible and possible Metasploit modules based on 1) *nmap service banner* and 2) *service name* and run them against the targets.  

Please see the slides above for more information regarding the tool as well as the video demo.

It is also possible to use the `-m` option in `msfHelper` along with msfconsole (load msgrpc Pass=xxx) if you would like to interact with the targets that msfHelper had compromised.

msfHelper by default only test ports which were found in metasploit modules.  If you would like to scan all ports, please use the `-a` option.
  
## Demo  
- The demo shows running msfHelper (exploit modules) against Metasploitable 2   
```
sudo python msfHelper.py -a 172.16.126.132 -t exploit
```
<a href="https://asciinema.org/a/9ZQ6OVWDpv0XMbpOWvvBhEB2A?autoplay=1" target="_blank"><img src="https://preview.ibb.co/no2GTo/Screen_Shot_2018_07_29_at_10_02_53_PM.png"/></a>  
  
## Docker

- Building from Dockerfile

```
docker build -t metasploithelper .
docker run --rm -it milo2012/metasploithelper
python msfHelper.py -a testphp.vulnweb.com
```

- Pull latest Docker image

```
docker pull milo2012/metasploithelper
docker run --rm -it milo2012/metasploithelper
python msfHelper.py -a testphp.vulnweb.com
```

- To see help menu

```  
docker pull milo2012/metasploithelper
docker run --rm -it milo2012/metasploithelper
python msfHelper.py -h
```
## Requirements

On *Kali Linux 2016.2 VM*

```bash
$ apt-get install git-core -y
$ git clone https://github.com/SpiderLabs/msfrpc
$ cd msfrpc && cd python-msfrpc && python setup.py install
$ pip install tabulate termcolor python-libnmap msgpack-python beautifulsoup4 termcolor requests
$ git clone https://github.com/milo2012/metasploitHelper
$ python msfHelper.py x.x.x.x -i
```  

## Usage

```
root@kali:/code# python msfHelper18.py -h
usage: PROG [-h] [-P MYPASSWORD] [-p PORTSINPUT] [-o OUTPUTDIRECTORY] [-i]
            [-m] [-a] [-n THREADS] [-u] [-q] [-gt GREATERTHAN] [--info] [-v]
            [-s] [-t CATEGORY] [-e {services,web,all,ports}]
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
  -o OUTPUTDIRECTORY    Location to save portList.csv, pathList.csv, nmap scan
                        results
  -i                    Intelligent mode (Match the Nmap service banner with
                        the Metasploit modules
  -m, --manual          Manually start up Msfconsole and 'load msgrpc
                        Pass=xxxx'
  -a, --scanall         Scan all 65535 TCP ports
  -n THREADS            Set how many concurrent threads to use (default: 5)
  -u, --update          Update Metasploit and metasploitHelper DB
  -q, --quick           Performs a quick scan - Do not use modules where
                        TARGETURI is set to /
  -gt GREATERTHAN       Only scan TCP ports greater than x number
  --info                Lookup information about ports online
  -v, --verbose         Verbose mode
  -s, --showonly        Show matching Metasploit modules but don't run
  -t CATEGORY           Choose between 'exploit' or 'auxiliary'

Whether to run Metasploit 'services', 'ports', 'web' modules or 'exploitdb':
  Options for executing commands

  -e {services,web,all,ports}, --exec-method {services,web,all,ports}
```  

## Sample Usage Examples

**Use the intelligent mode and scan/test the target IP :**
```
python msfHelper.py 192.168.1.6 -i
```

**Specify the ports to be tested :**
```
python msfHelper.py 192.168.1.6 -i -p 21,5432
```

**Run metasploit modules that matches the port number/services/uri paths:**
```
python msfHelper.py 192.168.1.6 -i -e ports
python msfHelper.py 192.168.1.6 -i -e services
python msfHelper.py 192.168.1.6 -i -e web
```

**Scan and test all ports on target host :**
```
python msfHelper.py 192.168.1.6 -i -a
```

**Enable verbose mode (see output from Metasploit :**
```
python msfHelper.py 192.168.1.6 -i -v
```

**Run msfHelper and interact with the shells :**
```
#on the first terminal window
$ msfconsole
$ load msgrpc Pass=xxxxx

#on the second terminal window
python msfHelper.py 192.168.1.6 -i -m -P xxxxx
```

