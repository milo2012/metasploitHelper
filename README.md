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
usage: metasploitHelper.py [-h] [-i NMAPFILE] [-o MSFRC] [-nocache] [-findWeb]
                           [-findPort]  
optional arguments:  
  -h, --help   show this help message and exit  
  -i NMAPFILE  [use Nmap .xml file]  
  -o MSFRC     [metasploit resource script]  
  -nocache     [search Metasploit folder instead of using default-path.csv and  
               port2Msf.csv (default=off]  
  -findWeb     [find only HTTP/HTTPs exploits (default=on)]  
  -findPort    [find only port-based matched exploits (default=on)]  
```  
     
##Sample Usage Examples
- Generate a metasploit resource script containing the list of exploits matching the port number and HTTP/HTTPs URI path.
```  
python metasploitHelper.py -i nmap.xml  
```    
- List only metasploit modules matching target URI in HTTP/HTTPs servers
```  
python metasploitHelper.py -i nmap.xml -findweb  
```    
- List only metasploit modules matching the port number   
```  
python metasploitHelper.py -i nmap.xml -findPort   
```  
      
##Description of Files  
- uriList.txt - This file contains the list of URIs gathered from Metasploit modules  
- port2Msf.csv - This file contains the ports to metasploit module mapping (along with any additional variables that are required to be supplied)  
- default-path.csv - This file contains the uri to metasploit module mapping   
  
##Example  
```   
root@kali:/git/metasploitHelper# python metasploitHelper.py -i nmapt_target1.xml 
- Brute Forcing URLs...
Found: http://149.174.110.102:80/SiteScope/                                    200      

Metasploit resource script: runMsf.rc written.
```  
