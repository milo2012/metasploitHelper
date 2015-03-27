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
usage: metasploitHelper.py [-h] [-i NMAPFILE] [-v] [-nocache] [-findWeb]
                           [-findPort] [-detect] [-enableRoot]

optional arguments:
  -h, --help   show this help message and exit
  -i NMAPFILE  [use Nmap .xml file]
  -v           [verbose (default=false)]
  -nocache     [search Metasploit folder instead of using default-path.csv and
               port2Msf.csv (default=off]
  -findWeb     [find only HTTP/HTTPs exploits (default=on)]
  -findPort    [find only port-based matched exploits (default=on)]
  -detect      [find Metasploit http module matched based on both URI and page
               title (default=off)]
  -enableRoot  [include Metasploit modules for root URI / (default=off)]
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

- Initial Testing with Random URLs...

- Brute Forcing URLs...
Found: http://192.168.112.167:80/index.php                                    200       

- Initial Testing with Random URLs...

- Brute Forcing URLs...
Found: http://192.168.112.167:8180/index.jsp                                  200       
Found: http://192.168.112.167:8180/manager/html                               401       
Found: http://192.168.112.167:8180/admin/index.jsp                            200       

Metasploit resource script: runAux.rc written.
Metasploit resource script: runExp.rc written.
Report written to report.txt.
root@kali:/git/metasploitHelper# python metasploitHelper.py -i nmapt_target.xml

- Initial Testing with Random URLs...

- Brute Forcing URLs...
Found: http://192.168.112.167:80/index.php                                    200       

- Initial Testing with Random URLs...

- Brute Forcing URLs...
Found: http://192.168.112.167:8180/index.jsp                                  200       
Found: http://192.168.112.167:8180/manager/html                               401       
Found: http://192.168.112.167:8180/admin/index.jsp                            200       

Metasploit resource script: runAux.rc written.
Metasploit resource script: runExp.rc written.
Report written to report.txt.

```  
