# metasploitHelper
**Introduction**

The reason for this script is that I want to be be able to take a NMAP xml file as input, automatically search for a Metasploit module and launches the Metasploit module against it.    
The script checks for metasploit modules matching the port number listed in the nmap XML file.  
The script also test URIs listed in urlList.txt against the web services and list the matching metasploit modules.  
The script then generates a metasploit resource script for the matching modules so that you can run the metasploit modules easily against the target hosts via the command "msfconsole -r msfRun.rc"  
  
Denial of service (DoS) modules in Metasploit are excluded.
  
    
**metasploitHelper.py**  
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot3.png)  

**Requirements:**  
pip install python-libnmap  
pip install requests --upgrade  

**Usage**  
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
     
**Sample Usage Examples:**    
Generate a metasploit resource script containing the list of exploits matching the port number and HTTP/HTTPs URI path.
- python metasploitHelper.py -i nmap.xml  
  
List only metasploit modules matching target URI in HTTP/HTTPs servers
- python metasploitHelper.py -i nmap.xml -findweb  
  
List only metasploit modules matching the port number   
- python metasploitHelper.py -i nmap.xml -findPort   
    
**Description of Files**  
- uriList.txt - This file contains the list of URIs gathered from Metasploit modules  
- port2Msf.csv - This file contains the ports to metasploit module mapping (along with any additional variables that are required to be supplied)  
- default-path.csv - This file contains the uri to metasploit module mapping   
          
