# metasploitHelper
metasploitHelper (Work in Progress)  

The reason for this script is that I want to be be able to take a NMAP xml file as input, automatically search for a Metasploit module and launches the Metasploit module against it.    

Denial of service (DoS) modules in Metasploit are excluded.

```
metasploitHelper.py    Uses a nmap .nmap file as input and metasploit modules (web/ports) and generate a metasploit resource script.
```   
  
**metasploitHelper.py**  
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot3.png)  

**Requirements:**  
pip install python-libnmap  
pip install requests --upgrade  
    
**Sample Commands:**    
Test HTTP/HTTPs services to see if any URI listed in default-path.csv exists and list the relevant metasploit module.  
List the metasploit module matching the port number    
- python metasploitHelper.py -i nmap.xml  
  
List only matching URI metasploit modules  
- python metasploitHelper.py -i nmap.xml -findweb  
  
List only metasploit module matching the port number   
- python metasploitHelper.py -i nmap.xml -findPort  

  
**searchMSF.py**    
To generate an updated version of port2Msf.csv, use the below command  
- python searchMSF.py -all  
    
**uriList.txt**    
- This file contains the list of URIs gathered from Metasploit modules  
  
**port2Msf.csv**      
- This file contains the ports to metasploit module mapping (along with any additional variables that are required to be supplied)  
  
**default-path.csv**      
- This file contains the uri to metasploit module mapping   
          
