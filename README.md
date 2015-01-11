# metasploitHelper
metasploitHelper (Work in Progress)  
  
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot1.png)  

Below is a sample screenshot of the application    
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot2.png)  
  
Features to be added
- The script will take a Nmap XML file as input.
- For HTTP/HTTPs related exploits, the script will extract all TARGETURI from the metasploit modules and attempts to try to see if the URIs are present on the HTTP/HTTPs server
- For other ports that match the ones in Metasploit, the Metasploit modules will be launched against the target without fingerprint the actual service running on the target server (blind hacking).

