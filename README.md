# metasploitHelper
metasploitHelper (Work in Progress)  
  
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot1.png)  

Below is a sample screenshot of the application    
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot2.png)  
  
Features to be added
- The script will take a Nmap XML file as input.
- For HTTP/HTTPs related exploits, the script will extract all TARGETURI from the metasploit modules and attempts to try to see if the URIs are present on the HTTP/HTTPs server
- For other ports that match the ones in Metasploit, the Metasploit modules will be launched against the target without fingerprint the actual service running on the target server (blind hacking).  
  
  
Below are the list of ports found in Metasploit modules (7 Jan 2015)
```
1
19
21
22
23
25
42
49
53
69
79
80
81
85
105
110
111
113
123
135
137
138
139
143
161
264
389
402
407
443
444
445
446
502
512
513
514
515
523
524
548
554
623
631
689
705
783
873
888
902
910
912
998
1000
1099
1100
1128
1158
1211
1220
1241
1311
```
