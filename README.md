# metasploitHelper
metasploitHelper (Work in Progress)  

The reason for this script is that I want to be be able to take a NMAP xml file as input, automatically search for a Metasploit module and launches the Metasploit module against it.  
  
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
1434
1521
1530
1533
1581
1582
1604
1720
1723
1755
1811
1900
2000
2001
2049
2067
2100
2103
2207
```
