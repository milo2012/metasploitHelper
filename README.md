# metasploitHelper
metasploitHelper (Work in Progress)  

The reason for this script is that I want to be be able to take a NMAP xml file as input, automatically search for a Metasploit module and launches the Metasploit module against it.    

Denial of service (DoS) modules in Metasploit are excluded.

```
metasploitHelper.py    Uses a nmap .nmap file as input and metasploit modules (web/ports) and generate a metasploit resource script.
extras\searchMSF.py    Search Metasploit modules folder             
                -       matching port number
                -       all TARGETURI paths
                -       all TARGETURI paths with matching module number
```   
  
**metasploitHelper.py**  
![alt tag](https://raw.githubusercontent.com/milo2012/metasploitHelper/master/screenshot3.png)  

Sample Commands:  
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
2362
2380
2381
2525
2940
2947
2967
3000
3037
3050
3057
3128
3200
3217
3299
3306
3389
3460
3500
3628
3632
3690
3780
3790
3817
4000
4322
4433
4444
4659
4672
4679
4848
5000
5038
5040
5051
5060
5061
5093
5168
5227
5247
5250
5355
5400
5405
5432
5466
5498
5554
5555
5560
5631
5632
5666
5800
5814
5900
5920
5984
6000
6050
6060
6070
6080
6101
6106
6112
6379
6405
6502
6503
6504
6542
6660
6661
6667
6905
6988
7000
7001
7021
7071
7144
7181
7210
7272
7426
7443
7510
7579
7580
7770
7777
7787
7902
8000
8001
8008
8014
8020
8028
8029
8030
8080
8082
8087
8090
8095
8161
8180
8222
8300
8400
8443
8503
8800
8812
8888
8899
9000
9002
9080
9084
9090
9100
9200
9390
9391
9495
9855
9999
10000
10001
10008
10051
10080
10202
10203
10628
11000
11211
11234
12174
12203
12221
12345
12345
12397
12401
12401
13364
13500
16102
17185
17185
18881
19810
20010
20031
20034
20101
20111
20111
20171
20222
22222
23472
26000
26122
27000
27017
27017
27888
27960
28784
30000
30000
30718
31001
32764
32764
32764
34205
34443
38080
38292
38292
40007
41025
41080
41523
41524
44334
44818
46823
46824
46824
48899
49152
49152
50000
50000
50000
50013
50013
50013
50013
50013
50013
50013
50013
50013
50013
50013
50013
50013
50013
52302
55553
57772
```
