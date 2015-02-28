metasploitHelper  
================  
##Introduction

- The reason for this script is that I want to be be able to take a NMAP xml file as input, automatically search for a Metasploit module and launches the Metasploit module against it.    
- The script checks for metasploit modules matching the port number listed in the nmap XML file.  
- The script also test URIs listed in urlList.txt against the web services and list the matching metasploit modules.  
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
http://100.4.1.2:80/sflog/                                       404       
http://100.4.1.2:80/qdPM/                                        404       
http://100.4.1.2:80/x7chat2                                      404       
http://100.4.1.2:80/bf102/                                       404       
http://100.4.1.2:80/SiteScope/                                   404       
http://100.4.1.2:80/mediawiki                                    404       
http://100.4.1.2:80/AjaXplorer-2.5.5/                            404       
http://100.4.1.2:80/mobilecartly/                                404       
http://100.4.1.2:80/vtigercrm/                                   404       
http://100.4.1.2:80/testlink-1.9.3/                              404       
http://100.4.1.2:80/vtigercrm/                                   404       
http://100.4.1.2:80/phpwiki                                      404       
http://100.4.1.2:80/manager                                      404       
http://100.4.1.2:80/struts2-blank/example/HelloWorld.action      404       
http://100.4.1.2:80/wikka/                                       404       
http://100.4.1.2:80/IDC.php                                      404       
http://100.4.1.2:80/struts2-blank/example/HelloWorld.action      404       
http://100.4.1.2:80/Auxiliumpetratepro/                          404       
http://100.4.1.2:80/invoker/JMXInvokerServlet                    404       
http://100.4.1.2:80/IDC.php                                      404       
http://100.4.1.2:80/interface/                                   404       
http://100.4.1.2:80/jos.php                                      404       
http://100.4.1.2:80/phptax/                                      404       
http://100.4.1.2:80/struts2-blank/example/HelloWorld.action      404       
http://100.4.1.2:80/openx/                                       404       
http://100.4.1.2:80/roller                                       404       
http://100.4.1.2:80/appRain-q-0.1.5                              404       
http://100.4.1.2:80/polarbearcms                                 404       
http://100.4.1.2:80/kordil_edms/                                 404       
http://100.4.1.2:80/log1cms2.0/                                  404       
http://100.4.1.2:80/com_extplorer_2.1.0/                         404       
http://100.4.1.2:80/glpi/                                        404       
http://100.4.1.2:80/glossword/1.8/                               404       
http://100.4.1.2:80/mt                                           404       
http://100.4.1.2:80/jenkins/                                     404       
http://100.4.1.2:80/SiteScope/                                   404       
http://100.4.1.2:80/blank-struts2/login.action                   404       
http://100.4.1.2:80/cuteflow_v.2.11.2/                           404       
http://100.4.1.2:80/moodle/                                      404       
http://100.4.1.2:80/phpmyadmin/                                  404       
http://100.4.1.2:80/gestioip/                                    404       
http://100.4.1.2:80/pandora_console/                             404       
http://100.4.1.2:80/www/                                         404       
http://100.4.1.2:80/zabbix/                                      404       
http://100.4.1.2:80/struts2-blank/example/HelloWorld.action      404       
http://100.4.1.2:80/index.jsp                                    404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/ctc/servlet                                  404       
http://100.4.1.2:80/d4d/statusFilter.php                         404       
http://100.4.1.2:80/cms400min/                                   404       
http://100.4.1.2:80/php/test.php                                 404       
http://100.4.1.2:80/ws/control                                   404       
http://100.4.1.2:80/umbraco/                                     404       
http://100.4.1.2:80/autopass                                     404       
http://100.4.1.2:80/vfolder.ghp                                  404       
http://100.4.1.2:80/SiteScope/                                   404       
http://100.4.1.2:80/soap                                         404       
http://100.4.1.2:80/pandora_console/                             404       
http://100.4.1.2:80/vcms/                                        404       
http://100.4.1.2:80/railo-context/                               404       
http://100.4.1.2:80/WebCalendar-1.2.4/                           404       
http://100.4.1.2:80/dolibarr/                                    404       
http://100.4.1.2:80/WeBid                                        404       
http://100.4.1.2:80/zabbix                                       404       
http://100.4.1.2:80/chat/                                        404       
http://100.4.1.2:80/centreon                                     404       
http://100.4.1.2:80/spywall/pbcontrol.php                        404       
http://100.4.1.2:80/hybridauth/                                  404       
http://100.4.1.2:80/forums/                                      404       
http://100.4.1.2:80/kimai/                                       404       
http://100.4.1.2:80/hastymail2/                                  404       
http://100.4.1.2:80/GetSimpleCMS                                 404       
http://100.4.1.2:80/seportal                                     404       
http://100.4.1.2:80/basilic-1.5.14/                              404       
http://100.4.1.2:80/sugarcrm/                                    404       
http://100.4.1.2:80/lite/                                        404       
http://100.4.1.2:80/php-charts_v1.0/                             404       
http://100.4.1.2:80/opensis/                                     404       
http://100.4.1.2:80/zimbraAdmin                                  404       
http://100.4.1.2:80/horde/                                       404       
http://100.4.1.2:80/php-ofc-library/                             404       
http://100.4.1.2:80/librettoCMS_v.2.2.2/                         404       
http://100.4.1.2:80/pp088/                                       404       
http://100.4.1.2:80/zm/                                          404       
http://100.4.1.2:80/ProjectSend/                                 404       
http://100.4.1.2:80/openemr                                      404       
http://100.4.1.2:80/narcissus-master/                            404       
http://100.4.1.2:80/openemr                                      404       
http://100.4.1.2:80/simple_e_document_v_1_31/                    404       
http://100.4.1.2:80/joomla                                       404       
http://100.4.1.2:80/xoda/                                        404       
http://100.4.1.2:80/sample                                       404       
http://100.4.1.2:80/index.php                                    404       
http://100.4.1.2:80/webtester5/                                  404       
http://100.4.1.2:80/tiki/                                        404       
http://100.4.1.2:80/joomla                                       404       
http://100.4.1.2:80/nagios3/cgi-bin/history.cgi                  404       
http://100.4.1.2:80/CimWeb                                       404       
http://100.4.1.2:80/PI/services/UCP/                             404       
http://100.4.1.2:80/apply.cgi                                    404       
http://100.4.1.2:80/users/password                               404       
http://100.4.1.2:80/openbravo/                                   404       
http://100.4.1.2:80/seam-booking/home.seam                       404       
http://100.4.1.2:80/ctc/servlet                                  404       
http://100.4.1.2:80/_all_dbs                                     404       
http://100.4.1.2:80/axis2/axis2-admin/login                      404       
http://100.4.1.2:80/zabbix/                                      404       
http://100.4.1.2:80/.svn/                                        404       
http://100.4.1.2:80/vcms2/                                       404       
http://100.4.1.2:80/Allegro                                      404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/manager/html                                 404       
http://100.4.1.2:80/forum/                                       404       
http://100.4.1.2:80/bitweaver/                                   404       
http://100.4.1.2:80/provision/index.php                          404       
http://100.4.1.2:80/clansphere_2011.3/                           404       
http://100.4.1.2:80/dolibarr/                                    404       
http://100.4.1.2:80/SiteScope/                                   200       
http://100.4.1.2:80/jenkins/                                     404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/SiteScope/                                   404       
http://100.4.1.2:80/SiteScope/                                   404       
http://100.4.1.2:80/crowd/services                               404       
http://100.4.1.2:80/mediawiki                                    404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/VPortal/mgtconsole/CheckPassword.jsp         404       
http://100.4.1.2:80/status                                       404       
http://100.4.1.2:80/data/login                                   404       
http://100.4.1.2:80/admin/index.jsp                              404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/imc                                          404       
http://100.4.1.2:80/www/                                         404       
http://100.4.1.2:80/sap/bc/soap/rfc                              404       
http://100.4.1.2:80/bvsmweb                                      404       
http://100.4.1.2:80/bvsmweb                                      404       
http://100.4.1.2:80/portal                                       404       
http://100.4.1.2:80/drupal                                       404       
http://100.4.1.2:80/userinfo/search                              404       
http://100.4.1.2:80/stmeetings/                                  404       
http://100.4.1.2:80/dolibarr/                                    404       
http://100.4.1.2:80/forum                                        404       

Metasploit resource script: runMsf.rc written.
```  
