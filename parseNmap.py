#! /usr/bin/env python

import commands
import re
import argparse
import sys
import commands
import sys
import commands,os	
import re
import os
from struct import *
from socket import *

try:
	pass
except ImportError:
	print "wget https://pypi.python.org/packages/source/p/python-nmap/python-nmap-0.3.4.tar.gz --no-check-certificate"
	print "tar xvfz python-nmap-0.3.4.tar.gz"
	print "cd python-nmap-0.3.4"
	print "python setup.py install"
try:
	import argparse
except ImportError:
	print "wget https://pypi.python.org/packages/source/a/argparse/argparse-1.2.2.tar.gz"
	print "tar xvfz argparse-1.2.2.tar.gz"
	print "cd argparse-1.2.2"
	print "python setup.py install"
	
	print "wget https://pypi.python.org/packages/source/s/setuptools/setuptools-7.0.tar.gz"
	print "tar xvfz setuptools-7.0.tar.gz"
	print "cd setuptools-7.0"
	print "python setup.py install"

resultsEnd=[]
origPath= os.getcwd()

internalIP= False
verbose= False
runPeepingTom=True
runClusterd=True
runWebsitesLogin=False
runFindVhost=False
runWhatWeb=False
preview=False

#Paths to Tools
toolsPath= "/tmp1/tools"
peepingTomPath= toolsPath+"/peepingtom/"

ipList=[]
domainsList=[]
filteredUrlList=[]
uniquePorts=[]
runCmdList=[]
httpList=[]
sslList=[]
sshList=[]
telnetList=[]
ntpList=[]
loginList=[]
urlList=[]
javaRMIList=[]
splunkList=[]
epolicyList=[]
mssqlList=[]
jdwpList=[]
rexecList=[]
tildeList=[]
ftpList=[]
vpnList=[]
f5List=[]
tomcatList=[]
jbossList=[]
apacheList=[]
phpList=[]
drupalList=[]
wordpressList=[]

port25=[]
port53=[]
port137=[]
port139=[]
port161=[]
port445=[]
port512=[]
port513=[]
port554=[]
port873=[]
port902=[]
port1080=[]
port1099=[]
port1723=[]
port2002=[]
port2401=[]
port3050=[]
port3306=[]
port3389=[]
port5060=[]
port5222=[]
port5432=[]
port5666=[]
port5850=[]
port5900=[]
port6000=[]
port6379=[]
port8098=[]
port9160=[]
port9390=[]
port9391=[]
port9929=[]
port10000=[]
port27017=[]
port50000=[]

ipList=[]
scanTCPList=[]
scanUDPList=[]

reportOutput=[]
filename= ''

#fullCmd= "rm *.log"
#commands.getoutput(fullCmd)

def lookupPort(matchPort):
	#path= "/opt/metasploit/apps/pro/modules"
	path= "/pentest/metasploit-framework/modules"
	fullCmd= 'grep -ir "Opt::RPORT" '+path
	results=  RunCommand(fullCmd)
	portList=[]
	lookupList=[]
	exploitList=[]
	resultsList= results.split("\n")
	for result in resultsList:
		result1= result.split(".rb:")[1].strip()
		exploitModule= result.split(".rb:")[0].strip()+".rb"
		portNo= find_between(result1,"RPORT(",")")
		if not any(c.isalpha() for c in portNo):
			if len(matchPort)>0:
				if portNo==matchPort:
					if portNo not in portList:
						portList.append(portNo)
					if "fuzzer" not in exploitModule and "auxiliary/dos/" not in exploitModule:
						print exploitModule
						exploitList.append([exploitModule,portNo])
						lookupList.append([exploitModule,portNo])


	for x in lookupList:
		lines=[]
		filename= x[0]
		if "fuzzer" not in filename:
			with open(filename) as f:
				lines= f.read().splitlines()
			startFound=False
			optionList=[]
			found=False
			tempStrList=[]
			finalList=[]
			for line in lines:
				if "register_options" in line:
					#print x[0]+"\t"+line
					#print x[0]
					startFound=True
				if "self.class)" in line and found==False:
					found1=False
					for y in optionList:
						if found1==True:
							y= y.strip()
							if "#" not in y:
								tempStrList.append(y)
						if ".new" in y:
							if found1==True:
								tempStrList=[]
								found1=False
							if "[" in y and "]" in y:
								y= y.strip()
								finalList.append(y)
							else:
								y= y.strip()
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
					m= re.search('"(.+?)"',y)
					temp1= str(m.group(1)).replace(",","")
					y= y.replace(m.group(1),temp1)
					result1 += y
				except AttributeError:
					result1 += y
					continue
			if len(str(result1))>0:
				finalList.append(result1)
			tempStr1=""
			for g in finalList:
				if "false" not in g.lower() and "rhost" not in g.lower():
					#print g
					parameterList= g.partition('[')[-1].rpartition(']')[0]
					parNameTemp=( g.split(",")[0]).partition("'")[-1].rpartition("'")[0]
					result= (parameterList.split(",")[-1]).strip()
					if result=='""' or result=="''":
						tempStr1+= parNameTemp
						tempStr1+= ","
						#print parNameTemp+"\t"+result
			if len(tempStr1)>0:
				if tempStr1[-1]==",":
					print "- Variables required for module: "+tempStr1[0:(len(tempStr1)-1)]
				#print tempStr1
def find_between( s, first, last ):
    try:
        start= s.index( first ) + len( first )
        end= s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def RunCommand(fullCmd):
    try:
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

def timeout_command(command, timeout):
	import subprocess, datetime, os, time, signal
    	start= datetime.datetime.now()
    	process= subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    	while process.poll() is None:
      		time.sleep(0.1)
      		now= datetime.datetime.now()
      		if (now - start).seconds> timeout:
        		os.kill(process.pid, signal.SIGKILL)
        		os.waitpid(-1, os.WNOHANG)
        		return None
    	return process.stdout.read()

def RunCommand(fullCmd):
    try:
	#print fullCmd
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

def extractPorts(results):
	global internalIP

	for x in results:
		hostNo=""
		for i in x:	
			if "Nmap scan report for " in i:
				hostNo= i.replace("Nmap scan report for ","").strip()

				if hostNo not in ipList:
					ipList.append(hostNo)
				#Check if IP is internal/external
				ipPart1= int(hostNo.split(".")[0])
				ipPart2= int(hostNo.split(".")[1])				
				int(hostNo.split(".")[2])				
				if (ipPart1==10 or ipPart1==172 or ipPart1==192):
					if (ipPart1==10):
						internalIP=True
					if (ipPart1==172):
						if (ipPart2>15 and ipPart2<32):
							internalIP=True
					if (ipPart1==192):
						if (ipPart2==192):
							internalIP=True	
				if hostNo not in ipList:
					ipList.append(hostNo)
				resultsEnd.append("\n"+hostNo)

       	 		if "/tcp" in i and "unknown" not in i and "port" not in i:
        	              	outputStr= str(i).replace(" open "," ")
        	               	outputStr= outputStr.replace("?"," ")
				outputStr= outputStr.strip()
		
				if "[host down]" not in hostNo:
	               		      	resultsEnd.append(outputStr.strip())
                        	
				portStatus= outputStr.split("/tcp")

				portNo= (portStatus[0]+"/tcp").strip()
				portType= (portStatus[1].strip()).split(" ")[0]
				(portStatus[1].strip()).replace(portType,"").strip()
				
				if outputStr not in uniquePorts and "filtered" not in outputStr:
					#print hostNo+"\t"+portNo
					found=False
					for x in uniquePorts:
						if x[0]==portNo:
							x[1]+=","+hostNo
							found=True
					if found==False:
						uniquePorts.append([portNo,hostNo])
		for x in uniquePorts:
			print x[0]
			print x[1].split(",")
			if "/tcp" in x[0]:
				x[0]=x[0].strip("/tcp")
				lookupPort(x[0])
				print "\n"										
#MAIN 

if __name__== '__main__':
    parser= argparse.ArgumentParser()
    parser.add_argument('-i', dest='nmapFile', action='store', help='[use Nmap .nmap files]')    

    if os.getuid()!=0:
	print "[!] Please run script as root"
	sys.exit()
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options= parser.parse_args()
    nmapFilename= ""

    if options.nmapFile:
	nmapFilename= options.nmapFile

    	os.chdir(origPath)
    	if len(nmapFilename)>1:
		nmapResultsList=[]
		with open(nmapFilename) as f:
			print nmapFilename
			nmapResultsList.append(f.readlines())	
    		print "- Parsing Nmap files"
    		extractPorts(nmapResultsList)			
    
