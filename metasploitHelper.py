# -*- coding: utf-8 -*- !/usr/bin/python

#pip install python-libnmap

from urlparse import urlparse
from xml.etree import ElementTree
from libnmap.parser import NmapParser
import re
import argparse
import sys
import requests
import multiprocessing
import commands

path = "/pentest/metasploit-framework/modules/"
requests.packages.urllib3.disable_warnings()

uriList=[]
uriMatch=[]
numProcesses = 20
outputFile = ""
portMatch=[]
contentList=[]
findWeb=True
findPort=True

contentList.append("spool runMsf.log")

class Worker1(multiprocessing.Process):

    def __init__(self,
            work_queue,
            result_queue,
          ):
        multiprocessing.Process.__init__(self)
        self.work_queue = work_queue
        self.result_queue = result_queue
        self.kill_received = False
    def run(self):
        while (not (self.kill_received)) and (self.work_queue.empty()==False):
            try:
                job = self.work_queue.get_nowait()
            except:
                break
            (jobid,scheme,hostNo,uri,portNo) = job
            rtnVal = (jobid,getHEAD(scheme,hostNo,uri,portNo))
            self.result_queue.put(rtnVal)

def execute1(jobs, num_processes=2):
    work_queue = multiprocessing.Queue()
    for job in jobs:
        work_queue.put(job)

    result_queue = multiprocessing.Queue()
    worker = []
    for i in range(int(num_processes)):
        worker.append(Worker1(work_queue, result_queue))
        worker[i].start()

    results = []
    while len(results) < len(jobs):
        result = result_queue.get()
        results.append(result)
    results.sort()
    return (results)

def RunCommand(fullCmd):
    try:
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def getHEAD(scheme,hostNo,uri,portNo):
	url = scheme+"://"+hostNo+":"+portNo+uri
	try:
		resp = requests.head(url,verify=False, timeout=3)
		if resp.status_code==200:
			print "Found: %-70s %-10s" % (url,resp.status_code)
		return (resp.status_code,url,uri)
	except requests.exceptions.Timeout:
		pass
	except Exception as e:
		print e
		pass

def extractParam(uri,filename):
	with open(filename) as f:
		lines = f.read().splitlines()
	moduleName = filename.replace(path,"")
	startFound=False
	pathList=[]
	tempStrList=[]
	finalList=[]
	optionList=[]
	found=False
	for line in lines:
		if "register_options" in line:
			startFound=True
		if "self.class)" in line and found==False:
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
			results = uri+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"]"
			return results
		else:
			results = uri+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"]"
			return results
	else:
		results = uri+","+moduleName+",[]"
		return results

def lookupAllPorts():
	fullCmd = 'grep -ir "Opt::RPORT" '+path
	results =  RunCommand(fullCmd)
	writeList=[]
	portList=[]
	lookupList=[]
	exploitList=[]
	resultsList = results.split("\n")
	for result in resultsList:
		result1 = result.split(".rb:")[1].strip()
		exploitModule = result.split(".rb:")[0].strip()+".rb"
		portNo = find_between(result1,"RPORT(",")")
		portNo = portNo.replace("'","")
		if not any(c.isalpha() for c in portNo):
			if "fuzzer" not in exploitModule and "auxiliary/dos" not in exploitModule:
				exploitList.append([exploitModule,str(portNo)])
	for x in exploitList:
		lines=[]
		filename = x[0]
		matchPort = x[1]
		if "fuzzer" not in filename:
			moduleName = filename.replace(path,"")

			tempStrList=[]
			finalList=[]
			with open(filename) as f:
				lines = f.read().splitlines()
			startFound=False
			optionList=[]
			found=False
			for line in lines:
				if "register_options" in line:
					startFound=True
				if "self.class)" in line and found==False:
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
						tempStr1+= ","
			moduleName = moduleName.replace(".rb","")
			if len(tempStr1)>0:
				if tempStr1[-1]==",":
					results = matchPort+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"]"
					writeList.append(results)
				else:
					results = matchPort+","+moduleName+",["+tempStr1[0:(len(tempStr1)-1)]+"]"
					writeList.append(results)
			else:
				results = matchPort+","+moduleName+",[]"
				writeList.append(results)
	f = open('port2Msf.csv','w')
	for x in writeList:
		f.write(x+"\n")
	f.close()

def lookupURI(showModules=False):
	fullCmd = 'grep -ir "OptString.new(\'TARGETURI\'" '+path
	results =  RunCommand(fullCmd)

	exploitList=[]
	pathList=[]
	uriList=[]
	defaultPathList=[]
	resultsList = results.split("\n")
	for result in resultsList:
		result1 = result.split(".rb:")[1].strip()
		exploitModule = result.split(".rb:")[0].strip()
		exploitModule = exploitModule.replace(path,"")
	
		portNo = find_between(result1,"[","]")
		if "fuzzer" not in exploitModule and "auxiliary/dos" not in exploitModule:
			exploitList.append([exploitModule,portNo])
			result1 = portNo.split(",")[-1]
			result1 = result1.replace("'","")
			result1 = result1.replace('"',"")
			result1 = result1.strip()
			if "/" in result1:
				exploitModule = exploitModule.replace(".rb","")
				filename = path+exploitModule+".rb"
				uri = result1
				results = extractParam(uri,filename)
				pathList.append(results)

				if result1!="/":
					if result1 not in uriList:
						uriList.append(result1)
	f = open('uriList.txt','w')
	for x in uriList:
		f.write(x+"\n")
	f.close()
	
	f = open('default-path.csv','w')
	for x in pathList:
		f.write(x+"\n")
	f.close()

def readDatabase():
	fname="default-path.csv"
	with open(fname) as f:
		tempList = f.readlines()
		for x in tempList:
			x = x.strip()
			if len(x)>0:
				x1 = x.split(",")
				uri = x1[0]
				msfModule = x1[1]
				paramNames = x1[2]
				uriList.append(uri)
				uriMatch.append([uri,msfModule,paramNames])
	fname="port2Msf.csv"
	with open(fname) as f:
		tempList = f.readlines()
		for x in tempList:
			x = x.strip()
			if len(x)>0:
				x1 = x.split(",")
				portNo = x1[0]
				msfModule = x1[1]
				addArg = x1[2]
				portMatch.append([portNo,msfModule])
def lookupPort(hostNo,portNo):
	for y in portMatch:	
		if y[0]==portNo:
			contentList.append("use "+y[1])
			contentList.append("set RHOST "+hostNo)
			contentList.append("set RHOSTS "+hostNo)
			contentList.append("set RPORT "+portNo)
			contentList.append("exploit\n")

def testURI(scheme,hostNo,portNo):
	print "- Brute Forcing URLs..."
	jobs = []
	jobid=0
	for x in uriList:
		x = x.strip()
		if len(x)>0 and x!="/":
			uri = x
			jobs.append((jobid,scheme,hostNo,uri,portNo))
			jobid = jobid+1
	resultsList = execute1(jobs,numProcesses)
	tempList=[]
	for i in resultsList:
		if i[1]!=None:
			status = i[1][0]
			url = i[1][1]
			uriPath = i[1][2]
			if status==302 or status==200 or status==401:
				tempList.append([status,url,uriPath])
	for x in tempList:
		uriPath = x[2]
		for x1 in uriMatch:
			uri=x1[0]		
			msfModule=x1[1]
			paramNames=x1[2]
			paramList=[]
			if uri==uriPath:
				o = urlparse(x[1])
				contentList.append('use '+msfModule)
				contentList.append('set RHOST '+(o.netloc).split(":")[0])
				contentList.append('set RHOSTS '+(o.netloc).split(":")[0])
				contentList.append('set RPORT '+(o.netloc).split(":")[1])

				if paramNames!="[]":
					paramNames=paramNames.replace("[","")
					paramNames=paramNames.replace("]","")
					paramList = paramNames.split("+")
					for y in paramList:
						contentList.append('set '+y)

				contentList.append('exploit')
def parseNmap(filename):
	ipList=[]
	httpList=[]
	httpsList=[]
	portList=[]
	portsList=[]
	stateList=[]
	serviceList=[]

	with open (filename, 'rt') as file:
		tree=ElementTree.parse(file)
	for node_2 in tree.iter('state'):
		state =   node_2.attrib.get('state')
		stateList.append(state)
	for node_2 in tree.iter('port'):
		port =   node_2.attrib.get('portid')
		portList.append(port)
	for node_2 in tree.iter('address'):
		ip_add =   node_2.attrib.get('addr')
		ipList.append(ip_add)
	for node_2 in tree.iter('service'):
		service =   node_2.attrib.get('name')
		serviceList.append(service)
	rep = NmapParser.parse_fromfile(filename) 
	for _host in rep.hosts:
		host = ', '.join(_host.hostnames)
		ip = (_host.address)

	counter=0
	while counter<len(stateList):
		if stateList[counter]=="open":
			if serviceList[counter]=="http":
				httpList.append([ipList[counter],portList[counter]])
			elif serviceList[counter]=="https":
				httpsList.append([ipList[counter],portList[counter]])
			else:
				portsList.append([ipList[counter],portList[counter]])
		counter+=1

	if findWeb==True:
		if len(httpList)>0:
			for x in httpList:
				url = "http://"+x[0]+":"+x[1]
				scheme = "http"
				hostNo = x[0]
				portNo = x[1]
				testURI(scheme,hostNo,portNo)
	if findWeb==True:
		if len(httpsList)>0:
			for x in httpsList:
				url = "https://"+x[0]+":"+x[1]
				scheme = "https"
				hostNo = x[0]
				portNo = x[1]
				testURI(scheme,hostNo,portNo)
	if findPort==True:
		if len(portsList)>0:
			for x in portsList:
				lookupPort(x[0],x[1])
if __name__== '__main__':
    parser= argparse.ArgumentParser()
    parser.add_argument('-i', dest='nmapFile', action='store', help='[use Nmap .xml file]')
    parser.add_argument('-o', dest='msfrc', action='store', help='[metasploit resource script]')
    parser.add_argument('-nocache', action='store_true', help='[search Metasploit folder instead of using default-path.csv and port2Msf.csv (default=off]')
    parser.add_argument('-findWeb', action='store_true', help='[find only HTTP/HTTPs exploits (default=on)]')
    parser.add_argument('-findPort', action='store_true', help='[find only port-based matched exploits (default=on)]')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options= parser.parse_args()

    if options.nocache:
	lookupAllPorts()
	lookupURI(showModules=False)
    if options.findWeb:
	findWeb=True
    else:
	findWeb=False
    if options.findPort:
	findPort=True
    else:
	findPort=False
    if not options.findPort and not options.findWeb:
	findPort=True
	findWeb=True

    outputFile = options.msfrc
    readDatabase()
    if options.nmapFile:
	parseNmap(options.nmapFile)


    if outputFile==None:
	outputFile="runMsf.rc"

    if len(contentList)>1:
	contentList.append("exit -y")
	f = open(outputFile, 'w')
	for x in contentList:
		f.write(x+"\n")
	f.close()
	print "\nMetasploit resource script: "+outputFile+" written."
    else:
	print "\n- No results found"
	
