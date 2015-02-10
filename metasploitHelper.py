# -*- coding: utf-8 -*- 
#!/usr/bin/python

#pip install python-libnmap

from urlparse import urlparse
from xml.etree import ElementTree
from libnmap.parser import NmapParser
import re
import argparse
import sys
import requests
import multiprocessing

requests.packages.urllib3.disable_warnings()

uriList=[]
uriMatch=[]
numProcesses = 20
outputFile = ""
portMatch=[]
contentList=[]
findWeb=True
findPort=True

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

def getHEAD(scheme,hostNo,uri,portNo):
	url = scheme+"://"+hostNo+":"+portNo+uri
	print url
	try:
		resp = requests.head(url,verify=False, timeout=3)
		print resp.status_code
		return (resp.status_code,url,uri)
		#(resp.status_code, resp.text, resp.headers)
	except requests.exceptions.Timeout:
		pass
	except Exception as e:
		print e
		pass

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
				uriList.append(uri)
				uriMatch.append([uri,msfModule])
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
		#print y[0]+"\t"+portNo
		if y[0]==portNo:
			contentList.append("USE "+y[1])
			contentList.append("SET RHOST "+hostNo)
			contentList.append("SET RHOSTS "+hostNo)
			contentList.append("SET RPORT "+portNo)
			contentList.append("exploit\n")

def testURI(scheme,hostNo,portNo):
	jobs = []
	jobid=0
	for x in uriList:
		x = x.strip()
		if len(x)>0 and x!="/":
			uri = x
			#print "here2: "+scheme+"://"+hostNo+":"+portNo+uri
			jobs.append((jobid,scheme,hostNo,uri,portNo))
			jobid = jobid+1
	resultsList = execute1(jobs,numProcesses)
	tempList=[]
	for i in resultsList:
		print i
		if i[1]!=None:
			status = i[1][0]
			url = i[1][1]
			uriPath = i[1][2]
			if status==302 or status==200 or status==401:
				tempList.append([status,url,uriPath])
	if len(tempList)<3:
		for x in tempList:
			uriPath = x[2]
			for x1 in uriMatch:
				uri=x1[0]
				msfModule=x1[1]
				if uri==uriPath:
					#print uriPath
					#print msfModule
					print x[1]
					o = urlparse(x[1])
					contentList.append('use '+msfModule)
					contentList.append('SET RHOST '+(o.netloc).split(":")[0])
					contentList.append('SET RHOSTS '+(o.netloc).split(":")[0])
					contentList.append('SET RPORT '+(o.netloc).split(":")[1])
					contentList.append('exploit')
def parseNmap(filename):
	ipList=[]
	httpList=[]
	httpsList=[]
	portList=[]

	with open (filename, 'rt') as file:
		tree=ElementTree.parse(file)
	for node_2 in tree.iter('address'):
		ip_add =   node_2.attrib.get('addr')
		#print ip_add
		ipList.append(ip_add)
	rep = NmapParser.parse_fromfile(filename) 
	for _host in rep.hosts:
		host = ', '.join(_host.hostnames)
		ip = (_host.address)
	#	print "----------------------------------------------------------------------------- "
	#	print "HostName: "'{0: >35}'.format(host,"--", ip)
	#Lists in order to store Additional information, Product and version next to the port information.
	list_name=[]
	list_tunnel=[]
	list_product=[]
	list_version=[]
	list_extrainf=[]
	for node_4 in tree.iter('service'): #ElementTree manipulation. Service Element which included the sub-elements product, version, extrainfo
		name = node_4.attrib.get('name')
		tunnel = node_4.attrib.get('tunnel')
		product = node_4.attrib.get('product')
		version = node_4.attrib.get('version')
		extrainf = node_4.attrib.get('extrainfo')
		list_name.append(name)
		list_tunnel.append(tunnel)
		list_product.append(product)
		list_version.append(version)
		list_extrainf.append(extrainf)
	for osmatch in _host.os.osmatches: #NmapParser manipulation to detect OS and accuracy of detection.
		os = osmatch.name
		accuracy = osmatch.accuracy
		#print "Operating System Guess: ", os, "- Accuracy Detection", accuracy
		break
		print "----------------------------------------------------------------------------- "
	counter = 0
	for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
		if list_name[counter]=="http":
			httpList.append([ipList[counter],str(services.port)])
			#print list_name[counter]
			#print ipList[counter]+"\t"+str(services.port)+"\t"+services.state+"\t"+list_product[counter]+"\t"+list_version[counter]
		elif list_name[counter]=='https':
			httpsList.append([ipList[counter],str(services.port)])
		else:
			portList.append([ipList[counter],str(services.port)])
		counter = counter + 1
	if findWeb==True:
		if len(httpList)>0:
			for x in httpList:
				url = "http://"+x[0]+":"+x[1]
				scheme = "http"
				hostNo = x[0]
				portNo = x[1]
				print url
				testURI(scheme,hostNo,portNo)

	if findWeb==True:
		if len(httpsList)>0:
			for x in httpsList:
				url = "https://"+x[0]+":"+x[1]
				scheme = "https"
				hostNo = x[0]
				portNo = x[1]
				print url
				testURI(scheme,hostNo,portNo)
	if findPort==True:
		if len(portList)>0:
			for x in portList:
				lookupPort(x[0],x[1])
if __name__== '__main__':
    parser= argparse.ArgumentParser()
    parser.add_argument('-i', dest='nmapFile', action='store', help='[use Nmap .xml file]')
    parser.add_argument('-o', dest='msfrc', action='store', help='[metasploit resource script]')
    parser.add_argument('-findWeb', action='store_true', help='[find only HTTP/HTTPs exploits]')
    parser.add_argument('-findPort', action='store_true', help='[find only port-based matched exploits]')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options= parser.parse_args()

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
    parseNmap(options.nmapFile)


    if outputFile==None:
	outputFile="runMsf.rc"

    if len(contentList)>0:
	f = open(outputFile, 'w')
	for x in contentList:
		f.write(x+"\n")
	f.close()
	print "Metasploit resource script: "+outputFile+" written."
	
