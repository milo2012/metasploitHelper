import commands
import operator
import re
import argparse
import sys

def lookupPort(matchPort):
	path = "/pentest/metasploit-framework/modules"
	fullCmd = 'grep -ir "Opt::RPORT" '+path
	results =  RunCommand(fullCmd)
	portList=[]
	lookupList=[]
	exploitList=[]
	resultsList = results.split("\n")
	for result in resultsList:
		result1 = result.split(".rb:")[1].strip()
		exploitModule = result.split(".rb:")[0].strip()+".rb"
		portNo = find_between(result1,"RPORT(",")")
		if not any(c.isalpha() for c in portNo):
			if len(matchPort)>0:
				if portNo==matchPort:
					lookupList.append([exploitModule,portNo])
			if portNo not in portList:
				portList.append(portNo)
			if "fuzzer" not in exploitModule and "auxiliary/dos" not in exploitModule:
				exploitList.append([exploitModule,portNo])

	for x in lookupList:
		lines=[]
		filename = x[0]
		if "fuzzer" not in filename:
			print filename+"\t"+x[1]
			with open(filename) as f:
				lines = f.read().splitlines()
			startFound=False
			optionList=[]
			varList=[]
			tempList=[]
			varStart=False
			found=False
			tempStrList=[]
			finalList=[]
			for line in lines:
				if "register_options" in line:
					#print x[0]+"\t"+line
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
				finalList.append(result1)
			tempStr1=""
			for g in finalList:
				if "false" not in g.lower() and "rhost" not in g.lower():
					#print g
					parameterList = g.partition('[')[-1].rpartition(']')[0]
					parNameTemp =( g.split(",")[0]).partition("'")[-1].rpartition("'")[0]
					result = (parameterList.split(",")[-1]).strip()
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
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def RunCommand(fullCmd):
    try:
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

if __name__ == '__main__':
	print "This tool parses Nmap XML file and checks for matching ports/exploits in Metasploit"
	print "The tool will print out if there any additional parameters that needs to be supplied to the Metasploit module."
	parser = argparse.ArgumentParser()
    	parser.add_argument('-host', dest='hostNo',  action='store', help='[Host number]')
    	parser.add_argument('-port', dest='portNo',  action='store', help='[Port Number]')

    	if len(sys.argv)==1:
        	parser.print_help()
        	sys.exit(1)
	options = parser.parse_args()
	if options.portNo:
		lookupPort(options.portNo)
   
'''
exploitList = sorted(exploitList, key=operator.itemgetter(1))
portList = sorted(portList)
httpExploitList=[]
url="http://localhost:"
for x in exploitList:
	#if x[1]==matchPort:
	lines=[]
	#print x[0]+"\t"+x[1]
	with open(x[0]) as f:
		lines = f.read().splitlines()
	next=False
	for line in lines:
		if next==True:
			result = (line.split(",")[2]).split(" ")[1]
			result = result.strip('"')
			result = result.strip("'")
			httpExploitList.append([x[0].strip(),x[1].strip(),result.strip()])
			next=False
		if "OptString.new('TARGETURI'" in line:
			if "[" in line and "]" in line:
				result = ((line.split("[")[1]).split("]")[0]).split(",")[2].strip()
				if result!="'/'" and result!='"/"' and result !='""':
					result = result.strip('"')
					result = result.strip("'")
					httpExploitList.append([x[0].strip(),x[1].strip(),result.strip()])
			else:
				next=True
#for portNo in portList:
#	print portNo
#for x in httpExploitList:
#	print url+x[1]+x[2]
'''
