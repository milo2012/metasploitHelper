import commands
import re
import argparse
import sys

path = "/pentest/metasploit-framework/modules"
enableParams=False

def allPort():
	count=1
	while count<65535:
		lookupPort(str(count),enableCsv=True)
		count+=1

def getAllModules():		
	portNo=0
	fileList=[]
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
		portNo = portNo.replace("'","")
		portNo = portNo.replace('"','')
		if not any(c.isalpha() for c in portNo):
			#lookupList.append([exploitModule,portNo])
			if portNo not in portList:
				portList.append(portNo)
			if "fuzzer" not in exploitModule and "auxiliary/dos" not in exploitModule:
				exploitList.append([portNo,exploitModule])

	return exploitList	

def readModule(portNoFilename,enableCsv=True):
	results = ""
	portNo=portNoFilename[0]		
	filename=portNoFilename[1]

	if "fuzzer" not in filename:
		if enableCsv!=True:
			print filename
		with open(filename) as f:
			lines = f.read().splitlines()
		startFound=False
		optionList=[]
		found=False
		tempStrList=[]
		finalList=[]
		for line in lines:
			if "register_options" in line:
				startFound=True
			if "end" in line:
				startFound=False
				#found=True
			if startFound==True:
				optionList.append(line)

		paramList=[]
		#For Metasploit modules options that are multiline
		tempStr1=""
		for z in optionList:
			if ".new" in z:
				tempStr1=tempStr1.replace("  "," ")
				if ".new" in tempStr1.lower() and "true" in tempStr1.lower():
					parameterList = tempStr1.partition('[')[-1].rpartition(']')[0]
					parNameTemp = ((tempStr1.split(",")[0]).partition("'")[-1].rpartition("'")[0]).strip()
					presetValue = (parameterList.split(",")[-1]).strip()
					presetValue = presetValue.replace("'","")
					presetValue = presetValue.replace('"','')
					if len(presetValue)<1:
						if parNameTemp not in paramList:
							paramList.append(parNameTemp)
				tempStr1=z
			else:
				tempStr1+=z
			
		result1=""
		for y in finalList:
			#Check if preset value is set for required variables
			parameterList = y.partition('[')[-1].rpartition(']')[0]
			parNameTemp = ((y.split(",")[0]).partition("'")[-1].rpartition("'")[0]).strip()
			presetValue = (parameterList.split(",")[-1]).strip()
			presetValue = presetValue.replace("'","")
			presetValue = presetValue.replace('"','')
			if len(presetValue)<1:
				if parNameTemp not in paramList:
					paramList.append(parNameTemp)

		#Display required parameters
		if enableCsv==False:
			if len(paramList)>0:
				for x in paramList:
					print x
		else:
			if len(paramList)>0:
				tmpStr2="["
				for x in paramList:
					tmpStr2+=x
					tmpStr2+=","
				tmpStr2=tmpStr2[:-1]
				tmpStr2+="]"
				results = [str(portNo),filename,tmpStr2]
				return results
			else:
				results = [str(portNo),filename,[]]
				return results


def lookupPort(matchPort,enableCsv=False):
	if enableCsv==False:
		print "\n- Modules Matching Port: "+str(matchPort)

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
			if enableCsv!=True:
				print filename
			with open(filename) as f:
				lines = f.read().splitlines()
			startFound=False
			optionList=[]
			found=False
			tempStrList=[]
			finalList=[]
			for line in lines:
				if "register_options" in line:
					startFound=True
				if "end" in line:
				#if "end" in line and found==False:
				#if "self.class)" in line and found==False:
					startFound=False
					found=True
				if startFound==True:
					optionList.append(line)

			paramList=[]
			#For Metasploit modules options that are multiline
			tempStr1=""
			for z in optionList:
				if ".new" in z:
					tempStr1=tempStr1.replace("  "," ")
					if ".new" in tempStr1.lower() and "true" in tempStr1.lower():
						parameterList = tempStr1.partition('[')[-1].rpartition(']')[0]
						parNameTemp = ((tempStr1.split(",")[0]).partition("'")[-1].rpartition("'")[0]).strip()
						presetValue = (parameterList.split(",")[-1]).strip()
						presetValue = presetValue.replace("'","")
						presetValue = presetValue.replace('"','')
						if len(presetValue)<1:
							if parNameTemp not in paramList:
								paramList.append(parNameTemp)
					tempStr1=z
				else:
					tempStr1+=z
			
			result1=""
			for y in finalList:
				#Check if preset value is set for required variables
				parameterList = y.partition('[')[-1].rpartition(']')[0]
				parNameTemp = ((y.split(",")[0]).partition("'")[-1].rpartition("'")[0]).strip()
				presetValue = (parameterList.split(",")[-1]).strip()
				presetValue = presetValue.replace("'","")
				presetValue = presetValue.replace('"','')
				if len(presetValue)<1:
					if parNameTemp not in paramList:
						paramList.append(parNameTemp)
			#Display required parameters
			if enableCsv==False:
				if len(paramList)>0:
					for x in paramList:
						print x
			else:
				if len(paramList)>0:
					tmpStr2="["
					for x in paramList:
						tmpStr2+=x
						tmpStr2+=","
					tmpStr2=tmpStr2[:-1]
					tmpStr2+="]"
					print str(matchPort)+","+filename+","+tmpStr2
					
def lookupURI(showModules=False):
	path = "/pentest/metasploit-framework/modules"
	#fullCmd = 'grep -ir "Opt::RPORT" '+path
	fullCmd = 'grep -ir "OptString.new(\'TARGETURI\'" '+path
	results =  RunCommand(fullCmd)
	exploitList=[]
	pathList=[]
	uriList=[]
	defaultPathList=[]
	resultsList = results.split("\n")
	for result in resultsList:
		result1 = result.split(".rb:")[1].strip()
		exploitModule = result.split(".rb:")[0].strip()+".rb"
		portNo = find_between(result1,"[","]")
		if "fuzzer" not in exploitModule and "auxiliary/dos" not in exploitModule:
			exploitList.append([exploitModule,portNo])
			result1 = portNo.split(",")[-1]
			result1 = result1.replace("'","")
			result1 = result1.replace('"',"")
			result1 = result1.strip()
			if "/" in result1:
				if result1!="/":
					if result1 not in uriList:
						uriList.append(result1)
				if result1=="/":
					defaultPathList.append([result1,exploitModule])
				else:
					if result1 not in pathList:		
						pathList.append([result1,exploitModule])
	if showModules==False:
		for x in uriList:
			print x
	else:
		for x in pathList:
			x[1] = x[1].replace(path,".")
			print x[0]+","+x[1]
		for x in defaultPathList:	
			x[1] = x[1].replace(path,".")
			print x[0]+","+x[1]

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
    	parser.add_argument('-uri', action='store_true', help='[shows targetURI from metasploit modules]')
    	parser.add_argument('-uriModules', action='store_true', help='[shows targetURI and modules from metasploit modules]')
    	parser.add_argument('-params', action='store_true', help='[list parameters required by metasploit module if any]')
    	parser.add_argument('-port', dest='portNo',  action='store', help='[Port Number]')
    	#parser.add_argument('-all', action='store_true', help='[show all metasploit modules along with port number]')
    	parser.add_argument('-all', action='store_true', help='[show all metasploit modules along with port number]')

    	if len(sys.argv)==1:
        	parser.print_help()
        	sys.exit(1)
	options = parser.parse_args()
	showModules=False
	
	if options.all:
		fileList = getAllModules()
		resultList=[]
		for file1 in fileList:
			results =readModule(file1)
			resultList.append(results)
		resultList = sorted(resultList, key=lambda x: x[0])
		for x in resultList:
			print x[0]+","+x[1]+","+str(x[2])
		sys.exit()
	if options.params:
		enableParams=True
	#if options.all:
	#	allPort()
	if options.uri:
		lookupURI(showModules=False)
	if options.uriModules:
		lookupURI(showModules=True)
	if options.portNo:
		lookupPort(options.portNo)
   
