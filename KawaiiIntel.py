import json
file = open("report.json","r")
data = file.read()
data = data.replace("\\","\\\\")
data = data.split("\r\n")
for i in data:
	try:
		info=json.loads(i)
	except:
		print "Error with line: "+i

