#Find functions in c file

import re
filename = "ejsc.c"
f = open(filename)

#Add line number
fb = open(filename+".bak",'w')
lines = f.readlines()
linenum = 1
for line in lines:
	#print line
	fb.write(str(linenum)+"="+line)
	linenum = linenum+1

fb.close()


f2 = open(filename+".bak")
contents2 = f2.read()

rule='(([A-Z,a-z])+)\(.*\)\s*\n{' 							#find functions
rule2='(([1-9].*[A-Z,a-z]+\s*)=\s*[A-Z,a-z]*\(.*\);)'		#value = function();
#print contents

string = re.findall(rule2,contents2)

ainf = open("assignment_in_"+filename,'w')

print "Function in "+filename+":"
for i in range (0,len(string)):
	#print str[i][0]
	ainf.write(string[i][0]+"\n")
ainf.close()
ainf = open("assignment_in_"+filename,'r')
assignment_lines = ainf.readlines()

assignment_linenum = ""
assignment_fun = ""

nocheck = open(filename+"_nocheck",'w')
nocheck.write("Assignment without check:\n"
			  "---------------------------------------\n")

for line in assignment_lines:
	num_func = line.split("=",3)
	num_func[1] = num_func[1].strip()
	num_func[0] = num_func[0]
	#print type(num_func[0])
	j = 0
	for i in range(0,5):
		next_num = int(num_func[0])+i
		rule3 = str(next_num)+".*"+num_func[1]+"\s*(==|!=|>|<|>=|<=)"
		result = re.search(rule3,contents2)
		if (result == None ):
			j = j+1
			if( j == 5 ):
			#print result.group()
				nocheck.write(line)
	#str = re.search(rule3,contents2)
	#print str

f2.close()
ainf.close()
f.close()