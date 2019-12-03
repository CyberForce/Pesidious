import sys
import os
import pickle
import re

infile = sys.argv[1]
outputfile = sys.argv[2]
outfile = open(outputfile, 'w')

with open(infile) as f:
  file = f.readlines()

adversarial_imports_dict = {}
libname = ""
funcname = ""

regex = re.compile('[@_!#$%^&*()<>?/\\|}{~:]') 

for imports in file:
	if(len(imports.split(":")) > 2):
		continue
	funcname , libname = imports.split(":")

	libname = libname[:-1]

	if("kernel32.dll" in libname or "user32.dll" in libname or "ntdll.dll" in libname 
    	or "ncrypt.dll" in libname or "gdi32.dll" in libname or "msvcrt.dll" in libname
    	or "shell32.dll" in libname or "comctl32.dll" in libname or "ole32.dll" in libname
    	or "oleaut32.dll" in libname or "crtdll.dll" in libname or "shlwapi.dll" in libname 
    	or "comdlg32.dll" in libname or "crypt32.dll" in libname or "netapi32.dll" in libname
    	or "msvcr100.dll" in libname or "mscoree.dll" in libname or "rasapi32.dll" in libname):

		

		if(libname not in adversarial_imports_dict):
			adversarial_imports_dict[libname] = []

		else:
			if(regex.search(funcname) == None):
				functions = adversarial_imports_dict[libname]
				functions.append(funcname)

with open(outputfile, 'wb') as handle:
    pickle.dump(adversarial_imports_dict, handle)

print(adversarial_imports_dict)

