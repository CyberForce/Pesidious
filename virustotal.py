import requests
import sys
import json
import os

from os import listdir
from os.path import isfile, join

mypath = sys.argv[1]
out = sys.argv[2]

onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

outfile = open(out + '.txt', 'w')
url = 'https://www.virustotal.com/vtapi/v2/file/scan'
params = {'apikey': 'bbd8c5dc4df8a8dc4d4c0cd3d9ec38b96471ab711bb71c2e608d45d6430fc328'}

for filename in onlyfiles:
	files = {'file': ((join(mypath, filename)), open((join(mypath, filename)), 'rb'))}
	response = requests.post(url, files=files, params=params)
	outfile.write(filename + ":" + response.json()['sha1'] + '\n')

