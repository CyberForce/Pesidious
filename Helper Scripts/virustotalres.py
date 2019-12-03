import requests
import sys
import json
import os

from os import listdir
from os.path import isfile, join

mypath = sys.argv[1]
out = sys.argv[2]

#onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
with open(mypath, 'r') as f:
	hashes = f.readlines()

outfile = open(out, 'a')

for sha in hashes:
	filename , shaHash = sha.split(":")
	original = filename.split("_")[2]
	original = original.split(".")[0]
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	params = {'apikey': 'bbd8c5dc4df8a8dc4d4c0cd3d9ec38b96471ab711bb71c2e608d45d6430fc328', 'resource': shaHash}
	response = requests.get(url, params=params)

	params1 = {'apikey': 'bbd8c5dc4df8a8dc4d4c0cd3d9ec38b96471ab711bb71c2e608d45d6430fc328', 'resource': original}
	response1 = requests.get(url, params=params1)

	outfile.write(sha[:-1] +  ' , ' + str(response.json()['positives']) + ' , ' + str(response1.json()['positives']) + '\n')
