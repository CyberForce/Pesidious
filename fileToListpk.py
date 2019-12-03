import sys
import os
import pickle


infile = sys.argv[1]
outputfile = sys.argv[2]
outfile = open(outputfile, 'w')

sections = []
with open(infile) as f:
  file = f.readlines()

for line in file:
	sections.append(line[:-1])

print(sections)

with open(outputfile, 'wb') as handle:
    pickle.dump(sections, handle)
