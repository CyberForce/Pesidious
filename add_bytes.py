import struct
import sys

file = sys.argv[1]

my_file=open(file, 'a')

for i in range(0, 400000000):
	my_file.write(struct.pack('B', 0))

my_file.close()