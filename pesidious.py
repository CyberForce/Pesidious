import os
import sys

cmd = sys.argv[1]
print(cmd)
if("classifier" in cmd):
	cmd_args = cmd.split(' ',2)
	print(cmd_args)
	os.system("python classifier.py " + cmd_args[2] )

if("mutate" in cmd):
	os.system("python rl-test.py -d ~/Downloads/test-samples --log debug")

if("rl-train" in cmd):
	os.system("python rl_train.py --log debug")

if("malgan" in cmd):
	os.system("python main_malgan.py --log debug")

if("extract-features" in cmd):
	os.system("python extract_features.py --log debug")
