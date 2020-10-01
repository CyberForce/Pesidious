import os
import sys

cmd = sys.argv[1]

if("classifier" in cmd):
	cmd_args = cmd.split(3)
	os.system("python classifier.py " + cmd_args )

if("mutate" in cmd):
	os.system("python rl-test.py -d ~/Downloads/test-samples --log debug")

if("rl-train" in cmd):
	os.system("python rl_train.py --log debug")

if("malgan" in cmd):
	os.system("python main_malgan.py --log debug")

if("extract-features" in cmd):
	os.system("python extract_features.py --log debug")
