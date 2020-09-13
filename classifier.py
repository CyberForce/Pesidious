import requests
import gzip
import json
import re

import sys
import os
import glob
module_path = os.path.dirname(os.path.abspath(sys.modules[__name__].__file__))

import logging
from logging import basicConfig, exception, debug, error, info, warning, getLogger
import argparse
from pathlib import Path
from tqdm import tqdm
from datetime import date
import os

from rich.logging import RichHandler
from rich.progress import track
from rich.traceback import install

from rich import print
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from pyfiglet import Figlet

# try:
#     # for RESTful interface to remote model
#     __private_data = json.load(open(os.path.join(module_path, 'params.json'), 'r'))
# except FileNotFoundError:
#     # if you want to use the cloud interface, you must populate your own params.json
#     # file.  Look at params.json.in for a template, which takes the following form
#     __private_data = {
#           "url": "http://my.av.api", # route to RESTful API interface
#           "username": "username",    # Username
#           "password": "password",    # password
#           "version": "1.0",          # version
#           "threshold": 0.70          # threshold
#     }
		# you may also need to change get_score_remote and/or get_label_remote below

# for local model
from gym_malware.envs.utils.pefeatures import PEFeatureExtractor
from gym_malware.envs.utils.pefeatures2 import PEFeatureExtractor2
from sklearn.externals import joblib
feature_extractor =  PEFeatureExtractor()
feature_extractor2 =  PEFeatureExtractor2()

def put_banner():
    # Printing heading banner
    f = Figlet(font="banner4")
    grid = Table.grid(expand=True, padding=1, pad_edge=True)
    grid.add_column(justify="right", ratio=38)
    grid.add_column(justify="left", ratio=62)
    grid.add_row(
        Text.assemble((f.renderText("PE"), "bold red")),
        Text(f.renderText("Sidious"), "bold white"),
    )
    print(grid)
    print(
        Panel(
            Text.assemble(
                ("Creating Chaos with Mutated Evasive Malware with ", "grey"),
                ("Reinforcement Learning ", "bold red"),
                ("and "),
                ("Generative Adversarial Networks", "bold red"),
                justify="center",
            )
        )
    )

put_banner()

def parse_args():
		parser = argparse.ArgumentParser(description='Reinforcement Training Module')

		parser.add_argument('-f', type=Path,
												help='Path to input file')

		parser.add_argument('-d', type=Path, 
												help='Path to input directory')

		parser.add_argument('--local_model', type=Path, default=Path("gym_malware/envs/utils/gradient_boosting.pkl")
												,help='Path to Local model (default : gym_malware/envs/utils/gradient_boosting.pkl)')

		parser.add_argument('--remote_model_config', type=Path,
												help='Config data for remote model (see params.json for refer)')

		parser.add_argument("--logfile", help = "The file path to store the logs. (default : classifier_logs_" + str(date.today()) + ".log)", type = Path, default = Path("classifier_logs_" + str(date.today()) + ".log"))
		
		logging_level = ["debug", "info", "warning", "error", "critical"]
		parser.add_argument(
				"-l",
				"--log",
				dest="log",
				metavar="LOGGING_LEVEL",
				choices=logging_level,
				default="info",
				help=f"Select the logging level. Keep in mind increasing verbosity might affect performance. Available choices include : {logging_level}",
		)

		args = parser.parse_args()
		return args

def logging_setup(logfile: str , log_level: str):

		from imp import reload
		reload(logging)

		log_dir = "Logs"

		if not os.path.exists(log_dir):
				os.mkdir(log_dir)

		logfile = os.path.join(log_dir, logfile)

		basicConfig(
				level=log_level.upper(),
				filemode='a',  # other options are w for write.
				format="%(message)s",
				filename=logfile
		)

		getLogger().addHandler(RichHandler())

class ClassificationFailure(Exception):
		pass

class FileRetrievalFailure(Exception):
		pass

# modify this function to git a remote API of your choice
# note that in this example, the API route expects version specification
# in addition to authentication username and password
def get_score_remote(bytez, private_data):
		try:
				response = requests.post(private_data['url'],
																 params={'version': private_data['version']},
																 auth=(private_data['username'],
																			 private_data['password']),
																 headers={
																		 'Content-Type': 'application/octet-stream'},
																 data=bytez)
		except ConnectionError:
				warning("[!] Bad route for hitting remote AV via RESTful interface. Please modify params.json (see params.json.in).")
				raise

		if not response.ok:
				raise(ClassificationFailure("Unable to get label for query"))
		json_response = response.json()
		if not 'data' in json_response or not 'score' in json_response['data']:
				raise(ClassificationFailure(
						"Can't find ['data']['score'] in response"))
		# mimic black box by thresholding here
		return json_response['data']['score']


def get_label_remote(bytez):
		# mimic black box by thresholding here
		return float( get_score_remote(bytez) >= __private_data['threshold'] )


def get_score_local(bytez, local_model):
		# extract features
		features = feature_extractor2.extract( bytez )
		# query the model
		score = local_model.predict_proba( features.reshape(1,-1) )[0,-1] # predict on single sample, get the malicious score
		return score

def get_label_local(bytez, local_model, local_model_threshold):
		# mimic black box by thresholding here
		score = get_score_local(bytez, local_model)
		label = float( get_score_local(bytez, local_model) >= local_model_threshold )
		#print("score={} (hidden), label={}".format(score,label)) 
		return score, label

def main():

	args = parse_args()
	logging_setup(str(args.logfile), args.log)

	info("[bold red] [*] Starting Binary Classifier Program ...\n", extra={"markup":True})

	if(args.f):
		info(f"[*] Reading File : [bold green]{str(args.f)}", extra={"markup":True})
		with open(args.f, 'rb') as infile:
				bytez = infile.read()

		if(args.remote_model_config):
			info("[*] Querying Remote Model ...")
			private_data = json.load(open(os.path.join(module_path, 'params.json'), 'r'))
			score = get_score_remote(bytez, private_data)
			info(f"[+] Score for {args.f} is : {score}")
		else:
			info("[*] Querying Local Model ...")
			local_model = joblib.load(os.path.join(module_path, args.local_model) )
			local_model_threshold = 0.60
			score, label = get_label_local(bytez, local_model, local_model_threshold)
			info("[+] Results:")
			info("\t[+] Score : {score}")
			if label == 1:
				info("\t[+] Label : [bold red]Malware \n", extra={"markup":True})
			elif label == 0:
				info("\t[+] Label : [bold green]Benign \n", extra={"markup":True})
				

	elif(args.d):
		info(f"[*] Reading binaries from - [bold green]{args.d}\n", extra={"markup":True})
		for file in track(os.listdir(args.d), description="Classifiying binaries ...", transient=True):
			file = os.path.join(args.d, file)
			info(f"\t[+] Reading File : [bold green]{file}", extra={"markup":True})
			with open(file, 'rb') as infile:
				bytez = infile.read()

			if(args.remote_model_config):
				info("\t[*] Querying Remote Model ...")
				private_data = json.load(open(os.path.join(module_path, 'params.json'), 'r'))
				score = get_score_remote(bytez, private_data)
				info(f"\t[+] Score for {file}: {score}")
			else:
				info("\t[*] Querying Local Model ...")
				local_model = joblib.load(os.path.join(module_path, args.local_model) )
				local_model_threshold = 0.60
				score, label = get_label_local(bytez, local_model, local_model_threshold)
				info("\t[+] Results:")
				info(f"\t\t[+] Score : {score}")
				if label == 1:
					info("\t\t[+] Label : [bold red]Malware \n", extra={"markup":True})
				elif label == 0:
					info("\t\t[+] Label : [bold green]Benign \n", extra={"markup":True})

	info("[bold green][+] Binary classifer completed succesfully ...", extra={"markup":True})
			

if __name__ == '__main__':
		main()