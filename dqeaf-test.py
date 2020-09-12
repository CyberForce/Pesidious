import math, random

import gym
import numpy as np
import sys
import os
np.random.seed(123)
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

from IPython.display import clear_output
import matplotlib.pyplot as plt
import torch.autograd as autograd 

import gym_malware
from gym_malware.envs.utils import interface, pefeatures
from gym_malware.envs.controls import manipulate2 as manipulate
from collections import namedtuple, deque
from statistics import mean 
import dqeaf

env_id = "malware-score-v0"
env = gym.make(env_id)
env.seed(123)

from collections import deque

ACTION_LOOKUP = {i: act for i, act in enumerate(manipulate.ACTION_TABLE.keys())}

# calculate epsilon


device = torch.device("cpu")

USE_CUDA = False
Variable = lambda *args, **kwargs: autograd.Variable(*args, **kwargs).cuda() if USE_CUDA else autograd.Variable(*args, **kwargs)

model = dqeaf.DQN().to(device)
model.load_state_dict(torch.load('saved_models/dqeaf1100.pt'))

print("Model's state_dict:")

for param_tensor in net.state_dict():
    print(param_tensor, "\t", net.state_dict()[param_tensor].size())

model.eval()

input_folder = sys.argv[1]
output_folder = 'evaded-samples'
onlyfiles = [f for f in os.listdir(input_folder)]

def test_model():


	T = 80 # total mutations allowed
	success = 0
	rn = dqeaf.RangeNormalize(-0.5,0.5)
	fe = pefeatures.PEFeatureExtractor()
	episode = 0

	for file in onlyfiles:
		try:
			with open(os.path.join(input_folder, file), 'rb') as infile:
				bytez = infile.read()
		except IOError:
			raise FileRetrievalFailure("Unable to read sha256 from")
		state = fe.extract( bytez )
		state_norm = rn(state)
		episode = episode + 1
		state_norm = torch.from_numpy(state_norm).float().unsqueeze(0).to(device)
		for mutation in range(1, T):
			
			actions = model.forward(state_norm)
			print(actions)

			action = torch.argmax(actions).item()
			action = ACTION_LOOKUP[action]
			bytez = manipulate.modify_without_breaking( bytez, [action] )
			new_label = interface.get_score_local( bytez )
			print('episode : ' + str(episode))
			print('mutation : ' + str(mutation))
			print('test action : ' + str(action))
			print('new label : ' + str(new_label))
			state = fe.extract(bytez)
			state_norm = rn(state)
			state_norm = torch.from_numpy(state_norm).float().unsqueeze(0).to(device)

			if(new_label < 0.90):
				with open(os.path.join(output_folder, file+'.exe'), mode='wb') as file1:
					file1.write(bytes(bytez))
				break

if __name__ == "__main__":
	test_model()
