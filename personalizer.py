from azure.cognitiveservices.personalizer import PersonalizerClient
from azure.cognitiveservices.personalizer.models import RankableAction, RewardRequest, RankRequest
from msrest.authentication import CognitiveServicesCredentials

import datetime, json, os, time, uuid

import gym
import gym_malware
from gym_malware.envs.utils import interface, pefeatures
from gym_malware.envs.controls import manipulate2 as manipulate


env_id = "malware-score-v0"
env = gym.make(env_id)
env.seed(123)

ACTION_LOOKUP = {i: act for i, act in enumerate(manipulate.ACTION_TABLE.keys())}

key_var_name = '378c80137f884780af7783cdd3ee6bdd'
#if not key_var_name in os.environ:
#    raise Exception('Please set/export the environment variable: {}'.format(key_var_name))
personalizer_key = key_var_name

# Replace <your-resource-name>: https://<your-resource-name>.api.cognitive.microsoft.com/
endpoint_var_name = 'https://rl-agent.cognitiveservices.azure.com/'
#if not endpoint_var_name in os.environ:
#    raise Exception('Please set/export the environment variable: {}'.format(endpoint_var_name))
personalizer_endpoint = endpoint_var_name

# Instantiate a Personalizer client
client = PersonalizerClient(personalizer_endpoint, CognitiveServicesCredentials(personalizer_key))

class RangeNormalize(object):
    def __init__(self, 
                 min_val, 
                 max_val):
        """
        Normalize a tensor between a min and max value
        Arguments
        ---------
        min_val : float
            lower bound of normalized tensor
        max_val : float
            upper bound of normalized tensor
        """
        self.min_val = min_val
        self.max_val = max_val

    def __call__(self, *inputs):
        outputs = []
        for idx, _input in enumerate(inputs):
            _min_val = _input.min()
            _max_val = _input.max()
            a = (self.max_val - self.min_val) / (_max_val - _min_val)
            b = self.max_val- a * _max_val
            _input = (_input * a ) + b
            outputs.append(_input)
        return outputs if idx > 1 else outputs[0]

if __name__ == "__main__":

	rn = RangeNormalize(-0.5,0.5)
	print(ACTION_LOOKUP)
	actions = ['overlay_append', 'section_rename', 'section_add', 'imports_append']
	# for key in ACTION_LOOKUP:
	# 	actions.append(ACTION_LOOKUP[key])

	# print(actions)

	for episode in range(1, 2000):
		eventid = str(uuid.uuid4())
		state = env.reset()
		state_norm = rn(state)
		for mutation in range(1, 80):
			rank_request = RankRequest( actions=actions, context_features=state_norm, eventid=eventid)
			response = client.rank(rank_request=rank_request)

			print("Personalizer service ranked the actions with the probabilities listed below:")
    
			rankedList = response.ranking
			for ranked in rankedList:
			    print(ranked.id, ':',ranked.probability)



