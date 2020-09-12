import argparse
import gym
import numpy as np
from itertools import count

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.distributions import Categorical

import gym_malware
from gym_malware.envs.utils import interface, pefeatures
from gym_malware.envs.controls import manipulate2 as manipulate
from collections import namedtuple, deque
from statistics import mean 

parser = argparse.ArgumentParser(description='PyTorch REINFORCE example')
parser.add_argument('--gamma', type=float, default=0.99, metavar='G',
                    help='discount factor (default: 0.99)')
parser.add_argument('--seed', type=int, default=543, metavar='N',
                    help='random seed (default: 543)')
parser.add_argument('--render', action='store_true',
                    help='render the environment')
parser.add_argument('--log-interval', type=int, default=10, metavar='N',
                    help='interval between training status logs (default: 10)')
args = parser.parse_args()

device = torch.device("cpu")

env = gym.make("malware-score-v0")
env.seed(args.seed)
torch.manual_seed(args.seed)

class Policy(nn.Module):
    def __init__(self):
        super(Policy, self).__init__()
        self.layers = nn.Sequential(
            nn.Dropout(0.1),
            nn.Linear(env.observation_space.shape[0], 1024),
            nn.BatchNorm1d(1024),
            nn.ELU(alpha=1.0),
            nn.Linear(1024, 256),
            nn.BatchNorm1d(256),
            nn.ELU(alpha=1.0),
            nn.Linear(256, env.action_space.n)
        )

        self.saved_log_probs = []
        self.rewards = []

    def forward(self, x):
        action_scores =  self.layers(x)
        return action_scores

# class Policy(nn.Module):
#     def __init__(self):
#         super(Policy, self).__init__()
#         self.affine1 = nn.Linear(4, 128)
#         self.dropout = nn.Dropout(p=0.6)
#         self.affine2 = nn.Linear(128, 2)

#         self.saved_log_probs = []
#         self.rewards = []

#     def forward(self, x):
#         x = self.affine1(x)
#         x = self.dropout(x)
#         x = F.relu(x)
#         action_scores = self.affine2(x)
#         return F.softmax(action_scores, dim=1)


policy = Policy()
optimizer = optim.Adam(policy.parameters(), lr=1e-2)
eps = np.finfo(np.float32).eps.item()

def update_epsilon(n):
    epsilon_start = 1.0
    epsilon = epsilon_start
    epsilon_final = 0.4
    epsilon_decay = 1000 # N from the research paper (equation #6)

    epsilon = 1.0 - (n/epsilon_decay)

    if epsilon <= epsilon_final:
        epsilon = epsilon_final

    return epsilon

def select_action(observation, epsilon):
    rand = np.random.random()
    if rand < epsilon:
        action = np.random.choice(env.action_space.n)
        return action

    actions = policy.forward(observation)
    action = torch.argmax(actions).item()
    policy.saved_log_probs.append(m.log_prob(action))
    print(action)
    return action.item()


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

def finish_episode():
    R = 0
    policy_loss = []
    returns = []
    for r in policy.rewards[::-1]:
        R = r + args.gamma * R
        returns.insert(0, R)
    returns = torch.tensor(returns)
    returns = (returns - returns.mean()) / (returns.std() + eps)
    for log_prob, R in zip(policy.saved_log_probs, returns):
        policy_loss.append(-log_prob * R)
    optimizer.zero_grad()
    policy_loss = torch.cat(policy_loss).sum()
    policy_loss.backward()
    optimizer.step()
    del policy.rewards[:]
    del policy.saved_log_probs[:]


def main():
    running_reward = 10

    rn = RangeNormalize(-0.5,0.5)
    D = 30000 # as mentioned in the research paper (total number of episodes)
    T = 80 # as mentioned in the paper (total number of mutations that the agent can perform on one file)
    B = 1000 # as mentioned in the paper (number of steps before learning starts)
    n = 0
    for i_episode in range(1, D):
        try:
            state, ep_reward = env.reset(), 0
            state_norm = rn(state)
            state_norm = torch.from_numpy(state_norm).float().unsqueeze(0).to(device)
            epsilon = update_epsilon(i_episode)
            for t in range(1, T):  # Don't infinite loop while learning
                action = select_action(state_norm, epsilon)
                state, reward, done, _ = env.step(action)
                if args.render:
                    env.render()
                policy.rewards.append(reward)
                ep_reward += reward
                print("episode : " + str(i_episode) + " turn : " + str(t) + " reward : " + str(reward))
                if done:
                    break


            running_reward = 0.05 * ep_reward + (1 - 0.05) * running_reward
            finish_episode()
            if i_episode % args.log_interval == 0:
                print('Episode {}\tLast reward: {:.2f}\tAverage reward: {:.2f}'.format(
                      i_episode, ep_reward, running_reward))
            if i_episode % 500 == 0:
                torch.save(policy.state_dict(), 'dqeaf-2' + str(i_episode) + '.pt')
        
        except Exception:
            continue



if __name__ == '__main__':
    main()