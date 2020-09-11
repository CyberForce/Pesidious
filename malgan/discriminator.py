# -*- coding: utf-8 -*-

from typing import List

import torch
import torch.nn as nn


# noinspection PyPep8Naming
class Discriminator(nn.Module):
    r""" MalGAN discriminator (substitute detector).  Simple feed forward network. """

    def __init__(self, M: int, hidden_size: List[int], g: nn.Module):
        r"""Discriminator Constructor

        Builds the discriminator block.

        :param M: Width of the malware feature vector
        :param hidden_size: Width of the hidden layer(s).
        :param g: Activation function
        """
        super().__init__()

        # Build the feed forward layers.
        self._layers = nn.ModuleList()
        for in_w, out_w in zip([M] + hidden_size[:-1], hidden_size):
            layer = nn.Sequential(nn.Linear(in_w, out_w), g)
            self._layers.append(layer)

        layer = nn.Sequential(nn.Linear(hidden_size[-1], 1), nn.Sigmoid())
        self._layers.append(layer)

    def forward(self, X: torch.Tensor) -> torch.Tensor:
        r"""
        Forward path through the discriminator.

        :param X: Input example tensor
        :return: :math:`D_{sigma}(x)` -- Value predicted by the discriminator.
        """
        d_theta = X
        for layer in self._layers:
            d_theta = layer(d_theta)
        # return d_theta
        err = 1e-7
        return torch.clamp(d_theta, err, 1. - err).view(-1)
