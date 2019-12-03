# -*- coding: utf-8 -*-
r"""
    malgan.generator
    ~~~~~~~~~~~~~

    Generator block for MalGAN.

    Based on the paper: "Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN"
    By Weiwei Hu and Ying Tan.

    :version: 0.0.0
    :copyright: (c) 2019 by Zayd Hammoudeh.
    :license: MIT, see LICENSE for more details.
"""
from typing import List, Tuple

import warnings

import torch
import torch.nn as nn


tc = torch.cuda if torch.cuda.is_available() else torch
TensorTuple = Tuple[torch.Tensor, torch.Tensor]


class Generator(nn.Module):
    r""" MalGAN generator block """

    # noinspection PyPep8Naming
    def __init__(self, M: int, Z: int, hidden_size: List[int], g: nn.Module):
        r"""Generator Constructor

        :param M: Dimension of the feature vector \p m
        :param Z: Dimension of the noise vector \p z
        :param hidden_size: Width of the hidden layer(s)
        :param g: Activation function
        """
        super().__init__()

        self._Z = Z

        # Build the feed forward net
        self._layers, dim = nn.ModuleList(), [M + self._Z] + hidden_size
        for d_in, d_out in zip(dim[:-1], dim[1:]):
            self._layers.append(nn.Sequential(nn.Linear(d_in, d_out), g))

        # Last layer is always sigmoid
        layer = nn.Sequential(nn.Linear(dim[-1], M), nn.Sigmoid())
        self._layers.append(layer)

    # noinspection PyUnresolvedReferences
    def forward(self, m: torch.Tensor,
                z: torch.Tensor = None) -> TensorTuple:  # pylint: disable=arguments-differ
        r"""
        Forward pass through the generator.  Automatically generates the noise vector \p z that
        is coupled with \p m.

        :param m: Input vector :math:`m`
        :param z: Noise vector :math:`z`.  If no random vector is specified, the random vector is
                  generated within this function call via a call to \p torch.rand
        :return: Tuple of (:math:`m'`, :math:`G_{\theta_{g}}`), i.e., the output tensor with the
                 feature predictions as well as the smoothed prediction that can be used for
                 back-propagation.
        """
        if z is None:
            num_ele = m.shape[0]
            z = tc.FloatTensor(num_ele, self._Z)
            z.uniform_(0, 1)

        # Concatenation of m and z
        o = torch.cat((m, z), dim=1)  # pylint: disable=unused-variable # noqa: W0612, F841
        for layer in self._layers:
            o = layer(o)
        g_theta = torch.max(m, o)  # Ensure binary bits only set positive

        # m_prime is binarized version of g_sigma
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            threshold = tc.FloatTensor([0.5])
        m_prime = (g_theta > threshold).float()
        return m_prime, g_theta
