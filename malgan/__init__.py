# -*- coding: utf-8 -*-
r"""
    malgan.__init__
    ~~~~~~~~~~~~~~~

    MalGAN complete architecture.

    Based on the paper: "Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN"
    By Weiwei Hu and Ying Tan.

    :copyright: (c) 2019 by Zayd Hammoudeh.
    :license: MIT, see LICENSE for more details.
"""
import logging
import os
import sys
from enum import Enum
from typing import Union, List, Tuple
from pathlib import Path
import pickle

import numpy as np

import tensorboardX
import torch
import torch.nn as nn
import torch.optim
import torch.utils.data
from torch.utils.data import Dataset, DataLoader, Subset
from tqdm import tqdm

from malgan._export_results import _export_results
from .detector import BlackBoxDetector
from .discriminator import Discriminator
from .generator import Generator

ListIntOrInt = Union[List[int], int]
PathOrStr = Union[str, Path]
TensorTuple = Tuple[torch.Tensor, torch.Tensor]


class MalwareDataset(Dataset):
    r"""
    Encapsulates a malware dataset.  All elements in the dataset will be either malware or benign
    """
    def __init__(self, x: Union[np.ndarray, torch.Tensor], y):
        super().__init__()

        if isinstance(x, np.ndarray):
            x = torch.from_numpy(x).float()
        self.x = x
        self.y = y

    def __getitem__(self, index):
        return self.x[index], self.y

    def __len__(self):
        return self.x.shape[0]

    @property
    def num_features(self):
        r""" Number of features in the dataset """
        logging.debug("self.x.shape[1] : " + str(self.x.shape[1]))
        return self.x.shape[1]


class _DataGroup:  # pylint: disable=too-few-public-methods
    r"""
    Encapsulates either PyTorch DataLoaders or Datasets.  This class is intended only for internal
    use by MalGAN.
    """
    def __init__(self, train: MalwareDataset, valid: MalwareDataset, test: MalwareDataset):
        self.train = train
        self.valid = valid
        self.test = test
        self.is_loaders = False

    def build_loader(self, batch_size: int = 0):
        r"""
        Constructs loaders from the datasets

        :param batch_size: Batch size for training
        """
        self.train = DataLoader(self.train, batch_size=batch_size, shuffle=True, pin_memory=True)
        if self.valid:
            self.valid = DataLoader(self.valid, batch_size=batch_size, pin_memory=True)
        self.test = DataLoader(self.test, batch_size=batch_size, pin_memory=True)
        self.is_loaders = True


# noinspection PyPep8Naming
class MalGAN(nn.Module):
    r""" Malware Generative Adversarial Network based on the work of Hu & Tan. """

    MALWARE_BATCH_SIZE = 32

    SAVED_MODEL_DIR = Path("saved_models")

    VALIDATION_SPLIT = 0.2

    tensorboard = None

    class Label(Enum):
        r""" Label value assigned to malware and benign examples """
        Malware = 1
        Benign = 0

    # noinspection PyPep8Naming
    def __init__(self, mal_data: MalwareDataset, ben_data: MalwareDataset, Z: int,
                 h_gen: ListIntOrInt, h_discrim: ListIntOrInt,
                 test_split: float = 0.2,
                 g_hidden: nn.Module = nn.LeakyReLU,
                 detector_type: BlackBoxDetector.Type = BlackBoxDetector.Type.LogisticRegression): # Try out with DecisionTree.
        r"""
        Malware Generative Adversarial Network Constructor

        :param mal_data: Malware training dataset.
        :param ben_data: Benign training dataset.
        :param Z: Dimension of the noise vector \p z
        :param test_split: Fraction of input data to be used for testing
        :param h_gen: Width of the hidden layer(s) in the GENERATOR.  If only a single hidden
                      layer is desired, then this can be only an integer.
        :param h_discrim: Width of the hidden layer(s) in the DISCRIMINATOR.  If only a single
                          hidden layer is desired, then this can be only an integer.
        :param detector_type: Learning algorithm to be used by the black-box detector
        """
        super().__init__()

        if mal_data.num_features != ben_data.num_features:
            raise ValueError("Mismatch in the number of features between malware and benign data")
        if Z <= 0:
            raise ValueError("Z must be a positive integers")
        if test_split <= 0. or test_split >= 1.:
            raise ValueError("test_split must be in the range (0,1)")
        self._M, self._Z = mal_data.num_features, Z  # pylint: disable=invalid-name

        # Format the hidden layer sizes and make sure all are valid values
        if isinstance(h_gen, int):
            h_gen = [h_gen]
        if isinstance(h_discrim, int):
            h_discrim = [h_discrim]
        self.d_discrim, self.d_gen = h_discrim, h_gen
        for h_size in [self.d_discrim, self.d_gen]:
            for w in h_size:
                if w <= 0:
                    raise ValueError("All hidden layer widths must be positive integers.")

        if not isinstance(g_hidden, nn.Module):
            g_hidden = g_hidden()
        self._g = g_hidden

        self._is_cuda = torch.cuda.is_available()

        logging.info("Constructing new MalGAN")
        
        logging.info("Malware Dimension (M): %d", self.M)
        logging.info("Latent Dimension (Z): %d", self.Z)
        logging.info("Test Split Ratio: %.3f", test_split)
        logging.info("Generator Hidden Layer Sizes: %s", h_gen)
        logging.info("Discriminator Hidden Layer Sizes: %s", h_discrim)
        logging.info("Blackbox Detector Type: %s", detector_type.name)
        logging.info("Activation Type: %s", self._g.__class__.__name__)
        logging.info("CUDA State: %s", "Enabled" if self._is_cuda else "Disabled")

        self._bb = BlackBoxDetector(detector_type)
        self._gen = Generator(M=self.M, Z=self.Z, hidden_size=h_gen, g=self._g)
        self._discrim = Discriminator(M=self.M, hidden_size=h_discrim, g=self._g)

        def split_train_valid_test(dataset: Dataset, is_benign: bool):
            """Helper function to partition into test, train, and validation subsets"""
            valid_len = 0 if is_benign else int(MalGAN.VALIDATION_SPLIT * len(dataset))
            test_len = int(test_split * len(dataset))

            # Order must be train, validation, test
            lengths = [len(dataset) - valid_len - test_len, valid_len, test_len]
            return _DataGroup(*torch.utils.data.random_split(dataset, lengths))

        # Split between train, test, and validation then construct the loaders
        self._mal_data = split_train_valid_test(mal_data, is_benign=False)
        self._ben_data = split_train_valid_test(ben_data, is_benign=True)
        # noinspection PyTypeChecker
        self._fit_blackbox(self._mal_data.train, self._ben_data.train)

        self._mal_data.build_loader(MalGAN.MALWARE_BATCH_SIZE)
        ben_bs_frac = len(ben_data) / len(mal_data)
        self._ben_data.build_loader(int(ben_bs_frac * MalGAN.MALWARE_BATCH_SIZE))
        # Set CUDA last to ensure all parameters defined
        if self._is_cuda:
            self.cuda()

    @property
    def M(self) -> int:
        r"""Width of the malware feature vector"""
        return self._M

    @property
    def Z(self) -> int:
        r"""Width of the generator latent noise vector"""
        return self._Z

    def _fit_blackbox(self, mal_train: Subset, ben_train: Subset) -> None:
        r"""
        Firsts the blackbox detector using the specified malware and benign training sets.

        :param mal_train: Malware training dataset
        :param ben_train: Benign training dataset
        """
        def extract_x(ds: Subset) -> torch.Tensor:
            # noinspection PyUnresolvedReferences
            x = ds.dataset.x[ds.indices]
            return x.cpu() if self._is_cuda else x

        mal_x = extract_x(mal_train)
        ben_x = extract_x(ben_train)
        merged_x = torch.cat((mal_x, ben_x))

        merged_y = torch.cat((torch.full((len(mal_train),), MalGAN.Label.Malware.value),
                              torch.full((len(ben_train),), MalGAN.Label.Benign.value)))
        logging.debug("Starting training of blackbox detector of type \"%s\"", self._bb.type.name)
        self._bb.fit(merged_x, merged_y)
        logging.debug("COMPLETED training of blackbox detector of type \"%s\"", self._bb.type.name)

    def fit_one_cycle(self, cyc_len: int, quiet_mode: bool = False) -> None:
        r"""
        Trains the model for the specified number of epochs.  The epoch with the best validation
        loss is used as the final model.

        :param cyc_len: Number of cycles (epochs) to train the model.
        :param quiet_mode: True if no printing to console should occur in this function
        """
        if cyc_len <= 0:
            raise ValueError("At least a single training cycle is required.")

        MalGAN.tensorboard = tensorboardX.SummaryWriter()
        if not self._is_cuda:
            MalGAN.tensorboard.add_graph(_CompGraph(self), torch.zeros(1, self.M))

        d_optimizer = torch.optim.Adam(self._discrim.parameters(), lr=1e-5)
        g_optimizer = torch.optim.Adam(self._gen.parameters(), lr=1e-4)

        best_epoch, best_loss = None, np.inf
        for epoch_cnt in range(1, cyc_len + 1):
            train_l_g, train_l_d = self._fit_epoch(epoch_cnt, g_optimizer, d_optimizer, quiet_mode)
            for block, loss in [("Generator", train_l_g), ("Discriminator", train_l_d)]:
                MalGAN.tensorboard.add_scalar('Train_%s_Loss' % block, loss, epoch_cnt)
                logging.debug("Epoch %d: Avg Train %s Loss: %.6f", epoch_cnt, block, loss)

            # noinspection PyTypeChecker
            valid_l_g = self._meas_loader_gen_loss(self._mal_data.valid)
            MalGAN.tensorboard.add_scalar('Validation_Generator_Loss', valid_l_g, epoch_cnt)
            if valid_l_g < best_loss:
                self._save(self._build_export_name(epoch_cnt))
                if best_epoch is not None:
                    self._delete_old_backup(best_epoch)
                best_epoch, best_loss = epoch_cnt, valid_l_g
                logging.debug("Epoch %d: New best validation loss: %.6f", best_epoch, best_loss)
            else:
                logging.debug("Epoch %d: Avg Validation Generator Loss: %.6f", epoch_cnt, valid_l_g)
        logging.debug("TRAINING COMPLETE. Best epoch is %d with loss %.6f", best_epoch, best_loss)
        MalGAN.tensorboard.close()

        self.load(self._build_export_name(best_epoch))
        self._save(self._build_export_name())
        self._delete_old_backup(best_epoch)

    def _build_export_name(self, epoch_num: int = None) -> str:
        r"""
        Builds the name that will be used when exporting the model.

        :param epoch_num: Optional epoch number associated with the model
        :return: Model name built from the model's parameters
        """
        name = ["malgan", "z=%d" % self.Z,
                "d-gen=%s" % str(self.d_gen).replace(" ", "_"),
                "d-disc=%s" % str(self.d_discrim).replace(" ", "_"),
                "bs=%d" % MalGAN.MALWARE_BATCH_SIZE,
                "bb=%s" % self._bb.type.name, "g=%s" % self._g.__class__.__name__,
                "final" if epoch_num is None else "epoch_%05d" % epoch_num]

        # Either add an epoch name or
        return MalGAN.SAVED_MODEL_DIR / "".join(["_".join(name).lower(), ".pth"])

    def _delete_old_backup(self, epoch_num: int) -> None:
        """
        Helper function to delete old backed up models

        :param epoch_num: Epoch number associated with old backed up model
        """
        backup_name = self._build_export_name(epoch_num)
        try:
            os.remove(str(backup_name))
        except OSError:
            logging.warning("Error trying to delete model: %s", backup_name)

    def _fit_epoch(self, epoch_num: int, g_optim: torch.optim.Optimizer,
                   d_optim: torch.optim.Optimizer, quiet_mode: bool) -> TensorTuple:
        r"""
        Trains a single entire epoch

        :param epoch_num: Epoch number
        :param g_optim: Generator optimizer
        :param d_optim: Discriminator optimizer
        :param quiet_mode: True if the function should be run in quiet mode
        :return: Average training loss
        """
        tot_l_g = tot_l_d = 0
        num_batch = min(len(self._mal_data.train), len(self._ben_data.train))

        logging.debug("Starting training epoch #%d with %d batches", epoch_num, num_batch)
        desc = "Epoch %d Progress" % epoch_num
        batch_generator = merged_data = zip(self._mal_data.train, self._ben_data.train)
        if not quiet_mode:
            batch_generator = tqdm(merged_data, total=num_batch, desc=desc, file=sys.stdout)
        for (m, _), (b, _) in batch_generator:
            if self._is_cuda:
                m, b = m.cuda(), b.cuda()
            m_prime, g_theta = self._gen.forward(m)
            l_g = self._calc_gen_loss(g_theta)
            g_optim.zero_grad()
            l_g.backward()
            # torch.nn.utils.clip_grad_value_(l_g, 1)
            g_optim.step()
            tot_l_g += l_g

            # Update the discriminator
            for x in [m_prime, b]:
                l_d = self._calc_discrim_loss(x)
                d_optim.zero_grad()
                l_d.backward()
                # torch.nn.utils.clip_grad_value_(l_d, 1)
                d_optim.step()
                tot_l_d += l_d
        logging.debug("COMPLETED training epoch #%d", epoch_num)
        return tot_l_g / num_batch, tot_l_d / num_batch

    def _meas_loader_gen_loss(self, loader: DataLoader) -> float:
        r""" Calculate the generator loss on malware dataset """
        loss = 0
        for m, _ in loader:
            if self._is_cuda:
                m = m.cuda()
            _, g_theta = self._gen.forward(m)
            loss += self._calc_gen_loss(g_theta)
        return loss / len(loader)

    def _calc_gen_loss(self, g_theta: torch.Tensor) -> torch.Tensor:
        r"""
        Calculates the parameter :math:`L_{G}` as defined in Eq. (3) of Hu & Tan's paper.

        :param g_theta: :math:`G(_{\theta_g}(m,z)` in Eq. (1) of Hu & Tan's paper
        :return: Loss for the generator smoothed output.
        """
        d_theta = self._discrim.forward(g_theta)
        return d_theta.log().mean()

    def _calc_discrim_loss(self, X: torch.Tensor) -> torch.Tensor:
        r"""
        Calculates the parameter :math:`L_{D}` as defined in Eq. (2) of Hu & Tan's paper.

        :param X: Examples to calculate the loss over.  May be a mix of benign and malware samples.
        """
        d_theta = self._discrim.forward(X)

        y_hat = self._bb.predict(X)
        d = torch.where(y_hat == MalGAN.Label.Malware.value, d_theta, 1 - d_theta)
        return -d.log().mean()

    def measure_and_export_results(self, cyc_len: int, adversarial_feature_vector_directory: str, output_filename: str) -> str:
        r"""
        Measure the test accuracy and provide results information

        :param cyc_len: Number of cycles (epochs) to train the model. #ADDED BY ME. 


        :return: Results information as a comma separated string
        """

        if not os.path.exists(adversarial_feature_vector_directory):
            os.mkdir(adversarial_feature_vector_directory)

        # noinspection PyTypeChecker
        valid_loss = self._meas_loader_gen_loss(self._mal_data.valid)
        # noinspection PyTypeChecker
        test_loss = self._meas_loader_gen_loss(self._mal_data.test)
        logging.debug("Final Validation Loss: %.6f", valid_loss)
        logging.debug("Final Test Loss: %.6f", test_loss)

        num_mal_test = 0
        y_mal_orig, m_prime_arr, bits_changed = [], [], []
        for m, _ in self._mal_data.test:
            y_mal_orig.append(self._bb.predict(m.cpu()))
            if self._is_cuda:
                m = m.cuda()
            num_mal_test += m.shape[0]

            m_prime, _ = self._gen.forward(m)
            m_prime_arr.append(m_prime.cpu() if self._is_cuda else m_prime)

            m_diff = m_prime - m
            bits_changed.append(torch.sum(m_diff.cpu(), dim=1))

            # logging.debug("The shape of m_diff is : " + str(m_diff.shape))
            # logging.debug("The type of m_diff is : " + str(type(m_diff)))

            # Sanity check no bits flipped 1 -> 0
            msg = "Malware signature changed to 0 which is not allowed"
            assert torch.sum(m_diff < -0.1) == 0, msg
        avg_changed_bits = torch.cat(bits_changed).mean()
        
        pickle.dump(m_prime_arr, open(os.path.join(adversarial_feature_vector_directory, output_filename), 'wb'))
        logging.debug("Avg. Malware Bits Changed Changed: %2f", avg_changed_bits)

        # BB prediction of the malware before the generator
        y_mal_orig = torch.cat(y_mal_orig)

        # Build an X tensor for prediction using the detector
        ben_test_arr = [x.cpu() if self._is_cuda else x for x, _ in self._ben_data.test]
        x = torch.cat(m_prime_arr + ben_test_arr)
        y_actual = torch.cat((torch.full((num_mal_test,), MalGAN.Label.Malware.value),
                             torch.full((len(x) - num_mal_test,), MalGAN.Label.Benign.value)))

        y_hat_post = self._bb.predict(x)
        if self._is_cuda:
            y_mal_orig, y_hat_post, y_actual = y_mal_orig.cpu(), y_hat_post.cpu(), y_actual.cpu()
        # noinspection PyProtectedMember
        y_prob = self._bb._model.predict_proba(x)  # pylint: disable=protected-access
        y_prob = y_prob[:, MalGAN.Label.Malware.value]
        return _export_results(self, valid_loss, test_loss, avg_changed_bits, y_actual,
                               y_mal_orig, y_prob, y_hat_post, cyc_len)

    def _save(self, file_path: PathOrStr) -> None:
        r"""
        Export the specified model to disk.  The function creates any files needed on the path.
        All exported models will be relative to \p EXPORT_DIR class object.

        :param file_path: Path to export the model.
        """
        if isinstance(file_path, str):
            file_path = Path(file_path)

        file_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.state_dict(), str(file_path))

    def forward(self, x: torch.Tensor) -> TensorTuple:  # pylint: disable=arguments-differ
        r"""
        Passes a malware tensor and augments it to make it more undetectable by

        :param x: Malware binary tensor
        :return: :math:`m'` and :math:`g_{\theta}` respectively
        """
        return self._gen.forward(x)

    def load(self, filename: PathOrStr) -> None:
        r"""
        Load a MalGAN object from disk.  MalGAN's \p EXPORT_DIR is prepended to the specified
        filename.

        :param filename: Path to the exported torch file
        """
        if isinstance(filename, Path):
            filename = str(filename)
        self.load_state_dict(torch.load(filename))
        self.eval()
        # Based on the recommendation of Soumith Chantala et al. in GAN Hacks that enabling dropout
        # in evaluation improves performance. Source code based on:
        # https://discuss.pytorch.org/t/using-dropout-in-evaluation-mode/27721
        for m in self._gen.modules():
            if m.__class__.__name__.startswith('Dropout'):
                m.train()

    @staticmethod
    def _print_memory_usage() -> None:
        """
        Helper function to print the allocated tensor memory.  This is used to debug out of memory
        GPU errors.
        """
        import gc
        import operator as op
        from functools import reduce
        for obj in gc.get_objects():
            # noinspection PyBroadException
            try:
                if torch.is_tensor(obj) or (hasattr(obj, 'data') and torch.is_tensor(obj.data)):
                    if len(obj.size()) > 0:  # pylint: disable=len-as-condition
                        obj_tot_size = reduce(op.mul, obj.size())
                    else:
                        obj_tot_size = "NA"
                    print(obj_tot_size, type(obj), obj.size())
            except:  # pylint: disable=bare-except  # NOQA E722
                pass


class _CompGraph(nn.Module):
    r""" Helper class used to visualize the computation graph """
    def __init__(self, malgan: MalGAN):
        super().__init__()
        self._malgan = malgan

    # noinspection PyProtectedMember
    def forward(self, x: torch.Tensor) -> torch.Tensor:  # pylint: disable=arguments-differ
        z = torch.zeros(x.shape[0], self._malgan.Z)
        m_prime, _ = self._malgan._gen.forward(x, z)  # pylint: disable=protected-access
        return self._malgan._discrim.forward(m_prime)  # pylint: disable=protected-access
