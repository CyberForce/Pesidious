import argparse
import glob
import os
import pickle
import re
import sys
import time
import traceback
from datetime import date
from logging import (basicConfig, debug, error, exception, getLogger, info,
                     warning)
# from handlers import TimedRotatingFileHandler
from pathlib import Path
from random import shuffle

# Installing rich modules for pretty printing
from rich import print
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import track
from rich.table import Table
from rich.text import Text
from rich.traceback import install

import lief
import torch
from pyfiglet import Figlet
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset

install()

import extract_features
# import main_malgan
# import binary_builder


SECTION_INDEX = 0


def parse_args():

    parser = argparse.ArgumentParser(
        description="PESidious Model Trainer. \nUse this script as a driver function to train the PEsidious model to generate evasive mutated malware."
    )

    parser.add_argument(
        "-m",
        "--malware-path",
        help="The filepath of the malicious PE files whose features are to be extracted.",
        type=Path,
        default=Path("Data/malware"),
    )
    parser.add_argument(
        "-b",
        "--benign-path",
        help="The filepath of the benign PE files whose features are to be extracted.",
        type=Path,
        default=Path("Data/benign"),
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        help="The filepath to where the feature vectors will be extracted. If this location does not exist, it will be created.",
        type=Path,
        default=Path("feature_vector_directory"),
    )
    parser.add_argument(
        "-f",
        "--logfile",
        help="The file path to store the logs.",
        type=Path,
        default=Path("extract_features_logs_" + str(date.today()) + ".log"),
    )

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


def logging_setup(logfile: str, log_level: str):

    log_dir = "Logs"

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, logfile)

    basicConfig(
        level=log_level.upper(),
        filemode="a",  # other options are w for write.
        format="%(message)s",
        filename=logfile,
    )

    getLogger().addHandler(RichHandler())


def main():

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

    # Read arguments and set logging configurations.
    args = parse_args()
    logging_setup(str(args.logfile), args.log)

    extract_features.main()

    pass


if __name__ == "__main__":
    main()
