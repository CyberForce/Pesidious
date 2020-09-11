import argparse
import glob
from logging import basicConfig, debug, error, info, warning
import os
import pickle
import re
import sys
import time
import traceback
from handlers import TimedRotatingFileHandler
from pathlib import Path
from random import shuffle
from tqdm import tqdm

from datetime import date

from sklearn.model_selection import train_test_split

import lief
import torch
from torch.utils.data import DataLoader, Dataset

from rich.logging import RichHandler
from rich.progress import Progress, TaskID, track
from rich.traceback import install

SECTION_INDEX = 0


def parse_args():
    
    parser = argparse.ArgumentParser(description='PE File Feature Extraction. \nThe purpose of this application is extract the feature vectors from PE files for the purpose of malware analysis and malware mutation.')

    parser.add_argument('-m',"--malware-path", help = "The filepath of the malicious PE files whose features are to be extracted.", type = Path, default=Path("Data/malware"))
    parser.add_argument('-b',"--benign-path", help = "The filepath of the benign PE files whose features are to be extracted.", type = Path, default=Path("Data/benign"))
    parser.add_argument('-o', "--output-dir", help = "The filepath to where the feature vectors will be extracted. If this location does not exist, it will be created.", type = Path, default = Path("feature_vector_directory"))
    parser.add_argument('-f', "--logfile", help = "The file path to store the logs.", type = Path, default = Path("extract_features_logs_" + str(date.today()) + ".log"))
    
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

    log_dir = "Logs"

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, logfile)

    basicConfig(
        level=log_level.upper(),
        filemode='a',  # other options are w for write.
        format="%(message)s",
        handlers=[RichHandler()],
        filename=logfile
    )
        
    info("\n\nStarting Feature Extraction Program ...")


def features_mapping_index(malware_path: str, benign_path: str, output_path: str):

    malware_feature_vector_directory, benign_feature_vector_directory = setup_directories(malware_path, benign_path, output_path)
    
    malware_pe_files = os.listdir(malware_path)
    malware_pe_files = [os.path.join(malware_path, files) for files in malware_pe_files]

    benign_pe_files = os.listdir(benign_path)
    benign_pe_files = [os.path.join(benign_path, files) for files in benign_pe_files]

    # Reading Imports filter files
    debug("Reading filtered Imports file ...")

    filtered_imports_file = Path("manipulation_content/imports_content.txt")

    with open(str(filtered_imports_file), 'r') as file:
        filtered_imports = file.read()

    filtered_imports_file = filtered_imports.split('\n')

    # debug("Filter Imports : " + str(filtered_imports_file))

    debug("Number of malware files : " + str(len(malware_pe_files)))
    debug("Number of benign files : " + str(len(benign_pe_files)))
    debug("Number of total files : " + str(len(malware_pe_files) + len(benign_pe_files)))
    debug("Output directory : " + str(output_path))

    info("Creating import features mapping ...")
    
    feature_vector_mapping = {}
    import_feature_vector_mapping = {}
    section_feature_vector_mapping =  {}
    
    index = 0
    index_section = 0
    index_import = 0
    
    files = malware_pe_files + benign_pe_files

    info("Starting import extraction ...")
    # for i, file in enumerate(malware_pe_files + benign_pe_files):
    for i in tqdm(range(len(files)), desc=("Progress: ")):
        file = files[i]
        debug('Num: %d - Name: %s - Number of import features: %s' % (i, file, len(feature_vector_mapping)))

        try:
            win32, feature_vector_mapping, index = extract_imports(file, feature_vector_mapping, filtered_imports_file, index)
            win32, import_feature_vector_mapping, index_import = extract_imports(file, import_feature_vector_mapping, filtered_imports_file, index_import)

            if not win32:
                info("Deleting PE file : " + file)
                os.remove(file)
                files.remove(file)
                info(file, " has been deleted ...")

            pass
        except:
            traceback.print_exc()

            info("Deleting PE file : " + file)
            os.remove(file)
            files.remove(file)
            info(file, " has been deleted ...")
        
        debug("Index Import : %d", index_import)

    SECTION_INDEX = index

    info("Import extraction completed with %d imports", SECTION_INDEX)
    info("Starting section extraction ...")

    # for i, file in enumerate(malware_pe_files + benign_pe_files):
    for i in tqdm(range(len(files)), desc=("Progress: ")):
        file = files[i]
        debug('Num: %d - Name: %s - Number of section features: %s' % (i, file, len(feature_vector_mapping)))

        try:
            win32, feature_vector_mapping, index = extract_sections(file, feature_vector_mapping, index)
            win32, section_feature_vector_mapping, index_section = extract_sections(file, section_feature_vector_mapping, index_section)

            if not win32:
                exception("Deleting PE file : " + file)
                os.remove(file)
                files.remove(file)
                exception(file, " has been deleted ...")

            pass
        except:
            traceback.print_exc()

            exception("Deleting PE file : " + file)
            os.remove(file)
            files.remove(file)
            exception(file, " has been deleted ...")
            pass

        debug("Index Section : %d" , index_section)

    info("Section extraction completed %d sections", index_section)
    info("Features mapping to index is complete ...")
    debug("Total size of feature vector mapping : " + str(len(feature_vector_mapping)))
    info("Pickling Feature vector mapping ...")

    for i, import_lib in enumerate(feature_vector_mapping):
        debug(">>>> feature vector value at [%d] : %s", i, str(import_lib))

    for i, import_lib in enumerate(section_feature_vector_mapping):
        debug("++++ feature vector value at [%d] : %s", i, str(import_lib))

    for i, import_lib in enumerate(import_feature_vector_mapping):
        debug("<<<< feature vector value at [%d] : %s", i, str(import_lib)) 

    pickle.dump(feature_vector_mapping,
                open(os.path.join(output_path,"feature_vector_mapping.pk"), 'wb'))

    pickle.dump(import_feature_vector_mapping,
                open(os.path.join(output_path,"import_feature_vector_mapping.pk"), 'wb'))

    pickle.dump(section_feature_vector_mapping,
                open(os.path.join(output_path,"section_feature_vector_mapping.pk"), 'wb'))

    info("Pickling feature vector mapping complete. You can find them at logs: ")
    debug("\t -> Feature Vector mapping - %s ", str(os.path.join(output_path,"feature_vector_mapping.pk")))
    debug("\t -> Import Feature Vector mapping - %s ", str(os.path.join(output_path,"import_feature_vector_mapping.pk")))
    debug("\t -> Section Feature Vector mapping - %s ", str(os.path.join(output_path,"section_feature_vector_mapping.pk")))

    # For feature vector with imports and sections:
    info("Creating feature vector with imports and sections for malware set...")
    malware_pe_files_feature_set = torch.Tensor(feature_generation(malware_pe_files, feature_vector_mapping))
    info("Creating feature vector with imports and sections for benign set...")
    benign_pe_files_feature_set = torch.Tensor(feature_generation(benign_pe_files, feature_vector_mapping))

    debug("malware_pe_files_feature_set type -> " + str(malware_pe_files_feature_set))
    debug("malware_pe_files_feature_set size -->" + str(malware_pe_files_feature_set.shape))

    pickle.dump(malware_pe_files_feature_set, open(os.path.join(malware_feature_vector_directory, "malware_feature_set.pk"), 'wb'))
    pickle.dump(benign_pe_files_feature_set, open(os.path.join(benign_feature_vector_directory, "benign_feature_set.pk"), 'wb'))

    # For feature vector with imports:
    info("Creating feature vector with imports for malware set ...")
    malware_pe_files_import_feature_set = torch.Tensor(feature_generation(malware_pe_files, import_feature_vector_mapping))
    info("Creating feature vector with imports for benign set ...")
    benign_pe_files_import_feature_set = torch.Tensor(feature_generation(benign_pe_files, import_feature_vector_mapping))
    
    debug("malware_pe_files_import_feature_set type -> " + str(malware_pe_files_import_feature_set))
    debug("malware_pe_files_import_feature_set size -->" + str(malware_pe_files_import_feature_set.shape))

    pickle.dump(malware_pe_files_import_feature_set, open(os.path.join(malware_feature_vector_directory, "malware_pe_files_import_feature_set.pk"), 'wb'))
    pickle.dump(benign_pe_files_import_feature_set, open(os.path.join(benign_feature_vector_directory, "benign_pe_files_import_feature_set.pk"), 'wb'))

    # For feature vector with sections:
    info("Creating feature vector with sections for malware set...")
    malware_pe_files_section_feature_set = torch.Tensor(feature_generation(malware_pe_files, section_feature_vector_mapping))
    info("Creating feature vector with sections for benign set...")
    benign_pe_files_section_feature_set = torch.Tensor(feature_generation(benign_pe_files, section_feature_vector_mapping))

    
    debug("malware_pe_files_section_feature_set type -> " + str(malware_pe_files_section_feature_set))
    debug("malware_pe_files_section_feature_set size -->" + str(malware_pe_files_section_feature_set.shape))

    pickle.dump(malware_pe_files_section_feature_set, open(os.path.join(malware_feature_vector_directory, "malware_pe_files_section_feature_set.pk"), 'wb'))
    pickle.dump(benign_pe_files_section_feature_set, open(os.path.join(benign_feature_vector_directory, "benign_pe_files_section_feature_set.pk"), 'wb'))

    pass

# From ALFA Adv-mlaware-viz
def filter_imported_functions(func_string_with_library):
    """
    Filters the returned imported functions of binary to remove those with special characters (lots of noise for some reason),
    and require functions to start with a capital letter since Windows API functions seem to obey Upper Camelcase convension.

    Update: The limitation for the upper case in the preprocessing step has been removed. 
    """
    func_string = func_string_with_library.split(":")[0]
    
    if re.match("^[a-zA-Z]*$", func_string):
        return True
    else:
        return False

# From ALFA Adv-mlaware-viz
def remove_encoding_indicator(func_string):
    """
    In many functions there is a following "A" or "W" to indicate unicode or ANSI respectively that we want to remove.
    Make a check that we have a lower case letter
    """
    if (func_string[-1] == 'A' or func_string[-1] == 'W') and func_string[-2].islower():
        return func_string[:-1]
    else:
        return func_string

# From ALFA Adv-mlaware-viz
def process_imported_functions_output(imports):

    # debug("\n\t-> Imports (before) : " + str(imports))
    imports = list(filter(lambda x: filter_imported_functions(x), imports))
    # debug("\n\t-> Imports (After filter_imported_functions) : " + str(imports))
    # imports = list(map(lambda x: remove_encoding_indicator(x), imports))
    # debug("\n\t-> Imports (before remove_encoding_indicator) : " + str(imports))

    return imports

def feature_generation(pe_files: list, feature_vector_mapping: dict):
    
    pe_files_feature_set = []

    # for i, file in enumerate(pe_files):
    for i in tqdm(range(len(pe_files)),desc="Progress: "):
        file = pe_files[i]
        debug('Num: %d - Name: %s ' % (i, file))
        feature_vector = [0] * len(feature_vector_mapping)

        try:
            binary = lief.parse(file)
            imports = [e.name + ':' + lib.name.lower() for lib in binary.imports for e in lib.entries]
            imports = process_imported_functions_output(imports)   

            sections = [section.name for section in binary.sections]         

            for lib_import in imports:
                if lib_import in feature_vector_mapping:
                    index = feature_vector_mapping[lib_import]
                    feature_vector[index] = 1

            for section in sections:
                if section in feature_vector_mapping:
                    index = feature_vector_mapping[section]
                    feature_vector[index] = 1

        except:
            exception("%s is not parseable!" % file)
            raise Exception("%s is not parseable!" % file)
        
        # pe_files_feature_vectors.append(feature_vector)
        # pe_files_feature_vectors.append(file)

        # debug("pe_files_feature_vectors (features, file)" + str(pe_files_feature_vectors))
        pe_files_feature_set.append(feature_vector)

    # debug("pe_files_feature_set the tensor thingi --> \n\n" + str(pe_files_feature_set))

    debug("Malware Vectors Type : " + str(type(pe_files_feature_set)))
    info("Feature Extraction complete ...")

    return pe_files_feature_set

def extract_imports(file, feature_vector_mapping: dict, filtered_import_list: list,index: int = 0, win32: bool = True):

    # debug("Filtered Imports File : " + str(filtered_import_list))
    
    # debug(file)
    binary = lief.parse(file)

    debug("%s File Type : %s", file, str(binary.optional_header.magic))
    if str(binary.optional_header.magic) != "PE_TYPE.PE32":
        info("%s is not a 32 bit application ...", file)

        win32 = False

        return win32, feature_vector_mapping, index

    # imports includes the library (DLL) the function comes from
    imports = [
        e.name + ':' + lib.name.lower()  for lib in binary.imports for e in lib.entries
    ]

    # debug("\n\t-> Imports (before) : " + str(imports))

    # preprocess imports to remove noise
    imports = process_imported_functions_output(imports)

    # debug("\n\t-> Imports (After): " + str(imports))

    for lib_import in imports:
        debug("\t--> Lib Imports : " + str(lib_import))

        if lib_import not in feature_vector_mapping:
            if lib_import in filtered_import_list and "hal.dll" not in lib_import:
                debug("\t\t--> Present in filtered import list")
                feature_vector_mapping[lib_import] = index
                index += 1

    return win32, feature_vector_mapping, index

def extract_sections(file, feature_vector_mapping: dict, index: int = 0, win32: bool = True):
    
    # debug(file)
    binary = lief.parse(file)

    debug("%s File Type : %s", file, str(binary.optional_header.magic))
    if str(binary.optional_header.magic) != "PE_TYPE.PE32":
        info("%s is not a 32 bit application ...", file)

        win32 = False

        return win32, feature_vector_mapping, index 

    sections = [section.name for section in binary.sections]
    # debug("Sections present : %s", str(sections))

    for section in sections:
        if section not in feature_vector_mapping:
            feature_vector_mapping[section] = index
            debug("Added %s at index [%d]", str(feature_vector_mapping[section]), index)
            index += 1

    return win32, feature_vector_mapping, index

def setup_directories(malware_path: str, benign_path: str, output_path: str):
    info("Setting up output directories ...")

    feature_vector_directory = output_path
    malware_feature_vector_directory = os.path.join(feature_vector_directory, "malware")
    benign_feature_vector_directory = os.path.join(feature_vector_directory, "benign")

    if not os.path.exists(feature_vector_directory):
        os.mkdir(feature_vector_directory)
        debug("Feature vector directory has been created at : " + feature_vector_directory)

    if not os.path.exists(malware_feature_vector_directory):
        os.mkdir(malware_feature_vector_directory)
        debug("Malicious feature vector path has been created at : " + malware_feature_vector_directory)
         
    if not os.path.exists(benign_feature_vector_directory):
        os.mkdir(benign_feature_vector_directory)
        debug("Benign feature vector path has been created at : " + benign_feature_vector_directory)

    info("Output directores have been setup ...")

    return malware_feature_vector_directory, benign_feature_vector_directory

def main():
    args = parse_args()

    # print(args)

    logging_setup(str(args.logfile), args.log_level)

    info("Setting parameters ...")
    info("\tMalware Directory - " + str(args.malware_path))
    info("\tBenign Directory - " + str(args.benign_path))
    info("\tOutput Directory - " + str(args.output_dir))
    info("\tLogfile - " + str(args.logfile))
    info("\tLog Level - " + str(args.log_level))
    info("\tDetailed Log - " + str(args.detailed_log))

    malware_path = str(args.malware_path)
    benign_path = str(args.benign_path)
    output_dir = str(args.output_dir)

    features_mapping_index(malware_path, benign_path, output_dir)
    pass

if __name__ == "__main__":
    main()
