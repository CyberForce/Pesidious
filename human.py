from __future__ import print_function, unicode_literals
from PyInquirer import style_from_dict, Token, prompt, Separator

import os
import sys
import random
import pickle
import struct
import array
import hashlib
import lief
import pefile
import json
# import tqdm
import argparse
import logging
from pathlib import Path
from datetime import date
from pyfiglet import Figlet

def parse_args():

    parser = argparse.ArgumentParser(
        description='Order 66. \nMutate your own malware using a collection of actions to make it more evasive.')

    parser.add_argument('-m', "--malware-path", help="The path to the directory with the malwares",
                        type=Path, default=Path("Data/human-data"))

    parser.add_argument('-s', "--section-name", help="Enter the path to the pickled file with the section names. Data type should be a list of section names.",
                        type=Path, default=Path("RL_Features/adversarial_sections_set.pk"))

    parser.add_argument('-i', "--add-imports", help="Enter the path to the pickled file with the import functions. Data type should be a dictionart with library and functions.",
                        type=Path, default=Path("RL_Features/human_imports.pk"))

    parser.add_argument('-c', "--section-content", help="Enter the path to a text file with the section contents.",
                        type=Path, default=Path("manipulation_content/section_content.txt"))

    parser.add_argument(
        '-o', "--output-dir", help="The filepath to where the mutated malware will be generated. If this location does not exist, it will be created.", type=Path, default=Path("Manually_Mutated_Binaries"))

    parser.add_argument('-d', "--detailed-log",
                        help="Detailed Logs", type=bool, default=False)
    parser.add_argument('-l', "--logfile", help="The file path to store the logs.",
                        type=str, default="binary_builder_logs_" + str(date.today()) + ".log")

    help_msg = " ".join(["Set the severity level of logs you want to collect. By default, the logging module logs the messages with a severity level of INFO or above. Valid choices (Enter the numeric values) are: \"[10] - DEBUG\", \"[20] - INFO\",",
                         "\"[30] - WARNING\", \"[40] - ERROR\" and \"[50] - CRITICAL\"."])
    parser.add_argument('-L', "--log-level", help=help_msg,
                        type=int, default=logging.INFO)

    args = parser.parse_args()
    return args


def logging_setup(detailed_log: bool, logfile: str, log_level: int):

    format_str = '%(name)s - %(asctime)s - %(levelname)s - %(message)s'
    format_date = '%d-%b-%y %H:%M:%S'

    log_dir = "Logs"

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, logfile)

    logging.basicConfig(
        level=logging.DEBUG,
        filemode='a',  # other options are w for write.
        datefmt=format_date,
        format=format_str,
        filename=logfile
    )

    if detailed_log:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)

    logging.info("\n\nStarting Adversial Malware Reconstruction ...")


def show_options(malware_folder: str, file, section_names, import_functions, section_content, output_dir):

    with open(os.path.join(malware_folder, file), 'rb') as binfile:
        bytez = binfile.read()

    while(True):
        questions = [
            {
                'type': 'list',
                'name': 'action',
                'message': '[*] Select the action you would like to use to mutate the malware : ',
                'choices': [
                    "[1] - Append random number of bytes",
                    "[2] - Append a DLL",
                    "[3] - Append a Section",
                    "[4] - Rename a Random Section",
                    "[5] - Remove Signature",
                    "[6] - Remove Debug",
                    "[7] - Mutate Malware"
                ]
            }
        ]

        answers = prompt(questions)

        action_number = int(answers["action"][1])

        if(action_number == 1):
            bytez = overlay_append(bytez)

        elif(action_number == 2):
            libname = (list(import_functions))

            libraries = []


            count = 0
            for lib in libname:
                dict = {
                    'name': lib
                }
                libraries.append(dict)

            questions = [
                {
                    'type': 'checkbox',
                    'name': 'dll',
                    'message': '[*] Select the libraries you would like to add to your malware : ',
                    'choices': libraries[:20]
                }
            ]

            answers = prompt(questions)
            #print(answers["dll"])

            # bytez = imports_append(bytez, libname[lib_number], import_functions)
            for lib in answers["dll"]:
                bytez = imports_append(bytez, lib, import_functions, output_dir)



        elif(action_number == 3):
            bytez = section_add(bytez, section_names, section_content, output_dir)

        elif(action_number == 4):
            bytez = section_rename(bytez, section_names)

        elif(action_number == 5):
            bytez = remove_signature(bytez)

        elif(action_number == 6):
            bytez = remove_debug(bytez)

        elif(action_number == 7):
            with open(os.path.join(output_dir,"modified.exe"), 'wb') as file1:
                file1.write(bytez)
            
            print("\n[*] Mutated file has been written to : " + str(os.path.join(output_dir,"modified.exe")))
            exit(1)

    pass


def show_malware(malware_folder: str):

    files = [f for f in os.listdir(malware_folder) if os.path.isfile(os.path.join(malware_folder, f))]

    questions = [
        {
            'type': 'list',
            'name': 'malware',
            'message': '[*] Select the malware you wish to mutate : ',
            'choices': files[:20]
        }
    ]

    answers = prompt(questions)

    return answers["malware"]


def __binary_to_bytez(binary, dos_stub=False, imports=False, overlay=False, relocations=False, resources=False, tls=False):
    # write the file back as bytez
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(dos_stub)  # rebuild DOS stub

    builder.build_imports(imports)  # rebuild IAT in another section
    # patch original import table with trampolines to new import table
    builder.patch_imports(imports)

    builder.build_overlay(overlay)  # rebuild overlay
    # rebuild relocation table in another section
    builder.build_relocations(relocations)
    builder.build_resources(resources)  # rebuild resources in another section
    builder.build_tls(tls)  # rebuilt TLS object in another section

    builder.build()  # perform the build process

    # return bytestring
    return array.array('B', builder.get_build()).tobytes()


def overlay_append(bytez):
    random.seed(1234565789)
    L = __random_length()
    # choose the upper bound for a uniform distribution in [0,upper]
    upper = random.randrange(256)
    # upper chooses the upper bound on uniform distribution:
    # upper=0 would append with all 0s
    # upper=126 would append with "printable ascii"
    # upper=255 would append with any character
    return bytez + bytes([random.randint(0, upper) for _ in range(L)])


def imports_append(bytez, libname, import_functions, output_dir):
    #COMMON_IMPORTS_NAMES = ['ADVAPI32.DLL', 'SHLWAPI.DLL', 'KERNEL32.DLL','USER32.DLL']

    importsFile = open(str(Path("manipulation_content/imports.txt")), 'w')

    importsFile.write(libname + '\n')
    for fun in (list(import_functions[libname])):
        importsFile.write(fun + '\n')

    #print('adding import library : ' + libname)
    with open(os.path.join(output_dir, "modified.exe"), 'wb') as file1:
        file1.write(bytez)

    importsFile.close()

    cmd = "./portable-executable/project-add-imports/bin/Debug/project-append-import" + " " +  str(os.path.join(output_dir,"modified.exe")) + " " + str(Path("manipulation_content/imports.txt")) + " " + str(os.path.join(output_dir,"modified.exe")) + " >/dev/null 2>&1"
    os.system(cmd)

    with open(os.path.join(output_dir,"modified.exe"), "rb") as binfile:
        bytez = binfile.read()

    return bytez


def section_add(bytez, section_names, section_content, output_dir):
    # section = random.choice(section_names)

    section_list = []
    for section in section_names:
        logging.info("\t\t\t\t--> Section : " + str(section))
        dict = {
            'name': section
        }
        section_list.append(dict)

    questions = [
        {
            'type': 'checkbox',
            'name': 'section',
            'message': '[*] Select a section to add : ',
            'choices': section_list[:20]
        }
    ]

    answers = prompt(questions)

    with open(os.path.join(output_dir, "modified.exe"), 'wb') as file1:
        file1.write(bytez)

    for section in answers["section"]:
        #cmd = "./portable-executable/project-add-sections/bin/Debug/project-append-section" + " " + str(os.path.join(output_dir, "modified.exe")) + " " + section + " " + section_content + " " + str(os.path.join(output_dir, "modified.exe"))
        # cmd = "./portable-executable/project-add-sections/bin/Debug/project-append-section " + str(os.path.join(output_dir, "modified.exe")) + " " + ".text" + " " + section_content + " " +  str(os.path.join(output_dir, "modified.exe"))
        cmd = "./portable-executable/project-add-sections/bin/Debug/project-append-section Manually_Mutated_Binaries/modified.exe " + section + " manipulation_content/section-content.txt Manually_Mutated_Binaries/modified.exe >/dev/null 2>&1"
        print(cmd)
        os.system(cmd)
        print('\t[+] adding section : ' + section)

    with open(os.path.join(output_dir, "modified.exe"), "rb") as binfile:
        bytez = binfile.read()

    return bytez


def section_rename(bytez, section_names):
    # rename a random section
    # random.seed(seed)
    binary = lief.PE.parse(bytez, name="")

    questions = [
        {
            'type': 'confirm',
            'name': 'section_rename',
            'message': '[*] Would you like to enter your own section name? : ',
            'default': True,
        },
        
    ]

    answers = prompt(questions)
    section_answer = []

    if answers["section_rename"]:
        questions = [
            {
                'type': 'input',
                'name': 'new_name',
                'message': '[*] Enter a new section name: ',
                'validate': lambda val: len(val) < 8 or 'Please entere a scetion name less than 8 characters'
            }
        ]

        answers_section = prompt(questions)
        
    else:
        questions = [
            {
                'type': 'list',
                'name': 'new_name',
                'message': '[*] Select a section to add : ',
                'choices': section_names[:20]
            }
        ]

        answers_section = prompt(questions)

    targeted_section = random.choice(binary.sections)
    targeted_section.name = answers_section["new_name"]

    bytez = __binary_to_bytez(binary)

    return bytez


def remove_signature(bytez):
    binary = lief.PE.parse(bytez, name="")

    if binary.has_signature:
        for i, e in enumerate(binary.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
                break
        if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0
            bytez = __binary_to_bytez(binary)
            return bytez
    # if no signature found, self.bytez is unmodified
    return bytez


def add_signature(bytez, output_dir):
    with open(os.path.join(output_dir, "modified.exe"), 'wb') as file1:
        file1.write(bytez)

    cmd = "echo 123456 | signcode -spc ~/authenticode.spc -v ~/authenticode.pvk -a sha1 -$ commercial -n putty.exe -i http://www.ms.com/ -t http://timestamp.verisign.com/scripts/timstamp.dll -tr 10 " + str(os.path.join(output_dir, "modified.exe"))
    os.system(cmd)

    with open(os.path.join(output_dir, "modified.exe"), "rb") as binfile:
        bytez = binfile.read()

    return bytez


def edit_tls(bytez, output_dir):
    with open(os.path.join(output_dir, "modified.exe"), 'wb') as file1:
        file1.write(bytez)

    cmd = './portable-executable/test-other/bin/edit-tls/test-other ' + os.path.join(output_dir, "modified.exe")
    os.system(cmd)

    with open(os.path.join(output_dir, "modified.exe"), "rb") as binfile:
        bytez = binfile.read()

    return bytez


def load_config_dir(bytez, output_dir):
    with open(os.path.join(output_dir, "modified.exe"), 'wb') as file1:
        file1.write(bytez)

    cmd = './portable-executable/test-other/bin/load-config-dir/test-other ' + os.path.join(output_dir, "modified.exe")
    os.system(cmd)

    with open(os.path.join(output_dir, "modified.exe"), "rb") as binfile:
        bytez = binfile.read()

    return bytez


def remove_debug(bytez):
    binary = lief.PE.parse(bytez, name="")

    if binary.has_debug:
        for i, e in enumerate(binary.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                break
        if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0
            bytez = __binary_to_bytez(binary)
            return bytez
    # if no signature found, self.bytez is unmodified
    return bytez


def __random_length():
    return 2**random.randint(5, 8)


def main():
    args = parse_args()

    logging_setup(args.detailed_log, args.logfile, args.log_level)

    os.system("clear")

    # Testing the figlet
    f = Figlet(font='poison')
    print(f.renderText('PE-RSON'))
    
    output_dir = os.path.join("Mutated_Binaries", args.output_dir)
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
        logging.info("Creating output directory ... at " + str(output_dir))

    print("[*] Setting parameters ...")
    print("\t[+] - Path to Malware files - " + str(args.malware_path))
    print("\t[+] - Path to Section Name - " + str(args.section_name))
    print("\t[+] - Path to Section Content - " +
                 str(args.section_content))
    print("\t[+] - Path to Import Functions - " + str(args.add_imports))
    print("\t[+] - Output Directory - " + str(output_dir))
    print("\t[+] - Logfile - " + str(args.logfile))
    print("\t[+] - Log Level - " + str(args.log_level))
    print("\t[+] - Detailed Log - " + str(args.detailed_log))

    module_path = os.path.split(os.path.abspath(
        sys.modules[__name__].__file__))[0]


    section_names = pickle.load(
        open(os.path.join(module_path, args.section_name), "rb"))
    import_functions = pickle.load(
        open(os.path.join(module_path, args.add_imports), "rb"))
    section_content = args.section_content

    logging.info("\t\t\t--> Section Names : " + str(section_names))

    file = show_malware(str(args.malware_path))
    while(True):
        show_options(args.malware_path, file, section_names, import_functions, str(section_content), str(args.output_dir))

    pass


if __name__ == "__main__":
    main()
