# def warn(*args, **kwargs):
#     pass

# import warnings
# warnings.warn = warn
# warnings.filterwarnings("ignore")




import sys

import lief  # pip install https://github.com/lief-project/LIEF/releases/download/0.7.0/linux_lief-0.7.0_py3.6.tar.gz
import json

import array
import struct  # byte manipulations
import random
import tempfile
import subprocess
import time
import functools
import signal
import multiprocessing

import pefile
import hashlib
import os
from pathlib import Path
from os import listdir
from os.path import isfile, join
import numpy as np
from gym_malware.envs.utils import interface, pefeatures2
from gym_malware.envs.controls import manipulate2 as manipulate
import pickle
from gym_malware import sha256_train, sha256_holdout, MAXTURNS

import requests
import json
from collections import defaultdict

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]

#COMMON_SECTION_NAMES = pickle.load(open(os.path.join(module_path, 'RL_Features/adversarial_sections_set1.pk'), "rb"))
COMMON_SECTION_NAMES = open(os.path.join(module_path, 'section_names.txt'), 'r').read().rstrip().split('\n')
COMMON_IMPORTS = open(os.path.join(module_path, 'imports.txt'), 'r').read().rstrip().split('\n')
section_content = "manipulation_content/section-content.txt"

min_score = 100.0





def evaluate(pefile):
    
    
    with open(pefile, "rb") as binfile:
        bytez = binfile.read()

    previous_bytez = bytez

    for i in range(80):
        
        action = random.randint(1,5)

       
        if(action == 1):
            print("overlay_append")
            bytez = overlay_append(bytez)
        
        elif(action == 2):
            print("section_rename")
            bytez = section_rename(bytez)
    
        elif(action == 3):
            print("section_add")
            bytez = section_add(bytez)

        elif(action == 4):
            print("imports_append")
            bytez = imports_append(bytez)

        #bytez = manipulate.modify_without_breaking( bytez, [action] )
        # with open("mutated.exe", 'wb') as file1:
        #     file1.write(bytez)

        # score = virus_total_score("mutated.exe")

        # print("score : " + str(score))

        # if(score > previous_score):
        #     bytez = previous_bytez
        #     outputFile.write("Remove\n") # dont add the previous action

        # else:
        #     previous_score = score
        #     previous_bytez = bytez
        
        # if(score < 10):
        #     with open("Mutated_malware/queried.exe", 'wb') as file1:
        #         file1.write(bytez)
        #     exit(1)

        

   
def add_imports(pefile, importfile, cpath, outfile):
    cmd = './' + cpath + ' ' + pefile + ' ' + importfile + ' ' + outfile
    os.system(cmd)


def add_sections(section_app: str, pefile: str, section_file: str, section_content: str, outfile:str):
    cmd = './' + section_app + ' ' + pefile + ' ' + section_file + ' ' + section_content + ' ' + outfile
    os.system(cmd)


def __binary_to_bytez(binary, dos_stub=False, imports=False, overlay=False, relocations=False, resources=False, tls=False):
    # write the file back as bytez
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(dos_stub) # rebuild DOS stub

    builder.build_imports(imports) # rebuild IAT in another section
    builder.patch_imports(imports) # patch original import table with trampolines to new import table

    builder.build_overlay(overlay) # rebuild overlay
    builder.build_relocations(relocations) # rebuild relocation table in another section
    builder.build_resources(resources) # rebuild resources in another section
    builder.build_tls(tls) # rebuilt TLS object in another section

    builder.build() # perform the build process

    # return bytestring
    return array.array('B', builder.get_build()).tobytes()

def __random_length():
    return 2**random.randint(5, 8)


def overlay_append(bytez):
    L = __random_length()
    # choose the upper bound for a uniform distribution in [0,upper]
    upper = random.randrange(256)
    # upper chooses the upper bound on uniform distribution:
    # upper=0 would append with all 0s
    # upper=126 would append with "printable ascii"
    # upper=255 would append with any character
    print("appended random bytes\n")
    return bytez + bytes([random.randint(0, upper) for _ in range(L)])

def imports_append(bytez):
    #COMMON_IMPORTS_NAMES = ['ADVAPI32.DLL', 'SHLWAPI.DLL', 'KERNEL32.DLL','USER32.DLL']
    
    importsFile = open("imports.txt" , 'w')

    libname = random.choice(list(COMMON_IMPORTS))

    while("hal" in libname): 
        libname = random.choice(list(COMMON_IMPORTS))

    while(len(list(COMMON_IMPORTS[libname])) < 20 ):
        libname = random.choice(list(COMMON_IMPORTS))

    importsFile.write(libname + '\n')
    for fun in (list(COMMON_IMPORTS[libname])):
        importsFile.write(fun + '\n')
    #print('adding import library : ' + libname)

    importsFile.close()

    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    sys.stdout.flush()
    cmd = " ./portable-executable/project-add-imports/bin/Debug/project-append-import modified.exe imports.txt modified.exe"
    os.system(cmd)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    print("appended import : " + libname + "\n")

    return bytez

def section_add(bytez):    
    section = random.choice(COMMON_SECTION_NAMES)
    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    sys.stdout.flush()
    cmd = "./portable-executable/project-add-sections/bin/Debug/project-append-section modified.exe " + section + " " + section_content + " modified.exe"
    os.system(cmd)

    #print('adding section : ' + section)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()
    
    print("added section : " + section + "\n")  

    return bytez

def section_rename(bytez):
    # rename a random section
    #random.seed(seed)
    binary = lief.PE.parse(bytez)
    for i in range(0, 10):   
        targeted_section = random.choice(binary.sections)
        old_name = targeted_section.name
        targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7] # current version of lief not allowing 8 chars?

    bytez = __binary_to_bytez(binary)

    print("section renamed from " + old_name + " to " + targeted_section.name + "\n")

    return bytez


def remove_signature(bytez):
    binary = lief.PE.parse(bytez)

    print("removed signature \n")

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
    # if no signature found, bytez is unmodified
    return bytez

def remove_debug(bytez):
    binary = lief.PE.parse(bytez)

    print("removed debug \n" )

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
    # if no signature found, bytez is unmodified
    return bytez


def calculate_hash(bytez):
    m = hashlib.sha256()
    m.update( bytez )


if __name__ == "__main__":

    pefile = sys.argv[1]
    evaluate(pefile)
    