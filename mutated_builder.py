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

from keras.models import load_model

ACTION_LOOKUP = {i: act for i, act in enumerate(manipulate.ACTION_TABLE.keys())}

from chainrl import create_acer_agent
import gym
module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]



COMMON_SECTION_NAMES = pickle.load(open(os.path.join(module_path, 'RL_Features/adversarial_sections_set1.pk'), "rb"))
COMMON_IMPORTS = pickle.load(open(os.path.join(module_path, 'RL_Features/adversarial_imports_set1.pk'), "rb"))
section_content = "manipulation_content/section-content.txt"

min_score = 100.0

outputFile = open("rl_out.txt", "w")

def get_latest_model_from(basedir):
    dirs = os.listdir(basedir)
    lastmodel = -1
    for d in dirs:
        try:
            if int(d) > lastmodel:
                lastmodel = int(d)
        except ValueError:
            continue

    assert lastmodel >= 0, "No saved models!"
    return os.path.join(basedir, str(lastmodel))

def show_output(line):
    # outputFile.write("\t|\n" )
    # outputFile.write("\t|\n" )
    # outputFile.write("\t--" )
    # outputFile.write(line)
    # outputFile.write("\n")

    print(line)
    print("\n")


def evaluate( action_function, pefolder, pefile , show):
    global min_score
    print("min score : " + str(min_score))
    with open("actions.txt" , "r") as a:
        actions = a.readlines()

    print(actions)

    with open(join(pefolder, pefile), "rb") as binfile:
        bytez = binfile.read()

    label = interface.get_label_local(bytez)

    if label == 0.0:
        with open("Mutated_malware/" + str(pefile) + "_RLA", 'wb') as file1:
            file1.write(bytez)
        return

    for j in range(160):
        action = action_function( bytez )
        print(action)
       
        if(action == "overlay_append"):
            bytez = overlay_append(bytez, show)
            


        elif(action == "section_rename"):
            bytez = section_rename(bytez, show)
        

        elif(action == "add_signature"):
            pass
            #print("not adding signature")

        elif(action == "edit_tls"):
            bytez = edit_tls(bytez)

        elif(action == "load_config_dir"):
            bytez = load_config_dir(bytez)

        elif(action == "section_add"):
            bytez = section_add(bytez, show)

        elif(action == "imports_append"):
            bytez = imports_append(bytez, show)

        elif(action == "remove_signature"):
            bytez = remove_signature(bytez, show)

        elif(action == "remove_debug"):
            bytez = remove_debug(bytez, show)

        #bytez = manipulate.modify_without_breaking( bytez, [action] )
        new_label = interface.get_label_local( bytez )

        if new_label == 0.0:
            score = interface.get_score_local(bytez)
            if(score < min_score):
                min_score = score
                with open("Mutated_malware/" + str(pefile) + "_RLA", 'wb') as file1:
                    file1.write(bytez)
                return

    score = interface.get_score_local(bytez)
    if(score < min_score):
        min_score = score
        with open("Mutated_malware/" + str(pefile) + "_RLA", 'wb') as file1:
            file1.write(bytez)

def add_imports(pefile, importfile, cpath, outfile):
    cmd = './' + cpath + ' ' + pefile + ' ' + importfile + ' ' + outfile
    os.system(cmd)

def add_sections(section_app: str, pefile: str, section_file: str, section_content: str, outfile:str):
    cmd = './' + section_app + ' ' + pefile + ' ' + section_file + ' ' + section_content + ' ' + outfile
    os.system(cmd)

def run_rl(pefolder, pefile, show):
    ENV_NAME = 'malware-test-v0' 
    env = gym.make(ENV_NAME)
    fe = pefeatures2.PEFeatureExtractor2()
    def agent_policy(agent):
        def f(bytez):
            feats = fe.extract( bytez )
            action_index = agent.act( feats ) 
            return ACTION_LOOKUP[ action_index ]
        return f
    agent_score = create_acer_agent(env)
    # pull latest stored model
    last_model_dir = get_latest_model_from('models/acer_score_chainer')
    agent_score.load( last_model_dir )
    evaluate( agent_policy(agent_score), pefolder, pefile, show )



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


def overlay_append(bytez, show):
    L = __random_length()
    # choose the upper bound for a uniform distribution in [0,upper]
    upper = random.randrange(256)
    # upper chooses the upper bound on uniform distribution:
    # upper=0 would append with all 0s
    # upper=126 would append with "printable ascii"
    # upper=255 would append with any character
    if(show):
        show_output("Appended random bytes")
    return bytez + bytes([random.randint(0, upper) for _ in range(L)])

def imports_append(bytez, show):
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

    cmd = " ./portable-executable/project-add-imports/bin/Debug/project-append-import modified.exe imports.txt modified.exe >/dev/null 2>&1"
    os.system(cmd)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    if(show):
        show_output("Added functions from a DLL ")

    return bytez

def section_add(bytez, show):    
    section = random.choice(COMMON_SECTION_NAMES)
    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    cmd = "./portable-executable/project-add-sections/bin/Debug/project-append-section modified.exe " + section + " " + section_content + " modified.exe >/dev/null 2>&1"
    os.system(cmd)

    #print('adding section : ' + section)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    if(show):
        show_output("Added a section")

    return bytez

def section_rename(bytez, show):
    # rename a random section
    #random.seed(seed)
    binary = lief.PE.parse(bytez, name="")
    for i in range(0, 10):   
        targeted_section = random.choice(binary.sections)
        targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7] # current version of lief not allowing 8 chars?

    bytez = __binary_to_bytez(binary)

    if(show):
        show_output("Renamed a section")

    return bytez


def remove_signature(bytez, show):
    binary = lief.PE.parse(bytez, name="")
    if(show):
        show_output("Removed signature")

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

def add_signature(bytez):
    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    cmd = "echo 123456 | signcode -spc ~/authenticode.spc -v ~/authenticode.pvk -a sha1 -$ commercial -n putty.exe -i http://www.ms.com/ -t http://timestamp.verisign.com/scripts/timstamp.dll -tr 10 modified.exe"
    os.system(cmd)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    return bytez

def edit_tls(bytez):
    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    cmd = './portable-executable/test-other/bin/edit-tls/test-other modified.exe >/dev/null 2>&1' 
    os.system(cmd)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    return bytez

def load_config_dir(bytez):
    with open("modified.exe", 'wb') as file1:
        file1.write(bytez)

    cmd = './portable-executable/test-other/bin/load-config-dir/test-other modified.exe >/dev/null 2>&1'
    os.system(cmd)

    with open("modified.exe", "rb") as binfile:
        bytez = binfile.read()

    return bytez


def remove_debug(bytez, show):
    binary = lief.PE.parse(bytez, name="")
    if(show):
        show_output("Removed Debug Flag")

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

def virus_total_url(file):
    print(file)
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': 'bbd8c5dc4df8a8dc4d4c0cd3d9ec38b96471ab711bb71c2e608d45d6430fc328'}
    files = {'file': ('myfile.exe', open(file, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()["permalink"]

if __name__ == "__main__":

    pefolder = sys.argv[1]
    #imports = "RL_Features/all_features/imports/imports"
    #sections = "RL_Features/all_features/sections/sections"

    importApp = "portable-executable/project-add-imports/bin/Debug/project-append-import"
    sectionApp = "portable-executable/project-add-sections/bin/Debug/project-append-section"

    #importsFiles = [f for f in listdir(imports) if isfile(join(imports, f))]
    #sectionsFiles = [f for f in listdir(sections) if isfile(join(sections, f))]
    pefiles = [f for f in listdir(pefolder) if isfile(join(pefolder, f))]

    sectionContent = "manipulation_content/section-content.txt"
    #importsFiles.sort()
    #sectionsFiles.sort()
    #print(importsFiles)
    #print(sectionsFiles)
    filenum = 0



    for pefile in pefiles:
        print("file number : " + str(filenum))
        filenum = filenum + 1
        min_score = 100.0
        malware = 0

        run_rl(pefolder, pefile, True)

        for i in range(0, 3):

            # if(i == 0):
            #     print("Extracting Features .....\n")
            # elif(i==1):
            #     print("Generating Adversarial Features .....\n")
            # else:
            #     print("Running RL Agent .....\n")

            # if(i == 2):
            print("turn : " + str(i))
            run_rl(pefolder, pefile, True)
            # else:
            #     run_rl(pefolder, pefile, False)

        # print("Uploading to VirusTotal .... \n")
        # original_url = virus_total_url(join(pefolder, pefile))
        # mutated_url = virus_total_url("Mutated_malware/" + str(pefile) + "_RLA")

        # print()
        # print(mutated_url)

        #     print("file numbr : " + str(importsFiles[i][:2]))
        #     add_imports(join(pefolder, pefile), join(imports, importsFiles[i]), importApp, "Mutated_malware/" + str(pefile) + "_GAN_" + str(importsFiles[i][:2]))
        #     add_sections(sectionApp, "Mutated_malware/" + str(pefile) + "_GAN_" + str(importsFiles[i][:2]), join(sections, sectionsFiles[i]), sectionContent ,"Mutated_malware/" + str(pefile) + "_GAN_" + str(importsFiles[i][:2]))
        #     malware = malware + 1


