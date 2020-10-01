
![Logo](https://github.com/CyberForce/Pesidious/blob/master/pesidoius%20logo.png)

# Malware Mutation using Deep Reinforcement Learning and GANs 

The purpose of the tool is to use artificial intelligence to mutate a malware sample to bypass AI powered classifiers while keeping its functionality intact. In the past, notable work has been done in this domain with researchers either looking at reinforcement learning or generative adversarial networks as their weapons of choice to modify the states of a malware executable in order to deceive anti-virus agents. Our solution makes use of a combination of deep reinforcement learning and GANs in order to overcome some of the limitations faced while using these approaches independently as showen below.


![Diagram](https://github.com/CyberForce/Pesidious/blob/master/Pesidious%20architecture%20(simplified).png)

Find our full documentation for the tool installation [here](https://vaya97chandni.gitbook.io/pesidious/) 


## Table of Content


+ [Overview](#overview)
+ [Installation Instructions](#installation-instructions)
+ [Getting Training Data](#getting-training-data)
+ [Running Instructions](#running-instructions) 
+ [Known Issues and Fixes](#known-issues-and-fixes)
+ [Built With](#built-with)
+ [Authors](#authors)
+ [Acknowledgments](#acknowledgments)
+ [References](#references)


## Overview

Pesidious is an open-source tool that uses Generative Adversarial Networks (GAN) and Reinforcement Learning (RL) to generate mutative malware that can evade nextgen AI-powered anti-virus scanners. 


## Installation Instructions

> :warning: Since this tool deals with malware files, it is strongly recommended to use a virtual machine. After installation of the tool, make sure to disconnect from the network.


The following steps will guide you through all the installations required to set up the environment.

1. [Install and set up Python 3.6.](https://realpython.com/installing-python/)

1. Clone the repository. 
    ```sh
    git clone https://github.com/CyberForce/Pesidious
    ```
1. Move into the project directory. 

    ```sh
    cd Pesidious
    ```

1. [Set up and activate a virtual environment with Python 3.6](https://docs.python.org/3/tutorial/venv.html)
    > :information: It is recommended to use a virtual environment to avoid conflicts between packages used by different applications


1. Make sure that you have pip 8.1.1 installed and set up.
   > This is due to later versions of pip not playing well with the PyTorch libary. 

   ```sh
   pip install pip==8.1.1
   ```
    
1. Install all the required libraries, by installing the requirements.txt file.

    ```sh
    pip install -r pip_requirements\requirements.txt
    ```
     
<!-- 1. Download malware and benign binary samples from [here](#training-and-testing-data). -->
 
## Getting Training Data

### Training Data

1. The GAN and RL trained models are already available in the tool. But if you want to train your own models, you will need your own malware and benign samples.
    + Malware samples can be downloaded from various sources. [VirusTotal](https://www.virustotal.com/gui/home)'s database of malicious samples is a good source. 
    + Benign samples can be scraped from a clean windows environment.

1. Create a folder to store the datasets.

   ```
   mkdir Data
   ```

1. Once you have downloaded the datasets, take care to place the files in the right directory in order to run the application with no errors. 

   1. Keep the downloaded folder `Data` in the root directory `Pesidious`. 
   
      ```
      Data/
       ├── benign
       │   ├── 1PasswordSetup-7.3.684.exe
       │   ├── 2to3.exe
       │   ├── 32BitMAPIBroker.exe       
       │   ├──    :
       │   ├──    :
       │   ├──    :
       │   |__ 7za.exe
       ├___malware
           ├── ffe96cd96a91fead84aee17d2c0617193ec183ddbf630b29eebbd1235e26227c
           ├── ffe5bcd034ceeca05f47ddb17f13b46188d5832668388e0badda7e8440f1730e
           ├── ffc0f4ed76db8ec2a050f2c36106387f473babf3c83c7c5b7c42706b3dac8782
           ├──    :
           ├──    :
           ├──    :
           |__ ff8f9699842bb44ef038ca7f675c9cc90ab8f00bc81564fa87f12d700e0040fb
      ```
      
   <!-- 1. Download the backdoor malware binary dataset [here](https://uowmailedu-my.sharepoint.com/:u:/g/personal/cvrv570_uowmail_edu_au/EXejpGJMibRAr0P35OnXmmUB5JX0fX33BSEN1CQQ_8fpDQ?e=8uTjPn) and place the **files** into the `gym_malware/envs/utils/samples` directory as illustrated below:
   
      ```
      gym_malware/
       ├── envs
       │   ├── controls
       │   ├──    :
       │   ├──    :
       │   ├──    :
       │   └── utils
       │       ├── gradient_boosting.pkl
       │       ├──    :
       │       ├──    :       
       │       ├──    :
       │       ├──    :
       │       ├──    :
       │       └── samples
       │           ├── e2ec96f7f0aacc20a0773142ce553585cf60804a8046c8164b0e9661c282869f
       │           ├── e2efec50227a549dadfe8dfcfed74b8c5d8857c431479e9891232fb568b038b9
       │           ├── e2f24c60448f81be8dc7ee5a6457327976483f9ab96ab8925da5ef6df3808c42
       │           ├── e3045dc6d4c2bbd682ddbe06b8952ae1341ad9521aff44136bab9f1e876a8248
       │           ├── e3059a70215078415b7d61b52bf6056a9575176197b7a16809b396ab4d43743b
       │           ├── e30ac19107ad669a13a151b3be16cf2cc735e0c18aa8b6d096e1c88411f6a21a
       │           ├── e30c91a7c37687e5e8305e0b8936ad84d0710ecca9cba7e0d6e07c963f6f9fdb
       │           ├── e3107121e6e515f84597b1e65bd92516327c5fffa9e80068b0e1c60d596568a1
      ``` -->
 
## Running Instructions

### Training Instructions


> Note: If you wish to skip the training and jump directly to testing our trained model [click here](#testing-instructions)

1. Feature extraction and feature mapping vector generation.

   + The first step in the training process is generating a feature vector mapping for section names and import functions from a    malware and benign binary samples.  

      ```sh
      python extract_features.py
      
      python extract_features.py --help
      ```
      > For more debugging information, view the log files generated in `Logs\extract_features_logs.log`.
    
   + The `extract_features.py` python script outputs the following files in the output directory:
      + **Features Vector Mapping** - _feature_vector_mapping.pk_, _import_feature_vector_mapping.pk_ and _section_feature_vector_mapping.pk_
      + **Malware Feature Vectors** - _malware-feature-set.pk_, _malware-pe-files-import-feature-set.pk_ and _malware-pe-files-section-feature-set.pk_
      + **Benign Feature Vectors** - _benign-feature-set.pk_, _benign-pe-files-import-feature-set.pk_ and _benign-pe-files-section-feature-set.pk_

1. Malware feature vector mutation using Generative Adversarial Networks. 

   + Once the feature mapping vector and the feature vectors for both the malware and benign binary samples have been generated, we can feed these feature vectors to a MalGAN model to generate adversarial feature vectors which appear to be benign. 
   
      ```sh
      python main_malgan.py
      
      python main_malgan.py --help 
      ```
      > For more information, [see below](#acknowledgments).
      
      > For more debugging information, view the log files generated in `Logs\"malGAN.log`.
   
   + You can train the MalGAN on either section features, import features or both by using the `--feature-type` flag. 
      > For example, to train the MalGAN for just sections using `--feature-type section`.
     
   + The `main_malgan.py` python script outputs the `adversarial_feature_array_set.pk` in the `adversarial_feature_vector_directory` directory.
   
   
<!-- 1. Binary Imports and Section Reconstruction.

   + Once we have the adversarial feature vector from the MalGAN, we can feed it the `binary_builder.py` python script which uses the original feature mapping vector from step 1 to map the adversarial features back to the import functions and section names. 
   
      ```sh
      python binary_builder.py
      
      python binary_builder.py --help
      ```
      > For more debugging information, view the log files generated in `Logs\"binary_builder_logs.log`.
   
   + Make sure to use the right feature vector mapping for the type of adversarial feature vector you have generated by using the `--feature-vector` optional argument. By default it will use the `feature_vector_mapping.pk` mapping. 
   
      > For example: If you have generated a adversarial feature vector of only the sections, make sure to add the command `--feature-vector section` to correctly reconstruct the section name.
   
   + The `binary_builder.py` python script outputs the `adversarial_imports_set.pk` or the `adversarial_section_set.pk`, based on the feature mapping you select, in the `adversarial_feature_vector_directory` directory.  -->
   
1. Training RL agent.

   + The RL agent will use deep learning to learn the most optimal policy that can generate the best combination of mutations for the malware. The following mutations are being used for the training : 
   
      > Appending random number of bytes to malware, Adding Imports, Adding Sections, Renaming sections, Appending to sections, UPX Pack/Unpack, Remove Debug Information.

   ```
   python rl_train.py
   ```
   

### Testing Instructions

The output from GAN has already been stored as (`gym_malware/envs/controls/adverarial_imports_set.pk` and `gym_malware/envs/controls/adverarial_sections_set.pk`) and is being used for the training. 

The training tests the learning agent after every 550 episodes with 200 samples. If the agent is able to generate 100 (50%) of mutated samples, the training stops and saves the model as `rl-model.pt` which is used by the testing script.


#### Execution

1. Run the `mutate.py` python script to mutate your malware samples. 

   ```
   python mutate.py -d /path/to/directory/with/malware/files
   ```

1. The mutated malware files will be stored in a directory called Mutated_malware in the following format

    ```
    Mutated_malware/mutated_<name-of-the-file>
    ```


## Known Issues and Fixes

> :warning: WARNING: This segment is currently under construction. We apologize for any inconvinience caused. Please proceed to the next section. [click here](#to-do)

1. `pip install -r requirements.txt` gives you an error.

   Solution:
    
      ```
      pip install tqdm
      pip install sklearn
      pip install lief
      ```
   
1. **ModuleNotFoundError: No module named 'tensorboardX'** error while running `python main_malgan.py` script.
      
   Solution:
      
      ```
      pip install tensorboardX
      ```
   
1. **Error with the execution of edit-tls, import-append, section-append or load-config-dir (not found)**
     
     Solution
     Give execute permission to these executables using the following commands on your terminal
     
     ```
     cd portable-executable/
     chmod 777 test-other/bin/load-config-dir/test-other
     chmod 777 test-other/bin/edit-tls/test-other
     chmod 777 project-add-sections/bin/Debug/project-append-section
     chmod 777 project-add-imports/bin/Debug/project-append-imports
     
     ```

## Built With

* [PyTorch](https://pytorch.org/) -  Open source machine learning library based on the Torch library.
* [Lief](https://github.com/lief-project/LIEF) - A cross platform library which can parse, modify and abstract ELF, PE and MachO formats.
* [PE Bliss](https://github.com/BackupGGCode/portable-executable-library) - PE libarry for rebuilding PE files, written in C++.
* [Gym-Malware](https://github.com/endgameinc/gym-malware/) - Malware manipulation environment for OpenAI's gym.
* [MalwareGAN](https://github.com/ZaydH/MalwareGAN) - Adversarial Malware Generation Using GANs.


## Authors

* **Chandni Vaya** - *X-Force Incident Response, IBM Security* - [Github](https://github.com/Chandni97)
* **Bedang Sen** - *X-Force Incident Response, IBM Security* - [Github](http://github.com/bedangSen/)

## Acknowledgments

* The gym-malware environment (https://github.com/endgameinc/gym-malware) was modified to extract only 518 out of 2350 features for the training of the agent i.e. byte histogram normalized to sum to unity and two-dimensional entropy histogram. Additionaly only 4 actions are used for the mutation i.e. append random bytes, append import, append section and remove signature.

* Gym-Malware Environment : https://github.com/endgameinc/gym-malware <br>
Deep Reinforcement Learning : https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8676031

* Yanming Lai's ([here])(https://github.com/yanminglai/Malware-GAN) and Zayd Hammoudeh's ([here])(https://github.com/ZaydH/MalwareGAN) work on implementation on Han and Tan's MalGAN played a crucial role in our understanding of the architecture. A mojority of the implementation of the MalGAN used in this project has been forked off Hammoudeh's work. 

## References

Anderson, H., Kharkar, A., Filar, B., Evans, D. and Roth, P. (2018). Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning. [online] arXiv.org. Available at: https://arxiv.org/abs/1801.08917.

Docs.microsoft.com. (n.d.). PE Format - Windows applications. [online] Available at: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts.

Fang, Z., Wang, J., Li, B., Wu, S., Zhou, Y. and Huang, H. (2019). Evading Anti-Malware Engines With Deep Reinforcement Learning. [online] Ieeexplore.ieee.org. Available at: https://ieeexplore.ieee.org/abstract/document/8676031 [Accessed 25 Aug. 2019].
https://resources.infosecinstitute.com. (2019). 

Malware Researcher’s Handbook (Demystifying PE File). [online] Available at: https://resources.infosecinstitute.com/2-malware-researchers-handbook-demystifying-pe-file/#gref.

Hu, W. and Tan, Y. (2018). Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN. [online] arXiv.org. Available at: https://arxiv.org/abs/1702.05983.
