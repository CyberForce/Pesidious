
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
    > It is recommended to use a virtual environment to avoid conflicts between packages used by different applications


1. Make sure that you have pip 8.1.1 installed and set up.
   > This is due to later versions of pip not playing well with the PyTorch libary. 

   ```sh
   pip install pip==8.1.1
   ```
    
1. Install all the required libraries, by installing the requirements.txt file.

    ```sh
    pip install -r pip_requirements\requirements.txt
    ```

### Mutate Your Malware

The output from GAN has already been stored as (`RL_Features/adverarial_imports_set.pk` and `RL_Features/adverarial_sections_set.pk`) which will be used for when adding imports and sections to the malware for mutation. 

1. You can test the sample classifier to score malware files.

    ```
    python classifier.py -d /path/to/directory/with/malware/files
    ```

1. Run the `mutate.py` python script to mutate your malware samples. 

   ```
   python mutate.py -d /path/to/directory/with/malware/files
   ```

1. The mutated malware files will be stored in a directory called Mutated_malware in the following format

    ```
    Mutated_malware/mutated_<name-of-the-file>
    ```
    
1. Once the malware files are mutated, you can run the classifier again to score the mutated malware.
    
    ```
    python classifier.py -d Mutated_malware/
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
   
1. **Error with the execution of import-append, section-append (not found)**
     
     Solution
     Give execute permission to these executables using the following commands on your terminal
     
     ```
     cd portable-executable/
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
