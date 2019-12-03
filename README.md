# Malware Mutation using Deep Reinforcement Learning and GANs 


The purpose of our project is to use artificial intelligence to mutate a malware sample to bypass anti-virus agents while keeping its functionality intact. In the past, notable work has been done in this domain with researchers either looking at reinforcement learning or generative adversarial networks as their weapons of choice to modify the states of a malware executable in order to deceive anti-virus agents. Our solution makes use of a combination of deep reinforcement learning and GANs in order to overcome some of the limitations faced while using these approaches independently.

Find our full documentation [here](https://docs.google.com/document/d/1WDYrzpCX6Mwkij3FSb7KGS-PKGtPhpxKtT-ywGrvi6w/edit?usp=sharing) 


## Table of Content


+ [Overview](#overview)
+ [Installation Instructions](#installation-instructions)
+ [Training and Testing Data](#training-and-testing-data)
+ [Running Instructions](#running-instructions) 
+ [Testing Procedures and results](#testing-procedures-and-results)
+ [Known Issues and Fixes](#known-issues-and-fixes)
+ [Future Additions](#to-do)
+ [Built With](#built-with)
+ [Authors](#authors)
+ [Acknowledgments](#acknowledgments)
+ [References](#references)



## Overview


The proposed solution successfully generates a mutated malware sample by using reinforcement learning to decide on the sequence of modifications to make. In case the modifications chosen by the RL agent is either adding import functions or adding/renaming section names, GANs are used to generate an adversarial feature vector of imports and sections that perturb a malware to appear benign in contrast to randomly selecting the imports and sections. 

<p align="center">
 <img src="https://i.imgur.com/ew95L8R.png" align="middle">
</p>


## Installation Instructions

> :warning: This has been tested on Linux devices only. Windows users may run into minor setup issues. Use Caution. 

The following steps will guide you through all the installations required to set up the environment.

1. Install and set up Python 3.6. [Installation Instructions](https://realpython.com/installing-python/)

1. Clone the repository. 
    ```sh
    git clone https://github.com/hitb-aichallenge/tAIchi.git
    ```
1. Move into the project directory. 

    ```sh
    cd tAIchi
    ```
    
1. Download malware and benign binary samples from [here](#training-and-testing-data).

 
1. Setting up a virtual environment in Python 3.6:

   1. Downloading and installing _virtualenv_. 
   
      ```sh
      pip install virtualenv
      ```
   
   1. Create the virtual environment in Python 3.6. Refer to this documumentation for more info [here](https://docs.python.org/3/tutorial/venv.html)
   
      ```sh
       virtualenv -p path\to\your\python.exe test_env
       ```    
       >Note: In Windows, your Python3.6 environment is most likely to be in the following directory: `C:\Python36\Python.exe`.
   
   1. Activate the test environment.     
   
        1. For Windows:
        ```sh
        test_env\Scripts\Activate
        ```        
        
        2. For Unix:
        ```sh
        source test_env/bin/activate
        ```    
   1. Test out the version of your virtualenv environment to confirm it is in Python3.6.     
           
      ```sh
      python --version
      ```    
1. Make sure that you have pip 8.1.1 installed and set up.
   > This is due to later versions of pip not playing well with the PyTorch libary. 

   ```sh
   pip install pip==8.1.1
   ```
   
1. Install PyTorch.

   ```
   pip install torch==1.1.0
   ```   
   > If you face any issues, refer to the official PyTorch link in order to download the torch library appropriate for you [here](https://pytorch.org/get-started/locally/).
   
   > :warning: Caution: torch 1.2.0 is not yet compatible with lief. So be sure to use a version below that. 

1. Install all the required libraries, by installing the requirements.txt file.

    ```sh
    pip install -r requirements.txt
    ```
     
 
## Training and Testing Data

### Training Data
1. In order to train the Generative Adversarial Network and Reinforcement Learning agents, a large dataset of malicious and benign binaries are required. For that purpose we are sharing the dataset that we have collected.

   + **1682 Benign binaries** - _Scraped from our host computers_.
   + **2094 Malware binaries** - _Downloaded from VirusTotal_.

1. Downaload the training dataset from [here](https://uowmailedu-my.sharepoint.com/:f:/g/personal/cvrv570_uowmail_edu_au/Ep8qkEt-XvFCiOBbQS9FynQBQh6gULH1RpoA9Wdlh8xn_A?e=VdjH1D)

1. Create a folder to store the datasets.

   ```
   mkdir Data
   ```

1. Once you have downloaded the datasets, take care to place the files in the right directory in order to run the application with no errors. 

   1. Keep the downloaded folder `Data` in the root directory `tAIchi`. 
   
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
      
   1. Download the backdoor malware binary dataset [here](https://uowmailedu-my.sharepoint.com/:u:/g/personal/cvrv570_uowmail_edu_au/EXejpGJMibRAr0P35OnXmmUB5JX0fX33BSEN1CQQ_8fpDQ?e=8uTjPn) and place the **files** into the `gym_malware/envs/utils/samples` directory as illustrated below:
   
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
      ```
   
### Testing Data

Download the malware binary testing dataset [here](https://uowmailedu-my.sharepoint.com/:u:/g/personal/cvrv570_uowmail_edu_au/Eba11TVqORhCigT0Mg_hS4IBw2B7PK2eRJWwqmqm9wR1LA?e=STnjmA) and place the **files** into the `testing-samples` directory.

 
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
   
   
1. Binary Imports and Section Reconstruction.

   + Once we have the adversarial feature vector from the MalGAN, we can feed it the `binary_builder.py` python script which uses the original feature mapping vector from step 1 to map the adversarial features back to the import functions and section names. 
   
      ```sh
      python binary_builder.py
      
      python binary_builder.py --help
      ```
      > For more debugging information, view the log files generated in `Logs\"binary_builder_logs.log`.
   
   + Make sure to use the right feature vector mapping for the type of adversarial feature vector you have generated by using the `--feature-vector` optional argument. By default it will use the `feature_vector_mapping.pk` mapping. 
   
      > For example: If you have generated a adversarial feature vector of only the sections, make sure to add the command `--feature-vector section` to correctly reconstruct the section name.
   
   + The `binary_builder.py` python script outputs the `adversarial_imports_set.pk` or the `adversarial_section_set.pk`, based on the feature mapping you select, in the `adversarial_feature_vector_directory` directory. 
   
1. Training RL agent.

   + The RL agent will use deep learning to learn the most optimal policy that can generate the best combination of mutations for the malware. The following mutations are being used for the training : 
   
      > Appending random number of bytes to malware, Adding Imports, Adding Sections, Renaming sections, Appending to sections, UPX Pack/Unpack, Remove Debug Information.

   ```
   python dqeaf.py
   ```
   

### Testing Instructions

The output from GAN has already been stored as (`gym_malware/envs/controls/adverarial_imports_set.pk` and `gym_malware/envs/controls/adverarial_sections_set.pk`) and is being used for the training. 

The training tests the learning agent after every 550 episodes with 200 samples. If the agent is able to generate 100 (50%) of mutated samples, the training stops and saves the model as dqeaf.pt which is used by the testing script.


#### Execution

1. Create a new directory `testing-samples` and copy your test samples into it. 


1. Run the `dqeaf-test.py` python script to mutate malware samples you loaded in `testing-samples` earlier. 

   ```
   python dqeaf-test.py testing-samples
   ```

1. The mutated malware samples will be stored in the `evaded-samples` directory.



## Testing Procedures and Results



##### Results comparing the number of functional mutations generated when trained with different thresholds for detection and maximum mutations allowed (Testing Data : 250 samples)


| Threshold for detection    | Maximum mutations allowed | Mutations Generated | Functional Mutation | Average VirusTotal Score |
|----------------------------|---------------------------|---------------------|---------------------|--------------------------|
|             90%            |             80            |         140         |         114         |           40/69          |
|             85%            |            120            |         115         |          62         |           29/69          |
|             80%            |            160            |          94         |          24         |           11/69          |

##### Results comparing the impact blackbox detector algorithm and activation function have on the TPR of the adversarially generated feature vector

<p align="center">
 <img src="https://lh5.googleusercontent.com/N0DSZWbPwMUmNo0JRWmuVwSxDLHRUit7t2jcgUW4UfvYLOF365_fT0hvLuK_QWocZ4D9ugYXIxj11LKBAYOYqoj-lPGZzpyhBW8D0H8J" align="middle">
</p>

#### Results comparing the impact the size of the feature vector have on the TPR of the adversarially generated feature vector

<p align="center">
 <img src="https://lh3.googleusercontent.com/QtenUP6It_5W4Pysmr1TKZ1HlYdh9Q9cJ7F8gQ_rneb3lwkMnnwzMdtnXfY3r3dwJcFyb3_O4AwEDOflg4LVMkdeI6KdiGBWDytBjAPGuONk6q5mN7gTMVMeRj3i384NtuE1TpHe" align="middle">
</p>


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
   
1. **IndexError: list index out of range**

   Solution:
   This issue arises because you might have some unclean data in your dataset. The `extract_features` python scripts takes care of the data cleaning process by removing the files that would lead to biased or inaccurate results. In order to fix this issue, run the script again using the now-cleaned dataset. 
   
      ```
      python extract_features.py
      ```
   > This data cleansing process is case-to-case. For our application, we have restricted our research to Windows 32 bit applications, and hence we are cleaning our datasets based on that. 
   

1. **Error with the classifier for RL**

   Solution:
   Install another version of the torch to work with RL. The torch version used with GAN might not be compatible with the RL agent.
   
      ```
      pip install torch==1.2.0+cpu torchvision==0.4.0+cpu -f https://download.pytorch.org/whl/torch_stable.html
      ```
     

## To Do

-  Substitute Blackbox detector with Virus total as the training detector. 
-  Combine scripts for reinforcement learning and malware generative adversarial network into one script for ease of use. 
-  Decrease the detectiong rates of the mutated malware.

## Built With

* [PyTorch](https://pytorch.org/) -  Open source machine learning library based on the Torch library.
* [Lief](https://github.com/lief-project/LIEF) - A cross platform library which can parse, modify and abstract ELF, PE and MachO formats.
* [PE Bliss](https://github.com/BackupGGCode/portable-executable-library) - PE libarry for rebuilding PE files, written in C++.
* [Gym-Malware](https://github.com/endgameinc/gym-malware/) - Malware manipulation environment for OpenAI's gym.
* [MalwareGAN](https://github.com/ZaydH/MalwareGAN) - Adversarial Malware Generation Using GANs.


## Authors

* **Chandni Vaya** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Github](https://github.com/Chandni97)
* **Bedang Sen** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Github](http://github.com/bedangSen/)
* **Prasant Adhikari** - *Research Student, New York Unviersity Abu Dhabi* - [Github](https://github.com/prasantadh)
* **Muhammad Osama Khan** - *Research Student, New York Unviersity Abu Dhabi* - [Github](https://github.com/mok232)


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
