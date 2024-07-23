## SMAsher

### Overview

Artifact repository of the work _SMAsher: Identify the State Manipulation Attacks in DeFi Ecosystem_

### Structure

#### Dataset

1. ETH contract bytecode: download from xblock https://xblock.pro/xblock-eth.html, from block 15,000,000 to 19,250,000.
2. BSC contract bytecode: obtaining from rpc node from 30,000,000 to 38,100,000. We publicize the dataset to https://userscloud.com/ti8uted8yc4j for public access.

#### Tool

-   flow: dataflow and state flow analysis logic
-   graph: phalcon-like call graph recovery
-   semantic: operation semantic features extraction from decompiled contract bytecode
-   gigahorse-toolchain: contract bytecode decompilor based on the core logic written in [sm.dl](gigahorse-toolchain/clients/sm.dl).
-   `contract.py`: decompile contract for semantic extraction based on the output of gigahorse
-   `identifier.py`: detection logic for using flow analysis to find the reachability of dataflow and the state flow and report related traces for attack identification
-   `smasher.py`: the entrance to run SMAsher
-   `global_params.py`: configuration of global parameters

#### Experimental Result

All experimental results are provided in directory [experiment](experiment). We also include a detailed readme for the experiment folder, see [README.md](experiment/README.md).

-   bsc_exp: detection results of SMAsher on analyzing 583,089 contract bytecode on BSC.
-   eth_exp: detection results of SMAsher on analyzing 797,482 contract bytecode on ETH.
-   comparison: call path recovery capability comparison with BlockWatchdog, containing its outputs.
-   dataprocess: scripts for analyzing the detection results, specifically, [bsc_exp.csv](experiment/dataprocess/bsc_exp.csv) and [eth_exp.csv](experiment/dataprocess/eth_exp.csv) label every identified contract with their attributes including:
    -   address
    -   creator
    -   platform
    -   created block
    -   created time
    -   attack block
    -   attack time
    -   time gap
    -   detection cost
    -   Sender profit
    -   Receiver profit
    -   profit
    -   phalcon url
    -   new attack

#### Other Directories

-   case_in_paper: solidity code snippet used in the pictures in paper
-   exec_utils: some utility scripts for running SMAsher in batch.
