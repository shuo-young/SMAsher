`bsc_exp`: experimental results on BSC dataset

-   attacks.json: containing attacker contract addresses on BSC
-   bsc_exp_res.tar.gz: raw outputs and logs of all contracts
-   bsc.csv: attributes of analysis results
-   tp.tar.gz: outputs of attacker contracts

`eth_exp`: experimental results on ETH dataset

-   attacks.json: containing attacker contract addresses on ETH
-   eth_exp_res.tar.gz: raw outputs and logs of all contracts
-   eth.csv: attributes of analysis results
-   tp.tar.gz: outputs of attacker contracts

`comparison`: comparison experiment with other tools

- BlockWatchdog: detection and call paths recovery comparison with BlockWatchdog
  -   bsc: BW outputs of AC on BSC
  -   eth: BW outputs of AC on ETH
  -   analysis_script.py: script for data analysis
- LookAhead
  - bsc.json: detection res on bsc dataset
  - eth.json: detection res on eth dataset
  - other scripts for comparison
- SmartCat
  - detect_res: detection res of SmartCat on both bsc and eth dataset
  - run.sh: script for batch running for comparison

`dataprocess`: scripts for experimental result analysis

-   ac_distribution: scripts for analyzing attacker contracts distribution
-   distribution: scripts for analyzing the detection time and the attributes in results
-   time_gap: analyzing the time gap between contract deployment and first attack
-   eoa_to_ac: map the eoa to their deployed attacker contracts
-   **bsc_exp.csv: labeled results on BSC dataset**
-   **eth_exp.csv: labeled results on ETH dataset**

`utils`: script for analyzing the analyzed number
