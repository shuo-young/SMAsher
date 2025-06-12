def get_EOA_Address(contract_address, creator_EOA):
    EOA = []
    # 取出重复的EOA
    for i in set(creator_EOA):
        if creator_EOA.count(i) > 1:
            if i not in EOA:
                EOA.append(i)
    # print(EOA)

    # 进行键值对匹配，一对多
    EOA_adresses = {}
    address_EOA = {}
    for i in range(len(EOA)):
        address_list = []
        for j in range(len(creator_EOA)):
            if EOA[i] == creator_EOA[j]:
                address_list.append(contract_address[j])
        EOA_adresses.update({EOA[i]: address_list})
    return EOA_adresses


import pandas as pd

if __name__ == "__main__":
    bsc_data = pd.read_csv("../bsc.csv")
    # print(bsc_data["contract address"])

    BSC_contract_address = bsc_data["contract address"].dropna().tolist()
    BSC_creator_EOA = bsc_data["creator_EOA"].dropna().tolist()

    ETH_data = pd.read_csv("../eth.csv")
    ETH_contract_address = ETH_data["contract address"].dropna().tolist()
    ETH_creator_EOA = ETH_data["creator_EOA"].dropna().tolist()

    BSC_EOA_adresses = get_EOA_Address(BSC_contract_address, BSC_creator_EOA)
    ETH_EOA_adresses = get_EOA_Address(ETH_contract_address, ETH_creator_EOA)

    print(BSC_EOA_adresses)
    print(ETH_EOA_adresses)
    print(len(BSC_contract_address))
    print(len(ETH_contract_address))
    print(len(set(BSC_contract_address + ETH_contract_address)))
    print(list(set(BSC_contract_address + ETH_contract_address)))
    print(len(BSC_EOA_adresses.keys()))
    max = 0
    address = ""
    count_bsc = 0
    for key in BSC_EOA_adresses.keys():
        count_bsc += len(BSC_EOA_adresses[key])
        if len(BSC_EOA_adresses[key]) > max:
            max = len(BSC_EOA_adresses[key])
            address = key
    print(address)
    print(max)
    print(count_bsc)
    print(ETH_EOA_adresses)
