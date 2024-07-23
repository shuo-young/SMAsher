import pandas as pd

data = pd.read_csv("../bsc.csv")

print(data.head())

grouped_data = data.groupby("creator_EOA")["contract address"].apply(list).reset_index()

grouped_data["num_addresses"] = grouped_data["contract address"].apply(len)
multiple_contracts = grouped_data[grouped_data["num_addresses"] > 1]

print(multiple_contracts)
print(sum(multiple_contracts["num_addresses"]))

multiple_contracts.to_csv("output.csv", index=False)
