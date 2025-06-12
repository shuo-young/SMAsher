import os
import json
import pandas as pd

directory = "./eth_exp/res"
directory_bsc = "./bsc_exp/res"
data = []

# Read all JSON files in the directory
for filename in os.listdir(directory):
    if filename.endswith(".json"):
        filepath = os.path.join(directory, filename)
        with open(filepath, "r") as file:
            json_data = json.load(file)
            # Assuming the JSON structure has one top-level key
            key = list(json_data.keys())[0]
            record = json_data[key]
            data.append(
                {
                    "time": record["time"],
                    "max_call_depth": record["max_call_depth"],
                    "visited_contracts_num": record["visited_contracts_num"],
                }
            )

for filename in os.listdir(directory_bsc):
    if filename.endswith(".json"):
        filepath = os.path.join(directory_bsc, filename)
        with open(filepath, "r") as file:
            json_data = json.load(file)
            # Assuming the JSON structure has one top-level key
            key = list(json_data.keys())[0]
            record = json_data[key]
            data.append(
                {
                    "time": record["time"],
                    "max_call_depth": record["max_call_depth"],
                    "visited_contracts_num": record["visited_contracts_num"],
                }
            )

# Convert the data to a DataFrame
df = pd.DataFrame(data)
print(df.head)
print(df.describe())
