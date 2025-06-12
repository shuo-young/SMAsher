import pandas as pd
import os
import json
from contract_feature_handler import ContractFeatureHandler
from classification_evaluator import ClassificationEvaluator

# 读取 Excel 文件
file_path = "bsc_exp.xlsx"
df = pd.read_excel(file_path)  # 确保文件路径正确

# 获取第一列的所有值并转成列表
first_column_values = df.iloc[:, 0].dropna().tolist()

print(first_column_values)

os.environ["no_proxy"] = "127.0.0.1"

res = {}

def procoss_address(address):
    try:
        contract_handler = ContractFeatureHandler(address, debug_flag=True, platform="bsc")
        if contract_handler.gigahorse_status != 'OK':
            print(f"Gigahorse ERROR for address: {address}")
        else:    
            df_tmp = pd.DataFrame([contract_handler.features])
            classificationEvaluator = ClassificationEvaluator()
            classificationEvaluator.evaluate_single(df_tmp)
            res[address] = classificationEvaluator.evaluate_hybrid(df_tmp)
            print(f"Processed address: {address}, Result: {res[address]}")
    except Exception as e:
        print(f"Error processing address {address}: {e}")

# 遍历地址列表并处理
for address in first_column_values[1:]:
    if not address:  # 跳过空地址
        print("Skipping empty address.")
        continue
    print(f"Processing address: {address}")
    procoss_address(address)
    print(f"Processed address: {address}")

# 将结果保存到文件
output_file = "classification_results.json"
with open(output_file, 'w') as f:
    json.dump(res, f, indent=4)
print(f"Results saved to {output_file}")

# 处理完所有地址后，输出结果
print("All addresses processed.")