from web3 import Web3

# 连接到以太坊节点，可以是本地节点或Infura等服务
# 这里使用了Infura的一个示例节点URL，你需要用自己的Infura项目ID替换
infura_url = "https://arb-mainnet.g.alchemy.com/v2/uQXNRP9T7_rg0AB1VZbjClHMf0w7OiCA"
web3 = Web3(Web3.HTTPProvider(infura_url))

# 检查是否成功连接
if not web3.is_connected():
    raise Exception("无法连接到以太坊节点")

# 输入合约地址
contract_address = "0x4276beaa49de905eed06fcdc0ad438a19d3861dd"

# 输入槽位ID（slot ID），通常为十六进制字符串
slot_id = "0xe"

# 输入区块号，可以是具体的区块号或 'latest'、'earliest' 或 'pending'
block_number = 206219812  # 或者你可以使用具体的区块号，如1234567


# 获取存储值
def get_storage_value(contract_address, slot_id, block_number):
    # 使用eth_getStorageAt RPC方法获取存储值
    storage_value = web3.eth.get_storage_at(
        contract_address, slot_id, block_identifier=block_number
    )

    return storage_value


# 调用函数获取存储值
try:
    storage_value = get_storage_value(
        web3.to_checksum_address(contract_address), slot_id, block_number
    )
    print(
        f"在合约地址 {contract_address} 的槽位 {slot_id} 和区块 {block_number} 下的存储值为: {storage_value.hex()}"
    )
except Exception as e:
    print(f"获取存储值时出错: {str(e)}")
