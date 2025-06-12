#!/bin/bash

# 定义文件路径
bsc_file="bsc_exp.csv"
eth_file="eth_exp.csv"

# 定义分析函数
analyze_contract() {
    local platform=$1
    local address=$2
    echo "Analyzing contract $address on platform $platform..."
    docker run --rm \
        -v "$(pwd)/detect_res:/app/gigahorse-toolchain/detect_res" \
        -v "$(pwd)/dots:/app/gigahorse-toolchain/dots" \
        -v "$(pwd)/pm_detector.py:/app/gigahorse-toolchain/pm_detector.py" \
        -v "$(pwd)/pm_token.py:/app/gigahorse-toolchain/pm_token.py" \
        pm_detector_image:latest -ch "$platform" -b "$address" -dt
}

# 处理 BSC 文件
while IFS=, read -r address creator platform created_block created_time attack_block attack_time attack_tx time_gap detection_cost sender receiver profit phalcon_url new_attack; do
    if [[ "$address" =~ ^0x[0-9a-fA-F]{40}$ && "$platform" == "BSC" ]]; then
        analyze_contract "bsc" "$address"
    fi
done < "$bsc_file"

# 处理 ETH 文件
while IFS=, read -r address creator platform created_block created_time attack_block attack_time attack_tx time_gap detection_cost sender receiver profit phalcon_url new_attack; do
    if [[ "$address" =~ ^0x[0-9a-fA-F]{40}$ && "$platform" == "ETH" ]]; then
        analyze_contract "eth" "$address"
    fi
done < "$eth_file"

echo "Analysis completed."