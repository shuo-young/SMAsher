import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

data_bsc = pd.read_csv("../bsc_exp.csv")
data_bsc["created_time"] = pd.to_datetime(data_bsc["created time"], errors="coerce")
data_bsc["attack_time"] = pd.to_datetime(data_bsc["attack time"], errors="coerce")
data_bsc["time_gap"] = (
    data_bsc["attack_time"] - data_bsc["created_time"]
).dt.total_seconds()
data_bsc = data_bsc.dropna(subset=["time_gap"])

data_eth = pd.read_csv("../eth_exp.csv")
data_eth["created_time"] = pd.to_datetime(data_eth["created time"], errors="coerce")
data_eth["attack_time"] = pd.to_datetime(data_eth["attack time"], errors="coerce")
data_eth["time_gap"] = (
    data_eth["attack_time"] - data_eth["created_time"]
).dt.total_seconds()
data_eth = data_eth.dropna(subset=["time_gap"])

bins = [0, 10, 30, 60, 300, 1800, 3600, 86400, float("inf")]
labels = [
    "0~10s",
    "10~30s",
    "30s~1min",
    "1~5min",
    "5~30min",
    "30min~1h",
    "1h~1d",
    "> 1d",
]

data_bsc["time_interval"] = pd.cut(
    data_bsc["time_gap"], bins=bins, labels=labels, right=False
)
data_eth["time_interval"] = pd.cut(
    data_eth["time_gap"], bins=bins, labels=labels, right=False
)
interval_data_bsc = data_bsc["time_interval"].value_counts().sort_index()
interval_data_eth = data_eth["time_interval"].value_counts().sort_index()

fig, ax = plt.subplots(figsize=(12, 7.5))
bar_width = 0.35
index = np.arange(len(labels))

bars1 = ax.bar(
    index,
    interval_data_bsc.values,
    bar_width,
    label="BSC",
    edgecolor="black",
    linewidth=1,
)
bars2 = ax.bar(
    index + bar_width,
    interval_data_eth.values,
    bar_width,
    label="ETH",
    edgecolor="black",
    linewidth=1,
)

# ax.set_xlabel("Time Gap Interval", fontsize=14)
ax.set_ylabel("Number of Attacks", fontsize=18)
plt.yticks(fontsize=16)
# ax.set_title(
#     "Time Gaps of AC Creation and Execuon on ETH and BSC Platforms", fontsize=16
# )
ax.set_xticks(index + bar_width / 2)
ax.set_xticklabels(labels, fontsize=19)
ax.legend(fontsize=19)
# ax.grid(True)

for bars in (bars1, bars2):
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            f"{int(height)}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),  # 3 points vertical offset
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=18,
        )

plt.tight_layout()
plt.show()
