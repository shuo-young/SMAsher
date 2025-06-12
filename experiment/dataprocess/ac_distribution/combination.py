import pandas as pd
import matplotlib.pyplot as plt


# Load the data from the CSV file to examine its structure
bsc_file_path = "../bsc_exp.csv"
bsc_data = pd.read_csv(
    bsc_file_path, delimiter=None, engine="python", on_bad_lines="warn"
)

# Convert 'created time' to datetime format
bsc_data["created time"] = pd.to_datetime(bsc_data["created time"], errors="coerce")

# Resample the data to get a monthly count of unique contract addresses
monthly_data = (
    bsc_data.set_index("created time").resample("M")["contract address"].nunique()
)
monthly_data.index = monthly_data.index.strftime("%Y-%m")

plt.figure(figsize=(15, 7))

# Scatter plot 'time' vs 'max_call_depth'
plt.subplot(1, 2, 1)

ax = monthly_data.plot(kind="bar", color="skyblue")
monthly_data.plot(kind="bar", color="skyblue", edgecolor="black", linewidth=1)
plt.title("Monthly Identified Attacker Contracts on BSC", fontsize=18)
plt.xlabel(None)
plt.ylabel("Number of Unique ACs", fontsize=16)
plt.xticks(rotation=45, fontsize=17)
plt.yticks(fontsize=16)
# plt.grid(True)
# Adding the text on top of the bars
for p in ax.patches:
    ax.annotate(
        str(p.get_height()),
        (p.get_x() + p.get_width() / 2.0, p.get_height()),
        xytext=(0, 1),
        textcoords="offset points",
        ha="center",
        fontsize=16,
    )

plt.subplot(1, 2, 2)
file_path = "../eth_exp.csv"
data = pd.read_csv(file_path, delimiter=None, engine="python", on_bad_lines="warn")

# Convert 'created time' to datetime format
data["created time"] = pd.to_datetime(
    data["created time"], format="%Y/%m/%d %H:%M:%S", errors="coerce"
)

# Resample the data to get a monthly count of unique contract addresses
data["created time"] = data["created time"].dt.to_period("M")
monthly_data = data.groupby("created time")["contract address"].nunique()

monthly_data.index = monthly_data.index.strftime("%Y-%m")

# Replotting with simplified x-axis labels
ax = monthly_data.plot(kind="bar", color="skyblue")
monthly_data.plot(kind="bar", color="teal", edgecolor="black", linewidth=1)
plt.title("Monthly Identified Attacker Contracts on ETH", fontsize=18)
# plt.xlabel("ETH", fontsize=16)
# plt.ylabel("Number of Unique ACs", fontsize=10)
plt.xlabel(None)
plt.xticks(rotation=45, fontsize=17)
plt.yticks(fontsize=16)
# plt.grid(True)
# Adding the text on top of the bars
for p in ax.patches:
    ax.annotate(
        str(p.get_height()),
        (p.get_x() + p.get_width() / 2.0, p.get_height()),
        xytext=(0, 1),
        textcoords="offset points",
        ha="center",
        fontsize=16,
    )


plt.tight_layout()
plt.show()
