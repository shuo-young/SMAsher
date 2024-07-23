import pandas as pd
import matplotlib.pyplot as plt


# Load the data from the CSV file to examine its structure
file_path = "../bsc_exp.csv"
data = pd.read_csv(file_path, delimiter=None, engine="python", on_bad_lines="warn")

# Convert 'created time' to datetime format
data["created time"] = pd.to_datetime(data["created time"], errors="coerce")

# Resample the data to get a monthly count of unique contract addresses
monthly_data = (
    data.set_index("created time").resample("M")["contract address"].nunique()
)

monthly_data.index = monthly_data.index.strftime("%Y-%m")

# Replotting with simplified x-axis labels
plt.figure(figsize=(7, 3.8))
ax = monthly_data.plot(kind="bar", color="skyblue")
monthly_data.plot(kind="bar", color="skyblue", edgecolor="black", linewidth=1)
# plt.title("Monthly Identified SMA Contract Addresses on BSC", fontsize=12)
plt.xlabel("Month", fontsize=10)
plt.ylabel("Number of Unique ACs", fontsize=10)
plt.xticks(rotation=45, fontsize=12)
plt.yticks(fontsize=8)
# plt.grid(True)
# Adding the text on top of the bars
for p in ax.patches:
    ax.annotate(
        str(p.get_height()),
        (p.get_x() + p.get_width() / 2.0, p.get_height()),
        xytext=(0, 1),
        textcoords="offset points",
        ha="center",
    )
plt.tight_layout()
plt.show()
