def count_gigahorse_commands(file_path):
    count = 0
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.startswith("gigahorse run command:"):
                count += 1
    return count


file_path = "1exp.log"
print(
    f"line count starting with 'gigahorse run command:': {count_gigahorse_commands(file_path)}"
)
