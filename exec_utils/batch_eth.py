import os
import subprocess
from concurrent.futures import ThreadPoolExecutor


def run_command(contract_file, folder_name):
    address = os.path.splitext(os.path.basename(contract_file))[0]
    block_number = 19250000
    command = f"python3 smasher.py -la {address} -bp ETH -bn {block_number} -d {folder_name} -v"
    print(f"Running command: {command}")
    subprocess.run(command, shell=True)


def process_file(root, file, folder_name):
    contract_file = os.path.join(root, file)
    run_command(contract_file, folder_name)


def process_folder(folder):
    folder_name = os.path.basename(folder)
    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = []
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".hex"):
                    futures.append(
                        executor.submit(process_file, root, file, folder_name)
                    )
        for future in futures:
            future.result()


def main():
    root_dir = "../get_x_code/output"
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = []
        for folder in os.listdir(root_dir):
            folder_path = os.path.join(root_dir, folder)
            if os.path.isdir(folder_path):
                futures.append(executor.submit(process_folder, folder_path))
        for future in futures:
            future.result()


if __name__ == "__main__":
    main()
