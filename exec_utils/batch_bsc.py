import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time
import threading

processed_folders = set()
processed_folders_lock = threading.Lock()


def get_block_number_from_folder_name(folder_name):
    try:
        parts = folder_name.split("_")
        last_number = int(parts[-1])
        return last_number + 1
    except (IndexError, ValueError):
        print(f"Invalid folder name format: {folder_name}")
        return None


def run_command(contract_file, folder_name, block_number):
    address = os.path.splitext(os.path.basename(contract_file))[0]
    command = f"python3 smasher.py -la {address} -bp BSC -bn {block_number} -d {folder_name} -v"
    print(f"Running command: {command}")
    subprocess.run(command, shell=True)


def process_file(root, file, folder_name, block_number):
    contract_file = os.path.join(root, file)
    run_command(contract_file, folder_name, block_number)


def process_folder(folder):
    folder_name = os.path.basename(folder)
    block_number = get_block_number_from_folder_name(folder_name)
    if block_number is None:
        return
    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = []
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".hex"):
                    futures.append(
                        executor.submit(
                            process_file, root, file, folder_name, block_number
                        )
                    )
        for future in futures:
            future.result()


def monitor_and_process_folders(root_dir):
    with ThreadPoolExecutor(max_workers=200) as executor:
        while True:
            futures = []
            for folder in os.listdir(root_dir):
                folder_path = os.path.join(root_dir, folder)
                with processed_folders_lock:
                    if os.path.isdir(folder_path) and folder not in processed_folders:
                        futures.append(executor.submit(process_folder, folder_path))
                        processed_folders.add(folder)
            for future in futures:
                future.result()
            time.sleep(21600)


if __name__ == "__main__":
    root_dir = "./contracts"
    monitor_and_process_folders(root_dir)
