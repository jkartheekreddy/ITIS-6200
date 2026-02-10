import os
import hashlib
import json

def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath,"rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print("Error hashing",filepath,":",e)
        return None

def traverse_directory(directory):
    file_hashes = {}
    for root,dirs,files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root,file)
            file_hash = hash_file(full_path)
            if file_hash:
                file_hashes[full_path] = file_hash
    return file_hashes

def generate_table():
    directory = input("Enter directory path to hash: ").strip()
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return
    print("Hashing files...")
    hashes = traverse_directory(directory)
    if not hashes:
        print("No files found.")
        return
    for path,file_hash in hashes.items():
        filename = os.path.basename(path)
        json_name = "hash_"+filename+".json"
        data = {"filepath":path,"hash":file_hash}
        with open(json_name,"w") as f:
            json.dump(data,f,indent=4)
        print("Created:",json_name)
    print("All hash tables generated.")

def validate_hash():
    directory = input("Enter directory path to verify: ").strip()
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return
    print("Verifying files...")
    json_files = []
    for f in os.listdir():
        if f.startswith("hash_") and f.endswith(".json"):
            json_files.append(f)
    if not json_files:
        print("No hash files found. Generate first.")
        return
    saved_hashes = {}
    for file in json_files:
        with open(file,"r") as f:
            data = json.load(f)
            saved_hashes[data["filepath"]] = data["hash"]
    current_hashes = traverse_directory(directory)
    saved_set = set(saved_hashes.keys())
    current_set = set(current_hashes.keys())
    deleted = saved_set - current_set
    for file in deleted:
        print(file,"has been DELETED")
    new_files = current_set - saved_set
    for file in new_files:
        print(file,"is NEW")
    common = saved_set & current_set
    for file in common:
        if saved_hashes[file] == current_hashes[file]:
            print(file,"hash is VALID")
        else:
            print(file,"hash is INVALID (MODIFIED)")

def main():
    while True:
        print("===== File Hashing System =====")
        print("1. Generate per-file hash tables")
        print("2. Verify hashes")
        print("3. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            generate_table()
        elif choice == "2":
            validate_hash()
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__=="__main__":
    main()
