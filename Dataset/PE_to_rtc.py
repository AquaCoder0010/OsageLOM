import os
from pathlib import Path
import pefile
import tqdm


global_failures = 0
def extract_opcode(file_content: bytes, output_path: str):
    global global_failures    
    try:
        pe = pefile.PE(data=file_content)
    except Exception as e:
        print(f"[{global_failures}] PE parsing error: {e}")
        global_failures += 1
        return

    # We collect executable sections
    executable_data = bytearray()
    for section in pe.sections:
        # 0x20000000 = IMAGE_SCN_MEM_EXECUTE
        if section.Characteristics & 0x20000000:
            executable_data.extend(section.get_data())
    

    with open(output_path, "wb") as f:
        f.write(executable_data)

def get_file_size_safe(filename):
    try:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            return size
        else:
            print(f"File not found: {filename}")
            return None
    except PermissionError:
        print(f"Permission denied: {filename}")
        return None
    except OSError as e:
        print(f"Error reading {filename}: {e}")
        return None


def find_all_exe_files(directory: str, limit : int) -> list[str]:
    exe_files = []
    file_count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".rtc"):
                if file_count < limit:
                    exe_files.append(os.path.join(root, file))
                    file_count += 1
                else:
                    break;
    return exe_files



def find_all_dll_files(directory: str, limit : int) -> list[str]:
    exe_files = []
    file_count = 0
    for root, _, files in tqdm.tqdm(os.walk(directory)):
        for file in files:
            if file.lower().endswith(".dll"):
                if file_count < limit and get_file_size_safe(directory) < (10) * (1024 ** 2):
                    exe_files.append(os.path.join(root, file))
                    file_count += 1
                else:
                    break;
    return exe_files



if __name__ == "__main__":
    WINDOW_DIR = "/home/aqua/mount-file/temp-sda3/Windows"
    exe_list = find_all_dll_files(WINDOW_DIR, 16000)

    print(len(exe_list))
    for exe in tqdm.tqdm(exe_list[8000:]):
        with open(exe, 'rb') as file:
            extract_opcode(file.read(), f"data/{exe.split('/')[-1][:-4]}.rtc")
        
