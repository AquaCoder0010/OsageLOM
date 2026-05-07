import pefile
from capstone import *

import os
import torch
from model_train.model import ByteFormer, create_byteformer

def infer(file_path: str) -> torch.Tensor:
    model = create_byteformer(mode="tiny", num_classes=2, max_num_tokens=50000)
    checkpoint = torch.load("best_model_final.pth", map_location="cpu")
    state_dict = checkpoint["model_state_dict"]
    model.load_state_dict(state_dict)
    model.eval()
    
    with open(file_path, "rb") as f:
        data = f.read()
    
    def extract_opcode(file_content: bytes):
        pe = pefile.PE(data=file_content)
        # We collect executable sections
        executable_data = bytearray()
        for section in pe.sections:
            # 0x20000000 = IMAGE_SCN_MEM_EXECUTE
            if section.Characteristics & 0x20000000:
                executable_data.extend(section.get_data())

        return executable_data;

    execu = extract_opcode(data)
    print(execu[:10])
    bytes_arr = torch.tensor(list(execu) + [256], dtype=torch.long).unsqueeze(0)
    
    with torch.no_grad():
        output = model(bytes_arr)
    
    return output


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Input: {file_path}")
        result = infer(file_path)
        print(result)
        prediction = result.argmax(dim=1).item()
        print("MALWARE" if prediction == 1 else "BENIGN")

