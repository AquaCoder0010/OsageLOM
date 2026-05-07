import os
import tempfile
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from django.conf import settings

import pefile
import torch
from model_train.model import create_byteformer


MODEL = None
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'best_model_final.pth')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_model():
    global MODEL
    if MODEL is None:
        model = create_byteformer(mode="tiny", num_classes=2, max_num_tokens=50000)
        checkpoint = torch.load(os.path.join(BASE_DIR, 'best_model_final.pth'), map_location="cpu")
        state_dict = checkpoint["model_state_dict"]
        model.load_state_dict(state_dict)
        model.eval()
        MODEL = model
    return MODEL


def extract_executable_sections(data: bytes) -> bytearray:
    pe = pefile.PE(data=data)
    executable_data = bytearray()
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            executable_data.extend(section.get_data())
    return executable_data


def is_valid_pe(file_bytes: bytes) -> bool:
    if len(file_bytes) < 2:
        return False
    mz_signature = int.from_bytes(file_bytes[:2], 'little')
    if mz_signature != 0x5A4D:
        return False
    if len(file_bytes) >= 64:
        pe_offset = int.from_bytes(file_bytes[60:64], 'little')
        if pe_offset + 4 <= len(file_bytes):
            pe_signature = int.from_bytes(file_bytes[pe_offset:pe_offset + 4], 'little')
            if pe_signature != 0x00004550:
                return False
    return True


def predict(file_path: str):
    model = get_model()
    with open(file_path, "rb") as f:
        data = f.read()
    executable_data = extract_executable_sections(data)
    bytes_arr = torch.tensor(list(executable_data) + [256], dtype=torch.long).unsqueeze(0)
    with torch.no_grad():
        output = model(bytes_arr)
    probabilities = torch.softmax(output, dim=1)
    confidence = probabilities[0][1].item()
    prediction = output.argmax(dim=1).item()
    return {
        'prediction': prediction,
        'confidence': confidence,
        'is_malware': prediction == 1,
        'label': 'MALWARE' if prediction == 1 else 'BENIGN'
    }

@require_POST
def scan_file(request):
    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return JsonResponse({'error': 'No file provided'}, status=400)
    file_bytes = uploaded_file.read()
    if not is_valid_pe(file_bytes):
        return JsonResponse({'error': 'Invalid PE file. Please upload a valid PE executable.'}, status=400)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_file:
        temp_file.write(file_bytes)
        temp_path = temp_file.name
    try:
        result = predict(temp_path)
    except Exception as e:
        os.unlink(temp_path)
        return JsonResponse({'error': f'Prediction failed: {str(e)}'}, status=500)
    os.unlink(temp_path)
    return JsonResponse({
        'filename': uploaded_file.name,
        'size': uploaded_file.size,
        'is_malware': result['is_malware'],
        'confidence': round(result['confidence'], 4),
        'detection': result['label']
    })


@ensure_csrf_cookie
def home(request):
    return render(request, 'scanner/index.html')