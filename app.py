import requests
import os
import tempfile
from flask import Flask, render_template, request, jsonify
from flask_wtf.csrf import CSRFProtect
import torch
from model_train.model import create_byteformer
from model_train.dataset import BytesTransform_o

import logging


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

SPACE_URL = "https://AquaCoder0010-osagelom.hf.space/predict"

csrf = CSRFProtect(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
    with open(file_path, 'rb') as f:
        value = f.read()

    payload = { "bytes_sequence": list(value) }
    result  = requests.post(SPACE_URL, json=payload).json()
    
    prediction = result['predicted_class']
    confidence = result['confidence']

    print(confidence)
    return { 'prediction': prediction, 'confidence': confidence, 'is_malware': prediction == 1, 'label': 'MALWARE' if prediction == 1 else 'BENIGN'}


@app.route('/')
def home():
    return render_template('index.html')


logger = logging.getLogger(__name__)

@app.route('/api/scan/', methods=['POST'])
@csrf.exempt
def scan_file():
    logger.info("=== Scan endpoint called ===")
    
    if 'file' not in request.files:
        logger.warning("No file in request")
        return jsonify({'error': 'No file provided'}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        logger.warning("Empty filename")
        return jsonify({'error': 'No file provided'}), 400

    logger.info(f"Received file: {uploaded_file.filename}, size: {uploaded_file.content_length}")

    file_bytes = uploaded_file.read()
    logger.info(f"Read {len(file_bytes)} bytes")

    if not is_valid_pe(file_bytes):
        logger.warning("Invalid PE file")
        return jsonify({'error': 'Invalid PE file. Please upload a valid PE executable.'}), 400

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_file:
            temp_file.write(file_bytes)
            temp_path = temp_file.name
        logger.info(f"Temp file created: {temp_path}")

        # Log before prediction – measure time
        import time
        start = time.time()
        result = predict(temp_path)
        elapsed = time.time() - start
        logger.info(f"Prediction completed in {elapsed:.2f} seconds. Result: {result}")

    except Exception as e:
        logger.exception("Prediction failed with exception:")  # logs full traceback
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        return jsonify({'error': 'Prediction failed: ' + str(e)}), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
            logger.info(f"Temp file deleted: {temp_path}")

    response = jsonify({
        'filename': uploaded_file.filename,
        'size': len(file_bytes),
        'is_malware': result['is_malware'],
        'confidence': round(result['confidence'], 4),
        'detection': result['label']
    })
    logger.info("Returning successful response")
    return response

if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
