const FILE_EXTENSIONS = ['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.msi', '.cab', '.jar'];

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileExtension(filename) {
    const ext = filename.toLowerCase().match(/\.[^.]+$/);
    return ext ? ext[0] : '';
}

function isValidPEFile(file) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = function(e) {
            const buffer = e.target.result;
            const view = new DataView(buffer);
            
            if (buffer.byteLength < 2) {
                resolve(false);
                return;
            }

            const mzSignature = view.getUint16(0, true);
            if (mzSignature !== 0x5A4D) {
                resolve(false);
                return;
            }

            if (buffer.byteLength >= 64) {
                const peOffset = view.getUint32(60, true);
                if (peOffset + 4 <= buffer.byteLength) {
                    const peSignature = view.getUint32(peOffset, true);
                    if (peSignature !== 0x00004550) {
                        resolve(false);
                        return;
                    }
                }
            }
            
            resolve(true);
        };
        reader.onerror = function() {
            resolve(false);
        };
        reader.readAsArrayBuffer(file.slice(0, 1024));
    });
}

function displayResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    const fileName = document.getElementById('fileName');
    const fileMeta = document.getElementById('fileMeta');
    const lastAnalysis = document.getElementById('lastAnalysis');
    const fileSize = document.getElementById('fileSize');
    const progressSection = document.getElementById('scanProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const verdictSection = document.getElementById('verdictSection');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictTitle = document.getElementById('verdictTitle');
    const verdictSubtitle = document.getElementById('verdictSubtitle');
    const confidenceFill = document.getElementById('confidenceFill');
    const confidenceValue = document.getElementById('confidenceValue');
    
    fileName.textContent = data.filename;
    
    const ext = getFileExtension(data.filename);
    const fileType = ext.replace('.', '').toUpperCase();
    fileMeta.textContent = `${fileType} - ${data.size}`;
    
    const now = new Date();
    lastAnalysis.textContent = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
    fileSize.textContent = data.size;
    
    progressSection.style.display = 'none';
    progressFill.style.width = '0%';
    
    verdictSection.style.display = 'block';
    
    verdictIcon.className = 'verdict-icon';
    verdictTitle.className = 'verdict-title';
    confidenceFill.className = 'confidence-fill';
    confidenceValue.className = 'confidence-value';
    
    const confidence = data.confidence * 100;
    const isMalware = data.is_malware;
    
    if (isMalware) {
        verdictIcon.classList.add('malware');
        verdictTitle.classList.add('malware');
        verdictTitle.textContent = 'MALWARE';
        verdictSubtitle.textContent = 'This file is classified as malicious';
        confidenceFill.classList.add('malware');
        confidenceValue.classList.add('malware');
    } else {
        verdictIcon.classList.add('clean');
        verdictTitle.classList.add('clean');
        verdictTitle.textContent = 'BENIGN';
        verdictSubtitle.textContent = 'This file appears to be clean';
        confidenceFill.classList.add('clean');
        confidenceValue.classList.add('clean');
    }
    
    confidenceFill.style.width = confidence + '%';
    confidenceValue.textContent = confidence.toFixed(2) + '% confidence';
    
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

async function scanFileAPI(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch('/api/scan/', {
        method: 'POST',
        body: formData
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Scan failed');
    }
    
    return await response.json();
}

async function handleFile(file) {
    const uploadZone = document.getElementById('uploadZone');
    const ext = getFileExtension(file.name);
    
    if (!FILE_EXTENSIONS.includes(ext)) {
        uploadZone.classList.add('dragerror');
        uploadZone.classList.remove('dragover');
        alert('Invalid file type. Please upload a PE file (EXE, DLL, SYS, SCR, CPL, OCX, MSI, CAB, JAR)');
        setTimeout(() => {
            uploadZone.classList.remove('dragerror');
        }, 2000);
        return false;
    }
    
    const isPE = await isValidPEFile(file);
    
    if (!isPE) {
        uploadZone.classList.add('dragerror');
        uploadZone.classList.remove('dragover');
        alert('Invalid PE file. The file does not appear to be a valid PE executable.');
        setTimeout(() => {
            uploadZone.classList.remove('dragerror');
        }, 2000);
        return false;
    }
    
    await uploadAndScan(file);
    return true;
}

async function uploadAndScan(file) {
    const scanProgress = document.getElementById('scanProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const uploadSection = document.querySelector('.upload-section');
    const verdictSection = document.getElementById('verdictSection');
    
    uploadSection.style.display = 'none';
    
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    
    const fileName = document.getElementById('fileName');
    const fileMeta = document.getElementById('fileMeta');
    const fileSize = document.getElementById('fileSize');
    
    fileName.textContent = file.name;
    fileMeta.textContent = file.name.split('.').pop().toUpperCase() + ' - ' + formatFileSize(file.size);
    fileSize.textContent = formatFileSize(file.size);
    
    const now = new Date();
    document.getElementById('lastAnalysis').textContent = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
    
    scanProgress.style.display = 'block';
    verdictSection.style.display = 'none';
    
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress > 90) progress = 90;
        
        progressFill.style.width = progress + '%';
        progressText.textContent = 'Analyzing file... ' + Math.floor(progress) + '%';
    }, 200);
    
    try {
        const result = await scanFileAPI(file);
        
        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        progressText.textContent = 'Analysis complete!';
        
        setTimeout(() => {
            displayResults(result);
        }, 300);
        
    } catch (error) {
        clearInterval(progressInterval);
        alert('Error: ' + error.message);
        resultsSection.style.display = 'none';
        uploadSection.style.display = 'block';
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const rescanBtn = document.getElementById('rescanBtn');
    const newFileBtn = document.getElementById('newFileBtn');
    
    let currentFile = null;
    
    uploadZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            currentFile = files[0];
            handleFile(currentFile);
        }
    });
    
    fileInput.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            currentFile = e.target.files[0];
            handleFile(currentFile);
        }
    });
    
    rescanBtn.addEventListener('click', function() {
        if (currentFile) {
            const resultsSection = document.getElementById('resultsSection');
            resultsSection.style.display = 'none';
            uploadAndScan(currentFile);
        }
    });
    
    newFileBtn.addEventListener('click', function() {
        currentFile = null;
        const resultsSection = document.getElementById('resultsSection');
        const uploadSection = document.querySelector('.upload-section');
        
        resultsSection.style.display = 'none';
        uploadSection.style.display = 'block';
        
        fileInput.value = '';
        
        uploadSection.scrollIntoView({ behavior: 'smooth' });
    });
});