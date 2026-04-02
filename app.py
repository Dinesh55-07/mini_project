from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
import sqlite3
import hashlib
from datetime import datetime
import shutil
import glob
import json
import mimetypes
import re
from difflib import SequenceMatcher

from source_watermark_engine import (
    watermark_source,
    extract_watermark,
    match_employee,
    score_employee_match,
    detect_language,
    extract_watermark_signature,
    compare_watermark_signatures,
)
from photo_source_forensics import analyze_source_photo
from pdf_steganography import watermark_pdf as steg_watermark_pdf, detect_watermark_in_pdf, match_watermark_to_employee


app = Flask(__name__)
CORS(app)
app.secret_key = 'securetrace-v2-2026-super-secret-key'

MAIL_USERNAME = 'sakthidinesh9751@gmail.com'  
MAIL_PASSWORD = 'hiap xadb txmf auel'

UPLOAD_FOLDER = 'uploads'
WATERMARKED_FOLDER = 'watermarked_pdfs'
SOURCE_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'source')
WATERMARKED_SOURCE_FOLDER = 'watermarked_sources'
PHOTO_UPLOAD_FOLDER = 'temp_images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_FOLDER, exist_ok=True)
os.makedirs(SOURCE_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_SOURCE_FOLDER, exist_ok=True)
os.makedirs(PHOTO_UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mail = Mail(app)

VALID_USER = 'admin'
VALID_PASS = 'securetrace123'
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_SOURCE_EXTENSIONS = {'py', 'js', 'ts', 'java', 'cpp', 'cc', 'cxx', 'c', 'h', 'hpp'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_source_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_SOURCE_EXTENSIONS


def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def _normalize_source_text(text: str) -> str:
    normalized_lines = []
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line:
            continue
        # Ignore synthetic watermark micro-comment lines for content similarity.
        if re.match(r'^(#|//)?\s*(note|review)\s*[\.,;:]?\s*$', line):
            continue
        line = re.sub(r'\s+', ' ', line)
        normalized_lines.append(line)
    return '\n'.join(normalized_lines)


def _source_similarity_score(ocr_text: str, candidate_path: str) -> int:
    if not candidate_path or not os.path.exists(candidate_path):
        return 0

    try:
        with open(candidate_path, 'r', encoding='utf-8', errors='replace') as f:
            candidate_text = f.read()
    except OSError:
        return 0

    ocr_norm = _normalize_source_text(ocr_text)
    cand_norm = _normalize_source_text(candidate_text)
    if not ocr_norm or not cand_norm:
        return 0

    ratio = SequenceMatcher(None, ocr_norm, cand_norm).ratio()
    return int(ratio * 100)

def init_database():
    conn = sqlite3.connect('securetrace.db')
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS employees (
        email TEXT PRIMARY KEY, 
        name TEXT NOT NULL, 
        department TEXT DEFAULT 'General',
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS watermark_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        employee_email TEXT,
        employee_name TEXT NOT NULL,
        document_name TEXT NOT NULL,
        watermarked_file TEXT NOT NULL,
        encryption_key TEXT DEFAULT 'forensic-only',
        forensic_data TEXT,
        watermark_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_email TEXT NOT NULL,
        recipient_name TEXT,
        filename TEXT NOT NULL,
        sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS source_watermark_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_email TEXT NOT NULL,
        employee_name TEXT NOT NULL,
        filename TEXT NOT NULL,
        language TEXT NOT NULL,
        watermarked_file TEXT NOT NULL,
        watermark_metadata TEXT,
        watermark_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()

init_database()

def get_employees_list():
    conn = sqlite3.connect('securetrace.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT email as id, name, email, department FROM employees ORDER BY name')
    employees = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return employees


def _file_sha256(file_path):
    """Return SHA256 hex digest for a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == VALID_USER and request.form['password'] == VALID_PASS:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/pdf-send')
@login_required
def pdf_send():
    return render_template('pdf_send.html', employees=get_employees_list())

@app.route('/employees', methods=['GET', 'POST'])
@login_required
def manage_employees():
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'delete':
            email = request.form['email']
            conn = sqlite3.connect('securetrace.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM employees WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            return redirect(url_for('manage_employees'))
        
        email = request.form['email'].lower().strip()
        name = request.form['name']
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO employees (email, name, department) VALUES (?, ?, ?)',
                      (email, name, request.form.get('department', 'General')))
        conn.commit()
        conn.close()
    
    employees = get_employees_list()
    return render_template('employees.html', employees=employees)

@app.route('/api/pdf-upload', methods=['POST'])
@login_required
def pdf_upload():
    try:
        if 'pdf_file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['pdf_file']
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({'error': 'Invalid PDF file'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        session['original_pdf'] = filename
        session['original_path'] = filepath
        session.modified = True
        
        return jsonify({
            'success': True, 
            'filename': filename,
            'message': 'PDF uploaded successfully!'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/pdf-watermarking')
@login_required
def pdf_watermarking():
    return render_template('pdf_watermarking.html', employees=get_employees_list())

@app.route('/source-watermarking')
@login_required
def source_watermarking():
    return render_template('source_watermarking.html', employees=get_employees_list())


@app.route('/source-send')
@login_required
def source_send():
    return render_template('source_send.html', employees=get_employees_list())


@app.route('/source-detect')
@login_required
def source_detect():
    return render_template('source_detect.html')

@app.route('/pdf-detect')
@login_required
def pdf_detect():
    return render_template('pdf_detect.html')

@app.route('/api/detect-pdf-watermark', methods=['POST'])
@login_required
def detect_pdf_watermark():
    temp_path = None
    try:
        if 'suspect_pdf' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['suspect_pdf']
        filename = secure_filename(file.filename)
        
        # Save uploaded file temporarily
        temp_path = os.path.join(PHOTO_UPLOAD_FOLDER, f"temp_{filename}")
        file.save(temp_path)

        # Step 0: Fast exact-file attribution using SHA256 fingerprint.
        suspect_hash = _file_sha256(temp_path)
        conn = sqlite3.connect('securetrace.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT employee_email, employee_name, document_name, forensic_data
            FROM watermark_logs
            ORDER BY rowid DESC
        ''')
        watermark_rows = [dict(row) for row in cursor.fetchall()]

        for row in watermark_rows:
            forensic_data = row.get('forensic_data')
            if not forensic_data:
                continue
            try:
                metadata = json.loads(forensic_data)
            except (TypeError, json.JSONDecodeError):
                continue

            if metadata.get('file_sha256') == suspect_hash:
                conn.close()
                return jsonify({
                    'success': True,
                    'leaked_by': row['employee_email'],
                    'name': row['employee_name'],
                    'matched_pdf': row['document_name'],
                    'confidence': '100%',
                    'detection_method': 'SHA256_File_Fingerprint',
                    'forensic_data': {
                        'suspect_hash': suspect_hash,
                        'matched_hash': metadata.get('file_sha256')
                    }
                })
        
        # Step 1: Extract watermark from PDF using LSB steganography
        success, extraction = detect_watermark_in_pdf(temp_path)
        
        if not success or not extraction:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'No encrypted watermark detected in PDF. If this PDF was watermarked before today\'s engine update, regenerate the watermark and test again.'
            })
        
        encrypted_watermark = extraction.get('encrypted_watermark')
        
        # Step 2: Try to match against all known employees
        cursor.execute('SELECT email, name FROM employees')
        employees = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('SELECT DISTINCT document_name FROM watermark_logs')
        known_pdfs = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        # Prioritize likely filename candidates first to reduce decrypt attempts.
        uploaded_name = filename
        normalized_name = re.sub(r'\s*\(\d+\)(?=\.[^.]+$)', '', uploaded_name)
        candidate_pdfs = []
        for preferred in [uploaded_name, normalized_name]:
            if preferred in known_pdfs and preferred not in candidate_pdfs:
                candidate_pdfs.append(preferred)
        for known_name in known_pdfs:
            if known_name not in candidate_pdfs:
                candidate_pdfs.append(known_name)

        for emp in employees:
            for pdf_name in candidate_pdfs:
                match_success, decrypted = match_watermark_to_employee(
                    encrypted_watermark,
                    emp['email'],
                    pdf_name
                )
                
                if match_success and decrypted:
                    best_match = {
                        'employee_email': emp['email'],
                        'employee_name': emp['name'],
                        'filename': pdf_name,
                        'decrypted_data': decrypted,
                        'confidence': '100%'
                    }
                    # Early exit on first valid decryption match.
                    return jsonify({
                        'success': True,
                        'leaked_by': best_match['employee_email'],
                        'name': best_match['employee_name'],
                        'matched_pdf': best_match['filename'],
                        'decrypted_watermark': best_match['decrypted_data'],
                        'confidence': best_match['confidence'],
                        'detection_method': 'LSB_Steganography_Decryption',
                        'all_matches': [best_match]
                    })
        
        return jsonify({
            'success': False,
            'message': 'Watermark detected but could not match to any employee',
            'extraction_info': extraction
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

@app.route('/api/watermark-pdf', methods=['POST'])
@login_required
def watermark_pdf(): 
    try:
        data = request.json
        employee_ids = data['employee_ids']
        original_pdf = session.get('original_pdf')
        
        if not original_pdf or not os.path.exists(f"uploads/{original_pdf}"):
            return jsonify({'error': 'No PDF uploaded'}), 400
        
        watermarked_files = {}
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()
        
        input_path = f"uploads/{original_pdf}"
        
        for emp_id in employee_ids:
            cursor.execute('SELECT email, name FROM employees WHERE email = ?', (emp_id,))
            emp = cursor.fetchone()
            if not emp:
                continue
                
            emp_email, emp_name = emp
            
            emp_folder = WATERMARKED_FOLDER + '/' + emp_email.replace('@', '_').replace('.', '_')
            os.makedirs(emp_folder, exist_ok=True)
            
            output_path = f"{emp_folder}/{original_pdf}"
            
            # Use LSB steganography to watermark PDF
            success, message, metadata = steg_watermark_pdf(
                input_path,
                emp_email,
                emp_name,
                output_path
            )
            
            if not success:
                return jsonify({'error': f'Watermark failed for {emp_name}: {message}'}), 500

            # Add deterministic file fingerprint for exact-file attribution fallback.
            if metadata is None:
                metadata = {}
            metadata['file_sha256'] = _file_sha256(output_path)
            
            # Store encrypted watermark info in database
            cursor.execute('''
                INSERT INTO watermark_logs (employee_email, employee_name, document_name, watermarked_file, forensic_data)
                VALUES (?, ?, ?, ?, ?)
            ''', (emp_email, emp_name, original_pdf, output_path, json.dumps(metadata)))
            
            watermarked_files[emp_email] = {
                'path': output_path,
                'filename': original_pdf,
                'name': emp_name,
                'watermark_method': 'LSB_Steganography'
            }
        
        conn.commit()
        conn.close()
        session['watermarked_files'] = watermarked_files
        
        return jsonify({
            'success': True,
            'count': len(employee_ids),
            'message': f'{len(employee_ids)} PDFs watermarked using LSB steganography with encryption',
            'method': 'LSB_Steganography'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/send-pdf-emails', methods=['POST'])
@login_required
def send_pdf_emails():
    try:
        data = request.json or {}
        selected_emails = data.get('employee_ids', [])
        custom_message = (data.get('custom_message') or '').strip()
        watermarked_files = session.get('watermarked_files', {})
        
        success_count = 0
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()
        
        for emp_email in selected_emails:
            file_info = watermarked_files.get(emp_email)
            if not file_info or not os.path.exists(file_info['path']):
                continue
            
            msg = Message(
                subject=f'Secure Document - {file_info["filename"]}',
                sender=MAIL_USERNAME,
                recipients=[emp_email],
                body=f'''Dear {file_info["name"]},

{custom_message if custom_message else 'Your personalized secure document is attached.'}'''
            )
            
            with open(file_info['path'], 'rb') as f:
                msg.attach(file_info['filename'], 'application/pdf', f.read())
            
            mail.send(msg)
            success_count += 1
            
            cursor.execute('INSERT INTO email_logs (recipient_email, recipient_name, filename) VALUES (?, ?, ?)',
                          (emp_email, file_info['name'], file_info['filename']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'sent': success_count, 
            'total': len(selected_emails),
            'sender': MAIL_USERNAME
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/source-upload', methods=['POST'])
@login_required
def source_upload():
    try:
        if 'source_file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400

        file = request.files['source_file']
        if file.filename == '' or not allowed_source_file(file.filename):
            return jsonify({'error': 'Invalid source file type'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(SOURCE_UPLOAD_FOLDER, filename)
        file.save(filepath)

        session['original_source'] = filename
        session['original_source_path'] = filepath
        session.modified = True

        return jsonify({
            'success': True,
            'filename': filename,
            'language': detect_language(filename),
            'message': 'Source file uploaded successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/watermark-source', methods=['POST'])
@login_required
def watermark_source_api():
    try:
        data = request.json or {}
        employee_ids = data.get('employee_ids', [])
        original_source = session.get('original_source')
        original_path = session.get('original_source_path')

        if not original_source or not original_path or not os.path.exists(original_path):
            return jsonify({'error': 'No source file uploaded'}), 400

        if not employee_ids:
            return jsonify({'error': 'No employees selected'}), 400

        with open(original_path, 'r', encoding='utf-8', errors='replace') as f:
            source_code = f.read()

        watermarked_files = {}
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()

        for emp_id in employee_ids:
            cursor.execute('SELECT email, name FROM employees WHERE email = ?', (emp_id,))
            emp = cursor.fetchone()
            if not emp:
                continue

            emp_email, emp_name = emp
            wm_code, metadata = watermark_source(
                source_code=source_code,
                filename=original_source,
                employee_id=emp_email,
                employee_name=emp_name,
            )

            emp_folder = os.path.join(
                WATERMARKED_SOURCE_FOLDER,
                emp_email.replace('@', '_').replace('.', '_')
            )
            os.makedirs(emp_folder, exist_ok=True)

            output_path = os.path.join(emp_folder, original_source)
            with open(output_path, 'w', encoding='utf-8', newline='') as wf:
                wf.write(wm_code)

            cursor.execute('''
                INSERT INTO source_watermark_logs
                (employee_email, employee_name, filename, language, watermarked_file, watermark_metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                emp_email,
                emp_name,
                original_source,
                metadata.get('language', 'unknown'),
                output_path,
                json.dumps(metadata)
            ))

            watermarked_files[emp_email] = {
                'path': output_path,
                'filename': original_source,
                'name': emp_name,
                'language': metadata.get('language', 'unknown')
            }

        conn.commit()
        conn.close()

        session['watermarked_source_files'] = watermarked_files
        session.modified = True

        return jsonify({
            'success': True,
            'count': len(watermarked_files),
            'message': f'{len(watermarked_files)} watermarked source files created'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/send-source-emails', methods=['POST'])
@login_required
def send_source_emails():
    try:
        data = request.json or {}
        selected_emails = data.get('employee_ids', [])
        custom_message = (data.get('custom_message') or '').strip()
        watermarked_files = session.get('watermarked_source_files', {})

        success_count = 0
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()

        for emp_email in selected_emails:
            file_info = watermarked_files.get(emp_email)
            if not file_info or not os.path.exists(file_info['path']):
                continue

            msg = Message(
                subject=f'Secure Source File - {file_info["filename"]}',
                sender=MAIL_USERNAME,
                recipients=[emp_email],
                body=f'''Dear {file_info["name"]},

{custom_message if custom_message else 'Your personalized source code file is attached.'}'''
            )

            guessed_type, _ = mimetypes.guess_type(file_info['filename'])
            mimetype = guessed_type or 'text/plain'

            with open(file_info['path'], 'rb') as f:
                msg.attach(file_info['filename'], mimetype, f.read())

            mail.send(msg)
            success_count += 1

            cursor.execute(
                'INSERT INTO email_logs (recipient_email, recipient_name, filename) VALUES (?, ?, ?)',
                (emp_email, file_info['name'], file_info['filename'])
            )

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'sent': success_count,
            'total': len(selected_emails),
            'sender': MAIL_USERNAME
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detect-source-watermark', methods=['POST'])
@login_required
def detect_source_watermark():
    try:
        if 'suspect_source' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['suspect_source']
        if file.filename == '' or not allowed_source_file(file.filename):
            return jsonify({'error': 'Invalid source file type'}), 400

        filename = secure_filename(file.filename)
        source_text = file.read().decode('utf-8', errors='replace')

        extraction = extract_watermark(source_text, filename)
        if extraction.get('confidence', 0) == 0:
            return jsonify({'success': False, 'message': 'No source watermark detected'})

        conn = sqlite3.connect('securetrace.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT email, name FROM employees')
        employees = [dict(row) for row in cursor.fetchall()]
        conn.close()

        matched_employee = None
        for emp in employees:
            if match_employee(extraction, emp['email']):
                matched_employee = emp
                break

        if matched_employee:
            return jsonify({
                'success': True,
                'filename': filename,
                'leaked_by': matched_employee['email'],
                'name': matched_employee['name'],
                'confidence': f"{extraction.get('confidence', 0)}%",
                'layers': extraction.get('layers', {}),
                'emp_hex': extraction.get('emp_hex')
            })

        return jsonify({
            'success': True,
            'filename': filename,
            'leaked_by': 'Unknown employee',
            'name': 'Not matched in employee database',
            'confidence': f"{extraction.get('confidence', 0)}%",
            'layers': extraction.get('layers', {}),
            'emp_hex': extraction.get('emp_hex')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detect-source-photo', methods=['POST'])
@login_required
def detect_source_photo():
    temp_path = None
    try:
        if 'suspect_image' not in request.files:
            return jsonify({'error': 'No image uploaded'}), 400

        file = request.files['suspect_image']
        if file.filename == '' or not allowed_image_file(file.filename):
            return jsonify({'error': 'Invalid image type'}), 400

        source_name_hint = request.form.get('source_name', '').strip()
        guessed_source_name = source_name_hint or 'suspect.py'
        safe_name = secure_filename(file.filename)
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
        temp_path = os.path.join(PHOTO_UPLOAD_FOLDER, f'{ts}_{safe_name}')
        file.save(temp_path)

        analysis = analyze_source_photo(temp_path, guessed_source_name=guessed_source_name)
        if not analysis.get('success'):
            if analysis.get('missing'):
                return jsonify({
                    'success': False,
                    'message': 'Photo OCR dependencies missing',
                    'missing': analysis.get('missing')
                }), 500
            return jsonify({'success': False, 'message': analysis.get('error', 'Photo analysis failed')}), 500

        extraction = analysis.get('extraction', {})
        ws_bits = extraction.get('layers', {}).get('whitespace', {}).get('bits_recovered', 0)
        cm_bits = extraction.get('layers', {}).get('comment', {}).get('bits_recovered', 0)
        if extraction.get('confidence', 0) == 0 and ws_bits < 6 and cm_bits < 2:
            return jsonify({
                'success': False,
                'message': 'No watermark signal detected from OCR output',
                'ocr_chars': analysis.get('ocr_chars', 0),
                'layers': extraction.get('layers', {}),
                'ocr_preview': (analysis.get('ocr_text', '')[:400])
            })

        conn = sqlite3.connect('securetrace.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.employee_email, s.employee_name, s.filename, s.watermarked_file
            FROM source_watermark_logs s
            INNER JOIN (
                SELECT employee_email, filename, MAX(id) AS latest_id
                FROM source_watermark_logs
                GROUP BY employee_email, filename
            ) latest ON latest.latest_id = s.id
        ''')
        candidates = [dict(row) for row in cursor.fetchall()]
        conn.close()

        # STEP 1: Extract watermark signature from OCR'd text
        ocr_text = analysis.get('ocr_text', '')
        ocr_signature = extract_watermark_signature(ocr_text)
        
        best = None
        ranked = []
        
        for c in candidates:
            # STEP 2: Extract signature from candidate's watermarked file
            try:
                with open(c.get('watermarked_file', ''), 'r', encoding='utf-8', errors='replace') as f:
                    candidate_file_text = f.read()
                candidate_signature = extract_watermark_signature(candidate_file_text)
            except (OSError, TypeError):
                candidate_signature = []
            
            # STEP 3: Compare signatures cryptographically (PRIMARY MATCHING)
            signature_confidence = compare_watermark_signatures(ocr_signature, candidate_signature)
            
            # STEP 4: Get traditional scoring metrics as fallback
            score_info = score_employee_match(
                extraction_result=extraction,
                employee_id=c['employee_email'],
                filename_override=c['filename']
            )
            wm_score = score_info['score']
            text_similarity = _source_similarity_score(ocr_text, c.get('watermarked_file', ''))
            
            # SIGNATURE-FIRST RANKING:
            # If signature confidence is high (>=70), use signature as primary metric
            # Otherwise fall back to traditional weighted scoring
            if signature_confidence >= 70:
                # Strong signature match: prioritize this candidate
                combined_score = int(signature_confidence)
                # Add small boost from text for fine-ranking within high-confidence matches
                combined_score = min(100, combined_score + (text_similarity * 0.1))
                detection_method = 'Watermark_Signature_Match'
            else:
                # Weak or no signature match: use traditional 50/50 weighted score
                combined_score = int((wm_score * 0.50) + (text_similarity * 0.50))
                detection_method = 'Traditional_Scoring'

            # Boost for filename hint (only if signature match is weak)
            if signature_confidence < 70 and source_name_hint and c['filename'].lower() == source_name_hint.lower():
                combined_score = min(100, combined_score + 20)
            
            enriched = {
                'email': c['employee_email'],
                'name': c['employee_name'],
                'filename': c['filename'],
                'watermarked_file': c.get('watermarked_file'),
                'score_info': score_info,
                'wm_score': wm_score,
                'text_similarity': text_similarity,
                'signature_confidence': signature_confidence,
                'combined_score': combined_score,
                'detection_method': detection_method,
            }
            ranked.append(enriched)
            if best is None or combined_score > best['combined_score']:
                best = enriched

        ranked.sort(key=lambda x: (-x['combined_score'], -x['signature_confidence'], -x['wm_score']))

        
        top_candidates = [
            {
                'email': r['email'],
                'name': r['name'],
                'filename': r['filename'],
                'score': r['combined_score'],
                'wm_score': r['wm_score'],
                'text_similarity': r['text_similarity'],
                'signature_confidence': r['signature_confidence'],
                'detection_method': r['detection_method'],
                'score_details': r['score_info']
            }
            for r in ranked[:3]
        ]

        if not best:
            return jsonify({'success': False, 'message': 'No source watermark candidates found in logs'})

        score_info = best['score_info']
        score = best['combined_score']
        has_min_evidence = (
            score_info.get('ws_total', 0) >= 6
            or score_info.get('cm_total', 0) >= 3
            or score_info.get('cm_match_len', 0) >= 3
        )
        strong_comment_match = (
            score_info.get('cm_match_len', 0) >= 3 and score_info.get('cm_ratio', 0) >= 0.66
        )
        second_score = ranked[1]['combined_score'] if len(ranked) > 1 else 0
        margin = score - second_score
        if ((score < 35 and not strong_comment_match) or not has_min_evidence) and margin < 6:
            return jsonify({
                'success': False,
                'message': 'Attribution confidence too low from photo OCR',
                'best_candidate': {
                    'email': best['email'],
                    'name': best['name'],
                    'filename': best['filename'],
                    'score': score,
                    'wm_score': best['wm_score'],
                    'text_similarity': best['text_similarity'],
                    'score_details': score_info
                },
                'ocr_chars': analysis.get('ocr_chars', 0),
                'layers': extraction.get('layers', {}),
                'ocr_preview': (analysis.get('ocr_text', '')[:400]),
                'top_candidates': top_candidates
            })

        return jsonify({
            'success': True,
            'mode': 'photo_ocr',
            'leaked_by': best['email'],
            'name': best['name'],
            'matched_source': best['filename'],
            'confidence': f"{score}%",
            'decision_margin': margin,
            'wm_score': best['wm_score'],
            'text_similarity': best['text_similarity'],
            'score_details': best['score_info'],
            'top_candidates': top_candidates,
            'layers': extraction.get('layers', {}),
            'ocr_chars': analysis.get('ocr_chars', 0),
            'ocr_preview': (analysis.get('ocr_text', '')[:400])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


if __name__ == '__main__':
    app.run(debug=True)
