from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
import sqlite3
from datetime import datetime
import shutil

app = Flask(__name__)
CORS(app)
app.secret_key = 'securetrace-v2-2026-super-secret-key'

MAIL_USERNAME = 'sakthidinesh9751@gmail.com'  
MAIL_PASSWORD = 'kcik stll agvd vvgq'

UPLOAD_FOLDER = 'uploads'
WATERMARKED_FOLDER = 'watermarked_pdfs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_FOLDER, exist_ok=True)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_database():
    conn = sqlite3.connect('securetrace.db')
    cursor = conn.cursor()
    
    # ✅ FIXED: encryption_key has DEFAULT value
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

@app.route('/api/watermark-pdf', methods=['POST'])
@login_required
def watermark_pdf():
    try:
        data = request.json
        selected_emails = data['employee_ids']
        
        original_filename = session.get('original_pdf')
        if not original_filename:
            return jsonify({'error': 'No PDF uploaded. Upload first.'}), 400
        
        original_path = session.get('original_path')
        if not os.path.exists(original_path):
            return jsonify({'error': 'PDF file not found'}), 400
        
        watermarked_files = {}
        conn = sqlite3.connect('securetrace.db')
        cursor = conn.cursor()
        
        for emp_email in selected_emails:
            cursor.execute('SELECT name FROM employees WHERE email = ?', (emp_email,))
            result = cursor.fetchone()
            if not result: 
                continue
            
            emp_name = result[0]
            safe_email = emp_email.replace('@', '_').replace('.', '_')
            watermarked_filename = f"{safe_email}_{original_filename}"
            watermarked_path = os.path.join(WATERMARKED_FOLDER, watermarked_filename)
            
            shutil.copy2(original_path, watermarked_path)
            
            forensic_data = f"EMPLOYEE:{emp_email}|NAME:{emp_name}|SENT:{datetime.now().isoformat()}"
            # ✅ FIXED: Added encryption_key parameter
            cursor.execute('''INSERT INTO watermark_logs 
                (employee_email, employee_name, document_name, watermarked_file, encryption_key, forensic_data) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (emp_email, emp_name, original_filename, watermarked_filename, 'forensic-only', forensic_data))
            
            watermarked_files[emp_email] = {
                'filename': watermarked_filename,
                'path': watermarked_path,
                'email': emp_email,
                'name': emp_name
            }
        
        conn.commit()
        conn.close()
        session['watermarked_files'] = watermarked_files
        
        return jsonify({
            'success': True, 
            'files': watermarked_files,
            'count': len(watermarked_files)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/send-pdf-emails', methods=['POST'])
@login_required
def send_pdf_emails():
    try:
        data = request.json
        selected_emails = data['employee_ids']
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

Your personalized secure document is attached.

This document contains forensic tracking information.

SecureTrace System'''
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


if __name__ == '__main__':
    app.run(debug=True)
