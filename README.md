# SecureTrace Forensic Platform

SecureTrace is a Flask-based forensic watermarking platform for tracking document and source-code leaks. It supports:

- PDF watermarking and leak attribution
- Source-code watermarking and leak attribution
- Photo/screenshot-based source leak attribution using OCR
- Employee management and email delivery workflows

The system is designed for controlled leak investigations where each employee receives a uniquely watermarked artifact.

## Table of Contents

- Overview
- Key Features
- Tech Stack
- Project Structure
- How It Works
- Installation
- Configuration
- Running the App
- Authentication
- API Endpoints
- OCR Photo Forensics Notes
- Database Schema
- Troubleshooting
- Security Notes
- Future Improvements

## Overview

SecureTrace embeds employee-specific forensic fingerprints into files and later attempts attribution from suspected leaked content.

For source code, two watermark channels are used:

1. Trailing whitespace pattern bits
2. Micro comment-variant bits (e.g., subtle note/review style changes)

For photo-based detection, the platform extracts text via OCR and then performs combined scoring:

- watermark similarity score
- source text similarity score

## Key Features

- Employee registry with SQLite persistence
- PDF watermarking and PDF leak detection
- Source-code watermarking for common programming languages
- OCR-based photo/screenshot source detection
- Candidate ranking with confidence and score breakdown
- UI pages for send/detect workflows
- Animated UI headings via reusable decrypted-text component

## Tech Stack

Backend:

- Python
- Flask
- Flask-CORS
- Flask-Mail
- SQLite

Forensics and OCR:

- pytesseract
- Tesseract OCR (native binary)
- OpenCV (cv2)
- Pillow
- NumPy

Frontend:

- Jinja2 templates
- Vanilla JavaScript
- CSS

## Project Structure

```text
mini/
  app.py
  source_watermark_engine.py
  photo_source_forensics.py
  utils.py
  securetrace.db
  static/
    style.css
    decrypted-text.js
  templates/
    base.html
    dashboard.html
    employees.html
    login.html
    index.html
    pdf_send.html
    pdf_detect.html
    pdf_watermarking.html
    source_send.html
    source_detect.html
    source_watermarking.html
  uploads/
    source/
  watermarked_pdfs/
  watermarked_sources/
  temp_images/
  leaks/
```

## How It Works

### 1) Watermarking

- Admin uploads a source file or PDF
- Admin selects one or more employees
- SecureTrace generates unique employee-specific watermark variants
- Watermarked files are stored and logged in SQLite

### 2) Detection

- Suspected leaked file or photo is uploaded
- Platform extracts forensic signals
- Candidate employees are scored
- Top candidate and confidence details are returned

### 3) Photo OCR Detection (Source)

- Image preprocessing (OpenCV/Pillow)
- OCR extraction (pytesseract/Tesseract)
- OCR cleanup
- Watermark extraction and employee scoring
- Content-similarity fallback ranking

## Installation

### Prerequisites

- Python 3.10+
- Windows/macOS/Linux
- Tesseract OCR installed on host machine

### 1) Clone and open the project

```bash
git clone <your-repo-url>
cd mini
```

### 2) Create and activate virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3) Install Python dependencies

```bash
pip install flask flask-cors flask-mail werkzeug pytesseract opencv-python pillow numpy
```

### 4) Install Tesseract OCR

- Install Tesseract on your machine
- Ensure `tesseract` is available in PATH, or set environment variable:

Windows PowerShell:

```powershell
$env:TESSERACT_CMD = "C:\Path\To\Tesseract-OCR\tesseract.exe"
```

The app also attempts auto-discovery in common Windows install paths.

## Configuration

Current app-level config is in `app.py`:

- Flask secret key
- Mail server settings (Gmail SMTP)
- Allowed file extensions
- Upload and output folders
- Default login credentials

Important variables currently present in code:

- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `VALID_USER`
- `VALID_PASS`

For production, move secrets to environment variables.

## Running the App

```bash
python app.py
```

Default URL:

- `http://127.0.0.1:5000`

## Authentication

Default login configured in app:

- Username: `admin`
- Password: `securetrace123`

## API Endpoints

### Page Routes

- `GET /`
- `GET|POST /login`
- `GET /logout`
- `GET /dashboard`
- `GET|POST /employees`
- `GET /pdf-watermarking`
- `GET /source-watermarking`
- `GET /pdf-send`
- `GET /pdf-detect`
- `GET /source-send`
- `GET /source-detect`

### API Routes

- `POST /api/pdf-upload`
- `POST /api/watermark-pdf`
- `POST /api/send-pdf-emails`
- `POST /api/detect-pdf-watermark`
- `POST /api/source-upload`
- `POST /api/watermark-source`
- `POST /api/send-source-emails`
- `POST /api/detect-source-watermark`
- `POST /api/detect-source-photo`

## OCR Photo Forensics Notes

Photo attribution is inherently noisy versus direct file detection.

Why false or low-confidence outcomes can occur:

- Camera blur, glare, perspective distortion
- OCR misreads punctuation and spacing
- Trailing-whitespace watermark channel is fragile after OCR
- Two candidate files can be textually very similar

Recommended policy for real deployments:

- Treat low-confidence OCR outputs as inconclusive
- Prefer direct source-file detection when available
- Use source filename hint when possible
- Require confidence and margin thresholds before attribution

## Database Schema

Database file:

- `securetrace.db`

Main tables:

- `employees`
- `watermark_logs` (PDF-oriented logs)
- `email_logs`
- `source_watermark_logs`

`source_watermark_logs` stores candidate comparison data, including:

- employee identity
- filename/language
- watermarked source path
- metadata and timestamp

## Troubleshooting

### OCR dependency errors

Symptoms:

- photo detection returns missing dependencies

Checks:

- `pip show pytesseract opencv-python pillow numpy`
- Confirm Tesseract executable path and permissions

### Wrong source attribution from photo

Checks:

- Ensure image quality is high (sharp, front-facing, minimal glare)
- Include source filename hint in UI
- Verify candidate watermarked files exist on disk
- Validate confidence and decision margin before trusting result

### Mail send issues

Checks:

- SMTP credentials
- Gmail app password usage
- firewall/port restrictions for TLS 587

## Security Notes

Current code contains hardcoded credentials and secrets for local development convenience.

Before production use:

- Move secrets to environment variables
- Rotate any exposed credentials
- Disable debug mode
- Add role-based access control
- Add request rate limiting and audit logging

## Future Improvements

- Add strict inconclusive mode for low-confidence OCR attribution
- Add robust OCR ensemble and confidence fusion
- Add unit/integration test suite and CI pipeline
- Add migrations and schema versioning
- Add Docker deployment setup
- Add REST API auth tokens for programmatic access

---

If you are integrating this project with another AI model, start from:

1. `app.py` for routes and orchestration
2. `source_watermark_engine.py` for watermark encoding/decoding and scoring
3. `photo_source_forensics.py` for OCR preprocessing and extraction pipeline
