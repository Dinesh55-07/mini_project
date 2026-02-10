from pdf2image import convert_from_path
from PIL import Image
from cryptography.fernet import Fernet
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
from datetime import datetime

def encrypt_watermark(emp_id):
    """Encrypt employee ID as watermark"""
    key = Fernet.generate_key()
    f = Fernet(key)
    data = f"EMP:{emp_id}|{datetime.now().strftime('%Y%m%d%H%M%S')}".encode()
    return key, f.encrypt(data)[:100]  

def embed_watermark(img_path, watermark_bytes):
    """Embed watermark in image LSB"""
    img = Image.open(img_path)
    pixels = list(img.getdata())
    binary_wm = ''.join(format(b, '08b') for b in watermark_bytes)
    
    new_pixels = []
    wm_idx = 0
    for pixel in pixels:
        if wm_idx < len(binary_wm):
            r, g, b = pixel
            bit = int(binary_wm[wm_idx])
            r = (r & 0xFE) | bit  
            new_pixels.append((r, g, b))
            wm_idx += 1
        else:
            new_pixels.append(pixel)
    
    img.putdata(new_pixels)
    return img

def images_to_pdf(img_paths, output_path):
    """Convert list of images to PDF"""
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    
    for img_path in img_paths:
        if os.path.exists(img_path):
            img = Image.open(img_path)
            img_width, img_height = img.size
            
            # Scale to fit page
            scale = min(width * 0.9 / img_width, height * 0.9 / img_height)
            img_width *= scale
            img_height *= scale
            
            x = (width - img_width) / 2
            y = (height - img_height) / 2
            
            c.drawImage(img_path, x, y, img_width, img_height)
            c.showPage()
    
    c.save()

def send_watermarked_email(recipient_email, recipient_name, emp_id, pdf_path):
    """Send watermarked PDF via Gmail"""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    
    # Config from app
    from app import app
    config = app.config['MAIL_CONFIG']
    
    try:
        msg = MIMEMultipart()
        msg['From'] = config['smtp_email']
        msg['To'] = recipient_email
        msg['Subject'] = f'🔐 SecureTrace: Watermarked Document - {emp_id}'
        
        body = f"""
Dear {recipient_name},

Your document has been watermarked with your Employee ID: {emp_id}

✅ Embedded using steganography (invisible watermark)
✅ If leaked, source can be traced back to you
✅ File: {os.path.basename(pdf_path)}

SecureTrace Team
        """
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach PDF
        with open(pdf_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(pdf_path)}'
            )
            msg.attach(part)
        
        # Send
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_email'], config['smtp_password'])
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email sent: {recipient_email}")
        return True
        
    except Exception as e:
        print(f"❌ Email failed {recipient_email}: {e}")
        return False
