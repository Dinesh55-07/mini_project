from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    def __repr__(self):
        return f'<Employee {self.emp_id}: {self.name}>'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='watermarked')
    watermarked_path = db.Column(db.String(300))

def create_sample_employees():
    if Employee.query.count() == 0:
        employees = [
            Employee(emp_id='EMP001', name='Rahul Kumar', email='rahul.kumar@example.com'),
            Employee(emp_id='EMP002', name='Priya Singh', email='priya.singh@example.com'),
            Employee(emp_id='EMP003', name='Amit Patel', email='amit.patel@example.com'),
            Employee(emp_id='EMP004', name='Neha Sharma', email='neha.sharma@example.com'),
            Employee(emp_id='EMP005', name='Vikram Reddy', email='vikram.reddy@example.com'),
        ]
        for emp in employees:
            db.session.add(emp)
        db.session.commit()
        print("✅ 5 sample employees created!")
