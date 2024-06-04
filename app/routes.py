from functools import wraps
from mailbox import Message
from flask import Blueprint, request, jsonify, session, flash, redirect, url_for, render_template
from flask_login import current_user, login_required, login_user, logout_user
from app.utils import compute_exam_id, decrypt_with_private_key, encrypt_with_public_key, sign_data, verify_signature
from .models import User, Exam, db
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from werkzeug.security import check_password_hash
import json
from .models import Exam, User
from . import db
from flask import jsonify
from flask import request, render_template, redirect, url_for, flash
from app import app, db
from app.models import Exam
import datetime
import pyotp
import uuid
import bcrypt 
from flask_mail import Message
from app import mail 

main = Blueprint('main', __name__)

@main.route('/')
def login():
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('main.login'))

    # Generate a new session ID
    new_session_id = str(uuid.uuid4())
    user.session_id = new_session_id
    db.session.commit()  # Commit the changes to save the new session ID

    # Generate OTP and save to user and session
    otp_secret = user.get_otp_secret()  # Ensure OTP secret is saved in the user model
    otp = pyotp.TOTP(otp_secret)
    otp_code = otp.now()

    # Save OTP secret and session ID in session
    session['otp_secret'] = otp_secret
    session['otp_timestamp'] = datetime.datetime.now().timestamp()
    session['user_id'] = user.id
    session['session_id'] = new_session_id

    # Send OTP via email
    msg = Message('Your Login OTP', recipients=[user.email])
    msg.body = f'Your OTP code is: {otp_code}'
    mail.send(msg)

    return redirect(url_for('auth.verify_otp'))

@main.route('/verify_email/<token>')
def verify_email(token):
    user = User.verify_reset_token(token)
    if user:
        user.is_verified = True
        db.session.commit()
        # Redirect the user to auth.verify_otp
        return redirect(url_for('auth.verify_otp'))
    else:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('main.login'))

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')  # Get the role from the form

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('main.signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user = User(email=email, password=hashed_password, role=role, is_verified=False)
        db.session.add(user)
        db.session.commit()  # Commit first to get the user ID
        
        # Generate key pair
        user.generate_key_pair()
        db.session.commit()  # Commit again to save the keys

        # Send verification email
        token = user.get_reset_token()
        verify_url = url_for('main.verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', recipients=[user.email])
        msg.body = f'Please click the link to verify your email: {verify_url}'
        mail.send(msg)

        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html')


# Remaining routes and functions...

def session_protected(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        user = current_user
        if user.is_authenticated and user.session_id != session.get('session_id'):
            flash('Your session is invalid or expired. Please log in again.', 'danger')
            logout_user()
            return redirect(url_for('auth.login'))
        return func(*args, **kwargs)
    return decorated_view

@main.route('/dashboard')
@login_required
@session_protected
def dashboard():
    if current_user.role == 'teacher':
        return render_template('dashboard.html',
    name=current_user.email)
    elif current_user.role == 'student':
        return render_template('student_dashboard.html', name=current_user.email)
    else:
        return render_template('dashboard.html', name=current_user.email)


@main.route('/create_exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    if request.method == 'POST':
        # Gather form data
        title = request.form.get('title')
        description = request.form.get('description')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        duration = request.form.get('duration')
        subject_name = request.form.get('subject_name')
        subject_code = request.form.get('subject_code')
        semester = request.form.get('semester')
        exam_date = request.form.get('exam_date')
        fixed_time = request.form.get('fixed_time')

        # Convert start_time and end_time to datetime objects
        try:
            start_time = datetime.datetime.fromisoformat(start_time_str)
            end_time = datetime.datetime.fromisoformat(end_time_str)
        except ValueError as e:
            flash('Invalid date format', 'danger')
            return redirect(url_for('main.create_exam'))

        # Process questions and options
        questions_list = request.form.getlist('questions[]')
        options_list = request.form.getlist('options[]')
        correct_answers_list = request.form.getlist('correct_answers[]')

        if not (questions_list and options_list):
            flash('Questions and options are required', 'danger')
            return redirect(url_for('main.create_exam'))

        exam_data = []
        for i, question_text in enumerate(questions_list):
            question_data = {
                "text": question_text,
                "options": options_list[i].split(',') if options_list and i < len(options_list) else [],
                "correct_answers": correct_answers_list[i].split(',') if correct_answers_list and i < len(correct_answers_list) else []
            }
            exam_data.append(question_data)

        exam_json = json.dumps(exam_data)

        # Generate exam ID
        exam_id = compute_exam_id(subject_name, subject_code, semester, exam_date, fixed_time, 1) 

        # Sign exam data
        teacher_private_key = current_user.get_private_key()
        data_to_sign = f"{exam_id}{exam_json}"
        digital_signature = sign_data(teacher_private_key, data_to_sign)

        # Encrypt exam data with the manager's public key
        manager_user = User.query.filter_by(role='manager').first()
        manager_public_key = manager_user.get_public_key()

        # Ensure data_to_encrypt is properly formatted and encoded
        data_to_encrypt = f"{exam_id}{exam_json}{digital_signature.hex()}"
        
        try:
            # Encrypt the data using the public key
            encrypted_aes_key, encrypted_data  = encrypt_with_public_key(manager_public_key, data_to_encrypt)
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('main.create_exam'))

        # Store encrypted data in the database
        exam = Exam(
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            questions=exam_json,
            encrypted_aes_key=encrypted_aes_key.hex(),
            encrypted_data=encrypted_data.hex(),  # Ensure it's stored as hexadecimal string
            digital_signature=digital_signature.hex()
        )

        try:
            db.session.add(exam)
            db.session.commit()
            flash('Exam created successfully', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error committing to database: {e}")
            flash('Error creating exam', 'danger')

        return redirect(url_for('main.dashboard'))

    return render_template('dashboard.html')
# Add other route functions below...

@main.route('/decrypt_exam/<int:exam_id>', methods=['GET'])
@login_required
def decrypt_exam(exam_id):
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized access'}), 403

    exam = Exam.query.get_or_404(exam_id)
    encrypted_data = bytes.fromhex(exam.encrypted_data)
    signature = bytes.fromhex(exam.digital_signature)

    # Decrypt the exam content using the manager's private key
    private_key = current_user.get_private_key()
    decrypted_content = decrypt_with_private_key(private_key, encrypted_data)
    
    # Extract the exam content and verify the signature
    content_and_signature = decrypted_content.rsplit(signature, 1)
    if len(content_and_signature) != 2:
        return jsonify({'message': 'Decryption failed'}), 400

    exam_content_json, received_signature = content_and_signature
    exam_content = json.loads(exam_content_json)
    teacher = User.query.filter_by(email=exam_content['teacher_email']).first()
    if not teacher:
        return jsonify({'message': 'Teacher not found'}), 404
    teacher_public_key = teacher.get_public_key()

    if verify_signature(teacher_public_key, signature, exam_content_json):
        return jsonify({'exam_content': exam_content, 'signature_verified': True}), 200
    else:
        return jsonify({'message': 'Signature verification failed'}), 400



@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
