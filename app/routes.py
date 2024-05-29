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
import datetime
import pyotp
import uuid
import bcrypt 
from flask_mail import Mail
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
        db.session.commit()

        # Send verification email
        token = user.get_reset_token()
        verify_url = url_for('main.verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', to=[user.email])
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
    return render_template('dashboard.html', name=current_user.email)

@main.route('/create_exam', methods=['POST'])
@login_required
def create_exam():
    if current_user.role != 'teacher':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()
    exam_id = compute_exam_id(
        data['subject_name'], data['subject_code'], data['semester'], 
        data['exam_date'], data['fixed_time'], data['exam_serial_number']
    )
    exam_questions = data['questions']

    # Create exam content to be signed and encrypted
    exam_content = {'exam_id': exam_id, 'questions': exam_questions, 'teacher_email': current_user.email}
    exam_content_json = json.dumps(exam_content)

    # Sign the exam content
    private_key = current_user.get_private_key()
    signature = sign_data(private_key, exam_content_json)

    # Encrypt the exam content and signature with the manager's public key
    manager = User.query.filter_by(role='manager').first()
    if not manager:
        return jsonify({'message': 'Manager not found'}), 404
    manager_public_key = manager.get_public_key()
    encrypted_data = encrypt_with_public_key(manager_public_key, exam_content_json + signature.hex())

    exam = Exam(
        title=data['title'],
        description=data['description'],
        start_time=data['start_time'],
        end_time=data['end_time'],
        duration=data['duration'],
        encrypted_data=encrypted_data.hex(),
        digital_signature=signature.hex()
    )

    db.session.add(exam)
    db.session.commit()

    return jsonify({'message': 'Exam created successfully'}), 201


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
    content_and_signature = decrypted_content.rsplit(signature.hex(), 1)
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
