from functools import wraps
from mailbox import Message
import timeit
from flask import Blueprint, request, jsonify, session, flash, redirect, url_for, render_template
from flask_login import current_user, login_required, login_user, logout_user
from app.utils import compute_exam_id, decrypt_with_private_key, encrypt_with_public_key, sign_data, verify_signature
from .models import Submission, User, Exam, db
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from werkzeug.security import check_password_hash
import json
from .models import Exam, User
from datetime import datetime
from . import db
from flask import jsonify
from flask import request, render_template, redirect, url_for, flash
import bleach
from app import app, db
from app.models import Exam
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
    email = bleach.clean(request.form.get('email'))
    password = bleach.clean(request.form.get('password'))
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('main.login'))

    new_session_id = str(uuid.uuid4())
    user.session_id = new_session_id
    session['logged_in'] = True
    db.session.commit()

    otp_secret = user.get_otp_secret()  
    otp = pyotp.TOTP(otp_secret)
    otp_code = otp.now()

    session['otp_secret'] = otp_secret
    session['otp_timestamp'] = datetime.now().timestamp()
    session['user_id'] = user.id
    session['session_id'] = new_session_id

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

        return redirect(url_for('auth.verify_otp'))
    else:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('main.login'))

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = bleach.clean(request.form.get('email'))
        password = bleach.clean(request.form.get('password'))
        confirm_password = bleach.clean(request.form.get('confirm_password'))
        role = bleach.clean(request.form.get('role'))
    
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('main.signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user = User(email=email, password=hashed_password, role=role, is_verified=False)
        db.session.add(user)
        db.session.commit() 
        
        user.generate_key_pair()
        db.session.commit()  

        token = user.get_reset_token()
        verify_url = url_for('main.verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', recipients=[user.email])
        msg.body = f'Please click the link to verify your email: {verify_url}'
        mail.send(msg)

        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html')


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
        return render_template('student_dashboard.html', name=current_user.email,available_exams=get_available_exams())
    else:
        return render_template('manager_dashboard.html', name=current_user.email, pending_exams=get_pending_exams())

def get_available_exams():
    available_exams = Exam.query.filter_by(is_approved=True).all()
    return available_exams

def get_pending_exams():
    pending_exams = Exam.query.filter_by(is_approved=False).all()
    return pending_exams

@main.route('/view_available_exams')
@login_required
@session_protected
def view_available_exams():
    available_exams = get_available_exams()
    print("Available Exams:", available_exams)  # Debug statement
    return render_template('available_exams.html', available_exams=available_exams)


@main.route('/view_pending_exams')
@login_required
@session_protected
def view_pending_exams():
    pending_exams = get_pending_exams()
    return render_template('pending_exams.html', pending_exams=pending_exams)


@main.route('/create_exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    if request.method == 'POST':
        title = bleach.clean(request.form.get('title'))
        description = bleach.clean(request.form.get('description'))
        start_time_str = bleach.clean(request.form.get('start_time'))
        end_time_str = bleach.clean(request.form.get('end_time'))
        duration = bleach.clean(request.form.get('duration'))
        subject_name = bleach.clean(request.form.get('subject_name'))
        subject_code = bleach.clean(request.form.get('subject_code'))
        semester = bleach.clean(request.form.get('semester'))
        exam_date_str = bleach.clean(request.form.get('exam_date'))
        fixed_time = bleach.clean(request.form.get('fixed_time'))

        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
            exam_date = datetime.strptime(exam_date_str, '%Y-%m-%d')
        except ValueError as e:
            flash('Invalid date format', 'danger')
            return redirect(url_for('main.create_exam'))

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
        data_size = len(exam_json)
        print("Data size = ", data_size)

        exam_id = compute_exam_id(subject_name, subject_code, semester, exam_date, fixed_time, 1)
        if not exam_id:
            flash('Failed to generate exam ID', 'danger')
            return redirect(url_for('main.create_exam'))

        teacher_private_key = current_user.get_private_key()
        data_to_sign = f"{exam_id}{exam_json}"
        digital_signature = sign_data(teacher_private_key, data_to_sign)

        manager_user = User.query.filter_by(role='manager').first()
        manager_public_key = manager_user.get_public_key()

        delimiter = "||SIGNATURE||"
        data_to_encrypt = f"{exam_id}{delimiter}{exam_json}{delimiter}{digital_signature.hex()}"

        try:
            encrypted_aes_key, encrypted_data = encrypt_with_public_key(manager_public_key, data_to_encrypt)
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('main.create_exam'))

        exam = Exam(
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            encrypted_aes_key=encrypted_aes_key.hex(),
            encrypted_data=encrypted_data.hex(),
            digital_signature=digital_signature.hex(),
            subject_name=subject_name,
            subject_code=subject_code,
            semester=semester,
            exam_date=exam_date,
            computed_exam_id=exam_id
        )

        try:
            db.session.add(exam)
            db.session.commit()
            flash('Exam created successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error creating exam', 'danger')

        return redirect(url_for('main.dashboard'))

    return render_template('dashboard.html')


@main.route('/decrypt_exam/<int:exam_id>', methods=['GET'])
@login_required
def decrypt_exam(exam_id):
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized access'}), 403

    exam = Exam.query.get_or_404(exam_id)
    encrypted_data = bytes.fromhex(exam.encrypted_data)
    encrypted_aes_key = bytes.fromhex(exam.encrypted_aes_key)
    signature = bytes.fromhex(exam.digital_signature)

    private_key = current_user.get_private_key()
    start_time = timeit.default_timer()  
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    iv = encrypted_data[:16]  
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    decrypted_str = decrypted_content.decode('utf-8')
    delimiter = "||SIGNATURE||"
    try:
        exam_id_str, remaining_content = decrypted_str.split(delimiter, 1)
        exam_json_str, received_signature_hex = remaining_content.rsplit(delimiter, 1)
        received_signature = bytes.fromhex(received_signature_hex)
    except ValueError:
        return jsonify({'message': 'Decryption failed, incorrect format'}), 400

    if received_signature != signature:
        return jsonify({'message': 'Decryption failed, signature mismatch'}), 400

    try:
        exam_content = json.loads(exam_json_str)
    except json.JSONDecodeError as e:
        print("JSON Decode Error:", e)
        return jsonify({'message': 'Error decoding exam JSON'}), 400

    end_time = timeit.default_timer() 
    decryption_time = end_time - start_time
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    return jsonify({'exam_content': exam_content, 'signature_verified': True}), 200


@main.route('/request_exam/<int:exam_id>', methods=['GET'])
@login_required
def request_exam(exam_id):
    if current_user.role != 'student':
        return jsonify({'message': 'Unauthorized access'}), 403

    exam = Exam.query.get_or_404(exam_id)
    encrypted_data = bytes.fromhex(exam.encrypted_for_student)
    encrypted_aes_key = bytes.fromhex(exam.encrypted_aes_key_for_student)
    signature = bytes.fromhex(exam.signature_student)

    private_key = current_user.get_private_key()
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    iv = encrypted_data[:16]  
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    decrypted_str = decrypted_content.decode('utf-8')
    delimiter = "||SIGNATURE||"
    try:
        exam_id_str, remaining_content = decrypted_str.split(delimiter, 1)
        exam_json_str, received_signature_hex = remaining_content.rsplit(delimiter, 1)
        received_signature = bytes.fromhex(received_signature_hex)
    except ValueError:
        return jsonify({'message': 'Decryption failed, incorrect format'}), 400

    if received_signature != signature:
        return jsonify({'message': 'Decryption failed, signature mismatch'}), 400

    try:
        exam_content = json.loads(exam_json_str)
    except json.JSONDecodeError as e:
        print("JSON Decode Error:", e)
        return jsonify({'message': 'Error decoding exam JSON'}), 400

    for question in exam_content:
        question.pop("correct_answers", None)
        question.setdefault("options", [])  

    return render_template('take_exam.html', exam_content=exam_content, exam_id=exam_id)


@main.route('/submit_exam', methods=['POST'])
@login_required
def submit_exam():
   
    answers = bleach.clean(request.form.getlist('answers[]'))
    exam_id = bleach.clean(request.form.get('exam_id'))

    submission = Submission(user_id=current_user.id, exam_id=exam_id, answers=json.dumps(answers))
    db.session.add(submission)
    db.session.commit()

    flash('Exam submitted successfully!', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    logout_user()
    return redirect(url_for('main.login'))

# Error handling
@main.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@main.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@main.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['X-Frame-Options'] = 'DENY'

    return response