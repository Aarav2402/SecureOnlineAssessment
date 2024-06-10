from functools import wraps
from mailbox import Message
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
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('main.login'))

    # Generate a new session ID
    new_session_id = str(uuid.uuid4())
    user.session_id = new_session_id
    db.session.commit()

    # Generate OTP and save to user and session
    otp_secret = user.get_otp_secret()  # Ensure OTP secret is saved in the user model
    otp = pyotp.TOTP(otp_secret)
    otp_code = otp.now()

    # Save OTP secret and session ID in session
    session['otp_secret'] = otp_secret
    session['otp_timestamp'] = datetime.now().timestamp()
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
        role = request.form.get('role') 

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('main.signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user = User(email=email, password=hashed_password, role=role, is_verified=False)
        db.session.add(user)
        db.session.commit() 
        
        # Generate key pair
        user.generate_key_pair()
        db.session.commit()  

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
        title = request.form.get('title')
        description = request.form.get('description')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        duration = request.form.get('duration')
        subject_name = request.form.get('subject_name')
        subject_code = request.form.get('subject_code')
        semester = request.form.get('semester')
        exam_date_str = request.form.get('exam_date')
        fixed_time = request.form.get('fixed_time')

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

    # Decrypt the AES key using the manager's private key
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
        print("Error decrypting AES key:", e)
        return jsonify({'message': str(e)}), 400

    # Decrypt the exam content using AES key
    iv = encrypted_data[:16]  # Assuming IV is the first 16 bytes
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Separate the exam_id, exam_json, and digital signature
    decrypted_str = decrypted_content.decode('utf-8')
    delimiter = "||SIGNATURE||"
    try:
        exam_id_str, remaining_content = decrypted_str.split(delimiter, 1)
        exam_json_str, received_signature_hex = remaining_content.rsplit(delimiter, 1)
        received_signature = bytes.fromhex(received_signature_hex)
    except ValueError as e:
        print("Error separating content:", e)
        return jsonify({'message': 'Decryption failed, incorrect format'}), 400

    # Check if the separated signature matches the stored signature
    if received_signature != signature:
        return jsonify({'message': 'Decryption failed, signature mismatch'}), 400

    # Parse the exam JSON content
    try:
        exam_content = json.loads(exam_json_str)
    except json.JSONDecodeError as e:
        print("JSON Decode Error:", e)
        return jsonify({'message': 'Error decoding exam JSON'}), 400

    # Fetch teacher email from the Exam model or a related model
    teacher = User.query.filter_by(role='teacher').first()  # Assuming there's a teacher_id field
    if not teacher:
        return jsonify({'message': 'Teacher not found'}), 404
    teacher_public_key = teacher.get_public_key()

    if verify_signature(teacher_public_key, signature, exam_id_str + exam_json_str):
        exam = Exam.query.get(exam_id)
        if exam:
            exam.is_approved = True
            db.session.commit()
        else:
            print("Exam not found")

        manager_private_key = current_user.get_private_key()

        # Sign the exam_id and exam_json
        data_to_sign = exam_id_str + exam_json_str
        digital_signature_student = sign_data(manager_private_key, data_to_sign)

        # Encrypt the data with student's public key
        student_user = User.query.filter_by(role='student').first()
        if not student_user:
            return jsonify({'message': 'Student not found'}), 404

        student_public_key = student_user.get_public_key()

        # Concatenate exam_id, exam_json, and digital signature for encryption
        data_to_encrypt = f"{exam_id_str}{delimiter}{exam_json_str}{delimiter}{digital_signature_student.hex()}"

        # Encrypt data for student
        try:
            encrypted_aes_key_student, encrypted_data_student = encrypt_with_public_key(student_public_key, data_to_encrypt)
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('main.create_exam'))

        # Update exam record with encrypted data for student
        exam.encrypted_for_student = encrypted_data_student.hex()
        exam.encrypted_aes_key_for_student = encrypted_aes_key_student.hex()
        exam.signature_student = digital_signature_student.hex()
        db.session.commit()
        return jsonify({'exam_content': exam_content, 'signature_verified': True}), 200
    else:
        return jsonify({'message': 'Signature verification failed'}), 400
    

@main.route('/request_exam/<int:exam_id>', methods=['GET'])
@login_required
def request_exam(exam_id):
    if current_user.role != 'student':
        return jsonify({'message': 'Unauthorized access'}), 403

    exam = Exam.query.get_or_404(exam_id)
    encrypted_data = bytes.fromhex(exam.encrypted_for_student)
    encrypted_aes_key = bytes.fromhex(exam.encrypted_aes_key_for_student)
    signature = bytes.fromhex(exam.signature_student)

    # Decrypt the AES key using the student's private key
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

    # Decrypt the exam content using AES key
    iv = encrypted_data[:16]  # Assuming IV is the first 16 bytes
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Separate the exam_id, exam_json, and digital signature
    decrypted_str = decrypted_content.decode('utf-8')
    delimiter = "||SIGNATURE||"
    try:
        exam_id_str, remaining_content = decrypted_str.split(delimiter, 1)
        exam_json_str, received_signature_hex = remaining_content.rsplit(delimiter, 1)
        received_signature = bytes.fromhex(received_signature_hex)
    except ValueError:
        return jsonify({'message': 'Decryption failed, incorrect format'}), 400

    # Check if the separated signature matches the stored signature
    if received_signature != signature:
        return jsonify({'message': 'Decryption failed, signature mismatch'}), 400

    # Parse the exam JSON content
    try:
        exam_content = json.loads(exam_json_str)
    except json.JSONDecodeError as e:
        print("JSON Decode Error:", e)
        return jsonify({'message': 'Error decoding exam JSON'}), 400

    # Remove correct answers
    for question in exam_content:
        question.pop("correct_answers", None)
        question.setdefault("options", [])  # Ensure options field is provided, defaulting to an empty list if not present

    # Render the HTML page with exam questions
    return render_template('take_exam.html', exam_content=exam_content, exam_id=exam_id)


@main.route('/submit_exam', methods=['POST'])
@login_required
def submit_exam():
    # Your logic to handle the exam submission goes here
    # For example, you can extract the form data, process it, and save it to the database
    
    # Example: extracting data from the form
    answers = request.form.getlist('answers[]')
    exam_id = request.form.get('exam_id')

    # Process the answers and save the submission
    submission = Submission(user_id=current_user.id, exam_id=exam_id, answers=json.dumps(answers))
    db.session.add(submission)
    db.session.commit()

    flash('Exam submitted successfully!', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
