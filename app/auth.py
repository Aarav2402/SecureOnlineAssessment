from functools import wraps
import bcrypt
from flask import Blueprint, request, jsonify, session, flash, redirect, url_for, render_template
from flask_login import current_user, login_required, login_user, logout_user
from app.utils import compute_exam_id, decrypt_with_private_key, encrypt_with_public_key, sign_data, verify_signature
from .models import User, Exam, db
from flask_mail import Message  
import uuid
from app import mail 

auth = Blueprint('auth', __name__)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, role='student')
        
        db.session.add(user)
        db.session.commit()  # Commit first to get the user ID
        
        # Generate key pair
        user.generate_key_pair()
        db.session.commit()  # Commit again to save the keys

        # Send verification email
        token = user.get_reset_token()
        verify_url = url_for('auth.verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', recipients=[user.email])
        msg.body = f'Please click the link to verify your email: {verify_url}'
        mail.send(msg)

        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')



@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email address.', 'warning')
                return redirect(url_for('auth.login'))

            # Generate a new session ID
            new_session_id = str(uuid.uuid4())
            user.session_id = new_session_id
            db.session.commit()

            # Generate and send OTP
            otp_code = user.generate_otp()
            msg = Message('Your OTP Code', recipients=[user.email])
            msg.body = f'Your OTP code is {otp_code}. It is valid for 30 seconds.'
            mail.send(msg)

            # Store session ID and user ID in session
            session['user_id'] = user.id
            session['session_id'] = new_session_id
            return redirect(url_for('auth.verify_otp'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html')

@auth.route('/verify_email/<token>')
def verify_email(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('auth.signup'))
    user.is_verified = True
    db.session.commit()
    flash('Your account has been verified! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        user = User.query.get(session['user_id'])
        otp_secret = session.get('otp_secret')  # Retrieve the OTP secret from the session

        # Check if the session ID matches
        if user and user.session_id == session.get('session_id'):
            if user.verify_otp(otp_code, otp_secret):
                login_user(user)
                session.pop('user_id', None)  # Remove user ID from session after successful login
                return redirect(url_for('main.dashboard'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
        else:
            flash('Session invalid or expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))
    return render_template('verify_otp.html')


@auth.route('/logout')
@login_required
def logout():
    current_user.session_id = None
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))