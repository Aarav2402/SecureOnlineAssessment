from flask import render_template, request, redirect, url_for, Blueprint, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from .models import User
from . import db, bcrypt, mail
from flask_mail import Message
import pyotp  
import datetime
from functools import wraps
from flask import session, redirect, url_for, flash
import uuid

main = Blueprint('main', __name__)

@main.route('/')
def login():
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
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

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('main.signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, role='student', is_verified=False)
        db.session.add(user)
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

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))