import base64
import os
from flask import current_app
from itsdangerous import Serializer
from . import db
from flask_login import UserMixin
from . import login_manager
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), nullable=False)  # For distinguishing between student, teacher, manager
    otp_secret = db.Column(db.String(16), nullable=True)  # Add this field for OTP
    session_id = db.Column(db.String(100), nullable=True)  # Add this field for session tracking
    private_key = db.Column(db.Text, nullable=True)  # Private key
    public_key = db.Column(db.Text, nullable=True)  # Public key

    def __repr__(self):
        return '<User %r>' % self.email

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encrypt the private key before storing
        encrypted_private_key = self.encrypt_private_key(private_pem)

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.private_key = base64.b64encode(encrypted_private_key).decode('utf-8')
        self.public_key = public_pem.decode('utf-8')
        db.session.commit()

    def encrypt_private_key(self, private_pem):
        # Generate a random salt
        salt = os.urandom(16)

        # Derive a key from the salt and a password
        password = b'super_secret_password'  # Use a secure method to store and retrieve this password
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password)

        # Encrypt the private key using AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_private_key = encryptor.update(private_pem) + encryptor.finalize()

        return salt + iv + encrypted_private_key + encryptor.tag

    def decrypt_private_key(self):
        # Decode the base64 encoded private key
        encrypted_private_key = base64.b64decode(self.private_key.encode('utf-8'))

        # Extract the salt, IV, encrypted private key, and tag
        salt = encrypted_private_key[:16]
        iv = encrypted_private_key[16:32]
        tag = encrypted_private_key[-16:]
        encrypted_private_key = encrypted_private_key[32:-16]

        # Derive the key using the same method as encryption
        password = b'super_secret_password'  # Use a secure method to store and retrieve this password
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password)

        # Decrypt the private key using AES
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()

        return serialization.load_pem_private_key(private_key, password=None)

    def get_private_key(self):
        return self.decrypt_private_key()

    def get_public_key(self):
        return serialization.load_pem_public_key(self.public_key.encode('utf-8'))
    
    def get_public_key_by_user_id(user_id):
        user = User.query.get(user_id)
        if user:
            return user.get_public_key()
        else:
            return None

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def get_otp_secret(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
            db.session.commit()  # Save the OTP secret to the database
        return self.otp_secret

    def generate_otp(self):
        otp_secret = self.get_otp_secret()
        totp = pyotp.TOTP(otp_secret)
        return totp.now()

    def verify_otp(self, otp_code, otp_secret):
        totp = pyotp.TOTP(otp_secret)
        result = totp.verify(otp_code, valid_window=1)
        print(f"OTP verification result: {result}")
        return result

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # Duration of the exam in minutes
    # questions = db.Column(db.Text, nullable=True)
    encrypted_data = db.Column(db.Text, nullable=True)  # Store encrypted exam data
    digital_signature = db.Column(db.Text, nullable=True)  # Store digital signature of the exam
    encrypted_aes_key = db.Column(db.Text, nullable=True)  # Store encrypted AES key

    def __repr__(self):
        return '<Exam %r>' % self.title

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # Type of question (e.g., multiple choice, essay)
    options = db.Column(db.Text, nullable=True)  # Options for MCQs, stored as a JSON string
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)

    def __repr__(self):
        return '<Question %r>' % self.text

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    marks_obtained = db.Column(db.Integer)

    def __repr__(self):
        return '<Response %r>' % self.id

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    marks = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Grade %r>' % self.id