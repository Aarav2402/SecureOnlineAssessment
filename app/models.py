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
    role = db.Column(db.String(20), nullable=False)  
    otp_secret = db.Column(db.String(16), nullable=True)  
    session_id = db.Column(db.String(100), nullable=True) 
    private_key = db.Column(db.Text, nullable=True) 
    public_key = db.Column(db.Text, nullable=True) 

    def __repr__(self):
        return '<User %r>' % self.email

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        encrypted_private_key = self.encrypt_private_key(private_pem)

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.private_key = base64.b64encode(encrypted_private_key).decode('utf-8')
        self.public_key = public_pem.decode('utf-8')
        db.session.commit()

    def encrypt_private_key(self, private_pem):
        salt = os.urandom(16)

       
        password = b'super_secret_password'  
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_private_key = encryptor.update(private_pem) + encryptor.finalize()

        return salt + iv + encrypted_private_key + encryptor.tag

    def decrypt_private_key(self):
        
        encrypted_private_key = base64.b64decode(self.private_key.encode('utf-8'))

        salt = encrypted_private_key[:16]
        iv = encrypted_private_key[16:32]
        tag = encrypted_private_key[-16:]
        encrypted_private_key = encrypted_private_key[32:-16]

        password = b''  
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password)

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
            db.session.commit() 
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
    duration = db.Column(db.Integer)  
    encrypted_data = db.Column(db.Text, nullable=True)  
    digital_signature = db.Column(db.Text, nullable=True)  
    encrypted_aes_key = db.Column(db.Text, nullable=True)  
    subject_name = db.Column(db.String(120), nullable=False)
    subject_code = db.Column(db.String(120), nullable=False)
    semester = db.Column(db.String(120), nullable=False)
    exam_date = db.Column(db.Date, nullable=False)
    is_approved = db.Column(db.Boolean, default=False) 
    computed_exam_id = db.Column(db.String(100), unique=True)  
    encrypted_for_student = db.Column(db.Text, nullable=True)
    encrypted_for_teacher = db.Column(db.Text, nullable=True)
    encrypted_for_manager = db.Column(db.Text, nullable=True)
    encrypted_aes_key_for_student = db.Column(db.Text, nullable=True)
    encrypted_aes_key_for_teacher = db.Column(db.Text, nullable=True)
    encrypted_aes_key_for_manager = db.Column(db.Text, nullable=True)
    signature_student = db.Column(db.Text, nullable=True)
    signature_teacher = db.Column(db.Text, nullable=True)
    signature_manager = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return '<Exam %r>' % self.title

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.computed_exam_id'), nullable=False)
    encrypted_submission = db.Column(db.Text)
    manager_signature = db.Column(db.Text)
    submission_time = db.Column(db.DateTime)
    masked_answer_id = db.Column(db.String(120))
    final_signature = db.Column(db.Text)
    encrypted_teacher_data = db.Column(db.Text)

    def __repr__(self):
        return '<Submission %r>' % self.text

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    marks = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Grade %r>' % self.id