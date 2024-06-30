# __init__.py

from flask import Flask, app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf import CSRFProtect
import os
import string 
import secrets  
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()


def generate_salt(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
    app.config['SECRET_KEY'] = ''
    app.config['SECURITY_PASSWORD_SALT'] = generate_salt() 
    app.config['BCRYPT_HASH_PREFIX'] = "$2b$"
    app.config['SESSION_COOKIE_SECURE'] = True  
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['SESSION_COOKIE_HTTPONLY'] = True  

    db_dir = os.path.join(app.instance_path, 'database')
    os.makedirs(db_dir, exist_ok=True)
    

    db_path = os.path.join(db_dir, 'app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'mysecureassessment@gmail.com'
    app.config['MAIL_PASSWORD'] = ''
    app.config['MAIL_DEFAULT_SENDER'] = 'mysecureassessment@gmail.com'


   
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    
    login_manager.login_view = 'auth.login'

    with app.app_context():
        
        from .routes import main as main_blueprint
        from .auth import auth as auth_blueprint

        
        app.register_blueprint(main_blueprint)
        app.register_blueprint(auth_blueprint)

        
        from .models import User, Exam, Submission, Grade
        db.create_all()

    return app

# Import the create_app function at the end to avoid circular imports
from .routes import main as main_blueprint
from .auth import auth as auth_blueprint