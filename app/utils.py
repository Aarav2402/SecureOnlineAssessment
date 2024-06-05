from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def compute_exam_id(subject_name, subject_code, semester, exam_date, fixed_time, exam_serial_number):
    return f"{subject_name}_{subject_code}_{semester}_{exam_date}_{fixed_time}_{exam_serial_number}"

def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# def encrypt_with_public_key(public_key, data):

#     ciphertext = public_key.encrypt(
#         data.encode('utf-8'),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return ciphertext


def encrypt_with_public_key(public_key, data):
    try:
        # Generate a random AES key
        aes_key = os.urandom(32)

        # Encrypt data using AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()

        # Encrypt AES key using RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_aes_key, iv + encrypted_data  # Include IV with encrypted data
    except Exception as e:
        raise  # Re-raise the exception for further handling

def decrypt_with_private_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
