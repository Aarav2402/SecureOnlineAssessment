import time
import timeit
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


def encrypt_with_public_key(public_key, data):
    try:
        start_time = timeit.default_timer()
        aes_key = os.urandom(32)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()

        end_time = timeit.default_timer()
        execution_time = end_time - start_time

        print(f"Encryption Time: {execution_time:.6f} seconds")

        print(f"AES Key: {aes_key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Encrypted Data: {encrypted_data.hex()}")

       
        start_time_rsa = timeit.default_timer()
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_time_rsa = timeit.default_timer()
        rsa_encryption_time = end_time_rsa - start_time_rsa

        print(f"RSA Encryption Time: {rsa_encryption_time:.6f} seconds")
        print(f"Encrypted AES Key: {encrypted_aes_key.hex()}")

        return encrypted_aes_key, iv + encrypted_data  

    except Exception as e:
        raise  

def decrypt_with_private_key(private_key, ciphertext):
    try:
        start_time = time.time()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        end_time = time.time()
        decryption_time = end_time - start_time

        print(f"Decryption Time: {decryption_time:.6f} seconds")

        return plaintext.decode('utf-8')

    except Exception as e:
        raise  # Re-raise the exception for further handling

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
