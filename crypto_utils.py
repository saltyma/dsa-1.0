import hashlib
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_image(image, private_key):
    image_bytes = image.tobytes()
    signature = private_key.sign(
        image_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return image, signature

def verify_signature(image, signature, public_key):
    try:
        image_bytes = image.tobytes()
        public_key.verify(
            signature,
            image_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def hash_password(password):
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    hashed_password = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, hashed_password

def verify_password(stored_password, salt, provided_password):
    hashed_password = hashlib.sha256((salt + provided_password).encode()).hexdigest()
    return hashed_password == stored_password
