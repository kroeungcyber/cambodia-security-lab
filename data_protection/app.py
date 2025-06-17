import os
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import secrets

app = Flask(__name__)

# Cambodian government IP ranges (example - should be updated with actual ranges)
GOVERNMENT_IPS = [
    '103.6.76.0/24',
    '202.58.224.0/19',
    '203.189.128.0/18'
]

def is_gov_ip(ip):
    """Check if IP is in Cambodian government ranges"""
    from ipaddress import ip_address, ip_network
    try:
        ip_obj = ip_address(ip)
        return any(ip_obj in ip_network(net) for net in GOVERNMENT_IPS)
    except ValueError:
        return False

# Configure security logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"]
)

# Password policy requirements
PASSWORD_MIN_LENGTH = 12
PASSWORD_COMPLEXITY = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$')

# Secure key derivation function parameters
KDF_ITERATIONS = 100_000
KEY_LENGTH = 32  # 256 bits for AES-256
SALT_LENGTH = 16  # 128 bits

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from a password and salt using PBKDF2 HMAC SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(plaintext: bytes, password: str) -> dict:
    """
    Encrypt plaintext using AES-256-GCM with a key derived from the password.
    Returns a dict with base64-encoded ciphertext, nonce, salt, and tag.
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    key = derive_key(password.encode(), salt)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return {
        'ciphertext': b64encode(ciphertext).decode(),
        'nonce': b64encode(nonce).decode(),
        'salt': b64encode(salt).decode(),
        'tag': b64encode(encryptor.tag).decode()
    }

def decrypt(enc_dict: dict, password: str) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM with a key derived from the password.
    Expects a dict with base64-encoded ciphertext, nonce, salt, and tag.
    """
    salt = b64decode(enc_dict['salt'])
    key = derive_key(password.encode(), salt)
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    ciphertext = b64decode(enc_dict['ciphertext'])
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

@app.route('/encrypt', methods=['POST'])
@limiter.limit("5 per minute")
def encrypt_route():
    # Restrict to government IPs if in production
    if os.getenv('FLASK_ENV') == 'production' and not is_gov_ip(request.remote_addr):
        security_logger.warning(
            f"Unauthorized access attempt from {request.remote_addr}"
        )
        return jsonify({
            'error': 'Access restricted to authorized networks',
            'error_km': 'ការចូលប្រើត្រូវបានដាក់កម្រិតសម្រាប់បណ្តាញដែលបានអនុញ្ញាត'
        }), 403
    """
    API endpoint to encrypt data.
    Expects JSON with 'data' (string) and 'password' (string).
    Returns encrypted data components.
    """
    content = request.json
    if not content or 'data' not in content or 'password' not in content:
        return jsonify({
            'error': 'Missing data or password',
            'error_km': 'ខ្វះទិន្នន័យ ឬពាក្យសម្ងាត់'
        }), 400
    
    # Validate password strength
    if not PASSWORD_COMPLEXITY.match(content['password']):
        security_logger.warning(
            f"Password policy violation from {request.remote_addr} - "
            f"Password: {content['password'][:3]}... (hidden)"
        )
        return jsonify({
            'error': 'Password must be at least 12 characters with uppercase, lowercase, number and special character',
            'error_km': 'ពាក្យសម្ងាត់ត្រូវតែមានយ៉ាងហោចណាស់ ១២ តួអក្សរ ដែលមានអក្សរធំ អក្សរតូច លេខ និងតួអក្សរពិសេស'
        }), 400
    plaintext = content['data'].encode()
    password = content['password']
    try:
        encrypted = encrypt(plaintext, password)
        return jsonify(encrypted), 200
    except Exception as e:
        security_logger.error(
            f"Encryption failed from {request.remote_addr} - {str(e)}"
        )
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
@limiter.limit("5 per minute")
def decrypt_route():
    # Restrict to government IPs if in production
    if os.getenv('FLASK_ENV') == 'production' and not is_gov_ip(request.remote_addr):
        security_logger.warning(
            f"Unauthorized access attempt from {request.remote_addr}"
        )
        return jsonify({
            'error': 'Access restricted to authorized networks'
        }), 403
    """
    API endpoint to decrypt data.
    Expects JSON with 'ciphertext', 'nonce', 'salt', 'tag', and 'password'.
    Returns decrypted plaintext.
    """
    content = request.json
    # Validate password strength for decrypt attempts too
    if 'password' in content and not PASSWORD_COMPLEXITY.match(content['password']):
        return jsonify({
            'error': 'Password must be at least 12 characters with uppercase, lowercase, number and special character'
        }), 400
    required_fields = ['ciphertext', 'nonce', 'salt', 'tag', 'password']
    if not content or not all(field in content for field in required_fields):
        return jsonify({
            'error': 'Missing required fields',
            'error_km': 'ខ្វះវាលដែលត្រូវការ'
        }), 400
    password = content['password']
    try:
        plaintext = decrypt(content, password)
        return jsonify({'data': plaintext.decode()}), 200
    except Exception as e:
        security_logger.error(
            f"Decryption failed from {request.remote_addr} - {str(e)}"
        )
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run the Flask app with HTTPS required in production
    context = ('/path/to/cert.pem', '/path/to/key.pem')  # Update with actual cert paths
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=context)
