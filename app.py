from flask import Flask, request, jsonify, g, redirect
import sqlite3
from bcrypt import gensalt, hashpw, checkpw
import base64
import hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
DATABASE = 'users.db'
public_key = None
if public_key is None:
    with open('public.pem', 'r') as f:
        public_key = f.read()

SIGNATURE_KEY = serialization.load_pem_public_key(public_key.encode('utf-8'))
def verify_signature(payload, signature):
    # return True # For now, always return True to bypass signature verification
    """
    Verifies the signature of the given payload using the public key.

    :param payload: The original payload as a string.
    :param signature: The signature to verify, base64-encoded.
    :return: True if the signature is valid, False otherwise.
    """
    try:
        # Create a new SHA-256 hash of the payload
        # h = SHA256.new(payload.encode('utf-8'))
        
        # Decode the base64-encoded signature
        decoded_signature = base64.b64decode(signature)
        
        # Create a verifier with the public key
        # verifier = PKCS1_v1_5.new(public_key)

        SIGNATURE_KEY.verify(
            decoded_signature,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Verify the signature
        print("Signature verified")
        return True  # verifier.verify(h, decoded_signature)
    except Exception as e:
        print(f"Verification failed: {e}")
        return False
# Middleware to verify the signature of incoming requests, disabled for testing
# modify the auth service to sign requests and then we will enable this
@app.before_request
def before_request():
    signature_header = request.headers.get('x-gateway-signature')
    if signature_header is None:
        return jsonify({'message': 'Invalid request, needs to be signed'}), 401
    
    # Extract the payload (in this example, we use the raw request data)
    # Adjust this as needed to match how the payload is constructed on your side
    payload = request.method + request.path

    print(payload)
    # Verify the signature
    if verify_signature(payload, signature_header):
        pass  # Continue processing the request

    else:
        return jsonify({'message': 'Invalid signature'}), 403

# Database connection setup
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                counter INTEGER DEFAULT 0
            )
        ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    # Hash the password
    salt = gensalt()
    password_hash = hashpw(password.encode('utf-8'), salt)

    # Store the user in the database
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, password_hash))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Email already exists'}), 409

    return jsonify({'message': 'User registered successfully'}), 201

# Route to verify user login credentials
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()

    if result and checkpw(password.encode('utf-8'), result[0]):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

# Route to retrieve user details by email
@app.route('/user/<email>', methods=['GET'])
def get_user(email):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, email FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        return jsonify({'id': user[0], 'email': user[1]})
    else:
        return jsonify({'message': 'User not found'}), 404

# Route to update the password (for password reset)
@app.route('/reset-password', methods=['POST'])
def reset_password():
    #lets have this endpoint require a jwt token in url params
    # return jsonify({'message': 'Password reset successful'}), 200
    data = request.get_json()
    email = request.headers.get('x-user-email')
    print(email)
    new_password = data.get('password')

    if not new_password:
        return jsonify({'message': 'New password is required'}), 400

    # Hash the new password
    salt = gensalt()
    new_password_hash = hashpw(new_password.encode('utf-8'), salt)

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE email = ?', (new_password_hash, email))
    db.commit()

    if cursor.rowcount > 0:
        print('Password updated successfully')
        # print('we are here')
        # return jsonify({'message': 'Password updated successfully'}), 200
        return redirect(f'/message?message="password reset successfully"', code=302)

    else:
        print('User not found')
        return jsonify({'message': 'User not found'}), 404
        # return redirect(f'/message?message="password reset failed"', code=302)

# Initialize the database on startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(port=5000)
