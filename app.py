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
import jwt

app = Flask(__name__)
DATABASE = 'users.db'
public_key = None
if public_key is None:
    with open('public.pem', 'r') as f:
        public_key = f.read()

SIGNATURE_KEY = serialization.load_pem_public_key(public_key.encode('utf-8'))
def verify_signature(payload, signature):
    # return True
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
        return True
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                user_id INTEGER UNIQUE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        

# Updated JWT verification to use RS256
@app.route('/query', methods=['POST'])
def run_query():
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({'message': 'JWT token is required'}), 401

    try:
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        email = decoded_token.get('email')
        if not email:
            return jsonify({'message': 'Invalid token'}), 401

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found'}), 404

        cursor.execute('SELECT * FROM admins WHERE user_id = ?', (user[0],))
        admin = cursor.fetchone()

        if not admin:
            return jsonify({'message': 'Access denied: user is not an admin'}), 403

        data = request.get_json()
        query = data.get('query')
        print(query)

        if not query:
            return jsonify({'message': 'SQL query is required'}), 400

        cursor.execute(query)
        db.commit()
        result = cursor.fetchall()
        return jsonify({'result': result}), 200

    # except Exception:
    #     return jsonify({'message': 'Token has expired'}), 401
    # except jwt.InvalidTokenError:
    #     return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/delete', methods=['DELETE'])
def delete_user():
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({'message': 'JWT token is required'}), 401

    try:
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        email = decoded_token.get('email')
        if not email:
            return jsonify({'message': 'Invalid token'}), 401

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found'}), 404

        cursor.execute('SELECT * FROM admins WHERE user_id = ?', (user[0],))
        admin = cursor.fetchone()

        if not admin:
            return jsonify({'message': 'Access denied: user is not an admin'}), 403
    except Exception as e:
        print(e)
        return jsonify({'error': "something went wrong"}), 500

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    db = get_db()
    cursor = db.cursor()

    # Attempt to delete the user
    cursor.execute('DELETE FROM users WHERE email = ?', (email,))
    db.commit()

    if cursor.rowcount > 0:
        return jsonify({'message': f'User with email {email} deleted successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404
    
    
@app.route('/update-usage', methods=['PUT'])
def update_counter():
    data = request.get_json()
    email = data.get('email')
    counter = data.get('counter')

    if not email or counter is None:
        return jsonify({'message': 'Email and counter value are required'}), 400

    db = get_db()
    cursor = db.cursor()

    # Update the counter for the specified user
    try:
        cursor.execute('UPDATE users SET counter = ? WHERE email = ?', (counter, email))
        db.commit()

        if cursor.rowcount > 0:
            return jsonify({'message': f'Counter for user {email} updated to {counter}'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error updating counter', 'error': 'something went wrong'}), 500



@app.route('/test', methods=['POST'])
def run_query2():
    email = 'test@gmail.com'
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    cursor.execute('SELECT * FROM admins WHERE user_id = ?', (user[0],))
    admin = cursor.fetchone()

    if not admin:
        return jsonify({'message': 'Access denied: user is not an admin'}), 403

    data = request.get_json()
    query = data.get('query')

    if not query:
        return jsonify({'message': 'SQL query is required'}), 400

    cursor.execute(query)
    db.commit()
    result = cursor.fetchall()
    return jsonify({'result': result}), 200


# old method, increase but not return the counter
# @app.route('/increase/<email>', methods=['POST'])
# def increase_counter(email):
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute('UPDATE users SET counter = counter + 1 WHERE email = ?', (email,))
#     db.commit()

#     if cursor.rowcount > 0:
#         return jsonify({'message': f'Counter for {email} increased successfully'}), 200
#     else:
#         return jsonify({'message': 'User not found'}), 404


#new method, increase and return the counter
@app.route('/increase/<email>', methods=['POST'])
def increase_counter(email):
    db = get_db()
    cursor = db.cursor()

    # Increase the counter
    cursor.execute('UPDATE users SET counter = counter + 1 WHERE email = ?', (email,))
    db.commit()

    if cursor.rowcount > 0:
        # Fetch the new counter value
        cursor.execute('SELECT counter FROM users WHERE email = ?', (email,))
        new_value = cursor.fetchone()[0]
        
        return jsonify({
            'message': f'Counter for {email} increased successfully',
            'counter': new_value
        }), 200
    else:
        return jsonify({'message': 'User not found'}), 404


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
