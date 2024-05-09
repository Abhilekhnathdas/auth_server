from flask import Flask, request, render_template, jsonify
import sqlite3
import os
import secrets
import string
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)

DATABASE = 'tokens.db'

def create_connection():
    conn = sqlite3.connect(DATABASE)
    # Check if the tokens table exists
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tokens'")
    table_exists = cursor.fetchone()
    if not table_exists:
        # Create the tokens table if it doesn't exist
        cursor.execute('''CREATE TABLE tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        token TEXT NOT NULL,
                        key TEXT DEFAULT NULL,
                        status TEXT DEFAULT 'active',
                        expiry_date TEXT DEFAULT NULL)''')
        conn.commit()
    cursor.close()
    return conn

def execute_query(query, args=()):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    conn.close()

def fetch_query(query, args=()):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    rows = cur.fetchall()
    conn.close()
    return rows

def generate_token():
    token_characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(token_characters) for _ in range(16))

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_token(token, key):
    cipher = Fernet(key)
    encrypted_token = cipher.encrypt(token.encode())
    return encrypted_token

def decrypt_token(encrypted_token, key):
    cipher = Fernet(key)
    decrypted_token = cipher.decrypt(encrypted_token).decode()
    return decrypted_token

@app.route('/auth/admin/')
def index():
    return render_template('index.html')

@app.route('/auth/admin/add_client_page')
def render_add_client_page():
    return render_template('add_client.html')

@app.route('/auth/admin/change_status_page')
def render_change_status_page():
    return render_template('change_status.html')

@app.route('/auth/admin/handle_expiry_page')
def render_handle_expiry_page():
    return render_template('handle_expiry.html')

@app.route('/auth/admin/add_client', methods=['POST'])
def add_client():
    data = request.json
    email = data.get('email')
    expiry_date = data.get('expiry_date')
    
    # Check if the client with the given email already exists
    existing_client = fetch_query("SELECT email FROM tokens WHERE email = ?", (email,))
    if existing_client:
        return jsonify({'message': 'Client already exists!'}), 400

    # If the client doesn't exist, generate a token and add the client
    token = generate_token()
    execute_query("INSERT INTO tokens (email, token, expiry_date) VALUES (?, ?, ?)", (email, token, expiry_date))
    return jsonify({'message': 'Client added successfully!'})

@app.route('/auth/admin/change_status', methods=['POST'])
def change_status():
    data = request.json
    email = data.get('email')
    status = data.get('status')
    
    # Check if the client with the given email exists
    existing_client = fetch_query("SELECT email FROM tokens WHERE email = ?", (email,))
    if not existing_client:
        return jsonify({'message': f'No active client found with email {email}!'}), 404

    # If the client exists, update its status
    execute_query("UPDATE tokens SET status = ?, key = NULL WHERE email = ?", (status, email))
    return jsonify({'message': 'Client status changed successfully!'})

@app.route('/auth/admin/handle_expiry', methods=['POST'])
def handle_expiry():
    data = request.json
    email = data.get('email')
    expiry_date = data.get('expiry_date')

    # Check if the email exists and is active
    rows = fetch_query("SELECT email, expiry_date FROM tokens WHERE email = ? AND status = 'active'", (email,))
    if rows:
        current_expiry_date = rows[0][1]
        # Check if the current expiry date is before the new expiry date
        if current_expiry_date < expiry_date:
            execute_query("UPDATE tokens SET expiry_date = ? WHERE email = ?", (expiry_date, email))
            return jsonify({'message': f'Expiry date updated successfully for {email}!'})
        else:
            return jsonify({'message': f'New expiry date must be after the current expiry date for {email}!'}), 400
    else:
        return jsonify({'message': f'No active client found with email {email}!'}), 404

@app.route('/validate', methods=['POST'])
def validate_token():
    data = request.json
    email = data.get('email')
    encrypted_token = data.get('encrypted_token')
    rows = fetch_query("SELECT token, key,status,expiry_date FROM tokens WHERE email = ?", (email,))
    if rows:
        token, key, status, expiry_date = rows[0]
        if status != 'active':
            return jsonify({'message': 'Authentication failed. Please contact the admin.'}), 401
        if datetime.strptime(expiry_date, '%Y-%m-%d') < datetime.now():
            return jsonify({'message': 'Token has expired. Please contact the admin.'}), 403
        if not key:
            # Client is authenticating for the first time
            new_key = generate_aes_key()
            encrypted_token_new = encrypt_token(token, new_key)
            execute_query("UPDATE tokens SET key = ? WHERE email = ?", (new_key, email))
            return jsonify({'encrypted_token': encrypted_token_new.hex(), 'message': 'Authentication successful!'}), 200
        else:
            # Client has a stored key
            try:
                decrypted_token = decrypt_token(bytes.fromhex(encrypted_token), key)
                if decrypted_token == token:
                    # Generate a new key and encrypt the token
                    new_key = generate_aes_key()
                    encrypted_token_new = encrypt_token(token, new_key)
                    execute_query("UPDATE tokens SET key = ? WHERE email = ?", (new_key, email))
                    return jsonify({'encrypted_token': encrypted_token_new.hex(), 'message': 'Authentication successful!'}), 200
                else:
                    return jsonify({'message': 'Authentication failed. Please contact the admin.'}), 401
            except Exception as e:
                execute_query("UPDATE tokens SET status = 'inactive' WHERE email = ?", (email,))
                return jsonify({'message': 'Authentication failed. Please contact the admin.'}), 401
    else:
        return jsonify({'message': 'Authentication failed. Please contact the admin.'}), 401

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0",port=8000)
