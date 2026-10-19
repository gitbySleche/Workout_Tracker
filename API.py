from flask import Flask, request, jsonify
from argon2 import PasswordHasher, exceptions
from datetime import datetime, timedelta
from dotenv import load_dotenv
import secrets
import sqlite3 
import jwt
import os


app = Flask(__name__)
load_dotenv('JWT_secret.env')
SECRET = os.environ.get("JWT_SECRET")


def get_db_connection():
    conn = sqlite3.connect('workouts.db')
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def create_access_token(user_id: int):
    now = datetime.now()
    payload = {"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=15)}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def validate_email(email: str):

    for character in email:
        if character == '@':
            index = email.index('@') 
            if email[index:index+10] == '@gmail.com' or email[index:index+12] == '@hotmail.com':
                return True
            break
    return False

def checkdb_for_email(email, cursor):

    cursor.execute('SELECT password, email, id FROM users WHERE email = :email', {'email': email})
    return cursor.fetchone()

@app.route('/sign_up', methods=["POST"])
def sign_up():

    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()
    ph = PasswordHasher()

    try:

        required_fields = ['username', 'email', 'password']

        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        elif validate_email(data['email']) is False:
            return jsonify({'error': 'invalid email.'}), 400

        elif checkdb_for_email(data['email'], cursor) is not None:
            return jsonify({'error': 'email already registered.'}), 400

        else:
            hashed_pass = ph.hash(data['password'])
            cursor.execute('INSERT into users(username, email, password) VALUES(:username, :email, :password)', {'username':data['username'], 'email':data['email'], 'password':hashed_pass})
            conn.commit()
        

    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400

    else:
        token = create_access_token(cursor.lastrowid)
        return jsonify({'token':token}), 201

    finally:
        conn.close()




if __name__ == '__main__':
    app.run(debug=True)
