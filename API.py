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

    cursor.execute('SELECT password, id FROM users WHERE email = :email', {'email': email})
    return cursor.fetchone()

@app.route('/sign_up', methods=['POST'])
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


@app.route('/login', methods=[])
def login():

    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()
    ph = PasswordHasher()
    
    try:

        required_fields = ['email', 'password']
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400    

        elif validate_email(data['email']) is False:
            return jsonify({'error': 'invalid email.'}), 400
        
        email_check = checkdb_for_email(data['email'], cursor)
        
        if email_check is not None:

            stored_hash = email_check[0]
            submitted_pass = data['password']

            try:
                ph.verify(stored_hash, submitted_pass)
                token = create_access_token(email_check[1])
                return jsonify({'token':token}), 201
            
            except exceptions.VerifyMismatchError:
                return jsonify({'error': 'invalid password.'}), 400
            
        else: 
            return jsonify({'error': 'email not found.'}), 400

    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400

    finally:
        conn.close()


@app.route('/workout', methods=['POST'])
def create_workout():

    data = request.get_json()
    header = request.headers.get('Authorization')
    conn = get_db_connection()
    cursor = conn.cursor()
        
    try:
        required_fields = ['title', 'exercises']
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400  

        elif not header or not header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401

        token = header.removeprefix('Bearer ')
        try:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401

        try:
            workout_title = data[0]
            exercises = data[1]
            user_id = payload['sub']
                
            cursor.execute('INSERT into workouts(title, user_id) VALUES(:title, :user_id)', {'title':workout_title, 'user_id':user_id})
            
            workout_id = cursor.lastrowid

            for exercise_id in exercises:
                cursor.execute('INSERT into workouts_exercises(workout_id, exercise_id) VALUES(:workout_id, :exercise_id)', {'workout_id':workout_id, 'exercise_id':exercise_id})

            conn.commit()

        except Exception as e:

            conn.rollback()
            return jsonify({'error': str(e)}), 400
        
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400    

    finally:
        conn.close()
    



if __name__ == '__main__':
    app.run(debug=True)
