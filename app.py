from flask import Flask, render_template, session, request, redirect, url_for, jsonify, make_response
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3
import hashlib
import secrets
import datetime

app = Flask(_name_)

# Hardcoded hashes for username and password (hashed using SHA-256)
USER_CREDENTIALS = [
    {
        "username": hashlib.sha256("user1".encode()).hexdigest(),
        "password": hashlib.sha256("password1".encode()).hexdigest(),
    },
]

# Key for encrypting the random number
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Dictionary to store active sessions
sessions = {}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)
    owner = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<Student {self.name}>'

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    # Hash received username and password
    username_hash = hashlib.sha256(data['username'].encode()).hexdigest()
    password_hash = hashlib.sha256(data['password'].encode()).hexdigest()

    # Validate credentials
    for cred in USER_CREDENTIALS:
        if cred['username'] == username_hash and cred['password'] == password_hash:
            # Generate a random session ID
            random_number = secrets.token_hex(16)
            encrypted_session_id = cipher.encrypt(random_number.encode())

            # Store session with expiration (e.g., 1 hour)
            expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
            sessions[random_number] = {"expires": expiration, "userid": cred['username']}

            # Set cookie
            response = make_response({"message": "Login successful!"})
            response.set_cookie('session_id', encrypted_session_id.decode(), httponly=True, max_age=60*60)
            return response

    return jsonify({"error": "Invalid username or password"}), 401

@app.before_request
def check_cookie():
    if request.endpoint not in ['login', 'static']:  # Skip login and static endpoints
        # Get the session ID from the cookie
        session_id_encrypted = request.cookies.get('session_id')
        if not session_id_encrypted:
            return jsonify({"error": "Authentication required"}), 401

        # Decrypt the session ID
        try:
            session_id = cipher.decrypt(session_id_encrypted.encode()).decode()
            session = sessions.get(session_id)
        except Exception:
            return jsonify({"error": "Invalid session"}), 401

        # Validate session
        session = sessions.get(session_id)
        if not session or session['expires'] < datetime.datetime.now():
            return jsonify({"error": "Session expired or invalid"}), 401

@app.route('/')
def index():
    # RAW Query
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)

@app.route('/add', methods=['POST'])
def add_student():
    name = request.form['name']
    age = request.form['age']
    grade = request.form['grade']
    userid = session.get('userid')
    
    

    connection = sqlite3.connect('instance/students.db')
    cursor = connection.cursor()

    # RAW Query
    # db.session.execute(
    #     text("INSERT INTO student (name, age, grade) VALUES (:name, :age, :grade)"),
    #     {'name': name, 'age': age, 'grade': grade}
    # )
    # db.session.commit()
    query = f"INSERT INTO student (name, age, grade, userid) VALUES ('{name}', {age}, '{grade}', '{userid}')"
    cursor.execute(query)
    connection.commit()
    connection.close()
    return redirect(url_for('index'))


@app.route('/delete/<string:id>') 
def delete_student(id):
    student = db.session.execute(text('SELECT * FROM student WHERE id={id}')).fetchAll()
    if student.userid is not session.get('userid'):
        return jsonify({"error": "User is not permitted to edit this student"}), 403
    # RAW Query
    db.session.execute(text(f"DELETE FROM student WHERE id={id}"))
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_student(id):
    if request.method == 'POST':
        student = db.session.execute(text('SELECT * FROM student WHERE id={id}')).fetchAll()
        if student.userid is not session.get('userid'):
            return jsonify({"error": "User is not permitted to edit this student"}), 403
        name = request.form['name']
        age = request.form['age']
        grade = request.form['grade']
        
        # RAW Query
        db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}"))
        db.session.commit()
        return redirect(url_for('index'))
    else:
        # RAW Query
        student = db.session.execute(text(f"SELECT * FROM student WHERE id={id}")).fetchone()
        return render_template('edit.html', student=student)

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

