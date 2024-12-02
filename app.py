# menambahkan jsonify, make_response
from flask import Flask, session, render_template, request, redirect, url_for, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3

#install pip install cryptpgraphy
#menambahkan code dibawah ini juga 
from cryptography.fernet import Fernet
import hashlib
import secrets
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Menambahkan Hardcoded hashes for username and password (hashed using SHA-256)
USER_CREDENTIALS = [
    {
        "username": hashlib.sha256("user1".encode()).hexdigest(),
        "password": hashlib.sha256("password1".encode()).hexdigest(),
    },
]
# --- Akhir menambahan Hardcoded

# Key for encrypting the random number
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

sessions = {}

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)
    userid = db.Column(db.String(256), nullable=False)
    

    def __repr__(self):
        return f'<Student {self.name}>'

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.form
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
                response = make_response(redirect(url_for('index')))
                response.set_cookie('session_id', encrypted_session_id.decode(), httponly=True, max_age=60*60)
                return response

        # If login fails, return to login page with error
        # return render_template('login.html', error="Invalid username or password")
    
    # GET request - show login page
    return render_template('login.html')

@app.before_request
def check_cookie():
    if request.endpoint not in ['login', 'static']:  # Skip login and static endpoints
        # Get the session ID from the cookie
        session_id_encrypted = request.cookies.get('session_id')
        if not session_id_encrypted:
            return redirect (url_for('login'))

        # Decrypt the session ID
        try:
            session_id = cipher.decrypt(session_id_encrypted.encode()).decode()
            session = sessions.get(session_id)
            print (session)
        except Exception:
            return redirect (url_for('login'))

        # Validate session
        session = sessions.get(session_id)
        if not session or session['expires'] < datetime.datetime.now():
            return redirect (url_for('login'))

#--- akhir penambahan kode ---

@app.route('/home')
def index():
    # RAW Query
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)

@app.route('/add', methods=['POST'])
def add_student():
    name = request.form['name']
    age = request.form['age']
    grade = request.form['grade']
    # Cuplikan pengamanan aset atau 'ownership'
    userid = session.get('userid')
    # end
    

    connection = sqlite3.connect('instance/students.db')
    cursor = connection.cursor()

    # RAW Query
    # db.session.execute(
    #     text("INSERT INTO student (name, age, grade) VALUES (:name, :age, :grade)"),
    #     {'name': name, 'age': age, 'grade': grade}
    # )
    # db.session.commit()


    query = f"INSERT INTO student (name, age, grade) VALUES ('{name}', {age}, '{grade}')"
    cursor.execute(query)
    connection.commit()
    connection.close()
    return redirect(url_for('index'))


@app.route('/delete/<string:id>') 
def delete_student(id):
    # Cuplikan pengamanan aset atau 'ownership'
    student = db.session.execute(text(f"SELECT * FROM student WHERE id={id}")).fetchone()
    if student.userid != session.get('userid'):
        return jsonify({"error": "User is not permitted to edit this student"}), 403
    # end

    # RAW Query
    db.session.execute(text(f"DELETE FROM student WHERE id={id}"))
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_student(id):
    # Cuplikan pengamanan aset atau 'ownership'
    student = db.session.execute(text(f"SELECT * FROM student WHERE id={id}")).fetchone()
    if student.userid != session.get('userid'):
        return '''Tidak boleh diupdate''', 403
    if request.method == 'POST':
    # end
        name = request.form['name']
        age = request.form['age']
        grade = request.form['grade']
        
        # RAW Query
        db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}"))
        db.session.commit()
        return redirect(url_for('index'))
    else:
        # RAW Query
        return render_template('edit.html', student=student)

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

