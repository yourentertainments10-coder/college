from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector

app = Flask(import_name=__name__)
app.secret_key = 'your_secret_key'

# Configure MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="8595",
    database="dbms"
)

cursor = db.cursor()

# Login route
@app.route('/')
def login():
    return render_template('login.html')

# Handle login submission
@app.route('/login', methods=['POST'])
def login_user():
    username = request.form['username']
    password = request.form['password']
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    if user:
        session['user'] = username
        return redirect(url_for('home'))
    else:
        return "Invalid credentials. Try again."

# Home route
@app.route('/home')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    else:
        return redirect(url_for('login'))

# Additional routes for each page
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/academic')
def academic():
    return render_template('academic.html')

@app.route('/admission_notices')
def admission_notices():
    return render_template('admission_notices.html')

@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        # Handle form submission here
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        cursor.execute("INSERT INTO contact_us (name, email, message) VALUES (%s, %s, %s)", (name, email, message))
        db.commit()
        return "Thank you for your message!"
    return render_template('contact_us.html')

@app.route('/exam_result')
def exam_result():
    return render_template('exam_result.html')

@app.route('/faculty_login')
def faculty_login():
    return render_template('faculty_login.html')

@app.route('/student_portal')
def student_portal():
    return render_template('student_portal.html')

@app.route('/timetable')
def timetable():
    return render_template('timetable.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

