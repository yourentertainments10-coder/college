from flask import Flask, render_template, request, redirect, url_for, session, abort, g, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, Regexp
import mysql.connector
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import bcrypt
import logging
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(hours=5)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Form Classes
class StudentLoginForm(FlaskForm):
    roll_no = StringField('Roll Number', validators=[
        DataRequired(),
        Regexp(r'^[0-9]{8}$', message='Roll number must be 8 digits')
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StudentRegistrationForm(FlaskForm):
    roll_no = StringField('Roll Number', validators=[
        DataRequired(),
        Regexp(r'^[0-9]{8}$', message='Roll number must be 8 digits')
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address')
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Name must be between 2 and 100 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Database Configuration
def init_db():
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root@123"
        )
        cursor = db.cursor()
        
        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS dseu")
        cursor.execute("USE dseu")
        
        # Create students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INT AUTO_INCREMENT PRIMARY KEY,
                roll_no VARCHAR(8) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                department VARCHAR(50),
                semester INT,
                batch_year YEAR,
                status ENUM('active', 'inactive') DEFAULT 'active'
            )
        """)
        
        db.commit()
        cursor.close()
        db.close()
        print("Database initialized successfully")
    except mysql.connector.Error as err:
        print(f"Error initializing database: {err}")

# Initialize database on startup
init_db()

def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root@123",
                database="dseu",
                autocommit=False  # Explicit transaction control
            )
            g.cursor = g.db.cursor(dictionary=True)
        except mysql.connector.Error as err:
            logger.error(f"Database connection error: {err}")
            return None, None
    return g.db, g.cursor

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    cursor = g.pop('cursor', None)
    if cursor:
        cursor.close()
    if db:
        db.close()

# Authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login to access this page', 'warning')
            if session.get('user_type') == 'faculty':
                return redirect(url_for('faculty_login'))
            return redirect(url_for('student_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return render_template('student_login.html', form=form)
            
        roll_no = form.roll_no.data
        password = form.password.data.encode('utf-8')
        
        try:
            cursor.execute(
                "SELECT * FROM students WHERE roll_no = %s AND status = 'active'", 
                (roll_no,)
            )
            student = cursor.fetchone()
            
            if student and bcrypt.checkpw(password, student['password'].encode('utf-8')):
                session.permanent = True
                session['user'] = student['full_name']
                session['user_type'] = 'student'
                session['roll_no'] = student['roll_no']
                session['user_id'] = student['id']
                flash('Login successful!', 'success')
                return redirect(url_for('student_portal'))
            else:
                flash("Invalid roll number or password.", "error")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "error")
            
    return render_template('student_login.html', form=form)

@app.route('/student_registration', methods=['GET', 'POST'])
def student_registration():
    form = StudentRegistrationForm()
    try:
        if form.validate_on_submit():
            db, cursor = get_db()
            if not db or not cursor:
                flash("Database connection error", "error")
                return render_template('student_registration.html', form=form)
                
            roll_no = form.roll_no.data
            email = form.email.data
            full_name = form.full_name.data
            password = form.password.data.encode('utf-8')
            
            # Hash the password
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
            
            try:
                # Check if roll number already exists
                cursor.execute("SELECT roll_no FROM students WHERE roll_no = %s", (roll_no,))
                if cursor.fetchone():
                    flash("Roll number already registered", "error")
                    return render_template('student_registration.html', form=form)
                
                # Check if email already exists
                cursor.execute("SELECT email FROM students WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash("Email already registered", "error")
                    return render_template('student_registration.html', form=form)
                
                cursor.execute(
                    """INSERT INTO students (roll_no, full_name, email, password) 
                       VALUES (%s, %s, %s, %s)""", 
                    (roll_no, full_name, email, hashed_password.decode('utf-8'))
                )
                db.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('student_login'))
            except mysql.connector.Error as err:
                db.rollback()  # Rollback in case of error
                flash(f"Registration failed: {err}", "error")
                app.logger.error(f"Database error during registration: {err}")
                
    except Exception as e:
        app.logger.error(f"Error during registration: {e}")
        flash("An error occurred during registration. Please try again.", "error")
        
    return render_template('student_registration.html', form=form)

@app.route('/faculty_login', methods=['GET', 'POST'])
def faculty_login():
    form = LoginForm()
    if form.validate_on_submit():
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return render_template('faculty_login.html', form=form)
            
        username = form.username.data
        password = form.password.data
        
        try:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s AND user_type = 'faculty'", 
                (username, password)
            )
            user = cursor.fetchone()
            
            if user:
                session['user'] = username
                session['user_type'] = 'faculty'
                flash('Login successful!', 'success')
                return redirect(url_for('faculty_dashboard'))
            else:
                flash("Invalid credentials. Please try again.", "error")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "error")
            
    return render_template('faculty_login.html', form=form)

@app.route('/faculty_registration', methods=['GET', 'POST'])
def faculty_registration():
    if request.method == 'POST':
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return render_template('faculty_registration.html')
            
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, user_type) VALUES (%s, %s, %s, 'faculty')", 
                (username, password, email)
            )
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('faculty_login'))
        except mysql.connector.Error as err:
            flash(f"Registration failed: {err}", "error")
            
    return render_template('faculty_registration.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Student Routes
@app.route('/student_portal')
@login_required
def student_portal():
    if session.get('user_type') != 'student':
        abort(403)
    return render_template('student_portal.html')

@app.route('/exam_result')
@login_required
def exam_result():
    if session.get('user_type') != 'student':
        abort(403)
    return render_template('exam_result.html')

@app.route('/timetable')
@login_required
def timetable():
    if session.get('user_type') != 'student':
        abort(403)
    return render_template('timetable.html')

# Faculty Routes
@app.route('/faculty_dashboard')
@login_required
def faculty_dashboard():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty_dashboard.html')

# Public Routes
@app.route('/about_us')
def about_us():
    try:
        return render_template('aboutus.html')
    except Exception as e:
        app.logger.error(f"Error rendering about us page: {e}")
        return render_template('404.html'), 404

@app.route('/academic')
def academic():
    try:
        return render_template('academics.html')
    except Exception as e:
        app.logger.error(f"Error rendering academics page: {e}")
        return render_template('404.html'), 404

@app.route('/admission_notices')
def admission_notices():
    try:
        return render_template('admission_notices.html')
    except Exception as e:
        app.logger.error(f"Error rendering admission notices page: {e}")
        return render_template('404.html'), 404

@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    try:
        if request.method == 'POST':
            # Handle form submission here
            flash('Message sent successfully!', 'success')
            return redirect(url_for('contact_us'))
        return render_template('contact_us.html')
    except Exception as e:
        app.logger.error(f"Error in contact us page: {e}")
        return render_template('404.html'), 404

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
