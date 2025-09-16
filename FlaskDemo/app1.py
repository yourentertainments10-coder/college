from flask import Flask, render_template, request, redirect, url_for, session, abort, g, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, Regexp
import mysql.connector
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import bcrypt
import logging
from datetime import timedelta, datetime

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
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Name must be between 2 and 100 characters')
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address')
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

class FacultyRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=50, message='Username must be between 4 and 50 characters')
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    submit = SubmitField('Register')

# Database Configuration
def init_db():
    try:
        # First try to connect without database
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root@123"  # Replace with your MySQL root password if you set one
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
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                user_type ENUM('faculty', 'admin') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status ENUM('active', 'inactive') DEFAULT 'active'
            )
        """)
        
        # Create courses table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS courses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                course_code VARCHAR(10) UNIQUE NOT NULL,
                course_name VARCHAR(100) NOT NULL,
                department VARCHAR(50),
                credits INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create classes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS classes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                course_id INT,
                faculty_id INT,
                section VARCHAR(10),
                semester INT,
                academic_year VARCHAR(9),
                room_number VARCHAR(20),
                schedule_time VARCHAR(50),
                schedule_day VARCHAR(20),
                max_students INT,
                FOREIGN KEY (course_id) REFERENCES courses(id),
                FOREIGN KEY (faculty_id) REFERENCES users(id)
            )
        """)

        # Create student_classes table (enrollment)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_classes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT,
                class_id INT,
                enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status ENUM('active', 'dropped', 'completed') DEFAULT 'active',
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (class_id) REFERENCES classes(id)
            )
        """)

        # Create attendance table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT,
                class_id INT,
                date DATE,
                status ENUM('present', 'absent', 'late') NOT NULL,
                marked_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (class_id) REFERENCES classes(id),
                FOREIGN KEY (marked_by) REFERENCES users(id)
            )
        """)

        # Create assignments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assignments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                class_id INT,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                due_date DATETIME,
                max_points INT,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (class_id) REFERENCES classes(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        # Create assignment_submissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assignment_submissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                assignment_id INT,
                student_id INT,
                submission_text TEXT,
                file_path VARCHAR(255),
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                grade FLOAT,
                feedback TEXT,
                graded_by INT,
                graded_at TIMESTAMP,
                FOREIGN KEY (assignment_id) REFERENCES assignments(id),
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (graded_by) REFERENCES users(id)
            )
        """)

        # Create grades table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS grades (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT,
                class_id INT,
                assignment_id INT,
                grade_type ENUM('assignment', 'midterm', 'final', 'project'),
                grade_value FLOAT,
                max_grade FLOAT,
                comments TEXT,
                graded_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (class_id) REFERENCES classes(id),
                FOREIGN KEY (assignment_id) REFERENCES assignments(id),
                FOREIGN KEY (graded_by) REFERENCES users(id)
            )
        """)

        # Create schedule table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedule (
                id INT AUTO_INCREMENT PRIMARY KEY,
                faculty_id INT,
                class_id INT,
                day_of_week ENUM('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'),
                start_time TIME,
                end_time TIME,
                room_number VARCHAR(20),
                type ENUM('lecture', 'lab', 'office_hours'),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (faculty_id) REFERENCES users(id),
                FOREIGN KEY (class_id) REFERENCES classes(id)
            )
        """)

        # Create notifications table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                user_type ENUM('student', 'faculty'),
                title VARCHAR(200),
                message TEXT,
                type ENUM('info', 'warning', 'success', 'error'),
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        db.commit()
        cursor.close()
        db.close()
        print("Database initialized successfully")
    except mysql.connector.Error as err:
        print(f"Error initializing database: {err}")
        if err.errno == 1045:  # Access denied
            print("Please check your MySQL username and password")
        elif err.errno == 2003:  # Can't connect
            print("Please make sure MySQL server is running")

# Initialize database on startup
init_db()

def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root@123",  # Replace with your MySQL root password if you set one
                database="dseu",
                autocommit=False
            )
            g.cursor = g.db.cursor(dictionary=True)
        except mysql.connector.Error as err:
            print(f"Database connection error: {err}")
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
        if 'user' not in session or not session.get('user_type'):
            flash('Please login to access this page', 'warning')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    try:
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error. Please try again later.", "error")
            return render_template('home.html', error=True)
            
        # Your existing code here
        return render_template('home.html')
    except Exception as e:
        flash("An error occurred. Please try again later.", "error")
        return render_template('home.html', error=True)

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return render_template('student_login.html', form=form)
            
        roll_no = form.roll_no.data
        password = form.password.data
        
        try:
            cursor.execute(
                "SELECT * FROM students WHERE roll_no = %s", 
                (roll_no,)
            )
            student = cursor.fetchone()
            
            if student:
                # Get the stored hash
                stored_hash = student['password']
                
                # Print debug information
                print(f"Attempting login for roll_no: {roll_no}")
                print(f"Input password: {password}")
                print(f"Stored hash: {stored_hash}")
                
                # Verify password
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    print("Password verified successfully")
                    session.permanent = True
                    session['user'] = student['full_name']
                    session['user_type'] = 'student'
                    session['roll_no'] = student['roll_no']
                    session['user_id'] = student['id']
                    flash('Login successful!', 'success')
                    return redirect(url_for('student_portal'))
                else:
                    print("Password verification failed")
            
            flash("Invalid roll number or password.", "error")
        except Exception as e:
            print(f"Login error: {e}")  # For debugging
            flash("An error occurred during login.", "error")
            
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
            password = form.password.data
            
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
            
            # Hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Insert new student
            cursor.execute(
                """INSERT INTO students (roll_no, full_name, email, password) 
                   VALUES (%s, %s, %s, %s)""", 
                (roll_no, full_name, email, hashed.decode('utf-8'))
            )
            db.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login'))
            
    except Exception as e:
        print(f"Registration error: {e}")  # For debugging
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
                "SELECT * FROM users WHERE username = %s AND user_type = 'faculty'", 
                (username,)
            )
            faculty = cursor.fetchone()
            
            if faculty:
                # Print for debugging
                print(f"Stored hash: {faculty['password']}")
                print(f"Input password: {password}")
                
                # Convert stored hash from string back to bytes
                stored_hash = faculty['password'].encode('utf-8')
                
                # Check password
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    session.permanent = True
                    session['user'] = faculty['username']
                    session['user_type'] = 'faculty'
                    session['user_id'] = faculty['id']
                    flash('Login successful!', 'success')
                    return redirect(url_for('faculty_dashboard'))
                else:
                    print("Password verification failed")
            
            flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"Login error: {e}")  # Print for debugging
            flash("An error occurred during login.", "error")
            
    return render_template('faculty_login.html', form=form)

@app.route('/faculty_registration', methods=['GET', 'POST'])
def faculty_registration():
    form = FacultyRegistrationForm()
    try:
        if form.validate_on_submit():
            db, cursor = get_db()
            if not db or not cursor:
                flash("Database connection error", "error")
                return render_template('faculty_registration.html', form=form)
                
            username = form.username.data
            email = form.email.data
            password = form.password.data
            
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash("Username already registered", "error")
                return render_template('faculty_registration.html', form=form)
            
            # Check if email already exists
            cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already registered", "error")
                return render_template('faculty_registration.html', form=form)
            
            # Hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Insert new faculty
            cursor.execute(
                """INSERT INTO users (username, email, password, user_type) 
                   VALUES (%s, %s, %s, 'faculty')""",
                (username, email, hashed.decode('utf-8'))
            )
            db.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('faculty_login'))
            
    except Exception as e:
        print("Faculty Registration error:", str(e))
        print(f"Registration error: {e}")  # For debugging
        flash("An error occurred during registration. Please try again.", "error")
        
    return render_template('faculty_registration.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('home'))

# Student Routes
@app.route('/student_portal')
@login_required
def student_portal():
    if session.get('user_type') != 'student':
        abort(403)
    
    try:
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return redirect(url_for('home'))
            
        student_id = session.get('user_id')
        
        # Get student's basic info
        cursor.execute("""
            SELECT * FROM students 
            WHERE id = %s AND status = 'active'
        """, (student_id,))
        student = cursor.fetchone()
        
        if not student:
            flash("Student not found", "error")
            return redirect(url_for('home'))
            
        # Initialize empty data structures for optional data
        classes = []
        attendance = {'attendance_percentage': 0}
        pending_assignments = []
        recent_grades = []
        
        # Try to get classes (if table exists)
        try:
            cursor.execute("""
                SELECT sc.*, c.section, co.course_name, u.username as faculty_name 
                FROM student_classes sc 
                JOIN classes c ON sc.class_id = c.id 
                JOIN courses co ON c.course_id = co.id 
                JOIN users u ON c.faculty_id = u.id 
                WHERE sc.student_id = %s AND sc.status = 'active'
            """, (student_id,))
            classes = cursor.fetchall() or []
        except mysql.connector.Error:
            pass  # Table might not exist yet
            
        # Try to get attendance (if table exists)
        try:
            cursor.execute("""
                SELECT 
                    COUNT(CASE WHEN status = 'present' THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0) as attendance_percentage 
                FROM attendance 
                WHERE student_id = %s
            """, (student_id,))
            attendance_result = cursor.fetchone()
            if attendance_result:
                attendance = attendance_result
        except mysql.connector.Error:
            pass
            
        # Try to get pending assignments (if table exists)
        try:
            cursor.execute("""
                SELECT a.*, c.section, co.course_name 
                FROM assignments a 
                JOIN classes c ON a.class_id = c.id 
                JOIN courses co ON c.course_id = co.id 
                JOIN student_classes sc ON c.id = sc.class_id 
                WHERE sc.student_id = %s 
                AND a.due_date > NOW() 
                AND NOT EXISTS (
                    SELECT 1 FROM assignment_submissions 
                    WHERE assignment_id = a.id AND student_id = %s
                )
            """, (student_id, student_id))
            pending_assignments = cursor.fetchall() or []
        except mysql.connector.Error:
            pass
            
        # Try to get recent grades (if table exists)
        try:
            cursor.execute("""
                SELECT g.*, c.section, co.course_name 
                FROM grades g 
                JOIN classes c ON g.class_id = c.id 
                JOIN courses co ON c.course_id = co.id 
                WHERE g.student_id = %s 
                ORDER BY g.created_at DESC LIMIT 5
            """, (student_id,))
            recent_grades = cursor.fetchall() or []
        except mysql.connector.Error:
            pass
            
        return render_template('student_portal.html',
                             student=student,
                             classes=classes,
                             attendance=attendance,
                             pending_assignments=pending_assignments,
                             recent_grades=recent_grades)
                             
    except Exception as e:
        app.logger.error(f"Error in student portal: {e}")
        flash("An error occurred while loading the portal", "error")
        return redirect(url_for('home'))

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

@app.route('/assignments')
@login_required
def assignments():
    if session.get('user_type') != 'student':
        abort(403)
    return render_template('assignments.html')

@app.route('/attendance')
@login_required
def attendance():
    if session.get('user_type') != 'student':
        abort(403)
    return render_template('attendance.html')

# Faculty Routes
@app.route('/faculty_dashboard')
@login_required
def faculty_dashboard():
    if session.get('user_type') != 'faculty':
        abort(403)
    
    try:
        db, cursor = get_db()
        if not db or not cursor:
            flash("Database connection error", "error")
            return redirect(url_for('home'))
            
        faculty_id = session.get('user_id')
        
        # Get faculty's basic info
        cursor.execute("""
            SELECT * FROM users 
            WHERE id = %s AND user_type = 'faculty' AND status = 'active'
        """, (faculty_id,))
        faculty = cursor.fetchone()
        
        if not faculty:
            flash("Faculty not found", "error")
            return redirect(url_for('home'))
            
        # Initialize empty data structures for optional data
        classes = []
        recent_assignments = []
        pending_submissions = 0
        schedule = []
        
        # Try to get classes (if table exists)
        try:
            cursor.execute("""
                SELECT c.*, co.course_name, COUNT(sc.id) as student_count 
                FROM classes c 
                JOIN courses co ON c.course_id = co.id 
                LEFT JOIN student_classes sc ON c.id = sc.class_id 
                WHERE c.faculty_id = %s 
                GROUP BY c.id
            """, (faculty_id,))
            classes = cursor.fetchall() or []
        except mysql.connector.Error:
            pass
            
        # Try to get recent assignments (if table exists)
        try:
            cursor.execute("""
                SELECT a.*, c.section, co.course_name 
                FROM assignments a 
                JOIN classes c ON a.class_id = c.id 
                JOIN courses co ON c.course_id = co.id 
                WHERE c.faculty_id = %s 
                ORDER BY a.created_at DESC LIMIT 5
            """, (faculty_id,))
            recent_assignments = cursor.fetchall() or []
        except mysql.connector.Error:
            pass
            
        # Try to get pending submissions count (if table exists)
        try:
            cursor.execute("""
                SELECT COUNT(*) as pending_count 
                FROM assignment_submissions as 
                JOIN assignments a ON as.assignment_id = a.id 
                JOIN classes c ON a.class_id = c.id 
                WHERE c.faculty_id = %s AND as.grade IS NULL
            """, (faculty_id,))
            result = cursor.fetchone()
            if result:
                pending_submissions = result['pending_count']
        except mysql.connector.Error:
            pass
            
        # Try to get today's schedule (if table exists)
        try:
            today = datetime.now().strftime('%A')
            cursor.execute("""
                SELECT s.*, c.section, co.course_name, co.course_code 
                FROM schedule s 
                JOIN classes c ON s.class_id = c.id 
                JOIN courses co ON c.course_id = co.id 
                WHERE s.faculty_id = %s AND s.day_of_week = %s 
                ORDER BY s.start_time
            """, (faculty_id, today))
            schedule = cursor.fetchall() or []
        except mysql.connector.Error:
            pass
            
        return render_template('faculty_dashboard.html',
                             faculty=faculty,
                             classes=classes,
                             recent_assignments=recent_assignments,
                             pending_submissions=pending_submissions,
                             schedule=schedule)
                             
    except Exception as e:
        app.logger.error(f"Error in faculty dashboard: {e}")
        flash("An error occurred while loading the dashboard", "error")
        return redirect(url_for('home'))

@app.route('/faculty/myclasses')
@login_required
def faculty_myclasses():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/myclasses.html')

@app.route('/faculty/students')
@login_required
def faculty_students():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/students.html')

@app.route('/faculty/attendance')
@login_required
def faculty_attendance():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/attendance.html')

@app.route('/faculty/assignments')
@login_required
def faculty_assignments():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/assignments.html')

@app.route('/faculty/grades')
@login_required
def faculty_grades():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/grades.html')

@app.route('/faculty/schedule')
@login_required
def faculty_schedule():
    if session.get('user_type') != 'faculty':
        abort(403)
    return render_template('faculty/schedule.html')

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

# Add before_request handler to check database connection
@app.before_request
def before_request():
    check_tables_exist()  # Ensure tables exist
    g.user = None
    if 'user' in session:
        g.user = session['user']
        
        # Skip database check for static files and some routes
        if request.endpoint and request.endpoint.startswith('static'):
            return
            
        # Verify database connection and session validity
        db, cursor = get_db()
        if not db or not cursor:
            session.clear()
            flash("Database connection lost. Please login again.", "error")
            return redirect(url_for('home'))
            
        try:
            if session.get('user_type') == 'student':
                cursor.execute(
                    "SELECT id FROM students WHERE roll_no = %s AND status = 'active'", 
                    (session.get('roll_no'),)
                )
            elif session.get('user_type') == 'faculty':
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s AND user_type = 'faculty'", 
                    (session.get('user'),)
                )
            
            if not cursor.fetchone():
                session.clear()
                flash("Session expired. Please login again.", "warning")
                return redirect(url_for('home'))
                
        except Exception as e:
            app.logger.error(f"Error checking session: {e}")
            session.clear()
            flash("An error occurred. Please login again.", "error")
            return redirect(url_for('home'))

# Add teardown handler
@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    cursor = g.pop('cursor', None)
    if cursor:
        cursor.close()
    if db:
        db.close()

# Also add this helper function to check if tables exist
def check_tables_exist():
    db, cursor = get_db()
    try:
        # Check if students table exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.tables 
            WHERE table_schema = 'dseu' 
            AND table_name IN ('students', 'users')
        """)
        count = cursor.fetchone()['COUNT(*)']
        if count < 2:
            init_db()  # Initialize database if tables don't exist
    except mysql.connector.Error as err:
        app.logger.error(f"Error checking tables: {err}")
        init_db()

if __name__ == '__main__':
    app.run(debug=True)
