import os
import secrets
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import bleach

# --- Configuration from environment variables ---
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'ReelReview', '.database', 'gtg.db')
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "your_email@example.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "your_email_password")
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", secrets.token_urlsafe(32))
BASE_URL = os.environ.get("BASE_URL", "https://yourdomain.com")  # Must be HTTPS in production

app = Flask(__name__, static_url_path='', static_folder='static')
app.secret_key = APP_SECRET_KEY

# Secure session cookie settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add secure headers to all responses
@app.after_request
def set_secure_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    return response

# Initialize (and update) the database schema
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_token TEXT,
            reset_token TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            review_date TEXT NOT NULL,
            reviewer_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            review_text TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# --- Email sending functions ---
def send_verification_email(email, token):
    recipient_email = email
    subject = "Verify Your Email"
    verification_link = f"{BASE_URL}/verify_email?token={token}"
    body = f"Please click the following link to verify your email: {verification_link}"
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        app.logger.info("Verification email sent!")
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")

def send_reset_email(email, token):
    recipient_email = email
    subject = "Reset Your Password"
    reset_link = f"{BASE_URL}/reset_password?token={token}"
    body = f"Please click the following link to reset your password: {reset_link}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        app.logger.info("Reset email sent!")
    except Exception as e:
        app.logger.error(f"Failed to send reset email: {e}")

# --- Routes ---
@app.route('/')
def index():
    # Use our helper from db.py to fetch reviews
    from db import GetAllGuesses
    reviews = GetAllGuesses()
    return render_template('index.html', reviews=reviews)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Apply Bleach cleaning to text inputs
        username = bleach.clean(request.form['username']).strip()
        email = bleach.clean(request.form['email']).strip().lower()
        # Do not bleach passwords because they must remain unchanged
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        max_username_length = 18
        max_password_length = 25

        if len(username) > max_username_length:
            flash(f'Username cannot exceed {max_username_length} characters.', 'error')
            return redirect(url_for('register'))
        if len(password) > max_password_length:
            flash(f'Password cannot exceed {max_password_length} characters.', 'error')
            return redirect(url_for('register'))
        if password != password_confirm:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('register'))

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("Username already exists.", 'error')
            conn.close()
            return redirect(url_for('register'))

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email already in use.", 'error')
            conn.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        verification_token = secrets.token_urlsafe(16)

        try:
            cursor.execute('''
                INSERT INTO users (username, password, email, verified, verification_token)
                VALUES (?, ?, ?, 0, ?)
            ''', (username, hashed_password, email, verification_token))
            conn.commit()
            send_verification_email(email, verification_token)
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('An integrity error occurred. Please try again.', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/verify_email')
def verify_email():
    token = request.args.get('token')
    if not token:
        flash("Invalid verification link.", 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE verification_token = ?', (token,))
    user = cursor.fetchone()

    if user:
        cursor.execute('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', (user[0],))
        conn.commit()
        flash("Email verified successfully! You can now log in.", 'success')
    else:
        flash("Invalid or expired verification link.", 'error')
    conn.close()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Apply Bleach cleaning
        username = bleach.clean(request.form['username']).strip()
        email = bleach.clean(request.form['email']).strip().lower()
        password = request.form['password']

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            flash("Invalid username or password.", 'error')
            conn.close()
            return redirect(url_for('login'))

        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        email_user = cursor.fetchone()
        if not email_user:
            flash("Invalid username or password.", 'error')
            conn.close()
            return redirect(url_for('login'))
        
        if user[3] != email:
            flash("Invalid username or password.", 'error')
            conn.close()
            return redirect(url_for('login'))
        
        if not check_password_hash(user[2], password):
            flash("Invalid username or password.", 'error')
            conn.close()
            return redirect(url_for('login'))
        
        if user[4] != 1:
            flash("Account not verified. Please check your email.", 'error')
            conn.close()
            return redirect(url_for('login'))
        
        session.clear()
        session['user_id'] = user[0]
        session['username'] = user[1]
        conn.close()
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Bleach cleaning for email
        email = bleach.clean(request.form['email']).strip().lower()
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            reset_token = secrets.token_urlsafe(16)
            cursor.execute('UPDATE users SET reset_token = ? WHERE id = ?', (reset_token, user[0]))
            conn.commit()
            send_reset_email(email, reset_token)
            flash("Password reset instructions have been sent to your email.", "success")
        else:
            # Do not reveal if the email exists
            flash("If an account with that email exists, reset instructions have been sent.", "info")
        conn.close()
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        token = request.args.get('token')
        if not token:
            flash("Invalid or missing token.", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE reset_token = ?', (token,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            flash("Invalid or expired token.", "error")
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)
    
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(new_password)
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE reset_token = ?', (token,))
        user = cursor.fetchone()
        if not user:
            flash("Invalid or expired token.", "error")
            conn.close()
            return redirect(url_for('login'))
        
        cursor.execute('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?', (hashed_password, user[0]))
        conn.commit()
        conn.close()
        flash("Your password has been updated successfully.", "success")
        return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Apply bleach to review inputs as well
        movie_title = bleach.clean(request.form['movie_title'])
        review_text = bleach.clean(request.form['review_text'])
        rating = request.form['rating']
        reviewer_name = session.get('username')

        max_title_length = 50  
        max_review_length = 250

        if len(movie_title) > max_title_length:
            flash(f'Movie title cannot exceed {max_title_length} characters.', 'error')
            return redirect(url_for('dashboard'))
        if len(review_text) > max_review_length:
            flash(f'Review text cannot exceed {max_review_length} characters.', 'error')
            return redirect(url_for('dashboard'))

        review_date = datetime.now().strftime("%Y-%m-%d")
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reviews (title, reviewer_name, review_text, review_date, rating, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (movie_title, reviewer_name, review_text, review_date, rating, session['user_id']))
        conn.commit()
        conn.close()

        flash("Review submitted successfully.", "success")
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reviews WHERE user_id = ?', (session['user_id'],))
    reviews = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', reviews=reviews)

@app.route('/delete_review/<int:review_id>', methods=['POST'])
def delete_review(review_id):
    if 'user_id' not in session:
        flash("You must be logged in to delete a review.", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reviews WHERE id = ? AND user_id = ?", (review_id, session['user_id']))
    review = cursor.fetchone()
    
    if not review:
        flash("Review not found or you do not have permission to delete it.", "error")
        conn.close()
        return redirect(url_for('index'))
    
    cursor.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
    conn.commit()
    conn.close()
    flash("Review deleted successfully.", "success")
    return redirect(url_for('index'))

@app.route('/reviews')
def reviews():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reviews')
    reviews = cursor.fetchall()
    conn.close()
    return render_template('reviews.html', reviews=reviews)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash("You must be logged in to delete your account.", "error")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Soft-delete the user record
    cursor.execute("""
        UPDATE users
        SET username = 'deleted user', email = '', verified = 0
        WHERE id = ?
    """, (user_id,))
    
    # Update reviews to show a deleted username
    cursor.execute("""
        UPDATE reviews
        SET reviewer_name = 'deleted user'
        WHERE user_id = ?
    """, (user_id,))
    
    conn.commit()
    conn.close()
    
    session.clear()
    flash("Your account has been deleted.", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    # In production, set debug=False
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=False, port=5000, host='0.0.0.0')