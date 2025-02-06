from flask import Flask, render_template, request, redirect, url_for, flash, session
import db
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "ReelReview"


# Initialize database
def init_db():
    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_token TEXT
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

# Send verification email
def send_verification_email(email, token):
    sender_email = "mrdobby07@gmail.com"  
    sender_password = "wssb wrhe xgdh esvu" 
    recipient_email = email

    # Email contents
    subject = "Verify Your Email"
    body = f"Please click the following link to verify your email: http://127.0.0.1:5000/verify_email?token={token}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email



    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        print("Verification email sent!")
    except Exception as e:
        print(f"Failed to send email: {e}")


@app.route('/')
def index():
    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reviews')
    reviews = db.GetAllGuesses()
    conn.close()
    return render_template('index.html', reviews=reviews)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        max_username_length = 18
        max_password_length = 25

        # Enforce character limit
        if len(username) > max_username_length:
            flash(f'Username cannot exceed {max_username_length} characters.')
            return redirect(url_for('register'))
        if len(password) > max_password_length:
            flash(f'Password cannot exceed {max_password_length} characters.')
            return redirect(url_for('register'))
        if password != password_confirm:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('register'))

        conn = sqlite3.connect('.database/gtg.db')
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("Username already exists.")
            conn.close()
            return redirect(url_for('register'))

        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email already in use.")
            conn.close()
            return redirect(url_for('register'))

        # Continue with registration if no conflicts
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
            flash('An integrity error occurred. Please try again.')
        finally:
            conn.close()
    
    return render_template('register.html')



@app.route('/verify_email')
def verify_email():
    token = request.args['token']
    if not token:
        return "Invalid verification link.", 400

    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE verification_token = ?', (token,))
    user = cursor.fetchone()

    if user:
        cursor.execute('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()
        return "Email verified successfully! You can now log in."
    else:
        conn.close()
        return "Invalid or expired verification link.", 400



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('.database/gtg.db')
        cursor = conn.cursor()
        
        # 1. Check if the username exists.
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            flash("Username doesn't exist.")
            conn.close()
            return redirect(url_for('login'))

        # 2. Check if the email exists in the database at all.
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        email_user = cursor.fetchone()
        if not email_user:
            flash("No account with that email.")
            conn.close()
            return redirect(url_for('login'))
        
        # 3. Check if the email is associated with the provided username.
        if user[3] != email:
            flash("Email not associated with username.")
            conn.close()
            return redirect(url_for('login'))
        
        # 4. Check if the password is correct.
        if not check_password_hash(user[2], password):
            flash("Incorrect password.")
            conn.close()
            return redirect(url_for('login'))
        
        # 5. Check if the account is verified.
        if user[4] != 1:
            flash("Account not verified.")
            conn.close()
            return redirect(url_for('login'))
        
        # All checks passed – log the user in.
        session['user_id'] = user[0]
        session['username'] = user[1]
        conn.close()
        return redirect(url_for('index'))
        
    return render_template('login.html')



@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Extract form data
        movie_title = request.form['movie_title']
        review_text = request.form['review_text']
        review_date = request.form['review_date']
        rating = request.form['rating']
        reviewer_name = session['username']  # Get username from session

        # Define maximum allowed lengths
        max_title_length = 50  
        max_review_length = 250

        # Server-side validation for character limits
        if len(movie_title) > max_title_length:
            flash(f'Movie title cannot exceed {max_title_length} characters.')
            return redirect(url_for('dashboard'))
        if len(review_text) > max_review_length:
            flash(f'Review text cannot exceed {max_review_length} characters.')
            return redirect(url_for('dashboard'))

        # Insert review into the database if validations pass
        conn = sqlite3.connect('.database/gtg.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reviews (title, reviewer_name, review_text, review_date, rating, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (movie_title, reviewer_name, review_text, review_date, rating, session['user_id']))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    # Fetch all reviews for the logged-in user
    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reviews WHERE user_id = ?', (session['user_id'],))
    reviews = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', reviews=reviews)



@app.route('/reviews')
def reviews():
    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reviews')  # Fetch all reviews (or filter as needed)
    reviews = cursor.fetchall()
    conn.close()
    return render_template('reviews.html', reviews=reviews)



@app.route("/logout")
def Logout():
    session.clear()
    return redirect("/")



@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash("You must be logged in to delete your account.")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    conn = sqlite3.connect('.database/gtg.db')
    cursor = conn.cursor()
    
    # Option 1: Soft-delete by updating the user's record and setting a deleted flag.
    cursor.execute("""
        UPDATE users
        SET username = 'deleted user', email = 0, verified = 0
        WHERE id = ?
    """, (user_id,))
    
    # Option 2: Also update reviews to show "deleted user" as the reviewer name.
    cursor.execute("""
        UPDATE reviews
        SET reviewer_name = 'deleted user'
        WHERE user_id = ?
    """, (user_id,))
    
    conn.commit()
    conn.close()
    
    # Clear the session so the user is logged out.
    session.clear()
    flash("Your account has been deleted.")
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)