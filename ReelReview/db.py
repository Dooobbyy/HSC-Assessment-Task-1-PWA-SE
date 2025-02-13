import os
import sqlite3
from werkzeug.security import check_password_hash

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'ReelReview', '.database', 'gtg.db')

def GetDB():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db

def CheckLogin(username, password):
    db = GetDB()
    # Note: Using lowercase table name "users"
    user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    
    if user is not None and check_password_hash(user['password'], password):
        return user
    
    db.close()
    return None

def GetAllGuesses():
    db = GetDB()
    guesses = db.execute("""
        SELECT reviews.id, reviews.review_text, reviews.title, reviews.reviewer_name, reviews.review_date, reviews.rating, users.username
        FROM reviews JOIN users ON reviews.user_id = users.id
        ORDER BY review_date DESC
    """).fetchall()
    db.close()
    return guesses
