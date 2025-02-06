from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import smtplib
from email.mime.text import MIMEText



def GetDB():

    # Connect to the database and return the connection object
    db = sqlite3.connect("ReelReview/.database/gtg.db")
    db.row_factory = sqlite3.Row

    return db

def CheckLogin(username, password):

    db = GetDB()

    # Ask the database for a single user matching the provided name
    user = db.execute("SELECT * FROM Users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    
    print (user['password'])
    print (password)

    # Do they exist?
    if user is not None:
        # OK they exist, is their password correct
        if check_password_hash(user['password'], password):
            # They got it right, return their details 
            return user
        
    # If we get here, the username or password failed.
    return None

def GetAllGuesses():
    # Connect, query all reviews (guesses) and then return the data
    db = GetDB()
    guesses = db.execute("""
        SELECT reviews.id, reviews.review_text, reviews.title, reviews.reviewer_name, reviews.review_date, reviews.rating, users.username
        FROM reviews JOIN users ON reviews.user_id = users.id
        ORDER BY review_date DESC
    """).fetchall()
    db.close()
    return guesses
