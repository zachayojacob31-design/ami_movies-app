"""
Ami Movies - Complete Web Application
Production Ready with All Features
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_compress import Compress
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, ValidationError
import sqlite3
import hashlib
import secrets
import re
import json
from datetime import datetime, timedelta
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
import pytz

# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///ami_movies.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'password-salt'
    WTF_CSRF_ENABLED = True
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    RATELIMIT_DEFAULT = "200 per day"
    RATELIMIT_STORAGE_URL = "memory://"

app.config.from_object(Config)

# Initialize extensions
bootstrap = Bootstrap5(app)
compress = Compress(app)

# Security headers
csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    'font-src': ["'self'", "https://cdn.jsdelivr.net"],
    'img-src': ["'self'", "data:", "https:", "http:"]
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_report_uri="/csp-report",
    force_https=True,
    session_cookie_secure=True,
    session_cookie_httponly=True
)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Email configuration
class EmailConfig:
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'your_email@gmail.com')
    SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'your_app_password')
    IS_CONFIGURED = all([SENDER_EMAIL != 'your_email@gmail.com', 
                        SENDER_PASSWORD != 'your_app_password'])

# Logging configuration
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/ami_movies.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Ami Movies startup')

# Database initialization
def init_db():
    """Initialize database with sample data"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            is_admin BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            avatar_url TEXT DEFAULT '/static/images/default-avatar.png',
            bio TEXT DEFAULT '',
            preferences TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            last_active TIMESTAMP
        )
    ''')
    
    # Password reset codes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            INDEX idx_user_code (user_id, code)
        )
    ''')
    
    # Movies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            year TEXT,
            rating REAL,
            genre TEXT,
            duration TEXT,
            director TEXT,
            cast TEXT,
            plot TEXT,
            poster_url TEXT,
            trailer_url TEXT,
            imdb_id TEXT,
            language TEXT DEFAULT 'English',
            country TEXT DEFAULT 'USA',
            awards TEXT,
            box_office TEXT,
            website TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_title (title),
            INDEX idx_genre (genre),
            INDEX idx_rating (rating)
        )
    ''')
    
    # Movie ratings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movie_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            rating INTEGER CHECK(rating >= 1 AND rating <= 10),
            review TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (movie_id) REFERENCES movies(id),
            UNIQUE(user_id, movie_id)
        )
    ''')
    
    # User preferences
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            preference_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (movie_id) REFERENCES movies(id),
            UNIQUE(user_id, movie_id, preference_type),
            INDEX idx_user_pref (user_id, preference_type)
        )
    ''')
    
    # Watch history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watch_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            watched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            duration_watched INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (movie_id) REFERENCES movies(id),
            INDEX idx_user_watch (user_id, watched_at)
        )
    ''')
    
    # Notifications
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            INDEX idx_user_notif (user_id, is_read)
        )
    ''')
    
    # Create admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    if cursor.fetchone()[0] == 0:
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', "Admin123!".encode('utf-8'),
            salt.encode('utf-8'), 100000
        ).hex()
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, salt, full_name, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', ("admin@amimovies.com", password_hash, salt, "Administrator", True))
        
        app.logger.info('Created admin user')
    
    # Add sample movies if not exists
    cursor.execute("SELECT COUNT(*) FROM movies")
    if cursor.fetchone()[0] == 0:
        movies = get_sample_movies()
        cursor.executemany('''
            INSERT INTO movies (title, year, rating, genre, duration, director, cast, plot, poster_url, trailer_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', movies)
        app.logger.info(f'Added {len(movies)} sample movies')
    
    conn.commit()
    conn.close()

def get_sample_movies():
    """Return list of sample movies with more details"""
    return [
        ("The Shawshank Redemption", "1994", 9.3, "Drama", "142 min", 
         "Frank Darabont", "Tim Robbins, Morgan Freeman, Bob Gunton",
         "Two imprisoned men bond over several years, finding solace and eventual redemption through acts of common decency.",
         "https://m.media-amazon.com/images/M/MV5BNDE3ODcxYzMtY2YzZC00NmNlLWJiNDMtZDViZWM2MzIxZDYwXkEyXkFqcGdeQXVyNjAwNDUxODI@._V1_.jpg",
         "https://www.youtube.com/watch?v=6hB3S9bIaco"),
        
        ("The Godfather", "1972", 9.2, "Crime, Drama", "175 min",
         "Francis Ford Coppola", "Marlon Brando, Al Pacino, James Caan",
         "The aging patriarch of an organized crime dynasty transfers control to his reluctant son.",
         "https://m.media-amazon.com/images/M/MV5BM2MyNjYxNmUtYTAwNi00MTYxLWJmNWYtYzZlODY3ZTk3OTFlXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg",
         "https://www.youtube.com/watch?v=sY1S34973zA"),
        
        ("The Dark Knight", "2008", 9.0, "Action, Crime, Drama", "152 min",
         "Christopher Nolan", "Christian Bale, Heath Ledger, Aaron Eckhart",
         "When the Joker wreaks havoc on Gotham, Batman faces his greatest psychological and physical test.",
         "https://m.media-amazon.com/images/M/MV5BMTMxNTMwODM0NF5BMl5BanBnXkFtZTcwODAyMTk2Mw@@._V1_.jpg",
         "https://www.youtube.com/watch?v=EXeTwQWrcwY"),
        
        ("Pulp Fiction", "1994", 8.9, "Crime, Drama", "154 min",
         "Quentin Tarantino", "John Travolta, Uma Thurman, Samuel L. Jackson",
         "The lives of two mob hitmen, a boxer, a gangster and his wife intertwine in four tales of violence and redemption.",
         "https://m.media-amazon.com/images/M/MV5BNGNhMDIzZTUtNTBlZi00MTRlLWFjM2ItYzViMjE3YzI5MjljXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg",
         "https://www.youtube.com/watch?v=s7EdQ4FqbhY"),
        
        ("Inception", "2010", 8.8, "Action, Sci-Fi, Thriller", "148 min",
         "Christopher Nolan", "Leonardo DiCaprio, Joseph Gordon-Levitt, Elliot Page",
         "A thief who steals corporate secrets through dream-sharing technology is given the task of planting an idea.",
         "https://m.media-amazon.com/images/M/MV5BMjAxMzY3NjcxNF5BMl5BanBnXkFtZTcwNTI5OTM0Mw@@._V1_.jpg",
         "https://www.youtube.com/watch?v=YoHD9XEInc0"),
        
        ("Fight Club", "1999", 8.8, "Drama", "139 min",
         "David Fincher", "Brad Pitt, Edward Norton, Meat Loaf",
         "An insomniac office worker and a devil-may-care soap maker form an underground fight club.",
         "https://m.media-amazon.com/images/M/MV5BNDIzNDU0YzEtYzE5Ni00ZjlkLTk5ZjgtNjM3NWE4YzA3Nzk3XkEyXkFqcGdeQXVyMjUzOTY1NTc@._V1_.jpg",
         "https://www.youtube.com/watch?v=SUXWAEX2jlg"),
        
        ("The Matrix", "1999", 8.7, "Action, Sci-Fi", "136 min",
         "Lana Wachowski, Lilly Wachowski", "Keanu Reeves, Laurence Fishburne, Carrie-Anne Moss",
         "A computer hacker learns from mysterious rebels about the true nature of his reality.",
         "https://m.media-amazon.com/images/M/MV5BNzQzOTk3OTAtNDQ0Zi00ZTVkLWI0MTEtMDllZjNkYzNjNTc4L2ltYWdlXkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
         "https://www.youtube.com/watch?v=vKQi3bBA1y8"),
        
        ("Interstellar", "2014", 8.6, "Adventure, Drama, Sci-Fi", "169 min",
         "Christopher Nolan", "Matthew McConaughey, Anne Hathaway, Jessica Chastain",
         "A team of explorers travel through a wormhole in space in an attempt to ensure humanity's survival.",
         "https://m.media-amazon.com/images/M/MV5BZjdkOTU3MDktN2IxOS00OGEyLWFmMjktY2FiMmZkNWIyODZiXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg",
         "https://www.youtube.com/watch?v=zSWdZVtXT7E"),
        
        ("Parasite", "2019", 8.6, "Comedy, Drama, Thriller", "132 min",
         "Bong Joon Ho", "Song Kang-ho, Lee Sun-kyun, Cho Yeo-jeong",
         "A poor family schemes to become employed by a wealthy family by infiltrating their household.",
         "https://m.media-amazon.com/images/M/MV5BYWZjMjk3ZTItODQ2ZC00NTY5LWE0ZDYtZTI3MjcwN2Q5NTVkXkEyXkFqcGdeQXVyODk4OTc3MTY@._V1_.jpg",
         "https://www.youtube.com/watch?v=5xH0HfJHsaY"),
        
        ("The Avengers", "2012", 8.0, "Action, Adventure, Sci-Fi", "143 min",
         "Joss Whedon", "Robert Downey Jr., Chris Evans, Scarlett Johansson",
         "Earth's mightiest heroes must come together to stop Loki from enslaving humanity.",
         "https://m.media-amazon.com/images/M/MV5BNDYxNjQyMjAtNTdiOS00NGYwLWFmNTAtNThmYjU5ZGI2YTI1XkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg",
         "https://www.youtube.com/watch?v=eOrNdBpGMv8"),
        
        ("Forrest Gump", "1994", 8.8, "Drama, Romance", "142 min",
         "Robert Zemeckis", "Tom Hanks, Robin Wright, Gary Sinise",
         "The history of the United States from the 1950s to the '70s unfolds from the perspective of an Alabama man.",
         "https://m.media-amazon.com/images/M/MV5BNWIwODRlZTUtY2U3ZS00Yzg1LWJhNzYtMmZiYmEyNmU1NjMzXkEyXkFqcGdeQXVyMTQxNzMzNDI@._V1_.jpg",
         "https://www.youtube.com/watch?v=bLvqoHBptjg"),
        
        ("The Lord of the Rings: The Return of the King", "2003", 9.0, "Action, Adventure, Drama", "201 min",
         "Peter Jackson", "Elijah Wood, Viggo Mortensen, Ian McKellen",
         "Gandalf and Aragorn lead the World of Men against Sauron's army to draw his gaze from Frodo and Sam.",
         "https://m.media-amazon.com/images/M/MV5BNzA5ZDNlZWMtM2NhNS00NDJjLTk4NDItYTRmY2EwMWZlMTY3XkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg",
         "https://www.youtube.com/watch?v=r5X-hFf6Bwo"),
        
        ("Spirited Away", "2001", 8.6, "Animation, Adventure, Family", "125 min",
         "Hayao Miyazaki", "Rumi Hiiragi, Miyu Irino, Mari Natsuki",
         "During her family's move to the suburbs, a sullen 10-year-old girl wanders into a world ruled by gods, witches, and spirits.",
         "https://m.media-amazon.com/images/M/MV5BMjlmZmI5MDctNDE2YS00YWE0LWE5ZWItZDBhYWQ0NTcxNWRhXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg",
         "https://www.youtube.com/watch?v=ByXuk9QqQkk"),
        
        ("The Silence of the Lambs", "1991", 8.6, "Crime, Drama, Thriller", "118 min",
         "Jonathan Demme", "Jodie Foster, Anthony Hopkins, Lawrence A. Bonney",
         "A young F.B.I. cadet must receive the help of an incarcerated and manipulative cannibal killer.",
         "https://m.media-amazon.com/images/M/MV5BNjNhZTk0ZmEtNjJhMi00YzFlLWE1MmEtYzM1M2ZmMGMwMTU4XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
         "https://www.youtube.com/watch?v=RuX2MQeb8UM"),
        
        ("Gladiator", "2000", 8.5, "Action, Adventure, Drama", "155 min",
         "Ridley Scott", "Russell Crowe, Joaquin Phoenix, Connie Nielsen",
         "A former Roman General sets out to exact vengeance against the corrupt emperor who murdered his family.",
         "https://m.media-amazon.com/images/M/MV5BMDliMmNhNDEtODUyOS00MjNlLTgxODEtN2U3NzIxMGVkZTA1L2ltYWdlXkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
         "https://www.youtube.com/watch?v=owK1qxDselE"),
        
        ("The Lion King", "1994", 8.5, "Animation, Adventure, Drama", "88 min",
         "Roger Allers, Rob Minkoff", "Matthew Broderick, Jeremy Irons, James Earl Jones",
         "Lion prince Simba and his father are targeted by his bitter uncle, who wants to ascend the throne himself.",
         "https://m.media-amazon.com/images/M/MV5BYTYxNGMyZTYtMjE3MS00MzNjLWFjNmYtMDk3N2FmM2JiM2M1XkEyXkFqcGdeQXVyNjY5NDU4MjI@._V1_.jpg",
         "https://www.youtube.com/watch?v=4sj1MT05lAA"),
        
        ("Avengers: Endgame", "2019", 8.4, "Action, Adventure, Drama", "181 min",
         "Anthony Russo, Joe Russo", "Robert Downey Jr., Chris Evans, Mark Ruffalo",
         "After the devastating events of Infinity War, the Avengers assemble once more to reverse Thanos' actions.",
         "https://m.media-amazon.com/images/M/MV5BMTc5MDE2ODcwNV5BMl5BanBnXkFtZTgwMzI2NzQ2NzM@._V1_.jpg",
         "https://www.youtube.com/watch?v=TcMBFSGVi1c"),
        
        ("The Departed", "2006", 8.5, "Crime, Drama, Thriller", "151 min",
         "Martin Scorsese", "Leonardo DiCaprio, Matt Damon, Jack Nicholson",
         "An undercover cop and a mole in the police attempt to identify each other.",
         "https://m.media-amazon.com/images/M/MV5BMTI1MTY2OTIxNV5BMl5BanBnXkFtZTYwNjQ4NjY3._V1_.jpg",
         "https://www.youtube.com/watch?v=iojhqm0JTW4"),
        
        ("Whiplash", "2014", 8.5, "Drama, Music", "106 min",
         "Damien Chazelle", "Miles Teller, J.K. Simmons, Melissa Benoist",
         "A promising young drummer enrolls at a cut-throat music conservatory.",
         "https://m.media-amazon.com/images/M/MV5BOTA5NDZlZGUtMjAxOS00YTRkLTkwYmMtYWQ0NWEwZDZiNjEzXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg",
         "https://www.youtube.com/watch?v=7d_jQycdQGo"),
        
        ("The Green Mile", "1999", 8.6, "Crime, Drama, Fantasy", "189 min",
         "Frank Darabont", "Tom Hanks, Michael Clarke Duncan, David Morse",
         "The lives of guards on Death Row are affected by one of their charges: a black man accused of murder.",
         "https://m.media-amazon.com/images/M/MV5BMTUxMzQyNjA5MF5BMl5BanBnXkFtZTYwOTU2NTY3._V1_.jpg",
         "https://www.youtube.com/watch?v=Ki4haFrqSrw")
    ]

# Database helper
def get_db():
    """Get database connection"""
    conn = sqlite3.connect('ami_movies.db')
    conn.row_factory = sqlite3.Row
    return conn

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Enter a valid email address")
    ], render_kw={"placeholder": "Enter your email"})
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ], render_kw={"placeholder": "Enter your password"})
    
    remember = BooleanField('Remember me')
    submit = SubmitField('Sign In', render_kw={"class": "btn-primary btn-lg w-100"})

class RegisterForm(FlaskForm):
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ], render_kw={"placeholder": "Enter your full name"})
    
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Enter a valid email address"),
        Length(max=120, message="Email is too long")
    ], render_kw={"placeholder": "Enter your email"})
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters"),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password must contain uppercase, lowercase, number and special character")
    ], render_kw={"placeholder": "Create a strong password"})
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ], render_kw={"placeholder": "Confirm your password"})
    
    submit = SubmitField('Create Account', render_kw={"class": "btn-success btn-lg w-100"})
    
    def validate_email(self, email):
        """Check if email already exists"""
        conn = get_db()
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email.data.lower(),)).fetchone()
        conn.close()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Enter a valid email address")
    ], render_kw={"placeholder": "Enter your email"})
    
    submit = SubmitField('Send Reset Code', render_kw={"class": "btn-primary w-100"})

class ResetPasswordForm(FlaskForm):
    code = StringField('Verification Code', validators=[
        DataRequired(message="Code is required"),
        Length(min=6, max=6, message="Code must be 6 digits"),
        Regexp(r'^\d{6}$', message="Code must be 6 digits")
    ], render_kw={"placeholder": "Enter 6-digit code"})
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters"),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password must contain uppercase, lowercase, number and special character")
    ], render_kw={"placeholder": "Enter new password"})
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('new_password', message="Passwords must match")
    ], render_kw={"placeholder": "Confirm new password"})
    
    submit = SubmitField('Reset Password', render_kw={"class": "btn-success w-100"})

class ProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Enter a valid email address"),
        Length(max=120, message="Email is too long")
    ])
    
    bio = TextAreaField('Bio', validators=[
        Length(max=500, message="Bio cannot exceed 500 characters")
    ], render_kw={"rows": 4, "placeholder": "Tell us about yourself..."})
    
    submit = SubmitField('Save Changes', render_kw={"class": "btn-primary"})

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required")
    ], render_kw={"placeholder": "Enter current password"})
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required"),
        Length(min=8, message="Password must be at least 8 characters"),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password must contain uppercase, lowercase, number and special character")
    ], render_kw={"placeholder": "Enter new password"})
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('new_password', message="Passwords must match")
    ], render_kw={"placeholder": "Confirm new password"})
    
    submit = SubmitField('Change Password', render_kw={"class": "btn-primary"})

class SearchForm(FlaskForm):
    query = StringField('Search', render_kw={"placeholder": "Search movies..."})
    genre = SelectField('Genre', choices=[
        ('', 'All Genres'), ('action', 'Action'), ('drama', 'Drama'), 
        ('comedy', 'Comedy'), ('sci-fi', 'Sci-Fi'), ('thriller', 'Thriller'),
        ('horror', 'Horror'), ('romance', 'Romance'), ('animation', 'Animation')
    ])
    year = SelectField('Year', choices=[
        ('', 'All Years'), ('2020s', '2020-2024'), ('2010s', '2010-2019'),
        ('2000s', '2000-2009'), ('1990s', '1990-1999'), ('1980s', '1980-1989'),
        ('1970s', '1970-1979')
    ])
    rating = SelectField('Minimum Rating', choices=[
        ('', 'Any Rating'), ('9', '9+'), ('8', '8+'), ('7', '7+'), ('6', '6+')
    ])
    submit = SubmitField('Search', render_kw={"class": "btn-primary"})

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# Utility functions
def hash_password(password, salt=None):
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'),
        salt.encode('utf-8'), 100000
    ).hex()
    return password_hash, salt

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    password_hash, _ = hash_password(password, salt)
    return password_hash == stored_hash

def send_reset_email(recipient_email, code):
    """Send password reset email"""
    if not EmailConfig.IS_CONFIGURED:
        app.logger.warning('Email not configured - running in demo mode')
        return False
    
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = "Ami Movies - Password Reset Code"
        message["From"] = EmailConfig.SENDER_EMAIL
        message["To"] = recipient_email
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #141414; color: white; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: #222; padding: 30px; border-radius: 10px; }}
                .logo {{ color: #e50914; font-size: 32px; font-weight: bold; text-align: center; margin-bottom: 20px; }}
                .code {{ background-color: #e50914; color: white; font-size: 36px; font-weight: bold; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0; letter-spacing: 5px; }}
                .message {{ font-size: 16px; line-height: 1.6; color: #aaa; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #444; text-align: center; color: #666; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🎬 AMI MOVIES</div>
                <div class="message">
                    <p>Hello!</p>
                    <p>You requested to reset your password. Use the verification code below to continue:</p>
                </div>
                <div class="code">{code}</div>
                <div class="message">
                    <p>This code will expire in <strong>10 minutes</strong>.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <p>For security reasons, never share this code with anyone.</p>
                </div>
                <div class="footer">
                    <p>© 2024 Ami Movies - Your Movie Collection</p>
                    <p>This is an automated email, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        part = MIMEText(html, "html")
        message.attach(part)
        
        with smtplib.SMTP(EmailConfig.SMTP_SERVER, EmailConfig.SMTP_PORT) as server:
            server.starttls()
            server.login(EmailConfig.SENDER_EMAIL, EmailConfig.SENDER_PASSWORD)
            server.sendmail(EmailConfig.SENDER_EMAIL, recipient_email, message.as_string())
        
        app.logger.info(f'Password reset email sent to {recipient_email}')
        return True
    except Exception as e:
        app.logger.error(f'Failed to send email: {str(e)}')
        return False

def update_last_active():
    """Update user's last active timestamp"""
    if 'user_id' in session:
        conn = get_db()
        conn.execute('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?', 
                    (session['user_id'],))
        conn.commit()
        conn.close()

# Routes
@app.route('/')
def index():
    """Home page"""
    update_last_active()
    
    conn = get_db()
    
    # Get featured movies
    featured = conn.execute('''
        SELECT * FROM movies 
        WHERE rating >= 8.5 
        ORDER BY RANDOM() 
        LIMIT 8
    ''').fetchall()
    
    # Get newest movies
    newest = conn.execute('''
        SELECT * FROM movies 
        ORDER BY year DESC 
        LIMIT 8
    ''').fetchall()
    
    # Get top rated
    top_rated = conn.execute('''
        SELECT * FROM movies 
        ORDER BY rating DESC 
        LIMIT 8
    ''').fetchall()
    
    # Get user stats if logged in
    user_stats = None
    if 'user_id' in session:
        user_id = session['user_id']
        user_stats = {
            'favorites': conn.execute('SELECT COUNT(*) FROM preferences WHERE user_id = ? AND preference_type = "favorite"', 
                                    (user_id,)).fetchone()[0],
            'watchlist': conn.execute('SELECT COUNT(*) FROM preferences WHERE user_id = ? AND preference_type = "watchlist"', 
                                    (user_id,)).fetchone()[0],
            'reviews': conn.execute('SELECT COUNT(*) FROM movie_ratings WHERE user_id = ?', 
                                   (user_id,)).fetchone()[0]
        }
    
    conn.close()
    
    return render_template('index.html', 
                         featured=featured, 
                         newest=newest, 
                         top_rated=top_rated,
                         user_stats=user_stats)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        
        conn = get_db()
        user = conn.execute('''
            SELECT * FROM users 
            WHERE email = ? AND is_active = 1
        ''', (email,)).fetchone()
        
        if user and verify_password(password, user['password_hash'], user['salt']):
            # Set session
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['full_name'] or user['email']
            session['is_admin'] = bool(user['is_admin'])
            session['avatar'] = user['avatar_url']
            
            # Update last login
            conn.execute('''
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, last_active = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (user['id'],))
            conn.commit()
            
            conn.close()
            
            app.logger.info(f'User {email} logged in successfully')
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            conn.close()
            app.logger.warning(f'Failed login attempt for {email}')
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    """Register page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        full_name = form.full_name.data.strip()
        email = form.email.data.lower()
        password = form.password.data
        
        # Hash password
        password_hash, salt = hash_password(password)
        
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, password_hash, salt, full_name)
                VALUES (?, ?, ?, ?)
            ''', (email, password_hash, salt, full_name))
            user_id = cursor.lastrowid
            
            # Create welcome notification
            cursor.execute('''
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (?, ?, ?, ?)
            ''', (user_id, 'Welcome to Ami Movies!', 
                  'Thank you for joining Ami Movies. Start exploring movies and building your watchlist.', 'success'))
            
            conn.commit()
            conn.close()
            
            app.logger.info(f'New user registered: {email}')
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            conn.close()
            flash('Email already registered. Please use a different email.', 'danger')
        except Exception as e:
            conn.close()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    """Logout user"""
    if 'user_id' in session:
        app.logger.info(f'User {session["user_email"]} logged out')
        session.clear()
        flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Forgot password page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        
        conn = get_db()
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate 6-digit code
            code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            expires_at = datetime.now() + timedelta(minutes=10)
            
            # Store reset code
            conn.execute('''
                INSERT INTO password_reset_codes (user_id, code, expires_at)
                VALUES (?, ?, ?)
            ''', (user['id'], code, expires_at))
            conn.commit()
            
            # Send email
            if EmailConfig.IS_CONFIGURED:
                if send_reset_email(email, code):
                    flash('Password reset code has been sent to your email.', 'success')
                else:
                    flash('Failed to send email. Please try again.', 'danger')
                    conn.close()
                    return redirect(url_for('forgot_password'))
            else:
                # Demo mode
                session['demo_reset_code'] = code
                session['reset_email'] = email
                flash(f'DEMO MODE: Your verification code is {code}', 'info')
            
            session['reset_email'] = email
            session['reset_user_id'] = user['id']
            conn.close()
            
            return redirect(url_for('reset_password'))
        else:
            conn.close()
            flash('No account found with this email.', 'danger')
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def reset_password():
    """Reset password page"""
    if 'reset_email' not in session:
        flash('Please request a password reset first.', 'warning')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        code = form.code.data
        new_password = form.new_password.data
        email = session['reset_email']
        
        conn = get_db()
        
        # Verify code
        reset_code = conn.execute('''
            SELECT prc.* FROM password_reset_codes prc
            JOIN users u ON prc.user_id = u.id
            WHERE u.email = ? AND prc.code = ? AND prc.used = 0
            ORDER BY prc.created_at DESC LIMIT 1
        ''', (email, code)).fetchone()
        
        if reset_code:
            # Check expiration
            expires_at = datetime.fromisoformat(reset_code['expires_at'])
            if datetime.now() > expires_at:
                conn.close()
                flash('Reset code has expired. Please request a new one.', 'danger')
                return redirect(url_for('forgot_password'))
            
            # Reset password
            password_hash, salt = hash_password(new_password)
            conn.execute('''
                UPDATE users 
                SET password_hash = ?, salt = ?
                WHERE email = ?
            ''', (password_hash, salt, email))
            
            # Mark code as used
            conn.execute('UPDATE password_reset_codes SET used = 1 WHERE id = ?', 
                        (reset_code['id'],))
            
            # Add notification
            conn.execute('''
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (?, ?, ?, ?)
            ''', (reset_code['user_id'], 'Password Changed', 
                  'Your password has been successfully changed.', 'success'))
            
            conn.commit()
            conn.close()
            
            # Clear session
            session.pop('reset_email', None)
            session.pop('reset_user_id', None)
            session.pop('demo_reset_code', None)
            
            app.logger.info(f'Password reset for {email}')
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            conn.close()
            flash('Invalid reset code. Please try again.', 'danger')
    
    return render_template('reset_password.html', form=form)

@app.route('/movies')
def movies():
    """Movies listing page"""
    update_last_active()
    
    search_query = request.args.get('q', '').strip()
    genre_filter = request.args.get('genre', '')
    year_filter = request.args.get('year', '')
    rating_filter = request.args.get('rating', '')
    page = request.args.get('page', 1, type=int)
    per_page = 12
    
    conn = get_db()
    
    # Build query
    query = 'SELECT * FROM movies'
    conditions = []
    params = []
    
    if search_query:
        conditions.append('(title LIKE ? OR genre LIKE ? OR cast LIKE ? OR director LIKE ?)')
        search_term = f'%{search_query}%'
        params.extend([search_term, search_term, search_term, search_term])
    
    if genre_filter:
        conditions.append('genre LIKE ?')
        params.append(f'%{genre_filter}%')
    
    if year_filter:
        if year_filter == '2020s':
            conditions.append('year >= ?')
            params.append('2020')
        elif year_filter == '2010s':
            conditions.append('year BETWEEN ? AND ?')
            params.extend(['2010', '2019'])
        elif year_filter == '2000s':
            conditions.append('year BETWEEN ? AND ?')
            params.extend(['2000', '2009'])
        elif year_filter == '1990s':
            conditions.append('year BETWEEN ? AND ?')
            params.extend(['1990', '1999'])
        elif year_filter == '1980s':
            conditions.append('year BETWEEN ? AND ?')
            params.extend(['1980', '1989'])
        elif year_filter == '1970s':
            conditions.append('year BETWEEN ? AND ?')
            params.extend(['1970', '1979'])
    
    if rating_filter:
        conditions.append('rating >= ?')
        params.append(float(rating_filter))
    
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    
    query += ' ORDER BY rating DESC'
    
    # Get total count
    count_query = 'SELECT COUNT(*) FROM movies'
    if conditions:
        count_query += ' WHERE ' + ' AND '.join(conditions)
    
    total = conn.execute(count_query, params).fetchone()[0]
    
    # Get paginated results
    params.append(per_page)
    params.append((page - 1) * per_page)
    movies_list = conn.execute(f'{query} LIMIT ? OFFSET ?', params).fetchall()
    
    # Get user preferences if logged in
    favorites = set()
    watchlist = set()
    if 'user_id' in session:
        user_id = session['user_id']
        fav_rows = conn.execute('SELECT movie_id FROM preferences WHERE user_id = ? AND preference_type = "favorite"', 
                               (user_id,)).fetchall()
        watch_rows = conn.execute('SELECT movie_id FROM preferences WHERE user_id = ? AND preference_type = "watchlist"', 
                                 (user_id,)).fetchall()
        favorites = {row['movie_id'] for row in fav_rows}
        watchlist = {row['movie_id'] for row in watch_rows}
    
    conn.close()
    
    # Pagination
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('movies.html',
                         movies=movies_list,
                         search_query=search_query,
                         genre_filter=genre_filter,
                         year_filter=year_filter,
                         rating_filter=rating_filter,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         favorites=favorites,
                         watchlist=watchlist)

@app.route('/movie/<int:movie_id>')
def movie_detail(movie_id):
    """Movie detail page"""
    update_last_active()
    
    conn = get_db()
    
    # Get movie details
    movie = conn.execute('SELECT * FROM movies WHERE id = ?', (movie_id,)).fetchone()
    
    if not movie:
        conn.close()
        flash('Movie not found.', 'danger')
        return redirect(url_for('movies'))
    
    # Get user preferences
    is_favorite = False
    is_watchlist = False
    user_rating = None
    
    if 'user_id' in session:
        user_id = session['user_id']
        
        # Check favorites and watchlist
        is_favorite = conn.execute('SELECT 1 FROM preferences WHERE user_id = ? AND movie_id = ? AND preference_type = "favorite"',
                                  (user_id, movie_id)).fetchone() is not None
        is_watchlist = conn.execute('SELECT 1 FROM preferences WHERE user_id = ? AND movie_id = ? AND preference_type = "watchlist"',
                                   (user_id, movie_id)).fetchone() is not None
        
        # Get user rating
        rating_row = conn.execute('SELECT rating, review FROM movie_ratings WHERE user_id = ? AND movie_id = ?',
                                 (user_id, movie_id)).fetchone()
        if rating_row:
            user_rating = dict(rating_row)
    
    # Get similar movies (same genre)
    similar_movies = []
    if movie['genre']:
        genres = movie['genre'].split(', ')
        if genres:
            genre_query = ' OR '.join(['genre LIKE ?' for _ in genres])
            similar_params = [f'%{genre}%' for genre in genres]
            similar_params.append(movie_id)  # Exclude current movie
            similar_params.append(6)  # Limit
            
            similar_movies = conn.execute(f'''
                SELECT * FROM movies 
                WHERE ({genre_query}) AND id != ? 
                ORDER BY rating DESC 
                LIMIT ?
            ''', similar_params).fetchall()
    
    # Get movie ratings stats
    rating_stats = conn.execute('''
        SELECT 
            COUNT(*) as total_ratings,
            AVG(rating) as avg_rating,
            COUNT(CASE WHEN rating >= 9 THEN 1 END) as five_star,
            COUNT(CASE WHEN rating >= 7 AND rating < 9 THEN 1 END) as four_star,
            COUNT(CASE WHEN rating >= 5 AND rating < 7 THEN 1 END) as three_star,
            COUNT(CASE WHEN rating >= 3 AND rating < 5 THEN 1 END) as two_star,
            COUNT(CASE WHEN rating < 3 THEN 1 END) as one_star
        FROM movie_ratings 
        WHERE movie_id = ?
    ''', (movie_id,)).fetchone()
    
    # Get recent reviews
    recent_reviews = conn.execute('''
        SELECT mr.*, u.full_name, u.avatar_url 
        FROM movie_ratings mr
        JOIN users u ON mr.user_id = u.id
        WHERE mr.movie_id = ? AND mr.review IS NOT NULL
        ORDER BY mr.created_at DESC
        LIMIT 5
    ''', (movie_id,)).fetchall()
    
    conn.close()
    
    return render_template('movie_detail.html',
                         movie=movie,
                         is_favorite=is_favorite,
                         is_watchlist=is_watchlist,
                         user_rating=user_rating,
                         similar_movies=similar_movies,
                         rating_stats=rating_stats,
                         recent_reviews=recent_reviews)

@app.route('/favorites')
@login_required
def favorites():
    """User's favorite movies"""
    update_last_active()
    
    page = request.args.get('page', 1, type=int)
    per_page = 12
    
    conn = get_db()
    user_id = session['user_id']
    
    # Get total count
    total = conn.execute('''
        SELECT COUNT(*) 
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "favorite"
    ''', (user_id,)).fetchone()[0]
    
    # Get paginated favorites
    favorites = conn.execute('''
        SELECT m.* 
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "favorite"
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
    ''', (user_id, per_page, (page - 1) * per_page)).fetchall()
    
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('movies.html',
                         movies=favorites,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         page_title="My Favorites",
                         favorites=set([m['id'] for m in favorites]))

@app.route('/watchlist')
@login_required
def watchlist():
    """User's watchlist"""
    update_last_active()
    
    page = request.args.get('page', 1, type=int)
    per_page = 12
    
    conn = get_db()
    user_id = session['user_id']
    
    # Get total count
    total = conn.execute('''
        SELECT COUNT(*) 
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "watchlist"
    ''', (user_id,)).fetchone()[0]
    
    # Get paginated watchlist
    watchlist_movies = conn.execute('''
        SELECT m.* 
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "watchlist"
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
    ''', (user_id, per_page, (page - 1) * per_page)).fetchall()
    
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('movies.html',
                         movies=watchlist_movies,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         page_title="My Watchlist",
                         watchlist=set([m['id'] for m in watchlist_movies]))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    update_last_active()
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get user stats
    stats = conn.execute('''
        SELECT 
            (SELECT COUNT(*) FROM preferences WHERE user_id = ? AND preference_type = "favorite") as favorites_count,
            (SELECT COUNT(*) FROM preferences WHERE user_id = ? AND preference_type = "watchlist") as watchlist_count,
            (SELECT COUNT(*) FROM movie_ratings WHERE user_id = ?) as reviews_count,
            (SELECT COUNT(*) FROM watch_history WHERE user_id = ?) as watched_count
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchone()
    
    # Get recent activity
    recent_activity = conn.execute('''
        SELECT 
            'favorite' as type, m.title, m.poster_url, p.created_at
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "favorite"
        UNION ALL
        SELECT 
            'watchlist' as type, m.title, m.poster_url, p.created_at
        FROM preferences p
        JOIN movies m ON p.movie_id = m.id
        WHERE p.user_id = ? AND p.preference_type = "watchlist"
        UNION ALL
        SELECT 
            'review' as type, m.title, m.poster_url, mr.created_at
        FROM movie_ratings mr
        JOIN movies m ON mr.movie_id = m.id
        WHERE mr.user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    ''', (session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    conn.close()
    
    form = ProfileForm(obj=user)
    form.bio.data = user['bio'] or ''
    
    return render_template('profile.html',
                         user=user,
                         form=form,
                         stats=stats,
                         recent_activity=recent_activity)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    form = ProfileForm()
    
    if form.validate_on_submit():
        full_name = form.full_name.data.strip()
        email = form.email.data.lower()
        bio = form.bio.data.strip()
        
        conn = get_db()
        
        try:
            # Check if email is already used by another user
            existing = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?',
                                   (email, session['user_id'])).fetchone()
            if existing:
                flash('Email already in use by another account.', 'danger')
                conn.close()
                return redirect(url_for('profile'))
            
            # Update profile
            conn.execute('''
                UPDATE users 
                SET full_name = ?, email = ?, bio = ?
                WHERE id = ?
            ''', (full_name, email, bio, session['user_id']))
            
            conn.commit()
            conn.close()
            
            # Update session
            session['user_email'] = email
            session['user_name'] = full_name or email
            
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            conn.close()
            app.logger.error(f'Profile update error: {str(e)}')
            flash('An error occurred. Please try again.', 'danger')
    
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        
        conn = get_db()
        user = conn.execute('SELECT password_hash, salt FROM users WHERE id = ?', 
                           (session['user_id'],)).fetchone()
        
        if user and verify_password(current_password, user['password_hash'], user['salt']):
            # Update password
            password_hash, salt = hash_password(new_password)
            conn.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
                       (password_hash, salt, session['user_id']))
            
            # Add notification
            conn.execute('''
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], 'Password Changed', 
                  'Your password has been updated successfully.', 'success'))
            
            conn.commit()
            conn.close()
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            conn.close()
            flash('Current password is incorrect.', 'danger')
    
    return render_template('change_password.html', form=form)

@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard"""
    conn = get_db()
    
    # Get system stats
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'active_users': conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
        'admin_users': conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1').fetchone()[0],
        'total_movies': conn.execute('SELECT COUNT(*) FROM movies').fetchone()[0],
        'total_favorites': conn.execute('SELECT COUNT(*) FROM preferences WHERE preference_type = "favorite"').fetchone()[0],
        'total_watchlist': conn.execute('SELECT COUNT(*) FROM preferences WHERE preference_type = "watchlist"').fetchone()[0],
        'total_ratings': conn.execute('SELECT COUNT(*) FROM movie_ratings').fetchone()[0],
        'total_reviews': conn.execute('SELECT COUNT(*) FROM movie_ratings WHERE review IS NOT NULL').fetchone()[0],
    }
    
    # Get recent users
    recent_users = conn.execute('''
        SELECT * FROM users 
        ORDER BY created_at DESC 
        LIMIT 10
    ''').fetchall()
    
    # Get user activity
    user_activity = conn.execute('''
        SELECT 
            u.email,
            u.full_name,
            u.last_login,
            u.last_active,
            (SELECT COUNT(*) FROM preferences WHERE user_id = u.id AND preference_type = "favorite") as favorites,
            (SELECT COUNT(*) FROM preferences WHERE user_id = u.id AND preference_type = "watchlist") as watchlist,
            (SELECT COUNT(*) FROM movie_ratings WHERE user_id = u.id) as ratings
        FROM users u
        WHERE u.last_active IS NOT NULL
        ORDER BY u.last_active DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin.html',
                         stats=stats,
                         recent_users=recent_users,
                         user_activity=user_activity)

# API Routes
@app.route('/api/toggle_preference', methods=['POST'])
@login_required
def toggle_preference():
    """Toggle favorite/watchlist preference"""
    try:
        data = request.get_json()
        movie_id = data.get('movie_id')
        pref_type = data.get('type')  # 'favorite' or 'watchlist'
        action = data.get('action')   # 'add' or 'remove'
        
        if not movie_id or not pref_type or not action:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        conn = get_db()
        
        if action == 'add':
            try:
                conn.execute('''
                    INSERT INTO preferences (user_id, movie_id, preference_type)
                    VALUES (?, ?, ?)
                ''', (session['user_id'], movie_id, pref_type))
                
                # Add notification for favorite
                if pref_type == 'favorite':
                    movie = conn.execute('SELECT title FROM movies WHERE id = ?', (movie_id,)).fetchone()
                    conn.execute('''
                        INSERT INTO notifications (user_id, title, message, type)
                        VALUES (?, ?, ?, ?)
                    ''', (session['user_id'], 'Added to Favorites',
                          f'You added "{movie["title"]}" to your favorites', 'info'))
                
                success = True
            except sqlite3.IntegrityError:
                success = False
        else:  # remove
            conn.execute('''
                DELETE FROM preferences 
                WHERE user_id = ? AND movie_id = ? AND preference_type = ?
            ''', (session['user_id'], movie_id, pref_type))
            success = True
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': success})
        
    except Exception as e:
        app.logger.error(f'API Error: {str(e)}')
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/submit_rating', methods=['POST'])
@login_required
def submit_rating():
    """Submit movie rating and review"""
    try:
        data = request.get_json()
        movie_id = data.get('movie_id')
        rating = data.get('rating')
        review = data.get('review', '').strip()
        
        if not movie_id or not rating or not 1 <= int(rating) <= 10:
            return jsonify({'success': False, 'message': 'Invalid rating'}), 400
        
        conn = get_db()
        
        # Check if rating exists
        existing = conn.execute('SELECT id FROM movie_ratings WHERE user_id = ? AND movie_id = ?',
                               (session['user_id'], movie_id)).fetchone()
        
        if existing:
            conn.execute('''
                UPDATE movie_ratings 
                SET rating = ?, review = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (rating, review, existing['id']))
        else:
            conn.execute('''
                INSERT INTO movie_ratings (user_id, movie_id, rating, review)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], movie_id, rating, review))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        app.logger.error(f'Rating Error: {str(e)}')
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get user notifications"""
    conn = get_db()
    
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 20
    ''', (session['user_id'],)).fetchall()
    
    # Mark as read
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    
    conn.close()
    
    return jsonify([dict(n) for n in notifications])

# Static pages
@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    """Privacy policy"""
    return render_template('privacy.html')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f'500 Error: {str(e)}')
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

# Health check endpoint for deployment
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# Sitemap for SEO
@app.route('/sitemap.xml')
def sitemap():
    pages = []
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            url = url_for(rule.endpoint, _external=True)
            pages.append(url)
    
    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    response = app.response_class(sitemap_xml, mimetype='application/xml')
    return response

# Initialize database on first run
with app.app_context():
    init_db()
    app.logger.info('Application initialized')

# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)