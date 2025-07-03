import os 
import json 
import base64 
import secrets 
from datetime import datetime, timedelta, date
from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash 
from flask_sqlalchemy import SQLAlchemy 
from flask_limiter import Limiter 
from flask_limiter.util import get_remote_address 
from flask_mail import Mail, Message 
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature 
import firebase_admin 
from firebase_admin import credentials, firestore 
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from werkzeug.utils import secure_filename
from pathlib import Path
import logging 
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Date, Text, Float, JSON
import math


#==== Flask App Config ====

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

#==== CSRF Protection ====
# Check if CSRF protection should be enabled (default: True)
CSRF_ENABLED = os.environ.get('CSRF_ENABLED', 'true').lower() == 'true'

if CSRF_ENABLED:
    csrf = CSRFProtect(app)
    print("✅ CSRF Protection enabled")
else:
    csrf = None
    print("⚠️ CSRF Protection disabled")

#==== Database Configuration ====
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///watch_and_earn.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

#==== Environment Config ====

CSRF_TOKEN_LENGTH = int(os.environ.get('CSRF_TOKEN_LENGTH', 16)) 
LOGIN_RATE_LIMIT = os.environ.get('LOGIN_RATE_LIMIT', '20 per minute') 
DAILY_REWARD = float(os.environ.get('DAILY_LOGIN_REWARD', 0.05)) 
MIN_WITHDRAW_AMOUNT = float(os.environ.get('MIN_WITHDRAW_AMOUNT', 150)) 
AUTO_LOGIN_AFTER_REGISTRATION = os.environ.get('AUTO_LOGIN_AFTER_REGISTRATION', 'false').lower() == 'true' 
ENABLE_REWARDS = os.environ.get('ENABLE_REWARDS', 'true').lower() == 'true' 
MAINTENANCE_MODE = os.environ.get('MAINTENANCE_MODE', 'false').lower() == 'true' 
PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 6)) 
PASSWORD_CONFIRMATION_REQUIRED = os.environ.get('PASSWORD_CONFIRMATION_REQUIRED', 'true').lower() == 'true' 
ALLOWED_ROLES = os.environ.get('ALLOWED_ROLES', 'User,YouTuber').split(',')

# Watch & Earn Restrictive Rules
VIDEO_WATCH_TIME = int(os.environ.get('VIDEO_WATCH_TIME', 30))  # Seconds to watch for reward
VIDEO_REWARD_AMOUNT = float(os.environ.get('VIDEO_REWARD_AMOUNT', 0.01))  # Reward per video
DAILY_ONLINE_TIME = int(os.environ.get('DAILY_ONLINE_TIME', 60))  # Seconds to stay online for daily reward
MAX_VIDEOS_PER_DAY = int(os.environ.get('MAX_VIDEOS_PER_DAY', 50))  # Max videos that can earn rewards per day
ANTI_CHEAT_TOLERANCE = int(os.environ.get('ANTI_CHEAT_TOLERANCE', 3))  # Focus loss tolerance before blocking
SESSION_HEARTBEAT_INTERVAL = int(os.environ.get('SESSION_HEARTBEAT_INTERVAL', 5))  # Heartbeat every 5 seconds

# IP Tracking Configuration
ENABLE_IP_TRACKING = os.environ.get('ENABLE_IP_TRACKING', 'true').lower() == 'true'
TRUST_PROXY_HEADERS = os.environ.get('TRUST_PROXY_HEADERS', 'true').lower() == 'true'
MAX_IP_HISTORY = int(os.environ.get('MAX_IP_HISTORY', 10))  # Keep last 10 IP addresses per user

#==== IP Address Tracking Utility ====

def get_client_ip():
    """Get the real client IP address, considering proxy headers if enabled"""
    if TRUST_PROXY_HEADERS:
        # Check common proxy headers in order of preference
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Cloudflare specific header
        cf_connecting_ip = request.headers.get('CF-Connecting-IP')
        if cf_connecting_ip:
            return cf_connecting_ip.strip()
    
    # Fall back to direct connection IP
    return request.remote_addr or 'Unknown'

def log_user_ip(user_id, action="login"):
    """Log user IP address for tracking purposes"""
    if not ENABLE_IP_TRACKING:
        return
    
    try:
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Create IP log entry
        ip_log = IPLog(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(ip_log)
        
        # Clean up old IP logs to prevent database bloat
        cleanup_old_ip_logs(user_id)
        
        db.session.commit()
        
    except Exception as e:
        print(f"❌ Failed to log IP for user {user_id}: {str(e)}")
        db.session.rollback()

def cleanup_old_ip_logs(user_id):
    """Keep only the most recent IP logs for a user"""
    try:
        # Get count of logs for this user
        log_count = IPLog.query.filter_by(user_id=user_id).count()
        
        if log_count > MAX_IP_HISTORY:
            # Get oldest logs to delete
            logs_to_delete = IPLog.query.filter_by(user_id=user_id)\
                .order_by(IPLog.timestamp.asc())\
                .limit(log_count - MAX_IP_HISTORY)\
                .all()
            
            for log in logs_to_delete:
                db.session.delete(log)
                
    except Exception as e:
        print(f"❌ Failed to cleanup IP logs for user {user_id}: {str(e)}")

#==== CSRF Token Setup ====

@app.before_request 
def csrf_protect(): 
    # Skip CSRF protection if Flask-WTF CSRF is enabled (it handles it automatically)
    if CSRF_ENABLED:
        return
        
    # Manual CSRF protection for when Flask-WTF CSRF is disabled
    if request.method == "POST": 
        # Skip CSRF for certain endpoints if needed
        exempt_endpoints = ['api_endpoint']  # Add any API endpoints here
        if request.endpoint in exempt_endpoints:
            return
            
        csrf_token = session.get('_csrf_token') 
        form_token = request.form.get('csrf_token')
        json_token = None
        
        # Check for CSRF token in JSON requests
        if request.is_json:
            json_token = request.json.get('csrf_token') if request.json else None
            
        if not csrf_token or csrf_token not in [form_token, json_token]: 
            return jsonify({'error': 'CSRF token missing or incorrect'}), 400

def generate_csrf_token(): 
    if '_csrf_token' not in session: 
        session['_csrf_token'] = secrets.token_hex(CSRF_TOKEN_LENGTH) 
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

#==== Email Config ====

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER') 
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587)) 
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True' 
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') 
mail = Mail(app)

#==== Rate Limiting ====

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[LOGIN_RATE_LIMIT])

#==== Firebase Setup ====

firebase_base64 = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY") 
if firebase_base64:
    try:
        firebase_dict = json.loads(base64.b64decode(firebase_base64).decode('utf-8')) 
        cred = credentials.Certificate(firebase_dict) 
        firebase_admin.initialize_app(cred) 
        db_firestore = firestore.client()
        print("✅ Firebase initialized successfully")
    except Exception as e:
        print(f"❌ Firebase initialization failed: {str(e)}")
        db_firestore = None
else:
    print("⚠️ Firebase not configured")
    db_firestore = None

#==== Serializer for Email Tokens ====

serializer = URLSafeTimedSerializer(app.secret_key)

#==== DB Models ====

class User(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password_hash = db.Column(db.String(200), nullable=False) 
    account_type = db.Column(db.String(10), nullable=False) 
    is_verified = db.Column(db.Boolean, default=False) 
    last_login_date = db.Column(db.DateTime) 
    total_watch_minutes = db.Column(db.Integer, default=0) 
    daily_bonus_given = db.Column(db.Boolean, default=False) 
    balance_usd = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_ip = db.Column(db.String(45))  # Store last known IP (IPv6 can be up to 45 chars)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    last_bonus_date = db.Column(db.Date)
    daily_online_time = db.Column(db.Integer, default=0)  # seconds online today
        
    # Anti-cheat fields
    videos_watched_today = db.Column(db.Integer, default=0)
    last_video_date = db.Column(db.Date)
    cheat_violations = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    session_start_time = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)
    last_bonus_claim = db.Column(db.DateTime)  # When bonus was last claimed
    last_activity_date = db.Column(db.Date, default=datetime.utcnow().date())  # Use Date (not db.date)
    current_session_start = db.Column(db.DateTime)
    total_daily_bonuses = db.Column(db.Integer, default=0)
    
    # Session tracking 
    session_token = db.Column(db.String(64))

    # Consecutive days and bonuses
    consecutive_days = db.Column(db.Integer, default=0)

    # Anti-cheat specific fields
    back_button_pressed = db.Column(db.Boolean, default=False)
    focus_lost_count = db.Column(db.Integer, default=0)
    
    # Additional tracking fields
    total_watch_time = db.Column(db.Integer, default=0)
    last_ip_address = db.Column(db.String(45))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Advanced Anti-Cheat Fields
    device_fingerprint = db.Column(db.String(200))  # Browser/device fingerprint
    time_zone = db.Column(db.String(50))  # User's timezone
    screen_resolution = db.Column(db.String(20))  # Screen dimensions
    user_agent_hash = db.Column(db.String(64))  # Hashed user agent
    click_pattern_score = db.Column(db.Float, default=0.0)  # ML-based click pattern analysis
    watch_velocity_score = db.Column(db.Float, default=0.0)  # Video consumption velocity
    behavioral_score = db.Column(db.Float, default=0.0)  # Overall behavioral analysis score
    proxy_detected = db.Column(db.Boolean, default=False)  # VPN/Proxy detection
    automation_detected = db.Column(db.Boolean, default=False)  # Bot/automation detection
    suspicious_activity_count = db.Column(db.Integer, default=0)  # Count of suspicious events
    risk_level = db.Column(db.String(10), default='low')  # low, medium, high, critical
    last_risk_assessment = db.Column(db.DateTime)  # When risk was last calculated
    
    # Device/Browser Consistency Tracking
    browser_changes_count = db.Column(db.Integer, default=0)  # How often browser changes
    device_changes_count = db.Column(db.Integer, default=0)  # How often device changes
    location_changes_count = db.Column(db.Integer, default=0)  # Geographic changes
    
    # Machine Learning Features
    ml_fraud_probability = db.Column(db.Float, default=0.0)  # ML model fraud probability
    feature_vector_hash = db.Column(db.String(64))  # Hash of ML features for comparison

class IPLog(db.Model):
    """Track user IP addresses and login history"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    user_agent = db.Column(db.Text)  # Browser/device info
    action = db.Column(db.String(50), default='login')  # login, register, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('ip_logs', lazy=True))

class WithdrawalRequest(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    amount = db.Column(db.Float, nullable=False) 
    status = db.Column(db.String(20), default='pending') 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship
    user = db.relationship('User', backref=db.backref('withdrawal_requests', lazy=True))

class Video(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    title = db.Column(db.String(200), nullable=False) 
    video_url = db.Column(db.String(500), nullable=False) 
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    min_watch_time = db.Column(db.Integer, default=VIDEO_WATCH_TIME)  # seconds
    reward_amount = db.Column(db.Float, default=VIDEO_REWARD_AMOUNT)
    
    # Add relationship
    uploader = db.relationship('User', backref=db.backref('videos', lazy=True))

class WatchSession(db.Model):
    __tablename__ = 'watch_sessions'  # Keep this as is
    """Track individual video watch sessions for anti-cheat"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    session_token = db.Column(db.String(100), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    watch_duration = db.Column(db.Integer, default=0)  # seconds actually watched
    focus_lost_count = db.Column(db.Integer, default=0)  # how many times user lost focus
    back_button_pressed = db.Column(db.Boolean, default=False)
    reward_given = db.Column(db.Boolean, default=False)
    cheating_detected = db.Column(db.Boolean, default=False)
    cheat_reason = db.Column(db.String(200))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    video_length = db.Column(db.Integer)  # total video length in seconds
    is_completed = db.Column(db.Boolean, default=False)
    is_suspicious = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('watch_sessions', lazy=True))
    video = db.relationship('Video', backref=db.backref('watch_sessions', lazy=True))
    

class DailySession(db.Model):
    """Track daily online sessions for daily rewards"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_date = db.Column(db.Date, default=datetime.utcnow().date)
    session_token = db.Column(db.String(100), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat = db.Column(db.DateTime, default=datetime.utcnow)
    total_online_time = db.Column(db.Integer, default=0)  # seconds
    focus_lost_count = db.Column(db.Integer, default=0)
    daily_reward_given = db.Column(db.Boolean, default=False)
    is_valid = db.Column(db.Boolean, default=True)
    ip_address = db.Column(db.String(45))
    
    user = db.relationship('User', backref=db.backref('daily_sessions', lazy=True))

class Withdrawal(db.Model):
    """Completed withdrawals"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(50))  # PayPal, Bank, etc.
    transaction_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='completed')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('withdrawals', lazy=True))

class Earning(db.Model):
    """Track user earnings"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(50))  # 'watch', 'daily_bonus', 'referral', etc.
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('earnings', lazy=True))
    video = db.relationship('Video', backref=db.backref('earnings', lazy=True))

class DeviceFingerprint(db.Model):
    """Track device fingerprints for fraud detection"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fingerprint_hash = db.Column(db.String(200), nullable=False)
    screen_resolution = db.Column(db.String(20))
    timezone = db.Column(db.String(50))
    language = db.Column(db.String(10))
    user_agent = db.Column(db.Text)
    canvas_fingerprint = db.Column(db.String(100))  # Canvas-based fingerprinting
    webgl_fingerprint = db.Column(db.String(100))   # WebGL-based fingerprinting
    audio_fingerprint = db.Column(db.String(100))   # Audio context fingerprinting
    plugins_list = db.Column(db.Text)  # Installed browser plugins
    fonts_list = db.Column(db.Text)    # Available fonts
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    times_seen = db.Column(db.Integer, default=1)
    is_suspicious = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('device_fingerprints', lazy=True))

class SecurityEvent(db.Model):
    """Log security events and suspicious activities"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)  # 'proxy_detected', 'bot_detected', etc.
    severity = db.Column(db.String(10), default='low')  # low, medium, high, critical
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    session_token = db.Column(db.String(100))
    additional_data = db.Column(db.JSON)  # Store additional context as JSON
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    admin_notes = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('security_events', lazy=True))

class MouseMovement(db.Model):
    """Track mouse movements for bot detection"""
    id = db.Column(db.Integer, primary_key=True)
    # FIXED: Now correctly references the table name 'watch_sessions'
    session_id = db.Column(db.Integer, db.ForeignKey('watch_sessions.id'), nullable=False)
    timestamp = db.Column(db.Float, nullable=False)  # Milliseconds since session start
    x_coordinate = db.Column(db.Integer)
    y_coordinate = db.Column(db.Integer)
    event_type = db.Column(db.String(10))  # 'move', 'click', 'scroll'
    velocity = db.Column(db.Float)  # Calculated velocity
    is_human_like = db.Column(db.Boolean, default=True)
    
    session = db.relationship('WatchSession', backref=db.backref('mouse_movements', lazy=True))

class KeystrokePattern(db.Model):
    """Track keystroke patterns for behavioral analysis"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(100))
    key_press
