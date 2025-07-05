import os 
import json 
import base64 
import secrets 
from datetime import datetime, timedelta 
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
    
    # Anti-cheat fields
    videos_watched_today = db.Column(db.Integer, default=0)
    last_video_date = db.Column(db.Date)
    cheat_violations = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    daily_online_time = db.Column(db.Integer, default=0)  # seconds online today
    session_start_time = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)

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

#==== Anti-Cheat Utility Functions ====

def create_session_token():
    """Create a unique session token"""
    return secrets.token_urlsafe(32)

def check_daily_video_limit(user_id):
    """Check if user has reached daily video limit"""
    user = User.query.get(user_id)
    today = datetime.utcnow().date()
    
    # Reset daily count if it's a new day
    if not user.last_video_date or user.last_video_date != today:
        user.videos_watched_today = 0
        user.last_video_date = today
        db.session.commit()
    
    return user.videos_watched_today < MAX_VIDEOS_PER_DAY

def is_user_banned(user_id):
    """Check if user is banned"""
    user = User.query.get(user_id)
    return user and user.is_banned

def ban_user(user_id, reason):
    """Ban user for cheating"""
    user = User.query.get(user_id)
    if user:
        user.is_banned = True
        user.ban_reason = reason
        user.cheat_violations += 1
        db.session.commit()
        print(f"🚨 User {user_id} banned: {reason}")

def detect_cheating(watch_session):
    """Detect various cheating methods"""
    cheating_detected = False
    reasons = []
    
    # Check if back button was pressed
    if watch_session.back_button_pressed:
        cheating_detected = True
        reasons.append("Back button pressed")
    
    # Check excessive focus loss
    if watch_session.focus_lost_count > ANTI_CHEAT_TOLERANCE:
        cheating_detected = True
        reasons.append(f"Lost focus {watch_session.focus_lost_count} times")
    
    # Check if watch duration is suspiciously short
    if watch_session.watch_duration < VIDEO_WATCH_TIME - 5:  # 5 second tolerance
        cheating_detected = True
        reasons.append("Insufficient watch time")
    
    # Check if session was too fast (impossible timing)
    if watch_session.end_time and watch_session.start_time:
        actual_duration = (watch_session.end_time - watch_session.start_time).total_seconds()
        if actual_duration < VIDEO_WATCH_TIME - 10:  # 10 second tolerance
            cheating_detected = True
            reasons.append("Session completed too quickly")
    
    return cheating_detected, reasons

def reset_daily_stats():
    """Reset daily stats for all users (run this daily via cron)"""
    try:
        users = User.query.all()
        for user in users:
            user.daily_bonus_given = False
            user.videos_watched_today = 0
            user.daily_online_time = 0
        db.session.commit()
        print("✅ Daily stats reset for all users")
    except Exception as e:
        print(f"❌ Failed to reset daily stats: {str(e)}")
        db.session.rollback()

#==== Utility Functions ====

def send_email(to, subject, body, html_body=None): 
    """Send email with both text and HTML versions"""
    if not app.config.get('MAIL_SERVER'):
        print(f"⚠️ Email not configured - would send to {to}: {subject}")
        return True  # Return True in development to avoid blocking
        
    try:
        msg = Message(
            subject=subject, 
            recipients=[to], 
            body=body, 
            html=html_body,
            sender=app.config['MAIL_USERNAME']
        ) 
        mail.send(msg)
        print(f"✅ Email sent successfully to {to}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email to {to}: {str(e)}")
        return False

def create_verification_email(email, verification_link):
    """Create professional verification email content"""
    
    # Plain text version
    text_body = f"""
Welcome to Watch & Earn!

Thank you for creating your account. To complete your registration and start earning, please verify your email address by clicking the link below:

{verification_link}

This verification link will expire in 1 hour for security reasons.

If you did not create this account, please ignore this email.

Best regards,
The Watch & Earn Team
    """
    
    # HTML version
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ background: #4CAF50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            .footer {{ color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎬 Welcome to Watch & Earn!</h1>
                <p>Verify your email to start earning</p>
            </div>
            <div class="content">
                <h2>Hello!</h2>
                <p>Thank you for joining Watch & Earn. You're one step away from starting to earn money by watching videos!</p>
                
                <p>Please click the button below to verify your email address:</p>
                
                <a href="{verification_link}" class="button">✅ Verify My Email</a>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                    {verification_link}
                </p>
                
                <div class="footer">
                    <p>⏰ This link expires in 1 hour</p>
                    <p>🔒 If you didn't create this account, please ignore this email</p>
                    <p>💰 Start earning today with Watch & Earn!</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return text_body, html_body

#==== Routes ====

@app.route('/') 
def home(): 
    if MAINTENANCE_MODE: 
        return render_template('maintenance.html') if os.path.exists('templates/maintenance.html') else "Site is under maintenance. Please check back later."
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST']) 
def register(): 
    if request.method == 'POST': 
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')
            role = request.form.get('account_type', '')

            # Validation
            if not all([email, password, role]):
                return jsonify({'error': 'All fields are required'}), 400

            if PASSWORD_CONFIRMATION_REQUIRED and password != confirm:
                return jsonify({'error': 'Passwords do not match'}), 400

            if len(password) < PASSWORD_MIN_LENGTH:
                return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters'}), 400

            if role not in ALLOWED_ROLES:
                return jsonify({'error': 'Invalid account type'}), 400

            if User.query.filter_by(email=email).first():
                return jsonify({'error': 'Email already exists'}), 409

            # Create user
            hashed = generate_password_hash(password)
            user = User(
                email=email, 
                password_hash=hashed, 
                account_type=role,
                last_ip=get_client_ip() if ENABLE_IP_TRACKING else None
            )
            
            db.session.add(user)
            db.session.commit()

            # Log registration IP
            log_user_ip(user.id, "register")

            # Send verification email
            token = serializer.dumps(email, salt='email-confirm')
            link = url_for('confirm_email', token=token, _external=True)
            
            text_body, html_body = create_verification_email(email, link)
            
            email_sent = send_email(
                email, 
                '🎬 Verify Your Watch & Earn Account', 
                text_body, 
                html_body
            )
            
            if not email_sent:
                print(f"⚠️ Email failed for {email}, but continuing...")

            # UPDATED: Always redirect to success page to guide email verification
            if AUTO_LOGIN_AFTER_REGISTRATION:
                session['user_id'] = user.id
                session['account_type'] = user.account_type
                
                # Redirect to appropriate success page based on account type
                if user.account_type == 'YouTuber':
                    success_route = 'youtuber_registration_success'
                else:
                    success_route = 'user_registration_success'
                    
                return jsonify({
                    'success': True,
                    'redirect': url_for(success_route, email=email),
                    'account_type': user.account_type,
                    'email_sent': email_sent
                })

            # If not auto-login, still redirect to success page
            if user.account_type == 'YouTuber':
                success_route = 'youtuber_registration_success'
            else:
                success_route = 'user_registration_success'
                
            return jsonify({
                'success': True,
                'redirect': url_for(success_route, email=email),
                'account_type': user.account_type,
                'email_sent': email_sent
            })
            
        except Exception as e:
            print(f"❌ Registration error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'Registration failed. Please try again.'}), 500

    return render_template('register.html')


# Add these new routes for success pages
@app.route('/registration-success/user')
def user_registration_success():
    email = request.args.get('email', '')
    return render_template('success/user_registration_success.html', email=email)

@app.route('/registration-success/youtuber')
def youtuber_registration_success():
    email = request.args.get('email', '')
    return render_template('success/youtuber_registration_success.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(LOGIN_RATE_LIMIT)
def login():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.is_banned:
                return jsonify({'error': f'Account banned: {user.ban_reason}'}), 403
            
            if user and check_password_hash(user.password_hash, password):
                if not user.is_verified:
                    return jsonify({'error': 'Please verify your email before logging in'}), 401
                
                # Update login info
                user.last_login_date = datetime.utcnow()
                user.session_start_time = datetime.utcnow()
                user.last_heartbeat = datetime.utcnow()
                
                if ENABLE_IP_TRACKING:
                    user.last_ip = get_client_ip()
                
                # Check if new day for daily bonus reset
                today = datetime.utcnow().date()
                if not user.last_video_date or user.last_video_date != today:
                    user.daily_bonus_given = False
                    user.videos_watched_today = 0
                    user.daily_online_time = 0
                    user.last_video_date = today
                
                db.session.commit()
                
                # Log login IP
                log_user_ip(user.id, "login")
                
                # Set session
                session['user_id'] = user.id
                session['account_type'] = user.account_type
                
                dashboard_route = 'youtuber_dashboard' if user.account_type == 'YouTuber' else 'user_dashboard'
                return jsonify({
                    'success': True,
                    'redirect': url_for(dashboard_route)
                })
            else:
                return jsonify({'error': 'Invalid email or password'}), 401
                
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'Login failed. Please try again.'}), 500
    
    return render_template('login.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # 1 hour
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.is_verified = True
            db.session.commit()
            flash('✅ Email verified successfully! You can now log in.', 'success')
        else:
            flash('❌ User not found.', 'error')
            
    except SignatureExpired:
        flash('⏰ Verification link has expired. Please register again.', 'error')
    except BadSignature:
        flash('❌ Invalid verification link.', 'error')
    except Exception as e:
        print(f"❌ Email confirmation error: {str(e)}")
        flash('❌ Email verification failed.', 'error')
    
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('account_type') != 'User':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        session.clear()
        return redirect(url_for('login'))
    
    # Get recent earnings
    recent_earnings = Earning.query.filter_by(user_id=user.id)\
        .order_by(Earning.timestamp.desc())\
        .limit(10).all()
    
    # Get available videos
    videos = Video.query.filter_by(is_active=True)\
        .order_by(Video.timestamp.desc()).all()
    
    # Check daily limits
    can_watch_more = check_daily_video_limit(user.id)
    time_until_daily_bonus = max(0, DAILY_ONLINE_TIME - user.daily_online_time)
    
    return render_template('user_dashboard.html', 
                         user=user, 
                         earnings=recent_earnings,
                         videos=videos,
                         can_watch_more=can_watch_more,
                         videos_remaining=MAX_VIDEOS_PER_DAY - user.videos_watched_today,
                         time_until_daily_bonus=time_until_daily_bonus)

# New restrictive watch and earn routes
@app.route('/watch_video/<int:video_id>')
def watch_video(video_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        return redirect(url_for('login'))
    
    if not check_daily_video_limit(user.id):
        flash('❌ Daily video limit reached. Come back tomorrow!', 'error')
        return redirect(url_for('user_dashboard'))
    
    video = Video.query.get_or_404(video_id)
    if not video.is_active:
        flash('❌ This video is no longer available.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Create watch session
    session_token = create_session_token()
    watch_session = WatchSession(
        user_id=user.id,
        video_id=video.id,
        session_token=session_token,
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', 'Unknown')
    )
    
    db.session.add(watch_session)
    db.session.commit()
    
    return render_template('watch_video.html', 
                         video=video, 
                         session_token=session_token,
                         min_watch_time=VIDEO_WATCH_TIME)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    """Keep track of user activity and session"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        session_type = data.get('type', 'video')  # 'video' or 'daily'
        focus_lost = data.get('focus_lost', 0)
        back_button = data.get('back_button', False)
        
        if session_type == 'video' and session_token:
            watch_session = WatchSession.query.filter_by(session_token=session_token).first()
            if watch_session and watch_session.user_id == session['user_id']:
                watch_session.focus_lost_count = focus_lost
                watch_session.back_button_pressed = back_button
                watch_session.watch_duration = data.get('watch_duration', 0)
                
                # Check for cheating
                if back_button:
                    watch_session.cheating_detected = True
                    watch_session.cheat_reason = "Back button pressed"
                
                db.session.commit()
                return jsonify({'success': True, 'cheating': watch_session.cheating_detected})
        
        elif session_type == 'daily':
            # Update daily session
            user = User.query.get(session['user_id'])
            user.last_heartbeat = datetime.utcnow()
            
            # Calculate online time
            if user.session_start_time:
                online_time = (datetime.utcnow() - user.session_start_time).total_seconds()
                user.daily_online_time = min(int(online_time), DAILY_ONLINE_TIME)
            
            db.session.commit()
            return jsonify({
                'success': True, 
                'online_time': user.daily_online_time,
                'required_time': DAILY_ONLINE_TIME
            })
            
        return jsonify({'error': 'Invalid session'}), 400
        
    except Exception as e:
        print(f"❌ Heartbeat error: {str(e)}")
        return jsonify({'error': 'Heartbeat failed'}), 500

@app.route('/api/complete_video', methods=['POST'])
def complete_video():
    """Complete video watch and give reward if conditions are met"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        watch_duration = data.get('watch_duration', 0)
        
        watch_session = WatchSession.query.filter_by(session_token=session_token).first()
        
        if not watch_session or watch_session.user_id != session['user_id']:
            return jsonify({'error': 'Invalid session'}), 400
        
        if watch_session.reward_given:
            return jsonify({'error': 'Reward already claimed'}), 400
        
        # Complete the session
        watch_session.end_time = datetime.utcnow()
        watch_session.watch_duration = watch_duration
        
        # Detect cheating
        cheating_detected, cheat_reasons = detect_cheating(watch_session)
        
        if cheating_detected:
            watch_session.cheating_detected = True
            watch_session.cheat_reason = '; '.join(cheat_reasons)
            
            # Increase user's cheat violations
            user = User.query.get(session['user_id'])
            user.cheat_violations += 1
            
            # Ban user if too many violations
            if user.cheat_violations >= 5:
                ban_user(user.id, "Multiple cheating violations")
                db.session.commit()
                session.clear()
                return jsonify({'error': 'Account banned for cheating', 'banned': True}), 403
            
            db.session.commit()
            return jsonify({
                'error': 'Cheating detected: ' + '; '.join(cheat_reasons),
                'violations': user.cheat_violations
            }), 400
        
        # Give reward
        user = User.query.get(session['user_id'])
        video = Video.query.get(watch_session.video_id)
        
        user.balance_usd += video.reward_amount
        user.videos_watched_today += 1
        user.total_watch_minutes += int(watch_duration // 60)
        
        watch_session.reward_given = True
        
        # Log earning
        earning = Earning(
            user_id=user.id,
            amount=video.reward_amount,
            source='watch',
            video_id=video.id
        )
        db.session.add(earning)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'reward': video.reward_amount,
            'new_balance': user.balance_usd,
            'videos_remaining': MAX_VIDEOS_PER_DAY - user.videos_watched_today
        })
        
    except Exception as e:
        print(f"❌ Complete video error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to complete video'}), 500

@app.route('/api/claim_daily_bonus', methods=['POST'])
def claim_daily_bonus():
    """Claim daily bonus if user stayed online for required time"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        
        if not user or user.is_banned:
            return jsonify({'error': 'Account unavailable'}), 403
        
        if user.daily_bonus_given:
            return jsonify({'error': 'Daily bonus already claimed'}), 400
        
        if user.daily_online_time < DAILY_ONLINE_TIME:
            return jsonify({
                'error': f'Need to stay online for {DAILY_ONLINE_TIME} seconds. You have {user.daily_online_time} seconds.',
                'required': DAILY_ONLINE_TIME,
                'current': user.daily_online_time
            }), 400
        
        # Give daily bonus
        user.balance_usd += DAILY_REWARD
        user.daily_bonus_given = True
        
        # Log earning
        earning = Earning(
            user_id=user.id,
            amount=DAILY_REWARD,
            source='daily_bonus'
        )
        db.session.add(earning)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'bonus': DAILY_REWARD,
            'new_balance': user.balance_usd
        })
        
    except Exception as e:
        print(f"❌ Daily bonus error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to claim bonus'}), 500

@app.route('/youtuber_dashboard')
def youtuber_dashboard():
    if 'user_id' not in session or session.get('account_type') != 'YouTuber':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    # Get user's videos
    videos = Video.query.filter_by(added_by=user.id)\
        .order_by(Video.timestamp.desc()).all()
    
    return render_template('youtuber_dashboard.html', user=user, videos=videos)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html') if os.path.exists('templates/404.html') else "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html') if os.path.exists('templates/500.html') else "Internal server error", 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

#==== Database Initialization ====

def init_db():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Print configuration status
            print(f"🗄️ Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
            
            if ENABLE_IP_TRACKING:
                print("🔍 IP tracking is ENABLED")
                print(f"📊 Keeping last {MAX_IP_HISTORY} IP addresses per user")
                if TRUST_PROXY_HEADERS:
                    print("🌐 Proxy headers (X-Forwarded-For, X-Real-IP) are trusted")
            else:
                print("❌ IP tracking is DISABLED")
                
            if MAINTENANCE_MODE:
                print("🚧 MAINTENANCE MODE is ENABLED")
                
            print(f"🎁 Daily reward: ${DAILY_REWARD}")
            print(f"💰 Min withdrawal: ${MIN_WITHDRAW_AMOUNT}")
                
    except Exception as e:
        print(f"❌ Database initialization failed: {str(e)}")

#==== Run App ====
#The above is what ive just added

@app.route('/edit_profile')
def edit_profile():
    """Display the edit profile page"""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('logout'))

    return render_template('edit_profile.html', user=user)

# Add this route for handling profile updates
@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Handle profile update requests"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401

    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        action = request.form.get('action')
        
        if action == 'update_basic':
            # Update basic information
            user.first_name = request.form.get('first_name', '').strip()
            user.last_name = request.form.get('last_name', '').strip()
            user.phone = request.form.get('phone', '').strip()
            
            db.session.commit()
            log_user_ip(user_id, "profile_update_basic")
            
            return jsonify({
                'success': True,
                'message': 'Basic information updated successfully!'
            })
        
        elif action == 'update_settings':
            # Update account settings
            new_account_type = request.form.get('account_type')
            
            if new_account_type not in ALLOWED_ROLES:
                return jsonify({'error': 'Invalid account type'}), 400
            
            old_type = user.account_type
            user.account_type = new_account_type
            session['account_type'] = new_account_type
            
            db.session.commit()
            log_user_ip(user_id, f"account_type_change_{old_type}_to_{new_account_type}")
            
            # Determine redirect URL
            dashboard_url = url_for('youtuber_dashboard') if new_account_type == 'YouTuber' else url_for('user_dashboard')
            
            return jsonify({
                'success': True,
                'message': f'Account type changed to {new_account_type}!',
                'redirect': dashboard_url
            })
        
        elif action == 'change_password':
            # Change password
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate current password
            if not check_password_hash(user.password_hash, current_password):
                return jsonify({'error': 'Current password is incorrect'}), 400
            
            # Validate new password
            if len(new_password) < PASSWORD_MIN_LENGTH:
                return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters long'}), 400
            
            if PASSWORD_CONFIRMATION_REQUIRED and new_password != confirm_password:
                return jsonify({'error': 'New passwords do not match'}), 400
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            log_user_ip(user_id, "password_change")
            
            return jsonify({
                'success': True,
                'message': 'Password updated successfully!'
            })
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        print(f"❌ Profile update error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating profile'}), 500

# Also update your existing profile route to handle the new fields
@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('logout'))

    return render_template('profile.html', user=user)

# Fixed forgot password route - replace your existing one
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle both display and submission of forgot password form"""
    if request.method == 'GET':
        return render_template('forgot_password.html')
    
    # POST method - handle form submission
    try:
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email address is required'}), 400
        
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Please enter a valid email address'}), 400
        
        # Check if user exists in database
        user = User.query.filter_by(email=email).first()
        
        # Always return success message (don't reveal if email exists)
        success_message = 'If an account with this email exists, a password reset link has been sent.'
        
        if user and user.is_verified:
            # Generate reset token using your existing serializer
            reset_token = serializer.dumps(email, salt='password-reset')
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            
            # Create professional reset email content
            text_body = f"""
Password Reset Request - Watch & Earn

You requested a password reset for your Watch & Earn account.

Click the link below to reset your password:
{reset_link}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
The Watch & Earn Team
            """
            
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                    .button {{ background: #ff6b6b; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
                    .footer {{ color: #666; font-size: 12px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 Password Reset Request</h1>
                        <p>Reset your Watch & Earn password</p>
                    </div>
                    <div class="content">
                        <h2>Hello!</h2>
                        <p>You requested a password reset for your Watch & Earn account.</p>
                        
                        <p>Click the button below to reset your password:</p>
                        
                        <a href="{reset_link}" class="button">🔑 Reset My Password</a>
                        
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                            {reset_link}
                        </p>
                        
                        <div class="footer">
                            <p>⏰ This link expires in 1 hour</p>
                            <p>🔒 If you didn't request this reset, please ignore this email</p>
                            <p>💰 Watch & Earn Team</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Send password reset email
            email_sent = send_email(
                email, 
                '🔒 Reset Your Watch & Earn Password', 
                text_body, 
                html_body
            )
            
            if not email_sent:
                print(f"❌ Failed to send password reset email to {email}")
                return jsonify({'error': 'Unable to send reset email. Please try again later.'}), 500
            
            print(f"✅ Password reset email sent successfully to {email}")
        
        # Always return success (security best practice)
        return jsonify({
            'success': True,
            'message': success_message
        }), 200
        
    except Exception as e:
        print(f"❌ Forgot password error: {str(e)}")
        return jsonify({'error': 'An internal error occurred. Please try again.'}), 500


# You also need this route to handle the actual password reset
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    try:
        # Verify the reset token
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>⏰ Reset Link Expired</h2>
            <p>Your password reset link has expired for security reasons.</p>
            <p><a href="/forgot_password" style="color: #4CAF50;">Request a new reset link</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400
    except BadSignature:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ Invalid Reset Link</h2>
            <p>This password reset link is invalid or has been tampered with.</p>
            <p><a href="/forgot_password" style="color: #4CAF50;">Request a new reset link</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ User Not Found</h2>
            <p>We couldn't find an account associated with this reset link.</p>
            <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
        </div>
        ''', 404
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or len(new_password) < PASSWORD_MIN_LENGTH:
            flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters long', 'error')
            return render_template('reset_password.html', token=token)
        
        if PASSWORD_CONFIRMATION_REQUIRED and new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Log password reset
        log_user_ip(user.id, "password_reset")
        
        flash('Password reset successfully! You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Remove this since you already have CSRF token generation in your code
# @app.context_processor
# def inject_csrf_token():
#     if 'csrf_token' not in session:
#         session['csrf_token'] = secrets.token_hex(16)
#     return dict(csrf_token=session['csrf_token'])

@app.route('/switch-account-type', methods=['POST'])
def switch_account_type():
    """Allow users to switch between User and YouTuber account types"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401
    
    try:
        new_account_type = request.form.get('account_type')
        
        # Validate account type
        if new_account_type not in ALLOWED_ROLES:
            return jsonify({'error': 'Invalid account type'}), 400
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if already the same type
        if user.account_type == new_account_type:
            return jsonify({'message': f'Already a {new_account_type}'}), 200
        
        # Update account type
        old_type = user.account_type
        user.account_type = new_account_type
        session['account_type'] = new_account_type
        
        db.session.commit()
        
        # Log the account type change
        log_user_ip(user.id, f"account_switch_{old_type}_to_{new_account_type}")
        
        # Determine redirect URL
        dashboard_url = url_for('youtuber_dashboard') if new_account_type == 'YouTuber' else url_for('user_dashboard')
        
        return jsonify({
            'success': True,
            'message': f'Successfully switched to {new_account_type} account!',
            'redirect': dashboard_url,
            'old_type': old_type,
            'new_type': new_account_type
        }), 200
        
    except Exception as e:
        print(f"❌ Account switch error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to switch account type. Please try again.'}), 500

@app.route('/watch', methods=['POST']) 
def track_watch(): 
    if not ENABLE_REWARDS: 
        return jsonify({'message': 'Rewards are currently disabled'})

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401
    
    watch_time = int(request.form.get('seconds_watched', 0))
    
    if watch_time >= 30:
        user = User.query.get(user_id)
        user.total_watch_minutes += watch_time // 60
        user.balance_usd += (watch_time / 60) * 0.01
        db.session.commit()
        
        # Log watch activity
        log_user_ip(user_id, f"watch_{watch_time}s")
        
        return jsonify({'message': 'Watch time tracked and rewarded'})
    return jsonify({'message': 'Watch time too short'})

@app.route('/daily-bonus', methods=['POST']) 
def give_daily_bonus(): 
    user_id = session.get('user_id') 
    if not user_id: 
        return jsonify({'error': 'Login required'}), 401 
    user = User.query.get(user_id) 
    now = datetime.utcnow() 
    if user.last_login_date is None or (now - user.last_login_date).days >= 1: 
        user.balance_usd += DAILY_REWARD 
        user.last_login_date = now 
        db.session.commit() 
        
        # Log daily bonus claim
        log_user_ip(user_id, "daily_bonus")
        
        return jsonify({'message': 'Daily bonus granted'}) 
    return jsonify({'message': 'Already claimed today'})

@app.route('/withdraw', methods=['POST']) 
def withdraw(): 
    user_id = session.get('user_id') 
    amount = float(request.form.get('amount')) 
    user = User.query.get(user_id) 
    if user.balance_usd >= MIN_WITHDRAW_AMOUNT and amount <= user.balance_usd: 
        req = WithdrawalRequest(user_id=user.id, amount=amount, status='pending') 
        user.balance_usd -= amount 
        db.session.add(req) 
        db.session.commit() 
        
        # Log withdrawal request
        log_user_ip(user_id, f"withdrawal_${amount}")
        
        return jsonify({'message': 'Withdrawal request submitted'}) 
    return jsonify({'error': f'Minimum withdrawal is ${MIN_WITHDRAW_AMOUNT} or insufficient balance'})

@app.route('/admin/panel') 
def admin_panel(): 
    users = User.query.all() 
    withdrawals = WithdrawalRequest.query.all() 
    videos = Video.query.all() 
    
    # Get IP tracking data if enabled
    ip_logs = []
    if ENABLE_IP_TRACKING:
        ip_logs = IPLog.query.order_by(IPLog.timestamp.desc()).limit(100).all()
    
    return render_template('admin_panel.html', 
                         users=users, 
                         withdrawals=withdrawals, 
                         videos=videos,
                         ip_logs=ip_logs,
                         ip_tracking_enabled=ENABLE_IP_TRACKING)

@app.route('/admin/user-ips/<int:user_id>')
def get_user_ip_history(user_id):
    """Get IP history for a specific user (admin only)"""
    if not ENABLE_IP_TRACKING:
        return jsonify({'error': 'IP tracking is disabled'}), 400
    
    # Note: Add admin authentication here in production
    ip_logs = IPLog.query.filter_by(user_id=user_id)\
        .order_by(IPLog.timestamp.desc())\
        .limit(50)\
        .all()
    
    logs_data = [{
        'ip_address': log.ip_address,
        'action': log.action,
        'timestamp': log.timestamp.isoformat(),
        'user_agent': log.user_agent
    } for log in ip_logs]
    
    return jsonify({'ip_logs': logs_data})

@app.route('/upload_video', methods=['POST']) 
def upload_video(): 
    if session.get('account_type') != 'YouTuber': 
        return jsonify({'error': 'Only YouTubers can upload videos'}), 403 
    
    title = request.form.get('title') 
    url = request.form.get('video_url') 
    user_id = session.get('user_id') 
    
    # Validate input
    if not title or not url:
        return jsonify({'error': 'Title and video URL are required'}), 400
    
    try:
        video = Video(title=title, video_url=url, added_by=user_id) 
        db.session.add(video) 
        db.session.commit() 
        
        # Log video upload
        log_user_ip(user_id, "video_upload")
        
        # For AJAX requests, return JSON
        if request.headers.get('Content-Type') == 'application/json' or request.is_json:
            return jsonify({
                'success': True,
                'message': 'Video uploaded successfully!',
                'redirect': url_for('upload_success', video_id=video.id)
            })
        
        # For form submissions, redirect to success page
        return redirect(url_for('upload_success', video_id=video.id))
        
    except Exception as e:
        print(f"❌ Video upload error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to upload video. Please try again.'}), 500

@app.route('/upload_success')
@app.route('/upload_success/<int:video_id>')
def upload_success(video_id=None):
    """Display video upload success page"""
    if session.get('account_type') != 'YouTuber': 
        return redirect(url_for('youtuber_dashboard'))
    
    # Get video details if video_id is provided
    video = None
    if video_id:
        video = Video.query.get(video_id)
        # Ensure the video belongs to the current user
        if video and video.added_by != session.get('user_id'):
            video = None
    
    # Get some stats for the page
    try:
        total_videos = Video.query.count()
        total_users = User.query.count()
        total_earned = db.session.query(db.func.sum(User.balance_usd)).scalar() or 0
    except:
        total_videos = 0
        total_users = 0
        total_earned = 0
    
    # Prepare template data
    template_data = {
        'video_title': video.title if video else None,
        'upload_time': video.timestamp.strftime('%B %d, %Y at %I:%M %p') if video else None,
        'total_videos': total_videos,
        'active_users': total_users,
        'total_earned': f"{total_earned:,.2f}"
    }
    
    return render_template('upload_success.html', **template_data)
    
@app.route('/test')
def test():
    return render_template('user_dashboard.html')

@app.route('/rules_popup')
def rules_popup():
    return render_template('rules_popup.html')  # or your actual template

@app.route('/terms')
def terms():
    return render_template('terms.html')

#==== Run App ====

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    app.run(debug=True)
else:
    # For production deployment (like Render)
    # Initialize database when app is imported
    init_db()
