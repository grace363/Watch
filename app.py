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

from functools import wraps
from flask import session, flash, redirect, url_for

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Access denied. Please log in.", "error")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

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

#app config
app.config['REWARDS_ENABLED'] = os.environ.get('REWARDS_ENABLED', 'True') == 'True'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_key')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///watch_and_earn.db')
app.config['DEBUG'] = os.environ.get('DEBUG', 'False') == 'True'
app.config['TESTING'] = os.environ.get('TESTING', 'False') == 'True'
 


#==== Database Configuration ====
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///watch_and_earn.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy()
db.init_app(app)

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
    is_admin = db.Column(db.Boolean, default=False)


    
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


from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    # ... other fields ...

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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


@app.route('/rules_popup')
def rules_popup():
    return render_template('rules_popup.html')  # or your actual template

@app.route('/terms')
def terms():
    return render_template('terms.html')

#==== Run App ====


@app.route('/api/user_stats')
def user_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    stats = {
        'total_earnings': user.balance_usd,
        'bonuses_claimed': user.bonuses_claimed if hasattr(user, 'bonuses_claimed') else 'N/A',
        'referrals': user.referral_count if hasattr(user, 'referral_count') else 'N/A'
    }

    return jsonify(stats)



@app.route('/earnings')
def earnings_page():
    return render_template('earnings.html')


@app.route("/admin/panel")
@admin_required
def admin_panel():
    users = User.query.all()
    videos = Video.query.all()
    env_config = {
        "DAILY_REWARD": DAILY_REWARD,
        "DAILY_ONLINE_TIME": DAILY_ONLINE_TIME,
        "MAX_VIDEOS_PER_DAY": MAX_VIDEOS_PER_DAY,
        "SESSION_HEARTBEAT_INTERVAL": SESSION_HEARTBEAT_INTERVAL
    }
    payment_requests = PaymentRequest.query.all()
    return render_template("admin_panel.html", users=users, videos=videos, config=env_config, payment_requests=payment_requests)

@app.route("/admin/reset_system", methods=["POST"])
@admin_required
def reset_system():
    for user in User.query.all():
        user.balance_usd = 0.0
        user.videos_watched_today = 0
        user.daily_bonus_given = False
        user.daily_online_time = 0
    db.session.commit()
    flash("System has been reset to default.", "success")
    return redirect(url_for("admin_panel"))

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/upload_youtube', methods=['POST'])
@admin_required
def upload_youtube():
    title = request.form.get('title')
    url = request.form.get('url')
    reward = float(request.form.get('reward', 0))
    watch_time = int(request.form.get('min_watch_time', 0))

    if not title or not url:
        flash("Missing title or URL", "error")
        return redirect(url_for("admin_panel"))

    new_video = Video(title=title, reward_amount=reward, min_watch_time=watch_time)
    db.session.add(new_video)
    db.session.commit()
    flash("YouTube video added successfully.", "success")
    return redirect(url_for("admin_panel"))

@app.route('/admin/upload_video', methods=['POST'])
@admin_required
def upload_video():
    if 'video_file' not in request.files:
        flash("No video file uploaded", "error")
        return redirect(url_for("admin_panel"))

    file = request.files['video_file']
    title = request.form.get('title')
    reward = float(request.form.get('reward', 0))
    watch_time = int(request.form.get('min_watch_time', 0))

    if file.filename == '' or not allowed_file(file.filename):
        flash("Invalid file type", "error")
        return redirect(url_for("admin_panel"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)

    new_video = Video(title=title or filename, reward_amount=reward, min_watch_time=watch_time)
    db.session.add(new_video)
    db.session.commit()

    flash("Local video uploaded successfully.", "success")
    return redirect(url_for("admin_panel"))

class PaymentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='payment_requests')
    amount = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')


@app.route('/admin/approve_payment', methods=['POST'])
@admin_required
def approve_payment():
    request_id = request.form.get('request_id')
    req = PaymentRequest.query.get(request_id)
    if req and req.status == 'pending':
        req.status = 'approved'
        db.session.commit()
        flash('Payment approved.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/reject_payment', methods=['POST'])
@admin_required
def reject_payment():
    request_id = request.form.get('request_id')
    req = PaymentRequest.query.get(request_id)
    if req and req.status == 'pending':
        req.status = 'rejected'
        db.session.commit()
        flash('Payment rejected.', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/update_config', methods=['POST'])
@admin_required
def update_config():
    for key in ["DAILY_REWARD", "DAILY_ONLINE_TIME", "MAX_VIDEOS_PER_DAY", "SESSION_HEARTBEAT_INTERVAL"]:
        val = request.form.get(key)
        if val:
            try:
                if val.lower() in ['true', 'false']:
                    app.config[key] = val.lower() == 'true'
                elif '.' in val:
                    app.config[key] = float(val)
                else:
                    app.config[key] = int(val)
            except Exception as e:
                flash(f"Invalid value for {key}: {val}", "error")
    flash("Environment settings updated.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/upload_sponsored', methods=['POST'])
@csrf.exempt
def upload_sponsored():
    title = request.form.get('ad_title')
    ad_type = request.form.get('ad_type')
    ad_file = request.files.get('ad_file')
    ad_url = request.form.get('ad_url')
    if ad_file:
        filename = secure_filename(ad_file.filename)
        ad_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash("Sponsored ad uploaded successfully.", "success")
    return redirect(url_for('admin_panel'))



@app.route('/admin/settings')
def admin_settings():
    config_states = {key: str(app.config.get(key, '')) for key in app.config}
    return render_template('admin_settings.html', config_states=config_states)


@app.route('/admin/reset_user_password', methods=['POST'])
@admin_required
def reset_user_password():
    user_id = request.form.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    if user and not user.is_admin:
        user.set_password("temp1234")
        db.session.commit()
        flash(f"Password for user {user.email} has been reset to 'temp1234'.", "success")
    else:
        flash("Invalid or admin user. Cannot reset.", "error")
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    app.run(debug=True)
else:
    # For production deployment (like Render)
    # Initialize database when app is imported
    init_db()









@app.route('/admin/settings')
def admin_settings():
    config_states = {key: str(app.config.get(key, '')) for key in app.config}
    return render_template('admin_settings.html', config_states=config_states)
