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
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature 
import firebase_admin 
from firebase_admin import credentials, firestore 
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template

#==== Flask App Config ====

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

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
    if request.method == "POST": 
        csrf_token = session.get('_csrf_token') 
        if not csrf_token or csrf_token != request.form.get('csrf_token'): 
            return "CSRF token missing or incorrect", 400

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
    firebase_dict = json.loads(base64.b64decode(firebase_base64).decode('utf-8')) 
    cred = credentials.Certificate(firebase_dict) 
    firebase_admin.initialize_app(cred) 
    db_firestore = firestore.client()

#==== SQLAlchemy Setup ====

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///watch_and_earn.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

#==== Serializer for Email Tokens ====

serializer = URLSafeTimedSerializer(app.secret_key)

#==== DB Models ====

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from sqlalchemy import String, Text, JSON, Index
import json

db = SQLAlchemy()

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
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_ip = db.Column(db.String(45))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    last_bonus_date = db.Column(db.Date)
    daily_online_time = db.Column(db.Integer, default=0)
        
    # Enhanced Anti-cheat fields
    videos_watched_today = db.Column(db.Integer, default=0)
    last_video_date = db.Column(db.Date)
    cheat_violations = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    ban_expires_at = db.Column(db.DateTime)  # Temporary bans
    session_start_time = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)
    last_bonus_claim = db.Column(db.DateTime)
    last_activity_date = db.Column(db.Date, default=datetime.utcnow().date())
    current_session_start = db.Column(db.DateTime)
    total_daily_bonuses = db.Column(db.Integer, default=0)
    consecutive_days = db.Column(db.Integer, default=0)
    
    # Advanced Session tracking 
    session_token = db.Column(db.String(64))
    active_sessions_count = db.Column(db.Integer, default=0)  # Prevent multiple sessions
    max_concurrent_sessions = db.Column(db.Integer, default=1)
    
    # Behavioral Anti-cheat
    back_button_pressed = db.Column(db.Boolean, default=False)
    focus_lost_count = db.Column(db.Integer, default=0)
    tab_switch_count = db.Column(db.Integer, default=0)  # Track tab switching
    window_blur_count = db.Column(db.Integer, default=0)  # Track window focus loss
    fast_forward_attempts = db.Column(db.Integer, default=0)  # Video manipulation attempts
    
    # Watch Pattern Analysis
    total_watch_time = db.Column(db.Integer, default=0)
    average_watch_completion = db.Column(db.Float, default=0.0)  # % of videos completed
    watch_streak = db.Column(db.Integer, default=0)  # Consecutive videos watched
    unusual_watch_patterns = db.Column(db.Integer, default=0)  # Flagged patterns
    
    # Device/Browser Fingerprinting
    device_fingerprint = db.Column(db.String(200))
    browser_fingerprint = db.Column(db.String(200))  # Separate browser fingerprint
    time_zone = db.Column(db.String(50))
    screen_resolution = db.Column(db.String(20))
    user_agent_hash = db.Column(db.String(64))
    canvas_fingerprint = db.Column(db.String(100))
    webgl_fingerprint = db.Column(db.String(100))
    audio_fingerprint = db.Column(db.String(100))
    
    # AI/ML Fraud Detection
    click_pattern_score = db.Column(db.Float, default=0.0)
    watch_velocity_score = db.Column(db.Float, default=0.0)
    behavioral_score = db.Column(db.Float, default=0.0)
    ml_fraud_probability = db.Column(db.Float, default=0.0)
    feature_vector_hash = db.Column(db.String(64))
    
    # Network/Proxy Detection
    proxy_detected = db.Column(db.Boolean, default=False)
    vpn_detected = db.Column(db.Boolean, default=False)
    tor_detected = db.Column(db.Boolean, default=False)
    datacenter_ip = db.Column(db.Boolean, default=False)
    
    # Automation Detection
    automation_detected = db.Column(db.Boolean, default=False)
    bot_score = db.Column(db.Float, default=0.0)  # 0.0 = human, 1.0 = bot
    headless_browser_detected = db.Column(db.Boolean, default=False)
    selenium_detected = db.Column(db.Boolean, default=False)
    puppeteer_detected = db.Column(db.Boolean, default=False)
    
    # Risk Assessment
    suspicious_activity_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(10), default='low')  # low, medium, high, critical
    trust_score = db.Column(db.Float, default=100.0)  # 0-100, higher = more trusted
    last_risk_assessment = db.Column(db.DateTime)
    
    # Consistency Tracking
    browser_changes_count = db.Column(db.Integer, default=0)
    device_changes_count = db.Column(db.Integer, default=0)
    location_changes_count = db.Column(db.Integer, default=0)
    ip_changes_count = db.Column(db.Integer, default=0)
    timezone_changes_count = db.Column(db.Integer, default=0)
    
    # Speed/Timing Analysis
    average_reaction_time = db.Column(db.Float, default=0.0)  # Click reaction times
    typing_speed_wpm = db.Column(db.Integer, default=0)  # Words per minute
    mouse_movement_entropy = db.Column(db.Float, default=0.0)  # Randomness of mouse movements
    
    # Earning Protection
    daily_earning_limit = db.Column(db.Float, default=5.0)  # Max daily earnings
    current_daily_earnings = db.Column(db.Float, default=0.0)
    last_earnings_reset = db.Column(db.Date, default=datetime.utcnow().date())
    weekly_earning_limit = db.Column(db.Float, default=25.0)
    current_weekly_earnings = db.Column(db.Float, default=0.0)
    
    # Account Flags
    manual_review_required = db.Column(db.Boolean, default=False)
    kyc_required = db.Column(db.Boolean, default=False)
    withdrawal_restricted = db.Column(db.Boolean, default=False)
    earning_restricted = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.username}>'


class AntiCheatRule(db.Model):
    """Define anti-cheat rules and thresholds"""
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(100), unique=True, nullable=False)
    rule_type = db.Column(db.String(50), nullable=False)  # 'behavioral', 'technical', 'pattern'
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    threshold_value = db.Column(db.Float)  # Numeric threshold
    threshold_timeframe = db.Column(db.Integer)  # Minutes/hours for time-based rules
    action_type = db.Column(db.String(20), default='flag')  # flag, warn, restrict, ban
    auto_action = db.Column(db.Boolean, default=False)  # Auto-execute action
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WatchSession(db.Model):
    __tablename__ = 'watch_session'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    session_token = db.Column(db.String(100), unique=True, nullable=False)
    
    # Timing Data
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    watch_duration = db.Column(db.Integer, default=0)  # seconds actually watched
    video_length = db.Column(db.Integer)  # total video length
    completion_percentage = db.Column(db.Float, default=0.0)
    
    # Behavioral Monitoring
    focus_lost_count = db.Column(db.Integer, default=0)
    tab_switches = db.Column(db.Integer, default=0)
    window_blur_events = db.Column(db.Integer, default=0)
    back_button_pressed = db.Column(db.Boolean, default=False)
    fast_forward_attempts = db.Column(db.Integer, default=0)
    rewind_attempts = db.Column(db.Integer, default=0)
    pause_count = db.Column(db.Integer, default=0)
    volume_changes = db.Column(db.Integer, default=0)
    fullscreen_toggles = db.Column(db.Integer, default=0)
    
    # Interaction Tracking
    mouse_movements = db.Column(db.Integer, default=0)
    mouse_clicks = db.Column(db.Integer, default=0)
    keyboard_events = db.Column(db.Integer, default=0)
    scroll_events = db.Column(db.Integer, default=0)
    
    # Quality Metrics
    video_buffer_events = db.Column(db.Integer, default=0)
    video_errors = db.Column(db.Integer, default=0)
    network_interruptions = db.Column(db.Integer, default=0)
    
    # Anti-Cheat Flags
    reward_given = db.Column(db.Boolean, default=False)
    cheating_detected = db.Column(db.Boolean, default=False)
    cheat_reason = db.Column(db.String(500))
    is_completed = db.Column(db.Boolean, default=False)
    is_suspicious = db.Column(db.Boolean, default=False)
    manual_review_required = db.Column(db.Boolean, default=False)
    
    # Technical Data
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    browser_fingerprint = db.Column(db.String(200))
    screen_resolution = db.Column(db.String(20))
    connection_speed = db.Column(db.String(20))  # Estimated connection speed
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('watch_sessions', lazy=True))
    video = db.relationship('Video', backref=db.backref('watch_sessions', lazy=True))

    # Indexes for performance
    __table_args__ = (
        Index('idx_user_date', 'user_id', 'created_at'),
        Index('idx_session_token', 'session_token'),
        Index('idx_suspicious', 'is_suspicious', 'cheating_detected'),
    )


class MouseMovementPattern(db.Model):
    """Track mouse movement patterns for bot detection"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('watch_session.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Movement Data (stored as JSON)
    movement_data = db.Column(JSON)  # Array of {x, y, timestamp, event_type}
    total_distance = db.Column(db.Float, default=0.0)
    average_speed = db.Column(db.Float, default=0.0)
    movement_entropy = db.Column(db.Float, default=0.0)  # Randomness measure
    
    # Pattern Analysis
    straight_line_ratio = db.Column(db.Float, default=0.0)  # How often moves in straight lines
    pause_frequency = db.Column(db.Float, default=0.0)  # How often mouse pauses
    acceleration_variance = db.Column(db.Float, default=0.0)  # Speed change patterns
    
    # Bot Detection Scores
    human_likelihood = db.Column(db.Float, default=0.5)  # 0.0 = bot, 1.0 = human
    pattern_regularity = db.Column(db.Float, default=0.0)  # Too regular = bot
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    session = db.relationship('WatchSession', backref=db.backref('mouse_patterns', lazy=True))
    user = db.relationship('User', backref=db.backref('mouse_patterns', lazy=True))


class BiometricData(db.Model):
    """Store behavioral biometric data"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('watch_session.id'), nullable=True)
    
    # Typing Patterns
    keystroke_dynamics = db.Column(JSON)  # Timing between keystrokes
    typing_rhythm_score = db.Column(db.Float, default=0.0)
    
    # Click Patterns
    click_timing_data = db.Column(JSON)  # Time between clicks
    double_click_timing = db.Column(db.Float, default=0.0)
    click_pressure_variance = db.Column(db.Float, default=0.0)
    
    # Scroll Patterns
    scroll_velocity_pattern = db.Column(JSON)
    scroll_acceleration_pattern = db.Column(JSON)
    
    # Touch Patterns (for mobile)
    touch_pressure_data = db.Column(JSON)
    swipe_velocity_data = db.Column(JSON)
    
    # Device Orientation (mobile)
    device_orientation_changes = db.Column(db.Integer, default=0)
    accelerometer_data = db.Column(JSON)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('biometric_data', lazy=True))


class NetworkAnalysis(db.Model):
    """Analyze network patterns for fraud detection"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    
    # Geolocation Data
    country = db.Column(db.String(2))  # ISO country code
    region = db.Column(db.String(50))
    city = db.Column(db.String(50))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timezone = db.Column(db.String(50))
    
    # ISP Information
    isp = db.Column(db.String(100))
    organization = db.Column(db.String(100))
    as_number = db.Column(db.String(20))  # Autonomous System Number
    
    # Risk Indicators
    is_proxy = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)
    is_tor = db.Column(db.Boolean, default=False)
    is_datacenter = db.Column(db.Boolean, default=False)
    is_mobile = db.Column(db.Boolean, default=False)
    is_hosting = db.Column(db.Boolean, default=False)
    
    # Connection Analysis
    connection_type = db.Column(db.String(20))  # broadband, mobile, satellite
    estimated_speed = db.Column(db.String(20))
    rtt_ms = db.Column(db.Integer)  # Round trip time
    
    # Reputation Scores
    ip_reputation_score = db.Column(db.Float, default=0.0)  # Third-party reputation
    threat_level = db.Column(db.String(20), default='low')
    
    # Usage Patterns
    users_from_ip = db.Column(db.Integer, default=1)  # How many users from this IP
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('network_analyses', lazy=True))


class FraudDetectionLog(db.Model):
    """Log all fraud detection events and decisions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('watch_session.id'), nullable=True)
    
    # Detection Info
    detection_type = db.Column(db.String(50), nullable=False)  # mouse_bot, proxy, pattern, etc.
    rule_triggered = db.Column(db.String(100))  # Which rule was triggered
    confidence_score = db.Column(db.Float, default=0.0)  # 0.0-1.0 confidence
    risk_score = db.Column(db.Float, default=0.0)  # Calculated risk score
    
    # Evidence Data
    evidence_data = db.Column(JSON)  # Store detection evidence
    raw_data = db.Column(JSON)  # Raw data that triggered detection
    
    # Actions Taken
    action_taken = db.Column(db.String(50))  # flag, warn, restrict, ban, none
    automated_action = db.Column(db.Boolean, default=True)
    manual_review_required = db.Column(db.Boolean, default=False)
    
    # Review Info
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime)
    review_decision = db.Column(db.String(20))  # confirmed, false_positive, inconclusive
    review_notes = db.Column(db.Text)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('fraud_logs', lazy=True))
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref=db.backref('reviewed_cases', lazy=True))
    session = db.relationship('WatchSession', backref=db.backref('fraud_logs', lazy=True))


class WhitelistedIP(db.Model):
    """IPs that are whitelisted from certain checks"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    ip_range = db.Column(db.String(50))  # CIDR notation for ranges
    reason = db.Column(db.String(200))
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # Optional expiration
    is_active = db.Column(db.Boolean, default=True)
    
    added_by_user = db.relationship('User', backref=db.backref('whitelisted_ips', lazy=True))


class BlacklistedIP(db.Model):
    """IPs that are blocked"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    ip_range = db.Column(db.String(50))  # CIDR notation for ranges
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # Optional expiration
    is_active = db.Column(db.Boolean, default=True)
    
    blocked_by_user = db.relationship('User', backref=db.backref('blacklisted_ips', lazy=True))


# Keep your existing models with anti-cheat enhancements
class Video(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    title = db.Column(db.String(200), nullable=False) 
    video_url = db.Column(db.String(500), nullable=False) 
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    min_watch_time = db.Column(db.Integer, default=30)  # seconds
    reward_amount = db.Column(db.Float, default=0.01)
    
    # Anti-cheat for videos
    max_daily_views_per_user = db.Column(db.Integer, default=5)
    requires_interaction = db.Column(db.Boolean, default=True)  # Require mouse/keyboard activity
    skip_detection_enabled = db.Column(db.Boolean, default=True)
    quality_threshold = db.Column(db.Float, default=0.8)  # Minimum completion quality
    
    uploader = db.relationship('User', backref=db.backref('videos', lazy=True))

#==== Util: Send Email ====

def send_email(to, subject, body, html_body=None): 
    """Send email with both text and HTML versions"""
    try:
        msg = Message(
            subject=subject, 
            recipients=[to], 
            body=body, 
            html=html_body,
            sender=app.config['MAIL_USERNAME']
        ) 
        mail.send(msg)
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
        return "Site is under maintenance. Please check back later." 
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST']) 
def register(): 
    if request.method == 'POST': 
        email = request.form['email'] 
        password = request.form['password'] 
        confirm = request.form.get('confirm_password') 
        role = request.form['account_type']

        if PASSWORD_CONFIRMATION_REQUIRED and password != confirm:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < PASSWORD_MIN_LENGTH:
            return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters'}), 400

        if role not in ALLOWED_ROLES:
            return jsonify({'error': 'Invalid account type'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409

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

        token = serializer.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        
        # Create professional email content
        text_body, html_body = create_verification_email(email, link)
        
        # Send verification email
        email_sent = send_email(
            email, 
            '🎬 Verify Your Watch & Earn Account', 
            text_body, 
            html_body
        )
        
        if not email_sent:
            return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500

        if AUTO_LOGIN_AFTER_REGISTRATION:
            session['user_id'] = user.id
            session['account_type'] = user.account_type
            return redirect(url_for('youtuber_dashboard' if user.account_type == 'YouTuber' else 'user_dashboard'))

        return jsonify({
            'success': True,
            'message': '🎉 Account created successfully! Please check your email to verify your account.',
            'email_sent': True
        })

    return render_template('register.html')

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

@app.route('/verify/<token>') 
def confirm_email(token): 
    try: 
        email = serializer.loads(token, salt='email-confirm', max_age=3600) 
    except SignatureExpired: 
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>⏰ Verification Link Expired</h2>
            <p>Your verification link has expired for security reasons.</p>
            <p><a href="/resend-verification" style="color: #4CAF50;">Request a new verification email</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400 
    except BadSignature: 
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ Invalid Verification Link</h2>
            <p>This verification link is invalid or has been tampered with.</p>
            <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400

    user = User.query.filter_by(email=email).first()
    if user:
        if user.is_verified:
            return '''
            <div style="text-align: center; padding: 50px; font-family: Arial;">
                <h2>✅ Already Verified</h2>
                <p>Your email has already been verified!</p>
                <p><a href="/login" style="color: #4CAF50; padding: 10px 20px; background: #f0f0f0; text-decoration: none; border-radius: 5px;">Login to Your Account</a></p>
            </div>
            ''', 200
        else:
            user.is_verified = True
            db.session.commit()
            
            # Log email verification
            log_user_ip(user.id, "email_verify")
            
            return '''
            <div style="text-align: center; padding: 50px; font-family: Arial;">
                <h2>🎉 Email Verified Successfully!</h2>
                <p>Welcome to Watch & Earn! Your account is now active.</p>
                <p>You can now start watching videos and earning money!</p>
                <p><a href="/login" style="color: white; padding: 15px 30px; background: #4CAF50; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;">🚀 Start Earning Now</a></p>
            </div>
            ''', 200
    return '''
    <div style="text-align: center; padding: 50px; font-family: Arial;">
        <h2>❌ User Not Found</h2>
        <p>We couldn't find an account associated with this verification link.</p>
        <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
    </div>
    ''', 404

@app.route('/login', methods=['GET', 'POST']) 
@limiter.limit(LOGIN_RATE_LIMIT) 
def login(): 
    if request.method == 'POST': 
        try:
            # Get form data
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Validate input
            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400
            
            # Find user
            user = User.query.filter_by(email=email).first()
            if not user: 
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Check password
            if not check_password_hash(user.password_hash, password): 
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Check if email is verified
            if not user.is_verified: 
                return jsonify({
                    'error': 'Please verify your email first.',
                    'needs_verification': True
                }), 403
            
            # Update IP tracking (with error handling)
            try:
                current_ip = get_client_ip()
                if ENABLE_IP_TRACKING:
                    user.last_ip = current_ip
                    log_user_ip(user.id, "login")
            except Exception as ip_error:
                print(f"⚠️ IP tracking failed: {str(ip_error)}")
                # Continue with login even if IP tracking fails
            
            # Set session data
            session.permanent = True  # Make session permanent
            session['user_id'] = user.id
            session['account_type'] = user.account_type
            session['email'] = user.email
            
            # Update last login (with error handling)
            try:
                user.last_login_date = datetime.utcnow()
                db.session.commit()
            except Exception as db_error:
                print(f"⚠️ Database update failed: {str(db_error)}")
                db.session.rollback()
                # Don't fail login if just the timestamp update fails
            
            # Return success response with redirect URL
            dashboard_url = url_for('youtuber_dashboard') if user.account_type == 'YouTuber' else url_for('user_dashboard')
            
            return jsonify({
                'success': True,
                'message': 'Login successful!',
                'redirect': dashboard_url,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'account_type': user.account_type
                }
            }), 200
            
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'An internal error occurred. Please try again.'}), 500

    return render_template('login.html')

# This integrates with your existing Flask app structure
# No need to redefine imports or mail config since you already have them

# Replace your existing forgot password routes with these fixed versions:

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

@app.route('/user_dashboard') 
def user_dashboard(): 
    if session.get('account_type') != 'User': 
        return 'Access denied', 403 
    return render_template('user_dashboard.html')

@app.route('/youtuber_dashboard') 
def youtuber_dashboard(): 
    if session.get('account_type') != 'YouTuber': 
        return 'Access denied', 403 
    return render_template('youtuber_dashboard.html')

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

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    user_id = session.get('user_id')
    if user_id:
        # Log logout
        log_user_ip(user_id, "logout")
    
    session.clear()
    return redirect(url_for('home'))

#==== Database Initialization ====

def init_db():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Print IP tracking status
        if ENABLE_IP_TRACKING:
            print("🔍 IP tracking is ENABLED")
            print(f"📊 Keeping last {MAX_IP_HISTORY} IP addresses per user")
            if TRUST_PROXY_HEADERS:
                print("🌐 Proxy headers (X-Forwarded-For, X-Real-IP) are trusted")
        else:
            print("❌ IP tracking is DISABLED")

@app.route('/rules_popup')
def rules_popup():
    return render_template('rules_popup.html')  # or your actual template

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/debug-scan')
def debug_scan():
    import os, sys, traceback
    from flask import jsonify

    debug_result = {}
    try:
        # ✅ Check session data
        debug_result['🧠 Session'] = dict(session)

        # ✅ Check routes
        debug_result['🧭 Registered Routes'] = list(app.view_functions.keys())

        # ✅ Check template rendering
        templates_to_test = [
            'login.html', 'register.html',
            'user_dashboard.html', 'youtuber_dashboard.html',
            'withdraw.html', 'rules.html'
        ]
        missing_templates = []
        for t in templates_to_test:
            try:
                render_template(t)
            except Exception:
                missing_templates.append(t)
        debug_result['📄 Missing Templates'] = missing_templates

        # ✅ Check user table and record count
        try:
            user_count = db.session.query(User).count()
        except Exception:
            user_count = '❌ Could not access User table (maybe not defined or DB error?)'
        debug_result['👥 User Count'] = user_count

        # ✅ App config checks
        debug_result['⚙️ Config'] = {
            'DEBUG': app.config.get('DEBUG'),
            'ENV': app.config.get('ENV'),
            'SECRET_KEY set': bool(app.config.get('SECRET_KEY')),
            'SQLALCHEMY_DATABASE_URI': str(app.config.get('SQLALCHEMY_DATABASE_URI', 'Not Set'))[:50] + '...'
        }

        # ✅ Test fake register and login form simulation
        debug_result['🧪 Form Endpoints'] = {}
        try:
            # Simulate rendering login
            login_page = render_template('login.html')
            register_page = render_template('register.html')
            debug_result['🧪 Form Endpoints']['login.html rendered'] = '✅ OK' if login_page else '⚠️ Empty'
            debug_result['🧪 Form Endpoints']['register.html rendered'] = '✅ OK' if register_page else '⚠️ Empty'
        except Exception as e:
            debug_result['🧪 Form Endpoints']['error'] = f"❌ {str(e)}"

        # ✅ Render environment basics
        debug_result['📦 Environment'] = {
            'Python Version': sys.version,
            'Current Path': os.getcwd()
        }

        return jsonify(debug_result)

    except Exception as e:
        return f"<h2>❌ Debug Crash</h2><pre>{traceback.format_exc()}</pre>", 500

#==== Run App ====

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    app.run(debug=True)
else:
    # For production deployment (like Render)
    # Initialize database when app is imported
    init_db()
