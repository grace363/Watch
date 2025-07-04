# Your existing imports and configuration remain the same
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
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# [Your existing Flask app configuration remains the same]

#==== MERGED DATABASE MODELS ====

class User(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password_hash = db.Column(db.String(200), nullable=False) 
    account_type = db.Column(db.String(10), nullable=False) 
    is_verified = db.Column(db.Boolean, default=False) 
    balance_usd = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Personal Information
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    
    # Login and Session Tracking
    last_login_date = db.Column(db.DateTime) 
    last_ip = db.Column(db.String(45))  # Store last known IP (IPv6 can be up to 45 chars)
    last_ip_address = db.Column(db.String(45))  # Keeping both for compatibility
    session_token = db.Column(db.String(64))
    session_start_time = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)
    current_session_start = db.Column(db.DateTime)
    
    # Daily Activity Tracking
    daily_online_time = db.Column(db.Integer, default=0)  # seconds online today
    daily_bonus_given = db.Column(db.Boolean, default=False) 
    last_bonus_date = db.Column(db.Date)
    last_bonus_claim = db.Column(db.DateTime)  # When bonus was last claimed
    last_activity_date = db.Column(db.Date, default=datetime.utcnow().date())
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)  # For compatibility
    
    # Video Watching Stats
    videos_watched_today = db.Column(db.Integer, default=0)
    last_video_date = db.Column(db.Date)
    total_watch_minutes = db.Column(db.Integer, default=0) 
    total_watch_time = db.Column(db.Integer, default=0)  # in seconds
    
    # Streak and Bonus Tracking
    consecutive_days = db.Column(db.Integer, default=0)
    total_daily_bonuses = db.Column(db.Integer, default=0)
    
    # Anti-cheat and Security
    cheat_violations = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    back_button_pressed = db.Column(db.Boolean, default=False)
    focus_lost_count = db.Column(db.Integer, default=0)
    
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
    
    # Add these methods to your User model
    def reset_daily_stats(self):
        """Reset daily statistics - call this at midnight"""
        self.daily_online_time = 0
        self.daily_bonus_given = False
        self.videos_watched_today = 0
        
    def can_watch_video(self):
        """Check if user can watch more videos today"""
        max_videos = int(os.environ.get('MAX_VIDEOS_PER_DAY', '50'))
        return (self.videos_watched_today or 0) < max_videos
    
    def can_claim_daily_bonus(self):
        """Check if user can claim daily bonus"""
        min_time = int(os.environ.get('DAILY_ONLINE_TIME', '3600'))
        return (not self.daily_bonus_given and 
                (self.daily_online_time or 0) >= min_time)

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
    min_watch_time = db.Column(db.Integer, default=30)  # seconds (merged from VIDEO_WATCH_TIME)
    reward_amount = db.Column(db.Float, default=0.01)  # Reward per video (merged from VIDEO_REWARD_AMOUNT)
    
    # Add relationship
    uploader = db.relationship('User', backref=db.backref('videos', lazy=True))

# MERGED: WatchSession and VideoSession (keeping WatchSession as primary)
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
    reward_earned = db.Column(db.Float, default=0.0)  # Merged from VideoSession
    cheating_detected = db.Column(db.Boolean, default=False)
    cheat_reason = db.Column(db.String(200))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    video_length = db.Column(db.Integer)  # total video length in seconds
    is_completed = db.Column(db.Boolean, default=False)
    is_suspicious = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    behavioral_data = db.Column(db.Text)  # JSON string of behavioral tracking data (merged)
    
    user = db.relationship('User', backref=db.backref('watch_sessions', lazy=True))
    video = db.relationship('Video', backref=db.backref('watch_sessions', lazy=True))

# MERGED: DailySession and UserSession (keeping both as they serve different purposes)
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

class UserSession(db.Model):
    """Track user sessions and behavioral data"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(100), nullable=False, unique=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat = db.Column(db.DateTime, default=datetime.utcnow)
    total_time = db.Column(db.Integer, default=0)  # Total session time in seconds
    mouse_movements = db.Column(db.Integer, default=0)
    click_count = db.Column(db.Integer, default=0)
    keyboard_events = db.Column(db.Integer, default=0)
    focus_changes = db.Column(db.Integer, default=0)
    page_visibility_changes = db.Column(db.Integer, default=0)
    device_info = db.Column(db.Text)  # JSON string of device information
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('user_sessions', lazy=True))

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
    source = db.Column(db.String(50), nullable=False)  # 'video_watch', 'daily_bonus', 'referral', 'admin_bonus', etc.
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=True)
    session_id = db.Column(db.Integer, db.ForeignKey('user_session.id'), nullable=True)  # Added session reference
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('earnings', lazy=True))
    video = db.relationship('Video', backref=db.backref('earnings', lazy=True))
    session = db.relationship('UserSession', backref=db.backref('earnings', lazy=True))

# [Keep all your existing advanced anti-cheat models as they are]
class DeviceFingerprint(db.Model):
    """Track device fingerprints for fraud detection"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fingerprint_hash = db.Column(db.String(200), nullable=False)
    screen_resolution = db.Column(db.String(20))
    timezone = db.Column(db.String(50))
    language = db.Column(db.String(10))
    user_agent = db.Column(db.Text)
    canvas_fingerprint = db.Column(db.String(100))
    webgl_fingerprint = db.Column(db.String(100))
    audio_fingerprint = db.Column(db.String(100))
    plugins_list = db.Column(db.Text)
    fonts_list = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    times_seen = db.Column(db.Integer, default=1)
    is_suspicious = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('device_fingerprints', lazy=True))

class SecurityEvent(db.Model):
    """Log security events and suspicious activities"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(10), default='low')
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    session_token = db.Column(db.String(100))
    additional_data = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    admin_notes = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('security_events', lazy=True))

class MouseMovement(db.Model):
    """Track mouse movements for bot detection"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('watch_session.id'), nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    x_coordinate = db.Column(db.Integer)
    y_coordinate = db.Column(db.Integer)
    event_type = db.Column(db.String(10))
    velocity = db.Column(db.Float)
    is_human_like = db.Column(db.Boolean, default=True)
    
    session = db.relationship('WatchSession', backref=db.backref('mouse_movements', lazy=True))

class KeystrokePattern(db.Model):
    """Track keystroke patterns for behavioral analysis"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(100))
    key_pressed = db.Column(db.String(10))
    dwell_time = db.Column(db.Float)
    flight_time = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_suspicious = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('keystroke_patterns', lazy=True))

class GeoLocation(db.Model):
    """Track user locations for anomaly detection"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    country = db.Column(db.String(2))
    region = db.Column(db.String(50))
    city = db.Column(db.String(50))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    is_proxy = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)
    is_tor = db.Column(db.Boolean, default=False)
    isp = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    distance_from_last = db.Column(db.Float)
    
    user = db.relationship('User', backref=db.backref('geo_locations', lazy=True))

class RiskScore(db.Model):
    """Store ML-based risk scores and fraud predictions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('watch_session.id'), nullable=True)
    model_version = db.Column(db.String(20))
    fraud_probability = db.Column(db.Float, nullable=False)
    behavioral_score = db.Column(db.Float)
    device_score = db.Column(db.Float)
    location_score = db.Column(db.Float)
    pattern_score = db.Column(db.Float)
    velocity_score = db.Column(db.Float)
    final_risk_level = db.Column(db.String(10))
    features_used = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.String(50))
    
    user = db.relationship('User', backref=db.backref('risk_scores', lazy=True))
    session = db.relationship('WatchSession', backref=db.backref('risk_scores', lazy=True))

class HoneypotInteraction(db.Model):
    """Track interactions with honeypot elements"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    session_token = db.Column(db.String(100))
    honeypot_type = db.Column(db.String(50))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    automatic_ban = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('honeypot_interactions', lazy=True))

#==== MERGED HELPER FUNCTIONS ====

def check_daily_video_limit(user_id):
    """Check if user can watch more videos today"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    max_videos = int(os.environ.get('MAX_VIDEOS_PER_DAY', '50'))
    today = datetime.utcnow().date()
    
    # Reset daily count if it's a new day
    if not user.last_video_date or user.last_video_date != today:
        user.videos_watched_today = 0
        user.last_video_date = today
        try:
            db.session.commit()
        except Exception as e:
            logging.error(f"Failed to reset video count for user {user_id}: {str(e)}")
            db.session.rollback()
    
    return user.videos_watched_today < max_videos

def reset_daily_stats():
    """Reset all users' daily statistics - should be run as a cron job"""
    try:
        users = User.query.all()
        for user in users:
            user.reset_daily_stats()
        db.session.commit()
        logging.info(f"✅ Reset daily stats for {len(users)} users")
    except Exception as e:
        logging.error(f"❌ Error resetting daily stats: {e}")
        db.session.rollback()

def schedule_daily_reset():
    """Schedule daily statistics reset"""
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=reset_daily_stats,
        trigger="cron",
        hour=0,
        minute=0,
        id='daily_reset'
    )
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

# [Keep all your existing anti-cheat utility functions]
# [Your existing routes and application logic remain the same]

# Add to your app initialization
def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()

# Initialize the scheduler
# schedule_daily_reset()  # Uncomment this when you're ready to use it
    
#==== Anti-Cheat Utility Functions ====

def reset_daily_data_if_needed(user):
    """Reset daily data if it's a new day"""
    today = datetime.utcnow().date()
    
    # Check if it's a new day compared to last activity
    if not user.last_activity_date or user.last_activity_date != today:
        logging.info(f"Resetting daily data for user {user.id} - New day detected")
        
        # Reset daily counters
        user.daily_online_time = 0
        user.daily_bonus_given = False
        user.videos_watched_today = 0
        user.last_activity_date = today
        user.current_session_start = datetime.utcnow()
        user.session_start_time = datetime.utcnow()  # Reset session tracking
        user.last_heartbeat = datetime.utcnow()
        
        # Handle consecutive days logic
        if user.last_bonus_date:
            # If user claimed bonus yesterday, they maintain streak
            if user.last_bonus_date == today - timedelta(days=1):
                # Consecutive days maintained
                pass
            else:
                # Streak broken - reset consecutive days
                user.consecutive_days = 0
        
        # Commit the reset
        try:
            db.session.commit()
            logging.info(f"Daily data reset successful for user {user.id}")
        except Exception as e:
            logging.error(f"Failed to reset daily data for user {user.id}: {str(e)}")
            db.session.rollback()
            raise e
    
    return user

# Additional helper function to check daily bonus eligibility
def can_claim_daily_bonus(user):
    """Check if user can claim daily bonus"""
    today = datetime.utcnow().date()
    
    # Check if already claimed today
    if user.daily_bonus_given and user.last_bonus_date == today:
        return False, "Already claimed today"
    
    # Check online time requirement
    if user.daily_online_time < DAILY_ONLINE_TIME:
        return False, f"Need {DAILY_ONLINE_TIME - user.daily_online_time} more seconds online"
    
    # Check if user is banned
    if user.is_banned:
        return False, "Account is banned"
    
    return True, "Eligible for bonus"

def create_session_token():
    """Create a unique session token"""
    return secrets.token_urlsafe(32)

def check_daily_video_limit(user_id):
    """Check if user has reached daily video limit"""
    user = User.query.get(user_id)
    if not user:
        return False
        
    today = datetime.utcnow().date()
    
    # Reset daily count if it's a new day
    if not user.last_video_date or user.last_video_date != today:
        user.videos_watched_today = 0
        user.last_video_date = today
        try:
            db.session.commit()
        except Exception as e:
            logging.error(f"Failed to reset video count for user {user_id}: {str(e)}")
            db.session.rollback()
    
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
        try:
            db.session.commit()
            logging.warning(f"🚨 User {user_id} banned: {reason}")
        except Exception as e:
            logging.error(f"Failed to ban user {user_id}: {str(e)}")
            db.session.rollback()

def detect_cheating(watch_session):
    """Detect various cheating methods"""
    cheating_detected = False
    reasons = []
    
    # Check if watch session exists and has required data
    if not watch_session:
        return False, []
    
    # 1. Check for impossible watch speeds
    if watch_session.video_length and watch_session.watch_duration:
        watch_ratio = watch_session.watch_duration / watch_session.video_length
        if watch_ratio > 1.5:  # Watched 50% faster than possible
            cheating_detected = True
            reasons.append("Impossible watch speed detected")
    
    # 2. Check for too short watch time
    if watch_session.watch_duration and watch_session.watch_duration < MIN_WATCH_TIME:
        cheating_detected = True
        reasons.append("Watch time too short")
    
    # 3. Check for session duration anomalies
    if watch_session.start_time and watch_session.end_time:
        actual_duration = (watch_session.end_time - watch_session.start_time).total_seconds()
        if watch_session.watch_duration > actual_duration * 1.2:  # 20% tolerance
            cheating_detected = True
            reasons.append("Watch duration exceeds session time")
    
    # 4. Check for multiple sessions from same IP in short time
    recent_sessions = WatchSession.query.filter(
        WatchSession.ip_address == watch_session.ip_address,
        WatchSession.start_time >= datetime.utcnow() - timedelta(minutes=5),
        WatchSession.user_id != watch_session.user_id
    ).count()
    
    if recent_sessions > 3:  # More than 3 different users from same IP in 5 minutes
        cheating_detected = True
        reasons.append("Multiple accounts from same IP")
    
    # 5. Check if back button was pressed
    if watch_session.back_button_pressed:
        cheating_detected = True
        reasons.append("Back button pressed")
    
    # 6. Check excessive focus loss
    if watch_session.focus_lost_count > ANTI_CHEAT_TOLERANCE:
        cheating_detected = True
        reasons.append(f"Lost focus {watch_session.focus_lost_count} times")
    
    # 7. Check if watch duration is suspiciously short
    if watch_session.watch_duration < VIDEO_WATCH_TIME - 5:  # 5 second tolerance
        cheating_detected = True
        reasons.append("Insufficient watch time")
    
    # 8. Check if session was too fast (impossible timing)
    if watch_session.end_time and watch_session.start_time:
        actual_duration = (watch_session.end_time - watch_session.start_time).total_seconds()
        if actual_duration < VIDEO_WATCH_TIME - 10:  # 10 second tolerance
            cheating_detected = True
            reasons.append("Session completed too quickly")
    
    return cheating_detected, reasons

# Additional helper functions you'll need:

def start_watch_session(user_id, video_id, video_length, ip_address, user_agent):
    """Start a new watch session"""
    user = User.query.get(user_id)
    if not user or user.is_banned:
        return None, "User not found or banned"
    
    # Check daily limits
    if not check_daily_video_limit(user_id):
        return None, "Daily video limit reached"
    
    # Reset daily data if needed
    reset_daily_data_if_needed(user)
    
    # Create new watch session
    watch_session = WatchSession(
        user_id=user_id,
        video_id=video_id,
        video_length=video_length,
        ip_address=ip_address,
        user_agent=user_agent,
        start_time=datetime.utcnow()
    )
    
    try:
        db.session.add(watch_session)
        db.session.commit()
        logging.info(f"Started watch session for user {user_id}, video {video_id}")
        return watch_session, "Success"
    except Exception as e:
        logging.error(f"Failed to start watch session: {str(e)}")
        db.session.rollback()
        return None, "Database error"

def end_watch_session(session_id, watch_duration):
    """End a watch session and check for cheating"""
    watch_session = WatchSession.query.get(session_id)
    if not watch_session:
        return False, "Session not found"
    
    # Update session end time and duration
    watch_session.end_time = datetime.utcnow()
    watch_session.watch_duration = watch_duration
    
    # Check for cheating
    is_cheating, cheat_reasons = detect_cheating(watch_session)
    
    if is_cheating:
        watch_session.is_suspicious = True
        ban_user(watch_session.user_id, f"Cheating detected: {', '.join(cheat_reasons)}")
        
        try:
            db.session.commit()
        except Exception as e:
            logging.error(f"Failed to mark session as suspicious: {str(e)}")
            db.session.rollback()
        
        return False, f"Cheating detected: {', '.join(cheat_reasons)}"
    
    # Mark as completed and update user stats
    watch_session.is_completed = True
    user = User.query.get(watch_session.user_id)
    
    if user:
        user.videos_watched_today += 1
        user.total_watch_time += watch_duration
        user.daily_online_time += watch_duration
        
        # Check if daily online time exceeded
        if user.daily_online_time > MAX_DAILY_ONLINE_TIME:
            ban_user(user.id, "Exceeded maximum daily online time")
            try:
                db.session.commit()
            except Exception as e:
                logging.error(f"Failed to update user stats: {str(e)}")
                db.session.rollback()
            return False, "Daily time limit exceeded"
    
    try:
        db.session.commit()
        logging.info(f"Completed watch session {session_id} for user {watch_session.user_id}")
        return True, "Session completed successfully"
    except Exception as e:
        logging.error(f"Failed to complete watch session: {str(e)}")
        db.session.rollback()
        return False, "Database error"

def get_user_stats(user_id):
    """Get comprehensive user statistics"""
    user = User.query.get(user_id)
    if not user:
        return None
    
    today = datetime.utcnow().date()
    
    # Reset daily data if needed
    reset_daily_data_if_needed(user)
    
    stats = {
        'user_id': user.id,
        'username': user.username,
        'videos_watched_today': user.videos_watched_today,
        'daily_online_time': user.daily_online_time,
        'daily_bonus_given': user.daily_bonus_given,
        'consecutive_days': user.consecutive_days,
        'total_watch_time': user.total_watch_time,
        'is_banned': user.is_banned,
        'ban_reason': user.ban_reason,
        'videos_remaining_today': MAX_VIDEOS_PER_DAY - user.videos_watched_today,
        'can_watch_more': user.videos_watched_today < MAX_VIDEOS_PER_DAY and not user.is_banned
    }
    
    return stats

def cleanup_old_sessions():
    """Clean up old watch sessions (run this periodically)"""
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    
    try:
        old_sessions = WatchSession.query.filter(WatchSession.created_at < cutoff_date).delete()
        db.session.commit()
        logging.info(f"Cleaned up {old_sessions} old watch sessions")
    except Exception as e:
        logging.error(f"Failed to cleanup old sessions: {str(e)}")
        db.session.rollback()

def validate_session_token(user_id, token):
    """Validate user session token"""
    user = User.query.get(user_id)
    if not user or user.session_token != token:
        return False
    return True

def update_user_session(user_id, ip_address):
    """Update user session info"""
    user = User.query.get(user_id)
    if user:
        user.last_ip_address = ip_address
        user.updated_at = datetime.utcnow()
        
        # Generate new session token if doesn't exist
        if not user.session_token:
            user.session_token = create_session_token()
        
        try:
            db.session.commit()
        except Exception as e:
            logging.error(f"Failed to update user session: {str(e)}")
            db.session.rollback()
    
    return user

def reset_daily_stats():
    """Reset daily stats for all users (run this daily via cron)"""
    try:
        users = User.query.all()
        for user in users:
            user.daily_bonus_given = False
            user.videos_watched_today = 0
            user.daily_online_time = 0
        db.session.commit()
        logging.info("✅ Daily stats reset for all users")
    except Exception as e:
        logging.error(f"❌ Failed to reset daily stats: {str(e)}")
        db.session.rollback()

def track_focus_loss(session_id):
    """Track when user loses focus on video"""
    watch_session = WatchSession.query.get(session_id)
    if watch_session:
        watch_session.focus_lost_count += 1
        try:
            db.session.commit()
            logging.info(f"Focus loss tracked for session {session_id}, count: {watch_session.focus_lost_count}")
        except Exception as e:
            logging.error(f"Failed to track focus loss: {str(e)}")
            db.session.rollback()

def track_back_button_press(session_id):
    """Track when user presses back button during video"""
    watch_session = WatchSession.query.get(session_id)
    if watch_session:
        watch_session.back_button_pressed = True
        try:
            db.session.commit()
            logging.warning(f"Back button press detected for session {session_id}")
        except Exception as e:
            logging.error(f"Failed to track back button press: {str(e)}")
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
            # Get form data with proper handling
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')
            role = request.form.get('account_type', '')
            username = request.form.get('username', '').strip()
            
            # Auto-generate username from email if not provided
            if not username:
                username = email.split('@')[0] if email else None

            # Validation
            if not all([email, password, role]):
                return jsonify({'error': 'All fields are required'}), 400
            
            # Validate username
            if not username or not username.strip():
                return jsonify({'error': 'Username is required'}), 400

            if PASSWORD_CONFIRMATION_REQUIRED and password != confirm:
                return jsonify({'error': 'Passwords do not match'}), 400

            if len(password) < PASSWORD_MIN_LENGTH:
                return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters'}), 400

            if role not in ALLOWED_ROLES:
                return jsonify({'error': 'Invalid account type'}), 400

            # Check for existing email
            if User.query.filter_by(email=email).first():
                return jsonify({'error': 'Email already exists'}), 409
            
            # Check for existing username
            if User.query.filter_by(username=username).first():
                return jsonify({'error': 'Username already exists'}), 409

            # Create user with username
            hashed = generate_password_hash(password)
            user = User(
                username=username,  # Add username field
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
            # Get login credentials - support both email and username
            email_or_username = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email_or_username or not password:
                return jsonify({'error': 'Email/Username and password are required'}), 400
            
            # Try to find user by email first, then by username
            user = User.query.filter_by(email=email_or_username).first()
            if not user:
                user = User.query.filter_by(username=email_or_username).first()
            
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
                return jsonify({'error': 'Invalid email/username or password'}), 401
                
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
    """Main user dashboard route - serves React component or template"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        session.clear()
        return redirect(url_for('login'))
    
    # If this is an API request (Accept: application/json), return JSON
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'user': {
                'id': user.id,
                'email': user.email,
                'balance_usd': float(user.balance_usd or 0),
                'videos_watched_today': user.videos_watched_today or 0,
                'total_watch_minutes': user.total_watch_minutes or 0,
                'daily_bonus_given': user.daily_bonus_given,
                'daily_online_time': user.daily_online_time or 0,
                'account_type': user.account_type,
                'consecutive_days': user.consecutive_days or 0
            }
        })
    
    # For regular browser requests, serve the React component or template
    # If you're using React, you might render a template that loads the React app
    return render_template('user_dashboard_react.html', user=user)

# Alternative: If you want to serve the React component directly
@app.route('/dashboard')
def dashboard_react():
    """Serve React dashboard component"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        session.clear()
        return redirect(url_for('login'))
    
    # Serve a template that loads your React component
    return render_template('dashboard.html', user=user)

# Add these database model updates if you don't have them
def init_db_columns():
    """Add any missing columns to existing tables"""
    try:
        # Add columns if they don't exist
        with app.app_context():
            db.create_all()
            
            # You might need to add these columns to your User model:
            # daily_online_time = db.Column(db.Integer, default=0)
            # videos_watched_today = db.Column(db.Integer, default=0)
            # total_watch_minutes = db.Column(db.Integer, default=0)
            # daily_bonus_given = db.Column(db.Boolean, default=False)
            # consecutive_days = db.Column(db.Integer, default=0)
            
    except Exception as e:
        print(f"Database initialization error: {e}")

# Daily reset function (call this with a cron job or scheduler)
def reset_daily_stats():
    """Reset daily statistics for all users"""
    try:
        users = User.query.all()
        for user in users:
            user.daily_bonus_given = False
            user.daily_online_time = 0
            user.videos_watched_today = 0
        
        db.session.commit()
        print("Daily stats reset completed")
    except Exception as e:
        print(f"Error resetting daily stats: {e}")
        db.session.rollback()

# Additional Flask routes to match your React frontend API calls

@app.route('/api/user/profile')
def api_user_profile():
    """API endpoint to get user profile data"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        session.clear()
        return jsonify({'error': 'User not found or banned'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'balance_usd': float(user.balance_usd or 0),
        'videos_watched_today': user.videos_watched_today or 0,
        'total_watch_minutes': user.total_watch_minutes or 0,
        'daily_bonus_given': user.daily_bonus_given,
        'daily_online_time': user.daily_online_time or 0,
        'account_type': user.account_type,
        'consecutive_days': user.consecutive_days or 0,
        'is_banned': user.is_banned
    })

@app.route('/api/videos/available')
def api_videos_available():
    """API endpoint to get available videos"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        return jsonify({'error': 'User not found or banned'}), 404
    
    # Get available videos
    videos = Video.query.filter_by(is_active=True)\
        .order_by(Video.timestamp.desc()).all()
    
    videos_data = []
    for video in videos:
        videos_data.append({
            'id': video.id,
            'title': video.title,
            'reward_amount': float(video.reward_amount or VIDEO_REWARD_AMOUNT),
            'min_watch_time': video.min_watch_time or VIDEO_WATCH_TIME,
            'added_by': video.added_by,
            'timestamp': video.timestamp.isoformat() if video.timestamp else None
        })
    
    return jsonify({
        'videos': videos_data,
        'can_watch_more': check_daily_video_limit(user.id),
        'videos_remaining': max(0, MAX_VIDEOS_PER_DAY - (user.videos_watched_today or 0))
    })

@app.route('/api/heartbeat', methods=['POST'])
def api_heartbeat():
    """API endpoint for session heartbeat tracking"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        return jsonify({'error': 'User not found or banned'}), 404
    
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        heartbeat_type = data.get('type', 'daily')
        behavioral_data = data.get('behavioral_data', {})
        
        # Update user's daily online time
        if heartbeat_type == 'daily':
            current_time = user.daily_online_time or 0
            new_time = min(current_time + 5, DAILY_ONLINE_TIME)  # 5 seconds per heartbeat
            user.daily_online_time = new_time
            
            # Optional: Log behavioral data for fraud detection
            if behavioral_data:
                # You could store this in a separate table for analysis
                pass
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'online_time': new_time,
                'time_remaining': max(0, DAILY_ONLINE_TIME - new_time)
            })
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': 'Invalid request data'}), 400

@app.route('/api/claim_daily_bonus', methods=['POST'])
def api_claim_daily_bonus():
    """API endpoint to claim daily bonus"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        return jsonify({'error': 'User not found or banned'}), 404
    
    try:
        data = request.get_json()
        behavioral_data = data.get('behavioral_data', {})
        device_data = data.get('device_data', {})
        
        # Check if bonus already claimed today
        if user.daily_bonus_given:
            return jsonify({'error': 'Daily bonus already claimed'}), 400
        
        # Check if user has been online long enough
        if (user.daily_online_time or 0) < DAILY_ONLINE_TIME:
            return jsonify({
                'error': f'You need {DAILY_ONLINE_TIME - (user.daily_online_time or 0)} more seconds online'
            }), 400
        
        # Calculate bonus amount (could vary based on consecutive days)
        consecutive_days = (user.consecutive_days or 0) + 1
        bonus_amount = DAILY_REWARD
        
        # Optional: Increase bonus for consecutive days
        if consecutive_days >= 7:
            bonus_amount *= 1.5  # 50% bonus for week streak
        elif consecutive_days >= 3:
            bonus_amount *= 1.2  # 20% bonus for 3+ days
        
        # Update user balance and status
        user.balance_usd = (user.balance_usd or 0) + bonus_amount
        user.daily_bonus_given = True
        user.consecutive_days = consecutive_days
        user.daily_online_time = 0  # Reset for next day
        
        # Record the earning
        earning = Earning(
            user_id=user.id,
            amount=bonus_amount,
            source='daily_bonus',
            description=f'Daily bonus - Day {consecutive_days}'
        )
        db.session.add(earning)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'bonus_amount': bonus_amount,
            'new_balance': float(user.balance_usd),
            'consecutive_days': consecutive_days
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to claim bonus'}), 500

@app.route('/api/watch_video', methods=['POST'])
def api_watch_video():
    """API endpoint to start watching a video"""
    if 'user_id' not in session or session.get('account_type') != 'User':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        return jsonify({'error': 'User not found or banned'}), 404
    
    try:
        data = request.get_json()
        video_id = data.get('video_id')
        session_token = data.get('session_token')
        
        if not video_id:
            return jsonify({'error': 'Video ID required'}), 400
        
        # Check daily video limit
        if not check_daily_video_limit(user.id):
            return jsonify({'error': 'Daily video limit reached'}), 400
        
        # Get video details
        video = Video.query.get(video_id)
        if not video or not video.is_active:
            return jsonify({'error': 'Video not found or inactive'}), 404
        
        # Create watch session (you might want to create a WatchSession model)
        min_watch_time = video.min_watch_time or VIDEO_WATCH_TIME
        reward_amount = video.reward_amount or VIDEO_REWARD_AMOUNT
        
        # You could create a watch session record here
        # watch_session = WatchSession(
        #     user_id=user.id,
        #     video_id=video_id,
        #     session_token=session_token,
        #     min_watch_time=min_watch_time,
        #     reward_amount=reward_amount
        # )
        # db.session.add(watch_session)
        # db.session.commit()
        
        return jsonify({
            'success': True,
            'video_id': video_id,
            'min_watch_time': min_watch_time,
            'reward_amount': reward_amount,
            'watch_url': f'/watch/{video_id}',
            'session_token': session_token
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to start video session'}), 500

# Helper function for daily video limit check
def check_daily_video_limit(user_id):
    """Check if user can watch more videos today"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    videos_watched_today = user.videos_watched_today or 0
    return videos_watched_today < MAX_VIDEOS_PER_DAY

# Constants that should match your React frontend
MAX_VIDEOS_PER_DAY = int(os.environ.get('MAX_VIDEOS_PER_DAY', '50'))
DAILY_ONLINE_TIME = int(os.environ.get('DAILY_ONLINE_TIME', '3600'))  # 1 hour
DAILY_REWARD = float(os.environ.get('DAILY_REWARD', '0.50'))
SESSION_HEARTBEAT_INTERVAL = int(os.environ.get('SESSION_HEARTBEAT_INTERVAL', '5'))  # 5 seconds

@app.route('/admin_panel')
def admin_panel():
    """Admin panel for managing videos"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'Admin':
        flash('❌ Admin access required!', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Get all videos for management
    videos = Video.query.order_by(Video.timestamp.desc()).all()
    
    # Get all users for management
    users = User.query.all()
    
    # Get all withdrawal requests for management
    withdrawals = WithdrawalRequest.query.all()
    
    # Get IP tracking data if enabled
    ip_logs = []
    if ENABLE_IP_TRACKING:
        ip_logs = IPLog.query.order_by(IPLog.timestamp.desc()).limit(100).all()
    
    # Get system stats
    total_users = User.query.count()
    total_videos = Video.query.count()
    active_videos = Video.query.filter_by(is_active=True).count()
    total_earnings = db.session.query(db.func.sum(User.balance_usd)).scalar() or 0
    
    return render_template('admin_panel.html', 
                         videos=videos,
                         users=users,
                         withdrawals=withdrawals,
                         ip_logs=ip_logs,
                         ip_tracking_enabled=ENABLE_IP_TRACKING,
                         total_users=total_users,
                         total_videos=total_videos,
                         active_videos=active_videos,
                         total_earnings=total_earnings,
                         max_file_size=MAX_FILE_SIZE_MB,
                         allowed_extensions=ALLOWED_EXTENSIONS,
                         default_watch_time=VIDEO_WATCH_TIME,
                         default_reward=VIDEO_REWARD_AMOUNT)

# Admin Video Upload Route (REPLACE YOUR EXISTING add_video ROUTE)
@app.route('/admin_add_video', methods=['POST'])
@limiter.limit(os.environ.get('ADMIN_UPLOAD_RATE_LIMIT', '5 per minute'))
def admin_add_video():
    """Admin route to add video files"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'Admin':
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    
    try:
        # Get form data
        title = request.form.get('title', '').strip()
        min_watch_time = int(request.form.get('min_watch_time', VIDEO_WATCH_TIME))
        reward_amount = float(request.form.get('reward_amount', VIDEO_REWARD_AMOUNT))
        video_type = request.form.get('video_type', 'file')  # 'file' or 'youtube'
        
        # Validation with configurable limits
        title_max_length = int(os.environ.get('VIDEO_TITLE_MAX_LENGTH', '200'))
        min_watch_time_limit = int(os.environ.get('MIN_WATCH_TIME_LIMIT', '10'))
        max_watch_time_limit = int(os.environ.get('MAX_WATCH_TIME_LIMIT', '300'))
        min_reward_amount = float(os.environ.get('MIN_REWARD_AMOUNT', '0.001'))
        max_reward_amount = float(os.environ.get('MAX_REWARD_AMOUNT', '1.0'))
        
        if not title or len(title) > title_max_length:
            flash(f'Video title is required and must be less than {title_max_length} characters.', 'error')
            return redirect(url_for('admin_panel'))
        
        if min_watch_time < min_watch_time_limit or min_watch_time > max_watch_time_limit:
            flash(f'Watch time must be between {min_watch_time_limit} and {max_watch_time_limit} seconds.', 'error')
            return redirect(url_for('admin_panel'))
        
        if reward_amount < min_reward_amount or reward_amount > max_reward_amount:
            flash(f'Reward amount must be between ${min_reward_amount} and ${max_reward_amount}.', 'error')
            return redirect(url_for('admin_panel'))
        
        video_url = None
        video_filename = None
        
        if video_type == 'file':
            # Handle file upload
            if 'video_file' not in request.files:
                flash('No video file selected.', 'error')
                return redirect(url_for('admin_panel'))
            
            file = request.files['video_file']
            if file.filename == '':
                flash('No video file selected.', 'error')
                return redirect(url_for('admin_panel'))
            
            if not allowed_file(file.filename):
                flash(f'Invalid file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
                return redirect(url_for('admin_panel'))
            
            # Generate unique filename
            original_filename = secure_filename(file.filename)
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
            
            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Check file size
            file_size_mb = get_file_size_mb(file_path)
            if file_size_mb > MAX_FILE_SIZE_MB:
                os.remove(file_path)  # Delete the file
                flash(f'File size too large. Maximum {MAX_FILE_SIZE_MB}MB allowed.', 'error')
                return redirect(url_for('admin_panel'))
            
            video_filename = unique_filename
            video_url = f"/static/uploads/videos/{unique_filename}"
            
        else:  # YouTube URL
            video_url = request.form.get('video_url', '').strip()
            if not video_url:
                flash('Video URL is required.', 'error')
                return redirect(url_for('admin_panel'))
            
            # Validate YouTube URL with configurable domains
            allowed_domains = os.environ.get('ALLOWED_VIDEO_DOMAINS', 'youtube.com,youtu.be').split(',')
            is_valid_url = any(domain in video_url for domain in allowed_domains)
            
            if not is_valid_url:
                flash(f'Please provide a valid video URL from: {", ".join(allowed_domains)}', 'error')
                return redirect(url_for('admin_panel'))
            
            # Check for duplicate URLs
            existing_video = Video.query.filter_by(video_url=video_url).first()
            if existing_video:
                flash('This video URL has already been added.', 'warning')
                return redirect(url_for('admin_panel'))
        
        # Create new video
        new_video = Video(
            title=title,
            video_url=video_url,
            video_filename=video_filename,  # Store filename for file uploads
            video_type=video_type,  # Store type (file or youtube)
            added_by=user.id,
            min_watch_time=min_watch_time,
            reward_amount=reward_amount,
            is_active=True,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(new_video)
        db.session.commit()
        
        # Log the action
        log_user_ip(user.id, "admin_video_upload")
        
        flash(f'Video "{title}" has been added successfully!', 'success')
        return redirect(url_for('admin_panel'))
        
    except ValueError as e:
        flash('Invalid number format in watch time or reward amount.', 'error')
        return redirect(url_for('admin_panel'))
    except Exception as e:
        print(f"❌ Error adding video: {str(e)}")
        db.session.rollback()
        flash('An error occurred while adding the video. Please try again.', 'error')
        return redirect(url_for('admin_panel'))

# Admin Delete Video Route
@app.route('/admin_delete_video/<int:video_id>', methods=['POST'])
def admin_delete_video(video_id):
    """Admin route to delete videos"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'Admin':
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    
    try:
        video = Video.query.get_or_404(video_id)
        
        # Delete physical file if it exists
        if video.video_filename and video.video_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], video.video_filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f"Warning: Could not delete file {file_path}: {e}")
        
        # Delete video record
        db.session.delete(video)
        db.session.commit()
        
        flash('Video deleted successfully!', 'success')
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        print(f"❌ Error deleting video: {str(e)}")
        db.session.rollback()
        flash('Error deleting video.', 'error')
        return redirect(url_for('admin_panel'))

# Make helper functions available in templates
@app.context_processor
def utility_processor():
    return dict(
        get_youtube_embed_url=get_youtube_embed_url,
        get_file_size_mb=get_file_size_mb,
        max_file_size_mb=MAX_FILE_SIZE_MB,
        allowed_extensions=ALLOWED_EXTENSIONS,
        video_watch_time=VIDEO_WATCH_TIME,
        video_reward_amount=VIDEO_REWARD_AMOUNT,
        daily_video_limit=DAILY_VIDEO_LIMIT
    )

@app.route('/api/complete_video', methods=['POST'])
def complete_video():
    """Complete video watch with advanced fraud detection"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        watch_duration = data.get('watch_duration', 0)
        final_mouse_data = data.get('mouse_data', {})
        completion_data = data.get('completion_data', {})
        
        user_id = session['user_id']
        user_ip = request.remote_addr
        
        watch_session = WatchSession.query.filter_by(session_token=session_token).first()
        
        if not watch_session or watch_session.user_id != user_id:
            return jsonify({'error': 'Invalid session'}), 400
        
        if watch_session.reward_given:
            return jsonify({'error': 'Reward already claimed'}), 400
        
        # Complete the session
        watch_session.end_time = datetime.utcnow()
        watch_session.watch_duration = watch_duration
        watch_session.is_completed = True
        
        # Enhanced fraud detection
        fraud_detected, fraud_reasons = comprehensive_fraud_detection(
            watch_session, final_mouse_data, completion_data, user_ip
        )
        
        # ML-based fraud probability
        ml_fraud_prob = calculate_ml_fraud_probability(watch_session, user_id)
        
        # Final risk assessment
        final_risk = calculate_final_risk_score(watch_session, ml_fraud_prob, fraud_reasons)
        
        user = User.query.get(user_id)
        
        if fraud_detected or final_risk['risk_level'] in ['high', 'critical']:
            watch_session.cheating_detected = True
            watch_session.cheat_reason = '; '.join(fraud_reasons)
            watch_session.is_suspicious = True
            
            # Update user fraud tracking
            user.cheat_violations += 1
            user.suspicious_activity_count += 1
            user.ml_fraud_probability = ml_fraud_prob
            user.risk_level = final_risk['risk_level']
            user.last_risk_assessment = datetime.utcnow()
            
            # Log comprehensive security event
            log_security_event(user_id, 'video_fraud_detected', 'critical', 
                             f'Video completion fraud: {"; ".join(fraud_reasons)}',
                             additional_data={
                                 'session_token': session_token,
                                 'ml_fraud_prob': ml_fraud_prob,
                                 'final_risk': final_risk,
                                 'watch_duration': watch_duration
                             })
            
            # Progressive banning system
            ban_result = check_progressive_ban(user)
            if ban_result['should_ban']:
                ban_user(user.id, ban_result['reason'])
                db.session.commit()
                session.clear()
                return jsonify({
                    'error': 'Account banned for repeated fraud attempts', 
                    'banned': True,
                    'reason': ban_result['reason']
                }), 403
            
            db.session.commit()
            return jsonify({
                'error': 'Fraud detected: ' + '; '.join(fraud_reasons),
                'violations': user.cheat_violations,
                'risk_level': user.risk_level,
                'ml_fraud_probability': ml_fraud_prob
            }), 400
        
        # Legitimate completion - give reward
        video = Video.query.get(watch_session.video_id)
        
        # Apply dynamic reward based on risk (lower risk = higher reward)
        base_reward = video.reward_amount
        risk_multiplier = get_risk_reward_multiplier(final_risk['risk_level'])
        final_reward = base_reward * risk_multiplier
        
        user.balance_usd += final_reward
        user.videos_watched_today += 1
        user.total_watch_minutes += int(watch_duration // 60)
        user.total_watch_time += int(watch_duration)
        
        # Update positive behavioral scores
        update_positive_behavioral_scores(user, watch_session)
        
        watch_session.reward_given = True
        
        # Log earning with enhanced data
        earning = Earning(
            user_id=user.id,
            amount=final_reward,
            source='watch',
            video_id=video.id
        )
        db.session.add(earning)
        
        # Store final risk score
        store_risk_score(user_id, watch_session.id, final_risk, ml_fraud_prob)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'reward': final_reward,
            'base_reward': base_reward,
            'risk_multiplier': risk_multiplier,
            'new_balance': user.balance_usd,
            'videos_remaining': MAX_VIDEOS_PER_DAY - user.videos_watched_today,
            'risk_level': final_risk['risk_level'],
            'behavioral_score': user.behavioral_score
        })
        
    except Exception as e:
        print(f"❌ Complete video error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to complete video'}), 500

@app.route('/api/balance', methods=['GET'])
def get_balance():
    """Get user balance with enhanced security and fraud detection"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        user_id = session['user_id']
        user_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Validate user exists and is not banned
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if user.is_banned:
            return jsonify({'error': 'Account is banned'}), 403
        
        # Check for excessive balance requests (rate limiting)
        try:
            balance_request_count = getattr(user, 'balance_request_count', 0)
            last_balance_request = getattr(user, 'last_balance_request', None)
            
            current_time = datetime.utcnow()
            
            # Reset counter if more than 1 minute has passed
            if last_balance_request and (current_time - last_balance_request).total_seconds() > 60:
                balance_request_count = 0
            
            # Check if too many requests in short time
            if balance_request_count > 30:  # Max 30 requests per minute
                log_security_event(user_id, 'excessive_balance_requests', 'medium',
                                 f'Excessive balance requests: {balance_request_count} in last minute')
                return jsonify({'error': 'Too many balance requests. Please wait.'}), 429
            
            # Update request tracking
            user.balance_request_count = balance_request_count + 1
            user.last_balance_request = current_time
            
        except Exception as e:
            print(f"⚠️ Balance request tracking failed: {str(e)}")
            # Continue without rate limiting if tracking fails
        
        # Check for proxy/VPN
        try:
            is_proxy = detect_proxy_vpn(user_ip)
            if is_proxy:
                log_security_event(user_id, 'proxy_balance_request', 'low',
                                 f'Balance requested from proxy/VPN: {user_ip}')
        except Exception as e:
            print(f"⚠️ Proxy detection failed: {str(e)}")
            is_proxy = False
        
        # Get current balance with validation
        try:
            current_balance = float(user.balance_usd or 0)
            
            # Validate balance integrity
            if current_balance < 0:
                log_security_event(user_id, 'negative_balance_detected', 'high',
                                 f'Negative balance detected: ${current_balance}')
                # Reset to 0 if somehow negative
                current_balance = 0
                user.balance_usd = 0
                
        except (ValueError, TypeError) as e:
            print(f"⚠️ Balance validation error: {str(e)}")
            current_balance = 0
            user.balance_usd = 0
        
        # Calculate earnings statistics
        try:
            total_earnings = db.session.query(func.sum(Earning.amount)).filter_by(user_id=user_id).scalar() or 0
            today_earnings = db.session.query(func.sum(Earning.amount)).filter(
                Earning.user_id == user_id,
                func.date(Earning.created_at) == datetime.utcnow().date()
            ).scalar() or 0
            
            # Get earnings by source
            earnings_by_source = db.session.query(
                Earning.source,
                func.sum(Earning.amount).label('total')
            ).filter_by(user_id=user_id).group_by(Earning.source).all()
            
            earnings_breakdown = {source: float(total) for source, total in earnings_by_source}
            
        except Exception as e:
            print(f"⚠️ Earnings calculation failed: {str(e)}")
            total_earnings = 0
            today_earnings = 0
            earnings_breakdown = {}
        
        # Get user stats
        try:
            user_stats = {
                'total_videos_watched': user.total_videos_watched or 0,
                'consecutive_days': user.consecutive_days or 0,
                'last_bonus_date': user.last_bonus_date.isoformat() if user.last_bonus_date else None,
                'daily_bonus_given': user.daily_bonus_given or False,
                'daily_online_time': user.daily_online_time or 0,
                'risk_level': user.risk_level or 'low',
                'account_status': 'active' if not user.is_banned else 'banned',
                'behavioral_score': getattr(user, 'behavioral_score', 100),
                'trust_multiplier': calculate_trust_multiplier(user) if hasattr(user, 'calculate_trust_multiplier') else 1.0
            }
        except Exception as e:
            print(f"⚠️ User stats calculation failed: {str(e)}")
            user_stats = {
                'total_videos_watched': 0,
                'consecutive_days': 0,
                'last_bonus_date': None,
                'daily_bonus_given': False,
                'daily_online_time': 0,
                'risk_level': 'low',
                'account_status': 'active',
                'behavioral_score': 100,
                'trust_multiplier': 1.0
            }
        
        # Check for pending payouts
        try:
            pending_payouts = db.session.query(func.sum(Payout.amount)).filter(
                Payout.user_id == user_id,
                Payout.status == 'pending'
            ).scalar() or 0
            
            completed_payouts = db.session.query(func.sum(Payout.amount)).filter(
                Payout.user_id == user_id,
                Payout.status == 'completed'
            ).scalar() or 0
            
        except Exception as e:
            print(f"⚠️ Payout calculation failed: {str(e)}")
            pending_payouts = 0
            completed_payouts = 0
        
        # Update user's last activity
        try:
            user.last_activity = datetime.utcnow()
            user.last_ip_address = user_ip
            db.session.commit()
        except Exception as e:
            print(f"⚠️ User activity update failed: {str(e)}")
            db.session.rollback()
        
        # Prepare response
        response_data = {
            'success': True,
            'balance': {
                'current': round(current_balance, 2),
                'currency': 'USD',
                'formatted': f'${current_balance:.2f}'
            },
            'earnings': {
                'total': round(float(total_earnings), 2),
                'today': round(float(today_earnings), 2),
                'breakdown': earnings_breakdown
            },
            'payouts': {
                'pending': round(float(pending_payouts), 2),
                'completed': round(float(completed_payouts), 2),
                'available_for_withdrawal': round(max(0, current_balance - pending_payouts), 2)
            },
            'user_stats': user_stats,
            'security': {
                'risk_level': user.risk_level or 'low',
                'account_verified': not user.is_banned,
                'proxy_detected': is_proxy,
                'last_updated': datetime.utcnow().isoformat()
            }
        }
        
        # Log successful balance request
        log_security_event(user_id, 'balance_requested', 'info',
                         f'Balance requested: ${current_balance:.2f}',
                         additional_data={
                             'ip_address': user_ip,
                             'user_agent': user_agent,
                             'proxy_detected': is_proxy
                         })
        
        print(f"✅ Balance requested: User {user_id}, Balance: ${current_balance:.2f}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"❌ Balance API error: {str(e)}")
        db.session.rollback()
        
        # Log the error
        try:
            log_security_event(session.get('user_id'), 'balance_api_error', 'high',
                             f'Balance API error: {str(e)}')
        except:
            pass
        
        return jsonify({
            'error': 'Failed to retrieve balance',
            'success': False,
            'message': 'An error occurred while fetching your balance. Please try again.'
        }), 500

@app.route('/api/balance/history', methods=['GET'])
def get_balance_history():
    """Get user balance history with pagination and filtering"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        user_id = session['user_id']
        
        # Validate user exists and is not banned
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if user.is_banned:
            return jsonify({'error': 'Account is banned'}), 403
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
        source_filter = request.args.get('source', None)
        start_date = request.args.get('start_date', None)
        end_date = request.args.get('end_date', None)
        
        # Build query
        query = Earning.query.filter_by(user_id=user_id)
        
        # Apply filters
        if source_filter:
            query = query.filter(Earning.source == source_filter)
        
        if start_date:
            try:
                start_date_obj = datetime.fromisoformat(start_date)
                query = query.filter(Earning.created_at >= start_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format'}), 400
        
        if end_date:
            try:
                end_date_obj = datetime.fromisoformat(end_date)
                query = query.filter(Earning.created_at <= end_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format'}), 400
        
        # Order by most recent first
        query = query.order_by(Earning.created_at.desc())
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Format earnings data
        earnings_data = []
        for earning in pagination.items:
            earnings_data.append({
                'id': earning.id,
                'amount': round(float(earning.amount), 2),
                'source': earning.source,
                'created_at': earning.created_at.isoformat(),
                'description': getattr(earning, 'description', None)
            })
        
        # Calculate summary statistics
        total_filtered = query.count()
        total_amount = db.session.query(func.sum(Earning.amount)).filter_by(user_id=user_id).scalar() or 0
        
        response_data = {
            'success': True,
            'earnings': earnings_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_filtered,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            },
            'summary': {
                'total_amount': round(float(total_amount), 2),
                'filtered_count': total_filtered,
                'sources': list(set(e.source for e in pagination.items))
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"❌ Balance history API error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve balance history',
            'success': False
        }), 500

# Helper function for trust multiplier calculation
def calculate_trust_multiplier(user):
    """Calculate trust multiplier based on user behavior"""
    try:
        base_multiplier = 1.0
        
        # Positive factors
        if user.consecutive_days > 7:
            base_multiplier += 0.1
        if user.consecutive_days > 30:
            base_multiplier += 0.2
        if getattr(user, 'behavioral_score', 100) > 90:
            base_multiplier += 0.1
        
        # Negative factors
        if user.risk_level == 'high':
            base_multiplier -= 0.3
        elif user.risk_level == 'medium':
            base_multiplier -= 0.1
        
        if getattr(user, 'cheat_violations', 0) > 0:
            base_multiplier -= 0.2
        
        # Ensure multiplier is between 0.1 and 2.0
        return max(0.1, min(2.0, base_multiplier))
        
    except Exception as e:
        print(f"⚠️ Trust multiplier calculation failed: {str(e)}")
        return 1.0
 
@app.route('/youtuber_dashboard')
def youtuber_dashboard():
    """YouTuber dashboard route"""
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        flash('Access denied. YouTuber account required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if user is banned
    if is_user_banned(user.id):
        flash(f'Your account has been banned. Reason: {user.ban_reason}', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get user's videos
        user_videos = Video.query.filter_by(added_by=user.id).order_by(Video.timestamp.desc()).all()
        
        # Calculate total watches across all user's videos
        total_watches = db.session.query(WatchSession).join(Video).filter(
            Video.added_by == user.id,
            WatchSession.reward_given == True
        ).count()
        
        # Calculate total revenue from user's videos
        total_revenue = db.session.query(db.func.sum(Earning.amount)).join(Video).filter(
            Video.added_by == user.id,
            Earning.source == 'watch'
        ).scalar() or 0.0
        
        # Count active videos
        active_videos = Video.query.filter_by(added_by=user.id, is_active=True).count()
        
        # Get recent watch sessions for user's videos
        recent_watches = db.session.query(WatchSession).join(Video).filter(
            Video.added_by == user.id,
            WatchSession.reward_given == True
        ).order_by(WatchSession.start_time.desc()).limit(5).all()
        
        return render_template('youtuber_dashboard.html',
                             user=user,
                             user_videos=user_videos,
                             total_watches=total_watches,
                             total_revenue=total_revenue,
                             active_videos=active_videos,
                             recent_watches=recent_watches,
                             VIDEO_WATCH_TIME=VIDEO_WATCH_TIME,
                             VIDEO_REWARD_AMOUNT=VIDEO_REWARD_AMOUNT)
                             
    except Exception as e:
        print(f"❌ Error in youtuber_dashboard: {str(e)}")
        flash('An error occurred while loading your dashboard.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_video', methods=['POST'])
@limiter.limit("10 per minute")
def add_video():
    """Add new video route"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        return jsonify({'success': False, 'message': 'YouTuber account required'}), 403
    
    if is_user_banned(user.id):
        return jsonify({'success': False, 'message': 'Your account is banned'}), 403
    
    try:
        # Get form data
        title = request.form.get('title', '').strip()
        video_url = request.form.get('video_url', '').strip()
        min_watch_time = int(request.form.get('min_watch_time', VIDEO_WATCH_TIME))
        reward_amount = float(request.form.get('reward_amount', VIDEO_REWARD_AMOUNT))
        
        # Validation
        if not title or len(title) > 200:
            flash('Video title is required and must be less than 200 characters.', 'error')
            return redirect(url_for('youtuber_dashboard'))
        
        if not video_url:
            flash('Video URL is required.', 'error')
            return redirect(url_for('youtuber_dashboard'))
        
        # Validate YouTube URL
        if 'youtube.com/watch' not in video_url and 'youtu.be/' not in video_url:
            flash('Please provide a valid YouTube video URL.', 'error')
            return redirect(url_for('youtuber_dashboard'))
        
        # Validate watch time and reward
        if min_watch_time < 10 or min_watch_time > 300:
            flash('Watch time must be between 10 and 300 seconds.', 'error')
            return redirect(url_for('youtuber_dashboard'))
        
        if reward_amount < 0.001 or reward_amount > 1.0:
            flash('Reward amount must be between $0.001 and $1.000.', 'error')
            return redirect(url_for('youtuber_dashboard'))
        
        # Check for duplicate URLs
        existing_video = Video.query.filter_by(video_url=video_url).first()
        if existing_video:
            flash('This video URL has already been added.', 'warning')
            return redirect(url_for('youtuber_dashboard'))
        
        # Create new video
        new_video = Video(
            title=title,
            video_url=video_url,
            added_by=user.id,
            min_watch_time=min_watch_time,
            reward_amount=reward_amount,
            is_active=True,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(new_video)
        db.session.commit()
        
        # Log the action
        log_user_ip(user.id, "video_upload")
        
        flash(f'Video "{title}" has been added successfully!', 'success')
        return redirect(url_for('youtuber_dashboard'))
        
    except ValueError as e:
        flash('Invalid number format in watch time or reward amount.', 'error')
        return redirect(url_for('youtuber_dashboard'))
    except Exception as e:
        print(f"❌ Error adding video: {str(e)}")
        db.session.rollback()
        flash('An error occurred while adding the video. Please try again.', 'error')
        return redirect(url_for('youtuber_dashboard'))

@app.route('/toggle_video_status', methods=['POST'])
@limiter.limit("20 per minute")
def toggle_video_status():
    """Toggle video active/inactive status"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        return jsonify({'success': False, 'message': 'YouTuber account required'}), 403
    
    if is_user_banned(user.id):
        return jsonify({'success': False, 'message': 'Your account is banned'}), 403
    
    try:
        data = request.get_json()
        video_id = data.get('video_id')
        
        if not video_id:
            return jsonify({'success': False, 'message': 'Video ID is required'}), 400
        
        # Get the video and verify ownership
        video = Video.query.filter_by(id=video_id, added_by=user.id).first()
        if not video:
            return jsonify({'success': False, 'message': 'Video not found or access denied'}), 404
        
        # Toggle status
        video.is_active = not video.is_active
        db.session.commit()
        
        status = 'activated' if video.is_active else 'deactivated'
        return jsonify({
            'success': True, 
            'message': f'Video "{video.title}" has been {status}',
            'new_status': video.is_active
        })
        
    except Exception as e:
        print(f"❌ Error toggling video status: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/delete_video', methods=['POST'])
@limiter.limit("10 per minute")
def delete_video():
    """Delete video route"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        return jsonify({'success': False, 'message': 'YouTuber account required'}), 403
    
    if is_user_banned(user.id):
        return jsonify({'success': False, 'message': 'Your account is banned'}), 403
    
    try:
        data = request.get_json()
        video_id = data.get('video_id')
        
        if not video_id:
            return jsonify({'success': False, 'message': 'Video ID is required'}), 400
        
        # Get the video and verify ownership
        video = Video.query.filter_by(id=video_id, added_by=user.id).first()
        if not video:
            return jsonify({'success': False, 'message': 'Video not found or access denied'}), 404
        
        video_title = video.title
        
        # Delete related records first (to maintain referential integrity)
        # Delete watch sessions
        WatchSession.query.filter_by(video_id=video.id).delete()
        
        # Delete earnings
        Earning.query.filter_by(video_id=video.id).delete()
        
        # Delete the video
        db.session.delete(video)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Video "{video_title}" has been deleted successfully'
        })
        
    except Exception as e:
        print(f"❌ Error deleting video: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while deleting the video'}), 500

@app.route('/video_analytics/<int:video_id>')
def video_analytics(video_id):
    """Get analytics for a specific video"""
    if 'user_id' not in session:
        return jsonify({'error': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        return jsonify({'error': 'YouTuber account required'}), 403
    
    try:
        # Verify video ownership
        video = Video.query.filter_by(id=video_id, added_by=user.id).first()
        if not video:
            return jsonify({'error': 'Video not found or access denied'}), 404
        
        # Get analytics data
        total_views = WatchSession.query.filter_by(video_id=video.id, reward_given=True).count()
        total_earnings = db.session.query(db.func.sum(Earning.amount)).filter_by(video_id=video.id).scalar() or 0.0
        
        # Get daily views for the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily_views = db.session.query(
            db.func.date(WatchSession.start_time).label('date'),
            db.func.count(WatchSession.id).label('views')
        ).filter(
            WatchSession.video_id == video.id,
            WatchSession.reward_given == True,
            WatchSession.start_time >= thirty_days_ago
        ).group_by(db.func.date(WatchSession.start_time)).all()
        
        # Average watch time
        avg_watch_time = db.session.query(db.func.avg(WatchSession.watch_duration)).filter_by(
            video_id=video.id, reward_given=True
        ).scalar() or 0
        
        return jsonify({
            'video_title': video.title,
            'total_views': total_views,
            'total_earnings': round(total_earnings, 3),
            'avg_watch_time': round(avg_watch_time, 1),
            'daily_views': [{'date': str(row.date), 'views': row.views} for row in daily_views],
            'is_active': video.is_active,
            'reward_amount': video.reward_amount,
            'min_watch_time': video.min_watch_time
        })
        
    except Exception as e:
        print(f"❌ Error getting video analytics: {str(e)}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/youtuber_settings')
def youtuber_settings():
    """YouTuber account settings"""
    if 'user_id' not in session:
        flash('Please log in to access settings.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        flash('Access denied. YouTuber account required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get user's video statistics
        total_videos = Video.query.filter_by(added_by=user.id).count()
        active_videos = Video.query.filter_by(added_by=user.id, is_active=True).count()
        
        # Get recent IP logs
        recent_ips = IPLog.query.filter_by(user_id=user.id).order_by(IPLog.timestamp.desc()).limit(10).all()
        
        return render_template('youtuber_settings.html',
                             user=user,
                             total_videos=total_videos,
                             active_videos=active_videos,
                             recent_ips=recent_ips)
                             
    except Exception as e:
        print(f"❌ Error in youtuber_settings: {str(e)}")
        flash('An error occurred while loading settings.', 'error')
        return redirect(url_for('youtuber_dashboard'))

@app.route('/bulk_video_action', methods=['POST'])
@limiter.limit("5 per minute")
def bulk_video_action():
    """Bulk actions on videos (activate/deactivate multiple videos)"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.account_type != 'YouTuber':
        return jsonify({'success': False, 'message': 'YouTuber account required'}), 403
    
    if is_user_banned(user.id):
        return jsonify({'success': False, 'message': 'Your account is banned'}), 403
    
    try:
        data = request.get_json()
        video_ids = data.get('video_ids', [])
        action = data.get('action')  # 'activate', 'deactivate', 'delete'
        
        if not video_ids or not action:
            return jsonify({'success': False, 'message': 'Video IDs and action are required'}), 400
        
        # Verify all videos belong to the user
        videos = Video.query.filter(Video.id.in_(video_ids), Video.added_by == user.id).all()
        
        if len(videos) != len(video_ids):
            return jsonify({'success': False, 'message': 'Some videos not found or access denied'}), 404
        
        updated_count = 0
        
        if action == 'activate':
            for video in videos:
                video.is_active = True
                updated_count += 1
        elif action == 'deactivate':
            for video in videos:
                video.is_active = False
                updated_count += 1
        elif action == 'delete':
            for video in videos:
                # Delete related records first
                WatchSession.query.filter_by(video_id=video.id).delete()
                Earning.query.filter_by(video_id=video.id).delete()
                db.session.delete(video)
                updated_count += 1
        else:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{updated_count} videos {action}d successfully'
        })
        
    except Exception as e:
        print(f"❌ Error in bulk video action: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

# Helper route for video URL validation
@app.route('/validate_video_url', methods=['POST'])
def validate_video_url():
    """Validate YouTube video URL"""
    if 'user_id' not in session:
        return jsonify({'valid': False, 'message': 'Please log in first'}), 401
    
    try:
        data = request.get_json()
        video_url = data.get('video_url', '').strip()
        
        if not video_url:
            return jsonify({'valid': False, 'message': 'URL is required'})
        
        # Basic YouTube URL validation
        if 'youtube.com/watch' not in video_url and 'youtu.be/' not in video_url:
            return jsonify({'valid': False, 'message': 'Please provide a valid YouTube video URL'})
        
        # Check if URL already exists
        existing_video = Video.query.filter_by(video_url=video_url).first()
        if existing_video:
            return jsonify({'valid': False, 'message': 'This video URL has already been added'})
        
        return jsonify({'valid': True, 'message': 'Valid YouTube URL'})
        
    except Exception as e:
        print(f"❌ Error validating video URL: {str(e)}")
        return jsonify({'valid': False, 'message': 'An error occurred'}), 500

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
