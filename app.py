import os
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import secrets

# Flask App
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///watch_and_earn.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Constants
MAX_VIDEOS_PER_DAY = 10
DAILY_ONLINE_TIME = 1800
DAILY_REWARD = 0.001

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    balance = db.Column(db.Float, default=0.0)
    account_type = db.Column(db.String(20), default='User')
    total_watch_minutes = db.Column(db.Integer, default=0)
    videos_watched_today = db.Column(db.Integer, default=0)
    daily_online_time = db.Column(db.Integer, default=0)
    daily_bonus_given = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    suspicious_activity_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='low')
    last_bonus_claim = db.Column(db.DateTime)

class Earning(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(50))
    video_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    reward_amount = db.Column(db.Float)
    min_watch_time = db.Column(db.Integer)
    added_by = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Helpers
def generate_fingerprint_hash(fingerprint: str) -> str:
    return hashlib.sha256(fingerprint.encode()).hexdigest()

def detect_proxy_vpn(ip_address: str) -> bool:
    return False

def check_daily_video_limit(user_id: int) -> bool:
    user = User.query.get(user_id)
    return user.videos_watched_today < MAX_VIDEOS_PER_DAY

# Routes
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Not logged in'}), 401

        data = request.get_json() or {}
        fingerprint = data.get('fingerprint', '')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')

        fingerprint_hash = generate_fingerprint_hash(fingerprint)
        is_proxy = detect_proxy_vpn(ip)

        return jsonify({
            'fingerprint_hash': fingerprint_hash,
            'is_proxy': is_proxy
        }), 200

    except Exception as e:
        print(f"❌ Heartbeat error: {e}")
        return jsonify({'error': 'Heartbeat failed'}), 500

@app.route('/api/balance', methods=['GET'])
def api_balance():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(session['user_id'])
    return jsonify({
        'balance': user.balance,
        'risk_level': user.risk_level,
        'suspicious_activity_count': user.suspicious_activity_count
    })

@app.route('/api/claim_daily_bonus', methods=['POST'])
def claim_daily_bonus():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(session['user_id'])

    if user.daily_bonus_given:
        return jsonify({'error': 'Bonus already claimed today'}), 403

    if user.daily_online_time < DAILY_ONLINE_TIME:
        return jsonify({
            'error': 'Need to stay online longer',
            'required': DAILY_ONLINE_TIME,
            'current': user.daily_online_time
        }), 400

    user.balance += DAILY_REWARD
    user.daily_bonus_given = True
    user.last_bonus_claim = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'bonus': DAILY_REWARD, 'new_balance': user.balance})

@app.route('/api/history', methods=['GET'])
def api_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    earnings = Earning.query.filter_by(user_id=session['user_id'])        .order_by(Earning.timestamp.desc()).limit(20).all()
    return jsonify({'history': [{
        'amount': e.amount,
        'source': e.source,
        'timestamp': e.timestamp.isoformat()
    } for e in earnings]})

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.is_banned:
        session.clear()
        return redirect(url_for('login'))

    recent_earnings = Earning.query.filter_by(user_id=user.id).order_by(Earning.timestamp.desc()).limit(10).all()
    videos = Video.query.filter_by(is_active=True).order_by(Video.timestamp.desc()).all()
    can_watch_more = check_daily_video_limit(user.id)
    time_until_daily_bonus = max(0, DAILY_ONLINE_TIME - (user.daily_online_time or 0))
    videos_remaining = max(0, MAX_VIDEOS_PER_DAY - (user.videos_watched_today or 0))

    return render_template('user_dashboard.html',
                           user=user,
                           earnings=recent_earnings,
                           videos=videos,
                           can_watch_more=can_watch_more,
                           videos_remaining=videos_remaining,
                           time_until_daily_bonus=time_until_daily_bonus,
                           MAX_VIDEOS_PER_DAY=MAX_VIDEOS_PER_DAY,
                           DAILY_ONLINE_TIME=DAILY_ONLINE_TIME)

@app.route('/')
def index():
    return redirect(url_for('user_dashboard'))

@app.route('/login')
def login():
    return "<h3>Login Page Placeholder</h3>"

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
