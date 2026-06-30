from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime

app = Flask(__name__)
# Security key for session management
app.config['SECRET_KEY'] = 'siter_cyberguard_super_secret_2026'
# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberguard.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- EDUCATIONAL CONTEXT ENGINE ---
VULNERABILITY_CONTEXT = {
    'Strict-Transport-Security': {
        'missing': 'The server does not force browsers to use secure (HTTPS) connections.',
        'why_required': 'It prevents attackers from downgrading the connection to insecure HTTP.',
        'impact': 'Man-in-the-Middle (MitM) attacks where hackers can intercept passwords and data.'
    },
    'Content-Security-Policy': {
        'missing': 'The server does not restrict where scripts and resources can be loaded from.',
        'why_required': 'It acts as a whitelist for approved content sources.',
        'impact': 'Cross-Site Scripting (XSS) attacks, allowing hackers to run malicious code on your site.'
    },
    'X-Frame-Options': {
        'missing': 'The server allows this website to be embedded in an iframe on other websites.',
        'why_required': 'It ensures your UI cannot be hijacked or overlaid by malicious actors.',
        'impact': 'Clickjacking attacks, tricking users into clicking invisible buttons to steal data.'
    },
    'X-Content-Type-Options': {
        'missing': 'The server allows browsers to "guess" the type of a file (MIME-sniffing).',
        'why_required': 'It forces the browser to strictly follow the declared content type.',
        'impact': 'Hackers can disguise malicious executable scripts as harmless image or text files.'
    }
}

# --- SCANNER LOGIC ---
def scan_url(url):
    if not url.startswith('http'):
        url = 'http://' + url

    results = {
        'url': url,
        'status': 'Unknown',
        'threats': [],
        'score': 100
    }

    try:
        response = requests.get(url, timeout=5)
        results['status'] = f"Online (Status Code: {response.status_code})"

        for header, context in VULNERABILITY_CONTEXT.items():
            if header not in response.headers:
                results['score'] -= 25
                results['threats'].append({
                    'header': header,
                    'missing': context['missing'],
                    'why': context['why_required'],
                    'impact': context['impact']
                })
    except Exception:
        results['status'] = "Offline or Unreachable!"
        results['score'] = 0

    return results

# --- ROUTES ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
            
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check username and password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    scan_results = None
    if request.method == 'POST':
        target_url = request.form.get('url')
        if target_url:
            scan_results = scan_url(target_url)
            new_scan = ScanHistory(user_id=current_user.id, url=target_url, score=scan_results['score'])
            db.session.add(new_scan)
            db.session.commit()
            
    user_history = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.date.desc()).all()
    return render_template('index.html', results=scan_results, history=user_history)

@app.route('/policy')
def policy():
    return render_template('policy.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)