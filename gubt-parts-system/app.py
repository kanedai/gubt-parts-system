import os
import requests
import shutil
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import json
import html

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# 使用绝对路径来存储数据库
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Get admin credentials from environment variables
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'securepassword')

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Login verification decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin verification decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('inventory'))
        return f(*args, **kwargs)
    return decorated_function

# Clear database and create new admin user
def reset_database():
    # Delete database file
    db_path = os.path.join(basedir, 'database', 'users.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    
    # Recreate database
    with app.app_context():
        db.create_all()
        # Create admin user
        admin = User(username=ADMIN_USER, is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()

# Ensure database directory exists
database_dir = os.path.join(basedir, 'database')
if not os.path.exists(database_dir):
    os.makedirs(database_dir)

# Create database and tables
with app.app_context():
    # Check if database reset is needed
    reset_db = os.getenv('RESET_DB', 'false').lower() == 'true'
    if reset_db:
        reset_database()
    else:
        db.create_all()  # This will create tables if they don't exist, but won't delete existing data
        # Ensure admin user exists
        admin = User.query.filter_by(username=ADMIN_USER).first()
        if not admin:
            admin = User(username=ADMIN_USER, is_admin=True)
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()

# Add context processor to provide current year and user info
@app.context_processor
def inject_context():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return {'now': datetime.now(), 'current_user': user}

@app.route('/logout')
def logout():
    session.clear()
    flash('You have successfully logged out', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to inventory page
    if 'user_id' in session:
        return redirect(url_for('inventory'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if it's the admin user from environment variables
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            # Check if admin user exists, create if not
            admin = User.query.filter_by(username=ADMIN_USER).first()
            if not admin:
                admin = User(username=ADMIN_USER, is_admin=True)
                admin.set_password(ADMIN_PASSWORD)
                db.session.add(admin)
                db.session.commit()
            else:
                # Update admin password to match environment variable
                admin.set_password(ADMIN_PASSWORD)
                db.session.commit()
                
            admin.last_login = datetime.now()
            db.session.commit()
            
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['is_admin'] = True
            
            return redirect(url_for('admin_dashboard'))
        
        # Regular user login
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            user.last_login = datetime.now()
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            # If admin, redirect to admin dashboard
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('inventory'))
        else:
            flash('Invalid username or password, please try again', 'error')
    
    return render_template('login.html')

@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    results = []
    error_message = None
    search_performed = False
    no_results = False
    
    if request.method == 'POST':
        search_performed = True
        item_name = request.form.get('item_name', '')
        models = request.form.get('models', '')
        reference_code = request.form.get('reference_code', '')
        
        # Build query parameters
        params = {}
        if item_name:
            params['item_name'] = item_name
        if models:
            params['models'] = models
        if reference_code:
            params['reference_code'] = reference_code
        
        # If no query parameters provided, show prompt
        if not params:
            flash('Please enter at least one search criterion', 'warning')
            return render_template('inventory.html', results=results, search_performed=False)
        
        try:
            # 从环境变量获取API URL
            api_url = os.getenv('API_URL')
            
            # 输出日志，帮助调试
            print(f"Sending request to: {api_url} with params: {params}")
            
            # Send GET request with timeout and error handling
            response = requests.get(api_url, params=params, timeout=10, verify=False)
            
            # 输出响应状态和内容，帮助调试
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text[:200]}...") # 只打印前200个字符
            
            # 检查响应状态
            if response.status_code == 200:
                data = response.json()
                
                # Check if data is returned
                if data and isinstance(data, list) and len(data) > 0 and 'data' in data[0] and len(data[0]['data']) > 0:
                    # Extract data and sort by inventory quantity
                    results = data[0]['data']
                    
                    # 清理每个项目的description字段
                    for item in results:
                        if 'description' in item and item['description']:
                            item['description'] = clean_html(item['description'])
                    
                    results.sort(key=lambda x: x.get('sum_actual_qty', 0), reverse=True)
                else:
                    # Normal query but no results found
                    no_results = True
            else:
                # This is a real API error
                error_message = f'System currently unavailable (Status code: {response.status_code})'
                
        except requests.exceptions.RequestException as e:
            print(f"Request error: {str(e)}")
            error_message = 'Network connection issue'
        except ValueError as e:
            print(f"JSON parsing error: {str(e)}")
            error_message = 'Data processing error'
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            error_message = 'Unexpected system error'
    
    return render_template('inventory.html', results=results, search_performed=search_performed, error_message=error_message, no_results=no_results)

# Admin dashboard
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

# 创建新用户
@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f'用户名 {username} 已存在', 'error')
            return redirect(url_for('create_user'))
        
        # Create new user
        new_user = User(username=username, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'User {username} created successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_user.html')

# Edit user
@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Do not allow editing the admin user defined in environment variables
    if user.username == ADMIN_USER:
        flash('Cannot edit main administrator account', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        # Check if username already exists (if username was changed)
        if username != user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash(f'Username {username} already exists', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
        
        # Update user information
        user.username = username
        user.is_admin = is_admin
        if password:  # Only update password if provided
            user.set_password(password)
        
        db.session.commit()
        flash('User information updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user.html', user=user)

# Delete user
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Do not allow deleting the admin user defined in environment variables
    if user.username == ADMIN_USER:
        flash('Cannot delete main administrator account', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Do not allow deleting yourself
    if user.id == session.get('user_id'):
        flash('Cannot delete currently logged in user', 'error')
        return redirect(url_for('admin_dashboard'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# 重置数据库
@app.route('/admin/reset-database', methods=['POST'])
@login_required
@admin_required
def admin_reset_database():
    if request.form.get('confirm') == 'RESET':
        # Reset database
        reset_database()
        flash('Database reset successful', 'success')
        # Clear session, force user to log in again
        session.clear()
        return redirect(url_for('login'))
    else:
        flash('Confirmation code error, database reset failed', 'error')
        return redirect(url_for('admin_dashboard'))

# 清理HTML标签和实体的函数
def clean_html(text):
    if not text:
        return ""
    
    # 解码HTML实体（如 &AMP;, &lt;, &gt; 等）
    text = html.unescape(text)
    
    # 移除HTML标签（如 <br>, <p> 等）
    text = re.sub(r'<[^>]*>', '', text)
    
    # 替换多个空格为单个空格
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

# User changes their own password
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.get(session['user_id'])
        
        # Check if current password is correct
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('change_password'))
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('change_password'))
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('inventory'))
    
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
