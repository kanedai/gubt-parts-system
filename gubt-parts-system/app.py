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

# Query log model
class QueryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    query_params = db.Column(db.Text, nullable=False)  # JSON string of search parameters
    query_results = db.Column(db.Text, nullable=True)  # JSON string of results
    created_at = db.Column(db.DateTime, default=datetime.now)
    posted_to_external = db.Column(db.Boolean, default=False)
    post_status = db.Column(db.String(50), nullable=True)  # success, failed, pending

# System configuration model
class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config_key = db.Column(db.String(100), unique=True, nullable=False)
    config_value = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.now)
    updated_by = db.Column(db.String(80), nullable=True)

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

# 添加JSON过滤器
@app.template_filter('from_json')
def from_json_filter(json_str):
    try:
        return json.loads(json_str) if json_str else None
    except:
        return None

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
            
            # Send GET request with timeout and error handling
            response = requests.get(api_url, params=params, timeout=10, verify=False)
            
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
                    
                    # 记录查询日志
                    current_user = User.query.get(session['user_id'])
                    query_log = QueryLog(
                        username=current_user.username,
                        query_params=json.dumps(params),
                        query_results=json.dumps(results[:10])  # 只保存前10条结果
                    )
                    db.session.add(query_log)
                    db.session.commit()
                    
                    # 异步POST到外部地址
                    post_to_external_api(current_user.username, params, results[:10], query_log.id)
                    
                else:
                    # Normal query but no results found
                    no_results = True
            else:
                # This is a real API error
                error_message = f'System currently unavailable (Status code: {response.status_code})'
                
        except requests.exceptions.RequestException as e:
            error_message = 'Network connection issue'
        except ValueError as e:
            error_message = 'Data processing error'
        except Exception as e:
            error_message = 'Unexpected system error'
    
    return render_template('inventory.html', results=results, search_performed=search_performed, error_message=error_message, no_results=no_results)

# Admin dashboard
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    # 获取查询日志统计
    total_queries = QueryLog.query.count()
    successful_posts = QueryLog.query.filter_by(posted_to_external=True).count()
    # 获取系统配置
    external_api_url = get_system_config('external_api_url', '')
    return render_template('admin_dashboard.html', 
                         users=users, 
                         total_queries=total_queries,
                         successful_posts=successful_posts,
                         external_api_url=external_api_url)

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

# 系统配置管理
@app.route('/admin/config', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_config():
    if request.method == 'POST':
        external_api_url = request.form.get('external_api_url', '').strip()
        current_user = User.query.get(session['user_id'])
        
        set_system_config(
            'external_api_url', 
            external_api_url, 
            'External API URL for posting query logs',
            current_user.username
        )
        
        flash('Configuration updated successfully', 'success')
        return redirect(url_for('admin_config'))
    
    # GET request - show current config
    external_api_url = get_system_config('external_api_url', '')
    return render_template('admin_config.html', external_api_url=external_api_url)

# 查询日志管理
@app.route('/admin/query-logs')
@login_required
@admin_required
def admin_query_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query_logs = QueryLog.query.order_by(QueryLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin_query_logs.html', query_logs=query_logs)

# 重新发送查询日志到外部API
@app.route('/admin/resend-log/<int:log_id>', methods=['POST'])
@login_required
@admin_required
def resend_query_log(log_id):
    query_log = QueryLog.query.get_or_404(log_id)
    
    try:
        query_params = json.loads(query_log.query_params)
        results = json.loads(query_log.query_results) if query_log.query_results else []
        
        post_to_external_api(query_log.username, query_params, results, log_id)
        flash('Query log resent successfully', 'success')
    except Exception as e:
        flash(f'Error resending query log: {str(e)}', 'error')
    
    return redirect(url_for('admin_query_logs'))

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

def get_system_config(key, default_value=None):
    """
    Get system configuration value
    """
    config = SystemConfig.query.filter_by(config_key=key).first()
    return config.config_value if config else default_value

def set_system_config(key, value, description=None, updated_by=None):
    """
    Set system configuration value
    """
    config = SystemConfig.query.filter_by(config_key=key).first()
    if config:
        config.config_value = value
        config.updated_at = datetime.now()
        config.updated_by = updated_by
        if description:
            config.description = description
    else:
        config = SystemConfig(
            config_key=key,
            config_value=value,
            description=description,
            updated_by=updated_by
        )
        db.session.add(config)
    db.session.commit()

def post_to_external_api(username, query_params, results, log_id):
    """
    POST查询信息到外部API
    """
    try:
        # 获取配置的外部API地址
        external_api_url = get_system_config('external_api_url')
        if not external_api_url:
            return
        
        # 准备POST数据
        post_data = {
            'username': username,
            'query_params': query_params,
            'results': results,
            'timestamp': datetime.now().isoformat(),
            'log_id': log_id
        }
        
        # 发送POST请求
        response = requests.post(
            external_api_url,
            json=post_data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        
        # 更新查询日志状态
        query_log = QueryLog.query.get(log_id)
        if query_log:
            if response.status_code == 200:
                query_log.posted_to_external = True
                query_log.post_status = 'success'
            else:
                query_log.post_status = f'failed_status_{response.status_code}'
            db.session.commit()
        
    except Exception as e:
        pass  # Silently handle external API errors
        # 更新查询日志状态
        query_log = QueryLog.query.get(log_id)
        if query_log:
            query_log.post_status = f'failed_error_{str(e)[:50]}'
            db.session.commit()

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
