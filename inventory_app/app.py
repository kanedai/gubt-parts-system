import os
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import json

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# 使用绝对路径来存储数据库
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 创建数据库和表
with app.app_context():
    db.create_all()
    # 检查是否有默认用户，如果没有则创建
    if not User.query.filter_by(username='admin').first():
        default_user = User(username='admin')
        default_user.set_password('admin')
        db.session.add(default_user)
        db.session.commit()

# 添加上下文处理器提供当前年份
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            return redirect(url_for('inventory'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    results = []
    error_message = None
    search_performed = False
    
    if request.method == 'POST':
        search_performed = True
        item_name = request.form.get('item_name', '')
        models = request.form.get('models', '')
        reference_code = request.form.get('reference_code', '')
        
        # 构建查询参数
        params = {}
        if item_name:
            params['item_name'] = item_name
        if models:
            params['models'] = models
        if reference_code:
            params['reference_code'] = reference_code
        
        # 如果没有提供任何查询参数，显示提示信息
        if not params:
            flash('Please enter at least one search criterion.', 'warning')
            return render_template('inventory.html', results=results, search_performed=False)
        
        try:
            # 从环境变量获取API URL
            api_url = os.getenv('API_URL')
            
            # 输出日志，帮助调试
            print(f"Sending request to: {api_url} with params: {params}")
            
            # 发送GET请求，增加超时设置和错误处理
            response = requests.get(api_url, params=params, timeout=10, verify=False)
            
            # 输出响应状态和内容，帮助调试
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text[:200]}...") # 只打印前200个字符
            
            # 检查响应状态
            if response.status_code == 200:
                data = response.json()
                
                # 检查是否有数据返回
                if data and isinstance(data, list) and len(data) > 0 and 'data' in data[0] and len(data[0]['data']) > 0:
                    # 提取数据并按库存数量排序
                    results = data[0]['data']
                    results.sort(key=lambda x: x.get('sum_actual_qty', 0), reverse=True)
                else:
                    # 不使用flash，而是在表格中显示无结果消息
                    # 不设置flash消息，因为我们现在在表格中显示无结果消息
                    pass
            else:
                error_message = f'System is currently unavailable (Status: {response.status_code})'
                
        except requests.exceptions.RequestException as e:
            print(f"Request error: {str(e)}")
            error_message = 'Network connection issue'
        except ValueError as e:
            print(f"JSON parsing error: {str(e)}")
            error_message = 'Data processing error'
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            error_message = 'Unexpected system error'
    
    return render_template('inventory.html', results=results, search_performed=search_performed, error_message=error_message)

# 移除了注册功能，用户需要联系销售代表获取访问权限

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
