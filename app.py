# Synkube云代码 - 最终修复版
import os
import secrets
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

# ======================
# 路径配置 & 自动创建
# ======================
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
upload_path = os.path.join(basedir, 'uploads')

os.makedirs(instance_path, exist_ok=True)
os.makedirs(upload_path, exist_ok=True)

# ======================
# Flask App 初始化
# ======================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "app.db")}'
app.config['UPLOAD_FOLDER'] = upload_path
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

# ======================
# 数据库模型
# ======================
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    share_name = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    invite_code = db.Column(db.String(50))
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('files', lazy=True))

# ======================
# 登录管理
# ======================
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======================
# 工具函数
# ======================
def get_user_upload_dir(user_id):
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

# ======================
# 基础HTML模板
# ======================
def render_page(content, title="Synkube", **context):
    base_template = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Synkube - {{ title or '云存储' }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar-brand { font-weight: bold; color: #0d6efd !important; }
        .card { box-shadow: 0 0.125rem 0.25rem rgba(0,0,0,.075); border: none; margin-bottom: 1.5rem; }
        .btn-synkube { background-color: #0d6efd; border-color: #0d6efd; color: white; }
        .btn-synkube:hover { background-color: #0b5ed7; border-color: #0a58ca; }
        footer { margin-top: 3rem; text-align: center; color: #6c757d; font-size: 0.9em; padding: 20px 0; }
        .list-group-item { display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">Synkube</a>
            {% if current_user.is_authenticated %}
                <span class="navbar-text">欢迎，{{ current_user.username }}！</span>
                <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('logout') }}">退出</a>
            {% endif %}
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}
              <div class="alert alert-info alert-dismissible fade show" role="alert">
                {{ msg }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        {{ content | safe }}
    </div>

    <footer>
        <p>© 2025 Synkube · 安全 · 高效 · 私有云</p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    '''
    context.update({'title': title, 'content': content})
    return render_template_string(base_template, **context)

# ======================
# 路由：主页
# ======================
@app.route('/')
@login_required
def index():
    user_files = File.query.filter_by(owner_id=current_user.id).all()
    public_files = File.query.filter(
        File.is_public == True,
        File.owner_id != current_user.id
    ).all()
    query = request.args.get('q', '').strip()

    # 构建我的文件列表
    my_files_html = '<ul class="list-group">'
    for file_obj in user_files:
        tags = []
        if file_obj.is_public:
            tags.append(f'<span class="badge bg-success">公开: {file_obj.share_name or file_obj.filename}</span>')
        if file_obj.invite_code:
            tags.append('<span class="badge bg-warning">需邀请码</span>')
        tag_str = ' '.join(tags) if tags else ''
        
        my_files_html += f'''
        <li class="list-group-item d-flex justify-content-between align-items-center">
            <div>
                <strong>{file_obj.filename}</strong><br>
                <small class="text-muted">{tag_str}</small>
            </div>
            <div>
                <a href="{url_for('download', filename=file_obj.stored_name)}" class="btn btn-sm btn-outline-primary">下载</a>
                <a href="{url_for('rename_form', file_id=file_obj.id)}" class="btn btn-sm btn-outline-secondary">重命名</a>
                <a href="{url_for('file_info', file_id=file_obj.id)}" class="btn btn-sm btn-outline-info">属性</a>
                <a href="{url_for('delete', file_id=file_obj.id)}" class="btn btn-sm btn-outline-danger"
                   onclick="return confirm(\'确定删除此文件？\')">删除</a>
            </div>
        </li>
        '''
    my_files_html += '</ul>' if user_files else '<p class="text-muted">暂无文件。</p>'

    # 构建他人公开文件列表
    public_files_html = '<ul class="list-group">'
    for file_obj in public_files:
        badge = '<span class="badge bg-warning ms-2">需邀请码</span>' if file_obj.invite_code else ''
        public_files_html += f'''
        <li class="list-group-item d-flex justify-content-between align-items-center">
            <div>
                <a href="{url_for('download_public', file_id=file_obj.id)}" class="text-decoration-none">{file_obj.share_name or file_obj.filename}</a>（来自：{file_obj.owner.username}）<br>
                <small class="text-muted">{badge}</small>
            </div>
        </li>
        '''
    public_files_html += '</ul>' if public_files else '<p class="text-muted">暂无他人公开文件。</p>'

    # 构建搜索表单
    search_form = f'''
    <div class="card p-3 mb-4">
        <form action="{url_for('search')}" method="GET">
            <div class="input-group">
                <input type="text" name="q" class="form-control" placeholder="搜索他人公开文件（按名称）..." value="{query or ''}">
                <button class="btn btn-outline-secondary" type="submit">搜索</button>
                {'<a href="' + url_for('index') + '" class="btn btn-outline-secondary">清除</a>' if query else ''}
            </div>
        </form>
    </div>
    '''

    # 构建上传表单
    upload_form = f'''
    <div class="card p-3 mb-4">
        <h5>上传新文件</h5>
        <form method="POST" enctype="multipart/form-data" action="{url_for('upload')}">
            <div class="mb-2">
                <input type="file" name="file" class="form-control" required>
            </div>
            <div class="form-check mb-2">
                <input class="form-check-input" type="checkbox" name="is_public" id="isPublic">
                <label class="form-check-label" for="isPublic">设为公开</label>
            </div>
            <div id="public-options" style="display:none;">
                <div class="mb-2">
                    <input type="text" name="share_name" class="form-control" placeholder="分享名称（如：项目报告）">
                </div>
                <div class="mb-2">
                    <input type="text" name="invite_code" class="form-control" placeholder="邀请码（可选，留空则公开访问）">
                </div>
            </div>
            <button type="submit" class="btn btn-synkube">上传</button>
        </form>
    </div>

    <script>
        document.getElementById('isPublic').addEventListener('change', function() {{
            document.getElementById('public-options').style.display = this.checked ? 'block' : 'none';
        }});
    </script>
    '''

    content = f'''
    <h2 class="mb-4">我的 Synkube</h2>
    
    {search_form}
    
    {upload_form}

    <!-- 我的文件 -->
    <div class="card p-3 mb-4">
        <h5>我的文件（<span class="badge bg-primary">{len(user_files)}</span>）</h5>
        {my_files_html}
    </div>

    <!-- 他人公开文件 -->
    <div class="card p-3">
        <h5>他人公开文件（<span class="badge bg-success">{len(public_files)}</span>）</h5>
        {public_files_html}
    </div>
    '''

    return render_page(content, "主页")

# ======================
# 搜索路由
# ======================
@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    results = []
    if q:
        results = File.query.filter(
            File.is_public == True,
            File.owner_id != current_user.id,
            db.or_(
                File.share_name.ilike(f'%{q}%'),
                File.filename.ilike(f'%{q}%')
            )
        ).all()

    results_html = '<ul class="list-group">'
    for file_obj in results:
        badge = '<span class="badge bg-warning ms-2">需邀请码</span>' if file_obj.invite_code else ''
        results_html += f'''
        <li class="list-group-item d-flex justify-content-between align-items-center">
            <div>
                <a href="{url_for('download_public', file_id=file_obj.id)}" class="text-decoration-none">{file_obj.share_name or file_obj.filename}</a>（来自：{file_obj.owner.username}）<br>
                <small class="text-muted">{badge}</small>
            </div>
        </li>
        '''
    results_html += '</ul>' if results else '<p class="text-muted">未找到匹配的公开文件。</p>'

    search_form = f'''
    <div class="card p-3 mb-4">
        <form action="{url_for('search')}" method="GET">
            <div class="input-group">
                <input type="text" name="q" class="form-control" placeholder="输入关键词..." value="{q}">
                <button class="btn btn-outline-secondary" type="submit">搜索</button>
                <a href="{url_for('index')}" class="btn btn-outline-secondary">返回主页</a>
            </div>
        </form>
    </div>
    '''

    content = f'''
    <h2 class="mb-4">🔍 搜索公开文件</h2>
    
    {search_form}

    {'<div class="card p-3"><h5>搜索结果（共 ' + str(len(results)) + ' 个）</h5>' + results_html + '</div>' if q else '<div class="alert alert-warning">请输入搜索关键词。</div>'}
    '''

    return render_page(content, "搜索")

# ========== 其他路由 ==========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('用户名已存在。')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        new_user = User(username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录。')
        return redirect(url_for('login'))
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card p-4">
                <h3 class="text-center mb-4">注册 Synkube</h3>
                <form method="post">
                    <div class="mb-3">
                        <input type="text" name="username" class="form-control" placeholder="用户名" required>
                    </div>
                    <div class="mb-3">
                        <input type="password" name="password" class="form-control" placeholder="密码" required>
                    </div>
                    <button type="submit" class="btn btn-synkube w-100">注册</button>
                </form>
                <div class="text-center mt-3">
                    <a href="/login">已有账号？去登录</a>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page(content, "注册")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误。')
        return redirect(url_for('login'))
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card p-4">
                <h3 class="text-center mb-4">登录 Synkube</h3>
                <form method="post">
                    <div class="mb-3">
                        <input type="text" name="username" class="form-control" placeholder="用户名" required>
                    </div>
                    <div class="mb-3">
                        <input type="password" name="password" class="form-control" placeholder="密码" required>
                    </div>
                    <button type="submit" class="btn btn-synkube w-100">登录</button>
                </form>
                <div class="text-center mt-3">
                    <a href="/register">没有账号？去注册</a>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page(content, "登录")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    is_public = request.form.get('is_public') == 'on'
    share_name = request.form.get('share_name', '').strip() if is_public else None
    invite_code = request.form.get('invite_code', '').strip() or None

    if not file or file.filename == '':
        flash('请选择文件！')
        return redirect(url_for('index'))
    if is_public and not share_name:
        flash('公开文件必须填写分享名称！')
        return redirect(url_for('index'))

    original_name = secure_filename(file.filename)
    stored_name = secrets.token_hex(16) + '_' + original_name

    user_dir = get_user_upload_dir(current_user.id)
    filepath = os.path.join(user_dir, stored_name)
    file.save(filepath)

    new_file = File(
        filename=original_name,
        stored_name=stored_name,
        share_name=share_name,
        owner_id=current_user.id,
        is_public=is_public,
        invite_code=invite_code
    )
    db.session.add(new_file)
    db.session.commit()
    flash('文件上传成功！')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    user_dir = get_user_upload_dir(current_user.id)
    return send_from_directory(user_dir, filename, as_attachment=True)

@app.route('/download/public/<int:file_id>', methods=['GET', 'POST'])
def download_public(file_id):
    file_obj = File.query.filter_by(id=file_id, is_public=True).first_or_404()
    if file_obj.invite_code:
        if request.method == 'POST':
            input_code = request.form.get('code', '').strip()
            if input_code == file_obj.invite_code:
                user_dir = get_user_upload_dir(file_obj.owner_id)
                return send_from_directory(user_dir, file_obj.stored_name, as_attachment=True)
            else:
                flash('邀请码错误！')
                return redirect(url_for('download_public', file_id=file_id))
        else:
            content = f'''
            <div class="row justify-content-center">
                <div class="col-md-5">
                    <div class="card p-4">
                        <h4>请输入邀请码</h4>
                        <p>下载：<strong>{file_obj.share_name or file_obj.filename}</strong></p>
                        <form method="post">
                            <div class="mb-3">
                                <input type="password" name="code" class="form-control" placeholder="邀请码" required>
                            </div>
                            <button type="submit" class="btn btn-synkube w-100">确认下载</button>
                        </form>
                        <div class="text-center mt-3">
                            <a href="{url_for('index')}">返回主页</a>
                        </div>
                    </div>
                </div>
            </div>
            '''
            return render_page(content, "输入邀请码")
    
    user_dir = get_user_upload_dir(file_obj.owner_id)
    return send_from_directory(user_dir, file_obj.stored_name, as_attachment=True)

@app.route('/rename/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    file_obj = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        flash('新文件名不能为空！')
        return redirect(url_for('rename_form', file_id=file_id))
    file_obj.filename = secure_filename(new_name)
    db.session.commit()
    flash('文件已重命名！')
    return redirect(url_for('index'))

@app.route('/rename_form/<int:file_id>')
@login_required
def rename_form(file_id):
    file_obj = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card p-4">
                <h4>重命名文件</h4>
                <form method="post" action="{url_for('rename_file', file_id=file_obj.id)}">
                    <div class="mb-3">
                        <input type="text" name="new_name" class="form-control" value="{file_obj.filename}" required>
                    </div>
                    <button type="submit" class="btn btn-synkube">保存</button>
                    <a href="{url_for('index')}" class="btn btn-secondary ms-2">取消</a>
                </form>
            </div>
        </div>
    </div>
    '''
    return render_page(content, "重命名")

@app.route('/file_info/<int:file_id>')
@login_required
def file_info(file_id):
    file_obj = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    user_dir = get_user_upload_dir(current_user.id)
    filepath = os.path.join(user_dir, file_obj.stored_name)
    size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    size_mb = round(size / (1024 * 1024), 2)

    is_public_text = '是' if file_obj.is_public else '否'
    share_name_display = f'<tr><td><strong>分享名称</strong></td><td>{file_obj.share_name or file_obj.filename}</td></tr>' if file_obj.is_public else ''
    invite_code_text = file_obj.invite_code or '无'

    content = f'''
    <div class="card p-4">
        <h4>文件属性</h4>
        <table class="table table-borderless">
            <tr><td width="150"><strong>原始文件名</strong></td><td>{file_obj.filename}</td></tr>
            <tr><td><strong>存储名</strong></td><td>{file_obj.stored_name}</td></tr>
            <tr><td><strong>大小</strong></td><td>{size_mb} MB</td></tr>
            <tr><td><strong>上传时间</strong></td><td>{file_obj.upload_time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><td><strong>是否公开</strong></td><td>{is_public_text}</td></tr>
            {share_name_display}
            <tr><td><strong>邀请码</strong></td><td>{invite_code_text}</td></tr>
        </table>
        <a href="{url_for('index')}" class="btn btn-secondary">返回主页</a>
    </div>
    '''
    return render_page(content, "文件属性")

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    file_obj = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    user_dir = get_user_upload_dir(current_user.id)
    filepath = os.path.join(user_dir, file_obj.stored_name)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(file_obj)
    db.session.commit()
    flash('文件已删除！')
    return redirect(url_for('index'))

# ======================
# 启动（自动初始化数据库）
# ======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 自动创建表
    print("✅ Synkube 启动中... 数据库和目录已自动初始化。")
    app.run(debug=True, host='0.0.0.0', port=5000)



