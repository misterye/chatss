from dotenv import load_dotenv
import os
import sqlite3
import secrets
from flask import Flask, request, redirect, url_for, render_template, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import logging
import re

# 加载 .env 文件
load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 生成安全的随机密钥

# 数据库连接函数
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# 清理文件名中的特殊字符
def clean_filename(filename):
    # 移除或替换不允许的字符
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    return filename.strip()

# 登录检查装饰器
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# 管理员权限检查装饰器
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录')
            return redirect(url_for('login'))
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if not user or not user['is_admin']:
            flash('需要管理员权限')
            return redirect(url_for('chat'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# 登录表单定义
class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('chat'))
        flash('用户名或密码错误')
    return render_template('login.html', form=form)

# 登出路由
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# 聊天页面路由
@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    conn = get_db()
    c = conn.cursor()
    username = session.get('username')
    current_chat_id = request.args.get('chat_id', None) or session.get('current_chat_id')
    chat_content = ''
    chat = None  # 初始化 chat 变量

    # 获取所有聊天记录
    c.execute("SELECT id, title, created_at FROM conversations WHERE user_id = ? ORDER BY created_at DESC",
              (session['user_id'],))
    conversations = c.fetchall()

    if request.method == 'POST' and 'message' in request.form:
        message = request.form['message'].strip()
        if not message:
            flash('消息不能为空')
            return redirect(url_for('chat'))
            
        if not current_chat_id:
            # 新建聊天
            title = message[:20] if len(message) > 20 else message
            cleaned_title = clean_filename(title)
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_path = f"conversations/{username}/{cleaned_title}_{created_at}.md"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            c.execute("""INSERT INTO conversations (user_id, title, created_at, file_path) 
                        VALUES (?, ?, ?, ?)""", (session['user_id'], title, created_at, file_path))
            conn.commit()
            current_chat_id = c.lastrowid
            session['current_chat_id'] = current_chat_id
            
            # 创建新聊天后更新 chat 变量
            c.execute("SELECT file_path FROM conversations WHERE id = ?", (current_chat_id,))
            chat = c.fetchone()
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"用户: {message}\n")
            chat_content = f"用户: {message}\n"
        else:
            # 继续现有聊天
            c.execute("SELECT file_path FROM conversations WHERE id = ? AND user_id = ?",
                      (current_chat_id, session['user_id']))
            chat = c.fetchone()
            
        if chat and os.path.exists(chat['file_path']):
            # 写入用户消息
            with open(chat['file_path'], 'a', encoding='utf-8') as f:
                f.write(f"用户: {message}\n")
            
            # 调用 API
            response = call_groq_api(message, current_chat_id)
            
            # 写入 AI 回复
            with open(chat['file_path'], 'a', encoding='utf-8') as f:
                f.write(f"AI: {response}\n")
            
            # 读取更新后的聊天内容
            with open(chat['file_path'], 'r', encoding='utf-8') as f:
                chat_content = f.read()
        else:
            flash("聊天记录不存在")
            return redirect(url_for('chat'))

        return render_template('chat.html', 
                            username=username,
                            conversations=conversations,
                            current_chat_id=current_chat_id,
                            chat_content=chat_content)

    # GET 请求处理
    if current_chat_id:
        c.execute("SELECT file_path FROM conversations WHERE id = ? AND user_id = ?",
                  (current_chat_id, session['user_id']))
        chat = c.fetchone()
        if chat and os.path.exists(chat['file_path']):
            with open(chat['file_path'], 'r', encoding='utf-8') as f:
                chat_content = f.read()

    return render_template('chat.html', 
                        username=username,
                        conversations=conversations,
                        current_chat_id=current_chat_id,
                        chat_content=chat_content)

# 调用 Groq API 的函数
def call_groq_api(message, chat_id):
    import requests
    import json
    
    # API endpoint 修正
    url = "https://careful-bat-89.deno.dev/api.groq.com/openai/v1/chat/completions"
    
    # 从环境变量获取 API key
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        return "错误：未设置 GROQ_API_KEY 环境变量"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "deepseek-r1-distill-llama-70b",
        "messages": [
            {
                "role": "system",
                "content": "你是一个友好的AI助手，请用中文回答用户的问题。"
            },
            {
                "role": "user",
                "content": message
            }
        ],
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result['choices'][0]['message']['content']
    except requests.exceptions.RequestException as e:
        print(f"API调用错误: {str(e)}")
        return "抱歉，API 调用出错，请检查 API key 是否正确设置。"

# 新建聊天路由
@app.route('/new_chat', methods=['GET', 'POST'])
@login_required
def new_chat():
    conn = get_db()
    c = conn.cursor()
    
    # 获取用户信息
    c.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
    username = c.fetchone()['username']
    
    # 创建新聊天
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = "新的对话"
    file_path = f"conversations/{username}/chat_{created_at}.md"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # 写入欢迎消息
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("AI: 您好！有什么可以帮到您？\n")
    
    # 插入数据库
    c.execute("""INSERT INTO conversations (user_id, title, created_at, file_path) 
                VALUES (?, ?, ?, ?)""", (session['user_id'], title, created_at, file_path))
    new_chat_id = c.lastrowid
    conn.commit()
    conn.close()
    
    session['current_chat_id'] = new_chat_id
    return redirect(url_for('chat'))

# 删除聊天路由
@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@login_required
def delete_chat(chat_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT file_path FROM conversations WHERE id = ? AND user_id = ?", (chat_id, session['user_id']))
    chat = c.fetchone()
    if chat and os.path.exists(chat['file_path']):
        try:
            os.remove(chat['file_path'])
            c.execute("DELETE FROM conversations WHERE id = ?", (chat_id,))
            conn.commit()
            if session.get('current_chat_id') == str(chat_id):  # 转换为字符串比较
                session.pop('current_chat_id', None)
            flash('聊天记录已删除')
        except Exception as e:
            flash(f"删除聊天失败: {str(e)}")
    conn.close()
    return redirect(url_for('chat'))

# 重命名聊天路由
@app.route('/rename_chat/<int:chat_id>', methods=['POST'])
@login_required
def rename_chat(chat_id):
    new_title = request.form['new_title']
    cleaned_new_title = clean_filename(new_title)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT file_path, user_id FROM conversations WHERE id = ? AND user_id = ?",
              (chat_id, session['user_id']))
    chat = c.fetchone()
    if chat:
        c.execute("SELECT username FROM users WHERE id = ?", (chat['user_id'],))
        username = c.fetchone()['username']
        old_file_path = chat['file_path']
        new_file_path = f"conversations/{username}/{username}_{cleaned_new_title}.md"
        if os.path.exists(old_file_path):
            try:
                os.rename(old_file_path, new_file_path)
                c.execute("UPDATE conversations SET title = ?, file_path = ? WHERE id = ?",
                          (new_title, new_file_path, chat_id))
                conn.commit()
                flash('聊天记录已重命名')
            except Exception as e:
                flash(f"重命名聊天失败: {str(e)}")
    conn.close()
    return redirect(url_for('chat'))

# 管理员后台路由
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

# 新增用户路由
@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    password_hash = generate_password_hash(password)
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        flash('用户添加成功')
    except sqlite3.IntegrityError:
        flash('用户名已存在')
    conn.close()
    return redirect(url_for('admin'))

# 修改用户信息路由
@app.route('/update_user/<int:user_id>', methods=['POST'])
@admin_required
def update_user(user_id):
    new_username = request.form['new_username']
    new_password = request.form['new_password']
    password_hash = generate_password_hash(new_password) if new_password else None
    conn = get_db()
    c = conn.cursor()
    try:
        if password_hash:
            c.execute("UPDATE users SET username = ?, password_hash = ? WHERE id = ?", (new_username, password_hash, user_id))
        else:
            c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
        conn.commit()
        flash('用户信息更新成功')
    except sqlite3.IntegrityError:
        flash('用户名已存在')
    conn.close()
    return redirect(url_for('admin'))

# 删除用户路由
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    username = c.fetchone()['username']
    c.execute("SELECT file_path FROM conversations WHERE user_id = ?", (user_id,))
    for row in c.fetchall():
        if os.path.exists(row['file_path']):
            try:
                os.remove(row['file_path'])
            except Exception as e:
                flash(f"删除文件失败: {str(e)}")
    c.execute("DELETE FROM conversations WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    flash('用户及其聊天记录已删除')
    conn.close()
    return redirect(url_for('admin'))

# 查看用户聊天记录路由
@app.route('/view_user_chats/<int:user_id>', methods=['GET'])
@admin_required
def view_user_chats(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM conversations WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    conversations = c.fetchall()
    conn.close()
    return render_template('user_chats.html', conversations=conversations)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=8502)