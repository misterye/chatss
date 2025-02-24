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

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 生成安全的随机密钥

# 数据库连接函数
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# 清理文件名中的特殊字符
def clean_filename(filename):
    return ''.join(c for c in filename if c.isalnum() or c in (' ', '_')).strip().replace(' ', '_')

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
    c.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
    username = c.fetchone()['username']
    
    # 获取用户聊天记录
    c.execute("SELECT * FROM conversations WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    conversations = c.fetchall()
    
    chat_content = ''
    current_chat_id = request.args.get('chat_id', None)
    
    if request.method == 'POST' and 'message' in request.form:
        message = request.form['message']
        if not current_chat_id:  # 新建聊天
            title = message[:10] if len(message) > 10 else message
            cleaned_title = clean_filename(title)
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_path = f"conversations/{username}/{username}_{cleaned_title}.md"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(f"用户: {message}\n")
            c.execute("INSERT INTO conversations (user_id, title, created_at, file_path) VALUES (?, ?, ?, ?)",
                      (session['user_id'], title, created_at, file_path))
            current_chat_id = c.lastrowid
        else:  # 继续现有聊天
            c.execute("SELECT file_path FROM conversations WHERE id = ? AND user_id = ?",
                      (current_chat_id, session['user_id']))
            chat = c.fetchone()
            if chat:
                with open(chat['file_path'], 'a') as f:
                    f.write(f"用户: {message}\n")
        
        # 调用Groq API
        response = call_groq_api(message, current_chat_id)
        if response:
            c.execute("SELECT file_path FROM conversations WHERE id = ?", (current_chat_id,))
            file_path = c.fetchone()['file_path']
            with open(file_path, 'a') as f:
                f.write(f"AI: {response}\n")
            chat_content = open(file_path).read()
    
    conn.commit()
    conn.close()
    return render_template('chat.html', username=username, conversations=conversations, chat_content=chat_content, current_chat_id=current_chat_id)

# 调用Groq API的函数
def call_groq_api(message, chat_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT file_path FROM conversations WHERE id = ? AND user_id = ?", (chat_id, session['user_id']))
    chat = c.fetchone()
    conn.close()
    
    history = []
    if chat and os.path.exists(chat['file_path']):
        with open(chat['file_path']) as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("用户: "):
                    history.append({"role": "user", "content": line[5:].strip()})
                elif line.startswith("AI: "):
                    history.append({"role": "assistant", "content": line[4:].strip()})
    
    history.append({"role": "user", "content": message})
    
    headers = {
        "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "deepseek-r1-distill-llama-70b",
        "messages": history
    }
    try:
        response = requests.post(
            "https://careful-bat-89.deno.dev/api.groq.com/openai/v1/chat/completions",
            json=data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        flash(f"API调用失败: {str(e)}")
        return None

# 新建聊天路由
@app.route('/new_chat', methods=['POST'])
@login_required
def new_chat():
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

if __name__ == '__main__':
    app.run(debug=True)