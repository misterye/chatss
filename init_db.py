import sqlite3
import os
from werkzeug.security import generate_password_hash

# 创建数据库连接
conn = sqlite3.connect('database.db')
c = conn.cursor()

# 创建users表
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0)''')

# 创建conversations表
c.execute('''CREATE TABLE IF NOT EXISTS conversations
             (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, created_at TEXT, file_path TEXT)''')

# 添加默认管理员用户
admin_password = 'shensi'
admin_password_hash = generate_password_hash(admin_password)
c.execute("INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES ('shensi', ?, 1)", (admin_password_hash,))

conn.commit()
conn.close()

# 确保conversations目录存在
if not os.path.exists('conversations'):
    os.makedirs('conversations')