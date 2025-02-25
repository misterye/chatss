document.addEventListener('DOMContentLoaded', () => {
    // 自动滚动到最新消息
    const chatMessages = document.getElementById('chat-messages');
    if (chatMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // 点击聊天记录切换对话
    document.querySelectorAll('.chat-list-item').forEach(item => {
        item.addEventListener('click', (e) => {
            if (!e.target.closest('.chat-actions')) {
                const chatId = item.dataset.chatId;
                window.location.href = `/chat?chat_id=${chatId}`;
            }
        });
    });

    // 重命名功能
    document.querySelectorAll('.editable-title').forEach(title => {
        title.addEventListener('click', function() {
            const chatId = this.dataset.chatId;
            const originalTitle = this.innerText;
            
            // 创建输入框
            const input = document.createElement('input');
            input.type = 'text';
            input.value = originalTitle;
            input.className = 'title-edit-input';
            
            // 替换文本为输入框
            this.replaceWith(input);
            input.focus();
            
            // 保存事件
            input.addEventListener('blur', async () => {
                const newTitle = input.value.trim();
                if (!newTitle || newTitle === originalTitle) {
                    input.replaceWith(this);
                    return;
                }

                try {
                    const response = await fetch(`/rename_chat/${chatId}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `new_title=${encodeURIComponent(newTitle)}`
                    });

                    if (response.ok) {
                        const link = this.parentElement.querySelector('a');
                        if (link) {
                            link.textContent = newTitle;
                        }
                        this.textContent = newTitle;
                        location.reload(); // 刷新页面更新列表
                    } else {
                        alert('重命名失败');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('请求失败，请检查网络');
                }
                input.replaceWith(this);
            });
        });
    });

    // 删除功能
    window.deleteChat = async (chatId) => {
        if (confirm('确定要删除此聊天记录吗？')) {
            try {
                const response = await fetch(`/delete_chat/${chatId}`, {
                    method: 'POST'
                });
                
                if (response.ok) {
                    location.reload(); // 刷新页面更新列表
                } else {
                    alert('删除失败');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('请求失败，请检查网络');
            }
        }
    };

    // 监听表单提交
    document.querySelector('form').addEventListener('submit', function(e) {
        e.preventDefault(); // 阻止表单默认提交
        const status = document.getElementById('sending-status');
        const submitButton = this.querySelector('button[type="submit"]');
        const form = this;
        
        status.style.display = 'block';
        submitButton.disabled = true;
        
        // 使用 fetch 发送表单数据
        fetch('/chat', {
            method: 'POST',
            body: new FormData(form)
        })
        .then(response => response.text())
        .then(html => {
            // 更新页面内容
            document.documentElement.innerHTML = html;
            // 重新绑定事件监听器
            attachEventListeners();
            // 滚动到底部
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
        })
        .finally(() => {
            status.style.display = 'none';
            submitButton.disabled = false;
        });
    });

    // 封装所有事件监听器
    function attachEventListeners() {
        // 自动滚动到最新消息
        const chatMessages = document.getElementById('chat-messages');
        if (chatMessages) {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        // 点击聊天记录切换对话
        document.querySelectorAll('.chat-list-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.chat-actions')) {
                    const chatId = item.dataset.chatId;
                    window.location.href = `/chat?chat_id=${chatId}`;
                }
            });
        });

        // 重新绑定表单提交事件
        document.querySelector('form').addEventListener('submit', function(e) {
            // ... (之前的表单提交代码)
        });
    }

    // 初始化事件监听器
    attachEventListeners();
});

// 编辑聊天标题
function editChatTitle(chatId) {
    event.preventDefault();
    const chatItem = document.querySelector(`.chat-list-item[data-chat-id="${chatId}"]`);
    const titleSpan = chatItem.querySelector('.chat-title');
    const originalTitle = titleSpan.textContent;

    const input = document.createElement('input');
    input.type = 'text';
    input.value = originalTitle;
    input.className = 'form-control form-control-sm';
    input.style.width = '150px';

    titleSpan.replaceWith(input);
    input.focus();

    const saveTitle = async () => {
        const newTitle = input.value.trim();
        if (!newTitle || newTitle === originalTitle) {
            input.replaceWith(titleSpan);
            return;
        }

        try {
            const response = await fetch(`/rename_chat/${chatId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `new_title=${encodeURIComponent(newTitle)}`
            });

            if (response.ok) {
                window.location.reload();
            } else {
                alert('重命名失败');
                input.replaceWith(titleSpan);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('请求失败，请检查网络');
            input.replaceWith(titleSpan);
        }
    };

    input.addEventListener('blur', saveTitle);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            saveTitle();
        }
    });
}

// 删除聊天记录
function deleteChat(chatId) {
    event.preventDefault();
    if (confirm('是否删除该聊天记录？')) {
        fetch(`/delete_chat/${chatId}`, {
            method: 'POST'
        })
        .then(response => {
            if (response.ok) {
                window.location.reload();
            } else {
                alert('删除失败');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('请求失败，请检查网络');
        });
    }
}

// 自动滚动到底部
function scrollToBottom() {
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 页面加载完成后滚动到底部
document.addEventListener('DOMContentLoaded', scrollToBottom);
