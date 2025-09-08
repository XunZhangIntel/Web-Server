// 通用AJAX请求函数
const apiRequest = async (url, method, data) => {
    try {
        let csrfToken = sessionStorage.getItem('csrf_token');

        console.log("First", csrfToken);

        if (!csrfToken) {
            const metaTag = document.querySelector('meta[name="csrf-token"]');
            if (metaTag) {
                csrfToken = metaTag.getAttribute('content');
                sessionStorage.setItem('csrf_token', csrfToken);
            }
        }

        const headers = {
            'Content-Type': 'application/json',
        };

        // 4. 如果有Token才添加CSRF头（对于GET请求可能不需要）
        if (csrfToken && method !== 'GET') {
            headers['X-CSRF-Token'] = csrfToken;
        }

        const response = await fetch(url, {
            method,
            headers,
            body: method !== 'GET' ? JSON.stringify(data) : undefined,
            credentials: 'include'
        });

        const newCsrfToken = response.headers.get('X-CSRF-Token');
        if (newCsrfToken) {
            sessionStorage.setItem('csrf_token', newCsrfToken);
            //console.log('CSRF Token已更新');
        }
        const result = await response.json();
       
        console.log("After", newCsrfToken);

        return result;
    } catch (error) {
        console.error('请求失败:', error);
        return { success: false, message: '网络错误' };
    }
};

document.addEventListener('DOMContentLoaded', () => {
    const loginModal = document.getElementById('loginModal');
    const closeBtn = document.querySelector('.close-btn');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    lorMessage = document.getElementById('loginMessage');
    const contentDiv = document.getElementById('content');
    const authButtons = document.getElementById('authButtons');
    const messageForm = document.getElementById('messageForm');
    const messageRes = document.getElementById('messageRes');

    messageRes.style.display = 'none';
    let isMouseDownInsideModal = false;

    authButtons.innerHTML = '<div class="loading-spinner"></div>';
    authButtons.hidden = false;

    // 显示留言
    const loadMessages = async () => {
        const messages = await apiRequest('php/messagesystem/get_messages.php', 'GET');
        const container = document.getElementById('messages');
        container.innerHTML = '';
        // 遍历消息数组，为每条消息创建DOM元素
        messages.forEach(msg => {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';

            const usernameH4 = document.createElement('h4');
            usernameH4.textContent = msg.username; // 自动转义

            const contentP = document.createElement('p');
            contentP.textContent = msg.content; // 自动转义

            const timeSmall = document.createElement('small');
            timeSmall.textContent = new Date(msg.created_at).toLocaleString();

            // 将元素添加到div中
            messageDiv.appendChild(usernameH4);
            messageDiv.appendChild(contentP);
            messageDiv.appendChild(timeSmall);

            // 将div添加到容器中
            container.appendChild(messageDiv);
        });
    };

    // 初始化主页
    if (document.getElementById('messages')) {
        loadMessages();
        //setInterval(loadMessages, 30000);

        // 检查登录状态
        apiRequest('php/utilities/get_user.php', 'GET').then(data => {
	        updateAuthButtons(data.username ? true : false, data.username);
	        setTimeout(() => {
                authButtons.classList.add('visible');
            }, 10);

         });
    }

    // 关闭登录弹窗
    closeBtn.addEventListener('click', function() {
        loginModal.style.display = 'none';
        resetLoginForm();
    });

    // 鼠标在弹窗内按下时标记
    loginModal.addEventListener('mousedown', function(e) {
        if (e.target === loginModal) {
            // 点击的是模态框背景（外部）
            isMouseDownInsideModal = false;
        } else {
            // 点击的是模态框内容（内部）
            isMouseDownInsideModal = true;
        }
    });

    // 鼠标在弹窗内移动时保持标记
    loginModal.addEventListener('mousemove', function() {
        if (isMouseDownInsideModal) {
            isMouseDownInsideModal = true;
        }
    });

    // 鼠标松开时关闭弹窗的逻辑
    loginModal.addEventListener('mouseup', function(e) {
        if (e.target === loginModal && !isMouseDownInsideModal) {
            // 只有在弹窗外部点击且不是从内部拖出的情况下才关闭
            loginModal.style.display = 'none';
        }
        isMouseDownInsideModal = false; // 重置标记
    });

    // 登录表单提交
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = {
                username: document.getElementById('loginUsername').value,
                password: document.getElementById('loginPassword').value
        };

        // 验证用户
        const result = await apiRequest('php/loginsystem/login.php', 'POST', formData);
	    console.log(result);
        if (result.success) {
            showMessage('登录成功！', 'success');
            // 模拟登录成功后的操作
            setTimeout(function() {
                loginModal.style.display = 'none';
                resetLoginForm();
                // 更新页面内容
                //updateContentForLoggedInUser(username);
                // 更改按钮状态
                updateAuthButtons(true, formData.username);
            }, 1000);
        } else {
            showMessage('用户名或密码错误', 'error');
        }
    });

    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        alert('注册功能敬请期待！');
        return;

        const formData = new FormData(this);

        const result = await apiRequest('php/register.php', 'POST', Object.fromEntries(formData.entries()));
        console.log(result);
        if (result.success) {
            showMessage(result.message, 'success');
            setTimeout(function() {
                loginModal.style.display = 'none';
                resetLoginForm();
                // 更新页面内容
                //updateContentForLoggedInUser(username);
                // 更改按钮状态
                updateAuthButtons(true, formData.get('username'));
            }, 1000);
        } else {
            showMessage(result.message, 'error');
        }

    });

    messageForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        content = this.content.value;

        if (content.trim() === '') {
            alert('留言内容不能为空');
            return;
        }

        if (content.length > 500) {
            alert('留言内容不能超过500个字');
            return;
        }

        const result = await apiRequest('php/messagesystem/post_message.php', 'POST', {message: content}); 
        if (result.success) {
            messageRes.classList.add('message', 'success');
            messageRes.textContent = '提交成功';
            messageRes.style.display = 'block';
            loadMessages();
            setTimeout(() => {
                messageRes.style.display = 'none';
            }, 2000);
        } else {
            messageRes.classList.add('message', 'error');
            messageRes.textContent = result.message;
            messageRes.style.display = 'block';
            setTimeout(() => {
                messageRes.style.display = 'none';
            }, 2000);
        }

        this.content.value = '';
        this.content.focus();
    });
});

// 新增主页功能
function loadMessages() {
    fetch('php/get_messages.php')
        .then(response => response.json())
        .then(messages => {
            const container = document.getElementById('messagesContainer');
            container.innerHTML = messages.map(msg => `
                <div class="message-item">
                    <div class="message-header">
                        <span class="message-author">${msg.username}</span>
                        <span class="message-time">${new Date(msg.created_at).toLocaleString()}</span>
                    </div>
                    <p>${msg.content}</p>
                </div>
            `).join('');
        });
}

function postMessage() {
    const content = document.getElementById('messageForm').value;
    console.log(content);
    return;
    if (!content.trim()) return;

    fetch('php/post_message.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `content=${encodeURIComponent(content)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('messageContent').value = '';
            loadMessages();
        }
    });
}

// 显示消息函数
function showMessage(message, type) {
    const lorMessage = document.getElementById('loginMessage');
    lorMessage.textContent = message;
    lorMessage.className = 'message ' + type;
    setTimeout(() => lorMessage.textContent = '', 3000);
}

// 重置登录表单
function resetLoginForm() {
    const loginForm = document.getElementById('loginForm');
    loginForm.reset();
    loginMessage.textContent = '';
    loginMessage.className = 'message';
}

// 更新页面内容
function updateContentForLoggedInUser(username) {
    contentDiv.innerHTML = `
    <h2>欢迎回来, ${username}!</h2>
    <p>这是您的个性化内容区域。</p>
    <div class="user-content">
    <p>您已成功登录系统，可以享受会员专属内容。</p>
    <ul>
    <li>专属优惠</li>
    <li>会员特权</li>
    <li>个性化推荐</li>
    </ul>
    </div>
    `;
}

// 更新认证按钮状态
function updateAuthButtons(isLoggedIn, username = '') {
    if (isLoggedIn) {
        document.querySelector('.auth-buttons').innerHTML = `
            <span>欢迎, ${username}</span>
            <button id="logoutBtn" class="btn-secondary">退出</button>
        `;
        // 添加退出按钮事件
        document.getElementById('logoutBtn').addEventListener('click', function() {
            logout();
        });
    } else {
        document.querySelector('.auth-buttons').innerHTML = `
           <button id="registerBtn" class="btn-secondary">注册</button>
           <button id="loginBtn" class="btn-primary">登录</button>
        `;
        // 重新绑定事件
        document.getElementById('loginBtn').addEventListener('click', function() {
            loginModal.style.display = 'block';
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('registerForm').style.display = 'none';
            if(document.querySelector('.modal-header h3')?.textContent === '用户注册') {
                document.querySelector('.modal-header h3').textContent = '用户登录';
                lorMessage = document.getElementById('loginMessage');
            }
        });
        document.getElementById('registerBtn').addEventListener('click', function() {
            loginModal.style.display = 'block';
            document.getElementById('registerForm').style.display = 'block';
            document.getElementById('loginForm').style.display = 'none';
            if(document.querySelector('.modal-header h3')?.textContent === '用户登录') {
                document.querySelector('.modal-header h3').textContent = '用户注册';
                lorMessage = document.getElementById('registerMessage');
            }
        });
    }
}

// 退出登录
function logout() {
    //contentDiv.innerHTML = '<p>请登录查看个性化内容</p>';
    apiRequest('php/loginsystem/logout.php', 'POST');
    updateAuthButtons(false);
}
