document.addEventListener('DOMContentLoaded', () => {
    const loginModal = document.getElementById('loginModal');
    const closeBtn = document.querySelector('.close-btn');
    const loginForm = document.getElementById('loginForm');
    const loginMessage = document.getElementById('loginMessage');
    const contentDiv = document.getElementById('content');
    const authButtons = document.getElementById('authButtons');
    let isMouseDownInsideModal = false;

    authButtons.innerHTML = '<div class="loading-spinner"></div>';
    authButtons.hidden = false;

    // 通用AJAX请求函数
    const apiRequest = async (url, method, data) => {
        try {
	    const csrfToken = sessionStorage.getItem('csrf_token');
            const response = await fetch(url, {
                method,
                headers: {
		    'Content-Type': 'application/json',
		    'X-CSRF-Token': csrfToken
		},
                body: JSON.stringify(data),
		credentials: 'include'
            });
            return await response.json();
        } catch (error) {
            console.error('请求失败:', error);
            return { success: false, message: '网络错误' };
        }
    };

    fetchCSRFToken();

    // 显示留言
    const loadMessages = async () => {
        const messages = await apiRequest('php/get_messages.php', 'GET');
        const container = document.getElementById('messages');
        container.innerHTML = messages.map(msg => `
            <div class="message">
                <h4>${msg.username}</h4>
                <p>${msg.content}</p>
                <small>${new Date(msg.created_at).toLocaleString()}</small>
            </div>
        `).join('');
    };

    // 初始化主页
    if (document.getElementById('messages')) {
        loadMessages();
        //setInterval(loadMessages, 30000);

        // 检查登录状态
        apiRequest('php/get_user.php', 'GET').then(data => {
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
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
        };

        // 验证用户
	const result = await apiRequest('php/login.php', 'POST', formData);
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

    // 显示消息函数
    function showMessage(message, type) {
        loginMessage.textContent = message;
        loginMessage.className = 'message ' + type;
    }
 
    // 重置登录表单
    function resetLoginForm() {
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
            });
            document.getElementById('registerBtn').addEventListener('click', function() {
                alert('注册功能即将推出！');
            });
        }
    }

    // 退出登录
    function logout() {
        //contentDiv.innerHTML = '<p>请登录查看个性化内容</p>';
	apiRequest('php/logout.php', 'POST');
        updateAuthButtons(false);
	fetchCSRFToken();
    }
    
    // Get CSRF Token
    async function fetchCSRFToken() {
        try {
            const result = await apiRequest('php/csrf.php', 'GET');
            console.log(result);
            if (result.success) {
	        sessionStorage.setItem('csrf_token', result.token);
                return result.token;
            } else {
                throw new Error('无法获取CSRF令牌');
            }
        } catch (error) {
            console.error('获取CSRF令牌失败', error);
            throw error;
        }
    }

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
    const content = document.getElementById('messageContent').value;
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

function showMessage(text, isSuccess) {
    const msgDiv = document.getElementById('message');
    msgDiv.textContent = text;
    msgDiv.className = isSuccess ? 'success' : 'error';
    setTimeout(() => msgDiv.textContent = '', 3000);
}
