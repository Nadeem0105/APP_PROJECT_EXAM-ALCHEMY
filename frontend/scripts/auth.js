document.addEventListener("DOMContentLoaded", function() {
    
    // --- State Variable ---
    let selectedRole = 'student'; // 'student' or 'teacher'

    // --- Element Selectors ---
    const roleStudentBtn = document.getElementById('role-student');
    const roleTeacherBtn = document.getElementById('role-teacher');
    
    const tabs = document.querySelectorAll('.tabs-trigger');
    const tabContents = document.querySelectorAll('.tabs-content');
    
    const loginForm = document.getElementById('login-form');
    const loginButton = document.getElementById('login-button');
    
    const signupForm = document.getElementById('signup-form');
    const signupButton = document.getElementById('signup-button');

    // --- Role Toggle Logic ---
    function setRole(role) {
        selectedRole = role;
        // Ensure buttons exist before trying to modify classes
        if (roleStudentBtn && roleTeacherBtn) {
            if (role === 'student') {
                roleStudentBtn.classList.replace('btn-outline', 'btn-primary');
                roleTeacherBtn.classList.replace('btn-primary', 'btn-outline');
            } else {
                roleTeacherBtn.classList.replace('btn-outline', 'btn-primary');
                roleStudentBtn.classList.replace('btn-primary', 'btn-outline');
            }
        }
    }

    // Add null checks in case elements don't exist
    if(roleStudentBtn) roleStudentBtn.addEventListener('click', () => setRole('student'));
    if(roleTeacherBtn) roleTeacherBtn.addEventListener('click', () => setRole('teacher'));

    // --- Tab Switching Logic ---
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs and content
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Add active class to clicked tab and its content
            tab.classList.add('active');
            const tabContentId = tab.dataset.tab + '-tab';
            const contentElement = document.getElementById(tabContentId);
            if (contentElement) { // Add null check
                contentElement.classList.add('active');
            }
        });
    });

    // --- Login Form Logic ---
    if (loginForm) {
        loginForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            
            // Add null check for button
            if (loginButton) {
                loginButton.disabled = true;
                loginButton.textContent = 'Signing In...';
            }


            const emailInput = document.getElementById('login-email');
            const passwordInput = document.getElementById('login-password');
            
            // Add null checks for inputs
            if (!emailInput || !passwordInput) {
                 console.error("Login form inputs not found!");
                 if (loginButton) {
                     loginButton.disabled = false;
                     loginButton.textContent = 'Sign In';
                 }
                 return; // Stop if inputs are missing
            }

            const email = emailInput.value;
            const password = passwordInput.value;


            try {
                // Check if loginUser function exists before calling
                if (typeof loginUser !== 'function') {
                    throw new Error("loginUser function is not loaded correctly. Check api.js.");
                }

                const data = await loginUser(email, password); // From api.js
                
                if (data.token) {
                    localStorage.setItem('authToken', data.token);
                }
                
                alert('Login successful! Redirecting to dashboard...');
                
                // Redirect to the correct dashboard based on role
                if (selectedRole === 'teacher') {
                    window.location.href = 'dashboard.html'; // Or teacher-dashboard.html
                } else {
                    window.location.href = 'student.html'; // Or student-dashboard.html
                }

            } catch (error) {
                console.error('Login Error:', error);
                alert('Login failed: ' + error.message);
                 if (loginButton) { // Add null check
                    loginButton.disabled = false;
                    loginButton.textContent = 'Sign In';
                }
            }
        });
    }

    // --- Sign Up Form Logic ---
    if (signupForm) {
        signupForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            // Add null check
            if(signupButton){
                signupButton.disabled = true;
                signupButton.textContent = 'Creating...';
            }


            const usernameInput = document.getElementById('signup-name');
            const emailInput = document.getElementById('signup-email');
            const passwordInput = document.getElementById('signup-password');

            // Add null checks for inputs
            if (!usernameInput || !emailInput || !passwordInput) {
                console.error("Signup form inputs not found!");
                 if (signupButton) {
                    signupButton.disabled = false;
                    signupButton.textContent = 'Create Account';
                 }
                return; // Stop if inputs are missing
            }

            const username = usernameInput.value;
            const email = emailInput.value;
            const password = passwordInput.value;

            
            // Format roles for the backend
            const roles = new Set();
            if (selectedRole === 'teacher') {
                roles.add('TEACHER');
            } else {
                roles.add('STUDENT');
            }

            try {
                 // Check if registerUser function exists before calling
                if (typeof registerUser !== 'function') {
                    throw new Error("registerUser function is not loaded correctly. Check api.js.");
                }

                const data = await registerUser(username, email, password, roles); // From api.js
                
                alert('Registration successful! Please log in.');
                
                // Switch to the login tab automatically
                const loginTabTrigger = document.querySelector('.tabs-trigger[data-tab="login"]');
                if(loginTabTrigger) loginTabTrigger.click(); // Add null check

                // Optionally pre-fill email
                const loginEmailInput = document.getElementById('login-email');
                 if(loginEmailInput) loginEmailInput.value = email; // Add null check


            } catch (error) {
                console.error('Sign Up Error:', error);
                alert('Registration failed: ' + error.message);
            } finally {
                 if(signupButton){ // Add null check
                    signupButton.disabled = false;
                    signupButton.textContent = 'Create Account';
                 }
            }
        });
    }
});

