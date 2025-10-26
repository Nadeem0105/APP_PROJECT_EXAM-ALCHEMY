/**
 * Attempts to log in a user.
 * @param {string} email - The user's email.
 * @param {string} password - The user's password.
 * @returns {Promise<object>} - The JSON response from the server.
 */
async function loginUser(email, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    });

    if (!response.ok) {
        // Check if the response is JSON or just text
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Login failed');
        } else {
            const errorText = await response.text();
            throw new Error(errorText || 'Login failed');
        }
    }
    return response.json();
}

/**
 * Attempts to register a new user.
 * @param {string} username
 * @param {string} email
 * @param {string} password
 * @param {Set<string>} roles
 * @returns {Promise<object>}
 */
async function registerUser(username, email, password, roles) {
    const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            email: email,
            password: password,
            roles: Array.from(roles) // Send roles as an array
        })
    });

    if (!response.ok) {
        // Check if the response is JSON or just text
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Registration failed');
        } else {
            const errorText = await response.text();
            throw new Error(errorText || 'Registration failed');
        }
    }
    
    // If successful, the backend now sends JSON for success too
    return response.json();
}

