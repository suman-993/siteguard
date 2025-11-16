# target_app.py
# This is the simple "real" web application we want to protect.
# It will run on port 8080 and should NOT be exposed publicly.
# Only our 'siteguard_app.py' WAF will talk to this.

from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

# A simple login form template
LOGIN_PAGE = """
<html>
<head>
    <title>Target App Login</title>
    <style>
        body { font-family: sans-serif; display: grid; place-items: center; min-height: 80vh; background-color: #f4f4f4; }
        form { background: #fff; border: 1px solid #ccc; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        div { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 300px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <form action="/login" method="POST">
        <h2>Target App Login</h2>
        <div>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username">
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
        </div>
        <button type="submit">Login</button>
        <p><small>Hint: admin / password123</small></p>
    </form>
</body>
</html>
"""

@app.route('/')
def home():
    """ The main homepage. """
    return '<h1>Welcome to the Target App!</h1><p>This is the application being protected by Siteguard.</p><a href="/login">Login</a> | <a href="/secret">Secret Page</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ A login page. """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # This is our "secure" login logic
        if username == 'admin' and password == 'password123':
            # On success, send a success message.
            resp = make_response('<h1>Login Successful!</h1><p>Welcome, admin.</p><a href="/">Home</a>', 200)
            return resp
        else:
            # On failure, return a 401 Unauthorized status.
            # Our WAF will be watching for this status code!
            resp = make_response('<h1>Login Failed.</h1><p>Incorrect username or password.</p>' + LOGIN_PAGE, 401)
            return resp
            
    # For GET request, just show the login form
    return render_template_string(LOGIN_PAGE)

@app.route('/secret')
def secret():
    """ A "protected" page. """
    return '<h1>This is the Secret Page</h1><p>You should only see this.</p>'

if __name__ == '__main__':
    # Run this app on port 8080.
    # Our WAF will run on 5000 and forward requests here.
    print("Starting Target App on http://127.0.0.1:8080")
    app.run(debug=True, port=8080, host='127.0.0.1')