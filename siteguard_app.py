# siteguard_app.py
# This is the main WAF and Reverse Proxy.
# It listens on port 5000, intercepts all requests,
# analyzes them, and then forwards them to the TARGET_APP.

from flask import Flask, request, abort, jsonify, render_template, make_response
import requests
import time
import datetime
from collections import defaultdict
import database  # Our database helper

app = Flask(__name__, template_folder='.')
# --- Configuration ---
# The URL of the "real" app we are protecting
TARGET_APP_URL = "http://127.0.0.1:8080" 

# --- Detection Thresholds ---
# Rate Limiting (DoS)
RATE_LIMIT_REQUESTS = 20  # Max requests
RATE_LIMIT_WINDOW = 10    # Per X seconds

# Brute Force
BRUTE_FORCE_ATTEMPTS = 5   # Max failed logins
BRUTE_FORCE_WINDOW = 300   # Per X seconds (5 minutes)

# Directory Scan
DIR_SCAN_404S = 10         # Max 404s
DIR_SCAN_WINDOW = 60       # Per X seconds (1 minute)

# --- Block Duration ---
BLOCK_DURATION_MINUTES = 10

# --- In-Memory Request Trackers ---
# These are simple dictionaries to track IPs.
# In a production app, you would use a persistent store like Redis.
# { 'ip_address': [timestamp1, timestamp2, ...] }
ip_request_tracker = defaultdict(list)
ip_failed_login_tracker = defaultdict(list)
ip_404_tracker = defaultdict(list)


@app.before_request
def siteguard_analysis():
    """
    This function runs before EVERY request.
    This is the core of our WAF logic.
    """
    # Get the user's IP
    ip = request.remote_addr
    
    # Don't block requests to our own dashboard
    if request.path.startswith('/siteguard_dashboard'):
        return None # Let the request proceed

    # --- 1. Check if IP is already blocked ---
    if database.is_ip_blocked(ip):
        # If blocked, stop the request immediately
        abort(403, "Your IP address has been temporarily blocked due to suspicious activity.")

    # --- 2. Rate Limiting (DoS Detection) ---
    current_time = time.time()
    request_times = ip_request_tracker[ip]
    
    # Keep only requests within the time window
    valid_request_times = [t for t in request_times if current_time - t < RATE_LIMIT_WINDOW]
    
    if len(valid_request_times) > RATE_LIMIT_REQUESTS:
        # Too many requests! Block them.
        database.block_ip(ip, "Rate Limit (DoS)", BLOCK_DURATION_MINUTES)
        ip_request_tracker[ip] = [] # Clear tracker after blocking
        abort(403, "Rate limit exceeded. Your IP is blocked.")
    
    # Log this request time
    valid_request_times.append(current_time)
    ip_request_tracker[ip] = valid_request_times
    
    return None # All checks passed, proceed to the proxy route


@app.after_request
def siteguard_response_analysis(response):
    """
    This function runs after a response is generated
    but before it's sent to the client.
    We use it to check for failed logins and 404s.
    """
    ip = request.remote_addr
    path = request.path
    
    # Don't analyze our own dashboard routes
    if path.startswith('/siteguard_dashboard'):
        return response

    current_time = time.time()

    # --- 3. Brute Force Detection (Failed Logins) ---
    # We check if the request was a POST to /login and if it failed (401 status)
    if path == '/login' and request.method == 'POST' and response.status_code == 401:
        login_times = ip_failed_login_tracker[ip]
        valid_login_times = [t for t in login_times if current_time - t < BRUTE_FORCE_WINDOW]
        
        if len(valid_login_times) > BRUTE_FORCE_ATTEMPTS:
            database.block_ip(ip, "Brute Force", BLOCK_DURATION_MINUTES)
            ip_failed_login_tracker[ip] = [] # Clear tracker
            abort(403, "Too many failed login attempts. Your IP is blocked.")
            
        valid_login_times.append(current_time)
        ip_failed_login_tracker[ip] = valid_login_times
        
        # Log this specific failed attempt
        database.log_suspicious_activity(ip, "Failed Login", path)

    # --- 4. Directory/Port Scan Detection (404s) ---
    if response.status_code == 404:
        scan_times = ip_404_tracker[ip]
        valid_scan_times = [t for t in scan_times if current_time - t < DIR_SCAN_WINDOW]
        
        if len(valid_scan_times) > DIR_SCAN_404S:
            database.block_ip(ip, "Directory Scan (404s)", BLOCK_DURATION_MINUTES)
            ip_404_tracker[ip] = [] # Clear tracker
            abort(403, "Too many 404s (Not Found). Your IP is blocked.")
        
        valid_scan_times.append(current_time)
        ip_404_tracker[ip] = valid_scan_times

        # Log this specific 404
        database.log_suspicious_activity(ip, "Page Not Found (404)", path)

    return response


@app.route('/siteguard_dashboard')
def dashboard():
    """
    Serves the main dashboard HTML page.
    """
    return render_template('index.html')

@app.route('/siteguard_dashboard/data')
def dashboard_data():
    """
    Provides data to the dashboard's JavaScript.
    """
    data = database.get_dashboard_data()
    return jsonify(data)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """
    This is the core reverse proxy. It catches ALL other requests
    and forwards them to the target app.
    """
    try:
        # Combine the target URL with the requested path
        url = f"{TARGET_APP_URL}/{path}"
        
        # --- Forward the request ---
        headers = {key: value for (key, value) in request.headers if key != 'Host'}
        # Ensure the 'Host' header matches the target app
        headers['Host'] = TARGET_APP_URL.replace('http://', '').replace('https://', '')
        
        data = request.get_data()
        
        # Make the corresponding request to the target app
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            params=request.args,
            cookies=request.cookies,
            allow_redirects=False # We handle redirects manually
        )

        # --- Process the response ---
        # Exclude certain headers that can cause issues
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [
            (name, value) for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]

        # Create a new Flask response
        response = make_response(resp.content, resp.status_code, resp_headers)
        return response

    except requests.exceptions.ConnectionError:
        # This happens if the target_app.py is not running
        return "<h1>Error: Cannot connect to target application.</h1><p>Is `target_app.py` running on port 8080?</p>", 503
    except Exception as e:
        print(f"Proxy Error: {e}")
        return "<h1>Internal Proxy Error</h1>", 500


if __name__ == '__main__':
    print(f"Starting Siteguard WAF on http://127.0.0.1:5000")
    print(f"Protecting Target App at {TARGET_APP_URL}")
    app.run(debug=True, port=5000, host='127.0.0.1')