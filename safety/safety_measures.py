from flask import request, abort
import re
from functools import wraps

def validate_input(input_data, pattern):
    if not re.match(pattern, input_data):
        abort(400, description="Invalid input format")

def prevent_xss(input_data):
    # A simple example of escaping HTML characters
    return input_data.replace("<", "&lt;").replace(">", "&gt;")

def csrf_protect():
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token")
            if not token or token != session.get("csrf_token"):
                abort(403, description="CSRF token missing or incorrect")
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = generate_random_token()
    return session["_csrf_token"]

def generate_random_token(length=32):
    return os.urandom(length).hex()