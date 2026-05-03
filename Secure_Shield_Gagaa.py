import json
import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)

# Better practice: load from environment variable in production
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "change_this_in_production")

bcrypt = Bcrypt(app)

# Defensive logging
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DB_FILE = 'users.json'
BLACKLIST_FILE = 'blacklist.json'


def load_data(file_path, default_type=dict):
    if not os.path.exists(file_path):
        return default_type()

    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return default_type()


def save_data(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)


def token_required(allowed_roles=None):
    if allowed_roles is None:
        allowed_roles = ["User", "Admin"]

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                return jsonify({'message': 'Token is missing!'}), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0] != "Bearer":
                return jsonify({'message': 'Invalid authorization format!'}), 401

            token = parts[1]

            blacklist = load_data(BLACKLIST_FILE, list)
            if token in blacklist:
                return jsonify({'message': 'Token has been revoked.'}), 401

            try:
                data = jwt.decode(
                    token,
                    app.config['SECRET_KEY'],
                    algorithms=["HS256"]
                )

                current_user_role = data.get("role")
                current_username = data.get("username")

                if current_user_role not in allowed_roles:
                    logging.warning(
                        f"User '{current_username}' attempted restricted access."
                    )
                    return jsonify({
                        'message': 'Access denied: insufficient permissions.'
                    }), 403

            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 401

            return f(data, *args, **kwargs)

        return decorated
    return decorator


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Request body required'}), 400

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "User")

    if not username or not password:
        return jsonify({
            'message': 'Username and password are required'
        }), 400

    users = load_data(DB_FILE, dict)

    if username in users:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    users[username] = {
        "password": hashed_password,
        "role": role
    }

    save_data(users, DB_FILE)

    return jsonify({
        'message': 'User registered successfully'
    }), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Request body required'}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            'message': 'Username and password required'
        }), 400

    users = load_data(DB_FILE, dict)
    user = users.get(username)

    if user and bcrypt.check_password_hash(user["password"], password):
        token = jwt.encode({
            "username": username,
            "role": user["role"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }, app.config["SECRET_KEY"], algorithm="HS256")

        return jsonify({"token": token}), 200

    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/logout', methods=['POST'])
@token_required()
def logout(current_user_data):
    auth_header = request.headers.get("Authorization")
    token = auth_header.split()[1]

    blacklist = load_data(BLACKLIST_FILE, list)

    if token not in blacklist:
        blacklist.append(token)
        save_data(blacklist, BLACKLIST_FILE)

    return jsonify({
        'message': 'Successfully logged out.'
    }), 200


@app.route('/profile', methods=['GET'])
@token_required(["User", "Admin"])
def get_profile(current_user_data):
    return jsonify({
        'message': f"Hello {current_user_data['username']}, role: {current_user_data['role']}"
    }), 200


@app.route('/user/<user_id>', methods=['DELETE'])
@token_required(["Admin"])
def delete_user(current_user_data, user_id):
    users = load_data(DB_FILE, dict)

    if user_id not in users:
        return jsonify({'message': 'User not found'}), 404

    del users[user_id]
    save_data(users, DB_FILE)

    return jsonify({
        'message': f"User '{user_id}' deleted by admin '{current_user_data['username']}'."
    }), 200


if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        save_data({}, DB_FILE)

    if not os.path.exists(BLACKLIST_FILE):
        save_data([], BLACKLIST_FILE)

    app.run(debug=True)
