from flask import request
from flask_restx import abort
import jwt
from constants import JWT_ALGORITHM, JWT_SECRET


def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)
            # role = user.get("role")
            # if role != "admin":
            # abort(400)
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            user = jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)
            role = user.get("role")
            if role != "admin":
                abort(400)
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper
