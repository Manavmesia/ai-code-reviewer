from flask_login import current_user
from functools import wraps
from flask import abort

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return fn(*args, **kwargs)
        return decorated
    return wrapper
