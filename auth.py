from authx import AuthX, AuthXConfig
from jose import jwt

config = AuthXConfig()
config.JWT_SECRET_KEY = 'verysecretkeythatnobodyknow'
config.JWT_TOKEN_LOCATION = ['cookies']
config.JWT_COOKIE_CSRF_PROTECT = False

auth = AuthX(config)

def decode_token(token: str) -> dict:
    return jwt.decode(token, config.JWT_SECRET_KEY, 'HS256')

def is_token_valid(token: str) -> bool:
    try:
        payload = decode_token(token)
        uid = payload.get('sub')
        if uid is None:
            return False
        return True
    except:
        print('Token is not valid')
        return False

def get_uid_from_token(token: str) -> str | None:
    try:
        payload = decode_token(token)
        uid = payload.get('sub')
        return uid
    except:
        print('Token is not valid')
        return None