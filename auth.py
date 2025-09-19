from authx import AuthX, AuthXConfig
from jose import jwt

class Authentication:

    def __init__(self):
        config = AuthXConfig()
        config.JWT_SECRET_KEY = 'verysecretkatthatnobodyknows'
        config.JWT_TOKEN_LOCATION = ['cookies']
        config.JWT_COOKIE_CSRF_PROTECT = False

        self.config = config
        self.auth = AuthX(config)

    def decode_token(self, token: str) -> dict:
        try:
            return jwt.decode(token=token, key=self.config.JWT_SECRET_KEY, algorithms='HS256')
        except:
            return dict()
    
    def get_uid_from_token(self, token: str) -> str | None:
        try:
            payload = self.decode_token(token=token)
            uid = payload.get('sub')
            
            return uid
        except:
            print(f'Token {token} is not valid')
            return None
    
    def validate_token(self, token: str) -> bool:
        uid = self.get_uid_from_token(token=token)
        return uid is not None
    
authentication = Authentication()