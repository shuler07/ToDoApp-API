from authx import AuthX, AuthXConfig


class Authentication:

    def __init__(self):
        config = AuthXConfig()
        config.JWT_SECRET_KEY = "verysecretkatthatnobodyknows"
        config.JWT_TOKEN_LOCATION = ["cookies"]
        config.JWT_COOKIE_CSRF_PROTECT = False

        self.config = config
        self.auth = AuthX(config)


authentication = Authentication()
