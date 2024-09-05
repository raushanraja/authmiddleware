from starlette.datastructures import Headers
import jwt

def decode_token(token, scope):
    if token:
        try:
            claims = jwt.decode(token, 'secret', algorithms=['HS256'])
            scope['user'] = claims
        except jwt.ExpiredSignatureError:
            scope['user'] = None
    else:
        scope['user'] = None


class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Get the token from the request headers
        headers = Headers(scope=scope)
        token = headers.get('authorization', '')
        if token.startswith('Bearer '):
            token = token[7:]
        else:
            token = None

        print(f"Token: {token}")

        # Validate the decode_token
        # decode_token(token, scope)

        # Call the next middleware
        await self.app(scope, receive, send)
