from starlette.responses import JSONResponse, RedirectResponse
from starlette.datastructures import Headers, URL, QueryParams
from fastapi import Request
import jwt

AUTHORIZE_URL = "http://localhost:8089/authorize"
CLIENT_ID = "raushan"
CLIENT_SECRET = "client_secret"
REDIRECT_URI = "http://localhost:8090/auth/callback"
RESPONSE_TYPE = "code"


def validate_token(token):
    if token:
        try:
            claims = jwt.decode(token, "secret", algorithms=["HS256"])
            return claims
        except jwt.ExpiredSignatureError:
            return None


def decode_token(token, scope):
    print(f"Token: {token}")
    if token:
        try:
            claims = jwt.decode(token, "secret", algorithms=["HS256"])
            scope["user"] = claims
        except jwt.ExpiredSignatureError:
            print("Token expired")
            scope["user"] = None
        except jwt.InvalidSignatureError:
            print("Invalid signature")
            scope["user"] = None
        except jwt.InvalidTokenError:
            scope["user"] = None
    else:
        scope["user"] = None

    return scope


class AuthMiddleware:
    def __init__(self, app, get_token):
        self.app = app
        self.get_token = get_token

    async def callback(self, scope, receive, send):
        # Get the code from the request query params
        query_params = QueryParams(scope["query_string"])
        code = query_params.get("code")
        client_id = query_params.get("client_id")
        if code:
            print(f"Code: {code} Client ID: {client_id}")
            # Call the token endpoint to get the token
            token = await self.get_token(code, "raushan")

            print(f"Token: {token}")

            # Redirect to the home page
            response = RedirectResponse(url="/", status_code=302)
            response.set_cookie("token", "Bearer " + token)
            await response(scope, receive, send)
            return
        response = JSONResponse({"status:": "error", "message": "Invalid code"})
        await response(scope, receive, send)
        return

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/auth/callback":
            await self.callback(scope, receive, send)
            return

        # Get the token from the request headers
        request = Request(scope=scope)
        token = request.cookies.get("token", "")
        if token:
            print("Token from cookie found \n\n")

        print(f"request: {request}")
        print(f"request: {request.cookies}")
        print(f"Token: {token}")
        if not token.startswith("Bearer"):
            url = f"{AUTHORIZE_URL}?client_id=raushan&client_secret={CLIENT_SECRET}"
            url += f"&redirect_uri={REDIRECT_URI}&response_type={RESPONSE_TYPE}"
            response = RedirectResponse(url=url, status_code=302)
            await response(scope, receive, send)
            return

        # Validate the decode_token
        token = token.split(" ")[1]
        decode_token(token, scope)

        # Call the next middleware
        await self.app(scope, receive, send)
