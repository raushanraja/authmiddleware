from collections.abc import Callable
from dataclasses import dataclass

import jwt
from fastapi import Request
from starlette.datastructures import QueryParams
from starlette.responses import JSONResponse, RedirectResponse


@dataclass
class Config:
    authorize_url: str
    unauthorized_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    response_type: str
    algorithms: list[str]
    secret_key: str
    audience: str
    issuer: str


class AuthMiddleware:
    def __init__(self, app, get_token: Callable, config: Config):
        self.app = app
        self.get_token = get_token
        self.config = config

    async def callback(self, scope, receive, send):
        # Get the code from the request query params
        query_params = QueryParams(scope["query_string"])
        code = query_params.get("code")
        client_id = query_params.get("client_id")
        if code:
            print(f"Code: {code} Client ID: {client_id}")
            # Call the token endpoint to get the token
            token = await self.get_token(code, self.config.client_id)

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
        try:
            if scope["type"] == "http" and scope["path"] == "/auth/callback":
                await self.callback(scope, receive, send)
                return

            # Get the token from the request headers
            request = Request(scope=scope)
            token = request.cookies.get("token", "").strip()

            if not token.startswith("Bearer"):
                url = f"{self.config.authorize_url}?client_id={self.config.client_id}&client_secret={self.config.client_secret}"
                url += f"&redirect_uri={self.config.redirect_uri}&response_type={self.config.response_type}"
                response = RedirectResponse(url=url, status_code=302)
                await response(scope, receive, send)
                return

            # Validate the decode_token
            token = token.split(" ")[1]
            self.decode_token(token, scope)

            # Call the next middleware
            await self.app(scope, receive, send)

        except Exception as e:
            print(f"Error: {e}")
            response = RedirectResponse(
                url=self.config.unauthorized_url, status_code=302
            )
            await response(scope, receive, send)
            return

    def decode_token(self, token, scope):
        print(f"Token: {token}")
        print(f"Secret Key: {self.config.secret_key}")
        print(f"Algorithms: {self.config.algorithms}")
        if token:
            claims = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=self.config.algorithms,
                audience=self.config.audience,
                issuer=self.config.issuer,
            )
            scope["user"] = claims
        else:
            raise Exception("Invalid token")
