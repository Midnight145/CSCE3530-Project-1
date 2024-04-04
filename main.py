import http
import time

from fastapi import FastAPI, Response, Request
from jwcrypto import jwk
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

import util

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
# noinspection PyTypeChecker
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.post("/auth")
@limiter.limit("10/second")
async def auth(auth_reqeust: util.AuthRequest, request: Request, response: Response, expired: bool = False) -> dict[str, str]:
    """
    Authentication endpoint, generates a JWT token
    :param auth_reqeust: The request object containing the username and password
    :param expired: Whether the key should be expired
    :return: The created JWT
    """
    time_ = time.time()
    key, token = util.generate_jwt_pair(auth_reqeust, expired)  # generate the JWT token
    print(f"Time taken to generate token: {time.time() - time_}")
    time_ = time.time()
    util.authenticate(request, auth_reqeust)
    print(f"Time taken to authenticate request: {time.time() - time_}")

    return {"jwt": token.serialize()}


@app.get("/.well-known/jwks.json")  # for now, we don't *need* to store the keys, we can generate them on the fly
def get_jwks() -> dict[str, list[jwk.JWK]]:
    """
    jwks endpoint
    :return: The list of valid keys
    """
    return {"keys": util.get_jwks()}


@app.post("/register")
async def register(request: util.RegistrationRequest, response: Response) -> dict[str, str]:
    """
    Register a new user
    :param request: The request object containing the username and email
    :param response: The fastapi.Response object to set the status code
    :return: The user's password
    """
    try:
        password = util.register_user(request)
    except ValueError as e:
        response.status_code = http.HTTPStatus.BAD_REQUEST
        return {"error": str(e)}
    except Exception as e:
        response.status_code = http.HTTPStatus.INTERNAL_SERVER_ERROR
        return {"error": str(e)}
    response.status_code = http.HTTPStatus.CREATED
    return {"password": password}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8080, reload=False)
