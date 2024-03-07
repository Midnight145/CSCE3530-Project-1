from fastapi import FastAPI
from jwcrypto import jwk

import util

app = FastAPI()


@app.post("/auth")
async def auth(request: util.AuthRequest, expired: bool = False) -> dict[str, str]:
    """
    Authentication endpoint, generates a JWT token
    :param request: The request object containing the username and password
    :param expired: Whether the key should be expired
    :return: The created JWT
    """
    key, token = util.generate_jwt_pair(request, expired)  # generate the JWT token

    return {"jwt": token.serialize()}


@app.get("/.well-known/jwks.json")  # for now, we don't *need* to store the keys, we can generate them on the fly
def get_jwks() -> dict[str, list[jwk.JWK]]:
    """
    jwks endpoint
    :return: The list of valid keys
    """
    return {"keys": util.get_jwks()}


util.init()  # initialize the database and generate dummy keys

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="localhost", port=8080, reload=True)
