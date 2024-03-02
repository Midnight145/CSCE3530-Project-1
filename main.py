import json
import typing

from fastapi import FastAPI

import util

app = FastAPI()

GeneratedRSAKey: typing.TypeAlias = dict[str, str]  # Type alias for the generated RSA key for readability
GeneratedJWK: typing.TypeAlias = dict[str, str]  # Type alias for the generated JWK for readability

keys: list[GeneratedRSAKey] = []  # List to store the JWK keys

@app.post("/auth")
async def auth(expired: bool = False) -> GeneratedJWK:
    """
    Authentication endpoint, generates a JWT token
    :param expired: Whether the key should be expired
    :return: The created JWT
    """

    key, token = util.generate_jwt(pubkey, privkey, expired)  # generate the JWT token
    if key:
        keys.append(json.loads(key.export()))

    return {"jwt": token.serialize()}


@app.get("/.well-known/jwks.json")  # for now we don't *need* to store the keys, we can generate them on the fly
def get_jwks() -> dict[str, list[GeneratedRSAKey]]:
    """
    jwks endpoint
    :return: The list of valid keys
    """
    return {"keys": keys}


pubkey, privkey = util.init_keys()  # generate the keys on startup

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8080, reload=True)