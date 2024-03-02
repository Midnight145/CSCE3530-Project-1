import datetime
import json
import os
import typing
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwcrypto import jwk, jwt

app = FastAPI()
keys = []  # List to store the JWK keys
pubkey: rsa.RSAPublicKey  # RSA public key
privkey: rsa.RSAPrivateKey  # RSA private key

GeneratedRSAKey: typing.TypeAlias = dict[str, str]  # Type alias for the generated RSA key for readability
GeneratedJWK: typing.TypeAlias = dict[str, str]  # Type alias for the generated JWK for readability


def init_keys() -> (rsa.RSAPublicKey, rsa.RSAPrivateKey):
    """
    Initialize the RSA keys on startup, creating them if necessary
    :return: Tuple of the public and private key objects
    """
    if os.path.exists('private.pem') and os.path.exists('public.pem'):
        with open('public.pem', 'rb') as f:
            public = serialization.load_pem_public_key(f.read())
        with open('private.pem', 'rb') as f:
            private = serialization.load_pem_private_key(f.read(), password=None)
        return public, private
    else:
        return create_keys()  # keys don't exist, create them


def create_keys() -> (rsa.RSAPublicKey, rsa.RSAPrivateKey):
    """
    Create the RSA keys if they don't exist on disk
    :return: Tuple of the public and private key objects
    """
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public = private.public_key()

    with open('private.pem', 'wb+') as f:
        f.write(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open('public.pem', 'wb+') as f:
        f.write(
            public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    return public, private


def generate_rsa_key(kid: str) -> jwk.JWK:
    """
    Generate a new RSA key and add it to the list of valid keys
    :param kid: Key ID to use for the new key
    :return: The created JWK
    """
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk_key = jwk.JWK.from_pem(pem)
    jwk_key.kid = kid  # assign the key ID to the JWK key
    keys.append(json.loads(jwk_key.export()))  # add the key to the list
    return jwk_key


@app.post("/auth")
async def auth(expired: bool = False) -> GeneratedJWK:
    """
    Authentication endpoint, generates a JWT token
    :param expired: Whether the key should be expired
    :return: The created JWT
    """
    kid = str(uuid4())
    if not expired:
        jwk_key = generate_rsa_key(kid)  # generate a new key, add to the list

    # offset used to set the expiration time +/- 30 minutes
    offset = 30 * 60 if not expired else -30 * 60

    header = {
        "alg": "RS256",
        "kid": kid
    }
    claims = {
        "sub": "example_user",
        "kid": kid,
        # i can just add offset to change expiry instead of playing with timedeltas
        "exp": datetime.datetime.now().timestamp() + offset
    }

    token = jwt.JWT(header=header, claims=claims)

    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    jwk_privkey = jwk.JWK.from_pem(pem)

    token.make_signed_token(jwk_privkey)  # actually sign the token

    return {"jwt": token.serialize()}


@app.get("/.well-known/jwks.json")  # for now we don't *need* to store the keys, we can generate them on the fly
def get_jwks() -> dict[str, list[GeneratedRSAKey]]:
    """
    jwks endpoint
    :return: The list of valid keys
    """
    return {"keys": keys}


pubkey, privkey = init_keys()  # generate the keys on startup
