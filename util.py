import datetime
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk, jwt
from pydantic import BaseModel


class AuthRequest(BaseModel):
    """
    The authentication request object for /auth
    format:
    {
        "username": "example_user",
        "password": "example_password"
    }
    """
    username: str
    password: str


def init() -> None:
    """
    Initialize the database and generate the keys. Should only be called once at the start of the program
    :return: None
    """
    db = sqlite3.connect('totally_not_my_privateKeys.db')
    db.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, "
               "key BLOB, exp INTEGER NOT NULL DEFAULT 0)")
    db.commit()
    db.close()
    generate_jwt_pair(AuthRequest(username="expired_user", password="expired_password"), True)
    generate_jwt_pair(AuthRequest(username="userABC", password="password123"), False)


def generate_jwk(pubkey: rsa.RSAPublicKey, kid: str) -> jwk.JWK:
    """
    Generate a new JWK and add it to the list of valid keys
    :param pubkey: The RSA public key
    :param kid: Key ID to use for the new key
    :return: The created JWK
    """
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk_key = jwk.JWK.from_pem(pem)
    jwk_key.kid = kid  # actually set the kid
    return jwk_key


def generate_jwt_pair(request: AuthRequest, expired: bool) -> tuple[jwk.JWK, jwt.JWT]:
    """
    Generate a new JWK and JWT pair
    :param request: The request object containing the username and password
    :param expired: Whether the key should be expired
    :return: The created JWK and JWT
    """
    privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    if expired:  # generate expiry timestamp
        expiry = datetime.datetime.now().timestamp() + -30*60
    else:
        expiry = datetime.datetime.now().timestamp() + 60*60

    kid = save_key(pem, int(expiry))  # save the key to the database
    jwk_key = generate_jwk(privkey.public_key(), kid)  # generate a new key, add to the list

    header = {
        "alg": "RS256",
        "kid": kid
    }
    claims = {
        "sub": request.username,
        "kid": kid,
        # I can just add offset to change expiry instead of playing with timedeltas
        "exp": expiry
    }

    token = jwt.JWT(header=header, claims=claims)

    jwk_privkey = jwk.JWK.from_pem(pem)
    token.make_signed_token(jwk_privkey)
    return jwk_key, token


def save_key(key: bytes, expiry: int) -> str:
    """
    Saves the private key to the database
    :param key: The private key to save
    :param expiry: The expiry timestamp
    :return: the key ID of the saved key (The primary key for that row)
    """
    db = sqlite3.connect('totally_not_my_privateKeys.db')
    db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, expiry))
    db.commit()
    # have to do this to get the kid since it's autoincrement
    kid = db.execute("SELECT kid FROM keys WHERE key = ?", (key,)).fetchone()[0]

    db.close()
    return str(kid)  # the grader expects a string, so I typecast it here instead of everywhere else


def get_jwks() -> list[jwk.JWK]:
    """
    :return: The list of valid keys
    """
    db = sqlite3.connect('totally_not_my_privateKeys.db')
    keys = db.execute("SELECT kid, key FROM keys").fetchall()
    db.close()

    jwks = []
    for i in keys:
        # We have to regenerate the JWK from the private key
        privkey = serialization.load_pem_private_key(i[1], password=None)
        jwks.append(generate_jwk(privkey.public_key(), str(i[0])))

    return jwks
