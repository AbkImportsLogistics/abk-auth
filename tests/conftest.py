import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt

from abk_auth.core import AbkAuth

REGION = "us-east-1"
USER_POOL_ID = "us-east-1_testpool"
APP_CLIENT_ID = "test-client-id"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
KID = "test-kid"


@pytest.fixture(scope="session")
def rsa_keys():
    """Genera un par RSA y el JWKS público correspondiente para firmar tokens de prueba."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_jwk = jwk.construct(public_pem, "RS256").to_dict()
    public_jwk["kid"] = KID
    jwks = {"keys": [public_jwk]}
    return {"private_pem": private_pem, "jwks": jwks}


@pytest.fixture
def make_token(rsa_keys):
    """Fábrica de id tokens firmados con la clave de prueba."""

    def _make(
        *,
        email="USER@abk.pe",
        name="Usuario Prueba",
        groups=None,
        token_use="id",
        audience=APP_CLIENT_ID,
        issuer=ISSUER,
        expired=False,
        kid=KID,
        extra=None,
    ):
        now = int(time.time())
        claims = {
            "sub": "abc-123",
            "aud": audience,
            "iss": issuer,
            "token_use": token_use,
            "iat": now,
            "exp": now - 60 if expired else now + 3600,
        }
        if email is not None:
            claims["email"] = email
        if name is not None:
            claims["name"] = name
        if groups is not None:
            claims["cognito:groups"] = groups
        if extra:
            claims.update(extra)
        return jwt.encode(
            claims, rsa_keys["private_pem"], algorithm="RS256", headers={"kid": kid}
        )

    return _make


@pytest.fixture
def auth(rsa_keys):
    """Instancia de AbkAuth con el JWKS pre-cargado (sin red) y dos API Keys."""
    instance = AbkAuth(
        region=REGION,
        user_pool_id=USER_POOL_ID,
        app_client_id=APP_CLIENT_ID,
        api_keys=["KEY_ABC", "KEY_XYZ"],
    )
    instance.validator._jwks = rsa_keys["jwks"]
    return instance
