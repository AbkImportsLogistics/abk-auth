from typing import Any

import httpx
from fastapi import HTTPException
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from abk_auth.models import User


class CognitoTokenValidator:
    """Valida id tokens emitidos por un User Pool de AWS Cognito."""

    def __init__(self, region: str, user_pool_id: str, app_client_id: str):
        self.app_client_id = app_client_id
        self.issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        self.keys_url = f"{self.issuer}/.well-known/jwks.json"
        self._jwks: dict[str, Any] = {}

    async def _fetch_jwks(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(self.keys_url)
            response.raise_for_status()
            return response.json()

    async def _get_signing_key(self, kid: str) -> dict[str, Any]:
        """Devuelve la clave pública para el `kid` dado, recargando el JWKS
        una sola vez si la clave no está en cache (rotación de claves de Cognito)."""
        key = self._find_key(kid)
        if key is None:
            self._jwks = await self._fetch_jwks()
            key = self._find_key(kid)
        if key is None:
            raise JWTError(f"No se encontró la clave de firma (kid={kid})")
        return key

    def _find_key(self, kid: str) -> dict[str, Any] | None:
        for key in self._jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    async def verify_token(self, token: str) -> User:

        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError:
            raise HTTPException(status_code=401, detail="Token malformado") from None

        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token sin 'kid'")

        try:
            signing_key = await self._get_signing_key(kid)
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="No se pudo validar el token: proveedor de identidad no disponible",
            ) from exc
        except JWTError:
            raise HTTPException(status_code=401, detail="Token inválido") from None

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.app_client_id,
                issuer=self.issuer,
                options={"verify_at_hash": False},
            )
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expirado") from None
        except JWTError:
            raise HTTPException(status_code=401, detail="Token inválido") from None

        if claims.get("token_use") != "id":
            raise HTTPException(
                status_code=401,
                detail="Tipo de token inválido: se requiere un id token",
            )

        return self._build_user(claims)

    @staticmethod
    def _build_user(claims: dict[str, Any]) -> User:
        email = claims.get("email") or claims.get("username")
        if not email:
            raise HTTPException(
                status_code=401,
                detail="El token no contiene email ni username",
            )
        email = email.lower()
        nombre = claims.get("name") or email.split("@")[0]

        grupos_cognito = claims.get("cognito:groups", [])
        grupos_reales = [
            g.lower()
            for g in grupos_cognito
            if not g.endswith("_google") and "us-east-1" not in g
        ]

        return User(email=email, nombre=nombre, roles=grupos_reales)
