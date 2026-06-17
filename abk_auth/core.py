import secrets
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request

from abk_auth.models import User
from abk_auth.validator import CognitoTokenValidator

M2M_EMAIL = "sistema@abk.pe"
M2M_NOMBRE = "Integración M2M"


class AbkAuth:
    """Fachada de seguridad para microservicios FastAPI.

    Expone dependencias listas para usar según lo que protege cada endpoint:

    - ``get_current_user``      -> usuario Cognito autenticado (sin exigir rol).
    - ``require_roles([...])``  -> usuario Cognito con alguno de los roles dados.
    - ``require_api_key()``     -> solo acceso M2M vía cabecera ``X-API-KEY``.
    - ``require_user_or_api_key()`` -> acepta cualquiera de los dos métodos.
    """

    def __init__(
        self,
        region: str,
        user_pool_id: str,
        app_client_id: str,
        api_keys: list[str] | None = None,
    ):
        """Inicializa la seguridad inyectando las credenciales de AWS y las API Keys permitidas."""
        self.validator = CognitoTokenValidator(region, user_pool_id, app_client_id)
        self.api_keys = api_keys or []

    def _check_api_key(self, request: Request) -> User | None:
        """Devuelve el usuario M2M si hay una API Key válida.

        - Sin cabecera ``X-API-KEY`` -> ``None`` (no es una llamada M2M).
        - Cabecera presente pero inválida -> 401.
        """
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return None

        api_key = api_key.strip()
        is_valid = any(
            secrets.compare_digest(api_key, valid_key) for valid_key in self.api_keys
        )
        if not is_valid:
            raise HTTPException(status_code=401, detail="API Key inválida")

        return User(email=M2M_EMAIL, nombre=M2M_NOMBRE, roles=[])

    async def _check_bearer(self, authorization: str | None) -> User | None:
        """Devuelve el usuario Cognito si hay un token Bearer; ``None`` si no hay cabecera."""
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[len("Bearer ") :].strip()
        return await self.validator.verify_token(token)

    async def get_current_user(self, authorization: str = Header(None)) -> User:
        """Autentica a un usuario Cognito mediante token Bearer."""
        user = await self._check_bearer(authorization)
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="No autenticado: se requiere cabecera Authorization (Bearer)",
            )
        return user

    def require_roles(self, allowed_roles: list[str]) -> Callable:
        """Protege una ruta exigiendo que el usuario Cognito tenga alguno de los roles dados."""

        def role_checker(current_user: User = Depends(self.get_current_user)) -> User:
            if not current_user.roles:
                raise HTTPException(status_code=403, detail="Cuenta sin rol asignado.")
            if not current_user.has_any_role(allowed_roles):
                raise HTTPException(
                    status_code=403,
                    detail=f"Permisos insuficientes. Requerido: {allowed_roles}",
                )
            return current_user

        return role_checker

    def require_api_key(self) -> Callable:
        """Protege una ruta exigiendo una API Key válida (acceso M2M, sin roles)."""

        def api_key_checker(request: Request) -> User:
            user = self._check_api_key(request)
            if user is None:
                raise HTTPException(
                    status_code=401,
                    detail="No autenticado: se requiere cabecera X-API-KEY",
                )
            return user

        return api_key_checker

    def require_user_or_api_key(self) -> Callable:
        """Acepta tanto un usuario Cognito (Bearer) como una API Key M2M."""

        async def checker(request: Request, authorization: str = Header(None)) -> User:
            user = self._check_api_key(request)
            if user is not None:
                return user
            user = await self._check_bearer(authorization)
            if user is not None:
                return user
            raise HTTPException(
                status_code=401,
                detail="No autenticado: se requiere cabecera Authorization (Bearer) o X-API-KEY",
            )

        return checker
