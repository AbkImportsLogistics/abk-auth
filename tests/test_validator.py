import httpx
import pytest
from fastapi import HTTPException


async def test_token_valido_devuelve_usuario(auth, make_token):
    user = await auth.validator.verify_token(make_token(groups=["admin", "finanzas"]))
    assert user.email == "user@abk.pe"  # normalizado a minúsculas
    assert user.nombre == "Usuario Prueba"
    assert user.roles == ["admin", "finanzas"]


async def test_grupos_internos_de_cognito_se_filtran(auth, make_token):
    token = make_token(groups=["Admin", "us-east-1_abc", "google_users_google"])
    user = await auth.validator.verify_token(token)
    assert user.roles == ["admin"]


async def test_nombre_por_defecto_es_el_usuario_del_email(auth, make_token):
    user = await auth.validator.verify_token(make_token(name=None))
    assert user.nombre == "user"


async def test_token_expirado(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(expired=True))
    assert exc.value.status_code == 401
    assert "expirado" in exc.value.detail.lower()


async def test_audiencia_incorrecta(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(audience="otro-client"))
    assert exc.value.status_code == 401


async def test_issuer_incorrecto(auth, make_token):
    token = make_token(issuer="https://cognito-idp.us-east-1.amazonaws.com/otro_pool")
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(token)
    assert exc.value.status_code == 401


async def test_access_token_es_rechazado(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(token_use="access"))
    assert exc.value.status_code == 401
    assert "id token" in exc.value.detail.lower()


async def test_token_sin_email_ni_username(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(email=None))
    assert exc.value.status_code == 401
    assert "email" in exc.value.detail.lower()


async def test_token_malformado(auth):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token("esto-no-es-un-jwt")
    assert exc.value.status_code == 401


async def test_fallo_de_red_devuelve_503(auth, make_token, monkeypatch):
    # kid desconocido fuerza una recarga del JWKS; simulamos que la red falla.
    async def boom():
        raise httpx.ConnectError("sin conexión")

    monkeypatch.setattr(auth.validator, "_fetch_jwks", boom)
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(kid="otro-kid"))
    assert exc.value.status_code == 503


async def test_rotacion_de_jwks_recarga_una_vez(auth, make_token, rsa_keys):
    # El validador arranca sin cache; debe recargar el JWKS al ver el kid.
    auth.validator._jwks = {}
    calls = {"n": 0}

    async def fake_fetch():
        calls["n"] += 1
        return rsa_keys["jwks"]

    auth.validator._fetch_jwks = fake_fetch
    user = await auth.validator.verify_token(make_token())
    assert user.email == "user@abk.pe"
    assert calls["n"] == 1
