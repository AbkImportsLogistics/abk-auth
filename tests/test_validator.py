import httpx
import pytest
from fastapi import HTTPException


async def test_token_valido_devuelve_usuario(auth, make_token):
    user = await auth.validator.verify_token(
        make_token(groups=["administrador", "finanzas"])
    )
    assert user.email == "user@abk.pe"  # normalizado a minúsculas
    assert user.nombre == "Usuario Prueba"
    assert user.roles == ["administrador", "finanzas"]


async def test_token_expone_el_sub(auth, make_token):
    # El sub (id inmutable de Cognito) se expone para enlazar con la DB de negocio.
    user = await auth.validator.verify_token(make_token())
    assert user.sub == "abc-123"

    # También en access token (no trae email, pero sí sub).
    access = await auth.validator.verify_token(
        make_token(token_use="access", email=None, name=None, client_id="test-client-id")
    )
    assert access.sub == "abc-123"


async def test_grupos_internos_de_cognito_se_filtran(auth, make_token):
    token = make_token(groups=["Administrador", "us-east-1_abc", "google_users_google"])
    user = await auth.validator.verify_token(token)
    assert user.roles == ["administrador"]


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


async def test_access_token_valido_es_aceptado(auth, make_token):
    # El access token no trae email/name ni aud; se valida vía client_id.
    token = make_token(
        token_use="access",
        email=None,
        name=None,
        groups=["administrador", "finanzas"],
        client_id="test-client-id",  # == APP_CLIENT_ID del conftest
        extra={"username": "user@abk.pe"},
    )
    user = await auth.validator.verify_token(token)
    assert user.email is None
    assert user.nombre == "user@abk.pe"  # cae al username
    assert user.roles == ["administrador", "finanzas"]
    assert user.is_admin()


async def test_access_token_con_client_id_incorrecto_es_rechazado(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(
            make_token(token_use="access", client_id="otro-client")
        )
    assert exc.value.status_code == 401
    assert "client_id" in exc.value.detail.lower()


async def test_token_con_token_use_no_soportado_es_rechazado(auth, make_token):
    with pytest.raises(HTTPException) as exc:
        await auth.validator.verify_token(make_token(token_use="refresh"))
    assert exc.value.status_code == 401


async def test_token_sin_email_arma_usuario_con_username_o_sub(auth, make_token):
    # Email opcional (caso access token): el usuario se arma con username/sub.
    user = await auth.validator.verify_token(make_token(email=None, name=None))
    assert user.email is None
    assert user.nombre == "abc-123"  # sub, al no haber email ni username


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
