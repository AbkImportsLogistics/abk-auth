import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(auth):
    """App FastAPI de prueba con un endpoint por cada dependencia de AbkAuth."""
    app = FastAPI()

    @app.get("/me")
    async def me(user=Depends(auth.get_current_user)):
        return {"email": user.email, "roles": user.roles}

    @app.get("/admin", dependencies=[Depends(auth.require_roles(["admin"]))])
    async def admin():
        return {"ok": True}

    @app.get("/m2m")
    async def m2m(user=Depends(auth.require_api_key())):
        return {"email": user.email, "roles": user.roles}

    @app.get("/mixto")
    async def mixto(user=Depends(auth.require_user_or_api_key())):
        return {"email": user.email}

    return TestClient(app)


# ---------------------------------------------------------------- get_current_user


def test_usuario_cognito_accede(client, make_token):
    r = client.get("/me", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 200
    assert r.json()["email"] == "user@abk.pe"


def test_sin_cabecera_es_401(client):
    assert client.get("/me").status_code == 401


def test_api_key_no_sirve_para_endpoint_de_usuario(client):
    # /me exige Bearer; una API Key no debe autenticar aquí.
    assert client.get("/me", headers={"X-API-KEY": "KEY_ABC"}).status_code == 401


# ------------------------------------------------------------------- require_roles


def test_usuario_con_rol_accede(client, make_token):
    token = make_token(groups=["admin"])
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_usuario_sin_rol_es_403(client, make_token):
    token = make_token(groups=[])
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_usuario_con_rol_distinto_es_403(client, make_token):
    token = make_token(groups=["finanzas"])
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_api_key_no_pasa_require_roles(client):
    # Una API Key M2M no tiene roles, por lo que no entra a /admin.
    assert client.get("/admin", headers={"X-API-KEY": "KEY_ABC"}).status_code == 401


# ----------------------------------------------------------------- require_api_key


def test_api_key_valida_accede(client):
    r = client.get("/m2m", headers={"X-API-KEY": "KEY_ABC"})
    assert r.status_code == 200
    assert r.json() == {"email": "sistema@abk.pe", "roles": []}


def test_api_key_invalida_es_401(client):
    assert client.get("/m2m", headers={"X-API-KEY": "MALA"}).status_code == 401


def test_m2m_sin_api_key_es_401(client):
    assert client.get("/m2m").status_code == 401


def test_bearer_no_sirve_para_endpoint_m2m(client, make_token):
    r = client.get("/m2m", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 401


# ------------------------------------------------------------ require_user_or_api_key


def test_mixto_acepta_api_key(client):
    r = client.get("/mixto", headers={"X-API-KEY": "KEY_XYZ"})
    assert r.status_code == 200
    assert r.json()["email"] == "sistema@abk.pe"


def test_mixto_acepta_usuario(client, make_token):
    r = client.get("/mixto", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 200
    assert r.json()["email"] == "user@abk.pe"


def test_mixto_sin_credenciales_es_401(client):
    assert client.get("/mixto").status_code == 401
