# abk-auth

Librería centralizada de autenticación para los microservicios de **ABK Dev**.

Valida usuarios contra un **User Pool de AWS Cognito** (id tokens JWT) y permite
proteger endpoints máquina-a-máquina (M2M) mediante **API Keys**. Está pensada
para importarse desde cualquier servicio FastAPI y declarar, por endpoint, qué
tipo de seguridad requiere.

---

## Instalación

Instalá directamente desde el repositorio, fijando una versión con un tag:

```bash
pip install "git+https://github.com/AbkImportsLogistics/abk-auth.git@v0.1.0"
```

Para fijar la dependencia en un microservicio, agregala a su `requirements.txt`:

```text
abk-auth @ git+https://github.com/AbkImportsLogistics/abk-auth.git@v0.1.0
```

> Usá siempre un tag (`@v0.1.0`) en vez de `@main` para que la versión instalada
> sea reproducible y no cambie sola entre despliegues.

Requisitos: **Python 3.10+**.

---

## Conceptos

La librería separa dos ideas que conviene no mezclar:

| Concepto          | Pregunta            | Cómo se prueba                     |
| ----------------- | ------------------- | ---------------------------------- |
| **Autenticación** | ¿Quién sos?         | Token Cognito (Bearer) o API Key   |
| **Autorización**  | ¿Qué podés hacer?   | Roles (grupos de Cognito)          |

- Un **usuario Cognito** llega con `Authorization: Bearer <id_token>` y trae sus
  roles desde los grupos del User Pool.
- Una **integración M2M** llega con `X-API-KEY: <clave>`. Autentica como servicio
  de confianza, pero **no tiene roles** (no atraviesa `require_roles`).

---

## Uso

### 1. Inicializar

```python
from abk_auth import AbkAuth

auth = AbkAuth(
    region="us-east-1",
    user_pool_id="us-east-1_xxxxxxx",
    app_client_id="xxxxxxxxxxxxxxxxxxxx",
    api_keys=["CLAVE_SERVICIO_A", "CLAVE_SERVICIO_B"],  # opcional
)
```

> Cargá `api_keys` y las credenciales desde variables de entorno o tu gestor de
> secretos, nunca hardcodeadas en el código.

### 2. Proteger endpoints

```python
from fastapi import Depends, FastAPI
from abk_auth import User

app = FastAPI()

# Endpoint que requiere un rol específico (usuario Cognito)
@app.get("/reportes", dependencies=[Depends(auth.require_roles(["finanzas", "administrador"]))])
async def reportes():
    return {"ok": True}

# Endpoint sin roles, protegido solo por API Key (M2M)
@app.post("/webhooks/pago", dependencies=[Depends(auth.require_api_key())])
async def webhook_pago():
    return {"recibido": True}

# Cualquier usuario Cognito autenticado (sin exigir rol)
@app.get("/perfil")
async def perfil(current_user: User = Depends(auth.get_current_user)):
    return {"email": current_user.email, "roles": current_user.roles}

# Acepta tanto un usuario Cognito como una API Key
@app.get("/datos")
async def datos(current_user: User = Depends(auth.require_user_or_api_key())):
    return {"solicitante": current_user.email}
```

---

## API

### `AbkAuth(region, user_pool_id, app_client_id, api_keys=None)`

Fachada de seguridad. Las dependencias que expone:

| Dependencia                    | Acepta                          | Devuelve / Falla |
| ------------------------------ | ------------------------------- | ---------------- |
| `get_current_user`             | Bearer (Cognito)                | `User` · 401 |
| `require_roles([...])`         | Bearer con alguno de los roles  | `User` · 401 / 403 |
| `require_api_key()`            | `X-API-KEY` válida              | `User` (M2M, sin roles) · 401 |
| `require_user_or_api_key()`    | Bearer **o** `X-API-KEY`        | `User` · 401 |

### `User`

```python
class User(BaseModel):
    email: EmailStr | None = None  # ausente en access tokens
    nombre: str
    roles: list[str] = []

    def is_admin(self) -> bool: ...  # True si tiene el rol "administrador"
    def has_any_role(self, allowed_roles: list[str]) -> bool: ...
```

Para integraciones M2M, `email` es `sistema@abk.pe`, `nombre` es `Integración M2M`
y `roles` está vacío.

---

## Respuestas de error

| Código | Situación |
| ------ | --------- |
| `401`  | Falta credencial, token inválido/expirado/malformado, no es un id token, API Key inválida, o id token sin `email` ni `username` |
| `403`  | Usuario autenticado pero sin el rol requerido |
| `503`  | No se pudo contactar a Cognito para obtener las claves de firma (JWKS) |

---

## Validación de tokens

`abk-auth` verifica, sobre cada id token de Cognito:

- **Firma** RS256 contra el JWKS público del User Pool.
- **`aud`** = `app_client_id`.
- **`iss`** = `https://cognito-idp.<region>.amazonaws.com/<user_pool_id>`.
- **`token_use`** = `id` (los access tokens se rechazan).
- **Expiración** (`exp`).

El JWKS se cachea en memoria y se recarga automáticamente si Cognito rota sus
claves de firma.

A partir de los claims se construye el `User`:

- `email`: claim `email` o, en su defecto, `username` (normalizado a minúsculas).
- `nombre`: claim `name` o, si falta, la parte del email anterior a la `@`.
- `roles`: los grupos de Cognito (`cognito:groups`) en minúsculas, descartando los
  grupos internos (los que terminan en `_google` o contienen `us-east-1`).

---

## Desarrollo

```bash
pip install -e ".[test]"
pytest
```

---

## Versionado

Cada versión se publica como un **tag de git**, que es lo que los microservicios
fijan al instalar (`@v0.1.0`).

1. Actualizá el número en [`version.txt`](version.txt) (única fuente de verdad;
   `pyproject.toml` la lee de ahí).
2. Commiteá y creá el tag con el mismo número, prefijado con `v`:

   ```bash
   git commit -am "Release 0.2.0"
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin main v0.2.0
   ```

A partir de ahí, cualquier servicio puede instalar esa versión con
`...abk-auth.git@v0.2.0`.
